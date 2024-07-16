const std = @import("std");
const network = @import("zig-network");
const sig = @import("../lib.zig");

const testing = std.testing;
const bincode = sig.bincode;

const ArrayList = std.ArrayList;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const UdpSocket = network.Socket;
const TcpListener = network.Socket;

const SocketAddr = sig.net.SocketAddr;
const Hash = sig.core.Hash;
const Signature = sig.core.Signature;
const Transaction = sig.core.Transaction;
const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const IpAddr = sig.net.IpAddr;
const ClientVersion = sig.version.ClientVersion;
const DynamicArrayBitSet = sig.bloom.bit_set.DynamicArrayBitSet;
const BitVecConfig = sig.bloom.bit_vec.BitVecConfig;
const ShortVecArrayListConfig = sig.bincode.shortvec.ShortVecArrayListConfig;

const sanitizeWallclock = sig.gossip.message.sanitizeWallclock;

const PACKET_DATA_SIZE = sig.net.packet.PACKET_DATA_SIZE;
const var_int_config_u16 = sig.bincode.varint.var_int_config_u16;
const var_int_config_u64 = sig.bincode.varint.var_int_config_u64;

/// returns current timestamp in milliseconds
pub fn getWallclockMs() u64 {
    return @intCast(std.time.milliTimestamp());
}

pub const MAX_EPOCH_SLOTS: u8 = 255;
pub const MAX_VOTES: u8 = 32;
pub const MAX_SLOT: u64 = 1_000_000_000_000_000;
pub const MAX_SLOT_PER_ENTRY: usize = 2048 * 8;
pub const MAX_DUPLICATE_SHREDS: u16 = 512;

/// Analogous to [VersionedCrdsValue](https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds.rs#L122)
pub const GossipVersionedData = struct {
    value: SignedGossipData,
    value_hash: Hash,
    timestamp_on_insertion: u64,
    cursor_on_insertion: u64,

    pub fn clone(self: *const GossipVersionedData, allocator: std.mem.Allocator) error{OutOfMemory}!GossipVersionedData {
        return .{
            .value = try self.value.clone(allocator),
            .value_hash = self.value_hash,
            .timestamp_on_insertion = self.timestamp_on_insertion,
            .cursor_on_insertion = self.cursor_on_insertion,
        };
    }

    pub fn deinit(self: *GossipVersionedData, allocator: std.mem.Allocator) void {
        self.value.deinit(allocator);
    }

    pub fn overwrites(new_value: *const @This(), old_value: *const @This()) bool {
        // labels must match
        std.debug.assert(@intFromEnum(new_value.value.label()) == @intFromEnum(old_value.value.label()));

        const new_ts = new_value.value.wallclock();
        const old_ts = old_value.value.wallclock();

        // TODO: improve the return type here
        if (new_ts > old_ts) {
            return true;
        } else if (new_ts < old_ts) {
            return false;
        } else {
            return old_value.value_hash.order(&new_value.value_hash) == .lt;
        }
    }
};

/// Analogous to [CrdsValue](https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds_value.rs#L45)
pub const SignedGossipData = struct {
    signature: Signature,
    data: GossipData,

    const Self = @This();

    pub fn init(data: GossipData) Self {
        return Self{
            .signature = Signature{},
            .data = data,
        };
    }

    pub fn initSigned(data: GossipData, keypair: *const KeyPair) !Self {
        var self = Self{
            .signature = Signature{},
            .data = data,
        };
        try self.sign(keypair);
        return self;
    }

    pub fn clone(self: *const Self, allocator: std.mem.Allocator) error{OutOfMemory}!Self {
        return .{
            .signature = self.signature,
            .data = try self.data.clone(allocator),
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
    }

    /// only used in tests
    pub fn random(rng: std.rand.Random, keypair: *const KeyPair) !Self {
        return try initSigned(GossipData.random(rng), keypair);
    }

    /// only used in tests
    pub fn randomWithIndex(rng: std.rand.Random, keypair: *const KeyPair, index: usize) !Self {
        return try initSigned(GossipData.randomFromIndex(rng, index), keypair);
    }

    pub fn sign(self: *Self, keypair: *const KeyPair) !void {
        // should always be enough space or is invalid msg
        var buf: [PACKET_DATA_SIZE]u8 = undefined;
        const bytes = try bincode.writeToSlice(&buf, self.data, bincode.Params.standard);
        var signature = try keypair.sign(bytes, null);
        self.signature.data = signature.toBytes();
    }

    pub fn verify(self: *Self, pubkey: Pubkey) !bool {
        // should always be enough space or is invalid msg
        var buf: [PACKET_DATA_SIZE]u8 = undefined;
        const msg = try bincode.writeToSlice(&buf, self.data, bincode.Params.standard);
        return self.signature.verify(pubkey, msg);
    }

    pub fn id(self: *const Self) Pubkey {
        return switch (self.data) {
            .LegacyContactInfo => |*v| {
                return v.id;
            },
            .Vote => |*v| {
                return v[1].from;
            },
            .LowestSlot => |*v| {
                return v[1].from;
            },
            .LegacySnapshotHashes => |*v| {
                return v.from;
            },
            .AccountsHashes => |*v| {
                return v.from;
            },
            .EpochSlots => |*v| {
                return v[1].from;
            },
            .LegacyVersion => |*v| {
                return v.from;
            },
            .Version => |*v| {
                return v.from;
            },
            .NodeInstance => |*v| {
                return v.from;
            },
            .DuplicateShred => |*v| {
                return v[1].from;
            },
            .SnapshotHashes => |*v| {
                return v.from;
            },
            .ContactInfo => |*v| {
                return v.pubkey;
            },
            .RestartLastVotedForkSlots => |*v| {
                return v.from;
            },
            .RestartHeaviestFork => |*v| {
                return v.from;
            },
        };
    }

    pub fn wallclock(self: *const Self) u64 {
        return switch (self.data) {
            .LegacyContactInfo => |*v| {
                return v.wallclock;
            },
            .Vote => |*v| {
                return v[1].wallclock;
            },
            .LowestSlot => |*v| {
                return v[1].wallclock;
            },
            .LegacySnapshotHashes => |*v| {
                return v.wallclock;
            },
            .AccountsHashes => |*v| {
                return v.wallclock;
            },
            .EpochSlots => |*v| {
                return v[1].wallclock;
            },
            .LegacyVersion => |*v| {
                return v.wallclock;
            },
            .Version => |*v| {
                return v.wallclock;
            },
            .NodeInstance => |*v| {
                return v.wallclock;
            },
            .DuplicateShred => |*v| {
                return v[1].wallclock;
            },
            .SnapshotHashes => |*v| {
                return v.wallclock;
            },
            .ContactInfo => |*v| {
                return v.wallclock;
            },
            .RestartLastVotedForkSlots => |*v| {
                return v.wallclock;
            },
            .RestartHeaviestFork => |*v| {
                return v.wallclock;
            },
        };
    }

    pub fn label(self: *const Self) GossipKey {
        return switch (self.data) {
            .LegacyContactInfo => {
                return .{ .LegacyContactInfo = self.id() };
            },
            .Vote => |*v| {
                return .{ .Vote = .{ v[0], self.id() } };
            },
            .LowestSlot => {
                return .{ .LowestSlot = self.id() };
            },
            .LegacySnapshotHashes => {
                return .{ .LegacySnapshotHashes = self.id() };
            },
            .AccountsHashes => {
                return .{ .AccountsHashes = self.id() };
            },
            .EpochSlots => |*v| {
                return .{ .EpochSlots = .{ v[0], self.id() } };
            },
            .LegacyVersion => {
                return .{ .LegacyVersion = self.id() };
            },
            .Version => {
                return .{ .Version = self.id() };
            },
            .NodeInstance => {
                return .{ .NodeInstance = self.id() };
            },
            .DuplicateShred => |*v| {
                return .{ .DuplicateShred = .{ v[0], self.id() } };
            },
            .SnapshotHashes => {
                return .{ .SnapshotHashes = self.id() };
            },
            .ContactInfo => {
                return .{ .ContactInfo = self.id() };
            },
            .RestartLastVotedForkSlots => {
                return .{ .RestartLastVotedForkSlots = self.id() };
            },
            .RestartHeaviestFork => {
                return .{ .RestartHeaviestFork = self.id() };
            },
        };
    }
};

/// Analogous to [CrdsValueLabel](https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds_value.rs#L500)
pub const GossipKey = union(enum) {
    LegacyContactInfo: Pubkey,
    Vote: struct { u8, Pubkey },
    LowestSlot: Pubkey,
    LegacySnapshotHashes: Pubkey,
    EpochSlots: struct { u8, Pubkey },
    AccountsHashes: Pubkey,
    LegacyVersion: Pubkey,
    Version: Pubkey,
    NodeInstance: Pubkey,
    DuplicateShred: struct { u16, Pubkey },
    SnapshotHashes: Pubkey,
    ContactInfo: Pubkey,
    RestartLastVotedForkSlots: Pubkey,
    RestartHeaviestFork: Pubkey,
};

/// Analogous to [CrdsData](https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds_value.rs#L85)
pub const GossipData = union(enum(u32)) {
    LegacyContactInfo: LegacyContactInfo,
    Vote: struct { u8, Vote },
    LowestSlot: struct { u8, LowestSlot },
    LegacySnapshotHashes: LegacySnapshotHashes,
    AccountsHashes: AccountsHashes,
    EpochSlots: struct { u8, EpochSlots },
    LegacyVersion: LegacyVersion,
    Version: Version,
    NodeInstance: NodeInstance,
    DuplicateShred: struct { u16, DuplicateShred },
    SnapshotHashes: SnapshotHashes,
    ContactInfo: ContactInfo,
    // https://github.com/anza-xyz/agave/commit/0a3810854fa4a11b0841c548dcbc0ada311b8830
    RestartLastVotedForkSlots: RestartLastVotedForkSlots,
    // https://github.com/anza-xyz/agave/commit/4a2871f38419b4d9b303254273b19a2e41707c47
    RestartHeaviestFork: RestartHeaviestFork,

    pub fn clone(self: *const GossipData, allocator: std.mem.Allocator) error{OutOfMemory}!GossipData {
        return switch (self.*) {
            .LegacyContactInfo => |*v| .{ .LegacyContactInfo = v.* },
            .Vote => |*v| .{ .Vote = .{ v[0], try v[1].clone(allocator) } },
            .LowestSlot => |*v| .{ .LowestSlot = .{ v[0], try v[1].clone(allocator) } },
            .LegacySnapshotHashes => |*v| .{ .LegacySnapshotHashes = try v.clone(allocator) },
            .AccountsHashes => |*v| .{ .AccountsHashes = try v.clone(allocator) },
            .EpochSlots => |*v| .{ .EpochSlots = .{ v[0], try v[1].clone(allocator) } },
            .LegacyVersion => |*v| .{ .LegacyVersion = v.* },
            .Version => |*v| .{ .Version = v.* },
            .NodeInstance => |*v| .{ .NodeInstance = v.* },
            .DuplicateShred => |*v| .{ .DuplicateShred = .{ v[0], try v[1].clone(allocator) } },
            .SnapshotHashes => |*v| .{ .SnapshotHashes = try v.clone(allocator) },
            .ContactInfo => |*v| .{ .ContactInfo = try v.clone() },
            .RestartLastVotedForkSlots => |*v| .{ .RestartLastVotedForkSlots = try v.clone(allocator) },
            .RestartHeaviestFork => |*v| .{ .RestartHeaviestFork = v.* },
        };
    }

    pub fn deinit(self: *GossipData, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .LegacyContactInfo => {},
            .Vote => |*v| v[1].deinit(allocator),
            .LowestSlot => |*v| v[1].deinit(allocator),
            .LegacySnapshotHashes => |*v| v.deinit(allocator),
            .AccountsHashes => |*v| v.deinit(allocator),
            .EpochSlots => |*v| v[1].deinit(allocator),
            .LegacyVersion => {},
            .Version => {},
            .NodeInstance => {},
            .DuplicateShred => |*v| v[1].deinit(allocator),
            .SnapshotHashes => |*v| v.deinit(allocator),
            .ContactInfo => |*v| v.deinit(),
            .RestartLastVotedForkSlots => |*v| v.deinit(allocator),
            .RestartHeaviestFork => {},
        }
    }

    pub fn sanitize(self: *const GossipData) !void {
        switch (self.*) {
            inline .LegacyContactInfo,
            .ContactInfo,
            .AccountsHashes,
            .LegacySnapshotHashes,
            .SnapshotHashes,
            .NodeInstance,
            .Version,
            .RestartLastVotedForkSlots,
            .RestartHeaviestFork,
            => |*v| {
                try v.sanitize();
            },
            .Vote => |*v| {
                const index = v[0];
                if (index >= MAX_VOTES) {
                    return error.ValueOutOfBounds;
                }

                const vote: Vote = v[1];
                try vote.sanitize();
            },
            .EpochSlots => |*v| {
                const index = v[0];
                if (index >= MAX_EPOCH_SLOTS) {
                    return error.ValueOutOfBounds;
                }

                const value: EpochSlots = v[1];
                try value.sanitize();
            },
            .DuplicateShred => |*v| {
                const index = v[0];
                if (index >= MAX_DUPLICATE_SHREDS) {
                    return error.ValueOutOfBounds;
                }

                const value: DuplicateShred = v[1];
                try value.sanitize();
            },
            .LowestSlot => |*v| {
                const index = v[0];
                if (index >= 1) {
                    return error.ValueOutOfBounds;
                }

                const value: LowestSlot = v[1];
                try value.sanitize();
            },
            else => {
                std.debug.print("sanitize not implemented for type: {s}\n", .{@tagName(self.*)});
                return error.NotImplemented;
            },
        }
    }

    // only used in tests
    pub fn setId(self: *GossipData, id: Pubkey) void {
        switch (self.*) {
            .LegacyContactInfo => |*v| {
                v.id = id;
            },
            .Vote => |*v| {
                v[1].from = id;
            },
            .LowestSlot => |*v| {
                v[1].from = id;
            },
            .LegacySnapshotHashes => |*v| {
                v.from = id;
            },
            .AccountsHashes => |*v| {
                v.from = id;
            },
            .EpochSlots => |*v| {
                v[1].from = id;
            },
            .LegacyVersion => |*v| {
                v.from = id;
            },
            .Version => |*v| {
                v.from = id;
            },
            .NodeInstance => |*v| {
                v.from = id;
            },
            .DuplicateShred => |*v| {
                v[1].from = id;
            },
            .SnapshotHashes => |*v| {
                v.from = id;
            },
            .ContactInfo => |*v| {
                v.pubkey = id;
            },
            .RestartLastVotedForkSlots => |*v| {
                v.from = id;
            },
            .RestartHeaviestFork => |*v| {
                v.from = id;
            },
        }
    }

    pub fn random(rng: std.rand.Random) GossipData {
        const v = rng.intRangeAtMost(u16, 0, 10);
        return GossipData.randomFromIndex(rng, v);
    }

    pub fn randomFromIndex(rng: std.rand.Random, index: usize) GossipData {
        switch (index) {
            0 => {
                return .{ .LegacyContactInfo = LegacyContactInfo.random(rng) };
            },
            1 => {
                return .{ .Vote = .{ rng.intRangeAtMost(u8, 0, MAX_VOTES - 1), Vote.random(rng) } };
            },
            2 => {
                return .{ .EpochSlots = .{ rng.intRangeAtMost(u8, 0, MAX_EPOCH_SLOTS - 1), EpochSlots.random(rng) } };
            },
            3 => {
                return .{ .LowestSlot = .{ 0, LowestSlot.random(rng) } };
            },
            4 => {
                return .{ .LegacySnapshotHashes = LegacySnapshotHashes.random(rng) };
            },
            5 => {
                return .{ .AccountsHashes = AccountsHashes.random(rng) };
            },
            6 => {
                return .{ .LegacyVersion = LegacyVersion.random(rng) };
            },
            7 => {
                return .{ .Version = Version.random(rng) };
            },
            8 => {
                return .{ .NodeInstance = NodeInstance.random(rng) };
            },
            9 => {
                return .{ .SnapshotHashes = SnapshotHashes.random(rng) };
            },
            // 10 => {
            //     return GossipData { .ContactInfo = ContactInfo.random(rng) };
            // },
            else => {
                return .{ .DuplicateShred = .{ rng.intRangeAtMost(u16, 0, MAX_DUPLICATE_SHREDS - 1), DuplicateShred.random(rng) } };
            },
        }
    }

    pub fn gossipAddr(self: *const @This()) ?SocketAddr {
        return switch (self.*) {
            .LegacyContactInfo => |*v| if (v.gossip.isUnspecified()) null else v.gossip,
            .ContactInfo => |*v| v.getSocket(.gossip),
            else => null,
        };
    }

    pub fn shredVersion(self: *const @This()) ?u16 {
        return switch (self.*) {
            .LegacyContactInfo => |*v| v.shred_version,
            .ContactInfo => |*v| v.shred_version,
            else => null,
        };
    }
};

/// analogous to [LegactContactInfo](https://github.com/anza-xyz/agave/blob/0d34a1a160129c4293dac248e14231e9e773b4ce/gossip/src/legacy_contact_info.rs#L26)
pub const LegacyContactInfo = struct {
    id: Pubkey,
    /// gossip address
    gossip: SocketAddr,
    /// address to connect to for replication
    /// analogous to `tvu` in agave
    turbine_recv: SocketAddr,
    /// address to forward shreds to
    /// analogous to `tvu_quic` in agave
    turbine_recv_quic: SocketAddr,
    /// address to send repair responses to
    repair: SocketAddr,
    /// transactions address
    tpu: SocketAddr,
    /// address to forward unprocessed transactions to
    tpu_forwards: SocketAddr,
    /// address to which to send bank state requests
    tpu_vote: SocketAddr,
    /// address to which to send JSON-RPC requests
    rpc: SocketAddr,
    /// websocket for JSON-RPC push notifications
    rpc_pubsub: SocketAddr,
    /// address to send repair requests to
    serve_repair: SocketAddr,
    /// latest wallclock picked
    wallclock: u64,
    /// node shred version
    shred_version: u16,

    pub fn sanitize(self: *const LegacyContactInfo) !void {
        try sanitizeWallclock(self.wallclock);
    }

    pub fn default(id: Pubkey) LegacyContactInfo {
        const unspecified_addr = SocketAddr.initIpv4(.{ 0, 0, 0, 0 }, 0);
        const wallclock = getWallclockMs();

        return LegacyContactInfo{
            .id = id,
            .gossip = unspecified_addr,
            .turbine_recv = unspecified_addr,
            .turbine_recv_quic = unspecified_addr,
            .repair = unspecified_addr,
            .tpu = unspecified_addr,
            .tpu_forwards = unspecified_addr,
            .tpu_vote = unspecified_addr,
            .rpc = unspecified_addr,
            .rpc_pubsub = unspecified_addr,
            .serve_repair = unspecified_addr,
            .wallclock = wallclock,
            .shred_version = 0,
        };
    }

    pub fn random(rng: std.rand.Random) LegacyContactInfo {
        return LegacyContactInfo{
            .id = Pubkey.random(rng),
            .gossip = SocketAddr.random(rng),
            .turbine_recv = SocketAddr.random(rng),
            .turbine_recv_quic = SocketAddr.random(rng),
            .repair = SocketAddr.random(rng),
            .tpu = SocketAddr.random(rng),
            .tpu_forwards = SocketAddr.random(rng),
            .tpu_vote = SocketAddr.random(rng),
            .rpc = SocketAddr.random(rng),
            .rpc_pubsub = SocketAddr.random(rng),
            .serve_repair = SocketAddr.random(rng),
            .wallclock = getWallclockMs(),
            .shred_version = rng.int(u16),
        };
    }

    /// call ContactInfo.deinit to free
    pub fn toContactInfo(self: *const LegacyContactInfo, allocator: std.mem.Allocator) !ContactInfo {
        var ci = ContactInfo.init(allocator, self.id, self.wallclock, self.shred_version);
        try ci.setSocket(.gossip, self.gossip);
        try ci.setSocket(.turbine_recv, self.turbine_recv);
        try ci.setSocket(.turbine_recv_quic, self.turbine_recv_quic);
        try ci.setSocket(.repair, self.repair);
        try ci.setSocket(.tpu, self.tpu);
        try ci.setSocket(.tpu_forwards, self.tpu_forwards);
        try ci.setSocket(.tpu_vote, self.tpu_vote);
        try ci.setSocket(.rpc, self.rpc);
        try ci.setSocket(.rpc_pubsub, self.rpc_pubsub);
        try ci.setSocket(.serve_repair, self.serve_repair);
        return ci;
    }

    pub fn fromContactInfo(ci: *const ContactInfo) LegacyContactInfo {
        return .{
            .id = ci.pubkey,
            .gossip = ci.getSocket(.gossip) orelse SocketAddr.UNSPECIFIED,
            .turbine_recv = ci.getSocket(.turbine_recv) orelse SocketAddr.UNSPECIFIED,
            .turbine_recv_quic = ci.getSocket(.turbine_recv_quic) orelse SocketAddr.UNSPECIFIED,
            .repair = ci.getSocket(.repair) orelse SocketAddr.UNSPECIFIED,
            .tpu = ci.getSocket(.tpu) orelse SocketAddr.UNSPECIFIED,
            .tpu_forwards = ci.getSocket(.tpu_forwards) orelse SocketAddr.UNSPECIFIED,
            .tpu_vote = ci.getSocket(.tpu_vote) orelse SocketAddr.UNSPECIFIED,
            .rpc = ci.getSocket(.rpc) orelse SocketAddr.UNSPECIFIED,
            .rpc_pubsub = ci.getSocket(.rpc_pubsub) orelse SocketAddr.UNSPECIFIED,
            .serve_repair = ci.getSocket(.serve_repair) orelse SocketAddr.UNSPECIFIED,
            .wallclock = ci.wallclock,
            .shred_version = ci.shred_version,
        };
    }
};

pub const Vote = struct {
    from: Pubkey,
    transaction: Transaction,
    wallclock: u64,
    slot: Slot = 0,

    pub const @"!bincode-config:slot" = bincode.FieldConfig(Slot){ .skip = true };

    pub fn clone(self: *const Vote, allocator: std.mem.Allocator) error{OutOfMemory}!Vote {
        return .{
            .from = self.from,
            .transaction = try self.transaction.clone(allocator),
            .wallclock = self.wallclock,
            .slot = self.slot,
        };
    }

    pub fn deinit(self: *Vote, allocator: std.mem.Allocator) void {
        self.transaction.deinit(allocator);
    }

    pub fn random(rng: std.rand.Random) Vote {
        return Vote{
            .from = Pubkey.random(rng),
            .transaction = Transaction.default(),
            .wallclock = getWallclockMs(),
            .slot = rng.int(u64),
        };
    }

    pub fn sanitize(self: *const Vote) !void {
        try sanitizeWallclock(self.wallclock);
        try self.transaction.sanitize();
    }
};

pub const LowestSlot = struct {
    from: Pubkey,
    root: u64, //deprecated
    lowest: u64,
    slots: []u64, //deprecated
    stash: []DeprecatedEpochIncompleteSlots, //deprecated
    wallclock: u64,

    pub fn clone(self: *const LowestSlot, allocator: std.mem.Allocator) error{OutOfMemory}!LowestSlot {
        const stash = try allocator.alloc(DeprecatedEpochIncompleteSlots, self.stash.len);
        for (stash, 0..) |*item, i| item.* = try self.stash[i].clone(allocator);
        return .{
            .from = self.from,
            .root = self.root,
            .lowest = self.lowest,
            .slots = try allocator.dupe(u64, self.slots),
            .stash = stash,
            .wallclock = self.wallclock,
        };
    }

    pub fn deinit(self: *LowestSlot, allocator: std.mem.Allocator) void {
        allocator.free(self.slots);
        for (self.stash) |*item| item.deinit(allocator);
        allocator.free(self.stash);
    }

    pub fn sanitize(value: *const LowestSlot) !void {
        try sanitizeWallclock(value.wallclock);
        if (value.lowest >= MAX_SLOT) {
            return error.ValueOutOfBounds;
        }
        if (value.root != 0) {
            return error.InvalidValue;
        }
        if (value.slots.len != 0) {
            return error.InvalidValue;
        }
        if (value.stash.len != 0) {
            return error.InvalidValue;
        }
    }

    pub fn random(rng: std.rand.Random) LowestSlot {
        var slots: [0]u64 = .{};
        var stash: [0]DeprecatedEpochIncompleteSlots = .{};
        return LowestSlot{
            .from = Pubkey.random(rng),
            .root = 0,
            .lowest = rng.int(u64),
            .slots = &slots,
            .stash = &stash,
            .wallclock = getWallclockMs(),
        };
    }
};

pub const DeprecatedEpochIncompleteSlots = struct {
    first: u64,
    compression: CompressionType,
    compressed_list: []u8,

    pub fn clone(self: *const DeprecatedEpochIncompleteSlots, allocator: std.mem.Allocator) error{OutOfMemory}!DeprecatedEpochIncompleteSlots {
        return .{
            .first = self.first,
            .compression = self.compression,
            .compressed_list = try allocator.dupe(u8, self.compressed_list),
        };
    }

    pub fn deinit(self: *DeprecatedEpochIncompleteSlots, allocator: std.mem.Allocator) void {
        allocator.free(self.compressed_list);
    }
};

pub const CompressionType = enum {
    Uncompressed,
    GZip,
    BZip2,
};

pub const LegacySnapshotHashes = AccountsHashes;

const SlotAndHash = @import("../accountsdb/snapshots.zig").SlotAndHash;

pub const AccountsHashes = struct {
    from: Pubkey,
    hashes: []SlotAndHash,
    wallclock: u64,

    pub fn clone(self: *const AccountsHashes, allocator: std.mem.Allocator) error{OutOfMemory}!AccountsHashes {
        return .{
            .from = self.from,
            .hashes = try allocator.dupe(SlotAndHash, self.hashes),
            .wallclock = self.wallclock,
        };
    }

    pub fn deinit(self: *AccountsHashes, allocator: std.mem.Allocator) void {
        allocator.free(self.hashes);
    }

    pub fn random(rng: std.rand.Random) AccountsHashes {
        var slice: [0]SlotAndHash = .{};
        return AccountsHashes{
            .from = Pubkey.random(rng),
            .hashes = &slice,
            .wallclock = getWallclockMs(),
        };
    }

    pub fn sanitize(value: *const AccountsHashes) !void {
        try sanitizeWallclock(value.wallclock);
        for (value.hashes) |*snapshot_hash| {
            if (snapshot_hash.slot >= MAX_SLOT) {
                return error.ValueOutOfBounds;
            }
        }
    }
};

pub const EpochSlots = struct {
    from: Pubkey,
    slots: []CompressedSlots,
    wallclock: u64,

    pub fn clone(self: *const EpochSlots, allocator: std.mem.Allocator) error{OutOfMemory}!EpochSlots {
        const slots = try allocator.alloc(CompressedSlots, self.slots.len);
        for (slots, 0..) |*slot, i| slot.* = try self.slots[i].clone(allocator);
        return .{
            .from = self.from,
            .slots = slots,
            .wallclock = self.wallclock,
        };
    }

    pub fn deinit(self: *EpochSlots, allocator: std.mem.Allocator) void {
        for (self.slots) |*slot| slot.deinit(allocator);
        allocator.free(self.slots);
    }

    pub fn random(rng: std.rand.Random) EpochSlots {
        var slice: [0]CompressedSlots = .{};
        return EpochSlots{
            .from = Pubkey.random(rng),
            .slots = &slice,
            .wallclock = getWallclockMs(),
        };
    }

    pub fn sanitize(value: *const EpochSlots) !void {
        try sanitizeWallclock(value.wallclock);
        for (value.slots) |slot| {
            try slot.sanitize();
        }
    }
};

pub const CompressedSlots = union(enum(u32)) {
    Flate2: Flate2,
    Uncompressed: Uncompressed,

    pub fn clone(self: *const CompressedSlots, allocator: std.mem.Allocator) error{OutOfMemory}!CompressedSlots {
        return switch (self.*) {
            .Flate2 => |*v| .{ .Flate2 = try v.clone(allocator) },
            .Uncompressed => |*v| .{ .Uncompressed = try v.clone(allocator) },
        };
    }

    pub fn deinit(self: *CompressedSlots, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .Flate2 => |*v| v.deinit(allocator),
            .Uncompressed => |*v| v.deinit(allocator),
        }
    }

    pub fn sanitize(self: *const CompressedSlots) !void {
        switch (self.*) {
            .Flate2 => |*v| try v.sanitize(),
            .Uncompressed => |*v| try v.sanitize(),
        }
    }
};

pub const Flate2 = struct {
    first_slot: Slot,
    num: usize,
    compressed: []u8,

    pub fn clone(self: *const Flate2, allocator: std.mem.Allocator) error{OutOfMemory}!Flate2 {
        return .{
            .first_slot = self.first_slot,
            .num = self.num,
            .compressed = try allocator.dupe(u8, self.compressed),
        };
    }

    pub fn deinit(self: *Flate2, allocator: std.mem.Allocator) void {
        allocator.free(self.compressed);
    }

    pub fn sanitize(self: *const Flate2) !void {
        if (self.first_slot >= MAX_SLOT) {
            return error.ValueOutOfBounds;
        }
        if (self.num >= MAX_SLOT_PER_ENTRY) {
            return error.ValueOutOfBounds;
        }
    }
};

pub const Uncompressed = struct {
    first_slot: Slot,
    num: usize,
    slots: BitVec(u8),

    pub fn clone(self: *const Uncompressed, allocator: std.mem.Allocator) error{OutOfMemory}!Uncompressed {
        return .{
            .first_slot = self.first_slot,
            .num = self.num,
            .slots = try self.slots.clone(allocator),
        };
    }

    pub fn deinit(self: *Uncompressed, allocator: std.mem.Allocator) void {
        self.slots.deinit(allocator);
    }

    pub fn sanitize(self: *const Uncompressed) !void {
        if (self.first_slot >= MAX_SLOT) {
            return error.ValueOutOfBounds;
        }
        if (self.num >= MAX_SLOT_PER_ENTRY) {
            return error.ValueOutOfBounds;
        }
        if (self.slots.len % 8 != 0) {
            return error.InvalidValue;
        }
        // TODO: check BitVec.capacity()
    }
};

// TODO: replace logic with another library
pub fn BitVec(comptime T: type) type {
    return struct {
        bits: ?[]T,
        len: usize,

        pub fn clone(self: *const BitVec(T), allocator: std.mem.Allocator) error{OutOfMemory}!BitVec(T) {
            return .{
                .bits = if (self.bits == null) null else try allocator.dupe(T, self.bits.?),
                .len = self.len,
            };
        }

        pub fn deinit(self: *BitVec(T), allocator: std.mem.Allocator) void {
            allocator.free(self.bits.?);
        }
    };
}

pub const LegacyVersion = struct {
    from: Pubkey,
    wallclock: u64,
    version: LegacyVersion1,

    pub fn random(rng: std.rand.Random) LegacyVersion {
        return LegacyVersion{
            .from = Pubkey.random(rng),
            .wallclock = getWallclockMs(),
            .version = LegacyVersion1.random(rng),
        };
    }
};

pub const LegacyVersion1 = struct {
    major: u16,
    minor: u16,
    patch: u16,
    commit: ?u32, // first 4 bytes of the sha1 commit hash

    pub fn random(rng: std.rand.Random) LegacyVersion1 {
        return LegacyVersion1{
            .major = rng.int(u16),
            .minor = rng.int(u16),
            .patch = rng.int(u16),
            .commit = rng.int(u32),
        };
    }
};

pub const Version = struct {
    from: Pubkey,
    wallclock: u64,
    version: LegacyVersion2,

    const Self = @This();

    pub fn init(from: Pubkey, wallclock: u64, version: LegacyVersion2) Self {
        return Self{
            .from = from,
            .wallclock = wallclock,
            .version = version,
        };
    }

    pub fn default(from: Pubkey) Self {
        return Self{
            .from = from,
            .wallclock = getWallclockMs(),
            .version = LegacyVersion2.CURRENT,
        };
    }

    pub fn random(rng: std.rand.Random) Version {
        return Version{
            .from = Pubkey.random(rng),
            .wallclock = getWallclockMs(),
            .version = LegacyVersion2.random(rng),
        };
    }

    pub fn sanitize(self: *const Self) !void {
        try sanitizeWallclock(self.wallclock);
    }
};

pub const LegacyVersion2 = struct {
    major: u16,
    minor: u16,
    patch: u16,
    commit: ?u32, // first 4 bytes of the sha1 commit hash
    feature_set: u32, // first 4 bytes of the FeatureSet identifier

    const Self = @This();

    pub const CURRENT = LegacyVersion2.init(1, 14, 17, 2996451279, 3488713414);

    pub fn random(rng: std.rand.Random) Self {
        return Self{
            .major = rng.int(u16),
            .minor = rng.int(u16),
            .patch = rng.int(u16),
            .commit = rng.int(u32),
            .feature_set = rng.int(u32),
        };
    }

    pub fn init(major: u16, minor: u16, patch: u16, commit: ?u32, feature_set: u32) Self {
        return Self{
            .major = major,
            .minor = minor,
            .patch = patch,
            .commit = commit,
            .feature_set = feature_set,
        };
    }
};

pub const NodeInstance = struct {
    from: Pubkey,
    wallclock: u64,
    timestamp: u64, // Timestamp when the instance was created.
    token: u64, // Randomly generated value at node instantiation.

    const Self = @This();

    pub fn random(rng: std.rand.Random) Self {
        return Self{
            .from = Pubkey.random(rng),
            .wallclock = getWallclockMs(),
            .timestamp = rng.int(u64),
            .token = rng.int(u64),
        };
    }

    pub fn init(rand: std.Random, from: Pubkey, wallclock: u64) Self {
        return Self{
            .from = from,
            .wallclock = wallclock,
            .timestamp = @intCast(std.time.microTimestamp()),
            .token = rand.int(u64),
        };
    }

    pub fn withWallclock(self: *Self, wallclock: u64) Self {
        return Self{
            .from = self.from,
            .wallclock = wallclock,
            .timestamp = self.timestamp,
            .token = self.token,
        };
    }

    pub fn sanitize(self: *const Self) !void {
        try sanitizeWallclock(self.wallclock);
    }
};

fn ShredTypeConfig() bincode.FieldConfig(ShredType) {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            try bincode.write(writer, @intFromEnum(data), params);
            return;
        }
    };

    return bincode.FieldConfig(ShredType){
        .serializer = S.serialize,
    };
}

pub const ShredType = enum(u8) {
    Data = 0b1010_0101,
    Code = 0b0101_1010,

    pub const BincodeSize = u8;

    /// Enables bincode serializer to serialize this data into a single byte instead of 4.
    pub const @"!bincode-config" = ShredTypeConfig();
};

pub const DuplicateShred = struct {
    from: Pubkey,
    wallclock: u64,
    slot: Slot,
    shred_index: u32,
    shred_type: ShredType,
    // Serialized DuplicateSlotProof split into chunks.
    num_chunks: u8,
    chunk_index: u8,
    chunk: []u8,

    pub fn clone(self: *const DuplicateShred, allocator: std.mem.Allocator) error{OutOfMemory}!DuplicateShred {
        return .{
            .from = self.from,
            .wallclock = self.wallclock,
            .slot = self.slot,
            .shred_index = self.shred_index,
            .shred_type = self.shred_type,
            .num_chunks = self.num_chunks,
            .chunk_index = self.chunk_index,
            .chunk = try allocator.dupe(u8, self.chunk),
        };
    }

    pub fn deinit(self: *DuplicateShred, allocator: std.mem.Allocator) void {
        allocator.free(self.chunk);
    }

    pub fn random(rng: std.rand.Random) DuplicateShred {
        // NOTE: cant pass around a slice here (since the stack data will get cleared)
        var slice = [0]u8{}; // empty slice
        const num_chunks = rng.intRangeAtMost(u8, 5, 100);
        const chunk_index = rng.intRangeAtMost(u8, 0, num_chunks - 1);

        return DuplicateShred{
            .from = Pubkey.random(rng),
            .wallclock = getWallclockMs(),
            .slot = rng.int(u64),
            .shred_index = rng.int(u32),
            .shred_type = ShredType.Data,
            .num_chunks = num_chunks,
            .chunk_index = chunk_index,
            .chunk = &slice,
        };
    }

    pub fn sanitize(value: *const DuplicateShred) !void {
        try sanitizeWallclock(value.wallclock);
        if (value.chunk_index >= value.num_chunks) {
            return error.ValueOutOfBounds;
        }
    }
};

pub const SnapshotHashes = struct {
    from: Pubkey,
    full: SlotAndHash,
    incremental: []SlotAndHash,
    wallclock: u64,

    pub fn clone(self: *const SnapshotHashes, allocator: std.mem.Allocator) error{OutOfMemory}!SnapshotHashes {
        return .{
            .from = self.from,
            .full = self.full,
            .incremental = try allocator.dupe(SlotAndHash, self.incremental),
            .wallclock = self.wallclock,
        };
    }

    pub fn deinit(self: *SnapshotHashes, allocator: std.mem.Allocator) void {
        allocator.free(self.incremental);
    }

    pub fn random(rng: std.rand.Random) SnapshotHashes {
        var slice: [0]SlotAndHash = .{};
        return SnapshotHashes{
            .from = Pubkey.random(rng),
            .full = .{ .slot = rng.int(u64), .hash = Hash.random(rng) },
            .incremental = &slice,
            .wallclock = getWallclockMs(),
        };
    }

    pub fn sanitize(self: *const @This()) !void {
        try sanitizeWallclock(self.wallclock);
        if (self.full.slot >= MAX_SLOT) {
            return error.ValueOutOfBounds;
        }
        for (self.incremental) |inc| {
            if (inc.slot >= MAX_SLOT) {
                return error.ValueOutOfBounds;
            }
            if (self.full.slot >= inc.slot) {
                return error.InvalidValue;
            }
        }
    }
};

pub const SocketTag = enum(u8) {
    gossip = 0,
    repair = 1,
    rpc = 2,
    rpc_pubsub = 3,
    serve_repair = 4,
    tpu = 5,
    tpu_forwards = 6,
    tpu_forwards_quic = 7,
    tpu_quic = 8,
    tpu_vote = 9,
    /// Analogous to [SOCKET_TAG_TVU](https://github.com/anza-xyz/agave/blob/0d34a1a160129c4293dac248e14231e9e773b4ce/gossip/src/contact_info.rs#L36)
    turbine_recv = 10,
    /// Analogous to [SOCKET_TAG_TVU_QUIC](https://github.com/anza-xyz/agave/blob/0d34a1a160129c4293dac248e14231e9e773b4ce/gossip/src/contact_info.rs#L37)
    turbine_recv_quic = 11,
    _,

    pub const BincodeSize = u8;
};
pub const SOCKET_CACHE_SIZE: usize = @intFromEnum(SocketTag.turbine_recv_quic) + 1;

pub const ContactInfo = struct {
    pubkey: Pubkey,
    wallclock: u64,
    outset: u64,
    shred_version: u16,
    version: ClientVersion,
    addrs: ArrayList(IpAddr),
    sockets: ArrayList(SocketEntry),
    extensions: ArrayList(Extension),
    cache: [SOCKET_CACHE_SIZE]SocketAddr = socket_addrs_unspecified(),

    // TODO: improve implementation of post deserialise method
    pub const @"!bincode-config:post-deserialize" = bincode.FieldConfig(ContactInfo){ .post_deserialize_fn = ContactInfo.buildCache };
    pub const @"!bincode-config:cache" = bincode.FieldConfig([SOCKET_CACHE_SIZE]SocketAddr){ .skip = true };
    pub const @"!bincode-config:addrs" = ShortVecArrayListConfig(IpAddr);
    pub const @"!bincode-config:sockets" = ShortVecArrayListConfig(SocketEntry);
    pub const @"!bincode-config:extensions" = ShortVecArrayListConfig(Extension);
    pub const @"!bincode-config:wallclock" = var_int_config_u64;

    const Self = @This();

    pub fn buildCache(self: *Self) void {
        var port: u16 = 0;
        for (self.sockets.items) |socket_entry| {
            port += socket_entry.offset;
            const addr = self.addrs.items[socket_entry.index];
            const socket = switch (addr) {
                .ipv4 => SocketAddr.initIpv4(addr.asV4(), port),
                .ipv6 => SocketAddr.initIpv6(addr.asV6(), port),
            };
            socket.sanitize() catch continue;
            self.cache[@intFromEnum(socket_entry.key)] = socket;
        }
    }

    pub fn toNodeInstance(self: *Self, rand: std.Random) NodeInstance {
        return NodeInstance.init(rand, self.pubkey, @intCast(std.time.milliTimestamp()));
    }

    pub fn deinit(self: Self) void {
        self.addrs.deinit();
        self.sockets.deinit();
        self.extensions.deinit();
    }

    pub fn initSpy(allocator: std.mem.Allocator, id: Pubkey, gossip_socket_addr: SocketAddr, shred_version: u16) !Self {
        var contact_info = Self.init(allocator, id, @intCast(std.time.microTimestamp()), shred_version);
        try contact_info.setSocket(.gossip, gossip_socket_addr);
        return contact_info;
    }

    pub fn init(
        allocator: std.mem.Allocator,
        pubkey: Pubkey,
        wallclock: u64,
        shred_version: u16,
    ) Self {
        const outset = @as(u64, @intCast(std.time.microTimestamp()));
        return Self{
            .pubkey = pubkey,
            .wallclock = wallclock,
            .outset = outset,
            .shred_version = shred_version,
            .version = ClientVersion.default(),
            .addrs = ArrayList(IpAddr).init(allocator),
            .sockets = ArrayList(SocketEntry).init(allocator),
            .extensions = ArrayList(void).init(allocator),
            .cache = socket_addrs_unspecified(),
        };
    }

    pub fn initDummyForTest(
        allocator: std.mem.Allocator,
        pubkey: Pubkey,
        wallclock: u64,
        outset: u64,
        shred_version: u16,
    ) ContactInfo {
        var addrs = ArrayList(IpAddr).initCapacity(allocator, 4) catch unreachable;
        var sockets = ArrayList(SocketEntry).initCapacity(allocator, 6) catch unreachable;

        for (0..4) |_| {
            addrs.append(IpAddr.newIpv4(127, 0, 0, 1)) catch unreachable;
        }

        for (0..6) |_| {
            sockets.append(.{ .key = .turbine_recv, .index = 20, .offset = 30 }) catch unreachable;
        }

        return ContactInfo{
            .pubkey = pubkey,
            .wallclock = wallclock,
            .outset = outset,
            .shred_version = shred_version,
            .version = ClientVersion.new(1, 2, 3, 4, 5, 6),
            .addrs = addrs,
            .sockets = sockets,
            .extensions = ArrayList(Extension).init(allocator),
        };
    }

    pub fn sanitize(self: *const Self) !void {
        try sanitizeWallclock(self.wallclock);
    }

    pub fn getSocket(self: *const Self, key: SocketTag) ?SocketAddr {
        const socket = &self.cache[@intFromEnum(key)];
        if (socket.eql(&SocketAddr.UNSPECIFIED)) {
            return null;
        }
        return socket.*;
    }

    pub fn setSocket(self: *Self, key: SocketTag, socket_addr: SocketAddr) !void {
        self.removeSocket(key);

        const offset: u16, const index: ?usize = blk: {
            var offset = socket_addr.port();
            const index = for (self.sockets.items, 0..) |socket, idx| {
                offset = std.math.sub(u16, offset, socket.offset) catch break idx;
            } else null;
            break :blk .{ offset, index };
        };

        const entry: SocketEntry = .{
            .key = key,
            .index = try self.pushAddr(socket_addr.ip()),
            .offset = offset,
        };

        if (index) |i| {
            self.sockets.items[i].offset -= entry.offset;
            try self.sockets.insert(i, entry);
        } else {
            try self.sockets.append(entry);
        }

        self.cache[@intFromEnum(key)] = socket_addr;
    }

    pub fn removeSocket(self: *Self, key: SocketTag) void {
        // find existing socket index
        const existing_socket_index = for (self.sockets.items, 0..) |socket, idx| {
            if (socket.key == key) break idx;
        } else null;
        // if found, remove it, it's associated IpAddr, set cache[key] to unspecified
        if (existing_socket_index) |index| {
            // first we remove this existing socket
            const removed_entry = self.sockets.orderedRemove(index);
            // reset the socket entry offset
            if (index < self.sockets.items.len - 1) {
                var next_entry = self.sockets.items[index];
                next_entry.offset += removed_entry.offset;
            }
            self.removeAddrIfUnused(removed_entry.index);
            self.cache[@intFromEnum(key)] = SocketAddr.unspecified();
        }
    }

    // Add IpAddr if it doesn't already exist otherwise return index
    fn pushAddr(self: *Self, ip_addr: IpAddr) !u8 {
        for (self.addrs.items, 0..) |addr, index| {
            if (addr.eql(&ip_addr)) {
                return std.math.cast(u8, index) orelse return error.IpAddrsSaturated;
            }
        }
        try self.addrs.append(ip_addr);
        return std.math.cast(u8, self.addrs.items.len - 1) orelse return error.IpAddrsSaturated;
    }

    pub fn removeAddrIfUnused(self: *Self, index: usize) void {
        for (self.sockets.items) |socket| {
            if (socket.index == index) {
                // exit because there's an existing socket entry that refs that addr index
                return;
            }
        }
        _ = self.addrs.orderedRemove(index);
        // now we reorder indexes in socket entries that are greater than this index
        for (self.sockets.items) |*socket| {
            if (socket.index > index) {
                socket.index -= 1;
            }
        }
    }

    pub fn clone(self: *const Self) error{OutOfMemory}!Self {
        return .{
            .pubkey = self.pubkey,
            .wallclock = self.wallclock,
            .outset = self.outset,
            .shred_version = self.shred_version,
            .version = self.version,
            .addrs = try self.addrs.clone(),
            .sockets = try self.sockets.clone(),
            .extensions = try self.extensions.clone(),
            .cache = self.cache,
        };
    }
};

/// This exists to provide a version of ContactInfo which can safely cross gossip table lock
/// boundaries without exposing unsafe pointers. For now it contains only the fields
/// required to satisfy existing usage, it can be extended in the future if required.
pub const ThreadSafeContactInfo = struct {
    pubkey: Pubkey,
    shred_version: u16,
    gossip_addr: ?SocketAddr,
    rpc_addr: ?SocketAddr,

    pub fn fromContactInfo(contact_info: ContactInfo) ThreadSafeContactInfo {
        return .{
            .pubkey = contact_info.pubkey,
            .shred_version = contact_info.shred_version,
            .gossip_addr = contact_info.getSocket(.gossip),
            .rpc_addr = contact_info.getSocket(.rpc),
        };
    }

    pub fn fromLegacyContactInfo(legacy_contact_info: LegacyContactInfo) ThreadSafeContactInfo {
        return .{
            .pubkey = legacy_contact_info.id,
            .shred_version = legacy_contact_info.shred_version,
            .gossip_addr = legacy_contact_info.gossip,
            .rpc_addr = legacy_contact_info.rpc,
        };
    }
};

/// This exists for future proofing to allow easier additions to ContactInfo.
/// Currently, ContactInfo has no extensions.
/// This may be changed in the future to a union or enum as extensions are added.
const Extension = void;

const NodePort = union(enum) {
    gossip: network.EndPoint,
    repair: network.EndPoint,
    rpc: network.EndPoint,
    rpc_pubsub: network.EndPoint,
    serve_repair: network.EndPoint,
    tpu: network.EndPoint,
    tpu_forwards: network.EndPoint,
    tpu_forwards_quic: network.EndPoint,
    tpu_quic: network.EndPoint,
    tpu_vote: network.EndPoint,
    turbine_recv: network.EndPoint,
    turbine_recv_quic: network.EndPoint,
};

const Sockets = struct {
    gossip: UdpSocket,
    ip_echo: ?TcpListener,
    turbine_recv: ArrayList(UdpSocket),
    turbine_recv_quic: ArrayList(UdpSocket),
    tpu: ArrayList(UdpSocket),
    tpu_forwards: ArrayList(UdpSocket),
    tpu_vote: ArrayList(UdpSocket),
    broadcast: ArrayList(UdpSocket),
    repair: UdpSocket,
    retransmit_sockets: ArrayList(UdpSocket),
    serve_repair: UdpSocket,
    ancestor_hashes_requests: UdpSocket,
    tpu_quic: UdpSocket,
    tpu_forwards_quic: UdpSocket,
};

pub const SocketEntry = struct {
    /// GossipMessageIdentifier, e.g. turbine_recv, tpu, etc
    key: SocketTag,
    /// IpAddr index in the accompanying addrs vector.
    index: u8,
    /// Port offset with respect to the previous entry.
    offset: u16,

    const Self = @This();

    pub const @"!bincode-config:offset" = var_int_config_u16;

    pub fn eql(self: *const Self, other: *const Self) bool {
        return self.key == other.key and
            self.index == other.index and
            self.offset == other.offset;
    }
};

fn socket_addrs_unspecified() [SOCKET_CACHE_SIZE]SocketAddr {
    return .{SocketAddr.unspecified()} ** SOCKET_CACHE_SIZE;
}

pub const RestartHeaviestFork = struct {
    from: Pubkey,
    wallclock: u64,
    last_slot: Slot,
    last_slot_hash: Hash,
    observed_stake: u64,
    shred_version: u16,

    const Self = @This();

    pub fn sanitize(self: *const Self) !void {
        try sanitizeWallclock(self.wallclock);
    }
};

pub const RestartLastVotedForkSlots = struct {
    from: Pubkey,
    wallclock: u64,
    offsets: SlotsOffsets,
    last_voted_slot: Slot,
    last_voted_hash: Hash,
    shred_version: u16,

    const Self = @This();

    pub fn clone(self: *const Self, allocator: std.mem.Allocator) error{OutOfMemory}!Self {
        return .{
            .from = self.from,
            .wallclock = self.wallclock,
            .offsets = try self.offsets.clone(allocator),
            .last_voted_slot = self.last_voted_slot,
            .last_voted_hash = self.last_voted_hash,
            .shred_version = self.shred_version,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.offsets.deinit(allocator);
    }

    pub fn sanitize(self: *const Self) !void {
        try sanitizeWallclock(self.wallclock);
    }
};

pub const SlotsOffsets = union(enum(u32)) {
    RunLengthEncoding: std.ArrayList(u16),
    RawOffsets: RawOffsets,

    pub fn clone(self: *const SlotsOffsets, allocator: std.mem.Allocator) error{OutOfMemory}!SlotsOffsets {
        return switch (self.*) {
            .RunLengthEncoding => |*arr| .{ .RunLengthEncoding = try arr.clone() },
            .RawOffsets => |*bits| .{ .RawOffsets = try bits.clone(allocator) },
        };
    }

    pub fn deinit(self: *SlotsOffsets, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .RunLengthEncoding => |*arr| arr.deinit(),
            .RawOffsets => |*bits| bits.deinit(allocator),
        }
    }
};

// note: need another struct so bincode deserialization/serialization works
const RawOffsets = struct {
    bits: DynamicArrayBitSet(u8),
    pub const @"!bincode-config:bits" = BitVecConfig(u8);

    pub fn clone(self: *const RawOffsets, allocator: std.mem.Allocator) error{OutOfMemory}!RawOffsets {
        return .{
            .bits = try self.bits.clone(allocator),
        };
    }

    pub fn deinit(self: *RawOffsets, allocator: std.mem.Allocator) void {
        self.bits.deinit(allocator);
    }
};

test "gossip.data: new contact info" {
    const seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    var ci = ContactInfo.init(testing.allocator, Pubkey.random(rng), @as(u64, @intCast(std.time.microTimestamp())), 0);
    defer ci.deinit();
}

test "gossip.data: socketaddr bincode serialize matches rust" {
    const Tmp = struct {
        addr: SocketAddr,
    };
    const tmp = Tmp{ .addr = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 1234) };
    var buf = [_]u8{0} ** 1024;
    const bytes = try bincode.writeToSlice(buf[0..], tmp, bincode.Params.standard);

    // #[derive(Serialize, Debug, Clone, Copy)]
    // pub struct Tmp {
    //     addr: SocketAddr
    // }
    // let tmp = Tmp { addr: socketaddr!(Ipv4Addr::LOCALHOST, 1234) };
    // println!("{:?}", bincode::serialize(&tmp).unwrap());

    // Enum discriminants are encoded as u32 (4 leading zeros)
    const rust_bytes = [_]u8{ 0, 0, 0, 0, 127, 0, 0, 1, 210, 4 };
    try testing.expectEqualSlices(u8, rust_bytes[0..rust_bytes.len], bytes);
}

test "gossip.data: set & get socket on contact info" {
    const seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    var ci = ContactInfo.init(testing.allocator, Pubkey.random(rng), @as(u64, @intCast(std.time.microTimestamp())), 0);
    defer ci.deinit();
    try ci.setSocket(.rpc, SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8899));

    var set_socket = ci.getSocket(.rpc);
    try testing.expect(set_socket.?.eql(&SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8899)));
    try testing.expect(ci.addrs.items[0].eql(&IpAddr.newIpv4(127, 0, 0, 1)));
    try testing.expect(ci.sockets.items[0].eql(&.{ .key = .rpc, .index = 0, .offset = 8899 }));
}

test "gossip.data: contact info bincode serialize matches rust bincode" {
    // ContactInfo generated using rust ConfigInfo::new_rand(..., ...); and printed in debug format
    // ContactInfo serialized using rust bincode
    //
    // ContactInfo {
    //     pubkey: 4NftWecdfGcYZMJahnAAX5Cw1PLGLZhYFB19wL6AkXqW,
    //     wallclock: 1721060646885,
    //     outset: 1721060141617172,
    //     shred_version: 0,
    //     version: 2.1.0 (src:00000000; feat:12366211, client:Agave),
    //     addrs: [127.0.0.1],
    //     sockets: [
    //         SocketEntry { key: 10, index: 0, offset: 8001 },
    //         SocketEntry { key: 11, index: 0, offset: 1 },
    //         SocketEntry { key: 5, index: 0, offset: 1 },
    //         SocketEntry { key: 6, index: 0, offset: 1 },
    //         SocketEntry { key: 9, index: 0, offset: 1 },
    //         SocketEntry { key: 1, index: 0, offset: 1 },
    //         SocketEntry { key: 4, index: 0, offset: 2 },
    //         SocketEntry { key: 8, index: 0, offset: 1 },
    //         SocketEntry { key: 7, index: 0, offset: 1 },
    //         SocketEntry { key: 2, index: 0, offset: 889 },
    //         SocketEntry { key: 3, index: 0, offset: 1 },
    //         SocketEntry { key: 0, index: 0, offset: 11780 }
    //     ],
    //     extensions: [],
    //     cache: [
    //         127.0.0.1:20680,
    //         127.0.0.1:8006,
    //         127.0.0.1:8899,
    //         127.0.0.1:8900,
    //         127.0.0.1:8008,
    //         127.0.0.1:8003,
    //         127.0.0.1:8004,
    //         127.0.0.1:8010,
    //         127.0.0.1:8009,
    //         127.0.0.1:8005,
    //         127.0.0.1:8001,
    //         127.0.0.1:8002
    //     ]
    // }

    const rust_contact_info_serialized_bytes = [_]u8{
        50,  32,  58,  140, 212, 209, 174, 133, 183, 143, 242, 155,
        13,  127, 185, 10,  117, 50,  199, 209, 255, 166, 74,  36,
        67,  97,  239, 155, 203, 202, 153, 93,  229, 191, 213, 185,
        139, 50,  20,  208, 96,  138, 75,  29,  6,   0,   0,   0,
        2,   1,   0,   0,   0,   0,   0,   131, 177, 188, 0,   3,
        1,   0,   0,   0,   0,   127, 0,   0,   1,   12,  10,  0,
        193, 62,  11,  0,   1,   5,   0,   1,   6,   0,   1,   9,
        0,   1,   1,   0,   1,   4,   0,   2,   8,   0,   1,   7,
        0,   1,   2,   0,   249, 6,   3,   0,   1,   0,   0,   132,
        92,  0,
    };

    const rust_contact_info_cache = [_]SocketAddr{
        SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 20680),
        SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8006),
        SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8899),
        SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8900),
        SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8008),
        SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8003),
        SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8004),
        SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8010),
        SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8009),
        SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8005),
        SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8001),
        SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8002),
    };

    // Build identical Sig contact info
    var sig_contact_info = ContactInfo{
        .pubkey = Pubkey.fromString("4NftWecdfGcYZMJahnAAX5Cw1PLGLZhYFB19wL6AkXqW") catch unreachable,
        .wallclock = 1721060646885,
        .outset = 1721060141617172,
        .shred_version = 0,
        .version = ClientVersion.new(2, 1, 0, 0, 12366211, 3),
        .addrs = ArrayList(IpAddr).init(testing.allocator),
        .sockets = ArrayList(SocketEntry).init(testing.allocator),
        .extensions = ArrayList(Extension).init(testing.allocator),
    };
    defer sig_contact_info.deinit();
    sig_contact_info.addrs.append(IpAddr.newIpv4(127, 0, 0, 1)) catch unreachable;
    sig_contact_info.sockets.append(.{ .key = .turbine_recv, .index = 0, .offset = 8001 }) catch unreachable;
    sig_contact_info.sockets.append(.{ .key = .turbine_recv_quic, .index = 0, .offset = 1 }) catch unreachable;
    sig_contact_info.sockets.append(.{ .key = .tpu, .index = 0, .offset = 1 }) catch unreachable;
    sig_contact_info.sockets.append(.{ .key = .tpu_forwards, .index = 0, .offset = 1 }) catch unreachable;
    sig_contact_info.sockets.append(.{ .key = .tpu_vote, .index = 0, .offset = 1 }) catch unreachable;
    sig_contact_info.sockets.append(.{ .key = .repair, .index = 0, .offset = 1 }) catch unreachable;
    sig_contact_info.sockets.append(.{ .key = .serve_repair, .index = 0, .offset = 2 }) catch unreachable;
    sig_contact_info.sockets.append(.{ .key = .tpu_quic, .index = 0, .offset = 1 }) catch unreachable;
    sig_contact_info.sockets.append(.{ .key = .tpu_forwards_quic, .index = 0, .offset = 1 }) catch unreachable;
    sig_contact_info.sockets.append(.{ .key = .rpc, .index = 0, .offset = 889 }) catch unreachable;
    sig_contact_info.sockets.append(.{ .key = .rpc_pubsub, .index = 0, .offset = 1 }) catch unreachable;
    sig_contact_info.sockets.append(.{ .key = .gossip, .index = 0, .offset = 11780 }) catch unreachable;
    sig_contact_info.buildCache();

    // Check that the cache is built correctly
    for (0.., sig_contact_info.cache) |i, socket| {
        try testing.expect(socket.eql(&rust_contact_info_cache[i]));
        break;
    }

    // Check that the serialized bytes match the rust serialized bytes
    var buf = std.ArrayList(u8).init(testing.allocator);
    bincode.write(buf.writer(), sig_contact_info, bincode.Params.standard) catch unreachable;
    defer buf.deinit();
    try testing.expect(std.mem.eql(u8, &rust_contact_info_serialized_bytes, buf.items));

    // Check that the deserialized contact info matches the original
    var stream = std.io.fixedBufferStream(buf.items);
    var sig_contact_info_deserialised = try bincode.read(testing.allocator, ContactInfo, stream.reader(), bincode.Params.standard);
    defer sig_contact_info_deserialised.deinit();
    try testing.expect(sig_contact_info_deserialised.addrs.items.len == 1);
    try testing.expect(sig_contact_info_deserialised.sockets.items.len == 12);
    try testing.expect(sig_contact_info_deserialised.pubkey.equals(&sig_contact_info.pubkey));
    try testing.expect(sig_contact_info_deserialised.outset == sig_contact_info.outset);
}

test "gossip.data: ContactInfo bincode roundtrip maintains data integrity" {
    var contact_info_bytes_from_mainnet = [109]u8{
        168, 36,  147, 159, 43,  110, 51,  177, 21,  191, 96,  206,
        25,  12,  133, 238, 147, 223, 2,   133, 105, 29,  83,  234,
        44,  111, 123, 246, 244, 15,  167, 219, 185, 175, 235, 255,
        204, 49,  220, 224, 176, 3,   13,  13,  6,   0,   242, 150,
        1,   17,  9,   0,   0,   0,   0,   22,  194, 36,  85,  0,
        1,   0,   0,   0,   0,   34,  221, 220, 125, 12,  0,   0,
        192, 62,  10,  0,   1,   11,  0,   1,   5,   0,   1,   6,
        0,   1,   9,   0,   1,   4,   0,   3,   8,   0,   1,   7,
        0,   1,   1,   0,   1,   2,   0,   248, 6,   3,   0,   1,
        0,
    };

    var stream = std.io.fixedBufferStream(&contact_info_bytes_from_mainnet);
    const ci2 = try bincode.read(testing.allocator, ContactInfo, stream.reader(), bincode.Params.standard);
    defer ci2.deinit();

    var buf = std.ArrayList(u8).init(testing.allocator);
    bincode.write(buf.writer(), ci2, bincode.Params.standard) catch unreachable;
    defer buf.deinit();

    try testing.expect(std.mem.eql(u8, buf.items, &contact_info_bytes_from_mainnet));
}

test "gossip.data: SocketEntry serializer works" {
    testing.log_level = .debug;

    comptime std.debug.assert(@intFromEnum(SocketTag.rpc_pubsub) == 3);
    const se: SocketEntry = .{ .key = .rpc_pubsub, .index = 3, .offset = 30304 };

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try bincode.write(buf.writer(), se, bincode.Params.standard);

    var stream = std.io.fixedBufferStream(buf.items);
    const other_se = try bincode.read(testing.allocator, SocketEntry, stream.reader(), bincode.Params.standard);

    try testing.expect(other_se.index == se.index);
    try testing.expect(other_se.key == se.key);
    try testing.expect(other_se.offset == se.offset);
}

test "gossip.data: test sig verify duplicateShreds" {
    var keypair = try KeyPair.create([_]u8{1} ** 32);
    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
    var rng = std.rand.DefaultPrng.init(0);
    var data = DuplicateShred.random(rng.random());
    data.from = pubkey;

    var value = try SignedGossipData.initSigned(GossipData{ .DuplicateShred = .{ 0, data } }, &keypair);

    try std.testing.expect(try value.verify(pubkey));
}

test "gossip.data: test sanitize GossipData" {
    var rng = std.rand.DefaultPrng.init(0);
    const rand = rng.random();

    for (0..4) |i| {
        const data = GossipData.randomFromIndex(rand, i);
        data.sanitize() catch {};
    }
}

test "gossip.data: test SignedGossipData label() and id() methods" {
    const kp_bytes = [_]u8{1} ** 32;
    var kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    var id = Pubkey.fromPublicKey(&pk);

    var legacy_contact_info = LegacyContactInfo.default(id);
    legacy_contact_info.wallclock = 0;

    var value = try SignedGossipData.initSigned(GossipData{
        .LegacyContactInfo = legacy_contact_info,
    }, &kp);

    try std.testing.expect(value.id().equals(&id));
    try std.testing.expect(value.label().LegacyContactInfo.equals(&id));
}

test "gossip.data: pubkey matches rust" {
    const kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    const id = Pubkey.fromPublicKey(&pk);

    const rust_bytes = [_]u8{
        138, 136, 227, 221, 116, 9,   241, 149, 253, 82,  219, 45, 60,  186, 93,  114,
        202, 103, 9,   191, 29,  148, 18,  27,  243, 116, 136, 1,  180, 15,  111, 92,
    };
    var buf = [_]u8{0} ** 1024;
    var bytes = try bincode.writeToSlice(buf[0..], id, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, rust_bytes[0..], bytes[0..bytes.len]);

    const out = try bincode.readFromSlice(std.testing.allocator, Pubkey, buf[0..], bincode.Params.standard);
    try std.testing.expectEqual(id, out);
}

test "gossip.data: contact info serialization matches rust" {
    const kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    const id = Pubkey.fromPublicKey(&pk);

    const gossip_addr = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 1234);

    var buf = [_]u8{0} ** 1024;

    var legacy_contact_info = LegacyContactInfo.default(id);
    legacy_contact_info.gossip = gossip_addr;
    legacy_contact_info.id = id;
    legacy_contact_info.wallclock = 0;

    var contact_info_rust = [_]u8{
        138, 136, 227, 221, 116, 9,   241, 149, 253, 82,  219, 45, 60,  186, 93,  114,
        202, 103, 9,   191, 29,  148, 18,  27,  243, 116, 136, 1,  180, 15,  111, 92,
        0,   0,   0,   0,   127, 0,   0,   1,   210, 4,   0,   0,  0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  0,   0,
    };
    var bytes = try bincode.writeToSlice(buf[0..], legacy_contact_info, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, bytes[0..bytes.len], &contact_info_rust);
}

test "gossip.data: test RestartHeaviestFork serialization matches rust" {
    var rust_bytes = [_]u8{ 82, 182, 93, 119, 193, 123, 4, 235, 68, 64, 82, 233, 51, 34, 232, 123, 245, 237, 236, 142, 251, 1, 123, 124, 26, 40, 219, 84, 165, 116, 208, 63, 19, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 20, 0 };

    const x = RestartHeaviestFork{
        .from = try Pubkey.fromString("6ZsiX6YcwEa93yWtVwGRiK8Ceoxq2VieVh2pvEiUtpCW"),
        .wallclock = 19,
        .last_slot = 12,
        .observed_stake = 11,
        .shred_version = 20,
        .last_slot_hash = Hash.default(),
    };

    var buf = [_]u8{0} ** 1024;
    var bytes = try bincode.writeToSlice(&buf, x, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, bytes[0..bytes.len], rust_bytes[0..bytes.len]);
}

test "gossip.data: test RestartLastVotedForkSlots serialization matches rust" {
    var rust_bytes = [_]u8{ 82, 182, 93, 119, 193, 123, 4, 235, 68, 64, 82, 233, 51, 34, 232, 123, 245, 237, 236, 142, 251, 1, 123, 124, 26, 40, 219, 84, 165, 116, 208, 63, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 16, 0, 0, 0, 0, 0, 0, 0, 255, 255, 239, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    var x = try DynamicArrayBitSet(u8).initFull(std.testing.allocator, 128);
    defer x.deinit(std.testing.allocator);
    x.setValue(20, false);
    x.setValue(40, false);

    const offsets = SlotsOffsets{
        .RawOffsets = .{ .bits = x },
    };

    const data = RestartLastVotedForkSlots{
        .from = try Pubkey.fromString("6ZsiX6YcwEa93yWtVwGRiK8Ceoxq2VieVh2pvEiUtpCW"),
        .wallclock = 0,
        .last_voted_slot = 0,
        .last_voted_hash = Hash.default(),
        .shred_version = 0,
        .offsets = offsets,
    };

    var buf = [_]u8{0} ** 1024;
    var bytes = try bincode.writeToSlice(buf[0..], data, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, bytes[0..bytes.len], rust_bytes[0..bytes.len]);
}

test "gossip.data: gossip data serialization matches rust" {
    const kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    const id = Pubkey.fromPublicKey(&pk);

    const gossip_addr = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 1234);

    var legacy_contact_info = LegacyContactInfo.default(id);
    legacy_contact_info.gossip = gossip_addr;
    legacy_contact_info.wallclock = 0;

    const gossip_data = GossipData{
        .LegacyContactInfo = legacy_contact_info,
    };

    var buf = [_]u8{0} ** 1024;
    var rust_gossip_data = [_]u8{
        0,   0,  0,   0,   138, 136, 227, 221, 116, 9,  241, 149, 253, 82,  219, 45,  60,
        186, 93, 114, 202, 103, 9,   191, 29,  148, 18, 27,  243, 116, 136, 1,   180, 15,
        111, 92, 0,   0,   0,   0,   127, 0,   0,   1,  210, 4,   0,   0,   0,   0,   0,
        0,   0,  0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,   0,   0,   0,   0,
        0,   0,  0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,   0,   0,   0,   0,
        0,   0,  0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,   0,   0,   0,   0,
        0,   0,  0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,   0,   0,   0,   0,
        0,   0,  0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,   0,   0,   0,   0,
        0,   0,  0,   0,   0,   0,   0,   0,   0,   0,
    };
    var bytes = try bincode.writeToSlice(buf[0..], gossip_data, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, bytes[0..bytes.len], rust_gossip_data[0..bytes.len]);
}

test "gossip.data: random gossip data" {
    const seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    var buf: [1000]u8 = undefined;

    {
        const data = LegacyContactInfo.random(rng);
        const result = try bincode.writeToSlice(&buf, data, bincode.Params.standard);
        _ = result;
    }
    {
        const data = EpochSlots.random(rng);
        const result = try bincode.writeToSlice(&buf, data, bincode.Params.standard);
        _ = result;
    }
    {
        const data = Vote.random(rng);
        const result = try bincode.writeToSlice(&buf, data, bincode.Params.standard);
        _ = result;
    }
    {
        const data = DuplicateShred.random(rng);
        const result = try bincode.writeToSlice(&buf, data, bincode.Params.standard);
        _ = result;
    }
    {
        const data = GossipData.random(rng);
        const result = try bincode.writeToSlice(&buf, data, bincode.Params.standard);
        _ = result;
    }
}

test "gossip.data: LegacyContactInfo <-> ContactInfo roundtrip" {
    const seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    const start = LegacyContactInfo.random(rng);
    const ci = try start.toContactInfo(std.testing.allocator);
    defer ci.deinit();
    const end = LegacyContactInfo.fromContactInfo(&ci);

    try std.testing.expect(std.meta.eql(start, end));
}

test "gossip.data: sanitize valid ContactInfo works" {
    var rand = std.rand.DefaultPrng.init(871329);
    const rng = rand.random();
    const info = ContactInfo.initDummyForTest(std.testing.allocator, Pubkey.random(rng), 100, 123, 246);
    defer info.deinit();
    const data = GossipData{ .ContactInfo = info };
    try data.sanitize();
}

test "gossip.data: sanitize invalid ContactInfo has error" {
    var rand = std.rand.DefaultPrng.init(3414214);
    const rng = rand.random();
    const info = ContactInfo.initDummyForTest(std.testing.allocator, Pubkey.random(rng), 1_000_000_000_000_000, 123, 246);
    defer info.deinit();
    const data = GossipData{ .ContactInfo = info };
    if (data.sanitize()) |_| return error.ExpectedError else |_| {}
}

test "gossip.data: sanitize valid NodeInstance works" {
    var rand = std.rand.DefaultPrng.init(23523413);
    const rng = rand.random();
    const instance = NodeInstance.random(rng);
    const data = GossipData{ .NodeInstance = instance };
    try data.sanitize();
}

test "gossip.data: sanitize invalid NodeInstance has error" {
    var rand = std.rand.DefaultPrng.init(524145234);
    const rng = rand.random();
    var instance = NodeInstance.random(rng);
    instance.wallclock = 1_000_000_000_487_283;
    const data = GossipData{ .NodeInstance = instance };
    if (data.sanitize()) |_| return error.ExpectedError else |_| {}
}

test "gossip.data: sanitize valid SnapshotHashes works" {
    var rand = std.rand.DefaultPrng.init(23523413);
    const rng = rand.random();
    var instance = SnapshotHashes.random(rng);
    instance.full.slot = 1000;
    const data = GossipData{ .SnapshotHashes = instance };
    try data.sanitize();
}

test "gossip.data: sanitize invalid SnapshotHashes full slot has error" {
    var rand = std.rand.DefaultPrng.init(524145234);
    const rng = rand.random();
    var instance = SnapshotHashes.random(rng);
    instance.full.slot = 1_000_000_000_487_283;
    const data = GossipData{ .SnapshotHashes = instance };
    if (data.sanitize()) |_| return error.ExpectedError else |_| {}
}

test "gossip.data: sanitize invalid SnapshotHashes incremental slot has error" {
    var rand = std.rand.DefaultPrng.init(524145234);
    const rng = rand.random();
    var incremental: [1]SlotAndHash = .{.{ .slot = 1_000_000_000_487_283, .hash = Hash.default() }};
    var instance = SnapshotHashes.random(rng);
    instance.incremental = &incremental;
    const data = GossipData{ .SnapshotHashes = instance };
    if (data.sanitize()) |_| return error.ExpectedError else |_| {}
}

test "gossip.data: sanitize SnapshotHashes full > incremental has error" {
    var rand = std.rand.DefaultPrng.init(524145234);
    const rng = rand.random();
    var incremental: [1]SlotAndHash = .{.{ .slot = 1, .hash = Hash.default() }};
    var instance = SnapshotHashes.random(rng);
    instance.full.slot = 2;
    instance.incremental = &incremental;
    const data = GossipData{ .SnapshotHashes = instance };
    if (data.sanitize()) |_| return error.ExpectedError else |_| {}
}
