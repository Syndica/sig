const std = @import("std");
const sig = @import("../sig.zig");

const testing = std.testing;
const bincode = sig.bincode;

const ArrayList = std.ArrayList;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const SocketAddr = sig.net.SocketAddr;
const Hash = sig.core.Hash;
const Signature = sig.core.Signature;
const Transaction = sig.core.Transaction;
const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const IpAddr = sig.net.IpAddr;
const ClientVersion = sig.version.ClientVersion;
const DynamicArrayBitSet = sig.bloom.bit_set.DynamicArrayBitSet;
const SlotAndHash = sig.core.hash.SlotAndHash;

const assert = std.debug.assert;
const getWallclockMs = sig.time.getWallclockMs;
const BitVecConfig = sig.bloom.bit_vec.BitVecConfig;
const sanitizeWallclock = sig.gossip.message.sanitizeWallclock;

const PACKET_DATA_SIZE = sig.net.Packet.DATA_SIZE;

pub const MAX_EPOCH_SLOTS: u8 = 255;
pub const MAX_VOTES: u8 = 32;
pub const MAX_SLOT: u64 = 1_000_000_000_000_000;
pub const MAX_SLOT_PER_ENTRY: usize = 2048 * 8;
pub const MAX_DUPLICATE_SHREDS: u16 = 512;

/// Analogous to [VersionedCrdsValue](https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds.rs#L122)
pub const GossipVersionedData = struct {
    data: GossipData,
    metadata: GossipMetadata,

    pub fn clone(self: *const GossipVersionedData, allocator: std.mem.Allocator) error{OutOfMemory}!GossipVersionedData {
        return .{
            .data = try self.data.clone(allocator),
            .metadata = self.metadata,
        };
    }

    pub fn deinit(self: *const GossipVersionedData, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
    }

    /// Returns which value should overwrite the other, or if they're equal
    pub fn overwrites(
        new_value: *const GossipVersionedData,
        old_value: *const GossipVersionedData,
    ) enum { new, old, eq } {
        // labels must match
        assert(@intFromEnum(new_value.data.label()) == @intFromEnum(old_value.data.label()));

        const new_ts = new_value.data.wallclock();
        const old_ts = old_value.data.wallclock();

        return if (new_ts > old_ts)
            .new
        else if (new_ts < old_ts)
            .old
        else switch (new_value.metadata.value_hash.order(&old_value.metadata.value_hash)) {
            // If the timestamps are equal, the outcome is determined by comparing the hashes
            .gt => .new,
            .lt => .old,
            .eq => .eq,
        };
    }

    pub fn signedData(self: GossipVersionedData) SignedGossipData {
        return .{
            .signature = self.metadata.signature,
            .data = self.data,
        };
    }
};

/// The metadata about a GossipData instance in the GossipTable
pub const GossipMetadata = struct {
    signature: Signature,
    value_hash: Hash,
    timestamp_on_insertion: u64,
    cursor_on_insertion: u64,
};

/// Analogous to [CrdsValue](https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds_value.rs#L45)
pub const SignedGossipData = struct {
    signature: Signature,
    data: GossipData,
    const Self = @This();

    pub fn initSigned(
        /// Assumed to be a valid & strong keypair, passing a bad or invalid keypair is illegal.
        keypair: *const KeyPair,
        /// Assumed to be valid, passing invalid data is illegal.
        data: GossipData,
    ) Self {
        // should always be enough space or is invalid msg
        var buf: [PACKET_DATA_SIZE]u8 = undefined;
        const bytes = bincode.writeToSlice(&buf, data, bincode.Params.standard) catch |err| {
            // should never be possible for a valid gossip value
            std.debug.panic("Unexpected bincode failure: {}", .{err});
        };
        const signature = keypair.sign(bytes, null) catch |err| switch (err) {
            error.KeyMismatch => unreachable, // the keypair must match, passing a mismatched keypair is illegal
            error.IdentityElement => unreachable, // this would only be possible with a weak or invalid keypair, which is illegal
            error.WeakPublicKey => unreachable, // this would only be possible with a weak or invalid keypair, which is illegal

            // TODO: inspecting the code reveals this error is never actually reached from this function, despite being part of the error set
            // we should upstream a fix to zig's stdlib that amends this or documents why it's part of the error set at all.
            error.NonCanonical => unreachable,
        };
        return .{
            .signature = .fromSignature(signature),
            .data = data,
        };
    }

    pub fn clone(self: *const Self, allocator: std.mem.Allocator) error{OutOfMemory}!Self {
        return .{
            .signature = self.signature,
            .data = try self.data.clone(allocator),
        };
    }

    pub fn deinit(self: *const Self, allocator: std.mem.Allocator) void {
        self.data.deinit(allocator);
    }

    pub fn verify(self: *const Self, pubkey: Pubkey) !void {
        // should always be enough space or is invalid msg
        var buf: [PACKET_DATA_SIZE]u8 = undefined;
        const msg = try bincode.writeToSlice(&buf, self.data, bincode.Params.standard);
        return try self.signature.verify(pubkey, msg);
    }

    pub fn id(self: *const Self) Pubkey {
        return self.data.id();
    }

    pub fn label(self: *const Self) GossipKey {
        return self.data.label();
    }

    pub fn wallclock(self: *const Self) u64 {
        return self.data.wallclock();
    }

    /// only used in tests.
    pub fn initRandom(
        random: std.Random,
        /// Assumed to be a valid & strong keypair, passing a bad or invalid keypair is illegal.
        keypair: *const KeyPair,
    ) Self {
        return initSigned(keypair, GossipData.initRandom(random));
    }

    /// only used in tests
    pub fn randomWithIndex(
        random: std.Random,
        /// Assumed to be a valid & strong keypair, passing a bad or invalid keypair is illegal.
        keypair: *const KeyPair,
        index: usize,
    ) !Self {
        var data = GossipData.randomFromIndex(random, index);
        const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
        data.setId(pubkey);
        return initSigned(keypair, data);
    }
};

/// Analogous to [CrdsValueLabel](https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds_value.rs#L500)
pub const GossipKey = union(GossipDataTag) {
    LegacyContactInfo: Pubkey,
    Vote: struct { u8, Pubkey },
    LowestSlot: Pubkey,
    LegacySnapshotHashes: Pubkey,
    AccountsHashes: Pubkey,
    EpochSlots: struct { u8, Pubkey },
    LegacyVersion: Pubkey,
    Version: Pubkey,
    NodeInstance: Pubkey,
    DuplicateShred: struct { u16, Pubkey },
    SnapshotHashes: Pubkey,
    ContactInfo: Pubkey,
    RestartLastVotedForkSlots: Pubkey,
    RestartHeaviestFork: Pubkey,
};

pub const GossipDataTag = enum(u32) {
    LegacyContactInfo,
    Vote,
    LowestSlot,
    LegacySnapshotHashes,
    AccountsHashes,
    EpochSlots,
    LegacyVersion,
    Version,
    NodeInstance,
    DuplicateShred,
    SnapshotHashes,
    ContactInfo,
    RestartLastVotedForkSlots,
    RestartHeaviestFork,

    pub fn Value(self: GossipDataTag) type {
        return switch (self) {
            .LegacyContactInfo => LegacyContactInfo,
            .Vote => struct { u8, Vote },
            .LowestSlot => struct { u8, LowestSlot },
            .LegacySnapshotHashes => LegacySnapshotHashes,
            .AccountsHashes => AccountsHashes,
            .EpochSlots => struct { u8, EpochSlots },
            .LegacyVersion => LegacyVersion,
            .Version => Version,
            .NodeInstance => NodeInstance,
            .DuplicateShred => struct { u16, DuplicateShred },
            .SnapshotHashes => SnapshotHashes,
            .ContactInfo => ContactInfo,
            .RestartLastVotedForkSlots => RestartLastVotedForkSlots,
            .RestartHeaviestFork => RestartHeaviestFork,
        };
    }
};

/// Analogous to [CrdsData](https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds_value.rs#L85)
pub const GossipData = union(GossipDataTag) {
    LegacyContactInfo: LegacyContactInfo,
    Vote: struct { u8, Vote },
    LowestSlot: struct { u8, LowestSlot },
    LegacySnapshotHashes: LegacySnapshotHashes,
    AccountsHashes: AccountsHashes,
    EpochSlots: struct { u8, EpochSlots },
    LegacyVersion: LegacyVersion,
    Version: Version,
    NodeInstance: NodeInstance,
    DuplicateShred: struct {
        u16, // shred index
        DuplicateShred,
    },
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

    pub fn deinit(self: *const GossipData, allocator: std.mem.Allocator) void {
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

    pub fn id(self: *const GossipData) Pubkey {
        return switch (self.*) {
            // zig fmt: off
            .LegacyContactInfo         => |v| v.id,
            .Vote                      => |v| v[1].from,
            .LowestSlot                => |v| v[1].from,
            .LegacySnapshotHashes      => |v| v.from,
            .AccountsHashes            => |v| v.from,
            .EpochSlots                => |v| v[1].from,
            .LegacyVersion             => |v| v.from,
            .Version                   => |v| v.from,
            .NodeInstance              => |v| v.from,
            .DuplicateShred            => |v| v[1].from,
            .SnapshotHashes            => |v| v.from,
            .ContactInfo               => |v| v.pubkey,
            .RestartLastVotedForkSlots => |v| v.from,
            .RestartHeaviestFork       => |v| v.from,
            // zig fmt: on
        };
    }

    pub fn label(self: *const GossipData) GossipKey {
        return switch (self.*) {
            // zig fmt: off
            .LegacyContactInfo         => |v|.{ .LegacyContactInfo        = v.id },
            .Vote                      => |v|.{ .Vote                     = .{ v[0], v[1].from } },
            .LowestSlot                => |v|.{ .LowestSlot               = v[1].from },
            .LegacySnapshotHashes      => |v|.{ .LegacySnapshotHashes     = v.from },
            .AccountsHashes            => |v|.{ .AccountsHashes           = v.from },
            .EpochSlots                => |v|.{ .EpochSlots               = .{ v[0], v[1].from } },
            .LegacyVersion             => |v|.{ .LegacyVersion            = v.from },
            .Version                   => |v|.{ .Version                  = v.from },
            .NodeInstance              => |v|.{ .NodeInstance             = v.from },
            .DuplicateShred            => |v|.{ .DuplicateShred           = .{ v[0], v[1].from } },
            .SnapshotHashes            => |v|.{ .SnapshotHashes           = v.from },
            .ContactInfo               => |v|.{ .ContactInfo              = v.pubkey },
            .RestartLastVotedForkSlots => |v|.{ .RestartLastVotedForkSlots= v.from },
            .RestartHeaviestFork       => |v|.{ .RestartHeaviestFork      = v.from },
            // zig fmt: on
        };
    }

    pub fn wallclockPtr(self: *GossipData) *u64 {
        return switch (self.*) {
            // zig fmt: off
            .LegacyContactInfo         => |*v| &v.wallclock,
            .Vote                      => |*v| &v[1].wallclock,
            .LowestSlot                => |*v| &v[1].wallclock,
            .LegacySnapshotHashes      => |*v| &v.wallclock,
            .AccountsHashes            => |*v| &v.wallclock,
            .EpochSlots                => |*v| &v[1].wallclock,
            .LegacyVersion             => |*v| &v.wallclock,
            .Version                   => |*v| &v.wallclock,
            .NodeInstance              => |*v| &v.wallclock,
            .DuplicateShred            => |*v| &v[1].wallclock,
            .SnapshotHashes            => |*v| &v.wallclock,
            .ContactInfo               => |*v| &v.wallclock,
            .RestartLastVotedForkSlots => |*v| &v.wallclock,
            .RestartHeaviestFork       => |*v| &v.wallclock,
            // zig fmt: on
        };
    }

    pub fn wallclock(self: *const GossipData) u64 {
        return switch (self.*) {
            // zig fmt: off
            .LegacyContactInfo         => |v| v.wallclock,
            .Vote                      => |v| v[1].wallclock,
            .LowestSlot                => |v| v[1].wallclock,
            .LegacySnapshotHashes      => |v| v.wallclock,
            .AccountsHashes            => |v| v.wallclock,
            .EpochSlots                => |v| v[1].wallclock,
            .LegacyVersion             => |v| v.wallclock,
            .Version                   => |v| v.wallclock,
            .NodeInstance              => |v| v.wallclock,
            .DuplicateShred            => |v| v[1].wallclock,
            .SnapshotHashes            => |v| v.wallclock,
            .ContactInfo               => |v| v.wallclock,
            .RestartLastVotedForkSlots => |v| v.wallclock,
            .RestartHeaviestFork       => |v| v.wallclock,
            // zig fmt: on
        };
    }

    /// only used in tests
    pub fn setId(self: *GossipData, new_id: Pubkey) void {
        switch (self.*) {
            // zig fmt: off
            .LegacyContactInfo         => |*v| v.id = new_id,
            .Vote                      => |*v| v[1].from = new_id,
            .LowestSlot                => |*v| v[1].from = new_id,
            .LegacySnapshotHashes      => |*v| v.from = new_id,
            .AccountsHashes            => |*v| v.from = new_id,
            .EpochSlots                => |*v| v[1].from = new_id,
            .LegacyVersion             => |*v| v.from = new_id,
            .Version                   => |*v| v.from = new_id,
            .NodeInstance              => |*v| v.from = new_id,
            .DuplicateShred            => |*v| v[1].from = new_id,
            .SnapshotHashes            => |*v| v.from = new_id,
            .ContactInfo               => |*v| v.pubkey = new_id,
            .RestartLastVotedForkSlots => |*v| v.from = new_id,
            .RestartHeaviestFork       => |*v| v.from = new_id,
            // zig fmt: on
        }
    }

    /// only used in tests
    pub fn initRandom(random: std.Random) GossipData {
        const v = random.intRangeAtMost(u16, 0, 10);
        return GossipData.randomFromIndex(random, v);
    }

    pub fn randomFromIndex(random: std.Random, index: usize) GossipData {
        return switch (index) {
            0 => .{ .LegacyContactInfo = LegacyContactInfo.initRandom(random) },
            1 => .{ .Vote = .{ random.intRangeAtMost(u8, 0, MAX_VOTES - 1), Vote.initRandom(random) } },
            2 => .{ .EpochSlots = .{ random.intRangeAtMost(u8, 0, MAX_EPOCH_SLOTS - 1), EpochSlots.initRandom(random) } },
            3 => .{ .LowestSlot = .{ 0, LowestSlot.initRandom(random) } },
            4 => .{ .LegacySnapshotHashes = LegacySnapshotHashes.initRandom(random) },
            5 => .{ .AccountsHashes = AccountsHashes.initRandom(random) },
            6 => .{ .LegacyVersion = LegacyVersion.initRandom(random) },
            7 => .{ .Version = Version.initRandom(random) },
            8 => .{ .NodeInstance = NodeInstance.initRandom(random) },
            9 => .{ .SnapshotHashes = SnapshotHashes.initRandom(random) },
            // 10 => .{ .ContactInfo = ContactInfo.initRandom(random) },
            else => .{ .DuplicateShred = .{ random.intRangeAtMost(u16, 0, MAX_DUPLICATE_SHREDS - 1), DuplicateShred.initRandom(random) } },
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

    pub fn initRandom(random: std.Random) LegacyContactInfo {
        return LegacyContactInfo{
            .id = Pubkey.initRandom(random),
            .gossip = SocketAddr.initRandom(random),
            .turbine_recv = SocketAddr.initRandom(random),
            .turbine_recv_quic = SocketAddr.initRandom(random),
            .repair = SocketAddr.initRandom(random),
            .tpu = SocketAddr.initRandom(random),
            .tpu_forwards = SocketAddr.initRandom(random),
            .tpu_vote = SocketAddr.initRandom(random),
            .rpc = SocketAddr.initRandom(random),
            .rpc_pubsub = SocketAddr.initRandom(random),
            .serve_repair = SocketAddr.initRandom(random),
            .wallclock = getWallclockMs(),
            .shred_version = random.int(u16),
        };
    }

    /// call ContactInfo.deinit to free
    pub fn toContactInfo(self: *const LegacyContactInfo, allocator: std.mem.Allocator) !ContactInfo {
        var ci = ContactInfo.init(allocator, self.id, self.wallclock, self.shred_version);
        errdefer ci.deinit();

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

    pub fn deinit(self: *const Vote, allocator: std.mem.Allocator) void {
        self.transaction.deinit(allocator);
    }

    pub fn initRandom(random: std.Random) Vote {
        return Vote{
            .from = Pubkey.initRandom(random),
            .transaction = Transaction.EMPTY,
            .wallclock = getWallclockMs(),
            .slot = random.int(u64),
        };
    }

    pub fn sanitize(self: *const Vote) !void {
        try sanitizeWallclock(self.wallclock);
        // Use the looser transaction sanitization rules for vote transactions within gossip
        // Matches Agave Transactions impl of the Sanitize trait.
        // [solana-sdk] https://github.com/anza-xyz/solana-sdk/blob/6efc4078ab7652ab6a1a08754d5c324cb26746ea/transaction/src/lib.rs#L202
        if (self.transaction.msg.signature_count > self.transaction.signatures.len) {
            return error.NotEnoughSignatures;
        }
        if (self.transaction.signatures.len > self.transaction.msg.account_keys.len) {
            return error.TooManySignatures;
        }
        try self.transaction.msg.validate();
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

    pub fn deinit(self: *const LowestSlot, allocator: std.mem.Allocator) void {
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

    pub fn initRandom(random: std.Random) LowestSlot {
        var slots: [0]u64 = .{};
        var stash: [0]DeprecatedEpochIncompleteSlots = .{};
        return LowestSlot{
            .from = Pubkey.initRandom(random),
            .root = 0,
            .lowest = random.int(u64),
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

    pub fn deinit(self: *const DeprecatedEpochIncompleteSlots, allocator: std.mem.Allocator) void {
        allocator.free(self.compressed_list);
    }
};

pub const CompressionType = enum {
    Uncompressed,
    GZip,
    BZip2,
};

pub const LegacySnapshotHashes = AccountsHashes;

pub const AccountsHashes = struct {
    from: Pubkey,
    hashes: []const SlotAndHash,
    wallclock: u64,

    pub fn clone(self: *const AccountsHashes, allocator: std.mem.Allocator) error{OutOfMemory}!AccountsHashes {
        return .{
            .from = self.from,
            .hashes = try allocator.dupe(SlotAndHash, self.hashes),
            .wallclock = self.wallclock,
        };
    }

    pub fn deinit(self: *const AccountsHashes, allocator: std.mem.Allocator) void {
        allocator.free(self.hashes);
    }

    pub fn initRandom(random: std.Random) AccountsHashes {
        return .{
            .from = Pubkey.initRandom(random),
            .hashes = &.{},
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

    pub fn deinit(self: *const EpochSlots, allocator: std.mem.Allocator) void {
        for (self.slots) |*slot| slot.deinit(allocator);
        allocator.free(self.slots);
    }

    pub fn initRandom(random: std.Random) EpochSlots {
        var slice: [0]CompressedSlots = .{};
        return EpochSlots{
            .from = Pubkey.initRandom(random),
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

    pub fn deinit(self: *const CompressedSlots, allocator: std.mem.Allocator) void {
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

    pub fn deinit(self: *const Flate2, allocator: std.mem.Allocator) void {
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

    pub fn deinit(self: *const Uncompressed, allocator: std.mem.Allocator) void {
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

        pub fn deinit(self: *const BitVec(T), allocator: std.mem.Allocator) void {
            allocator.free(self.bits.?);
        }
    };
}

pub const LegacyVersion = struct {
    from: Pubkey,
    wallclock: u64,
    version: LegacyVersion1,

    pub fn initRandom(random: std.Random) LegacyVersion {
        return LegacyVersion{
            .from = Pubkey.initRandom(random),
            .wallclock = getWallclockMs(),
            .version = LegacyVersion1.initRandom(random),
        };
    }
};

pub const LegacyVersion1 = struct {
    major: u16,
    minor: u16,
    patch: u16,
    commit: ?u32, // first 4 bytes of the sha1 commit hash

    pub fn initRandom(random: std.Random) LegacyVersion1 {
        return LegacyVersion1{
            .major = random.int(u16),
            .minor = random.int(u16),
            .patch = random.int(u16),
            .commit = random.int(u32),
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

    pub fn initRandom(random: std.Random) Version {
        return Version{
            .from = Pubkey.initRandom(random),
            .wallclock = getWallclockMs(),
            .version = LegacyVersion2.initRandom(random),
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

    pub fn initRandom(random: std.Random) Self {
        return Self{
            .major = random.int(u16),
            .minor = random.int(u16),
            .patch = random.int(u16),
            .commit = random.int(u32),
            .feature_set = random.int(u32),
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

    pub fn initRandom(random: std.Random) Self {
        return Self{
            .from = Pubkey.initRandom(random),
            .wallclock = getWallclockMs(),
            .timestamp = random.int(u64),
            .token = random.int(u64),
        };
    }

    pub fn init(random: std.Random, from: Pubkey, wallclock: u64) Self {
        return Self{
            .from = from,
            .wallclock = wallclock,
            .timestamp = @intCast(std.time.microTimestamp()),
            .token = random.int(u64),
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

pub const ShredType = sig.ledger.shred.ShredType;

pub const DuplicateShred = struct {
    from: Pubkey,
    wallclock: u64,
    slot: Slot,
    shred_index: u32,
    shred_type: ShredType,
    // Serialized DuplicateSlotProof split into chunks.
    num_chunks: u8,
    chunk_index: u8,
    chunk: []const u8,

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

    pub fn deinit(self: *const DuplicateShred, allocator: std.mem.Allocator) void {
        allocator.free(self.chunk);
    }

    pub fn initRandom(random: std.Random) DuplicateShred {
        // NOTE: cant pass around a slice here (since the stack data will get cleared)
        var slice = [0]u8{}; // empty slice
        const num_chunks = random.intRangeAtMost(u8, 5, 100);
        const chunk_index = random.intRangeAtMost(u8, 0, num_chunks - 1);

        return .{
            .from = .initRandom(random),
            .wallclock = getWallclockMs(),
            .slot = random.int(u64),
            .shred_index = random.int(u32),
            .shred_type = .data,
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
    incremental: IncrementalSnapshotsList,
    wallclock: u64,

    pub fn clone(self: *const SnapshotHashes, allocator: std.mem.Allocator) error{OutOfMemory}!SnapshotHashes {
        return .{
            .from = self.from,
            .full = self.full,
            .incremental = try self.incremental.clone(allocator),
            .wallclock = self.wallclock,
        };
    }

    pub fn deinit(self: *const SnapshotHashes, allocator: std.mem.Allocator) void {
        self.incremental.deinit(allocator);
    }

    pub fn initRandom(random: std.Random) SnapshotHashes {
        return .{
            .from = Pubkey.initRandom(random),
            .full = .{ .slot = random.int(u64), .hash = Hash.initRandom(random) },
            .incremental = IncrementalSnapshotsList.EMPTY,
            .wallclock = getWallclockMs(),
        };
    }

    pub fn sanitize(self: *const @This()) !void {
        try sanitizeWallclock(self.wallclock);
        if (self.full.slot >= MAX_SLOT) {
            return error.ValueOutOfBounds;
        }
        for (self.incremental.getSlice()) |inc| {
            if (inc.slot >= MAX_SLOT) {
                return error.ValueOutOfBounds;
            }
            if (self.full.slot >= inc.slot) {
                return error.InvalidValue;
            }
        }
    }

    /// List of incremental `SlotAndHash`es.
    /// Can be thought of as a tagged union, where the tag is a boolean derived from `.len == 1`.
    /// When the tag is `true`, the single item is represented inline in the `items` union.
    /// When the tag is `false`, the list of items is pointed to by the `items` union.
    ///
    /// This optimizes the case where we only have a single incremental snapshot.
    pub const IncrementalSnapshotsList = union(enum) {
        single: SlotAndHash,
        multiple: []const SlotAndHash,

        pub const @"!bincode-config": bincode.FieldConfig(IncrementalSnapshotsList) = .{
            .serializer = bincodeSerializeFn,
            .deserializer = bincodeDeserializeFn,
            .free = bincodeFreeFn,
            .skip = false,
            .post_deserialize_fn = null,
        };

        pub fn getSlice(inc: *const IncrementalSnapshotsList) []const SlotAndHash {
            return switch (inc.*) {
                .single => |*single| single[0..1],
                .multiple => |list| list,
            };
        }

        pub fn deinit(self: *const IncrementalSnapshotsList, allocator: std.mem.Allocator) void {
            switch (self.*) {
                .single => {},
                .multiple => |list| if (list.len > 0) allocator.free(list),
            }
        }

        /// Can optionally and safely have `.deinit` called.
        pub const EMPTY: IncrementalSnapshotsList = .{ .multiple = &.{} };

        /// The returned snapshot collection can optionally and safely have `.deinit` called.
        pub fn initSingle(single: SlotAndHash) IncrementalSnapshotsList {
            return .{ .single = single };
        }

        /// Responsibility to `.deinit` the returned snapshot list falls to the caller in order to free `list`, if `list` was allocated.
        /// Asserts `list.len != 1`.
        pub fn initList(list: []const SlotAndHash) IncrementalSnapshotsList {
            assert(list.len != 1);
            return .{ .multiple = list };
        }

        /// Responsibility to `.deinit` the returned snapshot collection with the specified allocator falls to the caller.
        /// Accepts any `list.len`.
        pub fn initListCloned(allocator: std.mem.Allocator, list: []const SlotAndHash) !IncrementalSnapshotsList {
            if (list.len == 1) return initSingle(list[0]);
            const uncloned = initList(list);
            return uncloned.clone(allocator);
        }

        pub fn clone(inc: *const IncrementalSnapshotsList, allocator: std.mem.Allocator) !IncrementalSnapshotsList {
            return switch (inc.*) {
                .single => |single| .{ .single = single },
                .multiple => |list| .{ .multiple = try allocator.dupe(SlotAndHash, list) },
            };
        }

        fn bincodeSerializeFn(writer: anytype, inc_list: anytype, params: bincode.Params) !void {
            try bincode.write(writer, inc_list.getSlice(), params);
        }

        fn bincodeDeserializeFn(limit_allocator: *bincode.LimitAllocator, reader: anytype, params: bincode.Params) !IncrementalSnapshotsList {
            const faililng_allocator = sig.utils.allocators.failing.allocator(.{});

            const maybe_len = try bincode.readIntAsLength(usize, reader, params);
            const len = maybe_len orelse return error.IncrementalListTooBig;
            switch (len) {
                0 => return EMPTY,
                1 => return initSingle(try bincode.read(faililng_allocator, SlotAndHash, reader, params)),
                else => {
                    const allocator = limit_allocator.allocator();
                    const list = try allocator.alloc(SlotAndHash, len);
                    errdefer allocator.free(list);

                    for (list) |*sah| sah.* = try bincode.read(faililng_allocator, SlotAndHash, reader, params);
                    return initList(list);
                },
            }
        }

        fn bincodeFreeFn(allocator: std.mem.Allocator, inc_list: anytype) void {
            IncrementalSnapshotsList.deinit(&inc_list, allocator);
        }
    };
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
    tpu_vote_quic = 12,
    /// Analogous to [SOCKET_TAG_TVU](https://github.com/anza-xyz/agave/blob/d9683093ec5ce3138ab94332e248c524a2e60454/gossip/src/contact_info.rs#L38)
    turbine_recv = 10,
    /// Analogous to [SOCKET_TAG_TVU_QUIC](https://github.com/anza-xyz/agave/blob/d9683093ec5ce3138ab94332e248c524a2e60454/gossip/src/contact_info.rs#L39)
    turbine_recv_quic = 11,
    _,

    pub const BincodeSize = u8;
};
pub const SOCKET_CACHE_SIZE: usize = @intFromEnum(SocketTag.tpu_vote_quic) + 1;

pub const ContactInfo = struct {
    pubkey: Pubkey,
    wallclock: u64,
    outset: u64,
    shred_version: u16,
    version: ClientVersion,
    addrs: ArrayList(IpAddr),
    sockets: ArrayList(SocketEntry),
    extensions: ArrayList(Extension),
    cache: [SOCKET_CACHE_SIZE]SocketAddr = .{SocketAddr.UNSPECIFIED} ** SOCKET_CACHE_SIZE,

    // TODO: improve implementation of post deserialise method
    pub const @"!bincode-config:post-deserialize" = bincode.FieldConfig(ContactInfo){ .post_deserialize_fn = ContactInfo.buildCache };
    pub const @"!bincode-config:cache" = bincode.FieldConfig([SOCKET_CACHE_SIZE]SocketAddr){ .skip = true };
    pub const @"!bincode-config:addrs" = bincode.shortvec.arrayListConfig(IpAddr);
    pub const @"!bincode-config:sockets" = bincode.shortvec.arrayListConfig(SocketEntry);
    pub const @"!bincode-config:extensions" = bincode.shortvec.arrayListConfig(Extension);
    pub const @"!bincode-config:wallclock" = bincode.VarIntConfig(u64);

    const Self = @This();

    pub fn buildCache(self: *Self) void {
        var port: u16 = 0;
        for (self.sockets.items) |socket_entry| {
            port += socket_entry.offset;
            const addr = self.addrs.items[socket_entry.index];
            const socket: SocketAddr = switch (addr) {
                .ipv4 => |ipv4| .initIpv4(ipv4.octets, port),
                .ipv6 => |ipv6| .initIpv6(ipv6.octets, port),
            };
            socket.sanitize() catch continue;

            const cache_index = @intFromEnum(socket_entry.key);
            if (cache_index >= SOCKET_CACHE_SIZE) {
                // warn
                continue;
            }
            self.cache[cache_index] = socket;
        }
    }

    pub fn toNodeInstance(self: *Self, random: std.Random) NodeInstance {
        return NodeInstance.init(random, self.pubkey, @intCast(std.time.milliTimestamp()));
    }

    pub fn deinit(self: *const Self) void {
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
        return .{
            .pubkey = pubkey,
            .wallclock = wallclock,
            .outset = outset,
            .shred_version = shred_version,
            .version = ClientVersion.CURRENT,
            .addrs = ArrayList(IpAddr).init(allocator),
            .sockets = ArrayList(SocketEntry).init(allocator),
            .extensions = ArrayList(void).init(allocator),
        };
    }

    pub fn initRandom(
        allocator: std.mem.Allocator,
        random: std.Random,
        pubkey: Pubkey,
        wallclock: u64,
        outset: u64,
        shred_version: u16,
    ) !ContactInfo {
        var addrs = try ArrayList(IpAddr).initCapacity(allocator, random.intRangeAtMost(usize, 4, 10));
        var sockets = try ArrayList(SocketEntry).initCapacity(allocator, random.intRangeAtMost(usize, 4, 10));

        for (0..addrs.items.len) |_| {
            addrs.appendAssumeCapacity(.initIpv4(.{ 127, 0, 0, 1 }));
        }

        for (0..sockets.items.len) |_| {
            sockets.appendAssumeCapacity(.{ .key = .turbine_recv, .index = 20, .offset = 30 });
        }

        return .{
            .pubkey = pubkey,
            .wallclock = wallclock,
            .outset = outset,
            .shred_version = shred_version,
            .version = .{
                .major = 0,
                .minor = 1,
                .patch = 2,
                .commit = 3,
                .feature_set = 4,
                .client = .sig,
            },
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
            var offset = socket_addr.getPort();
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
            self.cache[@intFromEnum(key)] = SocketAddr.UNSPECIFIED;
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
/// TODO: This struct is starting to look a lot like LegacyContactInfo, it would be nice to
/// create some comptime code that behaves like graphql.  For example, gossip would have a
/// generic getContactInfo function where you could pass in a custom type definition for a
/// struct that only includes fields for the specific ports you care about, and the function
/// would be able to populate that custom struct by iterating over the struct fields.
pub const ThreadSafeContactInfo = struct {
    pubkey: Pubkey,
    shred_version: u16,
    gossip_addr: ?SocketAddr,
    rpc_addr: ?SocketAddr,
    tpu_addr: ?SocketAddr,
    tvu_addr: ?SocketAddr,
    tpu_quic_addr: ?SocketAddr,
    tpu_vote_addr: ?SocketAddr,

    pub fn initRandom(
        random: std.Random,
        pubkey: Pubkey,
        shred_version: u16,
    ) ThreadSafeContactInfo {
        return .{
            .pubkey = pubkey,
            .shred_version = shred_version,
            .gossip_addr = .initRandom(random),
            .rpc_addr = .initRandom(random),
            .tpu_addr = .initRandom(random),
            .tvu_addr = .initRandom(random),
            .tpu_quic_addr = .initRandom(random),
            .tpu_vote_addr = .initRandom(random),
        };
    }

    pub fn fromContactInfo(contact_info: ContactInfo) ThreadSafeContactInfo {
        return .{
            .pubkey = contact_info.pubkey,
            .shred_version = contact_info.shred_version,
            .gossip_addr = contact_info.getSocket(.gossip),
            .rpc_addr = contact_info.getSocket(.rpc),
            .tpu_addr = contact_info.getSocket(.tpu),
            .tvu_addr = contact_info.getSocket(.turbine_recv),
            .tpu_quic_addr = contact_info.getSocket(.tpu_quic),
            .tpu_vote_addr = contact_info.getSocket(.tpu_vote),
        };
    }

    pub fn fromLegacyContactInfo(legacy_contact_info: LegacyContactInfo) ThreadSafeContactInfo {
        return .{
            .pubkey = legacy_contact_info.id,
            .shred_version = legacy_contact_info.shred_version,
            .gossip_addr = legacy_contact_info.gossip,
            .rpc_addr = legacy_contact_info.rpc,
            .tpu_addr = legacy_contact_info.tpu,
            .tvu_addr = legacy_contact_info.turbine_recv,
            .tpu_quic_addr = null,
            .tpu_vote_addr = legacy_contact_info.tpu_vote,
        };
    }
};

/// This exists for future proofing to allow easier additions to ContactInfo.
/// Currently, ContactInfo has no extensions.
/// This may be changed in the future to a union or enum as extensions are added.
const Extension = void;

const SocketEntry = struct {
    /// GossipMessageIdentifier, e.g. turbine_recv, tpu, etc
    key: SocketTag,
    /// IpAddr index in the accompanying addrs vector.
    index: u8,
    /// Port offset with respect to the previous entry.
    offset: u16,

    const Self = @This();

    pub const @"!bincode-config:offset" = bincode.VarIntConfig(u16);

    pub fn eql(self: *const Self, other: *const Self) bool {
        return self.key == other.key and
            self.index == other.index and
            self.offset == other.offset;
    }
};

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

    pub fn deinit(self: *const Self, allocator: std.mem.Allocator) void {
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

    pub fn deinit(self: *const SlotsOffsets, allocator: std.mem.Allocator) void {
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

    pub fn deinit(self: *const RawOffsets, allocator: std.mem.Allocator) void {
        self.bits.deinit(allocator);
    }
};

test "new contact info" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var ci = ContactInfo.init(testing.allocator, Pubkey.initRandom(random), @as(u64, @intCast(std.time.microTimestamp())), 0);
    defer ci.deinit();
}

test "socketaddr bincode serialize matches rust" {
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

test "set & get socket on contact info" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var ci = ContactInfo.init(testing.allocator, Pubkey.initRandom(random), @as(u64, @intCast(std.time.microTimestamp())), 0);
    defer ci.deinit();
    try ci.setSocket(.rpc, SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8899));

    var set_socket = ci.getSocket(.rpc);
    try testing.expect(set_socket.?.eql(&SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8899)));
    try testing.expectEqual(IpAddr.initIpv4(.{ 127, 0, 0, 1 }), ci.addrs.items[0]);
    try testing.expect(ci.sockets.items[0].eql(&.{ .key = .rpc, .index = 0, .offset = 8899 }));
}

test "contact info bincode serialize matches rust bincode" {
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
    var sig_contact_info: ContactInfo = .{
        .pubkey = .parse("4NftWecdfGcYZMJahnAAX5Cw1PLGLZhYFB19wL6AkXqW"),
        .wallclock = 1721060646885,
        .outset = 1721060141617172,
        .shred_version = 0,
        .version = .{
            .major = 2,
            .minor = 1,
            .patch = 0,
            .commit = 0,
            .feature_set = 12366211,
            .client = .agave,
        },
        .addrs = ArrayList(IpAddr).init(testing.allocator),
        .sockets = ArrayList(SocketEntry).init(testing.allocator),
        .extensions = ArrayList(Extension).init(testing.allocator),
    };
    defer sig_contact_info.deinit();
    try sig_contact_info.addrs.append(.initIpv4(.{ 127, 0, 0, 1 }));
    try sig_contact_info.sockets.append(.{ .key = .turbine_recv, .index = 0, .offset = 8001 });
    try sig_contact_info.sockets.append(.{ .key = .turbine_recv_quic, .index = 0, .offset = 1 });
    try sig_contact_info.sockets.append(.{ .key = .tpu, .index = 0, .offset = 1 });
    try sig_contact_info.sockets.append(.{ .key = .tpu_forwards, .index = 0, .offset = 1 });
    try sig_contact_info.sockets.append(.{ .key = .tpu_vote, .index = 0, .offset = 1 });
    try sig_contact_info.sockets.append(.{ .key = .repair, .index = 0, .offset = 1 });
    try sig_contact_info.sockets.append(.{ .key = .serve_repair, .index = 0, .offset = 2 });
    try sig_contact_info.sockets.append(.{ .key = .tpu_quic, .index = 0, .offset = 1 });
    try sig_contact_info.sockets.append(.{ .key = .tpu_forwards_quic, .index = 0, .offset = 1 });
    try sig_contact_info.sockets.append(.{ .key = .rpc, .index = 0, .offset = 889 });
    try sig_contact_info.sockets.append(.{ .key = .rpc_pubsub, .index = 0, .offset = 1 });
    try sig_contact_info.sockets.append(.{ .key = .gossip, .index = 0, .offset = 11780 });
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

test "ContactInfo bincode roundtrip maintains data integrity" {
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

test "SocketEntry serializer works" {
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

test "sig verify duplicateShreds" {
    var keypair = try KeyPair.generateDeterministic([_]u8{1} ** 32);
    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var data = DuplicateShred.initRandom(prng.random());
    data.from = pubkey;

    const value = SignedGossipData.initSigned(&keypair, .{ .DuplicateShred = .{ 0, data } });
    try value.verify(pubkey);
}

test "sanitize GossipData" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    for (0..4) |i| {
        const data = GossipData.randomFromIndex(random, i);
        data.sanitize() catch {};
    }
}

test "SignedGossipData label() and id() methods" {
    const kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.generateDeterministic(kp_bytes);
    const pk = kp.public_key;
    var id = Pubkey.fromPublicKey(&pk);

    var legacy_contact_info = LegacyContactInfo.default(id);
    legacy_contact_info.wallclock = 0;

    const value = SignedGossipData.initSigned(&kp, .{
        .LegacyContactInfo = legacy_contact_info,
    });

    try std.testing.expect(value.id().equals(&id));
    try std.testing.expect(value.label().LegacyContactInfo.equals(&id));
}

test "pubkey matches rust" {
    const kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.generateDeterministic(kp_bytes);
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

test "contact info serialization matches rust" {
    const kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.generateDeterministic(kp_bytes);
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

test "RestartHeaviestFork serialization matches rust" {
    var rust_bytes = [_]u8{ 82, 182, 93, 119, 193, 123, 4, 235, 68, 64, 82, 233, 51, 34, 232, 123, 245, 237, 236, 142, 251, 1, 123, 124, 26, 40, 219, 84, 165, 116, 208, 63, 19, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 0, 0, 0, 0, 0, 0, 0, 20, 0 };

    const x = RestartHeaviestFork{
        .from = .parse("6ZsiX6YcwEa93yWtVwGRiK8Ceoxq2VieVh2pvEiUtpCW"),
        .wallclock = 19,
        .last_slot = 12,
        .observed_stake = 11,
        .shred_version = 20,
        .last_slot_hash = Hash.ZEROES,
    };

    var buf = [_]u8{0} ** 1024;
    var bytes = try bincode.writeToSlice(&buf, x, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, bytes[0..bytes.len], rust_bytes[0..bytes.len]);
}

test "RestartLastVotedForkSlots serialization matches rust" {
    var rust_bytes = [_]u8{ 82, 182, 93, 119, 193, 123, 4, 235, 68, 64, 82, 233, 51, 34, 232, 123, 245, 237, 236, 142, 251, 1, 123, 124, 26, 40, 219, 84, 165, 116, 208, 63, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 16, 0, 0, 0, 0, 0, 0, 0, 255, 255, 239, 255, 255, 254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    var x = try DynamicArrayBitSet(u8).initFull(std.testing.allocator, 128);
    defer x.deinit(std.testing.allocator);
    x.setValue(20, false);
    x.setValue(40, false);

    const offsets = SlotsOffsets{
        .RawOffsets = .{ .bits = x },
    };

    const data = RestartLastVotedForkSlots{
        .from = .parse("6ZsiX6YcwEa93yWtVwGRiK8Ceoxq2VieVh2pvEiUtpCW"),
        .wallclock = 0,
        .last_voted_slot = 0,
        .last_voted_hash = Hash.ZEROES,
        .shred_version = 0,
        .offsets = offsets,
    };

    var buf = [_]u8{0} ** 1024;
    var bytes = try bincode.writeToSlice(buf[0..], data, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, bytes[0..bytes.len], rust_bytes[0..bytes.len]);
}

test "gossip data serialization matches rust" {
    const kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.generateDeterministic(kp_bytes);
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

test "random gossip data" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var buf: [1000]u8 = undefined;

    {
        const data = LegacyContactInfo.initRandom(random);
        const result = try bincode.writeToSlice(&buf, data, bincode.Params.standard);
        _ = result;
    }
    {
        const data = EpochSlots.initRandom(random);
        const result = try bincode.writeToSlice(&buf, data, bincode.Params.standard);
        _ = result;
    }
    {
        const data = Vote.initRandom(random);
        const result = try bincode.writeToSlice(&buf, data, bincode.Params.standard);
        _ = result;
    }
    {
        const data = DuplicateShred.initRandom(random);
        const result = try bincode.writeToSlice(&buf, data, bincode.Params.standard);
        _ = result;
    }
    {
        const data = GossipData.initRandom(random);
        const result = try bincode.writeToSlice(&buf, data, bincode.Params.standard);
        _ = result;
    }
}

test "LegacyContactInfo <-> ContactInfo roundtrip" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const start = LegacyContactInfo.initRandom(random);
    const ci = try start.toContactInfo(std.testing.allocator);
    defer ci.deinit();
    const end = LegacyContactInfo.fromContactInfo(&ci);

    try std.testing.expectEqual(start, end);
}

test "sanitize valid ContactInfo works" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const info = try ContactInfo.initRandom(std.testing.allocator, random, Pubkey.initRandom(random), 100, 123, 246);
    defer info.deinit();
    const data = GossipData{ .ContactInfo = info };
    try data.sanitize();
}

test "sanitize invalid ContactInfo has error" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const info = try ContactInfo.initRandom(std.testing.allocator, random, Pubkey.initRandom(random), 1_000_000_000_000_000, 123, 246);
    defer info.deinit();
    const data = GossipData{ .ContactInfo = info };
    if (data.sanitize()) |_| return error.ExpectedError else |_| {}
}

test "sanitize valid NodeInstance works" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const instance = NodeInstance.initRandom(random);
    const data = GossipData{ .NodeInstance = instance };
    try data.sanitize();
}

test "sanitize invalid NodeInstance has error" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    var instance = NodeInstance.initRandom(random);
    instance.wallclock = 1_000_000_000_487_283;
    const data = GossipData{ .NodeInstance = instance };
    if (data.sanitize()) |_| return error.ExpectedError else |_| {}
}

test "sanitize valid SnapshotHashes works" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    var instance = SnapshotHashes.initRandom(random);
    instance.full.slot = 1000;
    const data = GossipData{ .SnapshotHashes = instance };
    try data.sanitize();
}

test "sanitize invalid SnapshotHashes full slot has error" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    var instance = SnapshotHashes.initRandom(random);
    instance.full.slot = 1_000_000_000_487_283;
    const data = GossipData{ .SnapshotHashes = instance };
    if (data.sanitize()) |_| return error.ExpectedError else |_| {}
}

test "sanitize invalid SnapshotHashes incremental slot has error" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    var instance = SnapshotHashes.initRandom(random);
    instance.incremental = SnapshotHashes.IncrementalSnapshotsList.initSingle(.{ .slot = 1_000_000_000_487_283, .hash = Hash.ZEROES });
    const data = GossipData{ .SnapshotHashes = instance };
    if (data.sanitize()) |_| return error.ExpectedError else |_| {}
}

test "sanitize SnapshotHashes full > incremental has error" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    var instance = SnapshotHashes.initRandom(random);
    instance.full.slot = 2;
    instance.incremental = SnapshotHashes.IncrementalSnapshotsList.initSingle(.{ .slot = 1, .hash = Hash.ZEROES });
    const data = GossipData{ .SnapshotHashes = instance };
    if (data.sanitize()) |_| return error.ExpectedError else |_| {}
}

test "sanitize vote" {
    var vote = Vote{
        .from = .ZEROES,
        .transaction = .{
            .signatures = &.{ Signature.ZEROES, Signature.ZEROES },
            .version = .legacy,
            .msg = .{
                .signature_count = 1,
                .readonly_signed_count = 0,
                .readonly_unsigned_count = 0,
                .account_keys = &.{ Pubkey.ZEROES, Pubkey.ZEROES },
                .recent_blockhash = Hash.ZEROES,
                .instructions = &.{},
                .address_lookups = &.{},
            },
        },
        .wallclock = 0,
        .slot = 0,
    };

    try vote.sanitize();
    try std.testing.expectError(error.TooManySignatures, vote.transaction.validate());

    vote.transaction.msg.signature_count = 3;
    try std.testing.expectError(error.NotEnoughSignatures, vote.sanitize());
    vote.transaction.msg.signature_count = 1;

    vote.transaction.signatures = &[_]Signature{Signature.ZEROES} ** 3;
    try std.testing.expectError(error.TooManySignatures, vote.sanitize());
}
