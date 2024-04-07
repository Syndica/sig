const std = @import("std");
const SocketAddr = @import("../net/net.zig").SocketAddr;
const Tuple = std.meta.Tuple;
const Hash = @import("../core/hash.zig").Hash;
const Signature = @import("../core/signature.zig").Signature;
const Transaction = @import("../core/transaction.zig").Transaction;
const Slot = @import("../core/time.zig").Slot;
const bincode = @import("../bincode/bincode.zig");
const ArrayList = std.ArrayList;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const sanitizeWallclock = @import("./message.zig").sanitizeWallclock;
const PACKET_DATA_SIZE = @import("../net/packet.zig").PACKET_DATA_SIZE;

const network = @import("zig-network");
const var_int = @import("../utils/varint.zig");
const var_int_config_u16 = var_int.var_int_config_u16;
const var_int_config_u64 = var_int.var_int_config_u64;

const ShortVecArrayListConfig = @import("../utils/shortvec.zig").ShortVecArrayListConfig;
const IpAddr = @import("../net/net.zig").IpAddr;
const gossip = @import("sig").gossip;
const testing = std.testing;

const ClientVersion = @import("../version/version.zig").ClientVersion;

const Socket = network.Socket;
const UdpSocket = network.Socket;
const TcpListener = network.Socket;
const net = std.net;

/// returns current timestamp in milliseconds
pub fn getWallclockMs() u64 {
    return @intCast(std.time.milliTimestamp());
}

pub const MAX_EPOCH_SLOTS: u8 = 255;
pub const MAX_VOTES: u8 = 32;
pub const MAX_SLOT: u64 = 1_000_000_000_000_000;
pub const MAX_SLOT_PER_ENTRY: usize = 2048 * 8;
pub const MAX_DUPLICATE_SHREDS: u16 = 512;

// https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds.rs#L122
pub const GossipVersionedData = struct {
    value: SignedGossipData,
    value_hash: Hash,
    timestamp_on_insertion: u64,
    cursor_on_insertion: u64,

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
            return old_value.value_hash.cmp(&new_value.value_hash) == .lt;
        }
    }
};

// https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds_value.rs#L45
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
        var bytes = try bincode.writeToSlice(&buf, self.data, bincode.Params.standard);
        var sig = try keypair.sign(bytes, null);
        self.signature.data = sig.toBytes();
    }

    pub fn verify(self: *Self, pubkey: Pubkey) !bool {
        // should always be enough space or is invalid msg
        var buf: [PACKET_DATA_SIZE]u8 = undefined;
        var msg = try bincode.writeToSlice(&buf, self.data, bincode.Params.standard);
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
        };
    }
};

// https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds_value.rs#L500
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
};

// https://github.com/solana-labs/solana/blob/e0203f22dc83cb792fa97f91dbe6e924cbd08af1/gossip/src/crds_value.rs#L85
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

    pub fn sanitize(self: *const GossipData) !void {
        switch (self.*) {
            inline .LegacyContactInfo,
            .ContactInfo,
            .AccountsHashes,
            .LegacySnapshotHashes,
            .SnapshotHashes,
            .NodeInstance,
            .Version,
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
            .ContactInfo => |*v| v.getSocket(socket_tag.GOSSIP),
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

pub const LegacyContactInfo = struct {
    id: Pubkey,
    /// gossip address
    gossip: SocketAddr,
    /// address to connect to for replication
    tvu: SocketAddr,
    /// address to forward shreds to
    tvu_forwards: SocketAddr,
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
            .tvu = unspecified_addr,
            .tvu_forwards = unspecified_addr,
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
            .tvu = SocketAddr.random(rng),
            .tvu_forwards = SocketAddr.random(rng),
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
        try ci.setSocket(socket_tag.GOSSIP, self.gossip);
        try ci.setSocket(socket_tag.TVU, self.tvu);
        try ci.setSocket(socket_tag.TVU_FORWARDS, self.tvu_forwards);
        try ci.setSocket(socket_tag.REPAIR, self.repair);
        try ci.setSocket(socket_tag.TPU, self.tpu);
        try ci.setSocket(socket_tag.TPU_FORWARDS, self.tpu_forwards);
        try ci.setSocket(socket_tag.TPU_VOTE, self.tpu_vote);
        try ci.setSocket(socket_tag.RPC, self.rpc);
        try ci.setSocket(socket_tag.RPC_PUBSUB, self.rpc_pubsub);
        try ci.setSocket(socket_tag.SERVE_REPAIR, self.serve_repair);
        return ci;
    }

    pub fn fromContactInfo(ci: *const ContactInfo) LegacyContactInfo {
        return .{
            .id = ci.pubkey,
            .gossip = ci.getSocket(socket_tag.GOSSIP) orelse SocketAddr.UNSPECIFIED,
            .tvu = ci.getSocket(socket_tag.TVU) orelse SocketAddr.UNSPECIFIED,
            .tvu_forwards = ci.getSocket(socket_tag.TVU_FORWARDS) orelse SocketAddr.UNSPECIFIED,
            .repair = ci.getSocket(socket_tag.REPAIR) orelse SocketAddr.UNSPECIFIED,
            .tpu = ci.getSocket(socket_tag.TPU) orelse SocketAddr.UNSPECIFIED,
            .tpu_forwards = ci.getSocket(socket_tag.TPU_FORWARDS) orelse SocketAddr.UNSPECIFIED,
            .tpu_vote = ci.getSocket(socket_tag.TPU_VOTE) orelse SocketAddr.UNSPECIFIED,
            .rpc = ci.getSocket(socket_tag.RPC) orelse SocketAddr.UNSPECIFIED,
            .rpc_pubsub = ci.getSocket(socket_tag.RPC_PUBSUB) orelse SocketAddr.UNSPECIFIED,
            .serve_repair = ci.getSocket(socket_tag.SERVE_REPAIR) orelse SocketAddr.UNSPECIFIED,
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

    pub fn init(from: Pubkey, wallclock: u64) Self {
        var rng = std.rand.DefaultPrng.init(@intCast(std.time.milliTimestamp()));
        return Self{
            .from = from,
            .wallclock = wallclock,
            .timestamp = @intCast(std.time.microTimestamp()),
            .token = rng.random().int(u64),
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

pub const ShredType = enum(u8) {
    Data = 0b1010_0101,
    Code = 0b0101_1010,

    /// Enables bincode deserializer to deserialize this data from a single byte instead of 4.
    pub const BincodeSize = u8;

    /// Enables bincode serializer to serialize this data into a single byte instead of 4.
    pub const @"getty.sb" = struct {
        pub fn serialize(
            allocator: ?std.mem.Allocator,
            value: anytype,
            serializer: anytype,
        ) @TypeOf(serializer).Error!@TypeOf(serializer).Ok {
            _ = allocator;
            return try serializer.serializeInt(@intFromEnum(value));
        }
    };
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

    pub fn random(rng: std.rand.Random) DuplicateShred {
        // NOTE: cant pass around a slice here (since the stack data will get cleared)
        var slice = [0]u8{}; // empty slice
        var num_chunks = rng.intRangeAtMost(u8, 5, 100);
        var chunk_index = rng.intRangeAtMost(u8, 0, num_chunks - 1);

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

    pub fn random(rng: std.rand.Random) SnapshotHashes {
        var slice: [0]SlotAndHash = .{};
        return SnapshotHashes{
            .from = Pubkey.random(rng),
            .full = .{ .slot = rng.int(u64), .hash = Hash.random() },
            .incremental = &slice,
            .wallclock = getWallclockMs(),
        };
    }

    pub fn sanitize(self: *const @This()) !void {
        try sanitizeWallclock(self.wallclock);
        if (self.full[0] >= MAX_SLOT) {
            return error.ValueOutOfBounds;
        }
        for (self.incremental) |inc| {
            if (inc[0] >= MAX_SLOT) {
                return error.ValueOutOfBounds;
            }
            if (self.full[0] >= inc[0]) {
                return error.InvalidValue;
            }
        }
    }
};

pub const socket_tag = struct {
    pub const GOSSIP: u8 = 0;
    pub const REPAIR: u8 = 1;
    pub const RPC: u8 = 2;
    pub const RPC_PUBSUB: u8 = 3;
    pub const SERVE_REPAIR: u8 = 4;
    pub const TPU: u8 = 5;
    pub const TPU_FORWARDS: u8 = 6;
    pub const TPU_FORWARDS_QUIC: u8 = 7;
    pub const TPU_QUIC: u8 = 8;
    pub const TPU_VOTE: u8 = 9;
    pub const TVU: u8 = 10;
    pub const TVU_FORWARDS: u8 = 11;
    pub const TVU_QUIC: u8 = 12;
};
pub const SOCKET_CACHE_SIZE: usize = socket_tag.TVU_QUIC + 1;

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

    pub const @"!bincode-config:cache" = bincode.FieldConfig([SOCKET_CACHE_SIZE]SocketAddr){ .skip = true };
    pub const @"!bincode-config:addrs" = ShortVecArrayListConfig(IpAddr);
    pub const @"!bincode-config:sockets" = ShortVecArrayListConfig(SocketEntry);
    pub const @"!bincode-config:extensions" = ShortVecArrayListConfig(Extension);
    pub const @"!bincode-config:wallclock" = var_int_config_u64;

    const Self = @This();

    pub fn toNodeInstance(self: *Self) NodeInstance {
        return NodeInstance.init(self.Pubkey, @intCast(std.time.milliTimestamp()));
    }

    pub fn deinit(self: Self) void {
        self.addrs.deinit();
        self.sockets.deinit();
        self.extensions.deinit();
    }

    pub fn initSpy(allocator: std.mem.Allocator, id: Pubkey, gossip_socket_addr: SocketAddr, shred_version: u16) !Self {
        var contact_info = Self.init(allocator, id, @intCast(std.time.microTimestamp()), shred_version);
        try contact_info.setSocket(socket_tag.GOSSIP, gossip_socket_addr);
        return contact_info;
    }

    pub fn init(
        allocator: std.mem.Allocator,
        pubkey: Pubkey,
        wallclock: u64,
        shred_version: u16,
    ) Self {
        var outset = @as(u64, @intCast(std.time.microTimestamp()));
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
            sockets.append(.{ .key = 10, .index = 20, .offset = 30 }) catch unreachable;
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

    pub fn getSocket(self: *const Self, key: u8) ?SocketAddr {
        if (self.cache[key].eql(&SocketAddr.UNSPECIFIED)) {
            return null;
        }
        return self.cache[key];
    }

    pub fn setSocket(self: *Self, key: u8, socket_addr: SocketAddr) !void {
        self.removeSocket(key);

        var offset = socket_addr.port();
        var index: ?usize = null;
        for (self.sockets.items, 0..) |socket, idx| {
            offset = std.math.sub(u16, offset, socket.offset) catch {
                index = idx;
                break;
            };
        }

        var entry = SocketEntry.init(key, try self.pushAddr(socket_addr.ip()), offset);

        if (index) |i| {
            self.sockets.items[i].offset -= entry.offset;
            try self.sockets.insert(i, entry);
        } else {
            try self.sockets.append(entry);
        }

        self.cache[key] = socket_addr;
    }

    pub fn removeSocket(self: *Self, key: u8) void {
        // find existing socket index
        var existing_socket_index: ?usize = null;
        for (self.sockets.items, 0..) |socket, idx| {
            if (socket.key == key) {
                existing_socket_index = idx;
                break;
            }
        }
        // if found, remove it, it's associated IpAddr, set cache[key] to unspecified
        if (existing_socket_index) |index| {
            // first we remove this existing socket
            var removed_entry = self.sockets.orderedRemove(index);
            // reset the socket entry offset
            if (index < self.sockets.items.len - 1) {
                var next_entry = self.sockets.items[index];
                next_entry.offset += removed_entry.offset;
            }
            self.removeAddrIfUnused(removed_entry.index);
            self.cache[key] = SocketAddr.unspecified();
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
    tvu: network.EndPoint,
    tvu_forwards: network.EndPoint,
    tvu_quic: network.EndPoint,
};

const Sockets = struct {
    gossip: UdpSocket,
    ip_echo: ?TcpListener,
    tvu: ArrayList(UdpSocket),
    tvu_forwards: ArrayList(UdpSocket),
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
    key: u8, // GossipMessageidentifier, e.g. tvu, tpu, etc
    index: u8, // IpAddr index in the accompanying addrs vector.
    offset: u16, // Port offset with respect to the previous entry.

    pub const @"!bincode-config:offset" = var_int_config_u16;

    const Self = @This();

    pub fn init(key: u8, index: u8, offset: u16) Self {
        return Self{
            .key = key,
            .index = index,
            .offset = offset,
        };
    }

    pub fn eql(self: *const Self, other: *const Self) bool {
        return self.key == other.key and
            self.index == other.index and
            self.offset == other.offset;
    }
};

fn socket_addrs_unspecified() [13]SocketAddr {
    return .{
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
        SocketAddr.unspecified(),
    };
}

test "gossip.data: new contact info" {
    var seed: u64 = @intCast(std.time.milliTimestamp());
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
    var bytes = try bincode.writeToSlice(buf[0..], tmp, bincode.Params.standard);

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
    var seed: u64 = @intCast(std.time.milliTimestamp());
    var rand = std.rand.DefaultPrng.init(seed);
    const rng = rand.random();

    var ci = ContactInfo.init(testing.allocator, Pubkey.random(rng), @as(u64, @intCast(std.time.microTimestamp())), 0);
    defer ci.deinit();
    try ci.setSocket(socket_tag.RPC, SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8899));

    var set_socket = ci.getSocket(socket_tag.RPC);
    try testing.expect(set_socket.?.eql(&SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8899)));
    try testing.expect(ci.addrs.items[0].eql(&IpAddr.newIpv4(127, 0, 0, 1)));
    try testing.expect(ci.sockets.items[0].eql(&SocketEntry.init(socket_tag.RPC, 0, 8899)));
}

test "gossip.data: contact info bincode serialize matches rust bincode" {
    var rust_contact_info_serialized_bytes = [_]u8{
        57,  54, 18,  6,  106, 202, 13, 245, 224, 235, 33,  252, 254, 251, 161, 17, 248, 108, 25,  214, 169,
        154, 91, 101, 17, 121, 235, 82, 175, 197, 144, 145, 100, 200, 0,   0,   0,  0,   0,   0,   0,   44,
        1,   1,  2,   3,  4,   0,   0,  0,   5,   0,   0,   0,   6,   4,   0,   0,  0,   0,   127, 0,   0,
        1,   0,  0,   0,  0,   127, 0,  0,   1,   0,   0,   0,   0,   127, 0,   0,  1,   0,   0,   0,   0,
        127, 0,  0,   1,  6,   10,  20, 30,  10,  20,  30,  10,  20,  30,  10,  20, 30,  10,  20,  30,  10,
        20,  30, 0,
    };

    var pubkey = Pubkey.fromString("4rL4RCWHz3iNCdCaveD8KcHfV9YWGsqSHFPo7X2zBNwa") catch unreachable;
    var ci = ContactInfo.initDummyForTest(testing.allocator, pubkey, 100, 200, 300);
    defer ci.deinit();

    var buf = std.ArrayList(u8).init(testing.allocator);
    bincode.write(null, buf.writer(), ci, bincode.Params.standard) catch unreachable;
    defer buf.deinit();

    try testing.expect(std.mem.eql(u8, &rust_contact_info_serialized_bytes, buf.items));

    var stream = std.io.fixedBufferStream(buf.items);
    var ci2 = try bincode.read(testing.allocator, ContactInfo, stream.reader(), bincode.Params.standard);
    defer bincode.free(testing.allocator, ci2);

    try testing.expect(ci2.addrs.items.len == 4);
    try testing.expect(ci2.sockets.items.len == 6);
    try testing.expect(ci2.pubkey.equals(&ci.pubkey));
    try testing.expect(ci2.outset == ci.outset);
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
    var ci2 = try bincode.read(testing.allocator, ContactInfo, stream.reader(), bincode.Params.standard);
    defer bincode.free(testing.allocator, ci2);

    var buf = std.ArrayList(u8).init(testing.allocator);
    bincode.write(null, buf.writer(), ci2, bincode.Params.standard) catch unreachable;
    defer buf.deinit();

    try testing.expect(std.mem.eql(u8, buf.items, &contact_info_bytes_from_mainnet));
}

test "gossip.data: SocketEntry serializer works" {
    testing.log_level = .debug;

    var se = SocketEntry.init(3, 3, 30304);

    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();
    try bincode.write(null, buf.writer(), se, bincode.Params.standard);

    var stream = std.io.fixedBufferStream(buf.items);
    var other_se = try bincode.read(testing.allocator, SocketEntry, stream.reader(), bincode.Params.standard);

    try testing.expect(other_se.index == se.index);
    try testing.expect(other_se.key == se.key);
    try testing.expect(other_se.offset == se.offset);
}

test "gossip.data: test sig verify duplicateShreds" {
    var keypair = try KeyPair.create([_]u8{1} ** 32);
    var pubkey = Pubkey.fromPublicKey(&keypair.public_key);
    var rng = std.rand.DefaultPrng.init(0);
    var data = DuplicateShred.random(rng.random());
    data.from = pubkey;

    var value = try SignedGossipData.initSigned(GossipData{ .DuplicateShred = .{ 0, data } }, &keypair);

    try std.testing.expect(try value.verify(pubkey));
}

test "gossip.data: test sanitize GossipData" {
    var rng = std.rand.DefaultPrng.init(0);
    var rand = rng.random();

    for (0..4) |i| {
        const data = GossipData.randomFromIndex(rand, i);
        data.sanitize() catch {};
    }
}

test "gossip.data: test SignedGossipData label() and id() methods" {
    var kp_bytes = [_]u8{1} ** 32;
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
    var kp_bytes = [_]u8{1} ** 32;
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

    var out = try bincode.readFromSlice(std.testing.allocator, Pubkey, buf[0..], bincode.Params.standard);
    try std.testing.expectEqual(id, out);
}

test "gossip.data: contact info serialization matches rust" {
    var kp_bytes = [_]u8{1} ** 32;
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

test "gossip.data: gossip data serialization matches rust" {
    var kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    const id = Pubkey.fromPublicKey(&pk);

    const gossip_addr = SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 1234);

    var legacy_contact_info = LegacyContactInfo.default(id);
    legacy_contact_info.gossip = gossip_addr;
    legacy_contact_info.wallclock = 0;

    var gossip_data = GossipData{
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
    var seed: u64 = @intCast(std.time.milliTimestamp());
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
    var seed: u64 = @intCast(std.time.milliTimestamp());
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
    instance.full[0] = 1000;
    const data = GossipData{ .SnapshotHashes = instance };
    try data.sanitize();
}

test "gossip.data: sanitize invalid SnapshotHashes full slot has error" {
    var rand = std.rand.DefaultPrng.init(524145234);
    const rng = rand.random();
    var instance = SnapshotHashes.random(rng);
    instance.full[0] = 1_000_000_000_487_283;
    const data = GossipData{ .SnapshotHashes = instance };
    if (data.sanitize()) |_| return error.ExpectedError else |_| {}
}

test "gossip.data: sanitize invalid SnapshotHashes incremental slot has error" {
    var rand = std.rand.DefaultPrng.init(524145234);
    const rng = rand.random();
    var incremental: [1]struct { Slot, Hash } = .{.{ 1_000_000_000_487_283, Hash.default() }};
    var instance = SnapshotHashes.random(rng);
    instance.incremental = &incremental;
    const data = GossipData{ .SnapshotHashes = instance };
    if (data.sanitize()) |_| return error.ExpectedError else |_| {}
}

test "gossip.data: sanitize SnapshotHashes full > incremental has error" {
    var rand = std.rand.DefaultPrng.init(524145234);
    const rng = rand.random();
    var incremental: [1]struct { Slot, Hash } = .{.{ 1, Hash.default() }};
    var instance = SnapshotHashes.random(rng);
    instance.full[0] = 2;
    instance.incremental = &incremental;
    const data = GossipData{ .SnapshotHashes = instance };
    if (data.sanitize()) |_| return error.ExpectedError else |_| {}
}
