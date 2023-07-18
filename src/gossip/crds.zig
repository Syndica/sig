const std = @import("std");
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const SocketAddr = @import("net.zig").SocketAddr;
const Tuple = std.meta.Tuple;
const Hash = @import("../core/hash.zig").Hash;
const Signature = @import("../core/signature.zig").Signature;
const Transaction = @import("../core/transaction.zig").Transaction;
const Slot = @import("../core/slot.zig").Slot;
const Option = @import("../option.zig").Option;
const ContactInfo = @import("node.zig").ContactInfo;
const bincode = @import("bincode-zig");
const AutoArrayHashMap = std.AutoArrayHashMap;
const ArrayList = std.ArrayList;
const ArrayListConfig = @import("../utils/arraylist.zig").ArrayListConfig;
const Bloom = @import("../bloom/bloom.zig").Bloom;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

/// Cluster Replicated Data Store
pub const Crds = struct {
    store: AutoArrayHashMap(CrdsValueLabel, CrdsVersionedValue),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{ .store = AutoArrayHashMap(CrdsValueLabel, CrdsVersionedValue).init(allocator) };
    }

    pub fn deinit(self: *Self) void {
        self.store.deinit();
    }
};

pub const CrdsFilter = struct {
    filter: Bloom,
    mask: u64,
    mask_bits: u32,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .filter = Bloom.init(allocator, 0),
            .mask = 18_446_744_073_709_551_615,
            .mask_bits = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        self.filter.deinit();
    }
};

pub const CrdsVersionedValue = struct {
    value: CrdsValue,
    local_timestamp: u64,
    value_hash: Hash,
    /// Number of times duplicates of this value are recevied from gossip push.
    num_push_dups: u8,
};

pub const CrdsValue = struct {
    signature: Signature,
    data: CrdsData,

    const Self = @This();

    pub fn init(data: CrdsData) Self {
        return Self{
            .signature = Signature{},
            .data = data,
        };
    }

    pub fn initSigned(data: CrdsData, keypair: KeyPair) !Self {
        var self = Self{
            .signature = Signature{},
            .data = data,
        };
        try self.sign(keypair);
        return self;
    }

    pub fn sign(self: *Self, keypair: KeyPair) !void {
        var buf = [_]u8{0} ** 1500;
        var bytes = try bincode.writeToSlice(&buf, self.data, bincode.Params.standard);
        var sig = try keypair.sign(bytes, null);
        self.signature.data = sig.toBytes();
    }

    pub fn verify(self: *Self, pubkey: Pubkey) !bool {
        var buf = [_]u8{0} ** 1500;
        var msg = try bincode.writeToSlice(buf[0..], self.data, bincode.Params.standard);
        return self.signature.verify(pubkey, msg);
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
};

pub const CrdsValueLabel = union(enum) {
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

pub const CrdsData = union(enum(u32)) {
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
};

pub const Vote = struct {
    from: Pubkey,
    transaction: Transaction,
    wallclock: u64,
    slot: Slot = Slot.default(),

    pub const @"!bincode-config:slot" = bincode.FieldConfig{ .skip = true };
};

pub const LowestSlot = struct {
    from: Pubkey,
    root: u64, //deprecated
    lowest: u64,
    slots: []u64, //deprecated
    stash: []DeprecatedEpochIncompleteSlots, //deprecated
    wallclock: u64,
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

pub const AccountsHashes = struct {
    from: Pubkey,
    hashes: []struct { u64, Hash },
    wallclock: u64,
};

pub const EpochSlots = struct {
    from: Pubkey,
    slots: []CompressedSlots,
    wallclock: u64,
};

pub const CompressedSlots = union(enum(u32)) {
    Flate2: Flate2,
    Uncompressed: Uncompressed,
};

pub const Flate2 = struct {
    first_slot: Slot,
    num: usize,
    compressed: []u8,
};

pub const Uncompressed = struct {
    first_slot: Slot,
    num: usize,
    slots: BitVec(u8),
};

pub fn BitVec(comptime T: type) type {
    return struct {
        bits: Option([]T),
        len: usize,
    };
}

pub const LegacyVersion = struct {
    from: Pubkey,
    wallclock: u64,
    version: LegacyVersion1,
};

pub const LegacyVersion1 = struct {
    major: u16,
    minor: u16,
    patch: u16,
    commit: Option(u32), // first 4 bytes of the sha1 commit hash
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
            .wallclock = @intCast(std.time.milliTimestamp()),
            .version = LegacyVersion2.CURRENT,
        };
    }
};

pub const LegacyVersion2 = struct {
    major: u16,
    minor: u16,
    patch: u16,
    commit: Option(u32), // first 4 bytes of the sha1 commit hash
    feature_set: u32, // first 4 bytes of the FeatureSet identifier

    const Self = @This();

    pub const CURRENT = LegacyVersion2.init(1, 14, 17, Option(u32).Some(2996451279), 3488713414);

    pub fn init(major: u16, minor: u16, patch: u16, commit: Option(u32), feature_set: u32) Self {
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
};

pub const ShredType = enum(u32) {
    Data = 0b1010_0101,
    Code = 0b0101_1010,
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
};

pub const SnapshotHashes = struct {
    from: Pubkey,
    full: struct { Slot, Hash },
    incremental: []struct { Slot, Hash },
    wallclock: u64,
};
