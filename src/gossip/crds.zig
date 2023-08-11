const std = @import("std");
const SocketAddr = @import("net.zig").SocketAddr;
const Tuple = std.meta.Tuple;
const Hash = @import("../core/hash.zig").Hash;
const Signature = @import("../core/signature.zig").Signature;
const Transaction = @import("../core/transaction.zig").Transaction;
const Slot = @import("../core/slot.zig").Slot;
const Option = @import("../option.zig").Option;
const ContactInfo = @import("node.zig").ContactInfo;
const bincode = @import("../bincode/bincode.zig");
const ArrayList = std.ArrayList;
const ArrayListConfig = @import("../utils/arraylist.zig").ArrayListConfig;
const Bloom = @import("../bloom/bloom.zig").Bloom;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;

pub fn get_wallclock() u64 {
    return @intCast(std.time.milliTimestamp());
}

pub const CrdsVersionedValue = struct {
    value: CrdsValue,
    value_hash: Hash,
    timestamp_on_insertion: u64,
    cursor_on_insertion: u64,
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

    pub fn random(rng: std.rand.Random, keypair: KeyPair) !Self {
        return try Self.initSigned(CrdsData.random(rng), keypair);
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

    pub fn label(self: *const Self) CrdsValueLabel {
        return switch (self.data) {
            .LegacyContactInfo => {
                return CrdsValueLabel{ .LegacyContactInfo = self.id() };
            },
            .Vote => |*v| {
                return CrdsValueLabel{ .Vote = .{ v[0], self.id() } };
            },
            .LowestSlot => {
                return CrdsValueLabel{ .LowestSlot = self.id() };
            },
            .LegacySnapshotHashes => {
                return CrdsValueLabel{ .LegacySnapshotHashes = self.id() };
            },
            .AccountsHashes => {
                return CrdsValueLabel{ .AccountsHashes = self.id() };
            },
            .EpochSlots => |*v| {
                return CrdsValueLabel{ .EpochSlots = .{ v[0], self.id() } };
            },
            .LegacyVersion => {
                return CrdsValueLabel{ .LegacyVersion = self.id() };
            },
            .Version => {
                return CrdsValueLabel{ .Version = self.id() };
            },
            .NodeInstance => {
                return CrdsValueLabel{ .NodeInstance = self.id() };
            },
            .DuplicateShred => |*v| {
                return CrdsValueLabel{ .DuplicateShred = .{ v[0], self.id() } };
            },
            .SnapshotHashes => {
                return CrdsValueLabel{ .SnapshotHashes = self.id() };
            },
            .ContactInfo => {
                return CrdsValueLabel{ .ContactInfo = self.id() };
            },
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

    pub fn default() LegacyContactInfo {
        const unspecified_addr = SocketAddr.init_ipv4(.{ 0, 0, 0, 0 }, 0);
        const wallclock = get_wallclock();

        var seed: u64 = @intCast(std.time.milliTimestamp());
        var rand = std.rand.DefaultPrng.init(seed);
        const rng = rand.random();

        return LegacyContactInfo{
            .id = Pubkey.random(rng, .{ .skip_encoding = true }),
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
            .id = Pubkey.random(rng, .{ .skip_encoding = true }),
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
            .wallclock = get_wallclock(),
            .shred_version = rng.int(u16),
        };
    }
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

    pub fn random(rng: std.rand.Random) CrdsData {
        const v = rng.intRangeAtMost(u16, 0, 3);
        switch (v) {
            0 => {
                return CrdsData{ .LegacyContactInfo = LegacyContactInfo.random(rng) };
            },
            1 => {
                return CrdsData{ .EpochSlots = .{ rng.int(u8), EpochSlots.random(rng) } };
            },
            2 => {
                return CrdsData{ .Vote = .{ rng.int(u8), Vote.random(rng) } };
            },
            else => {
                return CrdsData{ .DuplicateShred = .{ rng.int(u16), DuplicateShred.random(rng) } };
            },
        }
    }
};

pub const Vote = struct {
    from: Pubkey,
    transaction: Transaction,
    wallclock: u64,
    slot: Slot = Slot.default(),

    pub const @"!bincode-config:slot" = bincode.FieldConfig(Slot){ .skip = true };

    pub fn random(rng: std.rand.Random) Vote {
        return Vote{
            .from = Pubkey.random(rng, .{ .skip_encoding = true }),
            .transaction = Transaction.default(),
            .wallclock = get_wallclock(),
            .slot = Slot.init(rng.int(u64)),
        };
    }
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

    pub fn random(rng: std.rand.Random) EpochSlots {
        var slice: [0]CompressedSlots = .{};
        return EpochSlots{
            .from = Pubkey.random(rng, .{ .skip_encoding = true }),
            .slots = &slice,
            .wallclock = get_wallclock(),
        };
    }
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
            .wallclock = get_wallclock(),
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

    pub fn random(rng: std.rand.Random) DuplicateShred {
        var slice = [_]u8{0} ** 32;
        return DuplicateShred{
            .from = Pubkey.random(rng, .{ .skip_encoding = true }),
            .wallclock = get_wallclock(),
            .slot = Slot.init(rng.int(u64)),
            .shred_index = rng.int(u32),
            .shred_type = ShredType.Data,
            .num_chunks = rng.int(u8),
            .chunk_index = rng.int(u8),
            .chunk = &slice,
        };
    }
};

pub const SnapshotHashes = struct {
    from: Pubkey,
    full: struct { Slot, Hash },
    incremental: []struct { Slot, Hash },
    wallclock: u64,
};

test "gossip.crds: test CrdsValue label() and id() methods" {
    var kp_bytes = [_]u8{1} ** 32;
    var kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    var id = Pubkey.fromPublicKey(&pk, true);

    var legacy_contact_info = LegacyContactInfo.default();
    legacy_contact_info.id = id;
    legacy_contact_info.wallclock = 0;

    var crds_value = try CrdsValue.initSigned(CrdsData{
        .LegacyContactInfo = legacy_contact_info,
    }, kp);

    try std.testing.expect(crds_value.id().equals(&id));
    try std.testing.expect(crds_value.label().LegacyContactInfo.equals(&id));
}

test "gossip.crds: pubkey matches rust" {
    var kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    const id = Pubkey.fromPublicKey(&pk, true);

    const rust_bytes = [_]u8{ 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92 };
    var buf = [_]u8{0} ** 1024;
    var bytes = try bincode.writeToSlice(buf[0..], id, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, rust_bytes[0..], bytes[0..bytes.len]);

    var out = try bincode.readFromSlice(std.testing.allocator, Pubkey, buf[0..], bincode.Params.standard);
    try std.testing.expectEqual(id, out);
}

test "gossip.crds: contact info serialization matches rust" {
    var kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    const id = Pubkey.fromPublicKey(&pk, true);

    const gossip_addr = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 1234);

    var buf = [_]u8{0} ** 1024;

    var legacy_contact_info = LegacyContactInfo.default();
    legacy_contact_info.gossip = gossip_addr;
    legacy_contact_info.id = id;
    legacy_contact_info.wallclock = 0;

    var contact_info_rust = [_]u8{ 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92, 0, 0, 0, 0, 127, 0, 0, 1, 210, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var bytes = try bincode.writeToSlice(buf[0..], legacy_contact_info, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, bytes[0..bytes.len], &contact_info_rust);
}

test "gossip.crds: crds data serialization matches rust" {
    var kp_bytes = [_]u8{1} ** 32;
    const kp = try KeyPair.create(kp_bytes);
    const pk = kp.public_key;
    const id = Pubkey.fromPublicKey(&pk, true);

    const gossip_addr = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 1234);

    var legacy_contact_info = LegacyContactInfo.default();
    legacy_contact_info.gossip = gossip_addr;
    legacy_contact_info.id = id;
    legacy_contact_info.wallclock = 0;

    var crds_data = CrdsData{
        .LegacyContactInfo = legacy_contact_info,
    };

    var buf = [_]u8{0} ** 1024;
    var rust_crds_data = [_]u8{ 0, 0, 0, 0, 138, 136, 227, 221, 116, 9, 241, 149, 253, 82, 219, 45, 60, 186, 93, 114, 202, 103, 9, 191, 29, 148, 18, 27, 243, 116, 136, 1, 180, 15, 111, 92, 0, 0, 0, 0, 127, 0, 0, 1, 210, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    var bytes = try bincode.writeToSlice(buf[0..], crds_data, bincode.Params.standard);
    try std.testing.expectEqualSlices(u8, bytes[0..bytes.len], rust_crds_data[0..bytes.len]);
}

test "gossip.crds: random crds data" {
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
        const data = CrdsData.random(rng);
        const result = try bincode.writeToSlice(&buf, data, bincode.Params.standard);
        _ = result;
    }
}
