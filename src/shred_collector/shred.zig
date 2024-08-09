const std = @import("std");
const sig = @import("../lib.zig");

const bincode = sig.bincode;

const Allocator = std.mem.Allocator;

const BitFlags = sig.utils.bitflags.BitFlags;
const Hash = sig.core.Hash;
const Nonce = sig.core.Nonce;
const Packet = sig.net.Packet;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;

const checkedAdd = sig.utils.math.checkedAdd;
const checkedSub = sig.utils.math.checkedSub;

const SIGNATURE_LENGTH = sig.core.SIGNATURE_LENGTH;

pub const MAX_SHREDS_PER_SLOT: usize = coding_shred.max_per_slot + data_shred.max_per_slot;

const DATA_SHREDS_PER_FEC_BLOCK: usize = 32;
const SIZE_OF_MERKLE_ROOT: usize = sig.core.HASH_SIZE;

pub const coding_shred = ShredConstants{
    .max_per_slot = 32_768,
    .payload_size = 1228, // TODO this can be calculated like solana
    .headers_size = 89,
};

pub const data_shred = ShredConstants{
    .max_per_slot = 32_768,
    .payload_size = 1203, // TODO this can be calculated like solana
    .headers_size = 88,
};

/// Analogous to [Shred](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/ledger/src/shred.rs#L245)
pub const Shred = union(ShredType) {
    Code: CodingShred,
    Data: DataShred,

    const Self = @This();

    pub fn deinit(self: Self) void {
        return switch (self) {
            inline .Code, .Data => |s| s.fields.deinit(),
        };
    }

    pub fn fromPayload(allocator: Allocator, payload_: []const u8) !Self {
        const variant = layout.getShredVariant(payload_) orelse return error.InvalidShredVariant;
        return switch (variant.shred_type) {
            .Code => .{ .Code = .{ .fields = try CodingShred.Fields.fromPayload(allocator, payload_) } },
            .Data => .{ .Data = .{ .fields = try DataShred.Fields.fromPayload(allocator, payload_) } },
        };
    }

    pub fn payload(self: Self) []const u8 {
        return switch (self) {
            inline .Code, .Data => |shred| shred.fields.payload,
        };
    }

    pub fn commonHeader(self: *const Self) *const CommonHeader {
        return switch (self.*) {
            inline .Code, .Data => |c| &c.fields.common,
        };
    }

    pub fn sanitize(self: *const Self) !void {
        if (self.commonHeader().shred_variant.shred_type != self) {
            return error.InconsistentShredVariant;
        }
        switch (self.*) {
            inline .Code, .Data => |s| try s.sanitize(),
        }
    }

    pub fn merkleRoot(self: Self) !Hash {
        return switch (self) {
            inline .Code, .Data => |s| getMerkleRoot(
                s.fields.payload,
                @TypeOf(s.fields).constants,
                s.fields.common.shred_variant,
            ),
        };
    }

    pub fn chainedMerkleRoot(self: Self) !Hash {
        return switch (self) {
            inline .Code, .Data => |s| layout.getChainedMerkleRoot(s.fields.payload) orelse
                error.InvalidPayloadSize,
        };
    }

    pub fn isLastInSlot(self: *const Self) bool {
        return switch (self.*) {
            .Code => false,
            .Data => |data| data.fields.custom.flags.isSet(.last_shred_in_slot),
        };
    }

    pub fn verify(self: Self, signer: sig.core.Pubkey) bool {
        return switch (self) {
            inline .Data, .Code => |s| s.fields.verify(signer),
        };
    }
};

/// Analogous to [ShredCode](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/shred/merkle.rs#L74)
pub const CodingShred = struct {
    fields: Fields,
    const Fields = GenericShred(CodingShredHeader, coding_shred);

    const Self = @This();
    const consts = coding_shred;

    pub fn sanitize(self: *const Self) !void {
        try self.fields.sanitize();
        if (self.fields.custom.num_coding_shreds > 8 * DATA_SHREDS_PER_FEC_BLOCK) {
            return error.InvalidNumCodingShreds;
        }
        _ = try self.erasureShardIndex();
    }

    pub fn erasureShardIndex(self: *const Self) !usize {
        // Assert that the last shred index in the erasure set does not
        // overshoot MAX_{DATA,CODE}_SHREDS_PER_SLOT.
        if (try checkedAdd(
            self.fields.common.fec_set_index,
            try checkedSub(@as(u32, @intCast(self.fields.custom.num_data_shreds)), 1),
        ) >= data_shred.max_per_slot) {
            return error.InvalidErasureShardIndex;
        }
        if (try checkedAdd(
            try self.firstCodingIndex(),
            try checkedSub(@as(u32, @intCast(self.fields.custom.num_coding_shreds)), 1),
        ) >= coding_shred.max_per_slot) {
            return error.InvalidErasureShardIndex;
        }
        const num_data_shreds: usize = @intCast(self.fields.custom.num_data_shreds);
        const num_coding_shreds: usize = @intCast(self.fields.custom.num_coding_shreds);
        const position: usize = @intCast(self.fields.custom.position);
        const fec_set_size = try checkedAdd(num_data_shreds, num_coding_shreds);
        const index = try checkedAdd(position, num_data_shreds);
        return if (index < fec_set_size) index else error.InvalidErasureShardIndex;
    }

    pub fn firstCodingIndex(self: *const Self) !u32 {
        return sig.utils.math.checkedSub(
            self.fields.common.index,
            @as(u32, @intCast(self.fields.custom.position)),
        );
    }
};

/// Analogous to [ShredData](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/shred/merkle.rs#L61)
pub const DataShred = struct {
    fields: Fields,
    const Fields = GenericShred(DataShredHeader, data_shred);

    const Self = @This();
    const consts = data_shred;

    pub fn sanitize(self: *const Self) !void {
        try self.fields.sanitize();
        // see ShredFlags comptime block for omitted check that is guaranteed at comptime.
        _ = try self.data();
        _ = try self.parent();
    }

    fn data(self: *const Self) ![]const u8 {
        const data_buffer_size = try capacity(consts, self.fields.common.shred_variant);
        const size = self.fields.custom.size;
        if (size > self.fields.payload.len or
            size < consts.headers_size or
            size > consts.headers_size + data_buffer_size)
        {
            return error.InvalidDataSize;
        }

        return self.fields.payload[consts.headers_size..size];
    }

    pub fn parent(self: *const Self) error{InvalidParentOffset}!Slot {
        const slot = self.fields.common.slot;
        if (self.fields.custom.parent_offset == 0 and slot != 0) {
            return error.InvalidParentOffset;
        }
        return checkedSub(slot, self.fields.custom.parent_offset) catch error.InvalidParentOffset;
    }

    pub fn erasureShardIndex(self: *const Self) error{IntegerOverflow}!usize {
        return @intCast(try checkedSub(self.fields.common.index, self.fields.common.fec_set_index));
    }

    pub fn dataComplete(self: Self) bool {
        return self.fields.custom.flags.isSet(.data_complete_shred);
    }

    pub fn isLastInSlot(self: Self) bool {
        return self.fields.custom.flags.isSet(.last_shred_in_slot);
    }

    pub fn referenceTick(self: Self) u8 {
        return self.fields.custom.flags
            .intersection(.shred_tick_reference_mask).state;
    }
};

/// Analogous to [Shred trait](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/ledger/src/shred/traits.rs#L6)
pub fn GenericShred(
    comptime CustomHeader: type,
    constants_: ShredConstants,
) type {
    return struct {
        common: CommonHeader,
        custom: CustomHeader,
        allocator: Allocator,
        payload: []const u8,

        const Self = @This();

        pub const constants = constants_;

        pub fn deinit(self: Self) void {
            self.allocator.free(self.payload);
        }

        pub fn fromPayload(allocator: Allocator, payload: []const u8) !Self {
            if (payload.len < constants.payload_size) {
                return error.InvalidPayloadSize;
            }
            const owned_payload = try allocator.alloc(u8, constants.payload_size);

            // TODO: It would be nice to find a way to get the payload in here without coping the entire thing.
            // The challenge is that the input payload is owned by the original packet list which was read
            // from the socket, and that list may be cluttered with a lot of garbage data.
            // So a copy like this may be needed somewhere. but it's worth some more thought.
            @memcpy(owned_payload, payload[0..constants.payload_size]);

            var buf = std.io.fixedBufferStream(payload[0..constants.payload_size]);
            const self = Self{
                .allocator = allocator,
                .common = try bincode.read(allocator, CommonHeader, buf.reader(), .{}),
                .custom = try bincode.read(allocator, CustomHeader, buf.reader(), .{}),
                .payload = owned_payload,
            };

            try self.sanitize();
            return self;
        }

        fn sanitize(self: *const Self) !void {
            _ = try self.merkleProof();

            if (self.common.index > constants.max_per_slot) {
                return error.InvalidShredIndex;
            }
            if (constants.payload_size != self.payload.len) {
                return error.InvalidPayloadSize;
            }
        }

        /// Unique identifier for each shred.
        pub fn id(self: *const Self) ShredId {
            return .{
                .slot = self.common.slot,
                .index = self.common.index,
                .shred_type = self.common.shred_variant.shred_type,
            };
        }

        /// The return contains a pointer to data owned by the shred.
        fn merkleProof(self: *const Self) !MerkleProofEntryList {
            return getMerkleProof(self.payload, constants, self.common.shred_variant);
        }

        fn erasureShardAsSlice(self: *const Self) ![]u8 {
            if (self.payload.len() != self.constants().payload_size) {
                return error.InvalidPayloadSize;
            }
            const end = constants.headers_size +
                try capacity(self.common.shred_variant) +
                SIGNATURE_LENGTH;
            if (self.payload.len < end) {
                return error.InsufficientPayloadSize;
            }
            return self.payload[SIGNATURE_LENGTH..end];
        }

        fn verify(self: Self, signer: sig.core.Pubkey) bool {
            const signed_data = self.merkleRoot() catch return false;
            const signature = layout.getSignature(self.payload) orelse return false;
            return signature.verify(signer, &signed_data.data);
        }

        /// this is the data that is signed by the signature
        pub fn merkleRoot(self: Self) !Hash {
            return getMerkleRoot(self.payload, constants, self.common.shred_variant);
        }
    };
}

pub const ShredId = struct {
    slot: Slot,
    index: u32,
    shred_type: sig.shred_collector.shred.ShredType,
};

pub const ErasureSetId = struct {
    slot: Slot,
    fec_set_index: u64,
};

fn getMerkleRoot(
    shred: []const u8,
    constants: ShredConstants,
    variant: ShredVariant,
) !Hash {
    const index = switch (variant.shred_type) {
        .Code => codeIndex(shred) orelse return error.InvalidErasureShardIndex,
        .Data => dataIndex(shred) orelse return error.InvalidErasureShardIndex,
    };
    const proof = try getMerkleProof(shred, constants, variant);
    const offset = try proofOffset(constants, variant);
    const node = try getMerkleNode(shred, SIGNATURE_LENGTH, offset);
    return calculateMerkleRoot(index, node, proof);
}

fn getMerkleProof(
    shred: []const u8,
    constants: ShredConstants,
    variant: ShredVariant,
) !MerkleProofEntryList {
    const size = variant.proof_size * merkle_proof_entry_size;
    const offset = try proofOffset(constants, variant);
    const end = offset + size;
    if (shred.len < end) {
        return error.InsufficentPayloadSize;
    }
    return .{
        .bytes = shred[offset..end],
        .len = variant.proof_size,
    };
}

fn getMerkleNode(shred: []const u8, start: usize, end: usize) !Hash {
    if (shred.len < end) return error.InvalidPayloadSize;
    return hashv(&.{ MERKLE_HASH_PREFIX_LEAF, shred[start..end] });
}

/// [get_merkle_root](https://github.com/anza-xyz/agave/blob/ed500b5afc77bc78d9890d96455ea7a7f28edbf9/ledger/src/shred/merkle.rs#L702)
fn calculateMerkleRoot(start_index: usize, start_node: Hash, proof: MerkleProofEntryList) !Hash {
    var index = start_index;
    var node = start_node;
    var iterator = proof.iterator();
    while (iterator.next()) |other| {
        node = if (index % 2 == 0)
            joinNodes(&node.data, &other)
        else
            joinNodes(&other, &node.data);
        index = index >> 1;
    }
    if (index != 0) return error.InvalidMerkleProof;
    return node;
}

const MERKLE_HASH_PREFIX_LEAF: *const [26]u8 = "\x00SOLANA_MERKLE_SHREDS_LEAF";
const MERKLE_HASH_PREFIX_NODE: *const [26]u8 = "\x01SOLANA_MERKLE_SHREDS_NODE";

fn joinNodes(lhs: []const u8, rhs: []const u8) Hash {
    // TODO check
    return hashv(&.{
        MERKLE_HASH_PREFIX_NODE,
        lhs[0..merkle_proof_entry_size],
        rhs[0..merkle_proof_entry_size],
    });
}

pub fn hashv(vals: []const []const u8) Hash {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    for (vals) |val| hasher.update(val);
    return .{ .data = hasher.finalResult() };
}

/// Where the merkle proof starts in the shred binary.
fn proofOffset(constants: ShredConstants, variant: ShredVariant) !usize {
    return constants.headers_size +
        try capacity(constants, variant) +
        if (variant.chained) SIZE_OF_MERKLE_ROOT else 0;
}

/// Analogous to [get_chained_merkle_root_offset](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/shred/merkle.rs#L364)
pub fn getChainedMerkleRootOffset(variant: ShredVariant) !usize {
    const constants = variant.shred_type.constants();
    if (!variant.chained) {
        return error.InvalidShredVariant;
    }
    return constants.headers_size + try capacity(constants, variant);
}

fn capacity(constants: ShredConstants, variant: ShredVariant) !usize {
    std.debug.assert(variant.chained or !variant.resigned);
    return checkedSub(
        constants.payload_size,
        constants.headers_size +
            if (variant.chained) SIZE_OF_MERKLE_ROOT else 0 +
            variant.proof_size * merkle_proof_entry_size +
            if (variant.resigned) SIGNATURE_LENGTH else 0,
    ) catch error.InvalidProofSize;
}

/// Shred index in the erasure batch.
/// This only works for coding shreds.
fn codeIndex(shred: []const u8) ?usize {
    const num_data_shreds: usize = @intCast(getInt(u16, shred, 83) orelse return null);
    const position: usize = @intCast(getInt(u16, shred, 87) orelse return null);
    return checkedAdd(num_data_shreds, position) catch null;
}

/// Shred index in the erasure batch
/// This only works for data shreds.
fn dataIndex(shred: []const u8) ?usize {
    const fec_set_index = getInt(u32, shred, 79) orelse return null;
    const layout_index = layout.getIndex(shred) orelse return null;
    const index = checkedSub(layout_index, fec_set_index) catch return null;
    return @intCast(index);
}

const MerkleProofEntry = [merkle_proof_entry_size]u8;
const merkle_proof_entry_size: usize = 20;

const MerkleProofIterator = Iterator(MerkleProofEntryList, MerkleProofEntry);

pub fn Iterator(comptime Collection: type, comptime Item: type) type {
    return struct {
        list: Collection,
        index: usize,

        pub fn next(self: *@This()) ?Item {
            if (self.index >= self.list.len) {
                return null;
            }
            defer self.index += 1;
            return self.list.get(self.index);
        }
    };
}

/// This is a reference. It does not own the data. Be careful with its lifetime.
const MerkleProofEntryList = struct {
    bytes: []const u8,
    len: usize,

    pub fn get(self: *@This(), index: usize) ?MerkleProofEntry {
        if (index > self.len) return null;
        const start = index * merkle_proof_entry_size;
        const end = start + merkle_proof_entry_size;
        var entry: MerkleProofEntry = undefined;
        @memcpy(&entry, self.bytes[start..end]);
        return entry;
    }

    pub fn iterator(self: @This()) MerkleProofIterator {
        return .{ .list = self, .index = 0 };
    }
};

pub const CommonHeader = struct {
    signature: Signature,
    shred_variant: ShredVariant,
    slot: Slot,
    index: u32,
    version: u16,
    fec_set_index: u32,

    pub const @"!bincode-config:shred_variant" = ShredVariantConfig;

    // Identifier for the erasure coding set that the shred belongs to.
    pub fn erasureSetId(self: @This()) ErasureSetId {
        return ErasureSetId{
            .slot = self.slot,
            .fec_set_index = self.fec_set_index,
        };
    }
};

pub const DataShredHeader = struct {
    parent_offset: u16,
    flags: ShredFlags,
    size: u16, // common shred header + data shred header + data
};

pub const CodingShredHeader = struct {
    num_data_shreds: u16,
    num_coding_shreds: u16,
    position: u16, // [0..num_coding_shreds)
};

pub const ShredType = enum(u8) {
    Code = 0b0101_1010,
    Data = 0b1010_0101,

    fn constants(self: @This()) ShredConstants {
        return switch (self) {
            .Code => coding_shred,
            .Data => data_shred,
        };
    }
};

pub const ShredVariant = struct {
    shred_type: ShredType,
    proof_size: u8,
    chained: bool,
    resigned: bool,

    const Self = @This();

    fn fromByte(byte: u8) error{ UnknownShredVariant, LegacyShredVariant }!Self {
        return switch (byte & 0xF0) {
            0x40 => .{
                .shred_type = .Code,
                .proof_size = byte & 0x0F,
                .chained = false,
                .resigned = false,
            },
            0x60 => .{
                .shred_type = .Code,
                .proof_size = byte & 0x0F,
                .chained = true,
                .resigned = false,
            },
            0x70 => .{
                .shred_type = .Code,
                .proof_size = byte & 0x0F,
                .chained = true,
                .resigned = true,
            },
            0x80 => .{
                .shred_type = .Data,
                .proof_size = byte & 0x0F,
                .chained = false,
                .resigned = false,
            },
            0x90 => .{
                .shred_type = .Data,
                .proof_size = byte & 0x0F,
                .chained = true,
                .resigned = false,
            },
            0xb0 => .{
                .shred_type = .Data,
                .proof_size = byte & 0x0F,
                .chained = true,
                .resigned = true,
            },
            @intFromEnum(ShredType.Code) => error.LegacyShredVariant,
            @intFromEnum(ShredType.Data) => error.LegacyShredVariant,
            else => error.UnknownShredVariant,
        };
    }

    fn toByte(self: Self) error{ UnknownShredVariant, LegacyShredVariant, IllegalProof }!u8 {
        if (self.proof_size & 0xF0 != 0) return error.IllegalProof;
        const big_end: u8 =
            if (self.shred_type == .Code and
            self.chained == false and
            self.resigned == false)
            0x40
        else if (self.shred_type == .Code and
            self.chained == true and
            self.resigned == false)
            0x60
        else if (self.shred_type == .Code and
            self.chained == true and
            self.resigned == true)
            0x70
        else if (self.shred_type == .Data and
            self.chained == false and
            self.resigned == false)
            0x80
        else if (self.shred_type == .Data and
            self.chained == true and
            self.resigned == false)
            0x90
        else if (self.shred_type == .Data and
            self.chained == true and
            self.resigned == true)
            0xb0
        else
            return error.UnknownShredVariant;
        return big_end | self.proof_size;
    }
};

pub const ShredVariantConfig = blk: {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, _: bincode.Params) !void {
            return writer.writeByte(try ShredVariant.toByte(data));
        }

        pub fn deserialize(_: std.mem.Allocator, reader: anytype, _: bincode.Params) !ShredVariant {
            return try ShredVariant.fromByte(try reader.readByte());
        }

        pub fn free(_: std.mem.Allocator, _: anytype) void {}
    };

    break :blk bincode.FieldConfig(ShredVariant){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
};

pub const ShredFlags = BitFlags(enum(u8) {
    shred_tick_reference_mask = 0b0011_1111,
    data_complete_shred = 0b0100_0000,
    last_shred_in_slot = 0b1100_0000,

    comptime {
        // This replaces a check that would otherwise
        // be ported from agave into DataShred.sanitize.
        std.testing.expect(
            @intFromEnum(ShredFlags.Flag.data_complete_shred) ==
                @intFromEnum(ShredFlags.Flag.last_shred_in_slot) &
                @intFromEnum(ShredFlags.Flag.data_complete_shred),
        ) catch unreachable;
    }
});

pub const ShredConstants = struct {
    max_per_slot: usize,
    payload_size: usize,
    headers_size: usize,
};

pub const layout = struct {
    const SIZE_OF_COMMON_SHRED_HEADER: usize = 83;
    const SIZE_OF_DATA_SHRED_HEADERS: usize = 88;
    const SIZE_OF_CODING_SHRED_HEADERS: usize = 89;
    const SIZE_OF_SIGNATURE: usize = sig.core.SIGNATURE_LENGTH;
    const SIZE_OF_SHRED_VARIANT: usize = 1;
    const SIZE_OF_SHRED_SLOT: usize = 8;

    const OFFSET_OF_SHRED_VARIANT: usize = SIZE_OF_SIGNATURE;
    const OFFSET_OF_SHRED_SLOT: usize = SIZE_OF_SIGNATURE + SIZE_OF_SHRED_VARIANT;
    const OFFSET_OF_SHRED_INDEX: usize = OFFSET_OF_SHRED_SLOT + SIZE_OF_SHRED_SLOT;

    pub fn getShred(packet: *const Packet) ?[]const u8 {
        if (getShredSize(packet) > packet.data.len) return null;
        return packet.data[0..getShredSize(packet)];
    }

    pub fn getShredSize(packet: *const Packet) usize {
        return if (packet.flags.isSet(.repair))
            packet.size -| @sizeOf(Nonce)
        else
            packet.size;
    }

    pub fn getSlot(shred: []const u8) ?Slot {
        return getInt(Slot, shred, OFFSET_OF_SHRED_SLOT);
    }

    pub fn getVersion(shred: []const u8) ?u16 {
        return getInt(u16, shred, 77);
    }

    pub fn getShredVariant(shred: []const u8) ?ShredVariant {
        if (shred.len <= OFFSET_OF_SHRED_VARIANT) return null;
        const byte = shred[OFFSET_OF_SHRED_VARIANT];
        return ShredVariant.fromByte(byte) catch null;
    }

    pub fn getIndex(shred: []const u8) ?u32 {
        return getInt(u32, shred, OFFSET_OF_SHRED_INDEX);
    }

    pub fn getSignature(shred: []const u8) ?Signature {
        if (shred.len < SIGNATURE_LENGTH) {
            return null;
        }
        return Signature.init(shred[0..SIZE_OF_SIGNATURE].*);
    }

    pub fn getSignedData(shred: []const u8) ?Hash {
        const variant = getShredVariant(shred) orelse return null;
        const constants = switch (variant.shred_type) {
            .Code => coding_shred,
            .Data => data_shred,
        };
        return getMerkleRoot(shred, constants, variant) catch null;
    }

    /// must be a data shred, otherwise the return value will be corrupted and meaningless
    pub fn getParentOffset(shred: []const u8) ?u16 {
        std.debug.assert(getShredVariant(shred).?.shred_type == .Data);
        return getInt(u16, shred, 83);
    }

    /// Analogous to [get_chained_merkle_root](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/shred.rs#L740)
    pub fn getChainedMerkleRoot(shred: []const u8) ?Hash {
        const variant = getShredVariant(shred) orelse return null;
        const offset = getChainedMerkleRootOffset(variant) catch return null;
        const end = offset +| SIZE_OF_MERKLE_ROOT;
        if (shred.len < end) return null;
        return Hash.fromSizedSlice(shred[offset..][0..SIZE_OF_MERKLE_ROOT]);
    }
};

/// Extracts a little-endian integer from within the slice,
/// starting at start_index.
fn getInt(
    comptime Int: type,
    data: []const u8,
    start_index: usize,
) ?Int {
    const end_index = start_index + @sizeOf(Int);
    if (data.len < end_index) return null;
    const bytes: *const [@sizeOf(Int)]u8 = @ptrCast(data[start_index..end_index]);
    return std.mem.readInt(Int, bytes, .little);
}

test "basic shred variant round trip" {
    try testShredVariantRoundTrip(0x4C, .{
        .shred_type = .Code,
        .proof_size = 0x0C,
        .chained = false,
        .resigned = false,
    });
}

fn testShredVariantRoundTrip(expected_byte: u8, start_variant: ShredVariant) !void {
    const actual_byte = try start_variant.toByte();
    try std.testing.expect(actual_byte == expected_byte);
    const end_variant = try ShredVariant.fromByte(actual_byte);
    try std.testing.expect(
        start_variant.shred_type == end_variant.shred_type and
            start_variant.proof_size == end_variant.proof_size and
            start_variant.chained == end_variant.chained and
            start_variant.resigned == end_variant.resigned,
    );
}

test "getShredVariant" {
    const variant = layout.getShredVariant(&test_data_shred).?;
    try std.testing.expect(.Data == variant.shred_type);
    try std.testing.expect(!variant.chained);
    try std.testing.expect(!variant.resigned);
    try std.testing.expect(6 == variant.proof_size);
}

test "dataIndex" {
    try std.testing.expect(31 == dataIndex(&test_data_shred).?);
}

test "getIndex" {
    try std.testing.expect(65 == layout.getIndex(&test_data_shred).?);
}

test "getMerkleRoot" {
    const variant = layout.getShredVariant(&test_data_shred).?;
    const merkle_root = try getMerkleRoot(&test_data_shred, data_shred, variant);
    const expected_signed_data = [_]u8{
        224, 241, 85,  253, 247, 62,  137, 179, 152, 192, 186, 203, 121, 194, 178, 130,
        33,  181, 143, 156, 220, 150, 69,  197, 81,  97,  237, 11,  74,  156, 129, 134,
    };
    try std.testing.expect(std.mem.eql(u8, &expected_signed_data, &merkle_root.data));
}

test "getSignature" {
    const signature = layout.getSignature(&test_data_shred).?;
    const expected_signature = [_]u8{
        102, 205, 108, 67,  218, 3,   214, 186, 28,  110, 167, 22,  75,  135, 233, 156, 45,  215, 209, 1,
        253, 53,  142, 52,  6,   98,  158, 51,  157, 207, 190, 22,  96,  106, 68,  248, 244, 162, 13,  205,
        193, 194, 143, 192, 142, 141, 134, 85,  93,  252, 43,  200, 224, 101, 12,  28,  97,  202, 230, 215,
        34,  217, 20,  7,
    };
    try std.testing.expect(std.mem.eql(u8, &expected_signature, &signature.data));
}

test "getSignedData" {
    const signed_data = layout.getSignedData(&test_data_shred).?;
    const expected_signed_data = [_]u8{
        224, 241, 85,  253, 247, 62,  137, 179, 152, 192, 186, 203, 121, 194, 178, 130,
        33,  181, 143, 156, 220, 150, 69,  197, 81,  97,  237, 11,  74,  156, 129, 134,
    };
    try std.testing.expect(std.mem.eql(u8, &expected_signed_data, &signed_data.data));
}

const test_data_shred = [_]u8{
    102, 205, 108, 67,  218, 3,   214, 186, 28,  110, 167, 22,  75,  135, 233, 156, 45,  215,
    209, 1,   253, 53,  142, 52,  6,   98,  158, 51,  157, 207, 190, 22,  96,  106, 68,  248,
    244, 162, 13,  205, 193, 194, 143, 192, 142, 141, 134, 85,  93,  252, 43,  200, 224, 101,
    12,  28,  97,  202, 230, 215, 34,  217, 20,  7,   134, 105, 170, 47,  18,  0,   0,   0,
    0,   65,  0,   0,   0,   71,  176, 34,  0,   0,   0,   1,   0,   192, 88,
} ++ .{0} ** 996 ++ .{
    247, 170, 109, 175, 191, 111, 108, 73,  56,  57,  34,  185, 81,  218, 60,  244, 53,  227,
    243, 72,  15,  175, 148, 58,  42,  0,   133, 246, 67,  118, 164, 221, 109, 136, 179, 199,
    15,  177, 139, 110, 105, 222, 165, 194, 78,  25,  172, 56,  165, 69,  28,  80,  215, 72,
    10,  21,  144, 236, 44,  107, 166, 65,  197, 164, 106, 113, 9,   68,  227, 37,  134, 158,
    192, 200, 22,  30,  244, 177, 106, 84,  161, 246, 35,  21,  26,  163, 104, 181, 13,  189,
    247, 250, 214, 101, 190, 52,  28,  152, 85,  9,   49,  168, 162, 199, 128, 242, 217, 219,
    71,  219, 72,  191, 107, 210, 46,  255, 206, 122, 234, 142, 229, 214, 240, 186,
};
