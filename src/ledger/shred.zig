const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const Allocator = std.mem.Allocator;

const BitFlags = sig.utils.bitflags.BitFlags;
const Hash = sig.core.Hash;
const Nonce = sig.core.Nonce;
const Packet = sig.net.Packet;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;

pub const MAX_SHREDS_PER_SLOT: usize =
    CodeShred.constants.max_per_slot +
    DataShred.constants.max_per_slot;

pub const DATA_SHREDS_PER_FEC_BLOCK: usize = 32;
const SIZE_OF_MERKLE_ROOT: usize = sig.core.Hash.SIZE;

pub const ShredType = enum(u8) {
    code = 0b0101_1010,
    data = 0b1010_0101,
};

/// Analogous to [Shred](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/ledger/src/shred.rs#L245)
pub const Shred = union(ShredType) {
    code: CodeShred,
    data: DataShred,

    pub fn deinit(self: Shred) void {
        return switch (self) {
            inline .code, .data => |s| s.deinit(),
        };
    }

    pub fn fromPayload(allocator: Allocator, data: []const u8) !Shred {
        const variant = layout.getShredVariant(data) orelse return error.InvalidShredVariant;
        return switch (variant.shred_type) {
            .code => .{ .code = try CodeShred.Generic.fromPayload(allocator, data) },
            .data => .{ .data = try DataShred.Generic.fromPayload(allocator, data) },
        };
    }

    pub fn fromPayloadOwned(allocator: Allocator, data: []u8) !Shred {
        const variant = layout.getShredVariant(data) orelse return error.InvalidShredVariant;
        return switch (variant.shred_type) {
            .code => .{ .code = try CodeShred.Generic.fromPayloadOwned(allocator, data) },
            .data => .{ .data = try DataShred.Generic.fromPayloadOwned(allocator, data) },
        };
    }

    pub fn clone(self: Shred) Allocator.Error!Shred {
        return switch (self) {
            .code => |shred| .{ .code = try shred.clone() },
            .data => |shred| .{ .data = try shred.clone() },
        };
    }

    pub fn payload(self: Shred) []const u8 {
        return switch (self) {
            inline .code, .data => |shred| shred.payload,
        };
    }

    pub fn mutablePayload(self: Shred) []u8 {
        return switch (self) {
            inline .code, .data => |shred| shred.payload,
        };
    }

    pub fn commonHeader(self: Shred) CommonHeader {
        return switch (self) {
            inline .code, .data => |c| c.common,
        };
    }

    pub fn sanitize(self: *const Shred) !void {
        if (self.commonHeader().variant.shred_type != @as(ShredType, self.*)) {
            return error.InconsistentShredVariant;
        }
        switch (self.*) {
            inline .code, .data => |s| try s.sanitize(),
        }
    }

    pub fn merkleRoot(self: Shred) !Hash {
        return switch (self) {
            inline .code, .data => |s| getMerkleRoot(
                s.payload,
                @TypeOf(s).constants,
                s.common.variant,
            ),
        };
    }

    pub fn merkleNode(self: Shred) !Hash {
        return switch (self) {
            inline .code, .data => |s| @TypeOf(s).Generic.merkleNode(s),
        };
    }

    pub fn merkleProof(self: Shred) !MerkleProofEntryList {
        return switch (self) {
            inline .code, .data => |s| @TypeOf(s).Generic.merkleProof(&s),
        };
    }

    pub fn chainedMerkleRoot(self: Shred) !Hash {
        return switch (self) {
            inline .code, .data => |s| layout.getChainedMerkleRoot(s.payload) orelse
                error.InvalidPayloadSize,
        };
    }

    pub fn isLastInSlot(self: *const Shred) bool {
        return switch (self.*) {
            .code => false,
            .data => |data| data.custom.flags.isSet(.last_shred_in_slot),
        };
    }

    pub fn verify(self: Shred, signer: sig.core.Pubkey) !void {
        return switch (self) {
            inline .data, .code => |s| @TypeOf(s).Generic.verify(s, signer),
        };
    }

    pub fn erasureShardIndex(self: Shred) !usize {
        return switch (self) {
            inline .data, .code => |s| s.erasureShardIndex(),
        };
    }

    pub fn erasureShardAsSlice(self: Shred) ![]const u8 {
        return switch (self) {
            inline .data, .code => |s| @TypeOf(s).Generic.erasureShardAsSlice(&s),
        };
    }

    pub fn id(self: Shred) ShredId {
        return switch (self) {
            inline .data, .code => |s| s.id(),
        };
    }

    pub fn retransmitterSignature(self: Shred) !Signature {
        return switch (self) {
            inline .data, .code => |s| s.retransmitterSignature(),
        };
    }
};

/// Analogous to [ShredCode](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/shred/merkle.rs#L74)
pub const CodeShred = struct {
    common: CommonHeader,
    custom: CodeHeader,
    allocator: Allocator,
    payload: []u8,

    const Generic = GenericShred(.code);

    pub const constants: ShredConstants = .{
        .max_per_slot = 32_768,
        .payload_size = 1228, // TODO this can be calculated like solana
        .headers_size = 89,
    };

    pub fn deinit(self: CodeShred) void {
        self.allocator.free(self.payload);
    }

    pub fn clone(self: CodeShred) Allocator.Error!CodeShred {
        var new = self;
        new.payload = try new.allocator.dupe(u8, new.payload);
        return new;
    }

    /// agave: ShredCode::from_recovered_shard
    pub fn fromRecoveredShard(
        allocator: Allocator,
        common_header: CommonHeader,
        code_header: CodeHeader,
        chained_merkle_root: ?Hash,
        retransmitter_signature: ?Signature,
        shard: []const u8,
    ) !CodeShred {
        if (common_header.variant.shred_type != .code) {
            return error.InvalidShredVariant;
        }
        if (shard.len != try capacity(constants, common_header.variant)) {
            return error.InvalidShardSize;
        }
        if (shard.len + constants.headers_size > constants.payload_size) {
            return error.InvalidShardSize;
        }

        const payload = try allocator.alloc(u8, constants.payload_size);
        @memcpy(payload[constants.headers_size..][0..shard.len], shard);
        @memset(payload[constants.headers_size + shard.len ..], 0);

        var buf = std.io.fixedBufferStream(payload);
        const writer = buf.writer();
        try bincode.write(writer, common_header, .{});
        try bincode.write(writer, code_header, .{});

        if (chained_merkle_root) |hash|
            try setChainedMerkleRoot(payload, common_header.variant, hash);

        if (retransmitter_signature) |sign|
            try setRetransmitterSignatureFor(payload, common_header.variant, sign);

        const shred: CodeShred = .{
            .allocator = allocator,
            .common = common_header,
            .custom = code_header,
            .payload = payload,
        };
        try shred.sanitize();
        return shred;
    }

    pub fn zeroedForTest(allocator: std.mem.Allocator) !CodeShred {
        return Generic.zeroedForTest(allocator);
    }

    pub fn sanitize(self: *const CodeShred) !void {
        try Generic.sanitize(self);
        if (self.custom.num_code_shreds > 8 * DATA_SHREDS_PER_FEC_BLOCK) {
            return error.InvalidNumCodeShreds;
        }
        _ = try self.erasureShardIndex();
    }

    pub fn writePayload(self: *CodeShred, new_payload: []const u8) !void {
        return Generic.writePayload(self, new_payload);
    }

    pub fn erasureShardIndex(self: *const CodeShred) !usize {
        // Assert that the last shred index in the erasure set does not
        // overshoot MAX_{DATA,CODE}_SHREDS_PER_SLOT.
        if (try std.math.add(
            u32,
            self.common.erasure_set_index,
            try std.math.sub(u32, @intCast(self.custom.num_data_shreds), 1),
        ) >= DataShred.constants.max_per_slot) {
            return error.InvalidErasureShardIndex;
        }
        if (try std.math.add(
            u32,
            try self.firstCodeIndex(),
            try std.math.sub(u32, self.custom.num_code_shreds, 1),
        ) >= CodeShred.constants.max_per_slot) {
            return error.InvalidErasureShardIndex;
        }
        const num_data_shreds: u64 = self.custom.num_data_shreds;
        const num_code_shreds: u64 = self.custom.num_code_shreds;
        const position: u64 = self.custom.erasure_code_index;
        const erasure_set_size = try std.math.add(u64, num_data_shreds, num_code_shreds);
        const index = try std.math.add(u64, position, num_data_shreds);
        return if (index < erasure_set_size) index else error.InvalidErasureShardIndex;
    }

    pub fn firstCodeIndex(self: *const CodeShred) !u32 {
        return std.math.sub(
            u32,
            self.common.index,
            self.custom.erasure_code_index,
        );
    }

    pub fn id(self: CodeShred) ShredId {
        return Generic.id(&self);
    }

    pub fn merkleRoot(self: CodeShred) !Hash {
        return Generic.merkleRoot(self);
    }

    pub fn chainedMerkleRoot(self: CodeShred) !Hash {
        return Generic.chainedMerkleRoot(self);
    }

    pub fn retransmitterSignature(self: CodeShred) !Signature {
        return Generic.retransmitterSignature(self);
    }
};

/// Analogous to [ShredData](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/shred/merkle.rs#L61)
pub const DataShred = struct {
    common: CommonHeader,
    custom: DataHeader,
    allocator: Allocator,
    payload: []u8,

    pub const constants: ShredConstants = .{
        .max_per_slot = 32_768,
        .payload_size = 1203, // TODO this can be calculated like solana
        .headers_size = 88,
    };

    const Self = @This();
    const Generic = GenericShred(.data);

    pub fn deinit(self: Self) void {
        self.allocator.free(self.payload);
    }

    pub fn clone(self: Self) Allocator.Error!Self {
        var new = self;
        new.payload = try new.allocator.dupe(u8, new.payload);
        return new;
    }

    /// agave: ShredData::from_recovered_shard
    pub fn fromRecoveredShard(
        allocator: Allocator,
        leader_signature: Signature,
        chained_merkle_root: ?Hash,
        retransmitter_signature: ?Signature,
        shard: []const u8,
    ) !Self {
        if (shard.len + Signature.SIZE > constants.payload_size) {
            return error.InvalidShardSize;
        }

        const payload = try allocator.alloc(u8, constants.payload_size);
        errdefer allocator.free(payload);
        @memcpy(payload[0..Signature.SIZE], &leader_signature.toBytes());
        @memcpy(payload[Signature.SIZE..][0..shard.len], shard);
        @memset(payload[Signature.SIZE + shard.len ..], 0);

        var shred = try Generic.fromPayloadOwned(allocator, payload);

        if (shard.len != try capacity(CodeShred.constants, shred.common.variant))
            return error.InvalidShardSize;

        if (chained_merkle_root) |hash|
            try setChainedMerkleRoot(payload, shred.common.variant, hash);

        if (retransmitter_signature) |sign|
            try setRetransmitterSignatureFor(payload, shred.common.variant, sign);

        try shred.sanitize();

        return shred;
    }

    pub fn zeroedForTest(allocator: std.mem.Allocator) !Self {
        return Generic.zeroedForTest(allocator);
    }

    pub fn sanitize(self: *const Self) !void {
        try Generic.sanitize(self);
        // see ShredFlags comptime block for omitted check that is guaranteed at comptime.
        _ = try self.data();
        _ = try self.parent();
    }

    pub fn writePayload(self: *Self, new_payload: []const u8) !void {
        return Generic.writePayload(self, new_payload);
    }

    pub fn data(self: *const Self) ![]const u8 {
        const data_buffer_size = try capacity(constants, self.common.variant);
        const size = self.custom.size;
        if (size > self.payload.len or
            size < constants.headers_size or
            size > constants.headers_size + data_buffer_size)
        {
            return error.InvalidDataSize;
        }

        return self.payload[constants.headers_size..size];
    }

    pub fn parent(self: *const Self) error{InvalidParentSlotOffset}!Slot {
        const slot = self.common.slot;
        if (self.custom.parent_slot_offset == 0 and slot != 0) {
            return error.InvalidParentSlotOffset;
        }
        return std.math.sub(
            u64,
            slot,
            self.custom.parent_slot_offset,
        ) catch error.InvalidParentSlotOffset;
    }

    pub fn erasureShardIndex(self: *const Self) !usize {
        return try std.math.sub(
            u32,
            self.common.index,
            self.common.erasure_set_index,
        );
    }

    pub fn dataComplete(self: Self) bool {
        return self.custom.flags.isSet(.data_complete_shred);
    }

    pub fn isLastInSlot(self: Self) bool {
        return self.custom.flags.isSet(.last_shred_in_slot);
    }

    pub fn referenceTick(self: Self) u8 {
        return self.custom.flags
            .intersection(.shred_tick_reference_mask).state;
    }

    pub fn id(self: Self) ShredId {
        return Generic.id(&self);
    }

    pub fn merkleRoot(self: Self) !Hash {
        return Generic.merkleRoot(self);
    }

    pub fn chainedMerkleRoot(self: Self) !Hash {
        return Generic.chainedMerkleRoot(self);
    }

    pub fn retransmitterSignature(self: Self) !Signature {
        return Generic.retransmitterSignature(self);
    }
};

/// Analogous to [Shred trait](https://github.com/anza-xyz/agave/blob/8c5a33a81a0504fd25d0465bed35d153ff84819f/ledger/src/shred/traits.rs#L6)
fn GenericShred(shred_type: ShredType) type {
    const Self = switch (shred_type) {
        .data => DataShred,
        .code => CodeShred,
    };
    const CustomHeader = switch (shred_type) {
        .data => DataHeader,
        .code => CodeHeader,
    };
    const constants = Self.constants;

    return struct {
        fn fromPayload(allocator: Allocator, payload: []const u8) !Self {
            // NOTE(x19): is it ok if payload.len > constants.payload_size? the test_data_shred is 1207 bytes
            if (payload.len < constants.payload_size) {
                return error.InvalidPayloadSize;
            }
            const owned_payload = try allocator.alloc(u8, constants.payload_size);
            errdefer allocator.free(owned_payload);

            // TODO: It would be nice to find a way to get the payload in here without coping the entire thing.
            // The challenge is that the input payload is owned by the original packet list which was read
            // from the socket, and that list may be cluttered with a lot of garbage data.
            // So a copy like this may be needed somewhere. but it's worth some more thought.
            @memcpy(owned_payload, payload[0..constants.payload_size]);

            return fromPayloadOwned(allocator, owned_payload);
        }

        /// these conditions must be met to call this function:
        /// - `payload` was allocated with `allocator`
        /// - payload.len >= constants.payload_size
        fn fromPayloadOwned(allocator: Allocator, payload: []u8) !Self {
            var buf = std.io.fixedBufferStream(payload[0..constants.payload_size]);
            const self = Self{
                .allocator = allocator,
                .common = try bincode.read(allocator, CommonHeader, buf.reader(), .{}),
                .custom = try bincode.read(allocator, CustomHeader, buf.reader(), .{}),
                .payload = payload,
            };

            try self.sanitize();
            return self;
        }

        fn zeroedForTest(allocator: std.mem.Allocator) !Self {
            const payload = try allocator.alloc(u8, constants.payload_size);
            return .{
                .common = CommonHeader.ZEROED_FOR_TEST,
                .custom = CustomHeader.ZEROED_FOR_TEST,
                .allocator = allocator,
                .payload = payload,
            };
        }

        fn sanitize(self: *const Self) !void {
            _ = try merkleProof(self);

            // Shred index must be 0 <= index < max_per_slot
            if (self.common.index >= constants.max_per_slot) {
                return error.InvalidShredIndex;
            }
            if (constants.payload_size != self.payload.len) {
                return error.InvalidPayloadSize;
            }
        }

        /// Unique identifier for each shred.
        fn id(self: *const Self) ShredId {
            return .{
                .slot = self.common.slot,
                .index = self.common.index,
                .shred_type = self.common.variant.shred_type,
            };
        }

        /// The return contains a pointer to data owned by the shred.
        fn merkleProof(self: *const Self) !MerkleProofEntryList {
            return getMerkleProofFor(self.payload, constants, self.common.variant);
        }

        fn merkleNode(self: Self) !Hash {
            const offset = try proofOffset(constants, self.common.variant);
            return getMerkleNodeAt(self.payload, Signature.SIZE, offset);
        }

        fn erasureShardAsSlice(self: *const Self) ![]const u8 {
            if (self.payload.len != constants.payload_size) {
                return error.InvalidPayloadSize;
            }
            const end = constants.headers_size +
                try capacity(constants, self.common.variant);
            if (self.payload.len < end) {
                return error.InsufficientPayloadSize;
            }
            const start = switch (self.common.variant.shred_type) {
                .data => Signature.SIZE,
                .code => constants.headers_size,
            };
            return self.payload[start..end];
        }

        fn verify(self: Self, leader: sig.core.Pubkey) !void {
            const root = try self.merkleRoot();
            const signature = layout.getLeaderSignature(self.payload) orelse
                return error.InvalidSignature;
            return try signature.verify(leader, &root.data);
        }

        /// this is the data that is signed by the signature
        fn merkleRoot(self: Self) !Hash {
            return getMerkleRoot(self.payload, constants, self.common.variant);
        }

        fn chainedMerkleRoot(self: Self) !Hash {
            return layout.getChainedMerkleRoot(self.payload) orelse error.InvalidPayloadSize;
        }

        /// agave: retransmitter_signature
        fn retransmitterSignature(self: Self) !Signature {
            const offset = try retransmitterSignatureOffset(self.common.variant);
            const end = offset + Signature.SIZE;
            if (self.payload.len < end) return error.InvalidPayloadSize;
            return .fromBytes(self.payload[offset..][0..64].*);
        }
    };
}

pub const ShredId = struct {
    slot: Slot,
    index: u32,
    shred_type: sig.ledger.shred.ShredType,
};

pub const ErasureSetId = struct {
    slot: Slot,
    /// The number that identifies the erasure set within a slot.
    /// This is shred index for the first data shred in the erasure set.
    /// aka "fec_set_index"
    erasure_set_index: u64,

    pub fn order(a: ErasureSetId, b: ErasureSetId) std.math.Order {
        if (a.slot == b.slot and a.erasure_set_index == b.erasure_set_index) {
            return .eq;
        } else if (a.slot < b.slot or a.slot == b.slot and a.erasure_set_index < b.erasure_set_index) {
            return .lt;
        } else if (a.slot > b.slot or a.slot == b.slot and a.erasure_set_index > b.erasure_set_index) {
            return .gt;
        } else {
            unreachable;
        }
    }
};

fn getMerkleRoot(
    shred: []const u8,
    constants: ShredConstants,
    variant: ShredVariant,
) !Hash {
    const index = switch (variant.shred_type) {
        .code => codeIndex(shred) orelse return error.InvalidErasureShardIndex,
        .data => dataIndex(shred) orelse return error.InvalidErasureShardIndex,
    };
    const proof = try getMerkleProofFor(shred, constants, variant);
    const offset = try proofOffset(constants, variant);
    const node = try getMerkleNodeAt(shred, Signature.SIZE, offset);
    return calculateMerkleRoot(index, node, proof);
}

/// agave: set_chained_merkle_root
fn setChainedMerkleRoot(shred: []u8, variant: ShredVariant, chained_merkle_root: Hash) !void {
    const offset = try getChainedMerkleRootOffset(variant);
    const end = offset + SIZE_OF_MERKLE_ROOT;
    if (shred.len < end) {
        return error.InvalidPayloadSize;
    }
    @memcpy(shred[offset..end], &chained_merkle_root.data);
}

pub fn getMerkleProof(shred: []const u8) !MerkleProofEntryList {
    const variant = layout.getShredVariant(shred) orelse return error.UnknownShredVariant;
    return getMerkleProofFor(shred, variant.constants(), variant);
}

fn getMerkleProofFor(
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

/// agave: set_merkle_proof
pub fn setMerkleProof(shred: []u8, proof: MerkleProofEntryList) !void {
    const variant = layout.getShredVariant(shred) orelse return error.UnknownShredVariant;
    try proof.sanitize();
    const proof_size = variant.proof_size;
    if (proof.len != proof_size) {
        return error.InvalidMerkleProof;
    }
    const offset = try proofOffset(variant.constants(), variant);
    if (shred.len < offset + proof.len * merkle_proof_entry_size) {
        return error.InvalidProofSize;
    }
    var start = offset;
    var proof_iterator = proof.iterator();
    while (proof_iterator.next()) |entry| {
        // TODO test: agave uses bincode here. does that make any difference?
        const end = merkle_proof_entry_size + start;
        @memcpy(shred[start..end], entry);
        start = end;
    }
}

pub fn getMerkleNode(shred: []const u8) !Hash {
    const variant = layout.getShredVariant(shred) orelse return error.UnknownShredVariant;
    const offset = try proofOffset(variant.constants(), variant);
    return getMerkleNodeAt(shred, Signature.SIZE, offset);
}

fn getMerkleNodeAt(shred: []const u8, start: usize, end: usize) !Hash {
    if (shred.len < end) return error.InvalidPayloadSize;
    return Hash.initMany(&.{ MERKLE_HASH_PREFIX_LEAF, shred[start..end] });
}

/// [get_merkle_root](https://github.com/anza-xyz/agave/blob/ed500b5afc77bc78d9890d96455ea7a7f28edbf9/ledger/src/shred/merkle.rs#L702)
fn calculateMerkleRoot(start_index: usize, start_node: Hash, proof: MerkleProofEntryList) !Hash {
    var index = start_index;
    var node = start_node;
    for (0..proof.len) |i| {
        const other = proof.get(i).?;
        node = if (index % 2 == 0)
            joinNodes(&node.data, other[0..])
        else
            joinNodes(other[0..], &node.data);
        index = index >> 1;
    }
    if (index != 0) return error.InvalidMerkleProof;
    return node;
}

pub const MERKLE_HASH_PREFIX_LEAF: *const [26]u8 = "\x00SOLANA_MERKLE_SHREDS_LEAF";
pub const MERKLE_HASH_PREFIX_NODE: *const [26]u8 = "\x01SOLANA_MERKLE_SHREDS_NODE";

/// agave: make_merkle_tree
pub fn makeMerkleTree(nodes: *std.ArrayList(Hash)) !void {
    var size = nodes.items.len;
    while (size > 1) {
        const offset = nodes.items.len - size;
        var index = offset;
        const end = offset + size;
        while (index < end) : (index += 2) {
            const node = &nodes.items[index];
            const other = &nodes.items[@min(index + 1, offset + size - 1)];
            const parent = joinNodes(&node.data, &other.data);
            try nodes.append(parent);
        }
        size = nodes.items.len - offset - size;
    }
}

/// agave: make_merkle_proof
///
/// return is owned
pub fn makeMerkleProof(
    allocator: Allocator,
    /// leaf index ~ shred's erasure shard index.
    index_: usize,
    /// number of leaves ~ erasure batch size.
    size_: usize,
    tree: []const Hash,
) !?MerkleProofEntryList {
    var index = index_;
    var size = size_;
    if (index >= size) {
        return null;
    }
    var offset: usize = 0;
    var proof = try allocator.alloc(u8, 140); // 140 is a guess. will realloc as needed
    errdefer allocator.free(proof);
    var write_cursor: usize = 0;
    while (size > 1) {
        const i = offset + @min(index ^ 1, size - 1);
        if (i >= tree.len) return null;
        const node = tree[i];
        if (write_cursor + merkle_proof_entry_size > proof.len) {
            proof = try allocator.realloc(proof, proof.len * 2);
        }
        @memcpy(
            proof[write_cursor..][0..merkle_proof_entry_size],
            node.data[0..merkle_proof_entry_size],
        );
        offset += size;
        size = (size + 1) >> 1;
        index >>= 1;
        write_cursor += merkle_proof_entry_size;
    }
    if (offset + 1 == tree.len) {
        return .{
            .bytes = try allocator.realloc(proof, write_cursor),
            .len = write_cursor / merkle_proof_entry_size,
        };
    } else {
        allocator.free(proof);
        return null;
    }
}

/// [agave] https://github.com/anza-xyz/agave/blob/f7f2f5f5acfdf83c2ee2fbc16da998acc06146ff/ledger/src/shred/merkle_tree.rs#L78
fn joinNodes(lhs: []const u8, rhs: []const u8) Hash {
    return .initMany(&.{
        MERKLE_HASH_PREFIX_NODE,
        lhs[0..merkle_proof_entry_size],
        rhs[0..merkle_proof_entry_size],
    });
}

/// Where the merkle proof starts in the shred binary.
fn proofOffset(constants: ShredConstants, variant: ShredVariant) !usize {
    return constants.headers_size +
        try capacity(constants, variant) +
        if (variant.chained) SIZE_OF_MERKLE_ROOT else 0;
}

/// Analogous to [get_chained_merkle_root_offset](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/shred/merkle.rs#L364)
pub fn getChainedMerkleRootOffset(variant: ShredVariant) !usize {
    const constants = variant.constants();
    if (!variant.chained) {
        return error.InvalidShredVariant;
    }
    return constants.headers_size + try capacity(constants, variant);
}

/// agave: retransmitter_signature_offset and get_retransmitter_signature_offset
fn retransmitterSignatureOffset(variant: ShredVariant) !usize {
    if (!variant.resigned) {
        return error.InvalidShredVariant;
    }
    return try proofOffset(variant.constants(), variant) +
        variant.proof_size * merkle_proof_entry_size;
}

fn capacity(constants: ShredConstants, variant: ShredVariant) !usize {
    std.debug.assert(variant.chained or !variant.resigned);
    return std.math.sub(
        usize,
        constants.payload_size,
        constants.headers_size +
            (if (variant.chained) SIZE_OF_MERKLE_ROOT else 0) +
            variant.proof_size * merkle_proof_entry_size +
            (if (variant.resigned) Signature.SIZE else 0),
    ) catch error.InvalidProofSize;
}

/// Shred index in the erasure batch.
/// This only works for code shreds.
fn codeIndex(shred: []const u8) ?usize {
    const num_data_shreds: usize = @intCast(getInt(u16, shred, 83) orelse return null);
    const position: usize = @intCast(getInt(u16, shred, 87) orelse return null);
    return std.math.add(u64, num_data_shreds, position) catch null;
}

/// Shred index in the erasure batch
/// This only works for data shreds.
fn dataIndex(shred: []const u8) ?usize {
    const erasure_set_index = getInt(u32, shred, 79) orelse return null;
    const layout_index = layout.getIndex(shred) orelse return null;
    const index = std.math.sub(u32, layout_index, erasure_set_index) catch return null;
    return index;
}

const MerkleProofEntry = [merkle_proof_entry_size]u8;
const merkle_proof_entry_size: usize = 20;

const MerkleProofIterator = ChunkIterator(u8, merkle_proof_entry_size);

pub fn ChunkIterator(comptime T: type, chunk_size: usize) type {
    return struct {
        slice: []const T,
        cursor: usize = 0,

        pub fn next(self: *@This()) ?*const [chunk_size]T {
            const end = self.cursor + chunk_size;
            if (end > self.slice.len) {
                return null;
            }
            defer self.cursor = end;
            return @ptrCast(self.slice[self.cursor..end]);
        }
    };
}

/// This contains a slice that may or may not be owned. Be careful with its lifetime.
pub const MerkleProofEntryList = struct {
    bytes: []const u8,
    len: usize,

    const Self = @This();

    pub fn deinit(self: Self, allocator: Allocator) void {
        allocator.free(self.bytes);
    }

    pub fn sanitize(self: Self) !void {
        if (self.len * merkle_proof_entry_size != self.bytes.len) {
            return error.InvalidMerkleProof;
        }
    }

    pub fn get(self: *const Self, index: usize) ?MerkleProofEntry {
        if (index > self.len) return null;
        const start = index * merkle_proof_entry_size;
        const end = start + merkle_proof_entry_size;
        var entry: MerkleProofEntry = undefined;
        @memcpy(&entry, self.bytes[start..end]);
        return entry;
    }

    pub fn iterator(self: Self) MerkleProofIterator {
        return .{ .slice = self.bytes };
    }

    pub fn eql(self: Self, other: Self) bool {
        return self.len == other.len and
            std.mem.eql(u8, self.bytes[0..self.len], other.bytes[0..other.len]);
    }
};

/// agave: setRetransmitterSignature
fn setRetransmitterSignatureFor(shred: []u8, variant: ShredVariant, signature: Signature) !void {
    const offset = try retransmitterSignatureOffset(variant);
    const end = offset + Signature.SIZE;
    if (shred.len < end) {
        return error.InvalidPayloadSize;
    }
    @memcpy(shred[offset..end], &signature.toBytes());
}

pub const CommonHeader = struct {
    leader_signature: Signature,
    variant: ShredVariant,
    slot: Slot,
    index: u32,
    version: u16,
    /// The number that identifies the erasure set within a slot.
    /// This is shred index for the first data shred in the erasure set.
    /// aka "fec_set_index"
    erasure_set_index: u32,

    pub const @"!bincode-config:variant" = ShredVariantConfig;

    const ZEROED_FOR_TEST: CommonHeader = .{
        .leader_signature = .ZEROES,
        .variant = ShredVariant{ .shred_type = .data, .proof_size = 0, .chained = false, .resigned = false },
        .slot = 0,
        .index = 0,
        .version = 0,
        .erasure_set_index = 0,
    };

    // Identifier for the erasure code set that the shred belongs to.
    pub fn erasureSetId(self: CommonHeader) ErasureSetId {
        return .{
            .slot = self.slot,
            .erasure_set_index = self.erasure_set_index,
        };
    }
};

pub const DataHeader = struct {
    /// Number of slots since this slot's parent: parent_slot = slot - parent_slot_offset
    parent_slot_offset: u16,
    flags: ShredFlags,
    size: u16, // common shred header + data shred header + data

    const Self = @This();

    const ZEROED_FOR_TEST = Self{
        .parent_slot_offset = 0,
        .flags = .{},
        .size = 0,
    };
};

pub const CodeHeader = struct {
    num_data_shreds: u16,
    num_code_shreds: u16,
    /// Within an erasure set, every code shred is numbered from 0 to the number of code
    /// shreds in the set. This index is the code shred's position within that sequence.
    erasure_code_index: u16,

    const Self = @This();

    const ZEROED_FOR_TEST = Self{
        .num_data_shreds = 0,
        .num_code_shreds = 0,
        .erasure_code_index = 0,
    };
};

pub const ShredVariant = struct {
    shred_type: ShredType,
    proof_size: u8,
    chained: bool,
    resigned: bool,

    const Self = @This();

    pub fn fromByte(byte: u8) error{ UnknownShredVariant, LegacyShredVariant }!Self {
        return switch (byte & 0xF0) {
            0x40 => .{
                .shred_type = .code,
                .proof_size = byte & 0x0F,
                .chained = false,
                .resigned = false,
            },
            0x60 => .{
                .shred_type = .code,
                .proof_size = byte & 0x0F,
                .chained = true,
                .resigned = false,
            },
            0x70 => .{
                .shred_type = .code,
                .proof_size = byte & 0x0F,
                .chained = true,
                .resigned = true,
            },
            0x80 => .{
                .shred_type = .data,
                .proof_size = byte & 0x0F,
                .chained = false,
                .resigned = false,
            },
            0x90 => .{
                .shred_type = .data,
                .proof_size = byte & 0x0F,
                .chained = true,
                .resigned = false,
            },
            0xb0 => .{
                .shred_type = .data,
                .proof_size = byte & 0x0F,
                .chained = true,
                .resigned = true,
            },
            @intFromEnum(ShredType.code) => error.LegacyShredVariant,
            @intFromEnum(ShredType.data) => error.LegacyShredVariant,
            else => error.UnknownShredVariant,
        };
    }

    pub fn toByte(self: Self) error{ UnknownShredVariant, LegacyShredVariant, IllegalProof }!u8 {
        if (self.proof_size & 0xF0 != 0) return error.IllegalProof;
        const big_end: u8 =
            if (self.shred_type == .code and
            self.chained == false and
            self.resigned == false)
                0x40
            else if (self.shred_type == .code and
            self.chained == true and
            self.resigned == false)
                0x60
            else if (self.shred_type == .code and
            self.chained == true and
            self.resigned == true)
                0x70
            else if (self.shred_type == .data and
            self.chained == false and
            self.resigned == false)
                0x80
            else if (self.shred_type == .data and
            self.chained == true and
            self.resigned == false)
                0x90
            else if (self.shred_type == .data and
            self.chained == true and
            self.resigned == true)
                0xb0
            else
                return error.UnknownShredVariant;
        return big_end | self.proof_size;
    }

    pub fn constants(self: Self) ShredConstants {
        return switch (self.shred_type) {
            .data => DataShred.constants,
            .code => CodeShred.constants,
        };
    }
};

pub const ShredVariantConfig = blk: {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, _: bincode.Params) !void {
            return writer.writeByte(try ShredVariant.toByte(data));
        }

        pub fn deserialize(
            _: *bincode.LimitAllocator,
            reader: anytype,
            _: bincode.Params,
        ) !ShredVariant {
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
    /// this means it is the last shred in an erasure set
    data_complete_shred = 0b0100_0000,
    last_shred_in_slot = 0b1100_0000,

    comptime {
        // This replaces a check that would otherwise
        // be ported from agave into DataShred.sanitize.
        std.debug.assert(@intFromEnum(ShredFlags.Flag.data_complete_shred) ==
            @intFromEnum(ShredFlags.Flag.last_shred_in_slot) &
                @intFromEnum(ShredFlags.Flag.data_complete_shred));
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
    const SIZE_OF_CODE_SHRED_HEADERS: usize = 89;
    const SIZE_OF_SIGNATURE: usize = sig.core.Signature.SIZE;
    const SIZE_OF_SHRED_VARIANT: usize = 1;
    const SIZE_OF_SHRED_SLOT: usize = 8;
    const SIZE_OF_INDEX: usize = 4;
    const SIZE_OF_VERSION: usize = 2;

    const OFFSET_OF_SHRED_VARIANT: usize = SIZE_OF_SIGNATURE; // 64
    const OFFSET_OF_SHRED_SLOT: usize = SIZE_OF_SIGNATURE + SIZE_OF_SHRED_VARIANT; // 64 + 1 = 65
    const OFFSET_OF_SHRED_INDEX: usize = OFFSET_OF_SHRED_SLOT + SIZE_OF_SHRED_SLOT; // 65 + 8 = 73
    const OFFSET_OF_ERASURE_SET_INDEX: usize =
        OFFSET_OF_SHRED_INDEX + SIZE_OF_INDEX + SIZE_OF_VERSION;

    pub fn getShredId(packet: *const Packet) !ShredId {
        const shred = getShred(packet) orelse return error.InvalidShred;
        return .{
            .slot = getSlot(shred) orelse return error.InvalidShred,
            .index = getIndex(shred) orelse return error.InvalidShred,
            .shred_type = getShredVariant(shred).?.shred_type,
        };
    }

    pub fn getShred(packet: *const Packet) ?[]const u8 {
        if (getShredSize(packet) > Packet.DATA_SIZE) return null;
        return packet.data()[0..getShredSize(packet)];
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

    pub fn getLeaderSignature(shred: []const u8) ?Signature {
        if (shred.len < Signature.SIZE) return null;
        return .fromBytes(shred[0..SIZE_OF_SIGNATURE].*);
    }

    pub fn merkleRoot(shred: []const u8) ?Hash {
        const variant = getShredVariant(shred) orelse return null;
        return getMerkleRoot(shred, variant.constants(), variant) catch null;
    }

    pub fn getErasureSetIndex(shred: []const u8) ?u32 {
        return getInt(u32, shred, OFFSET_OF_ERASURE_SET_INDEX);
    }

    /// must be a data shred, otherwise the return value will be corrupted and meaningless
    pub fn getParentSlotOffset(shred: []const u8) ?u16 {
        std.debug.assert(getShredVariant(shred).?.shred_type == .data);
        return getInt(u16, shred, 83);
    }

    /// Analogous to [get_chained_merkle_root](https://github.com/anza-xyz/agave/blob/7a9317fe25621c211fe4ab5491b88a4757d4b6d4/ledger/src/shred.rs#L740)
    pub fn getChainedMerkleRoot(shred: []const u8) ?Hash {
        const variant = getShredVariant(shred) orelse return null;
        const offset = getChainedMerkleRootOffset(variant) catch return null;
        const end = offset +| SIZE_OF_MERKLE_ROOT;
        if (shred.len < end) return null;
        return .{ .data = shred[offset..][0..SIZE_OF_MERKLE_ROOT].* };
    }

    pub fn setRetransmitterSignature(shred: []u8, signature: Signature) !void {
        const variant = getShredVariant(shred) orelse return error.UnknownShredVariant;
        return setRetransmitterSignatureFor(shred, variant, signature);
    }

    /// agave: get_reference_tick
    pub fn getReferenceTick(shred: []const u8) !u8 {
        const variant = getShredVariant(shred) orelse return error.InvalidShredVariant;
        if (variant.shred_type != .data) return error.NotDataShred;
        if (shred.len < 86) return error.InvalidPayloadSize;
        return shred[85] & @intFromEnum(ShredFlags.Flag.shred_tick_reference_mask);
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

pub fn overwriteShredForTest(allocator: Allocator, shred: *Shred, data: []const u8) !void {
    const constants = switch (shred.*) {
        .code => CodeShred.constants,
        .data => DataShred.constants,
    };

    if (shred.payload().len < constants.payload_size) {
        return error.InvalidPayloadSize;
    }

    const new_payload = try allocator.dupe(u8, shred.payload());
    @memset(new_payload, 0);

    var buf = std.io.fixedBufferStream(new_payload[0..constants.payload_size]);
    const writer = buf.writer();

    switch (shred.*) {
        inline .code, .data => |*typed_shred| {
            try bincode.write(writer, typed_shred.common, .{});
            try bincode.write(writer, typed_shred.custom, .{});
            allocator.free(typed_shred.payload);
            typed_shred.payload = new_payload;
        },
    }

    const offset = writer.context.pos;
    @memcpy(new_payload[offset .. offset + data.len], data);
}

test "basic shred variant round trip" {
    try testShredVariantRoundTrip(0x4C, .{
        .shred_type = .code,
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
    try std.testing.expect(.data == variant.shred_type);
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
    const merkle_root = try getMerkleRoot(&test_data_shred, DataShred.constants, variant);
    const expected_signed_data = [_]u8{
        224, 241, 85,  253, 247, 62,  137, 179, 152, 192, 186, 203, 121, 194, 178, 130,
        33,  181, 143, 156, 220, 150, 69,  197, 81,  97,  237, 11,  74,  156, 129, 134,
    };
    try std.testing.expect(std.mem.eql(u8, &expected_signed_data, &merkle_root.data));
}

test "getLeaderSignature" {
    const signature = layout.getLeaderSignature(&test_data_shred).?;
    const expected_signature = [_]u8{
        102, 205, 108, 67,  218, 3,   214, 186, 28,  110, 167, 22,  75,  135, 233, 156, 45,  215, 209, 1,
        253, 53,  142, 52,  6,   98,  158, 51,  157, 207, 190, 22,  96,  106, 68,  248, 244, 162, 13,  205,
        193, 194, 143, 192, 142, 141, 134, 85,  93,  252, 43,  200, 224, 101, 12,  28,  97,  202, 230, 215,
        34,  217, 20,  7,
    };
    try std.testing.expect(std.mem.eql(u8, &expected_signature, &signature.toBytes()));
}

test "layout.merkleRoot" {
    const signed_data = layout.merkleRoot(&test_data_shred).?;
    const expected_signed_data = [_]u8{
        224, 241, 85,  253, 247, 62,  137, 179, 152, 192, 186, 203, 121, 194, 178, 130,
        33,  181, 143, 156, 220, 150, 69,  197, 81,  97,  237, 11,  74,  156, 129, 134,
    };
    try std.testing.expect(std.mem.eql(u8, &expected_signed_data, &signed_data.data));
}

test "fromPayload" {
    const shred = try Shred.fromPayload(std.testing.allocator, &test_data_shred);
    defer shred.deinit();
}

pub const test_data_shred = [_]u8{
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

test "mainnet shreds look like agave" {
    const test_data = @import("test_shreds.zig");
    const test_shreds = test_data.mainnet_shreds;

    for (0..test_shreds.len) |i| {
        const payload = test_shreds[i];
        const shred = try Shred.fromPayload(std.testing.allocator, payload);
        defer shred.deinit();
        const actual_fields = test_data.ParsedFields{
            .slot = shred.commonHeader().slot,
            .index = shred.commonHeader().index,
            .erasure_set_index = shred.commonHeader().erasure_set_index,
            .merkle_root = (shred.merkleRoot() catch unreachable).data,
        };
        try std.testing.expectEqual(test_data.expected_data[i], actual_fields);
    }
}

test "merkleProof" {
    const shreds = try sig.ledger.tests.loadShredsFromFile(
        std.testing.allocator,
        sig.TEST_DATA_DIR ++ "shreds/merkle_proof_test_shreds_34_data_34_code.bin",
    );
    defer sig.ledger.tests.deinitShreds(std.testing.allocator, shreds);
    var i: usize = 0;
    for (shreds) |shred| {
        const proof = try shred.merkleProof();
        var iterator = proof.iterator();
        while (iterator.next()) |entry| {
            try std.testing.expectEqualSlices(u8, &test_proof[i], entry[0..]);
            i += 1;
        }
    }
}

test "merkle tree round trip" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const size = 100;

    var nodes = try std.ArrayList(Hash).initCapacity(allocator, size);
    defer nodes.deinit();
    for (0..size) |_| {
        nodes.appendAssumeCapacity(Hash.initRandom(random));
    }
    var tree = try nodes.clone();
    defer tree.deinit();
    try makeMerkleTree(&tree);
    const root = tree.items[tree.items.len - 1];
    for (0..size) |index| {
        const owned_proof = (try makeMerkleProof(allocator, index, size, tree.items)).?;
        defer owned_proof.deinit(allocator);
        for (nodes.items, 0..) |node, k| {
            if (k == index) {
                const recalculated_root = try calculateMerkleRoot(k, node, owned_proof);
                try std.testing.expectEqual(root.data, recalculated_root.data);
            } else {
                const recalculated_root = try calculateMerkleRoot(k, node, owned_proof);
                try std.testing.expect(!sig.utils.types.eql(root, recalculated_root));
            }
        }
    }
}

test makeMerkleTree {
    const nodes = [_]Hash{
        .parse("Avu3YJ9MpG6huLiaEBUs7itdTQFSn6vkNanGcthq9w54"),
        .parse("GVF24L5qCiF62NRaLCWeJ1qfVZRYzne13unogpc551jx"),
        .parse("83wW8QQ8skrj3Lj7FtKsRnK8gE8sJRoxbEdRgPAUtmoc"),
        .parse("Euw4JJYaFdJoHBowj5HsydBqRRr4jQGjZ6cSxidic8RW"),
        .parse("C84zcesazkS12kFSA3T4sf8BY5y9JkaJdvmMSSfMeduf"),
        .parse("Ffzixbkk66T817BBAYuX8FUGDHcfvmwJh7H6vG5BV1sU"),
        .parse("63CNwN3TyS26v4A7XiEouQjLDgZemRW3Jv5STEyXL7x5"),
        .parse("HNvav4QV3gjF4WQqcZhFEqXdXX7TvqLp948eCFcR6mHZ"),
        .parse("DbctQvG9j3YAJga8mngz2wxpR78nSHb1AF7AiAuGjV8q"),
        .parse("DVmofySDmFxrLgMRVwDVHRk4nugZhpyoZ7uHrTQfyma7"),
        .parse("7TK5tEQxV78HNX8rh74eFYt51Pj8YWxgbQrVAHjaZrnb"),
        .parse("Gg43BctSfRxhQeMJ9DfHzinuBopj3RN9nc6FRAzMfgnx"),
        .parse("2YWFoRGqQLe6fStqtpLoj9ZRNp4ymFmsC5KfMnWsKeyj"),
        .parse("Ef7WKvLsAR7a3HdGrhFJDFjVYMfy7ELLyfgVkYLxN9f3"),
        .parse("2DBNDzRpKt5ehUUeYM5o73CtdcLGhdZTHUaCKhM5A5Wp"),
        .parse("7VP1Gucxen6Y4RUCiRYiBgjKCaRAHWjCGWComPoxzxYG"),
        .parse("CD7EjB1Dkk1DQ78LzfUSLXpkjmwZwCCY5DLhD5fyeiYm"),
        .parse("5AomypabrrtAyh1n6hcvPhDp5mwKwV2Lf4t42k5mBuga"),
        .parse("6UqRDQ1B1LGFtADJf4i4bfvgNTEfiR7w7hppYQLtMoHQ"),
        .parse("CiGorzhT6qMMGEy95ghA7kWnoQRq6BdxpT2vEMCz58dk"),
        .parse("FcjVvzJwozaUNpHPLUDsCRdqboyxA85EWG4iAz3zM37c"),
        .parse("HbE2dgxM7YxMsqRXWGXWz4BFL4Xh2fP2iug31arspzQG"),
        .parse("CtNg3dw3o7YieqU2HVrGNTcKgyLseTfs3Hj7t5hLtXuT"),
        .parse("FXx2kK2WBSZjVVuKmdqCasC9UQzqPyvUNrxo2kPsJffd"),
        .parse("4pVU9F2sMYbj994HHXc74BT1m8UkDpnrtTyeSzukhpCV"),
        .parse("3iiaEpFZkaEgRH2vt36siSu6u2bVs7Wb6KbJJbE3XeUj"),
        .parse("8pBEYyqpM5yM11R9FYQ9Xs1Fafve3nbZTHHr3MNfmoQu"),
        .parse("D5pMWDvEZAmJJJiLw8GS1kj6XFRAMqjabRLpDHvNGKdo"),
    };
    const expected_tree = [_]Hash{
        .parse("Avu3YJ9MpG6huLiaEBUs7itdTQFSn6vkNanGcthq9w54"),
        .parse("GVF24L5qCiF62NRaLCWeJ1qfVZRYzne13unogpc551jx"),
        .parse("83wW8QQ8skrj3Lj7FtKsRnK8gE8sJRoxbEdRgPAUtmoc"),
        .parse("Euw4JJYaFdJoHBowj5HsydBqRRr4jQGjZ6cSxidic8RW"),
        .parse("C84zcesazkS12kFSA3T4sf8BY5y9JkaJdvmMSSfMeduf"),
        .parse("Ffzixbkk66T817BBAYuX8FUGDHcfvmwJh7H6vG5BV1sU"),
        .parse("63CNwN3TyS26v4A7XiEouQjLDgZemRW3Jv5STEyXL7x5"),
        .parse("HNvav4QV3gjF4WQqcZhFEqXdXX7TvqLp948eCFcR6mHZ"),
        .parse("DbctQvG9j3YAJga8mngz2wxpR78nSHb1AF7AiAuGjV8q"),
        .parse("DVmofySDmFxrLgMRVwDVHRk4nugZhpyoZ7uHrTQfyma7"),
        .parse("7TK5tEQxV78HNX8rh74eFYt51Pj8YWxgbQrVAHjaZrnb"),
        .parse("Gg43BctSfRxhQeMJ9DfHzinuBopj3RN9nc6FRAzMfgnx"),
        .parse("2YWFoRGqQLe6fStqtpLoj9ZRNp4ymFmsC5KfMnWsKeyj"),
        .parse("Ef7WKvLsAR7a3HdGrhFJDFjVYMfy7ELLyfgVkYLxN9f3"),
        .parse("2DBNDzRpKt5ehUUeYM5o73CtdcLGhdZTHUaCKhM5A5Wp"),
        .parse("7VP1Gucxen6Y4RUCiRYiBgjKCaRAHWjCGWComPoxzxYG"),
        .parse("CD7EjB1Dkk1DQ78LzfUSLXpkjmwZwCCY5DLhD5fyeiYm"),
        .parse("5AomypabrrtAyh1n6hcvPhDp5mwKwV2Lf4t42k5mBuga"),
        .parse("6UqRDQ1B1LGFtADJf4i4bfvgNTEfiR7w7hppYQLtMoHQ"),
        .parse("CiGorzhT6qMMGEy95ghA7kWnoQRq6BdxpT2vEMCz58dk"),
        .parse("FcjVvzJwozaUNpHPLUDsCRdqboyxA85EWG4iAz3zM37c"),
        .parse("HbE2dgxM7YxMsqRXWGXWz4BFL4Xh2fP2iug31arspzQG"),
        .parse("CtNg3dw3o7YieqU2HVrGNTcKgyLseTfs3Hj7t5hLtXuT"),
        .parse("FXx2kK2WBSZjVVuKmdqCasC9UQzqPyvUNrxo2kPsJffd"),
        .parse("4pVU9F2sMYbj994HHXc74BT1m8UkDpnrtTyeSzukhpCV"),
        .parse("3iiaEpFZkaEgRH2vt36siSu6u2bVs7Wb6KbJJbE3XeUj"),
        .parse("8pBEYyqpM5yM11R9FYQ9Xs1Fafve3nbZTHHr3MNfmoQu"),
        .parse("D5pMWDvEZAmJJJiLw8GS1kj6XFRAMqjabRLpDHvNGKdo"),
        .parse("8FhhiixoVmfx57W684YGXK2KF8WsC8bJCLye7WSDRuXX"),
        .parse("89Dn6RSPmjbhx2z3yTmxbpp53WhYdHZULrJxW2kutnB7"),
        .parse("FFWCyXHm8ZW4uBKtnr8adMzJtfc74jhiCGjbxkjEMFmj"),
        .parse("9BDbWZrbLzvUjSANudZZD2GkV7cE3Coqo8Fnyh1Jz4ww"),
        .parse("A12oZ3tmuEQf9PjJAFL3agzs4fxKUS5Xwq9oLkswsK1b"),
        .parse("2bPX8bpGqUbUM16MbxLs8LUb1wAruHoVmsaw2io9NiNJ"),
        .parse("D7uzP68j1WjinDcroo7rR77UZoaafdfjAzMd4pSyT6GJ"),
        .parse("7SJ7ry6TDcbtCybXDmwQmQwuUQVq6cCAmmiVxR7YhFik"),
        .parse("3NLoB2mVwq87vSKTv7rGFHNgVvqy8ZjaoqrQM4oq7jXo"),
        .parse("23QuXVPFnAbhFxkKf2sk3KNETyVkFk9EZM3A53HZWotc"),
        .parse("BbveVMySjupr6Mr2dkFeEJoxEq1BLzPB5MqWtmKXYpmU"),
        .parse("FL5wDqQNKgoibFJQod5GXRLZoqsKYocKF3WqN3Hjd1ko"),
        .parse("9gzituZoRNCM9F14Nr2uzzEfBVtukpfcNU9SrNHDEJb"),
        .parse("B95BBuX6P5hF6Xq1w6eEpT5py5YwFjyEKmJKDL8yrLkq"),
        .parse("4P5aCVJsuTUADqevAfEvzLBQ7aGTy2Hu8kygwoENNtbp"),
        .parse("6M92Yvq7gsA18wx6S5RNmRgVXE6vxheskHBeVeNng5BF"),
        .parse("55vksYsEAB5LvyCCBKEu8u2QwznSxFp5YgT4vchxJxJR"),
        .parse("HVqsRLBhmM8aBbZNMYktHZputgsUBtDDYaBVSBgtUFub"),
        .parse("9zWf6ZniGVr8c6PivETabujn5TyHPMyHjRjDBD1iDALN"),
        .parse("8fNrCWvf1T64xi4UEqxnqwRmABhTK9TZevaDbQhfp46G"),
        .parse("CYuvqKDoo6ohbi1XBYupwVotHRXY6dZmXWU7Snggt6S8"),
        .parse("H3FEfEnAZUutGqeQFWgNAuvwMs4MJELq7HnvsQg33aUz"),
        .parse("ExfUZS2bwAh2VTQuMpW48AHu2kGQNg8tEJhLVT2fYKgb"),
        .parse("8Ekq6Wg3sMSLnqqf81vZVJ19zdEeThb8mDruYp3Zmz8p"),
        .parse("9XiUqSkgM2hs7ofTwdnAgSzYXqFigi6FGbGu28WvPCaF"),
        .parse("CKjXJV7SLzrxyaJUc4xaUxcM8M3Eexfxv3MHcou13N5X"),
        .parse("EsV8thKpJBh72M4pEm3ZYUrTS8xge7CEzY4L4waQVcrJ"),
        .parse("4Ldwcp5b81BrE9e4SECwc4kmDq3AEuvaaATvU1eF7Phb"),
    };
    var nodes_list = std.ArrayList(Hash).init(std.testing.allocator);
    defer nodes_list.deinit();
    for (nodes) |n| try nodes_list.append(n);
    try makeMerkleTree(&nodes_list);
    for (nodes_list.items, 0..) |actual, i| {
        const expected = expected_tree[i];
        try std.testing.expectEqualSlices(u8, &expected.data, &actual.data);
    }
}

test makeMerkleProof {
    @setEvalBranchQuota(146 * 1000);
    const tree = [_]Hash{
        .parse("Bx9LW8aTjrh13cEeBru7tmyTrWkiXWnwVP7wNMy364j5"),
        .parse("FpV1bWLfkM65XEV2MuEB5jDFXPTmkZrL8ycdMstfJQrk"),
        .parse("stvy1uVFRKv8QrVTCAEZFRCkGssSic1ya9ibSmkDYsE"),
        .parse("AaewceZsfwdzXZZTWv2vZrt37STiaqMyVXCoT4BP3HKH"),
        .parse("7rWjphywgPvnDkkTcoA2166bYVq7U6Ux3fRYnAnE3yzU"),
        .parse("Cx5qGtjravyGkGZdZAPYevAPJUAKBYvecmchK5iZv16e"),
        .parse("C6b1zy8fdZsiQCCtSeEomMhXYMQRHHTEUnB24vZr2iZn"),
        .parse("EugqFJFXPfKaDxmgJnjfVppyaxvPPeitnX2USqmh6QjK"),
        .parse("9qvLbBQsS3NfwWuZYoMpnefqfE3fx2SKEpm9YufLcoZm"),
        .parse("AaNEKZ639cHJaHTaodEcv6GVDu2fZd236YVVWfqsgh8V"),
        .parse("HE8HKAM3ALTCJEzGEG83TTEij3i3V42T3seuJPmeTMN8"),
        .parse("6oY87eJaX8PLUNp8Qkyce34ap6CHm4itj45Tg2ZUPfQG"),
        .parse("GBmdTsaw4ZuYp2ALLvPQapbNyN8uBAM4yxqi7UEM9WqS"),
        .parse("5zffPFkVc8Yz6wRdzDVHk5tGiMt72Xa1S3FSQD79kzyB"),
        .parse("6mYt2Bv9eJsyjNjNgLn7cgvoNwEi2yUXq3chSaN2tBAk"),
        .parse("E1kfyXtKMgGE9TVAnU4FDVdE3bWVV3iBAbeKMJQqTy2M"),
        .parse("C89cUQPoqZRhiBCG8N7cqvSuPBEkpNJfroA9eMDhzkyF"),
        .parse("AjWMnZR37u2txd6jsS4Y3PHjo8GeCA9WWwrGya8DU2so"),
        .parse("AbnsxL1QF7B1Ljki5DeBzshaDoUB3zm4sAvBvHoMHDvE"),
        .parse("4DHzjExhzgHZBDc2KmAagCTfRj2SUjTquNuvTgZ6bpfq"),
        .parse("FFKiDtCVewMavX8ZxZCGPxN9zRtYR4BfJ1rSLrHGPESF"),
        .parse("4mMbVaCL5V3DVHHJ5zV9HxmVMAwrG3SX6FUvLCwSUiMq"),
        .parse("2DzuAMMcMdV8XarJhwbpgfTo3DAWvyevyowB7ugd9B5N"),
        .parse("EMdcMzfRcJQqMuGbXtUHwNyAkx4qCXwep6PYyaUsMf86"),
        .parse("FBYkn21APR9pThEHFUtFHfwi7T4TR1yNeAMRpsZ3QYCT"),
        .parse("AgGCfSV3aaGyLLhWohZjenZnEptot58JNkVLHtzUrv1J"),
        .parse("HFJrA51z4Lk1zyDScZ5TDQguP481E6Z9wgq3hhKgrH8o"),
        .parse("GRqdZSt53JnUksMp8qqVPK1B25ZXtVhDGhuu2znYgSsW"),
        .parse("7iFLoVuVUKnzf8N5d1R3beZoo5zFUYVqEieHdRky7qyw"),
        .parse("5REoZpdLej6Gdp75bGvi2exydk1X6vDYMMp8jaeE3BFL"),
        .parse("8fs4yx2jFUr6u2N4qZoxznk18SyUbkRRQeLsWKk3CCec"),
        .parse("9PNXzpa5GfPBYLgUyfcbSYHbXa1VvHEsnDZS1XMxaR4s"),
        .parse("3GfjjMPKzDEQhK2eo32t22qMefVJDPTuWhaUAzKVm7ZU"),
        .parse("26L3tEsmYqLSqThQKcpPtk7wPyHc4anVFTt2w8NDSRjn"),
        .parse("33vRjcTAVz8hUQreStDBEcbiwp51LFbMAzoPfkeReEPq"),
        .parse("5e4dq7ZD1UBToE9j85bvFbzhmc7jf4tNpxsDeii5ruK4"),
        .parse("3qyf4nWp524hSdbPi1GEpw7iB4A9Zv5pQe1Zqdx8ZJGn"),
        .parse("29Q1jRaE6oQkwn2N4Mkpg5CsRfXB7bngj1tFCxPakciR"),
        .parse("HvoTPjs5VwWaS5coBL2Tso6DHiMczhJwHGxp24PVnr47"),
        .parse("7PW6vwfBschMSvVXmSN6q72XTVhFDAB8Ek5RGcLfgYhi"),
        .parse("9nyEHFufr4WjFS6rnK64zvQNDj66urFk7ZBvmjGJ1vH8"),
        .parse("ChDuVAdfL16tvUQtEDokcCHM5qtS6BowW1AT7h3yjgsM"),
        .parse("544pGFuvRhB5A5CUnwDg6dchPdye99VJtFuSGk54DwwZ"),
        .parse("6ptdtQyxV3TqvZsCUw6AwrkstfSq3bgKxLPPM4xjD8NZ"),
        .parse("4XRJcKZKj2UfaWkeUs2gWDshzeeBCs6Rq82pJJFXsmQr"),
        .parse("FuFmzBJhNkqcYgNAhVPGsJbCGXcnyi1yT3FYb5C4r8Z7"),
        .parse("9BA7PjW4ViTLcEWT1iQS1rNX9thkiFg87si5a8EDA5y7"),
        .parse("2Zaj64ZdqawgKBGbpFEXJw1Kk1kFUzNjeNGL65ah5M6b"),
        .parse("3W8jM1YhspQJPMq7v6mfo2QbNyYVFGoE8rGcSgpAF5rv"),
        .parse("GGpGNC9pwiBL4C67F6qoJMzUdZ3RBtKpqE5Eb6Bvr9BA"),
        .parse("8FyaXRHM6amauitV56xReQVST5761mexLTRrQVERssRH"),
        .parse("AK9MvRkinupJMbQXmZQ8tKQchHqo4psoYsDq5iS4oz4M"),
        .parse("2zGtEcqViQ4yKkd3bJBkZxipNXMsxoSCDHdiBntmHNep"),
        .parse("6GLmAgGohejq6afPzFy3ckCaRgzannDa6WB5mccMVSS9"),
        .parse("3X73e745Duuemvp7BVjPStE99JqdisyrRFWGqbNwCWEs"),
        .parse("5DcQxHDWhT6S29EmcR23emFKfF8Ns2N7L4nfedx9GrJN"),
        .parse("2PMrr1jXhouP5CVKKM8TeJBeLuaHJjMvvfQQ2XXTU4fk"),
        .parse("8zYkwyXmf8SFXcf8ckiTEefLy8ycPvXVbNQ6bT69pfS6"),
        .parse("BEHGhyvyM4WkDyZbUxnoghNBDxDN2NXq4imnASiwk9H9"),
        .parse("6RwNHCQL3aT7zgTQgRugxC9SBVAq6JkZ7oV3QPtgS8CF"),
        .parse("4rbGzhJoyrDUEBNFnWXCbNiSAgbmnSm6ct5WLnBWbwQn"),
        .parse("HRL9nCpU4dYz2uQEP6YvXLqtHpnTbZizw1hc977yFUqs"),
        .parse("864cccyjMbHs1nHA62roRhjXkRyNTMi4pM8qXfiEHwJC"),
        .parse("Be5A1QfXGh7KjUFcgJuAPpBG3ZoKjedkqBSU42gDCrdS"),
        .parse("58qmjy9wNp58mjUkfXNX5B9ktTDcaxGC6t4vrzsndELp"),
        .parse("5bx6gYTcVxLBvtf9WmjTUd9gZZKUSLiDiQhiJM6iV6cx"),
        .parse("GZ3p8cpjTEXfqLqY3PjzNsqY9nfZDbR1bM8Wrgf7VHTy"),
        .parse("ELRJqXN61mTu9F9oj9DyS3ywnbQNoh3j2K6gfsBgMjg1"),
        .parse("F5grQyLqPmFjsjP5WQWq138Z4wvomw5nW5qREkbFycot"),
        .parse("GX24x4ZPEFUwpWZom7gSorwDqH5v39NNdaCcbvJUzg4v"),
        .parse("3mFtDKF8RzuzH4x9SVErd1LkYTwTv992RGTU9LoMye3i"),
        .parse("HeYVCMjVPwWQ3zMpF5vqZvfmm97toP6AoZyPTsLTW3sW"),
        .parse("9eQXk1Puxrp9ADWVE7SHxni2ab7Y2uCPFL2yrKPWv64B"),
        .parse("CDRBanMrvbAzTts881jUTMUSNxLSKQT2cJYdn6CYFRXq"),
        .parse("4CqcNaEGGBbxWE7qGuJ7rQHfpUowkUTXtjYrPyyGZQ63"),
        .parse("BJEY5rk8fvRvJwxt2E2qzYWvxhcPrb5ESyXXuehHgc7p"),
        .parse("AUi1FEP4Sb6NhGgns1ttKvP5ZXAoYYtA8UfmvF6Sg9wv"),
        .parse("DwLYXjMcn2tE8wuM6ShQ8Yx8zMPsUVAA7NYQDoAbthiN"),
        .parse("BVR6gB4GPM1fVZFNehNkG13LSbwjecGSCEbYUu5JY5kR"),
        .parse("Af7GsqqFBkdMQLsvd87sh9MwzgAnnfRV2pDghkX2VhPa"),
        .parse("4Qwxnp8VjpXK1ztpZtYydEXMpJpkQCAt3p7VLkt29gsq"),
        .parse("J62wxQtganLZiMMiPy2X2VsdwBMTwA4z99HYEYqGF62J"),
        .parse("ExKSbUQm2rM3QSPuN3WVrP5Gvdpo1VF2U2nDR4KRv4qu"),
        .parse("HiS77MrGWUsG2WwWmCgXQm3bL6LUoqjx1G7WEcTP67DC"),
        .parse("57kbNWRpQoCMbKGHMWviA7rSU7W2weZwK7mLP24ebPU"),
        .parse("3PDMX7pzsD8YYqAEPzm3Rw5hmPrfex2EEtFsnbxJgfJS"),
        .parse("3JjY5Y9cS8KpVXMFbdza8vTpf4cCjVqYZKxgk6TbbwNA"),
        .parse("J6am9e5xEQHFSK1SvSoYHiFmB3oiGYM5CcAFPC7qrHfh"),
        .parse("3jqQxSAvpaPH8WSezBbGR3me5Rftwnb53MTs1BAvZGWf"),
        .parse("GAknjw45DGKy4NmB2Hp6Gjye1QcBCayZXtWm5hoiMZhK"),
        .parse("98tLRxnihiTtyye4CxmMC4VzP9DT3usPFEwJAY1uhtCw"),
        .parse("BRy9MeT5qssZWsMgvytPXTXSSJcip8g6UdifXn4N8dZ4"),
        .parse("26dDnoc2DEp4Xmr8qAPq56BjGCPzyPgGCe366fNNmrsR"),
        .parse("8JLhLrCrwSX3zCcGAgL9VrVPqTtBAVsaVLKf8dQcyMC2"),
        .parse("HjnzKdG8oUxLhnRj8bzMFVpfyZudv72zRrkC8EQyYw2"),
        .parse("AfHf7M87CbErc48Sb4aNf5Cvxk47hL414xQLrKtqJhDC"),
        .parse("4CXveM6jn53oWdz9euYpWrEb5TEPWauVkHmisz6Jn6RR"),
        .parse("EzK8nNawwjfkirhgaW2pQpPuQWbKHm8ciGixn9jnf5d9"),
        .parse("Atyq6rxw6ke4qu84x3QhKWq1Vd5n6kvuGeWAqbkCqdzG"),
        .parse("DVtZ4C1ff1gszEjbhNamz9iBpaasSJDpKuZg7TMGrAFa"),
        .parse("C6WEeV7vzcCxxjWdyEfvoqZmHEbybcf812mW64Z1UsAb"),
        .parse("BsxdmftSSjGdhVvEuHDXsFU7gCYmMtWj8CZz6923Dxqb"),
        .parse("4R9Zo99us2XeBBDtnASG7ybkzjX79BiZw5iZ1qXoSxy7"),
        .parse("3S76Aa3EQqgVUENFfxq6ExNvD6uRVDxsJ8Se7H4oLrsY"),
        .parse("8fjA37W4yPTPu72j5mxE66DMJxniCckGuCWusEzuGcpk"),
        .parse("6EQVYYkVkCEo9UkM79EQp1BY19S3z7BhRgnPQW7PYqZe"),
        .parse("2jpcTvWKHu1TTo2VNroTeN2RiJ5NoWTNZnu1gmADPsDi"),
        .parse("HfpXFNuskqvADJpadEAU5d89RdaL8ocNe12pZ8GZy9Nc"),
        .parse("HFDNt5ZztGAbCN1mB6yj48XZgZ1ccf9sHo79EQejam2"),
        .parse("3zGqA95TBckLbw7q213DnnMQbsVfmo1dPYUnQbmoTSaj"),
        .parse("DmiKQ2yfzwFW857LnCbkFkg6UnDRe2bsT4vFe6CRtY4Z"),
        .parse("FPCxSZSAYskyDQdKnFaMs4KeDyVjGeA1HtaN4ARRkUmr"),
        .parse("HeVBzjBHGKXEXvKZSwthsrmKRZ1a3MSEjdAQ7vxh6dCt"),
        .parse("4vDREHaEV9BEsebAdcT2hTJ3PASxVGctEyKALrH4VoV6"),
        .parse("FB1Z2nSG3EGqyQRfjZwBnaQXyPDjFQ8nUwGgGgJgZyvS"),
        .parse("C3Nres82334oRKseqSKN7RgeWKQzBoEiqz1kfTBNXgrf"),
        .parse("CNLgTpk5FCW7ncYMU3nB27so7QE5BizpjVG8KAa6h1iH"),
        .parse("5E4aGGpbkutYzXxvfXf7pSZGXnNguSdLbJEDHMX3i6AS"),
        .parse("EXvua2pY15VHSJGUwQB6v1dGBUPc1vEixPavkFzxWHC6"),
        .parse("AuYHmAUg3ZJGPCtLvpzRUoWAZzYdbnKX8bj5vkCStDKC"),
        .parse("J8w6CXQaGbiMriE5EQ6gNSDfR8REf9Y5tqmGWPSg8GbF"),
        .parse("FZsyfzm6HgtR2sU3B2C3TmfsuNY2CmXjQNf2wD5nimiZ"),
        .parse("5hkdwEuHwG6RdWvVkHYELeJ8XsM2K7TtFbFay3XMGwAP"),
        .parse("eRKZbFKJkinG1fZ7hbv9eogkB56BJsbiorMkCSSPp3V"),
        .parse("7FMsczNNzwohTpEfzRthaZrtxAQkNjrZngYxYE7vwYbS"),
        .parse("G1A2o3JhxSKe1BJXURDJN3DvAeihUmn754SqmNPHopjL"),
        .parse("HDzsPL28ZWcSJzRYcbr3mWbFVDxy5TVzreszMZe2mF2N"),
        .parse("E19LBz8BbGxD8JdFstv3BPLxmSDkLDELrHeJfmbvz7LL"),
        .parse("2J6dzFFBeBFfbhsdXhQdbHWgim8dynUY622jB8PAftQy"),
        .parse("BezvqJJoBFa6qqdTawuBjeSDPeqvCh8uuwEGgGSphUZ1"),
        .parse("E8TSKDo4DudNDVj31WRpriczGUianB59mExsk4FXKXLa"),
        .parse("8z4FYYP3bPHpMicrZ2Bwop3Lh6jw3ShHuWFZqPr3RnDy"),
        .parse("CSu74jNs9HDwtKh4ppVAHoQm7seEUcjxpVxX92yFy7wC"),
        .parse("4niaphXxYzQ9zjVFScAyJ2v9S7hkgGgemCzrNkTW5UUY"),
        .parse("Bt3EdSLbrzmg9YinymV4UXPzwpaba2Ng4ALAvAdaK3tL"),
        .parse("43kNPuYbgKydPj33stP7r9371az9D2DmsRVpLgcZkGDe"),
        .parse("5YEZY8unUm6ztiyXf4Xa1aYDAwuUjRPFnujxL44zKjCw"),
        .parse("8Mydc1tbU7c3HP67ntoiJQa4SGwbqaHJR7FGcsyqVVCg"),
        .parse("FMJP8kyHLVb3qt7w2n2XZG6i3fJbgi7MXNgdsGzWbdVV"),
        .parse("3nWYmM6aSX6wwcxpxVp9p8Nf2pMCMj6i4Hij3GKq6ZJY"),
        .parse("9Heu1ukN3DM7KzgaGk8EUDqJoB81E1h4r72RD5wG2Ud"),
        .parse("5PQQLYveY6fHdFzQWukSzbT1J6QCDS64DKgg2v4BgE1a"),
        .parse("E3MWANRDpfXLKjvJGtog4GUh5D5MrwdzKvq6S5da2jSe"),
        .parse("4ZtSJ3pNL8j8escBBFD4JdZqnTJjpniaJqDbKhUCaU8M"),
        .parse("3SjiiTZMXsGS33QEt4mimdBNScBsyNrZuChWy6TnQd5z"),
        .parse("14ssfeqapneaBmL3eGVQBnB4gbTMaaAFZaUQZs26rDr3"),
    };
    const expected = [_][20]u8{
        .{ 142, 88, 63, 241, 80, 194, 115, 62, 209, 60, 63, 141, 196, 45, 211, 9, 145, 60, 5, 16 },
        .{ 128, 114, 151, 64, 189, 69, 180, 252, 187, 219, 88, 82, 36, 178, 137, 138, 223, 151, 59, 222 },
        .{ 44, 99, 97, 29, 31, 141, 236, 200, 68, 34, 226, 123, 11, 45, 214, 144, 17, 140, 240, 42 },
        .{ 193, 49, 89, 138, 77, 2, 103, 144, 93, 181, 101, 150, 120, 77, 14, 125, 41, 162, 14, 211 },
        .{ 67, 111, 22, 19, 137, 37, 71, 8, 66, 231, 112, 45, 56, 78, 126, 52, 213, 167, 217, 96 },
        .{ 65, 43, 252, 148, 140, 235, 207, 125, 56, 245, 130, 242, 95, 2, 185, 216, 208, 149, 175, 160 },
        .{ 36, 79, 50, 101, 43, 152, 43, 26, 133, 95, 29, 33, 83, 43, 125, 205, 187, 30, 10, 47 },
    };
    const proof = (try makeMerkleProof(std.testing.allocator, 2, 72, &tree)).?;
    defer proof.deinit(std.testing.allocator);
    for (expected, 0..) |entry, i| {
        try std.testing.expectEqualSlices(u8, &entry, &proof.get(i).?);
    }
}

const test_proof = [476][20]u8{
    .{ 13, 254, 186, 111, 139, 5, 181, 63, 145, 115, 242, 87, 188, 168, 39, 180, 2, 55, 8, 105 },
    .{ 233, 159, 111, 52, 53, 179, 0, 101, 35, 252, 187, 135, 10, 64, 239, 110, 68, 11, 251, 167 },
    .{ 194, 187, 155, 50, 128, 112, 45, 142, 79, 169, 169, 76, 69, 100, 8, 37, 156, 158, 31, 26 },
    .{ 181, 235, 70, 218, 19, 231, 82, 224, 204, 3, 152, 141, 57, 29, 29, 7, 54, 240, 236, 148 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 151, 61, 98, 134, 41, 73, 218, 33, 123, 6, 89, 136, 168, 209, 190, 139, 149, 100, 254, 142 },
    .{ 233, 159, 111, 52, 53, 179, 0, 101, 35, 252, 187, 135, 10, 64, 239, 110, 68, 11, 251, 167 },
    .{ 194, 187, 155, 50, 128, 112, 45, 142, 79, 169, 169, 76, 69, 100, 8, 37, 156, 158, 31, 26 },
    .{ 181, 235, 70, 218, 19, 231, 82, 224, 204, 3, 152, 141, 57, 29, 29, 7, 54, 240, 236, 148 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 137, 99, 76, 147, 43, 100, 235, 184, 81, 9, 36, 170, 160, 210, 163, 140, 186, 40, 39, 131 },
    .{ 158, 183, 165, 10, 129, 247, 129, 102, 94, 36, 183, 27, 147, 137, 61, 52, 227, 183, 243, 236 },
    .{ 194, 187, 155, 50, 128, 112, 45, 142, 79, 169, 169, 76, 69, 100, 8, 37, 156, 158, 31, 26 },
    .{ 181, 235, 70, 218, 19, 231, 82, 224, 204, 3, 152, 141, 57, 29, 29, 7, 54, 240, 236, 148 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 37, 147, 171, 117, 59, 155, 255, 149, 146, 63, 247, 249, 188, 67, 104, 142, 165, 228, 224, 99 },
    .{ 158, 183, 165, 10, 129, 247, 129, 102, 94, 36, 183, 27, 147, 137, 61, 52, 227, 183, 243, 236 },
    .{ 194, 187, 155, 50, 128, 112, 45, 142, 79, 169, 169, 76, 69, 100, 8, 37, 156, 158, 31, 26 },
    .{ 181, 235, 70, 218, 19, 231, 82, 224, 204, 3, 152, 141, 57, 29, 29, 7, 54, 240, 236, 148 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 177, 188, 121, 202, 153, 82, 215, 254, 87, 97, 142, 42, 190, 76, 37, 161, 73, 251, 100, 64 },
    .{ 165, 234, 51, 159, 248, 90, 210, 66, 72, 78, 203, 121, 89, 8, 211, 199, 55, 223, 174, 92 },
    .{ 49, 131, 204, 221, 185, 26, 13, 59, 254, 10, 245, 241, 233, 191, 232, 59, 34, 163, 251, 25 },
    .{ 181, 235, 70, 218, 19, 231, 82, 224, 204, 3, 152, 141, 57, 29, 29, 7, 54, 240, 236, 148 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 129, 249, 247, 191, 194, 211, 121, 146, 85, 227, 83, 174, 56, 125, 22, 115, 120, 127, 191, 47 },
    .{ 165, 234, 51, 159, 248, 90, 210, 66, 72, 78, 203, 121, 89, 8, 211, 199, 55, 223, 174, 92 },
    .{ 49, 131, 204, 221, 185, 26, 13, 59, 254, 10, 245, 241, 233, 191, 232, 59, 34, 163, 251, 25 },
    .{ 181, 235, 70, 218, 19, 231, 82, 224, 204, 3, 152, 141, 57, 29, 29, 7, 54, 240, 236, 148 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 29, 114, 69, 255, 206, 115, 34, 94, 114, 217, 66, 84, 239, 161, 160, 63, 192, 55, 108, 188 },
    .{ 205, 114, 194, 92, 233, 100, 70, 190, 145, 202, 38, 207, 117, 232, 214, 172, 226, 91, 202, 12 },
    .{ 49, 131, 204, 221, 185, 26, 13, 59, 254, 10, 245, 241, 233, 191, 232, 59, 34, 163, 251, 25 },
    .{ 181, 235, 70, 218, 19, 231, 82, 224, 204, 3, 152, 141, 57, 29, 29, 7, 54, 240, 236, 148 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 167, 154, 51, 61, 215, 80, 113, 214, 138, 79, 86, 197, 218, 61, 153, 21, 111, 241, 95, 25 },
    .{ 205, 114, 194, 92, 233, 100, 70, 190, 145, 202, 38, 207, 117, 232, 214, 172, 226, 91, 202, 12 },
    .{ 49, 131, 204, 221, 185, 26, 13, 59, 254, 10, 245, 241, 233, 191, 232, 59, 34, 163, 251, 25 },
    .{ 181, 235, 70, 218, 19, 231, 82, 224, 204, 3, 152, 141, 57, 29, 29, 7, 54, 240, 236, 148 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 190, 182, 120, 116, 119, 249, 4, 142, 63, 133, 118, 80, 101, 221, 148, 128, 137, 156, 185, 179 },
    .{ 251, 166, 99, 94, 219, 115, 46, 38, 69, 253, 32, 0, 97, 97, 96, 204, 4, 197, 118, 143 },
    .{ 91, 219, 32, 161, 63, 14, 218, 4, 208, 196, 91, 241, 38, 165, 114, 110, 219, 90, 205, 229 },
    .{ 54, 55, 175, 110, 49, 124, 122, 52, 67, 226, 111, 224, 247, 107, 221, 62, 125, 160, 59, 183 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 137, 170, 177, 229, 58, 129, 233, 6, 253, 179, 212, 199, 153, 227, 171, 120, 71, 192, 144, 229 },
    .{ 251, 166, 99, 94, 219, 115, 46, 38, 69, 253, 32, 0, 97, 97, 96, 204, 4, 197, 118, 143 },
    .{ 91, 219, 32, 161, 63, 14, 218, 4, 208, 196, 91, 241, 38, 165, 114, 110, 219, 90, 205, 229 },
    .{ 54, 55, 175, 110, 49, 124, 122, 52, 67, 226, 111, 224, 247, 107, 221, 62, 125, 160, 59, 183 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 107, 143, 227, 58, 29, 150, 89, 108, 168, 53, 237, 167, 11, 212, 42, 16, 109, 28, 173, 109 },
    .{ 89, 207, 58, 134, 174, 177, 192, 249, 146, 69, 68, 166, 151, 27, 57, 130, 56, 176, 147, 209 },
    .{ 91, 219, 32, 161, 63, 14, 218, 4, 208, 196, 91, 241, 38, 165, 114, 110, 219, 90, 205, 229 },
    .{ 54, 55, 175, 110, 49, 124, 122, 52, 67, 226, 111, 224, 247, 107, 221, 62, 125, 160, 59, 183 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 111, 74, 3, 77, 109, 251, 193, 25, 24, 89, 38, 225, 135, 107, 30, 200, 246, 211, 28, 196 },
    .{ 89, 207, 58, 134, 174, 177, 192, 249, 146, 69, 68, 166, 151, 27, 57, 130, 56, 176, 147, 209 },
    .{ 91, 219, 32, 161, 63, 14, 218, 4, 208, 196, 91, 241, 38, 165, 114, 110, 219, 90, 205, 229 },
    .{ 54, 55, 175, 110, 49, 124, 122, 52, 67, 226, 111, 224, 247, 107, 221, 62, 125, 160, 59, 183 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 70, 120, 173, 185, 65, 181, 80, 92, 88, 36, 161, 215, 54, 200, 177, 120, 200, 184, 72, 6 },
    .{ 226, 170, 32, 2, 191, 8, 62, 154, 191, 55, 1, 52, 70, 99, 101, 178, 15, 107, 5, 118 },
    .{ 77, 214, 68, 225, 178, 88, 254, 100, 112, 217, 112, 101, 44, 17, 152, 171, 203, 230, 192, 86 },
    .{ 54, 55, 175, 110, 49, 124, 122, 52, 67, 226, 111, 224, 247, 107, 221, 62, 125, 160, 59, 183 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 133, 249, 244, 253, 205, 134, 33, 103, 64, 120, 179, 168, 172, 119, 132, 54, 108, 238, 65, 128 },
    .{ 226, 170, 32, 2, 191, 8, 62, 154, 191, 55, 1, 52, 70, 99, 101, 178, 15, 107, 5, 118 },
    .{ 77, 214, 68, 225, 178, 88, 254, 100, 112, 217, 112, 101, 44, 17, 152, 171, 203, 230, 192, 86 },
    .{ 54, 55, 175, 110, 49, 124, 122, 52, 67, 226, 111, 224, 247, 107, 221, 62, 125, 160, 59, 183 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 77, 104, 195, 57, 61, 172, 243, 157, 105, 97, 55, 120, 185, 157, 62, 26, 118, 75, 31, 227 },
    .{ 222, 246, 178, 1, 35, 64, 102, 51, 95, 119, 238, 174, 209, 181, 50, 134, 98, 213, 159, 21 },
    .{ 77, 214, 68, 225, 178, 88, 254, 100, 112, 217, 112, 101, 44, 17, 152, 171, 203, 230, 192, 86 },
    .{ 54, 55, 175, 110, 49, 124, 122, 52, 67, 226, 111, 224, 247, 107, 221, 62, 125, 160, 59, 183 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 163, 149, 240, 149, 49, 58, 200, 29, 153, 190, 126, 222, 86, 185, 190, 66, 214, 42, 78, 237 },
    .{ 222, 246, 178, 1, 35, 64, 102, 51, 95, 119, 238, 174, 209, 181, 50, 134, 98, 213, 159, 21 },
    .{ 77, 214, 68, 225, 178, 88, 254, 100, 112, 217, 112, 101, 44, 17, 152, 171, 203, 230, 192, 86 },
    .{ 54, 55, 175, 110, 49, 124, 122, 52, 67, 226, 111, 224, 247, 107, 221, 62, 125, 160, 59, 183 },
    .{ 52, 196, 166, 124, 35, 175, 136, 38, 102, 137, 55, 175, 230, 128, 28, 241, 181, 220, 238, 222 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 89, 72, 2, 204, 231, 217, 219, 253, 238, 91, 86, 130, 60, 105, 43, 196, 64, 217, 181, 165 },
    .{ 196, 22, 58, 160, 152, 217, 146, 176, 85, 246, 84, 227, 238, 120, 2, 224, 177, 222, 175, 214 },
    .{ 46, 244, 26, 131, 254, 153, 240, 201, 43, 103, 66, 177, 87, 83, 151, 78, 9, 188, 200, 121 },
    .{ 94, 141, 148, 66, 238, 198, 185, 201, 221, 217, 9, 92, 45, 244, 3, 226, 216, 38, 242, 210 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 126, 157, 243, 197, 74, 180, 11, 164, 195, 64, 185, 31, 251, 0, 151, 117, 70, 23, 221, 119 },
    .{ 196, 22, 58, 160, 152, 217, 146, 176, 85, 246, 84, 227, 238, 120, 2, 224, 177, 222, 175, 214 },
    .{ 46, 244, 26, 131, 254, 153, 240, 201, 43, 103, 66, 177, 87, 83, 151, 78, 9, 188, 200, 121 },
    .{ 94, 141, 148, 66, 238, 198, 185, 201, 221, 217, 9, 92, 45, 244, 3, 226, 216, 38, 242, 210 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 211, 6, 38, 161, 23, 84, 250, 148, 105, 121, 4, 22, 203, 3, 193, 234, 124, 18, 64, 59 },
    .{ 204, 171, 9, 13, 89, 170, 71, 59, 17, 1, 159, 233, 177, 214, 82, 28, 105, 250, 235, 141 },
    .{ 46, 244, 26, 131, 254, 153, 240, 201, 43, 103, 66, 177, 87, 83, 151, 78, 9, 188, 200, 121 },
    .{ 94, 141, 148, 66, 238, 198, 185, 201, 221, 217, 9, 92, 45, 244, 3, 226, 216, 38, 242, 210 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 196, 14, 8, 230, 8, 134, 71, 226, 188, 11, 13, 148, 119, 146, 243, 224, 174, 67, 252, 128 },
    .{ 204, 171, 9, 13, 89, 170, 71, 59, 17, 1, 159, 233, 177, 214, 82, 28, 105, 250, 235, 141 },
    .{ 46, 244, 26, 131, 254, 153, 240, 201, 43, 103, 66, 177, 87, 83, 151, 78, 9, 188, 200, 121 },
    .{ 94, 141, 148, 66, 238, 198, 185, 201, 221, 217, 9, 92, 45, 244, 3, 226, 216, 38, 242, 210 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 108, 214, 248, 244, 72, 156, 5, 43, 128, 2, 230, 95, 171, 44, 108, 36, 80, 154, 3, 219 },
    .{ 62, 98, 62, 177, 231, 3, 117, 21, 226, 153, 167, 134, 5, 149, 106, 233, 191, 142, 17, 56 },
    .{ 162, 156, 174, 166, 108, 231, 106, 66, 185, 145, 87, 18, 159, 235, 146, 46, 148, 169, 167, 19 },
    .{ 94, 141, 148, 66, 238, 198, 185, 201, 221, 217, 9, 92, 45, 244, 3, 226, 216, 38, 242, 210 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 248, 108, 150, 0, 139, 145, 78, 93, 195, 252, 29, 146, 9, 3, 95, 239, 110, 245, 117, 171 },
    .{ 62, 98, 62, 177, 231, 3, 117, 21, 226, 153, 167, 134, 5, 149, 106, 233, 191, 142, 17, 56 },
    .{ 162, 156, 174, 166, 108, 231, 106, 66, 185, 145, 87, 18, 159, 235, 146, 46, 148, 169, 167, 19 },
    .{ 94, 141, 148, 66, 238, 198, 185, 201, 221, 217, 9, 92, 45, 244, 3, 226, 216, 38, 242, 210 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 209, 134, 252, 128, 55, 124, 12, 161, 57, 202, 19, 113, 185, 145, 177, 207, 189, 236, 235, 61 },
    .{ 70, 193, 37, 4, 227, 227, 26, 84, 122, 216, 14, 166, 79, 10, 145, 3, 17, 227, 153, 201 },
    .{ 162, 156, 174, 166, 108, 231, 106, 66, 185, 145, 87, 18, 159, 235, 146, 46, 148, 169, 167, 19 },
    .{ 94, 141, 148, 66, 238, 198, 185, 201, 221, 217, 9, 92, 45, 244, 3, 226, 216, 38, 242, 210 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 178, 255, 30, 79, 79, 255, 140, 82, 20, 214, 11, 68, 140, 69, 95, 212, 167, 7, 210, 73 },
    .{ 70, 193, 37, 4, 227, 227, 26, 84, 122, 216, 14, 166, 79, 10, 145, 3, 17, 227, 153, 201 },
    .{ 162, 156, 174, 166, 108, 231, 106, 66, 185, 145, 87, 18, 159, 235, 146, 46, 148, 169, 167, 19 },
    .{ 94, 141, 148, 66, 238, 198, 185, 201, 221, 217, 9, 92, 45, 244, 3, 226, 216, 38, 242, 210 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 121, 79, 23, 86, 26, 216, 227, 93, 158, 190, 172, 254, 11, 125, 83, 88, 59, 239, 25, 77 },
    .{ 254, 27, 70, 125, 89, 136, 19, 91, 41, 48, 98, 142, 153, 95, 127, 244, 62, 173, 19, 109 },
    .{ 253, 192, 159, 157, 25, 197, 24, 6, 219, 49, 105, 147, 169, 226, 246, 2, 104, 211, 144, 132 },
    .{ 203, 38, 239, 181, 196, 137, 86, 75, 87, 78, 196, 114, 226, 243, 109, 29, 135, 179, 175, 176 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 83, 180, 6, 60, 131, 168, 1, 245, 179, 150, 66, 10, 120, 177, 215, 131, 153, 148, 219, 87 },
    .{ 254, 27, 70, 125, 89, 136, 19, 91, 41, 48, 98, 142, 153, 95, 127, 244, 62, 173, 19, 109 },
    .{ 253, 192, 159, 157, 25, 197, 24, 6, 219, 49, 105, 147, 169, 226, 246, 2, 104, 211, 144, 132 },
    .{ 203, 38, 239, 181, 196, 137, 86, 75, 87, 78, 196, 114, 226, 243, 109, 29, 135, 179, 175, 176 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 50, 160, 111, 13, 243, 238, 231, 168, 110, 87, 237, 42, 205, 72, 126, 109, 71, 247, 106, 76 },
    .{ 249, 213, 0, 215, 88, 206, 186, 126, 130, 157, 187, 38, 221, 26, 184, 33, 189, 192, 254, 59 },
    .{ 253, 192, 159, 157, 25, 197, 24, 6, 219, 49, 105, 147, 169, 226, 246, 2, 104, 211, 144, 132 },
    .{ 203, 38, 239, 181, 196, 137, 86, 75, 87, 78, 196, 114, 226, 243, 109, 29, 135, 179, 175, 176 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 175, 196, 116, 107, 130, 213, 207, 16, 90, 226, 21, 162, 218, 238, 68, 89, 238, 249, 121, 42 },
    .{ 249, 213, 0, 215, 88, 206, 186, 126, 130, 157, 187, 38, 221, 26, 184, 33, 189, 192, 254, 59 },
    .{ 253, 192, 159, 157, 25, 197, 24, 6, 219, 49, 105, 147, 169, 226, 246, 2, 104, 211, 144, 132 },
    .{ 203, 38, 239, 181, 196, 137, 86, 75, 87, 78, 196, 114, 226, 243, 109, 29, 135, 179, 175, 176 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 185, 149, 73, 199, 63, 145, 92, 171, 128, 95, 52, 157, 22, 44, 254, 104, 197, 124, 225, 125 },
    .{ 218, 38, 148, 177, 18, 203, 96, 81, 68, 102, 34, 198, 64, 25, 5, 76, 31, 110, 17, 11 },
    .{ 173, 32, 230, 90, 220, 200, 26, 44, 234, 150, 221, 132, 15, 221, 35, 159, 234, 193, 17, 71 },
    .{ 203, 38, 239, 181, 196, 137, 86, 75, 87, 78, 196, 114, 226, 243, 109, 29, 135, 179, 175, 176 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 68, 65, 124, 23, 106, 22, 39, 245, 44, 222, 81, 34, 180, 67, 206, 68, 118, 198, 33, 219 },
    .{ 218, 38, 148, 177, 18, 203, 96, 81, 68, 102, 34, 198, 64, 25, 5, 76, 31, 110, 17, 11 },
    .{ 173, 32, 230, 90, 220, 200, 26, 44, 234, 150, 221, 132, 15, 221, 35, 159, 234, 193, 17, 71 },
    .{ 203, 38, 239, 181, 196, 137, 86, 75, 87, 78, 196, 114, 226, 243, 109, 29, 135, 179, 175, 176 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 210, 198, 153, 253, 20, 171, 204, 128, 119, 63, 29, 36, 68, 1, 186, 69, 50, 4, 133, 239 },
    .{ 10, 69, 85, 167, 196, 255, 56, 114, 43, 68, 4, 38, 19, 225, 240, 24, 0, 116, 226, 129 },
    .{ 173, 32, 230, 90, 220, 200, 26, 44, 234, 150, 221, 132, 15, 221, 35, 159, 234, 193, 17, 71 },
    .{ 203, 38, 239, 181, 196, 137, 86, 75, 87, 78, 196, 114, 226, 243, 109, 29, 135, 179, 175, 176 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 253, 169, 102, 235, 188, 239, 115, 67, 215, 147, 152, 231, 163, 17, 5, 33, 33, 255, 13, 160 },
    .{ 10, 69, 85, 167, 196, 255, 56, 114, 43, 68, 4, 38, 19, 225, 240, 24, 0, 116, 226, 129 },
    .{ 173, 32, 230, 90, 220, 200, 26, 44, 234, 150, 221, 132, 15, 221, 35, 159, 234, 193, 17, 71 },
    .{ 203, 38, 239, 181, 196, 137, 86, 75, 87, 78, 196, 114, 226, 243, 109, 29, 135, 179, 175, 176 },
    .{ 108, 115, 26, 81, 76, 171, 110, 137, 35, 31, 157, 68, 247, 47, 4, 208, 52, 139, 40, 38 },
    .{ 32, 101, 185, 114, 7, 154, 142, 17, 55, 196, 133, 118, 149, 55, 194, 214, 43, 207, 144, 236 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 156, 158, 254, 151, 132, 243, 239, 9, 157, 16, 174, 96, 31, 117, 239, 112, 174, 247, 227, 184 },
    .{ 179, 230, 53, 185, 29, 193, 67, 187, 238, 226, 196, 54, 150, 253, 171, 21, 65, 239, 101, 28 },
    .{ 169, 100, 236, 36, 227, 141, 12, 143, 183, 85, 142, 14, 97, 199, 54, 2, 58, 101, 231, 17 },
    .{ 8, 237, 232, 142, 128, 246, 74, 18, 75, 135, 237, 115, 246, 203, 83, 31, 168, 5, 244, 180 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 231, 240, 6, 74, 216, 58, 120, 197, 59, 72, 230, 118, 212, 39, 145, 56, 185, 48, 193, 163 },
    .{ 179, 230, 53, 185, 29, 193, 67, 187, 238, 226, 196, 54, 150, 253, 171, 21, 65, 239, 101, 28 },
    .{ 169, 100, 236, 36, 227, 141, 12, 143, 183, 85, 142, 14, 97, 199, 54, 2, 58, 101, 231, 17 },
    .{ 8, 237, 232, 142, 128, 246, 74, 18, 75, 135, 237, 115, 246, 203, 83, 31, 168, 5, 244, 180 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 162, 153, 42, 226, 192, 189, 224, 212, 80, 148, 128, 176, 121, 111, 108, 135, 133, 59, 242, 232 },
    .{ 74, 218, 75, 124, 174, 169, 62, 29, 35, 217, 44, 69, 214, 5, 15, 215, 172, 106, 121, 2 },
    .{ 169, 100, 236, 36, 227, 141, 12, 143, 183, 85, 142, 14, 97, 199, 54, 2, 58, 101, 231, 17 },
    .{ 8, 237, 232, 142, 128, 246, 74, 18, 75, 135, 237, 115, 246, 203, 83, 31, 168, 5, 244, 180 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 34, 149, 32, 44, 117, 2, 93, 172, 93, 231, 92, 232, 172, 166, 165, 209, 69, 84, 105, 174 },
    .{ 74, 218, 75, 124, 174, 169, 62, 29, 35, 217, 44, 69, 214, 5, 15, 215, 172, 106, 121, 2 },
    .{ 169, 100, 236, 36, 227, 141, 12, 143, 183, 85, 142, 14, 97, 199, 54, 2, 58, 101, 231, 17 },
    .{ 8, 237, 232, 142, 128, 246, 74, 18, 75, 135, 237, 115, 246, 203, 83, 31, 168, 5, 244, 180 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 94, 126, 16, 132, 47, 226, 252, 114, 216, 152, 203, 173, 170, 115, 184, 238, 127, 123, 221, 142 },
    .{ 81, 21, 133, 130, 208, 33, 9, 36, 113, 181, 152, 104, 3, 62, 160, 235, 88, 224, 178, 100 },
    .{ 166, 100, 209, 67, 176, 162, 7, 162, 1, 198, 114, 37, 109, 41, 214, 69, 69, 50, 84, 114 },
    .{ 8, 237, 232, 142, 128, 246, 74, 18, 75, 135, 237, 115, 246, 203, 83, 31, 168, 5, 244, 180 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 10, 113, 133, 223, 63, 39, 46, 225, 73, 200, 125, 210, 15, 89, 98, 154, 57, 186, 253, 36 },
    .{ 81, 21, 133, 130, 208, 33, 9, 36, 113, 181, 152, 104, 3, 62, 160, 235, 88, 224, 178, 100 },
    .{ 166, 100, 209, 67, 176, 162, 7, 162, 1, 198, 114, 37, 109, 41, 214, 69, 69, 50, 84, 114 },
    .{ 8, 237, 232, 142, 128, 246, 74, 18, 75, 135, 237, 115, 246, 203, 83, 31, 168, 5, 244, 180 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 162, 240, 17, 58, 66, 72, 150, 7, 106, 166, 40, 100, 155, 249, 160, 67, 114, 134, 253, 196 },
    .{ 163, 30, 74, 23, 46, 220, 219, 192, 215, 123, 29, 168, 131, 255, 76, 242, 217, 21, 233, 28 },
    .{ 166, 100, 209, 67, 176, 162, 7, 162, 1, 198, 114, 37, 109, 41, 214, 69, 69, 50, 84, 114 },
    .{ 8, 237, 232, 142, 128, 246, 74, 18, 75, 135, 237, 115, 246, 203, 83, 31, 168, 5, 244, 180 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 113, 198, 185, 168, 58, 25, 27, 214, 242, 191, 161, 221, 213, 139, 138, 178, 13, 141, 240, 54 },
    .{ 163, 30, 74, 23, 46, 220, 219, 192, 215, 123, 29, 168, 131, 255, 76, 242, 217, 21, 233, 28 },
    .{ 166, 100, 209, 67, 176, 162, 7, 162, 1, 198, 114, 37, 109, 41, 214, 69, 69, 50, 84, 114 },
    .{ 8, 237, 232, 142, 128, 246, 74, 18, 75, 135, 237, 115, 246, 203, 83, 31, 168, 5, 244, 180 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 97, 160, 23, 237, 249, 69, 63, 98, 18, 207, 109, 208, 73, 37, 110, 11, 45, 254, 237, 108 },
    .{ 19, 17, 129, 175, 186, 127, 45, 188, 253, 136, 219, 253, 42, 55, 86, 72, 119, 77, 241, 71 },
    .{ 0, 17, 159, 227, 120, 168, 213, 228, 137, 102, 155, 245, 85, 87, 160, 54, 125, 115, 214, 148 },
    .{ 212, 102, 2, 74, 37, 195, 153, 149, 96, 122, 185, 150, 251, 76, 4, 22, 191, 43, 19, 70 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 65, 17, 63, 155, 48, 228, 247, 173, 149, 122, 187, 57, 90, 119, 79, 49, 129, 134, 250, 178 },
    .{ 19, 17, 129, 175, 186, 127, 45, 188, 253, 136, 219, 253, 42, 55, 86, 72, 119, 77, 241, 71 },
    .{ 0, 17, 159, 227, 120, 168, 213, 228, 137, 102, 155, 245, 85, 87, 160, 54, 125, 115, 214, 148 },
    .{ 212, 102, 2, 74, 37, 195, 153, 149, 96, 122, 185, 150, 251, 76, 4, 22, 191, 43, 19, 70 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 105, 91, 60, 217, 215, 57, 227, 134, 73, 164, 103, 82, 244, 210, 239, 234, 209, 192, 5, 128 },
    .{ 20, 75, 239, 86, 251, 216, 99, 221, 228, 103, 180, 125, 205, 101, 236, 130, 184, 244, 202, 8 },
    .{ 0, 17, 159, 227, 120, 168, 213, 228, 137, 102, 155, 245, 85, 87, 160, 54, 125, 115, 214, 148 },
    .{ 212, 102, 2, 74, 37, 195, 153, 149, 96, 122, 185, 150, 251, 76, 4, 22, 191, 43, 19, 70 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 227, 1, 207, 71, 16, 240, 80, 75, 210, 83, 18, 253, 0, 87, 35, 149, 99, 196, 104, 142 },
    .{ 20, 75, 239, 86, 251, 216, 99, 221, 228, 103, 180, 125, 205, 101, 236, 130, 184, 244, 202, 8 },
    .{ 0, 17, 159, 227, 120, 168, 213, 228, 137, 102, 155, 245, 85, 87, 160, 54, 125, 115, 214, 148 },
    .{ 212, 102, 2, 74, 37, 195, 153, 149, 96, 122, 185, 150, 251, 76, 4, 22, 191, 43, 19, 70 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 149, 92, 133, 87, 211, 121, 44, 108, 196, 217, 67, 171, 199, 61, 159, 85, 57, 44, 229, 235 },
    .{ 152, 19, 251, 100, 25, 187, 167, 65, 130, 57, 210, 166, 69, 117, 162, 106, 109, 144, 128, 64 },
    .{ 254, 133, 240, 183, 178, 140, 79, 159, 220, 136, 97, 63, 81, 81, 177, 207, 186, 167, 171, 250 },
    .{ 212, 102, 2, 74, 37, 195, 153, 149, 96, 122, 185, 150, 251, 76, 4, 22, 191, 43, 19, 70 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 16, 248, 220, 18, 84, 142, 184, 93, 105, 20, 64, 226, 253, 254, 126, 170, 160, 19, 8, 164 },
    .{ 152, 19, 251, 100, 25, 187, 167, 65, 130, 57, 210, 166, 69, 117, 162, 106, 109, 144, 128, 64 },
    .{ 254, 133, 240, 183, 178, 140, 79, 159, 220, 136, 97, 63, 81, 81, 177, 207, 186, 167, 171, 250 },
    .{ 212, 102, 2, 74, 37, 195, 153, 149, 96, 122, 185, 150, 251, 76, 4, 22, 191, 43, 19, 70 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 215, 168, 119, 26, 179, 82, 209, 173, 124, 132, 194, 201, 149, 191, 135, 121, 138, 71, 46, 111 },
    .{ 171, 137, 96, 153, 54, 90, 184, 161, 113, 222, 0, 67, 89, 67, 123, 242, 158, 199, 8, 140 },
    .{ 254, 133, 240, 183, 178, 140, 79, 159, 220, 136, 97, 63, 81, 81, 177, 207, 186, 167, 171, 250 },
    .{ 212, 102, 2, 74, 37, 195, 153, 149, 96, 122, 185, 150, 251, 76, 4, 22, 191, 43, 19, 70 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 63, 166, 188, 198, 236, 216, 25, 121, 122, 219, 245, 255, 214, 60, 233, 82, 115, 248, 132, 211 },
    .{ 171, 137, 96, 153, 54, 90, 184, 161, 113, 222, 0, 67, 89, 67, 123, 242, 158, 199, 8, 140 },
    .{ 254, 133, 240, 183, 178, 140, 79, 159, 220, 136, 97, 63, 81, 81, 177, 207, 186, 167, 171, 250 },
    .{ 212, 102, 2, 74, 37, 195, 153, 149, 96, 122, 185, 150, 251, 76, 4, 22, 191, 43, 19, 70 },
    .{ 112, 137, 158, 82, 7, 42, 71, 183, 235, 46, 215, 218, 162, 136, 248, 39, 104, 114, 199, 167 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 93, 128, 93, 149, 204, 123, 89, 89, 244, 110, 175, 158, 1, 158, 7, 33, 124, 97, 146, 6 },
    .{ 159, 20, 162, 227, 242, 226, 127, 99, 148, 231, 68, 99, 100, 90, 109, 189, 95, 146, 76, 200 },
    .{ 35, 200, 99, 232, 204, 78, 104, 166, 198, 124, 43, 13, 236, 27, 119, 230, 169, 3, 143, 81 },
    .{ 190, 207, 118, 177, 182, 91, 138, 31, 84, 67, 218, 244, 249, 218, 165, 172, 94, 187, 227, 84 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 5, 223, 7, 246, 235, 39, 171, 47, 27, 184, 8, 39, 73, 177, 249, 218, 16, 35, 82, 131 },
    .{ 159, 20, 162, 227, 242, 226, 127, 99, 148, 231, 68, 99, 100, 90, 109, 189, 95, 146, 76, 200 },
    .{ 35, 200, 99, 232, 204, 78, 104, 166, 198, 124, 43, 13, 236, 27, 119, 230, 169, 3, 143, 81 },
    .{ 190, 207, 118, 177, 182, 91, 138, 31, 84, 67, 218, 244, 249, 218, 165, 172, 94, 187, 227, 84 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 78, 40, 28, 235, 150, 228, 211, 6, 22, 104, 154, 63, 46, 136, 136, 231, 131, 34, 128, 235 },
    .{ 128, 48, 165, 124, 241, 45, 25, 216, 235, 117, 77, 73, 87, 195, 23, 137, 134, 202, 71, 233 },
    .{ 35, 200, 99, 232, 204, 78, 104, 166, 198, 124, 43, 13, 236, 27, 119, 230, 169, 3, 143, 81 },
    .{ 190, 207, 118, 177, 182, 91, 138, 31, 84, 67, 218, 244, 249, 218, 165, 172, 94, 187, 227, 84 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 220, 84, 132, 168, 31, 185, 92, 67, 18, 158, 140, 252, 0, 217, 181, 27, 1, 122, 231, 3 },
    .{ 128, 48, 165, 124, 241, 45, 25, 216, 235, 117, 77, 73, 87, 195, 23, 137, 134, 202, 71, 233 },
    .{ 35, 200, 99, 232, 204, 78, 104, 166, 198, 124, 43, 13, 236, 27, 119, 230, 169, 3, 143, 81 },
    .{ 190, 207, 118, 177, 182, 91, 138, 31, 84, 67, 218, 244, 249, 218, 165, 172, 94, 187, 227, 84 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 64, 216, 33, 50, 0, 142, 27, 180, 16, 229, 221, 35, 150, 174, 25, 175, 129, 129, 42, 31 },
    .{ 171, 239, 37, 25, 73, 134, 35, 119, 28, 145, 59, 147, 79, 240, 94, 44, 160, 194, 64, 24 },
    .{ 134, 183, 196, 225, 227, 107, 224, 166, 85, 116, 245, 1, 119, 155, 77, 200, 251, 166, 5, 11 },
    .{ 190, 207, 118, 177, 182, 91, 138, 31, 84, 67, 218, 244, 249, 218, 165, 172, 94, 187, 227, 84 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 144, 65, 182, 179, 106, 237, 239, 64, 237, 169, 96, 114, 192, 126, 242, 62, 157, 221, 189, 101 },
    .{ 171, 239, 37, 25, 73, 134, 35, 119, 28, 145, 59, 147, 79, 240, 94, 44, 160, 194, 64, 24 },
    .{ 134, 183, 196, 225, 227, 107, 224, 166, 85, 116, 245, 1, 119, 155, 77, 200, 251, 166, 5, 11 },
    .{ 190, 207, 118, 177, 182, 91, 138, 31, 84, 67, 218, 244, 249, 218, 165, 172, 94, 187, 227, 84 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 198, 214, 45, 254, 195, 140, 58, 160, 159, 43, 60, 81, 228, 247, 166, 53, 79, 101, 141, 5 },
    .{ 175, 24, 181, 175, 52, 84, 189, 196, 122, 72, 214, 241, 30, 224, 152, 229, 192, 6, 239, 124 },
    .{ 134, 183, 196, 225, 227, 107, 224, 166, 85, 116, 245, 1, 119, 155, 77, 200, 251, 166, 5, 11 },
    .{ 190, 207, 118, 177, 182, 91, 138, 31, 84, 67, 218, 244, 249, 218, 165, 172, 94, 187, 227, 84 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 183, 126, 51, 21, 209, 182, 204, 199, 48, 156, 187, 159, 12, 177, 221, 58, 31, 231, 90, 248 },
    .{ 175, 24, 181, 175, 52, 84, 189, 196, 122, 72, 214, 241, 30, 224, 152, 229, 192, 6, 239, 124 },
    .{ 134, 183, 196, 225, 227, 107, 224, 166, 85, 116, 245, 1, 119, 155, 77, 200, 251, 166, 5, 11 },
    .{ 190, 207, 118, 177, 182, 91, 138, 31, 84, 67, 218, 244, 249, 218, 165, 172, 94, 187, 227, 84 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 23, 208, 69, 252, 131, 228, 209, 29, 62, 178, 15, 62, 140, 250, 131, 74, 233, 112, 160, 118 },
    .{ 223, 129, 203, 131, 85, 246, 57, 238, 151, 164, 123, 10, 52, 178, 118, 16, 86, 49, 179, 181 },
    .{ 184, 44, 126, 172, 51, 67, 23, 138, 211, 207, 236, 94, 81, 251, 195, 169, 16, 47, 88, 23 },
    .{ 115, 80, 203, 76, 4, 212, 49, 213, 161, 138, 205, 141, 241, 248, 124, 89, 124, 173, 29, 2 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 164, 101, 109, 241, 217, 51, 213, 159, 219, 163, 36, 119, 206, 96, 68, 18, 205, 251, 113, 101 },
    .{ 223, 129, 203, 131, 85, 246, 57, 238, 151, 164, 123, 10, 52, 178, 118, 16, 86, 49, 179, 181 },
    .{ 184, 44, 126, 172, 51, 67, 23, 138, 211, 207, 236, 94, 81, 251, 195, 169, 16, 47, 88, 23 },
    .{ 115, 80, 203, 76, 4, 212, 49, 213, 161, 138, 205, 141, 241, 248, 124, 89, 124, 173, 29, 2 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 25, 110, 110, 11, 75, 85, 236, 86, 133, 36, 8, 158, 176, 173, 125, 33, 81, 100, 178, 90 },
    .{ 120, 88, 72, 6, 162, 240, 217, 80, 150, 127, 242, 183, 88, 87, 71, 116, 158, 242, 209, 36 },
    .{ 184, 44, 126, 172, 51, 67, 23, 138, 211, 207, 236, 94, 81, 251, 195, 169, 16, 47, 88, 23 },
    .{ 115, 80, 203, 76, 4, 212, 49, 213, 161, 138, 205, 141, 241, 248, 124, 89, 124, 173, 29, 2 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 5, 75, 152, 252, 98, 129, 240, 185, 152, 112, 127, 231, 33, 50, 177, 100, 193, 90, 153, 174 },
    .{ 120, 88, 72, 6, 162, 240, 217, 80, 150, 127, 242, 183, 88, 87, 71, 116, 158, 242, 209, 36 },
    .{ 184, 44, 126, 172, 51, 67, 23, 138, 211, 207, 236, 94, 81, 251, 195, 169, 16, 47, 88, 23 },
    .{ 115, 80, 203, 76, 4, 212, 49, 213, 161, 138, 205, 141, 241, 248, 124, 89, 124, 173, 29, 2 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 204, 25, 228, 86, 105, 139, 230, 17, 165, 81, 9, 49, 215, 133, 64, 206, 83, 148, 37, 87 },
    .{ 236, 204, 122, 24, 249, 217, 93, 109, 13, 147, 78, 174, 91, 157, 231, 16, 229, 192, 200, 183 },
    .{ 16, 218, 34, 25, 148, 165, 87, 57, 196, 19, 225, 215, 155, 176, 69, 135, 9, 191, 243, 95 },
    .{ 115, 80, 203, 76, 4, 212, 49, 213, 161, 138, 205, 141, 241, 248, 124, 89, 124, 173, 29, 2 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 116, 230, 162, 48, 244, 243, 111, 145, 249, 197, 206, 163, 161, 241, 64, 32, 151, 253, 122, 253 },
    .{ 236, 204, 122, 24, 249, 217, 93, 109, 13, 147, 78, 174, 91, 157, 231, 16, 229, 192, 200, 183 },
    .{ 16, 218, 34, 25, 148, 165, 87, 57, 196, 19, 225, 215, 155, 176, 69, 135, 9, 191, 243, 95 },
    .{ 115, 80, 203, 76, 4, 212, 49, 213, 161, 138, 205, 141, 241, 248, 124, 89, 124, 173, 29, 2 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 41, 179, 206, 40, 187, 16, 50, 153, 95, 29, 43, 249, 78, 68, 125, 53, 167, 1, 103, 189 },
    .{ 98, 237, 140, 193, 239, 139, 78, 141, 172, 235, 100, 192, 255, 149, 84, 193, 157, 13, 98, 83 },
    .{ 16, 218, 34, 25, 148, 165, 87, 57, 196, 19, 225, 215, 155, 176, 69, 135, 9, 191, 243, 95 },
    .{ 115, 80, 203, 76, 4, 212, 49, 213, 161, 138, 205, 141, 241, 248, 124, 89, 124, 173, 29, 2 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 240, 236, 44, 220, 76, 138, 98, 3, 249, 79, 40, 195, 12, 66, 149, 47, 50, 98, 222, 198 },
    .{ 98, 237, 140, 193, 239, 139, 78, 141, 172, 235, 100, 192, 255, 149, 84, 193, 157, 13, 98, 83 },
    .{ 16, 218, 34, 25, 148, 165, 87, 57, 196, 19, 225, 215, 155, 176, 69, 135, 9, 191, 243, 95 },
    .{ 115, 80, 203, 76, 4, 212, 49, 213, 161, 138, 205, 141, 241, 248, 124, 89, 124, 173, 29, 2 },
    .{ 198, 129, 110, 82, 195, 126, 26, 97, 160, 171, 135, 33, 137, 78, 221, 2, 43, 35, 101, 163 },
    .{ 152, 18, 171, 179, 123, 11, 141, 26, 9, 23, 193, 10, 208, 94, 101, 237, 50, 43, 142, 192 },
    .{ 159, 85, 161, 52, 189, 106, 242, 29, 245, 192, 60, 196, 73, 36, 228, 75, 138, 196, 211, 46 },
    .{ 152, 57, 236, 135, 140, 163, 50, 4, 181, 250, 204, 95, 220, 37, 59, 175, 0, 194, 226, 170 },
    .{ 23, 118, 198, 123, 60, 221, 135, 169, 214, 53, 108, 0, 239, 210, 41, 173, 101, 134, 230, 41 },
    .{ 87, 96, 250, 245, 225, 226, 220, 242, 102, 66, 195, 139, 228, 242, 190, 217, 27, 59, 194, 224 },
    .{ 242, 224, 75, 112, 159, 45, 77, 118, 126, 77, 102, 237, 250, 12, 197, 60, 7, 49, 163, 96 },
    .{ 237, 22, 160, 112, 213, 148, 239, 62, 88, 37, 130, 208, 223, 94, 29, 142, 25, 178, 210, 248 },
    .{ 164, 235, 160, 70, 101, 226, 254, 117, 70, 189, 193, 209, 158, 139, 123, 220, 202, 125, 227, 64 },
    .{ 152, 0, 113, 7, 223, 76, 55, 35, 59, 38, 68, 91, 39, 247, 223, 188, 161, 23, 60, 199 },
    .{ 143, 189, 225, 94, 221, 255, 190, 82, 88, 53, 197, 35, 45, 179, 28, 56, 40, 153, 87, 70 },
    .{ 23, 118, 198, 123, 60, 221, 135, 169, 214, 53, 108, 0, 239, 210, 41, 173, 101, 134, 230, 41 },
    .{ 87, 96, 250, 245, 225, 226, 220, 242, 102, 66, 195, 139, 228, 242, 190, 217, 27, 59, 194, 224 },
    .{ 242, 224, 75, 112, 159, 45, 77, 118, 126, 77, 102, 237, 250, 12, 197, 60, 7, 49, 163, 96 },
    .{ 237, 22, 160, 112, 213, 148, 239, 62, 88, 37, 130, 208, 223, 94, 29, 142, 25, 178, 210, 248 },
    .{ 164, 235, 160, 70, 101, 226, 254, 117, 70, 189, 193, 209, 158, 139, 123, 220, 202, 125, 227, 64 },
    .{ 152, 0, 113, 7, 223, 76, 55, 35, 59, 38, 68, 91, 39, 247, 223, 188, 161, 23, 60, 199 },
    .{ 166, 248, 31, 43, 220, 198, 40, 83, 131, 197, 26, 84, 52, 177, 121, 141, 134, 52, 144, 208 },
    .{ 85, 66, 19, 192, 0, 189, 162, 209, 4, 0, 29, 34, 97, 69, 172, 25, 189, 196, 130, 144 },
    .{ 87, 96, 250, 245, 225, 226, 220, 242, 102, 66, 195, 139, 228, 242, 190, 217, 27, 59, 194, 224 },
    .{ 242, 224, 75, 112, 159, 45, 77, 118, 126, 77, 102, 237, 250, 12, 197, 60, 7, 49, 163, 96 },
    .{ 237, 22, 160, 112, 213, 148, 239, 62, 88, 37, 130, 208, 223, 94, 29, 142, 25, 178, 210, 248 },
    .{ 164, 235, 160, 70, 101, 226, 254, 117, 70, 189, 193, 209, 158, 139, 123, 220, 202, 125, 227, 64 },
    .{ 152, 0, 113, 7, 223, 76, 55, 35, 59, 38, 68, 91, 39, 247, 223, 188, 161, 23, 60, 199 },
    .{ 223, 202, 216, 9, 93, 236, 179, 216, 220, 248, 43, 1, 143, 31, 211, 112, 189, 38, 162, 119 },
    .{ 85, 66, 19, 192, 0, 189, 162, 209, 4, 0, 29, 34, 97, 69, 172, 25, 189, 196, 130, 144 },
    .{ 87, 96, 250, 245, 225, 226, 220, 242, 102, 66, 195, 139, 228, 242, 190, 217, 27, 59, 194, 224 },
    .{ 242, 224, 75, 112, 159, 45, 77, 118, 126, 77, 102, 237, 250, 12, 197, 60, 7, 49, 163, 96 },
    .{ 237, 22, 160, 112, 213, 148, 239, 62, 88, 37, 130, 208, 223, 94, 29, 142, 25, 178, 210, 248 },
    .{ 164, 235, 160, 70, 101, 226, 254, 117, 70, 189, 193, 209, 158, 139, 123, 220, 202, 125, 227, 64 },
    .{ 152, 0, 113, 7, 223, 76, 55, 35, 59, 38, 68, 91, 39, 247, 223, 188, 161, 23, 60, 199 },
};
