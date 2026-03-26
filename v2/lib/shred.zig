const std = @import("std");
const tracy = @import("tracy");
const solana = @import("solana.zig");
const ipc = @import("ipc.zig");
const net = @import("net.zig");

pub const reed_solomon_table = @import("shred/reed_solomon_table.zig");

const Hash = solana.Hash;
const Slot = solana.Slot;
const LeaderSchedule = solana.LeaderSchedule;
const Signature = solana.Signature;

const Ring = ipc.Ring;

const Packet = net.Packet;

pub const RecvConfig = extern struct {
    leader_schedule: LeaderSchedule,
    shred_version: u16,
};

pub const DeshredRing = Ring(256, DeshreddedFecSet);

pub const FecSetId = extern struct {
    slot: Slot,
    fec_set_idx: u32,

    pub fn eql(a: *const FecSetId, b: *const FecSetId) bool {
        return (a.slot == b.slot and a.fec_set_idx == b.fec_set_idx);
    }

    pub fn compare(a: *const FecSetId, b: *const FecSetId) std.math.Order {
        if (a.slot > b.slot) return .gt;
        if (a.slot < b.slot) return .lt;
        if (a.fec_set_idx > b.fec_set_idx) return .gt;
        if (a.fec_set_idx < b.fec_set_idx) return .lt;
        std.debug.assert(a.slot == b.slot);
        std.debug.assert(a.fec_set_idx == b.fec_set_idx);
        return .eq;
    }
};

// TODO: this should be sent as a notification/header, with the payload sent separately.
// Currently this copies a lot.
pub const DeshreddedFecSet = extern struct {
    merkle_root: Hash,
    chained_merkle_root: Hash,
    id: FecSetId,
    data_complete: bool,
    slot_complete: bool,
    payload_len: u16,

    // TODO: this should be sent separately, ideally in a mem pool.
    payload_buf: [32 * Shred.data_payload_max]u8,

    fn payload(self: *const DeshreddedFecSet) []const u8 {
        return self.payload_buf[0..self.payload_len];
    }
};

/// We can read the bincode directly - no deserialisation/copying required
/// Methods taking `shred: *const Shred` assume that shred is pointing to the buffer of a Packet
// https://github.com/solana-foundation/specs/blob/main/p2p/shred.md
pub const Shred = extern struct {
    signature: Signature align(1),
    variant: Variant align(1),
    slot: Slot align(1),
    slot_idx: u32 align(1),
    version: u16 align(1),
    fec_set_idx: u32 align(1),

    /// Union variant implied by shred.variant
    code_or_data: extern union {
        data: DataHeader,
        code: CodeHeader,
    } align(1),

    pub const DataHeader = extern struct {
        parent_offset: u16 align(1),
        flags: Flags align(1),
        size: u16 align(1),

        // [agave] https://github.com/anza-xyz/agave/blob/ce2b875e7a9587106cb505e14ab769f9356b8238/ledger/src/shred.rs#L146
        // NOTE: last_shred_in_slot implies data_complete
        pub const Flags = packed struct(u8) {
            // 0x1, 0x2, 0x4, 0x8, 0x10, 0x20
            reference_tick: u6,
            // 0x40
            data_complete: bool,
            // 0x80
            last_shred_in_slot: bool,
        };
    };

    pub const CodeHeader = extern struct {
        data_count: u16 align(1),
        code_count: u16 align(1),
        code_shred_idx: u16 align(1),
    };

    /// The lower 4 bits are used for the number of merkle roots, and the upper 4 bits are used
    /// to determine which kind of shred we have.
    /// It would be great to represent this as a packed struct, but Agave decided that the legacy
    /// Code and Data shreds should be defined like this:
    ///
    /// pub enum ShredType {
    ///     Data = 0b1010_0101,
    ///     Code = 0b0101_1010,
    /// }
    pub const Variant = extern struct {
        inner: u8,

        // [firedancer] https://github.com/firedancer-io/firedancer/blob/9f7770af997a1443e7903113fc03ca1ce3b0ad73/src/ballet/shred/fd_shred.c#L16
        // Legacy (non-merkle), and non-chained shreds are deprecated
        // https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0313-drop-unchained-merkle-shreds.md
        fn isSupported(self: Variant) bool {
            const variant = self.inner;

            return switch (variant & 0xF0) {
                // test upper 4 bits
                merkle_data_chained,
                merkle_code_chained,
                merkle_data_chained_resigned,
                merkle_code_chained_resigned,
                => true,

                else => false,
            };
        }

        fn headerSize(self: Variant) usize {
            const shared_base = @offsetOf(Shred, "code_or_data");

            return switch (self.inner & 0xF0) {
                legacy_data, // deprecated
                merkle_data, // deprecated
                merkle_data_chained,
                merkle_data_chained_resigned,
                => shared_base + @sizeOf(DataHeader),

                legacy_code, // deprecated
                merkle_code, // deprecated
                merkle_code_chained,
                merkle_code_chained_resigned,
                => shared_base + @sizeOf(CodeHeader),

                else => 0,
            };
        }

        pub fn merkleCount(self: Variant) u8 {
            return switch (self.inner & 0xF0) {
                legacy_data, legacy_code => 0, // deprecated
                else => self.inner & 0x0F,
            };
        }

        fn merkleSize(self: Variant) u16 {
            return self.merkleCount() * merkle_node_size;
        }

        fn isChained(self: Variant) bool {
            return switch (self.inner & 0xF0) {
                merkle_data_chained,
                merkle_code_chained,
                merkle_data_chained_resigned,
                merkle_code_chained_resigned,
                => true,
                else => false,
            };
        }

        fn isResigned(self: Variant) bool {
            return switch (self.inner & 0xF0) {
                merkle_data_chained_resigned, merkle_code_chained_resigned => true,
                else => false,
            };
        }

        pub fn isData(self: Variant) bool {
            return switch (self.inner & 0xF0) {
                legacy_data, // deprecated
                merkle_data, // deprecated
                merkle_data_chained,
                merkle_data_chained_resigned,
                => true,
                else => false,
            };
        }

        pub fn isCode(self: Variant) bool {
            return switch (self.inner & 0xF0) {
                legacy_code, // deprecated
                merkle_code, // deprecated
                merkle_code_chained,
                merkle_code_chained_resigned,
                => true,
                else => false,
            };
        }

        fn isMerkle(self: Variant) bool {
            return switch (self.inner & 0xF0) {
                merkle_data, // deprecated
                merkle_code, // deprecated
                merkle_data_chained,
                merkle_code_chained,
                merkle_data_chained_resigned,
                merkle_code_chained_resigned,
                => true,
                else => false,
            };
        }

        pub fn eql(self: Variant, other: Variant) bool {
            return self.inner == other.inner;
        }

        /// returns a code variant as a data variant (or vice versa), preserving its fields
        pub fn swapType(self: Variant) Variant {
            // swaps bit 4 and 5, swaps bit 6 and 7
            return .{
                .inner = ((self.inner & 0x50) << 1) |
                    ((self.inner & 0xA0) >> 1) |
                    (self.inner & 0x0F),
            };
        }

        // upper 4 bits
        const legacy_data = 0xA0; // deprecated
        const legacy_code = 0x50; // deprecated
        const merkle_data = 0x80; // deprecated by SIMD-0313
        const merkle_code = 0x40; // deprecated by SIMD-0313
        const merkle_data_chained = 0x90;
        const merkle_code_chained = 0x60;
        const merkle_data_chained_resigned = 0xB0;
        const merkle_code_chained_resigned = 0x70;
    };

    const min_header_size = @offsetOf(Shred, "code_or_data") +
        @min(@sizeOf(DataHeader), @sizeOf(CodeHeader));
    const min_size = 1203;
    const max_size = 1228;

    // This might not be possible? But this definitely always works as an upper bound
    const data_payload_max = min_size - @sizeOf(DataHeader);

    const merkle_node_size = 20;
    const merkle_root_size = 32;

    // [firedancer] https://github.com/firedancer-io/firedancer/commit/7cbb71919ec9b8045c247957280e5b15d1e0cb85
    /// Makes sure that the *layout* of the Shred is valid.
    pub fn fromPacketChecked(packet: *const Packet) !*const Shred {
        if (packet.len < min_header_size) return error.PacketUnderMinHeaderSize;

        const shred: *const Shred = @ptrCast(packet);
        if (!shred.variant.isSupported()) return error.UnsupportedVariant;

        const header_size = shred.variant.headerSize();
        if (packet.len < header_size) return error.PacketUnderHeaderSize;

        const trailer_size: u16 = shred.variant.merkleSize() +
            (if (shred.variant.isResigned()) @as(u16, Signature.SIZE) else 0) +
            @as(u16, Hash.SIZE); // all shreds are chained

        const zero_padding_size, const payload_size = if (shred.variant.isData()) sizes: {
            if (shred.code_or_data.data.size < header_size) return error.DataSmallerThanHeader;

            if (packet.len < min_size) return error.DataPacketUnderMinSize;

            const payload_size = shred.code_or_data.data.size - header_size;

            const effective_size = min_size;
            if (effective_size < header_size + payload_size + trailer_size)
                return error.DataEffectiveSizeTooSmall;

            break :sizes .{
                effective_size - header_size - payload_size - trailer_size,
                payload_size,
            };
        } else sizes: {
            const zero_padding_size = 0;
            if (header_size + zero_padding_size + trailer_size > max_size)
                return error.CodeShredOverMaxSize;

            break :sizes .{
                zero_padding_size,
                max_size - header_size - zero_padding_size - trailer_size,
            };
        };

        if (packet.len < header_size + payload_size + zero_padding_size + trailer_size)
            return error.PacketSizeUnderExpected3;

        if (shred.variant.isData()) {
            // [firedancer] https://github.com/firedancer-io/firedancer/commit/4936f39676997d95e5d15772d3904e5942fa9864
            const parent_offset = shred.code_or_data.data.parent_offset;
            const slot = shred.slot;
            const flags = shred.code_or_data.data.flags;

            if (flags.last_shred_in_slot and !flags.data_complete)
                return error.DataShredMarkedCompleteIsNotLastInSet;

            // TODO: support the upcoming feature shredXP8xLjJWp1AWh3gAFsFn4GSH1vohhCMDHw5koU, which
            // drops data shreds with data_complete=true that aren't the last data shred in the set.

            // TODO: drop shreds with last_shred_in_slot that aren't the last data shred in the set.

            if (parent_offset > slot) return error.BadOffset;

            if ((slot != 0 and parent_offset == 0) or (slot > 1 and parent_offset == slot))
                return error.BadSlotOrParentOffset;
            if (shred.slot_idx < shred.fec_set_idx) return error.BadSlotIdx;
        } else {
            const code_header = shred.code_or_data.code;

            if (code_header.code_shred_idx >= code_header.code_count)
                return error.BadCodeShredIdx;
            if (code_header.code_shred_idx > shred.slot_idx)
                return error.BadSlotIdx;
            if (code_header.data_count == 0 or code_header.code_count == 0)
                return error.NoCodeOrDataCount;
            if (code_header.code_count + code_header.data_count > 256)
                return error.CodeOrDataCountTooLarge;
        }

        return shred;
    }

    pub fn fromBufferUnchecked(buffer: *const Packet.Buffer) *const Shred {
        return @ptrCast(buffer);
    }

    // This is combined with fragments from other shreds in the erasure set to
    // reconstruct a collection of entries.
    pub fn erasureFragment(shred: *const Shred) ?[]const u8 {
        const buffer: *const Packet.Buffer = @ptrCast(@alignCast(shred));
        const header_size = shred.variant.headerSize();
        if (header_size == 0) unreachable; // we should have gotten rid of this shred earlier?

        // capacity = payload_size - headers_size - chained_merkle_root - merkle_proof - retransmitter_sig
        const payload_size: usize = if (shred.variant.isData()) min_size else max_size;
        // NOTE: all shreds are now chained
        const chained_size: usize = merkle_root_size;
        const proof_size: usize = @as(usize, shred.variant.merkleCount()) * merkle_node_size;
        const resign_size: usize = if (shred.variant.isResigned()) Signature.SIZE else 0;
        const trailer = chained_size + proof_size + resign_size;

        if (payload_size < header_size + trailer) return null;
        const cap = payload_size - header_size - trailer;

        const end = header_size + cap;
        if (end > Packet.capacity) return null;

        // Data shreds: erasure shard starts after signature (offset 64)
        // Code shreds: erasure shard starts after header
        const start_off: usize = if (shred.variant.isData()) Signature.SIZE else header_size;
        return buffer[start_off..end];
    }

    fn size(shred: *const Shred) u16 {
        return if (shred.variant.isCode())
            max_size
        else
            min_size;
    }

    const MerkleProofNode = extern struct { data: [merkle_node_size]u8 };

    fn merkleProofNodes(shred: *const Shred) []const MerkleProofNode {
        const buffer: *const Packet.Buffer = @ptrCast(@alignCast(shred));

        // The offset of the merkle inclusion proof
        const merkle_offset = shred.size() -
            shred.variant.merkleSize() -
            if (shred.variant.isResigned()) Signature.SIZE else 0;

        const merkle_proof_ptr: [*]const MerkleProofNode =
            @ptrCast(buffer[0..].ptr + merkle_offset);

        return merkle_proof_ptr[0..shred.variant.merkleCount()];
    }

    // The payload of a data shred. Asserts shred is a data shred.
    pub fn dataPayload(shred: *const Shred) []const u8 {
        std.debug.assert(shred.variant.isData());
        const buffer: *const Packet.Buffer = @ptrCast(@alignCast(shred));

        std.log.info("shred slot{} idx{} variant{}", .{ shred.slot, shred.slot_idx, shred.variant });

        return buffer[@offsetOf(Shred, "code_or_data") + @sizeOf(DataHeader) .. shred.code_or_data.data.size];
    }

    // The bytes which are checked against the merkle root.
    // includes: header (excluding signature) + code/data payload + chained root + maybe padding
    // does not include: retransmit signature + proof nodes
    // [firedancer] https://github.com/firedancer-io/firedancer/blob/9f7770af997a1443e7903113fc03ca1ce3b0ad73/src/ballet/shred/fd_shred.c#L109
    fn merkleProtected(shred: *const Shred) []const u8 {
        const erasure_protected_size = 1115 + @offsetOf(Shred, "code_or_data") + @sizeOf(DataHeader) -
            Signature.SIZE -
            merkle_node_size * shred.variant.merkleCount() -
            @intFromBool(shred.variant.isChained()) * @as(usize, merkle_root_size) -
            @intFromBool(shred.variant.isResigned()) * Signature.SIZE;

        const data_merkle_protected_size = erasure_protected_size +
            @as(usize, merkle_root_size) * @intFromBool(shred.variant.isChained());

        const code_merkle_protected_size = erasure_protected_size +
            @as(usize, merkle_root_size) * @intFromBool(shred.variant.isChained()) +
            @offsetOf(Shred, "code_or_data") + @sizeOf(CodeHeader) -
            Signature.SIZE;

        const merkle_protected_size = if (shred.variant.isData())
            data_merkle_protected_size
        else
            code_merkle_protected_size;

        return @as(*const Packet.Buffer, @ptrCast(@alignCast(shred)))[Signature.SIZE..][0..merkle_protected_size];
    }

    // Added by the node who retransmitted the shred to us over Turbine.
    // This is only used for the shreds in the final erasure set of the slot.
    // Only safe on pre-checked packets.
    fn retransmitterSignature(packet: *const Shred) ?[]const u8 {
        const shred = fromBufferUnchecked(packet);
        _ = shred;
    }

    // Reconstructs the merkle root from a shred
    pub fn merkleRoot(shred: *const Shred, out: *Hash) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "merkleRoot" });
        defer zone.deinit();

        std.debug.assert(shred.variant.isMerkle());

        const is_data = shred.variant.isData();

        const in_type_idx = if (is_data)
            shred.slot_idx - shred.fec_set_idx
        else
            shred.code_or_data.code.code_shred_idx;

        const shred_idx = if (is_data)
            in_type_idx
        else
            in_type_idx + shred.code_or_data.code.data_count;

        const merkle_protected = shred.merkleProtected();
        const merkle_tree = shred.merkleProofNodes();

        var leaf: Hash = undefined;
        hashLeaf(merkle_protected, &leaf);

        try computeMerkleRoot(shred_idx, &leaf, merkle_tree, out);
    }

    const MERKLE_HASH_PREFIX_LEAF: *const [26]u8 = "\x00SOLANA_MERKLE_SHREDS_LEAF";
    const MERKLE_HASH_PREFIX_NODE: *const [26]u8 = "\x01SOLANA_MERKLE_SHREDS_NODE";

    fn hashLeaf(merkle_protected_data: []const u8, out: *Hash) void {
        out.* = Hash.initMany(&.{ MERKLE_HASH_PREFIX_LEAF, merkle_protected_data });
    }

    fn joinNodes(out: *Hash, lhs: *const [20]u8, rhs: *const [20]u8) void {
        const t = Hash.initMany(&.{ MERKLE_HASH_PREFIX_NODE, lhs, rhs });
        out.* = t;
    }

    fn computeMerkleRoot(
        shred_idx: u32,
        leaf_node: *const Hash,
        proof_nodes: []const MerkleProofNode,
        out: *Hash,
    ) !void {
        var idx = shred_idx;
        out.* = leaf_node.*;

        for (proof_nodes) |*node| {
            switch (idx % 2) {
                0 => joinNodes(out, out.data[0..merkle_node_size], &node.data),
                1 => joinNodes(out, &node.data, out.data[0..merkle_node_size]),
                else => unreachable,
            }
            idx >>= 1;
        }

        if (idx != 0) return error.InvalidMerkleProof;
    }
};
