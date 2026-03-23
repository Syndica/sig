//! This service listens on a ringbuffer of packets, and validates, verifies, and deserialises
//! shreds.

const std = @import("std");
const bk = @import("binkode");
const start = @import("start");
const lib = @import("lib");
const tracy = @import("tracy");
const rs_table = common.reed_solomon_table;

// const shred = common.shred;
// const layout = shred.layout;

const Pair = common.net.Pair;
const Packet = common.net.Packet;
const Slot = common.solana.Slot;
const Hash = common.solana.Hash;
const Signature = common.solana.Signature;
const Pubkey = common.solana.Pubkey;
const Atomic = std.atomic.Value;

comptime {
    _ = start;
}

pub const name = .shred_receiver;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    net_pair: *Pair,
};

pub const ReadOnly = struct {
    config: *const lib.shred.RecvConfig,
};

// stubs
const stub_root_slot = 0;
const stub_max_slot = std.math.maxInt(Slot); // TODO agave uses BankForks for this

// we can read the bincode directly - no deserialisation/copying required
// Methods taking `self: *const Shred` assume that self is pointing to the Packet's buffer
// https://github.com/solana-foundation/specs/blob/main/p2p/shred.md
const Shred = extern struct {
    signature: Signature align(1),
    variant: Variant align(1),
    slot: Slot align(1),
    slot_idx: u32 align(1),
    version: u16 align(1),
    fec_set_idx: u32 align(1),
    code_or_data: extern union {
        data: DataHeader,
        code: CodeHeader,
    } align(1),

    const DataHeader = extern struct {
        parent_offset: u16 align(1),
        flags: u8 align(1),
        size: u16 align(1),
    };

    const CodeHeader = extern struct {
        data_count: u16 align(1),
        code_count: u16 align(1),
        code_shred_idx: u16 align(1),
    };

    const Variant = extern struct {
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

        fn merkleCount(self: Variant) u8 {
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

        fn isData(self: Variant) bool {
            return switch (self.inner & 0xF0) {
                legacy_data, // deprecated
                merkle_data, // deprecated
                merkle_data_chained,
                merkle_data_chained_resigned,
                => true,
                else => false,
            };
        }

        fn isCode(self: Variant) bool {
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

        fn eql(self: Variant, other: Variant) bool {
            return self.inner == other.inner;
        }

        /// returns a code variant as a data variant (or vice versa), preserving its fields
        fn swapType(self: Variant) Variant {
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

    const merkle_node_size = 20;
    const merkle_root_size = 32;

    // [firedancer] https://github.com/firedancer-io/firedancer/commit/7cbb71919ec9b8045c247957280e5b15d1e0cb85
    /// Makes sure that the *layout* of the Shred is valid.
    fn fromPacketChecked(packet: *const Packet) !*const Shred {
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

            if ((shred.code_or_data.data.flags & 0xC0) == 0x80) return error.BadFlags;
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

    fn fromBufferUnchecked(buffer: *const Packet.Buffer) *const Shred {
        return @ptrCast(buffer);
    }

    // This is combined with fragments from other shreds in the erasure set to
    // reconstruct a collection of entries.
    fn erasureFragment(shred: *const Shred) ?[]const u8 {
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
    fn dataPayload(shred: *const Shred) []const u8 {
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
    fn merkleRoot(shred: *const Shred, out: *Hash) !void {
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

test "Shred layout" {
    const types = &.{
        Shred,
        Shred.DataHeader,
        Shred.CodeHeader,
    };

    const expected_offsets = &.{
        &.{ 0x00, 0x40, 0x41, 0x49, 0x4d, 0x4f, 0x53 },
        &.{ 0x00, 0x02, 0x03 },
        &.{ 0x00, 0x02, 0x04 },
    };

    inline for (types, expected_offsets) |Type, offsets| {
        inline for (
            comptime std.meta.fieldNames(Type),
            offsets,
        ) |field_name, expected_offset| {
            const actual_offset = @offsetOf(Type, field_name);
            if (actual_offset == expected_offset) continue;

            @compileLog(std.fmt.comptimePrint(
                "{s} field {s} found with offset 0x{X}, expected 0x{X}",
                .{ @typeName(Type), field_name, actual_offset, expected_offset },
            ));
        }
    }

    if (@alignOf(Shred) != 1) @compileError("Shred should be align(1)");
}

// Represents a FEC (Forward Error Correction) set which has yet to be reconstructed.
const FecSetCtx = extern struct {
    data_shreds_received: std.StaticBitSet(data_shreds_max),
    code_shreds_received: std.StaticBitSet(code_shreds_max),

    // all packets are pre-validated shreds, i.e. Shred.fromPacketUnchecked is safe
    // items are valid iff its index is set to 1 in its corresponding bitset
    // TODO: these fields will likely cause a lot of memory use, consider using a pool of them in future
    data_shreds_buf: [data_shreds_max]Packet.Buffer,
    code_shreds_buf: [code_shreds_max]Packet.Buffer,

    // used to make sure that all code and data shreds have the same variant as eachother
    data_variant: Shred.Variant,
    code_variant: Shred.Variant,

    // we store the first seen, and make sure later shreds have the same one
    merkle_root: Hash,

    // https://github.com/firedancer-io/firedancer/blob/ecd2d6d8f5b9f926d0b9aa9360efe36ea1550ad6/src/ballet/reedsol/fd_reedsol.h#L23
    // https://github.com/solana-foundation/specs/blob/main/p2p/shred.md

    // There's now a max of 32+32 shreds
    // https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0317-enforce-32-data-shreds.md
    const data_shreds_max = 32;
    const code_shreds_max = 32;
    const fec_shred_cnt = 32;

    fn totalShredsReceived(self: *const FecSetCtx) u8 {
        const data_recv: u8 = @intCast(self.data_shreds_received.count());
        std.debug.assert(data_recv <= data_shreds_max);
        const code_recv: u8 = @intCast(self.code_shreds_received.count());
        std.debug.assert(code_recv <= code_shreds_max);

        comptime std.debug.assert(data_shreds_max + code_shreds_max < 256);

        return data_recv + code_recv;
    }
};

const FecSetId = extern struct {
    slot: Slot,
    fec_set_idx: u32,

    fn eql(a: *const FecSetId, b: *const FecSetId) bool {
        return (a.slot == b.slot and a.fec_set_idx == b.fec_set_idx);
    }

    fn compare(a: *const FecSetId, b: *const FecSetId) std.math.Order {
        if (a.slot > b.slot) return .gt;
        if (a.slot < b.slot) return .lt;
        if (a.fec_set_idx > b.fec_set_idx) return .gt;
        if (a.fec_set_idx < b.fec_set_idx) return .lt;
        std.debug.assert(a.slot == b.slot);
        std.debug.assert(a.fec_set_idx == b.fec_set_idx);
        return .eq;
    }
};

fn hashSignature(a: *const Signature) u32 {
    return @bitCast((a.r[0..2] ++ a.s[0..2]).*);
}

// TODO: this datastructure is a bit silly, worth profiling to see how slow it is
/// Tracks in-progress FEC sets
const ProgressMap = extern struct {
    const n = 256; // max number of in-progress fec sets. Number chosen arbitrarily.
    const Idx = u16;

    signatures: [n]Signature,
    sig_hashes: [n]u32,
    ids: [n]FecSetId,
    contexts: [n]FecSetCtx,

    used: [n]bool,

    // for evicting highest-slot first
    eviction_queue_len: Idx,
    eviction_queue_buf: [n]Idx,

    const empty: ProgressMap = .{
        .signatures = undefined,
        .sig_hashes = undefined,
        .ids = undefined,
        .contexts = undefined,

        .used = @splat(false),

        .eviction_queue_len = 0,
        .eviction_queue_buf = undefined,
    };

    fn evictionQueue(self: *ProgressMap) Queue {
        return .{
            .items = self.eviction_queue_buf[0..self.eviction_queue_len],
            .cap = n,
            .context = .{ .ids = &self.ids, .used = &self.used },
            .allocator = std.testing.failing_allocator,
        };
    }

    fn getFecSetCtx(self: *ProgressMap, signature: *const Signature) ?*FecSetCtx {
        const idx = self.getFecSetCtxIdx(signature) orelse return null;
        return &self.contexts[idx];
    }

    fn getFecSetCtxIdx(self: *const ProgressMap, signature: *const Signature) ?Idx {
        const hashed = hashSignature(signature);

        for (
            &self.signatures,
            &self.sig_hashes,
            &self.used,
            0..,
        ) |sig, hash, used, i| {
            if (!used) continue;
            if (hash != hashed) continue;
            if (!sig.eql(signature)) continue;
            return @intCast(i);
        }

        return null;
    }

    // NOTE: this function only sets the entry's id and sets used to true.
    // caller must populate all other fields before calling any ProgressMap functions again.
    fn allocFecSetCtx(self: *ProgressMap, fec_set_id: FecSetId) Idx {
        const zone = tracy.Zone.init(@src(), .{ .name = "allocFecSetCtx" });
        defer zone.deinit();

        {
            var eviction_queue = self.evictionQueue();

            tracy.plot(u16, "eviction queue count", @intCast(eviction_queue.count()));
        }

        const unused_idx = for (&self.used, 0..) |used, i| {
            if (!used) break i;
        } else self.evict() orelse unreachable; // safe: we can always evict if there's entries

        self.used[unused_idx] = true;
        self.ids[unused_idx] = fec_set_id;

        var eviction_queue = self.evictionQueue();

        eviction_queue.add(@intCast(unused_idx)) catch unreachable;
        self.eviction_queue_len += 1;

        tracy.plot(u16, "eviction queue count", @intCast(eviction_queue.count()));

        return @intCast(unused_idx);
    }

    fn containsFecSetId(self: *const ProgressMap, id: *const FecSetId) bool {
        for (self.ids, self.used) |found_id, used| {
            if (!used) continue;
            if (found_id.eql(id)) return true;
        }
        return false;
    }

    fn evict(self: *ProgressMap) ?Idx {
        const zone = tracy.Zone.init(@src(), .{ .name = "evict" });
        defer zone.deinit();

        var eviction_queue = self.evictionQueue();

        tracy.plot(u16, "eviction queue count", @intCast(eviction_queue.count()));

        const evict_idx = eviction_queue.removeOrNull() orelse return null;
        self.eviction_queue_len -= 1;
        tracy.plot(u16, "eviction queue count", @intCast(eviction_queue.count()));

        self.used[evict_idx] = false;

        self.signatures[evict_idx] = undefined;
        self.sig_hashes[evict_idx] = undefined;
        self.ids[evict_idx] = undefined;
        self.contexts[evict_idx] = undefined;

        return evict_idx;
    }

    const QueueContext = struct {
        ids: *const [n]FecSetId,
        used: *const [n]bool,

        fn compare(self: QueueContext, a: Idx, b: Idx) std.math.Order {
            std.debug.assert(self.used[a] and self.used[b]);

            // remove greatest (slot, fec id) first
            return std.math.Order.invert(FecSetId.compare(&self.ids[a], &self.ids[b]));
        }
    };

    const Queue = std.PriorityQueue(Idx, QueueContext, QueueContext.compare);
};

// TODO: this data structure needs replacing
fn FixedArrayMap(
    Key: type,
    Value: type,
    HashedKey: type,
    maybeHashFn: ?fn (*const Key) HashedKey,
    eql: fn (*const Key, *const Key) bool,
    n: usize,
) type {
    return extern struct {
        keys: [n]Key,
        vals: [n]Value,
        hash: if (maybeHashFn != null) [n]HashedKey else [n]void,
        used: [n]bool,

        const Self = @This();

        const empty: Self = .{
            .keys = @splat(undefined),
            .vals = @splat(undefined),
            .hash = @splat(undefined),
            .used = @splat(false),
        };

        fn get(self: *Self, key: *const Key) ?*Value {
            const idx = self.getIdx(key) orelse return null;
            return &self.vals[idx];
        }

        fn contains(self: *const Self, key: *const Key) bool {
            return self.getIdx(key) != null;
        }

        fn getIdx(self: *const Self, key: *const Key) ?u32 {
            const hashed = if (maybeHashFn) |hashFn| hashFn(key) else {};

            for (&self.keys, &self.hash, &self.used, 0..) |*k, hash, used, i| {
                if (!used) continue;
                if (hashed != hash) continue;
                if (!eql(key, k)) continue;
                return @intCast(i);
            }

            return null;
        }

        fn getIdxUnused(self: *const Self) ?u32 {
            for (&self.used, 0..) |used, i| {
                if (used) continue;
                return @intCast(i);
            }
            return null;
        }

        fn insertRemovingFirst(self: *Self, key: *const Key, insert: *const Value) void {
            const hashed = if (maybeHashFn) |hashFn| hashFn(key) else {};

            const target_idx = if (self.getIdxUnused()) |unused_idx| unused_idx else idx: {
                @branchHint(.likely);
                @memmove(self.keys[0 .. n - 2], self.keys[1 .. n - 1]);
                @memmove(self.vals[0 .. n - 2], self.vals[1 .. n - 1]);
                @memmove(self.hash[0 .. n - 2], self.hash[1 .. n - 1]);
                @memmove(self.used[0 .. n - 2], self.used[1 .. n - 1]);
                break :idx n - 1;
            };

            self.keys[target_idx] = key.*;
            self.vals[target_idx] = insert.*;
            self.hash[target_idx] = hashed;
            self.used[target_idx] = true;
        }

        fn containsValue(self: *const Self, value: *const Value) bool {
            for (&self.vals) |*val| if (val.eql(value)) return true;
            return false;
        }
    };
}

const State = struct {
    // NOTE: we don't need a VerifiedMerkleRoots cache, as our ProgressMap already handles this
    in_progress: ProgressMap,
    done: DoneMap,
    // verified_merkle_roots: VerifiedMerkleRoots,

    const empty: State = .{
        .in_progress = .empty,
        .done = .empty,
        // .verified_merkle_roots = .empty,
    };

    const DoneMap = FixedArrayMap(FecSetId, SignatureHash, void, null, FecSetId.eql, 256);
    // const VerifiedMerkleRoots = FixedArrayMap(Hash, void, MerkleRootHash, hashMerkleRoot, Hash.eql, 128);

    const SignatureHash = u32;
    // const MerkleRootHash = u32;

    // fn hashMerkleRoot(a: *const Hash) MerkleRootHash {
    //     return @bitCast(a.data[0..4]);
    // }
};

// NOTE: as of writing, @sizeOf(State) ~= 22MB. This is why it is defined here rather than inside
// of serviceMain.
var state: State = .empty;

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    std.log.info("Waiting for shreds on port {}", .{rw.pair.port});

    while (true) {
        const packet = it.next() orelse continue;
        defer it.markUsed();

        const zone = tracy.Zone.init(@src(), .{ .name = "shred recv" });
        defer zone.deinit();

        const packet = slice.get(0);
        defer slice.markUsed(1);
        defer std.log.info("", .{});

        std.log.info("Got packet", .{});

        // check that the shred variant is supported and the header is valid
        const shred = Shred.fromPacketChecked(packet) catch |err| {
            std.log.info("bad packet, err {}\n", .{err});
            continue; // TODO: report reasons for rejecting/ignoring shreds in all cases
        };

        // ignore shred from a slot that's too old or too new
        if (shred.slot < stub_root_slot) continue;
        if (shred.slot > stub_max_slot) continue;

        // ignore shred with wrong version
        if (shred.version != stub_shred_version.load(.monotonic)) continue;

        // ignore any with bad counts or indices (SIMD 0317 enforces this)
        if (shred.variant.isCode()) {
            if (shred.code_or_data.code.data_count != FecSetCtx.fec_shred_cnt) continue;
            if (shred.code_or_data.code.code_count != FecSetCtx.fec_shred_cnt) continue;
            if (shred.code_or_data.code.code_shred_idx >= FecSetCtx.fec_shred_cnt) continue;
        }

        const in_type_idx = if (shred.variant.isData())
            shred.slot_idx - shred.fec_set_idx
        else
            shred.code_or_data.code.code_shred_idx;

        if (shred.fec_set_idx % FecSetCtx.fec_shred_cnt != 0) continue;
        if (in_type_idx >= FecSetCtx.fec_shred_cnt) continue;

        if (shred.variant.isData()) {
            // data shreds marked as complete must be the last shred in the fec set.
            const slot_complete = 0x80; // hm
            if (((shred.code_or_data.data.flags & slot_complete) != 0) and
                (((shred.slot_idx + 1) % FecSetCtx.fec_shred_cnt) != 0))
            {
                std.log.info("data shred marked as complete isn't the last shred in the set", .{});
                continue;
            }
        }

        const merkle_layer_count = 7;
        if (shred.variant.merkleCount() > merkle_layer_count - 1) {
            std.log.info("merkleCount too large", .{});
            continue;
        }

        std.log.info("shred {} ({s}) passing baseline checks", .{
            @as(FecSetId, .{ .fec_set_idx = shred.fec_set_idx, .slot = shred.slot }),
            if (shred.variant.isCode()) "code" else "data",
        });

        // is fec set already being built?
        const maybe_fec_set = state.in_progress.getFecSetCtx(&shred.signature);
        if (maybe_fec_set == null) {
            std.log.info("got shred in unknown fec set", .{});

            // fec set is not currently being built (likely finished already)

            const fec_set_id: FecSetId = .{ .fec_set_idx = shred.fec_set_idx, .slot = shred.slot };

            // ignore shreds from already finished fec sets
            if (state.done.get(&fec_set_id)) |finished_set| {
                const signature_hash = hashSignature(&shred.signature);
                if (signature_hash == finished_set.*) {
                    std.log.info("got shred from finished fec set", .{});

                    continue;
                } else {
                    // we got a different hash, for the same slot + idx, this is likely equivocation
                    std.log.info("found equivocated shred?", .{});
                    continue;
                }
            }

            // if we have this FecSetId with a different signature, this means equivocation has occured
            if (state.in_progress.containsFecSetId(&fec_set_id)) {
                std.log.info("found equivocated shred", .{});

                continue;
            }
        }

        var shred_merkle_root: Hash = undefined;
        try shred.merkleRoot(&shred_merkle_root);

        const fec_set_id: FecSetId = .{ .fec_set_idx = shred.fec_set_idx, .slot = shred.slot };

        const fec_set_ctx: *FecSetCtx = if (maybe_fec_set) |fec_set_ctx| blk: {
            @branchHint(.likely); // fec set is being constructed, and this is not the first shred

            std.log.info("got shred in in-progress fec set", .{});

            // variant should match that of the first recorded shred in the fec set
            if ((shred.variant.isData() and !shred.variant.eql(fec_set_ctx.data_variant)) or
                (shred.variant.isCode() and !shred.variant.eql(fec_set_ctx.code_variant)))
            {
                std.log.info(
                    "dropping shred with variant mismatch, found {}, found_but_swapped: {}, expected_data: {}, expected_code: {}",
                    .{
                        shred.variant,
                        shred.variant.swapType(),
                        fec_set_ctx.data_variant,
                        fec_set_ctx.code_variant,
                    },
                );
                continue;
            }

            if (!fec_set_ctx.merkle_root.eql(&shred_merkle_root)) {
                std.log.info("merkle root mismatch\n", .{});
                continue;
            }
            // TODO: check against prev and next shred if present
            // TODO: update in_progress state
            // TODO: check for duplicates?

            break :blk fec_set_ctx;
        } else blk: {
            @branchHint(.unlikely); // this is the first shred of a new in-progress fec set
            std.log.info("got shred in new fec set", .{});

            shred.signature.verify(
                ro.leader_schedule.get(shred.slot) orelse {
                    std.log.info("unknown leader: {}", .{shred.slot});
                    continue;
                },
                &shred_merkle_root.data,
            ) catch |err| {
                std.log.info("verification failed: {}", .{err});
                continue;
            };

            std.log.info("got verified shred in new fec set", .{});
            // shred looks good, let's add a new ctx to in_progress

            const new_fec_set_idx = state.in_progress.allocFecSetCtx(fec_set_id);

            state.in_progress.contexts[new_fec_set_idx] = .{
                // we will check against these for equality in later received shreds
                .data_variant = if (shred.variant.isData())
                    shred.variant
                else
                    shred.variant.swapType(),

                .code_variant = if (shred.variant.isCode())
                    shred.variant
                else
                    shred.variant.swapType(),

                .merkle_root = shred_merkle_root,

                .data_shreds_received = .initEmpty(),
                .code_shreds_received = .initEmpty(),

                .data_shreds_buf = undefined,
                .code_shreds_buf = undefined,
            };

            state.in_progress.used[new_fec_set_idx] = true;
            state.in_progress.ids[new_fec_set_idx] = fec_set_id;
            state.in_progress.signatures[new_fec_set_idx] = shred.signature;
            state.in_progress.sig_hashes[new_fec_set_idx] = hashSignature(&shred.signature);

            std.debug.assert(state.in_progress.contexts[new_fec_set_idx].totalShredsReceived() == 0);

            break :blk &state.in_progress.contexts[new_fec_set_idx];

            // TODO: handle resigned shreds?
        };

        // We now have a new shred that has passed validation

        if (shred.variant.isCode()) {
            if (fec_set_ctx.code_shreds_received.isSet(in_type_idx)) {
                std.log.info("shred already in fec set, skipping", .{});
                continue;
            }

            fec_set_ctx.code_shreds_received.set(in_type_idx); // track shred as received
            fec_set_ctx.code_shreds_buf[in_type_idx] = packet.data; // persist packet to our state
        }
        if (shred.variant.isData()) {
            if (fec_set_ctx.data_shreds_received.isSet(in_type_idx)) {
                std.log.info("shred already in fec set, skipping", .{});
                continue;
            }

            fec_set_ctx.data_shreds_received.set(in_type_idx); // track shred as received
            fec_set_ctx.data_shreds_buf[in_type_idx] = packet.data; // persist packet to our state
        }

        std.debug.assert(fec_set_ctx.totalShredsReceived() >= 1); // we just received one

        std.log.info("got {}/32 shreds", .{fec_set_ctx.totalShredsReceived()});

        if (fec_set_ctx.totalShredsReceived() < FecSetCtx.fec_shred_cnt) {
            continue; // we're all good, but we haven't received enough to reconstruct the fec set yet
        }

        // starting fec set reconstruction now
        reedsol.reconstructFecSet(fec_set_ctx);

        std.debug.assert(fec_set_ctx.data_shreds_received.count() == FecSetCtx.data_shreds_max);

        var complete: bool = false;
        for (&fec_set_ctx.data_shreds_buf) |*data_packet| {
            const data_shred: *const Shred = .fromBufferUnchecked(data_packet);

            complete = complete or (data_shred.code_or_data.data.flags & 0x40) != 0;
            if (complete) break;
        }

        std.log.info("complete? {}", .{complete});

        state.done.insertRemovingFirst(&fec_set_id, &hashSignature(&shred.signature));

        if (complete) {
            var deshredded_buf: [64 * 1024]u8 = undefined;
            var bytes_written: u16 = 0;

            for (&fec_set_ctx.data_shreds_buf) |*data_shred| {
                const data_payload = Shred.fromBufferUnchecked(data_shred).dataPayload();
                @memcpy(deshredded_buf[bytes_written..][0..data_payload.len], data_payload);
                bytes_written += @intCast(data_payload.len);
            }

            std.log.info("deshredded!", .{});

            const deshredded_bytes = deshredded_buf[0..bytes_written];

            var bincode_buf: [64 * 1024]u8 = undefined;
            var bincode_fba = std.heap.FixedBufferAllocator.init(&bincode_buf);
            const bincode_fba_allocator = bincode_fba.allocator();

            const entries, const consumed = bincode.Entry.slice_config.decodeSlice(
                deshredded_bytes,
                bincode_fba_allocator,
                .{ .endian = .little, .int = .fixint },
                null,
            ) catch |err| {
                std.log.info("decode failed with err {}", .{err});
                continue;
            };
            _ = consumed;

            for (entries) |entry| {
                for (entry.transactions) |tx| {
                    switch (tx.message) {
                        .legacy => |msg| {
                            for (msg.account_keys) |key| {
                                std.log.info("(legacy) key: {f}", .{key});
                            }
                        },
                        .v0 => |msg| {
                            for (msg.account_keys) |key| {
                                std.log.info("(v0) key: {f}", .{key});
                            }
                        },
                    }
                }
            }
        }
    }
}

const reedsol = struct {
    // Reconstructs data shreds when 32/64 shreds have been received
    fn reconstructFecSet(fec_set_ctx: *FecSetCtx) void {
        const zone = tracy.Zone.init(@src(), .{ .name = "reconstructFecSet" });
        defer zone.deinit();

        const data_count = FecSetCtx.fec_shred_cnt;
        const code_count = FecSetCtx.fec_shred_cnt;
        const total_count = data_count + code_count;

        // Build present[] mask and collect erasure shard length from first present shred
        var present: [total_count]bool = @splat(false);
        var shard_len: usize = 0;

        for (0..data_count) |i| {
            if (fec_set_ctx.data_shreds_received.isSet(i)) {
                present[i] = true;
                if (shard_len == 0) {
                    const shred = Shred.fromBufferUnchecked(&fec_set_ctx.data_shreds_buf[i]);
                    if (shred.erasureFragment()) |frag| {
                        shard_len = frag.len;
                    }
                }
            }
        }
        for (0..code_count) |i| {
            if (fec_set_ctx.code_shreds_received.isSet(i)) {
                present[data_count + i] = true;
                if (shard_len == 0) {
                    const shred = Shred.fromBufferUnchecked(&fec_set_ctx.code_shreds_buf[i]);
                    if (shred.erasureFragment()) |frag| {
                        shard_len = frag.len;
                    }
                }
            }
        }

        if (shard_len == 0) return; // no valid shreds found

        // Collect 32 valid indices (indices of present shreds in encoding_matrix row order)
        var valid_indices: [data_count]u8 = undefined;
        var valid_count: u8 = 0;
        for (0..total_count) |i| {
            if (present[i]) {
                valid_indices[valid_count] = @intCast(i);
                valid_count += 1;
                if (valid_count == data_count) break;
            }
        }

        if (valid_count < data_count) return; // not enough shreds

        // Build 32x32 sub-matrix by picking rows from encoding_matrix
        var sub_matrix: [data_count][data_count]u8 = undefined;
        for (0..data_count) |r| {
            sub_matrix[r] = encoding_matrix[valid_indices[r]];
        }

        // Invert sub_matrix via Gaussian elimination on augmented [sub_matrix | identity]
        var aug: [data_count][data_count * 2]u8 = undefined;
        for (0..data_count) |r| {
            for (0..data_count) |c| {
                aug[r][c] = sub_matrix[r][c];
                aug[r][data_count + c] = if (r == c) @as(u8, 1) else @as(u8, 0);
            }
        }

        // Forward elimination
        for (0..data_count) |r| {
            if (aug[r][r] == 0) {
                for (r + 1..data_count) |r_below| {
                    if (aug[r_below][r] != 0) {
                        const tmp = aug[r];
                        aug[r] = aug[r_below];
                        aug[r_below] = tmp;
                        break;
                    }
                }
            }
            if (aug[r][r] == 0) {
                std.log.warn("FEC reconstruction: singular matrix at row {}", .{r});
                return;
            }
            if (aug[r][r] != 1) {
                const scale = field.div(1, aug[r][r]);
                for (0..data_count * 2) |c| {
                    aug[r][c] = field.mul(scale, aug[r][c]);
                }
            }
            for (r + 1..data_count) |r_below| {
                if (aug[r_below][r] != 0) {
                    const scale = aug[r_below][r];
                    for (0..data_count * 2) |c| {
                        aug[r_below][c] = field.add(aug[r_below][c], field.mul(scale, aug[r][c]));
                    }
                }
            }
        }
        // Back-substitution
        for (0..data_count) |d| {
            for (0..d) |r_above| {
                if (aug[r_above][d] != 0) {
                    const scale = aug[r_above][d];
                    for (0..data_count * 2) |c| {
                        aug[r_above][c] = field.add(aug[r_above][c], field.mul(scale, aug[d][c]));
                    }
                }
            }
        }

        // Extract inverted matrix from right half
        var inv: [data_count][data_count]u8 = undefined;
        for (0..data_count) |r| {
            for (0..data_count) |c| {
                inv[r][c] = aug[r][data_count + c];
            }
        }

        // Find leader signature from any present data or code shred (first 64 bytes)
        var leader_sig: [Signature.SIZE]u8 = undefined;
        var have_sig = false;
        for (0..data_count) |i| {
            if (fec_set_ctx.data_shreds_received.isSet(i)) {
                @memcpy(&leader_sig, fec_set_ctx.data_shreds_buf[i][0..Signature.SIZE]);
                have_sig = true;
                break;
            }
        }
        if (!have_sig) {
            for (0..code_count) |i| {
                if (fec_set_ctx.code_shreds_received.isSet(i)) {
                    @memcpy(&leader_sig, fec_set_ctx.code_shreds_buf[i][0..Signature.SIZE]);
                    have_sig = true;
                    break;
                }
            }
        }

        // Collect pointers to erasure shards for the 32 valid indices
        var shard_ptrs: [data_count][*]const u8 = undefined;
        for (0..data_count) |k| {
            const idx = valid_indices[k];
            if (idx < data_count) {
                const shred = Shred.fromBufferUnchecked(&fec_set_ctx.data_shreds_buf[idx]);
                shard_ptrs[k] = (shred.erasureFragment() orelse return).ptr;
            } else {
                const shred = Shred.fromBufferUnchecked(&fec_set_ctx.code_shreds_buf[idx - data_count]);
                shard_ptrs[k] = (shred.erasureFragment() orelse return).ptr;
            }
        }

        // For each missing data shred, reconstruct its erasure shard
        for (0..data_count) |i| {
            if (present[i]) continue; // already have this data shred

            // We need the i-th row of the inverted matrix to recover data shard i
            const inv_row = &inv[i];

            // Destination: write directly into the packet buffer
            var dest_packet = &fec_set_ctx.data_shreds_buf[i];

            // First, copy leader signature into bytes 0..64
            if (have_sig) {
                @memcpy(dest_packet[0..Signature.SIZE], &leader_sig);
            }

            // For data shreds, erasure shard starts at offset 64 (after signature)
            // and ends at headers_size + capacity. We compute it the same way.
            // The erasure shard for data shreds covers bytes [64 .. 64 + shard_len]
            const dest_start = Signature.SIZE; // 64
            const dest_end = dest_start + shard_len;
            if (dest_end > Packet.capacity) return;

            var dest = dest_packet[dest_start..dest_end];

            // Multiply: dest[byte] = sum over k of (inv_row[k] * shard_ptrs[k][byte])
            // First pass: dest = inv_row[0] * shard_ptrs[0]
            const coeff0 = inv_row[0];
            for (0..shard_len) |b| {
                dest[b] = field.mul(coeff0, shard_ptrs[0][b]);
            }
            // Remaining passes: dest += inv_row[k] * shard_ptrs[k]
            for (1..data_count) |k| {
                const coeff = inv_row[k];
                if (coeff == 0) continue;
                for (0..shard_len) |b| {
                    dest[b] = field.add(dest[b], field.mul(coeff, shard_ptrs[k][b]));
                }
            }

            // Mark this data shred as received
            fec_set_ctx.data_shreds_received.set(i);
        }
    }

    // GF(2^8) arithmetic and Reed-Solomon encoding matrix for erasure coding.
    // All operations use pre-computed lookup tables from reed_solomon_table.zig.
    const field = struct {
        inline fn add(a: u8, b: u8) u8 {
            return a ^ b;
        }

        inline fn mul(a: u8, b: u8) u8 {
            return rs_table.mul[a][b];
        }

        inline fn div(a: u8, b: u8) u8 {
            if (a == 0) return 0;
            const log_a = rs_table.log[a];
            const log_b = rs_table.log[b];
            const log_result: i16 = @as(i16, log_a) - @as(i16, log_b);
            return rs_table.exp[@intCast(if (log_result < 0) log_result + 255 else log_result)];
        }

        fn exp(a: u8, n: usize) u8 {
            if (n == 0) return 1;
            if (a == 0) return 0;
            var log_result: usize = @as(usize, rs_table.log[a]) * n;
            while (log_result >= 255) {
                log_result -= 255;
            }
            return rs_table.exp[log_result];
        }
    };

    /// Comptime-generated 64x32 encoding matrix for Reed-Solomon with data_count=32, code_count=32.
    /// Top 32 rows = identity matrix (for data shreds), bottom 32 rows = parity coefficients.
    /// Derived from: Vandermonde(64x32) * inverse(Vandermonde_top(32x32))
    const encoding_matrix: [64][32]u8 = blk: {
        @setEvalBranchQuota(1_000_000);

        const total = 64;
        const data = 32;

        // Step 1: Build 64x32 Vandermonde matrix
        var vandermonde: [total][data]u8 = undefined;
        for (0..total) |r| {
            for (0..data) |c| {
                vandermonde[r][c] = field.exp(@intCast(r), c);
            }
        }

        // Step 2: Extract top 32x32 submatrix and invert via Gaussian elimination
        // Build augmented matrix [top | identity]
        var aug: [data][data * 2]u8 = undefined;
        for (0..data) |r| {
            for (0..data) |c| {
                aug[r][c] = vandermonde[r][c];
            }
            for (0..data) |c| {
                aug[r][data + c] = if (r == c) 1 else 0;
            }
        }

        // Gaussian elimination (forward)
        for (0..data) |r| {
            // Find pivot
            if (aug[r][r] == 0) {
                for (r + 1..data) |r_below| {
                    if (aug[r_below][r] != 0) {
                        const tmp = aug[r];
                        aug[r] = aug[r_below];
                        aug[r_below] = tmp;
                        break;
                    }
                }
            }
            // Scale pivot row
            if (aug[r][r] != 1) {
                const scale = field.div(1, aug[r][r]);
                for (0..data * 2) |c| {
                    aug[r][c] = field.mul(scale, aug[r][c]);
                }
            }
            // Eliminate below
            for (r + 1..data) |r_below| {
                if (aug[r_below][r] != 0) {
                    const scale = aug[r_below][r];
                    for (0..data * 2) |c| {
                        aug[r_below][c] = field.add(aug[r_below][c], field.mul(scale, aug[r][c]));
                    }
                }
            }
        }
        // Back-substitution (eliminate above)
        for (0..data) |d| {
            for (0..d) |r_above| {
                if (aug[r_above][d] != 0) {
                    const scale = aug[r_above][d];
                    for (0..data * 2) |c| {
                        aug[r_above][c] = field.add(aug[r_above][c], field.mul(scale, aug[d][c]));
                    }
                }
            }
        }

        // Extract inverted top matrix from right half of augmented matrix
        var inv_top: [data][data]u8 = undefined;
        for (0..data) |r| {
            for (0..data) |c| {
                inv_top[r][c] = aug[r][data + c];
            }
        }

        // Step 3: Multiply Vandermonde(64x32) * inv_top(32x32) = encoding_matrix(64x32)
        var result: [total][data]u8 = undefined;
        for (0..total) |r| {
            for (0..data) |c| {
                var val: u8 = 0;
                for (0..data) |i| {
                    val = field.add(val, field.mul(vandermonde[r][i], inv_top[i][c]));
                }
                result[r][c] = val;
            }
        }

        break :blk result;
    };
};

const bincode = struct {
    // This isn't quite a bincode fixed int, nor a varint. It's some custom Solana thing used in
    // Agave's `short_vec`. I think it's supposed to be smaller than a fixed or varint for a u16.
    const compact_u16: bk.Codec(u16) = .implement(void, void, struct {
        pub fn encode(
            writer: *std.Io.Writer,
            _: bk.Config,
            values: []const u16,
            _: ?*[encode_stack_size]u64,
            limit: std.Io.Limit,
            _: void,
        ) bk.EncodeToWriterError!bk.EncodedCounts {
            const max_count = limit.max(values.len);
            var byte_count: usize = 0;
            for (values[0..max_count]) |val| {
                var rem: u16 = val;
                while (true) {
                    var elem: u8 = @truncate(rem & 0x7f);
                    rem >>= 7;
                    if (rem == 0) {
                        writer.writeByte(elem) catch return error.EncodeFailed;
                        byte_count += 1;
                        break;
                    } else {
                        elem |= 0x80;
                        writer.writeByte(elem) catch return error.EncodeFailed;
                        byte_count += 1;
                    }
                }
            }
            return .{ .value_count = max_count, .byte_count = byte_count };
        }

        pub const encode_min_size: usize = 1;
        pub const encode_stack_size: usize = 0;
        pub const decodeInit = null;

        pub fn decode(
            reader: *std.Io.Reader,
            _: bk.Config,
            _: ?std.mem.Allocator,
            values: []u16,
            decoded_count: *usize,
            _: void,
        ) bk.DecodeFromReaderError!void {
            for (values, 0..) |*value, i| {
                errdefer decoded_count.* = i;

                var result: u16 = 0;
                var shift: u4 = 0;
                for (0..3) |_| {
                    const byte = try reader.takeByte();
                    result |= @as(u16, byte & 0x7f) << shift;
                    if (byte & 0x80 == 0) break;
                    shift += 7;
                } else {
                    // Fourth byte would be needed → overflow for u16
                    return error.DecodeFailed;
                }
                value.* = result;
            }
            decoded_count.* = values.len;
        }

        pub fn decodeSkip(
            reader: *std.Io.Reader,
            _: bk.Config,
            value_count: usize,
            decoded_count: *usize,
            _: void,
        ) bk.DecodeSkipError!void {
            for (0..value_count) |i| {
                errdefer decoded_count.* = i;
                for (0..3) |_| {
                    const byte = try reader.takeByte();
                    if (byte & 0x80 == 0) break;
                } else {
                    return error.DecodeFailed;
                }
            }
            decoded_count.* = value_count;
        }

        pub const free = null;
    });

    // For slices that have a compact_u16 length rather than a u64
    fn shortVec(comptime Element: type, comptime element: bk.Codec(Element)) bk.Codec([]Element) {
        return comptime .implement(element.EncodeCtx, element.DecodeCtx, struct {
            pub fn encode(
                writer: *std.Io.Writer,
                config: bk.Config,
                values: []const []Element,
                _: ?*[encode_stack_size]u64,
                limit: std.Io.Limit,
                ctx: element.EncodeCtx,
            ) bk.EncodeToWriterError!bk.EncodedCounts {
                const max_count = limit.max(values.len);
                var byte_count: usize = 0;
                for (values[0..max_count]) |slice_val| {
                    // Write compact-u16 length
                    const len: u16 = std.math.cast(u16, slice_val.len) orelse return error.EncodeFailed;
                    const len_counts = try compact_u16.encodeOnePartialRaw(writer, config, &len, null, .unlimited, {});
                    byte_count += len_counts.byte_count;

                    // Write elements
                    const elem_counts = try element.encodeManyPartialRaw(writer, config, slice_val, null, .unlimited, ctx);
                    byte_count += elem_counts.byte_count;
                }
                return .{ .value_count = max_count, .byte_count = byte_count };
            }

            pub const encode_min_size: usize = 1;
            pub const encode_stack_size: usize = 0;

            pub fn decodeInit(
                gpa_opt: ?std.mem.Allocator,
                values: [][]Element,
                _: element.DecodeCtx,
            ) std.mem.Allocator.Error!void {
                _ = gpa_opt.?;
                @memset(values, &.{});
            }

            pub fn decode(
                reader: *std.Io.Reader,
                config: bk.Config,
                gpa_opt: ?std.mem.Allocator,
                values: [][]Element,
                decoded_count: *usize,
                ctx: element.DecodeCtx,
            ) bk.DecodeFromReaderError!void {
                const gpa = gpa_opt.?;
                for (values, 0..) |*value, i| {
                    errdefer decoded_count.* = i;

                    const len = try compact_u16.decode(reader, null, .default, {});

                    const elems = try gpa.alloc(Element, len);
                    errdefer gpa.free(elems);

                    // decode into elems
                    try element.decodeInitMany(gpa, elems, ctx);
                    errdefer element.freeMany(gpa, elems, ctx);

                    try element.decodeIntoMany(reader, gpa, config, elems, ctx);

                    value.* = elems;
                }
                decoded_count.* = values.len;
            }

            pub fn decodeSkip(
                reader: *std.Io.Reader,
                config: bk.Config,
                value_count: usize,
                decoded_count: *usize,
                ctx: element.DecodeCtx,
            ) bk.DecodeSkipError!void {
                for (0..value_count) |i| {
                    errdefer decoded_count.* = i;
                    const len = try compact_u16.decode(reader, null, .default, null);
                    try element.decodeSkip(reader, config, len, ctx);
                }
                decoded_count.* = value_count;
            }

            pub fn free(
                gpa_opt: ?std.mem.Allocator,
                slice_list: []const []Element,
                ctx: element.DecodeCtx,
            ) void {
                const gpa = gpa_opt.?;
                for (slice_list) |slice_value| {
                    element.freeMany(gpa, slice_value, ctx);
                    gpa.free(slice_value);
                }
            }
        });
    }

    const hash_codec: bk.Codec(Hash) = .standard(.tuple(.{
        .data = .array(.fixint),
    }));

    const pubkey_codec: bk.Codec(Pubkey) = .standard(.tuple(.{
        .data = .array(.fixint),
    }));

    const MessageHeader = struct {
        num_required_signatures: u8,
        num_readonly_signed_accounts: u8,
        num_readonly_unsigned_accounts: u8,

        const bk_config: bk.Codec(MessageHeader) = .standard(.tuple(.{
            .num_required_signatures = .fixint,
            .num_readonly_signed_accounts = .fixint,
            .num_readonly_unsigned_accounts = .fixint,
        }));
    };

    const CompiledInstruction = struct {
        program_id_index: u8,
        accounts: []u8,
        data: []u8,

        const bk_config: bk.Codec(CompiledInstruction) = .standard(.tuple(.{
            .program_id_index = .fixint,
            .accounts = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
            .data = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
        }));
    };

    const AddressLookup = struct {
        account_key: Pubkey,
        writable_indexes: []u8,
        readonly_indexes: []u8,

        const bk_config: bk.Codec(AddressLookup) = .standard(.tuple(.{
            .account_key = .from(pubkey_codec),
            .writable_indexes = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
            .readonly_indexes = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
        }));
    };

    const LegacyMessage = struct {
        header: MessageHeader,
        account_keys: []Pubkey,
        recent_blockhash: Hash,
        instructions: []CompiledInstruction,

        const bk_config: bk.Codec(LegacyMessage) = .standard(.tuple(.{
            .header = .from(MessageHeader.bk_config),
            .account_keys = .from(shortVec(Pubkey, pubkey_codec)),
            .recent_blockhash = .from(hash_codec),
            .instructions = .from(shortVec(CompiledInstruction, CompiledInstruction.bk_config)),
        }));
    };

    const V0Message = struct {
        header: MessageHeader,
        account_keys: []Pubkey,
        recent_blockhash: Hash,
        instructions: []CompiledInstruction,
        address_table_lookups: []AddressLookup,

        const bk_config: bk.Codec(V0Message) = .standard(.tuple(.{
            .header = .from(MessageHeader.bk_config),
            .account_keys = .from(shortVec(Pubkey, pubkey_codec)),
            .recent_blockhash = .from(hash_codec),
            .instructions = .from(shortVec(CompiledInstruction, CompiledInstruction.bk_config)),
            .address_table_lookups = .from(shortVec(AddressLookup, AddressLookup.bk_config)),
        }));
    };

    const VersionedMessage = union(enum) {
        // first byte & 0x80 == 0
        legacy: LegacyMessage,
        // first byte & 0x80 != 0
        v0: V0Message,

        const bk_config: bk.Codec(VersionedMessage) = .implement(void, void, struct {
            pub fn encode(
                writer: *std.Io.Writer,
                config: bk.Config,
                values: []const VersionedMessage,
                _: ?*[encode_stack_size]u64,
                limit: std.Io.Limit,
                _: void,
            ) bk.EncodeToWriterError!bk.EncodedCounts {
                const max_count = limit.max(values.len);
                var byte_count: usize = 0;
                for (values[0..max_count]) |value| {
                    switch (value) {
                        .legacy => |msg| {
                            // Legacy: no version prefix byte; MessageHeader.num_required_signatures
                            // is the first byte on the wire (written by LegacyMessage codec).
                            const counts = LegacyMessage.bk_config.encodeOnePartialRaw(
                                writer,
                                config,
                                &msg,
                                null,
                                .unlimited,
                                {},
                            ) catch return error.EncodeFailed;
                            byte_count += counts.byte_count;
                        },
                        .v0 => |msg| {
                            // V0: write version prefix byte (0x80 | 0x00 = 0x80), then V0Message.
                            writer.writeByte(0x80) catch return error.EncodeFailed;
                            byte_count += 1;
                            const counts = V0Message.bk_config.encodeOnePartialRaw(
                                writer,
                                config,
                                &msg,
                                null,
                                .unlimited,
                                {},
                            ) catch return error.EncodeFailed;
                            byte_count += counts.byte_count;
                        },
                    }
                }
                return .{ .value_count = max_count, .byte_count = byte_count };
            }

            pub const encode_min_size: usize = 1;
            pub const encode_stack_size: usize = 0;
            pub const decodeInit = null;

            pub fn decode(
                reader: *std.Io.Reader,
                config: bk.Config,
                gpa_opt: ?std.mem.Allocator,
                values: []VersionedMessage,
                decoded_count: *usize,
                _: void,
            ) bk.DecodeFromReaderError!void {
                for (values, 0..) |*value, i| {
                    errdefer decoded_count.* = i;

                    // Peek the first byte to determine version.
                    const first_byte = try reader.takeByte();

                    if (first_byte & 0x80 == 0) {
                        // Legacy message. The byte we just read is num_required_signatures.
                        // We need to "put it back" — reconstruct by reading the remaining
                        // MessageHeader fields (2 more bytes), then the rest of the message.
                        const num_readonly_signed = try reader.takeByte();
                        const num_readonly_unsigned = try reader.takeByte();
                        const header: MessageHeader = .{
                            .num_required_signatures = first_byte,
                            .num_readonly_signed_accounts = num_readonly_signed,
                            .num_readonly_unsigned_accounts = num_readonly_unsigned,
                        };

                        // Decode the remaining fields of LegacyMessage (account_keys, recent_blockhash, instructions)
                        const account_keys_codec = shortVec(Pubkey, pubkey_codec);
                        const account_keys = try account_keys_codec.decode(reader, gpa_opt, config, null);

                        var recent_blockhash: Hash = undefined;
                        try hash_codec.decodeIntoOne(reader, null, config, &recent_blockhash, null);

                        const instructions_codec = shortVec(CompiledInstruction, CompiledInstruction.bk_config);
                        const instructions = try instructions_codec.decode(reader, gpa_opt, config, null);

                        value.* = .{ .legacy = .{
                            .header = header,
                            .account_keys = account_keys,
                            .recent_blockhash = recent_blockhash,
                            .instructions = instructions,
                        } };
                    } else {
                        // Versioned message. The byte was consumed. Check version.
                        const version = first_byte & 0x7F;
                        if (version != 0) {
                            return error.DecodeFailed; // unsupported version
                        }

                        // Decode V0Message
                        const msg = try V0Message.bk_config.decode(reader, gpa_opt, config, null);
                        value.* = .{ .v0 = msg };
                    }
                }
                decoded_count.* = values.len;
            }

            pub fn decodeSkip(
                reader: *std.Io.Reader,
                config: bk.Config,
                value_count: usize,
                decoded_count: *usize,
                _: void,
            ) bk.DecodeSkipError!void {
                for (0..value_count) |i| {
                    errdefer decoded_count.* = i;
                    const first_byte = try reader.takeByte();

                    if (first_byte & 0x80 == 0) {
                        // Legacy: skip remaining 2 header bytes + fields
                        try reader.discardAll(2);
                        // Skip account_keys (shortVec of 32-byte pubkeys)
                        const ak_len = try compact_u16.decode(reader, null, .default, null);
                        try reader.discardAll(ak_len * Pubkey.SIZE);
                        // Skip recent_blockhash
                        try reader.discardAll(Hash.SIZE);
                        // Skip instructions
                        const ix_len = try compact_u16.decode(reader, null, .default, null);
                        try CompiledInstruction.bk_config.decodeSkip(reader, config, ix_len, {});
                    } else {
                        // V0: version byte already consumed. Skip V0Message.
                        try V0Message.bk_config.decodeSkip(reader, config, 1, {});
                    }
                }
                decoded_count.* = value_count;
            }

            pub fn free(
                gpa_opt: ?std.mem.Allocator,
                values: []const VersionedMessage,
                _: void,
            ) void {
                for (values) |value| {
                    switch (value) {
                        .legacy => |msg| LegacyMessage.bk_config.free(gpa_opt, &msg, null),
                        .v0 => |msg| V0Message.bk_config.free(gpa_opt, &msg, null),
                    }
                }
            }
        });
    };

    const VersionedTransaction = struct {
        signatures: []Signature,
        message: VersionedMessage,

        const bk_config: bk.Codec(VersionedTransaction) = .standard(.tuple(.{
            .signatures = .from(shortVec(Signature, Signature.bk_config)),
            .message = .from(VersionedMessage.bk_config),
        }));
    };

    const Entry = struct {
        num_hashes: u64,
        hash: Hash,
        transactions: []VersionedTransaction,

        const bk_config: bk.Codec(Entry) = .standard(.tuple(.{
            .num_hashes = .fixint,
            .hash = .from(hash_codec),
            .transactions = .sliceNonStd(VersionedTransaction.bk_config),
        }));

        // slice of entries
        const slice_config: bk.Codec([]Entry) = .standard(.sliceNonStd(Entry.bk_config));
    };
};
