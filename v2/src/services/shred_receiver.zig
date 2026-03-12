//! This service listens on a ringbuffer of packets, and validates, verifies, and deserialises
//! shreds.

const std = @import("std");
const start = @import("start");
const common = @import("common");
const tracy = @import("tracy");

// const shred = common.shred;
// const layout = shred.layout;

const Pair = common.net.Pair;
const Packet = common.net.Packet;
const Slot = common.solana.Slot;
const Hash = common.solana.Hash;
const Signature = common.solana.Signature;
const Atomic = std.atomic.Value;

comptime {
    _ = start;
}

pub const name = .shred_receiver;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    pair: *Pair,
};

pub const ReadOnly = struct {
    leader_schedule: *const common.solana.LeaderSchedule,
};

// stubs
const stub_root_slot = 0;
const stub_shred_version: Atomic(u16) = .{ .raw = 29062 }; // TODO: port over getShredAndIPFromEchoServer
const stub_max_slot = std.math.maxInt(Slot); // TODO agave uses BankForks for this

// we can read the bincode directly - no deserialisation/copying required
// Methods taking `self: *const Shred` assume that self is pointing to a Packet
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
        fn isValid(self: Variant) bool {
            const variant = self.inner;

            return switch (variant & 0xF0) {
                // test upper 4 bits
                merkle_data,
                merkle_code,
                merkle_data_chained,
                merkle_code_chained,
                merkle_data_chained_resigned,
                merkle_code_chained_resigned,
                => true,

                else => switch (variant) {
                    // legacy_data, legacy_code, with the correct (static) lower 4 bits
                    0xA5, 0x5A => true,
                    else => false,
                },
            };
        }

        fn headerSize(self: Variant) usize {
            const shared_base = @offsetOf(Shred, "code_or_data");

            return switch (self.inner & 0xF0) {
                legacy_data,
                merkle_data,
                merkle_data_chained,
                merkle_data_chained_resigned,
                => shared_base + @sizeOf(DataHeader),

                legacy_code,
                merkle_code,
                merkle_code_chained,
                merkle_code_chained_resigned,
                => shared_base + @sizeOf(CodeHeader),

                else => 0,
            };
        }

        fn merkleCount(self: Variant) u8 {
            return switch (self.inner & 0xF0) {
                legacy_data, legacy_code => 0,
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
                legacy_data,
                merkle_data,
                merkle_data_chained,
                merkle_data_chained_resigned,
                => true,
                else => false,
            };
        }

        fn isCode(self: Variant) bool {
            return switch (self.inner & 0xF0) {
                legacy_code,
                merkle_code,
                merkle_code_chained,
                merkle_code_chained_resigned,
                => true,
                else => false,
            };
        }

        fn isLegacy(self: Variant) bool {
            return switch (self.inner & 0xF0) {
                legacy_code, legacy_data => true,
                else => false,
            };
        }

        fn isMerkle(self: Variant) bool {
            return switch (self.inner & 0xF0) {
                merkle_data,
                merkle_code,
                merkle_data_chained,
                merkle_code_chained,
                merkle_data_chained_resigned,
                merkle_code_chained_resigned,
                => true,
                else => false,
            };
        }

        // upper 4 bits
        const legacy_data = 0xA0;
        const legacy_code = 0x50;
        const merkle_data = 0x80;
        const merkle_code = 0x40;
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
    /// Makes sure that the layout of the Shred is valid.
    fn fromPacketChecked(packet: *const Packet) !*const Shred {
        if (packet.size < min_header_size) return error.PacketUnderMinHeaderSize;

        const shred: *const Shred = @ptrCast(packet);
        if (!shred.variant.isValid()) return error.InvalidVariant;

        const header_size = shred.variant.headerSize();
        if (packet.size < header_size) return error.PacketUnderHeaderSize;

        const trailer_size: u16 = shred.variant.merkleSize() +
            (if (shred.variant.isResigned()) @as(u16, Signature.SIZE) else 0) +
            (if (shred.variant.isChained()) @as(u16, Hash.SIZE) else 0);

        const kind: enum { code, data } = if (shred.variant.isData())
            .data
        else if (shred.variant.isCode())
            .code
        else
            unreachable; // safe: checked variant above

        const zero_padding_size, const payload_size = sizes: switch (kind) {
            .data => {
                if (shred.code_or_data.data.size < header_size) return error.DataSmallerThanHeader;

                const is_legacy = shred.variant.isLegacy();
                if (!is_legacy and packet.size < min_size) return error.DataPacketUnderMinSize;

                const payload_size = shred.code_or_data.data.size - header_size;

                const effective_size = if (is_legacy) packet.size else min_size;
                if (effective_size < header_size + payload_size + trailer_size) return error.DataEffectiveSizeTooSmall;

                break :sizes .{
                    effective_size - header_size - payload_size - trailer_size,
                    payload_size,
                };
            },
            .code => {
                const zero_padding_size = 0;
                if (header_size + zero_padding_size + trailer_size > max_size) return error.CodeShredOverMaxSize;
                break :sizes .{
                    zero_padding_size,
                    max_size - header_size - zero_padding_size - trailer_size,
                };
            },
        };

        if (packet.size < header_size + payload_size + zero_padding_size + trailer_size)
            return error.PacketSizeUnderExpected3;

        switch (kind) {
            // [firedancer] https://github.com/firedancer-io/firedancer/commit/4936f39676997d95e5d15772d3904e5942fa9864
            .data => {
                const parent_offset = shred.code_or_data.data.parent_offset;
                const slot = shred.slot;

                if ((shred.code_or_data.data.flags & 0xC0) == 0x80) return error.BadFlags;
                if (parent_offset > slot) return error.BadOffset;

                if ((slot != 0 and parent_offset == 0) or (slot > 1 and parent_offset == slot))
                    return error.BadSlotOrParentOffset;
                if (shred.slot_idx < shred.fec_set_idx) return error.BadSlotIdx;
            },
            .code => {
                const code_header = shred.code_or_data.code;

                if (code_header.code_shred_idx >= code_header.code_count)
                    return error.BadCodeShredIdx;
                if (code_header.code_shred_idx > shred.slot_idx)
                    return error.BadSlotIdx;
                if (code_header.data_count == 0 or code_header.code_count == 0)
                    return error.NoCodeOrDataCount;
                if (code_header.code_count + code_header.data_count > 256)
                    return error.CodeOrDataCountTooLarge;
            },
        }

        return shred;
    }

    fn fromPacketUnchecked(packet: *const Packet) *const Shred {
        return @ptrCast(packet);
    }

    // This is combined with fragments from other shreds in the erasure set to
    // reconstruct a collection of entries.
    fn erasureFragment(shred: *const Shred) []const u8 {
        _ = shred;
    }

    // This is the Merkle root for the previous erasure set.
    fn chainedMerkleRoot(shred: *const Shred) *const [32]u8 {
        _ = shred;
    }

    // fn capacity(packet: *const Packet) u16 {
    //     const shred = fromPacketUnchecked(packet);
    //     // NOTE: ported this check from v1, isn't this a tautology?
    //     std.debug.assert(shred.variant.isChained() or !shred.variant.isResigned() );

    //     return shred.

    // // return std.math.sub(
    // //     usize,
    // //     constants.payload_size,
    // //     constants.headers_size +
    // //         (if (variant.chained) SIZE_OF_MERKLE_ROOT else 0) +
    // //         variant.proof_size * merkle_proof_entry_size +
    // //         (if (variant.resigned) Signature.SIZE else 0),
    // // ) catch error.InvalidProofSize;
    //     _ = shred;
    // }

    fn size(shred: *const Shred) u16 {
        const packet: *const Packet = @ptrCast(@alignCast(shred));

        return if (shred.variant.isCode())
            max_size
        else if (shred.variant.isLegacy() and shred.variant.isData())
            packet.size
        else
            min_size;
    }

    const MerkleProofNode = extern struct { data: [merkle_node_size]u8 };

    fn merkleProofNodes(shred: *const Shred) []const MerkleProofNode {
        const packet: *const Packet = @ptrCast(@alignCast(shred));

        // The offset of the merkle inclusion proof
        const merkle_offset = shred.size() -
            shred.variant.merkleSize() -
            if (shred.variant.isResigned()) Signature.SIZE else 0;

        const merkle_proof_ptr: [*]const MerkleProofNode =
            @ptrCast(packet.data[0..].ptr + merkle_offset);

        return merkle_proof_ptr[0..shred.variant.merkleCount()];
    }

    // The bytes which are checked against the merkle root.
    // includes: header (excluding signature) + code/data payload + chained root + maybe padding
    // does not include: retransmit signature + proof nodes
    // [firedancer] https://github.com/firedancer-io/firedancer/blob/9f7770af997a1443e7903113fc03ca1ce3b0ad73/src/ballet/shred/fd_shred.c#L109
    fn merkleProtected(shred: *const Shred) []const u8 {
        const erasure_protected_size = 1115 + @sizeOf(DataHeader) -
            Signature.SIZE -
            merkle_node_size * shred.variant.merkleCount() -
            @intFromBool(shred.variant.isChained()) * @as(usize, merkle_root_size) -
            @intFromBool(shred.variant.isResigned()) * Signature.SIZE;

        const data_merkle_protected_size = erasure_protected_size +
            @as(usize, merkle_root_size) * @intFromBool(shred.variant.isChained());

        const code_merkle_protected_size = erasure_protected_size +
            @as(usize, merkle_root_size) * @intFromBool(shred.variant.isChained()) +
            @sizeOf(CodeHeader) -
            Signature.SIZE;

        const merkle_protected_size = if (shred.variant.isData())
            data_merkle_protected_size
        else
            code_merkle_protected_size;

        return @as(*const Packet, @ptrCast(@alignCast(shred))).data[Signature.SIZE..merkle_protected_size];
    }

    // Added by the node who retransmitted the shred to us over Turbine.
    // This is only used for the shreds in the final erasure set of the slot.
    // Only safe on pre-checked packets.
    fn retransmitterSignature(packet: *const Packet) ?[]const u8 {
        const shred = fromPacketUnchecked(packet);
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

    fn joinNodes(out: *Hash, lhs: []const u8, rhs: []const u8) void {
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
                0 => joinNodes(out, &out.data, &node.data),
                1 => joinNodes(out, &node.data, &out.data),
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

const FecSetCtx = extern struct {
    data_shred_count: u32,
    code_shred_count: u32,

    data_shreds_received: std.StaticBitSet(data_shreds_max),
    code_shreds_received: std.StaticBitSet(code_shreds_max),

    // all packets are pre-validated shreds, i.e. Shred.fromPacketUnchecked is safe
    data_shreds_buf: [data_shreds_max]*?Packet,
    code_shreds_buf: [code_shreds_max]*?Packet,

    // https://github.com/firedancer-io/firedancer/blob/ecd2d6d8f5b9f926d0b9aa9360efe36ea1550ad6/src/ballet/reedsol/fd_reedsol.h#L23
    // https://github.com/solana-foundation/specs/blob/main/p2p/shred.md
    const data_shreds_max = 67;
    const code_shreds_max = 67;
    const fec_shred_cnt = 32;
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

const FinishedFecSets = std.AutoArrayHashMapUnmanaged(FecSetId, Signature);

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
            .context = .{ .ids = self.ids, .used = self.used },
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

    fn containsFecSetId(self: *const ProgressMap, id: *const FecSetId) bool {
        for (self.ids, self.used) |found_id, used| {
            if (!used) continue;
            if (found_id.eql(id)) return true;
        }
        return false;
    }

    fn peekEviction(self: *const ProgressMap) ?Idx {
        return self.eviction_queue.peek();
    }

    fn evict(self: *ProgressMap) bool {
        const evict_idx = self.eviction_queue.removeOrNull() orelse return false;

        self.used[evict_idx] = false;

        self.signatures[evict_idx] = undefined;
        self.sig_hashes[evict_idx] = undefined;
        self.ids[evict_idx] = undefined;
        self.contexts[evict_idx] = undefined;

        return true;
    }

    const QueueContext = struct {
        ids: *const [n]FecSetCtx,
        used: *const [n]bool,

        fn compare(self: QueueContext, a: Idx, b: Idx) std.math.Order {
            std.debug.assert(self.used[a] and self.used[b]);

            FecSetId.compare(&self.ids[a], &self.ids[b]);
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
                if (!used) continue;
                return i;
            }
            return null;
        }

        fn getOrInsert(self: *Self, key: *const Key, or_insert: *const Value) !void {
            if (self.getIdx(key)) |get_idx| return &self.vals[get_idx];

            const insert_idx = self.getIdxUnused() orelse return error.MapFull;
            const hashed = if (maybeHashFn) |hashFn| hashFn(key) else key;

            self.hash[insert_idx] = hashed;
            self.vals[insert_idx] = or_insert.*;
        }

        fn insertRemovingFirst(self: *Self, key: *const Key, insert: *const Value) void {
            const hashed = if (maybeHashFn) |hashFn| hashFn(key) else {};

            const target_idx = if (self.getIdxUnused()) |unused_idx| unused_idx else idx: {
                @branchHint(.likely);
                @memmove(self.keys[0 .. n - 2], self.keys[1 .. n - 1]);
                @memmove(self.vals[0 .. n - 2], self.vals[1 .. n - 1]);
                @memmove(self.hash[0 .. n - 2], self.hash[1 .. n - 1]);
                break :idx n - 1;
            };

            self.keys[target_idx] = key;
            self.vals[target_idx] = insert;
            self.hash[target_idx] = hashed;
        }

        fn containsValue(self: *const Self, value: *const Value) bool {
            for (&self.vals) |*val| if (val.eql(value)) return true;
            return false;
        }
    };
}

const State = struct {
    in_progress: ProgressMap,
    done: DoneMap,
    verified_merkle_roots: VerifiedMerkleRoots,

    const empty: State = .{
        .in_progress = .empty,
        .done = .empty,
        .verified_merkle_roots = .empty,
    };

    // const ProgressMap = FixedArrayMap(Signature, FecSetCtx, SignatureHash, hashSignature, Signature.eql, 256);
    const DoneMap = FixedArrayMap(FecSetId, SignatureHash, void, null, FecSetId.eql, 256);
    const VerifiedMerkleRoots = FixedArrayMap(Hash, void, MerkleRootHash, hashMerkleRoot, Hash.eql, 128);

    const SignatureHash = u32;
    const MerkleRootHash = u32;

    fn hashMerkleRoot(a: *const Hash) MerkleRootHash {
        return @bitCast(a.data[0..4]);
    }

    fn hashSignature(a: *const Signature) SignatureHash {
        return @bitCast((a.r[0..2] ++ a.s[0..2]).*);
    }
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    std.log.info("Waiting for shreds on port {}", .{rw.pair.port});
    _ = ro;

    var state: State = .empty;

    while (true) {
        var slice = rw.pair.recv.getReadable() catch continue;

        const zone = tracy.Zone.init(@src(), .{ .name = "shred recv" });
        defer zone.deinit();

        const packet = slice.get(0);
        defer slice.markUsed(1);

        const shred = Shred.fromPacketChecked(packet) catch |err| {
            std.log.info("bad packet, err {}\n", .{err});
            continue; // TODO: report reasons for rejecting/ignoring shreds in all cases
        };

        // ignore shred from a slot that's too old
        if (shred.slot < stub_root_slot) continue;

        // ignore any with wrong version
        if (shred.version != stub_shred_version.load(.monotonic)) continue;

        if (shred.variant.isCode()) {
            // ignore any with bad counts or indices
            if (shred.code_or_data.code.data_count != FecSetCtx.fec_shred_cnt) continue;
            if (shred.code_or_data.code.code_count != FecSetCtx.fec_shred_cnt) continue;
            if (shred.code_or_data.code.code_shred_idx >= FecSetCtx.fec_shred_cnt) continue;
        }
        if (shred.variant.isLegacy()) continue; // ignore legacy

        // is fec set already being built?
        const maybe_fec_set = state.in_progress.getFecSetCtx(&shred.signature);
        if (maybe_fec_set == null) {
            const fec_set_id: FecSetId = .{
                .fec_set_idx = shred.fec_set_idx,
                .slot = shred.slot,
            };

            // ignore shreds from already finished fec sets
            if (state.done.get(&fec_set_id)) |finished_set| {
                const signature_hash = State.hashSignature(&shred.signature);
                if (signature_hash == finished_set.*) {
                    // likely equivocation
                    continue;
                } else {
                    continue;
                }
            }

            // if we have this FecSetId with a different signature, this means equivocation
            if (state.in_progress.containsFecSetId(&fec_set_id)) continue;
        }

        // at

        std.log.info("packet_shred: {}\n", .{shred});

        const in_type_idx = if (shred.variant.isData())
            shred.slot_idx - shred.fec_set_idx
        else
            shred.code_or_data.code.code_shred_idx;

        const shred_idx = if (shred.variant.isData())
            in_type_idx
        else
            in_type_idx + shred.code_or_data.code.data_count;

        if (shred.fec_set_idx % FecSetCtx.fec_shred_cnt != 0) continue;
        if (in_type_idx >= FecSetCtx.fec_shred_cnt) continue;

        if (shred.variant.isData()) {
            const slot_complete = 0x80; // hm
            if ((shred.code_or_data.data.flags & slot_complete != 0) and (((shred.slot_idx + 1) % FecSetCtx.fec_shred_cnt) != 0))
                continue;
        }

        const merkle_layer_count = 7;
        if (shred.variant.merkleCount() > merkle_layer_count - 1) continue;

        var root: Hash = undefined;
        try shred.merkleRoot(&root);

        // const merkle_tree = shred.variant.merkleCount()

        // const reedsol

        // // packet.size

        // _ = Shred.fromPacketChecked(packet) orelse continue;

        // validateShred(packet, stub_root_slot, &stub_shred_version, stub_max_slot) catch |err| {
        //     std.log.info("invalid shred: {}", .{err});
        //     continue;
        // };

        // verifyShred(packet, ro.leader_schedule, &verified_roots) catch |err| {
        //     _ = err catch {};
        //     std.log.info("failed to verify shred: {}", .{err});
        //     continue;
        // };

        // // TODO: this is where we might retransmit

        // const payload = layout.getShred(packet, false) orelse {
        //     std.log.info("failed to get shred", .{});
        //     continue;
        // };

        // const packet_shred = shred.Shred.fromPayload(payload) catch |err| {
        //     std.log.info(
        //         "failed to deserialize verified shred {?}.{?}: {}",
        //         .{ layout.getSlot(payload), layout.getIndex(payload), err },
        //     );
        //     continue;
        // };

        // // try verified_shred_packets.append(verified_shred_packets_allocator, packet.*);
        // // var verifed_shred = packet_shred;
        // // switch (verifed_shred) {
        // //     inline else => |*code_or_data_shred| {
        // //         code_or_data_shred.payload = @ptrCast(verified_shred_packets.at(verified_shred_packets.len - 1));
        // //     },
        // // }

        // // try verified_shreds.append(verified_shreds_allocator, verifed_shred);

        // const verified_shred_header: *align(1) const Shred = @ptrCast(packet);
        // std.log.info("verified_shred_header.fec_set_idx: {}\n", .{verified_shred_header.fec_set_idx});

        // std.log.info(
        //     \\slot: {}
        //     \\erasure_set_index: {}
        //     \\index: {}
        //     \\shred_type: {}
        //     \\
        // , .{
        //     packet_shred.commonHeader().slot,
        //     packet_shred.commonHeader().erasure_set_index,
        //     packet_shred.commonHeader().index,
        //     packet_shred.commonHeader().variant.shred_type,
        // });
    }
}

// /// A set of Merkle Roots which we have already verified (and therefore don't have to verify again).
// /// Keeps up to `max_count` Merkle Roots. When full, removes the least recently inserted.
// const VerifiedMerkleRoots = struct {
//     map: Map,
//     max_count: u32,

//     const Map = std.ArrayHashMapUnmanaged(Hash, void, MapContext, true);

//     const MapContext = struct {
//         pub fn hash(_: MapContext, merkle_root: Hash) u32 {
//             return @bitCast(merkle_root.data[0..4].*);
//         }

//         pub fn eql(_: MapContext, a: Hash, b: Hash, _: usize) bool {
//             return a.eql(&b);
//         }
//     };

//     fn init(allocator: std.mem.Allocator, max_count: u32) !VerifiedMerkleRoots {
//         var map: Map = .{};
//         errdefer map.deinit(allocator);

//         try map.ensureTotalCapacity(allocator, max_count);

//         return .{ .map = map, .max_count = max_count };
//     }

//     fn deinit(self: *VerifiedMerkleRoots, allocator: std.mem.Allocator) void {
//         self.map.deinit(allocator);
//     }

//     fn wasVerified(self: *VerifiedMerkleRoots, hash: *const Hash) bool {
//         return self.map.contains(hash.*);
//     }

//     fn insert(self: *VerifiedMerkleRoots, hash: *const Hash) void {
//         if (self.map.count() == self.max_count) self.map.orderedRemoveAt(0);
//         self.map.putAssumeCapacityNoClobber(hash.*, {});
//     }
// };

// fn validateShred(
//     packet: *const Packet,
//     root: Slot,
//     shred_version: *const Atomic(u16),
//     max_slot: Slot,
// ) ShredValidationError!void {
//     const packet_shred = layout.getShred(packet, false) orelse return error.InsufficientShredSize;
//     const version = layout.getVersion(packet_shred) orelse return error.MissingVersion;
//     const slot = layout.getSlot(packet_shred) orelse return error.SlotMissing;
//     const index = layout.getIndex(packet_shred) orelse return error.IndexMissing;
//     const variant = layout.getShredVariant(packet_shred) orelse return error.VariantMissing;

//     if (version != shred_version.load(.acquire)) return error.WrongVersion;
//     if (slot > max_slot) return error.SlotTooNew;
//     switch (variant.shred_type) {
//         .code => {
//             if (index >= shred.CodeShred.constants.max_per_slot) {
//                 return error.CodeIndexTooHigh;
//             }
//             if (slot <= root) return error.RootedSlot;
//         },
//         .data => {
//             if (index >= shred.DataShred.constants.max_per_slot) {
//                 return error.DataIndexTooHigh;
//             }
//             const parent_slot_offset = layout.getParentSlotOffset(packet_shred) orelse {
//                 return error.ParentSlotOffsetMissing;
//             };
//             const parent = slot -| @as(Slot, @intCast(parent_slot_offset));
//             if (!verifyShredSlots(slot, parent, root)) return error.SlotVerificationFailed;
//         },
//     }

//     // TODO: check for feature activation of enable_chained_merkle_shreds
//     // 7uZBkJXJ1HkuP6R3MJfZs7mLwymBcDbKdqbF51ZWLier
//     // https://github.com/solana-labs/solana/pull/34916
//     // https://github.com/solana-labs/solana/pull/35076
// }

// fn verifyShredSlots(slot: Slot, parent: Slot, root: Slot) bool {
//     if (slot == 0 and parent == 0 and root == 0) {
//         return true; // valid write to slot zero.
//     }
//     // Ignore shreds that chain to slots before the root,
//     // or have invalid parent >= slot.
//     return root <= parent and parent < slot;
// }

// /// Analogous to [verify_shred_cpu](https://github.com/anza-xyz/agave/blob/83e7d84bcc4cf438905d07279bc07e012a49afd9/ledger/src/sigverify_shreds.rs#L35)
// pub fn verifyShred(
//     packet: *const Packet,
//     leader_schedule: *const common.solana.LeaderSchedule,
//     verified_merkle_roots: *VerifiedMerkleRoots,
// ) ShredVerificationFailure!void {
//     const zone = tracy.Zone.init(@src(), .{ .name = "verifyShred" });
//     defer zone.deinit();

//     const shred_ = layout.getShred(packet, false) orelse return error.InsufficientShredSize;
//     const slot = layout.getSlot(shred_) orelse return error.SlotMissing;
//     const signature = layout.getLeaderSignature(shred_) orelse return error.SignatureMissing;
//     const signed_data = layout.merkleRoot(shred_) orelse return error.SignedDataMissing;

//     if (verified_merkle_roots.wasVerified(&signed_data)) return;

//     const leader = leader_schedule.get(slot) orelse return error.LeaderUnknown;

//     signature.verify(leader, &signed_data.data) catch return error.FailedVerification;

//     verified_merkle_roots.insert(&signed_data);
// }

pub const ShredVerificationFailure = error{
    InsufficientShredSize,
    SlotMissing,
    SignatureMissing,
    SignedDataMissing,
    LeaderUnknown,
    FailedVerification,
    FailedCaching,
};

/// Something about the shred was unexpected, so we will discard it.
pub const ShredValidationError = error{
    InsufficientShredSize,
    MissingVersion,
    SlotMissing,
    IndexMissing,
    VariantMissing,
    WrongVersion,
    SlotTooNew,
    CodeIndexTooHigh,
    RootedSlot,
    DataIndexTooHigh,
    ParentSlotOffsetMissing,
    SlotVerificationFailed,
    SignatureMissing,
    SignedDataMissing,
};
