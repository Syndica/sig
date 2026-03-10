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

// net<->shred.zig

// net -(shred)-> Shred -(shred)-> net

// net_shred_net

// consensus -(rooted_slot)-> runtime

// consensus_runtime

// we can read the bincode directly - no deserialisation/copying required
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
            return self.merkleCount() * Hash.SIZE;
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

    // [firedancer] https://github.com/firedancer-io/firedancer/commit/7cbb71919ec9b8045c247957280e5b15d1e0cb85
    /// Makes sure that the layout of the Shred is valid
    fn fromPacketChecked(packet: *const Packet) !*const Shred {
        if (packet.size < min_header_size) return error.BadSize;

        const packet_shred: *const Shred = @ptrCast(packet);
        if (!packet_shred.variant.isValid()) return error.InvalidVariant;

        const header_size = packet_shred.variant.headerSize();
        if (packet.size < header_size) return error.BadSize;

        const trailer_size: u16 = packet_shred.variant.merkleSize() +
            if (packet_shred.variant.isResigned()) @as(u16, Signature.SIZE) else 0 +
                if (packet_shred.variant.isResigned()) @as(u16, Hash.SIZE) else 0;

        const kind: enum { code, data } = if (packet_shred.variant.isData())
            .data
        else if (packet_shred.variant.isCode())
            .code
        else
            unreachable; // safe: checked variant above

        const zero_padding_size, const payload_size = sizes: switch (kind) {
            .data => {
                const is_legacy = packet_shred.variant.inner & 0xF0 == Variant.legacy_data;
                if (!is_legacy and packet.size < min_size) return error.BadSize;

                const payload_size = packet.size - header_size;

                const effective_size = if (is_legacy) min_size else packet.size;
                if (effective_size < header_size + payload_size + trailer_size) return error.BadSize;

                break :sizes .{
                    effective_size - header_size - payload_size,
                    effective_size,
                };
            },
            .code => {
                const zero_padding_size = 0;
                if (header_size + zero_padding_size + trailer_size > max_size) return error.BadSize;
                break :sizes .{
                    zero_padding_size,
                    max_size - header_size - zero_padding_size - trailer_size,
                };
            },
        };

        if (packet.size < header_size + payload_size + zero_padding_size + trailer_size)
            return error.BadSize;

        switch (kind) {
            // [firedancer] https://github.com/firedancer-io/firedancer/commit/4936f39676997d95e5d15772d3904e5942fa9864
            .data => {
                const parent_offset = packet_shred.code_or_data.data.parent_offset;
                const slot = packet_shred.slot;

                if (packet_shred.code_or_data.data.flags & 0xC0 == 0x80) return error.BadFlags;
                if (parent_offset > slot) return error.BadOffset;

                if ((slot != 0 and parent_offset == 0) or (slot > 1 and parent_offset == slot))
                    return error.BadSlotOrParentOffset;
                if (packet_shred.slot_idx < packet_shred.fec_set_idx) return error.BadSlotIdx;
            },
            .code => {
                const code_header = packet_shred.code_or_data.code;

                if (code_header.code_shred_idx >= code_header.code_count)
                    return error.BadCodeShredIdx;
                if (code_header.code_shred_idx > packet_shred.slot_idx)
                    return error.BadSlotIdx;
                if (code_header.data_count == 0 or code_header.code_count == 0)
                    return error.NoCodeOrDataCount;
                if (code_header.code_count + code_header.data_count > 256)
                    return error.CodeOrDataCountTooLarge;
            },
        }

        return packet_shred;
    }

    fn fromPacketUnchecked(packet: *const Packet) *const Shred {
        return @ptrCast(packet);
    }

    // fn verify(
    //     packet: *const Packet,
    //     leader_schedule: *const common.solana.LeaderSchedule,
    //     verified_merkle_roots: *VerifiedMerkleRoots,
    // ) !void {
    //     const zone = tracy.Zone.init(@src(), .{ .name = "verifyShred" });
    //     defer zone.deinit();

    //     const header: Shred = @ptrCast(packet);

    //     if (verified_merkle_roots.wasVerified(&signed_data)) return;

    //     const leader = leader_schedule.get(slot) orelse return error.LeaderUnknown;

    //     signature.verify(leader, &signed_data.data) catch return error.FailedVerification;

    //     verified_merkle_roots.insert(&signed_data);
    // }
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

const FecSet = struct {
    data_shred_count: u32,
    code_shred_count: u32,

    data_shreds_received: std.StaticBitSet(data_shreds_max),
    code_shreds_received: std.StaticBitSet(code_shreds_max),

    // all packets are pre-validated shreds, i.e. Shred.fromPacketUnchecked is safe
    data_shreds_buf: [data_shreds_max]*?Packet,
    code_shreds_buf: [code_shreds_max]*?Packet,

    // https://github.com/firedancer-io/firedancer/blob/ecd2d6d8f5b9f926d0b9aa9360efe36ea1550ad6/src/ballet/reedsol/fd_reedsol.h#L23
    const data_shreds_max = 67;
    const code_shreds_max = 67;
    const fec_shred_cnt = 32;
};

fn SignatureMap(V: type) type {
    const MapContext = struct {
        pub fn hash(_: @This(), signature: Signature) u32 {
            return @bitCast(signature.r[0..4].*);
        }

        pub fn eql(_: @This(), a: Signature, b: Signature, _: usize) bool {
            return a.eql(&b);
        }
    };

    return std.ArrayHashMapUnmanaged(Signature, V, MapContext, true);
}

const FecSetTracker = struct {
    current: SignatureMap(FecSet),
    finished: SignatureMap(void),

    const empty: FecSetTracker = .{
        .current = .empty,
        .finished = .empty,
    };
};

const FecSetId = struct {
    slot: Slot,
    fec_set_idx: u32,

    fn eql(a: *const FecSetId, b: *const FecSetId) bool {
        return (a.slot == b.slot and a.fec_set_idx == b.fec_set_idx);
    }
};

const FinishedFecSets = std.AutoArrayHashMapUnmanaged(FecSetId, Signature);

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
        hash: if (maybeHashFn) [n]HashedKey else [n]void,
        used: [n]bool,

        const Self = @This();

        const empty: Self = .{
            .keys = @splat(undefined),
            .vals = @splat(undefined),
            .hash = @splat(undefined),
            .used = @splat(false),
        };

        fn get(self: *const Self, key: *const Key) ?*Value {
            const idx = self.getIdx(key) orelse return null;
            return &self.vals[idx];
        }

        fn getIdx(self: *const Self, key: *const Key) ?u32 {
            const hashed = if (maybeHashFn) |hashFn| hashFn(key) else key;

            for (&self.keys, &self.hash, &self.used, 0..) |k, hash, used, i| {
                if (!used) continue;
                if (hashed != hash) continue;
                if (!eql(key, k)) continue;
                return i;
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
            const hashed = if (maybeHashFn) |hashFn| hashFn(key) else key;

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

    const ProgressMap = FixedArrayMap(Signature, FecSet, SignatureHash, hashSignature, Signature.eql, 256);
    const DoneMap = FixedArrayMap(FecSetId, SignatureHash, void, null, FecSetId.eql, 256);
    const VerifiedMerkleRoots = FixedArrayMap(Hash, void, MerkleRootHash, hashMerkleRoot, Hash.eql, 128);

    const SignatureHash = u32;
    const MerkleRootHash = u32;

    fn hashMerkleRoot(a: *const Hash) MerkleRootHash {
        return @bitCast(a.data[0..4]);
    }

    fn hashSignature(a: *const Signature) SignatureHash {
        return @bitCast(a.r[0..2] ++ a.s[0..2]);
    }
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    std.log.info("Waiting for shreds on port {}", .{rw.pair.port});
    _ = ro;

    var verified_roots_fba_buf: [64 * 1024]u8 = undefined;
    var verified_roots_fba: std.heap.FixedBufferAllocator = .init(&verified_roots_fba_buf);
    const roots_allocator = verified_roots_fba.allocator();

    var verified_roots: VerifiedMerkleRoots = try .init(roots_allocator, 128);
    defer verified_roots.deinit(roots_allocator);

    // var current_fec_fba_buf: [64 * 1024]u8 = undefined;
    // var current_fec_fba: std.heap.FixedBufferAllocator = .init(&current_fec_fba_buf);
    // const current_fec_allocator = current_fec_fba.allocator();

    // var current_fec_sets: SignatureMap(FecSet) = .empty;
    // defer current_fec_sets.deinit(current_fec_allocator);

    // var verified_shreds_fba_buf: [64 * 1024]u8 = undefined;
    // var verified_shreds_fba: std.heap.FixedBufferAllocator = .init(&verified_shreds_fba_buf);
    // const verified_shreds_allocator = verified_shreds_fba.allocator();

    // var verified_shreds: std.SegmentedList(shred.Shred, 128) = .{};
    // defer verified_shreds.deinit(verified_shreds_allocator);

    // var verified_shred_packets_fba_buf: [64 * 1024]u8 = undefined;
    // var verified_shred_packets_fba: std.heap.FixedBufferAllocator = .init(&verified_shred_packets_fba_buf);
    // const verified_shred_packets_allocator = verified_shred_packets_fba.allocator();

    // var verified_shred_packets: std.SegmentedList(Packet, 128) = .{};
    // defer verified_shred_packets.deinit(verified_shred_packets_allocator);

    var current_fba_buf: [64 * 1024]u8 = undefined;
    var current_fba: std.heap.FixedBufferAllocator = .init(&current_fba_buf);
    const current_allocator = current_fba.allocator();

    var finished_fba_buf: [64 * 1024]u8 = undefined;
    var finished_fba: std.heap.FixedBufferAllocator = .init(&finished_fba_buf);
    const finished_allocator = finished_fba.allocator();

    // in-progress FEC sets
    var in_progress: SignatureMap(FecSet) = .empty;
    defer in_progress.deinit(current_allocator);

    // finished FEC sets
    var finished: FinishedFecSets = .empty;
    defer in_progress.deinit(finished_allocator);

    // std.autoarra

    while (true) {
        var slice = rw.pair.recv.getReadable() catch continue;

        const zone = tracy.Zone.init(@src(), .{ .name = "shred recv" });
        defer zone.deinit();

        const packet = slice.get(0);
        defer slice.markUsed(1);

        const packet_shred = Shred.fromPacketChecked(packet) catch |err| {
            std.log.info("bad packet, err {}\n", .{err});
            continue; // TODO: report reasons for rejecting/ignoring shreds in all cases
        };

        // ignore shred from a slot that's too old
        if (packet_shred.slot < stub_root_slot) continue;

        // ignore any with wrong version
        if (packet_shred.version != stub_shred_version.load(.monotonic)) continue;

        if (packet_shred.variant.isCode()) {
            // ignore any with bad counts or indices
            if (packet_shred.code_or_data.code.data_count != FecSet.fec_shred_cnt) continue;
            if (packet_shred.code_or_data.code.code_count != FecSet.fec_shred_cnt) continue;
            if (packet_shred.code_or_data.code.code_shred_idx >= FecSet.fec_shred_cnt) continue;
        }
        if (packet_shred.variant.isLegacy()) continue; // ignore legacy

        const maybe_fec_set = in_progress.getPtr(packet_shred.signature);
        if (maybe_fec_set == null) {
            const fec_set_id: FecSetId = .{
                .fec_set_idx = packet_shred.fec_set_idx,
                .slot = packet_shred.slot,
            };

            if (finished.contains(fec_set_id)) continue; // ignore any already finished fec sets
        }

        std.log.info("packet_shred: {}\n", .{packet_shred});

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
