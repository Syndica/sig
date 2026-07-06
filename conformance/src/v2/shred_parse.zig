//! Differential fuzz harness for the v2 shred parse / FEC reassembly
//! pipeline. Implements `sol_compat_shred_parse_v1`: decode a
//! `ShredParseContext` protobuf, feed every shred through the v2 Receiver,
//! collect per-shred parse outcomes and completed FEC sets, run per-slot
//! tick verification and per-transaction structural validation, and emit a
//! `ShredParseEffects` protobuf describing the block-level accept/reject
//! decision plus the parsed FEC sets in chain order.
//!
//! Signature verification is bypassed at compile time via
//! `-Ddebug-skip-shred-sig-verify=true` (set in `conformance/build.zig`) so
//! shreds can carry synthetic merkle roots without a leader keypair.
//! Shred-version mismatch checking stays on.

const std = @import("std");

const pb = @import("proto");
const sig_v2 = @import("sig_v2");

const Allocator = std.mem.Allocator;

const Shred = sig_v2.shred.Shred;
const DeshreddedFecSet = sig_v2.shred.DeshreddedFecSet;
const DeshredRing = sig_v2.shred.DeshredRing;
const FecSetCtx = sig_v2.shred.FecSetCtx;
const Receiver = sig_v2.shred.Receiver;

const Packet = sig_v2.net.Packet;

const Hash = sig_v2.solana.Hash;
const Slot = sig_v2.solana.Slot;
const LeaderSchedule = sig_v2.solana.LeaderSchedule;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const FEC_DATA_SHREDS: u32 = FecSetCtx.data_shreds_max; // 32, SIMD-0317
const FEC_CODING_SHREDS: u32 = FecSetCtx.code_shreds_max; // 32
const TICKS_PER_SLOT: u64 = sig_v2.solana.time.DEFAULT_TICKS_PER_SLOT;
const HASHES_PER_TICK: u64 = 62_500; // mainnet constant

const IN_PROGRESS_CAPACITY: u32 = 64;
const DONE_CAPACITY: u32 = 256;

/// Upper bound on shred.slot accepted by the parse pipeline:
/// `root + max(500, 2 * slots_in_epoch(epoch(root)))` against the default
/// (warmup=true) epoch schedule. Shreds past this bound are "too far in the
/// future" and must be discarded before they reach FEC assembly; the agave
/// reference harness derives the same bound via `ShredFilterContext` against
/// a bank built with `EpochSchedule::default()`
/// (agave/ledger/src/shred/filter.rs).
const MAX_SHRED_DISTANCE_MINIMUM: Slot = 500;
fn maxShredSlot(root: Slot) Slot {
    const schedule = sig_v2.solana.EpochSchedule.INIT;
    const slots_in_epoch = schedule.getSlotsInEpoch(schedule.getEpoch(root));
    const distance = @max(MAX_SHRED_DISTANCE_MINIMUM, 2 *| slots_in_epoch);
    return root +| distance;
}

// ---------------------------------------------------------------------------
// Entrypoint
// ---------------------------------------------------------------------------

pub export fn sol_compat_shred_parse_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    testAndHandleIO(out_ptr, out_size, in_ptr, in_size) catch |e| {
        std.debug.print("shred_parse error: {s}\n", .{@errorName(e)});
        return 0;
    };
    return 1;
}

fn testAndHandleIO(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) !void {
    const allocator = std.heap.c_allocator;

    // zig_protobuf leaks sometimes on invalid input; arena around decode.
    var decode_arena = std.heap.ArenaAllocator.init(allocator);
    defer decode_arena.deinit();

    var in_reader: std.Io.Reader = .fixed(in_ptr[0..in_size]);
    var ctx = try pb.ShredParseContext.decode(&in_reader, decode_arena.allocator());
    defer ctx.deinit(decode_arena.allocator());

    var effects = try executeShredParse(allocator, ctx);
    defer effects.deinit(allocator);

    var writer: std.Io.Writer.Allocating = .init(allocator);
    defer writer.deinit();
    try effects.encode(&writer.writer, allocator);
    const effects_bytes = writer.written();

    const out_slice = out_ptr[0..out_size.*];
    if (effects_bytes.len > out_slice.len) return error.OutputTooSmall;
    @memcpy(out_slice[0..effects_bytes.len], effects_bytes);
    out_size.* = effects_bytes.len;
}

// ---------------------------------------------------------------------------
// Per-fixture accumulators
// ---------------------------------------------------------------------------

/// Per-data-shred scratch for partial-FEC tick verification. Populated from
/// the Receiver's in-progress ctxs only — completed fec sets already carry
/// their entry batches on the ring.
const DataShredCapture = struct {
    slot: Slot,
    slot_idx: u32,
    /// LAST_SHRED_IN_BATCH (a.k.a. data_complete): terminates an entry batch.
    data_complete: bool,
    /// LAST_SHRED_IN_SLOT: terminates the slot. Implies `data_complete`.
    last_shred_in_slot: bool,
    /// Owned copy of `Shred.dataPayload()`. Freed in `resetPerInput`.
    payload: []u8,
};

/// Copy every data shred the Receiver has accepted into this FEC
/// context (received or RS-recovered) into `data_shreds`. Iterates
/// `data_shreds_received` — set bits index the populated entries of
/// `data_shreds_buf`; unset bits are uninitialised memory.
fn captureFromFecSetCtx(
    allocator: Allocator,
    ctx: *const FecSetCtx,
    out: *std.ArrayListUnmanaged(DataShredCapture),
) void {
    var bit_iter = ctx.data_shreds_received.iterator(.{});
    while (bit_iter.next()) |idx| {
        const shred: *const Shred = .fromBufferUnchecked(&ctx.data_shreds_buf[idx]);
        const payload_copy = allocator.dupe(u8, shred.dataPayload()) catch
            @panic("OutOfMemory");
        out.append(allocator, .{
            .slot = shred.slot,
            .slot_idx = shred.slot_idx,
            .data_complete = shred.code_or_data.data.flags.data_complete,
            .last_shred_in_slot = shred.code_or_data.data.flags.last_shred_in_slot,
            .payload = payload_copy,
        }) catch @panic("OutOfMemory");
    }
}

// ---------------------------------------------------------------------------
// Thread-local harness state (heap-allocated; reused across inputs)
// ---------------------------------------------------------------------------

threadlocal var harness_state: ?*HarnessState = null;

const HarnessState = struct {
    allocator: Allocator,
    receiver: Receiver,
    deshred_ring: *DeshredRing,
    leader_schedule: *LeaderSchedule,

    /// Per-shred parse result, in input order.
    shred_parse_results: std.ArrayListUnmanaged(bool) = .empty,
    /// Data shreds captured from still-in-progress FEC ctxs after the wire
    /// loop. Drives per-slot partial-FEC tick verification: agave's blockstore
    /// exposes every inserted shred to `get_slot_entries_with_shred_info`
    /// regardless of FEC completion, so a partial FEC set whose prefix is
    /// DATA_COMPLETE-terminated still gets tick-verified. Completed FEC sets
    /// contribute their whole batch via the ring; only the trailing
    /// in-progress fec set(s) show up here.
    in_progress_shreds: std.ArrayListUnmanaged(DataShredCapture) = .empty,

    fn init(allocator: Allocator) !*HarnessState {
        const self = try allocator.create(HarnessState);
        errdefer allocator.destroy(self);

        const ring = try allocator.create(DeshredRing);
        errdefer allocator.destroy(ring);
        ring.init();

        // ~13.8 MB — heap, not stack.
        const ls = try allocator.create(LeaderSchedule);
        errdefer allocator.destroy(ls);
        ls.base_slot = 0;
        @memset(&ls.leaders, .ZEROES);

        self.* = .{
            .allocator = allocator,
            .receiver = try .init(allocator, IN_PROGRESS_CAPACITY, DONE_CAPACITY),
            .deshred_ring = ring,
            .leader_schedule = ls,
        };
        errdefer self.receiver.deinit(allocator);

        return self;
    }

    /// Drop per-input state, retaining capacity of the accumulators.
    fn resetPerInput(self: *HarnessState) void {
        for (self.in_progress_shreds.items) |it| self.allocator.free(it.payload);
        self.in_progress_shreds.clearRetainingCapacity();
        self.shred_parse_results.clearRetainingCapacity();
    }
};

fn state(allocator: Allocator) !*HarnessState {
    if (harness_state) |st| return st;
    const st = try HarnessState.init(allocator);
    harness_state = st;
    return st;
}

// ---------------------------------------------------------------------------
// Per-input flow
// ---------------------------------------------------------------------------

fn executeShredParse(
    allocator: Allocator,
    ctx: pb.ShredParseContext,
) !pb.ShredParseEffects {
    var st = try state(allocator);

    // Drop all accumulated state from any previous fixture.
    st.deshred_ring.init();
    st.receiver.reset();
    st.resetPerInput();

    st.receiver.updateSlotRange(ctx.root_slot, maxShredSlot(ctx.root_slot));
    st.leader_schedule.base_slot = ctx.root_slot;

    // Map proto bool flags into the Receiver's per-feature activation slot.
    // Agave's `check_feature_activation` uses an epoch-delayed semantic:
    // a feature activated at slot `s` only takes effect for shreds in
    // epoch > epoch(s). Agave's harness uses `EpochSchedule::default()`,
    // which sets `warmup = true`: epoch 0 is only `MINIMUM_SLOTS_PER_EPOCH`
    // (= 32) slots long, and later epochs double in size up to
    // `DEFAULT_SLOTS_PER_EPOCH`. A feature activated at slot 0 therefore
    // first applies at the start of epoch 1, i.e. slot 32. The Receiver's
    // check is a plain `shred.slot >= activation_slot`, so map proto
    // `true` to slot 32 so sig's gate mirrors agave's epoch-aware check.
    // `false` -> disabled (maxInt).
    const MINIMUM_SLOTS_PER_EPOCH: Slot = 32;
    const features = ctx.features orelse pb.ShredFeatures{};
    st.receiver.features = .{
        .discard_unexpected_data_complete_shreds = //
        if (features.discard_unexpected_data_complete_shreds)
            MINIMUM_SLOTS_PER_EPOCH
        else
            std.math.maxInt(Slot),
    };

    // Fresh writer view for this input; the receiver writes completed FEC
    // sets directly through it.
    var deshred_writer = st.deshred_ring.get(.writer);

    for (ctx.shreds.items) |bytes| {
        if (bytes.len > Packet.capacity) {
            // Oversize shreds are rejected at the packet boundary; skip the
            // Receiver entirely.
            st.shred_parse_results.append(allocator, false) catch @panic("OutOfMemory");
            continue;
        }

        var packet: Packet = undefined;
        @memcpy(packet.data[0..bytes.len], bytes);
        // Zero the tail so the merkle / RS code reads deterministic bytes.
        @memset(packet.data[bytes.len..], 0);
        packet.len = @intCast(bytes.len);
        packet.addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);

        try st.shred_parse_results
            .append(allocator, !std.meta.isError(Shred.fromPacketChecked(&packet)));

        // shred_version is u16 on the wire but u32 in the proto schema; truncate.
        // The Receiver writes DeshreddedFecSet's to `deshred_writer` on
        // completion and dismisses its own ctx — we don't need to touch
        // the just-completed ctx at all.
        _ = st.receiver.processPacket(
            st.leader_schedule,
            @truncate(ctx.shred_version),
            &packet,
            &deshred_writer,
            .noop,
        ) catch continue;
    }

    // Snapshot data shreds from every ctx still in-progress after the wire
    // loop. Their ctxs are the ONLY reachable copy of those shreds, and the
    // partial-FEC tick-verify path needs them to walk contiguous slot_idxs
    // past the last completed fec set. (Completed fec sets don't appear
    // here: the Receiver moved them to `done` and destroyed their ctx.)
    for (st.receiver.in_progress.signature_map.values()) |fec_set_ctx| {
        captureFromFecSetCtx(allocator, fec_set_ctx, &st.in_progress_shreds);
    }

    return try buildProtoEffects(
        allocator,
        st.deshred_ring,
        st.in_progress_shreds.items,
        st.shred_parse_results.items,
        ctx.shred_version,
    );
}

// ---------------------------------------------------------------------------
// Chain validation + proto encoding
// ---------------------------------------------------------------------------

fn fecOrder(_: void, a: *const DeshreddedFecSet, b: *const DeshreddedFecSet) bool {
    if (a.id.slot != b.id.slot) return a.id.slot < b.id.slot;
    return a.id.fec_set_idx < b.id.fec_set_idx;
}

fn dataShredOrder(_: void, a: DataShredCapture, b: DataShredCapture) bool {
    if (a.slot != b.slot) return a.slot < b.slot;
    return a.slot_idx < b.slot_idx;
}

fn buildProtoEffects(
    allocator: Allocator,
    deshred_ring: *DeshredRing,
    in_progress_shreds: []DataShredCapture,
    shred_parse_results: []const bool,
    shred_version: u32,
) !pb.ShredParseEffects {
    var out: pb.ShredParseEffects = .{
        .block_parse_result = .ACCEPTED,
        .shred_results = .empty,
        .fec_set_results = .empty,
    };
    errdefer out.deinit(allocator);

    // shred_results: 1:1 copy from the accumulator.
    try out.shred_results.ensureTotalCapacityPrecise(allocator, shred_parse_results.len);
    out.shred_results.appendSliceAssumeCapacity(shred_parse_results);

    // Drain the ring into a pointer array so we can sort by (slot,
    // fec_set_idx). The `DeshreddedFecSet` pointers are stable into the
    // ring's storage until the next `deshred_ring.init()`.
    var fec_sets: std.ArrayListUnmanaged(*const DeshreddedFecSet) = .empty;
    defer fec_sets.deinit(allocator);
    var deshred_reader = deshred_ring.get(.reader);
    while (deshred_reader.next()) |ds| try fec_sets.append(allocator, ds);

    std.sort.heap(*const DeshreddedFecSet, fec_sets.items, {}, fecOrder);
    std.sort.heap(DataShredCapture, in_progress_shreds, {}, dataShredOrder);

    // Cross-FEC chained_merkle_root check (not enforced by the Receiver) +
    // per-slot tick verification, walking fec sets by slot and consuming
    // the matching in-progress shreds for the same slot.
    var fec_i: usize = 0;
    var ds_i: usize = 0;
    while (fec_i < fec_sets.items.len or ds_i < in_progress_shreds.len) {
        // Pick the next slot to process from whichever list has the smaller
        // remaining head.
        const next_fec_slot: Slot = if (fec_i < fec_sets.items.len)
            fec_sets.items[fec_i].id.slot
        else
            std.math.maxInt(Slot);
        const next_ds_slot: Slot = if (ds_i < in_progress_shreds.len)
            in_progress_shreds[ds_i].slot
        else
            std.math.maxInt(Slot);
        const slot = @min(next_fec_slot, next_ds_slot);

        // Slice out this slot's completed fec sets.
        var fec_end = fec_i;
        while (fec_end < fec_sets.items.len and fec_sets.items[fec_end].id.slot == slot)
            fec_end += 1;
        const slot_fec_sets = fec_sets.items[fec_i..fec_end];

        // Slice out this slot's trailing in-progress shreds.
        var ds_end = ds_i;
        while (ds_end < in_progress_shreds.len and in_progress_shreds[ds_end].slot == slot)
            ds_end += 1;
        const slot_trailing = in_progress_shreds[ds_i..ds_end];

        // Chain-validate + emit fec_set_results for this slot.
        var expected_idx: u32 = 0;
        var prev_merkle: ?Hash = null;
        for (slot_fec_sets) |ds| {
            // Gap or out-of-order -> remaining sets in this slot are dropped.
            if (ds.id.fec_set_idx != expected_idx) {
                out.block_parse_result = .REJECTED_INVALID_HEADER;
                break;
            }
            if (prev_merkle) |pm| {
                if (!pm.eql(&ds.chained_merkle_root)) {
                    out.block_parse_result = .REJECTED_INVALID_HEADER;
                    break;
                }
            }

            try out.fec_set_results.append(allocator, .{
                .completed = true,
                .merkle_root = try allocator.dupe(u8, &ds.merkle_root.data),
                .chained_merkle_root = try allocator.dupe(u8, &ds.chained_merkle_root.data),
                .payload = try allocator.dupe(u8, ds.payload_buf[0..ds.payload_len]),
                .slot = ds.id.slot,
                .fec_set_index = ds.id.fec_set_idx,
                .parent_offset = ds.parent_offset,
                .shred_version = shred_version,
                .num_data_shreds = FEC_DATA_SHREDS,
                .num_coding_shreds = FEC_CODING_SHREDS,
            });

            prev_merkle = ds.merkle_root;
            expected_idx += FEC_DATA_SHREDS;
        }

        // Tick verify this slot (fec sets + trailing shreds combined).
        if (out.block_parse_result != .REJECTED_INVALID_HEADER) {
            switch (try verifyTicksForSlot(allocator, slot, slot_fec_sets, slot_trailing)) {
                .ok => {},
                .rejected => out.block_parse_result = .REJECTED_INVALID_HEADER,
            }
        }

        fec_i = fec_end;
        ds_i = ds_end;
    }

    return out;
}

const TickVerifyOutcome = enum { ok, rejected };

/// Per-slot tick verification. Walks the contiguous slot-idx prefix from 0
/// in two phases:
///   1. Completed FEC sets in fec_set_index order — each one contributes
///      one entry batch (per SIMD-0317). If the batch doesn't terminate on
///      `data_complete`, its payload spills into the running batch buffer
///      so the next fec set can close it.
///   2. Trailing in-progress data shreds by slot_idx — per-shred walking,
///      same accumulate-until-data_complete-then-decode rhythm as agave's
///      blockstore.
/// Stops at the first gap. Trailing shreds with slot_idx below the last
/// completed fec set are skipped (they're covered by ring output).
fn verifyTicksForSlot(
    allocator: Allocator,
    slot: Slot,
    completed: []const *const DeshreddedFecSet, // sorted by fec_set_idx
    trailing: []const DataShredCapture, // sorted by slot_idx
) error{OutOfMemory}!TickVerifyOutcome {
    if (completed.len == 0 and trailing.len == 0) return .ok;

    // Per-slot scratch arena. 64 MiB easily covers any one slot.
    const fba_size: usize = 64 * 1024 * 1024;
    const fba_buf = try allocator.alloc(u8, fba_size);
    defer allocator.free(fba_buf);
    var fba = std.heap.FixedBufferAllocator.init(fba_buf);

    // slot_is_full := any surfaced shred (completed or in-progress)
    // carried LAST_SHRED_IN_SLOT.
    var slot_is_full = false;
    for (completed) |ds| slot_is_full = slot_is_full or ds.slot_complete;
    for (trailing) |s| slot_is_full = slot_is_full or s.last_shred_in_slot;

    var all_entries: std.ArrayListUnmanaged(sig_v2.solana.transaction.Entry) = .empty;
    // No deinit: storage is in `fba_buf`, freed via defer above.

    var batch_buf: std.ArrayListUnmanaged(u8) = .empty;
    var expected_slot_idx: u32 = 0;

    // Phase 1: completed fec sets (each = one batch, per SIMD-0317).
    for (completed) |ds| {
        if (ds.id.fec_set_idx != expected_slot_idx) break; // gap
        batch_buf.appendSlice(fba.allocator(), ds.payload_buf[0..ds.payload_len]) catch
            return .rejected;
        if (ds.data_complete) {
            // Zero-byte batch -> zero entries. Bincode would fail to decode
            // the u64 length prefix and incorrectly reject.
            if (batch_buf.items.len != 0) {
                var reader: std.Io.Reader = .fixed(batch_buf.items);
                const entries = sig_v2.solana.bincode.read(
                    &fba,
                    &reader,
                    sig_v2.solana.bincode.Vec(sig_v2.solana.transaction.Entry),
                ) catch return .rejected;
                for (entries.items) |e| {
                    all_entries.append(fba.allocator(), e) catch return .rejected;
                }
            }
            batch_buf = .empty;
        }
        expected_slot_idx += FEC_DATA_SHREDS;
    }

    // Phase 2: trailing in-progress shreds.
    for (trailing) |s| {
        // Shreds already covered by completed fec sets — skip. In-progress
        // ctxs are disjoint from completed ones by fec_set_id so this
        // should generally not occur, but be robust to fixtures that
        // interleave differently.
        if (s.slot_idx < expected_slot_idx) continue;
        if (s.slot_idx != expected_slot_idx) break; // gap
        batch_buf.appendSlice(fba.allocator(), s.payload) catch return .rejected;
        if (s.data_complete) {
            if (batch_buf.items.len != 0) {
                var reader: std.Io.Reader = .fixed(batch_buf.items);
                const entries = sig_v2.solana.bincode.read(
                    &fba,
                    &reader,
                    sig_v2.solana.bincode.Vec(sig_v2.solana.transaction.Entry),
                ) catch return .rejected;
                for (entries.items) |e| {
                    all_entries.append(fba.allocator(), e) catch return .rejected;
                }
            }
            batch_buf = .empty;
        }
        expected_slot_idx += 1;
    }

    // No decoded entries -> skip tick verify (would reject TooFewTicks
    // when slot_is_full).
    if (all_entries.items.len == 0) return .ok;

    if (sig_v2.solana.verify_ticks.verifyTicks(all_entries.items, .{
        .hashes_per_tick = HASHES_PER_TICK,
        .slot = slot,
        .max_tick_height = TICKS_PER_SLOT,
        .tick_height = 0,
        .slot_is_full = slot_is_full,
    })) {
        // tick window verified; fall through to per-tx checks
    } else |_| {
        return .rejected;
    }

    // Per-transaction structural checks (MTU bound, sanitize, account-lock
    // dedup). Any failure rejects the whole block.
    for (all_entries.items) |entry| {
        for (entry.transactions.items) |txn| {
            if (txn.serializedSize() > sig_v2.solana.transaction.VersionedTransaction.MAX_BYTES) {
                return .rejected;
            }
            if (!txn.sanitize()) {
                return .rejected;
            }
            if (!txn.validateAccountLocks()) {
                return .rejected;
            }
        }
    }

    return .ok;
}

// ---------------------------------------------------------------------------
// Self-test
// ---------------------------------------------------------------------------

test {
    // Compile-only; end-to-end behaviour is validated via conformance/run.py.
    std.testing.refAllDecls(@This());
}
