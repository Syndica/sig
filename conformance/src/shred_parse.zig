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
//!
//! The Receiver exposes no per-shred / per-completion callback interface,
//! so the harness synthesises those signals from its return value and by
//! peeking `receiver.in_progress` between calls. RS-recovered data shreds
//! whose ctx is destroyed inside `processPacket` are not captured; the
//! tick-verify path therefore sees only on-wire data shreds, which is a
//! known fidelity gap versus agave's blockstore-driven reconstruction.

const std = @import("std");

const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig_v2 = @import("sig_v2");

const Allocator = std.mem.Allocator;

const Shred = sig_v2.shred.Shred;
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

const FEC_DATA_SHREDS: u32 = FecSetCtx.fec_shred_count; // 32, SIMD-0317
const FEC_CODING_SHREDS: u32 = FecSetCtx.fec_shred_count; // 32
const TICKS_PER_SLOT: u64 = sig_v2.solana.time.DEFAULT_TICKS_PER_SLOT;
const HASHES_PER_TICK: u64 = 62_500; // mainnet constant

const IN_PROGRESS_CAPACITY: u32 = 64;
const DONE_CAPACITY: u32 = 256;

/// Upper bound on shred.slot: `root + max(500, slots_in_epoch(epoch(root)) / 2)`
/// against the default (warmup=true) epoch schedule.
/// [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-rc.1/ledger/src/shred/filter.rs#L405-L414
const MAX_SHRED_DISTANCE_MINIMUM: Slot = 500;
fn maxShredSlot(root: Slot) Slot {
    const schedule = sig_v2.solana.EpochSchedule.INIT;
    const slots_in_epoch = schedule.getSlotsInEpoch(schedule.getEpoch(root));
    const distance = @max(MAX_SHRED_DISTANCE_MINIMUM, slots_in_epoch / 2);
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
// Per-input capture buffers
// ---------------------------------------------------------------------------

/// Per-data-shred scratch for partial-FEC tick verification.
const DataShredCapture = struct {
    slot: Slot,
    fec_set_idx: u32,
    slot_idx: u32,
    parent_offset: u16,
    /// LAST_SHRED_IN_BATCH (a.k.a. data_complete): terminates an entry
    /// batch — the bytes from index `prev_batch_end .. slot_idx`
    /// inclusive bincode-decode as one `Vec<Entry>`.
    data_complete: bool,
    /// LAST_SHRED_IN_SLOT: terminates the slot. Implies `data_complete`.
    last_shred_in_slot: bool,
    /// Owned copy of `Shred.dataPayload()`. Freed in `reset` / `deinit`.
    payload: []u8,
};

/// Per-FEC-set scratch before slot-wide sort + chain validation.
const FECSetParseResult = struct {
    merkle_root: Hash,
    chained_merkle_root: Hash,
    /// Full concatenation of every data shred's data region across all 32
    /// slots (mirrors agave's fixture, not sig's ring which truncates at
    /// the first data_complete). Populated from `DataShredCapture` entries
    /// matching `(slot, fec_set_idx)` at proto-encode time.
    payload: []const u8,
    slot: Slot,
    fec_set_index: u32,
    parent_offset: u16,
    num_data_shreds: u32,
    num_coding_shreds: u32,
    /// LAST_SHRED_IN_BATCH (a.k.a. data_complete) was set on the final
    /// data shred of this FEC set, terminating an entry batch.
    data_complete: bool,
    /// LAST_SHRED_IN_SLOT was set on the final data shred of this FEC set,
    /// terminating the slot. Implies `data_complete`.
    slot_complete: bool,
};

/// Composite key for the "already captured" set.
const ShredKey = struct { slot: Slot, slot_idx: u32 };

// ---------------------------------------------------------------------------
// Thread-local harness state (heap-allocated; reused across inputs)
// ---------------------------------------------------------------------------

threadlocal var harness_state: ?*HarnessState = null;

const HarnessState = struct {
    allocator: Allocator,
    receiver: Receiver,
    deshred_ring: *DeshredRing,
    deshred_writer: DeshredRing.Iterator(.writer),
    /// Reader iterator kept alive across `processPacket` calls so successive
    /// completions are drained incrementally.
    deshred_reader: DeshredRing.Iterator(.reader),
    leader_schedule: *LeaderSchedule,

    // Per-input accumulators. Reset in executeShredParse; storage capacity
    // is retained.
    shred_parse_results: std.ArrayListUnmanaged(bool) = .empty,
    fec_set_results: std.ArrayListUnmanaged(FECSetParseResult) = .empty,
    data_shreds: std.ArrayListUnmanaged(DataShredCapture) = .empty,
    /// Dedup set for `data_shreds`; a shred can appear in `in_progress`
    /// across multiple processPacket calls, so we key on (slot, slot_idx).
    seen_data_shreds: std.AutoHashMapUnmanaged(ShredKey, void) = .empty,

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

        const receiver = try Receiver.init(allocator, IN_PROGRESS_CAPACITY, DONE_CAPACITY);

        self.* = .{
            .allocator = allocator,
            .receiver = receiver,
            .deshred_ring = ring,
            .deshred_writer = ring.get(.writer),
            .deshred_reader = ring.get(.reader),
            .leader_schedule = ls,
        };
        return self;
    }

    fn resetPerInput(self: *HarnessState) void {
        self.deshred_ring.init();
        self.receiver.reset();
        self.deshred_writer = self.deshred_ring.get(.writer);
        self.deshred_reader = self.deshred_ring.get(.reader);

        for (self.fec_set_results.items) |it| self.allocator.free(it.payload);
        self.fec_set_results.clearRetainingCapacity();
        for (self.data_shreds.items) |it| self.allocator.free(it.payload);
        self.data_shreds.clearRetainingCapacity();
        self.shred_parse_results.clearRetainingCapacity();
        self.seen_data_shreds.clearRetainingCapacity();
    }

    /// Snapshot a data shred into `data_shreds` if we haven't already.
    /// Called from the per-packet flow after Receiver accepts the shred,
    /// so we capture the completing shred even when its ctx is destroyed
    /// inside `processPacket`.
    fn captureShredIfNew(self: *HarnessState, shred: *const Shred) void {
        const key: ShredKey = .{ .slot = shred.slot, .slot_idx = shred.slot_idx };
        const gop = self.seen_data_shreds.getOrPut(self.allocator, key) catch
            @panic("OutOfMemory");
        if (gop.found_existing) return;

        const payload_copy = self.allocator.dupe(u8, shred.dataPayload()) catch
            @panic("OutOfMemory");
        self.data_shreds.append(self.allocator, .{
            .slot = shred.slot,
            .fec_set_idx = shred.fec_set_idx,
            .slot_idx = shred.slot_idx,
            .parent_offset = shred.code_or_data.data.parent_offset,
            .data_complete = shred.code_or_data.data.flags.data_complete,
            .last_shred_in_slot = shred.code_or_data.data.flags.last_shred_in_slot,
            .payload = payload_copy,
        }) catch @panic("OutOfMemory");
    }

    /// Drain any completions the Receiver just wrote to the deshred ring
    /// and turn each into a scratch `FECSetParseResult`. The ring provides
    /// merkle roots, FEC-set id and the batch/slot flags; per-shred data
    /// (payload concat, parent_offset) is filled in later from
    /// `data_shreds` because RS-recovered shreds aren't in our capture map.
    fn drainCompletions(self: *HarnessState) void {
        while (self.deshred_reader.next()) |completed| {
            self.fec_set_results.append(self.allocator, .{
                .merkle_root = completed.merkle_root,
                .chained_merkle_root = completed.chained_merkle_root,
                .payload = &.{}, // filled at proto-encode
                .slot = completed.id.slot,
                .fec_set_index = completed.id.fec_set_idx,
                .parent_offset = 0, // filled at proto-encode
                .num_data_shreds = FEC_DATA_SHREDS,
                .num_coding_shreds = FEC_CODING_SHREDS,
                .data_complete = completed.data_complete,
                .slot_complete = completed.slot_complete,
            }) catch @panic("OutOfMemory");
        }
        self.deshred_reader.markUsed();
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

    for (ctx.shreds.items) |bytes| {
        // Parse verdict: `shred_results[i] = Shred::fromPacketChecked().ok()`,
        // matching agave's `new_from_serialized_shred().ok() && chained().ok()`
        // (every variant plain Receiver accepts is chained-merkle, so the
        // parse succeeding implies the chained check). Emitted regardless
        // of what processPacket does with the shred.
        var parses = false;
        var packet: Packet = undefined;
        var parsed_shred: ?*const Shred = null;

        if (bytes.len <= Packet.capacity) {
            @memcpy(packet.data[0..bytes.len], bytes);
            // Zero the tail so the merkle / RS code reads deterministic bytes.
            @memset(packet.data[bytes.len..], 0);
            packet.len = @intCast(bytes.len);
            packet.addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);
            parsed_shred = Shred.fromPacketChecked(&packet) catch null;
            if (parsed_shred != null) parses = true;
        }
        st.shred_parse_results.append(allocator, parses) catch @panic("OutOfMemory");

        if (parsed_shred == null) continue;

        // shred_version is u16 on the wire but u32 in the proto schema; truncate.
        const result = st.receiver.processPacket(
            st.leader_schedule,
            @truncate(ctx.shred_version),
            &packet,
            &st.deshred_writer,
            .noop,
        ) catch |err| switch (err) {
            else => continue,
        };

        // Receiver accepted the shred. If it's a data shred, snapshot it
        // now — for `.fec_set_finished` the ctx has already been removed
        // from `in_progress`, so a post-call `captureInProgress` would
        // miss it. Dedup by (slot, slot_idx) so the same shred re-fed as
        // `.shred_already_seen` doesn't double-count. RS-recovered data
        // shreds still can't be reached without a Receiver hook and are
        // the known fidelity gap under option B.
        switch (result) {
            .unfinished_fec_set, .fec_set_finished => {
                const shred = parsed_shred.?;
                if (shred.variant.isData()) st.captureShredIfNew(shred);
            },
            .fec_set_already_finished, .shred_already_seen => {},
        }

        st.drainCompletions();
    }

    return try buildProtoEffects(allocator, st, ctx.shred_version);
}

// ---------------------------------------------------------------------------
// Chain validation + proto encoding
// ---------------------------------------------------------------------------

fn fecOrder(_: void, a: FECSetParseResult, b: FECSetParseResult) bool {
    if (a.slot != b.slot) return a.slot < b.slot;
    return a.fec_set_index < b.fec_set_index;
}

fn dataShredOrder(_: void, a: DataShredCapture, b: DataShredCapture) bool {
    if (a.slot != b.slot) return a.slot < b.slot;
    return a.slot_idx < b.slot_idx;
}

fn buildProtoEffects(
    allocator: Allocator,
    st: *HarnessState,
    shred_version: u32,
) !pb.ShredParseEffects {
    var out: pb.ShredParseEffects = .{
        .block_parse_result = .ACCEPTED,
        .shred_results = .empty,
        .fec_set_results = .empty,
    };
    errdefer out.deinit(allocator);

    // shred_results: 1:1 copy from the parse-verdict accumulator.
    try out.shred_results.ensureTotalCapacityPrecise(
        allocator,
        st.shred_parse_results.items.len,
    );
    out.shred_results.appendSliceAssumeCapacity(st.shred_parse_results.items);

    // Fill in per-FEC-set payload + parent_offset from the data-shred
    // captures. Every captured shred sits in exactly one FEC set; iterate
    // captures once per FEC set (bounded to 32 shreds per set, ~64
    // in-progress sets, so linear scan is fine).
    std.sort.heap(DataShredCapture, st.data_shreds.items, {}, dataShredOrder);
    for (st.fec_set_results.items) |*fec_res| {
        var payload: std.ArrayListUnmanaged(u8) = .empty;
        defer payload.deinit(st.allocator);
        for (st.data_shreds.items) |*ds| {
            if (ds.slot != fec_res.slot or ds.fec_set_idx != fec_res.fec_set_index) continue;
            payload.appendSlice(st.allocator, ds.payload) catch @panic("OutOfMemory");
            fec_res.parent_offset = ds.parent_offset;
        }
        fec_res.payload = payload.toOwnedSlice(st.allocator) catch @panic("OutOfMemory");
    }

    // Sort by (slot, fec_set_index) and chain-validate.
    std.sort.heap(FECSetParseResult, st.fec_set_results.items, {}, fecOrder);

    // Cross-FEC chained_merkle_root check (not enforced by the Receiver).
    var i: usize = 0;
    while (i < st.fec_set_results.items.len) {
        // Contiguous run of FEC sets for one slot.
        const slot = st.fec_set_results.items[i].slot;
        var j = i + 1;
        while (j < st.fec_set_results.items.len and
            st.fec_set_results.items[j].slot == slot) : (j += 1)
        {}

        var expected_idx: u32 = 0;
        var prev_merkle: ?Hash = null;
        for (st.fec_set_results.items[i..j]) |*r| {
            // Gap or out-of-order -> remaining sets in this slot are dropped.
            if (r.fec_set_index != expected_idx) {
                out.block_parse_result = .REJECTED_INVALID_HEADER;
                break;
            }
            if (prev_merkle) |pm| {
                if (!pm.eql(&r.chained_merkle_root)) {
                    out.block_parse_result = .REJECTED_INVALID_HEADER;
                    break;
                }
            }

            try out.fec_set_results.append(allocator, .{
                .completed = true,
                .merkle_root = try allocator.dupe(u8, &r.merkle_root.data),
                .chained_merkle_root = try allocator.dupe(u8, &r.chained_merkle_root.data),
                .payload = try allocator.dupe(u8, r.payload),
                .slot = r.slot,
                .fec_set_index = r.fec_set_index,
                .parent_offset = r.parent_offset,
                .shred_version = shred_version,
                .num_data_shreds = r.num_data_shreds,
                .num_coding_shreds = r.num_coding_shreds,
            });

            prev_merkle = r.merkle_root;
            expected_idx += FEC_DATA_SHREDS;
        }

        i = j;
    }

    // Per-slot tick verification, driven by every data shred the Receiver
    // accepted (on-wire only under option B; RS-recovered shreds aren't
    // captured because their ctx is destroyed inside processPacket).
    // Mirrors agave's `get_slot_entries_with_shred_info + verify_ticks`,
    // which reconstructs entries at DATA_COMPLETE-batch granularity from
    // whatever data shreds sit in the blockstore.
    var ds_i: usize = 0;
    while (ds_i < st.data_shreds.items.len) {
        const slot = st.data_shreds.items[ds_i].slot;
        var ds_j = ds_i + 1;
        while (ds_j < st.data_shreds.items.len and
            st.data_shreds.items[ds_j].slot == slot) : (ds_j += 1)
        {}

        if (out.block_parse_result != .REJECTED_INVALID_HEADER) {
            switch (try verifyTicksFromDataShreds(
                allocator,
                slot,
                st.data_shreds.items[ds_i..ds_j],
            )) {
                .ok => {},
                .rejected => out.block_parse_result = .REJECTED_INVALID_HEADER,
            }
        }

        ds_i = ds_j;
    }

    return out;
}

const TickVerifyOutcome = enum { ok, rejected };

/// Validates the fixed-shape header of an agave `VersionedBlockMarker`.
/// Consumes 5 or 6 bytes on success:
///
///   - `VersionedBlockMarker`: u16 tag, only `1` (V1) is valid.
///   - `BlockMarkerV1`: u8 tag in
///     `{0: BlockFooter, 1: BlockHeader, 2: UpdateParent, 3: GenesisCert}`.
///   - `LengthPrefixed<Inner>`: u16 length prefix (not enforced by agave).
///   - For markers 0..2: inner `Versioned<Footer|Header|UpdateParent>`
///     u8 tag, only `1` (V1) is valid. Marker 3 has no version tag byte.
///
/// Shape-only; deeper inner fields (BLS sigs, certs) are unmodelled.
fn validateBlockMarkerHeader(reader: *std.Io.Reader) bool {
    const outer_tag = reader.takeInt(u16, .little) catch return false;
    if (outer_tag != 1) return false;
    const inner_tag = reader.takeByte() catch return false;
    if (inner_tag > 3) return false;
    _ = reader.takeInt(u16, .little) catch return false;
    if (inner_tag <= 2) {
        const versioned_tag = reader.takeByte() catch return false;
        if (versioned_tag != 1) return false;
    }
    return true;
}

/// Per-slot tick verification driven by accepted data shreds. Walks the
/// contiguous prefix `slot_idx = 0, 1, 2, ...`; each DATA_COMPLETE-bounded
/// run concatenates to one bincode `Vec<Entry>` record (one shredder
/// batch). Stops at the first gap — agave's blockstore lookup behaves the
/// same way: `get_slot_entries_with_shred_info` only returns entries from
/// the contiguous-from-zero prefix. A trailing run with no terminating
/// DATA_COMPLETE is silently dropped. Returns `.rejected` on any decode or
/// tick-window failure, `.ok` otherwise.
fn verifyTicksFromDataShreds(
    allocator: Allocator,
    slot: Slot,
    shreds: []const DataShredCapture, // sorted by slot_idx
) error{OutOfMemory}!TickVerifyOutcome {
    std.debug.assert(shreds.len > 0);

    // Per-slot scratch arena. 64 MiB easily covers any one slot (raw shred
    // data is at most ~2 MiB pre-recovery).
    const fba_size: usize = 64 * 1024 * 1024;
    const fba_buf = try allocator.alloc(u8, fba_size);
    defer allocator.free(fba_buf);
    var fba = std.heap.FixedBufferAllocator.init(fba_buf);

    // slot_is_full := any captured shred carried LAST_SHRED_IN_SLOT.
    var slot_is_full = false;
    for (shreds) |s| slot_is_full = slot_is_full or s.last_shred_in_slot;

    var all_entries: std.ArrayListUnmanaged(sig_v2.solana.transaction.Entry) = .empty;
    // No deinit: storage is in `fba_buf`, freed via defer above.

    var expected_idx: u32 = 0;
    var batch_buf: std.ArrayListUnmanaged(u8) = .empty;
    for (shreds) |s| {
        // Gap in the contiguous-from-zero prefix -> stop. Anything past a
        // gap is unreachable from `get_slot_entries_with_shred_info`.
        if (s.slot_idx != expected_idx) break;
        batch_buf.appendSlice(fba.allocator(), s.payload) catch return .rejected;
        if (s.data_complete) {
            // Each data-complete batch is one wincode `BlockComponent`:
            // `Vec<Entry>` with a u64 length prefix, followed by a
            // `VersionedBlockMarker` when the length is 0.
            var reader: std.Io.Reader = .fixed(batch_buf.items);
            const entries = sig_v2.solana.bincode.read(
                &fba,
                &reader,
                sig_v2.solana.bincode.Vec(sig_v2.solana.transaction.Entry),
            ) catch return .rejected;
            if (entries.items.len == 0) {
                if (!validateBlockMarkerHeader(&reader)) return .rejected;
            }
            for (entries.items) |e| {
                all_entries.append(fba.allocator(), e) catch return .rejected;
            }
            batch_buf = .empty;
        }
        expected_idx += 1;
    }

    // No decoded entries -> skip tick verify (would reject TooFewTicks when
    // slot_is_full).
    if (all_entries.items.len == 0) return .ok;

    var tick_hash_count: u64 = 0;
    if (sig_v2.solana.verify_ticks.verifyTicks(all_entries.items, .{
        .hashes_per_tick = HASHES_PER_TICK,
        .slot = slot,
        .max_tick_height = TICKS_PER_SLOT,
        .tick_height = 0,
        .slot_is_full = slot_is_full,
        .tick_hash_count = &tick_hash_count,
    })) {
        // tick window verified; fall through to per-tx checks
    } else |_| {
        return .rejected;
    }

    // Per-transaction structural check. `VersionedTransaction.parse` folds
    // in what the removed `serializedSize`/`sanitize`/`validateAccountLocks`
    // helpers used to enforce separately (MAX_BYTES, structural invariants,
    // duplicate account keys). Since our transactions come from a bincode-
    // decoded `Entry`, we round-trip each back to bytes and feed them
    // through `parse` — matches the pattern the parseTransaction test
    // harness uses in v2/lib/solana/transaction.zig.
    const VT = sig_v2.solana.transaction.VersionedTransaction;
    const SliceReader = sig_v2.solana.transaction.SliceReader;
    for (all_entries.items) |entry| {
        for (entry.transactions.items) |txn| {
            var buf: [VT.MAX_BYTES]u8 = undefined;
            var writer: std.Io.Writer = .fixed(&buf);
            sig_v2.solana.bincode.write(&writer, txn) catch return .rejected;
            var reader: SliceReader = .{ .bytes = writer.buffered() };
            _ = VT.parse(&reader) catch return .rejected;
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
