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
const FecSetId = sig_v2.shred.FecSetId;
const PacketResult = sig_v2.shred.ReceiverPacketResult;

const Packet = sig_v2.net.Packet;

const Hash = sig_v2.solana.Hash;
const Slot = sig_v2.solana.Slot;
const Pubkey = sig_v2.solana.Pubkey;
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

    var effects = try executeShredParse(ctx, allocator);
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
// Effects: collects callback output into ArrayLists.
// ---------------------------------------------------------------------------

/// Mutable scratch shared between the Receiver callbacks and the harness body.
const Effects = struct {
    allocator: Allocator,

    /// Writer view into the Receiver's output ring. Re-armed per input.
    deshred_writer: *DeshredRing.Iterator(.writer),

    /// Per-shred parse result, in input order.
    shred_parse_results: std.ArrayListUnmanaged(bool) = .empty,

    /// Completed FEC sets, in completion order; sorted + chain-validated
    /// before being encoded to proto.
    fec_set_results: std.ArrayListUnmanaged(FECSetParseResult) = .empty,

    /// Set when any callback's allocator failed.
    allocator_failed: bool = false,

    /// Set by `reportChainConflict` when the Receiver detects a cross-FEC
    /// `chained_merkle_root` mismatch. Fuzz inputs are single-slot, so a
    /// single flag captures the whole-block rejection signal.
    chain_conflict: bool = false,

    /// Per-FEC-set scratch before slot-wide sort + chain validation.
    const FECSetParseResult = struct {
        merkle_root: Hash,
        chained_merkle_root: Hash,
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

    fn deinit(self: *Effects, alloc: Allocator) void {
        for (self.fec_set_results.items) |it| alloc.free(it.payload);
        self.fec_set_results.deinit(alloc);
        self.shred_parse_results.deinit(alloc);
    }

    /// Drop per-input state, retaining capacity.
    fn reset(self: *Effects) void {
        for (self.fec_set_results.items) |it| self.allocator.free(it.payload);
        self.fec_set_results.clearRetainingCapacity();
        self.shred_parse_results.clearRetainingCapacity();
        self.allocator_failed = false;
        self.chain_conflict = false;
    }

    // ----- Receiver(Effects) interface contract -----

    pub fn reportShredParseResult(self: *Effects, parses_as_chained: bool) void {
        self.shred_parse_results.append(self.allocator, parses_as_chained) catch {
            self.allocator_failed = true;
        };
    }

    /// NOTE: pointers passed in are only valid for the duration of this
    /// callback. We must copy anything we want to keep.
    pub fn reportFecSetCompleted(
        self: *Effects,
        completed: *const DeshreddedFecSet,
        ctx: *const FecSetCtx,
    ) void {
        // parent_offset is per-shred, not per-FEC-set; read it from the
        // first data shred (all 32 are valid after RS recovery).
        const first_data: *const Shred = .fromBufferUnchecked(&ctx.data_shreds_buf[0]);
        const parent_offset: u16 = first_data.code_or_data.data.parent_offset;

        const payload_copy = self.allocator.dupe(u8, completed.payload()) catch {
            self.allocator_failed = true;
            return;
        };

        self.fec_set_results.append(self.allocator, .{
            .merkle_root = completed.merkle_root,
            .chained_merkle_root = completed.chained_merkle_root,
            .payload = payload_copy,
            .slot = completed.id.slot,
            .fec_set_index = completed.id.fec_set_idx,
            .parent_offset = parent_offset,
            .num_data_shreds = FEC_DATA_SHREDS,
            .num_coding_shreds = FEC_CODING_SHREDS,
            .data_complete = completed.data_complete,
            .slot_complete = completed.slot_complete,
        }) catch {
            self.allocator.free(payload_copy);
            self.allocator_failed = true;
        };
    }

    pub fn reportReceiverPacketResult(self: *Effects, result: PacketResult) void {
        // Not part of `ShredParseEffects`; ignore.
        _ = .{ self, result };
    }

    pub fn reportChainConflict(self: *Effects, slot: Slot) void {
        // The fuzzer runs one slot per input, so a single boolean suffices;
        // any conflict means the whole block is rejected.
        _ = slot;
        self.chain_conflict = true;
    }

    /// Hand the Receiver a writable slot in the deshred ring. The harness
    /// never reads the ring, so it's pure scratch reset per input. A `null`
    /// `next()` means a single fixture overflowed the 1024 ring slots.
    pub fn writeCompletedFecSet(self: *Effects) *DeshreddedFecSet {
        return self.deshred_writer.next() orelse @panic("DeshredRing exhausted within a single fixture");
    }

    /// Required by the Receiver's produce protocol; the slot is otherwise unused.
    pub fn flushCompletedFecSet(self: *Effects) void {
        self.deshred_writer.markUsed();
    }
};

// ---------------------------------------------------------------------------
// Thread-local harness state (heap-allocated; reused across inputs)
// ---------------------------------------------------------------------------

threadlocal var harness_state: ?*HarnessState = null;

const HarnessReceiver = sig_v2.shred.Receiver(*Effects);

const HarnessState = struct {
    allocator: Allocator,
    /// Owned here so `receiver.effects` is a stable pointer.
    effects: Effects,
    receiver: HarnessReceiver,
    deshred_ring: *DeshredRing,
    /// Stored here (not on Effects) so `effects.deshred_writer` is stable
    /// across re-arms.
    deshred_writer: DeshredRing.Iterator(.writer),
    leader_schedule: *LeaderSchedule,

    fn init(alloc: Allocator) !*HarnessState {
        const self = try alloc.create(HarnessState);
        errdefer alloc.destroy(self);

        // Required by Receiver.processPacket even though we never read it;
        // `reportFecSetCompleted` is the canonical output channel.
        const ring = try alloc.create(DeshredRing);
        errdefer alloc.destroy(ring);
        ring.init();

        // ~13.8 MB — heap, not stack.
        const ls = try alloc.create(LeaderSchedule);
        errdefer alloc.destroy(ls);
        ls.base_slot = 0;
        @memset(&ls.leaders, .ZEROES);

        // Initialise the struct before constructing the receiver so we can
        // hand the receiver a stable `&self.effects` pointer.
        self.* = .{
            .allocator = alloc,
            .effects = .{
                .allocator = alloc,
                // Pointer fixed up below once `self.deshred_writer` is initialised.
                .deshred_writer = undefined,
            },
            .receiver = undefined,
            .deshred_ring = ring,
            .deshred_writer = ring.get(.writer),
            .leader_schedule = ls,
        };
        self.effects.deshred_writer = &self.deshred_writer;

        self.receiver = try HarnessReceiver.init(
            alloc,
            IN_PROGRESS_CAPACITY,
            DONE_CAPACITY,
            &self.effects,
        );
        errdefer self.receiver.deinit(alloc);

        return self;
    }
};

fn state(alloc: Allocator) !*HarnessState {
    if (harness_state) |st| return st;
    const st = try HarnessState.init(alloc);
    harness_state = st;
    return st;
}

// ---------------------------------------------------------------------------
// Per-input flow
// ---------------------------------------------------------------------------

fn executeShredParse(
    ctx: pb.ShredParseContext,
    alloc: Allocator,
) !pb.ShredParseEffects {
    var st = try state(alloc);

    // Drop all accumulated state from any previous fixture.
    st.deshred_ring.init();
    st.receiver.reset();
    st.effects.reset();

    st.receiver.updateSlotRange(ctx.root_slot, maxShredSlot(ctx.root_slot));
    st.leader_schedule.base_slot = ctx.root_slot;

    // Map proto bool flags into the Receiver's per-feature activation slot:
    // `true` -> active at slot 0, `false` -> disabled (maxInt).
    const features = ctx.features orelse pb.ShredFeatures{};
    st.receiver.features = .{
        .discard_unexpected_data_complete_shreds = if (features.discard_unexpected_data_complete_shreds)
            0
        else
            std.math.maxInt(Slot),
    };

    // Re-arm the writer view for this input.
    st.deshred_writer = st.deshred_ring.get(.writer);

    for (ctx.shreds.items) |bytes_box| {
        const bytes = bytes_box; // pb generated for `repeated bytes` -> []const u8
        if (bytes.len > Packet.capacity) {
            // Oversize shreds are rejected at the packet boundary; skip the
            // Receiver entirely.
            st.effects.shred_parse_results.append(alloc, false) catch {
                st.effects.allocator_failed = true;
            };
            continue;
        }

        var packet: Packet = undefined;
        @memcpy(packet.data[0..bytes.len], bytes);
        // Zero the tail so the merkle / RS code reads deterministic bytes.
        @memset(packet.data[bytes.len..], 0);
        packet.len = @intCast(bytes.len);
        packet.addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 0);

        // shred_version is u16 on the wire but u32 in the proto schema;
        // truncate.
        _ = st.receiver.processPacket(
            st.leader_schedule,
            @truncate(ctx.shred_version),
            &packet,
            .noop,
        ) catch |err| switch (err) {
            // Effects has already been notified for every error path the
            // Receiver itself classifies. Swallow and continue.
            else => {},
        };
    }

    if (st.effects.allocator_failed) return error.OutOfMemory;

    return try buildProtoEffects(alloc, &st.effects, ctx.shred_version);
}

// ---------------------------------------------------------------------------
// Chain validation + proto encoding (step 5)
// ---------------------------------------------------------------------------

fn fecOrder(_: void, a: Effects.FECSetParseResult, b: Effects.FECSetParseResult) bool {
    if (a.slot != b.slot) return a.slot < b.slot;
    return a.fec_set_index < b.fec_set_index;
}

fn buildProtoEffects(
    alloc: Allocator,
    effects: *Effects,
    shred_version: u32,
) !pb.ShredParseEffects {
    var out: pb.ShredParseEffects = .{
        .block_parse_result = .ACCEPTED,
        .shred_results = .empty,
        .fec_set_results = .empty,
    };
    errdefer out.deinit(alloc);

    // shred_results: 1:1 copy from the Effects accumulator.
    try out.shred_results.ensureTotalCapacityPrecise(
        alloc,
        effects.shred_parse_results.items.len,
    );
    out.shred_results.appendSliceAssumeCapacity(effects.shred_parse_results.items);

    // Receiver's per-shred chain check rejects the whole block. Cleared FEC
    // sets are still emitted so the diff vs agave stays comparable; the block
    // verdict overrides the tick-window result below.
    if (effects.chain_conflict) out.block_parse_result = .REJECTED_INVALID_HEADER;

    // Step 5: sort by (slot, fec_set_index) and chain-validate.
    std.sort.heap(
        Effects.FECSetParseResult,
        effects.fec_set_results.items,
        {},
        fecOrder,
    );

    // Cross-FEC chained_merkle_root check on completed sets. Redundant with
    // the Receiver's per-shred check (see `lookupFecSetRoots`) but kept as a
    // belt-and-braces invariant assertion on the emitted output.
    var i: usize = 0;
    while (i < effects.fec_set_results.items.len) {
        // Contiguous run of FEC sets for one slot.
        const slot = effects.fec_set_results.items[i].slot;
        var j = i + 1;
        while (j < effects.fec_set_results.items.len and
            effects.fec_set_results.items[j].slot == slot) : (j += 1)
        {}

        var expected_idx: u32 = 0;
        var prev_merkle: ?Hash = null;
        // When the chain breaks (gap, out-of-order, or root mismatch) the
        // rest of the slot is dropped from tick verification.
        var chain_broken = false;
        // Number of FECs that chained, before any break.
        var slot_chained_count: usize = 0;
        for (effects.fec_set_results.items[i..j]) |*r| {
            // Gap or out-of-order -> remaining sets in this slot are dropped.
            if (r.fec_set_index != expected_idx) {
                out.block_parse_result = .REJECTED_INVALID_HEADER;
                chain_broken = true;
                break;
            }
            if (prev_merkle) |pm| {
                if (!pm.eql(&r.chained_merkle_root)) {
                    out.block_parse_result = .REJECTED_INVALID_HEADER;
                    chain_broken = true;
                    break;
                }
            }

            try out.fec_set_results.append(alloc, .{
                .completed = true,
                .merkle_root = try alloc.dupe(u8, &r.merkle_root.data),
                .chained_merkle_root = try alloc.dupe(u8, &r.chained_merkle_root.data),
                .payload = try alloc.dupe(u8, r.payload),
                .slot = r.slot,
                .fec_set_index = r.fec_set_index,
                .parent_offset = r.parent_offset,
                .shred_version = shred_version,
                .num_data_shreds = r.num_data_shreds,
                .num_coding_shreds = r.num_coding_shreds,
            });

            prev_merkle = r.merkle_root;
            expected_idx += FEC_DATA_SHREDS;
            slot_chained_count += 1;
        }

        // Tick verification over the chain-valid prefix. Tick-window or
        // bincode failures reject the whole block.
        if (!chain_broken and slot_chained_count > 0 and out.block_parse_result != .REJECTED_INVALID_HEADER) {
            switch (try verifyTicksForSlot(alloc, slot, effects.fec_set_results.items[i .. i + slot_chained_count])) {
                .ok => {},
                .rejected => out.block_parse_result = .REJECTED_INVALID_HEADER,
            }
        }

        i = j;
    }

    return out;
}

const TickVerifyOutcome = enum { ok, rejected };

/// Per-slot tick verification. Decodes each shredder batch (concat the
/// `data_complete` run, bincode-decode as `Vec<Entry>`) and runs the v2
/// `verifyTicks` primitive. Returns `.rejected` on any decode or
/// tick-window failure, `.ok` otherwise; a trailing in-progress batch is
/// dropped silently per protocol.
fn verifyTicksForSlot(
    alloc: Allocator,
    slot: Slot,
    fecs: []const Effects.FECSetParseResult,
) error{OutOfMemory}!TickVerifyOutcome {
    std.debug.assert(fecs.len > 0);

    // Per-slot scratch arena. 64 MiB easily covers any one slot (raw shred
    // data is at most ~2 MiB pre-recovery).
    const fba_size: usize = 64 * 1024 * 1024;
    const fba_buf = try alloc.alloc(u8, fba_size);
    defer alloc.free(fba_buf);
    var fba = std.heap.FixedBufferAllocator.init(fba_buf);

    // slot_is_full := any FEC in this slot carried LAST_SHRED_IN_SLOT.
    var slot_is_full = false;
    for (fecs) |r| slot_is_full = slot_is_full or r.slot_complete;

    // Each `data_complete` run is one bincode `Vec<Entry>` record (one per
    // shredder batch); concatenate the run and decode.
    var all_entries: std.ArrayListUnmanaged(sig_v2.solana.transaction.Entry) = .empty;
    // No deinit: storage is in `fba_buf`, freed via defer above.

    var batch_start: usize = 0;
    while (batch_start < fecs.len) {
        // Group up to (and including) the next data_complete FEC. A trailing
        // run with no data_complete is an incomplete batch and is dropped.
        var batch_end: usize = batch_start;
        while (batch_end < fecs.len and !fecs[batch_end].data_complete) batch_end += 1;
        if (batch_end >= fecs.len) break; // no terminating data_complete; drop
        batch_end += 1; // include the data_complete FEC itself

        // Concatenate the batch payloads into a contiguous bincode input.
        var total: usize = 0;
        for (fecs[batch_start..batch_end]) |r| total += r.payload.len;

        // Zero-byte batch -> zero entries. Feeding this to bincode would
        // fail to decode the u64 length prefix and incorrectly reject.
        if (total == 0) {
            batch_start = batch_end;
            continue;
        }

        const batch_buf = fba.allocator().alloc(u8, total) catch return .rejected;
        var off: usize = 0;
        for (fecs[batch_start..batch_end]) |r| {
            @memcpy(batch_buf[off..][0..r.payload.len], r.payload);
            off += r.payload.len;
        }

        // bincode-deserialise as Vec<Entry>. On any error, reject.
        var reader: std.Io.Reader = .fixed(batch_buf);
        const entries = sig_v2.solana.bincode.read(
            &fba,
            &reader,
            sig_v2.solana.bincode.Vec(sig_v2.solana.transaction.Entry),
        ) catch return .rejected;

        for (entries.items) |e| {
            all_entries.append(fba.allocator(), e) catch return .rejected;
        }

        batch_start = batch_end;
    }

    // No decoded entries -> skip tick verify (would reject TooFewTicks when
    // slot_is_full).
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
