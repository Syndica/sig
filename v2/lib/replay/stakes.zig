//! Replay-owned stakes state, scoped to what replay itself reads while
//! executing transactions within a single epoch:
//!   - `EpochVoters` — the frozen per-epoch set of admitted voters
//!     (vote-pubkey, stake, commission) plus a derived side index
//!     for O(1) sol_get_epoch_stake lookup.
//!   - `LiveVoter` / `LiveVoters` — dense per-block live vote-account
//!     state (last-vote slot + timestamp), indexed in lockstep with
//!     `EpochVoters.entries` so per-slot sysvar updates scan them
//!     as parallel arrays.
//!   - `ReplayStakes` — the owner struct: one `EpochVoters` plus one
//!     `LiveVoters` per `BlockPool` slot.

const std = @import("std");

const replay = @import("../replay.zig");
const solana = @import("../solana.zig");
const collections = @import("../collections.zig");

const Pubkey = solana.Pubkey;
const Slot = solana.Slot;
const Epoch = solana.Epoch;

/// SIMD-0357 caps the admitted vote-account set at 2000 post-Alpenglow.
/// Pre-Alpenglow, the effective count on mainnet is around ~1400, so
/// this is a comfortable bound in both regimes.
pub const MAX_ALPENGLOW_VOTE_ACCOUNTS: u16 = 2000;

/// `FixedPubkeyMap` requires a power-of-two capacity and callers size to
/// >= 2x expected occupancy. ceil2(2 * 2000) = 4096.
pub const EPOCH_VOTERS_INDEX_CAP: usize = 4096;

const EpochVotersIndex = collections.FixedPubkeyMap(u16, EPOCH_VOTERS_INDEX_CAP);

/// Frozen per-epoch snapshot of admitted voters.
///
/// `entries` is the source of truth. `by_vote_pk` and `total_stake`
/// are derived from `entries` and refreshed atomically with it — only
/// at snapshot boot today; at each epoch-boundary crossing once
/// boundary derivation is wired in.
///
/// Layout is `extern` so the struct can be persisted or shared as-is;
/// downstream consumers may map it directly.
pub const EpochVoters = extern struct {
    len: u16,
    _pad0: [6]u8 = @splat(0),
    entries: [MAX_ALPENGLOW_VOTE_ACCOUNTS]Entry,
    by_vote_pk: EpochVotersIndex,
    total_stake: u64,

    /// One admitted voter. Positional row — the index of an entry in
    /// `entries[]` is the identity used by all sibling arrays (e.g.
    /// `LiveVoters.entries`). Sorted by `stake` desc at build time.
    pub const Entry = extern struct {
        vote_pk: Pubkey, //           32
        stake: u64, //                 8
        commission_bps: u16, //        2
        _pad: [6]u8 = @splat(0), //    6
    }; //                             48 B

    comptime {
        std.debug.assert(@sizeOf(Entry) == 48);
    }

    /// Zero the struct and reset the map to empty. Call before
    /// building.
    pub fn init(self: *EpochVoters) void {
        self.len = 0;
        self._pad0 = @splat(0);
        // `entries` intentionally left undefined; only slots
        // 0..len are read.
        self.by_vote_pk.init();
        self.total_stake = 0;
    }

    /// O(1) lookup of a voter's stake by vote pubkey. Miss returns 0
    /// (agave / firedancer parity with sol_get_epoch_stake).
    pub fn stakeOf(self: *const EpochVoters, vote_pk: Pubkey) u64 {
        const idx_ptr = self.by_vote_pk.getPtrConst(vote_pk) orelse return 0;
        return self.entries[idx_ptr.*].stake;
    }

    /// Populate from a single `VersionedEpochStakes` entry sourced
    /// from the snapshot manifest.
    ///
    /// `memory_base` is the base pointer used to resolve the entry's
    /// `RelativeSlice` fields (typically `snapshot_metadata.getMemory()`).
    ///
    /// Sorts `entries` by stake desc so positional index 0 is the
    /// highest-staked voter — matches SIMD-0357's post-Alpenglow
    /// admitted-set ordering, and gives a canonical index for the
    /// sibling `LiveVoters` arrays.
    ///
    /// `commission_bps` is filled zero — the trimmed
    /// `VersionedEpochStakes.VoteAccountEntry` on the snapshot side
    /// only carries `{ pubkey, stake }`, and no reader consumes
    /// commission today.
    ///
    /// Errors:
    /// - `error.TooManyVoters` if the entry exceeds
    ///   `MAX_ALPENGLOW_VOTE_ACCOUNTS`. Refuses to boot rather than
    ///   silently truncate; loosen when the snapshot producers are
    ///   confirmed to enforce the SIMD-0357 cap.
    /// - `error.MapFull` from the derived side index — should not
    ///   occur given the pow-2 / 2x-occupancy invariants.
    pub fn loadFromVersionedEpochStakes(
        self: *EpochVoters,
        entry: *const solana.snapshot.ExtraFields.VersionedEpochStakes,
        memory_base: []const u8,
    ) !void {
        self.init();
        if (entry.vote_accounts.len > MAX_ALPENGLOW_VOTE_ACCOUNTS) return error.TooManyVoters;
        const vote_accounts = entry.vote_accounts.sliceConst(memory_base.ptr);

        for (vote_accounts, 0..) |src, i| {
            self.entries[i] = .{
                .vote_pk = src.pubkey,
                .stake = src.stake,
                .commission_bps = 0,
            };
        }
        self.len = @intCast(vote_accounts.len);

        std.mem.sort(Entry, self.entries[0..self.len], {}, struct {
            fn stakeDesc(_: void, a: Entry, b: Entry) bool {
                return a.stake > b.stake;
            }
        }.stakeDesc);

        for (self.entries[0..self.len], 0..) |*e, i| {
            try self.by_vote_pk.insert(e.vote_pk, @intCast(i));
            self.total_stake += e.stake;
        }
    }
};

/// Pure implementation of the `sol_get_epoch_stake` SVM syscall
/// semantic (SIMD-0133).
///
/// Callers in the SVM layer are responsible for compute-meter
/// charging and for translating the pubkey argument out of VM
/// memory; this function assumes a validated optional pointer.
///
/// Semantics:
/// - `null` → total active stake for the current epoch.
/// - non-null → stake delegated to the vote account at that
///   address, or 0 if the address does not correspond to an
///   admitted voter (SIMD-0357 top-2000 post-Alpenglow; the full
///   admitted set pre-Alpenglow).
///
/// Not yet reachable at runtime — v2 has no SVM interpreter. Once
/// the exec tile grows one, register this as the handler for
/// `sol_get_epoch_stake` with the current epoch's `EpochVoters`
/// bound on the invoke context.
pub fn solGetEpochStake(
    epoch_voters: *const EpochVoters,
    maybe_vote_pk: ?*const Pubkey,
) u64 {
    const vote_pk = maybe_vote_pk orelse return epoch_voters.total_stake;
    return epoch_voters.stakeOf(vote_pk.*);
}

/// Drift bounds for the stake-weighted timestamp median, expressed
/// as percentages of the poh estimate offset since the epoch start.
/// Post-Alpenglow defaults match agave's `MAX_ALLOWABLE_DRIFT_PERCENTAGE_FAST`
/// and `MAX_ALLOWABLE_DRIFT_PERCENTAGE_SLOW_V2`.
pub const TimestampDrift = extern struct {
    fast_pct: u32,
    slow_pct: u32,

    pub const DEFAULT: TimestampDrift = .{ .fast_pct = 25, .slow_pct = 150 };
};

/// Anchor for the epoch-start drift bound: (slot, timestamp) of the
/// clock sysvar at the first slot of the current epoch.
pub const EpochStartTimestamp = extern struct {
    slot: Slot,
    timestamp: i64,
};

/// Pure stake-weighted median timestamp computed over `EpochVoters`
/// (stake weights) and one fork's `LiveVoters` (live vote
/// timestamps). Matches agave's `calculate_stake_weighted_timestamp`
/// semantic and is the value the per-slot clock sysvar update writes
/// into `Clock.unix_timestamp`.
///
/// Not yet reachable at runtime — v2 has no per-slot sysvar update
/// path. Once one exists it calls this function once per slot with
/// the current fork's `LiveVoters` and the epoch's `EpochVoters`.
///
/// Algorithm (per SIMD / agave):
/// 1. For each voter whose live row is `.update`, project the vote
///    timestamp to `current_slot` as
///    `last_vote_timestamp + elapsed_secs(last_vote_slot -> current_slot)`.
/// 2. Sort projections asc; walk while accumulating stake; return
///    the projection at which cumulative stake first exceeds
///    `total_live_stake / 2` — the stake-weighted median.
/// 3. If `epoch_start` is provided, bound the median against the
///    poh estimate offset by `drift.fast_pct` / `drift.slow_pct`.
///
/// Returns null iff no voter has a live `.update` row with non-zero
/// stake (no signal to aggregate).
pub fn stakeWeightedTimestamp(
    epoch_voters: *const EpochVoters,
    live_voters: *const LiveVoters,
    current_slot: Slot,
    slot_duration_ns: u64,
    epoch_start: ?EpochStartTimestamp,
    drift: TimestampDrift,
) ?i64 {
    var pairs: [MAX_ALPENGLOW_VOTE_ACCOUNTS]Pair = undefined;
    var n: usize = 0;
    var total_stake: u128 = 0;

    for (0..epoch_voters.len) |i| {
        const row = &live_voters.entries[i];
        if (row.kind != .update) continue;
        const stake = epoch_voters.entries[i].stake;
        if (stake == 0) continue;

        pairs[n] = .{
            .estimate = row.last_vote_timestamp +| elapsedSecs(row.last_vote_slot, current_slot, slot_duration_ns),
            .stake = stake,
        };
        n += 1;
        total_stake +|= stake;
    }
    if (total_stake == 0) return null;

    std.mem.sort(Pair, pairs[0..n], {}, Pair.byEstimateAsc);

    var acc: u128 = 0;
    var estimate: i64 = pairs[0].estimate;
    for (pairs[0..n]) |p| {
        acc +|= p.stake;
        if (acc > total_stake / 2) {
            estimate = p.estimate;
            break;
        }
    }

    if (epoch_start) |es| {
        estimate = clampDrift(estimate, es, current_slot, slot_duration_ns, drift);
    }
    return estimate;
}

const Pair = struct {
    estimate: i64,
    stake: u64,

    fn byEstimateAsc(_: void, a: Pair, b: Pair) bool {
        return a.estimate < b.estimate;
    }
};

/// `(to_slot - from_slot) * slot_duration_ns / 1e9`, saturating and
/// truncating to whole seconds.
fn elapsedSecs(from_slot: Slot, to_slot: Slot, slot_duration_ns: u64) i64 {
    const slots: u128 = to_slot -| from_slot;
    const ns: u128 = slots *| @as(u128, slot_duration_ns);
    const secs: u128 = ns / std.time.ns_per_s;
    return @intCast(@min(secs, @as(u128, std.math.maxInt(i64))));
}

fn clampDrift(
    estimate: i64,
    epoch_start: EpochStartTimestamp,
    current_slot: Slot,
    slot_duration_ns: u64,
    drift: TimestampDrift,
) i64 {
    const poh_off_secs = elapsedSecs(epoch_start.slot, current_slot, slot_duration_ns);
    const est_off_secs: i64 = @intCast(@max(0, estimate -| epoch_start.timestamp));

    const fast_bound = @divTrunc(poh_off_secs *| @as(i64, @intCast(drift.fast_pct)), 100);
    const slow_bound = @divTrunc(poh_off_secs *| @as(i64, @intCast(drift.slow_pct)), 100);

    if (est_off_secs > poh_off_secs and est_off_secs - poh_off_secs > slow_bound) {
        // Slower than poh by more than the slow bound: clamp forward.
        return epoch_start.timestamp +| poh_off_secs +| slow_bound;
    }
    if (est_off_secs < poh_off_secs and poh_off_secs - est_off_secs > fast_bound) {
        // Faster than poh by more than the fast bound: clamp back.
        return epoch_start.timestamp +| poh_off_secs -| fast_bound;
    }
    return estimate;
}

/// Fold a landed vote into the fork's `LiveVoters`. Overwrites the
/// admitted voter's row with the new `.update` state; no-op if the
/// vote account isn't in the admitted set (miss on `by_vote_pk`).
///
/// Miss semantics: post-Alpenglow (SIMD-0357) only the top-2000
/// admitted voters have positional slots. A vote tx from a non-
/// admitted vote account lands successfully at the tx level but
/// contributes nothing to the timestamp aggregate. Pre-Alpenglow
/// every vote account is admitted, so misses shouldn't happen in
/// practice.
///
/// Not yet reachable at runtime — v2 has no vote-program execution.
/// When the exec tile grows one, the committer path decodes each
/// landed vote ix and calls this with the extracted
/// `(vote_pk, last_vote_slot, last_vote_timestamp)`.
///
/// Vote-account deletion (the `.invalidate` transition) is not
/// modelled.
pub fn foldLandedVote(
    epoch_voters: *const EpochVoters,
    live_voters: *LiveVoters,
    vote_pk: Pubkey,
    last_vote_slot: Slot,
    last_vote_timestamp: i64,
) void {
    const idx_ptr = epoch_voters.by_vote_pk.getPtrConst(vote_pk) orelse return;
    live_voters.entries[idx_ptr.*] = .{
        .last_vote_slot = last_vote_slot,
        .last_vote_timestamp = last_vote_timestamp,
        .kind = .update,
    };
}

/// Per-block live vote-account state row. One per position in
/// `EpochVoters.entries`. `.unpopulated` means "no vote landed on
/// this fork yet"; `.update` carries the latest vote slot +
/// timestamp; `.invalidate` marks the voter as retired on this fork
/// (vote account closed).
pub const LiveVoter = extern struct {
    last_vote_slot: Slot, //          8
    last_vote_timestamp: i64, //      8
    kind: Kind, //                    1
    _pad: [7]u8 = @splat(0), //       7

    pub const Kind = enum(u8) {
        unpopulated = 0,
        update = 1,
        invalidate = 2,
    };

    pub const UNPOPULATED: LiveVoter = .{
        .last_vote_slot = 0,
        .last_vote_timestamp = 0,
        .kind = .unpopulated,
    };

    comptime {
        std.debug.assert(@sizeOf(LiveVoter) == 24);
    }
};

/// Dense per-block array indexed by position in `EpochVoters.entries`.
/// Not tagged with a length: `EpochVoters.len` bounds the readable
/// prefix; rows at higher indices are `.unpopulated` and inert.
pub const LiveVoters = extern struct {
    entries: [MAX_ALPENGLOW_VOTE_ACCOUNTS]LiveVoter,

    /// Zero out every row to `.unpopulated`. Used for the root block
    /// at snapshot boot, and as a defensive scrub before a
    /// `BlockPool` slot is re-issued.
    pub fn reset(self: *LiveVoters) void {
        @memset(&self.entries, LiveVoter.UNPOPULATED);
    }
};

comptime {
    // Sanity: keeps memory budgeting honest.
    std.debug.assert(@sizeOf(LiveVoters) == MAX_ALPENGLOW_VOTE_ACCOUNTS * 24);
}

/// Provisional owner struct for replay's stakes state.
///
/// **Temporary shape.** The rest of v2 exposes shared state as one
/// top-level region per collection (`BlockPool`, `TransactionPool`,
/// `ExecReqResponse`), each with its own mmap and passed around as
/// its own pointer. `ReplayStakes` bundles two such regions
/// (`epoch_voters`, `live_voters`) for now; the expected end state
/// is to split them into standalone top-level regions matching
/// that convention. `epoch_voters` and `live_voters` themselves are
/// durable — only the wrapping is provisional.
///
/// Not `extern` — a container of already-`extern` pieces; no
/// cross-process consumer maps `ReplayStakes` itself.
pub const ReplayStakes = struct {
    epoch_voters: EpochVoters,
    /// Indexed by `BlockRef` position within the `BlockPool`. Cloned
    /// from a parent block's slot at `onBlockCreate`. The root
    /// block's slot is filled by `reset()` at boot.
    live_voters: [replay.BlockPool.capacity]LiveVoters,
    /// **Provisional.** Hangs the epoch-boundary hard-stop off a
    /// single field. Once boundary derivation lands and replay
    /// tracks `current` / `t_minus_1` / `t_minus_2` rotation slots,
    /// the epoch of any given slot is derivable from the rotation
    /// state and this field is deleted.
    boot_epoch: Epoch,

    /// Zero-init the struct to a well-defined empty state. Actual
    /// data is populated by the snapshot boot loader and by the
    /// root-block setup path.
    pub fn init(self: *ReplayStakes) void {
        self.epoch_voters.init();
        for (&self.live_voters) |*lv| lv.reset();
        self.boot_epoch = 0;
    }

    /// Populate `epoch_voters` and `boot_epoch` from the snapshot
    /// manifest. `live_voters` is left in its `init()` state (all
    /// `.unpopulated`) — the root block has no parent to clone from.
    ///
    /// `root_slot` is the slot the snapshot was taken at (i.e. the
    /// root block's slot). `memory_base` is the base pointer used to
    /// resolve `RelativeSlice` values in `manifest`, typically
    /// `snapshot_metadata.getMemory()`.
    ///
    /// Errors:
    /// - `error.MissingEpochStakesForCurrentEpoch` if the manifest
    ///   has no `VersionedEpochStakes` entry for the boot epoch.
    ///   Post-Alpenglow this should always be present; on older
    ///   snapshots it may not be.
    /// - Propagates errors from `EpochVoters.loadFromVersionedEpochStakes`.
    pub fn loadFromSnapshot(
        self: *ReplayStakes,
        root_slot: Slot,
        manifest: *const solana.snapshot.Manifest,
        memory_base: []const u8,
    ) !void {
        self.boot_epoch = manifest.bank_fields.epoch_schedule.getEpoch(root_slot);

        const versioned = manifest.extra_fields.versioned_epoch_stakes.sliceConst(memory_base.ptr);
        const entry: *const solana.snapshot.ExtraFields.VersionedEpochStakes = blk: {
            for (versioned) |*ves| {
                if (ves.epoch == self.boot_epoch) break :blk ves;
            }
            return error.MissingEpochStakesForCurrentEpoch;
        };

        try self.epoch_voters.loadFromVersionedEpochStakes(entry, memory_base);
    }

    /// Called by replay whenever a fresh `BlockRef` is allocated
    /// from the `BlockPool` for a genuine new-block event (either a
    /// slot boundary or a fork within a slot). Byte-copies the
    /// parent block's `LiveVoters` row into the child slot so the
    /// child starts from an exact snapshot of the parent's fork
    /// state.
    ///
    /// Not called for same-slot canonical extensions — those reuse
    /// the parent's `BlockRef` unchanged (see
    /// `replay.setChildBlockRef`).
    pub fn onBlockCreate(
        self: *ReplayStakes,
        parent: replay.BlockRef,
        child: replay.BlockRef,
    ) void {
        // Explicit @memcpy on the byte view. Struct-assignment on a
        // ~48 KB value can pass through a stack temporary in Debug
        // mode; the byte-level memcpy stays in-place.
        @memcpy(
            std.mem.asBytes(&self.live_voters[child.index()]),
            std.mem.asBytes(&self.live_voters[parent.index()]),
        );
    }
};

test "EpochVoters init empties the map and clears len" {
    var ev: EpochVoters = undefined;
    ev.init();
    try std.testing.expectEqual(@as(u16, 0), ev.len);
    try std.testing.expectEqual(@as(u64, 0), ev.total_stake);

    var pk: Pubkey = .{ .data = .{0} ** 32 };
    pk.data[0] = 7;
    try std.testing.expectEqual(@as(?*const u16, null), ev.by_vote_pk.getPtrConst(pk));
}

test "EpochVoters.stakeOf returns 0 on miss, entry.stake on hit" {
    var ev: EpochVoters = undefined;
    ev.init();

    var pk_hit: Pubkey = .{ .data = .{0} ** 32 };
    pk_hit.data[0] = 1;
    var pk_miss: Pubkey = .{ .data = .{0} ** 32 };
    pk_miss.data[0] = 2;

    ev.entries[0] = .{ .vote_pk = pk_hit, .stake = 12345, .commission_bps = 700 };
    ev.len = 1;
    try ev.by_vote_pk.insert(pk_hit, 0);

    try std.testing.expectEqual(@as(u64, 12345), ev.stakeOf(pk_hit));
    try std.testing.expectEqual(@as(u64, 0), ev.stakeOf(pk_miss));
}

test "LiveVoters.reset yields all .unpopulated" {
    // 48 KB — fine on the test allocator's heap.
    const lv = try std.testing.allocator.create(LiveVoters);
    defer std.testing.allocator.destroy(lv);

    lv.reset();
    for (lv.entries) |row| {
        try std.testing.expectEqual(LiveVoter.Kind.unpopulated, row.kind);
    }
}

test "EpochVoters.loadFromVersionedEpochStakes sorts desc, builds index, sums total" {
    const VES = solana.snapshot.ExtraFields.VersionedEpochStakes;
    const VoteAccountEntry = VES.VoteAccountEntry;

    // Fake shared-memory blob: place three VoteAccountEntry rows at a
    // known aligned offset. The RelativeSlice base is the blob's
    // start.
    var buf: [4096]u8 align(@alignOf(VoteAccountEntry)) = @splat(0);
    const va_offset: u32 = 128;
    const va_ptr: [*]VoteAccountEntry = @ptrCast(@alignCast(&buf[va_offset]));

    var pk_a: Pubkey = .{ .data = .{0} ** 32 };
    pk_a.data[0] = 0xAA;
    var pk_b: Pubkey = .{ .data = .{0} ** 32 };
    pk_b.data[0] = 0xBB;
    var pk_c: Pubkey = .{ .data = .{0} ** 32 };
    pk_c.data[0] = 0xCC;

    // Intentionally not sorted at input.
    va_ptr[0] = .{ .pubkey = pk_a, .stake = 100 };
    va_ptr[1] = .{ .pubkey = pk_b, .stake = 500 };
    va_ptr[2] = .{ .pubkey = pk_c, .stake = 300 };

    const entry: VES = .{
        .epoch = 42,
        .total_stake = 0, // unused by the loader
        .vote_accounts = .{ .offset = va_offset, .len = 3 },
        .node_to_vote_accounts = .{},
        .epoch_authorized_voters = .{},
    };

    const ev = try std.testing.allocator.create(EpochVoters);
    defer std.testing.allocator.destroy(ev);

    try ev.loadFromVersionedEpochStakes(&entry, &buf);

    try std.testing.expectEqual(@as(u16, 3), ev.len);
    try std.testing.expectEqual(@as(u64, 900), ev.total_stake);

    // Sorted desc: 500, 300, 100.
    try std.testing.expectEqual(@as(u64, 500), ev.entries[0].stake);
    try std.testing.expectEqual(@as(u64, 300), ev.entries[1].stake);
    try std.testing.expectEqual(@as(u64, 100), ev.entries[2].stake);

    // Index resolves stake correctly regardless of input order.
    try std.testing.expectEqual(@as(u64, 100), ev.stakeOf(pk_a));
    try std.testing.expectEqual(@as(u64, 500), ev.stakeOf(pk_b));
    try std.testing.expectEqual(@as(u64, 300), ev.stakeOf(pk_c));

    // Commission_bps zero-filled (see doc comment).
    for (ev.entries[0..ev.len]) |e| {
        try std.testing.expectEqual(@as(u16, 0), e.commission_bps);
    }
}

test "EpochVoters.loadFromVersionedEpochStakes rejects over-cap input" {
    const VES = solana.snapshot.ExtraFields.VersionedEpochStakes;
    const entry: VES = .{
        .epoch = 0,
        .total_stake = 0,
        // A concocted RelativeSlice claiming length > MAX. Offset
        // doesn't matter — the length check fires before any read.
        .vote_accounts = .{ .offset = 0, .len = MAX_ALPENGLOW_VOTE_ACCOUNTS + 1 },
        .node_to_vote_accounts = .{},
        .epoch_authorized_voters = .{},
    };

    const ev = try std.testing.allocator.create(EpochVoters);
    defer std.testing.allocator.destroy(ev);

    const empty_base: [1]u8 = .{0};
    try std.testing.expectError(
        error.TooManyVoters,
        ev.loadFromVersionedEpochStakes(&entry, &empty_base),
    );
}

test "ReplayStakes.onBlockCreate byte-copies parent live_voters into child" {
    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    const parent_idx: usize = 3;
    const child_idx: usize = 7;

    stakes.live_voters[parent_idx].entries[0] = .{
        .last_vote_slot = 100,
        .last_vote_timestamp = 1_700_000_000,
        .kind = .update,
    };
    stakes.live_voters[parent_idx].entries[1] = .{
        .last_vote_slot = 101,
        .last_vote_timestamp = 1_700_000_001,
        .kind = .invalidate,
    };

    const parent_ref: replay.BlockRef = @enumFromInt(parent_idx);
    const child_ref: replay.BlockRef = @enumFromInt(child_idx);
    stakes.onBlockCreate(parent_ref, child_ref);

    try std.testing.expectEqual(@as(Slot, 100), stakes.live_voters[child_idx].entries[0].last_vote_slot);
    try std.testing.expectEqual(LiveVoter.Kind.update, stakes.live_voters[child_idx].entries[0].kind);
    try std.testing.expectEqual(LiveVoter.Kind.invalidate, stakes.live_voters[child_idx].entries[1].kind);
    try std.testing.expectEqual(LiveVoter.Kind.unpopulated, stakes.live_voters[child_idx].entries[2].kind);

    // Post-clone, mutating the child must not touch the parent.
    stakes.live_voters[child_idx].entries[0].last_vote_slot = 999;
    try std.testing.expectEqual(@as(Slot, 100), stakes.live_voters[parent_idx].entries[0].last_vote_slot);
}

test "solGetEpochStake matches SIMD-0133 semantics (null / hit / miss)" {
    const ev = try std.testing.allocator.create(EpochVoters);
    defer std.testing.allocator.destroy(ev);
    ev.init();

    var pk_hit: Pubkey = .{ .data = .{0} ** 32 };
    pk_hit.data[0] = 0xAA;
    var pk_miss: Pubkey = .{ .data = .{0} ** 32 };
    pk_miss.data[0] = 0xBB;

    ev.entries[0] = .{ .vote_pk = pk_hit, .stake = 777, .commission_bps = 0 };
    ev.len = 1;
    ev.total_stake = 777;
    try ev.by_vote_pk.insert(pk_hit, 0);

    // null arg -> total_stake.
    try std.testing.expectEqual(@as(u64, 777), solGetEpochStake(ev, null));

    // hit -> that voter's stake.
    try std.testing.expectEqual(@as(u64, 777), solGetEpochStake(ev, &pk_hit));

    // miss -> 0.
    try std.testing.expectEqual(@as(u64, 0), solGetEpochStake(ev, &pk_miss));
}

test "stakeWeightedTimestamp returns null when no voter has stake" {
    const ev = try std.testing.allocator.create(EpochVoters);
    defer std.testing.allocator.destroy(ev);
    ev.init();
    const lv = try std.testing.allocator.create(LiveVoters);
    defer std.testing.allocator.destroy(lv);
    lv.reset();

    try std.testing.expectEqual(
        @as(?i64, null),
        stakeWeightedTimestamp(ev, lv, 1000, 400 * std.time.ns_per_ms, null, .DEFAULT),
    );
}

test "stakeWeightedTimestamp picks stake-weighted median" {
    // Three voters, all at the same last_vote_slot (offset = 0), with
    // stakes 10 / 30 / 60 and distinct timestamps. Median crosses at
    // the voter carrying stake 60 → its timestamp wins.
    const ev = try std.testing.allocator.create(EpochVoters);
    defer std.testing.allocator.destroy(ev);
    ev.init();
    const lv = try std.testing.allocator.create(LiveVoters);
    defer std.testing.allocator.destroy(lv);
    lv.reset();

    var pk0: Pubkey = .{ .data = .{0} ** 32 };
    pk0.data[0] = 1;
    var pk1: Pubkey = .{ .data = .{0} ** 32 };
    pk1.data[0] = 2;
    var pk2: Pubkey = .{ .data = .{0} ** 32 };
    pk2.data[0] = 3;

    // Slot 100 for everyone; timestamps in the wrong sorted order.
    ev.entries[0] = .{ .vote_pk = pk0, .stake = 10, .commission_bps = 0 };
    ev.entries[1] = .{ .vote_pk = pk1, .stake = 30, .commission_bps = 0 };
    ev.entries[2] = .{ .vote_pk = pk2, .stake = 60, .commission_bps = 0 };
    ev.len = 3;
    ev.total_stake = 100;
    try ev.by_vote_pk.insert(pk0, 0);
    try ev.by_vote_pk.insert(pk1, 1);
    try ev.by_vote_pk.insert(pk2, 2);

    lv.entries[0] = .{ .last_vote_slot = 100, .last_vote_timestamp = 300, .kind = .update };
    lv.entries[1] = .{ .last_vote_slot = 100, .last_vote_timestamp = 100, .kind = .update };
    lv.entries[2] = .{ .last_vote_slot = 100, .last_vote_timestamp = 200, .kind = .update };

    // current_slot == last_vote_slot: no projection offset. Sorted
    // by estimate asc: (100, 30), (200, 60), (300, 10). Total = 100,
    // half = 50. acc after first = 30 (not > 50); after second = 90
    // (> 50) → estimate = 200.
    try std.testing.expectEqual(
        @as(?i64, 200),
        stakeWeightedTimestamp(ev, lv, 100, 400 * std.time.ns_per_ms, null, .DEFAULT),
    );
}

test "stakeWeightedTimestamp clamps against epoch-start drift" {
    // One voter with a wildly-slow timestamp; drift bound must clamp
    // forward to `epoch_start + poh_off + slow_bound`.
    const ev = try std.testing.allocator.create(EpochVoters);
    defer std.testing.allocator.destroy(ev);
    ev.init();
    const lv = try std.testing.allocator.create(LiveVoters);
    defer std.testing.allocator.destroy(lv);
    lv.reset();

    var pk0: Pubkey = .{ .data = .{0} ** 32 };
    pk0.data[0] = 1;
    ev.entries[0] = .{ .vote_pk = pk0, .stake = 100, .commission_bps = 0 };
    ev.len = 1;
    ev.total_stake = 100;
    try ev.by_vote_pk.insert(pk0, 0);

    // Voter's projected estimate = 1_000_000, way past poh-implied.
    lv.entries[0] = .{ .last_vote_slot = 100, .last_vote_timestamp = 1_000_000, .kind = .update };

    // 1000 slots at 400 ms = 400 s of poh offset. slow_pct = 150 →
    // slow_bound = 600 s. Cap = 1000 + 400 + 600 = 2000.
    const epoch_start: EpochStartTimestamp = .{ .slot = 100, .timestamp = 1000 };
    try std.testing.expectEqual(
        @as(?i64, 2000),
        stakeWeightedTimestamp(ev, lv, 1100, 400 * std.time.ns_per_ms, epoch_start, .DEFAULT),
    );
}

test "foldLandedVote overwrites admitted voter's row with .update" {
    const ev = try std.testing.allocator.create(EpochVoters);
    defer std.testing.allocator.destroy(ev);
    ev.init();
    const lv = try std.testing.allocator.create(LiveVoters);
    defer std.testing.allocator.destroy(lv);
    lv.reset();

    var pk_admit: Pubkey = .{ .data = .{0} ** 32 };
    pk_admit.data[0] = 0xAA;
    ev.entries[0] = .{ .vote_pk = pk_admit, .stake = 100, .commission_bps = 0 };
    ev.len = 1;
    ev.total_stake = 100;
    try ev.by_vote_pk.insert(pk_admit, 0);

    // Fresh row: .unpopulated.
    try std.testing.expectEqual(LiveVoter.Kind.unpopulated, lv.entries[0].kind);

    foldLandedVote(ev, lv, pk_admit, 500, 1_700_000_000);
    try std.testing.expectEqual(LiveVoter.Kind.update, lv.entries[0].kind);
    try std.testing.expectEqual(@as(Slot, 500), lv.entries[0].last_vote_slot);
    try std.testing.expectEqual(@as(i64, 1_700_000_000), lv.entries[0].last_vote_timestamp);

    // Subsequent fold overwrites in place.
    foldLandedVote(ev, lv, pk_admit, 501, 1_700_000_001);
    try std.testing.expectEqual(@as(Slot, 501), lv.entries[0].last_vote_slot);
    try std.testing.expectEqual(@as(i64, 1_700_000_001), lv.entries[0].last_vote_timestamp);
}

test "foldLandedVote is a no-op for non-admitted voters" {
    const ev = try std.testing.allocator.create(EpochVoters);
    defer std.testing.allocator.destroy(ev);
    ev.init();
    const lv = try std.testing.allocator.create(LiveVoters);
    defer std.testing.allocator.destroy(lv);
    lv.reset();

    var pk_stranger: Pubkey = .{ .data = .{0} ** 32 };
    pk_stranger.data[0] = 0xCC;

    // Nothing admitted. Fold must not touch any live row.
    foldLandedVote(ev, lv, pk_stranger, 999, 1_700_000_042);
    for (lv.entries) |row| {
        try std.testing.expectEqual(LiveVoter.Kind.unpopulated, row.kind);
    }
}
