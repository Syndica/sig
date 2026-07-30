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
const util = @import("../util.zig");

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
    /// `commission_bps` is carried across from
    /// `VersionedEpochStakes.VoteAccountEntry.commission_bps`, which
    /// the snapshot parser extracts from each vote-account data
    /// blob during `VersionedEpochStakes.read`.
    ///
    /// `total_stake` is summed from `entries[]`. Agave's
    /// authoritative total is accumulated unconditionally over the
    /// full vote-accounts map (including zero-stake rows) in
    /// `parse_epoch_vote_accounts`
    /// (https://github.com/anza-xyz/agave/blob/802264fcc093dc041a991e07d3196a96254b912e/runtime/src/epoch_stakes.rs#L337-L371)
    /// and serialized as `entry.total_stake`; the two agree when the
    /// snapshot's `vote_accounts` slice enumerates every summed row.
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
                .commission_bps = src.commission_bps,
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

/// Root-map capacity for the delegator → delegation table. Sized
/// with headroom over mainnet's ~600k stake accounts. Power-of-two
/// as required by `FixedPubkeyMap`; the effective occupancy budget
/// is half of this per its 2× load-factor invariant.
pub const MAX_STAKE_DELEGATIONS_ROOT_CAP: usize = 1 << 20;

/// Shared delta arena capacity. Bounds the total number of
/// stake-delegation mutations coexisting across all unrooted forks
/// between root advances. Sized with ~40× headroom over the
/// largest single-boundary redelegation cascade seen on mainnet
/// (~5k mutations); a full arena at 131k nodes represents ~433
/// slots of continuous churn at the historical peak of ~300
/// mutations/slot, well past any plausible unrooted depth.
///
/// See `stakes-v2-proposal-v2.md` §11.3 for why this is a hard
/// cap: OOM is treated as fatal, since it implies replay's
/// root-advance schedule is falling further behind than any
/// realistic consensus event can produce.
pub const MAX_STAKE_DELTA_NODES: usize = 1 << 17;

/// One delegator's current delegation state. Populated at boot
/// from each stake account's `StakeStateV2::Stake` variant.
///
/// `credits_observed` is carried alongside the delegation so
/// partitioned-rewards paths can attribute earnings without a
/// second accounts_db read at reward time.
pub const StakeDelegation = extern struct {
    voter_pk: Pubkey, //             32
    stake: u64, //                    8
    activation_epoch: Epoch, //       8
    deactivation_epoch: Epoch, //     8
    credits_observed: u64, //         8
}; //                                64 B

comptime {
    std.debug.assert(@sizeOf(StakeDelegation) == 64);
}

/// Rooted delegator → delegation table.
///
/// Populated once at boot (walking every stake account through
/// accounts_db) and mutated in place afterwards:
/// - At every root advance, the winning fork's ancestor chain of
///   `StakeDeltaNode`s is folded in (upserts / tombstones).
/// - During partitioned reward distribution at epoch start,
///   `credits_observed` is bumped in-row on each affected
///   delegation without any accounts_db round-trip.
///
/// A `FixedPubkeyMap` value of a 64 B `StakeDelegation` — the
/// table backing storage is `keys[cap] + values[cap]`, i.e.
/// `cap * 96 B` per instance (~96 MB at
/// `MAX_STAKE_DELEGATIONS_ROOT_CAP`).
pub const StakeDelegationsRoot = collections.FixedPubkeyMap(
    StakeDelegation,
    MAX_STAKE_DELEGATIONS_ROOT_CAP,
);

/// One landed stake-delegation mutation, held in the shared
/// `StakeDeltaArena`. Each node is owned by exactly one block —
/// the block on which its stake-ix committed — and chained
/// newest-first onto that block's `stake_delta_head` entry.
///
/// The block-tree parent link is the sole spine along which
/// ancestor deltas are reached: reads walk their own block's
/// head, then their parent's head, and so on up to the current
/// rooted block. No node is ever shared across two blocks, so
/// prune of a losing fork just walks and frees its own head chain.
///
/// The `next` field serves dual duty via `StakeDeltaArena`'s
/// intrusive free list: when the node is allocated, `next`
/// chain-links siblings on the same block; when freed, `next`
/// links the node into the arena's free list. Callers should
/// treat all other fields as undefined when the node is on the
/// free list.
///
/// See `stakes-v2-proposal-v2.md` §6.
pub const StakeDeltaNode = extern struct {
    delegator_pk: Pubkey, //                              32
    delegation: StakeDelegation, //                       64
    kind: Kind, //                                         1
    _pad: [3]u8 = @splat(0), //                            3
    next: StakeDeltaArena.Id.Optional, //                  4

    pub const Kind = enum(u8) {
        /// Delegator's row was created or updated on this block.
        /// `delegation` holds the post-tx state.
        upsert = 0,
        /// Delegator's account was closed on this block.
        /// `delegation` is undefined.
        tombstone = 1,
    };
}; //                                                    104 B

comptime {
    std.debug.assert(@sizeOf(StakeDeltaNode) == 104);
}

/// Shared arena of `StakeDeltaNode`s. Every delta node lives here,
/// referenced by `stake_delta_head[block]` chains. Inline
/// extern struct so it can be embedded directly in
/// `ReplayStakes` without a separate backing region.
///
/// Uses an intrusive free list on `StakeDeltaNode.next`: freed
/// nodes' `next` points to the previous free-head; the head
/// itself is the arena's `free_head`.
pub const StakeDeltaArena = extern struct {
    nodes: [MAX_STAKE_DELTA_NODES]StakeDeltaNode,
    /// Head of the free list. `.null` iff the arena is exhausted.
    free_head: Id.Optional,

    pub const Id = enum(u32) {
        _,

        pub fn index(self: Id) u32 {
            return @intFromEnum(self);
        }

        pub const Optional = util.PackedOptional(Id, std.math.maxInt(u32));
    };

    comptime {
        std.debug.assert(MAX_STAKE_DELTA_NODES < std.math.maxInt(u32));
    }

    /// Initialise the arena to fully-empty state: every node on
    /// the free list, chained 0 → 1 → ... → cap-1 → null.
    pub fn init(self: *StakeDeltaArena) void {
        for (self.nodes[0 .. MAX_STAKE_DELTA_NODES - 1], 0..) |*n, i| {
            n.* = undefined;
            n.next = .init(@enumFromInt(i + 1));
        }
        self.nodes[MAX_STAKE_DELTA_NODES - 1] = undefined;
        self.nodes[MAX_STAKE_DELTA_NODES - 1].next = .null;
        self.free_head = .init(@enumFromInt(0));
    }

    /// Allocate a node. Caller populates every field.
    /// `error.OutOfSpace` iff the arena is full — treat as fatal
    /// per `stakes-v2-proposal-v2.md` §11.3.
    pub fn createId(self: *StakeDeltaArena) !Id {
        const head = self.free_head.opt() orelse return error.OutOfSpace;
        self.free_head = self.nodes[head.index()].next;
        return head;
    }

    /// Return a node to the free list. `id` must have been
    /// obtained from a matching `createId` call and not already
    /// destroyed.
    pub fn destroyId(self: *StakeDeltaArena, id: Id) void {
        self.nodes[id.index()] = undefined;
        self.nodes[id.index()].next = self.free_head;
        self.free_head = .init(id);
    }

    pub fn indexToPtr(self: *StakeDeltaArena, id: Id) *StakeDeltaNode {
        return &self.nodes[id.index()];
    }

    pub fn indexToConstPtr(self: *const StakeDeltaArena, id: Id) *const StakeDeltaNode {
        return &self.nodes[id.index()];
    }
};

/// Per-block running `(effective, activating, deactivating)`
/// triple used by the `StakeHistory` sysvar update path.
///
/// Copied parent → child at `onBlockCreate`; maintained
/// incrementally by the committer as each stake-ix lands (the
/// exec tile has the pre-state in hand, so the delta is a
/// three-way subtract with no fork-aware cache read).
///
/// See `stakes-v2-proposal-v2.md` §6.2 / §11.4 for the
/// snapshot-at-boundary semantics: these three values are exact
/// for the epoch they were computed in; boundary derivation
/// recomputes them against the new epoch's activation state.
pub const StakeAggregates = extern struct {
    effective: u64, //    8
    activating: u64, //   8
    deactivating: u64, // 8

    pub const ZERO: StakeAggregates = .{
        .effective = 0,
        .activating = 0,
        .deactivating = 0,
    };
}; //                    24 B

comptime {
    std.debug.assert(@sizeOf(StakeAggregates) == 24);
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
    /// Rooted delegator → delegation table. Populated once at boot
    /// from accounts_db and mutated at each root advance (fold of
    /// the winning fork's ancestor delta chain) and during
    /// partitioned reward distribution (`credits_observed` bumps).
    stake_delegations_root: StakeDelegationsRoot,
    /// Shared arena of `StakeDeltaNode`s. All in-flight
    /// stake-delegation mutations across all unrooted forks share
    /// this pool; each node is chained onto exactly one block's
    /// `stake_delta_head` entry, freed on that block's fold-into-
    /// root or on that block's prune.
    stake_delta_arena: StakeDeltaArena,
    /// Per-block head of the arena chain owned by that block.
    /// `.null` means "no stake-ix landed on this block yet". Reads
    /// walk this head, then follow `replay.Node.parent` up the
    /// block tree to reach ancestor deltas. Zeroed to `.null` at
    /// `onBlockCreate` — deltas are per-block, never shared across
    /// parent/child.
    stake_delta_head: [replay.BlockPool.capacity]StakeDeltaArena.Id.Optional,
    /// Per-block running `(effective, activating, deactivating)`
    /// triple for the `StakeHistory` sysvar. Byte-copied
    /// parent → child at `onBlockCreate`; maintained incrementally
    /// by the committer on each stake-ix.
    stake_aggregates: [replay.BlockPool.capacity]StakeAggregates,
    /// **Provisional.** Hangs the epoch-boundary hard-stop off a
    /// single field. Once boundary derivation lands and replay
    /// tracks `current` / `t_minus_1` / `t_minus_2` rotation slots,
    /// the epoch of any given slot is derivable from the rotation
    /// state and this field is deleted.
    boot_epoch: Epoch,
    /// **Provisional.** First slot of the epoch immediately after
    /// `boot_epoch`. Slots at or beyond this trip
    /// `ensureSlotInBootEpoch` — the hard-stop for the
    /// not-yet-implemented boundary path. Cached at boot so the
    /// hot exec path avoids a per-slot `getEpoch` division.
    /// Deleted with `boot_epoch`.
    first_slot_of_next_epoch: Slot,

    /// Zero-init the struct to a well-defined empty state. Actual
    /// data is populated by the snapshot boot loader and by the
    /// root-block setup path.
    pub fn init(self: *ReplayStakes) void {
        self.epoch_voters.init();
        for (&self.live_voters) |*lv| lv.reset();
        self.stake_delegations_root.init();
        self.stake_delta_arena.init();
        for (&self.stake_delta_head) |*h| h.* = .null;
        for (&self.stake_aggregates) |*a| a.* = StakeAggregates.ZERO;
        self.boot_epoch = 0;
        self.first_slot_of_next_epoch = 0;
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
        const schedule = &manifest.bank_fields.epoch_schedule;
        self.boot_epoch = schedule.getEpoch(root_slot);
        self.first_slot_of_next_epoch = schedule.getFirstSlotInEpoch(self.boot_epoch + 1);

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
    /// slot boundary or a fork within a slot).
    ///
    /// Copies the parent's `LiveVoters` and `stake_aggregates`
    /// slots into the child, and resets the child's
    /// `stake_delta_head` to `.null` — ancestor deltas are reached
    /// by walking `replay.Node.parent`, not by copy.
    ///
    /// Not called for same-slot canonical extensions — those reuse
    /// the parent's `BlockRef` unchanged (see
    /// `replay.setChildBlockRef`).
    pub fn onBlockCreate(
        self: *ReplayStakes,
        parent: replay.BlockRef,
        child: replay.BlockRef,
    ) void {
        // Explicit @memcpy on the byte view — struct-assignment of
        // a ~48 KB value can pass through a stack temporary in
        // Debug mode; byte-level memcpy stays in place.
        @memcpy(
            std.mem.asBytes(&self.live_voters[child.index()]),
            std.mem.asBytes(&self.live_voters[parent.index()]),
        );
        self.stake_aggregates[child.index()] = self.stake_aggregates[parent.index()];
        self.stake_delta_head[child.index()] = .null;
    }

    /// Hard-stop guard for the not-yet-implemented boundary path.
    /// Called from replay at every new-slot event; returns
    /// `error.EpochBoundaryNotYetImplemented` when a fork tries to
    /// enter the epoch after `boot_epoch`.
    ///
    /// Deleted when boundary derivation lands.
    pub fn ensureSlotInBootEpoch(self: *const ReplayStakes, slot: Slot) !void {
        if (slot >= self.first_slot_of_next_epoch) {
            return error.EpochBoundaryNotYetImplemented;
        }
    }
};

/// Fold a landed stake-ix upsert into `block`'s delta chain and
/// running `stake_aggregates` triple.
///
/// - `delegator_pk`: the stake account whose delegation changed.
/// - `post_delegation`: the delegator's new state after the ix.
/// - `pre_contribution`: what the delegator contributed to
///   `(effective, activating, deactivating)` immediately before
///   this ix on this block's view. Zero for a newly-created stake
///   account.
/// - `post_contribution`: what the delegator contributes after
///   this ix. Both are computed by the exec tile from the
///   pre/post `StakeStateV2` + current epoch + stake_history —
///   the primitive is pure with respect to that computation.
///
/// The `next` link on the arena node points at the previous head
/// of `block`'s chain, so ancestor deltas remain reachable via
/// the block-tree parent walk (they live under other blocks'
/// heads).
///
/// Errors:
/// - `error.OutOfSpace` if the arena is exhausted. Treat as
///   fatal per `stakes-v2-proposal-v2.md` §11.3.
///
/// Not yet reachable at runtime — the exec tile grows a stake
/// program next; this is the sink the committer will call once
/// per landed stake-account write.
pub fn foldStakeIxUpsert(
    stakes: *ReplayStakes,
    block: replay.BlockRef,
    delegator_pk: Pubkey,
    post_delegation: StakeDelegation,
    pre_contribution: StakeAggregates,
    post_contribution: StakeAggregates,
) !void {
    const id = try stakes.stake_delta_arena.createId();
    stakes.stake_delta_arena.indexToPtr(id).* = .{
        .delegator_pk = delegator_pk,
        .delegation = post_delegation,
        .kind = .upsert,
        .next = stakes.stake_delta_head[block.index()],
    };
    stakes.stake_delta_head[block.index()] = .init(id);

    applyAggregateDelta(
        &stakes.stake_aggregates[block.index()],
        pre_contribution,
        post_contribution,
    );
}

/// Fold a landed stake-account closure into `block`'s delta chain
/// and running aggregates. Post state is implicitly zero — the
/// account no longer exists on this block.
///
/// `delegation_at_close` is stashed on the arena node purely for
/// debug / audit; the fold-into-root path only reads `.kind` for
/// tombstones and treats `delegation` as undefined. See
/// `stakes-v2-proposal-v2.md` §6.
///
/// Errors: `error.OutOfSpace` on arena exhaustion.
pub fn foldStakeIxTombstone(
    stakes: *ReplayStakes,
    block: replay.BlockRef,
    delegator_pk: Pubkey,
    delegation_at_close: StakeDelegation,
    pre_contribution: StakeAggregates,
) !void {
    const id = try stakes.stake_delta_arena.createId();
    stakes.stake_delta_arena.indexToPtr(id).* = .{
        .delegator_pk = delegator_pk,
        .delegation = delegation_at_close,
        .kind = .tombstone,
        .next = stakes.stake_delta_head[block.index()],
    };
    stakes.stake_delta_head[block.index()] = .init(id);

    applyAggregateDelta(
        &stakes.stake_aggregates[block.index()],
        pre_contribution,
        StakeAggregates.ZERO,
    );
}

/// `agg += post - pre`, applied field-wise with wrapping
/// arithmetic. The true totals across a block's aggregate history
/// are non-negative by construction (the sum of `post_contribution`
/// terms across every stake-ix and every delegator on the block's
/// ancestor chain), so wrapping is safe: intermediate values may
/// wrap when a single ix's `pre > post`, but the cumulative
/// running sum matches the mathematically-correct total.
fn applyAggregateDelta(
    agg: *StakeAggregates,
    pre: StakeAggregates,
    post: StakeAggregates,
) void {
    agg.effective +%= post.effective -% pre.effective;
    agg.activating +%= post.activating -% pre.activating;
    agg.deactivating +%= post.deactivating -% pre.deactivating;
}

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

test "StakeAggregates.ZERO is all zero" {
    const a: StakeAggregates = StakeAggregates.ZERO;
    try std.testing.expectEqual(@as(u64, 0), a.effective);
    try std.testing.expectEqual(@as(u64, 0), a.activating);
    try std.testing.expectEqual(@as(u64, 0), a.deactivating);
}

test "StakeDeltaArena: alloc + chain + destroy" {
    // ~13.6 MB inline arena — page allocator to keep it off the
    // testing allocator's small heap.
    const arena = try std.heap.page_allocator.create(StakeDeltaArena);
    defer std.heap.page_allocator.destroy(arena);
    arena.init();

    var dpk: Pubkey = .{ .data = .{0} ** 32 };
    dpk.data[0] = 0xD0;
    var vpk: Pubkey = .{ .data = .{0} ** 32 };
    vpk.data[0] = 0xE0;

    const id_a = try arena.createId();
    const n_a = arena.indexToPtr(id_a);
    n_a.* = .{
        .delegator_pk = dpk,
        .delegation = .{
            .voter_pk = vpk,
            .stake = 1,
            .activation_epoch = 0,
            .deactivation_epoch = std.math.maxInt(Epoch),
            .credits_observed = 0,
        },
        .kind = .upsert,
        .next = .null,
    };

    const id_b = try arena.createId();
    const n_b = arena.indexToPtr(id_b);
    n_b.* = .{
        .delegator_pk = dpk,
        .delegation = undefined,
        .kind = .tombstone,
        .next = .init(id_a),
    };

    try std.testing.expectEqual(StakeDeltaNode.Kind.tombstone, n_b.kind);
    try std.testing.expectEqual(id_a, n_b.next.opt().?);
    try std.testing.expectEqual(StakeDeltaNode.Kind.upsert, arena.indexToPtr(n_b.next.opt().?).kind);

    // Destroy + realloc — id_b's slot should be reused (LIFO).
    arena.destroyId(id_b);
    const id_c = try arena.createId();
    try std.testing.expectEqual(id_b, id_c);

    arena.destroyId(id_c);
    arena.destroyId(id_a);
}

test "StakeDelegationsRoot insert / getPtrConst round-trip" {
    // ~96 MB at MAX_STAKE_DELEGATIONS_ROOT_CAP — too large for the
    // testing allocator, use the page allocator.
    const root = try std.heap.page_allocator.create(StakeDelegationsRoot);
    defer std.heap.page_allocator.destroy(root);
    root.init();

    var delegator: Pubkey = .{ .data = .{0} ** 32 };
    delegator.data[0] = 0xD1;
    var voter: Pubkey = .{ .data = .{0} ** 32 };
    voter.data[0] = 0xE1;

    try root.insert(delegator, .{
        .voter_pk = voter,
        .stake = 12_345,
        .activation_epoch = 10,
        .deactivation_epoch = std.math.maxInt(Epoch),
        .credits_observed = 42,
    });

    const found = root.getPtrConst(delegator) orelse return error.NotFound;
    try std.testing.expectEqual(voter.data, found.voter_pk.data);
    try std.testing.expectEqual(@as(u64, 12_345), found.stake);
    try std.testing.expectEqual(@as(u64, 42), found.credits_observed);
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
    va_ptr[0] = .{ .pubkey = pk_a, .stake = 100, .commission_bps = 0 };
    va_ptr[1] = .{ .pubkey = pk_b, .stake = 500, .commission_bps = 0 };
    va_ptr[2] = .{ .pubkey = pk_c, .stake = 300, .commission_bps = 0 };

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

test "ReplayStakes.onBlockCreate copies aggregates and resets delta head" {
    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    const parent_idx: usize = 5;
    const child_idx: usize = 11;

    stakes.stake_aggregates[parent_idx] = .{
        .effective = 1_000,
        .activating = 200,
        .deactivating = 50,
    };
    const parent_ref: replay.BlockRef = @enumFromInt(parent_idx);
    const child_ref: replay.BlockRef = @enumFromInt(child_idx);

    // Simulate the parent having accumulated one delta node.
    const parent_head_id = try stakes.stake_delta_arena.createId();
    const parent_node = stakes.stake_delta_arena.indexToPtr(parent_head_id);
    parent_node.* = .{
        .delegator_pk = .{ .data = .{0xD0} ++ .{0} ** 31 },
        .delegation = .{
            .voter_pk = .{ .data = .{0xE0} ++ .{0} ** 31 },
            .stake = 42,
            .activation_epoch = 3,
            .deactivation_epoch = std.math.maxInt(Epoch),
            .credits_observed = 0,
        },
        .kind = .upsert,
        .next = .null,
    };
    stakes.stake_delta_head[parent_idx] = .init(parent_head_id);

    stakes.onBlockCreate(parent_ref, child_ref);

    try std.testing.expectEqual(@as(u64, 1_000), stakes.stake_aggregates[child_idx].effective);
    try std.testing.expectEqual(@as(u64, 200), stakes.stake_aggregates[child_idx].activating);
    try std.testing.expectEqual(@as(u64, 50), stakes.stake_aggregates[child_idx].deactivating);

    // Child's head is fresh — the parent's chain is NOT shared.
    try std.testing.expectEqual(
        @as(?StakeDeltaArena.Id, null),
        stakes.stake_delta_head[child_idx].opt(),
    );
    // Parent's head is untouched.
    try std.testing.expectEqual(parent_head_id, stakes.stake_delta_head[parent_idx].opt().?);

    // Mutating the child's aggregate must not touch the parent's.
    stakes.stake_aggregates[child_idx].effective = 9_999;
    try std.testing.expectEqual(@as(u64, 1_000), stakes.stake_aggregates[parent_idx].effective);
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

test "ensureSlotInBootEpoch rejects slots at/beyond the boundary" {
    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    // Boot into epoch 5 [500..600).
    stakes.boot_epoch = 5;
    stakes.first_slot_of_next_epoch = 600;

    // In-epoch slots pass.
    try stakes.ensureSlotInBootEpoch(500);
    try stakes.ensureSlotInBootEpoch(599);

    // Boundary and beyond trip.
    try std.testing.expectError(error.EpochBoundaryNotYetImplemented, stakes.ensureSlotInBootEpoch(600));
    try std.testing.expectError(error.EpochBoundaryNotYetImplemented, stakes.ensureSlotInBootEpoch(1_000_000));
}

test "foldStakeIxUpsert: new delegation on empty block" {
    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    const b: replay.BlockRef = @enumFromInt(3);
    var dpk: Pubkey = .{ .data = .{0} ** 32 };
    dpk.data[0] = 0xD1;
    var vpk: Pubkey = .{ .data = .{0} ** 32 };
    vpk.data[0] = 0xE1;

    const post: StakeDelegation = .{
        .voter_pk = vpk,
        .stake = 1_000,
        .activation_epoch = 5,
        .deactivation_epoch = std.math.maxInt(Epoch),
        .credits_observed = 0,
    };

    try foldStakeIxUpsert(
        stakes,
        b,
        dpk,
        post,
        StakeAggregates.ZERO,
        .{ .effective = 0, .activating = 1_000, .deactivating = 0 },
    );

    const head = stakes.stake_delta_head[b.index()].opt().?;
    const node = stakes.stake_delta_arena.indexToConstPtr(head);
    try std.testing.expectEqual(StakeDeltaNode.Kind.upsert, node.kind);
    try std.testing.expectEqual(dpk.data, node.delegator_pk.data);
    try std.testing.expectEqual(vpk.data, node.delegation.voter_pk.data);
    try std.testing.expectEqual(@as(u64, 1_000), node.delegation.stake);
    try std.testing.expectEqual(@as(?StakeDeltaArena.Id, null), node.next.opt());

    try std.testing.expectEqual(@as(u64, 0), stakes.stake_aggregates[b.index()].effective);
    try std.testing.expectEqual(@as(u64, 1_000), stakes.stake_aggregates[b.index()].activating);
    try std.testing.expectEqual(@as(u64, 0), stakes.stake_aggregates[b.index()].deactivating);
}

test "foldStakeIxUpsert: chains newest-first, ancestor node reachable via .next" {
    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    const b: replay.BlockRef = @enumFromInt(7);
    var dpk_a: Pubkey = .{ .data = .{0} ** 32 };
    dpk_a.data[0] = 0xA0;
    var dpk_b: Pubkey = .{ .data = .{0} ** 32 };
    dpk_b.data[0] = 0xB0;
    var vpk: Pubkey = .{ .data = .{0} ** 32 };
    vpk.data[0] = 0xE1;

    const post_a: StakeDelegation = .{
        .voter_pk = vpk,
        .stake = 100,
        .activation_epoch = 5,
        .deactivation_epoch = std.math.maxInt(Epoch),
        .credits_observed = 0,
    };
    const post_b: StakeDelegation = .{
        .voter_pk = vpk,
        .stake = 300,
        .activation_epoch = 5,
        .deactivation_epoch = std.math.maxInt(Epoch),
        .credits_observed = 0,
    };

    try foldStakeIxUpsert(stakes, b, dpk_a, post_a, StakeAggregates.ZERO, .{
        .effective = 100,
        .activating = 0,
        .deactivating = 0,
    });
    try foldStakeIxUpsert(stakes, b, dpk_b, post_b, StakeAggregates.ZERO, .{
        .effective = 300,
        .activating = 0,
        .deactivating = 0,
    });

    // Newest-first: head is b, its next is a.
    const head = stakes.stake_delta_head[b.index()].opt().?;
    const head_node = stakes.stake_delta_arena.indexToConstPtr(head);
    try std.testing.expectEqual(dpk_b.data, head_node.delegator_pk.data);

    const next = head_node.next.opt().?;
    const next_node = stakes.stake_delta_arena.indexToConstPtr(next);
    try std.testing.expectEqual(dpk_a.data, next_node.delegator_pk.data);
    try std.testing.expectEqual(@as(?StakeDeltaArena.Id, null), next_node.next.opt());

    try std.testing.expectEqual(@as(u64, 400), stakes.stake_aggregates[b.index()].effective);
}

test "foldStakeIxTombstone: aggregate subtracts pre-contribution" {
    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    const b: replay.BlockRef = @enumFromInt(4);
    var dpk: Pubkey = .{ .data = .{0} ** 32 };
    dpk.data[0] = 0xD2;
    var vpk: Pubkey = .{ .data = .{0} ** 32 };
    vpk.data[0] = 0xE2;

    // Seed the block's aggregate as if a prior upsert had contributed
    // 500 effective + 100 activating.
    stakes.stake_aggregates[b.index()] = .{
        .effective = 500,
        .activating = 100,
        .deactivating = 0,
    };

    const at_close: StakeDelegation = .{
        .voter_pk = vpk,
        .stake = 500,
        .activation_epoch = 3,
        .deactivation_epoch = std.math.maxInt(Epoch),
        .credits_observed = 99,
    };
    try foldStakeIxTombstone(stakes, b, dpk, at_close, .{
        .effective = 500,
        .activating = 100,
        .deactivating = 0,
    });

    const head = stakes.stake_delta_head[b.index()].opt().?;
    const node = stakes.stake_delta_arena.indexToConstPtr(head);
    try std.testing.expectEqual(StakeDeltaNode.Kind.tombstone, node.kind);
    try std.testing.expectEqual(dpk.data, node.delegator_pk.data);

    try std.testing.expectEqual(@as(u64, 0), stakes.stake_aggregates[b.index()].effective);
    try std.testing.expectEqual(@as(u64, 0), stakes.stake_aggregates[b.index()].activating);
    try std.testing.expectEqual(@as(u64, 0), stakes.stake_aggregates[b.index()].deactivating);
}

test "foldStakeIxUpsert: aggregate handles negative net change via wrapping" {
    // Delegator D shrinks stake from 1000 -> 400. pre.effective=1000,
    // post.effective=400 => the block's aggregate delta is -600.
    // Wrapping u64 subtraction produces the same running total as a
    // signed model.
    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    const b: replay.BlockRef = @enumFromInt(9);
    var dpk: Pubkey = .{ .data = .{0} ** 32 };
    dpk.data[0] = 0xD3;
    var vpk: Pubkey = .{ .data = .{0} ** 32 };
    vpk.data[0] = 0xE3;

    // Seed as if 1000 effective was already credited.
    stakes.stake_aggregates[b.index()] = .{
        .effective = 1_000,
        .activating = 0,
        .deactivating = 0,
    };

    const post: StakeDelegation = .{
        .voter_pk = vpk,
        .stake = 400,
        .activation_epoch = 3,
        .deactivation_epoch = std.math.maxInt(Epoch),
        .credits_observed = 0,
    };
    try foldStakeIxUpsert(
        stakes,
        b,
        dpk,
        post,
        .{ .effective = 1_000, .activating = 0, .deactivating = 0 },
        .{ .effective = 400, .activating = 0, .deactivating = 0 },
    );

    try std.testing.expectEqual(@as(u64, 400), stakes.stake_aggregates[b.index()].effective);
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------
// Exercise the primitives end-to-end at the stakes-module level:
//   boot -> query -> fold -> aggregate, across fork trees.
// These do not touch replay's fec-set / block_pool machinery — that
// path is covered by the bbt-replay black-box test.

test "integration: boot -> solGetEpochStake -> foldLandedVote -> stakeWeightedTimestamp" {
    const VES = solana.snapshot.ExtraFields.VersionedEpochStakes;
    const VoteAccountEntry = VES.VoteAccountEntry;

    // Synthesize a snapshot memory blob with three admitted voters,
    // stakes 100 / 250 / 650 — total 1000.
    var buf: [4096]u8 align(@alignOf(VoteAccountEntry)) = @splat(0);
    const va_off: u32 = 128;
    const va_ptr: [*]VoteAccountEntry = @ptrCast(@alignCast(&buf[va_off]));

    var pk_a: Pubkey = .{ .data = .{0} ** 32 };
    pk_a.data[0] = 0xA1;
    var pk_b: Pubkey = .{ .data = .{0} ** 32 };
    pk_b.data[0] = 0xB2;
    var pk_c: Pubkey = .{ .data = .{0} ** 32 };
    pk_c.data[0] = 0xC3;
    var pk_stranger: Pubkey = .{ .data = .{0} ** 32 };
    pk_stranger.data[0] = 0xFF;

    va_ptr[0] = .{ .pubkey = pk_a, .stake = 100, .commission_bps = 0 };
    va_ptr[1] = .{ .pubkey = pk_b, .stake = 250, .commission_bps = 0 };
    va_ptr[2] = .{ .pubkey = pk_c, .stake = 650, .commission_bps = 0 };

    const entry: VES = .{
        .epoch = 7,
        .total_stake = 0,
        .vote_accounts = .{ .offset = va_off, .len = 3 },
        .node_to_vote_accounts = .{},
        .epoch_authorized_voters = .{},
    };

    const ev = try std.testing.allocator.create(EpochVoters);
    defer std.testing.allocator.destroy(ev);
    try ev.loadFromVersionedEpochStakes(&entry, &buf);

    // Boot invariants: sorted desc, total_stake sums, all lookups hit.
    try std.testing.expectEqual(@as(u16, 3), ev.len);
    try std.testing.expectEqual(@as(u64, 1000), ev.total_stake);
    try std.testing.expectEqual(@as(u64, 650), ev.entries[0].stake);

    // Syscall: null -> total; hit -> voter's stake; miss -> 0.
    try std.testing.expectEqual(@as(u64, 1000), solGetEpochStake(ev, null));
    try std.testing.expectEqual(@as(u64, 250), solGetEpochStake(ev, &pk_b));
    try std.testing.expectEqual(@as(u64, 0), solGetEpochStake(ev, &pk_stranger));

    // Vote-tx fold: three landed votes on a fresh LiveVoters.
    const lv = try std.testing.allocator.create(LiveVoters);
    defer std.testing.allocator.destroy(lv);
    lv.reset();

    foldLandedVote(ev, lv, pk_a, 1000, 1_700_000_005);
    foldLandedVote(ev, lv, pk_b, 1000, 1_700_000_010);
    foldLandedVote(ev, lv, pk_c, 1000, 1_700_000_015);
    foldLandedVote(ev, lv, pk_stranger, 1000, 1_700_000_999); // no-op: unadmitted.

    // Stake-weighted median: sorted by estimate asc:
    // (a, 5, 100), (b, 10, 250), (c, 15, 650). Half = 500.
    // acc after a = 100 (≤ 500); after b = 350 (≤ 500); after c = 1000 (> 500)
    // → estimate = c's timestamp = 1_700_000_015.
    try std.testing.expectEqual(
        @as(?i64, 1_700_000_015),
        stakeWeightedTimestamp(ev, lv, 1000, 400 * std.time.ns_per_ms, null, .DEFAULT),
    );
}

test "integration: fork of depth 3 propagates via onBlockCreate, then diverges" {
    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    var pk_a: Pubkey = .{ .data = .{0} ** 32 };
    pk_a.data[0] = 1;
    var pk_b: Pubkey = .{ .data = .{0} ** 32 };
    pk_b.data[0] = 2;
    stakes.epoch_voters.entries[0] = .{ .vote_pk = pk_a, .stake = 100, .commission_bps = 0 };
    stakes.epoch_voters.entries[1] = .{ .vote_pk = pk_b, .stake = 200, .commission_bps = 0 };
    stakes.epoch_voters.len = 2;
    stakes.epoch_voters.total_stake = 300;
    try stakes.epoch_voters.by_vote_pk.insert(pk_a, 0);
    try stakes.epoch_voters.by_vote_pk.insert(pk_b, 1);

    const root_idx: usize = 0;
    const a_idx: usize = 1;
    const b_idx: usize = 2;
    const c_idx: usize = 3;

    const root_ref: replay.BlockRef = @enumFromInt(root_idx);
    const a_ref: replay.BlockRef = @enumFromInt(a_idx);
    const b_ref: replay.BlockRef = @enumFromInt(b_idx);
    const c_ref: replay.BlockRef = @enumFromInt(c_idx);

    // Root: pk_a votes at slot 100.
    foldLandedVote(&stakes.epoch_voters, &stakes.live_voters[root_idx], pk_a, 100, 1_700_000_100);

    // Root -> A: memcpy carries pk_a's row; then pk_b votes at A.
    stakes.onBlockCreate(root_ref, a_ref);
    try std.testing.expectEqual(@as(Slot, 100), stakes.live_voters[a_idx].entries[0].last_vote_slot);
    foldLandedVote(&stakes.epoch_voters, &stakes.live_voters[a_idx], pk_b, 200, 1_700_000_200);

    // A -> B: both rows carried; pk_a votes again at B.
    stakes.onBlockCreate(a_ref, b_ref);
    try std.testing.expectEqual(@as(Slot, 200), stakes.live_voters[b_idx].entries[1].last_vote_slot);
    foldLandedVote(&stakes.epoch_voters, &stakes.live_voters[b_idx], pk_a, 300, 1_700_000_300);

    // B -> C: everything up to B carried.
    stakes.onBlockCreate(b_ref, c_ref);
    try std.testing.expectEqual(@as(Slot, 300), stakes.live_voters[c_idx].entries[0].last_vote_slot);
    try std.testing.expectEqual(@as(Slot, 200), stakes.live_voters[c_idx].entries[1].last_vote_slot);
    try std.testing.expectEqual(@as(i64, 1_700_000_300), stakes.live_voters[c_idx].entries[0].last_vote_timestamp);
    try std.testing.expectEqual(@as(i64, 1_700_000_200), stakes.live_voters[c_idx].entries[1].last_vote_timestamp);

    // Root remains untouched by descendant folds.
    try std.testing.expectEqual(@as(Slot, 100), stakes.live_voters[root_idx].entries[0].last_vote_slot);
    try std.testing.expectEqual(LiveVoter.Kind.unpopulated, stakes.live_voters[root_idx].entries[1].kind);
}

test "integration: sibling forks stay isolated" {
    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    var pk_a: Pubkey = .{ .data = .{0} ** 32 };
    pk_a.data[0] = 1;
    var pk_b: Pubkey = .{ .data = .{0} ** 32 };
    pk_b.data[0] = 2;
    stakes.epoch_voters.entries[0] = .{ .vote_pk = pk_a, .stake = 100, .commission_bps = 0 };
    stakes.epoch_voters.entries[1] = .{ .vote_pk = pk_b, .stake = 200, .commission_bps = 0 };
    stakes.epoch_voters.len = 2;
    stakes.epoch_voters.total_stake = 300;
    try stakes.epoch_voters.by_vote_pk.insert(pk_a, 0);
    try stakes.epoch_voters.by_vote_pk.insert(pk_b, 1);

    const parent_idx: usize = 10;
    const left_idx: usize = 11;
    const right_idx: usize = 12;
    const parent_ref: replay.BlockRef = @enumFromInt(parent_idx);
    const left_ref: replay.BlockRef = @enumFromInt(left_idx);
    const right_ref: replay.BlockRef = @enumFromInt(right_idx);

    // Parent: pk_a votes.
    foldLandedVote(&stakes.epoch_voters, &stakes.live_voters[parent_idx], pk_a, 500, 1_700_000_500);

    // Fork left: pk_b votes on the left branch only.
    stakes.onBlockCreate(parent_ref, left_ref);
    foldLandedVote(&stakes.epoch_voters, &stakes.live_voters[left_idx], pk_b, 501, 1_700_000_501);

    // Fork right: pk_a re-votes on the right branch with a different timestamp.
    stakes.onBlockCreate(parent_ref, right_ref);
    foldLandedVote(&stakes.epoch_voters, &stakes.live_voters[right_idx], pk_a, 502, 1_700_000_502);

    // Left branch: pk_a inherited from parent, pk_b landed on left.
    try std.testing.expectEqual(@as(Slot, 500), stakes.live_voters[left_idx].entries[0].last_vote_slot);
    try std.testing.expectEqual(@as(Slot, 501), stakes.live_voters[left_idx].entries[1].last_vote_slot);

    // Right branch: pk_a re-voted on right (updated), pk_b never landed here.
    try std.testing.expectEqual(@as(Slot, 502), stakes.live_voters[right_idx].entries[0].last_vote_slot);
    try std.testing.expectEqual(LiveVoter.Kind.unpopulated, stakes.live_voters[right_idx].entries[1].kind);

    // Parent unchanged by either descendant.
    try std.testing.expectEqual(@as(Slot, 500), stakes.live_voters[parent_idx].entries[0].last_vote_slot);
    try std.testing.expectEqual(LiveVoter.Kind.unpopulated, stakes.live_voters[parent_idx].entries[1].kind);
}
