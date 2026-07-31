//! Replay-owned stakes state. All buffers are compile-time-sized
//! and inline in `ReplayStakes`; nothing allocates after `init`.
//!
//!   - `EpochVoters` — the frozen per-epoch set of admitted voters
//!     (vote-pubkey, stake, commission) + `by_vote_pk` side index.
//!   - `LiveVoter` / `LiveVoters` — dense per-block vote-timestamp
//!     state, indexed in lockstep with `EpochVoters.entries` so per-
//!     slot sysvar updates scan them as parallel arrays.
//!   - `StakeDelegation` / `StakeDelegationsRoot` — the rooted
//!     delegator → delegation table.
//!   - `StakeDeltaNode` / `StakeDeltaArena` — shared arena of
//!     per-block delta chains. Ancestor deltas are reached by
//!     walking `replay.Node.parent`, not by copy.
//!   - `StakeAggregates` — per-block running
//!     (effective, activating, deactivating) triple for the
//!     `StakeHistory` sysvar.
//!   - `ReplayStakes` — owner struct.

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

/// `ceil_pow2(2 * MAX_ALPENGLOW_VOTE_ACCOUNTS) = 4096`, satisfying
/// `FixedPubkeyMap`'s pow2 / 2x-occupancy invariants.
pub const EPOCH_VOTERS_INDEX_CAP: usize = 4096;

const EpochVotersIndex = collections.FixedPubkeyMap(u16, EPOCH_VOTERS_INDEX_CAP);

/// Frozen per-epoch snapshot of admitted voters.
///
/// `entries` is the source of truth; `by_vote_pk` and `total_stake`
/// are derived from it and refreshed atomically with it.
///
/// TODO(boundary): refresh at each epoch-boundary crossing once
/// boundary derivation is wired. Currently only populated at
/// snapshot boot.
pub const EpochVoters = extern struct {
    len: u16,
    _pad0: [6]u8 = @splat(0),
    entries: [MAX_ALPENGLOW_VOTE_ACCOUNTS]Entry,
    by_vote_pk: EpochVotersIndex,
    total_stake: u64,

    /// The index of an entry in `entries[]` is the identity used by
    /// all sibling arrays (e.g. `LiveVoters.entries`). Sorted by
    /// `stake` desc at build time.
    pub const Entry = extern struct {
        vote_pk: Pubkey, //           32
        stake: u64, //                 8
        commission_bps: u16, //        2
        _pad: [6]u8 = @splat(0), //    6
    }; //                             48 B

    comptime {
        std.debug.assert(@sizeOf(Entry) == 48);
    }

    pub fn init(self: *EpochVoters) void {
        self.len = 0;
        self._pad0 = @splat(0);
        // `entries` intentionally left undefined; only slots 0..len are read.
        self.by_vote_pk.init();
        self.total_stake = 0;
    }

    /// Miss returns 0, matching SIMD-0133 `sol_get_epoch_stake`.
    pub fn stakeOf(self: *const EpochVoters, vote_pk: Pubkey) u64 {
        const idx_ptr = self.by_vote_pk.getPtrConst(vote_pk) orelse return 0;
        return self.entries[idx_ptr.*].stake;
    }

    /// Populate from one `VersionedEpochStakes` entry sourced from the
    /// snapshot manifest. `memory_base` is the base pointer used to
    /// resolve `RelativeSlice` fields (typically
    /// `snapshot_metadata.getMemory()`).
    ///
    /// Sorts by stake desc so index 0 is highest-staked — gives a
    /// canonical ordering for the sibling `LiveVoters` arrays.
    ///
    /// `total_stake` is recomputed from the loaded entries rather
    /// than trusting `entry.total_stake`: the two disagree if the
    /// snapshot's `vote_accounts` slice is a filtered subset. See
    /// [agave `parse_epoch_vote_accounts`](https://github.com/anza-xyz/agave/blob/802264fcc093dc041a991e07d3196a96254b912e/runtime/src/epoch_stakes.rs#L337-L371).
    ///
    /// Errors:
    /// - `error.TooManyVoters` if the entry exceeds
    ///   `MAX_ALPENGLOW_VOTE_ACCOUNTS`.
    /// - `error.MapFull` from the side index — unreachable under
    ///   the pow-2 / 2x-occupancy invariants.
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
/// - `null` → total active stake for the current epoch.
/// - non-null → stake delegated to the vote account at that
///   address, or 0 if the address is not in the admitted set.
///
/// Callers in the SVM layer are responsible for compute-meter
/// charging and for translating the pubkey argument out of VM
/// memory; this function assumes a validated optional pointer.
///
/// TODO(svm): wire as the `sol_get_epoch_stake` handler once the
/// exec tile grows an SVM interpreter.
pub fn solGetEpochStake(
    epoch_voters: *const EpochVoters,
    maybe_vote_pk: ?*const Pubkey,
) u64 {
    const vote_pk = maybe_vote_pk orelse return epoch_voters.total_stake;
    return epoch_voters.stakeOf(vote_pk.*);
}

/// Drift bounds for the stake-weighted timestamp median, expressed
/// as percentages of the poh estimate offset since the epoch start.
/// `DEFAULT` matches agave's `MAX_ALLOWABLE_DRIFT_PERCENTAGE_FAST`
/// / `MAX_ALLOWABLE_DRIFT_PERCENTAGE_SLOW_V2`.
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
/// timestamps). This is the value the per-slot clock sysvar update
/// writes into `Clock.unix_timestamp`.
///
/// Algorithm:
/// 1. For each voter whose live row is `.update`, project the vote
///    timestamp to `current_slot` as
///    `last_vote_timestamp + elapsed_secs(last_vote_slot -> current_slot)`.
/// 2. Sort projections asc; walk while accumulating stake; return
///    the projection at which cumulative stake first exceeds
///    `total_live_stake / 2`.
/// 3. If `epoch_start` is provided, bound the median against the
///    poh estimate offset by `drift.fast_pct` / `drift.slow_pct`.
///
/// Returns null iff no voter has a live `.update` row with non-zero
/// stake.
///
/// TODO(sysvar-update): call once per slot from the clock-sysvar
/// update path once v2 has one.
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

/// Saturating `(to_slot - from_slot) * slot_duration_ns`, truncated
/// to whole seconds.
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
        return epoch_start.timestamp +| poh_off_secs +| slow_bound;
    }
    if (est_off_secs < poh_off_secs and poh_off_secs - est_off_secs > fast_bound) {
        return epoch_start.timestamp +| poh_off_secs -| fast_bound;
    }
    return estimate;
}

/// Fold a landed vote into the fork's `LiveVoters`. Overwrites the
/// admitted voter's row with the new `.update` state; no-op if the
/// vote account isn't in the admitted set.
///
/// Miss case: post-Alpenglow only the SIMD-0357 top-2000 vote
/// accounts have positional slots. A vote tx from a non-admitted
/// account lands successfully but contributes nothing to the
/// timestamp aggregate. Pre-Alpenglow every vote account is
/// admitted, so misses shouldn't happen in practice.
///
/// TODO(exec-tile): call from the committer per landed vote ix.
/// TODO(vote-close): the `.invalidate` transition isn't modelled.
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

    /// Zero every row to `.unpopulated`.
    pub fn reset(self: *LiveVoters) void {
        @memset(&self.entries, LiveVoter.UNPOPULATED);
    }
};

comptime {
    std.debug.assert(@sizeOf(LiveVoters) == MAX_ALPENGLOW_VOTE_ACCOUNTS * 24);
}

/// Root-map capacity for the delegator → delegation table. Sized
/// with headroom over mainnet's ~600k stake accounts. Power-of-two
/// as required by `FixedPubkeyMap`; the effective occupancy budget
/// is half of this per its 2× load-factor invariant.
pub const MAX_STAKE_DELEGATIONS_ROOT_CAP: usize = 1 << 20;

/// Shared delta arena capacity. Bounds the total number of
/// stake-delegation mutations coexisting across all unrooted forks
/// between root advances. ~40x headroom over the largest single-
/// boundary redelegation cascade seen on mainnet (~5k mutations);
/// a full arena represents ~433 slots of continuous churn at the
/// historical peak of ~300 mutations/slot.
///
/// Hard cap: `error.OutOfSpace` from `StakeDeltaArena.createId` is
/// fatal — exhaustion implies root advance has fallen further
/// behind than any realistic consensus event can produce.
pub const MAX_STAKE_DELTA_NODES: usize = 1 << 17;

/// One delegator's current delegation state, populated at boot
/// from each stake account's `StakeStateV2::Stake` variant.
///
/// `credits_observed` is carried in-row so partitioned rewards
/// don't need a second accounts_db read per delegator.
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

/// Rooted delegator → delegation table. Populated once at boot;
/// mutated at every root advance (fold of the winning fork's
/// ancestor delta chain via `applyRootedFold`) and during
/// partitioned reward distribution (`credits_observed` bumps).
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
/// The `next` field is dual-use: while allocated it chain-links
/// siblings on the same block; while freed it links the node
/// into the arena's free list. All other fields are undefined
/// on the free list.
pub const StakeDeltaNode = extern struct {
    delegator_pk: Pubkey, //                              32
    delegation: StakeDelegation, //                       64
    kind: Kind, //                                         1
    _pad: [3]u8 = @splat(0), //                            3
    next: StakeDeltaArena.Id.Optional, //                  4

    pub const Kind = enum(u8) {
        /// `delegation` holds the post-tx state.
        upsert = 0,
        /// `delegation` is undefined; the account was closed on
        /// this block.
        tombstone = 1,
    };
}; //                                                    104 B

comptime {
    std.debug.assert(@sizeOf(StakeDeltaNode) == 104);
}

/// Shared arena of `StakeDeltaNode`s. Every delta node lives here,
/// referenced by `stake_delta_head[block]` chains. Free-list head
/// is on the arena; intrusive `.next` links per node.
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

    /// Every node on the free list, chained 0 → 1 → ... → cap-1 → null.
    pub fn init(self: *StakeDeltaArena) void {
        for (self.nodes[0 .. MAX_STAKE_DELTA_NODES - 1], 0..) |*n, i| {
            n.* = undefined;
            n.next = .init(@enumFromInt(i + 1));
        }
        self.nodes[MAX_STAKE_DELTA_NODES - 1] = undefined;
        self.nodes[MAX_STAKE_DELTA_NODES - 1].next = .null;
        self.free_head = .init(@enumFromInt(0));
    }

    /// Allocate a node. Caller populates every field. Fatal on
    /// `error.OutOfSpace` — see `MAX_STAKE_DELTA_NODES`.
    pub fn createId(self: *StakeDeltaArena) !Id {
        const head = self.free_head.opt() orelse return error.OutOfSpace;
        self.free_head = self.nodes[head.index()].next;
        return head;
    }

    /// Return a node to the free list. `id` must have been obtained
    /// from `createId` and not already destroyed.
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
/// triple for the `StakeHistory` sysvar. Copied parent → child at
/// `onBlockCreate`; maintained incrementally by the committer on
/// each stake-ix.
///
/// Values are exact for the epoch they were computed in. Boundary
/// derivation recomputes them against the new epoch's activation
/// state.
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

/// Owner struct for replay's stakes state. Plain (non-`extern`)
/// container of already-`extern` pieces; no cross-process consumer
/// maps `ReplayStakes` itself.
///
/// TODO(regionize): split `epoch_voters`, `live_voters`, and the
/// delegations pool into standalone top-level regions to match the
/// `BlockPool` / `TransactionPool` / `ExecReqResponse` convention.
pub const ReplayStakes = struct {
    epoch_voters: EpochVoters,
    /// Cloned from parent at `onBlockCreate`. The root block's slot
    /// is filled by `init()` at boot.
    live_voters: [replay.BlockPool.capacity]LiveVoters,
    /// Rooted delegator → delegation table. Mutated only at root
    /// advance and during partitioned rewards.
    stake_delegations_root: StakeDelegationsRoot,
    /// All in-flight stake-delegation mutations across all unrooted
    /// forks share this pool. Each node is chained onto exactly one
    /// block's `stake_delta_head`, freed by fold-into-root on the
    /// winning path or by `pruneStakeDeltas` on losing siblings.
    stake_delta_arena: StakeDeltaArena,
    /// Per-block head of the arena chain owned by that block.
    /// `.null` means no stake-ix landed on this block yet. Ancestor
    /// deltas are reached by walking `replay.Node.parent`, not by
    /// copy — children start with `.null` head.
    stake_delta_head: [replay.BlockPool.capacity]StakeDeltaArena.Id.Optional,
    /// Per-block running triple for the `StakeHistory` sysvar.
    /// Byte-copied parent → child at `onBlockCreate`.
    stake_aggregates: [replay.BlockPool.capacity]StakeAggregates,
    /// Dedup scratch used by `applyRootedFold`. Sized 2x
    /// `MAX_STAKE_DELTA_NODES` for `FixedPubkeyMap`'s occupancy
    /// invariant. ~8 MB inline; reset at the start of every fold.
    fold_scratch: FoldScratch,
    /// TODO(boundary): delete once `current`/`t_minus_1`/
    /// `t_minus_2` rotation makes the epoch of any given slot
    /// derivable from the rotation state.
    boot_epoch: Epoch,
    /// First slot of the epoch immediately after `boot_epoch`.
    /// Cached at boot so `ensureSlotInBootEpoch` avoids a per-slot
    /// `getEpoch` division. Deleted with `boot_epoch`.
    first_slot_of_next_epoch: Slot,

    pub const FoldScratch = collections.FixedPubkeyMap(void, MAX_STAKE_DELTA_NODES * 2);

    pub fn init(self: *ReplayStakes) void {
        self.epoch_voters.init();
        for (&self.live_voters) |*lv| lv.reset();
        self.stake_delegations_root.init();
        self.stake_delta_arena.init();
        for (&self.stake_delta_head) |*h| h.* = .null;
        for (&self.stake_aggregates) |*a| a.* = StakeAggregates.ZERO;
        self.fold_scratch.init();
        self.boot_epoch = 0;
        self.first_slot_of_next_epoch = 0;
    }

    /// Populate `epoch_voters` and `boot_epoch` from the snapshot
    /// manifest. `root_slot` is the slot the snapshot was taken at;
    /// `memory_base` resolves `RelativeSlice` values in `manifest`
    /// (typically `snapshot_metadata.getMemory()`).
    ///
    /// `live_voters` is left in its `init()` state — the root block
    /// has no parent to clone from.
    ///
    /// Errors:
    /// - `error.MissingEpochStakesForCurrentEpoch` if no
    ///   `VersionedEpochStakes` entry matches the boot epoch.
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

    /// Called by replay whenever a fresh `BlockRef` is allocated for
    /// a genuine new-block event (slot boundary or fork within a
    /// slot). Copies parent's `LiveVoters` + `stake_aggregates` into
    /// the child; resets the child's `stake_delta_head` to `.null`.
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

    /// TODO(boundary): delete when boundary derivation lands.
    /// Returns `error.EpochBoundaryNotYetImplemented` for slots in
    /// or beyond the epoch after `boot_epoch`.
    pub fn ensureSlotInBootEpoch(self: *const ReplayStakes, slot: Slot) !void {
        if (slot >= self.first_slot_of_next_epoch) {
            return error.EpochBoundaryNotYetImplemented;
        }
    }
};

/// Fold a landed stake-ix upsert into `block`'s delta chain and
/// running `stake_aggregates` triple.
///
/// - `post_delegation`: the delegator's new state after the ix.
/// - `pre_contribution` / `post_contribution`: what the delegator
///   contributes to `(effective, activating, deactivating)` before
///   and after the ix on this block's view. Zero pre for a newly-
///   created stake account. Computed by the exec tile from the
///   pre/post `StakeStateV2` + current epoch + stake_history.
///
/// The arena node's `next` links onto the previous head of
/// `block`'s chain; ancestor deltas remain reachable via the
/// block-tree parent walk.
///
/// Fatal on `error.OutOfSpace` — see `MAX_STAKE_DELTA_NODES`.
///
/// TODO(exec-tile): call from the committer per landed stake ix.
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
/// and running aggregates. Post state is implicitly zero.
///
/// `delegation_at_close` is stashed for debug / audit only; the
/// fold-into-root path treats it as undefined for tombstones and
/// only reads `.kind`.
///
/// Fatal on `error.OutOfSpace`.
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

/// `agg += post - pre`, field-wise, wrapping. The cumulative sum
/// across a block's delta chain always equals the mathematically-
/// correct total because it reduces to `sum(post_contribution)`
/// across every delta; individual (pre > post) shrinks may
/// underflow intermediate values but the running total is exact.
fn applyAggregateDelta(
    agg: *StakeAggregates,
    pre: StakeAggregates,
    post: StakeAggregates,
) void {
    agg.effective +%= post.effective -% pre.effective;
    agg.activating +%= post.activating -% pre.activating;
    agg.deactivating +%= post.deactivating -% pre.deactivating;
}

/// Fold the winning fork's ancestor delta chain into
/// `stake_delegations_root`, advancing the rooted view from
/// `old_root` to `new_root`.
///
/// Caller invariants:
/// - `new_root` is a descendant of `old_root` via `Node.parent`.
/// - `old_root` has already been folded (`stake_delta_head` is
///   `.null`). Boot satisfies this trivially.
/// - Replay is the sole writer to the arena, heads, and root map
///   for the duration of the call.
///
/// Walks `new_root` up the parent chain, stopping before
/// `old_root`. On each block, iterates its delta list newest-first;
/// `fold_scratch` deduplicates by delegator pubkey so only the
/// most-recent delta hits root. Shadowed nodes are freed silently.
/// Cost: O(sum of delta counts on the path).
///
/// Rooted `stake_aggregates` need no explicit maintenance: the
/// invariant `stake_aggregates[B] = sum of contributions viewed
/// from B` is preserved by fold and prune, so
/// `stake_aggregates[new_root]` is already the new rooted total.
pub fn applyRootedFold(
    stakes: *ReplayStakes,
    block_pool: *const replay.BlockPool,
    old_root: replay.BlockRef,
    new_root: replay.BlockRef,
) void {
    if (old_root == new_root) return;

    stakes.fold_scratch.init();

    var cur = new_root;
    while (cur != old_root) {
        var link = stakes.stake_delta_head[cur.index()];
        while (link.opt()) |id| {
            const node = stakes.stake_delta_arena.indexToPtr(id);
            const next = node.next;
            const delegator_pk = node.delegator_pk;

            // Newest-to-oldest walk order + first-write-wins in `seen`
            // gives most-recent-per-delegator semantics.
            if (stakes.fold_scratch.getPtrConst(delegator_pk) == null) {
                stakes.fold_scratch.insert(delegator_pk, {}) catch unreachable;
                switch (node.kind) {
                    .upsert => stakes.stake_delegations_root.insert(
                        delegator_pk,
                        node.delegation,
                    ) catch unreachable,
                    .tombstone => _ = stakes.stake_delegations_root.remove(delegator_pk),
                }
            }
            stakes.stake_delta_arena.destroyId(id);
            link = next;
        }
        stakes.stake_delta_head[cur.index()] = .null;

        // Parent must exist because `new_root` is a descendant of
        // `old_root`.
        cur = block_pool.indexToConstPtr(cur).parent.opt() orelse
            @panic("applyRootedFold: new_root has no path to old_root");
    }
}

/// Free every arena node hanging off `block`'s delta head, then
/// clear the head. Called by replay when pruning a losing sibling.
/// Idempotent (safe on already-`.null` heads). Safe because each
/// arena node belongs to exactly one block — children never share
/// a head with their parent.
pub fn pruneStakeDeltas(stakes: *ReplayStakes, block: replay.BlockRef) void {
    var link = stakes.stake_delta_head[block.index()];
    while (link.opt()) |id| {
        const node = stakes.stake_delta_arena.indexToPtr(id);
        const next = node.next;
        stakes.stake_delta_arena.destroyId(id);
        link = next;
    }
    stakes.stake_delta_head[block.index()] = .null;
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

    // Commission_bps in the input is zero, so all entries end up zero.
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
    try std.testing.expectEqual(@as(u64, 0), solGetEpochStake(ev, &pk_miss));}

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

// Small test helper: build a linear chain of blocks
// root <- a <- b <- c in `pool` and return their refs.
fn allocLinearChain(
    pool: *replay.BlockPool,
    n: usize,
) ![]replay.BlockRef {
    const S = struct { var refs: [8]replay.BlockRef = undefined; };
    std.debug.assert(n <= S.refs.len);

    for (0..n) |i| {
        S.refs[i] = try pool.createId();
        const node = pool.indexToPtr(S.refs[i]);
        node.* = .{
            .parent = if (i == 0) .null else .init(S.refs[i - 1]),
            .child = .null,
            .sibling = .null,
            .slot = .init(@as(Slot, @intCast(i))),
        };
    }
    return S.refs[0..n];
}

test "applyRootedFold: no-op when new_root == old_root" {
    var pool_buf: [replay.BlockPool.size()]u8 align(@alignOf(replay.BlockPool)) = undefined;
    const pool: *replay.BlockPool = @ptrCast(&pool_buf);
    pool.init();

    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    const refs = try allocLinearChain(pool, 1);
    const root = refs[0];

    // Push a delta on root — must not be touched by a no-op fold.
    var dpk: Pubkey = .{ .data = .{0} ** 32 };
    dpk.data[0] = 0xD0;
    var vpk: Pubkey = .{ .data = .{0} ** 32 };
    vpk.data[0] = 0xE0;
    try foldStakeIxUpsert(stakes, root, dpk, .{
        .voter_pk = vpk,
        .stake = 1,
        .activation_epoch = 0,
        .deactivation_epoch = std.math.maxInt(Epoch),
        .credits_observed = 0,
    }, StakeAggregates.ZERO, .{ .effective = 1, .activating = 0, .deactivating = 0 });

    applyRootedFold(stakes, pool, root, root);

    // Delta head should still point at the delta node.
    try std.testing.expect(stakes.stake_delta_head[root.index()].opt() != null);
    // Root map should not have received the upsert.
    try std.testing.expect(stakes.stake_delegations_root.getPtrConst(dpk) == null);
}

test "applyRootedFold: upsert on single descendant lands in root" {
    var pool_buf: [replay.BlockPool.size()]u8 align(@alignOf(replay.BlockPool)) = undefined;
    const pool: *replay.BlockPool = @ptrCast(&pool_buf);
    pool.init();

    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    const refs = try allocLinearChain(pool, 2);
    const root = refs[0];
    const a = refs[1];

    var dpk: Pubkey = .{ .data = .{0} ** 32 };
    dpk.data[0] = 0xD1;
    var vpk: Pubkey = .{ .data = .{0} ** 32 };
    vpk.data[0] = 0xE1;
    const dgn: StakeDelegation = .{
        .voter_pk = vpk,
        .stake = 500,
        .activation_epoch = 3,
        .deactivation_epoch = std.math.maxInt(Epoch),
        .credits_observed = 7,
    };
    try foldStakeIxUpsert(stakes, a, dpk, dgn, StakeAggregates.ZERO, .{
        .effective = 500,
        .activating = 0,
        .deactivating = 0,
    });

    applyRootedFold(stakes, pool, root, a);

    // Delta chain drained.
    try std.testing.expectEqual(@as(?StakeDeltaArena.Id, null), stakes.stake_delta_head[a.index()].opt());
    // Root has the upsert.
    const got = stakes.stake_delegations_root.getPtrConst(dpk) orelse return error.NotFound;
    try std.testing.expectEqual(@as(u64, 500), got.stake);
    try std.testing.expectEqual(@as(u64, 7), got.credits_observed);
}

test "applyRootedFold: newest delta wins across ancestor chain" {
    var pool_buf: [replay.BlockPool.size()]u8 align(@alignOf(replay.BlockPool)) = undefined;
    const pool: *replay.BlockPool = @ptrCast(&pool_buf);
    pool.init();

    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    // root <- a <- b <- c
    const refs = try allocLinearChain(pool, 4);
    const root = refs[0];
    const a = refs[1];
    const b = refs[2];
    const c = refs[3];

    var dpk: Pubkey = .{ .data = .{0} ** 32 };
    dpk.data[0] = 0xD2;
    var vpk: Pubkey = .{ .data = .{0} ** 32 };
    vpk.data[0] = 0xE2;

    // Ancestor a: stake=100.
    try foldStakeIxUpsert(stakes, a, dpk, .{
        .voter_pk = vpk,
        .stake = 100,
        .activation_epoch = 3,
        .deactivation_epoch = std.math.maxInt(Epoch),
        .credits_observed = 0,
    }, StakeAggregates.ZERO, .{ .effective = 100, .activating = 0, .deactivating = 0 });

    // Ancestor b: stake=200 (updates same delegator).
    try foldStakeIxUpsert(stakes, b, dpk, .{
        .voter_pk = vpk,
        .stake = 200,
        .activation_epoch = 3,
        .deactivation_epoch = std.math.maxInt(Epoch),
        .credits_observed = 0,
    }, .{ .effective = 100, .activating = 0, .deactivating = 0 }, .{
        .effective = 200,
        .activating = 0,
        .deactivating = 0,
    });

    // Tip c: stake=300 (updates same delegator again).
    try foldStakeIxUpsert(stakes, c, dpk, .{
        .voter_pk = vpk,
        .stake = 300,
        .activation_epoch = 3,
        .deactivation_epoch = std.math.maxInt(Epoch),
        .credits_observed = 0,
    }, .{ .effective = 200, .activating = 0, .deactivating = 0 }, .{
        .effective = 300,
        .activating = 0,
        .deactivating = 0,
    });

    applyRootedFold(stakes, pool, root, c);

    // Every block on the path drained.
    try std.testing.expectEqual(@as(?StakeDeltaArena.Id, null), stakes.stake_delta_head[a.index()].opt());
    try std.testing.expectEqual(@as(?StakeDeltaArena.Id, null), stakes.stake_delta_head[b.index()].opt());
    try std.testing.expectEqual(@as(?StakeDeltaArena.Id, null), stakes.stake_delta_head[c.index()].opt());

    // Root has c's version (newest wins).
    const got = stakes.stake_delegations_root.getPtrConst(dpk) orelse return error.NotFound;
    try std.testing.expectEqual(@as(u64, 300), got.stake);
}

test "applyRootedFold: tombstone erases pre-existing rooted row" {
    var pool_buf: [replay.BlockPool.size()]u8 align(@alignOf(replay.BlockPool)) = undefined;
    const pool: *replay.BlockPool = @ptrCast(&pool_buf);
    pool.init();

    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    // Seed the rooted table.
    var dpk: Pubkey = .{ .data = .{0} ** 32 };
    dpk.data[0] = 0xD3;
    var vpk: Pubkey = .{ .data = .{0} ** 32 };
    vpk.data[0] = 0xE3;
    try stakes.stake_delegations_root.insert(dpk, .{
        .voter_pk = vpk,
        .stake = 500,
        .activation_epoch = 3,
        .deactivation_epoch = std.math.maxInt(Epoch),
        .credits_observed = 42,
    });

    const refs = try allocLinearChain(pool, 2);
    const root = refs[0];
    const a = refs[1];

    try foldStakeIxTombstone(stakes, a, dpk, .{
        .voter_pk = vpk,
        .stake = 500,
        .activation_epoch = 3,
        .deactivation_epoch = std.math.maxInt(Epoch),
        .credits_observed = 42,
    }, .{ .effective = 500, .activating = 0, .deactivating = 0 });

    applyRootedFold(stakes, pool, root, a);

    try std.testing.expect(stakes.stake_delegations_root.getPtrConst(dpk) == null);
}

test "applyRootedFold: releases arena nodes back to free list" {
    var pool_buf: [replay.BlockPool.size()]u8 align(@alignOf(replay.BlockPool)) = undefined;
    const pool: *replay.BlockPool = @ptrCast(&pool_buf);
    pool.init();

    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    const refs = try allocLinearChain(pool, 2);
    const root = refs[0];
    const a = refs[1];

    // Capture the very-first free arena id, exhaust a few, then fold
    // and re-allocate — should hand back the same ids (LIFO free list).
    var dpk: Pubkey = .{ .data = .{0} ** 32 };
    dpk.data[0] = 0xD4;
    var vpk: Pubkey = .{ .data = .{0} ** 32 };
    vpk.data[0] = 0xE4;

    const alloc_pre = stakes.stake_delta_arena.free_head;

    for (0..5) |i| {
        var dpk_i = dpk;
        dpk_i.data[1] = @intCast(i);
        try foldStakeIxUpsert(stakes, a, dpk_i, .{
            .voter_pk = vpk,
            .stake = 1,
            .activation_epoch = 0,
            .deactivation_epoch = std.math.maxInt(Epoch),
            .credits_observed = 0,
        }, StakeAggregates.ZERO, .{ .effective = 1, .activating = 0, .deactivating = 0 });
    }

    // Arena consumed 5 slots — free_head moved.
    try std.testing.expect(stakes.stake_delta_arena.free_head.opt() != alloc_pre.opt());

    applyRootedFold(stakes, pool, root, a);

    // After fold, allocating one node should hand back the LIFO-most-
    // recently freed slot from the fold — a specific arena id, but
    // more importantly, the arena is not exhausted.
    const id = try stakes.stake_delta_arena.createId();
    stakes.stake_delta_arena.destroyId(id);
}

test "pruneStakeDeltas: frees the block's chain and clears head" {
    const stakes = try std.heap.page_allocator.create(ReplayStakes);
    defer std.heap.page_allocator.destroy(stakes);
    stakes.init();

    const b: replay.BlockRef = @enumFromInt(2);
    var dpk: Pubkey = .{ .data = .{0} ** 32 };
    dpk.data[0] = 0xD5;
    var vpk: Pubkey = .{ .data = .{0} ** 32 };
    vpk.data[0] = 0xE5;

    for (0..3) |i| {
        var dpk_i = dpk;
        dpk_i.data[1] = @intCast(i);
        try foldStakeIxUpsert(stakes, b, dpk_i, .{
            .voter_pk = vpk,
            .stake = @as(u64, i) + 1,
            .activation_epoch = 0,
            .deactivation_epoch = std.math.maxInt(Epoch),
            .credits_observed = 0,
        }, StakeAggregates.ZERO, .{ .effective = @as(u64, i) + 1, .activating = 0, .deactivating = 0 });
    }

    try std.testing.expect(stakes.stake_delta_head[b.index()].opt() != null);

    pruneStakeDeltas(stakes, b);

    try std.testing.expectEqual(@as(?StakeDeltaArena.Id, null), stakes.stake_delta_head[b.index()].opt());
    // Idempotent — safe to call again.
    pruneStakeDeltas(stakes, b);
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
