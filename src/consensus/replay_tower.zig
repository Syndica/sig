const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const AutoArrayHashMapUnmanaged = std.AutoArrayHashMapUnmanaged;

const BlockTimestamp = sig.runtime.program.vote.state.BlockTimestamp;
const Lockout = sig.runtime.program.vote.state.Lockout;
const Ancestors = sig.core.Ancestors;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const EpochStakesMap = sig.core.EpochStakesMap;
const SlotAndHash = sig.core.hash.SlotAndHash;
const SlotHistory = sig.runtime.sysvar.SlotHistory;
const SortedSetUnmanaged = sig.utils.collections.SortedSetUnmanaged;
const TowerSync = sig.runtime.program.vote.state.TowerSync;
const Vote = sig.runtime.program.vote.state.Vote;
const VoteStateUpdate = sig.runtime.program.vote.state.VoteStateUpdate;
const StakeAndVoteAccountsMap = sig.core.vote_accounts.StakeAndVoteAccountsMap;
const UnixTimestamp = sig.core.UnixTimestamp;

const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const LatestValidatorVotes = sig.consensus.latest_validator_votes.LatestValidatorVotes;
const ThresholdDecision = sig.consensus.tower.ThresholdDecision;
const ProgressMap = sig.consensus.ProgressMap;
const Tower = sig.consensus.tower.Tower;
const TowerError = sig.consensus.tower.TowerError;
const VoteTransaction = sig.consensus.vote_transaction.VoteTransaction;
const VotedStakes = sig.consensus.progress_map.consensus.VotedStakes;
const LockoutIntervals = sig.consensus.progress_map.LockoutIntervals;

const Stake = u64;

const Logger = sig.trace.Logger("replay_tower");

const MAX_LOCKOUT_HISTORY = sig.consensus.tower.MAX_LOCKOUT_HISTORY;

const VOTE_THRESHOLD_DEPTH_SHALLOW: usize = 4;
const VOTE_THRESHOLD_DEPTH: usize = 8;
const SWITCH_FORK_THRESHOLD: f64 = 0.38;
const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days

const DUPLICATE_LIVENESS_THRESHOLD: f64 = 0.1;
pub const DUPLICATE_THRESHOLD: f64 = 1.0 - SWITCH_FORK_THRESHOLD - DUPLICATE_LIVENESS_THRESHOLD;

pub const VOTE_THRESHOLD_SIZE: f64 = 2.0 / 3.0;
pub const ExpirationSlot = Slot;
const VotedSlotAndPubkey = struct { slot: Slot, pubkey: Pubkey };

pub const LastVoteSignal = enum {
    normal,
    stray,
};

const ClusterVoteState = struct {
    /// Maps each validator (by their Pubkey) to the amount of stake they have voted
    /// with on this fork. Helps determine who has already committed to this
    /// fork and how much total stake that represents.
    voted_stakes: VotedStakes,
    /// Represents the total active stake in the network.
    total_stake: Stake,
    /// The sum of stake from all validators who have voted on the
    /// fork leading up to the current bank (slot).
    fork_stake: Stake,
    // Tree of intervals of lockouts of the form [slot, slot + slot.lockout],
    // keyed by end of the range
    lockout_intervals: LockoutIntervals,
    my_latest_landed_vote: ?Slot,

    pub fn deinit(self: *ClusterVoteState, allocator: std.mem.Allocator) void {
        self.voted_stakes.deinit(allocator);
        self.lockout_intervals.deinit(allocator);
    }
};

pub const HeaviestForkFailures = union(enum) {
    LockedOut: u64,
    FailedThreshold: struct {
        slot: Slot,
        vote_depth: u64,
        observed_stake: u64,
        total_stake: u64,
    },
    /// Failed to meet stake threshold for switching forks
    FailedSwitchThreshold: struct {
        slot: Slot,
        observed_stake: u64,
        total_stake: u64,
    },
    NoPropagatedConfirmation: struct {
        slot: Slot,
        observed_stake: u64,
        total_stake: u64,
    },
};

pub const CandidateVoteAndResetSlots = struct {
    // A slot that the validator will vote on given it passes all
    // remaining vote checks
    // Note: In Agave this is a Bank
    candidate_vote_slot: ?Slot,

    // A slot that the validator will reset its PoH to regardless
    // of voting behavior
    // Note: In Agave this is a Bank
    reset_slot: ?Slot,

    switch_fork_decision: SwitchForkDecision,
};

pub const SelectVoteAndResetForkResult = struct {
    vote_slot: ?struct {
        slot: Slot,
        decision: SwitchForkDecision,
    },
    reset_slot: ?Slot,
    heaviest_fork_failures: std.ArrayListUnmanaged(HeaviestForkFailures),

    pub fn deinit(self: *SelectVoteAndResetForkResult, allocator: std.mem.Allocator) void {
        self.heaviest_fork_failures.deinit(allocator);
    }
};

pub fn getSlotHistory(
    allocator: std.mem.Allocator,
    account_reader: sig.accounts_db.SlotAccountReader,
) !SlotHistory {
    const maybe_account = try account_reader.get(allocator, SlotHistory.ID);
    const account: sig.core.Account = maybe_account orelse return error.MissingSlotHistoryAccount;
    defer account.deinit(allocator);

    var data_iter = account.data.iterator();
    const slot_history = try sig.bincode.read(
        allocator,
        SlotHistory,
        data_iter.reader(),
        .{},
    );
    errdefer slot_history.deinit(allocator);

    if (data_iter.bytesRemaining() != 0) {
        return error.TrailingBytesInSlotHistory;
    }
    return slot_history;
}

// TODO Come up with a better name?
// Consensus? Given this contains the logic of deciding what to vote or fork-switch into,
//  making use of tower, fork choice etc
// Voter?
pub const ReplayTower = struct {
    logger: Logger,
    tower: Tower,
    node_pubkey: Pubkey,
    // TODO move the threshold_ to ReplayTower or a constant
    /// This is the number of ancestor slots to consider when calculating the switch threshold.
    threshold_depth: usize,
    /// This is the percentage of votes required within that depth to permit a fork switch.
    threshold_size: f64,
    last_vote: VoteTransaction,
    /// The blockhash used in the last vote transaction, may or may not equal the
    /// blockhash of the voted block itself, depending if the vote slot was refreshed.
    /// For instance, a vote for slot 5, may be refreshed/resubmitted for inclusion in
    ///  block 10, in  which case `last_vote_tx_blockhash` equals the blockhash of 10, not 5.
    /// For non voting validators this is NonVoting
    last_vote_tx_blockhash: BlockhashStatus,
    last_timestamp: BlockTimestamp,
    /// Restored last voted slot which cannot be found in SlotHistory at replayed root
    /// (This is a special field for slashing-free validator restart with edge cases).
    /// This could be emptied after some time; but left intact indefinitely for easier
    /// implementation
    /// Further, stray slot can be stale or not. `Stale` here means whether given
    /// bank_forks (=~ ledger) lacks the slot or not.
    stray_restored_slot: ?Slot,
    last_switch_threshold_check: ?struct { Slot, SwitchForkDecision },
    metrics: ReplayTowerMetrics,

    const Self = @This();

    pub fn init(
        logger: Logger,
        node_pubkey: Pubkey,
        tower: Tower,
        registry: *sig.prometheus.Registry(.{}),
    ) !ReplayTower {
        return .{
            .logger = logger,
            .tower = tower,
            .node_pubkey = node_pubkey,
            .threshold_depth = VOTE_THRESHOLD_DEPTH,
            .threshold_size = VOTE_THRESHOLD_SIZE,
            .last_vote = VoteTransaction.DEFAULT,
            .last_vote_tx_blockhash = .uninitialized,
            .last_timestamp = BlockTimestamp.ZEROES,
            .stray_restored_slot = null,
            .last_switch_threshold_check = null,
            .metrics = try ReplayTowerMetrics.init(registry),
        };
    }

    pub fn deinit(self: ReplayTower, allocator: std.mem.Allocator) void {
        self.last_vote.deinit(allocator);
    }

    pub fn refreshLastVoteTimestamp(
        self: *ReplayTower,
        heaviest_slot_on_same_fork: Slot,
    ) void {
        const timestamp = if (self.last_vote.timestamp()) |last_vote_timestamp|
            // To avoid a refreshed vote tx getting caught in deduplication filters,
            // we need to update timestamp. Increment by smallest amount to avoid skewing
            // the Timestamp Oracle.
            last_vote_timestamp +| 1
        else
            // If the previous vote did not send a timestamp due to clock error,
            // use the last good timestamp + 1
            self.last_timestamp.timestamp +| 1;

        if (self.last_vote.lastVotedSlot()) |last_voted_slot| {
            if (heaviest_slot_on_same_fork <= last_voted_slot) {
                self.logger.warn().logf(
                    \\Trying to refresh timestamp for vote on
                    \\{} using smaller heaviest bank {}
                , .{ last_voted_slot, heaviest_slot_on_same_fork });
                return;
            }
            self.last_timestamp = BlockTimestamp{
                .slot = last_voted_slot,
                .timestamp = timestamp,
            };
            self.last_vote.setTimestamp(timestamp);
        } else {
            self.logger.warn().logf(
                \\Trying to refresh timestamp for last vote on heaviest bank on same fork {},
                \\but there is no vote to refresh
            , .{heaviest_slot_on_same_fork});
        }
    }

    pub fn refreshLastVoteTxBlockhash(
        self: *ReplayTower,
        new_vote_tx_blockhash: Hash,
    ) void {
        self.last_vote_tx_blockhash = .{ .blockhash = new_vote_tx_blockhash };
    }

    pub fn markLastVoteTxBlockhashNonVoting(self: *ReplayTower) void {
        self.last_vote_tx_blockhash = .non_voting;
    }

    pub fn markLastVoteTxBlockhashHotSpare(self: *ReplayTower) void {
        self.last_vote_tx_blockhash = .hot_spare;
    }

    /// Record the vote in the tower and keep track of the last vote.
    pub fn recordBankVote(
        self: *ReplayTower,
        allocator: std.mem.Allocator,
        vote_slot: Slot,
        vote_hash: Hash,
    ) !?Slot {
        // Returns the new root if one is made after applying a vote for the given bank to
        // `self.vote_state`
        //
        // TODO add block_id to bank fields
        const block_id = Hash.ZEROES;
        // TODO expose feature set on Bank
        const is_enable_tower_active = true;

        const new_root = self.tower.recordBankVoteAndUpdateLockouts(
            vote_slot,
        ) catch |err| switch (err) {
            error.VoteTooOld => {
                self.metrics.stale_votes_rejected.inc();
                return err;
            },
            else => return err,
        };

        try self.updateLastVoteFromVoteState(
            allocator,
            vote_hash,
            is_enable_tower_active,
            block_id,
        );

        self.logger.info().logf(
            "recorded vote in tower for slot {d}, new root: {?d}",
            .{ vote_slot, new_root },
        );

        return new_root;
    }

    pub fn updateLastVoteFromVoteState(
        self: *ReplayTower,
        allocator: std.mem.Allocator,
        vote_hash: Hash,
        enable_tower_sync_ix: bool,
        block_id: Hash,
    ) !void {
        var new_vote = blk: {
            var new_lockouts = try std.ArrayListUnmanaged(Lockout)
                .initCapacity(allocator, self.tower.votes.len);
            try new_lockouts.appendSlice(allocator, self.tower.votes.constSlice());

            break :blk if (enable_tower_sync_ix)
                VoteTransaction{ .tower_sync = TowerSync{
                    .lockouts = new_lockouts,
                    .root = self.tower.root,
                    .hash = vote_hash,
                    .timestamp = null,
                    .block_id = block_id,
                } }
            else
                VoteTransaction{ .vote_state_update = VoteStateUpdate{
                    .lockouts = new_lockouts,
                    .root = self.tower.root,
                    .hash = vote_hash,
                    .timestamp = null,
                } };
        };

        const last_voted_slot = self.lastVotedSlot() orelse 0;
        new_vote.setTimestamp(self.maybeTimestamp(last_voted_slot));

        self.last_vote.deinit(allocator);
        self.last_vote = new_vote;
    }

    pub fn lastVotedSlot(self: *const ReplayTower) ?Slot {
        return self.last_vote.lastVotedSlot();
    }

    pub fn lastVotedSlotHash(self: *const ReplayTower) ?SlotAndHash {
        const last_voted_slot = self.last_vote.lastVotedSlot() orelse return null;
        return .{ .slot = last_voted_slot, .hash = self.last_vote.getHash() };
    }

    fn maybeTimestamp(self: *ReplayTower, current_slot: Slot) ?UnixTimestamp {
        if (current_slot > self.last_timestamp.slot or
            (self.last_timestamp.slot == 0 and current_slot == self.last_timestamp.slot))
        {
            const timestamp = std.time.timestamp();
            if (timestamp >= self.last_timestamp.timestamp) {
                self.last_timestamp = BlockTimestamp{
                    .slot = current_slot,
                    .timestamp = timestamp,
                };
                return timestamp;
            } else {
                // TODO Collect metrics
            }
        }
        return null;
    }

    /// Checks if a vote for `candidate_slot` is usable in a switching proof
    /// from `last_voted_slot` to `switch_slot`.
    ///
    /// We assume `candidate_slot` is not an ancestor of `last_voted_slot`.
    ///
    /// Returns null if `candidate_slot` or `switch_slot` is not present in `ancestors`
    fn isValidSwitchingProofVote(
        self: *const ReplayTower,
        candidate_slot: Slot,
        last_voted_slot: Slot,
        switch_slot: Slot,
        ancestors: *const AutoArrayHashMapUnmanaged(Slot, Ancestors),
        last_vote_ancestors: *const Ancestors,
    ) ?bool {

        // Ignore if the `candidate_slot` is a descendant of the `last_voted_slot`, since we do not
        // want to count votes on the same fork.
        if (isDescendantSlot(
            candidate_slot,
            last_voted_slot,
            ancestors,
        ) orelse return null) {
            return false;
        }

        if (last_vote_ancestors.ancestors.count() == 0) {
            // If `last_vote_ancestors` is empty, this means we must have a last vote that is stray. If the `last_voted_slot`
            // is stray, it must be descended from some earlier root than the latest root (the anchor at startup).
            // The above check also guarantees that the candidate slot is not a descendant of this stray last vote.
            //
            // This gives us a fork graph:
            //     / ------------- stray `last_voted_slot`
            // old root
            //     \- latest root (anchor) - ... - candidate slot
            //                                \- switch slot
            //
            // Thus the common ancestor of `last_voted_slot` and `candidate_slot` is `old_root`, which the `switch_slot`
            // descends from. Thus it is safe to use `candidate_slot` in the switching proof.
            //
            // Note: the calling function should have already panicked if we do not have ancestors and the last vote is not stray.
            std.debug.assert(self.isStrayLastVote());
            return true;
        }

        // Only consider forks that split at the common_ancestor of `switch_slot` and `last_voted_slot` or earlier.
        // This is to prevent situations like this from being included in the switching proof:
        //
        //         /-- `last_voted_slot`
        //     /--Y
        //    X    \-- `candidate_slot`
        //     \-- `switch_slot`
        //
        // The common ancestor of `last_voted_slot` and `switch_slot` is `X`. Votes for the `candidate_slot`
        // should not count towards the switch proof since `candidate_slot` is "on the same fork" as `last_voted_slot`
        // in relation to `switch_slot`.
        // However these candidate slots should be allowed:
        //
        //             /-- Y -- `last_voted_slot`
        //    V - W - X
        //        \    \-- `candidate_slot` -- `switch_slot`
        //         \    \-- `candidate_slot`
        //          \-- `candidate_slot`
        //
        // As the `candidate_slot`s forked off from `X` or earlier.
        //
        // To differentiate, we check the common ancestor of `last_voted_slot` and `candidate_slot`.
        // If the `switch_slot` descends from this ancestor, then the vote for `candidate_slot` can be included.
        if (greatestCommonAncestor(ancestors, candidate_slot, last_voted_slot)) |ancestor| {
            return isDescendantSlot(switch_slot, ancestor, ancestors);
        }

        return null;
    }

    /// Determines whether the validator is allowed to switch forks by evaluating
    /// the stake-weighted lockouts between the last voted slot and a candidate switch slot.
    ///
    /// It requires gathering of stake information from other validators' lockouts to justify switching to a
    /// different fork. It ensures safety by preventing forks from being abandoned prematurely.
    ///
    /// Returns a `SwitchForkDecision`, which indicates whether:
    /// - The switch is on the same fork (no switch required).
    /// - The switch is allowed (enough stake supports the fork change).
    /// - The switch is rejected (insufficient locked-out stake).
    /// - The last vote was purged due to duplication, allowing a fallback.
    ///
    /// Note that this function is purely computational. It Computes and
    /// returns a SwitchForkDecision. No side effects or state update.
    pub fn makeCheckSwitchThresholdDecision(
        self: *const ReplayTower,
        allocator: std.mem.Allocator,
        switch_slot: Slot,
        ancestors: *const AutoArrayHashMapUnmanaged(Slot, Ancestors),
        descendants: *const AutoArrayHashMapUnmanaged(Slot, SortedSetUnmanaged(Slot)),
        progress: *const ProgressMap,
        total_stake: u64,
        epoch_vote_accounts: *const StakeAndVoteAccountsMap,
        latest_validator_votes: *const LatestValidatorVotes,
        heaviest_subtree_fork_choice: *const HeaviestSubtreeForkChoice,
    ) !SwitchForkDecision {
        const last_voted = self.lastVotedSlotHash() orelse return SwitchForkDecision.same_fork;
        const last_voted_slot = last_voted.slot;
        const last_voted_hash = last_voted.hash;
        const root = try self.tower.getRoot();

        // `heaviest_subtree_fork_choice` entries are not cleaned by duplicate block purging/rollback logic,
        // so this is safe to check here. We return here if the last voted slot was rolled back/purged due to
        // being a duplicate because `ancestors`/`descendants`/`progress` structures may be missing this slot due
        // to duplicate purging. This would cause many of the `unwrap()` checks below to fail.
        const switch_hash = progress.getHash(switch_slot) orelse return error.MissingSlot;
        if (heaviest_subtree_fork_choice.latestDuplicateAncestor(
            SlotAndHash{ .slot = last_voted_slot, .hash = last_voted_hash },
        )) |latest_duplicate_ancestor| {
            // We're rolling back because one of the ancestors of the last vote was a duplicate. In this
            // case, it's acceptable if the switch candidate is one of ancestors of the previous vote,
            // just fail the switch check because there's no point in voting on an ancestor. ReplayStage
            // should then have a special case continue building an alternate fork from this ancestor, NOT
            // the `last_voted_slot`. This is in contrast to usual SwitchFailure where ReplayStage continues to build blocks
            // on latest vote. See `ReplayStage::select_vote_and_reset_forks()` for more details.
            if (heaviest_subtree_fork_choice.isStrictAncestor(&.{
                .slot = switch_slot,
                .hash = switch_hash,
            }, &.{
                .slot = last_voted_slot,
                .hash = last_voted_hash,
            })) {
                return SwitchForkDecision{
                    .failed_switch_duplicate_rollback = latest_duplicate_ancestor,
                };
            } else {
                const is_switch = if (progress.getHash(last_voted_slot)) |current_slot_hash|
                    !current_slot_hash.eql(last_voted_hash)
                else
                    true;

                if (is_switch) {
                    // Our last vote slot was purged because it was on a duplicate fork, don't continue below
                    // where checks may panic. We allow a freebie vote here that may violate switching
                    // thresholds
                    return SwitchForkDecision{ .switch_proof = Hash.ZEROES };
                }
            }
        }

        const last_vote_ancestors: Ancestors =
            ancestors.get(last_voted_slot) orelse blk: {
                if (self.isStrayLastVote()) {
                    // Unless last vote is stray and stale, ancestors.get(last_voted_slot) must
                    // return a value, justifying to panic! here.
                    // Also, adjustLockoutsAfterReplay() correctly makes last_voted_slot None,
                    // if all saved votes are ancestors of replayed_root_slot. So this code shouldn't be
                    // touched in that case as well.
                    // In other words, except being stray, all other slots have been voted on while
                    // this validator has been running, so we must be able to fetch ancestors for
                    // all of them.
                    // --
                    // This condition (stale stray last vote) shouldn't occur under normal validator
                    // operation, indicating something unusual happened.
                    // This condition could be introduced by manual ledger mishandling,
                    // validator SEGV, OS/HW crash, or plain No Free Space FS error.

                    // However, returning empty ancestors as a fallback here shouldn't result in
                    // slashing by itself (Note that we couldn't fully preclude any kind of slashing if
                    // the failure was OS or HW level).

                    // Firstly, lockout is ensured elsewhere.

                    // Also, there is no risk of optimistic conf. violation. Although empty ancestors
                    // could result in incorrect (= more than actual) locked_out_stake and
                    // false-positive SwitchProof later in this function, there should be no such a
                    // heavier fork candidate, first of all, if the last vote (or any of its
                    // unavailable ancestors) were already optimistically confirmed.
                    // The only exception is that other validator is already violating it...

                    if (self.isFirstSwitchCheck() and switch_slot < last_voted_slot) {
                        // `switch < last` is needed not to warn! this message just because of using
                        // newer snapshots on validator restart
                        self.logger.warn().logf(
                            \\bank_forks doesn't have corresponding data for the stray restored last vote({}),
                            \\meaning some inconsistency between saved tower and ledger.
                        , .{last_voted_slot});
                    }
                    break :blk .EMPTY;
                } else return error.NoAncestorsFoundForLastVote;
            };

        const switch_slot_ancestors = ancestors.get(switch_slot) orelse
            return error.NoAncestorsFoundForSwitchSlot;

        if (switch_slot == last_voted_slot or switch_slot_ancestors.containsSlot(last_voted_slot)) {
            // If the `switch_slot is a descendant of the last vote,
            // no switching proof is necessary
            return SwitchForkDecision{ .same_fork = {} };
        }

        if (last_vote_ancestors.containsSlot(switch_slot)) {
            if (self.isStrayLastVote()) {
                // This peculiar corner handling is needed mainly for a tower which is newer than
                // ledger. (Yeah, we tolerate it for ease of maintaining validator by operators)
                // This condition could be introduced by manual ledger mishandling,
                // validator SEGV, OS/HW crash, or plain No Free Space FS error.

                // When we're in this clause, it basically means validator is badly running
                // with a future tower while replaying past slots, especially problematic is
                // last_voted_slot.
                // So, don't re-vote on it by returning pseudo FailedSwitchThreshold, otherwise
                // there would be slashing because of double vote on one of last_vote_ancestors.
                // (Well, needless to say, re-creating the duplicate block must be handled properly
                // at the banking stage: https://github.com/solana-labs/solana/issues/8232)
                //
                // To be specific, the replay stage is tricked into a false perception where
                // last_vote_ancestors is AVAILABLE for descendant-of-`switch_slot`,  stale, and
                // stray slots (which should always be empty_ancestors).
                //
                // This is covered by test_future_tower_* in local_cluster
                self
                    .logger
                    .warn()
                    .logf(
                    "failed_switch_threshold. switch_proof_stake: {}, total_stake: {}",
                    .{ 0, total_stake },
                );

                return SwitchForkDecision{ .failed_switch_threshold = .{
                    .switch_proof_stake = 0,
                    .total_stake = total_stake,
                } };
            } else return error.NoAncestorsFoundForLastVote;
        }

        // By this point, we know the `switch_slot` is on a different fork
        // (is neither an ancestor nor descendant of `last_vote`), so a
        // switching proof is necessary
        const switch_proof = Hash.ZEROES;
        var locked_out_stake: u64 = 0;

        var locked_out_vote_accounts: SortedSetUnmanaged(Pubkey) = .empty;
        defer locked_out_vote_accounts.deinit(allocator);

        for (descendants.keys(), descendants.values()) |candidate_slot, *candidate_descendants| {
            // 1) Don't consider any banks that haven't been frozen yet
            //    because the needed stats are unavailable
            const stats = progress.getForkStats(candidate_slot) orelse continue;
            if (!stats.computed) continue;

            // 2) Only consider lockouts at the latest `frozen` bank
            //    on each fork, as that bank will contain all the
            //    lockout intervals for ancestors on that fork as well.
            // If any of the descendants have the `computed` flag set, then there must be a more
            // recent frozen bank on this fork to use, so we can ignore this one. Otherwise,
            // even if this bank has descendants, if they have not yet been frozen / stats computed,
            // then use this bank as a representative for the fork.
            const is_descendant_computed = for (candidate_descendants.items()) |d| {
                if (progress.getForkStats(d)) |stat| {
                    if (stat.computed) break true;
                }
            } else false;
            if (is_descendant_computed) continue;

            // 3) Don't consider lockouts on the `last_vote` itself
            if (candidate_slot == last_voted_slot) continue;

            // 4) Don't consider lockouts on any descendants of
            //    `last_vote`
            if (candidate_slot <= root) continue;

            // 5) Don't consider any banks before the root because
            //    all lockouts must be ancestors of `last_vote`
            const is_valid_switching_vote = self.isValidSwitchingProofVote(
                candidate_slot,
                last_voted_slot,
                switch_slot,
                ancestors,
                &last_vote_ancestors,
            ) orelse return error.MissingSlotInAncestors;

            if (!is_valid_switching_vote) continue;

            // By the time we reach here, any ancestors of the `last_vote`,
            // should have been filtered out, as they all have a descendant,
            // namely the `last_vote` itself.
            std.debug.assert(!last_vote_ancestors.containsSlot(candidate_slot));
            // Evaluate which vote accounts in the bank are locked out
            // in the interval candidate_slot..last_vote, which means
            // finding any lockout intervals in the `lockout_intervals` tree
            // for this bank that contain `last_vote`.

            const lockout_intervals =
                &progress.getForkProgress(candidate_slot).?.fork_stats.lockout_intervals;

            if (lockout_intervals.map.count() == 0) {
                continue;
            }
            // Find any locked out intervals for vote accounts in this bank with
            // `lockout_interval_end` >= `last_vote`, which implies they are locked out at
            // `last_vote` on another fork.
            // Iterate through the lockout intervals map and check each entry
            for (
                lockout_intervals.map.keys(),
                lockout_intervals.map.values(),
            ) |lockout_interval_end, *intervals_keyed_by_end| {
                // Only consider intervals that expire at or after last_voted_slot
                if (lockout_interval_end < last_voted_slot) {
                    continue;
                }

                for (intervals_keyed_by_end.items) |vote_account| {
                    const voted_slot, const voted_pubkey = vote_account;

                    if (locked_out_vote_accounts.contains(voted_pubkey)) {
                        continue;
                    }
                    // Only count lockouts on slots that are:
                    // 1) Not ancestors of `last_vote`, meaning being on different fork
                    // 2) Not from before the current root as we can't determine if
                    // anything before the root was an ancestor of `last_vote` or not
                    if (!last_vote_ancestors.containsSlot(voted_slot) and (
                        // Given a `lockout_interval_start` < root that appears in a
                        // bank for a `candidate_slot`, it must be that `lockout_interval_start`
                        // is an ancestor of the current root, because `candidate_slot` is a
                        // descendant of the current root
                        voted_slot > root))
                    {
                        const stake =
                            if (epoch_vote_accounts.get(voted_pubkey)) |staked_account|
                                staked_account.stake
                            else
                                0;
                        locked_out_stake += stake;

                        if (@as(f64, @floatFromInt(locked_out_stake)) / @as(
                            f64,
                            @floatFromInt(total_stake),
                        ) > SWITCH_FORK_THRESHOLD) {
                            return SwitchForkDecision{ .switch_proof = switch_proof };
                        }
                        try locked_out_vote_accounts.put(allocator, voted_pubkey);
                    }
                }
            }
        }
        // Check the latest votes for potentially gossip votes that haven't landed yet
        var gossip_votes_iter = latest_validator_votes
            .max_gossip_frozen_votes
            .iterator();

        while (gossip_votes_iter.next()) |entry| {
            const vote_account_pubkey = entry.key_ptr.*;
            const candidate_latest_frozen_vote = entry.value_ptr.*.slot;

            if (locked_out_vote_accounts.contains(vote_account_pubkey)) {
                continue;
            }

            if (candidate_latest_frozen_vote > last_voted_slot) {
                // Because `candidate_latest_frozen_vote` is the last vote made by some validator
                // in the cluster for a frozen bank `B` observed through gossip, we may have cleared
                // that frozen bank `B` because we `set_root(root)` for a `root` on a different fork,
                // like so:
                //
                //    |----------X ------candidate_latest_frozen_vote (frozen)
                // old root
                //    |----------new root ----last_voted_slot
                //
                // In most cases, because `last_voted_slot` must be a descendant of `root`, then
                // if `candidate_latest_frozen_vote` is not found in the ancestors/descendants map (recall these
                // directly reflect the state of BankForks), this implies that `B` was pruned from BankForks
                // because it was on a different fork than `last_voted_slot`, and thus this vote for `candidate_latest_frozen_vote`
                // should be safe to count towards the switching proof:
                //
                // However, there is also the possibility that `last_voted_slot` is a stray, in which
                // case we cannot make this conclusion as we do not know the ancestors/descendants
                // of strays. Hence we err on the side of caution here and ignore this vote. This
                // is ok because validators voting on different unrooted forks should eventually vote
                // on some descendant of the root, at which time they can be included in switching proofs.
                const is_valid = self.isValidSwitchingProofVote(
                    candidate_latest_frozen_vote,
                    last_voted_slot,
                    switch_slot,
                    ancestors,
                    &last_vote_ancestors,
                ) orelse false;

                if (is_valid) {
                    const stake_entry = epoch_vote_accounts.get(vote_account_pubkey);
                    const stake = if (stake_entry) |entry_stake| entry_stake.stake else 0;
                    locked_out_stake += stake;

                    const stake_ratio = @as(f64, @floatFromInt(locked_out_stake)) /
                        @as(f64, @floatFromInt(total_stake));
                    if (stake_ratio > SWITCH_FORK_THRESHOLD) {
                        return SwitchForkDecision{
                            .switch_proof = switch_proof,
                        };
                    }

                    try locked_out_vote_accounts.put(allocator, vote_account_pubkey);
                }
            }
        }
        // We have not detected sufficient lockout past the last voted slot to generate
        // a switching proof
        self
            .logger
            .info()
            .logf(
            "Final failed_switch_threshold. switch_proof_stake: {}, total_stake: {}",
            .{ locked_out_stake, total_stake },
        );

        return SwitchForkDecision{
            .failed_switch_threshold = .{
                .switch_proof_stake = locked_out_stake,
                .total_stake = total_stake,
            },
        };
    }

    /// Calls the makeCheckSwitchThresholdDecision and stores the result in
    /// ReplayTower.last_switch_threshold_check if the result is different from the last check.
    pub fn checkSwitchThreshold(
        self: *ReplayTower,
        allocator: std.mem.Allocator,
        switch_slot: Slot,
        ancestors: *const AutoArrayHashMapUnmanaged(Slot, Ancestors),
        descendants: *const AutoArrayHashMapUnmanaged(Slot, SortedSetUnmanaged(Slot)),
        progress: *const ProgressMap,
        total_stake: u64,
        epoch_vote_accounts: *const StakeAndVoteAccountsMap,
        latest_validator_votes: *const LatestValidatorVotes,
        heaviest_subtree_fork_choice: *const HeaviestSubtreeForkChoice,
    ) !SwitchForkDecision {
        const decision = try self.makeCheckSwitchThresholdDecision(
            allocator,
            switch_slot,
            ancestors,
            descendants,
            progress,
            total_stake,
            epoch_vote_accounts,
            latest_validator_votes,
            heaviest_subtree_fork_choice,
        );

        if (self.last_switch_threshold_check) |last_check| {
            if (switch_slot != last_check[0] and !std.meta.eql(decision, last_check[1])) {
                self.logger.trace().logf("new switch threshold check: slot {}: {any}", .{
                    switch_slot,
                    decision,
                });
                self.last_switch_threshold_check = .{ switch_slot, decision };
            }
        }

        return decision;
    }

    fn isFirstSwitchCheck(self: *const ReplayTower) bool {
        return self.last_switch_threshold_check == null;
    }

    /// Checks whether voting for the given `slot` meets various stake threshold conditions.
    /// Returns an array of failed `ThresholdDecision`s, if any.
    ///
    /// This is used to experiment with vote lockout behavior and assess whether a vote is
    /// justified based on recent vote history, lockout depth, and voting stake.
    ///
    /// Analogous to [check_vote_stake_thresholds](https://github.com/anza-xyz/agave/blob/3572983cc28393e3c39a971c274cdac9b2eb902a/core/src/consensus.rs#L1346)
    pub fn checkVoteStakeThresholds(
        self: *const ReplayTower,
        allocator: std.mem.Allocator,
        slot: Slot,
        voted_stakes: *const VotedStakes,
        total_stake: Stake,
    ) ![]ThresholdDecision {
        const threshold_size = 3;
        var threshold_decisions: [threshold_size]ThresholdDecision = undefined;

        // Generate the vote state assuming this vote is included.
        var vote_state = self.tower;
        try vote_state.processNextVoteSlot(slot);

        // Assemble all the vote thresholds and depths to check.
        const vote_thresholds_and_depths = [threshold_size]struct { depth: usize, size: f64 }{
            // The following two checks are log only and are currently being used for experimentation
            // purposes. We wish to impose a shallow threshold check to prevent the frequent 8 deep
            // lockouts seen multiple times a day. We check both the 4th and 5th deep here to collect
            // metrics to determine the right depth and threshold percentage to set in the future.
            .{ .depth = VOTE_THRESHOLD_DEPTH_SHALLOW, .size = SWITCH_FORK_THRESHOLD },
            .{ .depth = VOTE_THRESHOLD_DEPTH_SHALLOW + 1, .size = SWITCH_FORK_THRESHOLD },
            .{ .depth = self.threshold_depth, .size = self.threshold_size },
        };

        // Check one by one and add any failures to be returned
        var index: usize = 0;
        for (vote_thresholds_and_depths) |threshold| {
            const vote_threshold = checkVoteStakeThreshold(
                .from(self.logger),
                vote_state.nthRecentLockout(threshold.depth),
                self.tower.votes.constSlice(),
                threshold.depth,
                threshold.size,
                slot,
                voted_stakes,
                total_stake,
            );

            if (std.mem.eql(u8, @tagName(vote_threshold), "failed_threshold")) {
                threshold_decisions[index] = vote_threshold;
                index += 1;
            }
        }

        return allocator.dupe(ThresholdDecision, threshold_decisions[0..index]);
    }

    fn lastVoteSignal(self: *const ReplayTower) LastVoteSignal {
        return if (self.stray_restored_slot != null and
            self.stray_restored_slot == self.lastVotedSlot())
            .stray
        else
            .normal;
    }

    pub fn isStrayLastVote(self: *const ReplayTower) bool {
        const signal = self.lastVoteSignal();
        return signal == .stray;
    }

    /// Adjusts the tower's lockouts after a replay of the ledger up to `replayed_root`.
    /// This helps synchronize the in-memory tower state with the on-disk ledger history,
    /// particularly after a validator restart or divergence.
    ///
    /// The tower root can be older/newer if the validator booted from a newer/older snapshot, so
    /// tower lockouts may need adjustment.
    pub fn adjustLockoutsAfterReplay(
        self: *ReplayTower,
        allocator: std.mem.Allocator,
        replayed_root: Slot,
        slot_history: *const SlotHistory,
    ) !void {
        const tower_root = try self.tower.getRoot();
        const voted_slots = try self.tower.votedSlots(allocator);
        defer allocator.free(voted_slots);
        self.logger.info().logf(
            \\adjusting lockouts (after replay up to {}):
            \\{any} tower root: {} replayed root: {}
        , .{
            replayed_root,
            voted_slots,
            tower_root,
            replayed_root,
        });
        // Sanity assertions for roots. Must be in the slot history
        std.debug.assert(slot_history.check(replayed_root) == .found);

        var default_vote = VoteTransaction.DEFAULT;
        defer default_vote.deinit(allocator);

        var default_tower: VoteTransaction = .{ .tower_sync = TowerSync.ZEROES };
        defer default_tower.deinit(allocator);

        // This ensures that if vote_state.votes is empty,
        // then the only acceptable values for last_vote are:
        // - A default VoteStateUpdate or
        // - A default TowerSync
        std.debug.assert(
            (self.last_vote.eql(&default_vote) and
                self.tower.votes.len == 0) or
                (self.last_vote.eql(&default_tower) and
                    self.tower.votes.len == 0) or
                (self.tower.votes.len > 0),
        );

        if (self.lastVotedSlot()) |last_voted_slot| {
            if (tower_root <= replayed_root) {
                // Normally, we goes into this clause with possible help of
                // reconcileBlockstoreRootsWithExternalSource() (yet to be implemented)
                if (slot_history.check(last_voted_slot) == .too_old) {
                    // We could try hard to anchor with other older votes, but opt to simplify the
                    // following logic
                    self
                        .logger
                        .err()
                        .logf(
                        "The tower is too old: newest slot in tower ({}) " ++
                            "<< oldest slot in available history ({})",
                        .{ last_voted_slot, slot_history.oldest() },
                    );
                    return TowerError.TooOldTower;
                }

                try self.adjustLockoutsWithSlotHistory(
                    allocator,
                    slot_history,
                );
                self.tower.root = replayed_root;
            } else {
                self.logger.err().logf(
                    \\For some reason, we're REPROCESSING slots which has already been voted and
                    \\ROOTED by us; VOTING will be SUSPENDED UNTIL {}!
                , .{last_voted_slot});

                // Let's pass-through adjust_lockouts_with_slot_history just for sanitization,
                // using a synthesized SlotHistory.
                var warped_slot_history = SlotHistory{
                    .bits = try slot_history.bits.clone(allocator),
                    .next_slot = slot_history.next_slot,
                };

                defer warped_slot_history.deinit(allocator);
                // Ledger doesn't have the tower_root slot because of
                // (replayed_root < tower_root) in this else clause, meaning the tower is from
                // the future from the view of ledger.
                // Pretend the ledger has the future tower_root to anchor exactly with that
                // slot by adding tower_root to a slot history. The added slot will be newer
                // than all slots in the slot history (remember tower_root > replayed_root),
                // satisfying the slot history invariant.
                // Thus, the whole process will be safe as well because tower_root exists
                // within both tower and slot history, guaranteeing the success of adjustment
                // and retaining all of future votes correctly while sanitizing.
                warped_slot_history.add(tower_root);

                try self.adjustLockoutsWithSlotHistory(allocator, &warped_slot_history);
                // don't update root; future tower's root should be kept across validator
                // restarts to continue to show the scary messages at restarts until the next
                // voting.
            }
        } else {
            // This else clause is for newly created tower.
            // initializeLockoutsFromBank() should ensure the following invariant,
            // otherwise we're screwing something up.
            std.debug.assert(tower_root == replayed_root);
        }
    }

    /// Ensures that the ReplayTower's lockouts are consistent with the provided
    /// `slot_history`.
    ///
    /// On success, the tower's lockouts are reinitialized to match ledger state.
    fn adjustLockoutsWithSlotHistory(
        self: *ReplayTower,
        allocator: std.mem.Allocator,
        slot_history: *const SlotHistory,
    ) !void {
        const tower_root = try self.tower.getRoot();

        var still_in_future = true;
        var past_outside_history = false;
        var maybe_checked_slot: ?Slot = null;
        var maybe_anchored_slot: ?Slot = null;

        const voted = try self.tower.votedSlots(allocator);
        defer allocator.free(voted);

        var slots_in_tower = try std.ArrayListUnmanaged(Slot)
            .initCapacity(allocator, (1 + voted.len));
        defer slots_in_tower.deinit(allocator);

        slots_in_tower.appendAssumeCapacity(tower_root);
        slots_in_tower.appendSliceAssumeCapacity(voted);

        // retained slots will be consisted only from divergent slots
        var retain_flags_for_each_vote_in_reverse = try std.ArrayListUnmanaged(bool).initCapacity(
            allocator,
            slots_in_tower.items.len,
        );
        defer retain_flags_for_each_vote_in_reverse.deinit(allocator);

        // iterate over votes + root (if any) in the newest => oldest order
        // bail out early if bad condition is found
        var iter = std.mem.reverseIterator(slots_in_tower.items);
        while (iter.next()) |slot_in_tower| {
            const check = slot_history.check(slot_in_tower);

            if (maybe_anchored_slot == null and check == .found) {
                maybe_anchored_slot = slot_in_tower;
            } else if (maybe_anchored_slot != null and check == .not_found) {
                // this can't happen unless we're fed with bogus snapshot
                self
                    .logger
                    .err()
                    .log("The tower is fatally inconsistent with ledger." ++
                    "Possible causes: diverged ancestors");
                return TowerError.FatallyInconsistentDivergedAncestors;
            }

            if (still_in_future and check != .future) {
                still_in_future = false;
            } else if (!still_in_future and check == .future) {
                // really odd cases: bad ordered votes?
                self.logger.err().log("The tower is fatally inconsistent with ledger");
                return TowerError.FatallyInconsistentTimeWarp;
            }

            if (!past_outside_history and check == .too_old) {
                past_outside_history = true;
            } else if (past_outside_history and check != .too_old) {
                // really odd cases: bad ordered votes?
                self
                    .logger
                    .err()
                    .log("The tower is fatally inconsistent with ledger." ++
                    "Possible causes: not too old once after got too old");
                return TowerError.FatallyInconsistentReplayOutOfOrder;
            }

            if (maybe_checked_slot) |checked_slot| {
                // This is really special, only if tower is initialized and contains
                // a vote for the root, the root slot can repeat only once
                const voting_for_root = slot_in_tower == checked_slot and
                    slot_in_tower == tower_root;

                if (!voting_for_root) {
                    // Unless we're voting since genesis, slots_in_tower must always be older than last checked_slot
                    // including all vote slot and the root slot.
                    if (slot_in_tower >= checked_slot) {
                        return TowerError.FatallyInconsistentTowerSlotOrder;
                    }
                }
            }

            maybe_checked_slot = slot_in_tower;
            retain_flags_for_each_vote_in_reverse
                .appendAssumeCapacity(maybe_anchored_slot == null);
        }

        // Check for errors if not anchored
        if (maybe_anchored_slot == null) {
            // this error really shouldn't happen unless ledger/tower is corrupted
            self
                .logger
                .err()
                .log("The tower is fatally inconsistent with ledger." ++
                "Possible causes: no common slot for rooted tower");
            return TowerError.FatallyInconsistent;
        }

        std.debug.assert(
            slots_in_tower.items.len == retain_flags_for_each_vote_in_reverse.items.len,
        );

        // pop for the tower root
        _ = retain_flags_for_each_vote_in_reverse.pop();
        var retain_flags_for_each_vote = std.mem.reverseIterator(
            retain_flags_for_each_vote_in_reverse.items,
        );

        var flags = try std.DynamicBitSetUnmanaged.initEmpty(
            allocator,
            retain_flags_for_each_vote_in_reverse.items.len,
        );
        defer flags.deinit(allocator);

        var i: usize = 0;
        while (retain_flags_for_each_vote.next()) |flag| {
            flags.setValue(i, flag);
            i += 1;
        }

        const stale_votes = self.tower.votes.constSlice();
        self.tower.votes.clear();
        for (stale_votes, 0..) |vote, index| {
            if (flags.isSet(index)) self.tower.votes.appendAssumeCapacity(vote);
        }

        if (self.tower.votes.len == 0) {
            // we might not have banks for those votes so just reset.
            // That's because the votes may well past replayed_root
            self.last_vote.deinit(allocator);
            self.last_vote = VoteTransaction{ .vote = Vote.ZEROES };
        } else {
            const voted_slots = try self.tower.votedSlots(allocator);
            defer allocator.free(voted_slots);
            std.debug.assert(self.lastVotedSlot().? == voted_slots[voted_slots.len - 1]);
            self.stray_restored_slot = self.last_vote.lastVotedSlot();
        }

        return;
    }

    /// [Audit] The implementations below are found in consensus::fork_choice in Agave
    ///
    /// Returns whether the last vote is able to land, which determines if we should
    /// super refresh to vote at the tip.
    pub fn lastVoteAbleToLand(
        self: *const ReplayTower,
        heaviest_bank_on_same_voted_fork: Slot,
        progress: *const ProgressMap,
        slot_history: *const SlotHistory,
    ) bool {
        const last_voted_slot = self.lastVotedSlot() orelse {
            // No previous vote.
            return true;
        };

        const stats = progress.map.get(heaviest_bank_on_same_voted_fork) orelse {
            // No stats available (fork pruned, mid-repair, or no votes landed)
            // => No need to super refresh
            return true;
        };

        const my_latest_landed_vote_slot = stats.fork_stats.my_latest_landed_vote orelse {
            // We've never landed a vote on this fork
            return true;
        };

        // Check if our last vote is able to land in order to determine if we should
        // super refresh to vote at the tip. If any of the following are true, we
        // don't need to super refresh:
        return
        // 1. Last vote has landed
        (my_latest_landed_vote_slot >= last_voted_slot) or
            // 2. Already voting at the tip
            (last_voted_slot >= heaviest_bank_on_same_voted_fork) or
            // 3. Last vote is within this bank's slot hashes history, regular refresh is enough
            (slot_history.check(last_voted_slot) == .found);
    }

    /// Handles candidate selection when fork switching fails threshold checks
    pub fn selectCandidatesFailedSwitch(
        self: *const ReplayTower,
        allocator: std.mem.Allocator,
        heaviest_slot: Slot,
        heaviest_slot_on_same_voted_fork: ?Slot,
        progress: *const ProgressMap,
        failure_reasons: *std.ArrayListUnmanaged(HeaviestForkFailures),
        switch_proof_stake: u64,
        total_stake: u64,
        initial_switch_fork_decision: SwitchForkDecision,
        slot_history: *const ?SlotHistory,
    ) !CandidateVoteAndResetSlots {
        // If our last vote is unable to land (even through normal refresh), then we
        // temporarily "super" refresh our vote to the tip of our last voted fork.
        const can_land_last_vote = if (heaviest_slot_on_same_voted_fork) |slot|
            self.lastVoteAbleToLand(
                slot,
                progress,
                &(slot_history.* orelse return error.MissingSlotHistory),
            )
        else
            // No reset slot means we are in the middle of dump & repair. Last vote
            // landing is irrelevant. So set to true to not trigger a super refresh below,
            // and to keep the initial switch fork decision and only record the failure.
            true;

        const final_switch_fork_decision = if (!can_land_last_vote) blk: {
            // Decision rationale:
            // 1. We can't switch due to threshold constraints
            // 2. Our last vote is now outside the slot hashes history of the fork's tip
            //    (no possibility of this vote landing again)
            //
            // Action: Obey threshold while trying to register our vote on the current fork.
            // Voting at the tip of the current fork won't cause longer lockout
            // (lockout doesn't double after 512 slots) and might help achieve majority.
            break :blk SwitchForkDecision.same_fork;
        } else blk: {
            // Record the failed switch attempt with details
            const failure_detail = HeaviestForkFailures{
                .FailedSwitchThreshold = .{
                    .slot = heaviest_slot,
                    .observed_stake = switch_proof_stake,
                    .total_stake = total_stake,
                },
            };
            try failure_reasons.append(allocator, failure_detail);
            break :blk initial_switch_fork_decision;
        };

        const candidate_vote_slot = if (final_switch_fork_decision.canVote())
            // We need to "super" refresh our vote to the tip of our last voted fork
            // because our last vote is unable to land. This is inferred by
            // initially determining we can't vote but then determining we can vote
            // on the same fork.
            heaviest_slot_on_same_voted_fork
        else
            // Return original vote candidate for logging purposes (can't actually vote)
            heaviest_slot;

        return CandidateVoteAndResetSlots{
            .candidate_vote_slot = if (candidate_vote_slot) |slot| slot else null,
            .reset_slot = if (heaviest_slot_on_same_voted_fork) |slot| slot else null,
            .switch_fork_decision = final_switch_fork_decision,
        };
    }

    /// Selects appropriate banks for voting and reset based on fork decision
    pub fn selectCandidateVoteAndResetBanks(
        self: *const ReplayTower,
        allocator: std.mem.Allocator,
        heaviest_slot: Slot,
        heaviest_slot_on_same_voted_fork: ?Slot,
        progress: *const ProgressMap,
        failure_reasons: *std.ArrayListUnmanaged(HeaviestForkFailures),
        initial_switch_fork_decision: SwitchForkDecision,
        slot_history: *const ?SlotHistory,
    ) !CandidateVoteAndResetSlots {
        return switch (initial_switch_fork_decision) {
            .failed_switch_threshold => |failed_switch_threshold| try self
                .selectCandidatesFailedSwitch(
                allocator,
                heaviest_slot,
                heaviest_slot_on_same_voted_fork,
                progress,
                failure_reasons,
                failed_switch_threshold.switch_proof_stake,
                failed_switch_threshold.total_stake,
                initial_switch_fork_decision,
                slot_history,
            ),
            .failed_switch_duplicate_rollback => |latest_duplicate_ancestor| blk: {
                break :blk try selectCandidatesFailedSwitchDuplicateRollback(
                    allocator,
                    latest_duplicate_ancestor,
                    failure_reasons,
                    initial_switch_fork_decision,
                );
            },
            .same_fork, .switch_proof => blk: {
                break :blk CandidateVoteAndResetSlots{
                    .candidate_vote_slot = heaviest_slot,
                    .reset_slot = heaviest_slot,
                    .switch_fork_decision = initial_switch_fork_decision,
                };
            },
        };
    }

    /// Checks for all possible reasons we might not be able to vote on the candidate
    /// bank. Records any failure reasons, and doesn't early return so we can be sure
    /// to record all possible reasons.
    pub fn canVoteOnCandidateSlot(
        self: *const ReplayTower,
        allocator: std.mem.Allocator,
        candidate_vote_bank_slot: Slot,
        progress: *const ProgressMap,
        failure_reasons: *std.ArrayListUnmanaged(HeaviestForkFailures),
        switch_fork_decision: *const SwitchForkDecision,
    ) !bool {
        const fork_stats = progress.getForkStats(candidate_vote_bank_slot) orelse
            return error.ForkStatsNotFound;

        const fork_progress = progress.map.get(candidate_vote_bank_slot) orelse
            return error.PropagatedStatsNotFound;

        const propagated_stats = fork_progress.propagated_stats;

        const is_locked_out = fork_stats.is_locked_out;
        const vote_thresholds = &fork_stats.vote_threshold;
        const propagated_stake = propagated_stats.propagated_validators_stake;
        const is_leader_slot = propagated_stats.is_leader_slot;
        const fork_weight = fork_stats.forkWeight();
        const total_threshold_stake = fork_stats.total_stake;
        const total_epoch_stake = propagated_stats.total_epoch_stake;

        // Check if we are locked out
        if (is_locked_out) {
            try failure_reasons.append(
                allocator,
                .{ .LockedOut = candidate_vote_bank_slot },
            );
        }

        // Check vote thresholds
        var threshold_passed = true;
        for (vote_thresholds.items) |threshold_failure| {
            if (threshold_failure != .failed_threshold) continue;

            const vote_depth = threshold_failure.failed_threshold.vote_depth;
            const fork_stake = threshold_failure.failed_threshold.observed_stake;
            try failure_reasons.append(allocator, .{ .FailedThreshold = .{
                .slot = candidate_vote_bank_slot,
                .vote_depth = vote_depth,
                .observed_stake = fork_stake,
                .total_stake = total_threshold_stake,
            } });

            // Ignore shallow checks for voting purposes
            if (vote_depth >= self.threshold_depth) {
                threshold_passed = false;
            }
        }

        // Check leader slot propagation
        const propagation_confirmed = is_leader_slot or
            progress.leaderSlotIsPropagated(candidate_vote_bank_slot) orelse true;
        if (!propagation_confirmed) {
            try failure_reasons.append(allocator, .{ .NoPropagatedConfirmation = .{
                .slot = candidate_vote_bank_slot,
                .observed_stake = propagated_stake,
                .total_stake = total_epoch_stake,
            } });
        }

        // Final decision
        const switch_fork_can_vote = switch_fork_decision.canVote();
        const can_vote = !is_locked_out and
            threshold_passed and
            propagation_confirmed and
            switch_fork_can_vote;

        if (can_vote) {
            self.logger.info().logf(
                "Can vote on: {d} {d:.1}%",
                .{ candidate_vote_bank_slot, 100.0 * fork_weight },
            );
        } else {
            self.logger.info().logf(
                \\Cannot vote on slot {d}:
                \\ locked_out={}
                \\ threshold_passed={}
                \\ propagation_confirmed={}
                \\ switch_fork_can_vote={}
                \\ switch_fork_decision={any}"
            ,
                .{
                    candidate_vote_bank_slot,
                    is_locked_out,
                    threshold_passed,
                    propagation_confirmed,
                    switch_fork_can_vote,
                    switch_fork_decision.*,
                },
            );
        }

        return can_vote;
    }

    /// Selects banks for voting and reset based on fork selection rules.
    /// Returns a result containing:
    /// - Optional slot to vote on (with decision)
    /// - Optional slot to reset PoH to
    /// - List of any fork selection failures
    pub fn selectVoteAndResetForks(
        self: *ReplayTower,
        allocator: std.mem.Allocator,
        heaviest_slot: Slot,
        heaviest_slot_on_same_voted_fork: ?Slot,
        heaviest_epoch: Epoch,
        ancestors: *const AutoArrayHashMapUnmanaged(u64, Ancestors),
        descendants: *const AutoArrayHashMapUnmanaged(u64, SortedSetUnmanaged(u64)),
        progress: *const ProgressMap,
        latest_validator_votes: *const LatestValidatorVotes,
        fork_choice: *const HeaviestSubtreeForkChoice,
        epoch_stakes: *const EpochStakesMap,
        /// For reading the slot history account
        account_reader: sig.accounts_db.AccountReader,
    ) !SelectVoteAndResetForkResult {
        // Initialize result with failure list
        var failure_reasons: std.ArrayListUnmanaged(HeaviestForkFailures) = .empty;
        errdefer failure_reasons.deinit(allocator);

        const epoch_stake = epoch_stakes.get(heaviest_epoch) orelse return error.ForkStatsNotFound;
        // Check switch threshold conditions
        const initial_decision = try self.checkSwitchThreshold(
            allocator,
            heaviest_slot,
            ancestors,
            descendants,
            progress,
            epoch_stake.total_stake,
            &epoch_stake.stakes.vote_accounts.vote_accounts,
            latest_validator_votes,
            fork_choice,
        );

        const maybe_slot_history: ?SlotHistory =
            if (heaviest_slot_on_same_voted_fork) |heaviest| blk: {
                const slot_ancestors = ancestors.getPtr(heaviest) orelse
                    return error.MissingAncestors;
                break :blk try getSlotHistory(allocator, account_reader.forSlot(slot_ancestors));
            } else null;
        defer if (maybe_slot_history) |slot_history| slot_history.deinit(allocator);

        // Select candidate slots
        const candidate_slots = try self.selectCandidateVoteAndResetBanks(
            allocator,
            heaviest_slot,
            heaviest_slot_on_same_voted_fork,
            progress,
            &failure_reasons,
            initial_decision,
            &maybe_slot_history,
        );

        // Handle no viable candidate case
        const candidate_vote_slot = candidate_slots.candidate_vote_slot orelse {
            return SelectVoteAndResetForkResult{
                .vote_slot = null,
                .reset_slot = candidate_slots.reset_slot.?,
                .heaviest_fork_failures = failure_reasons,
            };
        };

        if (try self.canVoteOnCandidateSlot(
            allocator,
            candidate_vote_slot,
            progress,
            &failure_reasons,
            &candidate_slots.switch_fork_decision,
        )) {
            self.metrics.switch_fork_decision.observe(candidate_slots.switch_fork_decision);
            return SelectVoteAndResetForkResult{
                .vote_slot = .{
                    .slot = candidate_vote_slot,
                    .decision = candidate_slots.switch_fork_decision,
                },
                .reset_slot = candidate_vote_slot,
                .heaviest_fork_failures = failure_reasons,
            };
        } else {
            // Unable to vote on the candidate bank.
            return SelectVoteAndResetForkResult{
                .vote_slot = null,
                .reset_slot = if (candidate_slots.reset_slot) |slot| slot else null,
                .heaviest_fork_failures = failure_reasons,
            };
        }
    }
};

pub const BlockhashStatus = union(enum) {
    /// No vote since restart
    uninitialized,
    /// Non voting validator
    non_voting,
    /// Hot spare validator
    hot_spare,
    /// Successfully generated vote tx with blockhash
    blockhash: Hash,
};

pub const SwitchForkDecision = union(enum) {
    switch_proof: Hash,
    same_fork,
    failed_switch_threshold: struct {
        /// Switch proof stake
        switch_proof_stake: u64,
        /// Total stake
        total_stake: u64,
    },
    failed_switch_duplicate_rollback: Slot,

    pub fn canVote(self: *const SwitchForkDecision) bool {
        return switch (self.*) {
            .failed_switch_threshold => false,
            .failed_switch_duplicate_rollback => false,
            .same_fork => true,
            .switch_proof => true,
        };
    }
};

/// Handles fork selection when switch fails due to duplicate rollback
pub fn selectCandidatesFailedSwitchDuplicateRollback(
    allocator: std.mem.Allocator,
    heaviest_slot: Slot,
    failure_reasons: *std.ArrayListUnmanaged(HeaviestForkFailures),
    initial_switch_fork_decision: SwitchForkDecision,
) !CandidateVoteAndResetSlots {
    // If we can't switch and our last vote was on an unconfirmed duplicate slot,
    // we reset to the heaviest bank (even if not descendant of last vote)
    try failure_reasons.append(allocator, .{
        .FailedSwitchThreshold = .{
            .slot = heaviest_slot,
            .observed_stake = 0,
            .total_stake = 0,
        },
    });

    const reset_slot: ?Slot = heaviest_slot;
    return CandidateVoteAndResetSlots{
        .candidate_vote_slot = null,
        .reset_slot = reset_slot,
        .switch_fork_decision = initial_switch_fork_decision,
    };
}

/// Returns `Some(gca)` where `gca` is the greatest (by slot number)
/// common ancestor of both `slot_a` and `slot_b`.
///
/// Returns `null` if:
/// * `slot_a` is not in `ancestors`
/// * `slot_b` is not in `ancestors`
/// * There is no common ancestor of slot_a and slot_b in `ancestors`
fn greatestCommonAncestor(
    ancestors: *const AutoArrayHashMapUnmanaged(
        Slot,
        Ancestors,
    ),
    slot_a: Slot,
    slot_b: Slot,
) ?Slot {
    const ancestors_a = ancestors.get(slot_a) orelse return null;
    const ancestors_b = ancestors.get(slot_b) orelse return null;

    var max_slot: ?Slot = null;

    var superset, const subset = if (ancestors_a.ancestors.count() >= ancestors_b.ancestors.count())
        .{ ancestors_a, ancestors_b }
    else
        .{ ancestors_b, ancestors_a };

    if (superset.ancestors.count() == 0 or subset.ancestors.count() == 0) return null;

    for (superset.ancestors.keys()) |slot| {
        if (!subset.containsSlot(slot)) continue;
        max_slot = if (max_slot) |current_max| @max(current_max, slot) else slot;
    }

    return max_slot;
}

/// Checks if `maybe_descendant` is a descendant of `slot`.
///
/// Returns none if `maybe_descendant` is not present in `ancestors`
fn isDescendantSlot(
    maybe_descendant: Slot,
    slot: Slot,
    ancestors: *const AutoArrayHashMapUnmanaged(Slot, Ancestors),
) ?bool {
    return if (ancestors.get(maybe_descendant)) |candidate_slot_ancestors|
        candidate_slot_ancestors.containsSlot(slot)
    else
        null;
}

fn checkVoteStakeThreshold(
    logger: Logger,
    maybe_threshold_vote: ?Lockout,
    tower_before_applying_vote: []const Lockout,
    threshold_depth: usize,
    threshold_size: f64,
    slot: Slot,
    voted_stakes: *const VotedStakes,
    total_stake: u64,
) ThresholdDecision {
    const threshold_vote = maybe_threshold_vote orelse {
        // Tower isn't that deep.
        return .passed_threshold;
    };

    const fork_stake = voted_stakes.get(threshold_vote.slot) orelse {
        // We haven't seen any votes on this fork yet, so no stake
        return .{
            .failed_threshold = .{ .vote_depth = threshold_depth, .observed_stake = 0 },
        };
    };

    const lockout = @as(f64, @floatFromInt(fork_stake)) / @as(
        f64,
        @floatFromInt(total_stake),
    );

    logger.trace().logf(
        \\fork_stake slot: {}, threshold_vote slot: {}, lockout: {} fork_stake:
        \\{} total_stake: {}
    ,
        .{
            slot,
            threshold_vote.slot,
            lockout,
            fork_stake,
            total_stake,
        },
    );

    if (optimisticallyBypassVoteStakeThresholdCheck(
        tower_before_applying_vote,
        threshold_vote,
    ) or lockout > threshold_size) {
        return .passed_threshold;
    }

    return .{
        .failed_threshold = .{
            .vote_depth = threshold_depth,
            .observed_stake = fork_stake,
        },
    };
}

// Optimistically skip the stake check if casting a vote would not increase
// the lockout at this threshold. This is because if you bounce back to
// voting on the main fork after not voting for a while, your latest vote
// might pop off a lot of the votes in the tower. The stake from these votes
// would have rolled up to earlier votes in the tower, which presumably
// could have helped us pass the threshold check. Worst case, we'll just
// recheck later without having increased lockouts.
fn optimisticallyBypassVoteStakeThresholdCheck(
    tower_before_applying_vote: []const Lockout,
    threshold_vote: Lockout,
) bool {
    for (tower_before_applying_vote) |old_vote| {
        if (old_vote.slot == threshold_vote.slot and
            old_vote.confirmation_count == threshold_vote.confirmation_count)
        {
            return true;
        }
    }
    return false;
}

/// Collects cluster vote state for a frozen slot by aggregating landed votes across validators.
/// The result is used by fork choice (threshold checks, duplicate confirmation) and related
/// consensus decisions.
///
/// This function simulates each validator's next vote at `slot` (via processNextVoteSlot) to
/// project the lockout landscape and identify relevant vote slots. It helps with:
/// - Forward-looking analysis: see how the network would look AFTER everyone votes, helping
///   predict safety and consensus.
/// - Lockout expiry: when advancing to `slot`, expired votes are popped, changing the lockout
///   landscape before thresholds are evaluated.
/// - Root advancement: simulation may advance roots, revealing consensus that was not visible at
///   earlier depths.
/// - Consistent view: deterministic simulation produces the same projected state across validators.
///
/// Note: the simulated vote is excluded from stake accumulation; stake is credited only to the
/// latest landed vote (and its ancestors). As a result, `fork_stake` is taken from the parent of `slot`.
///
/// Analogous to [collect_vote_lockouts]https://github.com/anza-xyz/agave/blob/91520c7095c4db968fe666b80a1b80dfef1bd909/core/src/consensus.rs#L389
pub fn collectClusterVoteState(
    allocator: std.mem.Allocator,
    logger: Logger,
    vote_account_pubkey: ?Pubkey,
    bank_slot: Slot,
    vote_accounts: *const StakeAndVoteAccountsMap,
    ancestors: *const AutoArrayHashMapUnmanaged(Slot, Ancestors),
    progress_map: *const ProgressMap,
    latest_validator_votes: *LatestValidatorVotes,
) !ClusterVoteState {
    var zone = tracy.Zone.init(@src(), .{ .name = "collectClusterVoteState" });
    defer zone.deinit();

    // The state we are interested in.
    var vote_slots: SortedSetUnmanaged(Slot) = .empty;
    defer vote_slots.deinit(allocator);
    var voted_stakes = VotedStakes.empty;
    var total_stake: u64 = 0;
    // Tree of intervals of lockouts of the form [slot, slot + slot.lockout],
    // keyed by end of the range
    var lockout_intervals = LockoutIntervals.EMPTY;
    errdefer lockout_intervals.deinit(allocator);
    var my_latest_landed_vote: ?Slot = null;

    for (vote_accounts.keys(), vote_accounts.values()) |vote_address, vote| {
        // Skip accounts with no stake.
        if (vote.stake == 0) {
            continue;
        }

        logger.trace().logf(
            "{?} {} with stake {}",
            .{ vote_account_pubkey, vote_address, vote.stake },
        );

        var vote_state = try Tower.fromAccount(&vote.account.state);

        for (vote_state.votes.constSlice()) |lockout_vote| {
            const interval = try lockout_intervals.map
                .getOrPut(allocator, lockout_vote.lastLockedOutSlot());
            if (!interval.found_existing) {
                interval.value_ptr.* = .empty;
            }
            try interval.value_ptr.append(allocator, .{ lockout_vote.slot, vote_address });
        }

        // Vote account for this validator
        if (vote_account_pubkey != null and vote_address.equals(&vote_account_pubkey.?)) {
            my_latest_landed_vote = if (vote_state.nthRecentLockout(0)) |l| l.slot else null;
            logger.debug().logf("vote state {any}", .{vote_state});
            const observed_slot = if (vote_state.nthRecentLockout(0)) |l| l.slot else 0;

            logger.debug().logf("observed slot {any}", .{observed_slot});
        }
        const start_root = vote_state.root;

        // Track the last vote in latest validator votes for latest frozen states
        // so that it can be used to update the fork choice.
        if (vote_state.lastVotedSlot()) |last_landed_voted_slot| {
            if (progress_map.getHash(last_landed_voted_slot)) |frozen_hash| {
                _ = try latest_validator_votes.checkAddVote(
                    allocator,
                    vote_address,
                    last_landed_voted_slot,
                    frozen_hash,
                    .replay,
                );
            }
        }

        // Simulate next vote and extract vote slots using the provided bank slot.
        try vote_state.processNextVoteSlot(bank_slot);

        for (vote_state.votes.constSlice()) |lockout_vote| {
            try vote_slots.put(allocator, lockout_vote.slot);
        }

        if (start_root != vote_state.root) {
            if (start_root) |root| {
                try vote_slots.put(allocator, root);
            }
        }
        if (vote_state.root) |root| {
            try vote_slots.put(allocator, root);
        }

        // The last vote in the vote stack is a simulated vote on bank_slot, which
        // we added to the vote stack earlier in this function by calling processNextVoteSlot().
        // We don't want to update the ancestors stakes of this vote b/c it does not
        // represent an actual vote by the validator.

        // Note: It should not be possible for any vote state in this bank to have
        // a vote for a slot >= bank_slot, so we are guaranteed that the last vote in
        // this vote stack is the simulated vote, so this fetch should be sufficient
        // to find the last unsimulated vote.
        std.debug.assert(vote_state.nthRecentLockout(0).?.slot == bank_slot);

        if (vote_state.nthRecentLockout(1)) |lockout| {
            // Update all the parents of this last vote with the stake of this vote account
            try updateAncestorVotedStakes(
                allocator,
                &voted_stakes,
                lockout.slot,
                vote.stake,
                ancestors,
            );
        }
        total_stake += vote.stake;
    }

    try populateAncestorVotedStakes(
        allocator,
        &voted_stakes,
        vote_slots.items(),
        ancestors,
    );

    // As commented above, since the votes at current bank_slot are
    // simulated votes, the voted_stake for `bank_slot` is not populated.
    // Therefore, we use the voted_stake for the parent of bank_slot as the
    // `fork_stake` instead.
    const fork_stake: u64 = blk: {
        var bank_ancestors = ancestors.get(bank_slot) orelse break :blk 0;
        var max_parent: ?Slot = null;
        for (bank_ancestors.ancestors.keys()) |slot| {
            if (max_parent == null or slot > max_parent.?) {
                max_parent = slot;
            }
        }
        if (max_parent) |parent| {
            break :blk voted_stakes.get(parent) orelse 0;
        } else {
            break :blk 0;
        }
    };

    return ClusterVoteState{
        .voted_stakes = voted_stakes,
        .total_stake = total_stake,
        .fork_stake = fork_stake,
        .lockout_intervals = lockout_intervals,
        .my_latest_landed_vote = my_latest_landed_vote,
    };
}

pub fn populateAncestorVotedStakes(
    allocator: std.mem.Allocator,
    voted_stakes: *VotedStakes,
    vote_slots: []const Slot,
    ancestors: *const AutoArrayHashMapUnmanaged(Slot, Ancestors),
) !void {
    // If there's no ancestors, that means this slot must be from before the current root,
    // in which case the lockouts won't be calculated in bank_weight anyways, so ignore
    // this slot
    for (vote_slots) |vote_slot| {
        if (ancestors.getPtr(vote_slot)) |slot_ancestors| {
            _ = try voted_stakes.getOrPutValue(allocator, vote_slot, 0);

            for (slot_ancestors.ancestors.keys()) |slot| {
                _ = try voted_stakes.getOrPutValue(allocator, slot, 0);
            }
        }
    }
}

fn updateAncestorVotedStakes(
    allocator: std.mem.Allocator,
    voted_stakes: *VotedStakes,
    voted_slot: Slot,
    voted_stake: u64,
    ancestors: *const AutoArrayHashMapUnmanaged(Slot, Ancestors),
) !void {
    // If there's no ancestors, that means this slot must be from
    // before the current root, so ignore this slot
    if (ancestors.getPtr(voted_slot)) |vote_slot_ancestors| {
        const entry_vote_stake = try voted_stakes.getOrPutValue(allocator, voted_slot, 0);
        entry_vote_stake.value_ptr.* += voted_stake;
        for (vote_slot_ancestors.ancestors.keys()) |ancestor_slot| {
            // Ideally, slot should not be included the list of its ancestors.
            // still check to avoid double-counting by skipping.
            if (ancestor_slot == voted_slot) continue;
            const entry_voted_stake = try voted_stakes.getOrPutValue(allocator, ancestor_slot, 0);
            entry_voted_stake.value_ptr.* += voted_stake;
        }
    }
}

/// Analogous to [is_slot_duplicate_confirmed](https://github.com/anza-xyz/agave/blob/91520c7095c4db968fe666b80a1b80dfef1bd909/core/src/consensus.rs#L540)
pub fn isDuplicateSlotConfirmed(
    slot: Slot,
    voted_stakes: *const VotedStakes,
    total_stake: Stake,
) bool {
    if (voted_stakes.get(slot)) |stake| {
        return (@as(f64, @floatFromInt(stake)) / @as(f64, @floatFromInt(total_stake))) >
            DUPLICATE_THRESHOLD;
    } else {
        return false;
    }
}

test "is slot duplicate confirmed not enough stake failure" {
    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 52);

    const result = isDuplicateSlotConfirmed(
        0,
        &stakes,
        100,
    );
    try std.testing.expect(!result);
}

test "is slot duplicate confirmed unknown slot" {
    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);

    const result = isDuplicateSlotConfirmed(
        0,
        &stakes,
        100,
    );
    try std.testing.expect(!result);
}

test "is slot duplicate confirmed pass" {
    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 53);

    const result = isDuplicateSlotConfirmed(
        0,
        &stakes,
        100,
    );
    try std.testing.expect(result);
}

test "check_vote_threshold_forks" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    // Create the ancestor relationships
    var ancestors = std.AutoArrayHashMapUnmanaged(u64, Ancestors).empty;
    defer {
        var it = ancestors.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(allocator);
        }
        ancestors.deinit(allocator);
    }

    const vote_threshold_depth_plus_2 = VOTE_THRESHOLD_DEPTH + 2;
    try ancestors.ensureUnusedCapacity(allocator, vote_threshold_depth_plus_2);
    for (0..vote_threshold_depth_plus_2) |i| {
        var slot_parents: Ancestors = .EMPTY;
        errdefer slot_parents.deinit(allocator);
        for (0..i) |j| {
            try slot_parents.addSlot(allocator, j);
        }
        ancestors.putAssumeCapacity(i, slot_parents);
    }

    // Create votes such that
    // 1) 3/4 of the stake has voted on slot: VOTE_THRESHOLD_DEPTH - 2, lockout: 2
    // 2) 1/4 of the stake has voted on slot: VOTE_THRESHOLD_DEPTH, lockout: 2^9
    const total_stake: u64 = 4;
    const threshold_size: f64 = 0.67;
    const threshold_stake: u64 = @intFromFloat(@ceil(total_stake * threshold_size));
    const tower_votes = try allocator.alloc(u64, VOTE_THRESHOLD_DEPTH);
    defer {
        allocator.free(tower_votes);
    }
    for (tower_votes, 0..) |*slot, i| {
        slot.* = @as(u64, i);
    }

    var votes = [_]u64{VOTE_THRESHOLD_DEPTH - 2};
    var accounts = try genStakes(
        allocator,
        random,
        &.{
            .{ threshold_stake, &votes },
            .{ total_stake - threshold_stake, tower_votes },
        },
    );
    defer {
        for (accounts.values()) |*value| value.deinit(allocator);
        accounts.deinit(allocator);
    }

    // Initialize tower
    var replay_tower = try sig.consensus.replay_tower.createTestReplayTower(
        VOTE_THRESHOLD_DEPTH,
        threshold_size,
    );
    defer replay_tower.deinit(allocator);

    {
        // CASE 1: Record the first VOTE_THRESHOLD tower votes for fork 2. We want to
        // evaluate a vote on slot VOTE_THRESHOLD_DEPTH. The nth most recent vote should be
        // for slot 0, which is common to all account vote states, so we should pass the
        // threshold check
        const vote_to_evaluate = VOTE_THRESHOLD_DEPTH;
        for (tower_votes) |vote| {
            _ = try replay_tower.recordBankVote(
                allocator,
                vote,
                Hash.ZEROES,
            );
        }

        var progress_map: ProgressMap = .INIT;
        defer progress_map.deinit(allocator);

        var latest_votes: LatestValidatorVotes = .empty;
        defer latest_votes.deinit(allocator);

        var computed_banks = try collectClusterVoteState(
            allocator,
            .noop,
            null,
            vote_to_evaluate,
            &accounts,
            &ancestors,
            &progress_map,
            &latest_votes,
        );
        defer computed_banks.deinit(allocator);
        const result = try replay_tower.checkVoteStakeThresholds(
            std.testing.allocator,
            vote_to_evaluate,
            &computed_banks.voted_stakes,
            computed_banks.total_stake,
        );
        std.testing.allocator.free(result);
        try std.testing.expectEqual(0, result.len);
    }

    {
        // CASE 2: Now we want to evaluate a vote for slot VOTE_THRESHOLD_DEPTH + 1. This slot
        // will expire the vote in one of the vote accounts, so we should have insufficient
        // stake to pass the threshold
        var progres_map = ProgressMap.INIT;
        defer progres_map.deinit(allocator);

        var latest_votes = LatestValidatorVotes.empty;

        const vote_to_evaluate = VOTE_THRESHOLD_DEPTH;
        var computed_banks = try collectClusterVoteState(
            allocator,
            .noop,
            null,
            vote_to_evaluate,
            &accounts,
            &ancestors,
            &progres_map,
            &latest_votes,
        );
        defer computed_banks.deinit(allocator);
        const result = try replay_tower.checkVoteStakeThresholds(
            std.testing.allocator,
            vote_to_evaluate,
            &computed_banks.voted_stakes,
            computed_banks.total_stake,
        );
        std.testing.allocator.free(result);
        try std.testing.expectEqual(0, result.len);
    }
}

test "collect vote lockouts root" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const votes = try allocator.alloc(u64, MAX_LOCKOUT_HISTORY);
    for (votes, 0..) |*slot, i| {
        slot.* = @as(u64, i);
    }
    defer allocator.free(votes);

    var accounts = try genStakes(
        allocator,
        random,
        &.{ .{ 1, votes }, .{ 1, votes } },
    );
    defer {
        for (accounts.values()) |*value| value.deinit(allocator);
        accounts.deinit(allocator);
    }

    const account_latest_votes =
        try allocator.alloc(
            struct { Pubkey, sig.core.hash.SlotAndHash },
            accounts.count(),
        );
    defer allocator.free(account_latest_votes);

    for (accounts.keys(), 0..) |key, i| {
        account_latest_votes[i] =
            .{
                key,
                sig.core.hash.SlotAndHash{
                    .slot = (MAX_LOCKOUT_HISTORY - 1),
                    .hash = sig.core.hash.Hash.ZEROES,
                },
            };
    }

    var replay_tower = try sig.consensus.replay_tower.createTestReplayTower(
        0,
        0.67,
    );
    defer replay_tower.deinit(allocator);

    var ancestors = std.AutoArrayHashMapUnmanaged(u64, Ancestors).empty;
    defer {
        var it = ancestors.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(allocator);
        }
        ancestors.deinit(allocator);
    }

    const max_lockout_history_plus_1 = MAX_LOCKOUT_HISTORY + 1;
    try ancestors.ensureUnusedCapacity(allocator, max_lockout_history_plus_1);

    for (0..max_lockout_history_plus_1) |i| {
        _ = try replay_tower.recordBankVote(allocator, i, .initRandom(random));
        var slots: Ancestors = .EMPTY;
        errdefer slots.deinit(allocator);
        for (0..i) |j| {
            try slots.addSlot(allocator, j);
        }
        try ancestors.put(allocator, i, slots);
    }
    const root = Lockout{
        .slot = 0,
        .confirmation_count = MAX_LOCKOUT_HISTORY,
    };
    const expected_bank_stake = 2;
    const expected_total_stake = 2;

    try std.testing.expectEqual(0, replay_tower.tower.root);

    var latest_votes: LatestValidatorVotes = .empty;
    defer latest_votes.deinit(allocator);

    var progress_map = ProgressMap.INIT;
    defer progress_map.deinit(allocator);

    var fork_progress: sig.consensus.progress_map.ForkProgress = try .zeroes(allocator);
    errdefer fork_progress.deinit(allocator);

    for (accounts.values()) |value| {
        try progress_map.map.put(
            allocator,
            value.account.state.lastVotedSlot().?,
            fork_progress,
        );
    }

    var computed_banks = try collectClusterVoteState(
        allocator,
        .noop,
        .initRandom(random),
        MAX_LOCKOUT_HISTORY,
        &accounts,
        &ancestors,
        &progress_map,
        &latest_votes,
    );
    defer computed_banks.deinit(allocator);

    for (0..MAX_LOCKOUT_HISTORY) |i| {
        try std.testing.expectEqual(2, computed_banks.voted_stakes.get(i).?);
    }

    try std.testing.expectEqual(expected_bank_stake, computed_banks.fork_stake);
    try std.testing.expectEqual(expected_total_stake, computed_banks.total_stake);

    const new_votes =
        try latest_votes.takeVotesDirtySet(allocator, root.slot);
    defer allocator.free(new_votes);

    try std.testing.expectEqualSlices(
        struct { Pubkey, sig.core.hash.SlotAndHash },
        account_latest_votes,
        new_votes,
    );
}

test "collect vote lockouts sums" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    // two accounts voting for slot 0 with 1 token staked
    var votes = [_]u64{0};

    var accounts = try genStakes(
        allocator,
        random,
        &.{ .{ 1, &votes }, .{ 1, &votes } },
    );
    defer {
        for (accounts.values()) |*value| value.deinit(allocator);
        accounts.deinit(allocator);
    }

    const account_latest_votes = try allocator.alloc(
        struct { Pubkey, sig.core.hash.SlotAndHash },
        accounts.count(),
    );
    defer allocator.free(account_latest_votes);

    for (accounts.keys(), 0..) |key, i| {
        account_latest_votes[i] =
            .{
                key,
                sig.core.hash.SlotAndHash{
                    .slot = 0,
                    .hash = sig.core.hash.Hash.ZEROES,
                },
            };
    }

    // ancestors: slot 1 has ancestor 0, slot 0 has no ancestors
    var ancestors = std.AutoArrayHashMapUnmanaged(u64, Ancestors).empty;
    defer {
        var it = ancestors.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit(allocator);
        }
        ancestors.deinit(allocator);
    }
    const set0: Ancestors = .EMPTY;
    var set1: Ancestors = .EMPTY;
    try set1.addSlot(allocator, 0);
    try ancestors.put(allocator, 0, set0);
    try ancestors.put(allocator, 1, set1);

    var latest_votes = LatestValidatorVotes.empty;
    defer latest_votes.deinit(allocator);

    var progres_map = ProgressMap.INIT;
    defer progres_map.deinit(allocator);

    var fork_progress: sig.consensus.progress_map.ForkProgress = try .zeroes(allocator);
    errdefer fork_progress.deinit(allocator);

    for (accounts.values()) |account| {
        try progres_map.map.put(
            allocator,
            account.account.state.lastVotedSlot().?,
            fork_progress,
        );
    }

    var computed_banks = try collectClusterVoteState(
        allocator,
        .noop,
        null,
        1,
        &accounts,
        &ancestors,
        &progres_map,
        &latest_votes,
    );
    defer computed_banks.deinit(allocator);

    try std.testing.expectEqual(2, computed_banks.voted_stakes.get(0).?);
    try std.testing.expectEqual(2, computed_banks.total_stake);

    const new_votes = try latest_votes.takeVotesDirtySet(allocator, 0);
    defer allocator.free(new_votes);
    try std.testing.expectEqualSlices(
        struct { Pubkey, sig.core.hash.SlotAndHash },
        account_latest_votes,
        new_votes,
    );
}

test "check vote threshold without votes" {
    var tower = try createTestReplayTower(1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 1);

    const result = try tower.checkVoteStakeThresholds(
        std.testing.allocator,
        0,
        &stakes,
        2,
    );
    std.testing.allocator.free(result);
    try std.testing.expectEqual(0, result.len);
}

test "check vote threshold no skip lockout with new root" {
    var replay_tower = try createTestReplayTower(4, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, MAX_LOCKOUT_HISTORY);

    for (0..(MAX_LOCKOUT_HISTORY + 1)) |i| {
        stakes.putAssumeCapacity(i, 1);
        _ = try replay_tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    const result = try replay_tower.checkVoteStakeThresholds(
        std.testing.allocator,
        MAX_LOCKOUT_HISTORY + 1,
        &stakes,
        2,
    );
    std.testing.allocator.free(result);
    try std.testing.expect(result.len != 0);
}

test "is locked out empty" {
    var replay_tower = try createTestReplayTower(0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors: Ancestors = .EMPTY;
    defer ancestors.deinit(std.testing.allocator);
    try ancestors.addSlot(std.testing.allocator, 0);

    const result = try replay_tower.tower.isLockedOut(
        1,
        &ancestors,
    );
    try std.testing.expect(!result);
}

test "is locked out root slot child pass" {
    var replay_tower = try createTestReplayTower(0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors: Ancestors = .EMPTY;
    defer ancestors.deinit(std.testing.allocator);
    try ancestors.addSlot(std.testing.allocator, 0);

    replay_tower.tower.root = 0;

    const result = try replay_tower.tower.isLockedOut(
        1,
        &ancestors,
    );
    try std.testing.expect(!result);
}

test "is locked out root slot sibling fail" {
    var replay_tower = try createTestReplayTower(0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors: Ancestors = .EMPTY;
    defer ancestors.deinit(std.testing.allocator);
    try ancestors.addSlot(std.testing.allocator, 0);

    replay_tower.tower.root = 0;

    _ = try replay_tower.recordBankVote(
        std.testing.allocator,
        1,
        Hash.ZEROES,
    );

    const result = try replay_tower.tower.isLockedOut(
        2,
        &ancestors,
    );

    try std.testing.expect(result);
}

test "check already voted" {
    var replay_tower = try createTestReplayTower(0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.tower.root = 0;

    _ = try replay_tower.recordBankVote(
        std.testing.allocator,
        0,
        Hash.ZEROES,
    );

    try std.testing.expect(replay_tower.tower.hasVoted(0));
    try std.testing.expect(!replay_tower.tower.hasVoted(1));
}

test "check recent slot" {
    var replay_tower = try createTestReplayTower(0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    try std.testing.expect(replay_tower.tower.isRecent(1));
    try std.testing.expect(replay_tower.tower.isRecent(32));

    for (0..64) |i| {
        _ = try replay_tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    try std.testing.expect(!replay_tower.tower.isRecent(0));
    try std.testing.expect(!replay_tower.tower.isRecent(32));
    try std.testing.expect(!replay_tower.tower.isRecent(63));
    try std.testing.expect(replay_tower.tower.isRecent(65));
}

test "is locked out double vote" {
    var replay_tower = try createTestReplayTower(0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors: Ancestors = .EMPTY;
    defer ancestors.deinit(std.testing.allocator);
    try ancestors.addSlot(std.testing.allocator, 0);

    for (0..2) |i| {
        _ = try replay_tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    const result = try replay_tower.tower.isLockedOut(
        0,
        &ancestors,
    );

    try std.testing.expect(result);
}

test "is locked out child" {
    var replay_tower = try createTestReplayTower(0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors: Ancestors = .EMPTY;
    defer ancestors.deinit(std.testing.allocator);
    try ancestors.addSlot(std.testing.allocator, 0);

    _ = try replay_tower.recordBankVote(
        std.testing.allocator,
        0,
        Hash.ZEROES,
    );

    const result = try replay_tower.tower.isLockedOut(
        1,
        &ancestors,
    );

    try std.testing.expect(!result);
}

test "is locked out sibling" {
    var replay_tower = try createTestReplayTower(0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors: Ancestors = .EMPTY;
    defer ancestors.deinit(std.testing.allocator);
    try ancestors.addSlot(std.testing.allocator, 0);

    for (0..2) |i| {
        _ = try replay_tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    const result = try replay_tower.tower.isLockedOut(
        2,
        &ancestors,
    );

    try std.testing.expect(result);
}

test "is locked out last vote expired" {
    var replay_tower = try createTestReplayTower(0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors: Ancestors = .EMPTY;
    defer ancestors.deinit(std.testing.allocator);
    try ancestors.addSlot(std.testing.allocator, 0);

    for (0..2) |i| {
        _ = try replay_tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    const result = try replay_tower.tower.isLockedOut(
        4,
        &ancestors,
    );

    try std.testing.expect(!result);

    _ = try replay_tower.recordBankVote(
        std.testing.allocator,
        4,
        Hash.ZEROES,
    );

    try std.testing.expectEqual(0, replay_tower.tower.votes.get(0).slot);
    try std.testing.expectEqual(2, replay_tower.tower.votes.get(0).confirmation_count);
    try std.testing.expectEqual(4, replay_tower.tower.votes.get(1).slot);
    try std.testing.expectEqual(1, replay_tower.tower.votes.get(1).confirmation_count);
}

test "check vote threshold below threshold" {
    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 1);

    _ = try replay_tower.recordBankVote(
        std.testing.allocator,
        0,
        Hash.ZEROES,
    );

    const result = try replay_tower.checkVoteStakeThresholds(
        std.testing.allocator,
        1,
        &stakes,
        2,
    );
    std.testing.allocator.free(result);
    try std.testing.expect(result.len != 0);
}

test "check vote threshold above threshold" {
    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 2);

    _ = try replay_tower.recordBankVote(
        std.testing.allocator,
        0,
        Hash.ZEROES,
    );

    const result = try replay_tower.checkVoteStakeThresholds(
        std.testing.allocator,
        1,
        &stakes,
        2,
    );
    std.testing.allocator.free(result);
    try std.testing.expectEqual(0, result.len);
}

test "check vote thresholds above thresholds" {
    var tower = try createTestReplayTower(VOTE_THRESHOLD_DEPTH, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 3);

    stakes.putAssumeCapacity(0, 3);
    stakes.putAssumeCapacity(VOTE_THRESHOLD_DEPTH_SHALLOW, 2);
    stakes.putAssumeCapacity(VOTE_THRESHOLD_DEPTH_SHALLOW - 1, 2);

    for (0..VOTE_THRESHOLD_DEPTH) |i| {
        _ = try tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    const result = try tower.checkVoteStakeThresholds(
        std.testing.allocator,
        VOTE_THRESHOLD_DEPTH,
        &stakes,
        4,
    );

    std.testing.allocator.free(result);
    try std.testing.expectEqual(0, result.len);
}

test "check vote threshold deep below threshold" {
    var tower = try createTestReplayTower(VOTE_THRESHOLD_DEPTH, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 2);

    stakes.putAssumeCapacity(0, 6);
    stakes.putAssumeCapacity(VOTE_THRESHOLD_DEPTH_SHALLOW, 4);

    for (0..VOTE_THRESHOLD_DEPTH) |i| {
        _ = try tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    const result = try tower.checkVoteStakeThresholds(
        std.testing.allocator,
        VOTE_THRESHOLD_DEPTH,
        &stakes,
        10,
    );

    std.testing.allocator.free(result);
    try std.testing.expect(result.len != 0);
}

test "check vote threshold shallow below threshold" {
    var tower = try createTestReplayTower(VOTE_THRESHOLD_DEPTH, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 2);

    stakes.putAssumeCapacity(0, 7);
    stakes.putAssumeCapacity(VOTE_THRESHOLD_DEPTH_SHALLOW, 1);

    for (0..VOTE_THRESHOLD_DEPTH) |i| {
        _ = try tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    const result = try tower.checkVoteStakeThresholds(
        std.testing.allocator,
        VOTE_THRESHOLD_DEPTH,
        &stakes,
        10,
    );

    std.testing.allocator.free(result);
    try std.testing.expect(result.len != 0);
}

test "check vote threshold above threshold after pop" {
    var tower = try createTestReplayTower(1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 2);

    for (0..3) |i| {
        _ = try tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    const result = try tower.checkVoteStakeThresholds(
        std.testing.allocator,
        6,
        &stakes,
        2,
    );

    std.testing.allocator.free(result);
    try std.testing.expectEqual(0, result.len);
}

test "check vote threshold above threshold no stake" {
    var tower = try createTestReplayTower(1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);

    _ = try tower.recordBankVote(
        std.testing.allocator,
        0,
        Hash.ZEROES,
    );

    const result = try tower.checkVoteStakeThresholds(
        std.testing.allocator,
        1,
        &stakes,
        2,
    );

    std.testing.allocator.free(result);
    try std.testing.expect(result.len != 0);
}

test "check vote threshold lockouts not updated" {
    var tower = try createTestReplayTower(1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 2);

    stakes.putAssumeCapacity(0, 1);
    stakes.putAssumeCapacity(1, 2);

    for (0..3) |i| {
        _ = try tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    const result = try tower.checkVoteStakeThresholds(
        std.testing.allocator,
        6,
        &stakes,
        2,
    );

    std.testing.allocator.free(result);
    try std.testing.expect(result.len == 0);
}

test "default thresholds" {
    const allocator = std.testing.allocator;

    // Build a minimal fork with just the root slot present
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();
    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };

    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    const trees = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    try fixture.fillFork(allocator, .{ .root = root, .data = trees }, .active);

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var replay_tower = try ReplayTower.init(
        .noop,
        Pubkey.ZEROES,
        .{ .root = root.slot },
        &registry,
    );
    defer replay_tower.deinit(allocator);

    // Ensure candidate slot exists in progress
    const candidate_slot = root.slot;

    // Mark as leader slot so propagation is confirmed
    if (fixture.progress.map.getPtr(candidate_slot)) |fp| {
        fp.propagated_stats.is_leader_slot = true;
    } else {
        return error.MissingSlot;
    }

    // Inject a failed threshold at vote_depth=0 into fork stats
    const stats = fixture.progress.getForkStats(candidate_slot).?;
    try stats.vote_threshold.append(allocator, .{
        .failed_threshold = .{ .vote_depth = 0, .observed_stake = 0 },
    });

    // Now verify that canVoteOnCandidateSlot returns true and does not treat
    // vote_depth=0 as disqualifying with non-zero default threshold_depth
    var failure_reasons: std.ArrayListUnmanaged(HeaviestForkFailures) = .empty;
    defer failure_reasons.deinit(allocator);

    const can_vote = try replay_tower.canVoteOnCandidateSlot(
        allocator,
        candidate_slot,
        &fixture.progress,
        &failure_reasons,
        &SwitchForkDecision{ .same_fork = {} },
    );

    try std.testing.expect(can_vote);
}

test "maybe timestamp" {
    var replay_tower = try createTestReplayTower(0, 0);
    try std.testing.expect(replay_tower.maybeTimestamp(0) != null);
    try std.testing.expect(replay_tower.maybeTimestamp(1) != null);
    // Refuse to timestamp an older slot
    try std.testing.expect(replay_tower.maybeTimestamp(0) == null);
    // Refuse to timestamp the same slot twice
    try std.testing.expect(replay_tower.maybeTimestamp(1) == null);

    // Move last_timestamp into the past
    replay_tower.last_timestamp.timestamp -= 1;
    // slot 2 gets a timestamp
    try std.testing.expect(replay_tower.maybeTimestamp(2) != null);

    // Move last_timestamp well into the future
    replay_tower.last_timestamp.timestamp += 1_000_000;
    // slot 3 gets no timestamp
    try std.testing.expect(replay_tower.maybeTimestamp(3) == null);
}

test "refresh last vote timestamp" {
    var replay_tower = try createTestReplayTower(0, 0);

    // Tower has no vote or timestamp
    replay_tower.last_vote.setTimestamp(null);
    replay_tower.refreshLastVoteTimestamp(5);
    try std.testing.expectEqual(null, replay_tower.last_vote.timestamp());
    try std.testing.expectEqual(0, replay_tower.last_timestamp.slot);
    try std.testing.expectEqual(0, replay_tower.last_timestamp.timestamp);

    {
        // Tower has vote no timestamp, but is greater than heaviest_bank
        var expected_slots = try std.ArrayListUnmanaged(Lockout).initCapacity(
            std.testing.allocator,
            3,
        );
        defer expected_slots.deinit(std.testing.allocator);
        var lockouts = [_]Lockout{
            Lockout{ .slot = 0, .confirmation_count = 3 },
            Lockout{ .slot = 1, .confirmation_count = 2 },
            Lockout{ .slot = 6, .confirmation_count = 1 },
        };
        try expected_slots.appendSlice(std.testing.allocator, &lockouts);
        replay_tower.last_vote = VoteTransaction{
            .tower_sync = TowerSync{
                .lockouts = expected_slots,
                .root = null,
                .hash = Hash.ZEROES,
                .timestamp = null,
                .block_id = Hash.ZEROES,
            },
        };
        try std.testing.expectEqual(null, replay_tower.last_vote.timestamp());
        replay_tower.refreshLastVoteTimestamp(5);
        try std.testing.expectEqual(null, replay_tower.last_vote.timestamp());
        try std.testing.expectEqual(0, replay_tower.last_timestamp.slot);
        try std.testing.expectEqual(0, replay_tower.last_timestamp.timestamp);
    }

    // Tower has vote with no timestamp
    {
        var expected_slots = try std.ArrayListUnmanaged(Lockout).initCapacity(
            std.testing.allocator,
            3,
        );
        defer expected_slots.deinit(std.testing.allocator);
        var lockouts = [_]Lockout{
            Lockout{ .slot = 0, .confirmation_count = 3 },
            Lockout{ .slot = 1, .confirmation_count = 2 },
            Lockout{ .slot = 2, .confirmation_count = 1 },
        };
        try expected_slots.appendSlice(std.testing.allocator, &lockouts);
        replay_tower.last_vote = VoteTransaction{
            .tower_sync = TowerSync{
                .lockouts = expected_slots,
                .root = null,
                .hash = Hash.ZEROES,
                .timestamp = null,
                .block_id = Hash.ZEROES,
            },
        };
        try std.testing.expectEqual(null, replay_tower.last_vote.timestamp());
        replay_tower.refreshLastVoteTimestamp(5);
        try std.testing.expectEqual(1, replay_tower.last_vote.timestamp());
        try std.testing.expectEqual(2, replay_tower.last_timestamp.slot);
        try std.testing.expectEqual(1, replay_tower.last_timestamp.timestamp);
    }

    // Vote has timestamp
    {
        var expected_slots = try std.ArrayListUnmanaged(Lockout).initCapacity(
            std.testing.allocator,
            3,
        );
        defer expected_slots.deinit(std.testing.allocator);
        var lockouts = [_]Lockout{
            Lockout{ .slot = 0, .confirmation_count = 3 },
            Lockout{ .slot = 1, .confirmation_count = 2 },
            Lockout{ .slot = 2, .confirmation_count = 1 },
        };
        try expected_slots.appendSlice(std.testing.allocator, &lockouts);
        replay_tower.last_vote = VoteTransaction{
            .tower_sync = TowerSync{
                .lockouts = expected_slots,
                .root = null,
                .hash = Hash.ZEROES,
                .timestamp = null,
                .block_id = Hash.ZEROES,
            },
        };
        replay_tower.refreshLastVoteTimestamp(5);
        try std.testing.expectEqual(2, replay_tower.last_vote.timestamp());
        try std.testing.expectEqual(2, replay_tower.last_timestamp.slot);
        try std.testing.expectEqual(2, replay_tower.last_timestamp.timestamp);
    }
}

test "adjust lockouts after replay future slots" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    for (0..4) |i| {
        _ = try replay_tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);

    slot_history.add(@as(Slot, 0));
    slot_history.add(@as(Slot, 1));

    const replayed_root_slot: u64 = 1;

    try replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        replayed_root_slot,
        &slot_history,
    );

    var expected_votes = [_]Slot{ 2, 3 };

    const voted_slots = try replay_tower.tower.votedSlots(std.testing.allocator);
    defer std.testing.allocator.free(voted_slots);

    try std.testing.expectEqualSlices(
        Slot,
        &expected_votes,
        voted_slots,
    );
    try std.testing.expectEqual(replayed_root_slot, try replay_tower.tower.getRoot());
}

test "adjust lockouts after replay not found slots" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    for (0..4) |i| {
        _ = try replay_tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);

    slot_history.add(@as(Slot, 0));
    slot_history.add(@as(Slot, 1));
    slot_history.add(@as(Slot, 4));

    const replayed_root_slot: u64 = 4;

    try replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        replayed_root_slot,
        &slot_history,
    );

    var expected_votes = [_]Slot{ 2, 3 };

    const voted_slots = try replay_tower.tower.votedSlots(std.testing.allocator);
    defer std.testing.allocator.free(voted_slots);

    try std.testing.expectEqualSlices(
        Slot,
        &expected_votes,
        voted_slots,
    );
    try std.testing.expectEqual(replayed_root_slot, try replay_tower.tower.getRoot());
}

test "adjust lockouts after replay all rooted with no too old" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    for (0..3) |i| {
        _ = try replay_tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    for (0..6) |i| {
        slot_history.add(@as(Slot, i));
    }

    const replayed_root_slot: u64 = 5;

    try replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        replayed_root_slot,
        &slot_history,
    );

    const voted_slots = try replay_tower.tower.votedSlots(std.testing.allocator);
    defer std.testing.allocator.free(voted_slots);

    try std.testing.expect(voted_slots.len == 0);

    try std.testing.expectEqual(replayed_root_slot, try replay_tower.tower.getRoot());
    try std.testing.expectEqual(null, replay_tower.stray_restored_slot);
}

test "adjust lockouts after replay all rooted with too old" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    for (0..3) |i| {
        _ = try replay_tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    for (0..3) |i| {
        slot_history.add(@as(Slot, i));
    }

    slot_history.add(@as(Slot, MAX_ENTRIES));

    try replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        MAX_ENTRIES,
        &slot_history,
    );

    const voted_slots = try replay_tower.tower.votedSlots(std.testing.allocator);
    defer std.testing.allocator.free(voted_slots);

    try std.testing.expect(voted_slots.len == 0);

    try std.testing.expectEqual(MAX_ENTRIES, try replay_tower.tower.getRoot());
}

test "adjust lockouts after replay anchored future slots" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    for (0..5) |i| {
        _ = try replay_tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    for (0..3) |i| {
        slot_history.add(@as(Slot, i));
    }

    const replayed_root_slot = 2;

    try replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        replayed_root_slot,
        &slot_history,
    );

    const voted_slots = try replay_tower.tower.votedSlots(std.testing.allocator);
    defer std.testing.allocator.free(voted_slots);

    var expected_votes = [_]Slot{ 3, 4 };
    try std.testing.expectEqualSlices(
        Slot,
        &expected_votes,
        voted_slots,
    );
    try std.testing.expectEqual(replayed_root_slot, try replay_tower.tower.getRoot());
}

test "adjust lockouts after replay all not found" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    for (5..7) |i| {
        _ = try replay_tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    for (0..3) |i| {
        slot_history.add(@as(Slot, i));
    }
    slot_history.add(@as(Slot, 7));

    const replayed_root_slot = 7;

    try replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        replayed_root_slot,
        &slot_history,
    );

    const voted_slots = try replay_tower.tower.votedSlots(std.testing.allocator);
    defer std.testing.allocator.free(voted_slots);

    var expected_votes = [_]Slot{ 5, 6 };
    try std.testing.expectEqualSlices(
        Slot,
        &expected_votes,
        voted_slots,
    );
    try std.testing.expectEqual(replayed_root_slot, try replay_tower.tower.getRoot());
}

test "adjust lockouts after replay all not found even if rooted" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.tower.root = 4;

    for (5..7) |i| {
        _ = try replay_tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    for (0..3) |i| {
        slot_history.add(@as(Slot, i));
    }
    slot_history.add(@as(Slot, 7));

    const replayed_root_slot = 7;

    const result = replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        replayed_root_slot,
        &slot_history,
    );

    try std.testing.expectError(error.FatallyInconsistent, result);
}

test "test adjust lockouts after replay all future votes only root found" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.tower.root = 2;

    for (3..6) |i| {
        _ = try replay_tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    for (0..3) |i| {
        slot_history.add(@as(Slot, i));
    }

    const replayed_root_slot = 2;

    var expected_votes = [_]Slot{ 3, 4, 5 };

    const voted_slots = try replay_tower.tower.votedSlots(std.testing.allocator);
    defer std.testing.allocator.free(voted_slots);

    try std.testing.expectEqualSlices(
        Slot,
        &expected_votes,
        voted_slots,
    );
    try std.testing.expectEqual(replayed_root_slot, try replay_tower.tower.getRoot());
}

test "adjust lockouts after replay empty" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    slot_history.add(@as(Slot, 0));

    const replayed_root_slot = 0;

    const voted_slots = try replay_tower.tower.votedSlots(std.testing.allocator);
    defer std.testing.allocator.free(voted_slots);

    try std.testing.expect(voted_slots.len == 0);
    try std.testing.expectEqual(replayed_root_slot, try replay_tower.tower.getRoot());
}

test "adjust lockouts after replay too old tower" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    _ = try replay_tower.recordBankVote(
        std.testing.allocator,
        0,
        Hash.ZEROES,
    );

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    slot_history.add(@as(Slot, 0));
    slot_history.add(@as(Slot, MAX_ENTRIES));

    const voted_slots = try replay_tower.tower.votedSlots(std.testing.allocator);
    defer std.testing.allocator.free(voted_slots);

    const result = replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        MAX_ENTRIES,
        &slot_history,
    );

    try std.testing.expectError(TowerError.TooOldTower, result);
}

test "adjust lockouts after replay time warped" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 1, .confirmation_count = 1 },
    );

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 0, .confirmation_count = 1 },
    );

    replay_tower.last_vote = .{ .vote = try Vote.clone(.{
        .slots = &.{0},
        .hash = Hash.ZEROES,
        .timestamp = null,
    }, std.testing.allocator) };

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    slot_history.add(@as(Slot, 0));

    const result = replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        0,
        &slot_history,
    );

    try std.testing.expectError(TowerError.FatallyInconsistentTimeWarp, result);
}

test "adjust lockouts after replay diverged ancestor" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 1, .confirmation_count = 1 },
    );

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 2, .confirmation_count = 1 },
    );

    replay_tower.last_vote = .{ .vote = try Vote.clone(.{
        .slots = &.{2},
        .hash = Hash.ZEROES,
        .timestamp = null,
    }, std.testing.allocator) };

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    slot_history.add(@as(Slot, 0));
    slot_history.add(@as(Slot, 2));

    const result = replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        2,
        &slot_history,
    );

    try std.testing.expectError(TowerError.FatallyInconsistentDivergedAncestors, result);
}

test "adjust lockouts after replay out of order" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.votes.append(
        Lockout{ .slot = MAX_ENTRIES - 1, .confirmation_count = 1 },
    );

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 0, .confirmation_count = 1 },
    );

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 1, .confirmation_count = 1 },
    );

    replay_tower.last_vote = .{ .vote = try Vote.clone(.{
        .slots = &.{1},
        .hash = Hash.ZEROES,
        .timestamp = null,
    }, std.testing.allocator) };

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    slot_history.add(@as(Slot, MAX_ENTRIES));

    const result = replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        MAX_ENTRIES,
        &slot_history,
    );

    try std.testing.expectError(TowerError.FatallyInconsistentReplayOutOfOrder, result);
}

test "adjust lockouts after replay out of order via clearing history" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 13, .confirmation_count = 1 },
    );

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 14, .confirmation_count = 1 },
    );

    replay_tower.last_vote = .{ .vote = try Vote.clone(.{
        .slots = &.{14},
        .hash = Hash.ZEROES,
        .timestamp = null,
    }, std.testing.allocator) };
    // Triggers clearning of votes
    replay_tower.tower.root = MAX_ENTRIES * 2;

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    slot_history.add(@as(Slot, 0));
    slot_history.add(@as(Slot, 2));

    const result = replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        2,
        &slot_history,
    );

    try std.testing.expectError(TowerError.FatallyInconsistentReplayOutOfOrder, result);
}

test "adjust lockouts after replay reversed votes" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 2, .confirmation_count = 1 },
    );

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 1, .confirmation_count = 1 },
    );

    replay_tower.last_vote = .{ .vote = try Vote.clone(.{
        .slots = &.{1},
        .hash = Hash.ZEROES,
        .timestamp = null,
    }, std.testing.allocator) };

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    slot_history.add(@as(Slot, 0));
    slot_history.add(@as(Slot, 2));

    const result = replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        2,
        &slot_history,
    );

    try std.testing.expectError(TowerError.FatallyInconsistentTowerSlotOrder, result);
}

test "adjust lockouts after replay repeated non root votes" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 2, .confirmation_count = 1 },
    );

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 3, .confirmation_count = 1 },
    );

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 3, .confirmation_count = 1 },
    );

    replay_tower.last_vote = .{ .vote = try Vote.clone(.{
        .slots = &.{3},
        .hash = Hash.ZEROES,
        .timestamp = null,
    }, std.testing.allocator) };

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    slot_history.add(@as(Slot, 0));
    slot_history.add(@as(Slot, 2));

    const result = replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        2,
        &slot_history,
    );

    try std.testing.expectError(TowerError.FatallyInconsistentTowerSlotOrder, result);
}

test "adjust lockouts after replay vote on root" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.tower.root = 42;

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 42, .confirmation_count = 1 },
    );

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 43, .confirmation_count = 1 },
    );

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 44, .confirmation_count = 1 },
    );

    replay_tower.last_vote = .{ .vote = try Vote.clone(.{
        .slots = &.{44},
        .hash = Hash.ZEROES,
        .timestamp = null,
    }, std.testing.allocator) };

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    slot_history.add(@as(Slot, 42));

    var expected_votes = [_]Slot{ 43, 44 };

    try replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        42,
        &slot_history,
    );

    const voted_slots = try replay_tower.tower.votedSlots(std.testing.allocator);
    defer std.testing.allocator.free(voted_slots);

    try std.testing.expectEqualSlices(
        Slot,
        &expected_votes,
        voted_slots,
    );
}

test "adjust lockouts after replay vote on genesis" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 0, .confirmation_count = 1 },
    );

    replay_tower.last_vote = .{ .vote = try Vote.clone(.{
        .slots = &.{0},
        .hash = Hash.ZEROES,
        .timestamp = null,
    }, std.testing.allocator) };

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    slot_history.add(@as(Slot, 0));

    try replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        0,
        &slot_history,
    );

    try std.testing.expect(true);
}

test "adjust lockouts after replay future tower" {
    var replay_tower = try createTestReplayTower(10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 13, .confirmation_count = 1 },
    );

    try replay_tower.tower.votes.append(
        Lockout{ .slot = 14, .confirmation_count = 1 },
    );

    replay_tower.last_vote = .{ .vote = try Vote.clone(.{
        .slots = &.{14},
        .hash = Hash.ZEROES,
        .timestamp = null,
    }, std.testing.allocator) };
    replay_tower.tower.root = 12;

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.bits.deinit(std.testing.allocator);
    slot_history.add(@as(Slot, 0));
    slot_history.add(@as(Slot, 2));

    var expected_votes = [_]Slot{ 13, 14 };

    try replay_tower.adjustLockoutsAfterReplay(
        std.testing.allocator,
        2,
        &slot_history,
    );

    const voted_slots = try replay_tower.tower.votedSlots(std.testing.allocator);
    defer std.testing.allocator.free(voted_slots);

    try std.testing.expectEqual(
        12,
        try replay_tower.tower.getRoot(),
    );
    try std.testing.expectEqualSlices(
        Slot,
        &expected_votes,
        voted_slots,
    );
    try std.testing.expectEqual(
        14,
        replay_tower.stray_restored_slot,
    );
}

test "is slot confirmed not enough stake failure" {
    var tower = try createTestReplayTower(1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 1);

    const result = isSlotConfirmed(&tower, 0, &stakes, 2);
    try std.testing.expect(!result);
}

test "is slot confirmed unknown slot" {
    var tower = try createTestReplayTower(1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);

    const result = isSlotConfirmed(&tower, 0, &stakes, 2);
    try std.testing.expect(!result);
}

test "is slot confirmed pass" {
    var tower = try createTestReplayTower(1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = VotedStakes.empty;
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 2);

    const result = isSlotConfirmed(&tower, 0, &stakes, 2);
    try std.testing.expect(result);
}

test "default tower has no stray last vote" {
    var replay_tower = try createTestReplayTower(
        VOTE_THRESHOLD_DEPTH,
        VOTE_THRESHOLD_SIZE,
    );
    defer replay_tower.deinit(std.testing.allocator);

    try std.testing.expect(!replay_tower.isStrayLastVote());
}

test "recent votes full" {
    try voteAndCheckRecent(MAX_LOCKOUT_HISTORY);
}

test "recent votes empty" {
    try voteAndCheckRecent(0);
}

test "recent votes exact" {
    try voteAndCheckRecent(5);
}

test "greatestCommonAncestor" {
    const allocator = std.testing.allocator;

    // Test case: Basic common ancestor
    {
        var ancestors: AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
        defer {
            for (ancestors.values()) |*set| set.deinit(allocator);
            ancestors.deinit(allocator);
        }

        try ancestors.ensureUnusedCapacity(allocator, 2);
        ancestors.putAssumeCapacity(10, try createAncestor(allocator, &.{ 5, 3, 1 }));
        ancestors.putAssumeCapacity(20, try createAncestor(allocator, &.{ 8, 5, 2 }));

        // Both slots have common ancestor 5
        try std.testing.expectEqual(
            @as(?Slot, 5),
            greatestCommonAncestor(&ancestors, 10, 20),
        );
    }

    // Test case: No common ancestor
    {
        var ancestors: AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
        defer {
            for (ancestors.values()) |*set| set.deinit(allocator);
            ancestors.deinit(allocator);
        }

        try ancestors.ensureUnusedCapacity(allocator, 2);
        ancestors.putAssumeCapacity(10, try createAncestor(allocator, &.{ 3, 1 }));
        ancestors.putAssumeCapacity(20, try createAncestor(allocator, &.{ 8, 2 }));

        try std.testing.expectEqual(
            @as(?Slot, null),
            greatestCommonAncestor(&ancestors, 10, 20),
        );
    }

    // Test case: One empty ancestor set
    {
        var ancestors: AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
        defer {
            for (ancestors.values()) |*set| set.deinit(allocator);
            ancestors.deinit(allocator);
        }

        try ancestors.ensureUnusedCapacity(allocator, 2);
        ancestors.putAssumeCapacity(10, try createAncestor(allocator, &.{ 5, 3 }));
        ancestors.putAssumeCapacity(20, try createAncestor(allocator, &.{}));

        try std.testing.expectEqual(
            @as(?Slot, null),
            greatestCommonAncestor(&ancestors, 10, 20),
        );
    }

    // Test case: Missing slots
    {
        var ancestors: AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
        defer {
            for (ancestors.values()) |*set| set.deinit(allocator);
            ancestors.deinit(allocator);
        }

        try ancestors.ensureUnusedCapacity(allocator, 1);
        ancestors.putAssumeCapacity(10, try createAncestor(allocator, &.{ 5, 3 }));

        try std.testing.expectEqual(
            @as(?Slot, null),
            greatestCommonAncestor(&ancestors, 10, 99), // 99 doesn't exist
        );
    }

    // Test case: Multiple common ancestors (should pick greatest)
    {
        var ancestors: AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
        defer {
            for (ancestors.values()) |*set| set.deinit(allocator);
            ancestors.deinit(allocator);
        }

        try ancestors.put(allocator, 10, try createAncestor(allocator, &.{ 7, 5, 3 }));
        try ancestors.put(allocator, 20, try createAncestor(allocator, &.{ 7, 5, 4 }));

        // Should pick 7 (greater than 5)
        try std.testing.expectEqual(
            @as(?Slot, 7),
            greatestCommonAncestor(&ancestors, 10, 20),
        );
    }
}

test "isValidSwitchingProofVote basic cases" {
    // Test basic cases of switch proof validation
    const allocator = std.testing.allocator;

    var ancestors: AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
    defer {
        for (ancestors.values()) |*set| set.deinit(allocator);
        ancestors.deinit(allocator);
    }

    // Fork structure:
    //          /- 48
    // 0 - 43 - 44 - 47
    //            \- 110
    try ancestors.put(allocator, 0, try createAncestor(allocator, &.{}));
    try ancestors.put(allocator, 43, try createAncestor(allocator, &.{0}));
    try ancestors.put(allocator, 44, try createAncestor(allocator, &.{ 43, 0 }));
    try ancestors.put(allocator, 47, try createAncestor(allocator, &.{ 44, 43, 0 }));
    try ancestors.put(allocator, 48, try createAncestor(allocator, &.{ 47, 44, 43, 0 }));
    try ancestors.put(allocator, 110, try createAncestor(allocator, &.{ 44, 43, 0 }));

    const tower = try createTestReplayTower(0, 0);
    defer tower.deinit(std.testing.allocator);

    const last_voted_slot: Slot = 47;
    const switch_slot: Slot = 110;
    const last_vote_ancestors = ancestors.get(last_voted_slot).?;

    // Test 1: Candidate is descendant of last vote - should be INVALID
    // 48 is a descendant of 47 (our last vote), so it's on the same fork
    {
        const result = tower.isValidSwitchingProofVote(
            48,
            last_voted_slot,
            switch_slot,
            &ancestors,
            &last_vote_ancestors,
        );
        try std.testing.expect(result != null);
        try std.testing.expectEqual(false, result.?);
    }

    // Test 2: Candidate on valid different fork - should be VALID
    // 110 forked off at 44, which is an ancestor of both 47 and 110
    {
        const result = tower.isValidSwitchingProofVote(
            110,
            last_voted_slot,
            switch_slot,
            &ancestors,
            &last_vote_ancestors,
        );
        try std.testing.expect(result != null);
        try std.testing.expectEqual(true, result.?);
    }
}

test "isValidSwitchingProofVote descendant filtering" {
    // Test that votes on descendants of last vote don't count
    const allocator = std.testing.allocator;

    var ancestors: AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
    defer {
        for (ancestors.values()) |*set| set.deinit(allocator);
        ancestors.deinit(allocator);
    }

    // Fork structure:
    //                    /- 110 - 111 - 112
    // 0 - 43 - 44 - 45 - 46 - 47 - 48 - 49 - 50
    try ancestors.put(allocator, 0, try createAncestor(allocator, &.{}));
    try ancestors.put(allocator, 43, try createAncestor(allocator, &.{0}));
    try ancestors.put(allocator, 44, try createAncestor(allocator, &.{ 43, 0 }));
    try ancestors.put(allocator, 45, try createAncestor(allocator, &.{ 44, 43, 0 }));
    try ancestors.put(allocator, 46, try createAncestor(allocator, &.{ 45, 44, 43, 0 }));
    try ancestors.put(allocator, 47, try createAncestor(allocator, &.{ 46, 45, 44, 43, 0 }));
    try ancestors.put(allocator, 48, try createAncestor(allocator, &.{ 47, 46, 45, 44, 43, 0 }));
    try ancestors.put(allocator, 49, try createAncestor(allocator, &.{ 48, 47, 46, 45, 44, 43, 0 }));
    try ancestors.put(
        allocator,
        50,
        try createAncestor(allocator, &.{ 49, 48, 47, 46, 45, 44, 43, 0 }),
    );
    try ancestors.put(allocator, 110, try createAncestor(allocator, &.{ 45, 44, 43, 0 }));
    try ancestors.put(allocator, 111, try createAncestor(allocator, &.{ 110, 45, 44, 43, 0 }));
    try ancestors.put(allocator, 112, try createAncestor(allocator, &.{ 111, 110, 45, 44, 43, 0 }));

    const tower = try createTestReplayTower(0, 0);
    defer tower.deinit(std.testing.allocator);

    const last_voted_slot: Slot = 47;
    const switch_slot: Slot = 110;
    const last_vote_ancestors = ancestors.get(last_voted_slot).?;

    // Votes on descendants of last vote (48, 49, 50) should all be INVALID
    for ([_]Slot{ 48, 49, 50 }) |candidate| {
        const result = tower.isValidSwitchingProofVote(
            candidate,
            last_voted_slot,
            switch_slot,
            &ancestors,
            &last_vote_ancestors,
        );
        try std.testing.expect(result != null);
        try std.testing.expectEqual(false, result.?);
    }

    // Votes on the switch fork (110, 111, 112) should all be VALID
    for ([_]Slot{ 110, 111, 112 }) |candidate| {
        const result = tower.isValidSwitchingProofVote(
            candidate,
            last_voted_slot,
            switch_slot,
            &ancestors,
            &last_vote_ancestors,
        );
        try std.testing.expect(result != null);
        try std.testing.expectEqual(true, result.?);
    }
}

test "isValidSwitchingProofVote ancestor filtering" {
    // Test filtering based on lockout intervals that don't cover last vote
    const allocator = std.testing.allocator;

    var ancestors: AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
    defer {
        for (ancestors.values()) |*set| set.deinit(allocator);
        ancestors.deinit(allocator);
    }

    // Fork structure:
    //               /- 14 - 15
    // 0 - 12 - 13 -
    //               \- 45 - 46 - 47
    //                 \- 110
    try ancestors.put(allocator, 0, try createAncestor(allocator, &.{}));
    try ancestors.put(allocator, 12, try createAncestor(allocator, &.{0}));
    try ancestors.put(allocator, 13, try createAncestor(allocator, &.{ 12, 0 }));
    try ancestors.put(allocator, 14, try createAncestor(allocator, &.{ 13, 12, 0 }));
    try ancestors.put(allocator, 15, try createAncestor(allocator, &.{ 14, 13, 12, 0 }));
    try ancestors.put(allocator, 45, try createAncestor(allocator, &.{ 13, 12, 0 }));
    try ancestors.put(allocator, 46, try createAncestor(allocator, &.{ 45, 13, 12, 0 }));
    try ancestors.put(allocator, 47, try createAncestor(allocator, &.{ 46, 45, 13, 12, 0 }));
    try ancestors.put(allocator, 110, try createAncestor(allocator, &.{ 45, 13, 12, 0 }));

    const tower = try createTestReplayTower(0, 0);
    defer tower.deinit(std.testing.allocator);

    const last_voted_slot: Slot = 47;
    const switch_slot: Slot = 110;
    const last_vote_ancestors = ancestors.get(last_voted_slot).?;

    // Slot 14 and 15 are on a different fork
    // They should be VALID for contributing to switch proof
    for ([_]Slot{ 14, 15 }) |candidate| {
        const result = tower.isValidSwitchingProofVote(
            candidate,
            last_voted_slot,
            switch_slot,
            &ancestors,
            &last_vote_ancestors,
        );
        try std.testing.expect(result != null);
        try std.testing.expectEqual(true, result.?);
    }
}

test "isValidSwitchingProofVote common ancestor" {
    // This test covers the critical logic from Agave's test_switch_threshold_common_ancestor
    // Fork structure:
    //                                       /- 50
    //          /- 51    /- 45 - 46 - 47 - 48 - 49
    // 0 - 1 - 2 - 43 - 44
    //                   \- 110 - 111 - 112
    //                    \- 113
    //
    // Last vote: 49 (on path 43-44-45-46-47-48-49)
    // Switch slot: 111 (on path 43-44-110-111)
    //
    // Candidate slot 50 should NOT work because:
    //   - It's on the same fork as last_vote (49) relative to switch_slot (111)
    //   - The common ancestor of 50 and 49 is 48, and switch_slot (111) does NOT descend from 48
    //
    // Candidate slots 51, 111, 112, 113 SHOULD work because:
    //   - They forked off at or before the common ancestor of switch_slot and last_vote

    const allocator = std.testing.allocator;

    var ancestors: AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
    defer {
        for (ancestors.values()) |*set| set.deinit(allocator);
        ancestors.deinit(allocator);
    }

    // Build the ancestry information for each slot
    // Format: slot -> its ancestors (not including itself)
    try ancestors.put(
        allocator,
        0,
        try createAncestor(allocator, &.{}),
    );
    try ancestors.put(
        allocator,
        1,
        try createAncestor(allocator, &.{0}),
    );
    try ancestors.put(allocator, 2, try createAncestor(
        allocator,
        &.{ 1, 0 },
    ));
    try ancestors.put(allocator, 43, try createAncestor(
        allocator,
        &.{ 2, 1, 0 },
    ));
    try ancestors.put(allocator, 44, try createAncestor(
        allocator,
        &.{ 43, 2, 1, 0 },
    ));
    try ancestors.put(allocator, 45, try createAncestor(
        allocator,
        &.{ 44, 43, 2, 1, 0 },
    ));
    try ancestors.put(allocator, 46, try createAncestor(
        allocator,
        &.{ 45, 44, 43, 2, 1, 0 },
    ));
    try ancestors.put(allocator, 47, try createAncestor(
        allocator,
        &.{ 46, 45, 44, 43, 2, 1, 0 },
    ));
    try ancestors.put(allocator, 48, try createAncestor(
        allocator,
        &.{ 47, 46, 45, 44, 43, 2, 1, 0 },
    ));
    try ancestors.put(allocator, 49, try createAncestor(
        allocator,
        &.{ 48, 47, 46, 45, 44, 43, 2, 1, 0 },
    ));
    try ancestors.put(allocator, 50, try createAncestor(
        allocator,
        &.{ 49, 48, 47, 46, 45, 44, 43, 2, 1, 0 },
    ));
    try ancestors.put(
        allocator,
        51,
        try createAncestor(allocator, &.{ 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        110,
        try createAncestor(allocator, &.{ 44, 43, 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        111,
        try createAncestor(allocator, &.{ 110, 44, 43, 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        112,
        try createAncestor(allocator, &.{ 111, 110, 44, 43, 2, 1, 0 }),
    );
    try ancestors.put(allocator, 113, try createAncestor(allocator, &.{ 44, 43, 2, 1, 0 }));

    const tower = try createTestReplayTower(0, 0);
    defer tower.deinit(std.testing.allocator);

    const last_voted_slot: Slot = 49;
    const switch_slot: Slot = 111;
    const last_vote_ancestors = ancestors.get(last_voted_slot).?;

    // Test candidate 50: should be INVALID (false)
    // Because 50 is on the same fork as 49 relative to switch 111
    {
        const result = tower.isValidSwitchingProofVote(
            50, // candidate_slot
            last_voted_slot,
            switch_slot,
            &ancestors,
            &last_vote_ancestors,
        );
        try std.testing.expect(result != null);
        try std.testing.expectEqual(false, result.?);
    }

    // Test candidate 51: should be VALID (true)
    // Because 51 forked off at slot 2, before the common ancestor (44) of 49 and 111
    {
        const result = tower.isValidSwitchingProofVote(
            51,
            last_voted_slot,
            switch_slot,
            &ancestors,
            &last_vote_ancestors,
        );
        try std.testing.expect(result != null);
        try std.testing.expectEqual(true, result.?);
    }

    // Test candidate 111: should be VALID (true)
    // Because 111 is the switch slot itself
    {
        const result = tower.isValidSwitchingProofVote(
            111,
            last_voted_slot,
            switch_slot,
            &ancestors,
            &last_vote_ancestors,
        );
        try std.testing.expect(result != null);
        try std.testing.expectEqual(true, result.?);
    }

    // Test candidate 112: should be VALID (true)
    // Because 112 is on the switch fork
    {
        const result = tower.isValidSwitchingProofVote(
            112,
            last_voted_slot,
            switch_slot,
            &ancestors,
            &last_vote_ancestors,
        );
        try std.testing.expect(result != null);
        try std.testing.expectEqual(true, result.?);
    }

    // Test candidate 113: should be VALID (true)
    // Because 113 forked off at slot 44, which is the common ancestor
    {
        const result = tower.isValidSwitchingProofVote(
            113,
            last_voted_slot,
            switch_slot,
            &ancestors,
            &last_vote_ancestors,
        );
        try std.testing.expect(result != null);
        try std.testing.expectEqual(true, result.?);
    }
}

// Analogous to [test_switch_threshold](https://github.com/anza-xyz/agave/blob/1538a5d7823c5a4ea2c8000d14d09eff3bee2ef1/core/src/consensus.rs#L2103)
test "switch threshold" {
    const allocator = std.testing.allocator;

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    // Setup fork structure:
    //        /- 10 - 11 - 12 - 13 - 14  (minor fork 1)
    // 0 - 1 - 2
    //        \- 43 - 44 - 45 - 46 - 47 - 48 - 49 - 50  (minor fork 2)
    //                  \- 110  (switch target)
    //                  \- 112

    // Create ancestors map
    var ancestors: AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
    defer {
        for (ancestors.values()) |*set| set.deinit(allocator);
        ancestors.deinit(allocator);
    }

    // Build ancestry for all slots in the fork structure
    try ancestors.put(allocator, 0, try createAncestor(allocator, &.{}));
    try ancestors.put(allocator, 1, try createAncestor(allocator, &.{0}));
    try ancestors.put(allocator, 2, try createAncestor(allocator, &.{ 1, 0 }));

    // Minor fork 1: 10-14
    try ancestors.put(allocator, 10, try createAncestor(allocator, &.{ 2, 1, 0 }));
    try ancestors.put(allocator, 11, try createAncestor(allocator, &.{ 10, 2, 1, 0 }));
    try ancestors.put(allocator, 12, try createAncestor(allocator, &.{ 11, 10, 2, 1, 0 }));
    try ancestors.put(allocator, 13, try createAncestor(allocator, &.{ 12, 11, 10, 2, 1, 0 }));
    try ancestors.put(allocator, 14, try createAncestor(allocator, &.{ 13, 12, 11, 10, 2, 1, 0 }));

    // Minor fork 2: 43-50
    try ancestors.put(
        allocator,
        43,
        try createAncestor(allocator, &.{ 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        44,
        try createAncestor(allocator, &.{ 43, 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        45,
        try createAncestor(allocator, &.{ 44, 43, 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        46,
        try createAncestor(allocator, &.{ 45, 44, 43, 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        47,
        try createAncestor(allocator, &.{ 46, 45, 44, 43, 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        48,
        try createAncestor(allocator, &.{ 47, 46, 45, 44, 43, 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        49,
        try createAncestor(allocator, &.{ 48, 47, 46, 45, 44, 43, 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        50,
        try createAncestor(allocator, &.{ 49, 48, 47, 46, 45, 44, 43, 2, 1, 0 }),
    );

    // Switch target and other fork
    try ancestors.put(allocator, 110, try createAncestor(allocator, &.{ 44, 43, 2, 1, 0 }));
    try ancestors.put(allocator, 112, try createAncestor(allocator, &.{ 43, 2, 1, 0 }));

    // Create descendants map
    var descendants: AutoArrayHashMapUnmanaged(Slot, SortedSetUnmanaged(Slot)) = .empty;
    defer {
        for (descendants.values()) |*set| set.deinit(allocator);
        descendants.deinit(allocator);
    }

    // Helper to add descendants
    const addDescendants = struct {
        fn call(
            desc: *AutoArrayHashMapUnmanaged(Slot, SortedSetUnmanaged(Slot)),
            alloc: std.mem.Allocator,
            slot: Slot,
            desc_slots: []const Slot,
        ) !void {
            var set: SortedSetUnmanaged(Slot) = .empty;
            for (desc_slots) |s| try set.put(alloc, s);
            try desc.put(alloc, slot, set);
        }
    }.call;

    try addDescendants(&descendants, allocator, 0, &.{
        1,
        2,
        10,
        11,
        12,
        13,
        14,
        43,
        44,
        45,
        46,
        47,
        48,
        49,
        50,
        110,
        112,
    });
    try addDescendants(&descendants, allocator, 1, &.{
        2,
        10,
        11,
        12,
        13,
        14,
        43,
        44,
        45,
        46,
        47,
        48,
        49,
        50,
        110,
        112,
    });
    try addDescendants(
        &descendants,
        allocator,
        2,
        &.{ 10, 11, 12, 13, 14, 43, 44, 45, 46, 47, 48, 49, 50, 110, 112 },
    );
    try addDescendants(&descendants, allocator, 10, &.{ 11, 12, 13, 14 });
    try addDescendants(&descendants, allocator, 11, &.{ 12, 13, 14 });
    try addDescendants(&descendants, allocator, 12, &.{ 13, 14 });
    try addDescendants(&descendants, allocator, 13, &.{14});
    try addDescendants(&descendants, allocator, 14, &.{});
    try addDescendants(&descendants, allocator, 43, &.{ 44, 45, 46, 47, 48, 49, 50, 110, 112 });
    try addDescendants(&descendants, allocator, 44, &.{ 45, 46, 47, 48, 49, 50, 110 });
    try addDescendants(&descendants, allocator, 45, &.{ 46, 47, 48, 49, 50 });
    try addDescendants(&descendants, allocator, 46, &.{ 47, 48, 49, 50 });
    try addDescendants(&descendants, allocator, 47, &.{ 48, 49, 50 });
    try addDescendants(&descendants, allocator, 48, &.{ 49, 50 });
    try addDescendants(&descendants, allocator, 49, &.{50});
    try addDescendants(&descendants, allocator, 50, &.{});
    try addDescendants(&descendants, allocator, 110, &.{});
    try addDescendants(&descendants, allocator, 112, &.{});

    // Create progress map with all slots marked as computed
    var progress: ProgressMap = .INIT;
    defer {
        for (progress.map.values()) |*v| v.deinit(allocator);
        progress.map.deinit(allocator);
    }

    const slots_to_add = [_]Slot{
        0,
        1,
        2,
        10,
        11,
        12,
        13,
        14,
        43,
        44,
        45,
        46,
        47,
        48,
        49,
        50,
        110,
        112,
    };
    for (slots_to_add) |slot| {
        var fork_progress: ForkProgress = try .zeroes(allocator);
        fork_progress.fork_stats.computed = true;
        fork_progress.fork_stats.block_height = slot;
        try progress.map.put(allocator, slot, fork_progress);
    }

    // Add hashes to progress map
    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();
    for (slots_to_add) |slot| {
        if (progress.map.getPtr(slot)) |fork_progress| {
            fork_progress.fork_stats.slot_hash = Hash.initRandom(random);
        }
    }

    // Create epoch vote accounts (2 validators with 10000 stake each)
    var epoch_vote_accounts: StakeAndVoteAccountsMap = .empty;
    defer epoch_vote_accounts.deinit(allocator);

    const vote_pubkey1 = Pubkey.initRandom(random);
    const vote_pubkey2 = Pubkey.initRandom(random);

    try epoch_vote_accounts.put(allocator, vote_pubkey1, .{ .stake = 10000, .account = undefined });
    try epoch_vote_accounts.put(allocator, vote_pubkey2, .{ .stake = 10000, .account = undefined });

    const total_stake: u64 = 20000;
    const other_vote_account = vote_pubkey2;

    // Create tower and set last vote to 47
    var tower = try createTestReplayTower(0, 0);
    defer tower.deinit(allocator);
    _ = try tower.recordBankVote(allocator, 47, progress.getHash(47).?);

    // Create empty latest validator votes
    const latest_validator_votes: LatestValidatorVotes = .empty;

    // Create fork choice
    const fork_choice: HeaviestSubtreeForkChoice = try .init(
        allocator,
        .noop,
        .{ .slot = 0, .hash = progress.getHash(0).? },
        &registry,
    );
    defer fork_choice.deinit(allocator);

    // Test 1: Trying to switch to a descendant of last vote should always work (SameFork)
    {
        const decision = try tower.makeCheckSwitchThresholdDecision(
            allocator,
            48,
            &ancestors,
            &descendants,
            &progress,
            total_stake,
            &epoch_vote_accounts,
            &latest_validator_votes,
            &fork_choice,
        );
        try std.testing.expectEqual(SwitchForkDecision.same_fork, decision);
    }

    // Test 2: Trying to switch to another fork at 110 should fail (no stake)
    {
        const decision = try tower.makeCheckSwitchThresholdDecision(
            allocator,
            110,
            &ancestors,
            &descendants,
            &progress,
            total_stake,
            &epoch_vote_accounts,
            &latest_validator_votes,
            &fork_choice,
        );
        switch (decision) {
            .failed_switch_threshold => |threshold| {
                try std.testing.expectEqual(0, threshold.switch_proof_stake);
                try std.testing.expectEqual(total_stake, threshold.total_stake);
            },
            else => try std.testing.expect(false), // Should be FailedSwitchThreshold
        }
    }

    // Test 3: Adding lockout on descendant of last vote (50) shouldn't count
    {
        // Add lockout interval for slot 50: lockout from 49 to 100
        if (progress.map.getPtr(50)) |fork_progress| {
            const interval =
                try fork_progress.fork_stats.lockout_intervals.map.getOrPut(allocator, 100);
            if (!interval.found_existing) {
                interval.value_ptr.* = .empty;
            }
            try interval.value_ptr.append(allocator, .{ 49, other_vote_account });
        }

        const decision = try tower.makeCheckSwitchThresholdDecision(
            allocator,
            110,
            &ancestors,
            &descendants,
            &progress,
            total_stake,
            &epoch_vote_accounts,
            &latest_validator_votes,
            &fork_choice,
        );
        switch (decision) {
            .failed_switch_threshold => |threshold| {
                try std.testing.expectEqual(0, threshold.switch_proof_stake);
                try std.testing.expectEqual(total_stake, threshold.total_stake);
            },
            else => try std.testing.expect(false),
        }

        // Clear the lockout
        if (progress.map.getPtr(50)) |fork_progress| {
            fork_progress.fork_stats.lockout_intervals.deinit(allocator);
            fork_progress.fork_stats.lockout_intervals = .{ .map = .{} };
        }
    }

    // Test 4: Adding lockout on ancestor of last vote (45) shouldn't count
    {
        if (progress.map.getPtr(50)) |fork_progress| {
            const interval =
                try fork_progress
                    .fork_stats
                    .lockout_intervals
                    .map
                    .getOrPut(allocator, 100);
            if (!interval.found_existing) {
                interval.value_ptr.* = .empty;
            }
            try interval.value_ptr.append(allocator, .{ 45, other_vote_account });
        }

        const decision = try tower.makeCheckSwitchThresholdDecision(
            allocator,
            110,
            &ancestors,
            &descendants,
            &progress,
            total_stake,
            &epoch_vote_accounts,
            &latest_validator_votes,
            &fork_choice,
        );
        switch (decision) {
            .failed_switch_threshold => |threshold| {
                try std.testing.expectEqual(0, threshold.switch_proof_stake);
                try std.testing.expectEqual(total_stake, threshold.total_stake);
            },
            else => try std.testing.expect(false),
        }

        if (progress.map.getPtr(50)) |fork_progress| {
            fork_progress.fork_stats.lockout_intervals.deinit(allocator);
            fork_progress.fork_stats.lockout_intervals = .{ .map = .{} };
        }
    }

    // Test 5: Lockout on different fork (14) that doesn't cover last vote (12 to 46) shouldn't count
    {
        if (progress.map.getPtr(14)) |fork_progress| {
            const interval = try fork_progress
                .fork_stats
                .lockout_intervals
                .map
                .getOrPut(allocator, 46);
            if (!interval.found_existing) {
                interval.value_ptr.* = .empty;
            }
            try interval.value_ptr.append(allocator, .{ 12, other_vote_account });
        }

        const decision = try tower.makeCheckSwitchThresholdDecision(
            allocator,
            110,
            &ancestors,
            &descendants,
            &progress,
            total_stake,
            &epoch_vote_accounts,
            &latest_validator_votes,
            &fork_choice,
        );
        switch (decision) {
            .failed_switch_threshold => |threshold| {
                try std.testing.expectEqual(0, threshold.switch_proof_stake);
                try std.testing.expectEqual(total_stake, threshold.total_stake);
            },
            else => try std.testing.expect(false),
        }

        if (progress.map.getPtr(14)) |fork_progress| {
            fork_progress.fork_stats.lockout_intervals.deinit(allocator);
            fork_progress.fork_stats.lockout_intervals = .{ .map = .{} };
        }
    }

    // Test 6: Lockout on slot 13 that covers last vote shouldn't count because 14 is more recent frozen bank
    {
        if (progress.map.getPtr(13)) |fork_progress| {
            const interval = try fork_progress
                .fork_stats
                .lockout_intervals
                .map
                .getOrPut(allocator, 47);
            if (!interval.found_existing) {
                interval.value_ptr.* = .empty;
            }
            try interval.value_ptr.append(allocator, .{ 12, other_vote_account });
        }

        const decision = try tower.makeCheckSwitchThresholdDecision(
            allocator,
            110,
            &ancestors,
            &descendants,
            &progress,
            total_stake,
            &epoch_vote_accounts,
            &latest_validator_votes,
            &fork_choice,
        );
        switch (decision) {
            .failed_switch_threshold => |threshold| {
                try std.testing.expectEqual(0, threshold.switch_proof_stake);
                try std.testing.expectEqual(total_stake, threshold.total_stake);
            },
            else => try std.testing.expect(false),
        }

        if (progress.map.getPtr(13)) |fork_progress| {
            fork_progress.fork_stats.lockout_intervals.deinit(allocator);
            fork_progress.fork_stats.lockout_intervals = .{ .map = .{} };
        }
    }

    // Test 7: Lockout on different fork (14) that covers last vote (12 to 47) SHOULD succeed
    {
        if (progress.map.getPtr(14)) |fork_progress| {
            const interval =
                try fork_progress
                    .fork_stats
                    .lockout_intervals
                    .map
                    .getOrPut(allocator, 47);
            if (!interval.found_existing) {
                interval.value_ptr.* = .empty;
            }
            try interval.value_ptr.append(allocator, .{ 12, other_vote_account });
        }

        const decision = try tower.makeCheckSwitchThresholdDecision(
            allocator,
            110,
            &ancestors,
            &descendants,
            &progress,
            total_stake,
            &epoch_vote_accounts,
            &latest_validator_votes,
            &fork_choice,
        );
        try std.testing.expectEqual(SwitchForkDecision{ .switch_proof = Hash.ZEROES }, decision);

        // Test 7b: Adding unfrozen descendant (10000) shouldn't remove slot 14 from consideration
        {
            const desc_14 = descendants.getPtr(14).?;
            try desc_14.put(allocator, 10000);

            const decision2 = try tower.makeCheckSwitchThresholdDecision(
                allocator,
                110,
                &ancestors,
                &descendants,
                &progress,
                total_stake,
                &epoch_vote_accounts,
                &latest_validator_votes,
                &fork_choice,
            );
            try std.testing.expectEqual(
                SwitchForkDecision{ .switch_proof = Hash.ZEROES },
                decision2,
            );

            // Clean up descendant
            _ = desc_14.orderedRemove(10000);
        }

        if (progress.map.getPtr(14)) |fork_progress| {
            fork_progress.fork_stats.lockout_intervals.deinit(allocator);
            fork_progress.fork_stats.lockout_intervals = .{ .map = .{} };
        }
    }

    // Test 8: Setting a root should filter out lockouts below the root
    {
        // Add lockout that covers last vote
        if (progress.map.getPtr(14)) |fork_progress| {
            const interval =
                try fork_progress
                    .fork_stats
                    .lockout_intervals
                    .map
                    .getOrPut(allocator, 47);
            if (!interval.found_existing) {
                interval.value_ptr.* = .empty;
            }
            try interval.value_ptr.append(allocator, .{ 12, other_vote_account });
        }

        // Set root to 43
        tower.tower.root = 43;

        const decision = try tower.makeCheckSwitchThresholdDecision(
            allocator,
            110,
            &ancestors,
            &descendants,
            &progress,
            total_stake,
            &epoch_vote_accounts,
            &latest_validator_votes,
            &fork_choice,
        );

        // Should fail because lockout start (12) is below root (43)
        switch (decision) {
            .failed_switch_threshold => |threshold| {
                try std.testing.expectEqual(0, threshold.switch_proof_stake);
                try std.testing.expectEqual(total_stake, threshold.total_stake);
            },
            else => try std.testing.expect(false),
        }

        if (progress.map.getPtr(14)) |fork_progress| {
            fork_progress.fork_stats.lockout_intervals.deinit(allocator);
            fork_progress.fork_stats.lockout_intervals = .{ .map = .{} };
        }
    }
}

// Analogous to [test_switch_threshold_use_gossip_votes](https://github.com/anza-xyz/agave/blob/1538a5d7823c5a4ea2c8000d14d09eff3bee2ef1/core/src/consensus.rs#L2272)
test "switch threshold use gossip votes" {
    const allocator = std.testing.allocator;

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    // Setup: Use same fork structure as test_switch_threshold
    //        /- 10 - 11 - 12 - 13 - 14  (minor fork 1)
    // 0 - 1 - 2
    //        \\- 43 - 44 - 45 - 46 - 47 - 48 - 49 - 50  (minor fork 2)
    //                  \\- 110  (switch target)
    //                  \\- 112

    // Create ancestors map
    var ancestors: AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
    defer {
        for (ancestors.values()) |*set| set.deinit(allocator);
        ancestors.deinit(allocator);
    }

    try ancestors.put(allocator, 0, .EMPTY);
    try ancestors.put(allocator, 1, try createAncestor(allocator, &.{0}));
    try ancestors.put(allocator, 2, try createAncestor(allocator, &.{ 1, 0 }));
    try ancestors.put(allocator, 10, try createAncestor(allocator, &.{ 2, 1, 0 }));
    try ancestors.put(allocator, 11, try createAncestor(allocator, &.{ 10, 2, 1, 0 }));
    try ancestors.put(allocator, 12, try createAncestor(allocator, &.{ 11, 10, 2, 1, 0 }));
    try ancestors.put(allocator, 13, try createAncestor(allocator, &.{ 12, 11, 10, 2, 1, 0 }));
    try ancestors.put(allocator, 14, try createAncestor(allocator, &.{ 13, 12, 11, 10, 2, 1, 0 }));
    try ancestors.put(allocator, 43, try createAncestor(allocator, &.{ 2, 1, 0 }));
    try ancestors.put(allocator, 44, try createAncestor(allocator, &.{ 43, 2, 1, 0 }));
    try ancestors.put(
        allocator,
        45,
        try createAncestor(allocator, &.{ 44, 43, 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        46,
        try createAncestor(allocator, &.{ 45, 44, 43, 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        47,
        try createAncestor(allocator, &.{ 46, 45, 44, 43, 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        48,
        try createAncestor(allocator, &.{ 47, 46, 45, 44, 43, 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        49,
        try createAncestor(allocator, &.{ 48, 47, 46, 45, 44, 43, 2, 1, 0 }),
    );
    try ancestors.put(
        allocator,
        50,
        try createAncestor(allocator, &.{ 49, 48, 47, 46, 45, 44, 43, 2, 1, 0 }),
    );
    try ancestors.put(allocator, 110, try createAncestor(allocator, &.{ 44, 43, 2, 1, 0 }));
    try ancestors.put(allocator, 112, try createAncestor(allocator, &.{ 43, 2, 1, 0 }));

    // Create descendants map
    var descendants: AutoArrayHashMapUnmanaged(Slot, SortedSetUnmanaged(Slot)) = .empty;
    defer {
        for (descendants.values()) |*set| set.deinit(allocator);
        descendants.deinit(allocator);
    }

    const addDescendants = struct {
        fn call(
            desc: *AutoArrayHashMapUnmanaged(Slot, SortedSetUnmanaged(Slot)),
            alloc: std.mem.Allocator,
            slot: Slot,
            desc_slots: []const Slot,
        ) !void {
            var set: SortedSetUnmanaged(Slot) = .empty;
            for (desc_slots) |s| try set.put(alloc, s);
            try desc.put(alloc, slot, set);
        }
    }.call;

    try addDescendants(
        &descendants,
        allocator,
        0,
        &.{ 1, 2, 10, 11, 12, 13, 14, 43, 44, 45, 46, 47, 48, 49, 50, 110, 112 },
    );
    try addDescendants(
        &descendants,
        allocator,
        1,
        &.{ 2, 10, 11, 12, 13, 14, 43, 44, 45, 46, 47, 48, 49, 50, 110, 112 },
    );
    try addDescendants(
        &descendants,
        allocator,
        2,
        &.{ 10, 11, 12, 13, 14, 43, 44, 45, 46, 47, 48, 49, 50, 110, 112 },
    );
    try addDescendants(
        &descendants,
        allocator,
        43,
        &.{ 44, 45, 46, 47, 48, 49, 50, 110, 112 },
    );
    try addDescendants(&descendants, allocator, 44, &.{ 45, 46, 47, 48, 49, 50, 110 });
    try addDescendants(&descendants, allocator, 45, &.{ 46, 47, 48, 49, 50 });
    try addDescendants(&descendants, allocator, 46, &.{ 47, 48, 49, 50 });
    try addDescendants(&descendants, allocator, 47, &.{ 48, 49, 50 });
    try addDescendants(&descendants, allocator, 48, &.{ 49, 50 });
    try addDescendants(&descendants, allocator, 49, &.{50});

    // Create progress map with all slots
    var progress: ProgressMap = .INIT;
    defer progress.deinit(allocator);

    const slots_to_add = [_]Slot{
        0,
        1,
        2,
        10,
        11,
        12,
        13,
        14,
        43,
        44,
        45,
        46,
        47,
        48,
        49,
        50,
        110,
        112,
    };
    for (slots_to_add) |slot| {
        try progress.map.put(allocator, slot, try ForkProgress.zeroes(allocator));
    }

    // Add hashes to progress map
    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();
    for (slots_to_add) |slot| {
        if (progress.map.getPtr(slot)) |fork_progress| {
            fork_progress.fork_stats.slot_hash = .initRandom(random);
        }
    }

    // Create vote accounts with 10000 stake each (total_stake = 20000)
    const total_stake: u64 = 20000;
    var epoch_vote_accounts: StakeAndVoteAccountsMap = .empty;
    defer epoch_vote_accounts.deinit(allocator);

    var prng2: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const vote_pubkey1: Pubkey = .initRandom(prng2.random());
    const vote_pubkey2: Pubkey = .initRandom(prng2.random());
    const other_vote_account = vote_pubkey2;

    try epoch_vote_accounts.put(allocator, vote_pubkey1, .{ .stake = 10000, .account = undefined });
    try epoch_vote_accounts.put(allocator, vote_pubkey2, .{ .stake = 10000, .account = undefined });

    // Create tower and set last vote to 47
    var tower = try createTestReplayTower(0, 0);
    defer tower.deinit(allocator);
    _ = try tower.recordBankVote(allocator, 47, progress.getHash(47).?);

    // Create latest validator votes (initially empty)
    var latest_validator_votes: LatestValidatorVotes = .{
        .max_gossip_frozen_votes = .empty,
        .max_replay_frozen_votes = .empty,
        .fork_choice_dirty_set = .empty,
    };
    defer latest_validator_votes.deinit(allocator);

    // Create fork choice
    const fork_choice: HeaviestSubtreeForkChoice = try .init(
        allocator,
        .noop,
        .{ .slot = 0, .hash = progress.getHash(0).? },
        &registry,
    );
    defer fork_choice.deinit(allocator);

    // Test 1: Trying to switch to another fork at 110 should fail
    {
        const decision = try tower.makeCheckSwitchThresholdDecision(
            allocator,
            110,
            &ancestors,
            &descendants,
            &progress,
            total_stake,
            &epoch_vote_accounts,
            &latest_validator_votes,
            &fork_choice,
        );
        switch (decision) {
            .failed_switch_threshold => |threshold| {
                try std.testing.expectEqual(0, threshold.switch_proof_stake);
                try std.testing.expectEqual(total_stake, threshold.total_stake);
            },
            else => try std.testing.expect(false),
        }
    }

    // Test 2: Adding a vote on the descendant (50) shouldn't count toward the switch threshold
    {
        // Add lockout interval for slot 50: lockout from 49 to 100
        if (progress.map.getPtr(50)) |fork_progress| {
            const interval =
                try fork_progress.fork_stats.lockout_intervals.map.getOrPut(allocator, 100);
            if (!interval.found_existing) {
                interval.value_ptr.* = .empty;
            }
            try interval.value_ptr.append(allocator, .{ 49, other_vote_account });
        }

        const decision = try tower.makeCheckSwitchThresholdDecision(
            allocator,
            110,
            &ancestors,
            &descendants,
            &progress,
            total_stake,
            &epoch_vote_accounts,
            &latest_validator_votes,
            &fork_choice,
        );
        switch (decision) {
            .failed_switch_threshold => |threshold| {
                try std.testing.expectEqual(0, threshold.switch_proof_stake);
                try std.testing.expectEqual(total_stake, threshold.total_stake);
            },
            else => try std.testing.expect(false),
        }
    }

    // Test 3: Adding a later vote from gossip that isn't on the same fork should count toward the switch threshold
    {
        // Add gossip vote for slot 112
        _ = try latest_validator_votes.checkAddVote(
            allocator,
            other_vote_account,
            112,
            progress.getHash(112).?,
            .gossip,
        );

        const decision = try tower.makeCheckSwitchThresholdDecision(
            allocator,
            110,
            &ancestors,
            &descendants,
            &progress,
            total_stake,
            &epoch_vote_accounts,
            &latest_validator_votes,
            &fork_choice,
        );
        try std.testing.expectEqual(SwitchForkDecision{ .switch_proof = Hash.ZEROES }, decision);
    }

    // Test 4: If we now set a root that causes slot 112 to be purged from ancestors/descendants,
    // then the switch proof will now fail since that validator's vote can no longer be included
    {
        // Set root to 44 - this makes slot 112 (descendant of 43) unreachable
        tower.tower.root = 44;

        // Update ancestors and descendants to reflect new root
        // Rebuild ancestors from root 44
        for (ancestors.values()) |*set| set.deinit(allocator);
        ancestors.clearRetainingCapacity();
        try ancestors.put(allocator, 44, .EMPTY);
        try ancestors.put(allocator, 45, try createAncestor(allocator, &.{44}));
        try ancestors.put(allocator, 46, try createAncestor(allocator, &.{ 45, 44 }));
        try ancestors.put(allocator, 47, try createAncestor(allocator, &.{ 46, 45, 44 }));
        try ancestors.put(allocator, 48, try createAncestor(allocator, &.{ 47, 46, 45, 44 }));
        try ancestors.put(allocator, 49, try createAncestor(allocator, &.{ 48, 47, 46, 45, 44 }));
        try ancestors.put(
            allocator,
            50,
            try createAncestor(allocator, &.{ 49, 48, 47, 46, 45, 44 }),
        );
        try ancestors.put(allocator, 110, try createAncestor(allocator, &.{44}));
        // Note: 112 is no longer in ancestors because it descends from 43 which is below root 44

        // Rebuild descendants from root 44
        for (descendants.values()) |*set| set.deinit(allocator);
        descendants.clearRetainingCapacity();
        try addDescendants(&descendants, allocator, 44, &.{ 45, 46, 47, 48, 49, 50, 110 });
        try addDescendants(&descendants, allocator, 45, &.{ 46, 47, 48, 49, 50 });
        try addDescendants(&descendants, allocator, 46, &.{ 47, 48, 49, 50 });
        try addDescendants(&descendants, allocator, 47, &.{ 48, 49, 50 });
        try addDescendants(&descendants, allocator, 48, &.{ 49, 50 });
        try addDescendants(&descendants, allocator, 49, &.{50});

        const decision = try tower.makeCheckSwitchThresholdDecision(
            allocator,
            110,
            &ancestors,
            &descendants,
            &progress,
            total_stake,
            &epoch_vote_accounts,
            &latest_validator_votes,
            &fork_choice,
        );
        switch (decision) {
            .failed_switch_threshold => |threshold| {
                try std.testing.expectEqual(0, threshold.switch_proof_stake);
                try std.testing.expectEqual(total_stake, threshold.total_stake);
            },
            else => try std.testing.expect(false),
        }
    }
}

test "selectVoteAndResetForks stake not found" {
    const allocator = std.testing.allocator;
    const fork_tuples = sig.consensus.fork_choice.fork_tuples;

    const fork_choice = try sig.consensus.fork_choice.forkChoiceForTest(
        allocator,
        fork_tuples[0..],
    );
    defer fork_choice.deinit(allocator);

    var tower = try createTestReplayTower(8, 0.66);
    defer tower.deinit(allocator);

    const latest = LatestValidatorVotes.empty;

    const epoch_stakes: EpochStakes = .EMPTY_WITH_GENESIS;
    defer epoch_stakes.deinit(allocator);

    try std.testing.expectError(
        error.ForkStatsNotFound,
        tower.selectVoteAndResetForks(
            std.testing.allocator,
            100,
            null,
            100,
            &.{},
            &.{},
            &ProgressMap.INIT,
            &latest,
            &fork_choice,
            &.empty,
            .noop,
        ),
    );
}

const TreeNode = sig.consensus.fork_choice.TreeNode;
const ForkStats = sig.consensus.progress_map.ForkStats;
const ForkProgress = sig.consensus.progress_map.ForkProgress;
const EpochStakes = sig.core.EpochStakes;
const Stakes = sig.core.Stakes;

test "unconfirmed duplicate slots and lockouts for non heaviest fork" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    const root: SlotAndHash = .{ .slot = 0, .hash = .initRandom(random) };

    const hash4: SlotAndHash = .{ .slot = 4, .hash = .initRandom(random) };
    const hash3: SlotAndHash = .{ .slot = 3, .hash = .initRandom(random) };
    const hash2: SlotAndHash = .{ .slot = 2, .hash = .initRandom(random) };
    const hash5: SlotAndHash = .{ .slot = 5, .hash = .initRandom(random) };
    const hash1: SlotAndHash = .{ .slot = 1, .hash = .initRandom(random) };

    const hash6: SlotAndHash = .{ .slot = 6, .hash = .initRandom(random) };
    const hash7: SlotAndHash = .{ .slot = 7, .hash = .initRandom(random) };
    const hash8: SlotAndHash = .{ .slot = 8, .hash = .initRandom(random) };
    const hash9: SlotAndHash = .{ .slot = 9, .hash = .initRandom(random) };
    const hash10: SlotAndHash = .{ .slot = 10, .hash = .initRandom(random) };

    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    // Build fork structure:
    //
    //      slot 0
    //        |
    //      slot 1
    //      /    \
    // slot 2    |
    //    |      |
    // slot 3    |
    //    |      |
    // slot 4    |
    //         slot 5

    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[5]TreeNode{
        .{ hash1, root },
        .{ hash5, hash1 },
        .{ hash2, hash1 },
        .{ hash3, hash2 },
        .{ hash4, hash3 },
    });

    try fixture.fillFork(allocator, .{ .root = root, .data = trees1 }, .active);
    try fixture.fill_epoch_stake_random(allocator, random);

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const tmp_dir = tmp_dir_root.dir;

    // the directory into which the snapshots will be unpacked and copied to.
    var unpacked_snap_dir = try tmp_dir.makeOpenPath("snapshot", .{});
    defer unpacked_snap_dir.close();

    var accountsdb = try sig.accounts_db.AccountsDB.init(.{
        .allocator = allocator,
        .logger = .noop,
        .snapshot_dir = unpacked_snap_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 1,
    });
    defer accountsdb.deinit();

    var replay_tower = try ReplayTower.init(
        .noop,
        Pubkey.ZEROES,
        .{ .root = root.slot },
        &registry,
    );
    defer replay_tower.deinit(allocator);

    const bits = try DynamicArrayBitSet(u64).initEmpty(allocator, 10);
    defer bits.deinit(allocator);

    // Insert SlotHistory accounts at relevant fork slots so SlotHistoryAccessor can read them
    inline for (.{
        root.slot,
        hash1.slot,
        hash2.slot,
        hash3.slot,
        hash4.slot,
        hash5.slot,
        hash6.slot,
        hash7.slot,
        hash8.slot,
        hash9.slot,
        hash10.slot,
    }) |slot_to_write| {
        const slot_history_value = SlotHistory{ .bits = bits, .next_slot = slot_to_write };
        const sh_data_len = sig.bincode.sizeOf(slot_history_value, .{});
        const sh_data = try allocator.alloc(u8, sh_data_len);
        defer allocator.free(sh_data);
        _ = try sig.bincode.writeToSlice(sh_data, slot_history_value, .{});
        const sh_account: sig.runtime.AccountSharedData = .{
            .lamports = 1,
            .data = sh_data,
            .owner = sig.runtime.sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        };
        try accountsdb.putAccount(slot_to_write, SlotHistory.ID, sh_account);
    }

    const forks1 = try fixture.select_fork_slots(&replay_tower);
    const result = try replay_tower.selectVoteAndResetForks(
        allocator,
        forks1.heaviest,
        forks1.heaviest_on_same_fork,
        0, // heaviest_epoch
        &fixture.ancestors,
        &fixture.descendants,
        &fixture.progress,
        &LatestValidatorVotes.empty,
        &fixture.fork_choice,
        &fixture.epoch_stakes,
        accountsdb.accountReader(),
    );
    try std.testing.expectEqual(4, result.reset_slot.?);
    try std.testing.expectEqual(4, result.vote_slot.?.slot);
    try std.testing.expectEqual(.same_fork, result.vote_slot.?.decision);
    try std.testing.expectEqual(0, result.heaviest_fork_failures.items.len);

    // Record the vote for 5 which is not on the heaviest fork.
    _ = try replay_tower.recordBankVote(allocator, hash5.slot, hash5.hash);
    const forks2 = try fixture.select_fork_slots(&replay_tower);
    var result2 = try replay_tower.selectVoteAndResetForks(
        allocator,
        forks2.heaviest,
        forks2.heaviest_on_same_fork,
        0, // heaviest_epoch
        &fixture.ancestors,
        &fixture.descendants,
        &fixture.progress,
        &LatestValidatorVotes.empty,
        &fixture.fork_choice,
        &fixture.epoch_stakes,
        accountsdb.accountReader(),
    );

    defer {
        result2.heaviest_fork_failures.deinit(allocator);
    }

    try std.testing.expectEqual(null, result2.vote_slot);
    try std.testing.expectEqual(5, result2.reset_slot);

    // TODO: IN Agave this state update is done in ReplayStage::compute_bank_stats
    fixture.update_fork_stat_lockout(4, true);

    const forks3 = try fixture.select_fork_slots(&replay_tower);
    var result3 = try replay_tower.selectVoteAndResetForks(
        allocator,
        forks3.heaviest,
        forks3.heaviest_on_same_fork,
        0, // heaviest_epoch
        &fixture.ancestors,
        &fixture.descendants,
        &fixture.progress,
        &LatestValidatorVotes.empty,
        &fixture.fork_choice,
        &fixture.epoch_stakes,
        accountsdb.accountReader(),
    );

    defer {
        result3.heaviest_fork_failures.deinit(allocator);
    }

    try std.testing.expect(result3.heaviest_fork_failures.items.len == 2);

    switch (result3.heaviest_fork_failures.items[0]) {
        .FailedSwitchThreshold => |data| {
            try std.testing.expectEqual(4, data.slot);
            try std.testing.expectEqual(0, data.observed_stake);
            try std.testing.expectEqual(1000, data.total_stake);
        },
        else => try std.testing.expect(false), // Fail if not FailedSwitchThreshold
    }

    // Check second item is LockedOut with expected value
    switch (result3.heaviest_fork_failures.items[1]) {
        .LockedOut => |slot| {
            try std.testing.expectEqual(4, slot);
        },
        else => try std.testing.expect(false), // Fail if not LockedOut
    }

    // Continue building on 5
    //
    // Build fork structure:
    //         slot 5
    //           |
    //         slot 6
    //         /    \
    //    slot 7     slot 10
    //      |
    //    slot 8
    //      |
    //    slot 9
    var trees = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees.appendSliceAssumeCapacity(&[5]TreeNode{
        .{ hash6, hash5 },
        .{ hash7, hash6 },
        .{ hash8, hash7 },
        .{ hash9, hash8 },
        .{ hash10, hash6 },
    });

    try fixture.fillFork(allocator, .{ .root = hash5, .data = trees }, .active);

    // 4 is still the heaviest slot, but not votable because of lockout.
    // 9 is the deepest slot from our last voted fork (5), so it is what we should
    // reset to.
    const forks4 = try fixture.select_fork_slots(&replay_tower);

    var result4 = try replay_tower.selectVoteAndResetForks(
        allocator,
        forks4.heaviest,
        forks4.heaviest_on_same_fork,
        0, // heaviest_epoch
        &fixture.ancestors,
        &fixture.descendants,
        &fixture.progress,
        &LatestValidatorVotes.empty,
        &fixture.fork_choice,
        &fixture.epoch_stakes,
        accountsdb.accountReader(),
    );

    defer {
        result4.heaviest_fork_failures.deinit(allocator);
    }

    try std.testing.expectEqual(null, result4.vote_slot);
    try std.testing.expectEqual(9, result4.reset_slot);

    switch (result4.heaviest_fork_failures.items[0]) {
        .FailedSwitchThreshold => |data| {
            try std.testing.expectEqual(4, data.slot);
            try std.testing.expectEqual(0, data.observed_stake);
            try std.testing.expectEqual(1000, data.total_stake);
        },
        else => try std.testing.expect(false), // Fail if not FailedSwitchThreshold
    }

    // Check second item is LockedOut with expected value
    switch (result4.heaviest_fork_failures.items[1]) {
        .LockedOut => |slot| {
            try std.testing.expectEqual(4, slot);
        },
        else => try std.testing.expect(false), // Fail if not LockedOut
    }

    var split = try fixture.fork_choice.splitOff(allocator, &registry, hash6);
    defer split.deinit(allocator);

    const forks5 = try fixture.select_fork_slots(&replay_tower);

    var result5 = try replay_tower.selectVoteAndResetForks(
        allocator,
        forks5.heaviest,
        forks5.heaviest_on_same_fork,
        0, // heaviest_epoch
        &fixture.ancestors,
        &fixture.descendants,
        &fixture.progress,
        &LatestValidatorVotes.empty,
        &fixture.fork_choice,
        &fixture.epoch_stakes,
        accountsdb.accountReader(),
    );

    defer {
        result5.heaviest_fork_failures.deinit(allocator);
    }

    try std.testing.expectEqual(null, result5.vote_slot);
    try std.testing.expectEqual(5, result5.reset_slot);

    switch (result5.heaviest_fork_failures.items[0]) {
        .FailedSwitchThreshold => |data| {
            try std.testing.expectEqual(4, data.slot);
            try std.testing.expectEqual(0, data.observed_stake);
            try std.testing.expectEqual(1000, data.total_stake);
        },
        else => try std.testing.expect(false), // Fail if not FailedSwitchThreshold
    }

    // Check second item is LockedOut with expected value
    switch (result4.heaviest_fork_failures.items[1]) {
        .LockedOut => |slot| {
            try std.testing.expectEqual(4, slot);
        },
        else => try std.testing.expect(false), // Fail if not LockedOut
    }
}

test "test tower sync from bank failed lockout" {}

test "test VoteTooOld error triggers trackStaleVoteRejected" {
    var tower = try createTestReplayTower(1, 0.67);
    defer tower.deinit(std.testing.allocator);

    // Record a vote for slot 5
    _ = try tower.recordBankVote(
        std.testing.allocator,
        5,
        Hash.ZEROES,
    );

    // Get initial counter value
    const initial_stale_votes = tower.metrics.stale_votes_rejected.get();

    // Try to record a vote for an older slot (should trigger VoteTooOld)
    const result = tower.recordBankVote(
        std.testing.allocator,
        3, // Older than slot 5
        Hash.ZEROES,
    );

    // Should return VoteTooOld error
    try std.testing.expectError(error.VoteTooOld, result);

    // Check that stale vote rejected counter was incremented
    const final_stale_votes = tower.metrics.stale_votes_rejected.get();
    try std.testing.expectEqual(initial_stale_votes + 1, final_stale_votes);
}

const builtin = @import("builtin");
const DynamicArrayBitSet = sig.bloom.bit_set.DynamicArrayBitSet;

pub fn createTestReplayTower(
    threshold_depth: usize,
    threshold_size: f64,
) !ReplayTower {
    if (!builtin.is_test) {
        @compileError("createTestTower should only be used in test");
    }

    var replay_tower: ReplayTower = .{
        .logger = .noop,
        .tower = .{ .root = 0 },
        .node_pubkey = Pubkey.ZEROES,
        .threshold_depth = 0,
        .threshold_size = 0,
        .last_vote = VoteTransaction.DEFAULT,
        .last_vote_tx_blockhash = .uninitialized,
        .last_timestamp = BlockTimestamp.ZEROES,
        .stray_restored_slot = null,
        .last_switch_threshold_check = null,
        .metrics = try ReplayTowerMetrics.init(sig.prometheus.globalRegistry()),
    };

    replay_tower.threshold_depth = threshold_depth;
    replay_tower.threshold_size = threshold_size;
    return replay_tower;
}

fn isSlotConfirmed(
    replay_tower: *const ReplayTower,
    slot: Slot,
    voted_stakes: *const sig.consensus.progress_map.consensus.VotedStakes,
    total_stake: u64,
) bool {
    if (!builtin.is_test) {
        @compileError("isSlotConfirmed should only be used in test");
    }

    if (voted_stakes.get(slot)) |stake| {
        const stake_ratio = @as(f64, @floatFromInt(stake)) / @as(f64, @floatFromInt(total_stake));
        return stake_ratio > replay_tower.threshold_size;
    } else {
        return false;
    }
}

fn voteAndCheckRecent(num_votes: usize) !void {
    if (!builtin.is_test) {
        @compileError("voteAndCheckRecent should only be used in test");
    }
    var tower = try createTestReplayTower(1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var slots = std.ArrayList(Lockout).init(std.testing.allocator);
    defer slots.deinit();

    if (num_votes > 0) {
        for (0..num_votes) |i| {
            try slots.append(Lockout{
                .slot = i,
                .confirmation_count = @intCast(num_votes - i),
            });
        }
    }

    var expected_slots = try std.ArrayListUnmanaged(Lockout).initCapacity(
        std.testing.allocator,
        slots.items.len,
    );
    defer expected_slots.deinit(std.testing.allocator);
    try expected_slots.appendSlice(std.testing.allocator, slots.items);

    var expected = TowerSync{
        .lockouts = expected_slots,
        .root = if (num_votes > 0) 0 else null,
        .timestamp = null,
        .hash = Hash.ZEROES,
        .block_id = Hash.ZEROES,
    };

    for (0..num_votes) |i| {
        _ = try tower.recordBankVote(
            std.testing.allocator,
            i,
            Hash.ZEROES,
        );
    }

    expected.timestamp = tower.last_vote.timestamp();

    try std.testing.expectEqualDeep(
        expected.lockouts.items,
        tower.last_vote.tower_sync.lockouts.items,
    );
}

pub fn createTestSlotHistory(
    allocator: std.mem.Allocator,
) !SlotHistory {
    if (!builtin.is_test) {
        @compileError("createTestSlotHistory should only be used in test");
    }

    var bits = try DynamicArrayBitSet(u64).initFull(allocator, MAX_ENTRIES);
    bits.setRangeValue(.{ .start = 0, .end = MAX_ENTRIES }, false);
    bits.setValue(0, true);

    return SlotHistory{ .bits = bits, .next_slot = 1 };
}

fn createAncestor(allocator: std.mem.Allocator, slots: []const Slot) !Ancestors {
    if (!builtin.is_test) {
        @compileError("createAncestor should only be used in test");
    }
    var set: Ancestors = .EMPTY;
    errdefer set.deinit(allocator);
    for (slots) |slot| try set.addSlot(allocator, slot);
    return set;
}

fn fillProgressMapForkStats(
    allocator: std.mem.Allocator,
    progress_map: *ProgressMap,
    inputs: []struct { Slot, ForkStats },
) !void {
    for (inputs) |input| {
        progress_map.map.put(allocator, input[0], input[1]);
    }
}

pub const MAX_TEST_TREE_LEN = 100;
const SlotTracker = sig.replay.trackers.SlotTracker;
const Tree = struct { root: SlotAndHash, data: std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN) };
pub const TestFixture = struct {
    slot_tracker: SlotTracker,
    fork_choice: HeaviestSubtreeForkChoice,
    ancestors: AutoArrayHashMapUnmanaged(Slot, Ancestors) = .{},
    descendants: AutoArrayHashMapUnmanaged(Slot, SortedSetUnmanaged(Slot)) = .{},
    progress: ProgressMap = ProgressMap.INIT,
    epoch_stakes: EpochStakesMap,
    node_pubkeys: std.ArrayListUnmanaged(Pubkey),
    vote_pubkeys: std.ArrayListUnmanaged(Pubkey),
    latest_validator_votes_for_frozen_banks: LatestValidatorVotes,

    pub fn init(
        allocator: std.mem.Allocator,
        root: SlotAndHash,
    ) !TestFixture {
        const slot_tracker: SlotTracker = blk: {
            var constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
            errdefer constants.deinit(allocator);
            constants.parent_slot = root.slot -| 1;

            var state: sig.core.SlotState = .GENESIS;
            errdefer state.deinit(allocator);
            state.hash = .init(root.hash);

            break :blk try .init(allocator, root.slot, .{
                .constants = constants,
                .state = state,
            });
        };
        errdefer slot_tracker.deinit(allocator);

        return .{
            .slot_tracker = slot_tracker,
            .fork_choice = try .init(
                allocator,
                .noop,
                root,
                sig.prometheus.globalRegistry(),
            ),
            .node_pubkeys = .empty,
            .vote_pubkeys = .empty,
            .epoch_stakes = .{},
            .latest_validator_votes_for_frozen_banks = .empty,
        };
    }

    pub fn deinit(self: *TestFixture, allocator: std.mem.Allocator) void {
        self.fork_choice.deinit(allocator);
        self.progress.deinit(allocator);
        self.slot_tracker.deinit(allocator);
        self.node_pubkeys.deinit(allocator);
        self.vote_pubkeys.deinit(allocator);
        self.latest_validator_votes_for_frozen_banks.deinit(allocator);

        {
            var it = self.epoch_stakes.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.deinit(allocator);
            }
            self.epoch_stakes.deinit(allocator);
        }

        for (self.descendants.values()) |set| set.deinit(allocator);
        self.descendants.deinit(allocator);

        for (self.ancestors.values()) |*set| set.deinit(allocator);
        self.ancestors.deinit(allocator);
    }

    pub fn update_fork_stat_lockout(self: *TestFixture, slot: Slot, locked_out: bool) void {
        // TODO: IN Agave this state update is done in ReplayStage::compute_bank_stats
        self.progress.getForkStats(slot).?.is_locked_out = locked_out;
    }

    pub fn select_fork_slots(self: *const TestFixture, replay_tower: *const ReplayTower) !struct {
        heaviest: Slot,
        heaviest_on_same_fork: ?Slot,
    } {
        const heaviest_on_same_fork =
            (try self.fork_choice.heaviestSlotOnSameVotedFork(replay_tower)) orelse null;

        return .{
            .heaviest = self.fork_choice.heaviestOverallSlot().slot,
            .heaviest_on_same_fork = if (heaviest_on_same_fork == null)
                null
            else
                heaviest_on_same_fork.?.slot,
        };
    }

    pub fn fill_keys(
        self: *TestFixture,
        allocator: std.mem.Allocator,
        random: std.Random,
        num_keypairs: usize,
    ) !void {
        self.node_pubkeys.clearRetainingCapacity();
        self.vote_pubkeys.clearRetainingCapacity();

        try self.node_pubkeys.ensureTotalCapacityPrecise(allocator, num_keypairs);
        try self.vote_pubkeys.ensureTotalCapacityPrecise(allocator, num_keypairs);
        for (0..num_keypairs) |_| {
            self.node_pubkeys.appendAssumeCapacity(.initRandom(random));
            self.vote_pubkeys.appendAssumeCapacity(.initRandom(random));
        }
    }

    pub fn fillFork(
        self: *TestFixture,
        allocator: std.mem.Allocator,
        input_tree: Tree,
        frozen_state: enum { frozen, active },
    ) !void {
        // Add root to progress map.
        {
            try self.progress.map.ensureUnusedCapacity(allocator, 1);
            const prev_root = self.progress.map.fetchPutAssumeCapacity(input_tree.root.slot, fp: {
                var root_fp = try ForkProgress.zeroes(allocator);
                root_fp.fork_stats.computed = true;
                root_fp.fork_stats.my_latest_landed_vote = null;
                break :fp root_fp;
            });
            if (prev_root) |kv| kv.value.deinit(allocator);
        }
        // TODO check that root fork exist already and it is being extended
        for (input_tree.data.constSlice()) |tree| {
            const parent_slot = blk: {
                const p = tree[1] orelse break :blk 0;
                break :blk p.slot;
            };
            const parent_hash = blk: {
                const p = tree[1] orelse break :blk Hash.ZEROES;
                break :blk p.hash;
            };

            {
                var constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
                errdefer constants.deinit(allocator);

                var state: sig.core.SlotState = .GENESIS;
                errdefer state.deinit(allocator);

                constants.parent_slot = parent_slot;
                constants.parent_hash = parent_hash;
                constants.block_height = tree[0].slot + 1;
                state.hash = .init(tree[0].hash);

                try self.slot_tracker.put(
                    allocator,
                    tree[0].slot,
                    .{ .constants = constants, .state = state },
                );
            }

            // Populate forkchoice
            try self.fork_choice.addNewLeafSlot(allocator, tree[0], tree[1]);
            // Populate progress map
            {
                try self.progress.map.ensureUnusedCapacity(allocator, 1);
                const prev_root = self.progress.map.fetchPutAssumeCapacity(tree[0].slot, fp: {
                    var root_fp = try ForkProgress.zeroes(allocator);
                    root_fp.fork_stats.computed = false;
                    root_fp.fork_stats.my_latest_landed_vote = null;
                    break :fp root_fp;
                });
                if (prev_root) |kv| kv.value.deinit(allocator);
            }
            if (frozen_state == .frozen) {
                // new_bank.freeze();
                const new_slot = self.slot_tracker.get(parent_slot) orelse continue;
                new_slot.state.hash = .init(parent_hash);
                const fork_state = self.progress.getForkStats(parent_slot) orelse continue;
                fork_state.slot_hash = parent_hash;
            }
        }

        try self.descendants.ensureTotalCapacity(allocator, input_tree.data.len);
        try self.ancestors.ensureTotalCapacity(allocator, input_tree.data.len);
        // Populate ancenstors
        var extended_ancestors = try getAncestors(allocator, input_tree);
        defer {
            for (extended_ancestors.values()) |*set| set.deinit(allocator);
            extended_ancestors.deinit(allocator);
        }
        try extendForkTreeAncestors(allocator, &self.ancestors, extended_ancestors);

        // Populate decendants
        var extended_descendants = try getDescendants(allocator, input_tree);
        defer {
            for (extended_descendants.values()) |set| set.deinit(allocator);
            extended_descendants.deinit(allocator);
        }
        try extendForkTree(allocator, &self.descendants, extended_descendants);
    }

    pub fn fill_epoch_stake_random(
        self: *TestFixture,
        allocator: std.mem.Allocator,
        random: std.Random,
    ) !void {
        var epoch_stakes: EpochStakes = .EMPTY_WITH_GENESIS;
        epoch_stakes.total_stake = 1000;
        epoch_stakes.stakes.deinit(allocator);
        epoch_stakes.stakes = try Stakes(.delegation).initRandom(
            allocator,
            random,
            1,
        );

        // Always resest for now.
        self.epoch_stakes = .{};
        try self.epoch_stakes.put(allocator, 0, epoch_stakes);
    }
};

fn getDescendants(allocator: std.mem.Allocator, tree: Tree) !std.AutoArrayHashMapUnmanaged(
    Slot,
    SortedSetUnmanaged(Slot),
) {
    if (!builtin.is_test) {
        @compileError("getDescendants should only be used in test");
    }
    var descendants = std.AutoArrayHashMapUnmanaged(Slot, SortedSetUnmanaged(Slot)){};

    var children_map = std.AutoHashMap(Slot, std.ArrayList(Slot)).init(allocator);
    defer {
        var it = children_map.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit();
        }
        children_map.deinit();
    }

    try children_map.put(tree.root.slot, std.ArrayList(Slot).init(allocator));
    for (tree.data.constSlice()) |node| {
        try children_map.put(node[0].slot, std.ArrayList(Slot).init(allocator));
        if (node[1]) |parent| {
            try children_map.put(parent.slot, std.ArrayList(Slot).init(allocator));
        }
    }

    for (tree.data.constSlice()) |node| {
        if (node[1]) |parent| {
            try children_map.getPtr(parent.slot).?.append(node[0].slot);
        }
    }

    var visited = std.AutoHashMap(Slot, void).init(allocator);
    defer visited.deinit();

    var stack = std.ArrayList(struct { slot: Slot, processed: bool }).init(allocator);
    defer stack.deinit();

    try stack.append(.{ .slot = tree.root.slot, .processed = false });

    while (stack.items.len > 0) {
        var current = &stack.items[stack.items.len - 1];
        if (current.processed) {
            _ = stack.pop();

            var descendant_list: SortedSetUnmanaged(Slot) = .empty;
            errdefer descendant_list.deinit(allocator);

            if (children_map.get(current.slot)) |children| {
                for (children.items) |item| {
                    try descendant_list.put(allocator, item);
                }

                for (children.items) |child| {
                    if (descendants.get(child)) |child_descendants| {
                        var cd = child_descendants;
                        for (cd.items()) |item| {
                            try descendant_list.put(allocator, item);
                        }
                    }
                }
            }

            try descendants.put(allocator, current.slot, descendant_list);
        } else {
            if (visited.contains(current.slot)) {
                _ = stack.pop();
                continue;
            }
            try visited.put(current.slot, {});

            current.processed = true;

            if (children_map.get(current.slot)) |children| {
                var i = children.items.len;
                while (i > 0) {
                    i -= 1;
                    try stack.append(.{ .slot = children.items[i], .processed = false });
                }
            }
        }
    }

    return descendants;
}

fn getAncestors(allocator: std.mem.Allocator, tree: Tree) !std.AutoArrayHashMapUnmanaged(
    Slot,
    Ancestors,
) {
    if (!builtin.is_test) {
        @compileError("getAncestors should only be used in test");
    }
    var ancestors: std.AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
    errdefer ancestors.deinit(allocator);
    try ancestors.put(allocator, tree.root.slot, .EMPTY);

    var parent_map = std.AutoHashMap(Slot, Slot).init(allocator);
    defer parent_map.deinit();

    for (tree.data.constSlice()) |node| {
        const child = node[0];
        if (node[1]) |parent| {
            try parent_map.put(child.slot, parent.slot);
        }
    }

    var visited = std.AutoHashMap(Slot, void).init(allocator);
    defer visited.deinit();

    var queue = std.ArrayList(Slot).init(allocator);
    defer queue.deinit();
    try queue.append(tree.root.slot);
    try visited.put(tree.root.slot, {});

    while (queue.items.len > 0) {
        const current = queue.orderedRemove(0);

        for (tree.data.constSlice()) |node| {
            if (node[1]) |parent| {
                if (parent.slot == current) {
                    const child = node[0];
                    if (!visited.contains(child.slot)) {
                        try queue.append(child.slot);
                        try visited.put(child.slot, {});

                        var child_ancestors: Ancestors = .EMPTY;
                        errdefer child_ancestors.deinit(allocator);
                        try child_ancestors.addSlot(allocator, current);

                        if (ancestors.getPtr(current)) |parent_ancestors| {
                            for (parent_ancestors.ancestors.keys()) |item| {
                                try child_ancestors.addSlot(allocator, item);
                            }
                        }

                        try ancestors.put(allocator, child.slot, child_ancestors);
                    }
                }
            }
        }
    }

    return ancestors;
}

pub fn extendForkTree(
    allocator: std.mem.Allocator,
    original: *std.AutoArrayHashMapUnmanaged(Slot, SortedSetUnmanaged(Slot)),
    extension: std.AutoArrayHashMapUnmanaged(Slot, SortedSetUnmanaged(Slot)),
) !void {
    if (!builtin.is_test) {
        @compileError("extendForkTree should only be used in test");
    }
    if (extension.count() == 0) {
        return;
    }

    for (extension.keys(), extension.values()) |slot, *extension_children| {
        const original_children = original.getPtr(slot) orelse {
            try original.put(allocator, slot, try extension_children.clone(allocator));
            continue;
        };

        for (extension_children.items()) |extension_child| {
            try original_children.put(allocator, extension_child);
        }
    }
}

pub fn extendForkTreeAncestors(
    allocator: std.mem.Allocator,
    original: *std.AutoArrayHashMapUnmanaged(Slot, Ancestors),
    extension: std.AutoArrayHashMapUnmanaged(Slot, Ancestors),
) !void {
    if (!builtin.is_test) {
        @compileError("extendForkTree should only be used in test");
    }
    if (extension.count() == 0) {
        return;
    }

    for (extension.keys(), extension.values()) |slot, *extension_children| {
        const original_children = original.getPtr(slot) orelse {
            try original.put(allocator, slot, try extension_children.clone(allocator));
            continue;
        };

        for (extension_children.ancestors.keys()) |extension_child| {
            try original_children.addSlot(allocator, extension_child);
        }
    }
}

fn genStakes(
    allocator: std.mem.Allocator,
    random: std.Random,
    stakes: []const struct { u64, []u64 },
) !StakeAndVoteAccountsMap {
    if (!builtin.is_test) @compileError("genStakes only intended for tests");

    var map: StakeAndVoteAccountsMap = .empty;

    for (stakes) |stake| {
        const lamports, const votes = stake;

        var vote_state = try sig.runtime.program.vote.state.createTestVoteState(
            allocator,
            Pubkey.ZEROES,
            null,
            Pubkey.ZEROES,
            0,
        );
        for (votes) |slot| {
            try sig.runtime.program.vote.state.processSlotVoteUnchecked(
                allocator,
                &vote_state,
                slot,
            );
        }

        const rc = try allocator.create(sig.sync.ReferenceCounter);
        errdefer allocator.destroy(rc);
        rc.* = .init;

        try map.put(
            allocator,
            Pubkey.initRandom(random),
            .{
                .stake = lamports,
                .account = .{
                    .account = .{ .lamports = lamports },
                    .state = vote_state,
                    .rc = rc,
                },
            },
        );
    }
    return map;
}

pub const ReplayTowerMetrics = struct {
    switch_fork_decision: *sig.prometheus.VariantCounter(SwitchForkDecision),

    stale_votes_rejected: *sig.prometheus.Counter,
    stray_restored_slots: *sig.prometheus.Counter,

    pub const prefix = "replay_tower";

    pub fn init(registry: *sig.prometheus.Registry(.{})) !ReplayTowerMetrics {
        return try registry.initStruct(ReplayTowerMetrics);
    }
};
