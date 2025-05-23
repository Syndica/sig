const std = @import("std");
const sig = @import("../sig.zig");

const AutoHashMapUnmanaged = std.AutoHashMapUnmanaged;
const AutoArrayHashMapUnmanaged = std.AutoArrayHashMapUnmanaged;

const AccountsDB = sig.accounts_db.AccountsDB;
const BlockTimestamp = sig.runtime.program.vote.state.BlockTimestamp;
const Hash = sig.core.Hash;
const Lockout = sig.runtime.program.vote.state.Lockout;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SlotAndHash = sig.core.hash.SlotAndHash;
const SlotHistory = sig.runtime.sysvar.SlotHistory;
const SortedSet = sig.utils.collections.SortedSet;
const TowerSync = sig.runtime.program.vote.state.TowerSync;
const Vote = sig.runtime.program.vote.state.Vote;
const VoteStateUpdate = sig.runtime.program.vote.state.VoteStateUpdate;
const StakeAndVoteAccountsMap = sig.core.stake.StakeAndVoteAccountsMap;
const Logger = sig.trace.Logger;
const ScopedLogger = sig.trace.ScopedLogger;
const UnixTimestamp = sig.core.UnixTimestamp;

const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const LatestValidatorVotesForFrozenBanks =
    sig.consensus.unimplemented.LatestValidatorVotesForFrozenBanks;
const ThresholdDecision = sig.consensus.tower.ThresholdDecision;
const ProgressMap = sig.consensus.ProgressMap;
const Tower = sig.consensus.tower.Tower;
const TowerError = sig.consensus.tower.TowerError;
const VoteTransaction = sig.consensus.vote_transaction.VoteTransaction;
const VotedStakes = sig.consensus.tower.VotedStakes;

const Stake = u64;

const MAX_LOCKOUT_HISTORY = sig.consensus.tower.MAX_LOCKOUT_HISTORY;

const VOTE_THRESHOLD_DEPTH_SHALLOW: usize = 4;
const VOTE_THRESHOLD_DEPTH: usize = 8;
const SWITCH_FORK_THRESHOLD: f64 = 0.38;
const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days

pub const VOTE_THRESHOLD_SIZE: f64 = 2.0 / 3.0;

// TODO Come up with a better name?
// Consensus? Given this contains the logic of deciding what to vote or fork-switch into,
//  making use of tower, fork choice etc
// Voter?
pub const ReplayTower = struct {
    logger: ScopedLogger(@typeName(Self)),
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

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        logger: Logger,
        node_pubkey: Pubkey,
        vote_account_pubkey: Pubkey,
        fork_root: Slot,
        accounts_db: *AccountsDB,
    ) !ReplayTower {
        var tower = Tower.init(logger.unscoped());
        try tower.initializeLockoutsFromBank(
            allocator,
            &vote_account_pubkey,
            fork_root,
            accounts_db,
        );

        return .{
            .logger = logger.withScope(@typeName(Self)),
            .tower = tower,
            .node_pubkey = node_pubkey,
            .threshold_depth = 0,
            .threshold_size = 0,
            .last_vote = try VoteTransaction.default(allocator),
            .last_vote_tx_blockhash = .uninitialized,
            .last_timestamp = BlockTimestamp.ZEROES,
            .stray_restored_slot = null,
            .last_switch_threshold_check = null,
        };
    }

    pub fn deinit(self: *ReplayTower, allocator: std.mem.Allocator) void {
        self.last_vote.deinit(allocator);
    }

    pub fn newFromBankforks(
        allocator: std.mem.Allocator,
        logger: Logger,
        root_slot: *const Slot,
        root_hash: *const Hash,
        node_pubkey: *const Pubkey,
        vote_account: *const Pubkey,
    ) !Tower {
        _ = allocator;
        _ = logger;
        _ = root_slot;
        _ = root_hash;
        _ = node_pubkey;
        _ = vote_account;
        // Depends on having analogous structs for things like Bank, BankForks etc
        @panic("Unimplemented");
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

        const new_root = try self.tower.recordBankVoteAndUpdateLockouts(
            vote_slot,
        );

        try self.updateLastVoteFromVoteState(
            allocator,
            vote_hash,
            is_enable_tower_active,
            block_id,
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
                .initCapacity(allocator, self.tower.vote_state.votes.len);
            try new_lockouts.appendSlice(allocator, self.tower.vote_state.votes.constSlice());

            break :blk if (enable_tower_sync_ix)
                VoteTransaction{ .tower_sync = TowerSync{
                    .lockouts = new_lockouts,
                    .root = self.tower.vote_state.root_slot,
                    .hash = vote_hash,
                    .timestamp = null,
                    .block_id = block_id,
                } }
            else
                VoteTransaction{ .vote_state_update = VoteStateUpdate{
                    .lockouts = new_lockouts,
                    .root = self.tower.vote_state.root_slot,
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
        return if (self.last_vote.isEmpty())
            null
        else
            self.last_vote.slot(self.last_vote.len() - 1);
    }

    pub fn lastVotedSlotHash(self: *const ReplayTower) ?SlotAndHash {
        return if (self.lastVotedSlot()) |last_voted_slot|
            .{ .slot = last_voted_slot, .hash = self.last_vote.hash() }
        else
            null;
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

    /// Provides proof that enough validators voted for this new branch,
    /// so it's safe to switch to it.
    ///
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
        ancestors: *const AutoHashMapUnmanaged(Slot, SortedSet(Slot)),
        last_vote_ancestors: *const SortedSet(Slot),
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

        if (last_vote_ancestors.count() == 0) {
            // If `last_vote_ancestors` is empty, this means we must have a last vote that is stray. If the `last_voted_slot`
            // is stray, it must be descended from some earlier root than the latest root (the anchor at startup).
            // The above check also guarentees that the candidate slot is not a descendant of this stray last vote.
            //
            // This gives us a fork graph:
            //     / ------------- stray `last_voted_slot`
            // old root
            //     \- latest root (anchor) - ... - candidate slot
            //                                \- switch slot
            //
            // Thus the common acnestor of `last_voted_slot` and `candidate_slot` is `old_root`, which the `switch_slot`
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
    /// It requires gathering of stake information from other validators’ lockouts to justify switching to a
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
        ancestors: *const AutoHashMapUnmanaged(Slot, SortedSet(Slot)),
        descendants: *const AutoArrayHashMapUnmanaged(Slot, SortedSet(Slot)),
        progress: *const ProgressMap,
        total_stake: u64,
        epoch_vote_accounts: *const StakeAndVoteAccountsMap,
        latest_validator_votes_for_frozen_banks: *const LatestValidatorVotesForFrozenBanks,
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
        const switch_hash = progress.getHash(switch_slot).?;
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

        const last_vote_ancestors = ancestors.get(last_voted_slot) orelse blk: {
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
                break :blk SortedSet(u64).init(allocator);
            } else return error.NoAncestorsFoundForLastVote;
        };

        const switch_slot_ancestors = ancestors.get(switch_slot) orelse
            return error.NoAncestorsFoundForSwitchSlot;

        if (switch_slot == last_voted_slot or switch_slot_ancestors.contains(last_voted_slot)) {
            // If the `switch_slot is a descendant of the last vote,
            // no switching proof is necessary
            return SwitchForkDecision{ .same_fork = {} };
        }

        if (last_vote_ancestors.contains(switch_slot)) {
            if (self.isStrayLastVote()) {
                // This peculiar corner handling is needed mainly for a tower which is newer than
                // blockstore. (Yeah, we tolerate it for ease of maintaining validator by operators)
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
                return SwitchForkDecision{ .failed_switch_threshold = .{ 0, total_stake } };
            } else return error.NoAncestorsFoundForLastVote;
        }

        // By this point, we know the `switch_slot` is on a different fork
        // (is neither an ancestor nor descendant of `last_vote`), so a
        // switching proof is necessary
        const switch_proof = Hash.ZEROES;
        var locked_out_stake: u64 = 0;
        var locked_out_vote_accounts = SortedSet(Pubkey).init(allocator);
        var iterator = descendants.iterator();
        while (iterator.next()) |descendant| {
            const candidate_slot = descendant.key_ptr.*;
            var candidate_descendants = descendant.value_ptr.*;
            // 1) Don't consider any banks that haven't been frozen yet
            //    because the needed stats are unavailable
            // 2) Only consider lockouts at the latest `frozen` bank
            //    on each fork, as that bank will contain all the
            //    lockout intervals for ancestors on that fork as well.
            // 3) Don't consider lockouts on the `last_vote` itself
            // 4) Don't consider lockouts on any descendants of
            //    `last_vote`
            // 5) Don't consider any banks before the root because
            //    all lockouts must be ancestors of `last_vote`
            const is_progress_computed = if (progress.getForkStats(candidate_slot)) |stats|
                stats.computed
            else
                false;

            // If any of the descendants have the `computed` flag set, then there must be a more
            // recent frozen bank on this fork to use, so we can ignore this one. Otherwise,
            // even if this bank has descendants, if they have not yet been frozen / stats computed,
            // then use this bank as a representative for the fork.
            const is_descendant_computed = if (!is_progress_computed) blk: {
                break :blk for (candidate_descendants.items()) |d| {
                    if (progress.getForkStats(d)) |stats|
                        break stats.computed
                    else
                        break false;
                } else false;
            } else is_progress_computed;

            const is_candidate_eq_last_voted_slot = if (!is_descendant_computed)
                (candidate_slot == last_voted_slot)
            else
                is_descendant_computed;

            const is_candidate_less_eq_root = if (!is_candidate_eq_last_voted_slot)
                (candidate_slot <= root)
            else
                is_candidate_eq_last_voted_slot;

            const is_valid_switch = if (!is_candidate_less_eq_root)
                self.isValidSwitchingProofVote(
                    candidate_slot,
                    last_voted_slot,
                    switch_slot,
                    ancestors,
                    &last_vote_ancestors,
                ).?
            else
                is_candidate_less_eq_root;

            if (!is_valid_switch) {
                continue;
            }

            // By the time we reach here, any ancestors of the `last_vote`,
            // should have been filtered out, as they all have a descendant,
            // namely the `last_vote` itself.
            std.debug.assert(!last_vote_ancestors.contains(candidate_slot));
            // Evaluate which vote accounts in the bank are locked out
            // in the interval candidate_slot..last_vote, which means
            // finding any lockout intervals in the `lockout_intervals` tree
            // for this bank that contain `last_vote`.

            var lockout_intervals = progress
                .map
                .get(candidate_slot).?
                .fork_stats
                .lockout_intervals;

            // Find any locked out intervals for vote accounts in this bank with
            // `lockout_interval_end` >= `last_vote`, which implies they are locked out at
            // `last_vote` on another fork.
            const intervals_keyed_by_end = lockout_intervals.map.values()[last_voted_slot..];
            for (intervals_keyed_by_end) |interval_keyed_by_end| {
                for (interval_keyed_by_end.items) |vote_account| {
                    if (locked_out_vote_accounts.contains(vote_account[1])) {
                        continue;
                    }
                    // Only count lockouts on slots that are:
                    // 1) Not ancestors of `last_vote`, meaning being on different fork
                    // 2) Not from before the current root as we can't determine if
                    // anything before the root was an ancestor of `last_vote` or not
                    if (!last_vote_ancestors.contains(vote_account[0]) and (
                        // Given a `lockout_interval_start` < root that appears in a
                        // bank for a `candidate_slot`, it must be that `lockout_interval_start`
                        // is an ancestor of the current root, because `candidate_slot` is a
                        // descendant of the current root
                        vote_account[0] > root))
                    {
                        const stake =
                            if (epoch_vote_accounts.get(vote_account[1])) |staked_account|
                                staked_account[0]
                            else
                                0;
                        locked_out_stake += stake;

                        if (@as(f64, @floatFromInt(locked_out_stake)) / @as(
                            f64,
                            @floatFromInt(total_stake),
                        ) > SWITCH_FORK_THRESHOLD) {
                            return SwitchForkDecision{ .switch_proof = switch_proof };
                        }
                        try locked_out_vote_accounts.put(vote_account[1]);
                    }
                }
            }
        }
        // Check the latest votes for potentially gossip votes that haven't landed yet
        var gossip_votes_iter = latest_validator_votes_for_frozen_banks
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
                    const stake = if (stake_entry) |entry_stake| entry_stake[0] else 0;
                    locked_out_stake += stake;

                    const stake_ratio = @as(f64, @floatFromInt(locked_out_stake)) /
                        @as(f64, @floatFromInt(total_stake));
                    if (stake_ratio > SWITCH_FORK_THRESHOLD) {
                        return SwitchForkDecision{
                            .switch_proof = switch_proof,
                        };
                    }

                    locked_out_vote_accounts.put(vote_account_pubkey) catch unreachable;
                }
            }
        }
        // We have not detected sufficient lockout past the last voted slot to generate
        // a switching proof
        return SwitchForkDecision{ .failed_switch_threshold = .{ locked_out_stake, total_stake } };
    }

    /// Calls the makeCheckSwitchThresholdDecision and stores the result in
    /// ReplayTower.last_switch_threshold_check if the result is different from the last check.
    pub fn checkSwitchThreshold(
        self: *ReplayTower,
        allocator: std.mem.Allocator,
        switch_slot: Slot,
        ancestors: *const AutoHashMapUnmanaged(Slot, SortedSet(Slot)),
        descendants: *const AutoArrayHashMapUnmanaged(Slot, SortedSet(Slot)),
        progress: *const ProgressMap,
        total_stake: u64,
        epoch_vote_accounts: *const StakeAndVoteAccountsMap,
        latest_validator_votes_for_frozen_banks: *const LatestValidatorVotesForFrozenBanks,
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
            latest_validator_votes_for_frozen_banks,
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
    pub fn checkVoteStakeThresholds(
        self: *ReplayTower,
        allocator: std.mem.Allocator,
        slot: Slot,
        voted_stakes: *const VotedStakes,
        total_stake: Stake,
    ) ![]const ThresholdDecision {
        const threshold_size = 3;
        var threshold_decisions: [threshold_size]ThresholdDecision = undefined;

        // Generate the vote state assuming this vote is included.
        //
        var vote_state = self.tower.vote_state;
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
                self.logger.unscoped(),
                vote_state.nthRecentLockout(threshold.depth),
                self.tower.vote_state.votes.constSlice(),
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

    pub fn isStrayLastVote(self: *const ReplayTower) bool {
        return (self.stray_restored_slot != null and
            self.stray_restored_slot == self.lastVotedSlot());
    }

    /// Adjusts the tower's lockouts after a replay of the blockstore up to `replayed_root`.
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

        var default_vote = try VoteTransaction.default(allocator);
        defer default_vote.deinit(allocator);

        var default_tower = VoteTransaction{ .tower_sync = try TowerSync.zeroes(allocator) };
        defer default_tower.deinit(allocator);

        // This ensures that if vote_state.votes is empty,
        // then the only acceptable values for last_vote are:
        // - A default VoteStateUpdate or
        // - A default TowerSync
        std.debug.assert(
            (self.last_vote.eql(&default_vote) and
                self.tower.vote_state.votes.len == 0) or
                (self.last_vote.eql(&default_tower) and
                    self.tower.vote_state.votes.len == 0) or
                (self.tower.vote_state.votes.len > 0),
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
                self.tower.initializeRoot(replayed_root);
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
                // Blockstore doesn't have the tower_root slot because of
                // (replayed_root < tower_root) in this else clause, meaning the tower is from
                // the future from the view of blockstore.
                // Pretend the blockstore has the future tower_root to anchor exactly with that
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
    /// On success, the tower's lockouts are reinitialized to match blockstore state.
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
                    .log("The tower is fatally inconsistent with blockstore." ++
                    "Possible causes: diverged ancestors");
                return TowerError.FatallyInconsistentDivergedAncestors;
            }

            if (still_in_future and check != .future) {
                still_in_future = false;
            } else if (!still_in_future and check == .future) {
                // really odd cases: bad ordered votes?
                self.logger.err().log("The tower is fatally inconsistent with blockstore");
                return TowerError.FatallyInconsistentTimeWarp;
            }

            if (!past_outside_history and check == .too_old) {
                past_outside_history = true;
            } else if (past_outside_history and check != .too_old) {
                // really odd cases: bad ordered votes?
                self
                    .logger
                    .err()
                    .log("The tower is fatally inconsistent with blockstore." ++
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
                .log("The tower is fatally inconsistent with blockstore." ++
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

        try self.tower.initializeLockouts(flags);

        if (self.tower.vote_state.votes.len == 0) {
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
};

const BlockhashStatus = union(enum) {
    /// No vote since restart
    uninitialized,
    /// Non voting validator
    non_voting,
    /// Hot spare validator
    hot_spare,
    /// Successfully generated vote tx with blockhash
    blockhash: Hash,
};

const SwitchForkDecision = union(enum) {
    switch_proof: Hash,
    same_fork,
    failed_switch_threshold: struct {
        /// Switch proof stake
        Slot,
        /// Total stake
        Slot,
    },
    failed_switch_duplicate_rollback: Slot,
};

/// Returns `Some(gca)` where `gca` is the greatest (by slot number)
/// common ancestor of both `slot_a` and `slot_b`.
///
/// Returns `null` if:
/// * `slot_a` is not in `ancestors`
/// * `slot_b` is not in `ancestors`
/// * There is no common ancestor of slot_a and slot_b in `ancestors`
fn greatestCommonAncestor(
    ancestors: *const AutoHashMapUnmanaged(
        Slot,
        SortedSet(Slot),
    ),
    slot_a: Slot,
    slot_b: Slot,
) ?Slot {
    const ancestors_a = ancestors.get(slot_a) orelse return null;
    const ancestors_b = ancestors.get(slot_b) orelse return null;

    var max_slot: ?Slot = null;

    var superset, const subset = if (ancestors_a.count() >= ancestors_b.count())
        .{ ancestors_a, ancestors_b }
    else
        .{ ancestors_b, ancestors_a };

    if (superset.count() == 0 or subset.count() == 0) return null;

    for (superset.items()) |slot| {
        if (!subset.contains(slot)) continue;
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
    ancestors: *const AutoHashMapUnmanaged(Slot, SortedSet(Slot)),
) ?bool {
    return if (ancestors.get(maybe_descendant)) |candidate_slot_ancestors|
        candidate_slot_ancestors.contains(slot)
    else
        null;
}

fn checkVoteStakeThreshold(
    logger: sig.trace.Logger,
    maybe_threshold_vote: ?Lockout,
    tower_before_applying_vote: []const Lockout,
    threshold_depth: usize,
    threshold_size: f64,
    slot: Slot,
    voted_stakes: *const AutoHashMapUnmanaged(Slot, u64),
    total_stake: u64,
) ThresholdDecision {
    const threshold_vote = maybe_threshold_vote orelse {
        // Tower isn't that deep.
        return .passed_threshold;
    };

    const fork_stake = voted_stakes.get(threshold_vote.slot) orelse {
        // We haven't seen any votes on this fork yet, so no stake
        return .{
            .failed_threshold = .{ threshold_depth, 0 },
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
        return .{ .passed_threshold = {} };
    }

    return .{
        .failed_threshold = .{ threshold_depth, 0 },
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

test "check vote threshold without votes" {
    var tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 4, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    const result = try replay_tower.tower.isLockedOut(
        1,
        &ancestors,
    );
    try std.testing.expect(!result);
}

test "is locked out root slot child pass" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    replay_tower.tower.vote_state.root_slot = 0;

    const result = try replay_tower.tower.isLockedOut(
        1,
        &ancestors,
    );
    try std.testing.expect(!result);
}

test "is locked out root slot sibling fail" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    replay_tower.tower.vote_state.root_slot = 0;

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.tower.vote_state.root_slot = 0;

    _ = try replay_tower.recordBankVote(
        std.testing.allocator,
        0,
        Hash.ZEROES,
    );

    try std.testing.expect(replay_tower.tower.hasVoted(0));
    try std.testing.expect(!replay_tower.tower.hasVoted(1));
}

test "check recent slot" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

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

    try std.testing.expectEqual(0, replay_tower.tower.vote_state.votes.get(0).slot);
    try std.testing.expectEqual(2, replay_tower.tower.vote_state.votes.get(0).confirmation_count);
    try std.testing.expectEqual(4, replay_tower.tower.vote_state.votes.get(1).slot);
    try std.testing.expectEqual(1, replay_tower.tower.vote_state.votes.get(1).confirmation_count);
}

test "check vote threshold below threshold" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
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
    var tower = try createTestReplayTower(std.testing.allocator, VOTE_THRESHOLD_DEPTH, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
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
    var tower = try createTestReplayTower(std.testing.allocator, VOTE_THRESHOLD_DEPTH, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
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
    var tower = try createTestReplayTower(std.testing.allocator, VOTE_THRESHOLD_DEPTH, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
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
    var tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
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
    var tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
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
    var tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
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

test "maybe timestamp" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0);
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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0);

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.tower.vote_state.root_slot = 4;

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.tower.vote_state.root_slot = 2;

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 1, .confirmation_count = 1 },
    );

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 0, .confirmation_count = 1 },
    );

    const slots = [_]Slot{0};
    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    replay_tower.last_vote = VoteTransaction{ .vote = vote };

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 1, .confirmation_count = 1 },
    );

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 2, .confirmation_count = 1 },
    );

    const slots = [_]Slot{2};
    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    replay_tower.last_vote = VoteTransaction{ .vote = vote };

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = MAX_ENTRIES - 1, .confirmation_count = 1 },
    );

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 0, .confirmation_count = 1 },
    );

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 1, .confirmation_count = 1 },
    );

    const slots = [_]Slot{1};
    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    replay_tower.last_vote = VoteTransaction{ .vote = vote };

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 13, .confirmation_count = 1 },
    );

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 14, .confirmation_count = 1 },
    );

    const slots = [_]Slot{14};
    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    replay_tower.last_vote = VoteTransaction{ .vote = vote };
    // Triggers clearning of votes
    replay_tower.tower.initializeRoot(MAX_ENTRIES * 2);

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 2, .confirmation_count = 1 },
    );

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 1, .confirmation_count = 1 },
    );

    const slots = [_]Slot{1};
    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    replay_tower.last_vote = VoteTransaction{ .vote = vote };

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 2, .confirmation_count = 1 },
    );

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 3, .confirmation_count = 1 },
    );

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 3, .confirmation_count = 1 },
    );

    const slots = [_]Slot{3};
    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    replay_tower.last_vote = VoteTransaction{ .vote = vote };

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.tower.vote_state.root_slot = 42;

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 42, .confirmation_count = 1 },
    );

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 43, .confirmation_count = 1 },
    );

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 44, .confirmation_count = 1 },
    );

    const slots = [_]Slot{44};
    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    replay_tower.last_vote = VoteTransaction{ .vote = vote };

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 0, .confirmation_count = 1 },
    );

    const slots = [_]Slot{0};
    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    replay_tower.last_vote = VoteTransaction{ .vote = vote };

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
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 13, .confirmation_count = 1 },
    );

    try replay_tower.tower.vote_state.votes.append(
        Lockout{ .slot = 14, .confirmation_count = 1 },
    );

    const slots = [_]Slot{14};
    const vote = Vote{
        .slots = &slots,
        .hash = Hash.ZEROES,
        .timestamp = null,
    };

    replay_tower.last_vote = VoteTransaction{ .vote = vote };
    replay_tower.tower.initializeRoot(12);

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
    var tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 1);

    const result = isSlotConfirmed(&tower, 0, &stakes, 2);
    try std.testing.expect(!result);
}

test "is slot confirmed unknown slot" {
    var tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);

    const result = isSlotConfirmed(&tower, 0, &stakes, 2);
    try std.testing.expect(!result);
}

test "is slot confirmed pass" {
    var tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 2);

    const result = isSlotConfirmed(&tower, 0, &stakes, 2);
    try std.testing.expect(result);
}

test "default tower has no stray last vote" {
    var replay_tower = try createTestReplayTower(
        std.testing.allocator,
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
        var ancestors = AutoHashMapUnmanaged(Slot, SortedSet(Slot)){};
        defer {
            var it = ancestors.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.deinit();
            }
            ancestors.deinit(allocator);
        }

        try ancestors.put(allocator, 10, try createSet(allocator, &.{ 5, 3, 1 }));
        try ancestors.put(allocator, 20, try createSet(allocator, &.{ 8, 5, 2 }));

        // Both slots have common ancestor 5
        try std.testing.expectEqual(
            @as(?Slot, 5),
            greatestCommonAncestor(&ancestors, 10, 20),
        );
    }

    // Test case: No common ancestor
    {
        var ancestors = AutoHashMapUnmanaged(Slot, SortedSet(Slot)){};
        defer {
            var it = ancestors.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.deinit();
            }
            ancestors.deinit(allocator);
        }

        try ancestors.put(allocator, 10, try createSet(allocator, &.{ 3, 1 }));
        try ancestors.put(allocator, 20, try createSet(allocator, &.{ 8, 2 }));

        try std.testing.expectEqual(
            @as(?Slot, null),
            greatestCommonAncestor(&ancestors, 10, 20),
        );
    }

    // Test case: One empty ancestor set
    {
        var ancestors = AutoHashMapUnmanaged(Slot, SortedSet(Slot)){};
        defer {
            var it = ancestors.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.deinit();
            }
            ancestors.deinit(allocator);
        }

        try ancestors.put(allocator, 10, try createSet(allocator, &.{ 5, 3 }));
        try ancestors.put(allocator, 20, try createSet(allocator, &.{}));

        try std.testing.expectEqual(
            @as(?Slot, null),
            greatestCommonAncestor(&ancestors, 10, 20),
        );
    }

    // Test case: Missing slots
    {
        var ancestors = AutoHashMapUnmanaged(Slot, SortedSet(Slot)){};
        defer {
            var it = ancestors.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.deinit();
            }
            ancestors.deinit(allocator);
        }

        try ancestors.put(allocator, 10, try createSet(allocator, &.{ 5, 3 }));

        try std.testing.expectEqual(
            @as(?Slot, null),
            greatestCommonAncestor(&ancestors, 10, 99), // 99 doesn't exist
        );
    }

    // Test case: Multiple common ancestors (should pick greatest)
    {
        var ancestors = AutoHashMapUnmanaged(Slot, SortedSet(Slot)){};
        defer {
            var it = ancestors.iterator();
            while (it.next()) |entry| {
                entry.value_ptr.deinit();
            }
            ancestors.deinit(allocator);
        }

        try ancestors.put(allocator, 10, try createSet(allocator, &.{ 7, 5, 3 }));
        try ancestors.put(allocator, 20, try createSet(allocator, &.{ 7, 5, 4 }));

        // Should pick 7 (greater than 5)
        try std.testing.expectEqual(
            @as(?Slot, 7),
            greatestCommonAncestor(&ancestors, 10, 20),
        );
    }
}

const builtin = @import("builtin");
const DynamicArrayBitSet = sig.bloom.bit_set.DynamicArrayBitSet;

pub fn createTestReplayTower(
    allocator: std.mem.Allocator,
    threshold_depth: usize,
    threshold_size: f64,
) !ReplayTower {
    if (!builtin.is_test) {
        @compileError("createTestTower should only be used in test");
    }

    var replay_tower: ReplayTower = .{
        .logger = .noop,
        .tower = Tower.init(.noop),
        .node_pubkey = Pubkey.ZEROES,
        .threshold_depth = 0,
        .threshold_size = 0,
        .last_vote = try VoteTransaction.default(allocator),
        .last_vote_tx_blockhash = .uninitialized,
        .last_timestamp = BlockTimestamp.ZEROES,
        .stray_restored_slot = null,
        .last_switch_threshold_check = null,
    };

    replay_tower.threshold_depth = threshold_depth;
    replay_tower.threshold_size = threshold_size;
    return replay_tower;
}

fn isSlotConfirmed(
    replay_tower: *const ReplayTower,
    slot: Slot,
    voted_stakes: *const sig.consensus.tower.VotedStakes,
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
    var tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
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

fn createSet(allocator: std.mem.Allocator, slots: []const Slot) !SortedSet(Slot) {
    if (!builtin.is_test) {
        @compileError("createSet should only be used in test");
    }
    var set = SortedSet(Slot).init(allocator);
    for (slots) |slot| {
        try set.put(slot);
    }
    return set;
}
