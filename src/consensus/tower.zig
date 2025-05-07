const std = @import("std");
const sig = @import("../sig.zig");

const AutoHashMapUnmanaged = std.AutoHashMapUnmanaged;
const AutoArrayHashMapUnmanaged = std.AutoArrayHashMapUnmanaged;

const Account = sig.core.Account;
const AccountsDB = sig.accounts_db.AccountsDB;
const BankFields = sig.core.BankFields;
const EpochStakeMap = sig.core.stake.EpochStakeMap;
const BlockTimestamp = sig.runtime.program.vote_program.state.BlockTimestamp;
const Hash = sig.core.Hash;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const ProgressMap = sig.consensus.ProgressMap;
const LatestValidatorVotesForFrozenBanks =
    sig.consensus.unimplemented.LatestValidatorVotesForFrozenBanks;
const Lockout = sig.runtime.program.vote_program.state.Lockout;
const LockoutIntervals = sig.consensus.unimplemented.LockoutIntervals;
const Pubkey = sig.core.Pubkey;
const ReplayStage = sig.consensus.unimplemented.ReplayStage;
const Epoch = sig.core.Epoch;
const Slot = sig.core.Slot;
const SlotAndHash = sig.core.hash.SlotAndHash;
const SlotHistory = sig.runtime.sysvar.SlotHistory;
const SortedSet = sig.utils.collections.SortedSet;
const TowerStorage = sig.consensus.tower_storage.TowerStorage;
const TowerSync = sig.runtime.program.vote_program.state.TowerSync;
const TowerVoteState = sig.consensus.tower_state.TowerVoteState;
const Vote = sig.runtime.program.vote_program.state.Vote;
const VoteState = sig.runtime.program.vote_program.state.VoteState;
const VoteStateUpdate = sig.runtime.program.vote_program.state.VoteStateUpdate;
const VoteStateVersions = sig.runtime.program.vote_program.state.VoteStateVersions;
const VoteTransaction = sig.consensus.vote_transaction.VoteTransaction;
const StakeAndVoteAccountsMap = sig.core.stake.StakeAndVoteAccountsMap;
const Logger = sig.trace.Logger;
const ScopedLogger = sig.trace.ScopedLogger;
const UnixTimestamp = i64;

const MAX_LOCKOUT_HISTORY = sig.runtime.program.vote_program.state.MAX_LOCKOUT_HISTORY;
const VOTE_THRESHOLD_DEPTH_SHALLOW: usize = 4;
const VOTE_THRESHOLD_DEPTH: usize = 8;
pub const VOTE_THRESHOLD_SIZE: f64 = 2.0 / 3.0;
const SWITCH_FORK_THRESHOLD: f64 = 0.38;
const DUPLICATE_LIVENESS_THRESHOLD: f64 = 0.1;
const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days
const DUPLICATE_THRESHOLD = sig.consensus.unimplemented.DUPLICATE_THRESHOLD;

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

    pub fn canVote(self: *const SwitchForkDecision) bool {
        return switch (self.*) {
            .failed_switch_threshold => false,
            .failed_switch_duplicate_rollback => false,
            .same_fork => true,
            .switch_proof => true,
        };
    }
};

pub const Stake = u64;

pub const VotedSlot = Slot;
pub const VotedStakes = AutoHashMapUnmanaged(Slot, Stake);

const ComputedBankState = struct {
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
};

pub const ThresholdDecision = union(enum) {
    passed_threshold,
    failed_threshold: struct {
        // vote depth
        u64,
        // Observed stake
        u64,
    },
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

pub const TowerError = error{
    IoError,
    SerializeError,
    InvalidSignature,
    WrongTower,
    TooOldTower,
    FatallyInconsistent,
    FatallyInconsistentTimeWarp,
    FatallyInconsistentDivergedAncestors,
    FatallyInconsistentReplayOutOfOrder,
    HardFork,
    // Converted into erros from panics (debugs) in Agave
    /// Slots in tower are not older than last_checked_slot
    FatallyInconsistentTowerSlotOrder,
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

    pub fn default(allocator: std.mem.Allocator) !ReplayTower {
        return .{
            .logger = .noop,
            .tower = Tower.default(),
            .node_pubkey = Pubkey.ZEROES,
            .threshold_depth = 0,
            .threshold_size = 0,
            .last_vote = try VoteTransaction.default(allocator),
            .last_vote_tx_blockhash = .uninitialized,
            .last_timestamp = BlockTimestamp.ZEROES,
            .stray_restored_slot = null,
            .last_switch_threshold_check = null,
        };
    }

    pub fn init(
        allocator: std.mem.Allocator,
        logger: Logger,
        node_pubkey: *const Pubkey,
        vote_account_pubkey: *const Pubkey,
        fork_root: Slot,
        accounts_db: *AccountsDB,
    ) !ReplayTower {
        var replay_tower = try ReplayTower.default(allocator);
        replay_tower.logger = logger.withScope(@typeName(ReplayTower));
        replay_tower.node_pubkey = node_pubkey.*;

        var tower = Tower.default();
        tower.logger = logger.withScope(@typeName(Tower));
        try tower.initializeLockoutsFromBank(
            allocator,
            vote_account_pubkey,
            fork_root,
            accounts_db,
        );
        replay_tower.tower = tower;
        return replay_tower;
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

    pub fn recordBankVote(
        self: *ReplayTower,
        allocator: std.mem.Allocator,
        bank_fields: *const BankFields,
    ) !?Slot {
        // Returns the new root if one is made after applying a vote for the given bank to
        // `self.vote_state`
        //
        // TODO add block_id to bank fields
        const block_id = Hash.ZEROES;
        // TODO expose feature set on Bank
        const is_enable_tower_active = true;

        return try self.recordBankVoteAndUpdateLockouts(
            allocator,
            bank_fields.slot,
            bank_fields.hash,
            is_enable_tower_active,
            block_id,
        );
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

    /// Used inside the validator to simulate making a vote for a bank before
    /// it sends a vote transaction on-chain.
    fn recordBankVoteAndUpdateLockouts(
        self: *ReplayTower,
        allocator: std.mem.Allocator,
        vote_slot: Slot,
        vote_hash: Hash,
        enable_tower_sync_ix: bool,
        block_id: Hash,
    ) !?Slot {
        if (self.tower.vote_state.lastVotedSlot()) |last_voted_sot| {
            if (vote_slot <= last_voted_sot) {
                return error.VoteTooOld;
            }
        }

        const old_root = try self.tower.getRoot();

        try self.tower.vote_state.processNextVoteSlot(vote_slot);
        try self.updateLastVoteFromVoteState(allocator, vote_hash, enable_tower_sync_ix, block_id);

        const new_root = try self.tower.getRoot();

        if (old_root != new_root) {
            return new_root;
        } else {
            return null;
        }
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
                self.tower.vote_state.votes,
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

    ///  The tower root can be older/newer if the validator booted from a newer/older snapshot, so
    /// tower lockouts may need adjustment
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

    /// [Audit] The implementations below are found in consensus::fork_choice in Agave
    ///
    /// Returns whether the last vote is able to land, which determines if we should
    /// super refresh to vote at the tip.
    pub fn lastVoteAbleToLand(
        self: *const ReplayTower,
        reset_slot: ?Slot,
        progress: *const ProgressMap,
        slot_history: *const SlotHistory,
    ) bool {
        const heaviest_slot = reset_slot orelse {
            // No reset slot means we are in the middle of dump & repair. Last vote
            // landing is irrelevant.
            return true;
        };

        const last_voted_slot = self.lastVotedSlot() orelse {
            // No previous vote.
            return true;
        };

        const my_latest_landed_vote_slot = progress.myLatestLandedVote(
            heaviest_slot,
        ) orelse {
            // We've either never landed a vote or fork has been pruned or is in the
            // middle of dump & repair. Either way, no need to super refresh.
            return true;
        };

        // Check if our last vote is able to land in order to determine if we should
        // super refresh to vote at the tip. If any of the following are true, we
        // don't need to super refresh:
        return
        // 1. Last vote has landed
        (my_latest_landed_vote_slot >= last_voted_slot) or
            // 2. Already voting at the tip
            (last_voted_slot >= heaviest_slot) or
            // 3. Last vote is within slot hashes, regular refresh is enough
            slot_history.check(last_voted_slot) == .found;
    }

    /// Handles fork selection when switch threshold fails.
    ///
    /// Two cases:
    /// 1. If last vote can't land: vote at current fork tip (SameFork)
    /// 2. Otherwise: stay on current fork (don't vote) to prevent network halts
    ///
    /// Prevents mass fork abandonment that could stall the network.
    ///
    /// In essence this function re-evaluates whether to:
    ///
    /// Force a vote on the current fork (if stuck).
    /// Continue waiting (if switching is unsafe).
    /// Record failures for diagnostics.
    pub fn recheckForkDecisionFailedSwitchThreshold(
        self: *const ReplayTower,
        allocator: std.mem.Allocator,
        reset_slot: ?Slot,
        progress: *const ProgressMap,
        heaviest_bank_slot: Slot,
        failure_reasons: *std.ArrayListUnmanaged(HeaviestForkFailures),
        switch_proof_stake: u64,
        total_stake: u64,
        switch_fork_decision: SwitchForkDecision,
        slot_history: *const SlotHistory,
    ) !SwitchForkDecision {
        // Check if validator’s last vote is stuck (no block will include it).
        // if, so force a new vote on the current fork (SameFork) to unblock progress.
        if (!self.lastVoteAbleToLand(reset_slot, progress, slot_history)) {
            // If we reach here, these assumptions are true:
            // 1. We can't switch because of threshold
            // 2. Our last vote is now outside slot hashes history of the tip of fork
            // So, there was no hope of this last vote ever landing again.

            // In this case, we do want to obey threshold, yet try to register our vote on
            // the current fork, so we choose to vote at the tip of current fork instead.
            // This will not cause longer lockout because lockout doesn't double after 512
            // slots, it might be enough to get majority vote.
            return SwitchForkDecision.same_fork;
        }

        // If we can't switch, then reset to the next votable bank on the same
        // fork as our last vote, but don't vote.
        // We don't just reset to the heaviest fork when switch threshold fails because
        // a situation like this can occur:
        // Figure 1:
        //             slot 0
        //                 |
        //             slot 1
        //             /        \
        // slot 2 (last vote)     |
        //             |      slot 8 (10%)
        //     slot 4 (9%)
        // Imagine 90% of validators voted on slot 4, but only 9% landed. If everybody that fails
        // the switch threshold abandons slot 4 to build on slot 8 (because it's *currently* heavier),
        // then there will be no blocks to include the votes for slot 4, and the network halts
        // because 90% of validators can't vote
        self.logger.info().logf(
            \\ Waiting to switch vote to {d}, resetting to slot {?} for now,
            \\ switch proof stake: {d}, threshold stake: {d:.2}, total stake: {d}"
        ,
            .{
                heaviest_bank_slot,
                if (reset_slot) |slot| slot else null,
                switch_proof_stake,
                @as(f64, @floatFromInt(total_stake)) * SWITCH_FORK_THRESHOLD,
                total_stake,
            },
        );

        try failure_reasons.append(allocator, .{
            .FailedSwitchThreshold = .{
                .slot = heaviest_bank_slot,
                .observed_stake = switch_proof_stake,
                .total_stake = total_stake,
            },
        });

        // Return the original switch_fork_decision.
        return switch_fork_decision;
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
        slot_history: *const SlotHistory,
    ) !CandidateVoteAndResetSlots {
        // If our last vote is unable to land (even through normal refresh), then we
        // temporarily "super" refresh our vote to the tip of our last voted fork.
        const final_switch_fork_decision = try self.recheckForkDecisionFailedSwitchThreshold(
            allocator,
            if (heaviest_slot_on_same_voted_fork) |slot| slot else null,
            progress,
            heaviest_slot,
            failure_reasons,
            switch_proof_stake,
            total_stake,
            initial_switch_fork_decision,
            slot_history,
        );

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
        slot_history: *const SlotHistory,
    ) !CandidateVoteAndResetSlots {
        return switch (initial_switch_fork_decision) {
            .failed_switch_threshold => |data| try self.selectCandidatesFailedSwitch(
                allocator,
                heaviest_slot,
                heaviest_slot_on_same_voted_fork,
                progress,
                failure_reasons,
                data[0],
                data[1],
                initial_switch_fork_decision,
                slot_history,
            ),
            .failed_switch_duplicate_rollback => |latest_duplicate_ancestor| blk: {
                break :blk try selectCandidatesFailedSwitchDuplicateRollback(
                    allocator,
                    heaviest_slot,
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
        const propagated_stats = progress.getPropagatedStats(candidate_vote_bank_slot) orelse
            return error.PropagatedStatsNotFound;

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
            (try progress.getLeaderPropagationSlotMustExist(candidate_vote_bank_slot))[0];
        if (!propagation_confirmed) {
            try failure_reasons.append(allocator, .{ .NoPropagatedConfirmation = .{
                .slot = candidate_vote_bank_slot,
                .observed_stake = propagated_stake,
                .total_stake = total_epoch_stake,
            } });
        }

        // Final decision
        const can_vote = !is_locked_out and
            threshold_passed and
            propagation_confirmed and
            switch_fork_decision.canVote();

        if (can_vote) {
            self.logger.info().logf(
                "voting: {d} {d:.1}%",
                .{ candidate_vote_bank_slot, 100.0 * fork_weight },
            );
        }

        return can_vote;
    }

    /// Selects banks for voting and reset based on fork selection rules.
    /// Returns a result containing:
    /// - Optional bank to vote on (with decision)
    /// - Optional bank to reset PoH to
    /// - List of any fork selection failures
    pub fn selectVoteAndResetForks(
        self: *ReplayTower,
        allocator: std.mem.Allocator,
        heaviest_slot: Slot,
        heaviest_slot_on_same_voted_fork: ?Slot,
        heaviest_epoch: Epoch,
        ancestors: *const AutoHashMapUnmanaged(u64, SortedSet(u64)),
        descendants: *const AutoArrayHashMapUnmanaged(u64, SortedSet(u64)),
        progress: *const ProgressMap,
        latest_validator_votes_for_frozen_banks: *const LatestValidatorVotesForFrozenBanks,
        fork_choice: *const HeaviestSubtreeForkChoice,
        epoch_stakes: EpochStakeMap,
        slot_history: *const SlotHistory,
    ) !SelectVoteAndResetForkResult {
        // Initialize result with failure list
        var failure_reasons = try std.ArrayListUnmanaged(HeaviestForkFailures).initCapacity(
            allocator,
            0,
        );
        defer failure_reasons.deinit(allocator);

        const epoch_stake = epoch_stakes.get(heaviest_epoch) orelse return error.StakeNotFound;
        // Check switch threshold conditions
        const initial_decision = try self.checkSwitchThreshold(
            allocator,
            heaviest_slot,
            ancestors,
            descendants,
            progress,
            epoch_stake.total_stake,
            &epoch_stake.stakes.vote_accounts.accounts,
            latest_validator_votes_for_frozen_banks,
            fork_choice,
        );

        // Select candidate slots
        const slots = try self.selectCandidateVoteAndResetBanks(
            allocator,
            heaviest_slot,
            heaviest_slot_on_same_voted_fork,
            progress,
            &failure_reasons,
            initial_decision,
            slot_history,
        );

        // Handle no viable candidate case
        const candidate_vote_slot = slots.candidate_vote_slot orelse {
            return SelectVoteAndResetForkResult{
                .vote_slot = null,
                .reset_slot = slots.reset_slot.?,
                .heaviest_fork_failures = failure_reasons,
            };
        };

        if (try self.canVoteOnCandidateSlot(
            allocator,
            candidate_vote_slot,
            progress,
            &failure_reasons,
            &slots.switch_fork_decision,
        )) {
            return SelectVoteAndResetForkResult{
                .vote_slot = .{
                    .slot = candidate_vote_slot,
                    .decision = slots.switch_fork_decision,
                },
                .reset_slot = candidate_vote_slot,
                .heaviest_fork_failures = failure_reasons,
            };
        } else {
            return SelectVoteAndResetForkResult{
                .vote_slot = null,
                .reset_slot = if (slots.reset_slot) |slot| slot else null,
                .heaviest_fork_failures = failure_reasons,
            };
        }
    }

    test "tower: selectVoteAndResetForks stake not found" {
        const allocator = std.testing.allocator;
        const FrozenVotes = sig.consensus.unimplemented.FrozenVotes;
        const fork_tuples = sig.consensus.fork_choice.fork_tuples;

        var fork_choice = try sig.consensus.fork_choice.forkChoiceForTest(
            allocator,
            fork_tuples[0..],
        );
        defer fork_choice.deinit();

        var tower = try createTestReplayTower(allocator, 8, 0.66);
        defer tower.deinit(allocator);

        const latest = LatestValidatorVotesForFrozenBanks{
            .max_gossip_frozen_votes = std.AutoHashMap(Pubkey, FrozenVotes).init(allocator),
        };

        var slot_history = try createTestSlotHistory(std.testing.allocator);
        defer slot_history.deinit(allocator);

        try std.testing.expectError(
            error.StakeNotFound,
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
                .{},
                &slot_history,
            ),
        );
    }
};

pub const Tower = struct {
    logger: ScopedLogger(@typeName(Self)),
    vote_state: TowerVoteState,

    const Self = @This();

    pub fn default() Tower {
        var tower = Tower{
            .logger = .noop,
            .vote_state = .{},
        };
        // VoteState::root_slot is ensured to be Some in Tower
        tower.vote_state.root_slot = 0;
        return tower;
    }

    pub fn towerSlots(self: *const Tower, allocator: std.mem.Allocator) ![]Slot {
        var slots = try allocator.alloc(Slot, self.vote_state.votes.len);
        for (self.vote_state.votes.constSlice(), 0..) |vote, i| {
            slots[i] = vote.slot;
        }
        return slots;
    }

    // root may be forcibly set by arbitrary replay root slot, for example from a root
    // after replaying a snapshot.
    // Also, tower.getRoot() couldn't be null; initializeLockouts() ensures that.
    // Conceptually, every tower must have been constructed from a concrete starting point,
    // which establishes the origin of trust (i.e. root) whether booting from genesis (slot 0) or
    // snapshot (slot N). In other words, there should be no possibility a Tower doesn't have
    // root, unlike young vote accounts.
    pub fn getRoot(self: *const Tower) !Slot {
        if (self.vote_state.root_slot == null) return error.RootSlotMissing;
        return self.vote_state.root_slot.?;
    }

    // a slot is recent if it's newer than the last vote we have. If we haven't voted yet
    // but have a root (hard forks situation) then compare it to the root
    pub fn isRecent(self: *const Tower, slot: Slot) bool {
        if (self.vote_state.lastVotedSlot()) |last_voted_slot| {
            if (slot <= last_voted_slot) {
                return false;
            } else if (self.vote_state.root_slot) |root_slot| {
                if (slot <= root_slot) {
                    return false;
                }
            }
        }
        return true;
    }

    pub fn hasVoted(self: *const Tower, slot: Slot) bool {
        for (self.vote_state.votes.constSlice()) |vote| {
            if (slot == vote.slot) {
                return true;
            }
        }
        return false;
    }

    /// Use to check if a vote can be casted for this slot without violating previous lockouts
    pub fn isLockedOut(
        self: *const Tower,
        slot: Slot,
        ancestors: *const SortedSet(Slot),
    ) !bool {
        if (!self.isRecent(slot)) {
            return true;
        }

        // Check if a slot is locked out by simulating adding a vote for that
        // slot to the current lockouts to pop any expired votes. If any of the
        // remaining voted slots are on a different fork from the checked slot,
        // it's still locked out.
        var vote_state = self.vote_state;

        try vote_state.processNextVoteSlot(slot);

        for (vote_state.votes.constSlice()) |vote| {
            if (slot != vote.slot and
                // This means the validator is trying to vote on a fork incompatible with previous votes.
                !ancestors.contains(vote.slot))
            {
                return true;
            }
        }

        if (vote_state.root_slot) |root_slot| {
            if (slot != root_slot
            // This case should never happen because bank forks purges all
            // non-descendants of the root every time root is set
            and !ancestors.contains(root_slot)) {
                return error.InvalidRootSlot;
            }
        }

        // Not locked out, vote safe to be casted.
        return false;
    }

    fn votedSlots(self: *const Tower, allocator: std.mem.Allocator) ![]Slot {
        var slots = try allocator.alloc(Slot, self.vote_state.votes.len);
        for (self.vote_state.votes.slice(), 0..) |lockout, i| {
            slots[i] = lockout.slot;
        }
        return slots;
    }

    fn adjustLockoutsWithSlotHistory(
        self: *Tower,
        allocator: std.mem.Allocator,
        slot_history: *const SlotHistory,
    ) !void {
        const tower_root = try self.getRoot();

        var still_in_future = true;
        var past_outside_history = false;
        var maybe_checked_slot: ?Slot = null;
        var maybe_anchored_slot: ?Slot = null;

        const voted = try self.votedSlots(allocator);
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

        try self.initializeLockouts(flags);

        if (self.vote_state.votes.len == 0) {
            // we might not have banks for those votes so just reset.
            // That's because the votes may well past replayed_root
            self.last_vote.deinit(allocator);
            self.last_vote = VoteTransaction{ .vote = Vote.ZEROES };
        } else {
            const voted_slots = try self.votedSlots(allocator);
            defer allocator.free(voted_slots);
            std.debug.assert(self.lastVotedSlot().? == voted_slots[voted_slots.len - 1]);
            self.stray_restored_slot = self.last_vote.lastVotedSlot();
        }

        return;
    }

    fn initializeLockoutsFromBank(
        self: *Tower,
        allocator: std.mem.Allocator,
        vote_account_pubkey: *const Pubkey,
        fork_root: Slot,
        accounts_db: *AccountsDB,
    ) !void {
        const vote_account = accounts_db.getAccount(vote_account_pubkey) catch {
            self.initializeRoot(fork_root);
            return;
        };

        const vote_state = try stateFromAccount(
            allocator,
            &vote_account,
            vote_account_pubkey,
        );

        var lockouts = try std.ArrayListUnmanaged(Lockout).initCapacity(
            allocator,
            vote_state.votes.items.len,
        );
        for (vote_state.votes.items) |landed| {
            try lockouts.append(
                allocator,
                Lockout{
                    .slot = landed.lockout.slot,
                    .confirmation_count = landed.lockout.confirmation_count,
                },
            );
        }
        self.vote_state = TowerVoteState{
            .votes = try std.BoundedArray(Lockout, MAX_LOCKOUT_HISTORY)
                .fromSlice(try lockouts.toOwnedSlice(allocator)),
            .root_slot = vote_state.root_slot,
        };
        self.initializeRoot(fork_root);

        var flags = try std.DynamicBitSetUnmanaged.initEmpty(
            allocator,
            self.vote_state.votes.len,
        );
        defer flags.deinit(allocator);

        for (self.vote_state.votes.constSlice(), 0..) |vote, i| {
            flags.setValue(i, vote.slot > fork_root);
        }

        try self.initializeLockouts(flags);
    }

    fn initializeLockouts(
        self: *Tower,
        should_retain: std.DynamicBitSetUnmanaged,
    ) !void {
        std.debug.assert(should_retain.capacity() >= self.vote_state.votes.len);
        var retained = try std.BoundedArray(Lockout, MAX_LOCKOUT_HISTORY).init(0);
        for (self.vote_state.votes.constSlice(), 0..) |item, i| {
            if (should_retain.isSet(i)) {
                _ = try retained.append(item);
            }
        }
        self.vote_state.votes = retained;
    }

    // Updating root is needed to correctly restore from newly-saved tower for the next
    // boot
    fn initializeRoot(self: *Tower, root_slot: Slot) void {
        self.vote_state.root_slot = root_slot;
    }

    pub fn restore(
        tower_storage: *const TowerStorage,
        node_pubkey: *const Pubkey,
    ) !Tower {
        return try tower_storage.load(node_pubkey);
    }
};

pub fn lastVotedSlotInBank(
    allocator: std.mem.Allocator,
    accounts_db: *AccountsDB,
    vote_account_pubkey: *const Pubkey,
) ?Slot {
    const vote_account = accounts_db.getAccount(vote_account_pubkey) catch return null;
    const vote_state = stateFromAccount(
        allocator,
        &vote_account,
        vote_account_pubkey,
    ) catch return null;
    return vote_state.lastVotedSlot();
}

fn stateFromAccount(
    allocator: std.mem.Allocator,
    vote_account: *const Account,
    vote_account_pubkey: *const Pubkey,
) !VoteState {
    const buf = try allocator.alloc(u8, vote_account.data.len());
    // TODO Not sure if this is the way to get the data from the vote account. Review.
    _ = vote_account.writeToBuf(vote_account_pubkey, buf);
    const versioned_state = try sig.bincode.readFromSlice(
        allocator,
        VoteStateVersions,
        buf,
        .{},
    );
    return try versioned_state.convertToCurrent(allocator);
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
    var ancestors_a = ancestors.get(slot_a) orelse return null;
    var ancestors_b = ancestors.get(slot_b) orelse return null;

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

// Optimistically skip the stake check if casting a vote would not increase
// the lockout at this threshold. This is because if you bounce back to
// voting on the main fork after not voting for a while, your latest vote
// might pop off a lot of the votes in the tower. The stake from these votes
// would have rolled up to earlier votes in the tower, which presumably
// could have helped us pass the threshold check. Worst case, we'll just
// recheck later without having increased lockouts.
fn optimisticallyBypassVoteStakeThresholdCheck(
    // Needs to be an iterator that produces Lockout
    tower_before_applying_vote: anytype,
    threshold_vote: Lockout,
) bool {
    for (tower_before_applying_vote.constSlice()) |old_vote| {
        if (old_vote.slot == threshold_vote.slot and
            old_vote.confirmation_count == threshold_vote.confirmation_count)
        {
            return true;
        }
    }
    return false;
}

fn checkVoteStakeThreshold(
    logger: sig.trace.Logger,
    maybe_threshold_vote: ?Lockout,
    tower_before_applying_vote: anytype,
    threshold_depth: usize,
    threshold_size: f64,
    slot: Slot,
    voted_stakes: *const AutoHashMapUnmanaged(Slot, u64),
    total_stake: u64,
) ThresholdDecision {
    const threshold_vote = maybe_threshold_vote orelse {
        // Tower isn't that deep.
        return ThresholdDecision{ .passed_threshold = {} };
    };

    const fork_stake = voted_stakes.get(threshold_vote.slot) orelse {
        // We haven't seen any votes on this fork yet, so no stake
        return ThresholdDecision{
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
        return ThresholdDecision{ .passed_threshold = {} };
    }

    return ThresholdDecision{
        .failed_threshold = .{ threshold_depth, 0 },
    };
}

pub fn populateAncestorVotedStakes(
    voted_stakes: *SortedSet(Slot),
    vote_slots: []const Slot,
    ancestors: *const AutoHashMapUnmanaged(Slot, SortedSet(Slot)),
) !void {
    // If there's no ancestors, that means this slot must be from before the current root,
    // in which case the lockouts won't be calculated in bank_weight anyways, so ignore
    // this slot
    for (vote_slots) |vote_slot| {
        if (ancestors.get(vote_slot)) |maybe_slot_ancestors| {
            var slot_ancestors = maybe_slot_ancestors;
            try voted_stakes.put(vote_slot);
            for (slot_ancestors.items()) |slot| {
                _ = try voted_stakes.put(slot);
            }
        }
    }
}

fn updateAncestorVotedStakes(
    voted_stakes: *VotedStakes,
    voted_slot: Slot,
    voted_stake: u64,
    ancestors: *const AutoHashMapUnmanaged(Slot, SortedSet(Slot)),
) void {
    // If there's no ancestors, that means this slot must be from
    // before the current root, so ignore this slot
    if (ancestors.getPtr(voted_slot)) |vote_slot_ancestors| {
        var entry_vote_stake = try voted_stakes.getOrPutValue(voted_slot, 0);
        entry_vote_stake.value_ptr += voted_stake;
        var iter = vote_slot_ancestors.*.iterator();
        for (iter.next()) |ancestor_slot| {
            var entry_voted_stake = try voted_stakes.getOrPutValue(ancestor_slot, 0);
            entry_voted_stake.value_ptr += voted_stake;
        }
    }
}

pub fn isSlotDuplicateConfirmed(
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

/// Handles fork selection when switch fails due to duplicate rollback
pub fn selectCandidatesFailedSwitchDuplicateRollback(
    allocator: std.mem.Allocator,
    heaviest_slot: Slot,
    // [Audit] Only used in logging in Agave
    _: Slot,
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

test "tower: selectVoteAndResetForks stake not found" {
    const allocator = std.testing.allocator;
    const FrozenVotes = sig.consensus.unimplemented.FrozenVotes;
    const fork_tuples = sig.consensus.fork_choice.fork_tuples;

    var fork_choice = try sig.consensus.fork_choice.forkChoiceForTest(
        allocator,
        fork_tuples[0..],
    );
    defer fork_choice.deinit();

    var tower = try createTestReplayTower(allocator, 8, 0.66);
    defer tower.deinit(allocator);

    const latest = LatestValidatorVotesForFrozenBanks{
        .max_gossip_frozen_votes = std.AutoHashMap(Pubkey, FrozenVotes).init(allocator),
    };

    var slot_history = try createTestSlotHistory(std.testing.allocator);
    defer slot_history.deinit(allocator);

    try std.testing.expectError(
        error.StakeNotFound,
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
            .{},
            &slot_history,
        ),
    );
}

test "tower: check vote threshold without votes" {
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

test "tower: check vote threshold no skip lockout with new root" {
    var tower = try createTestReplayTower(std.testing.allocator, 4, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, MAX_LOCKOUT_HISTORY);

    for (0..(MAX_LOCKOUT_HISTORY + 1)) |i| {
        stakes.putAssumeCapacity(i, 1);
        _ = try tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
            Hash.ZEROES,
        );
    }

    const result = try tower.checkVoteStakeThresholds(
        std.testing.allocator,
        MAX_LOCKOUT_HISTORY + 1,
        &stakes,
        2,
    );
    std.testing.allocator.free(result);
    try std.testing.expect(result.len != 0);
}

test "tower: is slot confirmed not enough stake failure" {
    var tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 1);

    const result = isSlotConfirmed(&tower, 0, &stakes, 2);
    try std.testing.expect(!result);
}

test "tower: is slot confirmed unknown slot" {
    var tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);

    const result = isSlotConfirmed(&tower, 0, &stakes, 2);
    try std.testing.expect(!result);
}

test "tower: is slot confirmed pass" {
    var tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 2);

    const result = isSlotConfirmed(&tower, 0, &stakes, 2);
    try std.testing.expect(result);
}

test "tower: is slot duplicate confirmed not enough stake failure" {
    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 52);

    const result = isSlotDuplicateConfirmed(
        0,
        &stakes,
        100,
    );
    try std.testing.expect(!result);
}

test "tower: is slot duplicate confirmed unknown slot" {
    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);

    const result = isSlotDuplicateConfirmed(
        0,
        &stakes,
        100,
    );
    try std.testing.expect(!result);
}

test "tower: is slot duplicate confirmed pass" {
    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 53);

    const result = isSlotDuplicateConfirmed(
        0,
        &stakes,
        100,
    );
    try std.testing.expect(result);
}

test "tower: is locked out empty" {
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

test "tower: is locked out root slot child pass" {
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

test "tower: is locked out root slot sibling fail" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    replay_tower.tower.vote_state.root_slot = 0;

    _ = try replay_tower.recordBankVoteAndUpdateLockouts(
        std.testing.allocator,
        1,
        Hash.ZEROES,
        true,
        Hash.ZEROES,
    );

    const result = try replay_tower.tower.isLockedOut(
        2,
        &ancestors,
    );

    try std.testing.expect(result);
}

test "tower: check already voted" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.tower.vote_state.root_slot = 0;

    _ = try replay_tower.recordBankVoteAndUpdateLockouts(
        std.testing.allocator,
        0,
        Hash.ZEROES,
        true,
        Hash.ZEROES,
    );

    try std.testing.expect(replay_tower.tower.hasVoted(0));
    try std.testing.expect(!replay_tower.tower.hasVoted(1));
}

test "tower: check recent slot" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    try std.testing.expect(replay_tower.tower.isRecent(1));
    try std.testing.expect(replay_tower.tower.isRecent(32));

    for (0..64) |i| {
        _ = try replay_tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
            Hash.ZEROES,
        );
    }

    try std.testing.expect(!replay_tower.tower.isRecent(0));
    try std.testing.expect(!replay_tower.tower.isRecent(32));
    try std.testing.expect(!replay_tower.tower.isRecent(63));
    try std.testing.expect(replay_tower.tower.isRecent(65));
}

test "tower: is locked out double vote" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    for (0..2) |i| {
        _ = try replay_tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
            Hash.ZEROES,
        );
    }

    const result = try replay_tower.tower.isLockedOut(
        0,
        &ancestors,
    );

    try std.testing.expect(result);
}

test "tower: is locked out child" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    _ = try replay_tower.recordBankVoteAndUpdateLockouts(
        std.testing.allocator,
        0,
        Hash.ZEROES,
        true,
        Hash.ZEROES,
    );

    const result = try replay_tower.tower.isLockedOut(
        1,
        &ancestors,
    );

    try std.testing.expect(!result);
}

test "tower: is locked out sibling" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    for (0..2) |i| {
        _ = try replay_tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
            Hash.ZEROES,
        );
    }

    const result = try replay_tower.tower.isLockedOut(
        2,
        &ancestors,
    );

    try std.testing.expect(result);
}

test "tower: is locked out last vote expired" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    for (0..2) |i| {
        _ = try replay_tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
            Hash.ZEROES,
        );
    }

    const result = try replay_tower.tower.isLockedOut(
        4,
        &ancestors,
    );

    try std.testing.expect(!result);

    _ = try replay_tower.recordBankVoteAndUpdateLockouts(
        std.testing.allocator,
        4,
        Hash.ZEROES,
        true,
        Hash.ZEROES,
    );

    try std.testing.expectEqual(0, replay_tower.tower.vote_state.votes.get(0).slot);
    try std.testing.expectEqual(2, replay_tower.tower.vote_state.votes.get(0).confirmation_count);
    try std.testing.expectEqual(4, replay_tower.tower.vote_state.votes.get(1).slot);
    try std.testing.expectEqual(1, replay_tower.tower.vote_state.votes.get(1).confirmation_count);
}

test "tower: check vote threshold below threshold" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 1);

    _ = try replay_tower.recordBankVoteAndUpdateLockouts(
        std.testing.allocator,
        0,
        Hash.ZEROES,
        true,
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

test "tower: check vote threshold above threshold" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 2);

    _ = try replay_tower.recordBankVoteAndUpdateLockouts(
        std.testing.allocator,
        0,
        Hash.ZEROES,
        true,
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

test "tower: check vote thresholds above thresholds" {
    var tower = try createTestReplayTower(std.testing.allocator, VOTE_THRESHOLD_DEPTH, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 3);

    stakes.putAssumeCapacity(0, 3);
    stakes.putAssumeCapacity(VOTE_THRESHOLD_DEPTH_SHALLOW, 2);
    stakes.putAssumeCapacity(VOTE_THRESHOLD_DEPTH_SHALLOW - 1, 2);

    for (0..VOTE_THRESHOLD_DEPTH) |i| {
        _ = try tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
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

test "tower: check vote threshold deep below threshold" {
    var tower = try createTestReplayTower(std.testing.allocator, VOTE_THRESHOLD_DEPTH, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 2);

    stakes.putAssumeCapacity(0, 6);
    stakes.putAssumeCapacity(VOTE_THRESHOLD_DEPTH_SHALLOW, 4);

    for (0..VOTE_THRESHOLD_DEPTH) |i| {
        _ = try tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
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

test "tower: check vote threshold shallow below threshold" {
    var tower = try createTestReplayTower(std.testing.allocator, VOTE_THRESHOLD_DEPTH, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 2);

    stakes.putAssumeCapacity(0, 7);
    stakes.putAssumeCapacity(VOTE_THRESHOLD_DEPTH_SHALLOW, 1);

    for (0..VOTE_THRESHOLD_DEPTH) |i| {
        _ = try tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
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

test "tower: check vote threshold above threshold after pop" {
    var tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 1);

    stakes.putAssumeCapacity(0, 2);

    for (0..3) |i| {
        _ = try tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
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

test "tower: check vote threshold above threshold no stake" {
    var tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);

    _ = try tower.recordBankVoteAndUpdateLockouts(
        std.testing.allocator,
        0,
        Hash.ZEROES,
        true,
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

test "tower: check vote threshold lockouts not updated" {
    var tower = try createTestReplayTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = AutoHashMapUnmanaged(u64, u64){};
    defer stakes.deinit(std.testing.allocator);
    try stakes.ensureTotalCapacity(std.testing.allocator, 2);

    stakes.putAssumeCapacity(0, 1);
    stakes.putAssumeCapacity(1, 2);

    for (0..3) |i| {
        _ = try tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
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

test "tower: recent votes full" {
    try voteAndCheckRecent(MAX_LOCKOUT_HISTORY);
}

test "tower: recent votes empty" {
    try voteAndCheckRecent(0);
}

test "tower: recent votes exact" {
    try voteAndCheckRecent(5);
}

test "tower: maybe timestamp" {
    var replay_tower = try ReplayTower.default(std.testing.allocator);
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

test "tower: refresh last vote timestamp" {
    var replay_tower = try ReplayTower.default(std.testing.allocator);

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

test "tower: adjust lockouts after replay future slots" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    for (0..4) |i| {
        _ = try replay_tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
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

test "tower: adjust lockouts after replay not found slots" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    for (0..4) |i| {
        _ = try replay_tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
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

test "tower: adjust lockouts after replay all rooted with no too old" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    for (0..3) |i| {
        _ = try replay_tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
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

test "tower: adjust lockouts after replay all rooted with too old" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    for (0..3) |i| {
        _ = try replay_tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
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

test "tower: adjust lockouts after replay anchored future slots" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    for (0..5) |i| {
        _ = try replay_tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
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

test "tower: adjust lockouts after replay all not found" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    for (5..7) |i| {
        _ = try replay_tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
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

test "tower: adjust lockouts after replay all not found even if rooted" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.tower.vote_state.root_slot = 4;

    for (5..7) |i| {
        _ = try replay_tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
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

test "tower: test adjust lockouts after replay all future votes only root found" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.tower.vote_state.root_slot = 2;

    for (3..6) |i| {
        _ = try replay_tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
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

test "tower: adjust lockouts after replay empty" {
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

test "tower: adjust lockouts after replay too old tower" {
    var replay_tower = try createTestReplayTower(std.testing.allocator, 10, 0.9);
    defer replay_tower.deinit(std.testing.allocator);

    _ = try replay_tower.recordBankVoteAndUpdateLockouts(
        std.testing.allocator,
        0,
        Hash.ZEROES,
        true,
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

test "tower: adjust lockouts after replay time warped" {
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

test "tower: adjust lockouts after replay diverged ancestor" {
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

test "tower: adjust lockouts after replay out of order" {
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

test "tower: adjust lockouts after replay out of order via clearing history" {
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

test "tower: adjust lockouts after replay reversed votes" {
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

test "tower: adjust lockouts after replay repeated non root votes" {
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

test "tower: adjust lockouts after replay vote on root" {
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

test "tower: adjust lockouts after replay vote on genesis" {
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

test "tower: adjust lockouts after replay future tower" {
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

test "tower: default tower has no stray last vote" {
    var replay_tower = try createTestReplayTower(
        std.testing.allocator,
        VOTE_THRESHOLD_DEPTH,
        VOTE_THRESHOLD_SIZE,
    );
    defer replay_tower.deinit(std.testing.allocator);

    try std.testing.expect(!replay_tower.isStrayLastVote());
}

const builtin = @import("builtin");
const DynamicArrayBitSet = sig.bloom.bit_set.DynamicArrayBitSet;
fn createTestReplayTower(
    allocator: std.mem.Allocator,
    threshold_depth: usize,
    threshold_size: f64,
) !ReplayTower {
    if (!builtin.is_test) {
        @compileError("createTestTower should only be used in test");
    }
    var replay_tower = try ReplayTower.default(allocator);
    replay_tower.threshold_depth = threshold_depth;
    replay_tower.threshold_size = threshold_size;
    return replay_tower;
}

fn createTestSlotHistory(
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

fn isSlotConfirmed(
    replay_tower: *const ReplayTower,
    slot: Slot,
    voted_stakes: *const VotedStakes,
    total_stake: Stake,
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
        _ = try tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
            Hash.ZEROES,
        );
    }

    expected.timestamp = tower.last_vote.timestamp();

    try std.testing.expectEqualDeep(
        expected.lockouts.items,
        tower.last_vote.tower_sync.lockouts.items,
    );
}
