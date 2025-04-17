const std = @import("std");
const sig = @import("../sig.zig");

const AutoHashMap = std.AutoHashMap;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const Account = sig.core.Account;
const Bank = sig.accounts_db.Bank;
const BankForks = sig.consensus.unimplemented.BankForks;
const BlockTimestamp = sig.runtime.program.vote_program.state.BlockTimestamp;
const Hash = sig.core.Hash;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const LatestValidatorVotesForFrozenBanks =
    sig.consensus.unimplemented.LatestValidatorVotesForFrozenBanks;
const Lockout = sig.runtime.program.vote_program.state.Lockout;
const LockoutIntervals = sig.consensus.unimplemented.LockoutIntervals;
const ProgressMap = sig.consensus.unimplemented.ProgressMap;
const Pubkey = sig.core.Pubkey;
const ReplayStage = sig.consensus.unimplemented.ReplayStage;
const SavedTower = sig.consensus.tower_storage.SavedTower;
const SavedTowerVersion = sig.consensus.tower_storage.SavedTowerVersions;
const Slot = sig.core.Slot;
const SlotAndHash = sig.core.hash.SlotAndHash;
const SlotHistory = sig.runtime.sysvar.SlotHistory;
const SortedSet = sig.utils.collections.SortedSet;
const TowerStorage = sig.consensus.tower_storage.TowerStorage;
const TowerSync = sig.runtime.program.vote_program.state.TowerSync;
const TowerVoteState = sig.consensus.tower_state.TowerVoteState;
const Vote = sig.runtime.program.vote_program.state.Vote;
const VoteAccountsHashMap = sig.consensus.unimplemented.VoteAccountsHashMap;
const VoteState = sig.runtime.program.vote_program.state.VoteState;
const VoteStateUpdate = sig.runtime.program.vote_program.state.VoteStateUpdate;
const VoteStateVersions = sig.runtime.program.vote_program.state.VoteStateVersions;
const VoteTransaction = sig.consensus.vote_transaction.VoteTransaction;
const VotedSlotAndPubkey = sig.consensus.unimplemented.VotedSlotAndPubkey;
const Logger = sig.trace.Logger;
const ScopedLogger = sig.trace.ScopedLogger;

const UnixTimestamp = i64;

const MAX_LOCKOUT_HISTORY = sig.runtime.program.vote_program.state.MAX_LOCKOUT_HISTORY;
const VOTE_THRESHOLD_DEPTH_SHALLOW: usize = 4;
const VOTE_THRESHOLD_DEPTH: usize = 8;
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
};

pub const Stake = u64;

pub const VotedSlot = Slot;
pub const VotedStakes = AutoHashMap(Slot, Stake);

const ComputedBankState = struct {
    voted_stakes: VotedStakes,
    total_stake: Stake,
    fork_stake: Stake,
    // Tree of intervals of lockouts of the form [slot, slot + slot.lockout],
    // keyed by end of the range
    lockout_intervals: LockoutIntervals,
    my_latest_landed_vote: ?Slot,
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

    pub const DEFAULT = BlockhashStatus{ .uninitialized = {} };
};

// pub const TowerError = union(enum) {
//     // TODO add io err
//     io_error,
//     // TODO add bincode
//     serialize_error,
//     invalid_signature,
//     wrong_tower: []const u8,
//     too_old_tower: struct { Slot, Slot },
//     fatally_inconsistent: []const u8,
//     hard_fork: Slot,
// };

pub const TowerError = error{
    IoError,
    SerializeError,
    InvalidSignature,
    WrongTower,
    TooOldTower,
    FatallyInconsistent,
    HardFork,
};

pub const Tower = struct {
    logger: ScopedLogger(@typeName(Self)),
    node_pubkey: Pubkey,
    threshold_depth: usize,
    threshold_size: f64,
    vote_state: TowerVoteState,
    last_vote: VoteTransaction,
    // The blockhash used in the last vote transaction, may or may not equal the
    // blockhash of the voted block itself, depending if the vote slot was refreshed.
    // For instance, a vote for slot 5, may be refreshed/resubmitted for inclusion in
    //  block 10, in  which case `last_vote_tx_blockhash` equals the blockhash of 10, not 5.
    // For non voting validators this is NonVoting
    last_vote_tx_blockhash: BlockhashStatus,
    last_timestamp: BlockTimestamp,
    // Restored last voted slot which cannot be found in SlotHistory at replayed root
    // (This is a special field for slashing-free validator restart with edge cases).
    // This could be emptied after some time; but left intact indefinitely for easier
    // implementation
    // Further, stray slot can be stale or not. `Stale` here means whether given
    // bank_forks (=~ ledger) lacks the slot or not.
    stray_restored_slot: ?Slot,
    last_switch_threshold_check: ?struct { Slot, SwitchForkDecision },

    const Self = @This();

    pub fn default(allocator: std.mem.Allocator) !Tower {
        var tower = Tower{
            .logger = .noop,
            .node_pubkey = Pubkey.ZEROES,
            .threshold_depth = 0,
            .threshold_size = 0,
            .vote_state = try TowerVoteState.default(allocator),
            .last_vote = try VoteTransaction.default(allocator),
            .last_vote_tx_blockhash = BlockhashStatus.DEFAULT,
            .last_timestamp = BlockTimestamp.DEFAULT,
            .stray_restored_slot = null,
            .last_switch_threshold_check = null,
        };
        // VoteState::root_slot is ensured to be Some in Tower
        tower.vote_state.root_slot = 0;
        return tower;
    }

    pub fn init(
        allocator: std.mem.Allocator,
        logger: Logger,
        node_pubkey: *const Pubkey,
        vote_account_pubkey: *const Pubkey,
        fork_root: Slot,
        bank: *const Bank,
    ) !Tower {
        var tower = try Tower.default(allocator);
        tower.logger = logger.withScope(@typeName(Self));
        tower.node_pubkey = node_pubkey.*;
        try tower.initializeLockoutsFromBank(
            allocator,
            vote_account_pubkey,
            fork_root,
            bank,
        );
        return tower;
    }

    pub fn deinit(self: *Tower, allocator: std.mem.Allocator) void {
        self.last_vote.deinit(allocator);
        self.vote_state.deinit(allocator);
        // self.last_vote.deinit(allocator);
    }

    pub fn newFromBankforks(
        allocator: std.mem.Allocator,
        logger: Logger,
        bank_forks: *const BankForks,
        node_pubkey: *const Pubkey,
        vote_account: *const Pubkey,
    ) !Tower {
        const root_bank = bank_forks.rootBank();
        _, const heaviest_subtree_fork_choice = ReplayStage.initializeProgressAndForkChoice(
            &root_bank,
            &bank_forks.frozenBanks().inner.values(),
            node_pubkey,
            vote_account,
            std.ArrayList(SlotAndHash).init(allocator),
        );

        const fork_root = root_bank.bank_fields.slot;
        const heaviest = heaviest_subtree_fork_choice.heaviestOverallSlot();
        const heaviest_bank = bank_forks.getWithCheckedHash(heaviest) orelse {
            logger.withScope(@typeName(Tower))
                .err()
                .log(
                \\The best overall slot must be one of `frozen_banks`
                \\which all exist in bank_forks
            );
            return error.InvalidBank;
        };

        return Tower.init(
            allocator,
            logger,
            node_pubkey,
            vote_account,
            fork_root,
            &heaviest_bank,
        );
    }

    pub fn towerSlots(self: *const Tower, allocator: std.mem.Allocator) ![]Slot {
        var slots = std.ArrayListUnmanaged(Slot){};
        try slots.ensureTotalCapacity(
            allocator,
            self.vote_state.votes.items.len,
        );
        for (self.vote_state.votes.items) |vote| {
            slots.appendAssumeCapacity(vote.slot);
        }
        return slots.toOwnedSlice(allocator);
    }

    pub fn refreshLastVoteTimestamp(
        self: *Tower,
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
        self: *Tower,
        new_vote_tx_blockhash: Hash,
    ) void {
        self.last_vote_tx_blockhash = BlockhashStatus{ .blockhash = new_vote_tx_blockhash };
    }

    pub fn markLastVoteTxBlockhashNonVoting(self: *Tower) void {
        self.last_vote_tx_blockhash = BlockhashStatus{ .non_voting = {} };
    }

    pub fn markLastVoteTxBlockhashHotSpare(self: *Tower) void {
        self.last_vote_tx_blockhash = BlockhashStatus{ .hot_spare = {} };
    }

    pub fn recordBankVote(
        self: *Tower,
        allocator: std.mem.Allocator,
        bank: *const Bank,
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
            bank.bank_fields.slot,
            bank.bank_fields.hash,
            is_enable_tower_active,
            block_id,
        );
    }

    pub fn updateLastVoteFromVoteState(
        self: *Tower,
        allocator: std.mem.Allocator,
        vote_hash: Hash,
        enable_tower_sync_ix: bool,
        block_id: Hash,
    ) !void {
        var new_vote = if (enable_tower_sync_ix)
            VoteTransaction{ .tower_sync = TowerSync{
                .lockouts = try self.vote_state.votes.clone(allocator),
                .root = self.vote_state.root_slot,
                .hash = vote_hash,
                .timestamp = null,
                .block_id = block_id,
            } }
        else
            VoteTransaction{ .vote_state_update = VoteStateUpdate{
                .lockouts = try self.vote_state.votes.clone(allocator),
                .root = self.vote_state.root_slot,
                .hash = vote_hash,
                .timestamp = null,
            } };

        const last_voted_slot = if (self.lastVotedSlot()) |last_voted_slot|
            last_voted_slot
        else
            0;

        new_vote.setTimestamp(self.maybeTimestamp(last_voted_slot));

        // Free previous lockouts if they exist
        switch (self.last_vote) {
            .tower_sync => |*args| args.lockouts.deinit(allocator),
            .vote_state_update => |*args| args.lockouts.deinit(allocator),
            else => {},
        }

        self.last_vote = new_vote;
    }

    fn recordBankVoteAndUpdateLockouts(
        self: *Tower,
        allocator: std.mem.Allocator,
        vote_slot: Slot,
        vote_hash: Hash,
        enable_tower_sync_ix: bool,
        block_id: Hash,
    ) !?Slot {
        if (self.vote_state.lastVotedSlot()) |last_voted_sot| {
            if (vote_slot <= last_voted_sot) {
                return error.VoteTooOld;
            }
        }

        const old_root = try self.getRoot();

        try self.vote_state.processNextVoteSlot(allocator, vote_slot);
        try self.updateLastVoteFromVoteState(allocator, vote_hash, enable_tower_sync_ix, block_id);

        const new_root = try self.getRoot();

        if (old_root != new_root) {
            return new_root;
        } else {
            return null;
        }
    }

    pub fn lastVotedSlot(self: *const Tower) ?Slot {
        return if (self.last_vote.isEmpty())
            null
        else
            self.last_vote.slot(self.last_vote.len() - 1);
    }

    pub fn lastVotedSlotHash(self: *const Tower) ?SlotAndHash {
        return if (self.lastVotedSlot()) |last_voted_slot|
            .{ .slot = last_voted_slot, .hash = self.last_vote.hash() }
        else
            null;
    }

    fn maybeTimestamp(self: *Tower, current_slot: Slot) ?UnixTimestamp {
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

    // root may be forcibly set by arbitrary replay root slot, for example from a root
    // after replaying a snapshot.
    // Also, tower.root() couldn't be None; initialize_lockouts() ensures that.
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
        for (self.vote_state.votes.items) |vote| {
            if (slot == vote.slot) {
                return true;
            }
        }
        return false;
    }

    pub fn isLockedOut(
        self: *const Tower,
        allocator: std.mem.Allocator,
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
        var vote_state = try self.vote_state.clone(allocator);
        defer vote_state.votes.deinit(allocator);

        try vote_state.processNextVoteSlot(allocator, slot);

        for (vote_state.votes.items) |vote| {
            if (slot != vote.slot and !ancestors.contains(vote.slot)) {
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

        return false;
    }

    fn isValidSwitchingProofVote(
        self: *const Tower,
        candidate_slot: Slot,
        last_voted_slot: Slot,
        switch_slot: Slot,
        ancestors: *const std.AutoHashMap(Slot, SortedSet(Slot)),
        last_vote_ancestors: *const SortedSet(Slot),
    ) ?bool {

        // Ignore if the `candidate_slot` is a descendant of the `last_voted_slot`, since we do not
        // want to count votes on the same fork.
        if (Tower.isDescendantSlot(
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
        if (Tower.greatestCommonAncestor(ancestors, candidate_slot, last_voted_slot)) |ancestor| {
            return Tower.isDescendantSlot(switch_slot, ancestor, ancestors);
        }

        return null;
    }

    pub fn makeCheckSwitchThresholdDecision(
        self: *const Tower,
        allocator: std.mem.Allocator,
        switch_slot: Slot,
        ancestors: *const std.AutoHashMap(Slot, SortedSet(Slot)),
        descendants: *const std.AutoHashMap(Slot, SortedSet(Slot)),
        progress: *const ProgressMap,
        total_stake: u64,
        epoch_vote_accounts: *const VoteAccountsHashMap,
        latest_validator_votes_for_frozen_banks: *const LatestValidatorVotesForFrozenBanks,
        heaviest_subtree_fork_choice: *const HeaviestSubtreeForkChoice,
    ) !SwitchForkDecision {
        const last_voted = self.lastVotedSlotHash() orelse return SwitchForkDecision.same_fork;
        const last_voted_slot = last_voted.slot;
        const last_voted_hash = last_voted.hash;
        const root = try self.getRoot();

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
                // return Some(_), justifying to panic! here.
                // Also, adjust_lockouts_after_replay() correctly makes last_voted_slot None,
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
            } else @panic("TODO");
        };

        // TODO can error handling be improved here
        const switch_slot_ancestors = ancestors.get(switch_slot).?;

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
            } else {
                @panic("TODO add message");
            }
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
                .progress_map
                .get(candidate_slot).?
                .fork_stats
                .lockout_intervals;

            // Find any locked out intervals for vote accounts in this bank with
            // `lockout_interval_end` >= `last_vote`, which implies they are locked out at
            // `last_vote` on another fork.
            const intervals_keyed_by_end = lockout_intervals.values()[last_voted_slot..];
            for (intervals_keyed_by_end) |interval_keyed_by_end| {
                for (interval_keyed_by_end.items) |vote_account| {
                    if (locked_out_vote_accounts.contains(vote_account.pubkey)) {
                        continue;
                    }
                    // Only count lockouts on slots that are:
                    // 1) Not ancestors of `last_vote`, meaning being on different fork
                    // 2) Not from before the current root as we can't determine if
                    // anything before the root was an ancestor of `last_vote` or not
                    if (!last_vote_ancestors.contains(vote_account.slot) and (
                    // Given a `lockout_interval_start` < root that appears in a
                    // bank for a `candidate_slot`, it must be that `lockout_interval_start`
                    // is an ancestor of the current root, because `candidate_slot` is a
                    // descendant of the current root
                        vote_account.slot > root))
                    {
                        const stake =
                            if (epoch_vote_accounts.get(vote_account.pubkey)) |staked_account|
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
                        try locked_out_vote_accounts.put(vote_account.pubkey);
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
                    const stake = if (stake_entry) |entry_stake| entry_stake.stake else 0;
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
        self: *Tower,
        allocator: std.mem.Allocator,
        switch_slot: Slot,
        ancestors: *const std.AutoHashMap(Slot, SortedSet(Slot)),
        descendants: *const std.AutoHashMap(Slot, SortedSet(Slot)),
        progress: *const ProgressMap,
        total_stake: u64,
        epoch_vote_accounts: *const VoteAccountsHashMap,
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

    fn isFirstSwitchCheck(self: *const Tower) bool {
        return self.last_switch_threshold_check == null;
    }

    pub fn checkVoteStakeThresholds(
        self: *Tower,
        allocator: std.mem.Allocator,
        slot: Slot,
        voted_stakes: *const VotedStakes,
        total_stake: Stake,
    ) ![]const ThresholdDecision {
        const threshold_size = 3;
        var threshold_decisions: [threshold_size]ThresholdDecision = undefined;

        // Generate the vote state assuming this vote is included.
        //
        var vote_state = try self.vote_state.clone(allocator);
        defer vote_state.deinit(allocator);
        try vote_state.processNextVoteSlot(allocator, slot);

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
            const vote_threshold = Tower.checkVoteStakeThreshold(
                self.logger,
                vote_state.nthRecentLockout(threshold.depth),
                self.vote_state.votes.items,
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

    fn votedSlots(self: *const Tower, allocator: std.mem.Allocator) ![]Slot {
        var slots = try std.ArrayList(Slot).initCapacity(
            allocator,
            self.vote_state.votes.items.len,
        );
        errdefer slots.deinit();

        for (self.vote_state.votes.items) |lockout| {
            try slots.append(lockout.slot);
        }

        return slots.toOwnedSlice();
    }

    pub fn isStrayLastVote(self: *const Tower) bool {
        return (self.stray_restored_slot != null and
            self.stray_restored_slot == self.lastVotedSlot());
    }

    ///  The tower root can be older/newer if the validator booted from a newer/older snapshot, so
    /// tower lockouts may need adjustment
    pub fn adjustLockoutsAfterReplay(
        self: *Tower,
        allocator: std.mem.Allocator,
        replayed_root: Slot,
        slot_history: *const SlotHistory,
    ) !Tower {
        // sanity assertions for roots
        const tower_root = try self.getRoot();
        self.logger.info().logf(
            \\adjusting lockouts (after replay up to {}):
            \\{any} tower root: {} replayed root: {}
        , .{
            replayed_root,
            try self.votedSlots(allocator),
            tower_root,
            replayed_root,
        });
        std.debug.assert(slot_history.check(replayed_root) == .found);

        std.debug.assert(
            self.last_vote.eql(&VoteTransaction{
                .vote_state_update = try VoteStateUpdate.default(allocator),
            }) and
                self.vote_state.votes.items.len == 0 or
                (self.last_vote.eql(&VoteTransaction{
                .tower_sync = try TowerSync.default(allocator),
            }) and
                self.vote_state.votes.items.len == 0) or
                (self.vote_state.votes.items.len > 0),
        );

        if (self.lastVotedSlot()) |last_voted_slot| {
            if (tower_root <= replayed_root) {
                // Normally, we goes into this clause with possible help of
                // reconcile_blockstore_roots_with_external_source()
                if (slot_history.check(last_voted_slot) == .too_old) {
                    // We could try hard to anchor with other older votes, but opt to simplify the
                    // following logic
                    // TODO error to enum
                    return TowerError.TooOldTower;
                }

                try self.adjustLockoutsWithSlotHistory(
                    allocator,
                    slot_history,
                );
                self.initializeRoot(replayed_root);
            } else {
                // This should never occur under normal operation.
                // While this validator's voting is suspended this way,
                // suspended_decision_due_to_major_unsynced_ledger() will be also touched.

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
            // initialize_lockouts_from_bank() should ensure the following invariant,
            // otherwise we're screwing something up.
            std.debug.assert(tower_root == replayed_root);
        }

        return self.*;
    }

    // TODO revisit
    fn adjustLockoutsWithSlotHistory(
        self: *Tower,
        allocator: std.mem.Allocator,
        slot_history: *const SlotHistory,
    ) !void {
        const tower_root = try self.getRoot();
        // retained slots will be consisted only from divergent slots
        var retain_flags_for_each_vote_in_reverse = try std.ArrayList(bool).initCapacity(
            allocator,
            self.vote_state.votes.items.len,
        );
        defer retain_flags_for_each_vote_in_reverse.deinit();

        var still_in_future = true;
        var past_outside_history = false;
        var maybe_checked_slot: ?Slot = null;
        var maybe_anchored_slot: ?Slot = null;

        var slots_in_tower = std.ArrayList(Slot).init(allocator);
        defer slots_in_tower.deinit();
        try slots_in_tower.append(tower_root);
        try slots_in_tower.appendSlice(try self.votedSlots(allocator));

        // iterate over votes + root (if any) in the newest => oldest order
        // bail out early if bad condition is found
        var iter = std.mem.reverseIterator(slots_in_tower.items);
        while (iter.next()) |slot_in_tower| {
            const check = slot_history.check(slot_in_tower);

            if (maybe_anchored_slot == null and check == .found) {
                maybe_anchored_slot = slot_in_tower;
            } else if (maybe_anchored_slot != null and check == .not_found) {
                // this can't happen unless we're fed with bogus snapshot
                // TODO Agave returns error with data.
                return TowerError.FatallyInconsistent;
            }

            if (still_in_future and check != .future) {
                still_in_future = false;
            } else if (!still_in_future and check == .future) {
                // really odd cases: bad ordered votes?
                // TODO Agave returns error with data.
                return TowerError.FatallyInconsistent;
            }

            if (!past_outside_history and check == .too_old) {
                past_outside_history = true;
            } else if (past_outside_history and check != .too_old) {
                // really odd cases: bad ordered votes?
                // TODO Agave returns error with data.
                return TowerError.FatallyInconsistent;
            }

            if (maybe_checked_slot) |checked_slot| {
                // This is really special, only if tower is initialized and contains
                // a vote for the root, the root slot can repeat only once
                const voting_for_root = slot_in_tower == checked_slot and
                    slot_in_tower == tower_root;

                if (!voting_for_root) {
                    // Unless we're voting since genesis, slots_in_tower must always be older than last checked_slot
                    // including all vote slot and the root slot.
                    std.debug.assert(slot_in_tower < checked_slot);
                }
            }

            maybe_checked_slot = slot_in_tower;
            try retain_flags_for_each_vote_in_reverse.append(maybe_anchored_slot == null);
        }

        // Check for errors if not anchored
        if (maybe_anchored_slot == null) {
            // this error really shouldn't happen unless ledger/tower is corrupted
            // TODO Agave returns error with data.
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

        var reversed_flags = std.ArrayList(bool).init(allocator);
        defer reversed_flags.deinit();

        for (retain_flags_for_each_vote_in_reverse.items) |flag| {
            try reversed_flags.insert(0, flag);
        }

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

        self.initializeLockouts(flags);

        if (self.vote_state.votes.items.len == 0) {
            // we might not have banks for those votes so just reset.
            // That's because the votes may well past replayed_root
            self.last_vote = VoteTransaction{ .vote = Vote.DEFAULT };
        } else {
            const voted_slots = try self.votedSlots(allocator);
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
        bank: *const Bank,
    ) !void {
        const vote_account = bank.accounts_db.getAccount(vote_account_pubkey) catch {
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
            .votes = lockouts,
            .root_slot = vote_state.root_slot,
        };
        self.initializeRoot(fork_root);

        var flags = try std.DynamicBitSetUnmanaged.initEmpty(
            allocator,
            self.vote_state.votes.items.len,
        );
        defer flags.deinit(allocator);

        for (self.vote_state.votes.items, 0..) |vote, i| {
            flags.setValue(i, vote.slot > fork_root);
        }

        self.initializeLockouts(flags);
    }

    // TODO Revisit the closure pattern
    // fn initializeLockouts(
    //     self: *Tower,
    //     should_retain: fn (Lockout) ?bool,
    // ) void {
    //     for (self.vote_state.votes, 0..) |vote, i| {
    //         if (!should_retain(vote)) {
    //             self.vote_state.votes.orderedRemove(i);
    //         }
    //     }
    // }

    fn initializeLockouts(
        self: *Tower,
        should_retain: std.DynamicBitSetUnmanaged,
    ) void {
        var i: usize = 0;
        while (i < self.vote_state.votes.items.len) {
            if (!should_retain.isSet(i)) {
                _ = self.vote_state.votes.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    // Updating root is needed to correctly restore from newly-saved tower for the next
    // boot
    fn initializeRoot(self: *Tower, root_slot: Slot) void {
        self.vote_state.root_slot = root_slot;
    }

    pub fn save(
        self: *const Tower,
        tower_storage: *const TowerStorage,
        node_keypair: *const KeyPair,
    ) !void {
        const saved_tower = try SavedTower.init(self, node_keypair);
        try tower_storage.store(&SavedTowerVersion{ .current = saved_tower });
    }

    // Static methods

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

    pub fn restore(
        tower_storage: *const TowerStorage,
        node_pubkey: *const Pubkey,
    ) !Tower {
        return try tower_storage.load(node_pubkey);
    }

    pub fn collectVoteLockouts(
        allocator: std.mem.Allocator,
        logger: Logger,
        vote_account_pubkey: *const Pubkey,
        bank_slot: Slot,
        vote_accounts: *const VoteAccountsHashMap,
        ancestors: *const std.AutoHashMap(Slot, SortedSet(Slot)),
        get_frozen_hash: fn (Slot) ?Hash,
        latest_validator_votes_for_frozen_banks: *LatestValidatorVotesForFrozenBanks,
    ) ComputedBankState {
        var vote_slots = SortedSet(Slot).init(allocator);
        defer vote_slots.deinit();

        var voted_stakes = SortedSet(Slot, u64).init(allocator);
        defer voted_stakes.deinit();

        var total_stake: u64 = 0;

        // Tree of intervals of lockouts of the form [slot, slot + slot.lockout],
        // keyed by end of the range
        var lockout_intervals = LockoutIntervals.init(allocator);
        var my_latest_landed_vote: ?Slot = null;

        var vote_accounts_iter = vote_accounts.iterator();
        while (vote_accounts_iter.next()) |entry| {
            const key = entry.key_ptr.*;
            const voted_stake = entry.value_ptr.*.stake;
            const vote_account = entry.value_ptr.*.account;
            if (voted_stake == 0) {
                continue;
            }

            logger.trace().logf(
                "{} {} with stake {}",
                .{ vote_account_pubkey, key, voted_stake },
            );

            var vote_state = TowerVoteState.fromAccount(&vote_account);

            for (vote_state.votes) |vote| {
                const interval = try lockout_intervals
                    .getOrPut(vote.lastLockedOutSlot());
                if (!interval.found_existing) {
                    interval.value_ptr.* = std.ArrayList(VotedSlotAndPubkey);
                }
                try interval.value_ptr.*.append(.{ .slot = vote.slot, .pubkey = key });
            }

            if (key.equals(vote_account_pubkey)) {
                my_latest_landed_vote = if (vote_state.nthRecentLockout(0)) |l| l.slot() else null;
                logger.debug().logf("vote state {any}", vote_state);
                const observed_slot = if (vote_state.nthRecentLockout(0)) |l| l.slot else 0;

                logger.debug().logf("observed slot {any}", .{observed_slot});
            }
            const start_root = vote_state.root_slot;

            // Add the last vote to update the `heaviest_subtree_fork_choice`
            if (vote_state.lastVotedSlot()) |last_landed_voted_slot| {
                latest_validator_votes_for_frozen_banks.checkAndVote(
                    key,
                    last_landed_voted_slot,
                    get_frozen_hash(last_landed_voted_slot),
                    true,
                );
            }

            vote_state.processNextVoteSlot(bank_slot);

            for (vote_state.votes.items) |vote| {
                try vote_slots.put(vote.slot);
            }

            if (start_root != vote_state.root_slot) {
                if (start_root) |root| {
                    const vote = Lockout{ .slot = root, .confirmation_count = MAX_LOCKOUT_HISTORY };
                    logger.trace().logf("ROOT: {}", .{vote.slot});
                    try vote_slots.put(vote.slot());
                }
            }
            if (vote_state.root_slot) |root| {
                const vote = Lockout{ .slot = root, .confirmation_count = MAX_LOCKOUT_HISTORY };
                try vote_slots.put(vote.slot());
            }

            // The last vote in the vote stack is a simulated vote on bank_slot, which
            // we added to the vote stack earlier in this function by calling process_vote().
            // We don't want to update the ancestors stakes of this vote b/c it does not
            // represent an actual vote by the validator.

            // Note: It should not be possible for any vote state in this bank to have
            // a vote for a slot >= bank_slot, so we are guaranteed that the last vote in
            // this vote stack is the simulated vote, so this fetch should be sufficient
            // to find the last unsimulated vote.
            std.debug.assert(
                if (vote_state.nthRecentLockout(0)) |l| l.slot == bank_slot else false,
            );

            if (vote_state.nthRecentLockout(1)) |vote| {
                // Update all the parents of this last vote with the stake of this vote account
                try updateAncestorVotedStakes(
                    &voted_stakes,
                    vote.slot,
                    voted_stake,
                    ancestors,
                );
            }
            total_stake += voted_stake;
        }

        try populateAncestorVotedStakes(&voted_stakes, &vote_slots, ancestors);

        // As commented above, since the votes at current bank_slot are
        // simulated votes, the voted_stake for `bank_slot` is not populated.
        // Therefore, we use the voted_stake for the parent of bank_slot as the
        // `fork_stake` instead.
        const fork_stake = blk: {
            if (ancestors.get(bank_slot)) |bank_ancestors| {
                var max_parent: ?Slot = null;
                var iter = bank_ancestors.iterator();
                while (iter.next()) |slot| {
                    if (max_parent == null or slot.* > max_parent.?) {
                        max_parent = slot.*;
                    }
                }
                if (max_parent) |parent| {
                    break :blk voted_stakes.get(parent) orelse 0;
                }
            }
            break :blk 0;
        };

        return ComputedBankState{
            .voted_stakes = voted_stakes,
            .total_stake = total_stake,
            .fork_stake = fork_stake,
            .lockout_intervals = lockout_intervals,
            .my_latest_landed_vote = my_latest_landed_vote,
        };
    }

    pub fn lastVotedSlotInBank(
        allocator: std.mem.Allocator,
        bank: *const Bank,
        vote_account_pubkey: *const Pubkey,
    ) ?Slot {
        const vote_account = bank.accounts_db.getAccount(vote_account_pubkey) catch return null;
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
        const data = std.ArrayList(u8).init(allocator);
        const buf = data.items;
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
    /// Returns None if `maybe_descendant` is not present in `ancestors`
    fn isDescendantSlot(
        maybe_descendant: Slot,
        slot: Slot,
        ancestors: *const std.AutoHashMap(Slot, SortedSet(Slot)),
    ) ?bool {
        return if (ancestors.get(maybe_descendant)) |candidate_slot_ancestors|
            candidate_slot_ancestors.contains(slot)
        else
            null;
    }

    /// Returns `Some(gca)` where `gca` is the greatest (by slot number)
    /// common ancestor of both `slot_a` and `slot_b`.
    ///
    /// Returns `None` if:
    /// * `slot_a` is not in `ancestors`
    /// * `slot_b` is not in `ancestors`
    /// * There is no common ancestor of slot_a and slot_b in `ancestors`
    fn greatestCommonAncestor(
        ancestors: *const std.AutoHashMap(
            Slot,
            SortedSet(Slot),
        ),
        slot_a: Slot,
        slot_b: Slot,
    ) ?Slot {
        var ancestors_a = ancestors.get(slot_a) orelse return null;
        var ancestors_b = ancestors.get(slot_b) orelse return null;

        var max_slot: ?Slot = null;

        for (ancestors_a.items()) |slot| {
            for (ancestors_b.items()) |other_slot| {
                if (slot == other_slot and
                    (max_slot == null or
                    slot > max_slot.?))
                {
                    max_slot = slot;
                }
            }
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
        threshold_vote: *const Lockout,
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

    fn checkVoteStakeThreshold(
        logger: ScopedLogger(@typeName(Tower)),
        maybe_threshold_vote: ?*const Lockout,
        tower_before_applying_vote: anytype,
        threshold_depth: usize,
        threshold_size: f64,
        slot: Slot,
        voted_stakes: *const std.AutoHashMap(Slot, u64),
        total_stake: u64,
    ) ThresholdDecision {
        const threshold_vote = maybe_threshold_vote orelse {
            // Tower isn't that deep.
            return ThresholdDecision{ .passed_threshold = {} };
        };

        const fork_stake = voted_stakes.get(threshold_vote.slot) orelse {
            // We haven't seen any votes on this fork yet, so no stake
            return ThresholdDecision{
                .failed_threshold = .{ @as(u64, threshold_depth), 0 },
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

        if (Tower.optimisticallyBypassVoteStakeThresholdCheck(
            tower_before_applying_vote,
            threshold_vote,
        ) or lockout > threshold_size) {
            return ThresholdDecision{ .passed_threshold = {} };
        }

        return ThresholdDecision{
            .failed_threshold = .{ @as(u64, threshold_depth), 0 },
        };
    }

    pub fn populateAncestorVotedStakes(
        voted_stakes: *SortedSet(Slot),
        vote_slots: []const Slot,
        ancestors: *const std.AutoHashMap(Slot, SortedSet(Slot)),
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
        ancestors: *const std.AutoHashMap(Slot, SortedSet(Slot)),
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
};

test "tower: check vote threshold without votes" {
    var tower = try createTestTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = std.AutoHashMap(u64, u64).init(std.testing.allocator);
    defer stakes.deinit();

    try stakes.put(0, 1);

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
    var tower = try createTestTower(std.testing.allocator, 4, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = std.AutoHashMap(u64, u64).init(std.testing.allocator);
    defer stakes.deinit();

    for (0..(MAX_LOCKOUT_HISTORY + 1)) |i| {
        try stakes.put(i, 1);
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
    var tower = try createTestTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = std.AutoHashMap(u64, u64).init(std.testing.allocator);
    defer stakes.deinit();

    try stakes.put(0, 1);

    const result = isSlotConfirmed(&tower, 0, &stakes, 2);
    try std.testing.expect(!result);
}

test "tower: is slot confirmed unknown slot" {
    var tower = try createTestTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = std.AutoHashMap(u64, u64).init(std.testing.allocator);
    defer stakes.deinit();

    const result = isSlotConfirmed(&tower, 0, &stakes, 2);
    try std.testing.expect(!result);
}

test "tower: is slot confirmed pass" {
    var tower = try createTestTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = std.AutoHashMap(u64, u64).init(std.testing.allocator);
    defer stakes.deinit();

    try stakes.put(0, 2);

    const result = isSlotConfirmed(&tower, 0, &stakes, 2);
    try std.testing.expect(result);
}

test "tower: is slot duplicate confirmed not enough stake failure" {
    var stakes = std.AutoHashMap(u64, u64).init(std.testing.allocator);
    defer stakes.deinit();

    try stakes.put(0, 52);

    const result = Tower.isSlotDuplicateConfirmed(
        0,
        &stakes,
        100,
    );
    try std.testing.expect(!result);
}

test "tower: is slot duplicate confirmed unknown slot" {
    var stakes = std.AutoHashMap(u64, u64).init(std.testing.allocator);
    defer stakes.deinit();

    const result = Tower.isSlotDuplicateConfirmed(
        0,
        &stakes,
        100,
    );
    try std.testing.expect(!result);
}

test "tower: is slot duplicate confirmed pass" {
    var stakes = std.AutoHashMap(u64, u64).init(std.testing.allocator);
    defer stakes.deinit();

    try stakes.put(0, 53);

    const result = Tower.isSlotDuplicateConfirmed(
        0,
        &stakes,
        100,
    );
    try std.testing.expect(result);
}

test "tower: is locked out empty" {
    var tower = try createTestTower(std.testing.allocator, 0, 0.67);
    defer tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    const result = try tower.isLockedOut(
        std.testing.allocator,
        1,
        &ancestors,
    );
    try std.testing.expect(!result);
}

test "tower: is locked out root slot child pass" {
    var tower = try createTestTower(std.testing.allocator, 0, 0.67);
    defer tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    tower.vote_state.root_slot = 0;

    const result = try tower.isLockedOut(
        std.testing.allocator,
        1,
        &ancestors,
    );
    try std.testing.expect(!result);
}

test "tower: is locked out root slot sibling fail" {
    var tower = try createTestTower(std.testing.allocator, 0, 0.67);
    defer tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    tower.vote_state.root_slot = 0;

    _ = try tower.recordBankVoteAndUpdateLockouts(
        std.testing.allocator,
        1,
        Hash.ZEROES,
        true,
        Hash.ZEROES,
    );

    const result = try tower.isLockedOut(
        std.testing.allocator,
        2,
        &ancestors,
    );

    try std.testing.expect(result);
}

test "tower: check already voted" {
    var tower = try createTestTower(std.testing.allocator, 0, 0.67);
    defer tower.deinit(std.testing.allocator);

    tower.vote_state.root_slot = 0;

    _ = try tower.recordBankVoteAndUpdateLockouts(
        std.testing.allocator,
        0,
        Hash.ZEROES,
        true,
        Hash.ZEROES,
    );

    try std.testing.expect(tower.hasVoted(0));
    try std.testing.expect(!tower.hasVoted(1));
}

test "tower: check recent slot" {
    var tower = try createTestTower(std.testing.allocator, 0, 0.67);
    defer tower.deinit(std.testing.allocator);

    try std.testing.expect(tower.isRecent(1));
    try std.testing.expect(tower.isRecent(32));

    for (0..64) |i| {
        _ = try tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
            Hash.ZEROES,
        );
    }

    try std.testing.expect(!tower.isRecent(0));
    try std.testing.expect(!tower.isRecent(32));
    try std.testing.expect(!tower.isRecent(63));
    try std.testing.expect(tower.isRecent(65));
}

test "tower: is locked out double vote" {
    var tower = try createTestTower(std.testing.allocator, 0, 0.67);
    defer tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    for (0..2) |i| {
        _ = try tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
            Hash.ZEROES,
        );
    }

    const result = try tower.isLockedOut(
        std.testing.allocator,
        0,
        &ancestors,
    );

    try std.testing.expect(result);
}

test "tower: is locked out child" {
    var tower = try createTestTower(std.testing.allocator, 0, 0.67);
    defer tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    _ = try tower.recordBankVoteAndUpdateLockouts(
        std.testing.allocator,
        0,
        Hash.ZEROES,
        true,
        Hash.ZEROES,
    );

    const result = try tower.isLockedOut(
        std.testing.allocator,
        1,
        &ancestors,
    );

    try std.testing.expect(!result);
}

test "tower: is locked out sibling" {
    var tower = try createTestTower(std.testing.allocator, 0, 0.67);
    defer tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    for (0..2) |i| {
        _ = try tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
            Hash.ZEROES,
        );
    }

    const result = try tower.isLockedOut(
        std.testing.allocator,
        2,
        &ancestors,
    );

    try std.testing.expect(result);
}

test "tower: is locked out last vote expired" {
    var tower = try createTestTower(std.testing.allocator, 0, 0.67);
    defer tower.deinit(std.testing.allocator);

    var ancestors = SortedSet(Slot).init(std.testing.allocator);
    defer ancestors.deinit();
    try ancestors.put(0);

    for (0..2) |i| {
        _ = try tower.recordBankVoteAndUpdateLockouts(
            std.testing.allocator,
            i,
            Hash.ZEROES,
            true,
            Hash.ZEROES,
        );
    }

    const result = try tower.isLockedOut(
        std.testing.allocator,
        4,
        &ancestors,
    );

    try std.testing.expect(!result);

    _ = try tower.recordBankVoteAndUpdateLockouts(
        std.testing.allocator,
        4,
        Hash.ZEROES,
        true,
        Hash.ZEROES,
    );

    try std.testing.expectEqual(0, tower.vote_state.votes.items[0].slot);
    try std.testing.expectEqual(2, tower.vote_state.votes.items[0].confirmation_count);
    try std.testing.expectEqual(4, tower.vote_state.votes.items[1].slot);
    try std.testing.expectEqual(1, tower.vote_state.votes.items[1].confirmation_count);
}

test "tower: check vote threshold below threshold" {
    var tower = try createTestTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = std.AutoHashMap(u64, u64).init(std.testing.allocator);
    defer stakes.deinit();

    try stakes.put(0, 1);

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

test "tower: check vote threshold above threshold" {
    var tower = try createTestTower(std.testing.allocator, 1, 0.67);
    defer tower.deinit(std.testing.allocator);

    var stakes = std.AutoHashMap(u64, u64).init(std.testing.allocator);
    defer stakes.deinit();

    try stakes.put(0, 2);

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
    try std.testing.expectEqual(0, result.len);
}

const builtin = @import("builtin");
fn createTestTower(
    allocator: std.mem.Allocator,
    threshold_depth: usize,
    threshold_size: f64,
) !Tower {
    if (!builtin.is_test) {
        @panic("createTestTower should only be used in test");
    }
    var tower = try Tower.default(allocator);
    tower.threshold_depth = threshold_depth;
    tower.threshold_size = threshold_size;
    return tower;
}

fn isSlotConfirmed(
    tower: *const Tower,
    slot: Slot,
    voted_stakes: *const VotedStakes,
    total_stake: Stake,
) bool {
    if (!builtin.is_test) {
        @panic("isSlotConfirmed should only be used in test");
    }

    if (voted_stakes.get(slot)) |stake| {
        const stake_ratio = @as(f64, @floatFromInt(stake)) / @as(f64, @floatFromInt(total_stake));
        return stake_ratio > tower.threshold_size;
    } else {
        return false;
    }
}
