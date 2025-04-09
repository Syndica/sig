const std = @import("std");
const sig = @import("../sig.zig");

const AutoHashMap = std.AutoHashMap;

const TowerStorage = sig.consensus.tower_storage.TowerStorage;
const BlockTimestamp = sig.runtime.program.vote_program.state.BlockTimestamp;
const Lockout = sig.runtime.program.vote_program.state.Lockout;
const Vote = sig.runtime.program.vote_program.state.Vote;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const VoteStateUpdate = sig.runtime.program.vote_program.state.VoteStateUpdate;
const TowerSync = sig.runtime.program.vote_program.state.TowerSync;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Slot = sig.core.Slot;
const Bank = sig.accounts_db.Bank;
const SortedMap = sig.utils.collections.SortedMap;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const VOTE_THRESHOLD_DEPTH_SHALLOW: usize = 4;
pub const VOTE_THRESHOLD_DEPTH: usize = 8;
pub const SWITCH_FORK_THRESHOLD: f64 = 0.38;

// TODO this is defined in a different crate in Agave
pub const VoteTransaction = union(enum) {
    vote: Vote,
    vote_state_update: VoteStateUpdate,
    // TODO Check the serialisation for the difference with compact_
    compact_vote_state_update: VoteStateUpdate,
    tower_sync: TowerSync,

    pub fn default(allocator: std.mem.Allocator) VoteTransaction {
        return VoteTransaction{ .tower_sync = TowerSync.default(allocator) };
    }
};

// TODO this is defined in a different crate in Agave
pub const SlotHistory = struct {
    bits: std.DynamicBitSet,
    next_slot: u64,
};

// TODO Needs to be implemented and moved out of the tower.zig
pub const LatestValidatorVotesForFrozenBanks = struct {};
pub const VoteAccount = struct {};
pub const ProgressMap = struct {};

pub const VoteAccountsHashMap = std.ArrayHashMap(Pubkey, struct { u64, VoteAccount });

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
pub const ExpirationSlot = Slot;
pub const VotedSlot = Slot;
pub const VotedStakes = AutoHashMap(Slot, Stake);
pub const LockoutIntervals = SortedMap(ExpirationSlot, std.ArrayList(struct { VotedSlot, Pubkey }));

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

const TowerVoteState = struct {
    votes: std.ArrayList(Lockout),
    root_slot: ?Slot,

    pub fn default(allocator: std.mem.Allocator) TowerVoteState {
        return .{
            .votes = std.ArrayList(Lockout).init(allocator),
            .root_slot = null,
        };
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

    pub const DEFAULT = BlockhashStatus{.uninitialized};
};

const Tower = struct {
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

    pub fn default(allocator: std.mem.Allocator) Tower {
        return Tower{
            .node_pubkey = Pubkey.ZEROES,
            .threshold_depth = 0,
            .threshold_size = 0,
            .vote_state = TowerVoteState.default(allocator),
            .last_vote = VoteTransaction.default(allocator),
            .last_vote_tx_blockhash = BlockhashStatus.DEFAULT,
            .last_timestamp = BlockTimestamp.DEFAULT,
            .stray_restored_slot = null,
            .last_switch_threshold_check = null,
        };
    }

    pub fn init(
        allocator: std.mem.Allocator,
        node_pubkey: *const Pubkey,
        vote_account_pubkey: *const Pubkey,
        fork_root: Slot,
        bank: *const Bank,
    ) Tower {
        _ = allocator;
        _ = node_pubkey;
        _ = vote_account_pubkey;
        _ = fork_root;
        _ = bank;
        @panic("unimplimented");
    }

    pub fn newFromFankforks(
        allocator: std.mem.Allocator,
        // bank_forks: *const BankForks,
        node_pubkey: *const Pubkey,
        vote_account: *const Pubkey,
    ) Tower {
        _ = allocator;
        _ = node_pubkey;
        _ = vote_account;
        @panic("unimplimented");
    }

    pub fn isSlotDuplicateConfirmed(
        self: *const Tower,
        slot: Slot,
        voted_stakes: *const VotedStakes,
        total_stake: Stake,
    ) bool {
        _ = self;
        _ = slot;
        _ = voted_stakes;
        _ = total_stake;
        @panic("unimplimented");
    }

    pub fn towerSlots(self: *const Tower) []Slot {
        _ = self;
        @panic("unimplimented");
    }

    pub fn lastVoteTxBlockhash(self: *const Tower) BlockhashStatus {
        _ = self;
        @panic("unimplimented");
    }

    pub fn refreshLastVoteTimestamp(
        self: *Tower,
        heaviest_slot_on_same_fork: Slot,
    ) void {
        _ = self;
        _ = heaviest_slot_on_same_fork;
        @panic("unimplimented");
    }

    pub fn refreshLastVoteTxBlockhash(
        self: *Tower,
        new_vote_tx_blockhash: Hash,
    ) void {
        _ = self;
        _ = new_vote_tx_blockhash;
        @panic("unimplimented");
    }

    pub fn markLastVoteTxBlockhashNonVoting(self: *Tower) void {
        _ = self;
        @panic("unimplimented");
    }

    pub fn mark_last_vote_tx_blockhash_hot_spare(self: *Tower) void {
        _ = self;
        @panic("unimplimented");
    }

    pub fn recordBankVote(self: *Tower, bank: *const Bank) ?Slot {
        _ = self;
        _ = bank;
        @panic("unimplimented");
    }

    pub fn updateLastVoteFromVoteState(
        self: *Tower,
        vote_hash: Hash,
        enable_tower_sync_ix: bool,
        block_id: Hash,
    ) void {
        _ = self;
        _ = vote_hash;
        _ = enable_tower_sync_ix;
        _ = block_id;
        @panic("unimplimented");
    }

    fn recordBankVoteAndUpdateLockouts(
        self: *Tower,
        vote_slot: Slot,
        vote_hash: Hash,
        enable_tower_sync_ix: bool,
        block_id: Hash,
    ) ?Slot {
        _ = self;
        _ = vote_slot;
        _ = vote_hash;
        _ = enable_tower_sync_ix;
        _ = block_id;
        @panic("unimplimented");
    }

    pub fn lastVotedSlot(self: *const Tower) ?Slot {
        _ = self;
        @panic("unimplimented");
    }

    pub fn lastVotedSlotHash(self: *const Tower) ?struct { Slot, Hash } {
        _ = self;
        @panic("unimplimented");
    }

    pub fn strayRestoredSlot(self: *const Tower) ?Slot {
        _ = self;
        @panic("unimplimented");
    }

    pub fn lastVote(self: *const Tower) VoteTransaction {
        _ = self;
        @panic("unimplimented");
    }

    fn maybeTimestamp(self: *Tower, current_slot: Slot) ?i64 {
        _ = self;
        _ = current_slot;
        @panic("unimplimented");
    }

    pub fn root(self: *const Tower) Slot {
        _ = self;
        @panic("unimplimented");
    }

    pub fn isRecent(self: *const Tower, slot: Slot) bool {
        _ = self;
        _ = slot;
        @panic("unimplimented");
    }

    pub fn hasVoted(self: *const Tower, slot: Slot) bool {
        _ = self;
        _ = slot;
        @panic("unimplimented");
    }

    pub fn isLockedOut(
        self: *const Tower,
        slot: Slot,
        ancestors: *const std.ArrayHashMap(Slot, void),
    ) bool {
        _ = self;
        _ = slot;
        _ = ancestors;
        @panic("unimplimented");
    }

    fn isValidSwitchingProofVote(
        self: *const Tower,
        candidate_slot: Slot,
        last_voted_slot: Slot,
        switch_slot: Slot,
        ancestors: *const std.ArrayHashMap(Slot, std.ArrayHashMap(Slot, void)),
        last_vote_ancestors: *const std.ArrayHashMap(Slot, void),
    ) ?bool {
        _ = self;
        _ = candidate_slot;
        _ = last_voted_slot;
        _ = switch_slot;
        _ = ancestors;
        _ = last_vote_ancestors;
        @panic("unimplimented");
    }

    fn make_check_switch_threshold_decision(
        self: *const Tower,
        switch_slot: Slot,
        ancestors: *const std.ArrayHashMap(Slot, std.ArrayHashMap(Slot, void)),
        descendants: *const std.ArrayHashMap(Slot, std.ArrayHashMap(Slot, void)),
        progress: *const ProgressMap,
        total_stake: u64,
        epoch_vote_accounts: *const VoteAccountsHashMap,
        latest_validator_votes_for_frozen_banks: *const LatestValidatorVotesForFrozenBanks,
        heaviest_subtree_fork_choice: *const HeaviestSubtreeForkChoice,
    ) SwitchForkDecision {
        _ = self;
        _ = switch_slot;
        _ = ancestors;
        _ = descendants;
        _ = progress;
        _ = total_stake;
        _ = epoch_vote_accounts;
        _ = latest_validator_votes_for_frozen_banks;
        _ = heaviest_subtree_fork_choice;
        @panic("unimplimented");
    }

    pub fn checkSwitchThreshold(
        self: *Tower,
        switch_slot: Slot,
        ancestors: *const std.ArrayHashMap(Slot, std.ArrayHashMap(Slot, void)),
        descendants: *const std.ArrayHashMap(Slot, std.ArrayHashMap(Slot, void)),
        progress: *const ProgressMap,
        total_stake: u64,
        epoch_vote_accounts: *const VoteAccountsHashMap,
        latest_validator_votes_for_frozen_banks: *const LatestValidatorVotesForFrozenBanks,
        heaviest_subtree_fork_choice: *const HeaviestSubtreeForkChoice,
    ) SwitchForkDecision {
        _ = self;
        _ = switch_slot;
        _ = ancestors;
        _ = descendants;
        _ = progress;
        _ = total_stake;
        _ = epoch_vote_accounts;
        _ = latest_validator_votes_for_frozen_banks;
        _ = heaviest_subtree_fork_choice;
        @panic("unimplimented");
    }

    fn isFirstSwitchCheck(self: *const Tower) bool {
        _ = self;
        @panic("unimplimented");
    }

    pub fn checkVoteStakeThresholds(
        self: *const Tower,
        slot: Slot,
        voted_stakes: *const VotedStakes,
        total_stake: Stake,
    ) []ThresholdDecision {
        _ = self;
        _ = slot;
        _ = voted_stakes;
        _ = total_stake;
        @panic("unimplimented");
    }

    fn votedSlots(self: *const Tower) []Slot {
        _ = self;
        @panic("unimplimented");
    }

    pub fn isStrayLastVote(self: *const Tower) bool {
        _ = self;
        @panic("unimplimented");
    }

    pub fn adjustLockoutsAfterReplay(
        self: Tower,
        replayed_root: Slot,
        slot_history: *const SlotHistory,
    ) !Tower {
        _ = self;
        _ = replayed_root;
        _ = slot_history;
        @panic("unimplimented");
    }

    fn adjustLockoutsWithSlotHistory(
        self: *Tower,
        slot_history: *const SlotHistory,
    ) !void {
        _ = self;
        _ = slot_history;
        @panic("unimplimented");
    }

    fn initializeLockoutsFromBank(
        self: *Tower,
        vote_account_pubkey: *const Pubkey,
        fork_root: Slot,
        bank: *const Bank,
    ) void {
        _ = self;
        _ = vote_account_pubkey;
        _ = fork_root;
        _ = bank;
        @panic("unimplimented");
    }

    fn initializeLockouts(
        self: *Tower,
        should_retain: anytype,
    ) void {
        _ = self;
        _ = should_retain;
        @panic("unimplimented");
    }

    fn initialize_root(self: *Tower, fork_root: Slot) void {
        _ = self;
        _ = fork_root;
        @panic("unimplimented");
    }

    pub fn save(
        self: *const Tower,
        tower_storage: *const TowerStorage,
        node_keypair: *const KeyPair,
    ) !void {
        _ = self;
        _ = tower_storage;
        _ = node_keypair;
        @panic("unimplimented");
    }

    pub fn restore(
        tower_storage: *const TowerStorage,
        node_pubkey: *const Pubkey,
    ) !Tower {
        _ = tower_storage;
        _ = node_pubkey;
        @panic("unimplimented");
    }

    pub fn collectVoteLockouts(
        vote_account_pubkey: *const Pubkey,
        bank_slot: Slot,
        vote_accounts: *const VoteAccountsHashMap,
        ancestors: *const std.ArrayHashMap(Slot, std.ArrayHashMap(Slot, void)),
        get_frozen_hash: fn (Slot) ?Hash,
        latest_validator_votes_for_frozen_banks: *LatestValidatorVotesForFrozenBanks,
    ) ComputedBankState {
        _ = vote_account_pubkey;
        _ = bank_slot;
        _ = vote_accounts;
        _ = ancestors;
        _ = get_frozen_hash;
        _ = latest_validator_votes_for_frozen_banks;
        @panic("unimplimented");
    }

    pub fn lastVotedSlotInBank(
        bank: *const Bank,
        vote_account_pubkey: *const Pubkey,
    ) ?Slot {
        _ = bank;
        _ = vote_account_pubkey;
        @panic("unimplimented");
    }

    fn isDescendantSlot(
        maybe_descendant: Slot,
        slot: Slot,
        ancestors: *const std.ArrayHashMap(Slot, std.ArrayHashMap(Slot, void)),
    ) ?bool {
        _ = maybe_descendant;
        _ = slot;
        _ = ancestors;
        @panic("unimplimented");
    }

    fn greatestCommonAncestor(
        ancestors: *const std.ArrayHashMap(Slot, std.ArrayHashMap(Slot, void)),
        slot_a: Slot,
        slot_b: Slot,
    ) ?Slot {
        _ = ancestors;
        _ = slot_a;
        _ = slot_b;
        @panic("unimplimented");
    }

    fn optimisticallyBypassVoteStakeThresholdCheck(
        tower_before_applying_vote: anytype,
        threshold_vote: *const Lockout,
    ) bool {
        _ = tower_before_applying_vote;
        _ = threshold_vote;
        @panic("unimplimented");
    }

    fn checkVoteStakeThreshold(
        threshold_vote: ?*const Lockout,
        tower_before_applying_vote: anytype,
        threshold_depth: usize,
        threshold_size: f64,
        slot: Slot,
        voted_stakes: *const std.ArrayHashMap(Slot, u64),
        total_stake: u64,
    ) ThresholdDecision {
        _ = threshold_vote;
        _ = tower_before_applying_vote;
        _ = threshold_depth;
        _ = threshold_size;
        _ = slot;
        _ = voted_stakes;
        _ = total_stake;
        @panic("unimplimented");
    }

    pub fn populateAncestorVotedStakes(
        voted_stakes: *VotedStakes,
        vote_slots: anytype,
        ancestors: *const std.ArrayHashMap(Slot, std.ArrayHashMap(Slot, void)),
    ) void {
        _ = voted_stakes;
        _ = vote_slots;
        _ = ancestors;
        @panic("unimplimented");
    }

    fn updateAncestorVotedStakes(
        voted_stakes: *VotedStakes,
        voted_slot: Slot,
        voted_stake: u64,
        ancestors: *const std.ArrayHashMap(Slot, std.ArrayHashMap(Slot, void)),
    ) void {
        _ = voted_stakes;
        _ = voted_slot;
        _ = voted_stake;
        _ = ancestors;
        @panic("unimplimented");
    }
};
