const std = @import("std");
const sig = @import("../sig.zig");

const AutoHashMap = std.AutoHashMap;

const TowerStorage = sig.consensus.tower_storage.TowerStorage;
const BlockTimestamp = sig.runtime.program.vote_program.state.BlockTimestamp;
const Lockout = sig.runtime.program.vote_program.state.Lockout;
const Vote = sig.runtime.program.vote_program.state.Vote;
const VoteError = sig.runtime.program.vote_program.VoteError;
const MAX_LOCKOUT_HISTORY = sig.runtime.program.vote_program.state.MAX_LOCKOUT_HISTORY;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const VoteStateUpdate = sig.runtime.program.vote_program.state.VoteStateUpdate;
const TowerSync = sig.runtime.program.vote_program.state.TowerSync;
const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Slot = sig.core.Slot;
const Bank = sig.accounts_db.Bank;
const SortedMap = sig.utils.collections.SortedMap;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;

const UnixTimestamp = i64;

const VOTE_THRESHOLD_DEPTH_SHALLOW: usize = 4;
pub const VOTE_THRESHOLD_DEPTH: usize = 8;
pub const SWITCH_FORK_THRESHOLD: f64 = 0.38;
pub const DUPLICATE_LIVENESS_THRESHOLD: f64 = 0.1;

// TODO DUPLICATE_THRESHOLD is defined in replay stage in Agave
pub const DUPLICATE_THRESHOLD: f64 = 1.0 - SWITCH_FORK_THRESHOLD - DUPLICATE_LIVENESS_THRESHOLD;

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

    pub fn timestamp(self: *const VoteTransaction) ?UnixTimestamp {
        switch (self) {
            .vote => |args| args.timestamp,
            .vote_state_update => |args| args.timestamp,
            .compact_vote_state_update => |args| args.timestamp,
            .tower_sync => |args| args.timestamp,
        }
    }

    pub fn lastVotedSlot(self: *const VoteTransaction) ?i64 {
        switch (self) {
            .vote => |args| args.slots[args.slots.len - 1],
            .vote_state_update => |args| args.lockouts.items[args.lockouts.items.len - 1],
            .compact_vote_state_update => |args| args.lockouts.items[args.lockouts.items.len - 1],
            .tower_sync => |args| args.lockouts.items[args.lockouts.items.len - 1],
        }
    }

    pub fn setTimestamp(self: *VoteTransaction, ts: ?UnixTimestamp) void {
        switch (self.*) {
            .Vote => |*vote| vote.timestamp = ts,
            .VoteStateUpdate, .CompactVoteStateUpdate => |*vote_state_update| {
                vote_state_update.timestamp = ts;
            },
            .TowerSync => |*tower_sync| tower_sync.timestamp = ts,
        }
    }

    pub fn isEmpty(self: *const VoteTransaction) void {
        switch (self) {
            .Vote => |vote| vote.slots.len == 0,
            .VoteStateUpdate, .CompactVoteStateUpdate => |vote_state_update| {
                vote_state_update.lockouts.items.len == 0;
            },
            .TowerSync => |tower_sync| tower_sync.lockouts.items.len == 0,
        }
    }

    pub fn slot(self: *const VoteTransaction, i: usize) void {
        switch (self) {
            .Vote => |vote| vote.slots[i],
            .VoteStateUpdate, .CompactVoteStateUpdate => |vote_state_update| {
                vote_state_update.lockouts.items[i];
            },
            .TowerSync => |tower_sync| tower_sync.lockouts.items[i],
        }
    }

    pub fn len(self: *const VoteTransaction) usize {
        switch (self) {
            .Vote => |vote| vote.slots.len,
            .VoteStateUpdate, .CompactVoteStateUpdate => |vote_state_update| {
                vote_state_update.lockouts.items.len;
            },
            .TowerSync => |tower_sync| tower_sync.lockouts.items.len,
        }
    }

    pub fn hash(self: *const VoteTransaction) usize {
        switch (self) {
            .Vote => |vote| vote.hash,
            .VoteStateUpdate, .CompactVoteStateUpdate => |vote_state_update| {
                vote_state_update.hash;
            },
            .TowerSync => |tower_sync| tower_sync.hash,
        }
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

pub const VoteAccountsHashMap = std.AutoHashMap(Pubkey, struct { u64, VoteAccount });

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
    // TODO confirm if this can be a slice
    votes: std.ArrayList(Lockout),
    root_slot: ?Slot,

    pub fn default(allocator: std.mem.Allocator) TowerVoteState {
        return .{
            .votes = std.ArrayList(Lockout).init(allocator),
            .root_slot = null,
        };
    }

    pub fn lastLockout(self: *const TowerVoteState) ?*const Lockout {
        if (self.votes.items.len == 0) return null;
        return &self.votes.items[self.votes.items.len - 1];
    }

    pub fn lastVotedSlot(self: *const TowerVoteState) ?Slot {
        if (self.lastLockout()) return null;
        return self.lastLockout().?.slot;
    }

    pub fn clone(self: TowerVoteState) error{OutOfMemory}!TowerVoteState {
        return .{ .votes = try self.votes.clone(), .root_slot = self.root_slot };
    }

    pub fn processNextVoteSlot(self: *TowerVoteState, next_vote_slot: Slot) !void {
        // Ignore votes for slots earlier than we already have votes for
        if (self.lastVotedSlot()) |last_voted_slot| {
            if (next_vote_slot <= last_voted_slot) {
                return;
            }
        }

        self.popExpiredVotes(next_vote_slot);

        // Once the stack is full, pop the oldest lockout and distribute rewards
        if (self.votes.items.len == MAX_LOCKOUT_HISTORY) {
            const rooted_vote = self.votes.orderedRemove(0);
            self.root_slot = rooted_vote.slot;
        }
        try self.votes.append(
            Lockout{ .slot = next_vote_slot, .confirmation_count = 1 },
        );
        try self.doubleLockouts();
    }

    // Pop all recent votes that are not locked out at the next vote slot.  This
    // allows validators to switch forks once their votes for another fork have
    // expired. This also allows validators continue voting on recent blocks in
    // the same fork without increasing lockouts.
    pub fn popExpiredVotes(self: *TowerVoteState, next_vote_slot: Slot) void {
        while (self.lastLockout()) |vote| {
            if (!vote.isLockedOutAtSlot(next_vote_slot)) {
                _ = self.votes.popOrNull();
            } else {
                break;
            }
        }
    }

    pub fn doubleLockouts(self: *TowerVoteState) !void {
        const stack_depth = self.votes.items.len;

        for (self.votes.items, 0..) |*vote, i| {
            // Don't increase the lockout for this vote until we get more confirmations
            // than the max number of confirmations this vote has seen
            const confirmation_count = vote.lockout.confirmation_count;
            if (stack_depth > std.math.add(usize, i, confirmation_count) catch
                return error.ArithmeticOverflow)
            {
                vote.lockout.confirmation_count +|= 1;
            }
        }
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

pub const Tower = struct {
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

    pub fn newFromBankforks(
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

    pub fn towerSlots(self: *const Tower, allocator: std.mem.Allocator) []Slot {
        // TODO avoid this array list?
        var slots = std.ArrayList(Slot).init(allocator);
        for (self.vote_state.votes) |vote| {
            try slots.append(vote);
        }
        return slots.toOwnedSlice();
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
            self.last_timestamp.timestamp +| 1;

        if (self.last_vote.lastVotedSlot()) |last_voted_slot| {
            if (heaviest_slot_on_same_fork <= last_voted_slot) {
                return;
            }
            self.last_timestamp = BlockTimestamp{
                .slot = last_voted_slot,
                .timestamp = timestamp,
            };
            self.last_vote.setTimestamp(timestamp);
        } else {
            // TODO Agave logs here
        }
    }

    pub fn refreshLastVoteTxBlockhash(
        self: *Tower,
        new_vote_tx_blockhash: Hash,
    ) void {
        self.last_switch_threshold_check = BlockhashStatus{ .blockhash = new_vote_tx_blockhash };
    }

    pub fn markLastVoteTxBlockhashNonVoting(self: *Tower) void {
        self.last_switch_threshold_check = BlockhashStatus{.non_voting};
    }

    pub fn markLastVoteTxBlockhashHotSpare(self: *Tower) void {
        self.last_switch_threshold_check = BlockhashStatus{.hot_spare};
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
    ) !void {
        var new_vote = if (enable_tower_sync_ix)
            VoteTransaction{ .tower_sync = TowerSync{
                .lockouts = try self.vote_state.votes.clone(),
                .root = self.vote_state.root_slot,
                .hash = vote_hash,
                .timestamp = null,
                .block_id = block_id,
            } }
        else
            VoteTransaction{ .vote_state_update = VoteStateUpdate{
                .lockouts = try self.vote_state.votes.clone(),
                .root = self.vote_state.root_slot,
                .hash = vote_hash,
                .timestamp = null,
            } };

        const last_voted_slot = if (self.lastVotedSlot()) |last_voted_slot|
            last_voted_slot
        else
            0;

        new_vote.setTimestamp(self.maybeTimestamp(last_voted_slot));
        self.last_vote = new_vote;
    }

    fn recordBankVoteAndUpdateLockouts(
        self: *Tower,
        vote_slot: Slot,
        vote_hash: Hash,
        enable_tower_sync_ix: bool,
        block_id: Hash,
    ) ?Slot {
        if (self.vote_state.lastVotedSlot()) |last_voted_sot| {
            if (vote_slot <= last_voted_sot) {
                // TODO Can we improve things here and not be 1:1 even with erros
                // as the native programs?
                std.debug.panic(
                    "Error while recording vote {} {} in local tower {}",
                    .{ vote_slot, vote_hash, VoteError.vote_too_old },
                );
            }
        }

        const old_root = self.root();

        try self.vote_state.processNextVoteSlot(vote_slot);
        try self.updateLastVoteFromVoteState(vote_hash, enable_tower_sync_ix, block_id);

        const new_root = self.root();

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

    pub fn lastVotedSlotHash(self: *const Tower) ?struct { Slot, Hash } {
        if (self.lastVotedSlot()) |last_voted_slot|
            struct { last_voted_slot, self.last_vote.hash() }
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
                // Agave just logs here
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
    pub fn root(self: *const Tower) Slot {
        // TODO this is an unwrap in agave. Guess this is fine?
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
        for (self.vote_state.votes) |vote| {
            if (slot == vote.slot) {
                return true;
            }
        }
        return false;
    }

    pub fn isLockedOut(
        self: *const Tower,
        slot: Slot,
        ancestors: *const std.AutoHashMap(Slot, void),
    ) !bool {
        if (!self.isRecent(slot)) {
            return true;
        }

        // Check if a slot is locked out by simulating adding a vote for that
        // slot to the current lockouts to pop any expired votes. If any of the
        // remaining voted slots are on a different fork from the checked slot,
        // it's still locked out.
        var vote_state = try self.vote_state.clone();
        defer vote_state.deinit();

        try vote_state.processNextVoteSlot(slot);

        for (vote_state.votes.items) |vote| {
            if (slot != vote.slot() and !ancestors.contains(vote.slot)) {
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
        ancestors: *const std.AutoHashMap(Slot, std.AutoHashMap(Slot, void)),
        last_vote_ancestors: *const std.AutoHashMap(Slot, void),
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
        ancestors: *const std.AutoHashMap(Slot, std.AutoHashMap(Slot, void)),
        descendants: *const std.AutoHashMap(Slot, std.AutoHashMap(Slot, void)),
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
        ancestors: *const std.AutoHashMap(Slot, std.AutoHashMap(Slot, void)),
        descendants: *const std.AutoHashMap(Slot, std.AutoHashMap(Slot, void)),
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
        return self.last_switch_threshold_check == null;
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

    fn votedSlots(self: *const Tower, allocator: std.mem.Allocator) []Slot {
        var slots = try std.ArrayList(Slot).initCapacity(
            allocator,
            self.vote_state.votes.items.len,
        );
        errdefer slots.deinit();

        for (self.vote_state.votes.items) |lockout| {
            try slots.append(lockout.slot());
        }

        return slots.toOwnedSlice();
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

    // Static methods

    pub fn isSlotDuplicateConfirmed(
        slot: Slot,
        voted_stakes: *const VotedStakes,
        total_stake: Stake,
    ) bool {
        if (voted_stakes.get(slot)) |stake| {
            (@as(f64, stake) / @as(f64, total_stake)) > DUPLICATE_THRESHOLD;
        } else {
            return false;
        }
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
        ancestors: *const std.AutoHashMap(Slot, std.AutoHashMap(Slot, void)),
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
        ancestors: *const std.AutoHashMap(Slot, std.AutoHashMap(Slot, void)),
    ) ?bool {
        _ = maybe_descendant;
        _ = slot;
        _ = ancestors;
        @panic("unimplimented");
    }

    fn greatestCommonAncestor(
        ancestors: *const std.AutoHashMap(Slot, std.AutoHashMap(Slot, void)),
        slot_a: Slot,
        slot_b: Slot,
    ) ?Slot {
        _ = ancestors;
        _ = slot_a;
        _ = slot_b;
        @panic("unimplimented");
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
        const IteratorType = @TypeOf(tower_before_applying_vote);
        comptime {
            if (!@hasDecl(IteratorType, "next")) {
                @compileError("Parameter must be an iterator (must have next() method)");
            }
            const NextReturnType = @typeInfo(@TypeOf(IteratorType.next)).Fn.return_type.?;
            if (NextReturnType != Lockout) {
                @compileError("Iterator must produce Lockout items");
            }
        }

        for (tower_before_applying_vote.next()) |old_vote| {
            if (old_vote.slot() == threshold_vote.slot and
                old_vote.confirmation_count == threshold_vote.confirmation_count)
            {
                return true;
            }
        }
        return false;
    }

    fn checkVoteStakeThreshold(
        threshold_vote: ?*const Lockout,
        tower_before_applying_vote: anytype,
        threshold_depth: usize,
        threshold_size: f64,
        slot: Slot,
        voted_stakes: *const std.AutoHashMap(Slot, u64),
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
        voted_stakes: *std.AutoHashMap(Slot, void),
        vote_slots: []const Slot,
        ancestors: *const std.AutoHashMap(Slot, std.AutoHashMap(Slot, void)),
    ) void {
        // If there's no ancestors, that means this slot must be from before the current root,
        // in which case the lockouts won't be calculated in bank_weight anyways, so ignore
        // this slot
        for (vote_slots) |vote_slot| {
            if (ancestors.get(vote_slot)) |slot_ancestors| {
                _ = try voted_stakes.getOrPutValue(vote_slot, 0);
                var iter = slot_ancestors.iterator();
                while (iter.next()) |entry| {
                    _ = try voted_stakes.getOrPutValue(entry, 0);
                }
            }
        }
    }

    fn updateAncestorVotedStakes(
        voted_stakes: *VotedStakes,
        voted_slot: Slot,
        voted_stake: u64,
        ancestors: *const std.AutoHashMap(Slot, std.AutoHashMap(Slot, void)),
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
