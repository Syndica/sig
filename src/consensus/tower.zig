// TODO
// - Use sortedset
//
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
const SlotAndHash = sig.core.hash.SlotAndHash;
const Bank = sig.accounts_db.Bank;
const SortedMap = sig.utils.collections.SortedMap;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const SortedSet = sig.utils.collections.SortedSet;

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

    pub fn default(allocator: std.mem.Allocator) !VoteTransaction {
        return VoteTransaction{ .tower_sync = try TowerSync.default(allocator) };
    }

    pub fn timestamp(self: *const VoteTransaction) ?UnixTimestamp {
        return switch (self.*) {
            .vote => |args| args.timestamp,
            .vote_state_update => |args| args.timestamp,
            .compact_vote_state_update => |args| args.timestamp,
            .tower_sync => |args| args.timestamp,
        };
    }

    pub fn lastVotedSlot(self: *const VoteTransaction) ?Slot {
        return switch (self.*) {
            .vote => |args| args.slots[args.slots.len - 1],
            .vote_state_update => |args| args.lockouts.items[args.lockouts.items.len - 1].slot,
            .compact_vote_state_update => |args| args.lockouts.items[
                args.lockouts.items.len - 1
            ].slot,
            .tower_sync => |args| args.lockouts.items[args.lockouts.items.len - 1].slot,
        };
    }

    pub fn setTimestamp(self: *VoteTransaction, ts: ?UnixTimestamp) void {
        switch (self.*) {
            .vote => |*vote| vote.timestamp = ts,
            .vote_state_update, .compact_vote_state_update => |*vote_state_update| {
                vote_state_update.timestamp = ts;
            },
            .tower_sync => |*tower_sync| tower_sync.timestamp = ts,
        }
    }

    pub fn isEmpty(self: *const VoteTransaction) bool {
        return switch (self.*) {
            .vote => |vote| vote.slots.len == 0,
            .vote_state_update, .compact_vote_state_update => |vote_state_update| vote_state_update
                .lockouts.items.len == 0,
            .tower_sync => |tower_sync| tower_sync.lockouts.items.len == 0,
        };
    }

    pub fn slot(self: *const VoteTransaction, i: usize) Slot {
        return switch (self.*) {
            .vote => |vote| vote.slots[i],
            .vote_state_update, .compact_vote_state_update => |vote_state_update| vote_state_update
                .lockouts.items[i].slot,
            .tower_sync => |tower_sync| tower_sync.lockouts.items[i].slot,
        };
    }

    pub fn len(self: *const VoteTransaction) usize {
        return switch (self.*) {
            .vote => |vote| vote.slots.len,
            .vote_state_update, .compact_vote_state_update => |vote_state_update| vote_state_update
                .lockouts.items.len,
            .tower_sync => |tower_sync| tower_sync.lockouts.items.len,
        };
    }

    pub fn hash(self: *const VoteTransaction) Hash {
        return switch (self.*) {
            .vote => |vote| vote.hash,
            .vote_state_update, .compact_vote_state_update => |vote_state_update| vote_state_update
                .hash,
            .tower_sync => |tower_sync| tower_sync.hash,
        };
    }

    pub fn eql(self: *const VoteTransaction, other: *const VoteTransaction) bool {
        // TODO implement
        _ = self;
        _ = other;
        return true;
    }
};

pub const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days

// TODO this is defined in a different crate in Agave
//
pub const Check = enum {
    future,
    too_old,
    found,
    not_found,
};

pub const SlotHistory = struct {
    bits: std.DynamicBitSet,
    next_slot: u64,

    pub fn deinit(self: *SlotHistory) void {
        self.bits.deinit();
    }
    pub fn add(self: *SlotHistory, slot: u64) void {
        if (slot > self.next_slot and
            slot - self.next_slot >= MAX_ENTRIES)
        {
            // Wrapped past current history,
            // clear entire bitvec.
            const full_blocks = @as(usize, MAX_ENTRIES) / 64;
            for (0..full_blocks) |i| {
                self.bits.unset(i);
            }
        } else {
            for (self.next_slot..slot) |skipped| {
                self.bits.unset(skipped % MAX_ENTRIES);
            }
        }

        self.bits.set(slot % MAX_ENTRIES);
        self.next_slot = slot + 1;
    }

    pub fn check(self: *const SlotHistory, slot: u64) Check {
        if (slot > self.newest()) {
            return Check.future;
        } else if (slot < self.oldest()) {
            return Check.too_old;
        } else if (self.bits.isSet(slot % MAX_ENTRIES)) {
            return Check.found;
        } else {
            return Check.not_found;
        }
    }

    pub fn oldest(self: *const SlotHistory) u64 {
        return self.next_slot -| MAX_ENTRIES;
    }

    pub fn newest(self: *const SlotHistory) u64 {
        return self.next_slot - 1;
    }

    pub fn clone(
        self: *const SlotHistory,
        allocator: std.mem.Allocator,
    ) !SlotHistory {
        return SlotHistory{
            .bits = try self.bits.clone(allocator),
            .next_slot = self.next_slot,
        };
    }
};

pub const ForkStats = struct {
    computed: bool,
    lockout_intervals: LockoutIntervals,
};

pub const ForkProgress = struct {
    fork_stats: ForkStats,
};
// TODO Needs to be implemented and moved out of the tower.zig
pub const LatestValidatorVotesForFrozenBanks = struct {
    max_gossip_frozen_votes: std.AutoHashMap(Pubkey, struct { slot: Slot, hashes: []Hash }),
};
pub const VoteAccount = struct {};
pub const ProgressMap = struct {
    progress_map: std.AutoHashMap(Slot, ForkProgress),
    pub fn getHash(_: ProgressMap, _: Slot) ?Hash {
        @panic("Unimplemented");
    }
    pub fn getForkStats(_: ProgressMap, _: Slot) ?ForkStats {
        @panic("Unimplemented");
    }
};

pub const StakedAccount = struct { stake: u64, account: VoteAccount };

pub const VoteAccountsHashMap = std.AutoHashMap(Pubkey, StakedAccount);

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

const VotedSlotAndPubkey = struct { slot: Slot, pubkey: Pubkey };

pub const Stake = u64;
pub const ExpirationSlot = Slot;
pub const VotedSlot = Slot;
pub const VotedStakes = AutoHashMap(Slot, Stake);
// TODO modify SortedMap to allow array in value - support eq
pub const LockoutIntervals = SortedMap(ExpirationSlot, std.ArrayList(VotedSlotAndPubkey));

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
    votes: std.ArrayListUnmanaged(Lockout),
    root_slot: ?Slot,

    pub fn default(allocator: std.mem.Allocator) !TowerVoteState {
        return .{
            .votes = try std.ArrayListUnmanaged(Lockout).initCapacity(allocator, 0),
            .root_slot = null,
        };
    }

    pub fn lastLockout(self: *const TowerVoteState) ?*const Lockout {
        if (self.votes.items.len == 0) return null;
        return &self.votes.items[self.votes.items.len - 1];
    }

    pub fn lastVotedSlot(self: *const TowerVoteState) ?Slot {
        if (self.lastLockout() == null) return null;
        return self.lastLockout().?.slot;
    }

    pub fn clone(
        self: TowerVoteState,
        allocator: std.mem.Allocator,
    ) (error{OutOfMemory})!TowerVoteState {
        return .{ .votes = try self.votes.clone(allocator), .root_slot = self.root_slot };
    }

    pub fn nthRecentLockout(self: *const TowerVoteState, position: usize) ?*const Lockout {
        const pos = std.math.add(usize, self.votes.items.len, position +| 1) catch
            return null;
        return &self.votes.items[pos];
    }

    pub fn processNextVoteSlot(
        self: *TowerVoteState,
        allocator: std.mem.Allocator,
        next_vote_slot: Slot,
    ) !void {
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
            allocator,
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
            const confirmation_count = vote.confirmation_count;
            if (stack_depth > std.math.add(usize, i, confirmation_count) catch
                return error.ArithmeticOverflow)
            {
                vote.confirmation_count +|= 1;
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

    pub fn default(allocator: std.mem.Allocator) !Tower {
        return Tower{
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

    pub fn towerSlots(self: *const Tower, allocator: std.mem.Allocator) ![]Slot {
        // TODO avoid this array list?
        var slots = std.ArrayList(Slot).init(allocator);
        for (self.vote_state.votes.items) |vote| {
            try slots.append(vote.slot);
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
        self.last_vote_tx_blockhash = BlockhashStatus{ .blockhash = new_vote_tx_blockhash };
    }

    pub fn markLastVoteTxBlockhashNonVoting(self: *Tower) void {
        self.last_vote_tx_blockhash = BlockhashStatus{ .non_voting = {} };
    }

    pub fn markLastVoteTxBlockhashHotSpare(self: *Tower) void {
        self.last_vote_tx_blockhash = BlockhashStatus{ .hot_spare = {} };
    }

    pub fn recordBankVote(self: *Tower, bank: *const Bank) ?Slot {
        _ = self;
        _ = bank;
        @panic("unimplimented");
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

        const old_root = self.getRoot();

        try self.vote_state.processNextVoteSlot(vote_slot);
        try self.updateLastVoteFromVoteState(vote_hash, enable_tower_sync_ix, block_id);

        const new_root = self.getRoot();

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
    pub fn getRoot(self: *const Tower) Slot {
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
        defer allocator.free(vote_state.votes.items);

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
        const root = self.getRoot();

        // `heaviest_subtree_fork_choice` entries are not cleaned by duplicate block purging/rollback logic,
        // so this is safe to check here. We return here if the last voted slot was rolled back/purged due to
        // being a duplicate because `ancestors`/`descendants`/`progress` structures may be missing this slot due
        // to duplicate purging. This would cause many of the `unwrap()` checks below to fail.
        //
        // TODO: Handle if the last vote is on a dupe, and then we restart. The dupe won't be in
        // heaviest_subtree_fork_choice, so `heaviest_subtree_fork_choice.latest_invalid_ancestor()` will return
        // None, but the last vote will be persisted in tower.
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
                    // TODO: Properly handle this case
                    return SwitchForkDecision{ .switch_proof = Hash.ZEROES };
                }
            }
        }

        const last_vote_ancestors = (ancestors.get(last_voted_slot)) orelse blk: {
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
                    // TODO replicate the logs
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
            _, const intervals_keyed_by_end = lockout_intervals.range(last_voted_slot, null);
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
                // TODO log
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
    ) !std.ArrayList(ThresholdDecision) {
        var threshold_decisions = std.ArrayList(ThresholdDecision).init(allocator);
        // Generate the vote state assuming this vote is included.
        //
        var vote_state = try self.vote_state.clone(allocator);
        try vote_state.processNextVoteSlot(allocator, slot);

        // Assemble all the vote thresholds and depths to check.
        const vote_thresholds_and_depths = [_]struct { depth: usize, size: f64 }{
            // The following two checks are log only and are currently being used for experimentation
            // purposes. We wish to impose a shallow threshold check to prevent the frequent 8 deep
            // lockouts seen multiple times a day. We check both the 4th and 5th deep here to collect
            // metrics to determine the right depth and threshold percentage to set in the future.
            .{ .depth = VOTE_THRESHOLD_DEPTH_SHALLOW, .size = SWITCH_FORK_THRESHOLD },
            .{ .depth = VOTE_THRESHOLD_DEPTH_SHALLOW + 1, .size = SWITCH_FORK_THRESHOLD },
            .{ .depth = self.threshold_depth, .size = self.threshold_size },
        };

        // Check one by one and add any failures to be returned
        for (vote_thresholds_and_depths) |threshold| {
            const vote_threshold = Tower.checkVoteStakeThreshold(
                vote_state.nthRecentLockout(threshold.depth),
                self.vote_state.votes.items,
                threshold.depth,
                threshold.size,
                slot,
                voted_stakes,
                total_stake,
            );

            if (std.mem.eql(u8, @tagName(vote_threshold), "failed_threshold")) {
                try threshold_decisions.append(vote_threshold);
            }
        }

        return threshold_decisions;
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

    // TODO Add logging
    ///  The tower root can be older/newer if the validator booted from a newer/older snapshot, so
    /// tower lockouts may need adjustment
    pub fn adjustLockoutsAfterReplay(
        self: *Tower,
        allocator: std.mem.Allocator,
        replayed_root: Slot,
        slot_history: *const SlotHistory,
    ) !Tower {
        // sanity assertions for roots
        const tower_root = self.getRoot();

        std.debug.assert(slot_history.check(replayed_root) == Check.found);

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
                if (slot_history.check(last_voted_slot) == Check.too_old) {
                    // We could try hard to anchor with other older votes, but opt to simplify the
                    // following logic
                    // TODO error to enum
                    return TowerError.TooOldTower;
                }

                try self.adjustLockoutsWithSlotHistory(
                    slot_history,
                );
                self.initializeRoot(replayed_root);
            } else {
                // Let's pass-through adjust_lockouts_with_slot_history just for sanitization,
                // using a synthesized SlotHistory.
                var warped_slot_history = try slot_history.clone(allocator);
                defer warped_slot_history.deinit();
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

                try self.adjustLockoutsWithSlotHistory(&warped_slot_history);
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
        should_retain: fn (Lockout) ?bool,
    ) void {
        for (self.vote_state.votes, 0..) |vote, i| {
            if (!should_retain(vote)) {
                self.vote_state.votes.orderedRemove(i);
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
        _ = tower_storage;
        _ = node_pubkey;
        @panic("unimplimented");
    }

    pub fn collectVoteLockouts(
        vote_account_pubkey: *const Pubkey,
        bank_slot: Slot,
        vote_accounts: *const VoteAccountsHashMap,
        ancestors: *const std.AutoHashMap(Slot, SortedSet(Slot)),
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
        threshold: ?*const Lockout,
        tower_before_applying_vote: anytype,
        threshold_depth: usize,
        threshold_size: f64,
        _: Slot, // TODO add logging. only used in log in Agave
        voted_stakes: *const std.AutoHashMap(Slot, u64),
        total_stake: u64,
    ) ThresholdDecision {
        const threshold_vote = threshold orelse {
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
