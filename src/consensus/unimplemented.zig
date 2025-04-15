// Houses all unimplemented structure external to the tower
// but needed by it.
//
//
//

const std = @import("std");
const sig = @import("../sig.zig");
const Bank = sig.accounts_db.Bank;
const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const SlotAndHash = sig.core.hash.SlotAndHash;
const SortedMap = sig.utils.collections.SortedMap;

const tower = sig.consensus.tower;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const Vote = sig.runtime.program.vote_program.state.Vote;
const VoteStateUpdate = sig.runtime.program.vote_program.state.VoteStateUpdate;
const TowerSync = sig.runtime.program.vote_program.state.TowerSync;
const Lockout = sig.runtime.program.vote_program.state.Lockout;

const MAX_LOCKOUT_HISTORY = sig.runtime.program.vote_program.state.MAX_LOCKOUT_HISTORY;
pub const SWITCH_FORK_THRESHOLD = tower.SWITCH_FORK_THRESHOLD;

pub const MAX_ENTRIES = tower.MAX_ENTRIES;
pub const DUPLICATE_LIVENESS_THRESHOLD = tower.DUPLICATE_LIVENESS_THRESHOLD;
// TODO DUPLICATE_THRESHOLD is defined in replay stage in Agave
pub const DUPLICATE_THRESHOLD: f64 = 1.0 - SWITCH_FORK_THRESHOLD - DUPLICATE_LIVENESS_THRESHOLD;

const UnixTimestamp = i64;

pub const BankForks = struct {
    pub fn rootBank(self: *const BankForks) Bank {
        _ = self;
        @panic("Unimplemented");
    }
    pub fn frozenBanks(self: *const BankForks) SortedMap(Slot, Bank) {
        _ = self;
        @panic("Unimplemented");
    }
    pub fn getWithCheckedHash(
        self: *const BankForks,
        heaviest: SlotAndHash,
    ) ?Bank {
        _ = self;
        _ = heaviest;
        @panic("Unimplemented");
    }
};

pub const ForkStats = struct {
    computed: bool,
    lockout_intervals: LockoutIntervals,
};

pub const ForkProgress = struct {
    fork_stats: ForkStats,
};

pub const ProgressMap = struct {
    progress_map: std.AutoHashMap(Slot, ForkProgress),
    pub fn getHash(_: ProgressMap, _: Slot) ?Hash {
        @panic("Unimplemented");
    }
    pub fn getForkStats(_: ProgressMap, _: Slot) ?ForkStats {
        @panic("Unimplemented");
    }
};

pub const ReplayStage = struct {
    pub fn initializeProgressAndForkChoice(
        root_bank: *const Bank,
        frozen_banks: std.ArrayList(Bank),
        my_pubkey: *const Pubkey,
        vote_account: *const Pubkey,
        duplicate_slot_hashes: std.ArrayList(SlotAndHash),
    ) struct {
        ProgressMap,
        HeaviestSubtreeForkChoice,
    } {
        _ = root_bank;
        _ = frozen_banks;
        _ = my_pubkey;
        _ = vote_account;
        _ = duplicate_slot_hashes;
        @panic("Unimplemented");
    }
};

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

// TODO Needs to be implemented and moved out of the tower.zig
pub const LatestValidatorVotesForFrozenBanks = struct {
    max_gossip_frozen_votes: std.AutoHashMap(Pubkey, struct { slot: Slot, hashes: []Hash }),
    pub fn checkAndVote(
        self: *LatestValidatorVotesForFrozenBanks,
        vote_pubkey: Pubkey,
        frozend_hash: ?Hash,
        is_replay_vote: bool,
    ) struct { bool, ?Slot } {
        _ = self;
        _ = vote_pubkey;
        _ = frozend_hash;
        _ = is_replay_vote;
        @panic("Unimplemented");
    }
};

pub const VoteAccount = struct {};

pub const StakedAccount = struct { stake: u64, account: VoteAccount };

const VotedSlotAndPubkey = struct { slot: Slot, pubkey: Pubkey };
pub const VoteAccountsHashMap = std.AutoHashMap(Pubkey, StakedAccount);
pub const ExpirationSlot = Slot;
// TODO modify SortedMap to allow array in value - support eq
pub const LockoutIntervals = SortedMap(ExpirationSlot, std.ArrayList(VotedSlotAndPubkey));

pub const TowerVoteState = struct {
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
