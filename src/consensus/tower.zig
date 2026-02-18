const std = @import("std");
const sig = @import("../sig.zig");

const LockoutIntervals = sig.consensus.replay_tower.LockoutIntervals;
const Lockout = sig.runtime.program.vote.state.Lockout;
const VotedStakes = sig.consensus.progress_map.consensus.VotedStakes;
const Ancestors = sig.core.Ancestors;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const TowerStorage = sig.consensus.tower_storage.TowerStorage;

pub const MAX_LOCKOUT_HISTORY = sig.runtime.program.vote.state.MAX_LOCKOUT_HISTORY;

pub const Stake = u64;

pub const VotedSlot = Slot;

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

pub const ThresholdDecision = union(enum) {
    passed_threshold,
    failed_threshold: FailedThreshold,

    pub const FailedThreshold = struct {
        vote_depth: u64,
        observed_stake: u64,
    };

    pub fn eql(self: ThresholdDecision, other: ThresholdDecision) bool {
        return std.meta.eql(self, other);
    }
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
    /// Vote account is not owned by the vote program
    InvalidVoteAccountOwner,
};

pub const Tower = struct {
    root: ?Slot,
    votes: std.BoundedArray(Lockout, MAX_LOCKOUT_HISTORY) = .{},

    pub fn fromAccount(account_state: *const sig.runtime.program.vote.state.VoteStateV4) !Tower {
        var lockouts: std.BoundedArray(Lockout, MAX_LOCKOUT_HISTORY) = .{};
        for (account_state.votes.items) |landed| {
            try lockouts.append(.{
                .slot = landed.lockout.slot,
                .confirmation_count = landed.lockout.confirmation_count,
            });
        }
        return .{
            .root = account_state.root_slot,
            .votes = lockouts,
        };
    }

    pub fn setRoot(self: *Tower, new_root: Slot) void {
        self.root = new_root;

        // this slice is overwritten in place, but the loop capture stays ahead of those writes
        const stale_votes = self.votes.constSlice();
        self.votes.clear();
        for (stale_votes) |vote| {
            if (vote.slot > new_root) self.votes.appendAssumeCapacity(vote);
        }
    }

    /// Record a vote in the tower.
    /// Returns a new root slot when the oldest vote reaches maximum lockout.
    pub fn recordBankVoteAndUpdateLockouts(
        self: *Tower,
        vote_slot: Slot,
    ) !?Slot {
        if (self.lastVotedSlot()) |last_voted_sot| {
            if (vote_slot <= last_voted_sot) {
                return error.VoteTooOld;
            }
        }

        const old_root = try self.getRoot();

        try self.processNextVoteSlot(vote_slot);

        const new_root = try self.getRoot();

        if (old_root != new_root) {
            return new_root;
        } else {
            return null;
        }
    }

    pub fn towerSlots(self: *const Tower, allocator: std.mem.Allocator) ![]Slot {
        var slots = try allocator.alloc(Slot, self.votes.len);
        for (self.votes.constSlice(), 0..) |vote, i| {
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
        return if (self.root) |root| root else error.RootSlotMissing;
    }

    // a slot is recent if it's newer than the last vote we have. If we haven't voted yet
    // but have a root (hard forks situation) then compare it to the root
    pub fn isRecent(self: *const Tower, slot: Slot) bool {
        if (self.lastVotedSlot()) |last_voted_slot| {
            if (slot <= last_voted_slot) {
                return false;
            }
        } else if (self.root) |root| {
            if (slot <= root) {
                return false;
            }
        }
        return true;
    }

    pub fn hasVoted(self: *const Tower, slot: Slot) bool {
        for (self.votes.constSlice()) |vote| {
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
        ancestors: *const Ancestors,
    ) !bool {
        if (!self.isRecent(slot)) {
            return true;
        }

        // Check if a slot is locked out by simulating adding a vote for that
        // slot to the current lockouts to pop any expired votes. If any of the
        // remaining voted slots are on a different fork from the checked slot,
        // it's still locked out.
        var copy = self.*;

        try copy.processNextVoteSlot(slot);

        for (copy.votes.constSlice()) |vote| {
            if (slot != vote.slot and
                // This means the validator is trying to vote on a fork incompatible with previous votes.
                !ancestors.containsSlot(vote.slot))
            {
                return true;
            }
        }

        if (copy.root) |root| {
            if (slot != root
                // This case should never happen because bank forks purges all
                // non-descendants of the root every time root is set
            and !ancestors.containsSlot(root)) {
                return error.InvalidRootSlot;
            }
        }

        // Not locked out, vote safe to be casted.
        return false;
    }

    pub fn votedSlots(self: *const Tower, allocator: std.mem.Allocator) ![]Slot {
        var slots = try allocator.alloc(Slot, self.votes.len);
        for (self.votes.slice(), 0..) |lockout, i| {
            slots[i] = lockout.slot;
        }
        return slots;
    }

    pub fn restore(
        tower_storage: *const TowerStorage,
        node_pubkey: *const Pubkey,
    ) !Tower {
        return try tower_storage.load(node_pubkey);
    }

    pub fn lastLockout(self: *const Tower) ?Lockout {
        if (self.votes.len == 0) return null;
        return self.votes.get(self.votes.len - 1);
    }

    pub fn lastVotedSlot(self: *const Tower) ?Slot {
        return if (self.lastLockout()) |last_lockout| last_lockout.slot else null;
    }

    pub fn nthRecentLockout(self: *const Tower, position: usize) ?Lockout {
        const pos = std.math.sub(usize, self.votes.len, (position +| 1)) catch
            return null;
        return self.votes.get(pos);
    }

    pub fn processNextVoteSlot(
        self: *Tower,
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
        if (self.votes.len == MAX_LOCKOUT_HISTORY) {
            const rooted_vote = self.votes.orderedRemove(0);
            self.root = rooted_vote.slot;
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
    pub fn popExpiredVotes(self: *Tower, next_vote_slot: Slot) void {
        while (self.lastLockout()) |vote| {
            if (!vote.isLockedOutAtSlot(next_vote_slot)) {
                _ = self.votes.pop();
            } else {
                break;
            }
        }
    }

    fn doubleLockouts(self: *Tower) !void {
        const stack_depth = self.votes.len;

        for (self.votes.slice(), 0..) |*vote, i| {
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

test "isRecent with no votes checks root_slot" {
    // Set up tower with no votes but with a root
    var tower: Tower = .{ .root = 100 };

    // Slots at or before root should NOT be recent
    try std.testing.expect(!tower.isRecent(99));
    try std.testing.expect(!tower.isRecent(100));

    // Slots after root should be recent
    try std.testing.expect(tower.isRecent(101));
    try std.testing.expect(tower.isRecent(200));
}

test "isLockedOut with no votes and root" {
    const allocator = std.testing.allocator;

    var tower: Tower = .{ .root = 100 };

    // Create ancestors for a slot after root
    var ancestors_map: std.AutoArrayHashMapUnmanaged(Slot, void) = .empty;
    defer ancestors_map.deinit(allocator);

    // Slot 101 should have ancestors including the root (100)
    try ancestors_map.put(allocator, 100, {});
    try ancestors_map.put(allocator, 99, {});
    try ancestors_map.put(allocator, 98, {});

    const ancestors: Ancestors = .{ .ancestors = ancestors_map };

    // Slot 101 (after root, has root as ancestor) should NOT be locked out
    try std.testing.expect(!try tower.isLockedOut(101, &ancestors));

    // Slot 100 (the root itself) SHOULD be locked out (not recent, already finalized)
    try std.testing.expect(try tower.isLockedOut(100, &ancestors));

    // Slot 99 (before root) SHOULD be locked out (not recent)
    try std.testing.expect(try tower.isLockedOut(99, &ancestors));
}
