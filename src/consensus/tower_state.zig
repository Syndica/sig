const std = @import("std");
const sig = @import("../sig.zig");

const Slot = sig.core.Slot;
const Lockout = sig.runtime.program.vote_program.state.Lockout;
const Account = sig.core.Account;
const MAX_LOCKOUT_HISTORY = sig.runtime.program.vote_program.state.MAX_LOCKOUT_HISTORY;

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

    pub fn deinit(self: *TowerVoteState, allocator: std.mem.Allocator) void {
        self.votes.deinit(allocator);
    }

    pub fn fromAccount(account: *const Account) TowerVoteState {
        _ = account;
        @panic("Unimplemented");
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
