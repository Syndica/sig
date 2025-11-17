const std = @import("std");
const sig = @import("../sig.zig");

const Slot = sig.core.Slot;
const Lockout = sig.runtime.program.vote.state.Lockout;
const MAX_LOCKOUT_HISTORY = sig.runtime.program.vote.state.MAX_LOCKOUT_HISTORY;
const VoteAccount = sig.core.stakes.VoteAccount;

pub const TowerVoteState = struct {
    root_slot: ?Slot = null,
    votes: std.BoundedArray(Lockout, MAX_LOCKOUT_HISTORY) = .{},

    pub fn fromAccount(account: *const VoteAccount) !TowerVoteState {
        const vote_state = account.state;
        var lockouts: std.BoundedArray(Lockout, MAX_LOCKOUT_HISTORY) = .{};
        for (vote_state.votes.items) |landed| {
            try lockouts.append(.{
                .slot = landed.lockout.slot,
                .confirmation_count = landed.lockout.confirmation_count,
            });
        }
        return .{
            .root_slot = vote_state.root_slot,
            .votes = lockouts,
        };
    }

    pub fn lastLockout(self: *const TowerVoteState) ?Lockout {
        if (self.votes.len == 0) return null;
        return self.votes.get(self.votes.len - 1);
    }

    pub fn lastVotedSlot(self: *const TowerVoteState) ?Slot {
        return if (self.lastLockout()) |last_lockout| last_lockout.slot else null;
    }

    pub fn nthRecentLockout(self: *const TowerVoteState, position: usize) ?Lockout {
        const pos = std.math.sub(usize, self.votes.len, (position +| 1)) catch
            return null;
        return self.votes.get(pos);
    }

    pub fn processNextVoteSlot(
        self: *TowerVoteState,
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
                _ = self.votes.pop();
            } else {
                break;
            }
        }
    }

    fn doubleLockouts(self: *TowerVoteState) !void {
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
