const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const Slot = sig.core.Slot;
const Vote = sig.runtime.program.vote_program.state.Vote;
const VoteStateUpdate = sig.runtime.program.vote_program.state.VoteStateUpdate;
const TowerSync = sig.runtime.program.vote_program.state.TowerSync;

const UnixTimestamp = i64;

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
