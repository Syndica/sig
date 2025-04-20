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
    compact_vote_state_update: VoteStateUpdate,
    tower_sync: TowerSync,

    pub fn default(allocator: std.mem.Allocator) !VoteTransaction {
        return VoteTransaction{ .tower_sync = try TowerSync.default(allocator) };
    }

    pub fn deinit(self: *VoteTransaction, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .vote => |_| {},
            .vote_state_update => |*args| args.lockouts.deinit(allocator),
            .compact_vote_state_update => |*args| args.lockouts.deinit(allocator),
            .tower_sync => |*args| args.lockouts.deinit(allocator),
        }
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
            .vote => |args| if (args.slots.len == 0)
                null
            else
                args.slots[args.slots.len - 1],
            .vote_state_update => |args| if (args.lockouts.items.len == 0)
                null
            else
                args.lockouts.items[args.lockouts.items.len - 1].slot,
            .compact_vote_state_update => |args| if (args.lockouts.items.len == 0)
                null
            else
                args.lockouts.items[args.lockouts.items.len - 1].slot,
            .tower_sync => |args| if (args.lockouts.items.len == 0)
                null
            else
                args.lockouts.items[args.lockouts.items.len - 1].slot,
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
        if (@intFromEnum(self.*) != @intFromEnum(other.*)) {
            return false;
        }

        return switch (self.*) {
            .vote => |self_vote| {
                const other_vote = other.vote;
                return std.mem.eql(Slot, self_vote.slots, other_vote.slots) and
                    self_vote.hash.eql(other_vote.hash) and
                    self_vote.timestamp == other_vote.timestamp;
            },
            .vote_state_update => |self_vsu| {
                const other_vsu = other.vote_state_update;
                if (self_vsu.lockouts.items.len != other_vsu.lockouts.items.len or
                    !self_vsu.hash.eql(other_vsu.hash) or
                    self_vsu.timestamp != other_vsu.timestamp)
                {
                    return false;
                }
                for (
                    self_vsu.lockouts.items,
                    other_vsu.lockouts.items,
                ) |self_lockout, other_lockout| {
                    if (self_lockout.slot != other_lockout.slot or
                        self_lockout.confirmation_count != other_lockout.confirmation_count)
                    {
                        return false;
                    }
                }
                return true;
            },
            .compact_vote_state_update => |self_vsu| {
                const other_vsu = other.compact_vote_state_update;
                if (self_vsu.lockouts.items.len != other_vsu.lockouts.items.len or
                    !self_vsu.hash.eql(other_vsu.hash) or
                    self_vsu.timestamp != other_vsu.timestamp)
                {
                    return false;
                }
                for (
                    self_vsu.lockouts.items,
                    other_vsu.lockouts.items,
                ) |self_lockout, other_lockout| {
                    if (self_lockout.slot != other_lockout.slot or
                        self_lockout.confirmation_count != other_lockout.confirmation_count)
                    {
                        return false;
                    }
                }
                return true;
            },
            .tower_sync => |self_ts| {
                const other_ts = other.tower_sync;
                if (self_ts.lockouts.items.len != other_ts.lockouts.items.len or
                    !self_ts.hash.eql(other_ts.hash) or
                    self_ts.timestamp != other_ts.timestamp)
                {
                    return false;
                }
                for (
                    self_ts.lockouts.items,
                    other_ts.lockouts.items,
                ) |self_lockout, other_lockout| {
                    if (self_lockout.slot != other_lockout.slot or
                        self_lockout.confirmation_count != other_lockout.confirmation_count)
                    {
                        return false;
                    }
                }
                return true;
            },
        };
    }
};

const Lockout = sig.runtime.program.vote_program.state.Lockout;
test "vote_transaction.VoteTransaction - default initialization" {
    var vote_transaction = try VoteTransaction.default(std.testing.allocator);
    defer vote_transaction.deinit(std.testing.allocator);

    try std.testing.expectEqual(
        VoteTransaction{ .tower_sync = try TowerSync.default(std.testing.allocator) },
        vote_transaction,
    );
}

test "vote_transaction.VoteTransaction - variant equality" {
    // Test vote equality
    const vote1 = VoteTransaction{ .vote = .{
        .slots = &[_]Slot{ 1, 2, 3 },
        .hash = Hash.ZEROES,
        .timestamp = 100,
    } };
    const vote2 = VoteTransaction{ .vote = .{
        .slots = &[_]Slot{ 1, 2, 3 },
        .hash = Hash.ZEROES,
        .timestamp = 100,
    } };
    const vote_diff = VoteTransaction{ .vote = .{
        .slots = &[_]Slot{ 1, 2 },
        .hash = Hash.ZEROES,
        .timestamp = 100,
    } };
    try std.testing.expect(vote1.eql(&vote2));
    try std.testing.expect(!vote1.eql(&vote_diff));

    // Test vote_state_update equality
    var visual_state_update1 = VoteTransaction{ .vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout).initCapacity(std.testing.allocator, 3),
        .hash = Hash.ZEROES,
        .timestamp = 200,
        .root = 1,
    } };
    defer visual_state_update1.deinit(std.testing.allocator);
    visual_state_update1.vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 1, .confirmation_count = 1 },
    );
    visual_state_update1.vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 2, .confirmation_count = 2 },
    );

    var visual_state_update2 = VoteTransaction{ .vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout).initCapacity(std.testing.allocator, 3),
        .hash = Hash.ZEROES,
        .timestamp = 200,
        .root = 1,
    } };
    defer visual_state_update2.deinit(std.testing.allocator);
    visual_state_update2.vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 1, .confirmation_count = 1 },
    );
    visual_state_update2.vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 2, .confirmation_count = 2 },
    );

    // Test vote_state_update equality
    var compact_visual_state_update1 = VoteTransaction{ .compact_vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout).initCapacity(std.testing.allocator, 3),
        .hash = Hash.ZEROES,
        .timestamp = 200,
        .root = 1,
    } };
    defer compact_visual_state_update1.deinit(std.testing.allocator);
    compact_visual_state_update1.compact_vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 1, .confirmation_count = 1 },
    );
    compact_visual_state_update1.compact_vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 2, .confirmation_count = 2 },
    );

    var compact_visual_state_update2 = VoteTransaction{ .compact_vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout).initCapacity(std.testing.allocator, 3),
        .hash = Hash.ZEROES,
        .timestamp = 200,
        .root = 1,
    } };
    defer compact_visual_state_update2.deinit(std.testing.allocator);
    compact_visual_state_update2.compact_vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 1, .confirmation_count = 1 },
    );
    compact_visual_state_update2.compact_vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 2, .confirmation_count = 2 },
    );

    // Test tower_sync equality
    var tower_sync1 = VoteTransaction{ .tower_sync = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout).initCapacity(std.testing.allocator, 3),
        .hash = Hash.ZEROES,
        .timestamp = 200,
        .root = 1,
        .block_id = Hash.ZEROES,
    } };
    defer tower_sync1.deinit(std.testing.allocator);
    tower_sync1.tower_sync.lockouts.appendAssumeCapacity(
        .{ .slot = 1, .confirmation_count = 1 },
    );
    tower_sync1.tower_sync.lockouts.appendAssumeCapacity(
        .{ .slot = 2, .confirmation_count = 2 },
    );

    var tower_sync2 = VoteTransaction{ .tower_sync = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout).initCapacity(std.testing.allocator, 3),
        .hash = Hash.ZEROES,
        .timestamp = 200,
        .root = 1,
        .block_id = Hash.ZEROES,
    } };
    defer tower_sync2.deinit(std.testing.allocator);
    tower_sync2.tower_sync.lockouts.appendAssumeCapacity(
        .{ .slot = 1, .confirmation_count = 1 },
    );
    tower_sync2.tower_sync.lockouts.appendAssumeCapacity(
        .{ .slot = 2, .confirmation_count = 2 },
    );

    try std.testing.expect(compact_visual_state_update1.eql(&compact_visual_state_update2));

    // Test different variant inequality
    try std.testing.expect(!vote1.eql(&visual_state_update1));
}

test "vote_transaction.VoteTransaction - timestamp operations" {
    var vote = VoteTransaction{ .vote = .{
        .slots = &[_]Slot{1},
        .hash = Hash.ZEROES,
        .timestamp = null,
    } };

    try std.testing.expectEqual(@as(?UnixTimestamp, null), vote.timestamp());

    vote.setTimestamp(100);
    try std.testing.expectEqual(@as(?UnixTimestamp, 100), vote.timestamp());

    var vote_state_updated = VoteTransaction{ .vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 0),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
    } };

    try std.testing.expectEqual(@as(?UnixTimestamp, null), vote_state_updated.timestamp());

    vote_state_updated.setTimestamp(100);
    try std.testing.expectEqual(@as(?UnixTimestamp, 100), vote_state_updated.timestamp());

    var compact_vote_state_updated = VoteTransaction{ .compact_vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 0),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
    } };

    try std.testing.expectEqual(
        @as(?UnixTimestamp, null),
        compact_vote_state_updated.timestamp(),
    );

    compact_vote_state_updated.setTimestamp(100);
    try std.testing.expectEqual(
        @as(?UnixTimestamp, 100),
        compact_vote_state_updated.timestamp(),
    );

    var tower_sync = VoteTransaction{ .tower_sync = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 0),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
        .block_id = Hash.ZEROES,
    } };

    try std.testing.expectEqual(
        @as(?UnixTimestamp, null),
        tower_sync.timestamp(),
    );

    tower_sync.setTimestamp(100);
    try std.testing.expectEqual(
        @as(?UnixTimestamp, 100),
        tower_sync.timestamp(),
    );
}

test "vote_transaction.VoteTransaction - lastVotedSlot" {
    const empty_vote = VoteTransaction{ .vote = .{
        .slots = &[_]Slot{},
        .hash = Hash.ZEROES,
        .timestamp = null,
    } };
    try std.testing.expectEqual(null, empty_vote.lastVotedSlot());

    const vote = VoteTransaction{ .vote = .{
        .slots = &[_]Slot{ 1, 2, 3 },
        .hash = Hash.ZEROES,
        .timestamp = null,
    } };
    try std.testing.expectEqual(3, vote.lastVotedSlot());

    var vote_state_update = VoteTransaction{ .vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
    } };
    defer vote_state_update.deinit(std.testing.allocator);
    vote_state_update.vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 10, .confirmation_count = 1 },
    );
    vote_state_update.vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 20, .confirmation_count = 2 },
    );
    try std.testing.expectEqual(20, vote_state_update.lastVotedSlot());

    var compact_vote_state_update = VoteTransaction{ .compact_vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
    } };
    defer compact_vote_state_update.deinit(std.testing.allocator);
    compact_vote_state_update.compact_vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 10, .confirmation_count = 1 },
    );
    compact_vote_state_update.compact_vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 20, .confirmation_count = 2 },
    );
    try std.testing.expectEqual(20, compact_vote_state_update.lastVotedSlot());

    var towe_sync = VoteTransaction{ .tower_sync = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
        .block_id = Hash.ZEROES,
    } };
    defer towe_sync.deinit(std.testing.allocator);
    towe_sync.tower_sync.lockouts.appendAssumeCapacity(
        .{ .slot = 10, .confirmation_count = 1 },
    );
    towe_sync.tower_sync.lockouts.appendAssumeCapacity(
        .{ .slot = 20, .confirmation_count = 2 },
    );
    try std.testing.expectEqual(20, towe_sync.lastVotedSlot());
}

test "vote_transaction.VoteTransaction - slot access" {
    const vote = VoteTransaction{ .vote = .{
        .slots = &[_]Slot{ 10, 20, 30 },
        .hash = Hash.ZEROES,
        .timestamp = null,
    } };
    try std.testing.expectEqual(10, vote.slot(0));
    try std.testing.expectEqual(20, vote.slot(1));
    try std.testing.expectEqual(30, vote.slot(2));

    var vote_state_update = VoteTransaction{ .vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
    } };
    defer vote_state_update.deinit(std.testing.allocator);
    vote_state_update.vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 10, .confirmation_count = 1 },
    );
    vote_state_update.vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 20, .confirmation_count = 2 },
    );
    try std.testing.expectEqual(10, vote_state_update.slot(0));
    try std.testing.expectEqual(20, vote_state_update.slot(1));

    var compact_vote_state_update = VoteTransaction{ .compact_vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
    } };
    defer compact_vote_state_update.deinit(std.testing.allocator);
    compact_vote_state_update.compact_vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 10, .confirmation_count = 1 },
    );
    compact_vote_state_update.compact_vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 20, .confirmation_count = 2 },
    );
    try std.testing.expectEqual(10, compact_vote_state_update.slot(0));
    try std.testing.expectEqual(20, compact_vote_state_update.slot(1));

    var tower_sync = VoteTransaction{ .tower_sync = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
        .block_id = Hash.ZEROES,
    } };
    defer tower_sync.deinit(std.testing.allocator);
    tower_sync.tower_sync.lockouts.appendAssumeCapacity(
        .{ .slot = 10, .confirmation_count = 1 },
    );
    tower_sync.tower_sync.lockouts.appendAssumeCapacity(
        .{ .slot = 20, .confirmation_count = 2 },
    );
    try std.testing.expectEqual(10, tower_sync.slot(0));
    try std.testing.expectEqual(20, tower_sync.slot(1));
}

test "vote_transaction.VoteTransaction - length" {
    const vote = VoteTransaction{ .vote = .{
        .slots = &[_]Slot{ 1, 2, 3 },
        .hash = Hash.ZEROES,
        .timestamp = null,
    } };
    try std.testing.expectEqual(3, vote.len());

    var vote_state_update = VoteTransaction{ .vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
    } };
    defer vote_state_update.deinit(std.testing.allocator);

    vote_state_update.vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 1, .confirmation_count = 1 },
    );
    vote_state_update.vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 2, .confirmation_count = 2 },
    );
    try std.testing.expectEqual(2, vote_state_update.len());

    var compact_vote_state_update = VoteTransaction{ .compact_vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
    } };
    defer compact_vote_state_update.deinit(std.testing.allocator);

    compact_vote_state_update.compact_vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 1, .confirmation_count = 1 },
    );
    compact_vote_state_update.compact_vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 2, .confirmation_count = 2 },
    );
    try std.testing.expectEqual(2, compact_vote_state_update.len());

    var tower_sync = VoteTransaction{ .tower_sync = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
        .block_id = Hash.ZEROES,
    } };
    defer tower_sync.deinit(std.testing.allocator);

    tower_sync.tower_sync.lockouts.appendAssumeCapacity(
        .{ .slot = 1, .confirmation_count = 1 },
    );
    tower_sync.tower_sync.lockouts.appendAssumeCapacity(
        .{ .slot = 2, .confirmation_count = 2 },
    );
    try std.testing.expectEqual(2, tower_sync.len());
}

test "vote_transaction.VoteTransaction - hash" {
    const test_hash = Hash.ZEROES;
    const vote = VoteTransaction{ .vote = .{
        .slots = &[_]Slot{},
        .hash = test_hash,
        .timestamp = null,
    } };
    try std.testing.expect(test_hash.eql(vote.hash()));

    var vote_state_update = VoteTransaction{ .vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = test_hash,
        .timestamp = null,
        .root = 100,
    } };
    defer vote_state_update.deinit(std.testing.allocator);
    try std.testing.expect(test_hash.eql(vote_state_update.hash()));

    var compact_vote_state_update = VoteTransaction{ .compact_vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = test_hash,
        .timestamp = null,
        .root = 100,
    } };
    defer compact_vote_state_update.deinit(std.testing.allocator);
    try std.testing.expect(test_hash.eql(compact_vote_state_update.hash()));

    var tower_sync = VoteTransaction{ .tower_sync = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = test_hash,
        .timestamp = null,
        .root = 100,
        .block_id = Hash.ZEROES,
    } };
    defer tower_sync.deinit(std.testing.allocator);
    try std.testing.expect(test_hash.eql(tower_sync.hash()));
}
