const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const Slot = sig.core.Slot;
const Vote = sig.runtime.program.vote.state.Vote;
const VoteStateUpdate = sig.runtime.program.vote.state.VoteStateUpdate;
const TowerSync = sig.runtime.program.vote.state.TowerSync;

const UnixTimestamp = i64;

pub const VoteTransaction = union(enum) {
    vote: Vote,
    vote_state_update: VoteStateUpdate,
    compact_vote_state_update: VoteStateUpdate,
    tower_sync: TowerSync,

    pub const DEFAULT: VoteTransaction = .{ .tower_sync = TowerSync.ZEROES };

    pub fn deinit(self: VoteTransaction, allocator: std.mem.Allocator) void {
        switch (self) {
            .vote => |args| args.deinit(allocator),
            .vote_state_update => |args| args.deinit(allocator),
            .compact_vote_state_update => |args| args.deinit(allocator),
            .tower_sync => |args| args.deinit(allocator),
        }
    }

    pub fn timestamp(self: *const VoteTransaction) ?UnixTimestamp {
        return switch (self.*) {
            inline //
            .vote,
            .vote_state_update,
            .compact_vote_state_update,
            .tower_sync,
            => |args| args.timestamp,
        };
    }

    pub fn setTimestamp(self: *VoteTransaction, ts: ?UnixTimestamp) void {
        switch (self.*) {
            inline //
            .vote,
            .vote_state_update,
            .compact_vote_state_update,
            .tower_sync,
            => |*ptr| ptr.timestamp = ts,
        }
    }

    pub fn getHash(self: *const VoteTransaction) Hash {
        return switch (self.*) {
            inline //
            .vote,
            .vote_state_update,
            .compact_vote_state_update,
            .tower_sync,
            => |args| args.hash,
        };
    }

    pub fn isEmpty(self: *const VoteTransaction) bool {
        return self.slotCount() == 0;
    }

    pub fn slotCount(self: *const VoteTransaction) usize {
        return switch (self.*) {
            .vote => |vote| vote.slots.len,
            inline //
            .vote_state_update,
            .compact_vote_state_update,
            .tower_sync,
            => |args| args.lockouts.items.len,
        };
    }

    /// Asserts `index < self.slotCount()`.
    pub fn getSlot(self: *const VoteTransaction, index: usize) Slot {
        return switch (self.*) {
            .vote => |vote| vote.slots[index],
            inline //
            .vote_state_update,
            .compact_vote_state_update,
            .tower_sync,
            => |args| args.lockouts.items[index].slot,
        };
    }

    pub fn lastVotedSlot(self: *const VoteTransaction) ?Slot {
        const slot_count = self.slotCount();
        if (slot_count == 0) return null;
        return self.getSlot(slot_count - 1);
    }

    pub fn isFullTowerVote(self: *const VoteTransaction) bool {
        return switch (self.*) {
            .vote_state_update, .tower_sync => true,
            else => false,
        };
    }

    /// Asserts `slots.len == self.slotCount()`.
    /// Copies all slots from `self` to `slots`.
    pub fn copyAllSlotsTo(
        self: *const VoteTransaction,
        slots: []Slot,
    ) void {
        switch (self.*) {
            .vote => |vote| @memcpy(slots, vote.slots),
            inline //
            .vote_state_update,
            .compact_vote_state_update,
            .tower_sync,
            => |args| for (slots, args.lockouts.items) |*slot, lockout| {
                slot.* = lockout.slot;
            },
        }
    }

    pub fn eql(self: *const VoteTransaction, other: *const VoteTransaction) bool {
        if (@intFromEnum(self.*) != @intFromEnum(other.*)) return false;
        switch (self.*) {
            .vote => |self_vote| {
                const other_vote = other.vote;
                return self_vote.timestamp == other_vote.timestamp and
                    self_vote.hash.eql(other_vote.hash) and
                    std.mem.eql(Slot, self_vote.slots, other_vote.slots);
            },
            inline //
            .vote_state_update,
            .compact_vote_state_update,
            .tower_sync,
            => |self_pl, tag| {
                const other_pl = @field(other, @tagName(tag));
                if (self_pl.lockouts.items.len != other_pl.lockouts.items.len or
                    self_pl.timestamp != other_pl.timestamp or
                    !self_pl.hash.eql(other_pl.hash) //
                ) return false;
                for (self_pl.lockouts.items, other_pl.lockouts.items) |self_lo, other_lo| {
                    if (self_lo.slot != other_lo.slot or
                        self_lo.confirmation_count != other_lo.confirmation_count //
                    ) return false;
                }
                return true;
            },
        }
    }
};

const Lockout = sig.runtime.program.vote.state.Lockout;
test "vote_transaction.VoteTransaction - default initialization" {
    var vote_transaction = VoteTransaction.DEFAULT;
    defer vote_transaction.deinit(std.testing.allocator);

    try std.testing.expectEqual(
        VoteTransaction{ .tower_sync = TowerSync.ZEROES },
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

    var visual_state_update_diff = VoteTransaction{ .vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout).initCapacity(std.testing.allocator, 3),
        .hash = Hash.ZEROES,
        .timestamp = 200,
        .root = 1,
    } };
    defer visual_state_update_diff.deinit(std.testing.allocator);
    try std.testing.expect(visual_state_update1.eql(&visual_state_update2));
    try std.testing.expect(!visual_state_update1.eql(&visual_state_update_diff));

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

    var compact_visual_state_update_diff = VoteTransaction{ .compact_vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout).initCapacity(std.testing.allocator, 3),
        .hash = Hash.ZEROES,
        .timestamp = 200,
        .root = 1,
    } };
    defer compact_visual_state_update_diff.deinit(std.testing.allocator);
    try std.testing.expect(compact_visual_state_update1.eql(&compact_visual_state_update2));
    try std.testing.expect(!compact_visual_state_update1.eql(&compact_visual_state_update_diff));

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

    var tower_sync_diff = VoteTransaction{ .tower_sync = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout).initCapacity(std.testing.allocator, 3),
        .hash = Hash.ZEROES,
        .timestamp = 200,
        .root = 1,
        .block_id = Hash.ZEROES,
    } };
    defer tower_sync_diff.deinit(std.testing.allocator);

    try std.testing.expect(tower_sync1.eql(&tower_sync2));
    try std.testing.expect(!tower_sync1.eql(&tower_sync_diff));

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

test "vote_transaction.VoteTransaction - isEmpty" {
    const empty_vote = VoteTransaction{ .vote = .{
        .slots = &[_]Slot{},
        .hash = Hash.ZEROES,
        .timestamp = null,
    } };
    try std.testing.expect(empty_vote.isEmpty());

    const vote = VoteTransaction{ .vote = .{
        .slots = &[_]Slot{ 1, 2, 3 },
        .hash = Hash.ZEROES,
        .timestamp = null,
    } };
    try std.testing.expect(!vote.isEmpty());

    var vote_state_update = VoteTransaction{ .vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
    } };
    defer vote_state_update.deinit(std.testing.allocator);
    try std.testing.expect(vote_state_update.isEmpty());

    vote_state_update.vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 10, .confirmation_count = 1 },
    );
    try std.testing.expect(!vote_state_update.isEmpty());

    var compact_vote_state_update = VoteTransaction{ .compact_vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
    } };
    defer compact_vote_state_update.deinit(std.testing.allocator);
    try std.testing.expect(compact_vote_state_update.isEmpty());
    compact_vote_state_update.compact_vote_state_update.lockouts.appendAssumeCapacity(
        .{ .slot = 10, .confirmation_count = 1 },
    );
    try std.testing.expect(!compact_vote_state_update.isEmpty());

    var towe_sync = VoteTransaction{ .tower_sync = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = Hash.ZEROES,
        .timestamp = null,
        .root = 100,
        .block_id = Hash.ZEROES,
    } };
    defer towe_sync.deinit(std.testing.allocator);
    try std.testing.expect(towe_sync.isEmpty());
    towe_sync.tower_sync.lockouts.appendAssumeCapacity(
        .{ .slot = 10, .confirmation_count = 1 },
    );
    try std.testing.expect(!towe_sync.isEmpty());
}

test "vote_transaction.VoteTransaction - slot access" {
    const vote = VoteTransaction{ .vote = .{
        .slots = &[_]Slot{ 10, 20, 30 },
        .hash = Hash.ZEROES,
        .timestamp = null,
    } };
    try std.testing.expectEqual(10, vote.getSlot(0));
    try std.testing.expectEqual(20, vote.getSlot(1));
    try std.testing.expectEqual(30, vote.getSlot(2));

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
    try std.testing.expectEqual(10, vote_state_update.getSlot(0));
    try std.testing.expectEqual(20, vote_state_update.getSlot(1));

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
    try std.testing.expectEqual(10, compact_vote_state_update.getSlot(0));
    try std.testing.expectEqual(20, compact_vote_state_update.getSlot(1));

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
    try std.testing.expectEqual(10, tower_sync.getSlot(0));
    try std.testing.expectEqual(20, tower_sync.getSlot(1));
}

test "vote_transaction.VoteTransaction - length" {
    const vote = VoteTransaction{ .vote = .{
        .slots = &[_]Slot{ 1, 2, 3 },
        .hash = Hash.ZEROES,
        .timestamp = null,
    } };
    try std.testing.expectEqual(3, vote.slotCount());

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
    try std.testing.expectEqual(2, vote_state_update.slotCount());

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
    try std.testing.expectEqual(2, compact_vote_state_update.slotCount());

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
    try std.testing.expectEqual(2, tower_sync.slotCount());
}

test "vote_transaction.VoteTransaction - hash" {
    const test_hash = Hash.ZEROES;
    const vote = VoteTransaction{ .vote = .{
        .slots = &[_]Slot{},
        .hash = test_hash,
        .timestamp = null,
    } };
    try std.testing.expect(test_hash.eql(vote.getHash()));

    var vote_state_update = VoteTransaction{ .vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = test_hash,
        .timestamp = null,
        .root = 100,
    } };
    defer vote_state_update.deinit(std.testing.allocator);
    try std.testing.expect(test_hash.eql(vote_state_update.getHash()));

    var compact_vote_state_update = VoteTransaction{ .compact_vote_state_update = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = test_hash,
        .timestamp = null,
        .root = 100,
    } };
    defer compact_vote_state_update.deinit(std.testing.allocator);
    try std.testing.expect(test_hash.eql(compact_vote_state_update.getHash()));

    var tower_sync = VoteTransaction{ .tower_sync = .{
        .lockouts = try std.ArrayListUnmanaged(Lockout)
            .initCapacity(std.testing.allocator, 2),
        .hash = test_hash,
        .timestamp = null,
        .root = 100,
        .block_id = Hash.ZEROES,
    } };
    defer tower_sync.deinit(std.testing.allocator);
    try std.testing.expect(test_hash.eql(tower_sync.getHash()));
}
