const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;

/// TODO: these decls should be moved into their own actual namespaces in the codebase eventually.
const commitment = struct {
    pub const VOTE_THRESHOLD_SIZE: f64 = 2.0 / 3.0;
};

pub const VoteTracker = struct {
    /// Protects all access to `map`, and partial access to its elements.
    ///
    /// Any direct mutation to, or direct read from, `map`, must first acquire
    /// an appropriate guard on this lock.
    ///
    /// Each entry of `map` is guarded by its own `rwlock`. In order to obtain
    /// a guard on any of the aformentioned locks, a guard on this map lock
    /// must first be acquired, and then the entry's lock may be acquired
    /// before releasing the guard on this lock (but not after).
    ///
    /// TODO: document whether a read guard on this map lock permits acquiring
    /// a write guard on the entry's lock lock, and other potential restrictions
    /// and/or allowances around safely accessing any data.
    map_rwlock: std.Thread.RwLock,

    /// Map from a slot to a set of validators who have voted for that slot.
    /// See the doc comment on `map_rwlock` for commentary on accessing this field and its contents.
    map: Map,

    pub const EMPTY: VoteTracker = .{
        .mutex = .{},
        .map = .{},
    };

    pub const Map = std.AutoArrayHashMapUnmanaged(Slot, RwMuxSlotVoteTracker);
    pub const RwMuxSlotVoteTracker = struct {
        rwlock: std.Thread.RwLock,
        tracker: SlotVoteTracker,

        pub const EMPTY_ZEROES: RwMuxSlotVoteTracker = .{
            .rwlock = .{},
            .tracker = SlotVoteTracker.EMPTY_ZEROES,
        };
    };

    pub fn deinit(self: *VoteTracker, allocator: std.mem.Allocator) void {
        self.map_rwlock.lock();
        defer self.map_rwlock.unlock();
        const map = &self.map;
        for (map.values()) |*svt| {
            svt.rwlock.lock();
            defer svt.rwlock.unlock();
            svt.tracker.deinit(allocator);
        }
        map.deinit(allocator);
    }

    /// TODO: investigate why this alias even exists in the agave code
    const progressWithNewRootBank = purgeStaleState;

    /// Purge any outdated slot data
    fn purgeStaleState(self: *VoteTracker, new_root_bank_slot: Slot) void {
        self.map_rwlock.lock();
        defer self.map_rwlock.unlock();
        const map = &self.map;

        var start_idx: usize = 0;
        outer: while (start_idx != map.count()) {
            for (map.keys()[start_idx..], start_idx..) |slot, i| {
                if (slot >= new_root_bank_slot) continue;
                std.debug.assert(map.swapRemove(slot));
                start_idx = i;
                continue :outer;
            }
        }
    }

    /// NOTE: intended for tests
    pub fn insertVote(
        self: *const VoteTracker,
        allocator: std.mem.Allocator,
        slot: Slot,
        pubkey: Pubkey,
    ) !void {
        if (!builtin.is_test) @compileError(@src().fn_name ++ " can only be used in tests.");

        self.map_rwlock.lock();
        defer self.map_rwlock.unlock();
        const map = &self.map;

        const gop = try map.getOrPut(allocator, slot);
        errdefer if (!gop.found_existing) std.debug.assert(map.pop().key == slot);
        if (!gop.found_existing) gop.value_ptr.* = RwMuxSlotVoteTracker.EMPTY_ZEROES;
        const w_slot_vote_tracker = &gop.value_ptr.tracker;

        map.lockPointers();
        defer map.unlockPointers();

        const voted = &w_slot_vote_tracker.voted;
        errdefer if (!gop.found_existing) voted.deinit(allocator);

        const voted_slot_updates = w_slot_vote_tracker.initAndOrGetUpdates();
        errdefer if (!gop.found_existing) voted_slot_updates.deinit(allocator);

        if (!voted.contains(pubkey)) try voted.ensureUnusedCapacity(allocator, 1);
        try voted_slot_updates.ensureUnusedCapacity(allocator, 1);

        voted.putAssumeCapacity(pubkey, true);
        voted_slot_updates.appendAssumeCapacity(pubkey);
    }
};

pub const SlotVoteTracker = struct {
    /// Maps pubkeys that have voted for this slot
    /// to whether or not we've seen the vote on gossip.
    /// True if seen on gossip, false if only seen in replay.
    voted: std.AutoArrayHashMapUnmanaged(Pubkey, bool),
    optimistic_votes_tracker: std.AutoArrayHashMapUnmanaged(Hash, VoteStakeTracker),
    voted_slot_updates: ?std.ArrayListUnmanaged(Pubkey),
    gossip_only_stake: u64,

    pub const EMPTY_ZEROES: SlotVoteTracker = .{
        .voted = .{},
        .optimistic_votes_tracker = .{},
        .voted_slot_updates = null,
        .gossip_only_stake = 0,
    };

    pub fn deinit(self: SlotVoteTracker, allocator: std.mem.Allocator) void {
        var copy = self;
        copy.voted.deinit(allocator);
        copy.optimistic_votes_tracker.deinit(allocator);
        copy.initAndOrGetUpdates().deinit(allocator);
    }

    /// If there already are vote slot updates, returns the pointer to them.
    /// Otherwise, initializes them, and then returns the pointer.
    pub fn initAndOrGetUpdates(self: *SlotVoteTracker) *std.ArrayListUnmanaged(Pubkey) {
        return &self.voted_slot_updates orelse blk: {
            self.voted_slot_updates = .{};
            break :blk &self.voted_slot_updates.?;
        };
    }

    /// Take the current voted slot updates, i.e. returns `self.voted_slot_updates` and sets the field to null.
    pub fn takeUpdates(self: *SlotVoteTracker) ?std.ArrayListUnmanaged(Pubkey) {
        const vsu = self.voted_slot_updates orelse return null;
        self.voted_slot_updates = null;
        return vsu;
    }
};

pub const VoteStakeTracker = struct {
    voted: std.AutoArrayHashMapUnmanaged(Pubkey, void),
    stake: u64,

    pub const EMPTY_ZEROES: VoteStakeTracker = .{
        .voted = .{},
        .stake = 0,
    };

    pub fn deinit(self: VoteStakeTracker, allocator: std.mem.Allocator) void {
        var voted = self.voted;
        voted.deinit(allocator);
    }

    /// Returns tuple (reached_threshold_results, is_new) where
    /// Each index in `reached_threshold_results` is true if the corresponding threshold in the input
    /// `thresholds_to_check` was newly reached by adding the stake of the input `vote_pubkey`
    /// `is_new` is true if the vote has not been seen before.
    ///
    /// The caller is responsible for freeing `reached_threshold_results` using `allocator`.
    pub fn addVotePubkey(
        self: *VoteStakeTracker,
        allocator: std.mem.Allocator,
        vote_pubkey: Pubkey,
        stake: u64,
        total_stake: u64,
        thresholds_to_check: []const f64,
    ) std.mem.Allocator.Error!struct { []const bool, bool } {
        const is_new = !self.voted.contains(vote_pubkey);
        if (is_new) {
            try self.voted.put(allocator, vote_pubkey, {});
            const old_stake = self.stake;
            const new_stake = self.stake + stake;
            self.stake = new_stake;

            const reached_threshold_results = try allocator.alloc(bool, thresholds_to_check.len);
            errdefer allocator.free(reached_threshold_results);

            const total_stake_f64: f64 = @floatFromInt(total_stake);
            for (reached_threshold_results, thresholds_to_check) |*result, threshold| {
                const threshold_stake: u64 = @intFromFloat(total_stake_f64 * threshold);
                result.* = old_stake <= threshold_stake and threshold_stake < new_stake;
            }

            return .{ reached_threshold_results, is_new };
        } else {
            const reached_threshold_results = try allocator.alloc(bool, thresholds_to_check.len);
            errdefer allocator.free(reached_threshold_results);

            @memset(reached_threshold_results, false);
            return .{ reached_threshold_results, is_new };
        }
    }
};

test "VoteStakeTracker.addVotePubkey" {
    const allocator = std.testing.allocator;

    var prng = std.rand.DefaultPrng.init(21410);
    const random = prng.random();

    const total_epoch_stake = 10;
    var vote_stake_tracker = VoteStakeTracker.EMPTY_ZEROES;
    defer vote_stake_tracker.deinit(allocator);

    for (0..10) |i| {
        const pubkey = Pubkey.initRandom(random);
        const is_confirmed_thresholds, //
        const is_new //
        = try vote_stake_tracker.addVotePubkey(
            allocator,
            pubkey,
            1,
            total_epoch_stake,
            &.{ commitment.VOTE_THRESHOLD_SIZE, 0.0 },
        );
        defer allocator.free(is_confirmed_thresholds);

        const stake = vote_stake_tracker.stake;

        const is_confirmed_thresholds2, //
        const is_new2 //
        = try vote_stake_tracker.addVotePubkey(
            allocator,
            pubkey,
            1,
            total_epoch_stake,
            &.{ commitment.VOTE_THRESHOLD_SIZE, 0.0 },
        );
        defer allocator.free(is_confirmed_thresholds2);

        const stake2 = vote_stake_tracker.stake;

        // Stake should not change from adding same pubkey twice
        try std.testing.expectEqual(stake, stake2);
        try std.testing.expectEqual(2, is_confirmed_thresholds.len);
        try std.testing.expectEqual(2, is_confirmed_thresholds2.len);
        try std.testing.expect(!is_new2);
        try std.testing.expect(!is_confirmed_thresholds2[0]);
        try std.testing.expect(!is_confirmed_thresholds2[1]);

        // at i == 6, the voted stake is 70%, which is the first time crossing
        // the supermajority threshold
        if (i == 6) {
            try std.testing.expect(is_confirmed_thresholds[0]);
        } else {
            try std.testing.expect(!is_confirmed_thresholds[0]);
        }

        // at i == 6, the voted stake is 10%, which is the first time crossing
        // the 0% threshold
        if (i == 0) {
            try std.testing.expect(is_confirmed_thresholds[1]);
        } else {
            try std.testing.expect(!is_confirmed_thresholds[1]);
        }
        try std.testing.expect(is_new);
    }
}
