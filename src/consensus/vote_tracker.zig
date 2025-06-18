const std = @import("std");
const sig = @import("../sig.zig");
const builtin = @import("builtin");

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;

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
    map: std.AutoArrayHashMapUnmanaged(Slot, *RcRwSlotVoteTracker),

    pub const EMPTY: VoteTracker = .{
        .map_rwlock = .{},
        .map = .{},
    };

    pub const RcRwSlotVoteTracker = struct {
        /// Must call `rc.acquire()` before sharing a reference to this slot vote tracker
        /// with another thread. Should be done by any functions that directly get access
        /// to a SVT, so that callers do not need to; a holder of a SVT needs to manage
        /// the reference count appropriately after acquiring a SVT reference.
        rc: sig.sync.ReferenceCounter,
        tracker: sig.sync.RwMux(SlotVoteTracker),

        pub fn create(allocator: std.mem.Allocator) std.mem.Allocator.Error!*RcRwSlotVoteTracker {
            const self = try allocator.create(RcRwSlotVoteTracker);
            self.* = .{
                .rc = .{},
                .tracker = sig.sync.RwMux(SlotVoteTracker).init(SlotVoteTracker.EMPTY_ZEROES),
            };
            return self;
        }

        /// Destroys `self` after freeing all of its resources if it is the last reference.
        pub fn deinit(self: *RcRwSlotVoteTracker, allocator: std.mem.Allocator) void {
            if (!self.rc.release()) return;
            // can't unlock the rwmux, which is part of the freed memory,
            // and in theory this is the only remaining reference anyway.
            const tracker, _ = self.tracker.writeWithLock();
            tracker.deinit(allocator);
            allocator.destroy(self);
        }
    };

    pub fn deinit(self: *VoteTracker, allocator: std.mem.Allocator) void {
        std.debug.assert(self.map_rwlock.tryLock());
        const map = &self.map;
        for (map.values()) |rc_rw_svt| {
            rc_rw_svt.deinit(allocator);
        }
        map.deinit(allocator);
    }

    pub fn getSlotVoteTracker(self: *VoteTracker, slot: Slot) ?*RcRwSlotVoteTracker {
        // self.slot_vote_trackers.read().unwrap().get(&slot).cloned()
        self.map_rwlock.lockShared();
        defer self.map_rwlock.unlockShared();
        const rc_rw_svt = self.map.get(slot) orelse return null;
        std.debug.assert(rc_rw_svt.rc.acquire());
        return rc_rw_svt;
    }

    /// The caller is responsible for calling `.deinit(allocator)` on the result.
    pub fn getOrInsertSlotTracker(
        self: *VoteTracker,
        allocator: std.mem.Allocator,
        slot: Slot,
    ) std.mem.Allocator.Error!*RcRwSlotVoteTracker {
        blk: {
            self.map_rwlock.lockShared();
            defer self.map_rwlock.unlockShared();
            const rc_rw_svt = self.map.get(slot) orelse break :blk;
            // we acquired a lock on the map, this should never trigger unless rc is mismanaged.
            std.debug.assert(rc_rw_svt.rc.acquire());
            return rc_rw_svt;
        }

        self.map_rwlock.lock();
        defer self.map_rwlock.unlock();

        const gop = try self.map.getOrPut(allocator, slot);
        errdefer std.debug.assert(self.map.pop().?.key == slot);

        if (!gop.found_existing) {
            gop.value_ptr.* = try RcRwSlotVoteTracker.create(allocator);
        }
        // one reference for being in the map, another for the caller.
        //
        // we assert success because we just acquired a lock on the map,
        // failure shouldn't be possible, because `deinit` and `purgeStaleState`
        // would be waiting for the lock, meaning the one and only reference
        // is still valid.
        std.debug.assert(gop.value_ptr.*.rc.acquire());
        return gop.value_ptr.*;
    }

    /// TODO: investigate why this alias even exists in the agave code
    pub const progressWithNewRootBank = purgeStaleState;

    /// Purge any outdated slot data
    pub fn purgeStaleState(
        self: *VoteTracker,
        allocator: std.mem.Allocator,
        new_root_bank_slot: Slot,
    ) void {
        self.map_rwlock.lock();
        defer self.map_rwlock.unlock();
        const map = &self.map;

        var index: usize = 0;
        while (index != map.count()) {
            const keys = map.keys();
            if (keys[index] < new_root_bank_slot) {
                map.fetchSwapRemove(keys[index]).?.value.deinit(allocator);
            } else {
                index += 1;
            }
        }
    }

    pub fn insertVoteForTests(
        self: *VoteTracker,
        allocator: std.mem.Allocator,
        slot: Slot,
        pubkey: Pubkey,
    ) !void {
        if (!builtin.is_test) @compileError(@src().fn_name ++ " can only be used in tests.");

        self.map_rwlock.lock();
        defer self.map_rwlock.unlock();
        const map = &self.map;

        const gop = try map.getOrPut(allocator, slot);
        errdefer if (!gop.found_existing) std.debug.assert(map.pop().?.key == slot);
        if (!gop.found_existing) gop.value_ptr.* = try RcRwSlotVoteTracker.create(allocator);
        errdefer if (!gop.found_existing) gop.value_ptr.*.deinit(allocator);

        const slot_vote_tracker, //
        var slot_vote_tracker_lg //
        = gop.value_ptr.*.tracker.writeWithLock();
        defer slot_vote_tracker_lg.unlock();

        map.lockPointers();
        defer map.unlockPointers();

        const voted = &slot_vote_tracker.voted;
        errdefer if (!gop.found_existing) voted.deinit(allocator);

        const voted_slot_updates = slot_vote_tracker.initAndOrGetUpdates();
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

        for (copy.optimistic_votes_tracker.values()) |vst| vst.deinit(allocator);
        copy.optimistic_votes_tracker.deinit(allocator);

        copy.initAndOrGetUpdates().deinit(allocator);
    }

    /// If there already are vote slot updates, returns the pointer to them.
    /// Otherwise, initializes them, and then returns the pointer.
    pub fn initAndOrGetUpdates(self: *SlotVoteTracker) *std.ArrayListUnmanaged(Pubkey) {
        if (self.voted_slot_updates) |*vsu| return vsu;
        self.voted_slot_updates = .{};
        return &self.voted_slot_updates.?;
    }

    /// Take the current voted slot updates, i.e. returns `self.voted_slot_updates` and sets the field to null.
    pub fn takeUpdates(self: *SlotVoteTracker) ?std.ArrayListUnmanaged(Pubkey) {
        const vsu = self.voted_slot_updates orelse return null;
        self.voted_slot_updates = null;
        return vsu;
    }

    pub fn getOrInsertOptimisticVotesTracker(
        self: *SlotVoteTracker,
        allocator: std.mem.Allocator,
        hash: Hash,
    ) std.mem.Allocator.Error!*VoteStakeTracker {
        const gop = try self.optimistic_votes_tracker.getOrPut(allocator, hash);
        if (!gop.found_existing) gop.value_ptr.* = VoteStakeTracker.EMPTY_ZEROES;
        return gop.value_ptr;
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

    pub fn ensureTotalCapacity(
        self: *VoteStakeTracker,
        allocator: std.mem.Allocator,
        new_capacity: usize,
    ) std.mem.Allocator.Error!void {
        try self.voted.ensureTotalCapacity(allocator, new_capacity);
    }

    pub fn ensureUnusedCapacity(
        self: *VoteStakeTracker,
        allocator: std.mem.Allocator,
        additional_capacity: usize,
    ) std.mem.Allocator.Error!void {
        try self.voted.ensureUnusedCapacity(allocator, additional_capacity);
    }

    pub const AddVotePubkeyResult = enum {
        /// The vote has not been seen before.
        is_new,
        /// The vote has been seen before.
        is_old,
    };

    pub const AddVotePubkeyParams = struct {
        vote_pubkey: Pubkey,
        stake: u64,
        total_stake: u64,
        thresholds_to_check: []const f64,
    };

    /// Returns tuple (reached_thresholds, is_new) where
    /// Each index in `reached_thresholds` is true if the corresponding threshold in the input
    /// `thresholds_to_check` was newly reached by adding the stake of the input `vote_pubkey`.
    /// `is_new` is true if the vote has not been seen before.
    ///
    /// The caller is responsible for deiniting `reached_thresholds` using `allocator`.
    pub fn addVotePubkey(
        self: *VoteStakeTracker,
        allocator: std.mem.Allocator,
        params: AddVotePubkeyParams,
    ) std.mem.Allocator.Error!struct { std.DynamicBitSetUnmanaged, AddVotePubkeyResult } {
        try self.ensureUnusedCapacity(allocator, 1);
        var reached_thresholds: std.DynamicBitSetUnmanaged = .{};
        errdefer reached_thresholds.deinit(allocator);
        try reached_thresholds.resize(allocator, params.thresholds_to_check.len, false);
        const result = self.addVotePubkeyAssumeCapacity(&reached_thresholds, params);
        return .{ reached_thresholds, result };
    }

    /// Each index in `reached_thresholds` is true iff the corresponding threshold in the input
    /// `thresholds_to_check` was newly reached by adding the stake of the input `vote_pubkey`.
    /// Returns whether or not the vote has been seen before.
    pub fn addVotePubkeyAssumeCapacity(
        self: *VoteStakeTracker,
        /// Must be one of:
        /// - `*std.DynamicBitSetUnmanaged`
        /// - `*std.bit_set.ArrayBitSet(MaskInt, size)`
        /// - `*std.bit_set.IntegerBitSet(size)`
        ///
        /// `bit_length` must be equal to `thresholds_to_check.len`.
        reached_thresholds: anytype,
        params: AddVotePubkeyParams,
    ) AddVotePubkeyResult {
        const vote_pubkey = params.vote_pubkey;
        const stake = params.stake;
        const total_stake = params.total_stake;
        const thresholds_to_check = params.thresholds_to_check;

        const ReachedThresholds = @TypeOf(reached_thresholds.*);
        const bit_set_kind = comptime bitSetKind(ReachedThresholds) orelse @compileError(
            "Expected a bit set defined in the doc comment, got " ++
                @typeName(ReachedThresholds),
        );

        std.debug.assert( // must reserve capacity for at least 1 more entry
            self.voted.capacity() > self.voted.count(),
        );
        std.debug.assert( // thresholds inputs & outputs must be equal lengths
            thresholds_to_check.len == reached_thresholds.capacity(),
        );

        switch (bit_set_kind) {
            .dynamic => reached_thresholds.unsetAll(),
            .integer, .array => reached_thresholds.* = ReachedThresholds.initEmpty(),
        }

        const gop = self.voted.getOrPutAssumeCapacity(vote_pubkey);
        gop.value_ptr.* = {};
        if (gop.found_existing) return .is_old;

        const old_stake = self.stake;
        self.stake += stake;
        const new_stake = self.stake;

        const total_stake_f64: f64 = @floatFromInt(total_stake);
        for (thresholds_to_check, 0..) |threshold, i| {
            const threshold_stake: u64 = @intFromFloat(total_stake_f64 * threshold);
            const reached_threshold = old_stake <= threshold_stake and threshold_stake < new_stake;
            reached_thresholds.setValue(i, reached_threshold);
        }

        return .is_new;
    }

    inline fn bitSetKind(comptime ReachedThresholds: type) ?enum { dynamic, integer, array } {
        if (!@inComptime()) comptime unreachable;
        if (ReachedThresholds == std.DynamicBitSetUnmanaged) return .dynamic;

        if (@typeInfo(ReachedThresholds) != .@"struct") return null;

        if (!@hasDecl(ReachedThresholds, "bit_length")) return null;
        if (!@typeInfo(@TypeOf(&ReachedThresholds.bit_length)).pointer.is_const) {
            return null;
        }

        if (!@hasDecl(ReachedThresholds, "MaskInt")) return null;
        if (@TypeOf(&ReachedThresholds.MaskInt) != *const type) {
            return null;
        }

        const bit_length = ReachedThresholds.bit_length;
        const MaskInt = ReachedThresholds.MaskInt;

        if (bit_length > std.math.maxInt(usize)) return null;
        if (bit_length <= std.math.maxInt(u16)) {
            if (ReachedThresholds == std.bit_set.IntegerBitSet(bit_length)) return .integer;
        }
        if (std.math.isPowerOfTwo(@bitSizeOf(MaskInt))) {
            if (ReachedThresholds == std.bit_set.ArrayBitSet(MaskInt, bit_length)) return .array;
        }

        return null;
    }
};

test "VoteStakeTracker.addVotePubkey" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(21410);
    const random = prng.random();

    const total_epoch_stake = 10;
    var vote_stake_tracker = VoteStakeTracker.EMPTY_ZEROES;
    defer vote_stake_tracker.deinit(allocator);

    for (0..10) |i| {
        const pubkey = Pubkey.initRandom(random);
        var is_confirmed_thresholds, //
        const recency //
        = try vote_stake_tracker.addVotePubkey(allocator, .{
            .vote_pubkey = pubkey,
            .stake = 1,
            .total_stake = total_epoch_stake,
            .thresholds_to_check = &.{ sig.consensus.replay_tower.VOTE_THRESHOLD_SIZE, 0.0 },
        });
        defer is_confirmed_thresholds.deinit(allocator);

        const stake = vote_stake_tracker.stake;

        var is_confirmed_thresholds2, //
        const recency2 //
        = try vote_stake_tracker.addVotePubkey(allocator, .{
            .vote_pubkey = pubkey,
            .stake = 1,
            .total_stake = total_epoch_stake,
            .thresholds_to_check = &.{ sig.consensus.replay_tower.VOTE_THRESHOLD_SIZE, 0.0 },
        });
        defer is_confirmed_thresholds2.deinit(allocator);

        const stake2 = vote_stake_tracker.stake;

        // Stake should not change from adding same pubkey twice
        try std.testing.expectEqual(stake, stake2);
        try std.testing.expectEqual(2, is_confirmed_thresholds.bit_length);
        try std.testing.expectEqual(2, is_confirmed_thresholds2.bit_length);
        try std.testing.expectEqual(.is_old, recency2);
        try std.testing.expect(!is_confirmed_thresholds2.isSet(0));
        try std.testing.expect(!is_confirmed_thresholds2.isSet(1));

        // at i == 6, the voted stake is 70%, which is the first time crossing
        // the supermajority threshold
        if (i == 6) {
            try std.testing.expect(is_confirmed_thresholds.isSet(0));
        } else {
            try std.testing.expect(!is_confirmed_thresholds.isSet(0));
        }

        // at i == 6, the voted stake is 10%, which is the first time crossing
        // the 0% threshold
        if (i == 0) {
            try std.testing.expect(is_confirmed_thresholds.isSet(1));
        } else {
            try std.testing.expect(!is_confirmed_thresholds.isSet(1));
        }
        try std.testing.expectEqual(.is_new, recency);
    }
}
