const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const Random = std.Random;

const Ancestors = sig.core.Ancestors;
const Epoch = sig.core.Epoch;
const EpochSchedule = sig.core.epoch_schedule.EpochSchedule;
const EpochStakes = sig.core.EpochStakes;
const FeatureSet = sig.core.features.Set;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const LeaderSchedules = sig.core.leader_schedule.LeaderSchedules;
const LeaderSchedule = sig.core.leader_schedule.LeaderSchedule;

pub const ClusterConfig = struct {
    /// genesis time, used for computed clock.
    genesis_creation_time: i64,

    /// The number of ticks for each slot in this epoch.
    ticks_per_slot: u8,

    /// The number of ticks per second.
    ticks_per_second: u8,

    /// The number of hashes in each tick. Null means hashing is disabled.
    hashes_per_tick: ?u64,

    pub const default: ClusterConfig = .{
        .genesis_creation_time = 0,
        .ticks_per_slot = 64,
        .ticks_per_second = 160,
        .hashes_per_tick = null,
    };

    fn initFromBankFields(fields: sig.core.BankFields) ClusterConfig {
        const seconds_per_year: f64 = (365.242_199 * 24.0 * 60.0 * 60.0);
        const slots_per_second = fields.slots_per_year / seconds_per_year;
        const ticks_per_second: u8 = @intFromFloat(
            slots_per_second * @as(f64, @floatFromInt(fields.ticks_per_slot)),
        );
        return .{
            .genesis_creation_time = fields.genesis_creation_time,
            .ticks_per_slot = @intCast(fields.ticks_per_slot),
            .ticks_per_second = ticks_per_second,
            .hashes_per_tick = fields.hashes_per_tick,
        };
    }

    pub fn initFromGenesisConfig(config: *const sig.core.GenesisConfig) ClusterConfig {
        const ticks_per_nano = config.poh_config.target_tick_duration.asNanos();
        return .{
            .genesis_creation_time = config.creation_time,
            .ticks_per_slot = @intCast(config.ticks_per_slot),
            .ticks_per_second = @intCast(1_000_000_000 / ticks_per_nano),
            .hashes_per_tick = config.poh_config.hashes_per_tick,
        };
    }

    pub fn slotsPerYear(self: *const ClusterConfig) f64 {
        const seconds_per_year = (365.242_199 * 24.0 * 60.0 * 60.0);
        return seconds_per_year *
            @as(f64, @floatFromInt(self.ticks_per_second)) /
            @as(f64, @floatFromInt(self.ticks_per_slot));
    }

    pub fn nanosPerSlot(self: *const ClusterConfig) u64 {
        const seconds_per_slot = @as(f64, @floatFromInt(self.ticks_per_slot)) /
            @as(f64, @floatFromInt(self.ticks_per_second));
        return @as(u64, @intFromFloat(std.time.ns_per_s * seconds_per_slot));
    }
};

/// This is a WORK AROUND for our current lack of fork awareness outside of replay.
/// It ATTEMPTS to satisfy immediate requirements to run on testnet.
/// It MUST be replaced by a better implementation as soon as possible.
pub const EpochTracker = struct {
    cluster: ClusterConfig,

    /// The most recently rooted slot, set by consensus.
    root_slot: Atomic(Slot),

    /// Epoch Schedule
    /// Used to map slots to epochs and vice versa.
    /// Technically this can change, but pracitically it should be fine for now
    /// It should be moved to fork aware data.
    epoch_schedule: EpochSchedule,

    /// Ring buffer of the last 4 rooted epoch stakes.
    /// New epoch stakes are added when the first slot of a new epoch is rooted by consensus.
    rooted_epochs: RootedEpochBuffer,

    /// Unrooted epoch stakes buffer.
    /// Holds epoch stakes for forks which have crossed an epoch boundary but are not yet rooted.
    /// New epoch stakes are added by the first slot on each fork which crosses an epoch boundary.
    /// When the first insert happens for a new epoch, the buffer is cleared and the items deinitialized.
    ///
    /// Example:
    ///   - Last rooted slot is 30
    ///   - Epoch 0: slots 0-31
    ///   - Epoch 1: slots 32-63
    ///
    /// 34   32     33    E(1)
    ///  \    \    /
    ///   \     31        E(0)
    ///    \    /
    ///      30           E(0)
    ///
    ///   - Slot 32 becomes the first rooted slot in epoch 1
    ///   - The epoch stakes and leader schedule are computed from the epoch stakes computed by slot 32
    unrooted_epochs: UnrootedEpochBuffer,

    pub fn init(
        cluster: ClusterConfig,
        root_slot: Slot,
        epoch_schedule: EpochSchedule,
    ) EpochTracker {
        return .{
            .cluster = cluster,
            .root_slot = .init(root_slot),
            .epoch_schedule = epoch_schedule,
            .rooted_epochs = .{},
            .unrooted_epochs = .{},
        };
    }

    pub fn initFromManifest(
        allocator: Allocator,
        manifest: *const sig.accounts_db.snapshot.Manifest,
        feature_set: *const FeatureSet,
    ) !EpochTracker {
        const slot = manifest.bank_fields.slot;
        const epoch_schedule = manifest.bank_fields.epoch_schedule;

        var epoch_tracker = sig.core.EpochTracker.init(
            .initFromBankFields(manifest.bank_fields),
            slot,
            epoch_schedule,
        );
        errdefer epoch_tracker.deinit(allocator);

        const epoch_stakes_map = manifest.bank_extra.versioned_epoch_stakes;
        const min_epoch = std.mem.min(Epoch, manifest.bank_extra.versioned_epoch_stakes.keys());
        const max_epoch = std.mem.max(Epoch, manifest.bank_extra.versioned_epoch_stakes.keys());
        for (min_epoch..max_epoch + 1) |epoch| {
            const stakes = (epoch_stakes_map.get(epoch) orelse continue).current;
            const epoch_stakes = try stakes.convert(allocator, .delegation);
            errdefer epoch_stakes.deinit(allocator);
            try epoch_tracker.insertRootedEpochInfo(allocator, epoch_stakes, feature_set);
        }

        return epoch_tracker;
    }

    pub fn deinit(self: *const EpochTracker, allocator: Allocator) void {
        self.rooted_epochs.deinit(allocator);
        self.unrooted_epochs.deinit(allocator);
    }

    /// Get the EpochInfo which is 'active' for the current slot. This means the EpochInfo which
    /// is used to compute the leader schedule for the current slot's epoch. If the current slot is
    /// in epoch E, then this epoch info will have been 'saved' on the first rooted slot of epoch E-1,
    /// and will contain the stakes at the end of epoch E-2.
    /// If the slot is in Epoch 10, then this function will return an EpochInfo which was saved
    /// at the beginning of Epoch 9, and contains stakes from the end of Epoch 8.
    /// IF the slot is in Epoch 10, then EpochInfo.stakes.stakes.epoch wil be 9
    pub fn getEpochInfo(
        self: *const EpochTracker,
        slot: Slot,
    ) !*const EpochInfo {
        const epoch = self.epoch_schedule.getEpoch(
            slot -| self.epoch_schedule.leader_schedule_slot_offset,
        );
        return try self.rooted_epochs.get(epoch);
    }

    pub fn getEpochInfoNoOffset(
        self: *const EpochTracker,
        slot: Slot,
        ancestors: *const Ancestors,
    ) !*const EpochInfo {
        const epoch = self.epoch_schedule.getEpoch(slot);
        return self.rooted_epochs.get(epoch) catch self.unrooted_epochs.get(ancestors);
    }

    pub fn getLeaderSchedules(self: *const EpochTracker) !LeaderSchedules {
        const slot = self.root_slot.load(.monotonic);
        const epoch_info = try self.getEpochInfo(slot);
        const prev_epoch_info = self.getEpochInfo(
            slot -| self.epoch_schedule.leader_schedule_slot_offset,
        ) catch null;
        const next_epoch_info = self.getEpochInfo(
            slot +| self.epoch_schedule.leader_schedule_slot_offset,
        ) catch null;
        return .{
            .curr = epoch_info.leaders,
            .prev = if (prev_epoch_info) |info| info.leaders else null,
            .next = if (next_epoch_info) |info| info.leaders else null,
        };
    }

    pub fn onSlotRooted(
        self: *EpochTracker,
        allocator: Allocator,
        slot: Slot,
        ancestors: *const Ancestors,
    ) !void {
        if (self.rooted_epochs.isNext(self.epoch_schedule.getEpoch(slot)))
            try self.onFirstSlotInEpochRooted(allocator, ancestors);
        self.root_slot.store(slot, .monotonic);
    }

    fn onFirstSlotInEpochRooted(
        self: *EpochTracker,
        allocator: Allocator,
        ancestors: *const Ancestors,
    ) !void {
        const entry = try self.unrooted_epochs.take(ancestors);
        errdefer {
            entry.deinit(allocator);
            allocator.destroy(entry);
        }
        try self.rooted_epochs.insert(
            allocator,
            entry,
        );
    }

    pub fn insertRootedEpochInfo(
        self: *EpochTracker,
        allocator: Allocator,
        epoch_stakes: EpochStakes,
        feature_set: *const FeatureSet,
    ) !void {
        const leader_schedule_epoch = self.epoch_schedule.getLeaderScheduleEpoch(
            self.epoch_schedule.getFirstSlotInEpoch(epoch_stakes.stakes.epoch),
        );
        const leaders = try LeaderSchedule.init(
            allocator,
            leader_schedule_epoch,
            epoch_stakes.stakes.vote_accounts,
            &self.epoch_schedule,
            feature_set,
        );
        errdefer leaders.deinit(allocator);

        const epoch_info_ptr = try allocator.create(EpochInfo);
        errdefer allocator.destroy(epoch_info_ptr);

        epoch_info_ptr.* = .{
            .leaders = leaders,
            .stakes = epoch_stakes,
            .feature_set = feature_set.*,
        };

        try self.rooted_epochs.insert(allocator, epoch_info_ptr);
    }

    pub fn insertUnrootedEpochInfo(
        self: *EpochTracker,
        allocator: Allocator,
        slot: Slot,
        ancestors: *const Ancestors,
        epoch_stakes: EpochStakes,
        feature_set: *const FeatureSet,
    ) !*const EpochInfo {
        const epoch = self.epoch_schedule.getEpoch(slot);
        const leader_schedule_epoch = self.epoch_schedule.getLeaderScheduleEpoch(slot);
        if (epoch != epoch_stakes.stakes.epoch) return error.InvalidInsert;
        if (!self.rooted_epochs.isNext(epoch)) return error.InvalidInsert;

        const leaders = try LeaderSchedule.init(
            allocator,
            leader_schedule_epoch,
            epoch_stakes.stakes.vote_accounts,
            &self.epoch_schedule,
            feature_set,
        );
        errdefer leaders.deinit(allocator);

        return try self.unrooted_epochs.insert(
            allocator,
            slot,
            ancestors,
            .{
                .leaders = leaders,
                .stakes = epoch_stakes,
                .feature_set = feature_set.*,
            },
        );
    }

    pub fn initForTest(
        allocator: Allocator,
        random: Random,
        root_slot: Slot,
        epoch_schedule: EpochSchedule,
    ) !EpochTracker {
        if (!builtin.is_test) @compileError("only for tests");
        var self = EpochTracker.init(.default, root_slot, epoch_schedule);
        errdefer self.deinit(allocator);

        const epoch = epoch_schedule.getEpoch(root_slot);
        for (epoch -| 3..epoch + 1) |epoch_i| {
            const epoch_info_ptr = try allocator.create(EpochInfo);
            errdefer allocator.destroy(epoch_info_ptr);

            epoch_info_ptr.* = try EpochInfo.initRandom(
                allocator,
                random,
                .{ .epoch = epoch_i, .schedule = epoch_schedule },
            );
            errdefer epoch_info_ptr.deinit(allocator);

            try self.rooted_epochs.insert(allocator, epoch_info_ptr);
        }

        return self;
    }

    pub fn initWithEpochStakesOnlyForTest(
        allocator: Allocator,
        epoch_stakes: []const EpochStakes,
    ) !EpochTracker {
        if (!builtin.is_test) @compileError("only for tests");
        var self = EpochTracker.init(.default, 0, .INIT);
        errdefer self.deinit(allocator);

        for (epoch_stakes) |stakes| {
            const epoch_info_ptr = try allocator.create(EpochInfo);
            errdefer allocator.destroy(epoch_info_ptr);

            epoch_info_ptr.* = .{
                .leaders = .{
                    .leaders = &.{},
                    .start = 0,
                    .end = 0,
                },
                .stakes = stakes,
                .feature_set = .ALL_DISABLED,
            };
            errdefer epoch_info_ptr.deinit(allocator);

            try self.rooted_epochs.insert(allocator, epoch_info_ptr);
        }

        return self;
    }
};

pub const EpochInfo = struct {
    leaders: LeaderSchedule,
    stakes: EpochStakes,
    feature_set: sig.core.FeatureSet,

    pub fn deinit(self: *const EpochInfo, allocator: Allocator) void {
        self.leaders.deinit(allocator);
        self.stakes.deinit(allocator);
    }

    fn init(
        leaders: LeaderSchedule,
        stakes: EpochStakes,
        feature_set: sig.core.FeatureSet,
    ) EpochInfo {
        return .{
            .leaders = leaders,
            .stakes = stakes,
            .feature_set = feature_set,
        };
    }

    fn initRandom(allocator: Allocator, random: Random, options: struct {
        epoch: ?Epoch = null,
        schedule: EpochSchedule = .INIT,
        max_stakes_list_entries: usize = 5,
    }) !EpochInfo {
        const epoch = options.epoch orelse random.intRangeAtMost(Epoch, 0, 1_000);

        const stakes = try EpochStakes.initRandom(allocator, random, .{
            .epoch = epoch,
            .max_list_entries = options.max_stakes_list_entries,
        });
        errdefer stakes.deinit(allocator);

        const leaders = try LeaderSchedule.initRandom(allocator, random, .{
            .epoch = epoch,
            .schedule = options.schedule,
        });
        errdefer leaders.deinit(allocator);

        return .init(leaders, stakes, .ALL_DISABLED);
    }
};

/// Epoch Ring Buffer which holds 4 EpochInfo entries.
///
/// Inserts must increase monotonically by exactly 1 epoch.
/// Gets must be within range of the last 4 inserted epochs.
///
/// No process should ever need to access E-3 or older EpochInfos and it is thus safe to
/// deinitialize the corresponding data when overwriting entries with new epoch data.
const RootedEpochBuffer = struct {
    buf: [4]?*const EpochInfo = @splat(null),
    root: Atomic(Epoch) = .init(0),

    fn deinit(self: *const RootedEpochBuffer, allocator: Allocator) void {
        var buf = self.buf;
        for (&buf) |*maybe_entry| {
            if (maybe_entry.*) |entry| {
                entry.deinit(allocator);
                allocator.destroy(entry);
            }
            maybe_entry.* = null;
        }
    }

    pub fn insert(
        self: *RootedEpochBuffer,
        allocator: Allocator,
        value: *const EpochInfo,
    ) !void {
        const epoch = value.stakes.stakes.epoch;
        if (!self.isNext(epoch)) return error.InvalidInsert;

        const index = epoch % self.buf.len;
        if (self.buf[index]) |old_value| {
            old_value.deinit(allocator);
            allocator.destroy(old_value);
        }

        self.buf[index] = value;
        self.root.store(epoch, .monotonic);
    }

    pub fn get(
        self: *const RootedEpochBuffer,
        epoch: Epoch,
    ) !*const EpochInfo {
        const root_epoch = self.root.load(.monotonic);

        if (root_epoch == 0 and std.mem.allEqual(
            ?*const EpochInfo,
            &self.buf,
            null,
        )) return error.EpochNotFound;

        if (epoch > root_epoch or
            epoch + self.buf.len <= root_epoch or
            self.buf[epoch % self.buf.len] == null) return error.EpochNotFound;

        const epoch_at_index = self.buf[epoch % self.buf.len].?.stakes.stakes.epoch;
        if (epoch != epoch_at_index) return error.EpochOverwritten;

        return self.buf[epoch % self.buf.len].?;
    }

    pub fn isNext(self: *const RootedEpochBuffer, epoch: Epoch) bool {
        const root = self.root.load(.monotonic);
        if (root == 0 and (epoch == 1 or std.mem.allEqual(
            ?*const EpochInfo,
            &self.buf,
            null,
        ))) return true;
        return epoch == root + 1;
    }
};

const UnrootedEpochBuffer = struct {
    buf: [MAX_FORKS]?struct { slot: Slot, info: *const EpochInfo } = @splat(null),

    pub const MAX_FORKS = 4;

    fn deinit(self: *const UnrootedEpochBuffer, allocator: Allocator) void {
        var buf = self.buf;
        for (&buf) |*maybe_entry| {
            if (maybe_entry.*) |entry| {
                entry.info.deinit(allocator);
                allocator.destroy(entry.info);
            }
            maybe_entry.* = null;
        }
    }

    fn insert(
        self: *UnrootedEpochBuffer,
        allocator: Allocator,
        slot: Slot,
        ancestors: *const Ancestors,
        epoch_info: EpochInfo,
    ) !*const EpochInfo {
        const epoch = epoch_info.stakes.stakes.epoch;

        const index = for (&self.buf, 0..) |maybe_entry, i| {
            const entry = if (maybe_entry) |entry| entry else break i;
            const entry_epoch = entry.info.stakes.stakes.epoch;
            if (epoch > entry_epoch) {
                // Entry occupied by old epoch, we can overwrite it.
                entry.info.deinit(allocator);
                allocator.destroy(entry.info);
                break i;
            } else if (epoch == entry_epoch) {
                // Entry occupied by an existing fork.
                if (ancestors.containsSlot(entry.slot)) return error.DuplicateBranch;
                continue;
            } else {
                // We should never insert an epoch older than existing entries.
                return error.InvalidEpoch;
            }
        } else return error.MaxForksExceeded;

        const info_ptr = try allocator.create(EpochInfo);
        info_ptr.* = epoch_info;
        self.buf[index] = .{ .slot = slot, .info = info_ptr };

        return info_ptr;
    }

    pub fn get(
        self: *const UnrootedEpochBuffer,
        ancestors: *const Ancestors,
    ) !*const EpochInfo {
        for (&self.buf) |maybe_entry|
            if (maybe_entry) |entry|
                if (ancestors.containsSlot(entry.slot)) return entry.info;
        return error.ForkNotFound;
    }

    fn take(
        self: *UnrootedEpochBuffer,
        ancestors: *const Ancestors,
    ) !*const EpochInfo {
        for (&self.buf) |*maybe_entry|
            if (maybe_entry.*) |entry|
                if (ancestors.containsSlot(entry.slot)) {
                    const info = entry.info;
                    maybe_entry.* = null;
                    return info;
                };
        return error.ForkNotFound;
    }
};

test RootedEpochBuffer {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const epoch_schedule = EpochSchedule.custom(.{
        .slots_per_epoch = 32,
        .leader_schedule_slot_offset = 32,
        .warmup = false,
    });

    var buffer = RootedEpochBuffer{};
    defer buffer.deinit(allocator);

    // Assert all gets fail initially
    for (0..buffer.buf.len * 2) |epoch| {
        try std.testing.expectError(
            error.EpochNotFound,
            buffer.get(epoch),
        );
    }

    // Insert epoch 0 leader schedule
    var epoch: Epoch = 0;
    const info_0 = try allocator.create(EpochInfo);
    info_0.* = try EpochInfo.initRandom(
        allocator,
        random,
        .{
            .epoch = epoch,
            .schedule = epoch_schedule,
        },
    );
    try buffer.insert(allocator, info_0);

    // Check that duplicate insert fails
    try std.testing.expectError(
        error.InvalidInsert,
        buffer.insert(allocator, info_0),
    );

    // Insert epoch 1 leader schedule
    epoch += 1;
    const info_1 = try allocator.create(EpochInfo);
    info_1.* = try EpochInfo.initRandom(
        allocator,
        random,
        .{
            .epoch = epoch,
            .schedule = epoch_schedule,
        },
    );
    try buffer.insert(allocator, info_1);

    // Check that non-monotonic insert fails
    try std.testing.expectError(
        error.InvalidInsert,
        buffer.insert(allocator, info_0),
    );

    // Check that skipping an epoch insert fails
    const info_3 = try allocator.create(EpochInfo);
    info_3.* = try EpochInfo.initRandom(
        allocator,
        random,
        .{
            .epoch = epoch + 2,
            .schedule = epoch_schedule,
        },
    );
    defer {
        info_3.deinit(allocator);
        allocator.destroy(info_3);
    }
    try std.testing.expectError(
        error.InvalidInsert,
        buffer.insert(allocator, info_3),
    );

    // Insert 4 epochs
    for (0..4) |_| {
        epoch += 1;
        const info = try allocator.create(EpochInfo);
        info.* = try EpochInfo.initRandom(
            allocator,
            random,
            .{
                .epoch = epoch,
                .schedule = epoch_schedule,
            },
        );
        try buffer.insert(allocator, info);
    }

    // Check get outside of range fails
    try std.testing.expectError(error.EpochNotFound, buffer.get(epoch - 4));
    try std.testing.expectError(error.EpochNotFound, buffer.get(epoch + 1));

    // Check that we can get all 4 inserted epochs
    for (epoch - 3..epoch + 1) |epoch_i| {
        const info = try buffer.get(epoch_i);
        try std.testing.expectEqual(epoch_i, info.stakes.stakes.epoch);
    }

    // Get and save all but the oldest epoch for later comparison
    const expected = try allocator.alloc(EpochInfo, 3);
    defer {
        for (expected) |info| info.deinit(allocator);
        allocator.free(expected);
    }
    for (epoch - 2..epoch + 1, 0..) |epoch_i, i| {
        const info = try buffer.get(epoch_i);
        expected[i] = .{
            .leaders = .{
                .leaders = try allocator.dupe(Pubkey, info.leaders.leaders),
                .start = info.leaders.start,
                .end = info.leaders.end,
            },
            .stakes = try info.stakes.clone(allocator),
            .feature_set = .ALL_DISABLED,
        };
    }

    // Insert next epoch to overwrite the oldest epoch
    epoch += 1;
    const info_6 = try allocator.create(EpochInfo);
    info_6.* = try EpochInfo.initRandom(
        allocator,
        random,
        .{
            .epoch = epoch,
            .schedule = epoch_schedule,
        },
    );
    try buffer.insert(allocator, info_6);

    // Check that only the oldest epoch has been overwritten
    for (epoch - 3..epoch, expected) |epoch_i, expected_info| {
        const info = try buffer.get(epoch_i);
        try std.testing.expectEqualSlices(
            Pubkey,
            expected_info.leaders.leaders,
            info.leaders.leaders,
        );
        try std.testing.expectEqual(
            expected_info.stakes.total_stake,
            info.stakes.total_stake,
        );
        try std.testing.expectEqual(
            expected_info.stakes.stakes.epoch,
            info.stakes.stakes.epoch,
        );
    }
}

test UnrootedEpochBuffer {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const epoch_schedule = EpochSchedule.custom(.{
        .slots_per_epoch = 32,
        .leader_schedule_slot_offset = 32,
        .warmup = false,
    });

    var buffer = UnrootedEpochBuffer{};
    defer buffer.deinit(allocator);

    var branch = try Ancestors.initWithSlots(allocator, &.{ 10, 11, 12 });
    defer branch.deinit(allocator);

    // Get and take on empty buffer fails
    try std.testing.expectError(
        error.ForkNotFound,
        buffer.get(&branch),
    );
    try std.testing.expectError(
        error.ForkNotFound,
        buffer.take(&branch),
    );

    // Insert epoch info for slot 9
    const epoch_info = try EpochInfo.initRandom(
        allocator,
        random,
        .{ .epoch = 1, .schedule = epoch_schedule },
    );
    defer epoch_info.deinit(allocator);
    const epoch_info_ptr = try buffer.insert(
        allocator,
        9,
        &branch,
        epoch_info,
    );
    defer allocator.destroy(epoch_info_ptr);

    // Get and take without matching fork fails
    try std.testing.expectError(
        error.ForkNotFound,
        buffer.get(&branch),
    );
    try std.testing.expectError(
        error.ForkNotFound,
        buffer.take(&branch),
    );

    // Add slot 9 to ancestors and check get and take succeed
    try branch.addSlot(allocator, 9);
    const fetched_info = try buffer.get(&branch);
    const taken_info = try buffer.take(&branch);
    try std.testing.expectEqual(epoch_info_ptr, fetched_info);
    try std.testing.expectEqual(epoch_info_ptr, taken_info);
    try std.testing.expectError(
        error.ForkNotFound,
        buffer.get(&branch),
    );
}

test EpochTracker {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const epoch_schedule = EpochSchedule.custom(.{
        .slots_per_epoch = 32,
        .leader_schedule_slot_offset = 32,
        .warmup = false,
    });

    // Begin test at last slot in epoch 0
    var epoch_tracker = EpochTracker.init(.default, 31, epoch_schedule);
    defer epoch_tracker.deinit(allocator);

    // Only the root slot is set
    try std.testing.expectEqual(31, epoch_tracker.root_slot.load(.monotonic));
    try std.testing.expectError(error.EpochNotFound, epoch_tracker.getEpochInfo(0));
    try std.testing.expectError(error.EpochNotFound, epoch_tracker.rooted_epochs.get(0));
    try std.testing.expectError(error.ForkNotFound, epoch_tracker.unrooted_epochs.get(&.EMPTY));

    // Fill the buffers with epochs by inserting and then rooting the first slot for 10 epochs
    for (0..10) |epoch| {
        var branch = try Ancestors.initWithSlots(
            allocator,
            &.{epoch_schedule.getFirstSlotInEpoch(epoch)},
        );
        defer branch.deinit(allocator);

        _ = try epoch_tracker.insertUnrootedEpochInfo(
            allocator,
            branch.last(),
            &branch,
            try sig.core.stakes.randomEpochStakes(
                allocator,
                random,
                .{ .epoch = epoch },
            ),
            &.ALL_DISABLED,
        );

        try epoch_tracker.onSlotRooted(allocator, branch.last(), &branch);
    }

    // Check that the root slot is 9 * 32 and epochs 6, 7, 8, 9 are available
    try std.testing.expectEqual(9 * 32, epoch_tracker.root_slot.load(.monotonic));
    try std.testing.expectEqual(6, (try epoch_tracker.rooted_epochs.get(6)).stakes.stakes.epoch);
    try std.testing.expectEqual(7, (try epoch_tracker.rooted_epochs.get(7)).stakes.stakes.epoch);
    try std.testing.expectEqual(8, (try epoch_tracker.rooted_epochs.get(8)).stakes.stakes.epoch);
    try std.testing.expectEqual(9, (try epoch_tracker.rooted_epochs.get(9)).stakes.stakes.epoch);

    // Empty stakes for failing inserts
    var fail_stakes = try sig.core.stakes.randomEpochStakes(
        allocator,
        random,
        .{},
    );
    defer fail_stakes.deinit(allocator);

    // Check that trying to insert epoch info for epoch 9 fails because it is already rooted
    const branch = try Ancestors.initWithSlots(allocator, &.{319});
    defer branch.deinit(allocator);
    fail_stakes.stakes.epoch = epoch_schedule.getEpoch(branch.last());
    try std.testing.expectError(error.InvalidInsert, epoch_tracker.insertUnrootedEpochInfo(
        allocator,
        branch.last(),
        &branch,
        fail_stakes,
        &.ALL_DISABLED,
    ));

    // Create and test forking from epoch 9 -> epoch 10 (slot 319 -> slot 320)
    // Five branches which branch at slot 314:
    //   - branch 0: 314 -> 315 -> 320
    //   - branch 1: 314 -> 316 -> 321
    //   - ...
    //   - branch 4: 314 -> 319 -> 324
    const branches = try allocator.alloc(Ancestors, 5);
    defer {
        for (branches) |value| value.deinit(allocator);
        allocator.free(branches);
    }
    for (0..5) |i| branches[i] = try Ancestors.initWithSlots(
        allocator,
        &.{ 310, 311, 312, 313, 314, 315 + i, 320 + i },
    );

    // Insert four branches
    const insert_ptrs = try allocator.alloc(*const EpochInfo, 4);
    defer allocator.free(insert_ptrs);
    for (0..4) |i| insert_ptrs[i] = try epoch_tracker.insertUnrootedEpochInfo(
        allocator,
        branches[i].last(),
        &branches[i],
        try sig.core.stakes.randomEpochStakes(
            allocator,
            random,
            .{ .epoch = epoch_schedule.getEpoch(branches[i].last()) },
        ),
        &.ALL_DISABLED,
    );

    // Check that the pointers returned from insert match the pointers returned from get
    for (0..4) |i| try std.testing.expectEqual(
        insert_ptrs[i],
        try epoch_tracker.unrooted_epochs.get(&branches[i]),
    );

    // Check that another insert hits max forks
    fail_stakes.stakes.epoch = epoch_schedule.getEpoch(branches[4].last());
    try std.testing.expectError(error.MaxForksExceeded, epoch_tracker.insertUnrootedEpochInfo(
        allocator,
        branches[4].last(),
        &branches[4],
        fail_stakes,
        &.ALL_DISABLED,
    ));

    // Root the first slot from branch 2
    try epoch_tracker.onSlotRooted(allocator, branches[2].last(), &branches[2]);

    // Check that the pointers returned from insert match the pointers returned from get
    for (0..4) |i| try std.testing.expectEqual(
        insert_ptrs[i],
        if (i != 2)
            try epoch_tracker.unrooted_epochs.get(&branches[i])
        else
            try epoch_tracker.rooted_epochs.get(epoch_schedule.getEpoch(branches[i].last())),
    );

    // Check we can't insert unrooted if the epoch is already rooted
    try std.testing.expectError(error.InvalidInsert, epoch_tracker.insertUnrootedEpochInfo(
        allocator,
        branches[4].last(),
        &branches[4],
        fail_stakes,
        &.ALL_DISABLED,
    ));
}
