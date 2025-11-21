//! This file represents the data stored in agave's `Bank` struct. Sig does not
//! have an analogous struct because `Bank` is a massive disorganized struct
//! without unbounded responsibilities that makes the code hard to understand
//! and makes dependencies difficult to manage.
//!
//! Instead we have more granular, digestible structs with clear scopes, like
//! SlotConstants, SlotState, and EpochConstants. These store much of the same
//! data that's stored in agave's Bank. Other heavyweight fields from agave's
//! Bank like like `BankRc` (containing a pointer to accountsdb) and
//! `TransactionBatchProcessor` are not included in any "bank" struct in sig.
//! Instead, those large dependencies are managed independently.
//!
//! The philosophy is that breaking the Bank into separate pieces will enable us
//! to write code with a more minimal, clearer set of dependencies, to make the
//! code easier to understand and maintain.

const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const core = sig.core;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const Random = std.Random;

const RwMux = sig.sync.RwMux;

const SlotAccountReader = sig.accounts_db.account_store.SlotAccountReader;

const BlockhashQueue = core.BlockhashQueue;
const EpochSchedule = core.epoch_schedule.EpochSchedule;
const FeatureSet = core.FeatureSet;
const Hash = core.hash.Hash;
const HardForks = core.HardForks;
const LtHash = core.hash.LtHash;
const Pubkey = core.pubkey.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;
const ReservedAccounts = sig.core.ReservedAccounts;
const VoteAccount = sig.core.stakes.VoteAccount;
const EpochStakes = sig.core.EpochStakes;

const Epoch = core.time.Epoch;
const Slot = core.time.Slot;
const UnixTimestamp = core.time.UnixTimestamp;

const FeeRateGovernor = core.genesis_config.FeeRateGovernor;
const Inflation = core.genesis_config.Inflation;

const Ancestors = sig.core.Ancestors;
const EpochStakesMap = core.EpochStakesMap;
const Stakes = core.Stakes;

const StakeStateV2 = sig.runtime.program.stake.StakeStateV2;
const VoteState = sig.runtime.program.vote.state.VoteState;
const EpochRewardStatus = sig.replay.rewards.EpochRewardStatus;

const deinitMapAndValues = sig.utils.collections.deinitMapAndValues;
const cloneMapAndValues = sig.utils.collections.cloneMapAndValues;

const AtomicSlot = std.atomic.Value(Slot);

/// This is a WORK AROUND for our current lack of fork awareness outside of replay.
/// It ATTEMPTS to satisfy immediate requirements to run on testnet.
/// It MUST be replaced by a better implementation as soon as possible.
pub const MagicInfo = struct {
    /// The most recently rooted slot, set by consensus.
    root_slot: AtomicSlot,

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
        root_slot: Slot,
        epoch_schedule: EpochSchedule,
    ) MagicInfo {
        return .{
            .root_slot = .init(root_slot),
            .epoch_schedule = epoch_schedule,
            .rooted_epochs = .{},
            .unrooted_epochs = .{},
        };
    }

    pub fn deinit(self: *MagicInfo, allocator: Allocator) void {
        self.rooted_epochs.deinit(allocator);
        self.unrooted_epochs.deinit(allocator);
    }

    pub fn getLeaderSchedule(
        self: *const MagicInfo,
        slot: Slot,
    ) !LeaderSchedule {
        const epoch = self.epoch_schedule.getEpoch(slot -| self.epoch_schedule.leader_schedule_slot_offset);
        return .{
            .leaders = (try self.rooted_epochs.get(epoch)).leaders,
            .start = self.epoch_schedule.getFirstSlotInEpoch(epoch),
        };
    }

    pub fn onSlotRooted(
        self: *MagicInfo,
        allocator: Allocator,
        slot: Slot,
        ancestors: *const Ancestors,
    ) !void {
        if (self.rooted_epochs.isNext(self.epoch_schedule.getEpoch(slot)))
            try self.onFirstSlotInEpochRooted(allocator, ancestors);
        self.root_slot.store(slot, .monotonic);
    }

    fn onFirstSlotInEpochRooted(
        self: *MagicInfo,
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

    pub fn insertUnrootedEpochInfo(
        self: *MagicInfo,
        allocator: Allocator,
        slot: Slot,
        ancestors: *const Ancestors,
        epoch_info: EpochInfo,
    ) !*const EpochInfo {
        const epoch = self.epoch_schedule.getEpoch(slot);
        if (!self.rooted_epochs.isNext(epoch)) return error.InvalidInsert;
        return try self.unrooted_epochs.insert(
            allocator,
            slot,
            ancestors,
            epoch_info,
        );
    }
};

pub const EpochInfo = struct {
    leaders: []const Pubkey,
    stakes: EpochStakes,

    pub fn deinit(self: *const EpochInfo, allocator: Allocator) void {
        allocator.free(self.leaders);
        self.stakes.deinit(allocator);
    }

    pub fn init(leaders: []const Pubkey, stakes: EpochStakes) !EpochInfo {
        return .{
            .leaders = leaders,
            .stakes = stakes,
        };
    }

    pub fn initRandom(allocator: Allocator, random: Random, options: struct {
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

        const slots_in_epoch = options.schedule.getSlotsInEpoch(epoch);
        const leaders = try allocator.alloc(Pubkey, slots_in_epoch);
        for (leaders) |*leader| leader.* = Pubkey.initRandom(random);

        return .init(leaders, stakes);
    }
};

pub const LeaderSchedule = struct {
    leaders: []const Pubkey,
    start: Slot,

    pub fn getLeader(self: *const LeaderSchedule, slot: Slot) !Pubkey {
        if (slot < self.start) return error.SlotOutOfRange;
        const index = slot - self.start;
        if (index >= self.leaders.len) return error.SlotOutOfRange;
        return self.leaders[index];
    }

    pub fn initRandom(
        allocator: Allocator,
        random: Random,
        options: struct {
            epoch: ?Epoch = null,
            schedule: EpochSchedule = .INIT,
        },
    ) !LeaderSchedule {
        const epoch = options.epoch orelse random.intRangeAtMost(Epoch, 0, 1_000);

        const first_slot = options.schedule.getFirstSlotInEpoch(epoch);
        const last_slot = options.schedule.getFirstSlotInEpoch(epoch + 1) - 1;
        const num_slots = last_slot - first_slot + 1;

        const leaders = try allocator.alloc(Pubkey, num_slots);
        for (leaders) |*leader| leader.* = Pubkey.initRandom(random);

        return LeaderSchedule{
            .leaders = leaders,
            .start = first_slot,
            .last_slot = last_slot,
        };
    }
};

/// Epoch Ring Buffer which holds 4 EpochInfo entries.
///
/// Inserts must increase monotonically by exactly 1 epoch.
/// Gets must be within range of the last 4 inserted epochs.
///
/// No process should ever need to access E-3 or older EpochInfos and it is thus safe to
/// deinitialize the corresponding data when overwriting entries with new epoch data.
pub const RootedEpochBuffer = struct {
    buf: [4]?*const EpochInfo = [_]?*const EpochInfo{null} ** 4,
    root: ?Atomic(Epoch) = null,

    pub fn deinit(self: *RootedEpochBuffer, allocator: Allocator) void {
        for (0..self.buf.len) |i| {
            if (self.buf[i]) |value| {
                value.deinit(allocator);
                allocator.destroy(value);
            }
            self.buf[i] = null;
        }
        self.* = undefined;
    }

    pub fn insert(
        self: *RootedEpochBuffer,
        allocator: Allocator,
        value: *const EpochInfo,
    ) !void {
        const epoch = value.stakes.stakes.epoch;

        if (self.root != null and epoch != self.root.?.load(.monotonic) + 1)
            return error.InvalidInsert;

        const index = epoch & (self.buf.len - 1);
        if (self.buf[index]) |old_value| {
            old_value.deinit(allocator);
            allocator.destroy(old_value);
        }

        self.buf[index] = value;
        if (self.root == null)
            self.root = .init(epoch)
        else
            self.root.?.store(epoch, .monotonic);
    }

    pub fn get(
        self: *const RootedEpochBuffer,
        epoch: Epoch,
    ) !*const EpochInfo {
        const root_epoch = (self.root orelse return error.EpochNotFound).load(.monotonic);

        if (epoch > root_epoch or
            epoch < root_epoch - self.buf.len + 1 or
            self.buf[epoch & (self.buf.len - 1)] == null) return error.EpochNotFound;

        const epoch_at_index = self.buf[epoch & (self.buf.len - 1)].?.stakes.stakes.epoch;
        if (epoch != epoch_at_index) return error.EpochOverwritten;

        return self.buf[epoch & (self.buf.len - 1)].?;
    }

    pub fn isNext(self: *const RootedEpochBuffer, epoch: Epoch) bool {
        return if (self.root) |root| epoch == root.load(.monotonic) + 1 else true;
    }
};

pub const UnrootedEpochBuffer = struct {
    buf: [MAX_FORKS]?struct { Slot, *const EpochInfo } = [_]?struct { Slot, *const EpochInfo }{null} ** MAX_FORKS,

    pub const MAX_FORKS = 4;

    pub fn deinit(self: *UnrootedEpochBuffer, allocator: Allocator) void {
        for (0..self.buf.len) |i| {
            if (self.buf[i]) |entry| {
                _, const info = entry;
                info.deinit(allocator);
                allocator.destroy(info);
            }
            self.buf[i] = null;
        }
        self.* = undefined;
    }

    pub fn insert(
        self: *UnrootedEpochBuffer,
        allocator: Allocator,
        slot: Slot,
        ancestors: *const Ancestors,
        epoch_info: EpochInfo,
    ) !*const EpochInfo {
        const epoch = epoch_info.stakes.stakes.epoch;

        const insert_index = for (0..self.buf.len) |i| {
            if (self.buf[i] == null) {
                // Entry is free, we can use it.
                break i;
            }

            const item_slot, const item_info = self.buf[i].?;
            if (epoch > item_info.stakes.stakes.epoch) {
                // Entry occupied by old epoch, we can overwrite it.
                item_info.deinit(allocator);
                allocator.destroy(item_info);
                break i;
            } else if (epoch == item_info.stakes.stakes.epoch) {
                // Entry occupied by an existing fork.
                // Check we are not duplicating an insert for the same fork, otherwise continue.
                if (ancestors.containsSlot(item_slot)) {
                    return error.DuplicateBranch;
                }
                continue;
            } else {
                // epoch < self.buf[i].?.epoch
                return error.InvalidEpoch;
            }
        } else return error.MaxForksExceeded;

        const info_ptr = try allocator.create(EpochInfo);
        info_ptr.* = epoch_info;
        self.buf[insert_index] = .{ slot, info_ptr };

        return info_ptr;
    }

    pub fn get(
        self: *const UnrootedEpochBuffer,
        ancestors: *const Ancestors,
    ) !*const EpochInfo {
        return for (0..self.buf.len) |i| {
            if (self.buf[i] != null and ancestors.containsSlot(self.buf[i].?[0])) {
                break self.buf[i].?[1];
            }
        } else error.ForkNotFound;
    }

    pub fn take(
        self: *UnrootedEpochBuffer,
        ancestors: *const Ancestors,
    ) !*const EpochInfo {
        return for (0..self.buf.len) |i| {
            if (self.buf[i] != null and ancestors.containsSlot(self.buf[i].?[0])) {
                const info = self.buf[i].?[1];
                self.buf[i] = null;
                break info;
            }
        } else error.ForkNotFound;
    }
};

test "RootedEpochBuffer" {
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
        expected[i] = EpochInfo{
            .leaders = try allocator.dupe(Pubkey, info.leaders),
            .stakes = try info.stakes.clone(allocator),
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
            expected_info.leaders,
            info.leaders,
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

test "UnrootedEpochBuffer" {
    // TODO: Implement specific tests for UnrootedEpochBuffer
}

test "MagicInfo" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const epoch_schedule = EpochSchedule.custom(.{
        .slots_per_epoch = 32,
        .leader_schedule_slot_offset = 32,
        .warmup = false,
    });

    // Begin test at last slot in epoch 0
    var magic = MagicInfo.init(31, epoch_schedule);
    defer magic.deinit(allocator);

    // Only the root slot is set
    try std.testing.expectEqual(31, magic.root_slot.load(.monotonic));
    try std.testing.expectError(error.EpochNotFound, magic.getLeaderSchedule(0));
    try std.testing.expectError(error.EpochNotFound, magic.rooted_epochs.get(0));
    try std.testing.expectError(error.ForkNotFound, magic.unrooted_epochs.get(&.EMPTY));

    // Fill the buffers with epochs by inserting and then rooting the first slot for 10 epochs
    for (0..10) |epoch| {
        var branch = try Ancestors.initWithSlots(
            allocator,
            &.{epoch_schedule.getFirstSlotInEpoch(epoch)},
        );
        defer branch.deinit(allocator);

        const epoch_info = try EpochInfo.initRandom(
            allocator,
            random,
            .{ .epoch = epoch },
        );

        _ = try magic.insertUnrootedEpochInfo(
            allocator,
            branch.maxSlot(),
            &branch,
            epoch_info,
        );

        try magic.onSlotRooted(allocator, branch.maxSlot(), &branch);
    }

    // Check that the root slot is 9 * 32 and epochs 6, 7, 8, 9 are available
    try std.testing.expectEqual(9 * 32, magic.root_slot.load(.monotonic));
    try std.testing.expectEqual(6, (try magic.rooted_epochs.get(6)).stakes.stakes.epoch);
    try std.testing.expectEqual(7, (try magic.rooted_epochs.get(7)).stakes.stakes.epoch);
    try std.testing.expectEqual(8, (try magic.rooted_epochs.get(8)).stakes.stakes.epoch);
    try std.testing.expectEqual(9, (try magic.rooted_epochs.get(9)).stakes.stakes.epoch);

    // Empty stakes for failing inserts
    var empty_stakes = EpochStakes.EMPTY;

    // Check that trying to insert epoch info for epoch 9 fails because it is already rooted
    const branch = try Ancestors.initWithSlots(allocator, &.{319});
    defer branch.deinit(allocator);
    empty_stakes.stakes.epoch = epoch_schedule.getEpoch(branch.maxSlot());
    try std.testing.expectError(error.InvalidInsert, magic.insertUnrootedEpochInfo(
        allocator,
        branch.maxSlot(),
        &branch,
        .{ .leaders = &.{}, .stakes = empty_stakes },
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
    for (0..4) |i| insert_ptrs[i] = try magic.insertUnrootedEpochInfo(
        allocator,
        branches[i].maxSlot(),
        &branches[i],
        try EpochInfo.initRandom(
            allocator,
            random,
            .{ .epoch = epoch_schedule.getEpoch(branches[i].maxSlot()) },
        ),
    );

    // Check that the pointers returned from insert match the pointers returned from get
    for (0..4) |i| try std.testing.expectEqual(
        insert_ptrs[i],
        try magic.unrooted_epochs.get(&branches[i]),
    );

    // Check that another insert hits max forks
    empty_stakes.stakes.epoch = epoch_schedule.getEpoch(branches[4].maxSlot());
    try std.testing.expectError(error.MaxForksExceeded, magic.insertUnrootedEpochInfo(
        allocator,
        branches[4].maxSlot(),
        &branches[4],
        .{ .leaders = &.{}, .stakes = empty_stakes },
    ));

    // Root the first slot from branch 2
    try magic.onSlotRooted(allocator, branches[2].maxSlot(), &branches[2]);

    // Check that the pointers returned from insert match the pointers returned from get
    for (0..4) |i| try std.testing.expectEqual(
        insert_ptrs[i],
        if (i != 2)
            try magic.unrooted_epochs.get(&branches[i])
        else
            try magic.rooted_epochs.get(epoch_schedule.getEpoch(branches[i].maxSlot())),
    );

    // Check that another insert hits max forks
    try std.testing.expectError(error.InvalidInsert, magic.insertUnrootedEpochInfo(
        allocator,
        branches[4].maxSlot(),
        &branches[4],
        .{ .leaders = &.{}, .stakes = empty_stakes },
    ));

    // // Branch A now contains
    // // Duplicate insert on the same branch is not allowed
    // try std.testing.expectError(error.InvalidInsert, magic.insertUnrootedEpochInfo(
    //     allocator,
    //     branch_a.maxSlot() + 5,
    //     &branch_a,
    //     rooted_info_0.*,
    // ));

    // // Calling onSlotRooted before inserting unrooted stakes returns error
    // try std.testing.expectError(
    //     error.ForkNotFound,
    //     magic.onSlotRooted(allocator, &.EMPTY),
    // );

    // // Calling insertUnrootedEpochStakes fails if the slot / epoch is not the next epoch
    // try std.testing.expectError(
    //     error.InvalidInsert,
    //     magic.insertUnrootedEpochStakes(allocator, 64, &.EMPTY, .EMPTY),
    // );

    // // Create 5 Forks across the epoch 0 -> epoch 1 boundary
    // const forks = try allocator.alloc(struct { slot: Slot, ancestors: Ancestors }, 5);
    // defer {
    //     for (forks) |fork| fork.ancestors.deinit(allocator);
    //     allocator.free(forks);
    // }
    // for (forks, 0..) |*fork, i| {
    //     fork.* = .{
    //         .slot = 32 + i,
    //         .ancestors = try Ancestors.initWithSlots(allocator, &.{ 31, 32 + i }),
    //     };
    // }

    // for (0..4) |i| {
    //     try magic.insertUnrootedEpochStakes(
    //         allocator,
    //         forks[i].slot,
    //         &forks[i].ancestors,
    //         try EpochStakes.initRandom(allocator, random, .{ .epoch = 1 }),
    //     );
    // }

    // // Check that inserting fork 5 hits a max forks error
    // try std.testing.expectError(error.MaxForksExceeded, magic.insertUnrootedEpochStakes(
    //     allocator,
    //     forks[4].slot,
    //     &forks[4].ancestors,
    //     .EMPTY,
    // ));

    // // Get references to forks 0..4
    // const stake_refs: [4]*const EpochStakes = .{
    //     try magic.getEpochStakesForSlot(forks[0].slot, &forks[0].ancestors),
    //     try magic.getEpochStakesForSlot(forks[1].slot, &forks[1].ancestors),
    //     try magic.getEpochStakesForSlot(forks[2].slot, &forks[2].ancestors),
    //     try magic.getEpochStakesForSlot(forks[3].slot, &forks[3].ancestors),
    // };

    // // Root Fork 2
    // // try magic.onSlotRooted(allocator, &forks[2].ancestors);
    // // std.debug.print("{}", .{stake_refs[1].stakes.epoch});
    // var eav = try stake_refs[2].epoch_authorized_voters.clone(allocator);
    // defer eav.deinit(allocator);
    // var ntv = try stake_refs[2].node_id_to_vote_accounts.clone(allocator);
    // defer ntv.deinit(allocator);
    // var stakes = try stake_refs[2].stakes.clone(allocator);
    // defer stakes.deinit(allocator);
}
