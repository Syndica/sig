const std = @import("std");
const core = @import("lib.zig");

const Epoch = core.Epoch;
const Slot = core.Slot;

const DEFAULT_SLOTS_PER_EPOCH = core.time.DEFAULT_SLOTS_PER_EPOCH;

/// The default number of slots before an epoch starts to calculate the leader schedule.
pub const DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET: u64 = DEFAULT_SLOTS_PER_EPOCH;

/// The minimum number of slots per epoch during the warmup period.
///
/// Based on `MAX_LOCKOUT_HISTORY` from `vote_program`.
pub const MINIMUM_SLOTS_PER_EPOCH: u64 = 32;

/// Analogous to [EpochSchedule](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/sdk/program/src/epoch_schedule.rs#L35)
pub const EpochSchedule = extern struct {
    /// The maximum number of slots in each epoch.
    slots_per_epoch: u64,

    /// A number of slots before beginning of an epoch to calculate
    /// a leader schedule for that epoch.
    leader_schedule_slot_offset: u64,

    /// Whether epochs start short and grow.
    warmup: bool,

    /// The first epoch after the warmup period.
    ///
    /// Basically: `log2(slots_per_epoch) - log2(MINIMUM_SLOTS_PER_EPOCH)`.
    first_normal_epoch: core.Epoch,

    /// The first slot after the warmup period.
    ///
    /// Basically: `MINIMUM_SLOTS_PER_EPOCH * (2.pow(first_normal_epoch) - 1)`.
    first_normal_slot: core.Slot,

    pub const ID: core.Pubkey = .parse("SysvarEpochSchedu1e111111111111111111111111");
    pub const STORAGE_SIZE: u64 = 33;
    pub const DEFAULT: EpochSchedule = .custom(.{
        .slots_per_epoch = DEFAULT_SLOTS_PER_EPOCH,
        .leader_schedule_slot_offset = DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET,
        .warmup = true,
    });

    pub const SIZE_OF: u64 = @sizeOf(EpochSchedule);

    pub fn getEpoch(self: *const EpochSchedule, slot: Slot) Epoch {
        return self.getEpochAndSlotIndex(slot)[0];
    }

    pub fn getEpochAndSlotIndex(self: *const EpochSchedule, slot: Slot) struct { Epoch, usize } {
        if (slot < self.first_normal_slot) {
            var epoch = slot +| MINIMUM_SLOTS_PER_EPOCH +| 1;
            epoch = @ctz(std.math.ceilPowerOfTwo(u64, epoch) catch {
                std.debug.panic("failed to ceil power of two: {d}", .{epoch});
            }) -| @ctz(MINIMUM_SLOTS_PER_EPOCH) -| 1;

            const exponent = epoch +| @ctz(MINIMUM_SLOTS_PER_EPOCH);
            const epoch_len = std.math.powi(u64, 2, exponent) catch std.math.maxInt(u64);

            const slot_index = slot -| (epoch_len -| MINIMUM_SLOTS_PER_EPOCH);

            return .{ epoch, slot_index };
        } else {
            const normal_slot_index = slot -| self.first_normal_slot;
            const normal_epoch_index = std.math.divTrunc(
                u64,
                normal_slot_index,
                self.slots_per_epoch,
            ) catch 0;

            const epoch = self.first_normal_epoch +| normal_epoch_index;
            const slot_index = std.math.rem(u64, normal_slot_index, self.slots_per_epoch) catch 0;

            return .{ epoch, @intCast(slot_index) };
        }
    }

    pub fn getSlotsInEpoch(self: *const EpochSchedule, epoch: Epoch) u64 {
        comptime std.debug.assert(std.math.isPowerOfTwo(MINIMUM_SLOTS_PER_EPOCH));
        return if (epoch < self.first_normal_epoch)
            @as(Slot, 1) <<| epoch +| @ctz(MINIMUM_SLOTS_PER_EPOCH)
        else
            self.slots_per_epoch;
    }

    pub fn getFirstSlotInEpoch(self: *const EpochSchedule, epoch: Epoch) Slot {
        if (epoch <= self.first_normal_epoch) {
            const x = if (epoch >= 64)
                std.math.maxInt(u64)
            else
                std.math.pow(Epoch, 2, epoch);
            return (x -| 1) *| MINIMUM_SLOTS_PER_EPOCH;
        } else {
            return ((epoch -| self.first_normal_epoch) *|
                self.slots_per_epoch) +|
                self.first_normal_slot;
        }
    }

    pub fn getLastSlotInEpoch(self: *const EpochSchedule, epoch: Epoch) Slot {
        return self.getFirstSlotInEpoch(epoch) +| self.getSlotsInEpoch(epoch) -| 1;
    }

    pub fn getLeaderScheduleEpoch(self: *const EpochSchedule, slot: Slot) u64 {
        if (slot < self.first_normal_slot) {
            return self.getEpochAndSlotIndex(slot)[0] +| 1;
        } else {
            return self.first_normal_epoch +|
                (((slot -| self.first_normal_slot) +|
                    self.leader_schedule_slot_offset) / self.slots_per_epoch);
        }
    }

    pub fn custom(
        slots_per_epoch: u64,
        leader_schedule_slot_offset: u64,
        warmup: bool,
    ) !EpochSchedule {
        std.debug.assert(slots_per_epoch >= MINIMUM_SLOTS_PER_EPOCH);
        var first_normal_epoch: Epoch = 0;
        var first_normal_slot: Slot = 0;
        if (warmup) {
            std.debug.assert(slots_per_epoch <= std.math.maxInt(u63));
            const next_power_of_two = std.math.ceilPowerOfTwoAssert(u64, slots_per_epoch);
            const log2_slots_per_epoch = @ctz(next_power_of_two) -| @ctz(MINIMUM_SLOTS_PER_EPOCH);
            first_normal_epoch = log2_slots_per_epoch;
            first_normal_slot = next_power_of_two -| MINIMUM_SLOTS_PER_EPOCH;
        }
        return .{
            .slots_per_epoch = slots_per_epoch,
            .leader_schedule_slot_offset = leader_schedule_slot_offset,
            .warmup = warmup,
            .first_normal_epoch = first_normal_epoch,
            .first_normal_slot = first_normal_slot,
        };
    }

    pub fn initRandom(random: std.Random) EpochSchedule {
        return .{
            .slots_per_epoch = random.int(u64),
            .leader_schedule_slot_offset = random.int(u64),
            .warmup = random.boolean(),
            .first_normal_epoch = random.int(Epoch),
            .first_normal_slot = random.int(Slot),
        };
    }
};

test "epoch_schedule" {
    for (MINIMUM_SLOTS_PER_EPOCH..MINIMUM_SLOTS_PER_EPOCH * 16) |slots_per_epoch| {
        const epoch_schedule = try EpochSchedule.custom(
            slots_per_epoch,
            slots_per_epoch / 2,
            true,
        );

        try std.testing.expectEqual(epoch_schedule.getFirstSlotInEpoch(0), 0);
        try std.testing.expectEqual(
            epoch_schedule.getLastSlotInEpoch(0),
            MINIMUM_SLOTS_PER_EPOCH - 1,
        );

        var last_leader_schedule: u64 = 0;
        var last_epoch: u64 = 0;
        var last_slots_in_epoch: u64 = MINIMUM_SLOTS_PER_EPOCH;

        for (0..2 * slots_per_epoch) |slot| {
            const leader_schedule = epoch_schedule.getLeaderScheduleEpoch(slot);
            if (leader_schedule != last_leader_schedule) {
                try std.testing.expectEqual(leader_schedule, last_leader_schedule + 1);
                last_leader_schedule = leader_schedule;
            }

            const epoch, const offset = epoch_schedule.getEpochAndSlotIndex(slot);

            if (epoch != last_epoch) {
                try std.testing.expectEqual(epoch, last_epoch + 1);
                last_epoch = epoch;

                try std.testing.expectEqual(epoch_schedule.getFirstSlotInEpoch(epoch), slot);
                try std.testing.expectEqual(epoch_schedule.getLastSlotInEpoch(epoch - 1), slot - 1);

                const slots_in_epoch = epoch_schedule.getSlotsInEpoch(epoch);
                if (slots_in_epoch != last_slots_in_epoch and slots_in_epoch != slots_per_epoch) {
                    try std.testing.expectEqual(slots_in_epoch, last_slots_in_epoch * 2);
                }
                last_slots_in_epoch = slots_in_epoch;
            }

            try std.testing.expect(offset < last_slots_in_epoch);
        }

        try std.testing.expect(last_leader_schedule != 0);
        try std.testing.expect(last_epoch != 0);
        try std.testing.expectEqual(slots_per_epoch, last_slots_in_epoch);
    }
}
