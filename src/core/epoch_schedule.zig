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
            const normal_epoch_index = std.math.divTrunc(u64, normal_slot_index, self.slots_per_epoch) catch 0;

            const epoch = self.first_normal_epoch +| normal_epoch_index;
            const slot_index = std.math.rem(u64, normal_slot_index, self.slots_per_epoch) catch 0;

            return .{ epoch, @intCast(slot_index) };
        }
    }

    pub fn getSlotsInEpoch(self: *const EpochSchedule, epoch: Epoch) Slot {
        comptime std.debug.assert(std.math.isPowerOfTwo(MINIMUM_SLOTS_PER_EPOCH));
        return if (epoch < self.first_normal_epoch)
            @as(Slot, 1) <<| epoch +| @ctz(MINIMUM_SLOTS_PER_EPOCH)
        else
            self.slots_per_epoch;
    }

    pub fn default() !EpochSchedule {
        return EpochSchedule.custom(
            DEFAULT_SLOTS_PER_EPOCH,
            DEFAULT_LEADER_SCHEDULE_SLOT_OFFSET,
            true,
        );
    }

    pub fn custom(slots_per_epoch: u64, leader_schedule_slot_offset: u64, warmup: bool) !EpochSchedule {
        std.debug.assert(slots_per_epoch > MINIMUM_SLOTS_PER_EPOCH);
        var first_normal_epoch: Epoch = 0;
        var first_normal_slot: Slot = 0;
        if (warmup) {
            const next_power_of_two = try std.math.ceilPowerOfTwo(u64, slots_per_epoch);
            const log2_slots_per_epoch = @clz(next_power_of_two) -| @clz(MINIMUM_SLOTS_PER_EPOCH);
            first_normal_epoch = @intCast(log2_slots_per_epoch);
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

    pub fn random(rand: std.Random) EpochSchedule {
        return .{
            .slots_per_epoch = rand.int(u64),
            .leader_schedule_slot_offset = rand.int(u64),
            .warmup = rand.boolean(),
            .first_normal_epoch = rand.int(Epoch),
            .first_normal_slot = rand.int(Slot),
        };
    }
};
