const std = @import("std");
const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;

// inlined to avoid solana_clock dep
const DEFAULT_SLOTS_PER_EPOCH: u64 = 432_000;

/// The minimum number of slots per epoch during the warmup period.
///
/// Based on `MAX_LOCKOUT_HISTORY` from `vote_program`.
pub const MINIMUM_SLOTS_PER_EPOCH: u64 = 32;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/epoch-schedule/src/lib.rs#L56
pub const EpochSchedule = struct {
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
    first_normal_epoch: Epoch,

    /// The first slot after the warmup period.
    ///
    /// Basically: `MINIMUM_SLOTS_PER_EPOCH * (2.pow(first_normal_epoch) - 1)`.
    first_normal_slot: Slot,

    pub const ID =
        Pubkey.parseBase58String("SysvarEpochSchedu1e111111111111111111111111") catch unreachable;

    pub const DEFAULT = EpochSchedule.custom(
        DEFAULT_SLOTS_PER_EPOCH,
        DEFAULT_SLOTS_PER_EPOCH,
        true,
    ) catch unreachable;

    pub fn custom(
        slots_per_epoch: Slot,
        leader_schedule_slot_offset: Slot,
        warmup: bool,
    ) !EpochSchedule {
        std.debug.assert(slots_per_epoch >= MINIMUM_SLOTS_PER_EPOCH);
        const first_normal_epoch, const first_normal_slot = if (warmup) blk: {
            const next_power_of_two = std.math.ceilPowerOfTwo(Slot, slots_per_epoch) catch 0;
            break :blk .{
                @ctz(next_power_of_two) -| @ctz(MINIMUM_SLOTS_PER_EPOCH),
                next_power_of_two -| MINIMUM_SLOTS_PER_EPOCH,
            };
        } else .{ 0, 0 };
        return EpochSchedule{
            .slots_per_epoch = slots_per_epoch,
            .leader_schedule_slot_offset = leader_schedule_slot_offset,
            .warmup = warmup,
            .first_normal_epoch = first_normal_epoch,
            .first_normal_slot = first_normal_slot,
        };
    }
};
