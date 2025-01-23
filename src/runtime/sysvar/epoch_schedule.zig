// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/epoch-schedule/src/lib.rs
// https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h

const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;

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
    first_normal_epoch: u64,

    /// The first slot after the warmup period.
    ///
    /// Basically: `MINIMUM_SLOTS_PER_EPOCH * (2.pow(first_normal_epoch) - 1)`.
    first_normal_slot: u64,
};
