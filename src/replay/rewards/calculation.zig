const std = @import("std");
const sig = @import("../../sig.zig");

const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const EpochSchedule = sig.core.EpochSchedule;
const FeatureSet = sig.core.FeatureSet;
const Inflation = sig.core.Inflation;

const PreviousEpochInflationRewards = sig.replay.rewards.PreviousEpochInflationRewards;

const bank_utils = sig.core.bank_utils;

fn calculatePreviousEpochInflationRewards(
    slot: Slot,
    epoch: Epoch,
    slots_per_year: f64,
    previous_epoch: Epoch,
    previous_epoch_capitalization: u64,
    epoch_schedule: *const EpochSchedule,
    feature_set: *const FeatureSet,
    inflation: *const Inflation,
) PreviousEpochInflationRewards {
    const slot_in_years = bank_utils.getSlotInYearsForInflation(
        slot,
        epoch,
        slots_per_year,
        feature_set,
        epoch_schedule,
    );

    const validator_rate = inflation.validatorRate(slot_in_years);
    const foundation_rate = inflation.foundationRate(slot_in_years);

    const previous_epoch_duration_in_years = bank_utils.getEpochDurationInYears(
        previous_epoch,
        slots_per_year,
        epoch_schedule,
    );

    const validator_rewards = validator_rate *
        @as(f64, @floatFromInt(previous_epoch_capitalization)) *
        previous_epoch_duration_in_years;

    return PreviousEpochInflationRewards{
        .validator_rewards = @intFromFloat(validator_rewards),
        .previous_epoch_duration_in_years = previous_epoch_duration_in_years,
        .validator_rate = validator_rate,
        .foundation_rate = foundation_rate,
    };
}

// The values in this test are derived from an Agave bank vote state rewards update test
// [agave] https://github.com/anza-xyz/agave/blob/9e6bb8209d012e819e55ad90949dec17bc150fca/runtime/src/bank/tests.rs#L799-L802
test "calculatePreviousEpochInflationRewards" {
    const slot: Slot = 33;
    const epoch: Epoch = 1;
    const previous_epoch: Epoch = 0;
    const previous_epoch_capitalization: u64 = 43074320810;
    const slots_per_year: f64 = 32.00136089369159;

    const inflation = Inflation.DEFAULT;
    const feature_set = FeatureSet.ALL_DISABLED;
    const epoch_schedule = EpochSchedule.DEFAULT;

    const result = calculatePreviousEpochInflationRewards(
        slot,
        epoch,
        slots_per_year,
        previous_epoch,
        previous_epoch_capitalization,
        &epoch_schedule,
        &feature_set,
        &inflation,
    );

    const agave_validator_rewards: u64 = 2782502021;
    const agave_previous_epoch_duration_in_years = 0.9999574738806856;
    const agave_validator_rate: f64 = 0.06460044647148322;
    const agave_foundation_rate: f64 = 0.0034000234984991173;

    try std.testing.expectEqual(agave_validator_rewards, result.validator_rewards);
    try std.testing.expectEqual(
        agave_previous_epoch_duration_in_years,
        result.previous_epoch_duration_in_years,
    );
    try std.testing.expectEqual(agave_validator_rate, result.validator_rate);
    try std.testing.expectEqual(agave_foundation_rate, result.foundation_rate);
}
