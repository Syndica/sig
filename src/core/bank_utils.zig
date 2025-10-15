const std = @import("std");
const sig = @import("../sig.zig");

const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const EpochSchedule = sig.core.EpochSchedule;
const FeatureSet = sig.core.FeatureSet;

/// Returns the slot at which inflation starts, based on the feature set.
/// If full inflation is enabled for either mainnet or devnet/testnet, returns the
/// earlier of the two feature activation slots. If neither full inflation feature is enabled,
/// returns the pico inflation feature activation slot, or 0 if pico inflation is not enabled.
pub fn getInflationStartSlot(slot: Slot, feature_set: *const FeatureSet) Slot {
    const full_inflation_features = feature_set.fullInflationFeatures(slot);

    const mainnet_slot = full_inflation_features.mainnetSlot(feature_set);
    const devnet_and_testnet_slot = full_inflation_features.devnetAndTestnetSlot(feature_set);

    if (mainnet_slot != null or devnet_and_testnet_slot != null) {
        return @min(
            mainnet_slot orelse std.math.maxInt(Slot),
            devnet_and_testnet_slot orelse std.math.maxInt(Slot),
        );
    }

    return if (feature_set.active(.pico_inflation, slot))
        feature_set.get(.pico_inflation).?
    else
        0;
}

pub fn getInflationNumSlots(
    slot: Slot,
    epoch: Epoch,
    feature_set: *const FeatureSet,
    epoch_schedule: *const EpochSchedule,
) u64 {
    const inflation_activation_slot = getInflationStartSlot(slot, feature_set);
    const inflation_start_slot = epoch_schedule.getFirstSlotInEpoch(epoch_schedule.getEpoch(inflation_activation_slot) -| 1);
    return epoch_schedule.getFirstSlotInEpoch(epoch) - inflation_start_slot;
}

pub fn getSlotInYearsForInflation(
    slot: Slot,
    epoch: Epoch,
    slots_per_year: f64,
    feature_set: *const FeatureSet,
    epoch_schedule: *const EpochSchedule,
) f64 {
    std.debug.assert(slots_per_year > 0.0);
    const num_slots = getInflationNumSlots(slot, epoch, feature_set, epoch_schedule);
    return @as(f64, @floatFromInt(num_slots)) / slots_per_year;
}

pub fn getEpochDurationInYears(
    epoch: Epoch,
    slots_per_year: f64,
    epoch_schedule: *const EpochSchedule,
) f64 {
    std.debug.assert(slots_per_year > 0.0);
    return @as(f64, @floatFromInt(epoch_schedule.getSlotsInEpoch(epoch))) / slots_per_year;
}

test getInflationStartSlot {
    {
        const feature_set = FeatureSet.ALL_DISABLED;
        try std.testing.expectEqual(0, getInflationStartSlot(0, &feature_set));
        try std.testing.expectEqual(0, getInflationStartSlot(1_000, &feature_set));
        try std.testing.expectEqual(0, getInflationStartSlot(2_000, &feature_set));
    }

    {
        var feature_set = FeatureSet.ALL_DISABLED;
        feature_set.setSlot(.pico_inflation, 10);
        try std.testing.expectEqual(0, getInflationStartSlot(0, &feature_set));
        try std.testing.expectEqual(0, getInflationStartSlot(9, &feature_set));
        try std.testing.expectEqual(10, getInflationStartSlot(10, &feature_set));
        try std.testing.expectEqual(10, getInflationStartSlot(1_000, &feature_set));
    }

    {
        var feature_set = FeatureSet.ALL_DISABLED;
        feature_set.setSlot(.full_inflation_devnet_and_testnet, 10);
        try std.testing.expectEqual(0, getInflationStartSlot(0, &feature_set));
        try std.testing.expectEqual(0, getInflationStartSlot(9, &feature_set));
        try std.testing.expectEqual(10, getInflationStartSlot(10, &feature_set));
        try std.testing.expectEqual(10, getInflationStartSlot(1_000, &feature_set));
    }

    {
        var feature_set = FeatureSet.ALL_DISABLED;
        feature_set.setSlot(.full_inflation_mainnet_enable, 10);
        try std.testing.expectEqual(0, getInflationStartSlot(0, &feature_set));
        try std.testing.expectEqual(0, getInflationStartSlot(9, &feature_set));
        try std.testing.expectEqual(0, getInflationStartSlot(10, &feature_set));
        try std.testing.expectEqual(0, getInflationStartSlot(1_000, &feature_set));
    }

    {
        var feature_set = FeatureSet.ALL_DISABLED;
        feature_set.setSlot(.full_inflation_mainnet_vote, 10);
        feature_set.setSlot(.full_inflation_mainnet_enable, 10);
        try std.testing.expectEqual(0, getInflationStartSlot(0, &feature_set));
        try std.testing.expectEqual(0, getInflationStartSlot(9, &feature_set));
        try std.testing.expectEqual(10, getInflationStartSlot(10, &feature_set));
        try std.testing.expectEqual(10, getInflationStartSlot(1_000, &feature_set));
    }

    {
        var feature_set = FeatureSet.ALL_DISABLED;
        feature_set.setSlot(.pico_inflation, 9);
        feature_set.setSlot(.full_inflation_devnet_and_testnet, 10);
        try std.testing.expectEqual(0, getInflationStartSlot(0, &feature_set));
        try std.testing.expectEqual(9, getInflationStartSlot(9, &feature_set));
        try std.testing.expectEqual(10, getInflationStartSlot(10, &feature_set));
        try std.testing.expectEqual(10, getInflationStartSlot(999, &feature_set));
    }

    {
        var feature_set = FeatureSet.ALL_DISABLED;
        feature_set.setSlot(.full_inflation_mainnet_vote, 9);
        feature_set.setSlot(.full_inflation_mainnet_enable, 9);
        feature_set.setSlot(.full_inflation_devnet_and_testnet, 10);
        try std.testing.expectEqual(0, getInflationStartSlot(0, &feature_set));
        try std.testing.expectEqual(9, getInflationStartSlot(9, &feature_set));
        try std.testing.expectEqual(9, getInflationStartSlot(10, &feature_set));
        try std.testing.expectEqual(9, getInflationStartSlot(999, &feature_set));
    }
}

test getInflationNumSlots {
    const slots_per_epoch = 32;
    const epoch_schedule = EpochSchedule.custom(.{
        .slots_per_epoch = slots_per_epoch,
        .leader_schedule_slot_offset = slots_per_epoch,
        .warmup = true,
    });

    var slot: Slot = 0;
    var epoch: Epoch = 0;

    // Slot 0, epoch 0, no features activated
    var feature_set = FeatureSet.ALL_DISABLED;
    try std.testing.expectEqual(0, getInflationNumSlots(slot, epoch, &feature_set, &epoch_schedule));

    // Move forward 2 epochs
    slot += 2 * slots_per_epoch;
    epoch += 2;
    try std.testing.expectEqual(2 * slots_per_epoch, getInflationNumSlots(slot, epoch, &feature_set, &epoch_schedule));

    // Activate pico inflation
    feature_set.setSlot(.pico_inflation, slot);
    try std.testing.expectEqual(slots_per_epoch, getInflationNumSlots(slot, epoch, &feature_set, &epoch_schedule));

    // Move forward 1 epoch
    slot += slots_per_epoch;
    epoch += 1;
    try std.testing.expectEqual(2 * slots_per_epoch, getInflationNumSlots(slot, epoch, &feature_set, &epoch_schedule));

    // Activate full inflation for devnet/testnet
    feature_set.setSlot(.full_inflation_devnet_and_testnet, slot);
    try std.testing.expectEqual(slots_per_epoch, getInflationNumSlots(slot, epoch, &feature_set, &epoch_schedule));

    // Move forward 1 epoch
    slot += slots_per_epoch;
    epoch += 1;
    try std.testing.expectEqual(2 * slots_per_epoch, getInflationNumSlots(slot, epoch, &feature_set, &epoch_schedule));

    // Activate full inflation for mainnet -- should have no effect
    feature_set.setSlot(.full_inflation_mainnet_enable, slot);
    feature_set.setSlot(.full_inflation_mainnet_vote, slot);
    try std.testing.expectEqual(2 * slots_per_epoch, getInflationNumSlots(slot, epoch, &feature_set, &epoch_schedule));

    // Deactivate full inflation for devnet/testnet -- will revert to full inflation mainnet
    feature_set.setSlot(.full_inflation_devnet_and_testnet, std.math.maxInt(Slot));
    try std.testing.expectEqual(slots_per_epoch, getInflationNumSlots(slot, epoch, &feature_set, &epoch_schedule));

    // Move forward 1 epoch
    slot += slots_per_epoch;
    epoch += 1;
    try std.testing.expectEqual(2 * slots_per_epoch, getInflationNumSlots(slot, epoch, &feature_set, &epoch_schedule));
}

test getSlotInYearsForInflation {
    const slots_per_year: f64 = 2_000.5;
    const slots_per_epoch = 32;
    const epoch_schedule = EpochSchedule.custom(.{
        .slots_per_epoch = slots_per_epoch,
        .leader_schedule_slot_offset = slots_per_epoch,
        .warmup = true,
    });

    var slot: Slot = 0;
    var epoch: Epoch = 0;

    // Slot 0, epoch 0, no features activated
    var feature_set = FeatureSet.ALL_DISABLED;
    try std.testing.expectEqual(0, getSlotInYearsForInflation(slot, epoch, slots_per_year, &feature_set, &epoch_schedule));

    // Move forward 2 epochs
    slot += 2 * slots_per_epoch;
    epoch += 2;
    try std.testing.expectEqual(
        @as(f64, @floatFromInt(2 * slots_per_epoch)) / slots_per_year,
        getSlotInYearsForInflation(slot, epoch, slots_per_year, &feature_set, &epoch_schedule),
    );
}

test getEpochDurationInYears {
    const slots_per_year = 2_000.5;
    const slots_per_epoch: u64 = 32;
    const epoch_schedule = EpochSchedule.custom(.{
        .slots_per_epoch = slots_per_epoch,
        .leader_schedule_slot_offset = slots_per_epoch,
        .warmup = true,
    });

    try std.testing.expectEqual(
        @as(f64, slots_per_epoch) / slots_per_year,
        getEpochDurationInYears(0, slots_per_year, &epoch_schedule),
    );
}
