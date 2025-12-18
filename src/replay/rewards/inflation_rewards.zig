const std = @import("std");
const sig = @import("../../sig.zig");

const Epoch = sig.core.Epoch;
const EpochSchedule = sig.core.EpochSchedule;
const FeatureSet = sig.core.FeatureSet;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Stake = sig.runtime.program.stake.StakeStateV2.Stake;

const VoteState = sig.runtime.program.vote.state.VoteState;
const StakeHistory = sig.runtime.sysvar.StakeHistory;

pub const PointValue = struct {
    rewards: u64,
    points: u128,

    pub const ZERO: PointValue = .{ .rewards = 0, .points = 0 };
};

pub const CalculatedStakePoints = struct {
    points: u128,
    new_credits_observed: u64,
    force_credits_update_with_skipped_rewards: bool,
};

pub const CalculatedStakeRewards = struct {
    staker_rewards: u64,
    voter_rewards: u64,
    new_credits_observed: u64,
};

pub const RedeemRewardResult = struct {
    stakers_reward: u64,
    voters_reward: u64,
};

pub fn redeemRewards(
    epoch: Epoch,
    stake: *Stake,
    vote_state: *const VoteState,
    point_value: *const PointValue,
    stake_history: *const StakeHistory,
    new_rate_activation_epoch: ?Epoch,
) !RedeemRewardResult {
    const calculated_stake_rewards = try calculateStakeRewards(
        epoch,
        stake,
        point_value,
        vote_state,
        stake_history,
        new_rate_activation_epoch,
    ) orelse return error.NoCreditsToRedeem;

    stake.credits_observed = calculated_stake_rewards.new_credits_observed;
    stake.delegation.stake += calculated_stake_rewards.staker_rewards;

    return .{
        .stakers_reward = calculated_stake_rewards.staker_rewards,
        .voters_reward = calculated_stake_rewards.voter_rewards,
    };
}

pub fn calculateStakeRewards(
    epoch: Epoch,
    stake: *Stake,
    point_value: *const PointValue,
    vote_state: *const VoteState,
    stake_history: *const StakeHistory,
    new_rate_activation_epoch: ?Epoch,
) !?CalculatedStakeRewards {
    const calculated_stake_points = calculateStakePointsAndCredits(
        stake,
        vote_state,
        stake_history,
        new_rate_activation_epoch,
    );

    const points = calculated_stake_points.points;
    const new_credits_observed = calculated_stake_points.new_credits_observed;

    if (point_value.rewards == 0 or
        stake.delegation.activation_epoch == epoch or
        calculated_stake_points.force_credits_update_with_skipped_rewards)
    {
        return .{
            .staker_rewards = 0,
            .voter_rewards = 0,
            .new_credits_observed = new_credits_observed,
        };
    }

    if (points == 0 or point_value.points == 0) {
        return null;
    }

    const rewards = std.math.cast(u64, points * point_value.rewards / point_value.points) orelse
        return error.RewardsOverflow;

    if (rewards == 0) {
        return null;
    }

    const commission_split = commissionSplit(vote_state.commission, rewards);

    if (commission_split.leakedLamports()) {
        return null;
    }

    return .{
        .staker_rewards = commission_split.staker_rewards,
        .voter_rewards = commission_split.voter_rewards,
        .new_credits_observed = new_credits_observed,
    };
}

pub const CommissionSplit = struct {
    staker_rewards: u64,
    voter_rewards: u64,
    is_split: bool,

    pub fn leakedLamports(self: CommissionSplit) bool {
        // If is_split is true, there should be lamports allocated to both staker and voter.
        return (self.staker_rewards == 0 or self.voter_rewards == 0) and self.is_split;
    }
};

pub fn commissionSplit(commission: u8, rewards: u64) CommissionSplit {
    return switch (@min(commission, 100)) {
        0 => .{ .voter_rewards = 0, .staker_rewards = rewards, .is_split = false },
        100 => .{ .voter_rewards = rewards, .staker_rewards = 0, .is_split = false },
        else => |split| .{
            .voter_rewards = rewards * split / 100,
            .staker_rewards = rewards * (100 - split) / 100,
            .is_split = true,
        },
    };
}

pub fn calculatePoints(
    stake: Stake,
    vote_state: VoteState,
    stake_history: *const StakeHistory,
    new_rate_activation_epoch: ?Epoch,
) u128 {
    return calculateStakePointsAndCredits(
        &stake,
        &vote_state,
        stake_history,
        new_rate_activation_epoch,
    ).points;
}

pub fn calculateStakePointsAndCredits(
    stake: *const Stake,
    new_vote_state: *const VoteState,
    stake_history: *const StakeHistory,
    new_rate_activation_epoch: ?Epoch,
) CalculatedStakePoints {
    const credits_in_stake = stake.credits_observed;
    const credits_in_vote = new_vote_state.epochCredits();

    if (credits_in_vote == credits_in_stake) {
        return .{
            .points = 0,
            .new_credits_observed = credits_in_stake,
            .force_credits_update_with_skipped_rewards = false,
        };
    } else if (credits_in_vote < credits_in_stake) {
        return .{
            .points = 0,
            .new_credits_observed = credits_in_vote,
            .force_credits_update_with_skipped_rewards = true,
        };
    }

    var points: u128 = 0;
    var new_credits_observed: u64 = credits_in_stake;

    for (new_vote_state.epoch_credits.items) |epoch_credits| {
        const stake_amount: u128 = stake.getDelegation().getEffectiveStake(
            epoch_credits.epoch,
            stake_history,
            new_rate_activation_epoch,
        );

        const earned_credits: u128 = if (credits_in_stake < epoch_credits.prev_credits)
            epoch_credits.credits - epoch_credits.prev_credits
        else if (credits_in_stake < epoch_credits.credits)
            epoch_credits.credits - new_credits_observed
        else
            0;

        new_credits_observed = @max(new_credits_observed, epoch_credits.credits);

        const earned_points = stake_amount * earned_credits;
        points += earned_points;
    }

    return .{
        .points = points,
        .new_credits_observed = new_credits_observed,
        .force_credits_update_with_skipped_rewards = false,
    };
}

/// Returns the slot at which inflation starts, based on the feature set.
/// If full inflation is enabled for either mainnet or devnet/testnet, returns the
/// earlier of the two feature activation slots. If neither full inflation feature is enabled,
/// returns the pico inflation feature activation slot, or 0 if pico inflation is not enabled.
fn getInflationStartSlot(slot: Slot, feature_set: *const FeatureSet) Slot {
    const mainnet_vote = feature_set.get(.full_inflation_mainnet_vote) orelse std.math.maxInt(Slot);
    const mainnet = feature_set.get(.full_inflation_mainnet_enable) orelse std.math.maxInt(Slot);
    const devnet_and_testnet = feature_set.get(.full_inflation_devnet_and_testnet) orelse
        std.math.maxInt(Slot);

    return if (slot >= mainnet_vote and slot >= mainnet_vote or slot >= devnet_and_testnet)
        @min(mainnet, devnet_and_testnet)
    else if (feature_set.active(.pico_inflation, slot))
        feature_set.get(.pico_inflation).?
    else
        0;
}

fn getInflationNumSlots(
    slot: Slot,
    epoch: Epoch,
    feature_set: *const FeatureSet,
    epoch_schedule: *const EpochSchedule,
) u64 {
    const inflation_activation_slot = getInflationStartSlot(slot, feature_set);
    const inflation_start_slot = epoch_schedule.getFirstSlotInEpoch(
        epoch_schedule.getEpoch(inflation_activation_slot) -| 1,
    );
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
    const num_slots = getInflationNumSlots(
        slot,
        epoch,
        feature_set,
        epoch_schedule,
    );
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

pub fn newStakeForTest(
    stake: u64,
    voter_pubkey: Pubkey,
    epoch_credits: u64,
    activation_epoch: Epoch,
) Stake {
    return .{
        .delegation = .{
            .voter_pubkey = voter_pubkey,
            .stake = stake,
            .activation_epoch = activation_epoch,
            .deactivation_epoch = std.math.maxInt(Epoch),
        },
        .credits_observed = epoch_credits,
    };
}

test calculateStakePointsAndCredits {
    const allocator = std.testing.allocator;

    var vote_state = VoteState.DEFAULT;
    defer vote_state.deinit(allocator);

    const stake = newStakeForTest(
        10_000_000 * 1_000_000_000,
        Pubkey.ZEROES,
        vote_state.epochCredits(),
        std.math.maxInt(Epoch),
    );

    const epoch_slots: u128 = 14 * 24 * 3600 * 160;
    for (0..epoch_slots) |_| {
        try vote_state.incrementCredits(allocator, 0, 1);
    }

    try std.testing.expectEqual(
        stake.delegation.stake * epoch_slots,
        calculatePoints(stake, vote_state, &StakeHistory.INIT, null),
    );
}

test redeemRewards {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var vote_state = VoteState.DEFAULT;
    defer vote_state.deinit(allocator);

    var stake = newStakeForTest(
        1,
        Pubkey.initRandom(random),
        vote_state.epochCredits(),
        std.math.maxInt(Epoch),
    );

    {
        const rewards = redeemRewards(
            0,
            &stake,
            &vote_state,
            &.{ .rewards = 1_000_000_000, .points = 1 },
            &StakeHistory.INIT,
            null,
        );
        try std.testing.expectError(error.NoCreditsToRedeem, rewards);
    }

    try vote_state.incrementCredits(allocator, 0, 1);
    try vote_state.incrementCredits(allocator, 0, 1);

    {
        const rewards = try redeemRewards(
            0,
            &stake,
            &vote_state,
            &.{ .rewards = 1, .points = 1 },
            &StakeHistory.INIT,
            null,
        );
        try std.testing.expectEqual(
            RedeemRewardResult{ .stakers_reward = 2, .voters_reward = 0 },
            rewards,
        );
        try std.testing.expectEqual(3, stake.delegation.stake);
    }
}

test calculateStakeRewards {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var vote_state = VoteState.DEFAULT;
    defer vote_state.deinit(allocator);

    var stake = newStakeForTest(
        1,
        Pubkey.initRandom(random),
        vote_state.epochCredits(),
        std.math.maxInt(Epoch),
    );

    try std.testing.expectEqual(
        null,
        calculateStakeRewards(
            0,
            &stake,
            &.{ .rewards = 1_000_000_000, .points = 1 },
            &vote_state,
            &StakeHistory.INIT,
            null,
        ),
    );

    try vote_state.incrementCredits(allocator, 0, 1);
    try vote_state.incrementCredits(allocator, 0, 1);

    try std.testing.expectEqual(
        CalculatedStakeRewards{
            .staker_rewards = stake.delegation.stake * 2,
            .voter_rewards = 0,
            .new_credits_observed = 2,
        },
        try calculateStakeRewards(
            0,
            &stake,
            &.{ .rewards = 2, .points = 2 },
            &vote_state,
            &StakeHistory.INIT,
            null,
        ),
    );

    stake.credits_observed = 1;

    try std.testing.expectEqual(
        CalculatedStakeRewards{
            .staker_rewards = stake.delegation.stake,
            .voter_rewards = 0,
            .new_credits_observed = 2,
        },
        try calculateStakeRewards(
            0,
            &stake,
            &.{ .rewards = 1, .points = 1 },
            &vote_state,
            &StakeHistory.INIT,
            null,
        ),
    );

    try vote_state.incrementCredits(allocator, 1, 1);
    stake.credits_observed = 2;

    try std.testing.expectEqual(
        CalculatedStakeRewards{
            .staker_rewards = stake.delegation.stake,
            .voter_rewards = 0,
            .new_credits_observed = 3,
        },
        try calculateStakeRewards(
            1,
            &stake,
            &.{ .rewards = 2, .points = 2 },
            &vote_state,
            &StakeHistory.INIT,
            null,
        ),
    );

    try vote_state.incrementCredits(allocator, 2, 1);

    try std.testing.expectEqual(
        CalculatedStakeRewards{
            .staker_rewards = stake.delegation.stake * 2,
            .voter_rewards = 0,
            .new_credits_observed = 4,
        },
        try calculateStakeRewards(
            2,
            &stake,
            &.{ .rewards = 2, .points = 2 },
            &vote_state,
            &StakeHistory.INIT,
            null,
        ),
    );

    stake.credits_observed = 0;

    try std.testing.expectEqual(
        CalculatedStakeRewards{
            .staker_rewards = stake.delegation.stake * 4,
            .voter_rewards = 0,
            .new_credits_observed = 4,
        },
        try calculateStakeRewards(
            2,
            &stake,
            &.{ .rewards = 4, .points = 4 },
            &vote_state,
            &StakeHistory.INIT,
            null,
        ),
    );

    vote_state.commission = 99;

    try std.testing.expectEqual(
        null,
        try calculateStakeRewards(
            2,
            &stake,
            &.{ .rewards = 4, .points = 4 },
            &vote_state,
            &StakeHistory.INIT,
            null,
        ),
    );

    try std.testing.expectEqual(
        CalculatedStakeRewards{
            .staker_rewards = 0,
            .voter_rewards = 0,
            .new_credits_observed = 4,
        },
        try calculateStakeRewards(
            2,
            &stake,
            &.{ .rewards = 0, .points = 4 },
            &vote_state,
            &StakeHistory.INIT,
            null,
        ),
    );

    stake.credits_observed = 4;

    try std.testing.expectEqual(
        CalculatedStakeRewards{
            .staker_rewards = 0,
            .voter_rewards = 0,
            .new_credits_observed = 4,
        },
        calculateStakeRewards(
            2,
            &stake,
            &.{ .rewards = 0, .points = 4 },
            &vote_state,
            &StakeHistory.INIT,
            null,
        ),
    );

    try std.testing.expectEqual(
        CalculatedStakePoints{
            .points = 0,
            .new_credits_observed = 4,
            .force_credits_update_with_skipped_rewards = false,
        },
        calculateStakePointsAndCredits(
            &stake,
            &vote_state,
            &StakeHistory.INIT,
            null,
        ),
    );

    stake.credits_observed = 1_000;

    try std.testing.expectEqual(
        CalculatedStakePoints{
            .points = 0,
            .new_credits_observed = 4,
            .force_credits_update_with_skipped_rewards = true,
        },
        calculateStakePointsAndCredits(
            &stake,
            &vote_state,
            &StakeHistory.INIT,
            null,
        ),
    );

    stake.credits_observed = 4;

    try std.testing.expectEqual(
        CalculatedStakePoints{
            .points = 0,
            .new_credits_observed = 4,
            .force_credits_update_with_skipped_rewards = false,
        },
        calculateStakePointsAndCredits(
            &stake,
            &vote_state,
            &StakeHistory.INIT,
            null,
        ),
    );

    vote_state.commission = 0;
    stake.credits_observed = 3;
    stake.delegation.activation_epoch = 1;

    try std.testing.expectEqual(
        CalculatedStakeRewards{
            .staker_rewards = stake.delegation.stake,
            .voter_rewards = 0,
            .new_credits_observed = 4,
        },
        try calculateStakeRewards(
            2,
            &stake,
            &.{ .rewards = 1, .points = 1 },
            &vote_state,
            &StakeHistory.INIT,
            null,
        ),
    );

    stake.delegation.activation_epoch = 2;
    stake.credits_observed = 3;

    try std.testing.expectEqual(
        CalculatedStakeRewards{
            .staker_rewards = 0,
            .voter_rewards = 0,
            .new_credits_observed = 4,
        },
        try calculateStakeRewards(
            2,
            &stake,
            &.{ .rewards = 1, .points = 1 },
            &vote_state,
            &StakeHistory.INIT,
            null,
        ),
    );
}

test commissionSplit {
    try std.testing.expectEqual(
        CommissionSplit{ .staker_rewards = 1, .voter_rewards = 0, .is_split = false },
        commissionSplit(0, 1),
    );
    try std.testing.expectEqual(
        CommissionSplit{ .staker_rewards = 0, .voter_rewards = 1, .is_split = false },
        commissionSplit(std.math.maxInt(u8), 1),
    );
    try std.testing.expectEqual(
        CommissionSplit{ .staker_rewards = 0, .voter_rewards = 9, .is_split = true },
        commissionSplit(99, 10),
    );
    try std.testing.expectEqual(
        CommissionSplit{ .staker_rewards = 9, .voter_rewards = 0, .is_split = true },
        commissionSplit(1, 10),
    );
    try std.testing.expectEqual(
        CommissionSplit{ .staker_rewards = 5, .voter_rewards = 5, .is_split = true },
        commissionSplit(50, 10),
    );
    try std.testing.expectEqual(
        CommissionSplit{ .staker_rewards = 0, .voter_rewards = 0, .is_split = true },
        commissionSplit(50, 1),
    );
    try std.testing.expectEqual(
        CommissionSplit{ .staker_rewards = 1, .voter_rewards = 1, .is_split = true },
        commissionSplit(51, 3),
    );
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
    try std.testing.expectEqual(
        0,
        getInflationNumSlots(slot, epoch, &feature_set, &epoch_schedule),
    );

    // Move forward 2 epochs
    slot += 2 * slots_per_epoch;
    epoch += 2;
    try std.testing.expectEqual(2 * slots_per_epoch, getInflationNumSlots(
        slot,
        epoch,
        &feature_set,
        &epoch_schedule,
    ));

    // Activate pico inflation
    feature_set.setSlot(.pico_inflation, slot);
    try std.testing.expectEqual(slots_per_epoch, getInflationNumSlots(
        slot,
        epoch,
        &feature_set,
        &epoch_schedule,
    ));

    // Move forward 1 epoch
    slot += slots_per_epoch;
    epoch += 1;
    try std.testing.expectEqual(2 * slots_per_epoch, getInflationNumSlots(
        slot,
        epoch,
        &feature_set,
        &epoch_schedule,
    ));

    // Activate full inflation for devnet/testnet
    feature_set.setSlot(.full_inflation_devnet_and_testnet, slot);
    try std.testing.expectEqual(slots_per_epoch, getInflationNumSlots(
        slot,
        epoch,
        &feature_set,
        &epoch_schedule,
    ));

    // Move forward 1 epoch
    slot += slots_per_epoch;
    epoch += 1;
    try std.testing.expectEqual(2 * slots_per_epoch, getInflationNumSlots(
        slot,
        epoch,
        &feature_set,
        &epoch_schedule,
    ));

    // Activate full inflation for mainnet -- should have no effect
    feature_set.setSlot(.full_inflation_mainnet_enable, slot);
    feature_set.setSlot(.full_inflation_mainnet_vote, slot);
    try std.testing.expectEqual(2 * slots_per_epoch, getInflationNumSlots(
        slot,
        epoch,
        &feature_set,
        &epoch_schedule,
    ));

    // Deactivate full inflation for devnet/testnet -- will revert to full inflation mainnet
    feature_set.setSlot(.full_inflation_devnet_and_testnet, std.math.maxInt(Slot));
    try std.testing.expectEqual(slots_per_epoch, getInflationNumSlots(
        slot,
        epoch,
        &feature_set,
        &epoch_schedule,
    ));

    // Move forward 1 epoch
    slot += slots_per_epoch;
    epoch += 1;
    try std.testing.expectEqual(2 * slots_per_epoch, getInflationNumSlots(
        slot,
        epoch,
        &feature_set,
        &epoch_schedule,
    ));
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
    try std.testing.expectEqual(0, getSlotInYearsForInflation(
        slot,
        epoch,
        slots_per_year,
        &feature_set,
        &epoch_schedule,
    ));

    // Move forward 2 epochs
    slot += 2 * slots_per_epoch;
    epoch += 2;
    try std.testing.expectEqual(
        @as(f64, @floatFromInt(2 * slots_per_epoch)) / slots_per_year,
        getSlotInYearsForInflation(
            slot,
            epoch,
            slots_per_year,
            &feature_set,
            &epoch_schedule,
        ),
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
