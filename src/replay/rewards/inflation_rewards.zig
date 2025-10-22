const std = @import("std");
const sig = @import("../../sig.zig");

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
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

test "calculateStakePointsAndCredits" {
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
        calculatePoints(stake, vote_state, &StakeHistory.DEFAULT, null),
    );
}

test "redeemRewards" {
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
            &StakeHistory.DEFAULT,
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
            &StakeHistory.DEFAULT,
            null,
        );
        try std.testing.expectEqual(
            RedeemRewardResult{ .stakers_reward = 2, .voters_reward = 0 },
            rewards,
        );
        try std.testing.expectEqual(3, stake.delegation.stake);
    }
}

test "calculateStakeRewards" {
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
            &StakeHistory.DEFAULT,
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
            &StakeHistory.DEFAULT,
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
            &StakeHistory.DEFAULT,
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
            &StakeHistory.DEFAULT,
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
            &StakeHistory.DEFAULT,
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
            &StakeHistory.DEFAULT,
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
            &StakeHistory.DEFAULT,
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
            &StakeHistory.DEFAULT,
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
            &StakeHistory.DEFAULT,
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
            &StakeHistory.DEFAULT,
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
            &StakeHistory.DEFAULT,
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
            &StakeHistory.DEFAULT,
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
            &StakeHistory.DEFAULT,
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
            &StakeHistory.DEFAULT,
            null,
        ),
    );
}

test "commissionSplit" {
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
