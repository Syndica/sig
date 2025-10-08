const std = @import("std");
const sig = @import("../../sig.zig");

pub const calculation = @import("calculation.zig");

const Allocator = std.mem.Allocator;

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Stake = sig.core.stake.Stake;
const StakeStateV2 = sig.core.stake.StakeStateV2;
const VoteState = sig.core.vote_accounts.VoteState;
const EpochCredit = sig.runtime.program.vote.state.EpochCredit;

const StakeHistory = sig.runtime.sysvar.StakeHistory;

const DEFAULT_WARMUP_COOLDOWN_RATE = sig.core.stake.DEFAULT_WARMUP_COOLDOWN_RATE;

pub const PointValue = struct {
    rewards: u64,
    points: u128,
};

pub const CalculatedStakePoints = struct {
    points: u128,
    new_credits_observed: u64,
    force_credits_update_with_skipped_rewards: bool,
};

pub fn calculatePoints(
    stake: Stake,
    vote_state: VoteState,
    stake_history: StakeHistory,
    new_rate_activation_epoch: ?Epoch,
) u128 {
    return calculateStakePointsAndCredits(
        &stake,
        &vote_state,
        &stake_history,
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
    const credits_in_vote = new_vote_state.epoch_credits.getLastOrNull() orelse 0;

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
        const stake_amount: u128 = stake.getDelegation().getStake(
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

fn newStakeForTest(
    stake: u64,
    voter_pubkey: Pubkey,
    epoch_credits: ?EpochCredit,
    activation_epoch: Epoch,
) Stake {
    return .{
        .delegation = .{
            .voter_pubkey = voter_pubkey,
            .stake = stake,
            .activation_epoch = activation_epoch,
            .deactivation_epoch = Epoch.max,
            .deprecated_warmup_cooldown_rate = DEFAULT_WARMUP_COOLDOWN_RATE,
        },
        .credits_observed = if (epoch_credits) |credit| credit.credits orelse 0,
    };
}

test "calculateStakePointsAndCredits" {
    const allocator = std.testing.allocator;

    var vote_state = VoteState.DEFAULT;
    defer vote_state.deinit(allocator);

    const stake = newStakeForTest(
        10_000_000 * 1_000_000_000,
        Pubkey.ZEROES,
        vote_state.epoch_credits.getLastOrNull(),
        std.math.maxInt(Epoch),
    );

    const epoch_slots: u128 = 14 * 24 * 3600 * 160;
    for (0..epoch_slots) |_| {
        try vote_state.incrementCredits(allocator, 0, 1);
    }

    std.testing.expectEqual(
        stake.delegation.stake + epoch_slots,
        calculatePoints(stake, vote_state, StakeHistory.DEFAULT, null),
    );
}
