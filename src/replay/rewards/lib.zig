const std = @import("std");
const sig = @import("../../sig.zig");
const builtin = @import("builtin");

const Pubkey = sig.core.Pubkey;
const Stake = sig.core.stake.Stake;
const AccountSharedData = sig.runtime.AccountSharedData;

const VoteAccount = sig.core.vote_accounts.VoteAccount;

pub const calculation = @import("calculation.zig");
pub const inflation_rewards = @import("inflation_rewards.zig");
pub const EpochRewardsHasher = @import("EpochRewardsHasher.zig");

const PointValue = inflation_rewards.PointValue;

pub const REWARD_CALCULATION_NUM_BLOCKS: u64 = 1;

pub const PartitionedStakeReward = struct {
    stake_pubkey: Pubkey,
    stake: Stake,
    stake_reward: u64,
    commission: u8,

    pub fn initRandom(random: std.Random) PartitionedStakeReward {
        if (!builtin.is_test) @compileError("only for testing");
        return .{
            .stake_pubkey = Pubkey.initRandom(random),
            .stake = Stake.initRandom(random),
            .stake_reward = random.int(u64) % 1_000_000,
            .commission = @as(u8, random.int(u8) % 100),
        };
    }
};

pub const RewardType = enum {
    fee,
    rent,
    staking,
    voting,
};

pub const RewardInfo = struct {
    reward_type: RewardType,
    lamports: u64,
    post_balance: u64,
    commission: u8,
};

pub const PartitionedVoteReward = struct {
    vote_pubkey: Pubkey,
    rewards: RewardInfo,
    account: VoteAccount.MinimalAccount,
};

pub const StakeRewards = struct {
    stake_rewards: []const PartitionedStakeReward,
    total_stake_rewards_lamports: u64,

    pub fn deinit(self: StakeRewards, allocator: std.mem.Allocator) void {
        allocator.free(self.stake_rewards);
    }
};

pub const VoteRewards = struct {
    vote_rewards: []const PartitionedVoteReward,
    total_vote_rewards_lamports: u64,

    pub fn deinit(self: VoteRewards, allocator: std.mem.Allocator) void {
        allocator.free(self.vote_rewards);
    }
};

pub const ValidatorRewards = struct {
    vote_rewards: VoteRewards,
    stake_rewards: StakeRewards,
    point_value: PointValue,

    pub fn deinit(self: ValidatorRewards, allocator: std.mem.Allocator) void {
        self.vote_rewards.deinit(allocator);
        self.stake_rewards.deinit(allocator);
    }
};

pub const PreviousEpochInflationRewards = struct {
    validator_rewards: u64,
    previous_epoch_duration_in_years: f64,
    validator_rate: f64,
    foundation_rate: f64,
};

pub const RewardsForPartitioning = struct {
    vote_rewards: VoteRewards,
    stake_rewards: StakeRewards,
    point_value: PointValue,
    validator_rate: f64,
    foundation_rate: f64,
    previous_epoch_duration_in_years: f64,
    capitalization: u64,
};
