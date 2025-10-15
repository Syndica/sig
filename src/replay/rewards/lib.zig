const std = @import("std");
const sig = @import("../../sig.zig");
const builtin = @import("builtin");

const Pubkey = sig.core.Pubkey;
const Stake = sig.core.stake.Stake;

pub const inflation_rewards = @import("inflation_rewards.zig");

pub const EpochRewardsHasher = @import("EpochRewardsHasher.zig");

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
