const std = @import("std");
const sig = @import("../../sig.zig");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;

const Pubkey = sig.core.Pubkey;
const Stake = sig.runtime.program.stake.StakeStateV2.Stake;
const VoteAccount = sig.core.stakes.VoteAccount;

const AccountSharedData = sig.runtime.AccountSharedData;

pub const calculation = @import("calculation.zig");
pub const distribution = @import("distribution.zig");
pub const inflation_rewards = @import("inflation_rewards.zig");
pub const EpochRewardsHasher = @import("EpochRewardsHasher.zig");

const PointValue = inflation_rewards.PointValue;

pub const REWARD_CALCULATION_NUM_BLOCKS: u64 = 1;

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

pub const StakeReward = struct {
    stake_pubkey: Pubkey,
    stake_reward_info: RewardInfo,
    stake_account: AccountSharedData,

    pub fn deinit(self: StakeReward, allocator: Allocator) void {
        self.stake_account.deinit(allocator);
    }
};

pub const PartitionedVoteReward = struct {
    vote_pubkey: Pubkey,
    rewards: RewardInfo,
    account: VoteAccount.MinimalAccount,
};

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

pub fn PartitionedRewards(comptime T: type) type {
    return struct {
        entries: []const T,
        rc: *sig.sync.ReferenceCounter,

        pub fn init(
            allocator: Allocator,
            entries: []const T,
        ) !@This() {
            const rc = try allocator.create(sig.sync.ReferenceCounter);
            errdefer allocator.destroy(rc);
            rc.* = .init;
            return .{
                .entries = entries,
                .rc = rc,
            };
        }

        pub fn deinit(self: @This(), allocator: Allocator) void {
            if (self.rc.release()) {
                allocator.destroy(self.rc);
                allocator.free(self.entries);
            }
        }

        pub fn acquire(self: *const @This()) void {
            std.debug.assert(self.rc.acquire());
        }

        pub fn getAcquire(self: *const @This()) @This() {
            self.acquire();
            return self.*;
        }
    };
}

pub const PartitionedStakeRewards = PartitionedRewards(PartitionedStakeReward);
pub const PartitionedVoteRewards = PartitionedRewards(PartitionedVoteReward);

pub const PartitionedIndices = struct {
    entries: []const []const usize,
    rc: *sig.sync.ReferenceCounter,

    pub fn init(
        allocator: Allocator,
        entries: []const []const usize,
    ) !PartitionedIndices {
        const rc = try allocator.create(sig.sync.ReferenceCounter);
        errdefer allocator.destroy(rc);
        rc.* = .init;
        return .{
            .entries = entries,
            .rc = rc,
        };
    }

    pub fn deinit(self: PartitionedIndices, allocator: Allocator) void {
        if (self.rc.release()) {
            allocator.destroy(self.rc);
            for (self.entries) |entry| {
                allocator.free(entry);
            }
            allocator.free(self.entries);
        }
    }

    pub fn acquire(self: *const PartitionedIndices) void {
        std.debug.assert(self.rc.acquire());
    }

    pub fn getAcquire(self: *const PartitionedIndices) PartitionedIndices {
        self.acquire();
        return self.*;
    }
};

pub const StakeRewards = struct {
    stake_rewards: PartitionedStakeRewards,
    total_stake_rewards_lamports: u64,

    pub fn initEmpty(allocator: Allocator) !StakeRewards {
        return .{
            .stake_rewards = try PartitionedStakeRewards.init(
                allocator,
                &[_]PartitionedStakeReward{},
            ),
            .total_stake_rewards_lamports = 0,
        };
    }

    pub fn deinit(self: StakeRewards, allocator: std.mem.Allocator) void {
        self.stake_rewards.deinit(allocator);
    }
};

pub const VoteRewards = struct {
    vote_rewards: PartitionedVoteRewards,
    total_vote_rewards_lamports: u64,

    pub fn initEmpty(allocator: Allocator) !VoteRewards {
        return .{
            .vote_rewards = try PartitionedVoteRewards.init(
                allocator,
                &[_]PartitionedVoteReward{},
            ),
            .total_vote_rewards_lamports = 0,
        };
    }

    pub fn deinit(self: VoteRewards, allocator: std.mem.Allocator) void {
        self.vote_rewards.deinit(allocator);
    }
};

pub const ValidatorRewards = struct {
    vote_rewards: VoteRewards,
    stake_rewards: StakeRewards,
    point_value: PointValue,

    pub fn initEmpty(allocator: Allocator) Allocator.Error!ValidatorRewards {
        const vote_rewards = try VoteRewards.initEmpty(allocator);
        errdefer vote_rewards.deinit(allocator);
        const stake_rewards = try StakeRewards.initEmpty(allocator);
        errdefer stake_rewards.deinit(allocator);
        return .{
            .vote_rewards = vote_rewards,
            .stake_rewards = stake_rewards,
            .point_value = .ZERO,
        };
    }

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

    pub fn deinit(self: *RewardsForPartitioning, allocator: Allocator) void {
        self.vote_rewards.deinit(allocator);
        self.stake_rewards.deinit(allocator);
    }
};

pub const StartBlockHeightAndRewards = struct {
    distribution_start_block_height: u64,
    all_stake_rewards: PartitionedStakeRewards,

    pub fn deinit(self: StartBlockHeightAndRewards, allocator: Allocator) void {
        self.all_stake_rewards.deinit(allocator);
    }

    pub fn clone(self: StartBlockHeightAndRewards) StartBlockHeightAndRewards {
        return .{
            .distribution_start_block_height = self.distribution_start_block_height,
            .all_stake_rewards = self.all_stake_rewards.getAcquire(),
        };
    }
};

pub const StartBlockHeightAndPartitionedRewards = struct {
    distribution_start_block_height: u64,
    all_stake_rewards: PartitionedStakeRewards,
    partitioned_indices: PartitionedIndices,

    pub fn deinit(self: StartBlockHeightAndPartitionedRewards, allocator: Allocator) void {
        self.all_stake_rewards.deinit(allocator);
        self.partitioned_indices.deinit(allocator);
    }

    pub fn clone(self: StartBlockHeightAndPartitionedRewards) StartBlockHeightAndPartitionedRewards {
        return .{
            .distribution_start_block_height = self.distribution_start_block_height,
            .all_stake_rewards = self.all_stake_rewards.getAcquire(),
            .partitioned_indices = self.partitioned_indices.getAcquire(),
        };
    }
};

pub const EpochRewardPhase = union(enum) {
    calculating: StartBlockHeightAndRewards,
    distributing: StartBlockHeightAndPartitionedRewards,

    pub fn deinit(self: EpochRewardPhase, allocator: Allocator) void {
        switch (self) {
            .calculating => |s| s.deinit(allocator),
            .distributing => |s| s.deinit(allocator),
        }
    }

    pub fn clone(self: EpochRewardPhase) EpochRewardPhase {
        return switch (self) {
            .calculating => |s| .{ .calculating = s.clone() },
            .distributing => |s| .{ .distributing = s.clone() },
        };
    }
};

pub const EpochRewardStatus = union(enum) {
    active: EpochRewardPhase,
    inactive,

    pub fn deinit(self: EpochRewardStatus, allocator: Allocator) void {
        switch (self) {
            .active => |phase| phase.deinit(allocator),
            .inactive => {},
        }
    }

    pub fn clone(self: EpochRewardStatus) EpochRewardStatus {
        return switch (self) {
            .active => |phase| .{ .active = phase.clone() },
            .inactive => .inactive,
        };
    }
};
