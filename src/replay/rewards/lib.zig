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
pub const hasher = @import("hasher.zig");

pub const REWARD_CALCULATION_NUM_BLOCKS: u64 = 1;

pub const RewardType = enum {
    fee,
    rent,
    staking,
    voting,
};

/// Protocol-level reward information that was distributed by the bank.
/// Matches Agave's `RewardInfo` struct in runtime/src/reward_info.rs.
pub const RewardInfo = struct {
    reward_type: RewardType,
    /// Can be negative in edge cases (e.g., when rent is deducted)
    lamports: i64,
    post_balance: u64,
    /// Commission for vote/staking rewards, null for fee rewards
    commission: ?u8,
};

/// A reward paired with the pubkey of the account that received it.
/// Matches Agave's `(Pubkey, RewardInfo)` tuple used in `Bank.rewards`.
pub const KeyedRewardInfo = struct {
    pubkey: Pubkey,
    reward_info: RewardInfo,

    /// Convert to the ledger Reward format for storage.
    pub fn toLedgerReward(self: KeyedRewardInfo, allocator: Allocator) !sig.ledger.meta.Reward {
        const pubkey_bytes = try allocator.dupe(u8, &self.pubkey.data);
        return .{
            .pubkey = pubkey_bytes,
            .lamports = self.reward_info.lamports,
            .post_balance = self.reward_info.post_balance,
            .reward_type = self.reward_info.reward_type,
            .commission = self.reward_info.commission,
        };
    }
};

/// Protocol-level rewards that were distributed by the bank.
/// Matches Agave's `Bank.rewards: RwLock<Vec<(Pubkey, RewardInfo)>>`.
///
/// This is used to collect fee rewards, vote rewards, and staking rewards
/// during block processing. When the slot is rooted, these rewards are
/// written to the ledger for RPC queries.
pub const BlockRewards = struct {
    rewards: std.ArrayListUnmanaged(KeyedRewardInfo),
    allocator: Allocator,

    pub const EMPTY: BlockRewards = .{
        .rewards = .{},
        .allocator = undefined,
    };

    pub fn init(allocator: Allocator) BlockRewards {
        return .{
            .rewards = .{},
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *BlockRewards) void {
        self.rewards.deinit(self.allocator);
    }

    /// Push a reward to the list. Used by fee distribution, vote rewards, and staking rewards.
    /// Matches Agave's `self.rewards.write().unwrap().push(...)`.
    pub fn push(self: *BlockRewards, keyed_reward: KeyedRewardInfo) !void {
        try self.rewards.append(self.allocator, keyed_reward);
    }

    /// Reserve capacity for additional rewards.
    /// Matches Agave's `rewards.reserve(...)`.
    pub fn reserve(self: *BlockRewards, additional: usize) !void {
        try self.rewards.ensureUnusedCapacity(self.allocator, additional);
    }

    /// Get a slice of all rewards.
    pub fn items(self: *const BlockRewards) []const KeyedRewardInfo {
        return self.rewards.items;
    }

    /// Get the number of rewards.
    pub fn len(self: *const BlockRewards) usize {
        return self.rewards.items.len;
    }

    /// Check if empty.
    pub fn isEmpty(self: *const BlockRewards) bool {
        return self.rewards.items.len == 0;
    }

    /// Convert all rewards to ledger format for storage.
    pub fn toLedgerRewards(
        self: *const BlockRewards,
        allocator: Allocator,
    ) ![]sig.ledger.meta.Reward {
        const ledger_rewards = try allocator.alloc(sig.ledger.meta.Reward, self.rewards.items.len);
        errdefer allocator.free(ledger_rewards);

        for (self.rewards.items, 0..) |keyed_reward, i| {
            ledger_rewards[i] = try keyed_reward.toLedgerReward(allocator);
        }
        return ledger_rewards;
    }
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

pub const PreviousEpochInflationRewards = struct {
    validator_rewards: u64,
    previous_epoch_duration_in_years: f64,
    validator_rate: f64,
    foundation_rate: f64,
};

pub const EpochRewardStatus = union(enum) {
    active: struct {
        distribution_start_block_height: u64,
        all_stake_rewards: PartitionedStakeRewards,
        partitioned_indices: ?PartitionedIndices,
    },
    inactive,

    pub fn deinit(self: EpochRewardStatus, allocator: Allocator) void {
        switch (self) {
            .active => |active| {
                active.all_stake_rewards.deinit(allocator);
                if (active.partitioned_indices) |pi| pi.deinit(allocator);
            },
            .inactive => {},
        }
    }

    pub fn clone(self: EpochRewardStatus) EpochRewardStatus {
        return switch (self) {
            .active => |active| .{ .active = .{
                .distribution_start_block_height = active.distribution_start_block_height,
                .all_stake_rewards = active.all_stake_rewards.getAcquire(),
                .partitioned_indices = if (active.partitioned_indices) |pi|
                    pi.getAcquire()
                else
                    null,
            } },
            .inactive => .inactive,
        };
    }
};
