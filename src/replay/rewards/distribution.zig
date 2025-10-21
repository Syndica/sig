const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;

const SlotAccountReader = sig.accounts_db.SlotAccountReader;

const EpochRewardStatus = sig.replay.rewards.EpochRewardStatus;

const EpochRewards = sig.runtime.sysvar.EpochRewards;

const getSysvarFromAccount = sig.replay.update_sysvar.getSysvarFromAccount;

pub fn distributePartitionedEpochRewards(
    allocator: Allocator,
    block_height: u64,
    epoch_reward_status: *EpochRewardStatus,
    account_reader: SlotAccountReader,
) !void {
    const reward_phase = switch (epoch_reward_status.*) {
        .active => |phase| phase,
        .inactive => return,
    };

    const start_block_height = switch (reward_phase) {
        .calculating => |calc| calc.distribution_start_block_height,
        .distributing => |dist| dist.distribution_start_block_height,
    };

    if (block_height < start_block_height) {
        return;
    }

    switch (reward_phase) {
        .calculating => |calc| {
            const epoch_rewards_sysvar = try getSysvarFromAccount(
                EpochRewards,
                allocator,
                account_reader,
            ) orelse EpochRewards.DEFAULT;

            const partition_indices =
                try sig.replay.rewards.EpochRewardsHasher.hashRewardsIntoPartitions(
                    allocator,
                    calc.all_stake_rewards.entries,
                    &epoch_rewards_sysvar.parent_blockhash,
                    epoch_rewards_sysvar.num_partitions,
                );

            epoch_reward_status.* = .{ .active = .{
                .distributing = .{
                    .distribution_start_block_height = calc.distribution_start_block_height,
                    .all_stake_rewards = calc.all_stake_rewards,
                    .partitioned_indices = try .init(allocator, partition_indices),
                },
            } };
        },
        .distributing => {},
    }
}
