const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicU64 = std.atomic.Value(u64);

const Slot = sig.core.Slot;
const Ancestors = sig.core.Ancestors;
const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const EpochSchedule = sig.core.EpochSchedule;
const StakesCache = sig.core.StakesCache;
const Stake = sig.core.stake.Stake;
const StakeStateV2 = sig.core.stake.StakeStateV2;

const SlotAccountReader = sig.accounts_db.SlotAccountReader;

const SlotAccountStore = sig.replay.slot_account_store.SlotAccountStore;

const EpochRewardStatus = sig.replay.rewards.EpochRewardStatus;
const StartBlockHeightAndPartitionedRewards = sig.replay.rewards.StartBlockHeightAndPartitionedRewards;
const StakeReward = sig.replay.rewards.StakeReward;

const AccountSharedData = sig.runtime.AccountSharedData;
const EpochRewards = sig.runtime.sysvar.EpochRewards;
const Rent = sig.runtime.sysvar.Rent;

const getSysvarFromAccount = sig.replay.update_sysvar.getSysvarFromAccount;
const updateSysvarAccount = sig.replay.update_sysvar.updateSysvarAccount;

pub fn distributePartitionedEpochRewards(
    allocator: Allocator,
    slot: Slot,
    epoch: Epoch,
    block_height: u64,
    epoch_schedule: EpochSchedule,
    epoch_reward_status: *EpochRewardStatus,
    stakes_cache: *StakesCache,
    capitalization: *AtomicU64,
    ancestors: *const Ancestors,
    rent: *const Rent,
    slot_store: SlotAccountStore,
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
                slot_store.reader,
            ) orelse EpochRewards.DEFAULT;

            const partition_indices = try sig.replay.rewards.EpochRewardsHasher.hashRewardsIntoPartitions(
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

    const partition_rewards: StartBlockHeightAndPartitionedRewards = switch (reward_phase) {
        .calculating => unreachable,
        .distributing => |dist| dist,
    };

    const end_block_height = start_block_height + partition_rewards.partitioned_indices.entries.len;

    std.debug.assert(epoch_schedule.getSlotsInEpoch(epoch) >
        partition_rewards.partitioned_indices.entries.len);

    if (block_height >= start_block_height and block_height < end_block_height) {
        const partition_index = block_height - start_block_height;
        try distributeEpochRewardsInPartition(
            allocator,
            slot,
            ancestors,
            rent,
            partition_rewards,
            partition_index,
            capitalization,
            stakes_cache,
            slot_store,
        );
    }

    if (block_height +| 1 >= end_block_height) {
        epoch_reward_status.* = .{ .inactive = {} };
        var epoch_rewards_sysvar = try getSysvarFromAccount(
            EpochRewards,
            allocator,
            slot_store.reader,
        ) orelse EpochRewards.DEFAULT;
        epoch_rewards_sysvar.active = false;
        try updateSysvarAccount(
            EpochRewards,
            allocator,
            epoch_rewards_sysvar,
            .{
                .slot = slot,
                .capitalization = capitalization,
                .ancestors = ancestors,
                .rent = rent,
                .account_store = slot_store.writer,
            },
        );
    }
}

fn distributeEpochRewardsInPartition(
    allocator: Allocator,
    slot: Slot,
    ancestors: *const Ancestors,
    rent: *const Rent,
    partition_rewards: StartBlockHeightAndPartitionedRewards,
    partition_index: u64,
    capitalization: *AtomicU64,
    stakes_cache: *StakesCache,
    slot_store: SlotAccountStore,
) !void {
    const lamports_distributed, const lamports_burnt, const updated_stake_rewards =
        try storeStakeAccountsInPartition(
            allocator,
            partition_rewards,
            partition_index,
            stakes_cache,
            slot_store,
            null, // TODO: pass in new_rate_activation_epoch
        );
    _ = capitalization.fetchAdd(lamports_distributed, .monotonic);

    var epoch_rewards = try getSysvarFromAccount(
        EpochRewards,
        allocator,
        slot_store.reader,
    ) orelse EpochRewards.DEFAULT;

    std.debug.assert(epoch_rewards.active);
    epoch_rewards.distributed_rewards += lamports_burnt + lamports_distributed;
    std.debug.assert(epoch_rewards.distributed_rewards <= epoch_rewards.total_rewards);

    try updateSysvarAccount(
        EpochRewards,
        allocator,
        epoch_rewards,
        .{
            .slot = slot,
            .capitalization = capitalization,
            .ancestors = ancestors,
            .rent = rent,
            .account_store = slot_store.writer,
        },
    );

    // NOTE: This looks like its only required for metrics.
    // updateRewardHistoryInPartition();
    _ = updated_stake_rewards;
}

fn storeStakeAccountsInPartition(
    allocator: Allocator,
    partition_rewards: StartBlockHeightAndPartitionedRewards,
    partition_index: u64,
    stakes_cache: *StakesCache,
    slot_store: SlotAccountStore,
    new_rate_activation_epoch: ?Epoch,
) !struct { u64, u64, []const StakeReward } {
    var lamports_distributed: u64 = 0;
    var lamports_burnt: u64 = 0;

    const indices = if (partition_index >= partition_rewards.partitioned_indices.entries.len) {
        return error.InvalidPartitionIndex;
    } else partition_rewards.partitioned_indices.entries[partition_index];

    var updated_stake_rewards = try std.ArrayListUnmanaged(StakeReward)
        .initCapacity(allocator, indices.len);

    {
        const stakes, var stakes_lg = stakes_cache.stakes.readWithLock();
        defer stakes_lg.unlock();

        for (indices) |index| {
            const partitioned_reward = if (index >= partition_rewards.all_stake_rewards.entries.len) {
                return error.InvalidStakeRewardIndex;
            } else partition_rewards.all_stake_rewards.entries[index];

            if (try buildUpdatedStakeReward(
                allocator,
                stakes.stake_delegations,
                partitioned_reward,
                slot_store,
            )) |stake_reward| {
                lamports_distributed += partitioned_reward.stake_reward;
                updated_stake_rewards.appendAssumeCapacity(stake_reward);
            } else {
                lamports_burnt += partitioned_reward.stake_reward;
            }
        }
    }

    for (updated_stake_rewards.items) |stake_reward| {
        try stakes_cache.checkAndStore(
            allocator,
            stake_reward.pubkey,
            stake_reward.stake_account,
            new_rate_activation_epoch,
        );
        try slot_store.put(stake_reward.pubkey, stake_reward.stake_account);
    }

    return .{
        lamports_distributed,
        lamports_burnt,
        try updated_stake_rewards.toOwnedSlice(allocator),
    };
}

fn buildUpdatedStakeReward(
    allocator: Allocator,
    stake_accounts: std.AutoArrayHashMapUnmanaged(Pubkey, Stake),
    partitioned_reward: sig.replay.rewards.PartitionedStakeReward,
    slot_store: SlotAccountStore,
) !?StakeReward {
    const cached_stake_state = stake_accounts.get(partitioned_reward.stake_pubkey) orelse
        return null;

    var account = try slot_store.get(allocator, partitioned_reward.stake_pubkey) orelse
        return null;

    // NOTE: If we stored the full stake state in the stake account we might be able to skip
    // deserializing and just update the stake directly.
    var stake_state = try StakeStateV2.fromAccount(account);
    switch (stake_state) {
        .stake => {},
        else => return null,
    }

    stake_state.stake.stake = cached_stake_state;
    account.lamports += partitioned_reward.stake_reward;

    std.debug.assert(stake_state.stake.stake.delegation.stake +| partitioned_reward.stake_reward ==
        partitioned_reward.stake.delegation.stake);

    const stake_data = try allocator.alloc(u8, StakeStateV2.SIZE);
    errdefer allocator.free(stake_data);
    @memset(stake_data, 0);
    _ = try sig.bincode.writeToSlice(
        stake_data,
        stake_state,
        .{},
    );

    return .{
        .pubkey = partitioned_reward.stake_pubkey,
        .reward_info = .{
            .reward_type = .staking,
            .lamports = partitioned_reward.stake_reward,
            .post_balance = account.lamports,
            .commission = partitioned_reward.commission,
        },
        .stake_account = .{
            .lamports = account.lamports,
            .data = stake_data,
            .owner = account.owner,
            .executable = account.executable,
            .rent_epoch = account.rent_epoch,
        },
    };
}
