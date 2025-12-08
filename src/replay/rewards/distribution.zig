const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicU64 = std.atomic.Value(u64);

const Slot = sig.core.Slot;
const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const EpochSchedule = sig.core.EpochSchedule;
const StakesCache = sig.core.StakesCache;
const Stake = sig.runtime.program.stake.StakeStateV2.Stake;
const StakeStateV2 = sig.runtime.program.stake.StakeStateV2;

const SlotAccountStore = sig.accounts_db.SlotAccountStore;

// const SlotAccountStore = sig.replay.slot_account_store.SlotAccountStore;

const EpochRewardStatus = sig.replay.rewards.EpochRewardStatus;
const StartBlockHeightAndPartitionedRewards =
    sig.replay.rewards.StartBlockHeightAndPartitionedRewards;
const StakeReward = sig.replay.rewards.StakeReward;

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
                slot_store.reader(),
            ) orelse EpochRewards.INIT;

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

    const partition_rewards: StartBlockHeightAndPartitionedRewards = switch (epoch_reward_status.*) {
        .active => |dist| switch (dist) {
            .distributing => |d| d,
            .calculating => unreachable,
        },
        .inactive => unreachable,
    };

    const end_block_height = start_block_height + partition_rewards.partitioned_indices.entries.len;

    std.debug.assert(epoch_schedule.getSlotsInEpoch(epoch) >
        partition_rewards.partitioned_indices.entries.len);

    if (block_height >= start_block_height and block_height < end_block_height) {
        const partition_index = block_height - start_block_height;
        try distributeEpochRewardsInPartition(
            allocator,
            slot,
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
            slot_store.reader(),
        ) orelse EpochRewards.INIT;
        epoch_rewards_sysvar.active = false;
        try updateSysvarAccount(
            EpochRewards,
            allocator,
            epoch_rewards_sysvar,
            .{
                .slot = slot,
                .slot_store = slot_store,
                .rent = rent,
                .capitalization = capitalization,
            },
        );
    }
}

fn distributeEpochRewardsInPartition(
    allocator: Allocator,
    slot: Slot,
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
    defer {
        for (updated_stake_rewards) |reward| reward.deinit(allocator);
        allocator.free(updated_stake_rewards);
    }
    _ = capitalization.fetchAdd(lamports_distributed, .monotonic);

    var epoch_rewards = try getSysvarFromAccount(
        EpochRewards,
        allocator,
        slot_store.reader(),
    ) orelse EpochRewards.INIT;

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
            .rent = rent,
            .slot_store = slot_store,
        },
    );

    // NOTE: Used for metadata
    // updateRewardHistoryInPartition(updated_stake_rewards);
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
            const partitioned_reward = if (index >=
                partition_rewards.all_stake_rewards.entries.len)
            {
                return error.InvalidStakeRewardIndex;
            } else partition_rewards.all_stake_rewards.entries[index];

            const stake_reward = buildUpdatedStakeReward(
                allocator,
                stakes.stake_accounts,
                partitioned_reward,
                slot_store,
            ) catch |err| switch (err) {
                error.MissingStakeAccountInCache,
                error.MissingStakeAccountInDb,
                error.InvalidAccountData,
                => {
                    lamports_burnt += partitioned_reward.stake_reward;
                    continue;
                },
                else => return err,
            };

            lamports_distributed += partitioned_reward.stake_reward;
            updated_stake_rewards.appendAssumeCapacity(stake_reward);
        }
    }

    for (updated_stake_rewards.items) |stake_reward| {
        try stakes_cache.checkAndStore(
            allocator,
            stake_reward.stake_pubkey,
            stake_reward.stake_account,
            new_rate_activation_epoch,
        );
        try slot_store.put(stake_reward.stake_pubkey, stake_reward.stake_account);
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
) !StakeReward {
    _ = stake_accounts.get(partitioned_reward.stake_pubkey) orelse
        return error.MissingStakeAccountInCache;

    var account = try slot_store.reader().get(allocator, partitioned_reward.stake_pubkey) orelse
        return error.MissingStakeAccountInDb;

    // NOTE: If we stored the full stake state in the stake account we might be able to skip
    // deserializing and just update the stake directly.
    var stake_state = try StakeStateV2.fromAccount(allocator, account);
    switch (stake_state) {
        .stake => {},
        else => return error.InvalidAccountData,
    }

    account.lamports += partitioned_reward.stake_reward;
    std.debug.assert(stake_state.stake.stake.delegation.stake +| partitioned_reward.stake_reward ==
        partitioned_reward.stake.delegation.stake);
    stake_state.stake.stake = partitioned_reward.stake;

    const stake_data = try allocator.alloc(u8, account.data.len());
    errdefer allocator.free(stake_data);
    @memset(stake_data, 0);
    _ = try sig.bincode.writeToSlice(
        stake_data,
        stake_state,
        .{},
    );

    return .{
        .stake_pubkey = partitioned_reward.stake_pubkey,
        .stake_reward_info = .{
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

// const TestEnvironment = struct {
//     slot_state: sig.core.SlotState,
//     slot_constants: sig.core.SlotConstants,
//     account_map: sig.accounts_db.account_store.ThreadSafeAccountMap,
//     ancestors: sig.core.Ancestors,

//     slot: Slot,
//     epoch: Epoch,
//     rent: Rent,
//     epoch_schedule: EpochSchedule,

//     pub fn init(allocator: Allocator) !TestEnvironment {
//         var ancestors = sig.core.Ancestors.EMPTY;
//         errdefer ancestors.deinit(allocator);
//         try ancestors.addSlot(allocator, 0);

//         return .{
//             .slot_state = .GENESIS,
//             .slot_constants = try .genesis(allocator, .DEFAULT),
//             .account_map = .init(allocator),
//             .ancestors = ancestors,
//             .slot = 0,
//             .epoch = 0,
//             .rent = .INIT,
//             .epoch_schedule = .INIT,
//         };
//     }

//     pub fn deinit(self: *TestEnvironment, allocator: Allocator) void {
//         self.slot_state.deinit(allocator);
//         self.slot_constants.deinit(allocator);
//         self.account_map.deinit();
//         self.ancestors.deinit(allocator);
//     }

//     pub fn slotStore(self: *TestEnvironment) SlotAccountStore {
//         const account_store = sig.accounts_db.AccountStore{
//             .thread_safe_map = &self.account_map,
//         };
//         return account_store.forSlot(self.slot, &self.ancestors);
//     }
// };

// test storeStakeAccountsInPartition {
//     const PartitionedStakeReward = sig.replay.rewards.PartitionedStakeReward;

//     const allocator = std.testing.allocator;
//     var prng = std.Random.DefaultPrng.init(0);
//     const random = prng.random();

//     var env = try TestEnvironment.init(allocator);
//     defer env.deinit(allocator);

//     env.slot_state.reward_status = .{ .active = .{ .calculating = .{
//         .distribution_start_block_height = 0,
//         .all_stake_rewards = try .init(
//             allocator,
//             try allocator.dupe(PartitionedStakeReward, &[_]PartitionedStakeReward{
//                 .{
//                     .stake_pubkey = Pubkey.initRandom(random),
//                     .stake = .{
//                         .delegation = .{
//                             .voter_pubkey = Pubkey.initRandom(random),
//                             .stake = 1_000_000_000,
//                             .activation_epoch = 0,
//                             .deactivation_epoch = std.math.maxInt(Epoch),
//                             .deprecated_warmup_cooldown_rate = 0.0,
//                         },
//                         .credits_observed = 0,
//                     },
//                     .stake_reward = 1_000_000_000,
//                     .commission = 50,
//                 },
//             }),
//         ),
//     } } };
// }

test distributePartitionedEpochRewards {
    const PartitionedStakeReward = sig.replay.rewards.PartitionedStakeReward;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    const slot = 0;
    const epoch = 0;
    const block_height = 0;
    const epoch_schedule = EpochSchedule.INIT;
    var capitalization = AtomicU64.init(0);
    const rent = sig.core.RentCollector.DEFAULT.rent;

    var ancestors = sig.core.Ancestors.EMPTY;
    defer ancestors.deinit(allocator);
    try ancestors.addSlot(allocator, 0);

    var db_context = try sig.accounts_db.Two.initTest(allocator);
    defer db_context.deinit();

    const account_store = sig.accounts_db.AccountStore{
        .accounts_db_two = &db_context.db,
    };
    const slot_store = account_store.forSlot(0, &ancestors);

    var stakes_cache = sig.core.StakesCache.EMPTY;
    defer stakes_cache.deinit(allocator);

    // Partitioned Reward
    var partitioned_reward = sig.replay.rewards.PartitionedStakeReward{
        .stake_pubkey = Pubkey.initRandom(random),
        .stake = .{
            .delegation = .{
                .voter_pubkey = Pubkey.initRandom(random),
                .stake = 1_000_000_000,
                .activation_epoch = 0,
                .deactivation_epoch = std.math.maxInt(Epoch),
                .deprecated_warmup_cooldown_rate = 0.0,
            },
            .credits_observed = 0,
        },
        .stake_reward = 1_000_000_000,
        .commission = 50,
    };

    // Stake State for Distribution
    var data = [_]u8{0} ** StakeStateV2.SIZE;
    const stake_state = StakeStateV2{ .stake = .{
        .meta = .{
            .rent_exempt_reserve = 0,
            .authorized = .{
                .staker = Pubkey.initRandom(random),
                .withdrawer = Pubkey.initRandom(random),
            },
            .lockup = .{
                .unix_timestamp = 0,
                .epoch = 0,
                .custodian = Pubkey.initRandom(random),
            },
        },
        .stake = partitioned_reward.stake,
        .flags = .EMPTY,
    } };
    _ = try sig.bincode.writeToSlice(
        &data,
        stake_state,
        .{},
    );
    const account = sig.runtime.AccountSharedData{
        .lamports = 5_000_000_000,
        .data = &data,
        .owner = sig.runtime.program.stake.ID,
        .executable = false,
        .rent_epoch = 0,
    };
    try slot_store.put(partitioned_reward.stake_pubkey, account);
    {
        var stakes, var guard = stakes_cache.stakes.writeWithLock();
        defer guard.unlock();
        try stakes.stake_accounts.put(
            allocator,
            partitioned_reward.stake_pubkey,
            partitioned_reward.stake,
        );
    }

    partitioned_reward.stake.delegation.stake = 2_000_000_000;
    var partition_rewards: StartBlockHeightAndPartitionedRewards = .{
        .distribution_start_block_height = 0,
        .partitioned_indices = try sig.replay.rewards.PartitionedIndices.init(
            allocator,
            try allocator.dupe(
                []const usize,
                &[_][]const usize{try allocator.dupe(usize, &[_]usize{0})},
            ),
        ),
        .all_stake_rewards = try sig.replay.rewards.PartitionedStakeRewards.init(
            allocator,
            try allocator.dupe(
                PartitionedStakeReward,
                &[_]PartitionedStakeReward{partitioned_reward},
            ),
        ),
    };
    defer partition_rewards.deinit(allocator);

    const epoch_rewards = sig.runtime.sysvar.EpochRewards{
        .distribution_starting_block_height = 0,
        .num_partitions = 1,
        .parent_blockhash = .ZEROES,
        .total_points = 0,
        .total_rewards = 1_000_000_000,
        .distributed_rewards = 0,
        .active = true,
    };
    try updateSysvarAccount(EpochRewards, allocator, epoch_rewards, .{
        .slot = 0,
        .capitalization = &capitalization,
        .rent = &rent,
        .slot_store = slot_store,
    });

    var epoch_reward_status = EpochRewardStatus{
        .active = .{ .distributing = partition_rewards },
    };

    try distributePartitionedEpochRewards(
        allocator,
        slot,
        epoch,
        block_height,
        epoch_schedule,
        &epoch_reward_status,
        &stakes_cache,
        &capitalization,
        &rent,
        slot_store,
    );
}

test distributeEpochRewardsInPartition {
    const PartitionedStakeReward = sig.replay.rewards.PartitionedStakeReward;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    const slot = 0;
    var capitalization = AtomicU64.init(0);
    const rent = sig.core.RentCollector.DEFAULT.rent;

    var ancestors = sig.core.Ancestors.EMPTY;
    defer ancestors.deinit(allocator);
    try ancestors.addSlot(allocator, 0);

    var db_context = try sig.accounts_db.Two.initTest(allocator);
    defer db_context.deinit();

    const account_store = sig.accounts_db.AccountStore{
        .accounts_db_two = &db_context.db,
    };
    const slot_store = account_store.forSlot(0, &ancestors);

    var stakes_cache = sig.core.StakesCache.EMPTY;
    defer stakes_cache.deinit(allocator);

    // Partitioned Reward
    const partition_index: u64 = 0;
    var partitioned_reward = sig.replay.rewards.PartitionedStakeReward{
        .stake_pubkey = Pubkey.initRandom(random),
        .stake = .{
            .delegation = .{
                .voter_pubkey = Pubkey.initRandom(random),
                .stake = 1_000_000_000,
                .activation_epoch = 0,
                .deactivation_epoch = std.math.maxInt(Epoch),
                .deprecated_warmup_cooldown_rate = 0.0,
            },
            .credits_observed = 0,
        },
        .stake_reward = 1_000_000_000,
        .commission = 50,
    };

    // Stake State for Distribution
    var data = [_]u8{0} ** StakeStateV2.SIZE;
    const stake_state = StakeStateV2{ .stake = .{
        .meta = .{
            .rent_exempt_reserve = 0,
            .authorized = .{
                .staker = Pubkey.initRandom(random),
                .withdrawer = Pubkey.initRandom(random),
            },
            .lockup = .{
                .unix_timestamp = 0,
                .epoch = 0,
                .custodian = Pubkey.initRandom(random),
            },
        },
        .stake = partitioned_reward.stake,
        .flags = .EMPTY,
    } };
    _ = try sig.bincode.writeToSlice(
        &data,
        stake_state,
        .{},
    );
    const account = sig.runtime.AccountSharedData{
        .lamports = 5_000_000_000,
        .data = &data,
        .owner = sig.runtime.program.stake.ID,
        .executable = false,
        .rent_epoch = 0,
    };
    try slot_store.put(partitioned_reward.stake_pubkey, account);
    {
        var stakes, var guard = stakes_cache.stakes.writeWithLock();
        defer guard.unlock();
        try stakes.stake_accounts.put(
            allocator,
            partitioned_reward.stake_pubkey,
            partitioned_reward.stake,
        );
    }

    partitioned_reward.stake.delegation.stake = 2_000_000_000;
    var partition_rewards: StartBlockHeightAndPartitionedRewards = .{
        .distribution_start_block_height = 0,
        .partitioned_indices = try sig.replay.rewards.PartitionedIndices.init(
            allocator,
            try allocator.dupe(
                []const usize,
                &[_][]const usize{try allocator.dupe(usize, &[_]usize{0})},
            ),
        ),
        .all_stake_rewards = try sig.replay.rewards.PartitionedStakeRewards.init(
            allocator,
            try allocator.dupe(
                PartitionedStakeReward,
                &[_]PartitionedStakeReward{partitioned_reward},
            ),
        ),
    };
    defer partition_rewards.deinit(allocator);

    const epoch_rewards = sig.runtime.sysvar.EpochRewards{
        .distribution_starting_block_height = 0,
        .num_partitions = 1,
        .parent_blockhash = .ZEROES,
        .total_points = 0,
        .total_rewards = 1_000_000_000,
        .distributed_rewards = 0,
        .active = true,
    };
    try updateSysvarAccount(EpochRewards, allocator, epoch_rewards, .{
        .slot = 0,
        .capitalization = &capitalization,
        .rent = &rent,
        .slot_store = slot_store,
    });

    try distributeEpochRewardsInPartition(
        allocator,
        slot,
        &rent,
        partition_rewards,
        partition_index,
        &capitalization,
        &stakes_cache,
        slot_store,
    );
}

test storeStakeAccountsInPartition {
    const PartitionedStakeReward = sig.replay.rewards.PartitionedStakeReward;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var ancestors = sig.core.Ancestors.EMPTY;
    defer ancestors.deinit(allocator);
    try ancestors.addSlot(allocator, 0);

    // Partitioned Reward
    var partitioned_reward = sig.replay.rewards.PartitionedStakeReward{
        .stake_pubkey = Pubkey.initRandom(random),
        .stake = .{
            .delegation = .{
                .voter_pubkey = Pubkey.initRandom(random),
                .stake = 1_000_000_000,
                .activation_epoch = 0,
                .deactivation_epoch = std.math.maxInt(Epoch),
                .deprecated_warmup_cooldown_rate = 0.0,
            },
            .credits_observed = 0,
        },
        .stake_reward = 1_000_000_000,
        .commission = 50,
    };

    {
        // Partitioned Rewards
        const partition_index: u64 = 0;
        var partition_rewards: StartBlockHeightAndPartitionedRewards = .{
            .distribution_start_block_height = 0,
            .partitioned_indices = try sig.replay.rewards.PartitionedIndices.init(
                allocator,
                try allocator.dupe(
                    []const usize,
                    &[_][]const usize{try allocator.dupe(usize, &[_]usize{0})},
                ),
            ),
            .all_stake_rewards = try sig.replay.rewards.PartitionedStakeRewards.init(
                allocator,
                try allocator.dupe(
                    PartitionedStakeReward,
                    &[_]PartitionedStakeReward{partitioned_reward},
                ),
            ),
        };
        defer partition_rewards.deinit(allocator);

        var db_context = try sig.accounts_db.Two.initTest(allocator);
        defer db_context.deinit();

        const account_store = sig.accounts_db.AccountStore{
            .accounts_db_two = &db_context.db,
        };
        const slot_store = account_store.forSlot(0, &ancestors);

        var stakes_cache = sig.core.StakesCache.EMPTY;
        defer stakes_cache.deinit(allocator);

        const result = try storeStakeAccountsInPartition(
            allocator,
            partition_rewards,
            partition_index,
            &stakes_cache,
            slot_store,
            null,
        );
        std.debug.print("result: {any}\n", .{result});
    }

    {
        var db_context = try sig.accounts_db.Two.initTest(allocator);
        defer db_context.deinit();

        const account_store = sig.accounts_db.AccountStore{
            .accounts_db_two = &db_context.db,
        };
        const slot_store = account_store.forSlot(0, &ancestors);

        var stakes_cache = sig.core.StakesCache.EMPTY;
        defer stakes_cache.deinit(allocator);

        // Stake State for Distribution
        var data = [_]u8{0} ** StakeStateV2.SIZE;
        const stake_state = StakeStateV2{ .stake = .{
            .meta = .{
                .rent_exempt_reserve = 0,
                .authorized = .{
                    .staker = Pubkey.initRandom(random),
                    .withdrawer = Pubkey.initRandom(random),
                },
                .lockup = .{
                    .unix_timestamp = 0,
                    .epoch = 0,
                    .custodian = Pubkey.initRandom(random),
                },
            },
            .stake = partitioned_reward.stake,
            .flags = .EMPTY,
        } };
        _ = try sig.bincode.writeToSlice(
            &data,
            stake_state,
            .{},
        );
        const account = sig.runtime.AccountSharedData{
            .lamports = 5_000_000_000,
            .data = &data,
            .owner = sig.runtime.program.stake.ID,
            .executable = false,
            .rent_epoch = 0,
        };
        try slot_store.put(partitioned_reward.stake_pubkey, account);

        // Partitioned Rewards
        const partition_index: u64 = 0;
        partitioned_reward.stake.delegation.stake = 2_000_000_000;
        var partition_rewards: StartBlockHeightAndPartitionedRewards = .{
            .distribution_start_block_height = 0,
            .partitioned_indices = try sig.replay.rewards.PartitionedIndices.init(
                allocator,
                try allocator.dupe(
                    []const usize,
                    &[_][]const usize{try allocator.dupe(usize, &[_]usize{0})},
                ),
            ),
            .all_stake_rewards = try sig.replay.rewards.PartitionedStakeRewards.init(
                allocator,
                try allocator.dupe(
                    PartitionedStakeReward,
                    &[_]PartitionedStakeReward{partitioned_reward},
                ),
            ),
        };
        defer partition_rewards.deinit(allocator);

        {
            var stakes, var guard = stakes_cache.stakes.writeWithLock();
            defer guard.unlock();
            try stakes.stake_accounts.put(
                allocator,
                partitioned_reward.stake_pubkey,
                partitioned_reward.stake,
            );
        }

        const result = try storeStakeAccountsInPartition(
            allocator,
            partition_rewards,
            partition_index,
            &stakes_cache,
            slot_store,
            null,
        );
        defer {
            for (result[2]) |sr| sr.deinit(allocator);
            allocator.free(result[2]);
        }
    }
}

test buildUpdatedStakeReward {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var ancestors = sig.core.Ancestors.EMPTY;
    defer ancestors.deinit(allocator);
    try ancestors.addSlot(allocator, 0);

    var db_context = try sig.accounts_db.Two.initTest(allocator);
    defer db_context.deinit();

    const account_store = sig.accounts_db.AccountStore{
        .accounts_db_two = &db_context.db,
    };
    const slot_store = account_store.forSlot(0, &ancestors);

    var partitioned_reward = sig.replay.rewards.PartitionedStakeReward{
        .stake_pubkey = Pubkey.initRandom(random),
        .stake = .{
            .delegation = .{
                .voter_pubkey = Pubkey.initRandom(random),
                .stake = 1_000_000_000,
                .activation_epoch = 0,
                .deactivation_epoch = std.math.maxInt(Epoch),
                .deprecated_warmup_cooldown_rate = 0.0,
            },
            .credits_observed = 0,
        },
        .stake_reward = 1_000_000_000,
        .commission = 50,
    };

    var stake_accounts = std.AutoArrayHashMapUnmanaged(Pubkey, Stake).empty;
    defer stake_accounts.deinit(allocator);

    {
        const result = buildUpdatedStakeReward(
            allocator,
            stake_accounts,
            partitioned_reward,
            slot_store,
        );
        try std.testing.expectError(error.MissingStakeAccountInCache, result);
    }

    try stake_accounts.put(allocator, partitioned_reward.stake_pubkey, partitioned_reward.stake);

    {
        const result = buildUpdatedStakeReward(
            allocator,
            stake_accounts,
            partitioned_reward,
            slot_store,
        );
        try std.testing.expectError(error.MissingStakeAccountInDb, result);
    }

    var invalid_data = [_]u8{0} ** StakeStateV2.SIZE;
    try slot_store.put(partitioned_reward.stake_pubkey, .{
        .lamports = 5_000_000_000,
        .data = &invalid_data,
        .owner = sig.runtime.program.stake.ID,
        .executable = false,
        .rent_epoch = 0,
    });

    {
        const result = buildUpdatedStakeReward(
            allocator,
            stake_accounts,
            partitioned_reward,
            slot_store,
        );
        try std.testing.expectError(error.InvalidAccountData, result);
    }

    var data = [_]u8{0} ** StakeStateV2.SIZE;
    const stake_state = StakeStateV2{ .stake = .{
        .meta = .{
            .rent_exempt_reserve = 0,
            .authorized = .{
                .staker = Pubkey.initRandom(random),
                .withdrawer = Pubkey.initRandom(random),
            },
            .lockup = .{
                .unix_timestamp = 0,
                .epoch = 0,
                .custodian = Pubkey.initRandom(random),
            },
        },
        .stake = partitioned_reward.stake,
        .flags = .EMPTY,
    } };
    _ = try sig.bincode.writeToSlice(
        &data,
        stake_state,
        .{},
    );
    try slot_store.put(partitioned_reward.stake_pubkey, .{
        .lamports = 5_000_000_000,
        .data = &data,
        .owner = sig.runtime.program.stake.ID,
        .executable = false,
        .rent_epoch = 0,
    });

    partitioned_reward.stake.delegation.stake = 2_000_000_000;

    {
        const result = try buildUpdatedStakeReward(
            allocator,
            stake_accounts,
            partitioned_reward,
            slot_store,
        );
        defer result.deinit(allocator);

        try std.testing.expectEqual(6_000_000_000, result.stake_reward_info.post_balance);
    }
}
