const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicU64 = std.atomic.Value(u64);

const SlotAccountStore = sig.accounts_db.SlotAccountStore;

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Epoch = sig.core.Epoch;
const EpochSchedule = sig.core.EpochSchedule;
const FeatureSet = sig.core.FeatureSet;
const Inflation = sig.core.Inflation;
const VoteAccounts = sig.core.stakes.VoteAccounts;
const VoteAccount = sig.core.stakes.VoteAccount;
const SlotState = sig.core.SlotState;
const SlotConstants = sig.core.SlotConstants;
const Stakes = sig.core.Stakes;
const StakesCache = sig.core.stakes.StakesCacheGeneric(.stake);

const AccountSharedData = sig.runtime.AccountSharedData;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const Stake = sig.runtime.program.stake.StakeStateV2.Stake;
const VoteState = sig.runtime.program.vote.state.VoteState;

const PreviousEpochInflationRewards = sig.replay.rewards.PreviousEpochInflationRewards;
const VoteRewards = sig.replay.rewards.VoteRewards;
const StakeRewards = sig.replay.rewards.StakeRewards;
const PointValue = sig.replay.rewards.inflation_rewards.PointValue;
const PartitionedStakeReward = sig.replay.rewards.PartitionedStakeReward;
const PartitionedStakeRewards = sig.replay.rewards.PartitionedStakeRewards;
const PartitionedVoteReward = sig.replay.rewards.PartitionedVoteReward;

const redeemRewards = sig.replay.rewards.inflation_rewards.redeemRewards;
const calculatePoints = sig.replay.rewards.inflation_rewards.calculatePoints;
const getEpochDurationInYears = sig.replay.rewards.inflation_rewards.getEpochDurationInYears;
const getSlotInYearsForInflation = sig.replay.rewards.inflation_rewards.getSlotInYearsForInflation;

const EpochRewards = sig.runtime.sysvar.EpochRewards;
const UpdateSysvarAccountDeps = sig.replay.update_sysvar.UpdateSysvarAccountDeps;
const updateSysvarAccount = sig.replay.update_sysvar.updateSysvarAccount;

pub fn beginPartitionedRewards(
    allocator: Allocator,
    slot: Slot,
    /// These are not constant until we process the new epoch
    slot_constants: *SlotConstants,
    slot_state: *SlotState,
    slot_store: SlotAccountStore,
    epoch_tracker: *sig.core.EpochTracker,
) !void {
    const epoch = epoch_tracker.epoch_schedule.getEpoch(slot);
    const parent_epoch = epoch_tracker.epoch_schedule.getEpoch(slot_constants.parent_slot);

    const current_epoch_info = try epoch_tracker.getEpochInfoNoOffset(
        slot,
        &slot_constants.ancestors,
    );
    const epoch_vote_accounts = current_epoch_info.stakes.stakes.vote_accounts;

    const slots_per_year = epoch_tracker.cluster.slotsPerYear();
    const previous_epoch_capitalization = &slot_state.capitalization;
    const epoch_schedule = &epoch_tracker.epoch_schedule;
    const feature_set = &slot_constants.feature_set;
    const inflation = &slot_constants.inflation;
    const stakes_cache = &slot_state.stakes_cache;

    const new_warmup_and_cooldown_rate_epoch = feature_set.newWarmupCooldownRateEpoch(
        epoch_schedule,
    );

    const distributed_rewards, const point_value, const stake_rewards =
        try calculateRewardsAndDistributeVoteRewards(
            allocator,
            slot,
            epoch,
            slots_per_year,
            parent_epoch,
            previous_epoch_capitalization,
            epoch_schedule,
            feature_set,
            inflation,
            stakes_cache,
            &epoch_vote_accounts,
            new_warmup_and_cooldown_rate_epoch,
            slot_store,
        );

    const distribution_starting_blockheight = slot_constants.block_height + 1;
    const num_partitions = try getRewardDistributionNumBlocks(
        stake_rewards.entries.len,
        epoch,
        epoch_schedule,
    );

    slot_state.reward_status = .{ .active = .{
        .distribution_start_block_height = distribution_starting_blockheight,
        .all_stake_rewards = stake_rewards,
        .partitioned_indices = null,
    } };

    const blockhash_queue, var blockhash_queue_lg = slot_state.blockhash_queue.readWithLock();
    defer blockhash_queue_lg.unlock();

    try createEpochRewardsSysvar(
        allocator,
        point_value,
        distributed_rewards,
        distribution_starting_blockheight,
        num_partitions,
        blockhash_queue.last_hash orelse return error.NoLastBlockhashInBlockhashQueue,
        .{
            .slot = slot,
            .slot_store = slot_store,
            .capitalization = &slot_state.capitalization,
            .rent = &slot_constants.rent_collector.rent,
        },
    );
}

const MAX_PARTITIONED_REWARDS_PER_BLOCK: u64 = 4096;

fn getRewardDistributionNumBlocks(
    total_stake_accounts: usize,
    epoch: Epoch,
    epoch_schedule: *const EpochSchedule,
) !u64 {
    if (epoch_schedule.warmup and epoch < epoch_schedule.first_normal_epoch) {
        return 1;
    }

    const num_chunks = try std.math.divCeil(
        u64,
        total_stake_accounts,
        MAX_PARTITIONED_REWARDS_PER_BLOCK,
    );

    // Ensure at least 1 block, but cap to a maximum number of blocks
    // MINIMUM_SLOTS_PER_EPOCH > MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH
    const MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH: u64 = 10;
    const max_chunks = try std.math.divFloor(
        u64,
        epoch_schedule.slots_per_epoch,
        MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH,
    );

    return @min(@max(num_chunks, 1), max_chunks);
}

fn createEpochRewardsSysvar(
    allocator: Allocator,
    point_value: PointValue,
    distributed_rewards: u64,
    distribution_starting_block_height: u64,
    num_partitions: u64,
    last_blockhash: Hash,
    update_sysvar_deps: UpdateSysvarAccountDeps,
) !void {
    const epoch_rewards = EpochRewards{
        .distribution_starting_block_height = distribution_starting_block_height,
        .num_partitions = num_partitions,
        .parent_blockhash = last_blockhash,
        .total_points = point_value.points,
        .total_rewards = point_value.rewards,
        .distributed_rewards = distributed_rewards,
        .active = true,
    };

    try updateSysvarAccount(
        EpochRewards,
        allocator,
        epoch_rewards,
        update_sysvar_deps,
    );
}

fn calculateRewardsAndDistributeVoteRewards(
    allocator: Allocator,
    slot: Slot,
    epoch: Epoch,
    slots_per_year: f64,
    previous_epoch: Epoch,
    capitalization: *AtomicU64,
    epoch_schedule: *const EpochSchedule,
    feature_set: *const FeatureSet,
    inflation: *const Inflation,
    stakes_cache: *StakesCache,
    epoch_vote_accounts: *const VoteAccounts,
    new_warmup_and_cooldown_rate_epoch: ?Epoch,
    slot_store: SlotAccountStore,
) !struct {
    u64,
    PointValue,
    PartitionedStakeRewards,
} {
    // TODO: Lookup in rewards calculation cache
    var rewards_for_partitioning = try calculateRewardsForPartitioning(
        allocator,
        slot,
        epoch,
        slots_per_year,
        previous_epoch,
        capitalization.load(.monotonic),
        epoch_schedule,
        feature_set,
        inflation,
        stakes_cache,
        epoch_vote_accounts,
        new_warmup_and_cooldown_rate_epoch,
    );
    defer rewards_for_partitioning.deinit(allocator);

    try storeVoteAccountsPartitioned(
        allocator,
        slot_store,
        stakes_cache,
        rewards_for_partitioning.vote_rewards.vote_rewards.entries,
        new_warmup_and_cooldown_rate_epoch,
    );

    // TODO: Update vote rewards
    // Looks like this is for metadata, and not protocol defining

    std.debug.assert(rewards_for_partitioning.point_value.rewards >=
        rewards_for_partitioning.vote_rewards.total_vote_rewards_lamports +
            rewards_for_partitioning.stake_rewards.total_stake_rewards_lamports);

    _ = capitalization.fetchAdd(
        rewards_for_partitioning.vote_rewards.total_vote_rewards_lamports,
        .monotonic,
    );

    rewards_for_partitioning.stake_rewards.stake_rewards.acquire();
    return .{
        rewards_for_partitioning.vote_rewards.total_vote_rewards_lamports,
        rewards_for_partitioning.point_value,
        rewards_for_partitioning.stake_rewards.stake_rewards,
    };
}

fn storeVoteAccountsPartitioned(
    allocator: Allocator,
    slot_store: SlotAccountStore,
    stakes_cache: *StakesCache,
    vote_rewards: []const PartitionedVoteReward,
    new_warmup_and_cooldown_rate_epoch: ?Epoch,
) !void {
    for (vote_rewards) |vote_reward| {
        const account = (try slot_store.reader().get(allocator, vote_reward.vote_pubkey)) orelse
            return error.MissingVoteAccount;
        defer account.deinit(allocator);

        // NOTE: Cloning should not be necessary here. Check and store only uses the account data to deserialise
        // the stake state and obtain the delegation and credits observed. This will be addressed during
        // transition to using stakes delegations deltas, so is acceptable for now.
        var account_shared_data = try AccountSharedData.fromAccount(allocator, &account);
        defer account_shared_data.deinit(allocator);

        account_shared_data.lamports = vote_reward.account.lamports;

        try stakes_cache.checkAndStore(
            allocator,
            vote_reward.vote_pubkey,
            account_shared_data,
            new_warmup_and_cooldown_rate_epoch,
        );
        try slot_store.put(vote_reward.vote_pubkey, account_shared_data);
    }
}

const RewardsForPartitioning = struct {
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

fn calculateRewardsForPartitioning(
    allocator: Allocator,
    slot: Slot,
    epoch: Epoch,
    slots_per_year: f64,
    previous_epoch: Epoch,
    previous_epoch_capitalization: u64,
    epoch_schedule: *const EpochSchedule,
    feature_set: *const FeatureSet,
    inflation: *const Inflation,
    stakes_cache: *StakesCache,
    epoch_vote_accounts: *const VoteAccounts,
    new_warmup_and_cooldown_rate_epoch: ?Epoch,
) !RewardsForPartitioning {
    const prev_inflation_rewards = calculatePreviousEpochInflationRewards(
        slot,
        epoch,
        slots_per_year,
        previous_epoch,
        previous_epoch_capitalization,
        epoch_schedule,
        feature_set,
        inflation,
    );

    const validator_rewards = try calculateValidatorRewards(
        allocator,
        slot,
        feature_set,
        previous_epoch,
        prev_inflation_rewards.validator_rewards,
        stakes_cache,
        epoch_vote_accounts,
        new_warmup_and_cooldown_rate_epoch,
    ) orelse try ValidatorRewards.initEmpty(allocator);
    errdefer validator_rewards.deinit(allocator);

    return .{
        .vote_rewards = validator_rewards.vote_rewards,
        .stake_rewards = validator_rewards.stake_rewards,
        .point_value = validator_rewards.point_value,
        .validator_rate = prev_inflation_rewards.validator_rate,
        .foundation_rate = prev_inflation_rewards.foundation_rate,
        .previous_epoch_duration_in_years = prev_inflation_rewards.previous_epoch_duration_in_years,
        .capitalization = previous_epoch_capitalization,
    };
}

const ValidatorRewards = struct {
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

fn calculateValidatorRewards(
    allocator: Allocator,
    slot: Slot,
    feature_set: *const FeatureSet,
    rewarded_epoch: Epoch,
    rewards: u64,
    stakes_cache: *StakesCache,
    epoch_vote_accounts: *const VoteAccounts,
    new_warmup_and_cooldown_rate_epoch: ?Epoch,
) !?ValidatorRewards {
    const stakes, var stakes_lg = stakes_cache.stakes.readWithLock();
    defer stakes_lg.unlock();

    const stake_history = &stakes.stake_history;
    var filtered_stake_delegations =
        try filterStakesDelegations(allocator, slot, feature_set, stakes);
    defer filtered_stake_delegations.deinit(allocator);

    const point_value = try calculateRewardPointsPartitioned(
        rewards,
        &stakes.stake_history,
        filtered_stake_delegations.items(.stake),
        epoch_vote_accounts,
        new_warmup_and_cooldown_rate_epoch,
    ) orelse return null;

    return try calculateStakeVoteRewards(
        allocator,
        stake_history,
        filtered_stake_delegations,
        epoch_vote_accounts,
        rewarded_epoch,
        point_value,
        new_warmup_and_cooldown_rate_epoch,
    );
}

const FilteredStakesDelegations = std.MultiArrayList(struct { pubkey: Pubkey, stake: Stake });

fn filterStakesDelegations(
    allocator: Allocator,
    slot: u64,
    feature_set: *const FeatureSet,
    stakes: *const Stakes(.stake),
) !FilteredStakesDelegations {
    var result = FilteredStakesDelegations{};
    if (feature_set.active(.stake_minimum_delegation_for_rewards, slot)) {
        const min_delegation = @max(sig.runtime.program.stake.getMinimumDelegation(
            slot,
            feature_set,
        ), 1_000_000_000); // LAMPORTS_PER_SOL

        for (stakes.stake_accounts.keys(), stakes.stake_accounts.values()) |key, value| {
            if (value.delegation.stake < min_delegation) continue;
            try result.append(allocator, .{ .pubkey = key, .stake = value });
        }
    } else {
        for (stakes.stake_accounts.keys(), stakes.stake_accounts.values()) |key, value| {
            try result.append(allocator, .{ .pubkey = key, .stake = value });
        }
    }
    return result;
}

fn calculateRewardPointsPartitioned(
    rewards: u64,
    stake_history: *const StakeHistory,
    stake_delegations: []const Stake,
    epoch_vote_accounts: *const VoteAccounts,
    new_warmup_and_cooldown_rate_epoch: ?Epoch,
) !?PointValue {
    var points: u128 = 0;
    for (stake_delegations) |stake| {
        const vote_pubkey = stake.delegation.voter_pubkey;
        const vote_account = epoch_vote_accounts.getAccount(vote_pubkey) orelse continue;
        if (!vote_account.account.owner.equals(&sig.runtime.program.vote.ID)) continue;
        points += calculatePoints(
            stake,
            &vote_account.state,
            stake_history,
            new_warmup_and_cooldown_rate_epoch,
        );
    }
    return if (points > 0) PointValue{ .rewards = rewards, .points = points } else null;
}

const VoteReward = struct {
    commission: u8,
    rewards: u64,
    account: VoteAccount.MinimalAccount,
};

fn calculateStakeVoteRewards(
    allocator: Allocator,
    stake_history: *const StakeHistory,
    stake_delegations: FilteredStakesDelegations,
    cached_vote_accounts: *const VoteAccounts,
    rewarded_epoch: Epoch,
    point_value: PointValue,
    new_warmup_and_cooldown_rate_epoch: ?Epoch,
) !ValidatorRewards {
    var vote_account_rewards_map = std.AutoArrayHashMapUnmanaged(Pubkey, VoteReward).empty;
    defer vote_account_rewards_map.deinit(allocator);
    try vote_account_rewards_map.ensureTotalCapacity(
        allocator,
        cached_vote_accounts.vote_accounts.count(),
    );

    var partitioned_stake_rewards = std.ArrayListUnmanaged(PartitionedStakeReward){};
    defer partitioned_stake_rewards.deinit(allocator);

    // Use par iter?
    var total_stake_rewards: u64 = 0;
    const pubkeys = stake_delegations.items(.pubkey);
    const stakes = stake_delegations.items(.stake);
    for (pubkeys, stakes) |stake_pubkey, *stake| {
        const vote_pubkey = stake.delegation.voter_pubkey;
        const vote_account = cached_vote_accounts.getAccount(vote_pubkey) orelse continue;

        const redeemed = redeemRewards(
            rewarded_epoch,
            stake,
            &vote_account.state,
            &point_value,
            stake_history,
            new_warmup_and_cooldown_rate_epoch,
        ) catch |e| switch (e) {
            error.NoCreditsToRedeem => continue,
            else => return e,
        };

        const commission = vote_account.state.commission();

        var voters_reward_entry = try vote_account_rewards_map.getOrPut(allocator, vote_pubkey);
        if (!voters_reward_entry.found_existing) {
            voters_reward_entry.value_ptr.* = .{
                .commission = commission,
                .rewards = 0,
                .account = vote_account.account,
            };
        }

        voters_reward_entry.value_ptr.rewards +|= redeemed.voters_reward;
        total_stake_rewards +|= redeemed.stakers_reward;

        try partitioned_stake_rewards.append(allocator, .{
            .stake_pubkey = stake_pubkey,
            .stake = stake.*,
            .stake_reward = redeemed.stakers_reward,
            .commission = commission,
        });
    }

    const vote_rewards = try calculateVoteAccountsToStore(allocator, vote_account_rewards_map);
    errdefer vote_rewards.deinit(allocator);

    const stake_rewards_slice = try partitioned_stake_rewards.toOwnedSlice(allocator);
    errdefer allocator.free(stake_rewards_slice);

    return .{
        .vote_rewards = vote_rewards,
        .stake_rewards = .{
            .stake_rewards = try .init(allocator, stake_rewards_slice),
            .total_stake_rewards_lamports = total_stake_rewards,
        },
        .point_value = point_value,
    };
}

fn calculateVoteAccountsToStore(
    allocator: Allocator,
    vote_reward_map: std.AutoArrayHashMapUnmanaged(Pubkey, VoteReward),
) !VoteRewards {
    var total_vote_rewards: u64 = 0;
    var vote_rewards = try std.ArrayListUnmanaged(PartitionedVoteReward).initCapacity(
        allocator,
        vote_reward_map.count(),
    );

    const keys = vote_reward_map.keys();
    const values = vote_reward_map.values();
    for (keys, values) |vote_pubkey, *vote_reward| {
        vote_reward.account.lamports = try std.math.add(
            u64,
            vote_reward.account.lamports,
            vote_reward.rewards,
        );

        try vote_rewards.append(allocator, .{
            .vote_pubkey = vote_pubkey,
            .rewards = .{
                .reward_type = .voting,
                .lamports = vote_reward.rewards,
                .post_balance = vote_reward.account.lamports,
                .commission = vote_reward.commission,
            },
            .account = vote_reward.account,
        });
        total_vote_rewards +|= vote_reward.rewards;
    }

    const vote_rewards_slice = try vote_rewards.toOwnedSlice(allocator);
    errdefer allocator.free(vote_rewards_slice);

    return .{
        .vote_rewards = try .init(allocator, vote_rewards_slice),
        .total_vote_rewards_lamports = total_vote_rewards,
    };
}

fn calculatePreviousEpochInflationRewards(
    slot: Slot,
    epoch: Epoch,
    slots_per_year: f64,
    previous_epoch: Epoch,
    previous_epoch_capitalization: u64,
    epoch_schedule: *const EpochSchedule,
    feature_set: *const FeatureSet,
    inflation: *const Inflation,
) PreviousEpochInflationRewards {
    const slot_in_years = getSlotInYearsForInflation(
        slot,
        epoch,
        slots_per_year,
        feature_set,
        epoch_schedule,
    );

    const validator_rate = inflation.validatorRate(slot_in_years);
    const foundation_rate = inflation.foundationRate(slot_in_years);

    const previous_epoch_duration_in_years = getEpochDurationInYears(
        previous_epoch,
        slots_per_year,
        epoch_schedule,
    );

    const validator_rewards = validator_rate *
        @as(f64, @floatFromInt(previous_epoch_capitalization)) *
        previous_epoch_duration_in_years;

    return PreviousEpochInflationRewards{
        .validator_rewards = @intFromFloat(validator_rewards),
        .previous_epoch_duration_in_years = previous_epoch_duration_in_years,
        .validator_rate = validator_rate,
        .foundation_rate = foundation_rate,
    };
}

fn newVoteAccountForTest(
    allocator: Allocator,
    random: std.Random,
    comission: u8,
    voter_epoch: Epoch,
) !VoteAccount {
    const vote_pubkey = Pubkey.initRandom(random);
    var vote_state = try VoteState.init(
        allocator,
        Pubkey.initRandom(random),
        Pubkey.initRandom(random),
        Pubkey.initRandom(random),
        comission,
        voter_epoch,
    );
    defer vote_state.deinit(allocator);
    var vote_state_v4 = try sig.runtime.program.vote.state.VoteStateV4.fromVoteStateV3(
        allocator,
        vote_state,
        vote_pubkey,
    );
    errdefer vote_state_v4.deinit(allocator);
    return VoteAccount.init(
        allocator,
        .{
            .lamports = 1234,
            .owner = sig.runtime.program.vote.ID,
        },
        vote_state_v4,
    );
}

test calculateRewardsAndDistributeVoteRewards {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const slot = 32;
    const epoch = 1;
    const previous_epoch = 0;
    const epoch_schedule = EpochSchedule.INIT;
    const inflation = Inflation.DEFAULT;
    const feature_set = FeatureSet.ALL_DISABLED;
    var previous_epoch_capitalization = AtomicU64.init(43074320810);
    const slots_per_year: f64 = 32.00136089369159;

    const vote_account_0_pubkey = Pubkey.initRandom(random);
    const vote_account_0_stake: u64 = 5_000_000_000;
    var vote_account_0 = try VoteAccount.init(
        allocator,
        .{
            .lamports = 10_000_000_000,
            .owner = sig.runtime.program.vote.ID,
        },
        try .init(
            allocator,
            Pubkey.initRandom(random),
            Pubkey.initRandom(random),
            Pubkey.initRandom(random),
            10,
            epoch,
            vote_account_0_pubkey,
        ),
    );
    try vote_account_0.state.epoch_credits.append(allocator, .{
        .credits = 10,
        .epoch = 1,
        .prev_credits = 5,
    });

    const stake_account_0_pubkey = Pubkey.initRandom(random);
    const stake_account_0_stake = sig.runtime.program.stake.state.StakeStateV2.Stake{
        .delegation = .{
            .voter_pubkey = vote_account_0_pubkey,
            .stake = 5_000_000_000,
            .activation_epoch = 0,
            .deactivation_epoch = std.math.maxInt(Epoch),
            .deprecated_warmup_cooldown_rate = 0.0,
        },
        .credits_observed = 0,
    };

    var epoch_vote_accounts = VoteAccounts{};
    defer epoch_vote_accounts.deinit(allocator);
    try epoch_vote_accounts.vote_accounts.put(allocator, vote_account_0_pubkey, .{
        .account = vote_account_0,
        .stake = vote_account_0_stake,
    });

    var stakes_cache = StakesCache.EMPTY;
    defer stakes_cache.deinit(allocator);

    {
        var stakes, var guard = stakes_cache.stakes.writeWithLock();
        defer guard.unlock();

        try stakes.stake_accounts.put(allocator, stake_account_0_pubkey, stake_account_0_stake);
        try stakes.stake_history.entries.append(.{ .epoch = 1, .stake = .{
            .activating = 0,
            .effective = 500_000_000_000,
            .deactivating = 0,
        } });
    }

    var test_context = try sig.accounts_db.Two.initTest(allocator);
    defer test_context.deinit();

    var ancestors = sig.core.Ancestors.EMPTY;
    defer ancestors.deinit(allocator);
    try ancestors.addSlot(allocator, 0);

    const account_store = sig.accounts_db.AccountStore{
        .accounts_db_two = &test_context.db,
    };
    const vote_account_shared_data = try vote_account_0.toAccountSharedData(allocator);
    defer vote_account_shared_data.deinit(allocator);
    try account_store.put(
        0,
        vote_account_0_pubkey,
        vote_account_shared_data,
    );
    const slot_store = account_store.forSlot(slot, &ancestors);

    var result = try calculateRewardsAndDistributeVoteRewards(
        allocator,
        slot,
        epoch,
        slots_per_year,
        previous_epoch,
        &previous_epoch_capitalization,
        &epoch_schedule,
        &feature_set,
        &inflation,
        &stakes_cache,
        &epoch_vote_accounts,
        null,
        slot_store,
    );
    defer result[2].deinit(allocator);

    const updated_vote_account = try slot_store.reader().get(
        allocator,
        vote_account_0_pubkey,
    );
    defer updated_vote_account.?.deinit(allocator);
}

test calculateRewardsForPartitioning {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const slot = 32;
    const epoch = 1;
    const previous_epoch = 0;
    const epoch_schedule = EpochSchedule.INIT;
    const inflation = Inflation.DEFAULT;
    const feature_set = FeatureSet.ALL_DISABLED;
    const previous_epoch_capitalization: u64 = 43074320810;
    const slots_per_year: f64 = 32.00136089369159;

    const vote_account_0_pubkey = Pubkey.initRandom(random);
    const vote_account_0_stake: u64 = 5_000_000_000;
    var vote_account_0 = try VoteAccount.init(
        allocator,
        .{
            .lamports = 10_000_000_000,
            .owner = sig.runtime.program.vote.ID,
        },
        try .init(
            allocator,
            Pubkey.initRandom(random),
            Pubkey.initRandom(random),
            Pubkey.initRandom(random),
            10,
            epoch,
            vote_account_0_pubkey,
        ),
    );
    try vote_account_0.state.epoch_credits.append(allocator, .{
        .credits = 10,
        .epoch = 1,
        .prev_credits = 5,
    });

    const stake_account_0_pubkey = Pubkey.initRandom(random);
    const stake_account_0_stake = sig.runtime.program.stake.state.StakeStateV2.Stake{
        .delegation = .{
            .voter_pubkey = vote_account_0_pubkey,
            .stake = 5_000_000_000,
            .activation_epoch = 0,
            .deactivation_epoch = std.math.maxInt(Epoch),
            .deprecated_warmup_cooldown_rate = 0.0,
        },
        .credits_observed = 0,
    };

    var epoch_vote_accounts = VoteAccounts{};
    defer epoch_vote_accounts.deinit(allocator);
    try epoch_vote_accounts.vote_accounts.put(allocator, vote_account_0_pubkey, .{
        .account = vote_account_0,
        .stake = vote_account_0_stake,
    });

    var stakes_cache = StakesCache.EMPTY;
    defer stakes_cache.deinit(allocator);

    {
        var stakes, var guard = stakes_cache.stakes.writeWithLock();
        defer guard.unlock();

        try stakes.stake_accounts.put(allocator, stake_account_0_pubkey, stake_account_0_stake);
        try stakes.stake_history.entries.append(.{ .epoch = 1, .stake = .{
            .activating = 0,
            .effective = 500_000_000_000,
            .deactivating = 0,
        } });
    }

    var rewards = try calculateRewardsForPartitioning(
        allocator,
        slot,
        epoch,
        slots_per_year,
        previous_epoch,
        previous_epoch_capitalization,
        &epoch_schedule,
        &feature_set,
        &inflation,
        &stakes_cache,
        &epoch_vote_accounts,
        null,
    );
    defer rewards.deinit(allocator);
}

test calculateValidatorRewards {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    { // Null
        const slot = 0;
        const previous_epoch = 0;
        const previous_rewards: u64 = 0;
        const feature_set = FeatureSet.ALL_DISABLED;
        const epoch_vote_accounts = VoteAccounts{};
        var stakes_cache = StakesCache.EMPTY;

        const rewards = try calculateValidatorRewards(
            allocator,
            slot,
            &feature_set,
            previous_epoch,
            previous_rewards,
            &stakes_cache,
            &epoch_vote_accounts,
            null,
        );

        try std.testing.expectEqual(null, rewards);
    }

    const slot = 32;
    const epoch = 1;
    const previous_epoch = 0;
    const previous_rewards: u64 = 0;
    const feature_set = FeatureSet.ALL_DISABLED;

    const vote_account_0_pubkey = Pubkey.initRandom(random);
    const vote_account_0_stake: u64 = 5_000_000_000;
    var vote_account_0 = try VoteAccount.init(
        allocator,
        .{
            .lamports = 10_000_000_000,
            .owner = sig.runtime.program.vote.ID,
        },
        try .init(
            allocator,
            Pubkey.initRandom(random),
            Pubkey.initRandom(random),
            Pubkey.initRandom(random),
            10,
            epoch,
            vote_account_0_pubkey,
        ),
    );
    try vote_account_0.state.epoch_credits.append(allocator, .{
        .credits = 10,
        .epoch = 1,
        .prev_credits = 5,
    });

    const stake_account_0_pubkey = Pubkey.initRandom(random);
    const stake_account_0_stake = sig.runtime.program.stake.state.StakeStateV2.Stake{
        .delegation = .{
            .voter_pubkey = vote_account_0_pubkey,
            .stake = 5_000_000_000,
            .activation_epoch = 0,
            .deactivation_epoch = std.math.maxInt(Epoch),
            .deprecated_warmup_cooldown_rate = 0.0,
        },
        .credits_observed = 0,
    };

    var epoch_vote_accounts = VoteAccounts{};
    defer epoch_vote_accounts.deinit(allocator);
    try epoch_vote_accounts.vote_accounts.put(allocator, vote_account_0_pubkey, .{
        .account = vote_account_0,
        .stake = vote_account_0_stake,
    });

    var stakes_cache = StakesCache.EMPTY;
    defer stakes_cache.deinit(allocator);

    {
        var stakes, var guard = stakes_cache.stakes.writeWithLock();
        defer guard.unlock();

        try stakes.stake_accounts.put(allocator, stake_account_0_pubkey, stake_account_0_stake);
        try stakes.stake_history.entries.append(.{ .epoch = 1, .stake = .{
            .activating = 0,
            .effective = 500_000_000_000,
            .deactivating = 0,
        } });
    }

    const rewards = try calculateValidatorRewards(
        allocator,
        slot,
        &feature_set,
        previous_epoch,
        previous_rewards,
        &stakes_cache,
        &epoch_vote_accounts,
        null,
    );
    defer rewards.?.deinit(allocator);
}

test filterStakesDelegations {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    const slot = 30;
    const stakes = try Stakes(.stake).initRandom(allocator, random, 100);
    defer stakes.deinit(allocator);

    var feature_set = FeatureSet.ALL_DISABLED;

    {
        var result = try filterStakesDelegations(allocator, slot, &feature_set, &stakes);
        defer result.deinit(allocator);
        try std.testing.expectEqual(stakes.stake_accounts.count(), result.items(.stake).len);
    }

    feature_set.setSlot(.stake_minimum_delegation_for_rewards, slot);

    {
        var result = try filterStakesDelegations(allocator, slot, &feature_set, &stakes);
        defer result.deinit(allocator);

        for (result.items(.stake)) |stake| {
            try std.testing.expect(stake.delegation.stake >= 1_000_000_000);
        }
    }
}

test calculateRewardPointsPartitioned {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    const slot = 32;
    const epoch = 1;

    { // Empty returns null point value
        var stakes = Stakes(.stake).EMPTY;
        defer stakes.deinit(allocator);

        var vote_accounts = VoteAccounts{};
        defer vote_accounts.deinit(allocator);

        var filtered_stake_delegations = try filterStakesDelegations(
            allocator,
            slot,
            &FeatureSet.ALL_DISABLED,
            &stakes,
        );
        defer filtered_stake_delegations.deinit(allocator);

        const rewards: u64 = 1_000_000_000;
        const point_value = try calculateRewardPointsPartitioned(
            rewards,
            &stakes.stake_history,
            filtered_stake_delegations.items(.stake),
            &vote_accounts,
            null,
        );

        try std.testing.expectEqual(null, point_value);
    }

    // Non-empty returns point value

    var vote_accounts = VoteAccounts{};
    defer vote_accounts.deinit(allocator);

    const rc = try allocator.create(sig.sync.ReferenceCounter);
    errdefer allocator.destroy(rc);
    rc.* = .init;

    const vote_account_0_pubkey = Pubkey.initRandom(random);
    const vote_account_0_stake: u64 = 5_000_000_000;
    var vote_account_0 = VoteAccount{
        .account = .{
            .lamports = 10_000_000_000,
            .owner = sig.runtime.program.vote.ID,
        },
        .state = try .init(
            allocator,
            Pubkey.initRandom(random),
            Pubkey.initRandom(random),
            Pubkey.initRandom(random),
            10,
            epoch,
            vote_account_0_pubkey,
        ),
        .rc = rc,
    };
    try vote_account_0.state.epoch_credits.append(allocator, .{
        .credits = 10,
        .epoch = 1,
        .prev_credits = 5,
    });
    try vote_accounts.vote_accounts.put(allocator, vote_account_0_pubkey, .{
        .stake = vote_account_0_stake,
        .account = vote_account_0,
    });

    const stakes = try allocator.alloc(Stake, 1);
    defer allocator.free(stakes);
    stakes[0] = .{
        .delegation = .{
            .voter_pubkey = vote_account_0_pubkey,
            .stake = 5_000_000_000,
            .activation_epoch = 0,
            .deactivation_epoch = std.math.maxInt(Epoch),
            .deprecated_warmup_cooldown_rate = 0.0,
        },
        .credits_observed = 0,
    };

    var stake_history = StakeHistory.INIT;
    try stake_history.entries.append(.{ .epoch = 1, .stake = .{
        .activating = 0,
        .effective = 500_000_000_000,
        .deactivating = 0,
    } });

    const rewards: u64 = 1_000_000_000;
    const point_value = try calculateRewardPointsPartitioned(
        rewards,
        &stake_history,
        stakes,
        &vote_accounts,
        null,
    );

    // This test does not validate the point value, just that it is calculated
    try std.testing.expectEqual(PointValue{
        .points = 25_000_000_000,
        .rewards = rewards,
    }, point_value);
}

test calculateStakeVoteRewards {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var stake_delegations = FilteredStakesDelegations{};
    defer stake_delegations.deinit(allocator);

    var cached_vote_accounts = VoteAccounts{};
    defer cached_vote_accounts.deinit(allocator);

    var rewarded_epoch: Epoch = 5;
    const vote_epoch: Epoch = 0;
    const vote_commission: u8 = 0;
    const stake_epoch_credits: u64 = 0;
    const stake_activation_epoch: Epoch = 3;

    const vote_pubkey_0 = Pubkey.initRandom(random);
    const vote_account_0 = try newVoteAccountForTest(
        allocator,
        random,
        vote_commission,
        vote_epoch,
    );
    try cached_vote_accounts.vote_accounts.put(
        allocator,
        vote_pubkey_0,
        .{ .stake = 1_000_000_000, .account = vote_account_0 },
    );

    const stake_0_pubkey = Pubkey.initRandom(random);
    const stake_0 = sig.replay.rewards.inflation_rewards.newStakeForTest(
        1_000_000_000,
        vote_pubkey_0,
        stake_epoch_credits,
        stake_activation_epoch,
    );
    try stake_delegations.append(allocator, .{ .pubkey = stake_0_pubkey, .stake = stake_0 });

    { // No Credits To Redeem
        const result = try calculateStakeVoteRewards(
            allocator,
            &StakeHistory.INIT,
            stake_delegations,
            &cached_vote_accounts,
            rewarded_epoch,
            .{ .rewards = 1, .points = 0 },
            null,
        );
        defer result.deinit(allocator);

        try std.testing.expectEqual(0, result.stake_rewards.stake_rewards.entries.len);
    }

    rewarded_epoch -= 1;

    { // Zero Rewards
        const result = try calculateStakeVoteRewards(
            allocator,
            &StakeHistory.INIT,
            stake_delegations,
            &cached_vote_accounts,
            rewarded_epoch,
            .ZERO,
            null,
        );
        defer result.deinit(allocator);

        for (result.vote_rewards.vote_rewards.entries) |pvr| {
            try std.testing.expectEqual(0, pvr.rewards.lamports);
        }

        for (result.stake_rewards.stake_rewards.entries) |psr| {
            try std.testing.expectEqual(0, psr.stake_reward);
        }
    }

    rewarded_epoch += 1;
    var stake_account = &stake_delegations.items(.stake)[0];
    stake_account.credits_observed = 5;

    var vote_account = cached_vote_accounts.vote_accounts.getPtr(vote_pubkey_0).?;
    try vote_account.account.state.incrementCredits(allocator, stake_activation_epoch + 1, 10);

    var stake_history = StakeHistory.INIT;
    try stake_history.entries.append(.{ .epoch = stake_activation_epoch, .stake = .{
        .activating = 1_000_000_000,
        .effective = 500_000_000_000,
        .deactivating = 1_000_000_000,
    } });

    { // Non-zero Rewards
        const result = try calculateStakeVoteRewards(
            allocator,
            &stake_history,
            stake_delegations,
            &cached_vote_accounts,
            rewarded_epoch,
            .{ .points = 1, .rewards = 1 },
            null,
        );
        defer result.deinit(allocator);

        try std.testing.expectEqual(1, result.vote_rewards.vote_rewards.entries.len);
        try std.testing.expectEqual(1, result.stake_rewards.stake_rewards.entries.len);
    }
}

test calculateVoteAccountsToStore {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var vote_reward_map = std.AutoArrayHashMapUnmanaged(Pubkey, VoteReward).empty;
    defer vote_reward_map.deinit(allocator);

    {
        const vote_rewards = try calculateVoteAccountsToStore(allocator, vote_reward_map);
        defer vote_rewards.deinit(allocator);
        try std.testing.expectEqual(0, vote_rewards.vote_rewards.entries.len);
    }

    const vote_account_0_pubkey = Pubkey.initRandom(random);
    const vote_account_0_reward = VoteReward{
        .commission = 10,
        .rewards = 1_000_000_000,
        .account = .{
            .lamports = 10_000_000_000,
            .owner = sig.runtime.program.vote.ID,
        },
    };
    try vote_reward_map.put(allocator, vote_account_0_pubkey, vote_account_0_reward);

    {
        const vote_rewards = try calculateVoteAccountsToStore(allocator, vote_reward_map);
        defer vote_rewards.deinit(allocator);
        try std.testing.expectEqual(1, vote_rewards.vote_rewards.entries.len);
        try std.testing.expectEqual(
            vote_account_0_pubkey,
            vote_rewards.vote_rewards.entries[0].vote_pubkey,
        );
        try std.testing.expectEqual(
            vote_account_0_reward.rewards,
            vote_rewards.vote_rewards.entries[0].rewards.lamports,
        );
        try std.testing.expectEqual(
            vote_account_0_reward.rewards,
            vote_rewards.total_vote_rewards_lamports,
        );
    }
}

// The values in this test are derived from an Agave bank vote state rewards update test
// [agave] https://github.com/anza-xyz/agave/blob/9e6bb8209d012e819e55ad90949dec17bc150fca/runtime/src/bank/tests.rs#L799-L802
test calculatePreviousEpochInflationRewards {
    const slot: Slot = 33;
    const epoch: Epoch = 1;
    const previous_epoch: Epoch = 0;
    const previous_epoch_capitalization: u64 = 43074320810;
    const slots_per_year: f64 = 32.00136089369159;

    const inflation = Inflation.DEFAULT;
    const feature_set = FeatureSet.ALL_DISABLED;
    const epoch_schedule = EpochSchedule.INIT;

    const result = calculatePreviousEpochInflationRewards(
        slot,
        epoch,
        slots_per_year,
        previous_epoch,
        previous_epoch_capitalization,
        &epoch_schedule,
        &feature_set,
        &inflation,
    );

    const agave_validator_rewards: u64 = 2782502021;
    const agave_previous_epoch_duration_in_years = 0.9999574738806856;
    const agave_validator_rate: f64 = 0.06460044647148322;
    const agave_foundation_rate: f64 = 0.0034000234984991173;

    try std.testing.expectEqual(agave_validator_rewards, result.validator_rewards);
    try std.testing.expectEqual(
        agave_previous_epoch_duration_in_years,
        result.previous_epoch_duration_in_years,
    );
    try std.testing.expectEqual(agave_validator_rate, result.validator_rate);
    try std.testing.expectEqual(agave_foundation_rate, result.foundation_rate);
}
