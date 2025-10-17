const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const EpochSchedule = sig.core.EpochSchedule;
const FeatureSet = sig.core.FeatureSet;
const Inflation = sig.core.Inflation;
const StakesCache = sig.core.StakesCache;
const VoteAccounts = sig.core.vote_accounts.VoteAccounts;
const Stakes = sig.core.Stakes;
const Stake = sig.core.stake.Stake;

const AccountSharedData = sig.runtime.AccountSharedData;
const StakeHistory = sig.runtime.sysvar.StakeHistory;

const PreviousEpochInflationRewards = sig.replay.rewards.PreviousEpochInflationRewards;
const ValidatorRewards = sig.replay.rewards.ValidatorRewards;
const VoteRewards = sig.replay.rewards.VoteRewards;
const PointValue = sig.replay.rewards.inflation_rewards.PointValue;
const PartitionedStakeReward = sig.replay.rewards.PartitionedStakeReward;
const PartitionedVoteReward = sig.replay.rewards.PartitionedVoteReward;

const bank_utils = sig.core.bank_utils;

const redeemRewards = sig.replay.rewards.inflation_rewards.redeemRewards;
const calculatePoints = sig.replay.rewards.inflation_rewards.calculatePoints;

/// NOTE: UNTESTED
fn calculateValidatorRewards(
    slot: Slot,
    feature_set: *const FeatureSet,
    rewarded_epoch: Epoch,
    rewards: u64,
    stakes_cache: StakesCache,
    epoch_vote_accounts: *const VoteAccounts,
    new_warmup_and_cooldown_rate_epoch: ?Epoch,
) !ValidatorRewards {
    const stakes, const stakes_lg = stakes_cache.stakes.readWithLock();
    defer stakes_lg.unlock();

    const stake_history = &stakes.stake_history;
    const filtered_stake_delegations = try filterStakesDelegations(slot, feature_set, stakes);

    const point_value = try calculateRewardPointsPartitioned(
        rewards,
        &stakes.stake_history,
        filtered_stake_delegations.items(.delegation),
        epoch_vote_accounts,
        new_warmup_and_cooldown_rate_epoch,
    ) orelse return 0;

    const result = try calculateStakeVoteRewards(
        stake_history,
        filtered_stake_delegations,
        epoch_vote_accounts,
        rewarded_epoch,
        point_value,
        new_warmup_and_cooldown_rate_epoch,
    );

    _ = result;

    // TODO: Implement
    return error.Unimplemented;
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

        for (stakes.stake_delegations.keys(), stakes.stake_delegations.values()) |key, value| {
            if (value.delegation.stake >= min_delegation) {
                try result.append(allocator, .{ .pubkey = key, .stake = value });
            }
        }
    } else {
        for (stakes.stake_delegations.keys(), stakes.stake_delegations.values()) |key, value| {
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
            vote_account.state,
            stake_history,
            new_warmup_and_cooldown_rate_epoch,
        );
    }
    return if (points > 0) PointValue{ .rewards = rewards, .points = points } else null;
}

const VoteReward = struct {
    commission: u8,
    rewards: u64,
    account: AccountSharedData,
};

/// NOTE: UNTESTED
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
    errdefer vote_account_rewards_map.deinit(allocator);
    try vote_account_rewards_map.ensureTotalCapacity(
        allocator,
        cached_vote_accounts.vote_accounts.count(),
    );

    var partitioned_stake_rewards = std.ArrayListUnmanaged(PartitionedStakeReward){};
    errdefer partitioned_stake_rewards.deinit(allocator);

    // Use par iter?
    var total_stake_rewards: u64 = 0;
    const pubkeys = stake_delegations.keys();
    const stakes = stake_delegations.values();
    for (pubkeys, stakes) |stake_pubkey, stake_delegation| {
        const vote_pubkey = stake_delegation.voter_pubkey;
        const vote_account = cached_vote_accounts.getAccount(vote_pubkey) orelse {
            return error.MissingVoteAccount;
        };
        var stake_state = stake_delegation.stake;

        const redeemed = try redeemRewards(
            rewarded_epoch,
            &stake_state,
            &vote_account.state,
            &point_value,
            stake_history,
            new_warmup_and_cooldown_rate_epoch,
        ) orelse continue; // TODO: Log warning

        const commission = vote_account.state.commission;

        var voters_reward_entry = try vote_account_rewards_map.getOrPut(allocator, vote_pubkey);
        if (!voters_reward_entry.found_existing) {
            voters_reward_entry.value_ptr.* = .{
                .commission = commission,
                .rewards = 0,
                .account = vote_account.account, // TODO: Cloning account here, does minimal account work?
            };
        } else {
            voters_reward_entry.value_ptr.voter_rewards +|= redeemed.voters_reward;
        }

        total_stake_rewards += redeemed.stakers_reward;

        try partitioned_stake_rewards.append(allocator, .{
            .stake_pubkey = stake_pubkey,
            .stake = stake_state,
            .stake_reward = redeemed.stakers_reward,
            .commission = commission,
        });
    }

    return .{
        .vote_rewards = try calculateVoteAccountsToStore(vote_account_rewards_map),
        .stake_rewards = .{
            .stake_rewards = partitioned_stake_rewards.toOwnedSlice(allocator),
            .total_stake_rewards_lamports = total_stake_rewards,
        },
        .point_value = point_value,
    };
}

/// NOTE: This function expects compete vote accounts i.e. AccountSharedData's, not MinimalAccounts
/// Hopefully we can work around this.
/// NOTE: UNTESTED
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
    for (keys, values) |vote_pubkey, vote_reward| {
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
        total_vote_rewards += vote_reward.rewards;
    }

    return .{
        .vote_rewards = vote_rewards.toOwnedSlice(allocator),
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
    const slot_in_years = bank_utils.getSlotInYearsForInflation(
        slot,
        epoch,
        slots_per_year,
        feature_set,
        epoch_schedule,
    );

    const validator_rate = inflation.validatorRate(slot_in_years);
    const foundation_rate = inflation.foundationRate(slot_in_years);

    const previous_epoch_duration_in_years = bank_utils.getEpochDurationInYears(
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
        try std.testing.expectEqual(stakes.stake_delegations.count(), result.items(.stake).len);
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
    const VoteAccount = sig.core.vote_accounts.VoteAccount;

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

    var stake_history = StakeHistory.DEFAULT;
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
    const epoch_schedule = EpochSchedule.DEFAULT;

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
