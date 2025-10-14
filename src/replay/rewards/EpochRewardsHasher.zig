const std = @import("std");
const sig = @import("../../sig.zig");

const Allocator = std.mem.Allocator;
const SipHasher13 = std.hash.SipHash64(1, 3);

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;

const PartitionedStakeReward = sig.replay.rewards.PartitionedStakeReward;

pub const EpochRewardsHasher = @This();

hasher: SipHasher13,
partitions: usize,

pub fn init(partitions: usize, seed: *const Hash) !EpochRewardsHasher {
    const key: [SipHasher13.key_length]u8 = @splat(0);
    var hasher = SipHasher13.init(&key);
    _ = try hasher.writer().write(&seed.data);
    return EpochRewardsHasher{
        .hasher = hasher,
        .partitions = partitions,
    };
}

pub fn hashAddressToPartition(
    self: EpochRewardsHasher,
    address: *const Pubkey,
) usize {
    var v_self = self;
    _ = try v_self.hasher.writer().write(&address.data);
    const hash: u128 = v_self.hasher.finalInt();
    return @intCast(@as(u128, v_self.partitions * hash) / @as(u128, std.math.maxInt(u64) + 1));
}

fn hashRewardsIntoPartitions(
    allocator: Allocator,
    stake_rewards: []const PartitionedStakeReward,
    parent_blockhash: *const Hash,
    num_partitions: usize,
) ![]std.ArrayListUnmanaged(usize) {
    const hasher = try EpochRewardsHasher.init(num_partitions, parent_blockhash);

    var indices = try allocator.alloc(std.ArrayListUnmanaged(usize), num_partitions);
    for (indices) |*list| list.* = std.ArrayListUnmanaged(usize).empty;
    errdefer {
        for (indices) |*list| list.deinit(allocator);
        allocator.free(indices);
    }

    for (stake_rewards, 0..) |reward, index| {
        const partition_index = hasher.hashAddressToPartition(&reward.stake_pubkey);
        try indices[partition_index].append(allocator, index);
    }

    return indices;
}

test "hashRewardsIntoPartitions" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    { // Empty case
        const partition_indices = try hashRewardsIntoPartitions(
            allocator,
            &[_]PartitionedStakeReward{},
            &Hash.ZEROES,
            5,
        );
        defer {
            for (partition_indices) |*list| list.deinit(allocator);
            allocator.free(partition_indices);
        }

        var total_hashed: usize = 0;
        for (partition_indices) |list| total_hashed += list.items.len;

        try std.testing.expectEqual(0, total_hashed);
    }

    { // Non-empty case
        const expected_num = 12345;

        const stake_rewards = try allocator.alloc(PartitionedStakeReward, expected_num);
        defer allocator.free(stake_rewards);
        for (stake_rewards) |*stake_reward| {
            stake_reward.* = PartitionedStakeReward.initRandom(random);
        }

        const partition_indices = try hashRewardsIntoPartitions(
            allocator,
            stake_rewards,
            &Hash.ZEROES,
            5,
        );
        defer {
            for (partition_indices) |*list| list.deinit(allocator);
            allocator.free(partition_indices);
        }

        var total_hashed: usize = 0;
        for (partition_indices) |list| total_hashed += list.items.len;

        try std.testing.expectEqual(expected_num, total_hashed);
    }
}
