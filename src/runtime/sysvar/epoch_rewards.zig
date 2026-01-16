const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/epoch-rewards/src/lib.rs#L26
pub const EpochRewards = extern struct {
    /// The starting block height of the rewards distribution in the current
    /// epoch
    distribution_starting_block_height: u64,

    /// Number of partitions in the rewards distribution in the current epoch
    num_partitions: u64,

    /// The blockhash of the parent block of the first block in the epoch,
    /// used as a seed for partitioning
    parent_blockhash: Hash,

    /// The total rewards points calculated for the current epoch, where points
    /// equals the sum of (delegated stake * credits observed) for all
    /// delegations
    total_points: u128 align(16),

    /// The total rewards calculated for the current epoch. This may be greater
    /// than the total `distributed_rewards` at the end of the rewards period,
    /// due to rounding and inability to deliver rewards smaller than 1 lamport.
    total_rewards: u64,

    /// The rewards currently distributed for the current epoch, in lamports
    distributed_rewards: u64,

    /// Whether the rewards period (including calculation and distribution) is
    /// active
    active: bool,

    pub const ID: Pubkey = .parse("SysvarEpochRewards1111111111111111111111111");

    pub const INIT: EpochRewards = .{
        .distribution_starting_block_height = 0,
        .num_partitions = 0,
        .parent_blockhash = Hash.ZEROES,
        .total_points = 0,
        .total_rewards = 0,
        .distributed_rewards = 0,
        .active = false,
    };

    pub const STORAGE_SIZE: u64 = 81;

    pub fn initRandom(random: std.Random) EpochRewards {
        if (!builtin.is_test) @compileError("only for testing");
        return .{
            .distribution_starting_block_height = random.int(u64),
            .num_partitions = random.int(u64),
            .parent_blockhash = Hash.initRandom(random),
            .total_points = random.int(u128),
            .total_rewards = random.int(u64),
            .distributed_rewards = random.int(u64),
            .active = random.boolean(),
        };
    }
};
