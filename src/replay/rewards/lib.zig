const std = @import("std");
const sig = @import("../../sig.zig");

// pub const calculation = @import("calculation.zig");
pub const points = @import("points.zig");

const Allocator = std.mem.Allocator;

const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;
const Stake = sig.core.stake.Stake;

pub const PointValue = struct {
    rewards: u64,
    points: u128,
};

pub const PartitionedStakeRewards = struct {
    stake_pubkey: Pubkey,
    stake: Stake,
    stake_reward: u64,
    commission: u8,
};
