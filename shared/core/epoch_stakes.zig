const std = @import("std");
const sig = @import("../lib.zig");

const Allocator = std.mem.Allocator;
const Epoch = sig.core.Epoch;
const Pubkey = sig.core.Pubkey;

pub const Delegation = sig.runtime.program.stake.StakeStateV2.Delegation;

pub const Stakes = struct {
    stake_accounts: std.AutoArrayHashMapUnmanaged(Pubkey, Delegation),
    epoch: Epoch,

    pub const EMPTY: Stakes = .{
        .stake_accounts = .empty,
        .epoch = 0,
    };

    pub fn deinit(self: *const Stakes, allocator: Allocator) void {
        var stake_accounts = self.stake_accounts;
        stake_accounts.deinit(allocator);
    }
};

pub const EpochStakes = struct {
    stakes: Stakes,
    total_stake: u64,

    pub const EMPTY: EpochStakes = .{
        .stakes = .EMPTY,
        .total_stake = 0,
    };

    pub const EMPTY_WITH_GENESIS: EpochStakes = .{
        .stakes = .{
            .stake_accounts = .empty,
            .epoch = 0,
        },
        .total_stake = 0,
    };

    pub fn deinit(self: *const EpochStakes, allocator: Allocator) void {
        self.stakes.deinit(allocator);
    }
};
