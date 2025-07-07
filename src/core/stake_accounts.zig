const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const bincode = sig.bincode;
const vote_program = sig.runtime.program.vote;
const stake_program = sig.runtime.program.stake;

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;

const AccountSharedData = sig.runtime.AccountSharedData;

const VoteState = sig.runtime.program.vote.state.VoteState;
const VersionedVoteState = sig.runtime.program.vote.state.VoteStateVersions;

const Rent = sig.runtime.sysvar.Rent;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const StakeHistoryEntry = sig.runtime.sysvar.StakeHistory.Entry;
const ClusterStake = sig.runtime.sysvar.StakeHistory.ClusterStake;
const RwMux = sig.sync.RwMux;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

pub const StakeAccounts = std.AutoArrayHashMapUnmanaged(Pubkey, StakeAccount);

pub const StakeAccount = struct {
    account: AccountSharedData,
    state: StakeStateV2,

    pub fn deinit(self: *const StakeAccount, allocator: Allocator) void {
        self.account.deinit(allocator);
    }

    pub fn getDelegation(self: StakeAccount) Delegation {
        return self.state.getDelegation() orelse
            @panic("StakeAccount does not have a delegation");
    }

    /// Takes ownership of `account`.
    pub fn fromAccountSharedData(allocator: Allocator, account: AccountSharedData) !StakeAccount {
        errdefer account.deinit(allocator);

        if (!stake_program.ID.equals(&account.owner)) return error.InvalidOwner;

        const state = try bincode.readFromSlice(
            failing_allocator,
            StakeStateV2,
            account.data,
            .{},
        );

        if (state.getDelegation() == null) return error.NoDelegation;

        return .{
            .account = account,
            .state = state,
        };
    }
};

pub const StakeStateV2 = union(enum) {
    uninitialized,
    initialized: Meta,
    stake: struct { meta: Meta, stake: Stake, flags: StakeFlags },
    rewards_pool,

    pub const SIZE = 200;

    pub fn getStake(self: *const StakeStateV2) ?Stake {
        return switch (self.*) {
            .uninitialized => null,
            .initialized => null,
            .stake => |s| s.stake,
            .rewards_pool => null,
        };
    }

    pub fn getDelegation(self: *const StakeStateV2) ?Delegation {
        return switch (self.*) {
            .uninitialized => null,
            .initialized => null,
            .stake => |s| s.stake.delegation,
            .rewards_pool => null,
        };
    }
};

pub const Meta = struct {
    rent_exempt_reserve: u64,
    authorized: Authorized,
    lockup: Lockup,
};

pub const Stake = struct {
    delegation: Delegation,
    credits_observed: u64,
};

pub const StakeFlags = struct {
    bits: u8,
    pub const EMPTY: StakeFlags = .{ .bits = 0 };
};

pub const Authorized = struct {
    staker: Pubkey,
    withdrawer: Pubkey,
};

pub const Lockup = struct {
    unix_timestamp: i64,
    epoch: Epoch,
    custodian: Pubkey,
};

pub const Delegation = struct {
    stake: u64,
    voter_pubkey: Pubkey,
    activation_epoch: Epoch,
    deactivation_epoch: Epoch,
    deprecated_warmup_cooldown_rate: f64,

    pub fn isBootstrap(self: *const Delegation) bool {
        return self.activation_epoch == std.math.maxInt(u64);
    }

    pub fn getStake(
        self: *const Delegation,
        epoch: Epoch,
        stake_history: *const StakeHistory,
        new_rate_activation_epoch: ?Epoch,
    ) u64 {
        return self.getStakeActivatingAndDeactivating(
            epoch,
            stake_history,
            new_rate_activation_epoch,
        ).effective;
    }

    /// Returns tuple of effective stake and activating stake.
    pub fn getEffectiveAndActivating(
        self: *const Delegation,
        epoch: Epoch,
        history: *const StakeHistory,
        new_rate_activation_epoch: ?Epoch,
    ) struct { u64, u64 } {
        if (self.activation_epoch == std.math.maxInt(u64)) {
            return .{ self.stake, 0 };
        } else if (self.activation_epoch == self.deactivation_epoch) {
            return .{ 0, 0 };
        } else if (epoch == self.activation_epoch) {
            return .{ 0, self.stake };
        } else if (epoch < self.activation_epoch) {
            return .{ 0, 0 };
        } else if (history.getEntry(self.activation_epoch)) |entry| {
            var prev_epoch = entry.epoch;
            var prev_cluster_stake = entry.stake;
            var current_epoch: Epoch = undefined;
            var current_effective_stake: u64 = 0;

            while (true) {
                current_epoch = prev_epoch + 1;

                if (prev_cluster_stake.deactivating == 0) break;

                const remaining_activated_stake = self.stake - current_effective_stake;
                const weight = @as(f64, @floatFromInt(remaining_activated_stake)) / @as(f64, @floatFromInt(prev_cluster_stake.activating));
                const warmup_cooldown_rate = warmupCooldownRate(current_epoch, new_rate_activation_epoch);

                const newly_effective_cluster_stake = @as(f64, @floatFromInt(prev_cluster_stake.effective)) * warmup_cooldown_rate;
                const weighted_effective_state: u64 = @intFromFloat(weight * newly_effective_cluster_stake);
                const newly_effective_stake = @max(weighted_effective_state, 1);

                current_effective_stake += newly_effective_stake;
                if (current_effective_stake >= self.stake) {
                    current_effective_stake = self.stake;
                    break;
                }

                if (current_epoch >= epoch or current_epoch >= self.deactivation_epoch) break;

                if (history.getEntry(current_epoch)) |next_entry| {
                    prev_epoch = next_entry.epoch;
                    prev_cluster_stake = next_entry.stake;
                } else break;
            }

            return .{
                current_effective_stake,
                self.stake - current_effective_stake,
            };
        } else {
            return .{ 0, 0 };
        }
    }

    pub fn getStakeActivatingAndDeactivating(
        self: *const Delegation,
        epoch: Epoch,
        history: *const StakeHistory,
        new_rate_activation_epoch: ?Epoch,
    ) ClusterStake {
        const effective_stake, const activating_stake = self.getEffectiveAndActivating(
            epoch,
            history,
            new_rate_activation_epoch,
        );

        if (epoch < self.deactivation_epoch) {
            return .{
                .effective = effective_stake,
                .activating = activating_stake,
                .deactivating = 0,
            };
        } else if (epoch == self.deactivation_epoch) {
            return .{
                .effective = effective_stake,
                .activating = 0,
                .deactivating = effective_stake,
            };
        } else if (history.getEntry(epoch)) |entry| {
            var prev_epoch = entry.epoch;
            var prev_cluster_stake = entry.stake;
            var current_epoch: Epoch = undefined;
            var current_effective_stake = effective_stake;

            while (true) {
                current_epoch = prev_epoch + 1;

                if (prev_cluster_stake.deactivating == 0) break;

                const weight = @as(f64, @floatFromInt(current_effective_stake)) / @as(f64, @floatFromInt(prev_cluster_stake.deactivating));
                const warmup_cooldown_rate = warmupCooldownRate(current_epoch, new_rate_activation_epoch);

                const newly_not_effective_cluster_stake = @as(f64, @floatFromInt(prev_cluster_stake.effective)) * warmup_cooldown_rate;
                const wieghted_not_effective_state: u64 = @intFromFloat(weight * newly_not_effective_cluster_stake);
                const newly_not_effective_stake = @max(wieghted_not_effective_state, 1);

                current_effective_stake = current_effective_stake -| newly_not_effective_stake;
                if (current_effective_stake == 0) break;
                if (current_epoch >= epoch) break;

                if (history.getEntry(current_epoch)) |next_entry| {
                    prev_epoch = entry.epoch;
                    prev_cluster_stake = next_entry.stake;
                } else break;
            }

            return .{
                .effective = current_effective_stake,
                .activating = 0,
                .deactivating = current_effective_stake,
            };
        } else {
            return .{
                .effective = 0,
                .activating = 0,
                .deactivating = 0,
            };
        }
    }
};

const DEFAULT_WARMUP_COOLDOWN_RATE: f64 = 0.25;
const NEW_WARMUP_COOLDOWN_RATE: f64 = 0.09;

fn warmupCooldownRate(current_epoch: Epoch, new_rate_activation_epoch: ?Epoch) f64 {
    return if (current_epoch < new_rate_activation_epoch orelse std.math.maxInt(u64))
        DEFAULT_WARMUP_COOLDOWN_RATE
    else
        NEW_WARMUP_COOLDOWN_RATE;
}

pub fn createStakeAccount(
    allocator: Allocator,
    authorized: Pubkey,
    voter_pubkey: Pubkey,
    vote_account: AccountSharedData,
    rent: Rent,
    lamports: u64,
    activation_epoch: Epoch,
) !AccountSharedData {
    if (!builtin.is_test) @compileError("only for testing");

    const stake_account = AccountSharedData{
        .lamports = lamports,
        .owner = stake_program.ID,
        .data = try allocator.alloc(u8, StakeStateV2.SIZE),
        .executable = false,
        .rent_epoch = 0,
    };
    errdefer allocator.free(stake_account.data);

    const versioned_vote_state = try bincode.readFromSlice(
        allocator,
        VersionedVoteState,
        vote_account.data,
        .{},
    );
    const vote_state = try versioned_vote_state.convertToCurrent(allocator);
    defer vote_state.deinit();

    const minimum_rent = rent.minimumBalance(StakeStateV2.SIZE);

    const stake_state = StakeStateV2{ .stake = .{
        .meta = .{
            .rent_exempt_reserve = minimum_rent,
            .authorized = .{ .staker = authorized, .withdrawer = authorized },
            .lockup = .{ .unix_timestamp = 0, .epoch = 0, .custodian = Pubkey.ZEROES },
        },
        .stake = .{
            .delegation = .{
                .stake = lamports - minimum_rent,
                .voter_pubkey = voter_pubkey,
                .activation_epoch = activation_epoch,
                .deactivation_epoch = std.math.maxInt(u64),
                .deprecated_warmup_cooldown_rate = DEFAULT_WARMUP_COOLDOWN_RATE,
            },
            .credits_observed = vote_state.getCredits(),
        },
        .flags = .EMPTY,
    } };

    _ = try bincode.writeToSlice(stake_account.data, stake_state, .{});

    return stake_account;
}

pub fn getStakeFromStakeAccount(account: AccountSharedData) !Stake {
    if (!builtin.is_test) @compileError("only for testing");

    const state_state = try bincode.readFromSlice(
        failing_allocator,
        StakeStateV2,
        account.data,
        .{},
    );

    return state_state.getStake().?;
}
