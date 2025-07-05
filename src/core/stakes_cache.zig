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
const VoteStateVersions = sig.runtime.program.vote.state.VoteStateVersions;

const StakeHistory = sig.runtime.sysvar.StakeHistory;
const StakeHistoryEntry = sig.runtime.sysvar.StakeHistory.Entry;
const ClusterStake = sig.runtime.sysvar.StakeHistory.ClusterStake;
const RwMux = sig.sync.RwMux;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

pub const StakesCache = struct {
    stakes: RwMux(Stakes),

    pub fn initEmpty(allocator: std.mem.Allocator, epoch: Epoch) Allocator.Error!StakesCache {
        return .{ .stakes = RwMux(Stakes).init(try Stakes.initEmpty(allocator, epoch)) };
    }

    pub fn deinit(self: *StakesCache, allocator: Allocator) void {
        var stakes: *Stakes, var stakes_guard = self.stakes.writeWithLock();
        defer stakes_guard.unlock();
        stakes.deinit(allocator);
    }

    pub fn checkAndStore(
        self: *StakesCache,
        allocator: Allocator,
        pubkey: Pubkey,
        account: AccountSharedData,
        new_rate_activation_epoch: ?Epoch,
    ) Allocator.Error!void {
        if (account.lamports == 0) {
            if (vote_program.ID.equals(&account.owner)) {
                var stakes, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                stakes.removeVoteAccount(pubkey);
            } else if (stake_program.ID.equals(&account.owner)) {
                var stakes: *Stakes, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                stakes.removeStakeDelegation(pubkey, new_rate_activation_epoch);
            }
            return;
        }

        if (vote_program.ID.equals(&account.owner)) {
            if (VoteStateVersions.isCorrectSizeAndInitialized(account.data)) {
                const vote_account = VoteAccount.fromAccountSharedData(allocator, account) catch {
                    var stakes: *Stakes, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    stakes.removeVoteAccount(pubkey);
                    return;
                };
                var stakes: *Stakes, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                try stakes.upsertVoteAccount(allocator, pubkey, vote_account, new_rate_activation_epoch);
            } else {
                var stakes: *Stakes, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                stakes.removeVoteAccount(pubkey);
            }
        } else if (stake_program.ID.equals(&account.owner)) {
            const stake_account = StakeAccount.fromAccountSharedData(account) catch {
                var stakes: *Stakes, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                stakes.removeStakeDelegation(pubkey, new_rate_activation_epoch);
                return;
            };
            var stakes: *Stakes, var stakes_guard = self.stakes.writeWithLock();
            defer stakes_guard.unlock();
            try stakes.upsertStakeDelegation(
                allocator,
                pubkey,
                stake_account,
                new_rate_activation_epoch,
            );
        }
    }
};

pub const Stakes = struct {
    vote_accounts: VoteAccounts,
    stake_delegations: std.AutoArrayHashMapUnmanaged(Pubkey, StakeAccount),
    unused: u64,
    epoch: Epoch,
    stake_history: StakeHistory,

    pub fn initEmpty(allocator: Allocator, epoch: Epoch) Allocator.Error!Stakes {
        return .{
            .vote_accounts = .{
                .vote_accounts = .{},
                .staked_nodes = .{},
            },
            .stake_delegations = .{},
            .unused = 0,
            .epoch = epoch,
            .stake_history = try .default(allocator),
        };
    }

    pub fn deinit(self: *const Stakes, allocator: Allocator) void {
        var votes = self.vote_accounts;
        votes.deinit(allocator);
        var delegations = self.stake_delegations;
        delegations.deinit(allocator);
        self.stake_history.deinit(allocator);
    }

    pub fn calculateStake(
        self: *Stakes,
        pubkey: Pubkey,
        new_rate_activation_epoch: ?Epoch,
    ) u64 {
        var stake: u64 = 0;
        for (self.stake_delegations.values()) |*stake_account| {
            const delegation = stake_account.delegation();
            if (!delegation.voter_pubkey.equals(&pubkey)) continue;
            stake += delegation.getStake(
                self.epoch,
                &self.stake_history,
                new_rate_activation_epoch,
            );
        }
        return stake;
    }

    pub fn upsertVoteAccount(
        self: *Stakes,
        allocator: Allocator,
        pubkey: Pubkey,
        account: VoteAccount,
        new_rate_activation_epoch: ?Epoch,
    ) Allocator.Error!void {
        std.debug.assert(account.account.lamports > 0);

        // TODO: move this function call into vote accounts insert to prevent execution
        // on failure paths in vote_accounts.insert
        const stake = self.calculateStake(pubkey, new_rate_activation_epoch);

        try self.vote_accounts.insert(allocator, pubkey, account, stake);
    }

    pub fn upsertStakeDelegation(
        self: *Stakes,
        allocator: Allocator,
        pubkey: Pubkey,
        account: StakeAccount,
        new_rate_activation_epoch: ?Epoch,
    ) Allocator.Error!void {
        std.debug.assert(account.account.lamports > 0);
        const delegation = account.delegation();
        const voter_pubkey = delegation.voter_pubkey;
        const stake = delegation.getStake(
            self.epoch,
            &self.stake_history,
            new_rate_activation_epoch,
        );

        if (try self.stake_delegations.fetchPut(
            allocator,
            pubkey,
            account,
        )) |old_account_entry| {
            const old_account = old_account_entry.value;
            const old_delegation = old_account.delegation();
            const old_voter_pubkey = old_delegation.voter_pubkey;
            const old_stake = old_delegation.getStake(
                self.epoch,
                &self.stake_history,
                new_rate_activation_epoch,
            );
            if (!voter_pubkey.equals(&old_voter_pubkey) or stake != old_stake) {
                self.vote_accounts.subStake(old_voter_pubkey, old_stake);
                try self.vote_accounts.addStake(allocator, voter_pubkey, stake);
            }
        } else {
            try self.vote_accounts.addStake(allocator, voter_pubkey, stake);
        }
    }

    pub fn removeVoteAccount(
        self: *Stakes,
        pubkey: Pubkey,
    ) void {
        _ = self.vote_accounts.remove(pubkey);
    }

    pub fn removeStakeDelegation(
        self: *Stakes,
        pubkey: Pubkey,
        new_rate_activation_epoch: ?Epoch,
    ) void {
        var account = self.stake_delegations.getPtr(pubkey) orelse return;
        _ = self.stake_delegations.swapRemove(pubkey);
        const removed_delegation = account.delegation();
        const removed_stake = removed_delegation.getStake(
            self.epoch,
            &self.stake_history,
            new_rate_activation_epoch,
        );
        self.vote_accounts.subStake(removed_delegation.voter_pubkey, removed_stake);
    }
};

/// Current sync protection provided by read write lock in stakes cache, if accessing
/// this struct in contexts outside StakesCache function calls we may need to add sync
/// primitives here as well.
pub const VoteAccounts = struct {
    /// Arc<...>
    vote_accounts: std.AutoArrayHashMapUnmanaged(Pubkey, struct {
        stake: u64,
        account: VoteAccount,
    }),
    /// OnceLock<Arc<...>>
    staked_nodes: std.AutoArrayHashMapUnmanaged(Pubkey, u64),

    pub fn deinit(self: *const VoteAccounts, allocator: Allocator) void {
        for (self.vote_accounts.values()) |v| v.account.deinit(allocator);
        var votes = self.vote_accounts;
        votes.deinit(allocator);
        var stakes = self.staked_nodes;
        stakes.deinit(allocator);
    }

    pub fn getAccount(self: *const VoteAccounts, pubkey: Pubkey) ?VoteAccount {
        const entry = self.vote_accounts.getPtr(pubkey) orelse return null;
        return entry.account;
    }
    pub fn getDelegatedStake(self: *const VoteAccounts, pubkey: Pubkey) u64 {
        const entry = self.vote_accounts.getPtr(pubkey) orelse return 0;
        return entry.stake;
    }

    pub fn remove(
        self: *VoteAccounts,
        pubkey: Pubkey,
    ) void {
        const entry = self.vote_accounts.get(pubkey) orelse return;
        _ = self.vote_accounts.swapRemove(pubkey);
        self.subNodeStake(pubkey, entry.stake);
    }

    pub fn insert(
        self: *VoteAccounts,
        allocator: Allocator,
        pubkey: Pubkey,
        account: VoteAccount,
        caclulated_stake: u64,
    ) Allocator.Error!void {
        const entry = try self.vote_accounts.getOrPut(allocator, pubkey);
        if (entry.found_existing) {
            const old_stake = entry.value_ptr.stake;
            const old_node_pubkey = entry.value_ptr.account.state.node_pubkey;

            // may require sync primitive on staked nodes
            // if let Some(staked_nodes) = self.staked_nodes.get_mut() ...
            const new_node_pubkey = account.state.node_pubkey;
            if (!new_node_pubkey.equals(&old_node_pubkey)) {
                // Remove the old node pubkey from staked nodes
                self.subNodeStake(old_node_pubkey, old_stake);
                // Add the new node pubkey to staked nodes
                try self.addNodeStake(allocator, new_node_pubkey, old_stake);
            }
        } else {
            entry.value_ptr.* = .{ .stake = caclulated_stake, .account = account };
            // may require sync primitive on staked nodes
            // if let Some(staked_nodes) = self.staked_nodes.get_mut() ...
            try self.addNodeStake(allocator, account.state.node_pubkey, caclulated_stake);
        }
    }

    pub fn addStake(
        self: *VoteAccounts,
        allocator: Allocator,
        pubkey: Pubkey,
        delta: u64,
    ) Allocator.Error!void {
        const entry = self.vote_accounts.getPtr(pubkey) orelse return;
        entry.stake += delta;
        try self.addNodeStake(allocator, entry.account.state.node_pubkey, delta);
    }

    pub fn subStake(
        self: *VoteAccounts,
        pubkey: Pubkey,
        delta: u64,
    ) void {
        const entry = self.vote_accounts.getPtr(pubkey) orelse return;
        if (entry.stake < delta) @panic("subtraction value exceeds vote account's stake");
        entry.stake -= delta;

        // may require sync primitive on staked nodes
        // if let Some(staked_nodes) = self.staked_nodes.get_mut() ...
        self.subNodeStake(entry.account.state.node_pubkey, delta);
    }

    fn addNodeStake(
        self: *VoteAccounts,
        allocator: Allocator,
        pubkey: Pubkey,
        stake: u64,
    ) Allocator.Error!void {
        // may require sync primitive on staked nodes
        // if let Some(staked_nodes) = self.staked_nodes.get_mut() ...
        const entry = try self.staked_nodes.getOrPut(allocator, pubkey);
        if (entry.found_existing)
            entry.value_ptr.* += stake
        else
            entry.value_ptr.* = stake;
    }

    fn subNodeStake(
        self: *VoteAccounts,
        pubkey: Pubkey,
        stake: u64,
    ) void {
        if (stake == 0) return;

        // may require sync primitive on staked nodes
        // if let Some(staked_nodes) = self.staked_nodes.get_mut() ...
        const current_stake = self.staked_nodes.getPtr(pubkey) orelse
            @panic("staked node not present");

        switch (std.math.order(current_stake.*, stake)) {
            .lt => @panic("subtraction value exceeds node's stake"),
            .eq => _ = self.staked_nodes.swapRemove(pubkey),
            .gt => current_stake.* -= stake,
        }
    }
};

/// NOTE: This struct is wrapped in an `Arc` in agave
pub const VoteAccount = struct {
    account: AccountSharedData,
    state: VoteState,

    pub fn deinit(self: *const VoteAccount, allocator: Allocator) void {
        allocator.free(self.account.data);
        self.state.deinit();
    }

    pub fn clone(self: VoteAccount, allocator: Allocator) Allocator.Error!VoteAccount {
        return .{
            .account = .{
                .lamports = self.account.lamports,
                .owner = self.account.owner,
                .data = try allocator.dupe(u8, self.account.data),
                .executable = self.account.executable,
                .rent_epoch = self.account.rent_epoch,
            },
            .state = try self.state.clone(),
        };
    }

    /// NOTE: Agave does some funky unsafe rust here. I've gone with the simple approach for now
    /// which should be okay...
    pub fn fromAccountSharedData(allocator: Allocator, account: AccountSharedData) !VoteAccount {
        if (!vote_program.ID.equals(&account.owner)) return error.InvalidOwner;

        const state = try bincode.readFromSlice(
            allocator,
            VoteStateVersions,
            account.data,
            .{},
        );

        return .{
            .account = try account.clone(allocator),
            .state = state.current,
        };
    }
};

pub const StakeAccount = struct {
    account: AccountSharedData,
    state: StakeStateV2,

    pub fn deinit(self: *const StakeAccount, allocator: Allocator) void {
        allocator.free(self.account.data);
    }

    // TODO: Consider ownership of the account data.
    pub fn fromAccountSharedData(account: AccountSharedData) !StakeAccount {
        if (!stake_program.ID.equals(&account.owner)) return error.InvalidOwner;

        // TODO: Do we need to use borsh?
        const state = try bincode.readFromSlice(
            failing_allocator,
            StakeStateV2,
            account.data,
            .{},
        );

        if (state.delegation() == null) return error.InvalidDelegation;

        return .{
            .account = account,
            .state = state,
        };
    }

    pub fn delegation(self: StakeAccount) Delegation {
        return self.state.delegation() orelse
            @panic("StakeAccount does not have a delegation");
    }
};

pub const StakeStateV2 = union(enum) {
    uninitialized,
    initialized: Meta,
    stake: struct { meta: Meta, stake: Stake, flags: StakeFlags },
    rewards_pool,

    pub const SIZE = 200;

    pub fn delegation(self: *const StakeStateV2) ?Delegation {
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
    voter_pubkey: Pubkey,
    stake: u64,
    activation_epoch: Epoch,
    deactivation_epoch: Epoch = std.math.maxInt(u64),
    /// deprecated
    _warmup_cooldown_rate: f64 = 0.25,

    pub fn isBootstrap(self: *const Delegation) bool {
        // TODO:
        _ = self;
        return false;
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

    pub fn getStakeAndActivating(
        self: *const Delegation,
        epoch: Epoch,
        history: *const StakeHistory,
        new_rate_activation_epoch: ?Epoch,
    ) struct { u64, u64 } {
        const delegated_stake = self.stake;

        if (self.isBootstrap()) {
            return .{ delegated_stake, 0 };
        } else if (self.activation_epoch == self.deactivation_epoch) {
            return .{ 0, 0 };
        } else if (epoch == self.activation_epoch) {
            return .{ 0, delegated_stake };
        } else if (epoch == self.activation_epoch) {
            return .{ delegated_stake, 0 };
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

                const remaining_activated_stake = delegated_stake - current_effective_stake;
                const weight = @as(f64, @floatFromInt(remaining_activated_stake)) / @as(f64, @floatFromInt(prev_cluster_stake.activating));
                const warmup_cooldown_rate = warmupCooldownRate(current_epoch, new_rate_activation_epoch);

                const newly_effective_cluster_stake = @as(f64, @floatFromInt(prev_cluster_stake.effective)) * warmup_cooldown_rate;
                const weighted_effective_state: u64 = @intFromFloat(weight * newly_effective_cluster_stake);
                const newly_effective_stake = @max(weighted_effective_state, 1);

                current_effective_stake += newly_effective_stake;
                if (current_effective_stake >= delegated_stake) {
                    current_effective_stake = delegated_stake;
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
                delegated_stake - current_effective_stake,
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
        const effective_stake, const activating_stake = self.getStakeAndActivating(
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

test "check and store account" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    var stakes_cache = try StakesCache.initEmpty(allocator, 0);
    defer stakes_cache.deinit(allocator);

    const pubkey = Pubkey.initRandom(prng.random());
    const account = AccountSharedData{
        .lamports = 1,
        .owner = vote_program.ID,
        .data = &[_]u8{},
        .executable = false,
        .rent_epoch = 0,
    };

    try stakes_cache.checkAndStore(allocator, pubkey, account, null);
}

const TestStakedNodeAccounts = struct {
    vote_pubkey: Pubkey,
    vote_account: AccountSharedData,
    stake_pubkey: Pubkey,
    stake_account: AccountSharedData,

    pub fn deinit(self: TestStakedNodeAccounts, allocator: Allocator) void {
        allocator.free(self.vote_account.data);
        allocator.free(self.stake_account.data);
    }
};

const Clock = sig.runtime.sysvar.Clock;

/// vote_state::createAccount
fn createVoteAccount(
    allocator: Allocator,
    node_pubkey: Pubkey,
    authorized_voter: Pubkey,
    authorized_withdrawer: Pubkey,
    commission: u8,
    lamports: u64,
) !AccountSharedData {
    const vote_account = AccountSharedData{
        .lamports = lamports,
        .owner = vote_program.ID,
        .data = try allocator.alloc(u8, VoteState.MAX_VOTE_STATE_SIZE),
        .executable = false,
        .rent_epoch = 0,
    };
    errdefer allocator.free(vote_account.data);

    const vote_state = try VoteState.init(
        allocator,
        node_pubkey,
        authorized_voter,
        authorized_withdrawer,
        commission,
        Clock.DEFAULT,
    );
    defer vote_state.deinit();

    _ = try bincode.writeToSlice(vote_account.data, VoteStateVersions{ .current = vote_state }, .{});

    return vote_account;
}

const Rent = sig.runtime.sysvar.Rent;

/// stake_state::createAccount
fn createStakeAccount(
    allocator: Allocator,
    authorized: Pubkey,
    voter_pubkey: Pubkey,
    vote_account: AccountSharedData,
    rent: Rent,
    lamports: u64,
    activation_epoch: Epoch,
) !AccountSharedData {
    const stake_account = AccountSharedData{
        .lamports = lamports,
        .owner = stake_program.ID,
        .data = try allocator.alloc(u8, StakeStateV2.SIZE),
        .executable = false,
        .rent_epoch = 0,
    };
    errdefer allocator.free(stake_account.data);

    const vote_state_versions = try bincode.readFromSlice(
        allocator,
        VoteStateVersions,
        vote_account.data,
        .{},
    );
    defer vote_state_versions.deinit();
    const vote_state = vote_state_versions.current;

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
                ._warmup_cooldown_rate = DEFAULT_WARMUP_COOLDOWN_RATE,
            },
            .credits_observed = vote_state.getCredits(),
        },
        .flags = .EMPTY,
    } };

    _ = try bincode.writeToSlice(stake_account.data, stake_state, .{});

    return stake_account;
}

fn createStakedNodeAccounts(allocator: Allocator, random: std.Random, stake: u64) !TestStakedNodeAccounts {
    const vote_pubkey, const vote_account = blk: {
        const vote_pubkey = Pubkey.initRandom(random);
        const vote_authority = Pubkey.initRandom(random);
        const vote_account = try createVoteAccount(
            allocator,
            vote_pubkey,
            vote_authority,
            vote_authority,
            0,
            1,
        );
        break :blk .{ vote_pubkey, vote_account };
    };
    errdefer allocator.free(vote_account.data);

    const stake_pubkey, const stake_account = blk: {
        const staked_vote_authority = Pubkey.initRandom(random);
        const staked_vote_account = try createVoteAccount(
            allocator,
            vote_pubkey,
            staked_vote_authority,
            staked_vote_authority,
            0,
            1,
        );
        defer allocator.free(staked_vote_account.data);

        const stake_pubkey = Pubkey.initRandom(random);
        const stake_account = try createStakeAccount(
            allocator,
            stake_pubkey,
            vote_pubkey,
            staked_vote_account,
            Rent.FREE,
            stake,
            std.math.maxInt(u64),
        );

        break :blk .{ stake_pubkey, stake_account };
    };

    return .{
        .vote_pubkey = vote_pubkey,
        .vote_account = vote_account,
        .stake_pubkey = stake_pubkey,
        .stake_account = stake_account,
    };
}

pub fn stakeFromAccount(account: AccountSharedData) !Stake {
    const state = try bincode.readFromSlice(
        failing_allocator,
        StakeStateV2,
        account.data,
        .{},
    );
    return state.stake.stake;
}

test "stakes basic" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    for (0..1) |i| {
        var stakes_cache = try StakesCache.initEmpty(allocator, i);
        defer stakes_cache.deinit(allocator);

        var accs = try createStakedNodeAccounts(allocator, prng.random(), 10);
        defer accs.deinit(allocator);

        try stakes_cache.checkAndStore(allocator, accs.vote_pubkey, accs.vote_account, null);
        try stakes_cache.checkAndStore(allocator, accs.stake_pubkey, accs.stake_account, null);
        const stake_1 = try stakeFromAccount(accs.stake_account);
        {
            const stakes: *Stakes, var stakes_guard = stakes_cache.stakes.writeWithLock();
            defer stakes_guard.unlock();
            try std.testing.expect(stakes.vote_accounts.getAccount(accs.vote_pubkey) != null);
            try std.testing.expectEqual(
                stake_1.delegation.getStake(i, &StakeHistory.EMPTY, null),
                stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey),
            );
        }

        accs.stake_account.lamports = 42;
        try stakes_cache.checkAndStore(allocator, accs.stake_pubkey, accs.stake_account, null);
        {
            const stakes: *Stakes, var stakes_guard = stakes_cache.stakes.writeWithLock();
            defer stakes_guard.unlock();
            try std.testing.expect(stakes.vote_accounts.getAccount(accs.vote_pubkey) != null);
            try std.testing.expectEqual(
                stake_1.delegation.getStake(i, &StakeHistory.EMPTY, null),
                stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey),
            );
        }

        const vote_account = try createVoteAccount(
            allocator,
            Pubkey.initRandom(prng.random()),
            accs.vote_pubkey,
            accs.vote_pubkey,
            0,
            1,
        );
        defer allocator.free(vote_account.data);
        var stake_account = try createStakeAccount(
            allocator,
            Pubkey.initRandom(prng.random()),
            accs.vote_pubkey,
            vote_account,
            Rent.FREE,
            42,
            std.math.maxInt(u64),
        );
        defer allocator.free(stake_account.data);

        try stakes_cache.checkAndStore(allocator, accs.stake_pubkey, stake_account, null);
        const stake_2 = try stakeFromAccount(stake_account);
        {
            const stakes: *Stakes, var stakes_guard = stakes_cache.stakes.writeWithLock();
            defer stakes_guard.unlock();
            try std.testing.expect(stakes.vote_accounts.getAccount(accs.vote_pubkey) != null);
            try std.testing.expectEqual(
                stake_2.delegation.getStake(i, &StakeHistory.EMPTY, null),
                stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey),
            );
        }

        stake_account.lamports = 0;
        try stakes_cache.checkAndStore(allocator, accs.stake_pubkey, stake_account, null);
        {
            const stakes: *Stakes, var stakes_guard = stakes_cache.stakes.writeWithLock();
            defer stakes_guard.unlock();
            try std.testing.expect(stakes.vote_accounts.getAccount(accs.vote_pubkey) != null);
            try std.testing.expectEqual(
                0,
                stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey),
            );
        }
    }
}
