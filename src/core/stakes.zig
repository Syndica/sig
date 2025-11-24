const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;

const bincode = sig.bincode;
const vote_program = sig.runtime.program.vote;
const stake_program = sig.runtime.program.stake;

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;

const AccountSharedData = sig.runtime.AccountSharedData;
const VersionedVoteState = sig.runtime.program.vote.state.VoteStateVersions;
const Rent = sig.runtime.sysvar.Rent;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const StakeStateV2 = sig.runtime.program.stake.StakeStateV2;
const StakeFlags = StakeStateV2.StakeFlags;
const Delegation = StakeStateV2.Delegation;
const Stake = StakeStateV2.Stake;
const Meta = StakeStateV2.Meta;
const VoteState = sig.runtime.program.vote.state.VoteState;
const VoteStateVersions = sig.runtime.program.vote.state.VoteStateVersions;

const RwMux = sig.sync.RwMux;

const deinitMapAndValues = sig.utils.collections.deinitMapAndValues;
const createTestVoteAccount = sig.runtime.program.vote.state.createTestVoteAccount;
const createTestVoteAccountWithAuthorized =
    sig.runtime.program.vote.state.createTestVoteAccountWithAuthorized;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

pub const StakesType = enum {
    delegation,
    stake,
    account,

    pub fn T(self: StakesType) type {
        return switch (self) {
            .delegation => Delegation,
            .stake => Stake,
            .account => StakeAccount,
        };
    }
};

pub fn StakesCacheGeneric(comptime stakes_type: StakesType) type {
    const T = Stakes(stakes_type);

    return struct {
        stakes: RwMux(T),

        const Self = @This();

        pub const EMPTY: Self = .{ .stakes = .init(.EMPTY) };

        pub fn deinit(self: *Self, allocator: Allocator) void {
            var stakes: *T, var stakes_guard = self.stakes.writeWithLock();
            defer stakes_guard.unlock();
            stakes.deinit(allocator);
        }

        /// Checks if the account is a vote or stake account, and updates the stakes accordingly.
        /// [agave] https://github.com/anza-xyz/agave/blob/4807a7a0e51148acd1b0dd0f3f52a12c40378ed3/runtime/src/stakes.rs#L67
        pub fn checkAndStore(
            self: *Self,
            allocator: Allocator,
            pubkey: Pubkey,
            account: AccountSharedData,
            new_rate_activation_epoch: ?Epoch,
        ) !void {
            if (account.lamports == 0) {
                if (vote_program.ID.equals(&account.owner)) {
                    var stakes, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    try stakes.removeVoteAccount(allocator, pubkey);
                } else if (stake_program.ID.equals(&account.owner)) {
                    var stakes: *T, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    try stakes.removeStakeAccount(allocator, pubkey, new_rate_activation_epoch);
                }
                return;
            }

            if (vote_program.ID.equals(&account.owner)) {
                if (!VersionedVoteState.isCorrectSizeAndInitialized(account.data)) {
                    var stakes: *T, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    try stakes.removeVoteAccount(allocator, pubkey);
                    return;
                }

                // does *not* take ownership of the account
                var vote_account = VoteAccount.fromAccountSharedData(allocator, account) catch {
                    var stakes: *T, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    try stakes.removeVoteAccount(allocator, pubkey);
                    return;
                };
                errdefer vote_account.deinit(allocator);

                var stakes: *T, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                try stakes.upsertVoteAccount(
                    allocator,
                    pubkey,
                    vote_account,
                    new_rate_activation_epoch,
                );
            } else if (stake_program.ID.equals(&account.owner)) {
                const stake_account = StakeAccount.init(
                    allocator,
                    try account.clone(allocator),
                ) catch {
                    var stakes: *T, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    try stakes.removeStakeAccount(allocator, pubkey, new_rate_activation_epoch);
                    return;
                };

                var stakes: *T, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                try stakes.upsertStakeAccount(
                    allocator,
                    pubkey,
                    stake_account,
                    new_rate_activation_epoch,
                );
            }
        }

        pub fn activateEpoch(
            self: *Self,
            allocator: Allocator,
            next_epoch: Epoch,
            new_rate_activation_epoch: ?Epoch,
        ) !void {
            var stakes, var stakes_lg = self.stakes.writeWithLock();
            defer stakes_lg.unlock();

            const stake_delegations = stakes.stake_accounts.values();
            var stake_history_entry = StakeHistory.StakeState.DEFAULT;
            for (stake_delegations) |stake_delegation| {
                const delegation = stake_delegation.getDelegation();
                stake_history_entry.add(delegation.getStakeState(
                    stakes.epoch,
                    &stakes.stake_history,
                    new_rate_activation_epoch,
                ));
            }

            try stakes.stake_history.insertEntry(stakes.epoch, stake_history_entry);
            stakes.epoch = next_epoch;

            try refreshVoteAccounts(
                allocator,
                next_epoch,
                stakes,
                new_rate_activation_epoch,
            );
        }

        fn refreshVoteAccounts(
            allocator: Allocator,
            epoch: Epoch,
            stakes: *Stakes(stakes_type),
            new_activation_rate_epoch: ?Epoch,
        ) !void {
            var new_vote_accounts = VoteAccounts{};
            errdefer new_vote_accounts.deinit(allocator);
            const keys = stakes.vote_accounts.vote_accounts.keys();
            const values = stakes.vote_accounts.vote_accounts.values();
            for (keys, values) |vote_pubkey, stake_and_vote_account| {
                try new_vote_accounts.vote_accounts.put(allocator, vote_pubkey, .{
                    .stake = 0,
                    .account = stake_and_vote_account.account.getAcquire(),
                });
            }

            for (stakes.stake_accounts.values()) |stake_delegation| {
                const delegation = stake_delegation.getDelegation();
                const vote_account = new_vote_accounts.vote_accounts.getPtr(
                    delegation.voter_pubkey,
                ).?;
                vote_account.stake += delegation.getEffectiveStake(
                    epoch,
                    &stakes.stake_history,
                    new_activation_rate_epoch,
                );
            }

            new_vote_accounts.staked_nodes = try VoteAccounts.computeStakedNodes(
                allocator,
                &new_vote_accounts.vote_accounts,
            );

            stakes.vote_accounts.deinit(allocator);
            stakes.vote_accounts = new_vote_accounts;
        }
    };
}

pub fn Stakes(comptime stakes_type: StakesType) type {
    const T = stakes_type.T();
    const StakeAccounts = std.AutoArrayHashMapUnmanaged(Pubkey, T);

    return struct {
        vote_accounts: VoteAccounts,
        stake_accounts: StakeAccounts,
        unused: u64,
        epoch: Epoch,
        stake_history: StakeHistory,

        const Self = @This();

        pub const EMPTY: Self = .{
            .vote_accounts = .{},
            .stake_accounts = .empty,
            .unused = 0,
            .epoch = 0,
            .stake_history = .INIT,
        };

        pub fn deinit(self: *const Self, allocator: Allocator) void {
            self.vote_accounts.deinit(allocator);
            // Only the .account type contains allocated data in the stake_delegations.
            if (stakes_type == .account) {
                for (self.stake_accounts.values()) |*v| v.deinit(allocator);
            }
            var delegations = self.stake_accounts;
            delegations.deinit(allocator);
        }

        pub fn clone(self: *const Self, allocator: Allocator) Allocator.Error!Self {
            return self.convert(allocator, stakes_type);
        }

        pub fn convert(
            self: *const Self,
            allocator: Allocator,
            comptime output_type: StakesType,
        ) Allocator.Error!Stakes(output_type) {
            const vote_accounts = try self.vote_accounts.clone(allocator);
            errdefer vote_accounts.deinit(allocator);

            var stake_delegations: std.AutoArrayHashMapUnmanaged(Pubkey, output_type.T()) = .empty;
            try stake_delegations.ensureTotalCapacity(allocator, self.stake_accounts.count());
            errdefer {
                // Only the .account type contains allocated data in the stake_delegations.
                if (output_type == .account) {
                    for (stake_delegations.values()) |*v| v.deinit(allocator);
                }
                stake_delegations.deinit(allocator);
            }
            for (self.stake_accounts.keys(), self.stake_accounts.values()) |key, value| {
                const new_value: output_type.T() = switch (stakes_type) {
                    .account => try value.clone(allocator),
                    .delegation => value,
                    .stake => switch (output_type) {
                        .stake => value,
                        .delegation => value.delegation,
                        else => unreachable,
                    },
                };

                stake_delegations.putAssumeCapacity(key, new_value);
            }

            return .{
                .vote_accounts = vote_accounts,
                .stake_accounts = stake_delegations,
                .unused = self.unused,
                .epoch = self.epoch,
                .stake_history = self.stake_history,
            };
        }

        pub fn calculateStake(
            self: *const Self,
            pubkey: Pubkey,
            new_rate_activation_epoch: ?Epoch,
        ) u64 {
            var stake: u64 = 0;
            for (self.stake_accounts.values()) |*stake_delegations| {
                const delegation = stake_delegations.getDelegation();
                if (!delegation.voter_pubkey.equals(&pubkey)) continue;
                stake += delegation.getEffectiveStake(
                    self.epoch,
                    &self.stake_history,
                    new_rate_activation_epoch,
                );
            }
            return stake;
        }

        /// Takes ownership of `account`.
        pub fn upsertVoteAccount(
            self: *Self,
            allocator: Allocator,
            pubkey: Pubkey,
            account: VoteAccount,
            new_rate_activation_epoch: ?Epoch,
        ) !void {
            std.debug.assert(account.account.lamports > 0);
            var maybe_old_account = try self.vote_accounts.insert(
                allocator,
                pubkey,
                account,
                .init(stakes_type, self, new_rate_activation_epoch),
            );
            if (maybe_old_account) |*old_account| old_account.deinit(allocator);
        }

        pub fn removeVoteAccount(self: *Self, allocator: Allocator, pubkey: Pubkey) !void {
            try self.vote_accounts.remove(allocator, pubkey);
        }

        /// Takes ownership of `account` iff `stakes_type` is `account`.
        pub fn upsertStakeAccount(
            self: *Self,
            allocator: Allocator,
            pubkey: Pubkey,
            account: StakeAccount,
            new_rate_activation_epoch: ?Epoch,
        ) !void {
            std.debug.assert(account.account.lamports > 0);
            defer if (stakes_type != .account) account.deinit(allocator);
            errdefer if (stakes_type == .account) account.deinit(allocator);

            const delegation = account.getDelegation();
            const voter_pubkey = delegation.voter_pubkey;
            const stake = delegation.getEffectiveStake(
                self.epoch,
                &self.stake_history,
                new_rate_activation_epoch,
            );

            const entry = switch (stakes_type) {
                .delegation => account.getDelegation(),
                .stake => account.getStake(),
                .account => account,
            };

            if (try self.stake_accounts.fetchPut(
                allocator,
                pubkey,
                entry,
            )) |old_account_entry| {
                const old_account: T = old_account_entry.value;
                defer if (stakes_type == .account) old_account.deinit(allocator);

                const old_delegation = old_account.getDelegation();
                const old_voter_pubkey = old_delegation.voter_pubkey;
                const old_stake = old_delegation.getEffectiveStake(
                    self.epoch,
                    &self.stake_history,
                    new_rate_activation_epoch,
                );

                if (!voter_pubkey.equals(&old_voter_pubkey) or stake != old_stake) {
                    try self.vote_accounts.subStake(old_voter_pubkey, old_stake);
                    try self.vote_accounts.addStake(allocator, voter_pubkey, stake);
                }
            } else {
                try self.vote_accounts.addStake(allocator, voter_pubkey, stake);
            }
        }

        pub fn removeStakeAccount(
            self: *Self,
            allocator: Allocator,
            pubkey: Pubkey,
            new_rate_activation_epoch: ?Epoch,
        ) !void {
            var account: T = (self.stake_accounts.fetchSwapRemove(pubkey) orelse return).value;
            defer if (stakes_type == .account) account.deinit(allocator);

            const removed_delegation = account.getDelegation();
            const removed_stake = removed_delegation.getEffectiveStake(
                self.epoch,
                &self.stake_history,
                new_rate_activation_epoch,
            );

            try self.vote_accounts.subStake(removed_delegation.voter_pubkey, removed_stake);
        }

        pub fn initRandom(
            allocator: Allocator,
            random: std.Random,
            max_list_entries: usize,
        ) Allocator.Error!Self {
            const vote_accounts = try VoteAccounts.initRandom(allocator, random, max_list_entries);
            errdefer vote_accounts.deinit(allocator);

            var stake_delegations = std.AutoArrayHashMapUnmanaged(Pubkey, T).empty;
            errdefer {
                if (stakes_type == .account) {
                    for (stake_delegations.values()) |*v| v.deinit(allocator);
                }
                stake_delegations.deinit(allocator);
            }

            for (0..random.uintAtMost(usize, max_list_entries)) |_| {
                try stake_delegations.put(
                    allocator,
                    Pubkey.initRandom(random),
                    if (stakes_type == .account)
                        T.initRandom(allocator, random)
                    else
                        T.initRandom(random),
                );
            }

            const stake_history = StakeHistory.initRandom(random);
            errdefer stake_history.deinit(allocator);

            return .{
                .vote_accounts = vote_accounts,
                .stake_accounts = stake_delegations,
                .unused = random.int(u64),
                .epoch = random.int(Epoch),
                .stake_history = stake_history,
            };
        }
    };
}

pub const StakeAndVoteAccount = struct {
    stake: u64,
    account: VoteAccount,

    pub fn init(stake: u64, account: VoteAccount) StakeAndVoteAccount {
        return .{ .stake = stake, .account = account };
    }

    pub fn deinit(self: *StakeAndVoteAccount, allocator: Allocator) void {
        self.account.deinit(allocator);
    }
};

pub const StakeAndVoteAccountsMap = sig.utils.collections.PubkeyMap(StakeAndVoteAccount);
pub const StakedNodesMap = sig.utils.collections.PubkeyMap(u64);

/// Deserialization in Agave allows invalid vote accounts to exist for snapshot
/// compatibility. It is noted that this should change to a hard error in the
/// future. We take the hard error on deserialisation approach and can write a
/// custom deserializer if we come across a need to deserialize invalid vote
/// accounts.
///
/// Analogous to [VoteAccounts](https://github.com/anza-xyz/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/vote/src/vote_account.rs#L45-L46)
pub const VoteAccounts = struct {
    /// Maps pubkeys to vote account and delegated stake.
    vote_accounts: StakeAndVoteAccountsMap = .{},
    /// Maps vote account node pubkeys to their total delegated stake.
    /// NOTE: Should we make this nullable and emulate Agave's beahviour? I think it is fine
    /// to just compute the staked nodes on deserialisation but am open to changing this approach.
    staked_nodes: StakedNodesMap = .{},

    pub const @"!bincode-config" = bincode.FieldConfig(VoteAccounts){ .deserializer = deserialize };
    pub const @"!bincode-config:staked_nodes" = bincode.FieldConfig(StakedNodesMap){ .skip = true };

    pub fn clone(
        self: *const VoteAccounts,
        allocator: std.mem.Allocator,
    ) Allocator.Error!VoteAccounts {
        const zone = tracy.Zone.init(@src(), .{ .name = "VoteAccounts.clone" });
        defer zone.deinit();

        var staked_nodes = try self.staked_nodes.clone(allocator);
        errdefer staked_nodes.deinit(allocator);

        var vote_accounts: StakeAndVoteAccountsMap = .{};
        errdefer vote_accounts.deinit(allocator);

        const accounts = self.vote_accounts.values();
        for (self.vote_accounts.keys(), accounts, 0..) |key, value, i| {
            // guaranteed to always have at least one reference remaining after the `release
            // since we release all ones up to the last one acquired. this means the caller
            // retains ownership of the vote accounts and we don't need to de-init anywhere.
            errdefer for (accounts[0 .. i + 1]) |a| std.debug.assert(!a.account.rc.release());
            value.account.acquire();
            try vote_accounts.put(allocator, key, value);
        }

        return .{
            .staked_nodes = staked_nodes,
            .vote_accounts = vote_accounts,
        };
    }

    pub fn deinit(self: *const VoteAccounts, allocator: Allocator) void {
        deinitMapAndValues(allocator, self.vote_accounts);
        var staked_nodes = self.staked_nodes;
        staked_nodes.deinit(allocator);
    }

    pub fn getAccount(self: *const VoteAccounts, pubkey: Pubkey) ?VoteAccount {
        const entry = self.vote_accounts.getPtr(pubkey) orelse return null;
        return entry.account;
    }

    pub fn getDelegatedStake(self: *const VoteAccounts, pubkey: Pubkey) u64 {
        const entry = self.vote_accounts.getPtr(pubkey) orelse return 0;
        return entry.stake;
    }

    /// Inserts a new vote account into the `vote_accounts` map, or updates an existing one.
    /// If the vote account is new, it will calculate the stake and add it to the `staked_nodes` map
    /// If the vote account already exists, and the node pubkey has changed, it will move the stake
    /// from the old node to the new node in the `staked_nodes` map.
    ///
    /// Takes ownership of `account` and returns the previous value if it existed.
    pub fn insert(
        self: *VoteAccounts,
        allocator: Allocator,
        pubkey: Pubkey,
        account: VoteAccount,
        calculated_stake_context: CalculateStakeContext,
    ) !?StakeAndVoteAccount {
        const entry = try self.vote_accounts.getOrPut(allocator, pubkey);

        const new_node_pubkey = account.getNodePubkey();
        if (entry.found_existing) {
            const old_stake = entry.value_ptr.stake;
            const old_node_pubkey = entry.value_ptr.account.getNodePubkey();

            if (!new_node_pubkey.equals(&old_node_pubkey)) {
                try self.subNodeStake(old_node_pubkey, old_stake);
                try self.addNodeStake(allocator, new_node_pubkey, old_stake);
            }

            const old_entry_value = entry.value_ptr.*;
            entry.value_ptr.account = account;
            return old_entry_value;
        } else {
            const calculated_stake = calculated_stake_context.calculateStake(pubkey);
            entry.value_ptr.* = .{ .stake = calculated_stake, .account = account };
            try self.addNodeStake(allocator, new_node_pubkey, calculated_stake);
            return null;
        }
    }

    /// Removes the vote account identified by `pubkey` from the `vote_accounts` map, and updates
    /// the `staked_nodes` map by subtracting the stake of the removed vote account.
    pub fn remove(self: *VoteAccounts, allocator: std.mem.Allocator, pubkey: Pubkey) !void {
        var entry: StakeAndVoteAccount = self.vote_accounts.get(pubkey) orelse return;
        defer entry.deinit(allocator);
        _ = self.vote_accounts.swapRemove(pubkey);
        try self.subNodeStake(entry.account.getNodePubkey(), entry.stake);
    }

    /// Adds `delta` to the stake of the vote account identified by `pubkey`, and updates the
    /// `staked_nodes` map. If the vote account does not exist, it will do nothing.
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

    /// Subtracts `delta` from the stake of the vote account identified by
    /// `pubkey`, and updates the `staked_nodes` map. Panics if `delta` is
    /// greater than the current stake.
    pub fn subStake(self: *VoteAccounts, pubkey: Pubkey, delta: u64) !void {
        const entry = self.vote_accounts.getPtr(pubkey) orelse return;
        if (entry.stake < delta) return error.SubStakeOverflow;
        entry.stake -= delta;
        try self.subNodeStake(entry.account.state.node_pubkey, delta);
    }

    /// Adds `stake` to an entry in `staked_nodes`. If the entry does not exist,
    /// one will be created.
    fn addNodeStake(
        self: *VoteAccounts,
        allocator: Allocator,
        pubkey: Pubkey,
        stake: u64,
    ) Allocator.Error!void {
        if (stake == 0) return;

        const entry = try self.staked_nodes.getOrPut(allocator, pubkey);

        if (entry.found_existing)
            entry.value_ptr.* += stake
        else
            entry.value_ptr.* = stake;
    }

    /// Subtracts `stake` from an entry in `staked_nodes`. If the entry does not
    /// exist, it will panic.
    fn subNodeStake(self: *VoteAccounts, pubkey: Pubkey, stake: u64) !void {
        if (stake == 0) return;

        const current_stake = self.staked_nodes.getPtr(pubkey) orelse
            return error.NodeNotFound;

        switch (std.math.order(current_stake.*, stake)) {
            .lt => return error.SubStakeOverflow,
            .eq => _ = self.staked_nodes.swapRemove(pubkey),
            .gt => current_stake.* -= stake,
        }
    }

    pub fn computeStakedNodes(
        allocator: Allocator,
        accounts: *const StakeAndVoteAccountsMap,
    ) Allocator.Error!StakedNodesMap {
        var staked_nodes = StakedNodesMap{};
        errdefer staked_nodes.deinit(allocator);

        for (accounts.keys(), accounts.values()) |_, value| {
            if (value.stake > 0) {
                const entry = try staked_nodes.getOrPut(allocator, value.account.getNodePubkey());
                if (entry.found_existing)
                    entry.value_ptr.* += value.stake
                else
                    entry.value_ptr.* = value.stake;
            }
        }

        return staked_nodes;
    }

    /// Analogous to [deserialize_accounts_hash_map](https://github.com/anza-xyz/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/vote/src/vote_account.rs#L431-L438)
    fn deserialize(
        limit_allocator: *bincode.LimitAllocator,
        reader: anytype,
        _: bincode.Params,
    ) !VoteAccounts {
        const allocator = limit_allocator.backing_allocator;

        var vote_accounts = try bincode.readWithLimit(
            limit_allocator,
            StakeAndVoteAccountsMap,
            reader,
            .{},
        );
        errdefer {
            for (vote_accounts.values()) |*v| v.deinit(allocator);
            vote_accounts.deinit(allocator);
        }

        return .{
            .vote_accounts = vote_accounts,
            .staked_nodes = try computeStakedNodes(
                allocator,
                &vote_accounts,
            ),
        };
    }

    pub fn initRandom(
        allocator: Allocator,
        random: std.Random,
        max_list_entries: usize,
    ) Allocator.Error!VoteAccounts {
        if (!builtin.is_test) @compileError("only for testing");

        var self: VoteAccounts = .{};
        errdefer self.deinit(allocator);

        for (0..random.intRangeAtMost(u64, 1, max_list_entries)) |_| {
            var vote_account = try VoteAccount.initRandom(
                allocator,
                random,
                Pubkey.initRandom(random),
            );
            errdefer vote_account.deinit(allocator);
            try self.vote_accounts.put(
                allocator,
                Pubkey.initRandom(random),
                .{
                    .stake = random.int(u64),
                    .account = vote_account,
                },
            );
        }

        self.staked_nodes = try computeStakedNodes(
            allocator,
            &self.vote_accounts,
        );

        return self;
    }
};

pub const StakeAccount = struct {
    account: AccountSharedData,
    // When initializing the `StakeAccount` we require that the `StakeStateV2` contained in the
    // account data is the `stake` variant which contains `meta: Meta, stake: Stake, flags: StakeFlags`.
    // For now, only the `Stake` field of the `stake variant is used, if in future we require the `Meta` or `Flags`
    // we can simply add them in the initialisation method.
    stake: Stake,

    /// Takes ownership of `account`.
    pub fn init(allocator: Allocator, account: AccountSharedData) !StakeAccount {
        errdefer account.deinit(allocator);

        if (!stake_program.ID.equals(&account.owner)) return error.InvalidOwner;

        const state = try bincode.readFromSlice(
            failing_allocator,
            StakeStateV2,
            account.data,
            .{},
        );

        const stake = state.getStake() orelse return error.InvalidData;

        return .{
            .account = account,
            .stake = stake,
        };
    }

    pub fn deinit(self: *const StakeAccount, allocator: Allocator) void {
        self.account.deinit(allocator);
    }

    pub fn clone(self: *const StakeAccount, allocator: Allocator) Allocator.Error!StakeAccount {
        return .{
            .account = try self.account.clone(allocator),
            .stake = self.stake,
        };
    }

    pub fn getDelegation(self: StakeAccount) Delegation {
        return self.stake.delegation;
    }

    pub fn getStake(self: StakeAccount) Stake {
        return self.stake;
    }
};

pub const VoteAccount = struct {
    account: MinimalAccount,
    state: VoteState,
    rc: *sig.sync.ReferenceCounter,

    /// Represents the minimal amount of information needed from the account data.
    pub const MinimalAccount = struct {
        lamports: u64,
        owner: Pubkey,
    };

    pub const @"!bincode-config" = bincode.FieldConfig(VoteAccount){
        .serializer = serialize,
        .deserializer = deserialize,
    };
    pub const @"!bincode-config:state" = bincode.FieldConfig(VoteState){ .skip = true };

    pub fn init(
        allocator: Allocator,
        account: MinimalAccount,
        state: VoteState,
    ) Allocator.Error!VoteAccount {
        const rc = try allocator.create(sig.sync.ReferenceCounter);
        errdefer allocator.destroy(rc);
        rc.* = .init;

        return .{
            .account = .{ .lamports = account.lamports, .owner = account.owner },
            .state = state,
            .rc = rc,
        };
    }

    pub fn deinit(self: *VoteAccount, allocator: Allocator) void {
        if (self.rc.release()) {
            self.state.deinit(allocator);
            allocator.destroy(self.rc);
        }
    }

    pub fn acquire(self: *const VoteAccount) void {
        std.debug.assert(self.rc.acquire());
    }

    pub fn getAcquire(self: *const VoteAccount) VoteAccount {
        self.acquire();
        return self.*;
    }

    pub fn getLamports(self: *const VoteAccount) u64 {
        return self.account.lamports;
    }

    pub fn getNodePubkey(self: *const VoteAccount) Pubkey {
        return self.state.node_pubkey;
    }

    /// Does not take ownership of `account`.
    pub fn fromAccountSharedData(
        allocator: std.mem.Allocator,
        account: AccountSharedData,
    ) !VoteAccount {
        if (!vote_program.ID.equals(&account.owner)) return error.InvalidOwner;

        var versioned_vote_state = try bincode.readFromSlice(
            allocator,
            VoteStateVersions,
            account.data,
            .{},
        );
        defer versioned_vote_state.deinit(allocator); // `convertToCurrent` clones

        var vote_state = try versioned_vote_state.convertToCurrent(allocator);
        errdefer vote_state.deinit(allocator);

        return .init(
            allocator,
            .{ .lamports = account.lamports, .owner = account.owner },
            vote_state,
        );
    }

    pub fn toAccountSharedData(
        self: *const VoteAccount,
        allocator: std.mem.Allocator,
    ) !AccountSharedData {
        if (!builtin.is_test) @compileError("only for tests");
        const versioned_state = VoteStateVersions{ .current = self.state };
        const data = try sig.bincode.writeAlloc(allocator, versioned_state, .{});
        return .{
            .lamports = self.account.lamports,
            .owner = self.account.owner,
            .data = data,
            .executable = false,
            .rent_epoch = std.math.maxInt(u64),
        };
    }

    fn serialize(writer: anytype, data: anytype, _: bincode.Params) anyerror!void {
        _ = writer;
        _ = data;
        @compileError("can't serialize VoteAccount with current representation");
    }

    /// Deserialize the `AccountSharedData`, and attempt to deserialize `VoteState` from the account data.
    fn deserialize(
        limit_allocator: *bincode.LimitAllocator,
        reader: anytype,
        _: bincode.Params,
    ) !VoteAccount {
        const allocator = limit_allocator.allocator();
        const deserialized = try bincode.readWithLimit(
            limit_allocator,
            AccountSharedData,
            reader,
            .{},
        );
        defer deserialized.deinit(allocator);

        return fromAccountSharedData(
            limit_allocator.backing_allocator,
            deserialized,
        );
    }

    pub fn equals(self: *const VoteAccount, other: *const VoteAccount) bool {
        return self.account.lamports == other.account.lamports and
            self.account.owner.equals(&other.account.owner) and
            self.state.equals(&other.state);
    }

    pub fn initRandom(
        allocator: Allocator,
        random: std.Random,
        node_pubkey: ?Pubkey,
    ) Allocator.Error!VoteAccount {
        if (!builtin.is_test) @compileError("only for tests");

        const account = try createTestVoteAccountWithAuthorized(
            allocator,
            node_pubkey orelse .initRandom(random),
            .initRandom(random),
            .initRandom(random),
            random.int(u8),
            random.intRangeAtMost(u64, 1, 1_000_000),
            random.int(Epoch),
        );
        defer account.deinit(allocator);

        return VoteAccount.fromAccountSharedData(allocator, account) catch |err| {
            switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                // We just created a 'valid' vote account, so the only possible
                // error is `OutOfMemory`.
                else => unreachable,
            }
        };
    }
};

pub const CalculateStakeContext = struct {
    stakes: union(enum) {
        delegation: *const Stakes(.delegation),
        stake: *const Stakes(.stake),
        account: *const Stakes(.account),
    },
    new_rate_activation_epoch: ?Epoch,

    pub fn init(
        comptime stakes_type: StakesType,
        stakes: *const Stakes(stakes_type),
        new_rate_activation_epoch: ?Epoch,
    ) CalculateStakeContext {
        return .{
            .stakes = switch (stakes_type) {
                .delegation => .{ .delegation = stakes },
                .stake => .{ .stake = stakes },
                .account => .{ .account = stakes },
            },
            .new_rate_activation_epoch = new_rate_activation_epoch,
        };
    }

    pub fn calculateStake(self: *const CalculateStakeContext, pubkey: Pubkey) u64 {
        return switch (self.stakes) {
            .delegation => |stakes| stakes.calculateStake(pubkey, self.new_rate_activation_epoch),
            .stake => |stakes| stakes.calculateStake(pubkey, self.new_rate_activation_epoch),
            .account => |stakes| stakes.calculateStake(pubkey, self.new_rate_activation_epoch),
        };
    }
};

fn createStakeAccount(
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

    var versioned_vote_state = try bincode.readFromSlice(
        allocator,
        VersionedVoteState,
        vote_account.data,
        .{},
    );
    defer versioned_vote_state.deinit(allocator);

    var vote_state = try versioned_vote_state.convertToCurrent(allocator);
    defer vote_state.deinit(allocator);

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
            },
            .credits_observed = vote_state.getCredits(),
        },
        .flags = .EMPTY,
    } };

    _ = try bincode.writeToSlice(stake_account.data, stake_state, .{});

    return stake_account;
}

pub const RandomStakesOptions = struct {
    epoch: Epoch = 0,
    max_nodes: usize = 1,
    num_voters: usize = 1,
    num_delegations: usize = 1,
    commission_min: u8 = 0,
    commission_max: u8 = 100,
    new_rate_activation_epoch: ?Epoch = null,
    delegation_min: u64 = 100_000_000, // 0.1 SOL
    delegation_max: u64 = 10_000_000_000, // 10 SOL
    // Default to bootstrapped activations so all delegations are active.
    activation_epoch_min: Epoch = std.math.maxInt(Epoch),
    activation_epoch_max: Epoch = std.math.maxInt(Epoch),
    effective_epochs_min: Epoch = std.math.maxInt(Epoch),
    effective_epochs_max: Epoch = std.math.maxInt(Epoch),
};

pub fn randomEpochStakes(
    allocator: Allocator,
    random: std.Random,
    options: RandomStakesOptions,
) !sig.core.EpochStakes {
    if (!builtin.is_test) @compileError("only for tests");

    var stakes = try randomStakes(allocator, random, options);
    defer stakes.deinit(allocator);

    var stakes_cache = StakesCacheGeneric(.stake){
        .stakes = RwMux(Stakes(.stake)).init(stakes),
    };

    return sig.replay.epoch_transitions.getEpochStakes(
        allocator,
        options.epoch + 1,
        &stakes_cache,
    );
}

// Initialize random `valid` EpochStakes for testing
pub fn randomStakes(
    allocator: Allocator,
    random: std.Random,
    options: RandomStakesOptions,
) !Stakes(.stake) {
    if (!builtin.is_test) @compileError("only for tests");

    var self = Stakes(.stake){
        .vote_accounts = .{},
        .stake_accounts = .empty,
        .unused = 0,
        .epoch = options.epoch,
        .stake_history = .INIT,
    };

    for (0..options.epoch) |e| {
        try self.stake_history.insertEntry(e, .{
            .effective = 1_000_000_000 * 1_000_000, // 1 million SOL
            .activating = 250_000_000 * 1_000_000, // 250k SOL
            .deactivating = 250_000_000 * 1_000_000, // 250k SOL
        });
    }

    const nodes = try allocator.alloc(Pubkey, options.max_nodes);
    defer allocator.free(nodes);
    for (nodes) |*node| node.* = Pubkey.initRandom(random);

    const voters = try allocator.alloc(Pubkey, options.num_voters);
    defer allocator.free(voters);
    for (voters) |*voter| voter.* = Pubkey.initRandom(random);

    for (0..options.num_voters) |i| {
        var vote_state = try VoteState.init(
            allocator,
            nodes[random.uintLessThan(usize, options.max_nodes)],
            Pubkey.initRandom(random),
            Pubkey.initRandom(random),
            random.intRangeAtMost(
                u8,
                options.commission_min,
                options.commission_max,
            ),
            options.epoch + 1,
        );
        errdefer vote_state.deinit(allocator);
        var vote_account = try VoteAccount.init(allocator, .{
            .lamports = 1_000_000_000,
            .owner = vote_program.ID,
        }, vote_state);
        errdefer vote_account.deinit(allocator);
        try self.upsertVoteAccount(
            allocator,
            voters[i],
            vote_account,
            options.new_rate_activation_epoch,
        );
    }

    for (0..options.num_delegations) |_| {
        const activation_epoch = random.intRangeAtMost(
            Epoch,
            options.activation_epoch_min,
            options.activation_epoch_max,
        );
        const deactivation_epoch = activation_epoch +|
            random.intRangeAtMost(
                Epoch,
                options.effective_epochs_min,
                options.effective_epochs_max,
            );
        const staker_delegation = Stake{
            .delegation = .{
                .voter_pubkey = voters[random.uintLessThan(usize, options.num_voters)],
                .stake = random.intRangeAtMost(
                    u64,
                    options.delegation_min,
                    options.delegation_max,
                ),
                .activation_epoch = activation_epoch,
                .deactivation_epoch = deactivation_epoch,
                .deprecated_warmup_cooldown_rate = 0,
            },
            .credits_observed = 0,
        };
        const stake_account = StakeAccount{
            .account = .{
                .lamports = 1,
                .data = &.{},
                .owner = stake_program.ID,
                .executable = false,
                .rent_epoch = 0,
            },
            .stake = staker_delegation,
        };
        try self.upsertStakeAccount(
            allocator,
            Pubkey.initRandom(random),
            stake_account,
            options.new_rate_activation_epoch,
        );
    }

    return self;
}

test "randomEpochStakes produces valid leader schedule" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const epoch = 10;
    var epoch_stakes = try randomEpochStakes(
        allocator,
        random,
        .{ .epoch = epoch },
    );
    defer epoch_stakes.deinit(allocator);

    const leaders = try sig.core.magic_leader_schedule.LeaderSchedule.init(
        allocator,
        epoch_stakes.stakes.epoch,
        epoch_stakes.stakes.vote_accounts,
        &.INIT,
        &.ALL_DISABLED,
    );
    defer leaders.deinit(allocator);
}

test "randomStakes creates valid stakes" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var stakes = try randomStakes(allocator, random, .{
        .epoch = 10,
        .max_nodes = 10,
        .num_voters = 20,
        .num_delegations = 100,
        .activation_epoch_min = 0,
        .activation_epoch_max = 10,
    });
    defer stakes.deinit(allocator);

    try std.testing.expectEqual(10, stakes.epoch);
    try std.testing.expect(10 >= stakes.vote_accounts.staked_nodes.count());
    try std.testing.expectEqual(20, stakes.vote_accounts.vote_accounts.count());
    try std.testing.expectEqual(100, stakes.stake_accounts.count());
}

const VoteAccountsArray = std.ArrayListUnmanaged(struct { Pubkey, StakeAndVoteAccount });

pub fn createRandomVoteAccounts(
    allocator: Allocator,
    random: std.Random,
    num_nodes: u64,
    num_entries: u64,
) !VoteAccountsArray {
    if (!builtin.is_test) @compileError("only for testing");

    const node_pukeys = try allocator.alloc(Pubkey, num_nodes);
    defer allocator.free(node_pukeys);
    for (node_pukeys) |*pubkey| pubkey.* = Pubkey.initRandom(random);

    var vote_accounts = try VoteAccountsArray.initCapacity(allocator, num_entries);
    errdefer vote_accounts.deinit(allocator);

    for (0..num_entries) |_| {
        const node_pubkey = node_pukeys[random.intRangeLessThan(u64, 0, num_nodes)];
        const account = try VoteAccount.initRandom(allocator, random, node_pubkey);
        const stake = random.intRangeAtMost(u64, 0, 1_000_000);
        vote_accounts.appendAssumeCapacity(.{ Pubkey.initRandom(random), .{
            .stake = stake,
            .account = account,
        } });
    }

    return vote_accounts;
}

pub fn calculateStakedNodes(
    allocator: Allocator,
    accounts: []struct { Pubkey, StakeAndVoteAccount },
) Allocator.Error!StakedNodesMap {
    if (!builtin.is_test) @compileError("only for testing");

    var staked_nodes = StakedNodesMap{};
    errdefer staked_nodes.deinit(allocator);

    for (accounts) |item| {
        const stake = item[1].stake;
        const account = item[1].account;
        if (stake == 0) continue;
        const entry = try staked_nodes.getOrPut(allocator, account.getNodePubkey());
        if (entry.found_existing)
            entry.value_ptr.* += stake
        else
            entry.value_ptr.* = stake;
    }

    return staked_nodes;
}

fn getStakeFromStakeAccount(account: AccountSharedData) !Stake {
    if (!builtin.is_test) @compileError("only for testing");

    const state_state = try bincode.readFromSlice(
        failing_allocator,
        StakeStateV2,
        account.data,
        .{},
    );

    return state_state.getStake().?;
}

pub const TestStakedNodeAccounts = struct {
    vote_pubkey: Pubkey,
    vote_account: AccountSharedData,
    stake_pubkey: Pubkey,
    stake_account: AccountSharedData,

    pub fn init(allocator: Allocator, random: std.Random, stake: u64) !TestStakedNodeAccounts {
        if (!builtin.is_test) @compileError("only for testing");

        const vote_pubkey, const vote_account = blk: {
            const vote_pubkey = Pubkey.initRandom(random);
            const vote_authority = Pubkey.initRandom(random);
            const vote_account = try createTestVoteAccount(
                allocator,
                vote_pubkey,
                vote_authority,
                0,
                1,
                0,
            );
            break :blk .{ vote_pubkey, vote_account };
        };
        errdefer allocator.free(vote_account.data);

        const stake_pubkey, const stake_account = blk: {
            const staked_vote_authority = Pubkey.initRandom(random);
            const staked_vote_account = try createTestVoteAccount(
                allocator,
                vote_pubkey,
                staked_vote_authority,
                0,
                1,
                0,
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

    pub fn stakeAccount(self: *const TestStakedNodeAccounts) !StakeAccount {
        return .{
            .account = self.stake_account,
            .stake = try getStakeFromStakeAccount(self.stake_account),
        };
    }

    pub fn voteAccount(self: *const TestStakedNodeAccounts, allocator: Allocator) !VoteAccount {
        return try VoteAccount.fromAccountSharedData(
            allocator,
            self.vote_account,
        );
    }

    pub fn deinit(self: TestStakedNodeAccounts, allocator: Allocator) void {
        self.vote_account.deinit(allocator);
        self.stake_account.deinit(allocator);
    }
};

test "stakes basic" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    inline for (.{
        StakesType.delegation,
        StakesType.stake,
        StakesType.account,
    }) |stakes_type| {
        for (0..4) |i| {
            const StakesT = Stakes(stakes_type);

            const stake_history_empty: StakeHistory = .INIT;

            var stakes_cache: StakesCacheGeneric(stakes_type) = .EMPTY;
            defer stakes_cache.deinit(allocator);
            {
                const stakes: *StakesT, var guard = stakes_cache.stakes.writeWithLock();
                defer guard.unlock();
                stakes.epoch = i;
            }

            var accs = try TestStakedNodeAccounts.init(allocator, prng.random(), 10);
            defer accs.deinit(allocator);

            try stakes_cache.checkAndStore(allocator, accs.vote_pubkey, accs.vote_account, null);
            try stakes_cache.checkAndStore(allocator, accs.stake_pubkey, accs.stake_account, null);
            var stake = try getStakeFromStakeAccount(accs.stake_account);
            {
                const stakes: *StakesT, var stakes_guard = stakes_cache.stakes.writeWithLock();
                defer stakes_guard.unlock();
                try std.testing.expect(stakes.vote_accounts.getAccount(accs.vote_pubkey) != null);
                try std.testing.expectEqual(
                    stake.delegation.getEffectiveStake(i, &stake_history_empty, null),
                    stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey),
                );
            }

            accs.stake_account.lamports = 42;
            try stakes_cache.checkAndStore(allocator, accs.stake_pubkey, accs.stake_account, null);
            {
                const stakes: *StakesT, var stakes_guard = stakes_cache.stakes.writeWithLock();
                defer stakes_guard.unlock();
                try std.testing.expect(stakes.vote_accounts.getAccount(accs.vote_pubkey) != null);
                try std.testing.expectEqual(
                    stake.delegation.getEffectiveStake(i, &stake_history_empty, null),
                    stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey),
                );
            }

            const vote_account = try createTestVoteAccount(
                allocator,
                Pubkey.initRandom(prng.random()),
                accs.vote_pubkey,
                0,
                1,
                0,
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
            stake = try getStakeFromStakeAccount(stake_account);
            {
                const stakes: *StakesT, var stakes_guard = stakes_cache.stakes.writeWithLock();
                defer stakes_guard.unlock();
                try std.testing.expect(stakes.vote_accounts.getAccount(accs.vote_pubkey) != null);
                try std.testing.expectEqual(
                    stake.delegation.getEffectiveStake(i, &stake_history_empty, null),
                    stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey),
                );
            }

            stake_account.lamports = 0;
            try stakes_cache.checkAndStore(allocator, accs.stake_pubkey, stake_account, null);
            {
                const stakes: *StakesT, var stakes_guard = stakes_cache.stakes.writeWithLock();
                defer stakes_guard.unlock();
                try std.testing.expect(stakes.vote_accounts.getAccount(accs.vote_pubkey) != null);
                try std.testing.expectEqual(
                    0,
                    stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey),
                );
            }
        }
    }
}

test "stakes vote account disappear reappear" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    inline for (.{
        StakesType.delegation,
        StakesType.stake,
        StakesType.account,
    }) |stakes_type| {
        var stakes_cache: StakesCacheGeneric(stakes_type) = .EMPTY;
        defer stakes_cache.deinit(allocator);

        {
            const stakes: *Stakes(stakes_type), var guard = stakes_cache.stakes.writeWithLock();
            defer guard.unlock();
            stakes.epoch = 4;
        }

        var accs = try TestStakedNodeAccounts.init(allocator, random, 10);
        defer accs.deinit(allocator);

        // Store vote and stake accounts
        try stakes_cache.checkAndStore(allocator, accs.vote_pubkey, accs.vote_account, null);
        try stakes_cache.checkAndStore(allocator, accs.stake_pubkey, accs.stake_account, null);

        {
            const stakes: *Stakes(stakes_type), var guard = stakes_cache.stakes.writeWithLock();
            defer guard.unlock();

            const vote_accounts = stakes.vote_accounts;
            try std.testing.expect(vote_accounts.getAccount(accs.vote_pubkey) != null);
            try std.testing.expectEqual(vote_accounts.getDelegatedStake(accs.vote_pubkey), 10);
        }

        // Zero lamports removes vote account
        accs.vote_account.lamports = 0;
        try stakes_cache.checkAndStore(allocator, accs.vote_pubkey, accs.vote_account, null);

        {
            const stakes: *Stakes(stakes_type), var guard = stakes_cache.stakes.writeWithLock();
            defer guard.unlock();

            try std.testing.expectEqual(null, stakes.vote_accounts.getAccount(accs.vote_pubkey));
            try std.testing.expectEqual(stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey), 0);
        }

        // Postivie lamports re-adds vote account
        accs.vote_account.lamports = 1;
        try stakes_cache.checkAndStore(allocator, accs.vote_pubkey, accs.vote_account, null);

        {
            const stakes: *Stakes(stakes_type), var guard = stakes_cache.stakes.writeWithLock();
            defer guard.unlock();

            const vote_accounts = stakes.vote_accounts;
            try std.testing.expect(vote_accounts.getAccount(accs.vote_pubkey) != null);
            try std.testing.expectEqual(vote_accounts.getDelegatedStake(accs.vote_pubkey), 10);
        }

        // Invalid data removes vote account
        const valid_data = accs.vote_account.data;
        const invalid_data = try allocator.alloc(u8, accs.vote_account.data.len + 1);
        defer allocator.free(invalid_data);
        @memset(invalid_data, 0);
        @memcpy(invalid_data[0..accs.vote_account.data.len], accs.vote_account.data);
        accs.vote_account.data = invalid_data;

        try stakes_cache.checkAndStore(allocator, accs.vote_pubkey, accs.vote_account, null);

        {
            const stakes: *Stakes(stakes_type), var guard = stakes_cache.stakes.writeWithLock();
            defer guard.unlock();

            try std.testing.expect(stakes.vote_accounts.getAccount(accs.vote_pubkey) == null);
            try std.testing.expectEqual(stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey), 0);
        }

        accs.vote_account.lamports = 1;
        accs.vote_account.data = valid_data;
        try stakes_cache.checkAndStore(allocator, accs.vote_pubkey, accs.vote_account, null);

        {
            const stakes: *Stakes(stakes_type), var guard = stakes_cache.stakes.writeWithLock();
            defer guard.unlock();

            const vote_accounts = stakes.vote_accounts;
            try std.testing.expect(vote_accounts.getAccount(accs.vote_pubkey) != null);
            try std.testing.expectEqual(vote_accounts.getDelegatedStake(accs.vote_pubkey), 10);
        }

        // Uninitialized vote account removes vote account
        var vote_state: VoteState = .DEFAULT;
        errdefer vote_state.deinit(allocator);

        try std.testing.expect(vote_state.isUninitialized());

        _ = try bincode.writeToSlice(
            accs.vote_account.data,
            VersionedVoteState{ .current = vote_state },
            .{},
        );

        try stakes_cache.checkAndStore(allocator, accs.vote_pubkey, accs.vote_account, null);

        {
            const stakes: *Stakes(stakes_type), var guard = stakes_cache.stakes.writeWithLock();
            defer guard.unlock();

            try std.testing.expect(stakes.vote_accounts.getAccount(accs.vote_pubkey) == null);
            try std.testing.expectEqual(stakes.vote_accounts.getDelegatedStake(accs.vote_pubkey), 0);
        }
    }
}

test "get stake effective and activating" {
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    const delegation = Delegation{
        .voter_pubkey = Pubkey.initRandom(random),
        .stake = 1000,
        .activation_epoch = 5,
        .deactivation_epoch = 10,
    };

    var stake_history: StakeHistory = .INIT;
    stake_history.entries.appendAssumeCapacity(.{
        .epoch = 5,
        .stake = .{
            .effective = 100,
            .activating = 30,
            .deactivating = 10,
        },
    });

    const effective, const activating = delegation.getEffectiveAndActivatingStake(
        6,
        &stake_history,
        null,
    );

    try std.testing.expectEqual(833, effective);
    try std.testing.expectEqual(167, activating);
}

test "get stake state" {
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    const delegation = Delegation{
        .voter_pubkey = Pubkey.initRandom(random),
        .stake = 1_000,
        .activation_epoch = 5,
        .deactivation_epoch = 10,
    };

    var stake_history: StakeHistory = .INIT;
    stake_history.entries.appendSliceAssumeCapacity(&.{
        .{ .epoch = 13, .stake = .{
            .effective = 0,
            .activating = 0,
            .deactivating = 0,
        } },
        .{ .epoch = 12, .stake = .{
            .effective = 500_000,
            .activating = 0,
            .deactivating = 500_000,
        } },
        .{ .epoch = 11, .stake = .{
            .effective = 1_000_000,
            .activating = 0,
            .deactivating = 500_000,
        } },
        .{ .epoch = 10, .stake = .{
            .effective = 2_000_000,
            .activating = 0,
            .deactivating = 1_000_000,
        } },
    });

    const effective, const activating = delegation.getEffectiveAndActivatingStake(
        12,
        &stake_history,
        null,
    );

    try std.testing.expectEqual(1000, effective);
    try std.testing.expectEqual(0, activating);

    const stake_state = delegation.getStakeState(12, &stake_history, null);

    try std.testing.expectEqual(250, stake_state.effective);
    try std.testing.expectEqual(0, stake_state.activating);
    try std.testing.expectEqual(250, stake_state.deactivating);
}

test "vote account invalid owner" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    const account_state: AccountSharedData = .{
        .data = &.{},
        .executable = false,
        .lamports = 0,
        .rent_epoch = 0,
        .owner = Pubkey.initRandom(random),
    };

    try std.testing.expectError(
        error.InvalidOwner,
        VoteAccount.fromAccountSharedData(allocator, account_state),
    );
}

test "staked nodes" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var accounts = try createRandomVoteAccounts(
        allocator,
        random,
        64,
        1024,
    );
    defer accounts.deinit(allocator);

    var stakes: Stakes(.delegation) = .EMPTY;
    defer stakes.deinit(allocator);

    var vote_accounts = VoteAccounts{};
    defer vote_accounts.deinit(allocator);

    // Add vote accounts and check staked nodes
    for (accounts.items, 0..) |item, i| {
        const pubkey = item[0];
        const stake = item[1].stake;
        const account = item[1].account;

        try stakes.stake_accounts.put(allocator, Pubkey.initRandom(random), .{
            .voter_pubkey = pubkey,
            .stake = stake,
            .activation_epoch = std.math.maxInt(u64),
            .deactivation_epoch = std.math.maxInt(u64),
            .deprecated_warmup_cooldown_rate = 0,
        });

        var maybe_old = try vote_accounts.insert(
            allocator,
            pubkey,
            account,
            .init(.delegation, &stakes, null),
        );
        defer if (maybe_old) |*old| old.deinit(allocator);

        if ((i + 1) % 128 == 0) {
            var expected_staked_nodes = try calculateStakedNodes(
                allocator,
                accounts.items[0 .. i + 1],
            );
            defer expected_staked_nodes.deinit(allocator);
            for (expected_staked_nodes.keys(), expected_staked_nodes.values()) |key, value| {
                const actual_value = vote_accounts.staked_nodes.get(key) orelse
                    return error.NodeNotFound;
                try std.testing.expectEqual(value, actual_value);
            }
        }
    }

    // Remove some vote accounts
    for (0..256) |i| {
        const index = random.intRangeLessThan(u64, 0, accounts.items.len);
        const pubkey, _ = accounts.swapRemove(index);
        try vote_accounts.remove(allocator, pubkey);
        if ((i + 1) % 32 == 0) {
            var expected_staked_nodes = try calculateStakedNodes(allocator, accounts.items);
            defer expected_staked_nodes.deinit(allocator);
            for (expected_staked_nodes.keys(), expected_staked_nodes.values()) |key, value| {
                const actual_value = vote_accounts.staked_nodes.get(key) orelse
                    @panic("key not found in actual staked nodes");
                try std.testing.expectEqual(value, actual_value);
            }
        }
    }

    // Modify the stakes for some of the accounts
    for (0..2048) |i| {
        const index = random.intRangeLessThan(u64, 0, accounts.items.len);
        const pubkey, const account_and_stake = accounts.items[index];
        const old_stake = account_and_stake.stake;
        const new_stake = random.intRangeAtMost(u64, 0, 1_000_000);
        if (new_stake < old_stake) {
            try vote_accounts.subStake(pubkey, old_stake - new_stake);
        } else {
            try vote_accounts.addStake(allocator, pubkey, new_stake - old_stake);
        }
        accounts.items[index][1].stake = new_stake;
        if ((i + 1) % 128 == 0) {
            var expected_staked_nodes = try calculateStakedNodes(allocator, accounts.items);
            defer expected_staked_nodes.deinit(allocator);
            for (expected_staked_nodes.keys(), expected_staked_nodes.values()) |key, value| {
                const actual_value = vote_accounts.staked_nodes.get(key) orelse
                    @panic("key not found in actual staked nodes");
                try std.testing.expectEqual(value, actual_value);
            }
        }
    }

    // Remove everything
    while (accounts.items.len > 0) {
        const index = random.intRangeLessThan(u64, 0, accounts.items.len);
        const pubkey, _ = accounts.swapRemove(index);
        try vote_accounts.remove(allocator, pubkey);
        if (accounts.items.len % 32 == 0) {
            var expected_staked_nodes = try calculateStakedNodes(allocator, accounts.items);
            defer expected_staked_nodes.deinit(allocator);
            for (expected_staked_nodes.keys(), expected_staked_nodes.values()) |key, value| {
                const actual_value = vote_accounts.staked_nodes.get(key) orelse
                    @panic("key not found in actual staked nodes");
                try std.testing.expectEqual(value, actual_value);
            }
        }
    }
    try std.testing.expectEqual(0, vote_accounts.staked_nodes.count());
}

test "staked nodes update" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var stakes: Stakes(.delegation) = .EMPTY;
    defer stakes.deinit(allocator);

    var vote_accounts: VoteAccounts = .{};
    defer vote_accounts.deinit(allocator);

    const pubkey = Pubkey.initRandom(random);
    const node_pubkey = Pubkey.initRandom(random);
    const account_0 = try VoteAccount.initRandom(
        allocator,
        random,
        node_pubkey,
    );

    {
        try stakes.stake_accounts.put(allocator, Pubkey.initRandom(random), .{
            .voter_pubkey = pubkey,
            .stake = 42,
            .activation_epoch = std.math.maxInt(u64),
            .deactivation_epoch = std.math.maxInt(u64),
            .deprecated_warmup_cooldown_rate = 0,
        });

        account_0.acquire();
        const maybe_old = try vote_accounts.insert(
            allocator,
            pubkey,
            account_0,
            .init(.delegation, &stakes, null),
        );

        try std.testing.expectEqual(null, maybe_old);
        try std.testing.expectEqual(42, vote_accounts.getDelegatedStake(pubkey));
        try std.testing.expectEqual(42, vote_accounts.staked_nodes.get(node_pubkey).?);
    }

    {
        try stakes.stake_accounts.put(allocator, Pubkey.initRandom(random), .{
            .voter_pubkey = pubkey,
            .stake = 0,
            .activation_epoch = std.math.maxInt(u64),
            .deactivation_epoch = std.math.maxInt(u64),
            .deprecated_warmup_cooldown_rate = 0,
        });

        var maybe_old = try vote_accounts.insert(
            allocator,
            pubkey,
            account_0,
            .init(.delegation, &stakes, null),
        );
        defer maybe_old.?.deinit(allocator);

        try std.testing.expectEqual(42, maybe_old.?.stake);
        try std.testing.expect(account_0.equals(&maybe_old.?.account));
        try std.testing.expect(account_0.equals(&vote_accounts.getAccount(pubkey).?));
        try std.testing.expectEqual(42, vote_accounts.getDelegatedStake(pubkey));
        try std.testing.expectEqual(42, vote_accounts.staked_nodes.get(node_pubkey).?);
    }

    const account_1 = try VoteAccount.initRandom(allocator, random, node_pubkey);

    {
        try stakes.stake_accounts.put(allocator, Pubkey.initRandom(random), .{
            .voter_pubkey = pubkey,
            .stake = 0,
            .activation_epoch = std.math.maxInt(u64),
            .deactivation_epoch = std.math.maxInt(u64),
            .deprecated_warmup_cooldown_rate = 0,
        });

        var maybe_old = try vote_accounts.insert(
            allocator,
            pubkey,
            account_1,
            .init(.delegation, &stakes, null),
        );
        defer maybe_old.?.deinit(allocator);

        try std.testing.expectEqual(42, maybe_old.?.stake);
        try std.testing.expect(account_0.equals(&maybe_old.?.account));
        try std.testing.expect(account_1.equals(&vote_accounts.getAccount(pubkey).?));
        try std.testing.expectEqual(42, vote_accounts.getDelegatedStake(pubkey));
        try std.testing.expectEqual(42, vote_accounts.staked_nodes.get(node_pubkey).?);
    }

    const new_node_pubkey = Pubkey.initRandom(random);
    const account_2 = try VoteAccount.initRandom(allocator, random, new_node_pubkey);

    {
        try stakes.stake_accounts.put(allocator, Pubkey.initRandom(random), .{
            .voter_pubkey = pubkey,
            .stake = 0,
            .activation_epoch = std.math.maxInt(u64),
            .deactivation_epoch = std.math.maxInt(u64),
            .deprecated_warmup_cooldown_rate = 0,
        });

        var maybe_old = try vote_accounts.insert(
            allocator,
            pubkey,
            account_2,
            .init(.delegation, &stakes, null),
        );
        defer maybe_old.?.deinit(allocator);

        try std.testing.expectEqual(42, maybe_old.?.stake);
        try std.testing.expect(account_1.equals(&maybe_old.?.account));
        try std.testing.expect(account_2.equals(&vote_accounts.getAccount(pubkey).?));
        try std.testing.expectEqual(42, vote_accounts.getDelegatedStake(pubkey));
        try std.testing.expectEqual(null, vote_accounts.staked_nodes.get(node_pubkey));
        try std.testing.expectEqual(42, vote_accounts.staked_nodes.get(new_node_pubkey).?);
    }
}

test "staked nodes zero stake" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var stakes: Stakes(.delegation) = .EMPTY;
    defer stakes.deinit(allocator);

    var vote_accounts = VoteAccounts{};
    defer vote_accounts.deinit(allocator);

    const pubkey = Pubkey.initRandom(random);
    const node_pubkey = Pubkey.initRandom(random);
    const account_0 = try VoteAccount.initRandom(allocator, random, node_pubkey);

    {
        try stakes.stake_accounts.put(allocator, Pubkey.initRandom(random), .{
            .voter_pubkey = pubkey,
            .stake = 0,
            .activation_epoch = std.math.maxInt(u64),
            .deactivation_epoch = std.math.maxInt(u64),
            .deprecated_warmup_cooldown_rate = 0,
        });

        const maybe_old = try vote_accounts.insert(
            allocator,
            pubkey,
            account_0,
            .init(.delegation, &stakes, null),
        );

        try std.testing.expectEqual(null, maybe_old);
        try std.testing.expect(account_0.equals(&vote_accounts.getAccount(pubkey).?));
        try std.testing.expectEqual(0, vote_accounts.getDelegatedStake(pubkey));
        try std.testing.expectEqual(null, vote_accounts.staked_nodes.get(node_pubkey));
    }

    const new_node_pubkey = Pubkey.initRandom(random);
    const account_1 = try VoteAccount.initRandom(allocator, random, new_node_pubkey);

    {
        try stakes.stake_accounts.put(allocator, Pubkey.initRandom(random), .{
            .voter_pubkey = pubkey,
            .stake = 0,
            .activation_epoch = std.math.maxInt(u64),
            .deactivation_epoch = std.math.maxInt(u64),
            .deprecated_warmup_cooldown_rate = 0,
        });

        var maybe_old = try vote_accounts.insert(
            allocator,
            pubkey,
            account_1,
            .init(.delegation, &stakes, null),
        );
        defer maybe_old.?.deinit(allocator);

        try std.testing.expectEqual(0, maybe_old.?.stake);
        try std.testing.expect(account_0.equals(&maybe_old.?.account));
        try std.testing.expect(account_1.equals(&vote_accounts.getAccount(pubkey).?));
        try std.testing.expectEqual(0, vote_accounts.getDelegatedStake(pubkey));
        try std.testing.expectEqual(null, vote_accounts.staked_nodes.get(node_pubkey));
        try std.testing.expectEqual(null, vote_accounts.staked_nodes.get(new_node_pubkey));
    }
}

test "stakes activate epoch" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_accounts = std.ArrayListUnmanaged(TestStakedNodeAccounts).empty;
    defer {
        for (test_accounts.items) |acc| acc.deinit(allocator);
        test_accounts.deinit(allocator);
    }

    var stakes_cache = StakesCacheGeneric(.stake).EMPTY;
    defer stakes_cache.deinit(allocator);

    for (0..16) |_| {
        const accs = try TestStakedNodeAccounts.init(allocator, random, 1_000);
        try test_accounts.append(allocator, accs);
        try stakes_cache.checkAndStore(
            allocator,
            accs.vote_pubkey,
            accs.vote_account,
            null,
        );
        try stakes_cache.checkAndStore(
            allocator,
            accs.stake_pubkey,
            accs.stake_account,
            null,
        );
    }

    try stakes_cache.activateEpoch(allocator, 1, null);
}
