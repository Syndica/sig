const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;

const bincode = sig.bincode;
const vote_program = sig.runtime.program.vote;

const Pubkey = sig.core.Pubkey;
const CalculateStakeContext = sig.core.stake.CaclulateStakeContext;

const AccountSharedData = sig.runtime.AccountSharedData;

const VoteState = sig.runtime.program.vote.state.VoteState;
const VoteStateVersions = sig.runtime.program.vote.state.VoteStateVersions;

const Clock = sig.runtime.sysvar.Clock;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

const deinitMapAndValues = sig.utils.collections.deinitMapAndValues;

pub const StakeAndVoteAccountsMap = std.AutoArrayHashMapUnmanaged(Pubkey, StakeAndVoteAccount);
pub const StakedNodesMap = std.AutoArrayHashMapUnmanaged(Pubkey, u64);

pub const StakeAndVoteAccount = struct {
    stake: u64,
    account: VoteAccount,

    pub fn init(stake: u64, account: VoteAccount) StakeAndVoteAccount {
        return .{ .stake = stake, .account = account };
    }

    pub fn deinit(self: *const StakeAndVoteAccount, allocator: Allocator) void {
        self.account.deinit(allocator);
    }

    pub fn clone(
        self: *const StakeAndVoteAccount,
        allocator: Allocator,
    ) Allocator.Error!StakeAndVoteAccount {
        return .{ .stake = self.stake, .account = try self.account.clone(allocator) };
    }
};

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

        var result = VoteAccounts{};
        errdefer result.deinit(allocator);

        try result.vote_accounts.ensureTotalCapacity(allocator, self.vote_accounts.capacity());
        for (self.vote_accounts.keys(), self.vote_accounts.values()) |key, value|
            try result.vote_accounts.put(allocator, key, try value.clone(allocator));

        try result.staked_nodes.ensureTotalCapacity(allocator, self.staked_nodes.capacity());
        for (self.staked_nodes.keys(), self.staked_nodes.values()) |key, value|
            try result.staked_nodes.put(allocator, key, value);

        return result;
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
    /// Takes ownership of `account` and returns the previous value if it existed.
    pub fn insert(
        self: *VoteAccounts,
        allocator: Allocator,
        pubkey: Pubkey,
        account: VoteAccount,
        calculated_stake_context: CalculateStakeContext,
    ) !?StakeAndVoteAccount {
        errdefer account.deinit(allocator);

        const entry = try self.vote_accounts.getOrPut(allocator, pubkey);
        if (entry.found_existing) {
            const old_stake = entry.value_ptr.stake;
            const old_node_pubkey = entry.value_ptr.account.getNodePubkey();
            const new_node_pubkey = account.getNodePubkey();
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
            try self.addNodeStake(allocator, account.state.node_pubkey, calculated_stake);
            return null;
        }
    }

    /// Removes the vote account identified by `pubkey` from the `vote_accounts` map, and updates
    /// the `staked_nodes` map by subtracting the stake of the removed vote account.
    pub fn remove(self: *VoteAccounts, allocator: std.mem.Allocator, pubkey: Pubkey) !void {
        const entry: StakeAndVoteAccount = self.vote_accounts.get(pubkey) orelse return;
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

    fn computeStakedNodes(
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
        const allocator = limit_allocator.backing_allocator; // VoteAccounts stores this.
        var vote_accounts = try bincode.readWithLimit(
            limit_allocator,
            StakeAndVoteAccountsMap,
            reader,
            .{},
        );
        errdefer {
            for (vote_accounts.values()) |v| v.deinit(allocator);
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
        // TODO: Uncomment once not required by bank init random
        // if (!builtin.is_test) @compileError("only for testing");

        var self = VoteAccounts{};
        errdefer self.deinit(allocator);

        for (0..random.intRangeAtMost(u64, 1, max_list_entries)) |_| {
            try self.vote_accounts.put(
                allocator,
                Pubkey.initRandom(random),
                .{ .stake = random.int(u64), .account = try createRandomVoteAccount(
                    allocator,
                    random,
                    Pubkey.initRandom(random),
                ) },
            );
        }

        self.staked_nodes = try computeStakedNodes(
            allocator,
            &self.vote_accounts,
        );

        return self;
    }
};

pub const VoteAccount = struct {
    account: AccountSharedData,
    state: VoteState,

    pub const @"!bincode-config" = bincode.FieldConfig(VoteAccount){ .deserializer = deserialize };
    pub const @"!bincode-config:state" = bincode.FieldConfig(VoteState){ .skip = true };

    pub fn deinit(self: *const VoteAccount, allocator: Allocator) void {
        self.account.deinit(allocator);
        self.state.deinit();
    }

    pub fn clone(self: VoteAccount, allocator: Allocator) Allocator.Error!VoteAccount {
        const account = try self.account.clone(allocator);
        errdefer account.deinit(allocator);
        return .{
            .account = account,
            .state = try self.state.clone(),
        };
    }

    pub fn getLamports(self: *const VoteAccount) u64 {
        return self.account.lamports;
    }

    pub fn getNodePubkey(self: *const VoteAccount) Pubkey {
        return self.state.node_pubkey;
    }

    pub fn equals(self: *const VoteAccount, other: *const VoteAccount) bool {
        return self.account.equals(&other.account) and self.state.equals(&other.state);
    }

    /// Takes ownership of `account`.
    pub fn fromAccountSharedData(
        allocator: std.mem.Allocator,
        account: AccountSharedData,
    ) !VoteAccount {
        errdefer account.deinit(allocator);

        if (!vote_program.ID.equals(&account.owner)) return error.InvalidOwner;

        const versioned_vote_state = try bincode.readFromSlice(
            allocator,
            VoteStateVersions,
            account.data,
            .{},
        );
        errdefer versioned_vote_state.deinit();

        return .{
            .account = account,
            .state = try versioned_vote_state.convertToCurrent(allocator),
        };
    }

    /// Deserialize the `AccountSharedData`, and attempt to deserialize
    /// `VoteState` from the account data.
    fn deserialize(
        limit_allocator: *bincode.LimitAllocator,
        reader: anytype,
        _: bincode.Params,
    ) !VoteAccount {
        return fromAccountSharedData(
            limit_allocator.backing_allocator, // VoteState stores this.
            try bincode.readWithLimit(limit_allocator, AccountSharedData, reader, .{}),
        );
    }

    pub fn initRandom(
        allocator: Allocator,
        random: std.Random,
        node_pubkey: ?Pubkey,
    ) Allocator.Error!VoteAccount {
        // TODO: Uncomment once not required by bank init random
        // if (!builtin.is_test) @compileError("only for testing");

        const account = try createVoteAccount(
            allocator,
            node_pubkey orelse .initRandom(random),
            .initRandom(random),
            .initRandom(random),
            random.int(u8),
            random.intRangeAtMost(u64, 1, 1_000_000),
            .initRandom(random),
        );

        return VoteAccount.fromAccountSharedData(
            allocator,
            account,
        ) catch |err| {
            switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                // We just created a 'valid' vote account, so the only possible
                // error is `OutOfMemory`.
                else => unreachable,
            }
        };
    }
};

pub fn createVoteAccount(
    allocator: Allocator,
    node_pubkey: Pubkey,
    authorized_voter: Pubkey,
    authorized_withdrawer: Pubkey,
    commission: u8,
    lamports: u64,
    clock: ?Clock,
) Allocator.Error!AccountSharedData {
    // TODO: Uncomment once not required by bank init random
    // if (!builtin.is_test) @compileError("only for testing");

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
        clock orelse Clock.DEFAULT,
    );
    defer vote_state.deinit();

    _ = bincode.writeToSlice(
        vote_account.data,
        VoteStateVersions{ .current = vote_state },
        .{},
    ) catch unreachable;
    // unreachable: We just created a 'valid' vote state and allocated
    // MAX_VOTE_STATE_SIZE bytes

    return vote_account;
}

pub fn createRandomVoteAccount(
    allocator: Allocator,
    random: std.Random,
    node_pubkey: Pubkey,
) Allocator.Error!VoteAccount {
    // TODO: Uncomment once not required by bank init random
    // if (!builtin.is_test) @compileError("only for testing");

    const account = try createVoteAccount(
        allocator,
        node_pubkey,
        Pubkey.initRandom(random),
        Pubkey.initRandom(random),
        random.int(u8),
        random.intRangeAtMost(u64, 1, 1_000_000),
        Clock.initRandom(random),
    );

    return VoteAccount.fromAccountSharedData(
        allocator,
        account,
    ) catch |err| {
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // We just created a 'valid' vote account, so the only possible
            // error is `OutOfMemory`.
            else => unreachable,
        }
    };
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
        const account = try createRandomVoteAccount(allocator, random, node_pubkey);
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

test "vote account from account" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var account = try createRandomVoteAccount(allocator, random, Pubkey.initRandom(random));
    defer account.deinit(allocator);

    { // Success
        const actual = try VoteAccount.fromAccountSharedData(
            allocator,
            try account.account.clone(allocator),
        );
        defer actual.deinit(allocator);

        try std.testing.expect(account.account.equals(&actual.account));
        try std.testing.expect(account.state.equals(&actual.state));
    }

    { // Invalid owner
        const original_owner = account.account.owner;
        defer account.account.owner = original_owner;

        account.account.owner = Pubkey.initRandom(random);
        const actual = VoteAccount.fromAccountSharedData(
            allocator,
            try account.account.clone(allocator),
        );

        try std.testing.expectError(error.InvalidOwner, actual);
    }

    { // Invalid data

        const original_first_byte = account.account.data[0];
        defer account.account.data[0] = original_first_byte;

        account.account.data[0] = 0xFF;
        const actual = VoteAccount.fromAccountSharedData(
            allocator,
            try account.account.clone(allocator),
        );

        try std.testing.expectError(error.InvalidEnumTag, actual);
    }

    { // Invalid data

        const original_data_len = account.account.data.len;
        defer account.account.data.len = original_data_len;

        account.account.data.len = 0;
        const actual = VoteAccount.fromAccountSharedData(
            allocator,
            try account.account.clone(allocator),
        );

        try std.testing.expectError(error.EndOfStream, actual);
    }
}

test "vote account serialize and deserialize" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var account = try createRandomVoteAccount(allocator, random, Pubkey.initRandom(random));
    defer account.deinit(allocator);

    const expected_serialised = try bincode.writeAlloc(allocator, account.account, .{});
    defer allocator.free(expected_serialised);

    const actual_serialised = try bincode.writeAlloc(
        allocator,
        account,
        .{},
    );
    defer allocator.free(actual_serialised);

    try std.testing.expectEqualSlices(u8, expected_serialised, actual_serialised);

    const actual_deserialized = try bincode.readFromSlice(
        allocator,
        VoteAccount,
        actual_serialised,
        .{},
    );
    defer actual_deserialized.deinit(allocator);

    try std.testing.expect(account.account.equals(&actual_deserialized.account));
    try std.testing.expect(account.state.equals(&actual_deserialized.state));
}

test "vote accounts serialize and deserialize" {
    const Stakes = sig.core.Stakes;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var vote_accounts = VoteAccounts{};
    defer vote_accounts.deinit(allocator);

    var stakes: Stakes(.delegation) = .EMPTY;
    defer stakes.deinit(allocator);

    // Add stake delegation for the vote pubket for the calculate stake context.
    const vote_pubkey = Pubkey.initRandom(random);
    try stakes.stake_delegations.put(allocator, Pubkey.initRandom(random), .{
        .voter_pubkey = vote_pubkey,
        .stake = 10,
        .activation_epoch = std.math.maxInt(u64),
        .deactivation_epoch = std.math.maxInt(u64),
        .deprecated_warmup_cooldown_rate = 0,
    });

    // Insert a valid vote account
    var account = try createRandomVoteAccount(allocator, random, Pubkey.initRandom(random));
    _ = try vote_accounts.insert(
        allocator,
        vote_pubkey,
        try account.clone(allocator),
        .init(.delegation, &stakes, null),
    );

    { // Valid serialization and deserialization
        const serialized = try bincode.writeAlloc(allocator, vote_accounts, .{});
        defer allocator.free(serialized);
        const deserialized = try bincode.readFromSlice(
            allocator,
            VoteAccounts,
            serialized,
            .{},
        );
        defer deserialized.deinit(allocator);
        try std.testing.expectEqual(
            vote_accounts.vote_accounts.count(),
            deserialized.vote_accounts.count(),
        );
        for (
            vote_accounts.vote_accounts.keys(),
            vote_accounts.vote_accounts.values(),
        ) |key, value| {
            const actual_value = deserialized.vote_accounts.get(key) orelse
                return error.VoteAccountNotFound;
            try std.testing.expectEqual(value.stake, actual_value.stake);
            try std.testing.expect(value.account.account.equals(&actual_value.account.account));
            try std.testing.expect(value.account.state.equals(&actual_value.account.state));
        }
        for (vote_accounts.staked_nodes.keys(), vote_accounts.staked_nodes.values()) |key, value| {
            const deserialized_value = deserialized.staked_nodes.get(key) orelse
                return error.NodeNotFound;
            try std.testing.expectEqual(value, deserialized_value);
        }
    }

    // Insert a vote account with wrong owner
    account.account.owner = Pubkey.initRandom(random);
    try vote_accounts.vote_accounts.put(
        allocator,
        Pubkey.initRandom(random),
        .{ .stake = 0, .account = account },
    );

    { // Invalid serialization and deserialization
        const serialized = try bincode.writeAlloc(allocator, vote_accounts, .{});
        defer allocator.free(serialized);
        try std.testing.expectError(error.InvalidOwner, bincode.readFromSlice(
            allocator,
            VoteAccounts,
            serialized,
            .{},
        ));
    }
}

test "staked nodes" {
    const Stakes = sig.core.Stakes;

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

        try stakes.stake_delegations.put(allocator, Pubkey.initRandom(random), .{
            .voter_pubkey = pubkey,
            .stake = stake,
            .activation_epoch = std.math.maxInt(u64),
            .deactivation_epoch = std.math.maxInt(u64),
            .deprecated_warmup_cooldown_rate = 0,
        });

        const maybe_old = try vote_accounts.insert(
            allocator,
            pubkey,
            account,
            .init(.delegation, &stakes, null),
        );
        defer if (maybe_old) |old| old.deinit(allocator);

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
    const Stakes = sig.core.Stakes;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var stakes: Stakes(.delegation) = .EMPTY;
    defer stakes.deinit(allocator);

    var vote_accounts = VoteAccounts{};
    defer vote_accounts.deinit(allocator);

    const pubkey = Pubkey.initRandom(random);
    const node_pubkey = Pubkey.initRandom(random);
    const account_0 = try createRandomVoteAccount(
        allocator,
        random,
        node_pubkey,
    );

    {
        try stakes.stake_delegations.put(allocator, Pubkey.initRandom(random), .{
            .voter_pubkey = pubkey,
            .stake = 42,
            .activation_epoch = std.math.maxInt(u64),
            .deactivation_epoch = std.math.maxInt(u64),
            .deprecated_warmup_cooldown_rate = 0,
        });

        const maybe_old = try vote_accounts.insert(
            allocator,
            pubkey,
            try account_0.clone(allocator),
            .init(.delegation, &stakes, null),
        );

        try std.testing.expectEqual(null, maybe_old);
        try std.testing.expectEqual(42, vote_accounts.getDelegatedStake(pubkey));
        try std.testing.expectEqual(42, vote_accounts.staked_nodes.get(node_pubkey).?);
    }

    {
        try stakes.stake_delegations.put(allocator, Pubkey.initRandom(random), .{
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
        defer maybe_old.?.deinit(allocator);

        try std.testing.expectEqual(42, maybe_old.?.stake);
        try std.testing.expect(account_0.equals(&maybe_old.?.account));
        try std.testing.expect(account_0.equals(&vote_accounts.getAccount(pubkey).?));
        try std.testing.expectEqual(42, vote_accounts.getDelegatedStake(pubkey));
        try std.testing.expectEqual(42, vote_accounts.staked_nodes.get(node_pubkey).?);
    }

    const account_1 = try createRandomVoteAccount(allocator, random, node_pubkey);

    {
        try stakes.stake_delegations.put(allocator, Pubkey.initRandom(random), .{
            .voter_pubkey = pubkey,
            .stake = 0,
            .activation_epoch = std.math.maxInt(u64),
            .deactivation_epoch = std.math.maxInt(u64),
            .deprecated_warmup_cooldown_rate = 0,
        });

        const maybe_old = try vote_accounts.insert(
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
    const account_2 = try createRandomVoteAccount(allocator, random, new_node_pubkey);

    {
        try stakes.stake_delegations.put(allocator, Pubkey.initRandom(random), .{
            .voter_pubkey = pubkey,
            .stake = 0,
            .activation_epoch = std.math.maxInt(u64),
            .deactivation_epoch = std.math.maxInt(u64),
            .deprecated_warmup_cooldown_rate = 0,
        });

        const maybe_old = try vote_accounts.insert(
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
    const Stakes = sig.core.Stakes;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var stakes: Stakes(.delegation) = .EMPTY;
    defer stakes.deinit(allocator);

    var vote_accounts = VoteAccounts{};
    defer vote_accounts.deinit(allocator);

    const pubkey = Pubkey.initRandom(random);
    const node_pubkey = Pubkey.initRandom(random);
    const account_0 = try createRandomVoteAccount(allocator, random, node_pubkey);

    {
        try stakes.stake_delegations.put(allocator, Pubkey.initRandom(random), .{
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
    const account_1 = try createRandomVoteAccount(allocator, random, new_node_pubkey);

    {
        try stakes.stake_delegations.put(allocator, Pubkey.initRandom(random), .{
            .voter_pubkey = pubkey,
            .stake = 0,
            .activation_epoch = std.math.maxInt(u64),
            .deactivation_epoch = std.math.maxInt(u64),
            .deprecated_warmup_cooldown_rate = 0,
        });

        const maybe_old = try vote_accounts.insert(
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
