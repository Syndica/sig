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
const VoteStateVersions = sig.runtime.program.vote.state.VoteStateVersions;

const Clock = sig.runtime.sysvar.Clock;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const StakeHistoryEntry = sig.runtime.sysvar.StakeHistory.Entry;
const ClusterStake = sig.runtime.sysvar.StakeHistory.ClusterStake;
const RwMux = sig.sync.RwMux;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

/// Deserialization in Agave allows invalid vote accounts to exist for snapshot compatibility. It is
/// noted that this should change to a hard error in the future. We take the hard error on desererialisation
/// approach and can write a custom deserializer if we come across a need to deserialize invalid vote accounts.
/// [agave] https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/vote/src/vote_account.rs#L431-L438
///
/// [agave] https://github.com/firedancer-io/agave/blob/10fe1eb29aac9c236fd72d08ae60a3ef61ee8353/vote/src/vote_account.rs#L45-L46
pub const VoteAccounts = struct {
    /// Maps pubkeys to vote account and delegated stake.
    vote_accounts: std.AutoArrayHashMapUnmanaged(Pubkey, VoteAccountAndDelegatedStake) = .{},
    /// Maps vote account node pubkeys to their total delegated stake.
    staked_nodes: std.AutoArrayHashMapUnmanaged(Pubkey, u64) = .{},

    pub const @"!bincode-config" = bincode.FieldConfig(
        VoteAccounts,
    ){ .deserializer = deserialize };

    pub const @"!bincode-config:staked_nodes" = bincode.FieldConfig(
        std.AutoArrayHashMapUnmanaged(Pubkey, u64),
    ){ .skip = true };

    pub const VoteAccountAndDelegatedStake = struct {
        vote_account: VoteAccount,
        delegated_stake: u64,

        pub fn deinit(self: *const VoteAccountAndDelegatedStake, allocator: Allocator) void {
            self.vote_account.deinit(allocator);
        }
    };

    pub fn deinit(self: *const VoteAccounts, allocator: Allocator) void {
        for (self.vote_accounts.values()) |v| v.deinit(allocator);
        var votes = self.vote_accounts;
        votes.deinit(allocator);
        var stakes = self.staked_nodes;
        stakes.deinit(allocator);
    }

    pub fn getAccount(self: *const VoteAccounts, pubkey: Pubkey) ?VoteAccount {
        const entry = self.vote_accounts.getPtr(pubkey) orelse return null;
        return entry.vote_account;
    }

    pub fn getDelegatedStake(self: *const VoteAccounts, pubkey: Pubkey) u64 {
        const entry = self.vote_accounts.getPtr(pubkey) orelse return 0;
        return entry.delegated_stake;
    }

    /// Inserts a new vote account into the `vote_accounts` map, or updates an existing one.
    /// If the vote account is new, it will calculate the stake and add it to the `staked_nodes` map.
    /// If the vote account already exists, and the node pubkey has changed, it will move the stake
    /// from the old node to the new node in the `staked_nodes` map.
    pub fn insert(
        self: *VoteAccounts,
        allocator: Allocator,
        pubkey: Pubkey,
        account: VoteAccount,
        caclulated_stake: u64,
    ) Allocator.Error!?VoteAccountAndDelegatedStake {
        const entry = try self.vote_accounts.getOrPut(allocator, pubkey);
        if (entry.found_existing) {
            const old_stake = entry.value_ptr.delegated_stake;
            const old_node_pubkey = entry.value_ptr.vote_account.getNodePubkey();
            const new_node_pubkey = account.getNodePubkey();
            if (!new_node_pubkey.equals(&old_node_pubkey)) {
                self.subNodeStake(old_node_pubkey, old_stake);
                try self.addNodeStake(allocator, new_node_pubkey, old_stake);
            }
            const old_entry_value = entry.value_ptr.*;
            entry.value_ptr.vote_account = try account.clone(allocator);
            return old_entry_value;
        } else {
            entry.value_ptr.* = .{ .delegated_stake = caclulated_stake, .vote_account = try account.clone(allocator) };
            try self.addNodeStake(allocator, account.state.node_pubkey, caclulated_stake);
            return null;
        }
    }

    /// Removes the vote account identified by `pubkey` from the `vote_accounts` map, and updates
    /// the `staked_nodes` map by subtracting the stake of the removed vote account.
    pub fn remove(self: *VoteAccounts, allocator: std.mem.Allocator, pubkey: Pubkey) void {
        const entry: VoteAccountAndDelegatedStake = self.vote_accounts.get(pubkey) orelse return;
        defer entry.deinit(allocator);
        _ = self.vote_accounts.swapRemove(pubkey);
        self.subNodeStake(entry.vote_account.getNodePubkey(), entry.delegated_stake);
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
        entry.delegated_stake += delta;
        try self.addNodeStake(allocator, entry.vote_account.state.node_pubkey, delta);
    }

    /// Subtracts `delta` from the stake of the vote account identified by `pubkey`, and updates the
    /// `staked_nodes` map. Panics if `delta` is greater than the current stake.
    pub fn subStake(self: *VoteAccounts, pubkey: Pubkey, delta: u64) void {
        const entry = self.vote_accounts.getPtr(pubkey) orelse return;
        if (entry.delegated_stake < delta) @panic("subtraction value exceeds vote account's stake");
        entry.delegated_stake -= delta;
        self.subNodeStake(entry.vote_account.state.node_pubkey, delta);
    }

    /// Adds `stake` to an entry in `staked_nodes`. If the entry does not exist, one will be created.
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

    /// Subtracts `stake` from an entry in `staked_nodes`. If the entry does not exist, it will panic.
    fn subNodeStake(self: *VoteAccounts, pubkey: Pubkey, stake: u64) void {
        if (stake == 0) return;

        const current_stake = self.staked_nodes.getPtr(pubkey) orelse
            @panic("pubkey not present in staked_nodes");

        switch (std.math.order(current_stake.*, stake)) {
            .lt => @panic("subtraction value exceeds node's stake"),
            .eq => _ = self.staked_nodes.swapRemove(pubkey),
            .gt => current_stake.* -= stake,
        }
    }

    fn deserialize(allocator: Allocator, reader: anytype, _: bincode.Params) !VoteAccounts {
        var vote_accounts = try bincode.read(
            allocator,
            std.AutoArrayHashMapUnmanaged(Pubkey, VoteAccountAndDelegatedStake),
            reader,
            .{},
        );
        errdefer vote_accounts.deinit(allocator);

        var staked_nodes = std.AutoArrayHashMapUnmanaged(Pubkey, u64){};
        errdefer staked_nodes.deinit(allocator);

        for (vote_accounts.keys(), vote_accounts.values()) |_, value| {
            if (value.delegated_stake > 0) {
                const entry = try staked_nodes.getOrPut(allocator, value.vote_account.getNodePubkey());
                if (entry.found_existing)
                    entry.value_ptr.* += value.delegated_stake
                else
                    entry.value_ptr.* = value.delegated_stake;
            }
        }

        return .{
            .vote_accounts = vote_accounts,
            .staked_nodes = staked_nodes,
        };
    }
};

pub const VoteAccount = struct {
    account: AccountSharedData,
    state: VoteState,

    pub const @"!bincode-config" = bincode.FieldConfig(VoteAccount){
        .serializer = serialize,
        .deserializer = deserialize,
    };

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

    /// Creates a `VoteAccount` from an `AccountSharedData`, taking ownership of the `AccountSharedData`.
    pub fn fromAccountSharedData(allocator: Allocator, account: AccountSharedData) !VoteAccount {
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

    /// Serialize only the `AccountSharedData` part of the `VoteAccount`.
    fn serialize(writer: anytype, data: VoteAccount, _: bincode.Params) !void {
        try bincode.write(writer, data.account, .{});
    }

    /// Deserialize the `AccountSharedData`, and attempt to deserialize `VoteState` from the account data.
    fn deserialize(allocator: Allocator, reader: anytype, _: bincode.Params) !VoteAccount {
        return fromAccountSharedData(
            allocator,
            try bincode.read(allocator, AccountSharedData, reader, .{}),
        );
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
) !AccountSharedData {
    if (!builtin.is_test) @compileError("only for testing");

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

    _ = try bincode.writeToSlice(
        vote_account.data,
        VoteStateVersions{ .current = vote_state },
        .{},
    );

    return vote_account;
}

pub fn createRandomVoteAccount(
    allocator: Allocator,
    random: std.Random,
    node_pubkey: Pubkey,
) !VoteAccount {
    if (!builtin.is_test) @compileError("only for testing");
    const account = try createVoteAccount(
        allocator,
        node_pubkey,
        Pubkey.initRandom(random),
        Pubkey.initRandom(random),
        random.int(u8),
        random.intRangeAtMost(u64, 1, 1_000_000),
        Clock.initRandom(random),
    );
    return VoteAccount.fromAccountSharedData(allocator, account);
}

const VoteAccountsArray = std.ArrayListUnmanaged(struct { Pubkey, VoteAccounts.VoteAccountAndDelegatedStake });

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
            .delegated_stake = stake,
            .vote_account = account,
        } });
    }

    return vote_accounts;
}

pub fn calculateStakedNodes(
    allocator: Allocator,
    accounts: []struct { Pubkey, VoteAccounts.VoteAccountAndDelegatedStake },
) Allocator.Error!std.AutoArrayHashMapUnmanaged(Pubkey, u64) {
    if (!builtin.is_test) @compileError("only for testing");

    var staked_nodes = std.AutoArrayHashMapUnmanaged(Pubkey, u64){};
    errdefer staked_nodes.deinit(allocator);

    for (accounts) |item| {
        const stake = item[1].delegated_stake;
        const account = item[1].vote_account;
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
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var vote_accounts = VoteAccounts{};
    defer vote_accounts.deinit(allocator);

    // Insert a valid vote account
    var account = try createRandomVoteAccount(allocator, random, Pubkey.initRandom(random));
    _ = try vote_accounts.insert(allocator, Pubkey.initRandom(random), account, 10);

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
        for (vote_accounts.vote_accounts.keys(), vote_accounts.vote_accounts.values()) |key, value| {
            const deserialized_value = deserialized.vote_accounts.get(key) orelse
                @panic("key not found in deserialized vote accounts");
            try std.testing.expectEqual(value.delegated_stake, deserialized_value.delegated_stake);
            try std.testing.expect(value.vote_account.account.equals(&deserialized_value.vote_account.account));
            try std.testing.expect(value.vote_account.state.equals(&deserialized_value.vote_account.state));
        }
        for (vote_accounts.staked_nodes.keys(), vote_accounts.staked_nodes.values()) |key, value| {
            const deserialized_value = deserialized.staked_nodes.get(key) orelse
                @panic("key not found in deserialized staked nodes");
            try std.testing.expectEqual(value, deserialized_value);
        }
    }

    // Insert a vote account with wrong owner
    account.account.owner = Pubkey.initRandom(random);
    try vote_accounts.vote_accounts.put(
        allocator,
        Pubkey.initRandom(random),
        .{ .delegated_stake = 0, .vote_account = account },
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
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var accounts = try createRandomVoteAccounts(
        allocator,
        random,
        64,
        1024,
    );
    defer {
        for (accounts.items) |item| item[1].deinit(allocator);
        accounts.deinit(allocator);
    }

    var vote_accounts = VoteAccounts{};
    defer vote_accounts.deinit(allocator);

    // Add vote accounts and check staked nodes
    for (accounts.items, 0..) |item, i| {
        const pubkey = item[0];
        const stake = item[1].delegated_stake;
        const account = item[1].vote_account;

        const maybe_old = try vote_accounts.insert(allocator, pubkey, account, stake);
        defer if (maybe_old) |old| old.deinit(allocator);

        if ((i + 1) % 1 == 0) {
            var expected_staked_nodes = try calculateStakedNodes(allocator, accounts.items[0 .. i + 1]);
            defer expected_staked_nodes.deinit(allocator);
            for (expected_staked_nodes.keys(), expected_staked_nodes.values()) |key, expected_value| {
                const actual_value = vote_accounts.staked_nodes.get(key) orelse
                    @panic("key not found in actual staked nodes");
                try std.testing.expectEqual(expected_value, actual_value);
            }
        }
    }

    // Remove some vote accounts
    for (0..256) |i| {
        const index = random.intRangeLessThan(u64, 0, accounts.items.len);
        const pubkey, const account_and_stake = accounts.swapRemove(index);
        account_and_stake.deinit(allocator);
        vote_accounts.remove(allocator, pubkey);
        if ((i + 1) % 1 == 0) {
            var expected_staked_nodes = try calculateStakedNodes(allocator, accounts.items);
            defer expected_staked_nodes.deinit(allocator);
            for (expected_staked_nodes.keys(), expected_staked_nodes.values()) |key, expected_value| {
                const actual_value = vote_accounts.staked_nodes.get(key) orelse
                    @panic("key not found in actual staked nodes");
                try std.testing.expectEqual(expected_value, actual_value);
            }
        }
    }

    // Modify the stakes for some of the accounts
    for (0..2048) |i| {
        const index = random.intRangeLessThan(u64, 0, accounts.items.len);
        const pubkey, const account_and_stake = accounts.items[index];
        const old_stake = account_and_stake.delegated_stake;
        const new_stake = random.intRangeAtMost(u64, 0, 1_000_000);
        if (new_stake < old_stake) {
            vote_accounts.subStake(pubkey, old_stake - new_stake);
        } else {
            try vote_accounts.addStake(allocator, pubkey, new_stake - old_stake);
        }
        accounts.items[index][1].delegated_stake = new_stake;
        if ((i + 1) % 1 == 0) {
            var expected_staked_nodes = try calculateStakedNodes(allocator, accounts.items);
            defer expected_staked_nodes.deinit(allocator);
            for (expected_staked_nodes.keys(), expected_staked_nodes.values()) |key, expected_value| {
                const actual_value = vote_accounts.staked_nodes.get(key) orelse
                    @panic("key not found in actual staked nodes");
                try std.testing.expectEqual(expected_value, actual_value);
            }
        }
    }

    // Remove everything
    while (accounts.items.len > 0) {
        const index = random.intRangeLessThan(u64, 0, accounts.items.len);
        const pubkey, const account_and_stake = accounts.swapRemove(index);
        account_and_stake.deinit(allocator);
        vote_accounts.remove(allocator, pubkey);
        if ((accounts.items.len + 1) % 1 == 0) {
            var expected_staked_nodes = try calculateStakedNodes(allocator, accounts.items);
            defer expected_staked_nodes.deinit(allocator);
            for (expected_staked_nodes.keys(), expected_staked_nodes.values()) |key, expected_value| {
                const actual_value = vote_accounts.staked_nodes.get(key) orelse
                    @panic("key not found in actual staked nodes");
                try std.testing.expectEqual(expected_value, actual_value);
            }
        }
    }
    try std.testing.expectEqual(0, vote_accounts.staked_nodes.count());
}

test "staked nodes update" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);
    const random = prng.random();

    var vote_accounts = VoteAccounts{};
    defer vote_accounts.deinit(allocator);

    const pubkey = Pubkey.initRandom(random);
    const node_pubkey = Pubkey.initRandom(random);
    const account_0 = try createRandomVoteAccount(allocator, random, node_pubkey);
    defer account_0.deinit(allocator);

    {
        const maybe_old = try vote_accounts.insert(allocator, pubkey, account_0, 42);
        try std.testing.expectEqual(null, maybe_old);
        try std.testing.expectEqual(42, vote_accounts.getDelegatedStake(pubkey));
        try std.testing.expectEqual(42, vote_accounts.staked_nodes.get(node_pubkey).?);
    }

    {
        const maybe_old = try vote_accounts.insert(allocator, pubkey, account_0, 0);
        defer maybe_old.?.deinit(allocator);
        try std.testing.expectEqual(42, maybe_old.?.delegated_stake);
        try std.testing.expect(account_0.equals(&maybe_old.?.vote_account));
        try std.testing.expect(account_0.equals(&vote_accounts.getAccount(pubkey).?));
        try std.testing.expectEqual(42, vote_accounts.getDelegatedStake(pubkey));
        try std.testing.expectEqual(42, vote_accounts.staked_nodes.get(node_pubkey).?);
    }

    const account_1 = try createRandomVoteAccount(allocator, random, node_pubkey);
    defer account_1.deinit(allocator);

    {
        const maybe_old = try vote_accounts.insert(allocator, pubkey, account_1, 0);
        defer maybe_old.?.deinit(allocator);
        try std.testing.expectEqual(42, maybe_old.?.delegated_stake);
        try std.testing.expect(account_0.equals(&maybe_old.?.vote_account));
        try std.testing.expect(account_1.equals(&vote_accounts.getAccount(pubkey).?));
        try std.testing.expectEqual(42, vote_accounts.getDelegatedStake(pubkey));
        try std.testing.expectEqual(42, vote_accounts.staked_nodes.get(node_pubkey).?);
    }

    const new_node_pubkey = Pubkey.initRandom(random);
    const account_2 = try createRandomVoteAccount(allocator, random, new_node_pubkey);
    defer account_2.deinit(allocator);

    {
        const maybe_old = try vote_accounts.insert(allocator, pubkey, account_2, 0);
        defer maybe_old.?.deinit(allocator);
        try std.testing.expectEqual(42, maybe_old.?.delegated_stake);
        try std.testing.expect(account_1.equals(&maybe_old.?.vote_account));
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

    var vote_accounts = VoteAccounts{};
    defer vote_accounts.deinit(allocator);

    const pubkey = Pubkey.initRandom(random);
    const node_pubkey = Pubkey.initRandom(random);
    const account_0 = try createRandomVoteAccount(allocator, random, node_pubkey);
    defer account_0.deinit(allocator);

    {
        const maybe_old = try vote_accounts.insert(allocator, pubkey, account_0, 0);
        try std.testing.expectEqual(null, maybe_old);
        try std.testing.expect(account_0.equals(&vote_accounts.getAccount(pubkey).?));
        try std.testing.expectEqual(0, vote_accounts.getDelegatedStake(pubkey));
        try std.testing.expectEqual(null, vote_accounts.staked_nodes.get(node_pubkey));
    }

    const new_node_pubkey = Pubkey.initRandom(random);
    const account_1 = try createRandomVoteAccount(allocator, random, new_node_pubkey);
    defer account_1.deinit(allocator);

    {
        const maybe_old = try vote_accounts.insert(allocator, pubkey, account_1, 0);
        defer maybe_old.?.deinit(allocator);
        try std.testing.expectEqual(0, maybe_old.?.delegated_stake);
        try std.testing.expect(account_0.equals(&maybe_old.?.vote_account));
        try std.testing.expect(account_1.equals(&vote_accounts.getAccount(pubkey).?));
        try std.testing.expectEqual(0, vote_accounts.getDelegatedStake(pubkey));
        try std.testing.expectEqual(null, vote_accounts.staked_nodes.get(node_pubkey));
        try std.testing.expectEqual(null, vote_accounts.staked_nodes.get(new_node_pubkey));
    }
}
