const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const Allocator = std.mem.Allocator;

const Account = sig.core.account.Account;
const Epoch = sig.core.time.Epoch;
const Pubkey = sig.core.pubkey.Pubkey;

const deinitMapAndValues = sig.utils.collections.deinitMapAndValues;
const cloneMapAndValues = sig.utils.collections.cloneMapAndValues;

pub const EpochStakeMap = std.AutoArrayHashMapUnmanaged(Epoch, EpochStakes);

pub fn epochStakeMapDeinit(
    epoch_stakes: EpochStakeMap,
    allocator: Allocator,
) void {
    for (epoch_stakes.values()) |epoch_stake| {
        epoch_stake.deinit(allocator);
    }

    var copy = epoch_stakes;
    copy.deinit(allocator);
}

pub fn epochStakeMapClone(
    epoch_stakes: EpochStakeMap,
    allocator: Allocator,
) Allocator.Error!EpochStakeMap {
    var cloned: EpochStakeMap = .{};
    errdefer epochStakeMapDeinit(cloned, allocator);
    try cloned.ensureTotalCapacity(allocator, epoch_stakes.count());

    for (epoch_stakes.keys(), epoch_stakes.values()) |key, value| {
        const cloned_value = try value.clone(allocator);
        cloned.putAssumeCapacityNoClobber(key, cloned_value);
    }

    return cloned;
}

pub fn epochStakeMapRandom(
    random: std.Random,
    allocator: Allocator,
    min_list_entries: usize,
    max_list_entries: usize,
) Allocator.Error!EpochStakeMap {
    var map: EpochStakeMap = .{};
    errdefer epochStakeMapDeinit(map, allocator);

    const map_len = random.intRangeAtMost(usize, min_list_entries, max_list_entries);
    try map.ensureTotalCapacity(allocator, map_len);

    for (0..map_len) |_| {
        const value_ptr = while (true) {
            const gop = map.getOrPutAssumeCapacity(random.int(Epoch));
            if (gop.found_existing) continue;
            break gop.value_ptr;
        };
        value_ptr.* = try EpochStakes.initRandom(allocator, random, max_list_entries);
    }

    return map;
}

/// Analogous to [EpochStakes](https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/runtime/src/epoch_stakes.rs#L22)
pub const EpochStakes = struct {
    stakes: Stakes(.delegation),
    total_stake: u64,
    node_id_to_vote_accounts: NodeIdToVoteAccountsMap,
    epoch_authorized_voters: EpochAuthorizedVoters,

    /// Creates an empty `EpochStakes` with a single stake history entry at epoch 0.
    pub fn initEmpty(allocator: std.mem.Allocator) !EpochStakes {
        var history: EpochAndStakeHistory = .{};
        try history.append(allocator, .{
            .epoch = 0,
            .history_entry = .{
                .effective = 0,
                .activating = 0,
                .deactivating = 0,
            },
        });
        return .{
            .total_stake = 0,
            .stakes = .{
                .epoch = 0,
                .history = history,
                .vote_accounts = .{
                    .accounts = .{},
                    .staked_nodes = null,
                },
                .delegations = .{},
                .unused = 0,
            },
            .node_id_to_vote_accounts = .{},
            .epoch_authorized_voters = .{},
        };
    }

    pub fn deinit(epoch_stakes: EpochStakes, allocator: Allocator) void {
        epoch_stakes.stakes.deinit(allocator);
        deinitMapAndValues(allocator, epoch_stakes.node_id_to_vote_accounts);

        var epoch_authorized_voters = epoch_stakes.epoch_authorized_voters;
        epoch_authorized_voters.deinit(allocator);
    }

    pub fn clone(
        epoch_stakes: EpochStakes,
        allocator: Allocator,
    ) Allocator.Error!EpochStakes {
        const stakes = try epoch_stakes.stakes.clone(allocator);
        errdefer stakes.deinit(allocator);

        const node_id_to_vote_accounts =
            try cloneMapAndValues(allocator, epoch_stakes.node_id_to_vote_accounts);
        errdefer deinitMapAndValues(allocator, node_id_to_vote_accounts);

        var epoch_authorized_voters = try epoch_stakes.epoch_authorized_voters.clone(allocator);
        errdefer epoch_authorized_voters.deinit(allocator);

        return .{
            .stakes = stakes,
            .total_stake = epoch_stakes.total_stake,
            .node_id_to_vote_accounts = node_id_to_vote_accounts,
            .epoch_authorized_voters = epoch_authorized_voters,
        };
    }

    pub fn initRandom(
        allocator: Allocator,
        /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
        /// for commentary on the runtime of this function.
        random: std.Random,
        max_list_entries: usize,
    ) Allocator.Error!EpochStakes {
        var result_stakes = try Stakes(.delegation).initRandom(allocator, random, max_list_entries);
        errdefer result_stakes.deinit(allocator);

        const node_id_to_vote_accounts =
            try nodeIdToVoteAccountsMapRandom(allocator, random, max_list_entries);
        errdefer deinitMapAndValues(allocator, node_id_to_vote_accounts);

        var epoch_authorized_voters =
            try epochAuthorizedVotersRandom(allocator, random, max_list_entries);
        errdefer epoch_authorized_voters.deinit(allocator);

        return .{
            .stakes = result_stakes,
            .total_stake = random.int(u64),
            .node_id_to_vote_accounts = node_id_to_vote_accounts,
            .epoch_authorized_voters = epoch_authorized_voters,
        };
    }
};

/// Analogous to [Stakes](https://github.com/anza-xyz/agave/blob/1f3ef3325fb0ce08333715aa9d92f831adc4c559/runtime/src/stakes.rs#L186).
/// It differs in that its delegation element parameterization is narrowed to only accept the specific types we actually need to implement.
pub fn Stakes(comptime delegation_type: enum {
    delegation,
    stake,
}) type {
    const Element = switch (delegation_type) {
        .delegation => Delegation,
        .stake => Stake,
    };

    return struct {
        vote_accounts: VoteAccounts,
        delegations: DelegationsMap,
        unused: u64,
        /// current epoch, used to calculate current stake
        epoch: Epoch,
        history: EpochAndStakeHistory,

        const Self = @This();
        pub const DelegationsMap = std.AutoArrayHashMapUnmanaged(Pubkey, Element);

        pub fn deinit(stakes: Self, allocator: Allocator) void {
            var copy = stakes;
            copy.vote_accounts.deinit(allocator);
            copy.delegations.deinit(allocator);
            copy.history.deinit(allocator);
        }

        pub fn clone(
            stakes: Self,
            allocator: Allocator,
        ) Allocator.Error!Self {
            const vote_accounts = try stakes.vote_accounts.clone(allocator);
            errdefer vote_accounts.deinit(allocator);

            var delegations = try stakes.delegations.clone(allocator);
            errdefer delegations.deinit(allocator);

            const history = try stakes.history.clone(allocator);
            errdefer allocator.free(history);

            return .{
                .vote_accounts = vote_accounts,
                .delegations = delegations,
                .unused = stakes.unused,
                .epoch = stakes.epoch,
                .history = history,
            };
        }

        pub fn initRandom(
            allocator: Allocator,
            /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
            /// for commentary on the runtime of this function.
            random: std.Random,
            max_list_entries: usize,
        ) Allocator.Error!Self {
            const vote_accounts = try VoteAccounts.initRandom(random, allocator, max_list_entries);
            errdefer vote_accounts.deinit(allocator);

            var delegations: DelegationsMap = .{};
            errdefer delegations.deinit(allocator);

            const delegations_count = random.uintAtMost(usize, max_list_entries);
            try delegations.ensureTotalCapacity(allocator, delegations_count);

            for (0..delegations_count) |_| {
                const key = Pubkey.initRandom(random);
                const gop = delegations.getOrPutAssumeCapacity(key);
                if (gop.found_existing) continue;
                gop.value_ptr.* = Element.initRandom(random);
            }

            const history = try stakeHistoryRandom(random, allocator, max_list_entries);
            errdefer allocator.free(history);

            return .{
                .vote_accounts = vote_accounts,
                .delegations = delegations,
                .unused = random.int(u64),
                .epoch = random.int(Epoch),
                .history = history,
            };
        }
    };
}

/// Analogous to [Delegation](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/sdk/program/src/stake/state.rs#L607)
pub const Delegation = struct {
    /// to whom the stake is delegated
    voter_pubkey: Pubkey,
    /// activated stake amount, set at delegate() time
    stake: u64,
    /// epoch at which this stake was activated, std::Epoch::MAX if is a bootstrap stake
    activation_epoch: Epoch,
    /// epoch the stake was deactivated, std::Epoch::MAX if not deactivated
    deactivation_epoch: Epoch,
    /// DEPRECATED: since 1.16.7
    deprecated_warmup_cooldown_rate: f64,

    pub fn initRandom(random: std.Random) Delegation {
        return .{
            .voter_pubkey = Pubkey.initRandom(random),
            .stake = random.int(u64),
            .activation_epoch = random.int(Epoch),
            .deactivation_epoch = random.int(Epoch),
            .deprecated_warmup_cooldown_rate = random.float(f64),
        };
    }
};

/// Analogous to [Stake](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/sdk/program/src/stake/state.rs#L918)
pub const Stake = struct {
    delegation: Delegation,
    /// Credits observed is credits from vote account state when delegated or redeemed.
    credits_observed: u64,

    pub fn initRandom(random: std.Random) Stake {
        return .{
            .delegation = Delegation.initRandom(random),
            .credits_observed = random.int(u64),
        };
    }
};

/// Analogous to [NodeVoteAccounts](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/runtime/src/epoch_stakes.rs#L14)
pub const NodeVoteAccounts = struct {
    vote_accounts: []const Pubkey,
    total_stake: u64,

    pub fn deinit(node_vote_accounts: NodeVoteAccounts, allocator: Allocator) void {
        allocator.free(node_vote_accounts.vote_accounts);
    }

    pub fn clone(
        node_vote_accounts: NodeVoteAccounts,
        allocator: Allocator,
    ) Allocator.Error!NodeVoteAccounts {
        return .{
            .vote_accounts = try allocator.dupe(Pubkey, node_vote_accounts.vote_accounts),
            .total_stake = node_vote_accounts.total_stake,
        };
    }

    pub fn initRandom(
        random: std.Random,
        allocator: Allocator,
        max_list_entries: usize,
    ) Allocator.Error!NodeVoteAccounts {
        const vote_accounts =
            try allocator.alloc(Pubkey, random.uintLessThan(usize, max_list_entries));
        errdefer allocator.free(vote_accounts);
        for (vote_accounts) |*vote_account| vote_account.* = Pubkey.initRandom(random);
        return .{
            .vote_accounts = vote_accounts,
            .total_stake = random.int(u64),
        };
    }
};

/// Analogous to [NodeIdToVoteAccounts](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/runtime/src/epoch_stakes.rs#L9)
pub const NodeIdToVoteAccountsMap = std.AutoArrayHashMapUnmanaged(Pubkey, NodeVoteAccounts);

pub fn nodeIdToVoteAccountsMapRandom(
    allocator: Allocator,
    random: std.Random,
    max_list_entries: usize,
) Allocator.Error!NodeIdToVoteAccountsMap {
    var node_id_to_vote_accounts = NodeIdToVoteAccountsMap.Managed.init(allocator);
    errdefer deinitMapAndValues(allocator, node_id_to_vote_accounts.unmanaged);

    try sig.rand.fillHashmapWithRng(
        &node_id_to_vote_accounts,
        random,
        random.uintAtMost(usize, max_list_entries),
        struct {
            allocator: Allocator,
            max_list_entries: usize,

            pub fn randomKey(_: @This(), rand: std.Random) !Pubkey {
                return Pubkey.initRandom(rand);
            }

            pub fn randomValue(ctx: @This(), rand: std.Random) !NodeVoteAccounts {
                return try NodeVoteAccounts.initRandom(rand, ctx.allocator, ctx.max_list_entries);
            }
        }{
            .allocator = allocator,
            .max_list_entries = max_list_entries,
        },
    );

    return node_id_to_vote_accounts.unmanaged;
}

/// Analogous to [EpochAuthorizedVoters](https://github.com/anza-xyz/agave/blob/42df56cac041077e471655579d6189a389c53882/runtime/src/epoch_stakes.rs#L10)
pub const EpochAuthorizedVoters = std.AutoArrayHashMapUnmanaged(Pubkey, Pubkey);

pub fn epochAuthorizedVotersRandom(
    allocator: Allocator,
    random: std.Random,
    max_list_entries: usize,
) Allocator.Error!EpochAuthorizedVoters {
    var epoch_authorized_voters = EpochAuthorizedVoters.Managed.init(allocator);
    errdefer epoch_authorized_voters.deinit();

    try sig.rand.fillHashmapWithRng(
        &epoch_authorized_voters,
        random,
        random.uintAtMost(usize, max_list_entries),
        struct {
            pub fn randomKey(rand: std.Random) !Pubkey {
                return Pubkey.initRandom(rand);
            }
            pub fn randomValue(rand: std.Random) !Pubkey {
                return Pubkey.initRandom(rand);
            }
        },
    );

    return epoch_authorized_voters.unmanaged;
}

/// Analogous to [VersionedEpochStake](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/runtime/src/epoch_stakes.rs#L137)
pub const VersionedEpochStake = union(enum(u32)) {
    current: Current,

    pub fn deinit(self: VersionedEpochStake, allocator: Allocator) void {
        switch (self) {
            .current => |current| current.deinit(allocator),
        }
    }

    pub fn initRandom(
        allocator: Allocator,
        random: std.Random,
        max_list_entries: usize,
    ) Allocator.Error!VersionedEpochStake {
        // randomly generate the tag otherwise
        comptime std.debug.assert(@typeInfo(VersionedEpochStake).@"union".fields.len == 1);
        return .{
            .current = try Current.initRandom(allocator, random, max_list_entries),
        };
    }

    pub fn clone(self: *const VersionedEpochStake, allocator: Allocator) !VersionedEpochStake {
        return switch (self.*) {
            .current => |current| .{ .current = try current.clone(allocator) },
        };
    }

    pub const Current = struct {
        stakes: Stakes(.stake),
        total_stake: u64,
        node_id_to_vote_accounts: NodeIdToVoteAccountsMap,
        epoch_authorized_voters: EpochAuthorizedVoters,

        pub fn deinit(self: Current, allocator: Allocator) void {
            self.stakes.deinit(allocator);
            deinitMapAndValues(allocator, self.node_id_to_vote_accounts);
            var epoch_authorized_voters = self.epoch_authorized_voters;
            epoch_authorized_voters.deinit(allocator);
        }

        pub fn initRandom(
            allocator: Allocator,
            random: std.Random,
            max_list_entries: usize,
        ) Allocator.Error!Current {
            const stakes = try Stakes(.stake).initRandom(allocator, random, max_list_entries);
            errdefer stakes.deinit(allocator);

            const node_id_to_vote_accounts = try nodeIdToVoteAccountsMapRandom(
                allocator,
                random,
                max_list_entries,
            );
            errdefer deinitMapAndValues(allocator, node_id_to_vote_accounts);

            var epoch_authorized_voters =
                try epochAuthorizedVotersRandom(allocator, random, max_list_entries);
            errdefer epoch_authorized_voters.deinit(allocator);

            return .{
                .stakes = stakes,
                .total_stake = random.int(u64),
                .node_id_to_vote_accounts = node_id_to_vote_accounts,
                .epoch_authorized_voters = epoch_authorized_voters,
            };
        }

        pub fn clone(self: *const Current, allocator: Allocator) !Current {
            const stakes = try self.stakes.clone(allocator);
            errdefer stakes.deinit(allocator);

            const node_id_to_vote_accounts =
                try cloneMapAndValues(allocator, self.node_id_to_vote_accounts);
            errdefer deinitMapAndValues(allocator, node_id_to_vote_accounts);

            const epoch_authorized_voters = try self.epoch_authorized_voters.clone(allocator);
            errdefer epoch_authorized_voters.deinit(allocator);

            return .{
                .stakes = stakes,
                .total_stake = self.total_stake,
                .node_id_to_vote_accounts = node_id_to_vote_accounts,
                .epoch_authorized_voters = epoch_authorized_voters,
            };
        }
    };
};

/// Analogous to [StakeHistoryEntry](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/sdk/program/src/stake_history.rs#L17)
pub const StakeHistoryEntry = struct {
    /// effective stake at this epoch
    effective: u64,
    /// sum of portion of stakes not fully warmed up
    activating: u64,
    /// requested to be cooled down, not fully deactivated yet
    deactivating: u64,

    pub fn initRandom(random: std.Random) StakeHistoryEntry {
        return .{
            .effective = random.int(u64),
            .activating = random.int(u64),
            .deactivating = random.int(u64),
        };
    }
};

pub const EpochAndStakeHistoryEntry = struct {
    epoch: Epoch,
    history_entry: StakeHistoryEntry,

    pub fn initRandom(random: std.Random) EpochAndStakeHistoryEntry {
        return .{
            .epoch = random.int(Epoch),
            .history_entry = StakeHistoryEntry.initRandom(random),
        };
    }
};

/// Analogous to [StakeHistory](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/sdk/program/src/stake_history.rs#L62)
pub const EpochAndStakeHistory = std.ArrayListUnmanaged(EpochAndStakeHistoryEntry);

pub fn stakeHistoryRandom(
    random: std.Random,
    allocator: Allocator,
    max_list_entries: usize,
) Allocator.Error!EpochAndStakeHistory {
    const stake_history_len = random.uintAtMost(usize, max_list_entries);

    const stake_history = try allocator.alloc(EpochAndStakeHistoryEntry, stake_history_len);
    errdefer allocator.free(stake_history);

    for (stake_history) |*entry| entry.* = EpochAndStakeHistoryEntry.initRandom(random);

    return EpochAndStakeHistory.fromOwnedSlice(stake_history);
}

pub const StakeAndVoteAccount = struct { u64, VoteAccount };

pub const StakeAndVoteAccountsMap = std.AutoArrayHashMapUnmanaged(Pubkey, StakeAndVoteAccount);

pub fn stakeAndVoteAccountsMapDeinit(
    map: StakeAndVoteAccountsMap,
    allocator: Allocator,
) void {
    var copy = map;
    for (copy.values()) |stake_and_vote_account| {
        _, const vote_account = stake_and_vote_account;
        vote_account.deinit(allocator);
    }
    copy.deinit(allocator);
}

pub fn stakeAndVoteAccountsMapClone(
    map: StakeAndVoteAccountsMap,
    allocator: Allocator,
) Allocator.Error!StakeAndVoteAccountsMap {
    var cloned: StakeAndVoteAccountsMap = .{};
    errdefer stakeAndVoteAccountsMapDeinit(cloned, allocator);

    try cloned.ensureTotalCapacity(allocator, map.count());
    for (map.keys(), map.values()) |key, value| {
        const stake, const vote_account = value;
        const vote_account_cloned = try vote_account.clone(allocator);
        cloned.putAssumeCapacityNoClobber(key, .{ stake, vote_account_cloned });
    }

    return cloned;
}

pub fn stakeAndVoteAccountsMapClearRetainingCapacity(
    map: *StakeAndVoteAccountsMap,
    allocator: Allocator,
) void {
    for (map.values()) |pair| {
        _, const vote_account = pair;
        vote_account.deinit(allocator);
    }
    map.clearRetainingCapacity();
}

pub fn stakeAndVoteAccountsMapRandom(
    random: std.Random,
    allocator: Allocator,
    max_list_entries: usize,
) Allocator.Error!StakeAndVoteAccountsMap {
    var result: StakeAndVoteAccountsMap = .{};
    errdefer stakeAndVoteAccountsMapDeinit(result, allocator);

    const entry_count = random.uintAtMost(usize, max_list_entries);
    try result.ensureTotalCapacity(allocator, entry_count);
    for (0..entry_count) |_| {
        const key = Pubkey.initRandom(random);
        const gop = result.getOrPutAssumeCapacity(key);
        if (gop.found_existing) continue;
        const value = try VoteAccount.initRandom(
            random,
            allocator,
            max_list_entries,
            error{ RandomError1, RandomError2, RandomError3 },
        );
        gop.value_ptr.* = .{ random.int(u64), value };
    }

    return result;
}

/// Analogous to [VoteAccounts](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/vote/src/vote_account.rs#L44)
pub const VoteAccounts = struct {
    accounts: StakeAndVoteAccountsMap,
    staked_nodes: ?StakedNodesMap,

    pub const @"!bincode-config:staked_nodes" = bincode.FieldConfig(?StakedNodesMap){
        .skip = true,
        .default_value = @as(?StakedNodesMap, null),
    };

    pub const StakedNodesMap = std.AutoArrayHashMapUnmanaged(
        Pubkey, // VoteAccount.vote_state.node_pubkey.
        u64, // Total stake across all vote-accounts.
    );

    pub fn deinit(
        vote_accounts: VoteAccounts,
        allocator: Allocator,
    ) void {
        var copy = vote_accounts;

        for (copy.accounts.values()) |entry| {
            _, const vote_account = entry;
            vote_account.deinit(allocator);
        }
        copy.accounts.deinit(allocator);

        if (copy.staked_nodes) |*staked_nodes| {
            staked_nodes.deinit(allocator);
        }
    }

    pub fn clone(
        vote_accounts: VoteAccounts,
        allocator: Allocator,
    ) Allocator.Error!VoteAccounts {
        const accounts = try stakeAndVoteAccountsMapClone(vote_accounts.accounts, allocator);
        errdefer stakeAndVoteAccountsMapDeinit(accounts, allocator);

        var staked_nodes: ?StakedNodesMap =
            if (vote_accounts.staked_nodes) |map| try map.clone(allocator) else null;
        errdefer if (staked_nodes) |*map| map.deinit(allocator);

        return .{
            .accounts = accounts,
            .staked_nodes = staked_nodes,
        };
    }

    pub fn stakedNodes(self: *VoteAccounts, allocator: Allocator) !*const StakedNodesMap {
        if (self.staked_nodes) |*staked_nodes| {
            return staked_nodes;
        }
        const vote_accounts = self.accounts;
        var staked_nodes = std.AutoArrayHashMap(Pubkey, u64).init(allocator);
        var iter = vote_accounts.iterator();
        while (iter.next()) |vote_entry| {
            if (vote_entry.value_ptr[0] == 0) continue;
            const vote_state = try vote_entry.value_ptr[1].voteState();
            const node_entry = try staked_nodes.getOrPut(vote_state.node_pubkey);
            if (!node_entry.found_existing) {
                node_entry.value_ptr.* = 0;
            }
            node_entry.value_ptr.* += vote_entry.value_ptr[0];
        }
        self.staked_nodes = staked_nodes.unmanaged;
        return &self.staked_nodes.?;
    }

    /// NOTE: in the original agave code, this method returns 0 instead of null.
    pub fn getDelegatedStake(self: VoteAccounts, pubkey: Pubkey) u64 {
        const stake, _ = self.accounts.get(pubkey) orelse return 0;
        return stake;
    }

    pub fn initRandom(
        random: std.Random,
        allocator: Allocator,
        max_list_entries: usize,
    ) Allocator.Error!VoteAccounts {
        var stakes_vote_accounts = StakeAndVoteAccountsMap.Managed.init(allocator);
        errdefer stakes_vote_accounts.deinit();

        errdefer for (stakes_vote_accounts.values()) |pair| {
            _, const vote_account = pair;
            vote_account.account.deinit(allocator);
        };

        try sig.rand.fillHashmapWithRng(
            &stakes_vote_accounts,
            random,
            random.uintAtMost(usize, max_list_entries),
            struct {
                allocator: Allocator,
                max_list_entries: usize,

                pub fn randomKey(_: @This(), rand: std.Random) !Pubkey {
                    return Pubkey.initRandom(rand);
                }
                pub fn randomValue(ctx: @This(), rand: std.Random) !StakeAndVoteAccount {
                    const vote_account: VoteAccount = try VoteAccount.initRandom(
                        rand,
                        ctx.allocator,
                        ctx.max_list_entries,
                        error{ RandomError1, RandomError2, RandomError3 },
                    );
                    errdefer vote_account.deinit(ctx.allocator);
                    return .{ rand.int(u64), vote_account };
                }
            }{
                .allocator = allocator,
                .max_list_entries = max_list_entries,
            },
        );

        var stakes_maybe_staked_nodes =
            if (random.boolean()) std.AutoArrayHashMap(Pubkey, u64).init(allocator) else null;
        errdefer if (stakes_maybe_staked_nodes) |*staked_nodes| staked_nodes.deinit();

        if (stakes_maybe_staked_nodes) |*staked_nodes| {
            try sig.rand.fillHashmapWithRng(
                staked_nodes,
                random,
                random.uintAtMost(usize, max_list_entries),
                struct {
                    pub fn randomKey(rand: std.Random) !Pubkey {
                        return Pubkey.initRandom(rand);
                    }
                    pub fn randomValue(rand: std.Random) !u64 {
                        return rand.int(u64);
                    }
                },
            );
        }

        return .{
            .accounts = stakes_vote_accounts.unmanaged,
            .staked_nodes = if (stakes_maybe_staked_nodes) |staked_nodes|
                staked_nodes.unmanaged
            else
                null,
        };
    }
};

pub const VoteAccount = struct {
    account: Account,
    vote_state: ?anyerror!VoteState = null,

    pub const @"!bincode-config:vote_state" =
        bincode.FieldConfig(?anyerror!VoteState){ .skip = true };

    pub fn deinit(vote_account: VoteAccount, allocator: Allocator) void {
        vote_account.account.deinit(allocator);
    }

    pub fn clone(
        vote_account: VoteAccount,
        allocator: Allocator,
    ) Allocator.Error!VoteAccount {
        const account = try vote_account.account.cloneOwned(allocator);
        errdefer account.deinit(allocator);
        return .{
            .account = account,
            .vote_state = vote_account.vote_state,
        };
    }

    pub fn voteState(self: *@This()) !VoteState {
        if (self.vote_state) |vs| {
            return vs;
        }
        const assert_alloc = sig.utils.allocators.failing.allocator(.{
            .alloc = .assert,
            .resize = .assert,
            .free = .assert,
        });

        var data_iter = self.account.data.iterator();
        const vote_state = bincode.read(
            assert_alloc,
            VoteState,
            data_iter.reader(),
            .{},
        );
        self.vote_state = vote_state;
        return vote_state;
    }

    pub fn initRandom(
        random: std.Random,
        allocator: Allocator,
        max_list_entries: usize,
        comptime RandomErrorSet: type,
    ) Allocator.Error!VoteAccount {
        const account =
            try Account.initRandom(allocator, random, random.uintAtMost(usize, max_list_entries));
        errdefer account.deinit(allocator);

        const vote_state: ?anyerror!VoteState =
            switch (random.enumValue(enum { null, err, value })) {
                .null => null,
                .err => @as(anyerror!VoteState, sig.rand.errorValue(random, RandomErrorSet)),
                .value => VoteState.initRandom(random),
            };

        return .{
            .account = account,
            .vote_state = vote_state,
        };
    }
};

pub const VoteState = struct {
    /// The variant of the rust enum
    tag: u32, // TODO: consider varint bincode serialization (in rust this is enum)
    /// the node that votes in this account
    node_pubkey: Pubkey,

    pub fn initRandom(random: std.Random) VoteState {
        return .{
            .tag = 0, // must always be 0, since this is the enum tag
            .node_pubkey = Pubkey.initRandom(random),
        };
    }
};

test "deserialize VoteState.node_pubkey" {
    const bytes = .{
        2,  0,   0,   0, 60,  155, 13,  144, 187, 252, 153, 72,  190, 35,  87,  94,  7,  178,
        90, 174, 158, 6, 199, 179, 134, 194, 112, 248, 166, 232, 144, 253, 128, 249, 67, 118,
    } ++ .{0} ** 1586 ++ .{ 31, 0, 0, 0, 0, 0, 0, 0, 1 } ++ .{0} ** 24;
    const vote_state = try bincode.readFromSlice(undefined, VoteState, &bytes, .{});
    const expected_pubkey =
        try Pubkey.parseBase58String("55abJrqFnjm7ZRB1noVdh7BzBe3bBSMFT3pt16mw6Vad");
    try std.testing.expect(expected_pubkey.equals(&vote_state.node_pubkey));
}
