const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const Epoch = sig.core.time.Epoch;
const Pubkey = sig.core.pubkey.Pubkey;
const Stakes = sig.core.stake.Stakes;

const StakeHistory = sig.runtime.sysvar.StakeHistory;

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
        const stake_history = try StakeHistory.initWithEntries(allocator, &.{.{
            .epoch = 0,
            .stake = .{
                .effective = 0,
                .activating = 0,
                .deactivating = 0,
            },
        }});

        return .{
            .total_stake = 0,
            .stakes = .{
                .vote_accounts = .{},
                .stake_delegations = .{},
                .unused = 0,
                .epoch = 0,
                .stake_history = stake_history,
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
pub const VersionedEpochStakes = union(enum(u32)) {
    current: Current,

    pub fn deinit(self: VersionedEpochStakes, allocator: Allocator) void {
        switch (self) {
            .current => |current| current.deinit(allocator),
        }
    }

    pub fn initRandom(
        allocator: Allocator,
        random: std.Random,
        max_list_entries: usize,
    ) Allocator.Error!VersionedEpochStakes {
        // randomly generate the tag otherwise
        comptime std.debug.assert(@typeInfo(VersionedEpochStakes).@"union".fields.len == 1);
        return .{
            .current = try Current.initRandom(allocator, random, max_list_entries),
        };
    }

    pub fn clone(self: *const VersionedEpochStakes, allocator: Allocator) !VersionedEpochStakes {
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
