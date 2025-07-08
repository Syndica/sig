const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const Allocator = std.mem.Allocator;

const Account = sig.core.account.Account;
const Epoch = sig.core.time.Epoch;
const Pubkey = sig.core.pubkey.Pubkey;
const VoteAccounts = sig.core.vote_accounts.VoteAccounts;

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
        const history = try StakeHistory.initWithEntries(allocator, &.{.{
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
                .epoch = 0,
                .history = history,
                .vote_accounts = .{},
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

// NOTE: Comment from stakes enum in agave:
//
// For backward compatibility, we can only serialize and deserialize
// Stakes<Delegation> in the old `epoch_stakes` bank snapshot field. However,
// Stakes<StakeAccount> entries are added to the bank's epoch stakes hashmap
// when crossing epoch boundaries and Stakes<Stake> entries are added when
// starting up from bank snapshots that have the new epoch stakes field. By
// using this enum, the cost of converting all entries to Stakes<Delegation> is
// put off until serializing new snapshots. This helps avoid bogging down epoch
// boundaries and startup with the conversion overhead.
//
// The only difference between the Stake and Delegation types is that the Stake type contains
// a `credits_observed` field, why don't we just skip that in the serialization and use one type?
//
// The comes the question of the StakeAccount, which contains a StakeStateV2 and an AccountSharedData,
// which is a little more complex. However, as agave notes these entries are added to the epoch stakes
// on epoch boundaries from the stakes cache (I think... to confirm). It looks like the stakes cache may
// not actually need to contain the complete StakesStateV2, so we could benefit from some simplification
// there as well.
//
// To begin, lets take a look at the usage of EpochStakes in Agave.
//
// The Bank contains an 'epoch_stakes' field, which is a HashMap<Epoch, EpochStakes>.
//    - `Bank::new_from_paths` - populates the epoch_stakes from epoch 0 to leader schedule epoch -- uses StakesEnum::Accounts
//    - `Bank::get_fields_to_serialize` - splits the epoch_stakes into EpochStakes and VersionedEpochStakes
//    - `Bank::update_epoch_stakes` - removes old entries, creates and inserts a new entry using bank.stakes_cache.stakes() -- uses StakesEnum::Accounts
//    - a bunch of accessors methods

//
// pub struct EpochStakes {
//     #[serde(with = "serde_stakes_to_delegation_format")]
//     stakes: Arc<StakesEnum>,
//     total_stake: u64,
//     node_id_to_vote_accounts: Arc<HashMap<Pubkey, NodeVoteAccounts>>,
//     epoch_authorized_voters: Arc<HashMap<Pubkey, Pubkey>>,
//
//     pub fn new(stakes: Arc<StakesEnum>, leader_schedule_epoch: Epoch) -> Self
//     pub fn new_for_tests(vote_accounts_hash_map: VoteAccountsHashMap, leader_schedule_epoch: Epoch) -> Self
//     pub fn stakes(&self) -> &StakesEnum
//     pub fn total_stake(&self) -> u64
//     pub fn set_total_stake(&mut self, total_stake: u64)
//     pub fn node_id_to_vote_accounts(&self) -> &Arc<HashMap<Pubkey, NodeVoteAccounts>>
//     pub fn node_id_to_stake(&self, node_id: &Pubkey) -> Option<u64>
//     pub fn epoch_authorized_voters(&self) -> &Arc<HashMap<Pubkey, Pubkey>>
//     pub fn vote_account_stake(&self, vote_account: &Pubkey) -> u64
// }
// pub struct NodeVoteAccounts {
//     pub vote_accounts: Vec<Pubkey>,
//     pub total_stake: u64,
// }
// pub enum StakesEnum {
//     Accounts(Stakes<StakeAccount>),
//     Delegations(Stakes<Delegation>),
//     Stakes(Stakes<Stake>),
// }
// pub struct StakeAccount {
//     account: AccountSharedData,
//     stake_state: StakeStateV2,
// }
// pub struct Delegation {
//     pub voter_pubkey: Pubkey,
//     pub stake: u64,
//     pub activation_epoch: Epoch,
//     pub deactivation_epoch: Epoch,
//     pub warmup_cooldown_rate: f64, // deprecated since 1.16.7
// }
// pub struct Stake {
//     pub delegation: Delegation,
//     pub credits_observed: u64,
// }
//
// And also consider StakesCache
//
// pub(crate) struct StakesCache(RwLock<Stakes<StakeAccount>>);
//
// pub struct Stakes<T: Clone> {
//     pub vote_accounts: VoteAccounts,
//     pub stake_delegations: ImHashMap<Pubkey, T>,
//     pub unused: u64,
//     pub epoch: Epoch,
//     pub stake_history: StakeHistory,
// }
//
// Proposed Epoch Staked Nodes

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
        history: StakeHistory,

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
            const vote_accounts = try VoteAccounts.initRandom(allocator, random, max_list_entries);
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

            const history = try StakeHistory.initRandom(allocator, random);
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
