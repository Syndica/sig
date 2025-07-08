const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

// const Account = sig.core.account.Account;
const Epoch = sig.core.time.Epoch;
const Pubkey = sig.core.pubkey.Pubkey;
const VoteAccounts = sig.core.vote_accounts.VoteAccounts;
const Delegation = sig.core.stake_accounts.Delegation;
const Stake = sig.core.stake_accounts.Stake;
const StakeAccount = sig.core.stake_accounts.StakeAccount;
const Stakes = sig.core.stake_accounts.Stakes;

const StakeHistory = sig.runtime.sysvar.StakeHistory;

// Improve the dependencies.
const vote_program = sig.runtime.program.vote;
// const Lockout = vote_program.state.Lockout;

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const VoteAccounts = sig.core.vote_accounts.VoteAccounts;
const VoteAccount = sig.core.vote_accounts.VoteAccount;

const AccountSharedData = sig.runtime.AccountSharedData;
const VersionedVoteState = sig.runtime.program.vote.state.VoteStateVersions;
const Rent = sig.runtime.sysvar.Rent;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const StakeState = sig.runtime.sysvar.StakeHistory.StakeState;

const RwMux = sig.sync.RwMux;

const createVoteAccount = sig.core.vote_accounts.createVoteAccount;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

pub fn StakesCacheGeneric(comptime stakes_type: StakesType) type {
    const StakesT = Stakes(stakes_type);

    return struct {
        stakes: RwMux(StakesT),

        const Self = @This();

        pub fn T() type {
            return StakesT;
        }

        pub fn init(allocator: Allocator) Allocator.Error!Self {
            return .{ .stakes = RwMux(StakesT).init(try StakesT.init(allocator)) };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            var stakes: *StakesT, var stakes_guard = self.stakes.writeWithLock();
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
                    var stakes: *StakesT, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    try stakes.removeStakeAccount(allocator, pubkey, new_rate_activation_epoch);
                }
                return;
            }

            if (vote_program.ID.equals(&account.owner)) {
                if (!VersionedVoteState.isCorrectSizeAndInitialized(account.data)) {
                    var stakes: *StakesT, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    try stakes.removeVoteAccount(allocator, pubkey);
                    return;
                }

                const vote_account = VoteAccount.fromAccountSharedData(
                    allocator,
                    try account.clone(allocator),
                ) catch {
                    var stakes: *StakesT, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    try stakes.removeVoteAccount(allocator, pubkey);
                    return;
                };

                var stakes: *StakesT, var stakes_guard = self.stakes.writeWithLock();
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
                    var stakes: *StakesT, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    try stakes.removeStakeAccount(allocator, pubkey, new_rate_activation_epoch);
                    return;
                };

                var stakes: *StakesT, var stakes_guard = self.stakes.writeWithLock();
                defer stakes_guard.unlock();
                try stakes.upsertStakeAccount(
                    allocator,
                    pubkey,
                    stake_account,
                    new_rate_activation_epoch,
                );
            }
        }
    };
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
};
