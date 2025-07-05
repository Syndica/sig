const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;

const bincode = sig.bincode;
const vote_program = sig.runtime.program.vote;
const stake_program = sig.runtime.program.stake;

const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const VoteAccounts = sig.core.vote_accounts.VoteAccounts;
const VoteAccount = sig.core.vote_accounts.VoteAccount;

const AccountSharedData = sig.runtime.AccountSharedData;
const VersionedVoteState = sig.runtime.program.vote.state.VoteStateVersions;
const Rent = sig.runtime.sysvar.Rent;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const ClusterStake = sig.runtime.sysvar.StakeHistory.ClusterStake;

const RwMux = sig.sync.RwMux;

const createVoteAccount = sig.core.vote_accounts.createVoteAccount;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

pub fn StakesCacheGeneric(comptime stakes_type: StakesType) type {
    const StakesT = Stakes(stakes_type);

    return struct {
        stakes: RwMux(StakesT),

        const Self = @This();

        pub fn default() Self {
            return .{ .stakes = RwMux(StakesT).init(StakesT.DEFAULT) };
        }

        pub fn deinit(self: *Self, allocator: Allocator) void {
            var stakes: *StakesT, var stakes_guard = self.stakes.writeWithLock();
            defer stakes_guard.unlock();
            stakes.deinit(allocator);
        }

        pub fn checkAndStore(
            self: *Self,
            allocator: Allocator,
            pubkey: Pubkey,
            account: AccountSharedData,
            new_rate_activation_epoch: ?Epoch,
        ) Allocator.Error!void {
            if (account.lamports == 0) {
                if (vote_program.ID.equals(&account.owner)) {
                    var stakes, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    stakes.removeVoteAccount(allocator, pubkey);
                } else if (stake_program.ID.equals(&account.owner)) {
                    var stakes: *StakesT, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    stakes.removeStakeAccount(allocator, pubkey, new_rate_activation_epoch);
                }
                return;
            }

            if (vote_program.ID.equals(&account.owner)) {
                if (VersionedVoteState.isCorrectSizeAndInitialized(account.data)) {
                    const vote_account = VoteAccount.fromAccountSharedData(
                        allocator,
                        try account.clone(allocator),
                    ) catch {
                        var stakes: *StakesT, var stakes_guard = self.stakes.writeWithLock();
                        defer stakes_guard.unlock();
                        stakes.removeVoteAccount(allocator, pubkey);
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
                } else {
                    var stakes: *StakesT, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    stakes.removeVoteAccount(allocator, pubkey);
                }
            } else if (stake_program.ID.equals(&account.owner)) {
                const stake_account = StakeAccount.fromAccountSharedData(
                    allocator,
                    try account.clone(allocator),
                ) catch {
                    var stakes: *StakesT, var stakes_guard = self.stakes.writeWithLock();
                    defer stakes_guard.unlock();
                    stakes.removeStakeAccount(allocator, pubkey, new_rate_activation_epoch);
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
//    - `Bank::new_from_paths` - populates the epoch_stakes from epoch 0 to leader schedule epoch
//    - `Bank::get_fields_to_serialize` - splits the epoch_stakes into EpochStakes and VersionedEpochStakes
//    - `Bank::update_epoch_stakes` - removes old entries, creates and inserts a new entry using bank.stakes_cache.stakes()
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
    account,
};

// pub const Stakes = StakesGeneric(.stake);

pub fn Stakes(comptime stakes_type: StakesType) type {
    const T = switch (stakes_type) {
        .delegation => Delegation,
        .stake => Stake,
        .account => StakeAccount,
    };
    const is_account_type = stakes_type == .account;

    return struct {
        vote_accounts: VoteAccounts,
        stake_delegations: std.AutoArrayHashMapUnmanaged(Pubkey, T),
        unused: u64,
        epoch: Epoch,
        stake_history: StakeHistory,

        const Self = @This();

        pub const DEFAULT: Self = .{
            .vote_accounts = .{},
            .stake_delegations = .{},
            .unused = 0,
            .epoch = 0,
            .stake_history = .{},
        };

        pub fn deinit(self: *const Self, allocator: Allocator) void {
            self.vote_accounts.deinit(allocator);
            if (is_account_type) for (self.stake_delegations.values()) |*v| v.deinit(allocator);
            var delegations = self.stake_delegations;
            delegations.deinit(allocator);
            self.stake_history.deinit(allocator);
        }

        pub fn clone(self: *const Self, allocator: Allocator) Allocator.Error!Self {
            const vote_accs = try self.vote_accounts.clone(allocator);
            errdefer vote_accs.deinit(allocator);

            var stake_delegations = std.AutoArrayHashMapUnmanaged(Pubkey, T){};
            errdefer {
                if (is_account_type) for (stake_delegations.values()) |*v| v.deinit(allocator);
                stake_delegations.deinit(allocator);
            }
            for (self.stake_delegations.keys(), self.stake_delegations.values()) |key, value|
                try stake_delegations.put(
                    allocator,
                    key,
                    if (is_account_type) value.clone(allocator) else value,
                );

            const stake_history = try self.stake_history.clone(allocator);
            errdefer stake_history.deinit(allocator);

            return .{
                .vote_accounts = vote_accs,
                .stake_delegations = stake_delegations,
                .unused = self.unused,
                .epoch = self.epoch,
                .stake_history = stake_history,
            };
        }

        pub fn calculateStake(
            self: *const Self,
            pubkey: Pubkey,
            new_rate_activation_epoch: ?Epoch,
        ) u64 {
            var stake: u64 = 0;
            for (self.stake_delegations.values()) |*stake_delegations| {
                const delegation = stake_delegations.getDelegation();
                if (!delegation.voter_pubkey.equals(&pubkey)) continue;
                stake += delegation.getStake(
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
        ) Allocator.Error!void {
            std.debug.assert(account.account.lamports > 0);
            errdefer account.deinit(allocator);

            // TODO: move this function call into vote accounts insert to prevent execution
            // on failure paths in vote_accounts.insert
            const stake = self.calculateStake(pubkey, new_rate_activation_epoch);

            const maybe_old_account = try self.vote_accounts.insert(
                allocator,
                pubkey,
                account,
                stake,
            );

            if (maybe_old_account) |old_account| old_account.deinit(allocator);
        }

        pub fn removeVoteAccount(
            self: *Self,
            allocator: Allocator,
            pubkey: Pubkey,
        ) void {
            self.vote_accounts.remove(allocator, pubkey);
        }

        /// Takes ownership of `account` iff `stakes_type` is `account`.
        pub fn upsertStakeAccount(
            self: *Self,
            allocator: Allocator,
            pubkey: Pubkey,
            account: StakeAccount,
            new_rate_activation_epoch: ?Epoch,
        ) Allocator.Error!void {
            std.debug.assert(account.account.lamports > 0);
            defer if (!is_account_type) account.deinit(allocator);
            errdefer if (is_account_type) account.deinit(allocator);

            const delegation = account.getDelegation();
            const voter_pubkey = delegation.voter_pubkey;
            const stake = delegation.getStake(
                self.epoch,
                &self.stake_history,
                new_rate_activation_epoch,
            );

            const entry = switch (stakes_type) {
                .delegation => account.getDelegation(),
                .stake => account.getStake(),
                .account => account,
            };

            if (try self.stake_delegations.fetchPut(
                allocator,
                pubkey,
                entry,
            )) |old_account_entry| {
                const old_account: T = old_account_entry.value;
                defer if (is_account_type) old_account.deinit(allocator);

                const old_delegation = old_account.getDelegation();
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

        pub fn removeStakeAccount(
            self: *Self,
            allocator: Allocator,
            pubkey: Pubkey,
            new_rate_activation_epoch: ?Epoch,
        ) void {
            var account: T = (self.stake_delegations.fetchSwapRemove(pubkey) orelse return).value;
            defer if (is_account_type) account.deinit(allocator);

            const removed_delegation = account.getDelegation();
            const removed_stake = removed_delegation.getStake(
                self.epoch,
                &self.stake_history,
                new_rate_activation_epoch,
            );

            self.vote_accounts.subStake(removed_delegation.voter_pubkey, removed_stake);
        }

        pub fn initRandom(
            allocator: Allocator,
            random: std.Random,
            max_list_entries: usize,
        ) Allocator.Error!Self {
            const vote_accounts = try VoteAccounts.initRandom(allocator, random, max_list_entries);
            errdefer vote_accounts.deinit(allocator);

            var stake_delegations = std.AutoArrayHashMapUnmanaged(Pubkey, T){};
            errdefer {
                if (is_account_type) for (stake_delegations.values()) |*v| v.deinit(allocator);
                stake_delegations.deinit(allocator);
            }

            for (0..random.uintAtMost(usize, max_list_entries)) |_| {
                try stake_delegations.put(
                    allocator,
                    Pubkey.initRandom(random),
                    if (is_account_type) T.initRandom(allocator, random) else T.initRandom(random),
                );
            }

            const stake_history = try StakeHistory.initRandom(allocator, random);
            errdefer stake_history.deinit(allocator);

            return .{
                .vote_accounts = vote_accounts,
                .stake_delegations = stake_delegations,
                .unused = random.int(u64),
                .epoch = random.int(Epoch),
                .stake_history = stake_history,
            };
        }
    };
}

pub const StakeAccount = struct {
    account: AccountSharedData,
    state: StakeStateV2,

    pub fn deinit(self: *const StakeAccount, allocator: Allocator) void {
        self.account.deinit(allocator);
    }

    pub fn clone(self: *const StakeAccount, allocator: Allocator) Allocator.Error!StakeAccount {
        return .{
            .account = try self.account.clone(allocator),
            .state = self.state,
        };
    }

    pub fn getDelegation(self: StakeAccount) Delegation {
        return self.state.getDelegation() orelse
            @panic("StakeAccount does not have a delegation");
    }

    pub fn getStake(self: StakeAccount) Stake {
        return self.state.getStake() orelse
            @panic("StakeAccount does not have a stake");
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
    /// Credits observed is credits from vote account state when delegated or redeemed.
    credits_observed: u64,

    pub fn getDelegation(self: *const Stake) Delegation {
        return self.delegation;
    }

    pub fn initRandom(random: std.Random) Stake {
        return .{
            .delegation = Delegation.initRandom(random),
            .credits_observed = random.int(u64),
        };
    }
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

    pub fn isBootstrap(self: *const Delegation) bool {
        return self.activation_epoch == std.math.maxInt(u64);
    }

    pub fn getDelegation(self: *const Delegation) Delegation {
        return self.*;
    }

    pub fn getStake(
        self: *const Delegation,
        epoch: Epoch,
        stake_history: *const StakeHistory,
        new_rate_activation_epoch: ?Epoch,
    ) u64 {
        return self.getClusterStake(
            epoch,
            stake_history,
            new_rate_activation_epoch,
        ).effective;
    }

    /// TODO: Rename
    pub fn getClusterStake(
        self: *const Delegation,
        epoch: Epoch,
        history: *const StakeHistory,
        new_rate_activation_epoch: ?Epoch,
    ) ClusterStake {
        const effective_stake, const activating_stake = self.getClusterEffectiveAndActivatingStake(
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

                const weight = @as(f64, @floatFromInt(current_effective_stake)) /
                    @as(f64, @floatFromInt(prev_cluster_stake.deactivating));
                const warmup_cooldown_rate =
                    warmupCooldownRate(current_epoch, new_rate_activation_epoch);

                const newly_not_effective_cluster_stake =
                    @as(f64, @floatFromInt(prev_cluster_stake.effective)) * warmup_cooldown_rate;
                const wieghted_not_effective_state: u64 =
                    @intFromFloat(weight * newly_not_effective_cluster_stake);
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

    /// TODO: Rename
    pub fn getClusterEffectiveAndActivatingStake(
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
                const weight = @as(f64, @floatFromInt(remaining_activated_stake)) /
                    @as(f64, @floatFromInt(prev_cluster_stake.activating));
                const warmup_cooldown_rate =
                    warmupCooldownRate(current_epoch, new_rate_activation_epoch);

                const newly_effective_cluster_stake =
                    @as(f64, @floatFromInt(prev_cluster_stake.effective)) * warmup_cooldown_rate;
                const weighted_effective_state: u64 =
                    @intFromFloat(weight * newly_effective_cluster_stake);
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

const DEFAULT_WARMUP_COOLDOWN_RATE: f64 = 0.25;
const NEW_WARMUP_COOLDOWN_RATE: f64 = 0.09;

fn warmupCooldownRate(current_epoch: Epoch, new_rate_activation_epoch: ?Epoch) f64 {
    return if (current_epoch < new_rate_activation_epoch orelse std.math.maxInt(u64))
        DEFAULT_WARMUP_COOLDOWN_RATE
    else
        NEW_WARMUP_COOLDOWN_RATE;
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

const TestStakedNodeAccounts = struct {
    vote_pubkey: Pubkey,
    vote_account: AccountSharedData,
    stake_pubkey: Pubkey,
    stake_account: AccountSharedData,

    pub fn init(allocator: Allocator, random: std.Random, stake: u64) !TestStakedNodeAccounts {
        if (!builtin.is_test) @compileError("only for testing");

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
                null,
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
                null,
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

            var stakes_cache = StakesCacheGeneric(stakes_type).default();
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
                    stake.delegation.getStake(i, &StakeHistory.EMPTY, null),
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
                    stake.delegation.getStake(i, &StakeHistory.EMPTY, null),
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
                null,
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
                    stake.delegation.getStake(i, &StakeHistory.EMPTY, null),
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
