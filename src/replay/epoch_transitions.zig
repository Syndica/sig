const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicU64 = std.atomic.Value(u64);

const bincode = sig.bincode;
const features = sig.core.features;
const program = sig.runtime.program;
const builtin_programs = sig.runtime.program.builtin_programs;

const AccountsDb = sig.accounts_db.AccountsDB;
const AccountStore = sig.accounts_db.AccountStore;
const SlotAccountReader = sig.accounts_db.SlotAccountReader;

const Epoch = sig.core.Epoch;
const StakesCache = sig.core.StakesCache;
const Ancestors = sig.core.Ancestors;
const Account = sig.core.Account;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const ReservedAccounts = sig.core.ReservedAccounts;
const EpochStakes = sig.core.EpochStakes;
const EpochStakesMap = sig.core.EpochStakesMap;

const EpochTracker = sig.replay.trackers.EpochTracker;
const EpochConstants = sig.core.EpochConstants;
const SlotState = sig.core.SlotState;
const SlotConstants = sig.core.SlotConstants;
const AccountSharedData = sig.runtime.AccountSharedData;
const FeatureSet = sig.core.FeatureSet;
const Stakes = sig.core.Stakes;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const VoteAccounts = sig.core.vote_accounts.VoteAccounts;
const StakeAndVoteAccountsMap = sig.core.vote_accounts.StakeAndVoteAccountsMap;
const Delegation = sig.core.stake.Delegation;
const Stake = sig.core.stake.Stake;

const applyFeatureActivations = @import("apply_feature_activations.zig").applyFeatureActivations;

pub const SlotAccountStore = struct {
    slot: Slot,
    state: *SlotState,
    writer: AccountStore,
    reader: SlotAccountReader,

    pub fn init(
        slot: Slot,
        state: *SlotState,
        writer: AccountStore,
        ancestors: *const Ancestors,
    ) SlotAccountStore {
        return .{
            .slot = slot,
            .state = state,
            .writer = writer,
            .reader = writer.reader().forSlot(ancestors),
        };
    }

    pub fn get(self: *const SlotAccountStore, key: Pubkey) !?Account {
        return self.reader.get(key);
    }

    pub fn put(
        self: SlotAccountStore,
        key: Pubkey,
        account: AccountSharedData,
    ) !void {
        try self.writer.put(self.slot, key, account);
    }

    pub fn putAndUpdateCapitalization(
        self: SlotAccountStore,
        key: Pubkey,
        new_account: AccountSharedData,
    ) !void {
        const old_account_data_len = if (try self.get(key)) |old_account| blk: {
            const diff = if (new_account.lamports > old_account.lamports)
                new_account.lamports - old_account.lamports
            else
                old_account.lamports - new_account.lamports;
            _ = self.state.capitalization.fetchSub(diff, .monotonic);
            break :blk old_account.data.len();
        } else blk: {
            _ = self.state.capitalization.fetchAdd(new_account.lamports, .monotonic);
            break :blk 0;
        };

        try self.put(key, new_account);

        // NOTE: update account size delta in slot state?
        _ = old_account_data_len;
    }

    pub fn burnAndPurgeAccount(self: SlotAccountStore, key: Pubkey, account: AccountSharedData) !void {
        const account_data_len = account.data.len;

        _ = self.state.capitalization.fetchSub(account.lamports, .monotonic);
        var acc = account;
        acc.lamports = 0;
        @memset(acc.data, 0);
        try self.put(key, acc);

        // NOTE: update account size delta in slot state?
        _ = account_data_len;
    }

    pub fn putPrecompile(
        self: SlotAccountStore,
        allocator: Allocator,
        precompile: program.precompiles.Precompile,
    ) !void {
        const maybe_account = try self.get(precompile.program_id);
        defer if (maybe_account) |account| account.deinit(allocator);

        if (maybe_account) |account| if (!account.executable) {
            try self.burnAndPurgeAccount(
                precompile.program_id,
                try AccountSharedData.fromAccount(allocator, &account),
            );
        } else return;

        // assert!(!self.freeze_started()); NOTE: Do we need this?

        const lamports, const rent_epoch = inheritLamportsAndRentEpoch(maybe_account);

        try self.putAndUpdateCapitalization(
            precompile.program_id,
            .{
                .lamports = lamports,
                .data = &.{},
                .executable = true,
                .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                .rent_epoch = rent_epoch,
            },
        );
    }

    pub fn putBuiltinProgramAccount(
        self: SlotAccountStore,
        allocator: Allocator,
        builtin_program: builtin_programs.BuiltinProgram,
    ) !void {
        if (try self.reader.get(builtin_program.program_id)) |account| {
            if (sig.runtime.ids.NATIVE_LOADER_ID.equals(&account.owner)) return;
            const account_shared_data = try AccountSharedData.fromAccount(allocator, &account);
            defer allocator.free(account_shared_data.data);
            try self.burnAndPurgeAccount(builtin_program.program_id, account_shared_data);
        }

        const lamports, const rent_epoch = inheritLamportsAndRentEpoch(null);
        const account: AccountSharedData = .{
            .lamports = lamports,
            .data = try allocator.dupe(u8, builtin_program.data),
            .executable = true,
            .owner = sig.runtime.ids.NATIVE_LOADER_ID,
            .rent_epoch = rent_epoch,
        };
        defer allocator.free(account.data);

        try self.putAndUpdateCapitalization(builtin_program.program_id, account);
    }

    fn inheritLamportsAndRentEpoch(
        maybe_account: ?Account,
    ) struct { u64, u64 } {
        return if (maybe_account) |account|
            .{ account.lamports, account.rent_epoch }
        else
            .{ 1, 0 };
    }
};

/// Process a new epoch. This includes:
/// 1. Apply feature activations.
/// 2. Activate stakes cache for the new epoch.
/// 3. Update epoch stakes
/// 4. Begin partitioned rewards
pub fn process_new_epoch(
    allocator: Allocator,
    slot: Slot,
    slot_state: *SlotState,
    /// These are not constant until we process the new epoch
    slot_constants: *SlotConstants,
    epoch_tracker: *EpochTracker,
    account_store: AccountStore,
) !void {
    const slot_store = SlotAccountStore.init(
        slot,
        slot_state,
        account_store,
        &Ancestors.EMPTY,
    );

    try applyFeatureActivations(
        allocator,
        slot_store,
        &slot_constants.feature_set,
        &slot_constants.reserved_accounts,
        true, // allow_new_activations
    );

    // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L1623-L1631
    const current_epoch = epoch_tracker.schedule.getEpoch(slot);
    try activateEpoch(
        allocator,
        current_epoch,
        &slot_state.stakes_cache,
        null, // TODO: pass in new_rate_activation_epoch
    );

    // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L1632-L1636
    const parent_epoch = epoch_tracker.schedule.getEpoch(slot_constants.parent_slot);
    try updateEpochStakes(
        allocator,
        slot,
        parent_epoch,
        &slot_state.stakes_cache,
        epoch_tracker,
    );

    // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L1637-L1647
    // try beginPartitionedRewards();
}

pub fn updateEpochStakes(
    allocator: Allocator,
    slot: Slot,
    parent_epoch: Epoch,
    stakes_cache: *StakesCache,
    epoch_tracker: *EpochTracker,
) !void {
    const leader_schedule_epoch = epoch_tracker.schedule.getLeaderScheduleEpoch(slot);
    if (!epoch_tracker.epochs.contains(leader_schedule_epoch)) {
        const parent_epoch_constants = epoch_tracker.getForSlot(parent_epoch) orelse {
            return error.ParentEpochConstantsNotFound;
        };

        const epoch_stakes = try getEpochStakes(
            allocator,
            leader_schedule_epoch,
            stakes_cache,
        );
        errdefer epoch_stakes.deinit(allocator);

        const epoch_constants = EpochConstants{
            .hashes_per_tick = parent_epoch_constants.hashes_per_tick,
            .ticks_per_slot = parent_epoch_constants.ticks_per_slot,
            .ns_per_slot = parent_epoch_constants.ns_per_slot,
            .genesis_creation_time = parent_epoch_constants.genesis_creation_time,
            .slots_per_year = parent_epoch_constants.slots_per_year,
            .stakes = epoch_stakes,
            .rent_collector = parent_epoch_constants.rent_collector,
        };

        try epoch_tracker.put(allocator, leader_schedule_epoch, epoch_constants);
    }
}

pub fn getEpochStakes(
    allocator: Allocator,
    leader_schedule_epoch: Epoch,
    stakes_cache: *StakesCache,
) !EpochStakes {
    const stakes = blk: {
        const stakes, var stakes_lg = stakes_cache.stakes.readWithLock();
        defer stakes_lg.unlock();
        break :blk try stakes.clone(allocator);
    };
    const epoch_vote_accounts = stakes.vote_accounts.vote_accounts;

    var node_id_to_vote_accounts = std.AutoArrayHashMapUnmanaged(Pubkey, sig.core.epoch_stakes.NodeVoteAccounts){};
    errdefer sig.utils.collections.deinitMapAndValues(allocator, node_id_to_vote_accounts);

    var epoch_authorized_voters = std.AutoArrayHashMapUnmanaged(Pubkey, Pubkey){};
    errdefer epoch_authorized_voters.deinit(allocator);

    var total_stake: u64 = 0;
    for (epoch_vote_accounts.keys(), epoch_vote_accounts.values()) |key, stake_and_vote_account| {
        if (stake_and_vote_account.stake > 0) {
            total_stake += stake_and_vote_account.stake;

            var vote_state = stake_and_vote_account.account.state;
            if (vote_state.voters.getAuthorizedVoter(leader_schedule_epoch)) |authorized_voter| {
                const node_vote_accounts = try node_id_to_vote_accounts.getOrPut(allocator, authorized_voter);

                if (!node_vote_accounts.found_existing) {
                    node_vote_accounts.value_ptr.* = .EMPTY;
                }

                node_vote_accounts.value_ptr.total_stake += stake_and_vote_account.stake;
                try node_vote_accounts.value_ptr.vote_accounts.append(allocator, key);

                try epoch_authorized_voters.put(allocator, key, authorized_voter);
            }
        }
    }

    const new_stakes = try stakes.convert(allocator, .delegation);

    return .{
        .stakes = new_stakes,
        .total_stake = total_stake,
        .node_id_to_vote_accounts = node_id_to_vote_accounts,
        .epoch_authorized_voters = epoch_authorized_voters,
    };
}

pub fn activateEpoch(
    allocator: Allocator,
    epoch: Epoch,
    stakes_cache: *StakesCache,
    new_rate_activation_epoch: ?Epoch,
) !void {
    const stakes, var stakes_lg = stakes_cache.stakes.writeWithLock();
    defer stakes_lg.unlock();

    const stake_delegations = stakes.stake_delegations.values();
    var stake_history_entry = StakeHistory.StakeState.DEFAULT;
    for (stake_delegations) |stake_delegation| {
        const delegation = stake_delegation.getDelegation();
        stake_history_entry.add(delegation.getStakeState(
            epoch,
            stakes.stake_history,
            new_rate_activation_epoch,
        ));
    }

    try stakes.stake_history.insertEntry(epoch, stake_history_entry);
    stakes.epoch = epoch;
    stakes.vote_accounts = try refreshVoteAccounts(
        allocator,
        epoch,
        stakes.vote_accounts.vote_accounts,
        stakes.stake_delegations.values(),
        stakes.stake_history,
        new_rate_activation_epoch,
    );
}

pub fn refreshVoteAccounts(
    allocator: Allocator,
    epoch: Epoch,
    stake_and_vote_accounts: StakeAndVoteAccountsMap,
    stake_delegations: []Delegation,
    stake_history: StakeHistory,
    new_activation_rate_epoch: ?Epoch,
) !VoteAccounts {
    var delegated_stakes = std.AutoArrayHashMapUnmanaged(Pubkey, u64){};
    errdefer delegated_stakes.deinit(allocator);

    for (stake_delegations) |stake_delegation| {
        const delegation = stake_delegation.getDelegation();
        const entry = try delegated_stakes.getOrPut(allocator, delegation.voter_pubkey);
        if (!entry.found_existing) {
            entry.value_ptr.* = 0;
        }
        entry.value_ptr.* += delegation.getStake(
            epoch,
            stake_history,
            new_activation_rate_epoch,
        );
    }

    var new_vote_accounts = VoteAccounts{};
    errdefer new_vote_accounts.deinit(allocator);
    for (stake_and_vote_accounts.keys(), stake_and_vote_accounts.values()) |vote_pubkey, stake_and_vote_account| {
        const delegated_stake = delegated_stakes.get(vote_pubkey) orelse 0;
        try new_vote_accounts.vote_accounts.put(allocator, vote_pubkey, .{
            .stake = delegated_stake,
            .account = try stake_and_vote_account.account.clone(allocator),
        });
    }

    return new_vote_accounts;
}

// pub fn beginPartitionedRewards() !void {
//     // TODO: Implement partitioned rewards logic
// }

// pub const PartitionedStakeRewards = struct {
//     stake_pubkey: Pubkey,
//     stake: Stake,
//     stake_reward: u64,
//     commission: u8,
// };

// pub const CalculateRewardsAndDistributeRewardsResult = struct {
//     distribute_rewards: u64,
//     point_value: u64,
//     stake_rewards: []PartitionedStakeRewards, // TODO: make reference counted
// };

// pub fn calculateRewardsAndDistributeVoteRewards(
//     allocator: Allocator,
//     previous_epoch: Epoch,
//     // reward_calc_tracer,
//     // rewards_metrics,
// ) !void {
//     _ = allocator;
//     _ = previous_epoch;
// }

// pub fn calculateRewardsForPartitioning(
//     previous_epoch: Epoch,
// ) !void {}

// pub fn getRewardDistributionNumBlocks() u64 {
//     // TODO: Implement
//     return 0;
// }

// pub fn setEpochRewardsStatusCalculation() !void {
//     // TODO: Implement
// }

// pub fn createEpochRewardsSysvar() !void {
//     // TODO: Implement
// }
