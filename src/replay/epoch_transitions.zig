const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicU64 = std.atomic.Value(u64);

const AccountStore = sig.accounts_db.AccountStore;

const Epoch = sig.core.Epoch;
const StakesCache = sig.core.StakesCache;
const Ancestors = sig.core.Ancestors;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const EpochStakes = sig.core.EpochStakes;

const EpochTracker = sig.replay.trackers.EpochTracker;
const EpochConstants = sig.core.EpochConstants;
const SlotState = sig.core.SlotState;
const SlotConstants = sig.core.SlotConstants;
const StakeHistory = sig.runtime.sysvar.StakeHistory;
const VoteAccounts = sig.core.vote_accounts.VoteAccounts;
const StakeAndVoteAccountsMap = sig.core.vote_accounts.StakeAndVoteAccountsMap;
const Delegation = sig.core.stake.Delegation;

const SlotAccountStore = @import("slot_account_store.zig").SlotAccountStore;
const applyFeatureActivations = @import("apply_feature_activations.zig").applyFeatureActivations;

/// Process a new epoch. This includes:
/// 1. Apply feature activations.
/// 2. Activate stakes cache for the new epoch.
/// 3. Update epoch stakes
/// 4. Begin partitioned rewards
pub fn processNewEpoch(
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

    var node_id_to_vote_accounts = std.AutoArrayHashMapUnmanaged(
        Pubkey,
        sig.core.epoch_stakes.NodeVoteAccounts,
    ){};
    errdefer sig.utils.collections.deinitMapAndValues(allocator, node_id_to_vote_accounts);

    var epoch_authorized_voters = std.AutoArrayHashMapUnmanaged(Pubkey, Pubkey){};
    errdefer epoch_authorized_voters.deinit(allocator);

    var total_stake: u64 = 0;
    for (epoch_vote_accounts.keys(), epoch_vote_accounts.values()) |key, stake_and_vote_account| {
        if (stake_and_vote_account.stake > 0) {
            total_stake += stake_and_vote_account.stake;

            var vote_state = stake_and_vote_account.account.state;
            if (vote_state.voters.getAuthorizedVoter(leader_schedule_epoch)) |authorized_voter| {
                const node_vote_accounts = try node_id_to_vote_accounts.getOrPut(
                    allocator,
                    authorized_voter,
                );

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
        const entry = try delegated_stakes.getOrPut(
            allocator,
            delegation.voter_pubkey,
        );
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
    const keys = stake_and_vote_accounts.keys();
    const values = stake_and_vote_accounts.values();
    for (keys, values) |vote_pubkey, stake_and_vote_account| {
        const delegated_stake = delegated_stakes.get(vote_pubkey) orelse 0;
        try new_vote_accounts.vote_accounts.put(allocator, vote_pubkey, .{
            .stake = delegated_stake,
            .account = try stake_and_vote_account.account.clone(allocator),
        });
    }

    return new_vote_accounts;
}
