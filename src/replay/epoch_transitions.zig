const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicU64 = std.atomic.Value(u64);

const Epoch = sig.core.Epoch;
const StakesCache = sig.core.StakesCache;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const EpochStakes = sig.core.EpochStakes;

const EpochTracker = sig.replay.trackers.EpochTracker;
const EpochConstants = sig.core.EpochConstants;
const SlotState = sig.core.SlotState;
const SlotConstants = sig.core.SlotConstants;

const SlotAccountStore = @import("slot_account_store.zig").SlotAccountStore;
const applyFeatureActivations = @import("apply_feature_activations.zig").applyFeatureActivations;
const beginPartitionedRewards = sig.replay.rewards.calculation.beginPartitionedRewards;

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
    slot_store: SlotAccountStore,
) !void {
    try applyFeatureActivations(
        allocator,
        slot_store,
        epoch_tracker,
        slot_constants,
        true, // allow_new_activations
    );

    // [agave] https://github.com/anza-xyz/agave/blob/b6c96e84b10396b92912d4574dae7d03f606da26/runtime/src/bank.rs#L1623-L1631
    const epoch = epoch_tracker.schedule.getEpoch(slot);
    try slot_state.stakes_cache.activateEpoch(
        allocator,
        epoch,
        slot_constants.feature_set.newWarmupCooldownRateEpoch(&epoch_tracker.schedule),
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
    try beginPartitionedRewards(
        allocator,
        slot,
        slot_state,
        slot_constants,
        epoch_tracker,
        slot_store,
    );
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
        // TODO: This is mixing the wrong epoch constants with the wrong stakes.
        // We are setting epoch constants for the leader schedule epoch with the epoch constants from the parent epoch.
        const parent_epoch_constants = epoch_tracker.get(parent_epoch) orelse {
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
