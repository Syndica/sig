const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);

const RwMux = sig.sync.RwMux;
const SortedSet = sig.utils.collections.SortedSet;

const Epoch = sig.core.Epoch;
const EpochStakesMap = sig.core.EpochStakesMap;
const EpochSchedule = sig.core.EpochSchedule;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SlotAndHash = sig.core.hash.SlotAndHash;
const SlotState = sig.core.SlotState;
const SlotConstants = sig.core.SlotConstants;
const Transaction = sig.core.transaction.Transaction;

const BlockstoreReader = sig.ledger.BlockstoreReader;
const LedgerResultWriter = sig.ledger.result_writer.LedgerResultWriter;

const SlotHistory = sig.runtime.sysvar.SlotHistory;

const ReplayTower = sig.consensus.replay_tower.ReplayTower;
const ProgressMap = sig.consensus.progress_map.ProgressMap;
const ForkChoice = sig.consensus.fork_choice.ForkChoice;
const LatestValidatorVotesForFrozenBanks =
    sig.consensus.unimplemented.LatestValidatorVotesForFrozenBanks;

const EpochStakeMap = sig.core.stake.EpochStakeMap;
const BlockhashQueue = sig.core.blockhash_queue.BlockhashQueue;

const SlotTracker = sig.replay.trackers.SlotTracker;
const EpochTracker = sig.replay.trackers.EpochTracker;

pub const isSlotDuplicateConfirmed = sig.consensus.tower.isSlotDuplicateConfirmed;
pub const collectVoteLockouts = sig.consensus.replay_tower.collectVoteLockouts;

const MAX_VOTE_REFRESH_INTERVAL_MILLIS: usize = 5000;

pub const ConsensusDependencies = struct {
    allocator: Allocator,
    replay_tower: *ReplayTower,
    progress_map: *ProgressMap,
    slot_tracker: *SlotTracker,
    epoch_tracker: *const EpochTracker,
    fork_choice: *ForkChoice,
    blockstore_reader: *BlockstoreReader,
    ledger_result_writer: *LedgerResultWriter,
    ancestors: *const std.AutoArrayHashMapUnmanaged(u64, SortedSet(u64)),
    descendants: *const std.AutoArrayHashMapUnmanaged(u64, SortedSet(u64)),
    vote_account: Pubkey,
    slot_history: *const SlotHistory,
    latest_validator_votes_for_frozen_banks: *LatestValidatorVotesForFrozenBanks,
};

pub fn processConsensus(maybe_deps: ?ConsensusDependencies) !void {
    const deps = if (maybe_deps) |deps|
        deps
    else
        return error.Todo;

    var epoch_stakes_map: EpochStakesMap = .empty;
    errdefer epoch_stakes_map.deinit(deps.allocator);

    try epoch_stakes_map.ensureTotalCapacity(deps.allocator, deps.epoch_tracker.epochs.count());
    defer epoch_stakes_map.deinit(deps.allocator);

    for (deps.epoch_tracker.epochs.keys(), deps.epoch_tracker.epochs.values()) |key, constants| {
        epoch_stakes_map.putAssumeCapacity(key, constants.stakes);
    }

    const newly_computed_slot_stats = try computeBankStats(
        deps.allocator,
        deps.vote_account,
        deps.ancestors,
        deps.slot_tracker,
        &deps.epoch_tracker.schedule,
        &epoch_stakes_map,
        deps.progress_map,
        deps.fork_choice,
        deps.latest_validator_votes_for_frozen_banks,
    );
    _ = newly_computed_slot_stats;
    // TODO: for each newly_computed_slot_stats:
    //           tower_duplicate_confirmed_forks
    //           mark_slots_duplicate_confirmed
    const heaviest_slot = deps.fork_choice.heaviestOverallSlot().slot;
    const heaviest_slot_on_same_voted_fork =
        (try deps.fork_choice.heaviestSlotOnSameVotedFork(deps.replay_tower)) orelse null;

    const heaviest_epoch: Epoch = deps.epoch_tracker.schedule.getEpoch(heaviest_slot);

    const now = sig.time.Instant.now();
    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = now,
        .last_print_time = now,
    };

    const vote_and_reset_forks = try deps.replay_tower.selectVoteAndResetForks(
        deps.allocator,
        heaviest_slot,
        if (heaviest_slot_on_same_voted_fork) |h| h.slot else null,
        heaviest_epoch,
        deps.ancestors,
        deps.descendants,
        deps.progress_map,
        deps.latest_validator_votes_for_frozen_banks,
        deps.fork_choice,
        &epoch_stakes_map,
        deps.slot_history,
    );
    const maybe_voted_slot = vote_and_reset_forks.vote_slot;
    const maybe_reset_slot = vote_and_reset_forks.reset_slot;
    const heaviest_fork_failures = vote_and_reset_forks.heaviest_fork_failures;

    if (maybe_voted_slot == null) {
        _ = maybeRefreshLastVote(
            deps.replay_tower,
            deps.progress_map,
            if (heaviest_slot_on_same_voted_fork) |h| h.slot else null,
            &last_vote_refresh_time,
        );
    }

    if (deps.replay_tower.tower.isRecent(heaviest_slot) and
        heaviest_fork_failures.items.len != 0)
    {
        // TODO Implemented the Self::log_heaviest_fork_failures
    }

    // Vote on the fork
    if (maybe_voted_slot) |voted| {
        const slot_tracker = deps.slot_tracker;
        const found_slot_info = slot_tracker.get(voted.slot) orelse
            return error.MissingSlot;

        const voted_hash = found_slot_info.state.hash.readCopy() orelse
            return error.MissingSlotInTracker;

        try handleVotableBank(
            deps.allocator,
            deps.ledger_result_writer,
            voted.slot,
            voted_hash,
            deps.slot_tracker,
            deps.replay_tower,
            deps.progress_map,
            deps.fork_choice,
        );
    }

    // Reset onto a fork
    if (maybe_reset_slot) |reset_slot| {
        // TODO implement
        _ = reset_slot;
    }
}

const LastVoteRefreshTime = struct {
    last_refresh_time: sig.time.Instant,
    last_print_time: sig.time.Instant,
};

/// Determines whether to refresh and submit an updated version of the last vote based on several conditions.
///
/// A vote refresh is performed when all of the following conditions are met:
/// 1. Validator Status:
///    - Not operating as a hotspare or non-voting validator
///    - Has attempted to vote at least once previously
/// 2. Fork Status:
///    - There exists a heaviest slot (`heaviest_slot_on_same_fork`) on our previously voted fork
///    - We've successfully landed at least one vote (`latest_landed_vote_slot`) on this fork
/// 3. Vote Progress:
///    - Our latest vote attempt (`last_vote_slot`) is still tracked in the progress map
///    - The latest landed vote is older than our last vote attempt (`latest_landed_vote_slot` < `last_vote_slot`)
/// 4. Block Progress:
///    - The heaviest bank is sufficiently ahead of our last vote (by at least `REFRESH_VOTE_BLOCKHEIGHT` blocks)
/// 5. Timing:
///    - At least `MAX_VOTE_REFRESH_INTERVAL_MILLIS` milliseconds have passed since last refresh attempt
///
/// If all conditions are satisfied:
/// - Creates a new vote transaction for the same slot (`last_vote_slot`) with:
///   * Current timestamp
///   * New blockhash from `heaviest_bank_on_same_fork`
///   * Fresh signature
/// - Submits this refreshed vote to the cluster
///
/// Returns:
/// - `true` if a refreshed vote was successfully created and submitted
/// - `false` if any condition was not met or the refresh failed
///
/// Note: This is not simply resending the same vote, but creating a new distinct transaction that:
/// - Votes for the same slot
/// - Contains updated metadata (timestamp/blockhash)
/// - Generates a new signature
/// - Will be processed as a separate transaction by the network
///
/// Analogous to [maybe_refresh_last_vote](https://github.com/anza-xyz/agave/blob/ccdcdbe9b6ff7dbd583d2101fe57b7cc41a6f863/core/src/replay_stage.rs#L2606)
fn maybeRefreshLastVote(
    replay_tower: *ReplayTower,
    progress: *const ProgressMap,
    maybe_heaviest_slot_on_same_fork: ?Slot,
    last_vote_refresh_time: *LastVoteRefreshTime,
) bool {
    const heaviest_bank_on_same_fork = maybe_heaviest_slot_on_same_fork orelse {
        // Only refresh if blocks have been built on our last vote
        return false;
    };

    // Need to land at least one vote in order to refresh
    const latest_landed_vote_slot = blk: {
        const fork_stat = progress.getForkStats(heaviest_bank_on_same_fork) orelse return false;
        break :blk fork_stat.my_latest_landed_vote orelse return false;
    };

    const last_voted_slot = replay_tower.lastVotedSlot() orelse {
        // Need to have voted in order to refresh
        return false;
    };

    // If our last landed vote on this fork is greater than the vote recorded in our tower
    // this means that our tower is old AND on chain adoption has failed. Warn the operator
    // as they could be submitting slashable votes.
    if (latest_landed_vote_slot > last_voted_slot and
        last_vote_refresh_time.last_print_time.elapsed().asSecs() >= 1)
    {
        last_vote_refresh_time.last_print_time = sig.time.Instant.now();
        // TODO log
    }

    if (latest_landed_vote_slot >= last_voted_slot) {
        // Our vote or a subsequent vote landed do not refresh
        return false;
    }

    const maybe_last_vote_tx_blockhash: ?Hash = switch (replay_tower.last_vote_tx_blockhash) {
        // Since the checks in vote generation are deterministic, if we were non voting or hot spare
        // on the original vote, the refresh will also fail. No reason to refresh.
        // On the fly adjustments via the cli will be picked up for the next vote.
        .non_voting, .hot_spare => return false,
        // In this case we have not voted since restart, our setup is unclear.
        // We have a vote from our previous restart that is eligible for refresh, we must refresh.
        .uninitialized => null,
        .blockhash => |blockhash| blockhash,
    };

    // TODO Need need a FIFO queue of `recent_blockhash` items
    // Add after transaction scheduling.
    if (maybe_last_vote_tx_blockhash) |last_vote_tx_blockhash| {
        // Check the blockhash queue to see if enough blocks have been built on our last voted fork
        _ = last_vote_tx_blockhash;
    }

    if (last_vote_refresh_time.last_refresh_time.elapsed().asMillis() <
        MAX_VOTE_REFRESH_INTERVAL_MILLIS)
    {
        // This avoids duplicate refresh in case there are multiple forks descending from our last voted fork
        // It also ensures that if the first refresh fails we will continue attempting to refresh at an interval no less
        // than MAX_VOTE_REFRESH_INTERVAL_MILLIS
        return false;
    }

    // All criteria are met, refresh the last vote using the blockhash of `heaviest_bank_on_same_fork`
    // Update timestamp for refreshed vote
    // AUDIT: Rest of code replaces Self::refresh_last_vote in Agave
    replay_tower.refreshLastVoteTimestamp(heaviest_bank_on_same_fork);

    // TODO Transaction generation to be implemented.
    // Currently hardcoding to non voting transaction.
    const vote_tx_result: GenerateVoteTxResult = .non_voting;

    return switch (vote_tx_result) {
        .tx => |_| {
            // TODO to be implemented
            return true;
        },
        .non_voting => {
            replay_tower.markLastVoteTxBlockhashNonVoting();
            return true;
        },
        .hot_spare => {
            replay_tower.markLastVoteTxBlockhashHotSpare();
            return false;
        },
        else => false,
    };
}

pub const AncestorHashesReplayUpdate = union(enum) {
    dead: Slot,
    dead_duplicate_confirmed: Slot,
    /// `Slot` belongs to a fork we have pruned. We have observed that this fork is "popular" aka
    /// reached 52+% stake through votes in turbine/gossip including votes for descendants. These
    /// votes are hash agnostic since we have not replayed `Slot` so we can never say for certainty
    /// that this fork has reached duplicate confirmation, but it is suspected to have. This
    /// indicates that there is most likely a block with invalid ancestry present and thus we
    /// collect an ancestor sample to resolve this issue. `Slot` is the deepest slot in this fork
    /// that is popular, so any duplicate problems will be for `Slot` or one of it's ancestors.
    popular_pruned_fork: Slot,
};

pub const GenerateVoteTxResult = union(enum) {
    // non voting validator, not eligible for refresh
    // until authorized keypair is overriden
    non_voting,
    // hot spare validator, not eligble for refresh
    // until set identity is invoked
    hot_spare,
    // failed generation, eligible for refresh
    fails,
    // TODO add Transaction
    tx: Transaction,
};

/// Handles a votable bank by recording the vote, update commitment cache,
/// potentially processing a new root, and pushing the vote.
///
/// Analogous to [handle_votable_bank](https://github.com/anza-xyz/agave/blob/ccdcdbe9b6ff7dbd583d2101fe57b7cc41a6f863/core/src/replay_stage.rs#L2388)
fn handleVotableBank(
    allocator: std.mem.Allocator,
    ledger_result_writer: *LedgerResultWriter,
    vote_slot: Slot,
    vote_hash: Hash,
    slot_tracker: *SlotTracker,
    replay_tower: *ReplayTower,
    progress: *ProgressMap,
    fork_choice: *ForkChoice,
) !void {
    const maybe_new_root = try replay_tower.recordBankVote(
        allocator,
        vote_slot,
        vote_hash,
    );

    if (maybe_new_root) |new_root| {
        try checkAndHandleNewRoot(
            allocator,
            ledger_result_writer,
            slot_tracker,
            progress,
            fork_choice,
            new_root,
        );
    }

    // TODO update_commitment_cache

    try pushVote(
        replay_tower,
    );
}

/// Pushes a new vote transaction to the network and updates tower state.
///
/// - Generates a new vote transaction.
/// - Updates the tower's last vote blockhash.
/// - Creates a saved tower state.
/// - Sends the vote operation to the voting sender.
///
/// Analogous to [push_vote](https://github.com/anza-xyz/agave/blob/ccdcdbe9b6ff7dbd583d2101fe57b7cc41a6f863/core/src/replay_stage.rs#L2775)
fn pushVote(
    replay_tower: *ReplayTower,
) !void {

    // TODO Transaction generation to be implemented.
    // Currently hardcoding to non voting transaction.
    const vote_tx_result: GenerateVoteTxResult = .non_voting;

    switch (vote_tx_result) {
        .tx => |vote_tx| {
            _ = vote_tx;
            // TODO to be implemented
        },
        .non_voting => {
            replay_tower.markLastVoteTxBlockhashNonVoting();
        },
        else => {
            // Do nothing
        },
    }
}

/// Processes a new root slot by updating various system components to reflect the new root.
///
/// - Validates the new root exists and has a hash.
/// - Gets all slots rooted at the new root.
/// - Updates ledger state with the new roots.
/// - Cleans up progress map for non-existent slots.
/// - Updates fork choice with the new root.
///
/// Analogous to [check_and_handle_new_root](https://github.com/anza-xyz/agave/blob/ccdcdbe9b6ff7dbd583d2101fe57b7cc41a6f863/core/src/replay_stage.rs#L4002)
fn checkAndHandleNewRoot(
    allocator: std.mem.Allocator,
    ledger_result_writer: *LedgerResultWriter,
    slot_tracker: *SlotTracker,
    progress: *ProgressMap,
    fork_choice: *ForkChoice,
    new_root: Slot,
) !void {
    // get the root bank before squash.
    if (slot_tracker.slots.count() == 0) return error.EmptySlotTracker;
    const root_tracker = slot_tracker.get(new_root) orelse return error.MissingSlot;
    const maybe_root_hash = root_tracker.state.hash.readCopy();
    const root_hash = maybe_root_hash orelse return error.MissingHash;

    const rooted_slots = try slot_tracker.parents(allocator, new_root);
    defer allocator.free(rooted_slots);

    try ledger_result_writer.setRoots(rooted_slots);

    // Audit: The rest of the code maps to Self::handle_new_root in Agave.
    // Update the slot tracker.
    // Set new root.
    slot_tracker.root = new_root;
    // Prune non rooted slots
    slot_tracker.pruneNonRooted(allocator);

    // TODO
    // - Prune program cache bank_forks.read().unwrap().prune_program_cache(new_root);
    // - Extra operations as part of setting new root:
    //   - cleare reward cache root_bank.clear_epoch_rewards_cache
    //   - extend banks banks.extend(parents.iter());
    //   - operations around snapshot_controller
    //   - After setting a new root, prune the banks that are no longer on rooted paths self.prune_non_rooted(root, highest_super_majority_root);

    // Update the progress map.
    // Remove entries from the progress map no longer in the slot tracker.
    var progress_keys = progress.map.keys();
    var index: usize = 0;
    while (index < progress_keys.len) {
        const progress_slot = progress_keys[index];
        if (slot_tracker.get(progress_slot) == null) {
            const removed_value = progress.map.fetchSwapRemove(progress_slot) orelse continue;
            defer removed_value.value.deinit(allocator);
            progress_keys = progress.map.keys();
        } else {
            index += 1;
        }
    }

    // Update forkchoice
    try fork_choice.setTreeRoot(&.{
        .slot = new_root,
        .hash = root_hash,
    });
}

/// Analogous to https://github.com/anza-xyz/agave/blob/234afe489aa20a04a51b810213b945e297ef38c7/core/src/replay_stage.rs#L1029-L1118
///
/// Handle fork resets in specific circumstances:
/// - When a validator needs to switch to a different fork after voting on a fork that becomes invalid
/// - When a block producer needs to reset their fork choice after detecting a better fork
/// - When handling cases where the validator's current fork becomes less optimal than an alternative fork
///
/// TODO: Currently a placeholder function. Would be implemened when voting and producing blocks is supported.
fn resetFork(
    progress: *const ProgressMap,
    blockstore: *const BlockstoreReader,
    reset_slot: Slot,
    last_reset_hash: Hash,
    last_blockhash: Hash,
    last_reset_bank_descendants: std.ArrayList(Slot),
) !void {
    _ = progress;
    _ = blockstore;
    _ = reset_slot;
    _ = last_reset_hash;
    _ = last_blockhash;
    _ = last_reset_bank_descendants;
}

fn computeBankStats(
    allocator: std.mem.Allocator,
    my_vote_pubkey: Pubkey,
    ancestors: *const std.AutoArrayHashMapUnmanaged(u64, SortedSet(u64)),
    slot_tracker: *SlotTracker,
    epoch_schedule: *const EpochSchedule,
    epoch_stakes_map: *const EpochStakesMap,
    progress: *ProgressMap,
    fork_choice: *ForkChoice,
    latest_validator_votes: *LatestValidatorVotesForFrozenBanks,
) ![]Slot {
    var new_stats = std.ArrayListUnmanaged(Slot).empty;
    errdefer new_stats.deinit(allocator);
    var frozen_slots = try slot_tracker.frozenSlots(allocator);
    defer frozen_slots.deinit(allocator);
    // TODO agave sorts this by the slot first. Is this needed for the implementation to be correct?
    // If not, then we can avoid sorting here which may be verbose given frozen_slots is a map.
    for (frozen_slots.keys()) |slot| {
        const epoch = epoch_schedule.getEpoch(slot);
        const epoch_stakes = epoch_stakes_map.get(epoch) orelse return error.MissingEpochStakes;
        const fork_stat = progress.getForkStats(slot) orelse return error.MissingSlot;
        if (!fork_stat.computed) {
            // TODO Self::adopt_on_chain_tower_if_behind
            // Gather voting information from all vote accounts to understand the current consensus state.
            const computed_bank_state = try collectVoteLockouts(
                allocator,
                .noop,
                &my_vote_pubkey,
                slot,
                &epoch_stakes.stakes.vote_accounts.vote_accounts,
                ancestors,
                progress,
                latest_validator_votes,
            );

            try fork_choice.computeBankStats(
                allocator,
                epoch_stakes_map,
                epoch_schedule,
                latest_validator_votes,
            );
            const fork_stats = progress.getForkStats(slot) orelse return error.MissingForkStats;
            fork_stats.fork_stake = computed_bank_state.fork_stake;
            fork_stats.total_stake = computed_bank_state.total_stake;
            fork_stats.voted_stakes = computed_bank_state.voted_stakes;
            fork_stats.lockout_intervals = computed_bank_state.lockout_intervals;
            fork_stats.block_height = blk: {
                const slot_info = slot_tracker.get(slot) orelse return error.MissingSlots;
                break :blk slot_info.constants.block_height;
            };
            fork_stats.my_latest_landed_vote = computed_bank_state.my_latest_landed_vote;
            fork_stats.computed = true;
            try new_stats.append(allocator, slot);
        }
    }
    return try new_stats.toOwnedSlice(allocator);
}

const testing = std.testing;
const TreeNode = sig.consensus.fork_choice.TreeNode;
const testEpochStakes = sig.consensus.fork_choice.testEpochStakes;
const TestDB = sig.ledger.tests.TestDB;
const TestFixture = sig.consensus.replay_tower.TestFixture;
const MAX_TEST_TREE_LEN = sig.consensus.replay_tower.MAX_TEST_TREE_LEN;
const Lockout = sig.runtime.program.vote.state.Lockout;

const createTestReplayTower = sig.consensus.replay_tower.createTestReplayTower;

test "maybeRefreshLastVote - no heaviest slot on same fork" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    defer replay_tower.deinit(std.testing.allocator);

    const now = sig.time.Instant.now();
    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = now,
        .last_print_time = now,
    };

    const result = sig.replay.consensus.maybeRefreshLastVote(
        &replay_tower,
        &fixture.progress,
        null,
        &last_vote_refresh_time,
    );

    try testing.expectEqual(false, result);
}

test "maybeRefreshLastVote - no landed vote" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    defer replay_tower.deinit(std.testing.allocator);

    const now = sig.time.Instant.now();
    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = now,
        .last_print_time = now,
    };

    // not vote in progress map.
    try testing.expectEqual(0, fixture.progress.map.count());
    const result = sig.replay.consensus.maybeRefreshLastVote(
        &replay_tower,
        &fixture.progress,
        10, // Not in progress map.
        &last_vote_refresh_time,
    );

    try testing.expectEqual(false, result);
}

test "maybeRefreshLastVote - latest landed vote newer than last vote" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };
    const hash3 = SlotAndHash{
        .slot = 3,
        .hash = Hash.initRandom(random),
    };
    const hash2 = SlotAndHash{
        .slot = 2,
        .hash = Hash.initRandom(random),
    };
    const hash1 = SlotAndHash{
        .slot = 1,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[3]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
        .{ hash3, hash2 },
    });

    try fixture.fill_fork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = .fromOwnedSlice(try std.testing.allocator.dupe(Lockout, &.{
                .{ .slot = 3, .confirmation_count = 3 },
                .{ .slot = 4, .confirmation_count = 2 },
                .{ .slot = 5, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    const now = sig.time.Instant.now();
    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = now,
        .last_print_time = now,
    };

    const result = sig.replay.consensus.maybeRefreshLastVote(
        &replay_tower,
        &fixture.progress,
        hash3.slot,
        &last_vote_refresh_time,
    );

    try testing.expectEqual(false, result);
}

test "maybeRefreshLastVote - non voting validator" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };
    const hash3 = SlotAndHash{
        .slot = 3,
        .hash = Hash.initRandom(random),
    };
    const hash2 = SlotAndHash{
        .slot = 2,
        .hash = Hash.initRandom(random),
    };
    const hash1 = SlotAndHash{
        .slot = 1,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[3]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
        .{ hash3, hash2 },
    });

    try fixture.fill_fork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = .fromOwnedSlice(try std.testing.allocator.dupe(Lockout, &.{
                .{ .slot = 3, .confirmation_count = 3 },
                .{ .slot = 4, .confirmation_count = 2 },
                .{ .slot = 5, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    replay_tower.last_vote_tx_blockhash = .non_voting;

    const now = sig.time.Instant.now();
    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = now,
        .last_print_time = now,
    };

    const result = sig.replay.consensus.maybeRefreshLastVote(
        &replay_tower,
        &fixture.progress,
        hash3.slot,
        &last_vote_refresh_time,
    );

    try testing.expectEqual(false, result);
}

test "maybeRefreshLastVote - hotspare validator" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };
    const hash3 = SlotAndHash{
        .slot = 3,
        .hash = Hash.initRandom(random),
    };
    const hash2 = SlotAndHash{
        .slot = 2,
        .hash = Hash.initRandom(random),
    };
    const hash1 = SlotAndHash{
        .slot = 1,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[3]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
        .{ hash3, hash2 },
    });

    try fixture.fill_fork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = .fromOwnedSlice(try std.testing.allocator.dupe(Lockout, &.{
                .{ .slot = 3, .confirmation_count = 3 },
                .{ .slot = 4, .confirmation_count = 2 },
                .{ .slot = 5, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    replay_tower.last_vote_tx_blockhash = .hot_spare;

    const now = sig.time.Instant.now();
    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = now,
        .last_print_time = now,
    };

    const result = sig.replay.consensus.maybeRefreshLastVote(
        &replay_tower,
        &fixture.progress,
        hash3.slot,
        &last_vote_refresh_time,
    );

    try testing.expectEqual(false, result);
}

test "maybeRefreshLastVote - refresh interval not elapsed" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };
    const hash3 = SlotAndHash{
        .slot = 3,
        .hash = Hash.initRandom(random),
    };
    const hash2 = SlotAndHash{
        .slot = 2,
        .hash = Hash.initRandom(random),
    };
    const hash1 = SlotAndHash{
        .slot = 1,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[3]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
        .{ hash3, hash2 },
    });

    try fixture.fill_fork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = .fromOwnedSlice(try std.testing.allocator.dupe(Lockout, &.{
                .{ .slot = 3, .confirmation_count = 3 },
                .{ .slot = 4, .confirmation_count = 2 },
                .{ .slot = 5, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    replay_tower.last_vote_tx_blockhash = .{ .blockhash = Hash.ZEROES };

    const now = sig.time.Instant.now();
    var last_vote_refresh_time: LastVoteRefreshTime = .{
        // Will last_vote_refresh_time.last_refresh_time.elapsed().asMillis() as zero
        // thereby satisfying the test condition of that value being
        // less than MAX_VOTE_REFRESH_INTERVAL_MILLIS
        .last_refresh_time = now,
        .last_print_time = now,
    };

    const result = sig.replay.consensus.maybeRefreshLastVote(
        &replay_tower,
        &fixture.progress,
        hash3.slot,
        &last_vote_refresh_time,
    );

    try testing.expectEqual(false, result);
}

test "maybeRefreshLastVote - successfully refreshed and mark last_vote_tx_blockhash as non voting" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const hash3 = SlotAndHash{
        .slot = 3,
        .hash = Hash.initRandom(random),
    };
    const hash2 = SlotAndHash{
        .slot = 2,
        .hash = Hash.initRandom(random),
    };
    const hash1 = SlotAndHash{
        .slot = 1,
        .hash = Hash.initRandom(random),
    };
    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[3]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
        .{ hash3, hash2 },
    });

    try fixture.fill_fork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = .fromOwnedSlice(try std.testing.allocator.dupe(Lockout, &.{
                .{ .slot = 3, .confirmation_count = 3 },
                .{ .slot = 4, .confirmation_count = 2 },
                .{ .slot = 5, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    replay_tower.last_vote_tx_blockhash = .{ .blockhash = Hash.ZEROES };

    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = sig.time.Instant.now().sub(
            sig.time.Duration.fromMillis(MAX_VOTE_REFRESH_INTERVAL_MILLIS),
        ),
        .last_print_time = sig.time.Instant.now(),
    };

    const result = sig.replay.consensus.maybeRefreshLastVote(
        &replay_tower,
        &fixture.progress,
        hash3.slot,
        &last_vote_refresh_time,
    );

    try testing.expectEqual(true, result);
    try testing.expectEqual(.non_voting, replay_tower.last_vote_tx_blockhash);
}

test "checkAndHandleNewRoot - missing slot" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var slot_tracker: SlotTracker = SlotTracker{ .root = root.slot, .slots = .{} };
    defer {
        var it = slot_tracker.slots.iterator();
        while (it.next()) |entry| {
            testing.allocator.destroy(entry.value_ptr.*);
        }
        slot_tracker.slots.deinit(testing.allocator);
    }

    const constants = try SlotConstants.genesis(testing.allocator, .initRandom(random));
    defer constants.deinit(testing.allocator);
    try slot_tracker.put(testing.allocator, root.slot, .{
        .constants = constants,
        .state = .GENESIS,
    });

    const logger = .noop;
    var registry = sig.prometheus.Registry(.{}).init(testing.allocator);
    defer registry.deinit();

    var db = try TestDB.init(@src());
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);

    var ledger_result_writer = try LedgerResultWriter.init(
        testing.allocator,
        logger,
        db,
        &registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    // Try to check a slot that doesn't exist in the tracker
    const result = checkAndHandleNewRoot(
        testing.allocator,
        &ledger_result_writer,
        &slot_tracker,
        &fixture.progress,
        &fixture.fork_choice,
        123, // Non-existent slot
    );

    try testing.expectError(error.MissingSlot, result);
}

test "checkAndHandleNewRoot - missing hash" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var slot_tracker: SlotTracker = SlotTracker{ .root = root.slot, .slots = .{} };
    defer {
        var it = slot_tracker.slots.iterator();
        while (it.next()) |entry| {
            testing.allocator.destroy(entry.value_ptr.*);
        }
        slot_tracker.slots.deinit(testing.allocator);
    }

    const constants = try SlotConstants.genesis(testing.allocator, .initRandom(random));
    defer constants.deinit(testing.allocator);
    try slot_tracker.put(testing.allocator, root.slot, .{
        .constants = constants,
        .state = .GENESIS,
    });

    const logger = .noop;
    var registry = sig.prometheus.Registry(.{}).init(testing.allocator);
    defer registry.deinit();

    var db = try TestDB.init(@src());
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);

    var ledger_result_writer = try LedgerResultWriter.init(
        testing.allocator,
        logger,
        db,
        &registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    // Try to check a slot that doesn't exist in the tracker
    const result = checkAndHandleNewRoot(
        testing.allocator,
        &ledger_result_writer,
        &slot_tracker,
        &fixture.progress,
        &fixture.fork_choice,
        root.slot, // Non-existent hash
    );

    try testing.expectError(error.MissingHash, result);
}

test "checkAndHandleNewRoot - empty slot tracker" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var slot_tracker: SlotTracker = SlotTracker{ .root = root.slot, .slots = .{} };
    const logger = .noop;
    var registry = sig.prometheus.Registry(.{}).init(testing.allocator);
    defer registry.deinit();

    var db = try TestDB.init(@src());
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);

    var ledger_result_writer = try LedgerResultWriter.init(
        testing.allocator,
        logger,
        db,
        &registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    // Try to check a slot that doesn't exist in the tracker
    const result = checkAndHandleNewRoot(
        testing.allocator,
        &ledger_result_writer,
        &slot_tracker,
        &fixture.progress,
        &fixture.fork_choice,
        root.slot,
    );

    try testing.expectError(error.EmptySlotTracker, result);
}

test "checkAndHandleNewRoot - success" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const hash3 = SlotAndHash{
        .slot = 3,
        .hash = Hash.initRandom(random),
    };
    const hash2 = SlotAndHash{
        .slot = 2,
        .hash = Hash.initRandom(random),
    };
    const hash1 = SlotAndHash{
        .slot = 1,
        .hash = Hash.initRandom(random),
    };
    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var slot_tracker: SlotTracker = SlotTracker{ .root = root.slot, .slots = .{} };
    defer {
        var it = slot_tracker.slots.iterator();
        while (it.next()) |entry| {
            testing.allocator.destroy(entry.value_ptr.*);
        }
        slot_tracker.slots.deinit(testing.allocator);
    }

    var constants2 = try SlotConstants.genesis(testing.allocator, .initRandom(random));
    defer constants2.deinit(testing.allocator);
    var constants3 = try SlotConstants.genesis(testing.allocator, .initRandom(random));
    defer constants3.deinit(testing.allocator);
    var state2 = SlotState.GENESIS;
    var state3 = SlotState.GENESIS;
    constants2.parent_slot = hash1.slot;
    constants3.parent_slot = hash2.slot;
    state2.hash = .init(hash2.hash);
    state3.hash = .init(hash3.hash);
    try slot_tracker.put(testing.allocator, hash2.slot, .{
        .constants = constants2,
        .state = state2,
    });
    try slot_tracker.put(testing.allocator, hash3.slot, .{
        .constants = constants3,
        .state = state3,
    });

    // Add some entries to progress map that should be removed
    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[3]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
        .{ hash3, hash2 },
    });

    try fixture.fill_fork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    var db = try TestDB.init(@src());
    defer db.deinit();

    var registry = sig.prometheus.Registry(.{}).init(testing.allocator);
    defer registry.deinit();
    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);

    var ledger_result_writer = try LedgerResultWriter.init(
        testing.allocator,
        .noop,
        db,
        &registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    try testing.expectEqual(4, fixture.progress.map.count());
    try testing.expect(fixture.progress.map.contains(hash1.slot));
    try checkAndHandleNewRoot(
        testing.allocator,
        &ledger_result_writer,
        &slot_tracker,
        &fixture.progress,
        &fixture.fork_choice,
        hash3.slot,
    );

    try testing.expectEqual(1, fixture.progress.map.count());
    for (slot_tracker.slots.keys()) |remaining_slots| {
        try testing.expect(remaining_slots >= hash3.slot);
    }
    try testing.expect(!fixture.progress.map.contains(hash1.slot));
}

test "computeBankStats - child bank heavier" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    // Set up slots and hashes for the fork tree: 0 -> 1 -> 2
    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    const hash1 = SlotAndHash{ .slot = 1, .hash = Hash.initRandom(random) };
    const hash2 = SlotAndHash{ .slot = 2, .hash = Hash.initRandom(random) };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    try fixture.fill_keys(testing.allocator, random, 1);

    // Create the tree of banks in a BankForks object
    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[2]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
    });
    try fixture.fill_fork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    const my_node_pubkey = fixture.node_pubkeys.items[0];
    const votes = [_]u64{2};
    for (votes) |vote| {
        _ = vote;
        // const result = fixture.simulate_vote(vote, my_vote_pubkey, &fixture.tower);
        // try testing.expectEqual(@as(usize, 0), result.len);
    }

    var frozen_slots = try fixture.slot_tracker.frozenSlots(
        testing.allocator,
    );
    defer frozen_slots.deinit(testing.allocator);
    errdefer frozen_slots.deinit(testing.allocator);

    // TODO move this into fixture?
    const versioned_stakes = try testEpochStakes(
        testing.allocator,
        fixture.vote_pubkeys.items,
        10000,
        random,
    );
    defer versioned_stakes.deinit(testing.allocator);

    const keys = versioned_stakes.stakes.vote_accounts.vote_accounts.keys();
    for (keys) |key| {
        var vote_account = versioned_stakes.stakes.vote_accounts.vote_accounts.getPtr(key).?;
        const LandedVote = sig.runtime.program.vote.state.LandedVote;
        try vote_account.account.state.votes.append(LandedVote{
            .latency = 0,
            .lockout = Lockout{
                .slot = 1,
                .confirmation_count = 4,
            },
        });
    }

    var epoch_stakes = EpochStakesMap.empty;
    defer epoch_stakes.deinit(testing.allocator);
    try epoch_stakes.put(testing.allocator, 0, versioned_stakes);

    const epoch_schedule = EpochSchedule.DEFAULT;
    const newly_computed_slot_stats = try computeBankStats(
        testing.allocator,
        my_node_pubkey,
        &fixture.ancestors,
        &fixture.slot_tracker,
        &epoch_schedule,
        &epoch_stakes,
        &fixture.progress,
        &fixture.fork_choice,
        &fixture.latest_validator_votes_for_frozen_banks,
    );
    defer testing.allocator.free(newly_computed_slot_stats);

    // Sort frozen slots by slot number
    const slot_list = try testing.allocator.alloc(u64, frozen_slots.count());
    defer testing.allocator.free(slot_list);
    var i: usize = 0;
    for (frozen_slots.keys()) |slot| {
        slot_list[i] = slot;
        i += 1;
    }
    std.mem.sort(u64, slot_list, {}, std.sort.asc(u64));

    // Check that fork weights are non-decreasing
    for (slot_list, 0..) |_, idx| {
        if (idx + 1 < slot_list.len) {
            const first = fixture.progress.getForkStats(slot_list[idx]) orelse
                return error.MissingForkStats;
            const second = fixture.progress.getForkStats(slot_list[idx + 1]) orelse
                return error.MissingForkStats;
            try testing.expect(second.fork_stake >= first.fork_stake);
        }
    }

    // Check that the heaviest slot is always the leaf (slot 3)
    for (slot_list) |slot| {
        const slot_info = fixture.slot_tracker.get(slot) orelse
            return error.MissingSlot;
        const best = fixture.fork_choice.heaviestSlot(
            .{ .slot = slot, .hash = slot_info.state.hash.readCopy().? },
        ) orelse
            return error.MissingSlot;
        try testing.expectEqual(2, best.slot);
    }
}

test "computeBankStats - same weight selects lower slot" {
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();

    // Set up slots and hashes for the fork tree: 0 -> 1, 0 -> 2
    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    const hash1 = SlotAndHash{ .slot = 1, .hash = Hash.initRandom(random) };
    const hash2 = SlotAndHash{ .slot = 2, .hash = Hash.initRandom(random) };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    try fixture.fill_keys(testing.allocator, random, 1);
    const my_vote_pubkey = fixture.vote_pubkeys.items[0];

    // Create the tree: root -> 1, root -> 2
    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[_]TreeNode{
        .{ hash1, root },
        .{ hash2, root },
    });
    try fixture.fill_fork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    const versioned_stakes = try testEpochStakes(
        testing.allocator,
        fixture.vote_pubkeys.items,
        10000,
        random,
    );
    defer versioned_stakes.deinit(testing.allocator);

    var epoch_stakes = EpochStakesMap.empty;
    defer epoch_stakes.deinit(testing.allocator);
    try epoch_stakes.put(testing.allocator, 0, versioned_stakes);
    try epoch_stakes.put(testing.allocator, 1, versioned_stakes);

    const epoch_schedule = EpochSchedule.DEFAULT;
    const newly_computed_slot_stats = try computeBankStats(
        testing.allocator,
        my_vote_pubkey,
        &fixture.ancestors,
        &fixture.slot_tracker,
        &epoch_schedule,
        &epoch_stakes,
        &fixture.progress,
        &fixture.fork_choice,
        &fixture.latest_validator_votes_for_frozen_banks,
    );
    defer testing.allocator.free(newly_computed_slot_stats);

    // Check that stake for slot 1 and slot 2 is equal
    const bank1 = fixture.slot_tracker.get(1).?;
    const bank2 = fixture.slot_tracker.get(2).?;

    const stake1 = fixture.fork_choice.stakeForSubtree(
        &.{ .slot = 1, .hash = bank1.state.hash.readCopy().? },
    ).?;
    const stake2 = fixture.fork_choice.stakeForSubtree(
        &.{ .slot = 2, .hash = bank2.state.hash.readCopy().? },
    ).?;
    try testing.expectEqual(stake1, stake2);

    // Select the heaviest bank
    const heaviest = fixture.fork_choice.heaviestOverallSlot();
    // Should pick the lower of the two equally weighted banks
    try testing.expectEqual(@as(u64, 1), heaviest.slot);
}
