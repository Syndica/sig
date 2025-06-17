const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);

const LedgerResultWriter = sig.ledger.result_writer.LedgerResultWriter;

const SortedSet = sig.utils.collections.SortedSet;
const ReplayTower = sig.consensus.replay_tower.ReplayTower;
const ProgressMap = sig.consensus.progress_map.ProgressMap;
const ForkChoice = sig.consensus.fork_choice.ForkChoice;
const LatestValidatorVotesForFrozenBanks =
    sig.consensus.unimplemented.LatestValidatorVotesForFrozenBanks;

const EpochStakeMap = sig.core.stake.EpochStakeMap;

const SlotTracker = sig.replay.trackers.SlotTracker;
const EpochTracker = sig.replay.trackers.EpochTracker;
const BlockstoreReader = sig.ledger.BlockstoreReader;

const SlotHistory = sig.runtime.sysvar.SlotHistory;

const Transaction = sig.core.transaction.Transaction;
const Pubkey = sig.core.Pubkey;
const SlotAndHash = sig.core.hash.SlotAndHash;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const Hash = sig.core.Hash;

const RwMux = sig.sync.RwMux;

pub const isSlotDuplicateConfirmed = sig.consensus.tower.isSlotDuplicateConfirmed;

const MAX_VOTE_REFRESH_INTERVAL_MILLIS: usize = 5000;

pub const ConsensusDependencies = struct {
    allocator: Allocator,
    replay_tower: *ReplayTower,
    progress_map: *ProgressMap,
    slot_tracker: *SlotTracker,
    epoch_tracker: *EpochTracker,
    fork_choice: *ForkChoice,
    blockstore_reader: *BlockstoreReader,
    ledger_result_writer: *LedgerResultWriter,
    ancestors: std.AutoHashMapUnmanaged(u64, SortedSet(u64)),
    descendants: std.AutoArrayHashMapUnmanaged(u64, SortedSet(u64)),
    vote_account: Pubkey,
    slot_history: SlotHistory,
    epoch_stakes: EpochStakeMap,
    latest_validator_votes_for_frozen_banks: LatestValidatorVotesForFrozenBanks,
};

pub fn processConsensus(maybe_deps: ?ConsensusDependencies) !void {
    const deps = if (maybe_deps) |deps|
        deps
    else
        return error.Todo;

    const heaviest_slot = deps.fork_choice.heaviestOverallSlot().slot;
    const heaviest_slot_on_same_voted_fork =
        (try deps.fork_choice.heaviestSlotOnSameVotedFork(deps.replay_tower)) orelse null;

    const heaviest_epoch: Epoch = deps.epoch_tracker.schedule.getEpoch(heaviest_slot);

    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = sig.time.Instant.now(),
        .last_print_time = sig.time.Instant.now(),
    };

    const vote_and_reset_forks = try deps.replay_tower.selectVoteAndResetForks(
        deps.allocator,
        heaviest_slot,
        if (heaviest_slot_on_same_voted_fork) |h| h.slot else null,
        heaviest_epoch,
        &deps.ancestors,
        &deps.descendants,
        deps.progress_map,
        &deps.latest_validator_votes_for_frozen_banks,
        deps.fork_choice,
        deps.epoch_stakes,
        &deps.slot_history,
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
        var found_slot = slot_tracker.slots.get(voted.slot) orelse
            return error.MissingSlot;

        const voted_hash = found_slot.state.hash.read().get().* orelse
            return error.MissingSlotInTracker;

        try handleVotableBank(
            deps.allocator,
            deps.blockstore_reader,
            voted.slot,
            voted_hash,
            deps.slot_tracker,
            deps.replay_tower,
            deps.progress_map,
            deps.fork_choice,
            deps.ledger_result_writer,
        );
    }

    // Reset onto a fork
    if (maybe_reset_slot) |reset_slot| {
        // TODO implement
        _ = &reset_slot;
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
        _ = &last_vote_tx_blockhash;
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
            _ = &vote_tx;
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
    var root_tracker = slot_tracker.slots.get(new_root) orelse return error.MissingSlot;
    const maybe_root_hash, var hash_lg = root_tracker.state.hash.readWithLock();
    defer hash_lg.unlock();
    const root_hash = maybe_root_hash.* orelse return error.MissingHash;

    const rooted_slots = try slot_tracker.parents(allocator, new_root);
    defer allocator.free(rooted_slots);

    // TODO implement leader_schedule_cache.set_root.
    try ledger_result_writer.setRoots(rooted_slots);

    // Audit: The rest of the code maps to Self::handle_new_root in Agave.
    slot_tracker.root = new_root;
    // TODO
    // - Prune program cache bank_forks.read().unwrap().prune_program_cache(new_root);
    // - Extra operations as part of setting new root:
    //   - cleare reward cache root_bank.clear_epoch_rewards_cache
    //   - extend banks banks.extend(parents.iter());
    //   - operations around snapshot_controller
    //   - After setting a new root, prune the banks that are no longer on rooted paths self.prune_non_rooted(root, highest_super_majority_root);

    // Update the progress map.
    var to_remove = try std.ArrayListUnmanaged(Slot).initCapacity(
        allocator,
        progress.map.count(),
    );
    defer to_remove.deinit(allocator);

    var it = progress.map.iterator();
    while (it.next()) |entry| {
        // TODO should frozen state be taking into consideration.
        if (slot_tracker.slots.get(entry.key_ptr.*) == null) {
            to_remove.appendAssumeCapacity(entry.key_ptr.*);
        }
    }

    for (to_remove.items) |key| {
        _ = progress.map.swapRemove(key);
    }

    // Update forkchoice
    try fork_choice.setTreeRoot(&.{
        .slot = new_root,
        .hash = root_hash,
    });
}

fn resetFork(
    progress: *const ProgressMap,
    blockstore: *const BlockstoreReader,
    reset_slot: Slot,
    last_reset_hash: Hash,
    last_blockhash: Hash,
    last_reset_bank_descendants: std.ArrayList(Slot),
) !void {
    _ = &progress;
    _ = &blockstore;
    _ = &reset_slot;
    _ = &last_reset_hash;
    _ = &last_blockhash;
    _ = &last_reset_bank_descendants;
}

const testing = std.testing;
const TreeNode = sig.consensus.fork_choice.TreeNode;
const TestDB = sig.ledger.tests.TestDB;
const TestFixture = sig.consensus.replay_tower.TestFixture;
const MAX_TEST_TREE_LEN = sig.consensus.replay_tower.MAX_TEST_TREE_LEN;
const Lockout = sig.runtime.program.vote.state.Lockout;
const createTestReplayTower = sig.consensus.replay_tower.createTestReplayTower;
const LtHash = sig.core.hash.LtHash;

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

    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = sig.time.Instant.now(),
        .last_print_time = sig.time.Instant.now(),
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

    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = sig.time.Instant.now(),
        .last_print_time = sig.time.Instant.now(),
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
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );

    var expected_slots = try std.ArrayListUnmanaged(Lockout).initCapacity(
        std.testing.allocator,
        3,
    );
    defer expected_slots.deinit(std.testing.allocator);
    var lockouts = [_]Lockout{
        Lockout{ .slot = 0, .confirmation_count = 3 },
        Lockout{ .slot = 1, .confirmation_count = 2 },
        Lockout{ .slot = 2, .confirmation_count = 1 },
    };
    try expected_slots.appendSlice(std.testing.allocator, &lockouts);
    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = expected_slots,
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };
    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = sig.time.Instant.now(),
        .last_print_time = sig.time.Instant.now(),
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
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );

    var expected_slots = try std.ArrayListUnmanaged(Lockout).initCapacity(
        std.testing.allocator,
        3,
    );
    defer expected_slots.deinit(std.testing.allocator);
    var lockouts = [_]Lockout{
        Lockout{ .slot = 3, .confirmation_count = 3 },
        Lockout{ .slot = 4, .confirmation_count = 2 },
        Lockout{ .slot = 5, .confirmation_count = 1 },
    };
    try expected_slots.appendSlice(std.testing.allocator, &lockouts);
    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = expected_slots,
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    replay_tower.last_vote_tx_blockhash = .non_voting;

    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = sig.time.Instant.now(),
        .last_print_time = sig.time.Instant.now(),
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
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );

    var expected_slots = try std.ArrayListUnmanaged(Lockout).initCapacity(
        std.testing.allocator,
        3,
    );
    defer expected_slots.deinit(std.testing.allocator);
    var lockouts = [_]Lockout{
        Lockout{ .slot = 3, .confirmation_count = 3 },
        Lockout{ .slot = 4, .confirmation_count = 2 },
        Lockout{ .slot = 5, .confirmation_count = 1 },
    };
    try expected_slots.appendSlice(std.testing.allocator, &lockouts);
    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = expected_slots,
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    replay_tower.last_vote_tx_blockhash = .hot_spare;

    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = sig.time.Instant.now(),
        .last_print_time = sig.time.Instant.now(),
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
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );

    var expected_slots = try std.ArrayListUnmanaged(Lockout).initCapacity(
        std.testing.allocator,
        3,
    );
    defer expected_slots.deinit(std.testing.allocator);
    var lockouts = [_]Lockout{
        Lockout{ .slot = 3, .confirmation_count = 3 },
        Lockout{ .slot = 4, .confirmation_count = 2 },
        Lockout{ .slot = 5, .confirmation_count = 1 },
    };
    try expected_slots.appendSlice(std.testing.allocator, &lockouts);
    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = expected_slots,
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    replay_tower.last_vote_tx_blockhash = .{ .blockhash = Hash.ZEROES };

    var last_vote_refresh_time: LastVoteRefreshTime = .{
        // Will last_vote_refresh_time.last_refresh_time.elapsed().asMillis() as zero
        // thereby satisfying the test condition of that value being
        // less than MAX_VOTE_REFRESH_INTERVAL_MILLIS
        .last_refresh_time = sig.time.Instant.now(),
        .last_print_time = sig.time.Instant.now(),
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
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );

    var expected_slots = try std.ArrayListUnmanaged(Lockout).initCapacity(
        std.testing.allocator,
        3,
    );
    defer expected_slots.deinit(std.testing.allocator);
    var lockouts = [_]Lockout{
        Lockout{ .slot = 3, .confirmation_count = 3 },
        Lockout{ .slot = 4, .confirmation_count = 2 },
        Lockout{ .slot = 5, .confirmation_count = 1 },
    };
    try expected_slots.appendSlice(std.testing.allocator, &lockouts);
    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = expected_slots,
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
            entry.value_ptr.*.constants.hard_forks.deinit(testing.allocator);
        }
        slot_tracker.slots.deinit(testing.allocator);
    }

    try slot_tracker.slots.put(testing.allocator, root.slot, .{
        .constants = .{
            .slot = 0,
            .parent_slot = 0,
            .parent_hash = Hash.ZEROES,
            .block_height = 0,
            .hard_forks = try .initRandom(random, testing.allocator, 10),
            .max_tick_height = 0,
            .fee_rate_governor = .initRandom(random),
            .epoch_reward_status = .inactive,
        },
        .state = .{
            .hash = RwMux(?Hash).init(null),
            .capitalization = std.atomic.Value(u64).init(0),
            .transaction_count = std.atomic.Value(u64).init(0),
            .tick_height = std.atomic.Value(u64).init(0),
            .collected_rent = std.atomic.Value(u64).init(0),
            .accounts_lt_hash = sig.sync.Mux(LtHash).init(LtHash{
                .data = [_]u16{0} ** LtHash.NUM_ELEMENTS,
            }),
        },
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
            entry.value_ptr.*.constants.hard_forks.deinit(testing.allocator);
        }
        slot_tracker.slots.deinit(testing.allocator);
    }

    try slot_tracker.slots.put(testing.allocator, root.slot, .{
        .constants = .{
            .slot = 0,
            .parent_slot = 0,
            .parent_hash = Hash.ZEROES,
            .block_height = 0,
            .hard_forks = try .initRandom(random, testing.allocator, 10),
            .max_tick_height = 0,
            .fee_rate_governor = .initRandom(random),
            .epoch_reward_status = .inactive,
        },
        .state = .{
            .hash = RwMux(?Hash).init(null),
            .capitalization = std.atomic.Value(u64).init(0),
            .transaction_count = std.atomic.Value(u64).init(0),
            .tick_height = std.atomic.Value(u64).init(0),
            .collected_rent = std.atomic.Value(u64).init(0),
            .accounts_lt_hash = sig.sync.Mux(LtHash).init(LtHash{
                .data = [_]u16{0} ** LtHash.NUM_ELEMENTS,
            }),
        },
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
            entry.value_ptr.*.constants.hard_forks.deinit(testing.allocator);
        }
        slot_tracker.slots.deinit(testing.allocator);
    }

    try slot_tracker.slots.put(testing.allocator, hash2.slot, .{
        .constants = .{
            .slot = hash2.slot,
            .parent_slot = hash1.slot,
            .parent_hash = Hash.ZEROES,
            .block_height = 0,
            .hard_forks = try .initRandom(random, testing.allocator, 10),
            .max_tick_height = 0,
            .fee_rate_governor = .initRandom(random),
            .epoch_reward_status = .inactive,
        },
        .state = .{
            .hash = RwMux(?Hash).init(hash2.hash),
            .capitalization = std.atomic.Value(u64).init(0),
            .transaction_count = std.atomic.Value(u64).init(0),
            .tick_height = std.atomic.Value(u64).init(0),
            .collected_rent = std.atomic.Value(u64).init(0),
            .accounts_lt_hash = sig.sync.Mux(LtHash).init(LtHash{
                .data = [_]u16{0} ** LtHash.NUM_ELEMENTS,
            }),
        },
    });
    try slot_tracker.slots.put(testing.allocator, hash3.slot, .{
        .constants = .{
            .slot = hash3.slot,
            .parent_slot = hash2.slot,
            .parent_hash = Hash.ZEROES,
            .block_height = 0,
            .hard_forks = try .initRandom(random, testing.allocator, 10),
            .max_tick_height = 0,
            .fee_rate_governor = .initRandom(random),
            .epoch_reward_status = .inactive,
        },
        .state = .{
            .hash = RwMux(?Hash).init(hash3.hash),
            .capitalization = std.atomic.Value(u64).init(0),
            .transaction_count = std.atomic.Value(u64).init(0),
            .tick_height = std.atomic.Value(u64).init(0),
            .collected_rent = std.atomic.Value(u64).init(0),
            .accounts_lt_hash = sig.sync.Mux(LtHash).init(LtHash{
                .data = [_]u16{0} ** LtHash.NUM_ELEMENTS,
            }),
        },
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

    try testing.expectEqual(3, fixture.progress.map.count());
    try testing.expect(fixture.progress.map.contains(hash1.slot));
    try checkAndHandleNewRoot(
        testing.allocator,
        &ledger_result_writer,
        &slot_tracker,
        &fixture.progress,
        &fixture.fork_choice,
        hash3.slot,
    );

    try testing.expectEqual(2, fixture.progress.map.count());
    try testing.expect(!fixture.progress.map.contains(hash1.slot));
}
