const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const ArrayListUnmanaged = std.ArrayListUnmanaged;

const LedgerResultWriter = sig.ledger.result_writer.LedgerResultWriter;

const SortedSet = sig.utils.collections.SortedSet;
const ReplayTower = sig.consensus.replay_tower.ReplayTower;
const ProgressMap = sig.consensus.progress_map.ProgressMap;
const VotedStakes = sig.consensus.progress_map.consensus.VotedStakes;
const ForkChoice = sig.consensus.fork_choice.ForkChoice;
const LatestValidatorVotesForFrozenBanks =
    sig.consensus.unimplemented.LatestValidatorVotesForFrozenBanks;

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
    vote_account: Pubkey,
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
    const ancestors: std.AutoHashMapUnmanaged(u64, SortedSet(u64)) = .empty;
    const descendants: std.AutoArrayHashMapUnmanaged(u64, SortedSet(u64)) = .empty;

    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = sig.time.Instant.now(),
        .last_print_time = sig.time.Instant.now(),
    };
    const latest_validator_votes_for_frozen_banks = LatestValidatorVotesForFrozenBanks{
        .max_gossip_frozen_votes = .{},
    };
    const bits = try sig.bloom.bit_set.DynamicArrayBitSet(u64).initEmpty(deps.allocator, 10);
    defer bits.deinit(deps.allocator);
    const slot_history = SlotHistory{ .bits = bits, .next_slot = 0 };

    const vote_and_reset_forks = try deps.replay_tower.selectVoteAndResetForks(
        deps.allocator,
        heaviest_slot,
        if (heaviest_slot_on_same_voted_fork) |h| h.slot else null,
        heaviest_epoch,
        &ancestors,
        &descendants,
        deps.progress_map,
        &latest_validator_votes_for_frozen_banks,
        deps.fork_choice,
        .{},
        &slot_history,
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
        // Implemented the log
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

/// Identifies and returns slots that should be marked as "duplicate confirmed" based on
/// the validator's voting state and stake distribution.
///
/// "Duplicate confirmed" means the slot has received enough stake-weighted votes
/// from validators to be considered definitively confirmed by the network,
/// even if there are multiple competing versions of that slot.
///
/// This means the slot becomes a valid candidate for fork selection and
/// can influence which chain the validator builds upon.
///
/// Note: 1. This is "duplicate confirmed", which is different from "regular" confirmation,
/// where a slot is simply processed and frozen.
/// Note: 2. The slot is skipped if it is already duplicate confirmed in the progress map's fork state
///          or if the slot is not already frozen.
fn towerDuplicateConfirmedForks(
    allocator: std.mem.Allocator,
    progress_map: *const ProgressMap,
    slot_tracker: *const SlotTracker,
    vote_stakes: VotedStakes,
    total_stake: u64,
    slot: Slot,
) ![]const SlotAndHash {
    var duplicate_confirmed_forks: ArrayListUnmanaged(SlotAndHash) = .{};

    var it = progress_map.map.iterator();
    while (it.next()) |entry| {
        const entry_slot = entry.key_ptr.*;
        const fork_progress = entry.value_ptr.*;
        if (fork_progress.fork_stats.duplicate_confirmed_hash != null) continue;

        var found_slot = slot_tracker.slots.get(entry_slot) orelse
            return error.MissingSlot;

        //TODO should found_slot.state.hash be a mutex
        const found_slot_hash = found_slot.state.hash.read().get().* orelse
            return error.MissingSlotInTracker;
        var state = found_slot.state;
        if (!state.isFrozen()) {
            continue;
        }

        const is_slot_duplicate_confirmed = isSlotDuplicateConfirmed(
            slot,
            &vote_stakes,
            total_stake,
        );

        if (is_slot_duplicate_confirmed) {
            try duplicate_confirmed_forks.append(
                allocator,
                SlotAndHash{
                    .slot = slot,
                    .hash = found_slot_hash,
                },
            );
        }
    }
    return try duplicate_confirmed_forks.toOwnedSlice(allocator);
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

fn handleVotableBank(
    allocator: std.mem.Allocator,
    blockstore_reader: *BlockstoreReader,
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
            blockstore_reader,
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

fn checkAndHandleNewRoot(
    allocator: std.mem.Allocator,
    blockstore_reader: *BlockstoreReader,
    slot_tracker: *SlotTracker,
    progress: *ProgressMap,
    fork_choice: *ForkChoice,
    new_root: Slot,
) !void {
    // get the root bank before squash.
    var root_tracker = slot_tracker.slots.get(new_root) orelse return error.MissingSlot;
    const root_hash, var hash_lg = root_tracker.state.hash.readWithLock();
    defer hash_lg.unlock();

    const rooted_slots = try slot_tracker.parents(allocator, new_root);

    if (slot_tracker.slots.count() == 0) return error.EmptySlotTracker;
    // TODO implement leader_schedule_cache.set_root.

    // TODO have this a seperate function?
    {
        // TODO revisit these values.
        var lowest_cleanup_slot = RwMux(Slot).init(0);
        var max_root = std.atomic.Value(Slot).init(0);
        var registry = sig.prometheus.Registry(.{}).init(allocator);
        defer registry.deinit();

        var writer = LedgerResultWriter{
            .allocator = allocator,
            .db = blockstore_reader.db,
            .logger = .noop,
            .lowest_cleanup_slot = &lowest_cleanup_slot,
            .max_root = &max_root,
            .scan_and_fix_roots_metrics = try registry.initStruct(
                sig.ledger.result_writer.ScanAndFixRootsMetrics,
            ),
        };

        try writer.setRoots(rooted_slots);
    }

    // Audit: The rest of the code maps to Self::handle_new_root in Agave.
    // Update the progress map.
    // TODO Move to its own function?
    {
        var to_remove = try std.ArrayListUnmanaged(Slot).initCapacity(
            allocator,
            progress.map.count(),
        );
        defer to_remove.deinit();

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
    }

    // Update forkchoice
    try fork_choice.setTreeRoot(&.{
        .slot = new_root,
        .hash = root_hash.* orelse return error.MissingHash,
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
        std.testing.allocator,
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
        std.testing.allocator,
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
        std.testing.allocator,
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
        std.testing.allocator,
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
        std.testing.allocator,
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
        std.testing.allocator,
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
        std.testing.allocator,
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
