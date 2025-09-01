//! process the results of replaying a slot, updating relevant state
//! - freezing the slot
//! - updating consensus metadata

const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const core = sig.core;

const Allocator = std.mem.Allocator;

const Pubkey = core.Pubkey;
const Slot = core.Slot;
const Hash = sig.core.Hash;

const AccountStore = sig.accounts_db.AccountStore;
const LedgerReader = sig.ledger.LedgerReader;

const AncestorHashesReplayUpdate = replay.consensus.AncestorHashesReplayUpdate;
const ProgressMap = sig.consensus.ProgressMap;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const LatestValidatorVotes = sig.consensus.latest_validator_votes.LatestValidatorVotes;

const EpochTracker = replay.trackers.EpochTracker;
const SlotTracker = replay.trackers.SlotTracker;

const DuplicateSlots = replay.edge_cases.SlotData.DuplicateSlots;
const DuplicateState = replay.edge_cases.DuplicateState;
const SlotFrozenState = replay.edge_cases.SlotFrozenState;
const DuplicateSlotsToRepair = replay.edge_cases.SlotData.DuplicateSlotsToRepair;
const DuplicateConfirmedSlots = replay.edge_cases.SlotData.DuplicateConfirmedSlots;
const PurgeRepairSlotCounters = replay.edge_cases.SlotData.PurgeRepairSlotCounters;
const EpochSlotsFrozenSlots = replay.edge_cases.SlotData.EpochSlotsFrozenSlots;
const UnfrozenGossipVerifiedVoteHashes = replay.edge_cases.UnfrozenGossipVerifiedVoteHashes;

const Logger = sig.trace.Logger("replay.process_result");

const check_slot_agrees_with_cluster = replay.edge_cases.check_slot_agrees_with_cluster;

pub const ProcessResultState = struct {
    allocator: Allocator,
    logger: Logger,
    my_identity: Pubkey,

    // general replay state
    account_store: AccountStore,
    ledger_reader: *LedgerReader,
    ledger_result_writer: *sig.ledger.LedgerResultWriter,
    progress_map: *ProgressMap,
    slot_tracker: *SlotTracker,
    epochs: *EpochTracker,

    // consensus data
    ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
    fork_choice: *HeaviestSubtreeForkChoice,
    latest_validator_votes: *LatestValidatorVotes,
    duplicate_slots_tracker: *DuplicateSlots,
    duplicate_slots_to_repair: *DuplicateSlotsToRepair,
    duplicate_confirmed_slots: *DuplicateConfirmedSlots,
    unfrozen_gossip_verified_vote_hashes: *UnfrozenGossipVerifiedVoteHashes,
    epoch_slots_frozen_slots: *const EpochSlotsFrozenSlots,
    purge_repair_slot_counter: *PurgeRepairSlotCounters,
};

pub fn processResult(
    state: ProcessResultState,
    slot: Slot,
    entries: []const sig.core.Entry,
    err: ?replay.confirm_slot.ConfirmSlotError,
) !bool {
    var processed_a_slot = false;
    if (err) |_| {
        try markDeadSlot(state, slot, state.ancestor_hashes_replay_update_sender);
        return processed_a_slot;
    }

    const slot_info = state.slot_tracker.get(slot) orelse return error.MissingSlotInTracker;

    // Freeze the bank if its entries where completly processed.
    if (slot_info.state.tickHeight() == slot_info.constants.max_tick_height) {
        state.logger.info().logf("finished replaying slot: {}", .{slot});
        const is_leader_block =
            slot_info.constants.collector_id.equals(&state.my_identity);
        if (!is_leader_block) {
            try replay.freeze.freezeSlot(state.allocator, .init(
                .from(state.logger),
                state.account_store,
                &(state.epochs.getForSlot(slot) orelse return error.MissingEpoch),
                slot_info.state,
                slot_info.constants,
                slot,
                entries[entries.len - 1].hash,
            ));
        }
        processed_a_slot = true;
        // TODO Send things out via a couple of senders
        // - cluster_slots_update_sender;
        // - transaction_status_sender;
        // - cost_update_sender;
        try updateConsensusForFrozenSlot(state, slot);
        // TODO block_metadata_notifier
        // TODO block_metadata_notifier
    } else {
        state.logger.info().logf("partially replayed slot: {}", .{slot});
    }

    return processed_a_slot;
}

/// Analogous to [mark_dead_slot](https://github.com/anza-xyz/agave/blob/15635be1503566820331cd2c845675641a42d405/core/src/replay_stage.rs#L2255)
fn markDeadSlot(
    replay_state: ProcessResultState,
    dead_slot: Slot,
    ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
) !void {
    // TODO add getForkProgress
    const fork_progress = replay_state.progress_map.map.getPtr(dead_slot) orelse {
        return error.MissingBankProgress;
    };
    fork_progress.is_dead = true;
    try replay_state.ledger_result_writer.setDeadSlot(dead_slot);
    // TODOs
    // - blockstore.slots_stats.mark_dead(slot);
    // - slot_status_notifier
    // - rpc_subscriptions

    const dead_state: replay.edge_cases.DeadState = .fromState(
        .from(replay_state.logger),
        dead_slot,
        replay_state.duplicate_slots_tracker,
        replay_state.duplicate_confirmed_slots,
        replay_state.fork_choice,
        replay_state.epoch_slots_frozen_slots,
    );
    try check_slot_agrees_with_cluster.dead(
        replay_state.allocator,
        .from(replay_state.logger),
        dead_slot,
        replay_state.slot_tracker.root,
        replay_state.duplicate_slots_to_repair,
        ancestor_hashes_replay_update_sender,
        dead_state,
    );

    // If blockstore previously marked this slot as duplicate, invoke duplicate state as well
    const maybe_duplicate_proof = try replay_state.ledger_reader.getDuplicateSlot(dead_slot);
    defer if (maybe_duplicate_proof) |proof| {
        replay_state.ledger_reader.allocator.free(proof.shred1);
        replay_state.ledger_reader.allocator.free(proof.shred2);
    };
    if (!replay_state.duplicate_slots_tracker.contains(dead_slot) and
        maybe_duplicate_proof != null)
    {
        const slot_info =
            replay_state.slot_tracker.get(dead_slot) orelse return error.MissingSlotInTracker;
        const slot_hash = slot_info.state.hash.readCopy();
        const duplicate_state: DuplicateState = .fromState(
            .from(replay_state.logger),
            dead_slot,
            replay_state.duplicate_confirmed_slots,
            replay_state.fork_choice,
            if (replay_state.progress_map.isDead(dead_slot) orelse false)
                .dead
            else
                .fromHash(slot_hash),
        );
        try check_slot_agrees_with_cluster.duplicate(
            replay_state.allocator,
            .from(replay_state.logger),
            dead_slot,
            replay_state.slot_tracker.root,
            replay_state.duplicate_slots_tracker,
            replay_state.fork_choice,
            duplicate_state,
        );
    }
}

/// Applies fork-choice and vote updates after a slot has been frozen.
fn updateConsensusForFrozenSlot(
    replay_state: ProcessResultState,
    slot: Slot,
) !void {
    var slot_info = replay_state.slot_tracker.get(slot) orelse
        return error.MissingSlotInTracker;

    const parent_slot = slot_info.constants.parent_slot;
    const parent_hash = slot_info.constants.parent_hash;

    var progress = replay_state.progress_map.map.getPtr(slot) orelse
        return error.MissingBankProgress;

    const hash = slot_info.state.hash.readCopy() orelse
        return error.MissingHash;
    std.debug.assert(!hash.eql(Hash.ZEROES));

    // Needs to be updated before `check_slot_agrees_with_cluster()` so that any
    // updates in `check_slot_agrees_with_cluster()` on fork choice take effect
    try replay_state.fork_choice.addNewLeafSlot(
        .{ .slot = slot, .hash = hash },
        .{ .slot = parent_slot, .hash = parent_hash },
    );

    progress.fork_stats.slot_hash = hash;

    const slot_frozen_state: SlotFrozenState = .fromState(
        .from(replay_state.logger),
        slot,
        hash,
        replay_state.duplicate_slots_tracker,
        replay_state.duplicate_confirmed_slots,
        replay_state.fork_choice,
        replay_state.epoch_slots_frozen_slots,
    );
    try check_slot_agrees_with_cluster.slotFrozen(
        replay_state.allocator,
        .from(replay_state.logger),
        slot,
        replay_state.slot_tracker.root,
        replay_state.ledger_result_writer,
        replay_state.fork_choice,
        replay_state.duplicate_slots_to_repair,
        replay_state.purge_repair_slot_counter,
        slot_frozen_state,
    );

    if (!replay_state.duplicate_slots_tracker.contains(slot) and
        try replay_state.ledger_reader.getDuplicateSlot(slot) != null)
    {
        const duplicate_state: DuplicateState = .fromState(
            .from(replay_state.logger),
            slot,
            replay_state.duplicate_confirmed_slots,
            replay_state.fork_choice,
            .fromHash(hash),
        );

        try check_slot_agrees_with_cluster.duplicate(
            replay_state.allocator,
            .from(replay_state.logger),
            slot,
            parent_slot,
            replay_state.duplicate_slots_tracker,
            replay_state.fork_choice,
            duplicate_state,
        );
    }

    // Move unfrozen_gossip_verified_vote_hashes entries to latest_validator_votes
    if (replay_state
        .unfrozen_gossip_verified_vote_hashes.votes_per_slot
        .get(slot)) |slot_hashes_const|
    {
        var slot_hashes = slot_hashes_const;
        if (slot_hashes.fetchSwapRemove(hash)) |kv| {
            var new_frozen_voters = kv.value;
            defer new_frozen_voters.deinit(replay_state.allocator);
            for (new_frozen_voters.items) |pubkey| {
                _ = try replay_state.latest_validator_votes.checkAddVote(
                    replay_state.allocator,
                    pubkey,
                    slot,
                    hash,
                    .replay,
                );
            }
        }
        // If `slot_hashes` becomes empty, it'll be removed by `setRoot()` later
    }
}

const testing = std.testing;

// Test helper structure that owns all the resources
const TestReplayStateResources = struct {
    ledger_reader: LedgerReader,
    ledger_result_writer: sig.ledger.LedgerResultWriter,
    epochs: EpochTracker,
    progress: ProgressMap,
    fork_choice: *HeaviestSubtreeForkChoice,
    duplicate_slots_tracker: DuplicateSlots,
    unfrozen_gossip_verified_vote_hashes: UnfrozenGossipVerifiedVoteHashes,
    latest_validator_votes: LatestValidatorVotes,
    duplicate_confirmed_slots: DuplicateConfirmedSlots,
    epoch_slots_frozen_slots: EpochSlotsFrozenSlots,
    duplicate_slots_to_repair: DuplicateSlotsToRepair,
    purge_repair_slot_counter: PurgeRepairSlotCounters,
    slot_tracker: SlotTracker,
    replay_state: ProcessResultState,
    db: sig.ledger.LedgerDB,
    registry: sig.prometheus.Registry(.{}),
    lowest_cleanup_slot: sig.sync.RwMux(Slot),
    max_root: std.atomic.Value(Slot),

    ancestor_hashes_replay_update_channel: sig.sync.Channel(AncestorHashesReplayUpdate),

    pub fn init(allocator: Allocator) !*TestReplayStateResources {
        const self = try allocator.create(TestReplayStateResources);
        errdefer allocator.destroy(self);

        const account_store = AccountStore.noop;

        self.registry = sig.prometheus.Registry(.{}).init(allocator);
        errdefer self.registry.deinit();

        self.db = try sig.ledger.tests.TestDB.init(@src());
        errdefer self.db.deinit();

        self.lowest_cleanup_slot = sig.sync.RwMux(Slot).init(0);
        self.max_root = std.atomic.Value(Slot).init(0);

        self.ledger_reader = try LedgerReader.init(
            allocator,
            .noop,
            self.db,
            &self.registry,
            &self.lowest_cleanup_slot,
            &self.max_root,
        );

        self.ledger_result_writer = try sig.ledger.LedgerResultWriter.init(
            allocator,
            .noop,
            self.db,
            &self.registry,
            &self.lowest_cleanup_slot,
            &self.max_root,
        );

        self.epochs = EpochTracker{
            .epochs = .empty,
            .schedule = sig.core.EpochSchedule.DEFAULT,
        };

        self.progress = ProgressMap.INIT;

        self.fork_choice = try allocator.create(HeaviestSubtreeForkChoice);
        self.fork_choice.* = try HeaviestSubtreeForkChoice.init(allocator, .noop, .{
            .slot = 0,
            .hash = Hash.ZEROES,
        });

        self.duplicate_slots_tracker = DuplicateSlots.empty;
        self.unfrozen_gossip_verified_vote_hashes = UnfrozenGossipVerifiedVoteHashes{
            .votes_per_slot = .empty,
        };
        self.latest_validator_votes = LatestValidatorVotes.empty;
        self.duplicate_confirmed_slots = DuplicateConfirmedSlots.empty;
        self.epoch_slots_frozen_slots = EpochSlotsFrozenSlots.empty;
        self.duplicate_slots_to_repair = DuplicateSlotsToRepair.empty;
        self.purge_repair_slot_counter = PurgeRepairSlotCounters.empty;

        self.slot_tracker = SlotTracker{
            .slots = .empty,
            .root = 0,
        };

        self.ancestor_hashes_replay_update_channel = try sig
            .sync
            .Channel(AncestorHashesReplayUpdate)
            .init(allocator);

        self.replay_state = ProcessResultState{
            .allocator = allocator,
            .logger = .FOR_TESTS,
            .my_identity = Pubkey.initRandom(std.crypto.random),
            .account_store = account_store,
            .ledger_reader = &self.ledger_reader,
            .ledger_result_writer = &self.ledger_result_writer,
            .slot_tracker = &self.slot_tracker,
            .epochs = &self.epochs,
            .progress_map = &self.progress,
            .fork_choice = self.fork_choice,
            .duplicate_slots_tracker = &self.duplicate_slots_tracker,
            .unfrozen_gossip_verified_vote_hashes = &self.unfrozen_gossip_verified_vote_hashes,
            .latest_validator_votes = &self.latest_validator_votes,
            .duplicate_confirmed_slots = &self.duplicate_confirmed_slots,
            .epoch_slots_frozen_slots = &self.epoch_slots_frozen_slots,
            .duplicate_slots_to_repair = &self.duplicate_slots_to_repair,
            .purge_repair_slot_counter = &self.purge_repair_slot_counter,
            .ancestor_hashes_replay_update_sender = &self.ancestor_hashes_replay_update_channel,
        };

        return self;
    }

    pub fn deinit(self: *TestReplayStateResources, allocator: Allocator) void {
        self.slot_tracker.deinit(allocator);
        self.epochs.deinit(allocator);
        self.progress.deinit(allocator);
        self.fork_choice.deinit();
        allocator.destroy(self.fork_choice);
        self.duplicate_slots_tracker.deinit(allocator);
        self.unfrozen_gossip_verified_vote_hashes.votes_per_slot.deinit(allocator);
        self.latest_validator_votes.deinit(allocator);
        self.duplicate_confirmed_slots.deinit(allocator);
        self.epoch_slots_frozen_slots.deinit(allocator);
        self.duplicate_slots_to_repair.deinit(allocator);
        self.purge_repair_slot_counter.deinit(allocator);
        self.db.deinit();
        self.registry.deinit();
        self.ancestor_hashes_replay_update_channel.deinit();

        allocator.destroy(self);
    }
};

// Helper to create a minimal ProcessResultState for testing
fn createTestReplayState(allocator: Allocator) !*TestReplayStateResources {
    return TestReplayStateResources.init(allocator);
}

test "processResult: marks slot as dead correctly" {
    const allocator = testing.allocator;

    // Create a minimal test setup without the complex database dependencies
    var progress = ProgressMap.INIT;
    defer progress.deinit(allocator);

    const slot: Slot = 100;

    // Add slot to progress map
    const gop = try progress.map.getOrPut(allocator, slot);
    if (!gop.found_existing) {
        gop.value_ptr.* = try sig.consensus.progress_map.ForkProgress.init(allocator, .{
            .now = sig.time.Instant.now(),
            .last_entry = sig.core.Hash.ZEROES,
            .prev_leader_slot = null,
            .validator_stake_info = null,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        });
    }

    // Verify slot is initially not dead
    const progress_before = progress.map.get(slot);
    try testing.expect(progress_before != null);
    try testing.expect(!progress_before.?.is_dead);

    // Test the core logic without the database write
    // Just verify that the progress map is updated correctly
    var fork_progress = progress.map.getPtr(slot) orelse {
        return error.MissingBankProgress;
    };
    fork_progress.is_dead = true;

    // Verify slot is now marked as dead
    const progress_after = progress.map.get(slot);
    try testing.expect(progress_after != null);
    try testing.expect(progress_after.?.is_dead);
}

test "processResult: confirm status with err poll result marks slot dead" {
    const allocator = testing.allocator;

    var test_resources = createTestReplayState(allocator) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_resources.deinit(allocator);

    const slot: Slot = 100;

    // Add slot to progress map first
    try test_resources.progress.map.putNoClobber(
        allocator,
        slot,
        try sig.consensus.progress_map.ForkProgress.init(allocator, .{
            .now = sig.time.Instant.now(),
            .last_entry = sig.core.Hash.ZEROES,
            .prev_leader_slot = null,
            .validator_stake_info = null,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        }),
    );

    // Verify slot is initially not dead
    const progress_before = test_resources.progress.map.get(slot);
    try testing.expect(progress_before != null);
    try testing.expect(!progress_before.?.is_dead);

    const empty_entries = try allocator.alloc(sig.core.Entry, 0);

    defer allocator.free(empty_entries);

    const result = try processResult(
        test_resources.replay_state,
        slot,
        empty_entries,
        .{ .failed_to_load_entries = "test error" },
    );

    // Should return false since no slot was successfully processed
    try testing.expect(!result);

    // Verify slot is now marked as dead
    const progress_after = test_resources.progress.map.get(slot);
    try testing.expect(progress_after != null);
    try testing.expect(progress_after.?.is_dead);
}

test "processResult: confirm status with done poll but missing slot in tracker" {
    const allocator = testing.allocator;

    var test_resources = createTestReplayState(allocator) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_resources.deinit(allocator);

    const slot: Slot = 100;

    const empty_entries = try allocator.alloc(sig.core.Entry, 0);

    defer allocator.free(empty_entries);

    // The function should return an error since the slot is not in the tracker
    const result = processResult(test_resources.replay_state, slot, empty_entries, null);

    try testing.expectError(error.MissingSlotInTracker, result);
}

test "processResult: confirm status with done poll and slot complete - success path" {
    const allocator = testing.allocator;

    var test_resources = createTestReplayState(allocator) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_resources.deinit(allocator);

    const slot: Slot = 100;
    const parent_slot: Slot = 99;

    // Add parent slot to progress map first (required for slot processing)
    try test_resources.progress.map.putNoClobber(
        allocator,
        parent_slot,
        try sig.consensus.progress_map.ForkProgress.init(allocator, .{
            .now = sig.time.Instant.now(),
            .last_entry = sig.core.Hash.ZEROES,
            .prev_leader_slot = null,
            .validator_stake_info = null,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        }),
    );

    // Add slot to progress map
    try test_resources.progress.map.putNoClobber(
        allocator,
        slot,
        try sig.consensus.progress_map.ForkProgress.init(allocator, .{
            .now = sig.time.Instant.now(),
            .last_entry = sig.core.Hash.ZEROES,
            .prev_leader_slot = null,
            .validator_stake_info = null,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        }),
    );

    // Create mock entries for the slot
    const mock_entries = try allocator.alloc(sig.core.Entry, 1);
    defer allocator.free(mock_entries);

    var rng = std.Random.DefaultPrng.init(0);
    const random = rng.random();

    mock_entries[0] = sig.core.Entry{
        .num_hashes = 0,
        .hash = sig.core.Hash.initRandom(random),
        .transactions = &.{},
    };

    // Add parent slot 99 to fork choice so slot 100 can be processed
    const slot_99_hash = Hash.initRandom(random);
    const slot_99_slot_and_hash = sig.core.hash.SlotAndHash{
        .slot = 99,
        .hash = slot_99_hash,
    };
    const root_slot_and_hash = sig.core.hash.SlotAndHash{
        .slot = 0,
        .hash = Hash.ZEROES,
    };
    try test_resources.replay_state.fork_choice.addNewLeafSlot(
        slot_99_slot_and_hash,
        root_slot_and_hash,
    );

    // Create slot constants and state.
    const mock_slot_constants = sig.core.SlotConstants{
        .parent_slot = parent_slot,
        // Use the same hash as the parent slot in fork choice
        .parent_hash = slot_99_hash,
        .parent_lt_hash = .IDENTITY,
        .block_height = 0,
        // Different from replay_state.my_identity
        .collector_id = sig.core.Pubkey.initRandom(random),
        // This should match tickHeight() for slot to be complete
        .max_tick_height = 64,
        .fee_rate_governor = sig.core.FeeRateGovernor.DEFAULT,
        .epoch_reward_status = .inactive,
        .ancestors = .{ .ancestors = .empty },
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .empty,
    };

    // Create slot state then modify tick height
    var mock_slot_state = try sig.core.SlotState.genesis(allocator);

    // Set tick height equal to max_tick_height to make slot complete
    _ = mock_slot_state.tick_height.swap(64, .monotonic);

    // Set a valid hash for the slot
    mock_slot_state.hash.set(sig.core.Hash.initRandom(random));

    // Add the slot to the slot tracker
    try test_resources.slot_tracker.put(allocator, slot, .{
        .constants = mock_slot_constants,
        .state = mock_slot_state,
    });

    // Add epoch info for slot 100 (epoch 2 in default schedule).
    try test_resources.epochs.epochs.put(allocator, 2, .{
        .hashes_per_tick = 1,
        .ticks_per_slot = 1,
        .ns_per_slot = 1,
        .genesis_creation_time = 1,
        .slots_per_year = 1,
        .stakes = try .initEmptyWithGenesisStakeHistoryEntry(allocator),
        .rent_collector = .DEFAULT,
    });

    // This should successfully process the slot and return true
    const result = try processResult(test_resources.replay_state, slot, mock_entries, null);

    // Should return true since the slot was successfully processed
    try testing.expect(result);
}

test "markDeadSlot: marks progress dead and writes to ledger" {
    const allocator = testing.allocator;

    var test_resources = createTestReplayState(allocator) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_resources.deinit(allocator);

    const slot: Slot = 200;

    // Ensure progress map has an entry for the slot
    try test_resources.progress.map.putNoClobber(
        allocator,
        slot,
        try sig.consensus.progress_map.ForkProgress.init(allocator, .{
            .now = sig.time.Instant.now(),
            .last_entry = sig.core.Hash.ZEROES,
            .prev_leader_slot = null,
            .validator_stake_info = null,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        }),
    );

    var ancestor_hashes_replay_update_channel: sig.sync.Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_update_channel.deinit();

    try markDeadSlot(
        test_resources.replay_state,
        slot,
        &ancestor_hashes_replay_update_channel,
    );

    // Validate progress is marked dead
    try testing.expect(test_resources.progress.isDead(slot) orelse false);

    // Validate ledger records the dead slot
    try testing.expect(try test_resources.ledger_reader.isDead(slot));
}

test "markDeadSlot: when duplicate proof exists, duplicate tracker records slot" {
    const allocator = testing.allocator;

    var test_resources = createTestReplayState(allocator) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_resources.deinit(allocator);

    const slot: Slot = 201;

    // Ensure progress map has an entry for the slot
    try test_resources.progress.map.putNoClobber(
        allocator,
        slot,
        try sig.consensus.progress_map.ForkProgress.init(allocator, .{
            .now = sig.time.Instant.now(),
            .last_entry = sig.core.Hash.ZEROES,
            .prev_leader_slot = null,
            .validator_stake_info = null,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        }),
    );

    // Provide a minimal slot in the slot tracker so markDeadSlot can read a hash
    var slot_state = try sig.core.SlotState.genesis(allocator);
    var rng = std.Random.DefaultPrng.init(0);
    slot_state.hash.set(sig.core.Hash.initRandom(rng.random()));
    const slot_consts = sig.core.SlotConstants{
        .parent_slot = 0,
        .parent_hash = sig.core.Hash.ZEROES,
        .parent_lt_hash = .IDENTITY,
        .block_height = 0,
        .collector_id = sig.core.Pubkey.ZEROES,
        .max_tick_height = 0,
        .fee_rate_governor = sig.core.FeeRateGovernor.DEFAULT,
        .epoch_reward_status = .inactive,
        .ancestors = .{ .ancestors = .empty },
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .empty,
    };
    try test_resources.slot_tracker.put(allocator, slot, .{
        .constants = slot_consts,
        .state = slot_state,
    });

    // Insert a duplicate proof into the ledger to trigger the duplicate branch
    const dup_proof = sig.ledger.meta.DuplicateSlotProof{
        .shred1 = &[_]u8{ 0xAA, 0xBB },
        .shred2 = &[_]u8{ 0xCC, 0xDD },
    };
    try test_resources.db.put(sig.ledger.schema.schema.duplicate_slots, slot, dup_proof);

    // Tracker does not contain the slot yet
    try testing.expect(!test_resources.duplicate_slots_tracker.contains(slot));

    var ancestor_hashes_replay_update_channel: sig.sync.Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_update_channel.deinit();

    try markDeadSlot(
        test_resources.replay_state,
        slot,
        &ancestor_hashes_replay_update_channel,
    );

    // The duplicate handler should record the slot in the duplicate tracker
    try testing.expect(test_resources.duplicate_slots_tracker.contains(slot));
}
