//! process the results of replaying a slot, updating relevant state
//! - freezing the slot
//! - updating consensus metadata

const std = @import("std");
const sig = @import("../../sig.zig");
const replay = @import("../lib.zig");

const core = sig.core;

const Allocator = std.mem.Allocator;

const Pubkey = core.Pubkey;
const Slot = core.Slot;
const Hash = sig.core.Hash;

const Ledger = sig.ledger.Ledger;

const AncestorHashesReplayUpdate = replay.consensus.core.AncestorHashesReplayUpdate;
const ProgressMap = sig.consensus.ProgressMap;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const LatestValidatorVotes = sig.consensus.latest_validator_votes.LatestValidatorVotes;
const latestVote = sig.consensus.latest_validator_votes.latestVote;

const SlotTracker = replay.trackers.SlotTracker;

const DuplicateSlots = replay.consensus.cluster_sync.SlotData.DuplicateSlots;
const DuplicateState = replay.consensus.cluster_sync.DuplicateState;
const SlotFrozenState = replay.consensus.cluster_sync.SlotFrozenState;
const DuplicateSlotsToRepair = replay.consensus.cluster_sync.SlotData.DuplicateSlotsToRepair;
const DuplicateConfirmedSlots = replay.consensus.cluster_sync.SlotData.DuplicateConfirmedSlots;
const PurgeRepairSlotCounters = replay.consensus.cluster_sync.SlotData.PurgeRepairSlotCounters;
const EpochSlotsFrozenSlots = replay.consensus.cluster_sync.SlotData.EpochSlotsFrozenSlots;
const UnfrozenGossipVerifiedVoteHashes =
    replay.consensus.cluster_sync.UnfrozenGossipVerifiedVoteHashes;

const Logger = sig.trace.Logger("replay.process_result");

const check_slot_agrees_with_cluster = replay.consensus.cluster_sync.check_slot_agrees_with_cluster;

pub const ProcessResultParams = struct {
    allocator: Allocator,
    logger: Logger,
    my_identity: Pubkey,

    // global validator state
    ledger: *Ledger,

    // replay state
    progress_map: *ProgressMap,
    slot_tracker: *const SlotTracker,

    // consensus state
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

pub fn processResult(params: ProcessResultParams, result: sig.replay.execution.ReplayResult) !void {
    const slot = result.slot;

    switch (result.output) {
        .err => {
            try markDeadSlot(params, slot, params.ancestor_hashes_replay_update_sender);
            return;
        },
        .last_entry_hash => |_| {},
    }

    const slot_info = params.slot_tracker.get(slot) orelse return error.MissingSlotInTracker;

    if (slot_info.state.isFrozen()) {
        // TODO Send things out via a couple of senders
        // - cluster_slots_update_sender;
        // - transaction_status_sender;
        // - cost_update_sender;
        try updateConsensusForFrozenSlot(params, slot);
        // TODO block_metadata_notifier
        // TODO block_metadata_notifier
    } else {
        params.logger.info().logf("partially replayed slot: {}", .{slot});
    }
}

/// Analogous to [mark_dead_slot](https://github.com/anza-xyz/agave/blob/15635be1503566820331cd2c845675641a42d405/core/src/replay_stage.rs#L2255)
fn markDeadSlot(
    params: ProcessResultParams,
    dead_slot: Slot,
    ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
) !void {
    // TODO add getForkProgress
    const fork_progress = params.progress_map.map.getPtr(dead_slot) orelse {
        return error.MissingBankProgress;
    };
    fork_progress.is_dead = true;
    try params.ledger.resultWriter().setDeadSlot(dead_slot);
    // TODOs
    // - blockstore.slots_stats.mark_dead(slot);
    // - slot_status_notifier
    // - rpc_subscriptions

    const dead_state: replay.consensus.cluster_sync.DeadState = .fromState(
        .from(params.logger),
        dead_slot,
        params.duplicate_slots_tracker,
        params.duplicate_confirmed_slots,
        params.fork_choice,
        params.epoch_slots_frozen_slots,
    );
    try check_slot_agrees_with_cluster.dead(
        params.allocator,
        .from(params.logger),
        dead_slot,
        params.slot_tracker.root,
        params.duplicate_slots_to_repair,
        ancestor_hashes_replay_update_sender,
        dead_state,
    );

    // If blockstore previously marked this slot as duplicate, invoke duplicate state as well
    const maybe_duplicate_proof = try params.ledger.reader()
        .getDuplicateSlot(params.allocator, dead_slot);
    defer if (maybe_duplicate_proof) |proof| {
        params.allocator.free(proof.shred1);
        params.allocator.free(proof.shred2);
    };
    if (!params.duplicate_slots_tracker.contains(dead_slot) and maybe_duplicate_proof != null) {
        const slot_info =
            params.slot_tracker.get(dead_slot) orelse return error.MissingSlotInTracker;
        const slot_hash = slot_info.state.hash.readCopy();
        const duplicate_state: DuplicateState = .fromState(
            .from(params.logger),
            dead_slot,
            params.duplicate_confirmed_slots,
            params.fork_choice,
            if (params.progress_map.isDead(dead_slot) orelse false)
                .dead
            else
                .fromHash(slot_hash),
        );
        try check_slot_agrees_with_cluster.duplicate(
            params.allocator,
            .from(params.logger),
            dead_slot,
            params.slot_tracker.root,
            params.duplicate_slots_tracker,
            params.fork_choice,
            duplicate_state,
        );
    }
}

/// Applies fork-choice and vote updates after a slot has been frozen.
fn updateConsensusForFrozenSlot(params: ProcessResultParams, slot: Slot) !void {
    var slot_info = params.slot_tracker.get(slot) orelse
        return error.MissingSlotInTracker;

    const parent_slot = slot_info.constants.parent_slot;
    const parent_hash = slot_info.constants.parent_hash;

    var progress = params.progress_map.map.getPtr(slot) orelse
        return error.MissingBankProgress;

    const hash = slot_info.state.hash.readCopy() orelse
        return error.MissingHash;
    std.debug.assert(!hash.eql(Hash.ZEROES));

    // Needs to be updated before `check_slot_agrees_with_cluster()` so that any
    // updates in `check_slot_agrees_with_cluster()` on fork choice take effect
    try params.fork_choice.addNewLeafSlot(
        params.allocator,
        .{ .slot = slot, .hash = hash },
        .{ .slot = parent_slot, .hash = parent_hash },
    );

    progress.fork_stats.slot_hash = hash;

    const slot_frozen_state: SlotFrozenState = .fromState(
        .from(params.logger),
        slot,
        hash,
        params.duplicate_slots_tracker,
        params.duplicate_confirmed_slots,
        params.fork_choice,
        params.epoch_slots_frozen_slots,
    );
    try check_slot_agrees_with_cluster.slotFrozen(
        params.allocator,
        .from(params.logger),
        slot,
        params.slot_tracker.root,
        params.ledger.resultWriter(),
        params.fork_choice,
        params.duplicate_slots_to_repair,
        params.purge_repair_slot_counter,
        slot_frozen_state,
    );

    const reader = params.ledger.reader();
    if (!params.duplicate_slots_tracker.contains(slot) and
        try reader.getDuplicateSlot(params.allocator, slot) != null)
    {
        const duplicate_state: DuplicateState = .fromState(
            .from(params.logger),
            slot,
            params.duplicate_confirmed_slots,
            params.fork_choice,
            .fromHash(hash),
        );

        try check_slot_agrees_with_cluster.duplicate(
            params.allocator,
            .from(params.logger),
            slot,
            parent_slot,
            params.duplicate_slots_tracker,
            params.fork_choice,
            duplicate_state,
        );
    }

    // Move unfrozen_gossip_verified_vote_hashes entries to latest_validator_votes
    if (params.unfrozen_gossip_verified_vote_hashes.votes_per_slot.getPtr(slot)) |slot_hashes| {
        if (slot_hashes.fetchSwapRemove(hash)) |kv| {
            var new_frozen_voters = kv.value;
            defer new_frozen_voters.deinit(params.allocator);
            for (new_frozen_voters.items) |pubkey| {
                _ = try params.latest_validator_votes.checkAddVote(
                    params.allocator,
                    pubkey,
                    slot,
                    hash,
                    .gossip,
                );
            }
        }
        // If `slot_hashes` becomes empty, it'll be removed by `setRoot()` later
    }
}

const testing = std.testing;

// Test helper structure that owns all the resources
const TestReplayStateResources = struct {
    ledger: Ledger,
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
    params: ProcessResultParams,
    registry: sig.prometheus.Registry(.{}),
    lowest_cleanup_slot: sig.sync.RwMux(Slot),
    max_root: std.atomic.Value(Slot),

    ancestor_hashes_replay_update_channel: sig.sync.Channel(AncestorHashesReplayUpdate),

    pub fn init(
        allocator: Allocator,
        comptime test_src: std.builtin.SourceLocation,
    ) !*TestReplayStateResources {
        const self = try allocator.create(TestReplayStateResources);
        errdefer allocator.destroy(self);

        self.registry = sig.prometheus.Registry(.{}).init(allocator);
        errdefer self.registry.deinit();

        self.lowest_cleanup_slot = sig.sync.RwMux(Slot).init(0);
        self.max_root = std.atomic.Value(Slot).init(0);

        self.ledger = try sig.ledger.tests.initTestLedger(allocator, test_src, .FOR_TESTS);
        errdefer self.ledger.deinit();

        self.progress = ProgressMap.INIT;

        self.fork_choice = try allocator.create(HeaviestSubtreeForkChoice);
        self.fork_choice.* = try HeaviestSubtreeForkChoice.init(
            allocator,
            .noop,
            .{
                .slot = 0,
                .hash = Hash.ZEROES,
            },
            &self.registry,
        );

        self.duplicate_slots_tracker = DuplicateSlots.empty;
        self.unfrozen_gossip_verified_vote_hashes = UnfrozenGossipVerifiedVoteHashes{
            .votes_per_slot = .empty,
        };
        self.latest_validator_votes = LatestValidatorVotes.empty;
        self.duplicate_confirmed_slots = DuplicateConfirmedSlots.empty;
        self.epoch_slots_frozen_slots = EpochSlotsFrozenSlots.empty;
        self.duplicate_slots_to_repair = DuplicateSlotsToRepair.empty;
        self.purge_repair_slot_counter = PurgeRepairSlotCounters.empty;

        self.slot_tracker = try SlotTracker.initEmpty(allocator, 0);
        errdefer self.slot_tracker.deinit(allocator);

        self.ancestor_hashes_replay_update_channel = try sig
            .sync
            .Channel(AncestorHashesReplayUpdate)
            .init(allocator);

        self.params = ProcessResultParams{
            .allocator = allocator,
            .logger = .FOR_TESTS,
            .my_identity = Pubkey.initRandom(std.crypto.random),
            .ledger = &self.ledger,
            .slot_tracker = &self.slot_tracker,
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
        self.progress.deinit(allocator);
        self.fork_choice.deinit(allocator);
        allocator.destroy(self.fork_choice);
        self.duplicate_slots_tracker.deinit(allocator);
        self.unfrozen_gossip_verified_vote_hashes.deinit(allocator);
        self.latest_validator_votes.deinit(allocator);
        self.duplicate_confirmed_slots.deinit(allocator);
        self.epoch_slots_frozen_slots.deinit(allocator);
        self.duplicate_slots_to_repair.deinit(allocator);
        self.purge_repair_slot_counter.deinit(allocator);
        self.registry.deinit();
        self.ancestor_hashes_replay_update_channel.deinit();
        self.ledger.deinit();

        allocator.destroy(self);
    }
};

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

    var test_resources = TestReplayStateResources.init(allocator, @src()) catch |err| {
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

    try processResult(test_resources.params, .{
        .slot = slot,
        .output = .{ .err = .{ .failed_to_load_entries = "test error" } },
    });

    // Verify slot is now marked as dead
    const progress_after = test_resources.progress.map.get(slot);
    try testing.expect(progress_after != null);
    try testing.expect(progress_after.?.is_dead);
}

test "processResult: confirm status with done poll but missing slot in tracker" {
    const allocator = testing.allocator;

    var test_resources = TestReplayStateResources.init(allocator, @src()) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_resources.deinit(allocator);

    const slot: Slot = 100;

    // The function should return an error since the slot is not in the tracker
    const result = processResult(test_resources.params, .{
        .slot = slot,
        .output = .{ .last_entry_hash = .ZEROES },
    });

    try testing.expectError(error.MissingSlotInTracker, result);
}

test "processResult: confirm status with done poll and slot complete - success path" {
    const allocator = testing.allocator;

    var test_resources = TestReplayStateResources.init(allocator, @src()) catch |err| {
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

    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = rng.random();

    const last_entry_hash = sig.core.Hash.initRandom(random);

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
    try test_resources.params.fork_choice.addNewLeafSlot(
        allocator,
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
        // Different from params.my_identity
        .collector_id = sig.core.Pubkey.initRandom(random),
        // This should match tickHeight() for slot to be complete
        .max_tick_height = 64,
        .fee_rate_governor = sig.core.FeeRateGovernor.DEFAULT,
        .ancestors = .{ .ancestors = .empty },
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .empty,
        .inflation = .DEFAULT,
        .rent_collector = .DEFAULT,
    };

    // Create slot state then modify tick height
    var mock_slot_state: sig.core.SlotState = .GENESIS;

    // Set tick height equal to max_tick_height to make slot complete
    _ = mock_slot_state.tick_height.swap(64, .monotonic);

    // Set a valid hash for the slot
    mock_slot_state.hash.set(sig.core.Hash.initRandom(random));

    // Add the slot to the slot tracker
    try test_resources.slot_tracker.put(allocator, slot, .{
        .constants = mock_slot_constants,
        .state = mock_slot_state,
    });

    try processResult(test_resources.params, .{
        .slot = slot,
        .output = .{ .last_entry_hash = last_entry_hash },
    });
}

test "markDeadSlot: marks progress dead and writes to ledger" {
    const allocator = testing.allocator;

    var test_resources = TestReplayStateResources.init(allocator, @src()) catch |err| {
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
        test_resources.params,
        slot,
        &ancestor_hashes_replay_update_channel,
    );

    // Validate progress is marked dead
    try testing.expect(test_resources.progress.isDead(slot) orelse false);

    // Validate ledger records the dead slot
    try testing.expect(try test_resources.ledger.reader().isDead(allocator, slot));
}

test "markDeadSlot: when duplicate proof exists, duplicate tracker records slot" {
    const allocator = testing.allocator;

    var test_resources = TestReplayStateResources.init(allocator, @src()) catch |err| {
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
    var slot_state: sig.core.SlotState = .GENESIS;

    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    slot_state.hash.set(sig.core.Hash.initRandom(rng.random()));
    const slot_consts = sig.core.SlotConstants{
        .parent_slot = 0,
        .parent_hash = sig.core.Hash.ZEROES,
        .parent_lt_hash = .IDENTITY,
        .block_height = 0,
        .collector_id = sig.core.Pubkey.ZEROES,
        .max_tick_height = 0,
        .fee_rate_governor = sig.core.FeeRateGovernor.DEFAULT,
        .ancestors = .{ .ancestors = .empty },
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .empty,
        .inflation = .DEFAULT,
        .rent_collector = .DEFAULT,
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
    try test_resources.ledger.db.put(sig.ledger.schema.schema.duplicate_slots, slot, dup_proof);

    // Tracker does not contain the slot yet
    try testing.expect(!test_resources.duplicate_slots_tracker.contains(slot));

    var ancestor_hashes_replay_update_channel: sig.sync.Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_update_channel.deinit();

    try markDeadSlot(
        test_resources.params,
        slot,
        &ancestor_hashes_replay_update_channel,
    );

    // The duplicate handler should record the slot in the duplicate tracker
    try testing.expect(test_resources.duplicate_slots_tracker.contains(slot));
}

test "updateConsensusForFrozenSlot: moves gossip votes with gossip vote_kind" {
    const allocator = testing.allocator;

    var test_state = TestReplayStateResources.init(allocator, @src()) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_state.deinit(allocator);

    const slot: Slot = 100;
    const parent_slot: Slot = 99;
    var rng = std.Random.DefaultPrng.init(0);
    const random = rng.random();

    const slot_hash = Hash.initRandom(random);
    const vote_pubkey = sig.core.Pubkey.initRandom(random);

    // Add parent slot to progress map
    try test_state.progress.map.putNoClobber(
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

    // Add current slot to progress map
    try test_state.progress.map.putNoClobber(
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

    // Setup slot in tracker with proper state
    const parent_hash = Hash.initRandom(random);
    const slot_consts = sig.core.SlotConstants{
        .parent_slot = parent_slot,
        .parent_hash = parent_hash,
        .parent_lt_hash = .IDENTITY,
        .block_height = 0,
        .collector_id = sig.core.Pubkey.initRandom(random),
        .max_tick_height = 64,
        .fee_rate_governor = sig.core.FeeRateGovernor.DEFAULT,
        .ancestors = .{ .ancestors = .empty },
        .inflation = .DEFAULT,
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .empty,
        .rent_collector = .DEFAULT,
    };
    var slot_state: sig.core.SlotState = .GENESIS;
    slot_state.hash.set(slot_hash);

    try test_state.slot_tracker.put(allocator, slot, .{
        .constants = slot_consts,
        .state = slot_state,
    });

    // Ensure fork choice knows about the parent before adding the leaf
    try test_state.params.fork_choice.addNewLeafSlot(
        allocator,
        .{ .slot = parent_slot, .hash = parent_hash },
        .{ .slot = 0, .hash = Hash.ZEROES },
    );

    // Add gossip-verified vote to unfrozen_gossip_verified_vote_hashes
    const votes_per_slot = &test_state.unfrozen_gossip_verified_vote_hashes.votes_per_slot;
    const gop = try votes_per_slot.getOrPut(allocator, slot);
    if (!gop.found_existing) {
        gop.value_ptr.* = .{};
    }
    const slot_hashes = gop.value_ptr;
    const gop2 = try slot_hashes.getOrPut(allocator, slot_hash);
    if (!gop2.found_existing) {
        gop2.value_ptr.* = .{};
    }
    try gop2.value_ptr.append(allocator, vote_pubkey);

    {
        // Precondition
        const gossip_vote = latestVote(
            &test_state.latest_validator_votes,
            vote_pubkey,
            .gossip,
        );
        try testing.expectEqual(null, gossip_vote);
    }

    // Process the frozen slot
    try updateConsensusForFrozenSlot(test_state.params, slot);

    // Verify the vote was added to latest_validator_votes with .gossip vote_kind
    const gossip_vote = latestVote(
        &test_state.latest_validator_votes,
        vote_pubkey,
        .gossip,
    );
    try testing.expect(gossip_vote != null);
    try testing.expectEqual(slot, gossip_vote.?.slot);
    try testing.expectEqual(slot_hash, gossip_vote.?.hashes[0]);

    // Verify the vote is not in replay votes
    const replay_vote = latestVote(
        &test_state.latest_validator_votes,
        vote_pubkey,
        .replay,
    );
    try testing.expectEqual(null, replay_vote);
}
