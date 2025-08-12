const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SlotLeaders = sig.core.leader_schedule.SlotLeaders;
const SlotState = sig.core.bank.SlotState;

const AccountStore = sig.accounts_db.AccountStore;
const AccountReader = sig.accounts_db.AccountReader;
const SlotAccountReader = sig.accounts_db.account_store.SlotAccountReader;

const BlockstoreDB = sig.ledger.BlockstoreDB;
const BlockstoreReader = sig.ledger.BlockstoreReader;
const LedgerResultWriter = sig.ledger.result_writer.LedgerResultWriter;

const ProgressMap = sig.consensus.ProgressMap;

const ReplayExecutionState = replay.execution.ReplayExecutionState;
const SlotTracker = replay.trackers.SlotTracker;
const EpochTracker = replay.trackers.EpochTracker;

const updateSysvarsForNewSlot = replay.update_sysvar.updateSysvarsForNewSlot;

const LatestValidatorVotesForFrozenSlots =
    sig.consensus.latest_validator_votes.LatestValidatorVotes;

/// Number of threads to use in replay's thread pool
const NUM_THREADS = 4;

const SWITCH_FORK_THRESHOLD: f64 = 0.38;
const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days
const DUPLICATE_LIVENESS_THRESHOLD: f64 = 0.1;
pub const DUPLICATE_THRESHOLD: f64 = 1.0 - SWITCH_FORK_THRESHOLD - DUPLICATE_LIVENESS_THRESHOLD;

pub const ReplayDependencies = struct {
    /// Used for all allocations within the replay stage
    allocator: Allocator,
    logger: sig.trace.Logger,
    my_identity: sig.core.Pubkey,
    /// Tell replay when to exit
    exit: *std.atomic.Value(bool),
    /// Used in the EpochManager
    epoch_schedule: sig.core.EpochSchedule,
    /// Used to get the entries to validate them and execute the transactions
    blockstore_reader: *BlockstoreReader,
    /// Used to update the ledger with consensus results
    ledger_result_writer: *LedgerResultWriter,
    account_store: AccountStore,
    slot_leaders: SlotLeaders,
    /// The slot to start replaying from.
    root_slot: Slot,
    root_slot_constants: sig.core.SlotConstants,
    root_slot_state: sig.core.SlotState,
    current_epoch: sig.core.Epoch,
    current_epoch_constants: sig.core.EpochConstants,
    hard_forks: sig.core.HardForks,
};

pub const Logger = sig.trace.ScopedLogger("replay");

pub const SlotData = struct {
    duplicate_confirmed_slots: replay.edge_cases.DuplicateConfirmedSlots,
    epoch_slots_frozen_slots: replay.edge_cases.EpochSlotsFrozenSlots,
    duplicate_slots_to_repair: replay.edge_cases.DuplicateSlotsToRepair,
    purge_repair_slot_counter: replay.edge_cases.PurgeRepairSlotCounters,
    unfrozen_gossip_verified_vote_hashes: replay.edge_cases.UnfrozenGossipVerifiedVoteHashes,
    duplicate_slots: replay.edge_cases.DuplicateSlots,
};

const ReplayState = struct {
    allocator: Allocator,
    logger: Logger,
    thread_pool: *ThreadPool,
    slot_leaders: SlotLeaders,
    slot_tracker: *SlotTracker,
    epochs: *EpochTracker,
    hard_forks: sig.core.HardForks,
    account_store: AccountStore,
    progress_map: *ProgressMap,
    blockstore_db: BlockstoreDB,
    execution: ReplayExecutionState,

    fn init(deps: ReplayDependencies) !ReplayState {
        const thread_pool = try deps.allocator.create(ThreadPool);
        errdefer deps.allocator.destroy(thread_pool);
        thread_pool.* = ThreadPool.init(.{ .max_threads = NUM_THREADS });

        var root_slot_state = deps.root_slot_state;
        const last_blockhash = root_slot_state.blockhash_queue.readField("last_hash") orelse
            return error.InvalidBlockhashQueue;

        const slot_tracker = try deps.allocator.create(SlotTracker);
        errdefer deps.allocator.destroy(slot_tracker);
        slot_tracker.* = try .init(deps.allocator, deps.root_slot, .{
            .constants = deps.root_slot_constants,
            .state = root_slot_state,
        });
        errdefer slot_tracker.deinit(deps.allocator);

        const epoch_tracker = try deps.allocator.create(EpochTracker);
        errdefer deps.allocator.destroy(epoch_tracker);
        epoch_tracker.* = .{ .schedule = deps.epoch_schedule };
        errdefer epoch_tracker.deinit(deps.allocator);
        try epoch_tracker.epochs
            .put(deps.allocator, deps.current_epoch, deps.current_epoch_constants);

        const progress_map = try deps.allocator.create(ProgressMap);
        progress_map.* = ProgressMap.INIT;
        try progress_map.map.put(
            deps.allocator,
            slot_tracker.root,
            try .init(deps.allocator, .{
                .now = .now(),
                .last_entry = last_blockhash,
                .prev_leader_slot = null, // non-block-producing
                .validator_stake_info = null, // non-voting
                .num_blocks_on_fork = 0,
                .num_dropped_blocks_on_fork = 0,
            }),
        );

        return .{
            .allocator = deps.allocator,
            .logger = .from(deps.logger),
            .thread_pool = thread_pool,
            .slot_leaders = deps.slot_leaders,
            .slot_tracker = slot_tracker,
            .epochs = epoch_tracker,
            .hard_forks = deps.hard_forks,
            .account_store = deps.account_store,
            .blockstore_db = deps.blockstore_reader.db,
            .progress_map = progress_map,
            .execution = try ReplayExecutionState.init(
                deps.allocator,
                deps.logger,
                deps.my_identity,
                thread_pool,
                deps.account_store,
                deps.blockstore_reader,
                slot_tracker,
                epoch_tracker,
                progress_map,
            ),
        };
    }

    fn deinit(self: *ReplayState) void {
        self.thread_pool.shutdown();
        self.thread_pool.deinit();
        self.allocator.destroy(self.thread_pool);
        self.slot_tracker.deinit(self.allocator);
        self.allocator.destroy(self.slot_tracker);
        self.epochs.deinit(self.allocator);
        self.allocator.destroy(self.epochs);
        self.hard_forks.deinit(self.allocator);
    }
};

/// Run the replay service indefinitely.
pub fn run(deps: ReplayDependencies) !void {
    var state = try ReplayState.init(deps);
    defer state.deinit();

    while (!deps.exit.load(.monotonic)) try advanceReplay(&state);
}

/// Run a single iteration of the entire replay process. Includes:
/// - replay all active slots that have not been replayed yet
/// - running concensus on the latest updates
fn advanceReplay(state: *ReplayState) !void {
    state.logger.info().log("advancing replay");
    try trackNewSlots(
        state.allocator,
        state.account_store,
        &state.blockstore_db,
        state.slot_tracker,
        state.epochs,
        state.slot_leaders,
        &state.hard_forks,
        state.progress_map,
    );

    const processed_a_slot = try replay.execution.replayActiveSlots(&state.execution);
    if (!processed_a_slot) std.time.sleep(100 * std.time.ns_per_ms);

    _ = &replay.edge_cases.processEdgeCases;

    // ignore errors in consensus since they are expected until the inputs are provided
    replay.consensus.processConsensus(null) catch |e|
        state.logger.err().logf("consensus failed with an error: {}", .{e});

    // TODO: dump_then_repair_correct_slots

    // TODO: maybe_start_leader
}

/// Identifies new slots in the ledger and starts tracking them in the slot
/// tracker.
///
/// Analogous to
/// [generate_new_bank_forks](https://github.com/anza-xyz/agave/blob/146ebd8be3857d530c0946003fcd58be220c3290/core/src/replay_stage.rs#L4149)
fn trackNewSlots(
    allocator: Allocator,
    account_store: AccountStore,
    blockstore_db: *BlockstoreDB,
    slot_tracker: *SlotTracker,
    epoch_tracker: *EpochTracker,
    slot_leaders: SlotLeaders,
    hard_forks: *const sig.core.HardForks,
    /// needed for update_fork_propagated_threshold_from_votes
    _: *ProgressMap,
) !void {
    const root = slot_tracker.root;
    var frozen_slots = try slot_tracker.frozenSlots(allocator);
    defer frozen_slots.deinit(allocator);

    var frozen_slots_since_root = try std.ArrayListUnmanaged(sig.core.Slot)
        .initCapacity(allocator, frozen_slots.count());
    defer frozen_slots_since_root.deinit(allocator);
    for (frozen_slots.keys()) |slot| if (slot >= root) {
        frozen_slots_since_root.appendAssumeCapacity(slot);
    };

    var next_slots = try BlockstoreReader
        .getSlotsSince(allocator, blockstore_db, frozen_slots_since_root.items);
    defer {
        for (next_slots.values()) |*list| list.deinit(allocator);
        next_slots.deinit(allocator);
    }

    for (next_slots.keys(), next_slots.values()) |parent_slot, children| {
        const parent_info = frozen_slots.get(parent_slot) orelse return error.MissingParent;
        for (children.items) |slot| {
            if (slot_tracker.contains(slot)) continue;

            const epoch_info = epoch_tracker.getPtrForSlot(slot) orelse
                return error.MissingEpoch;

            const constants, var state = try newSlotFromParent(
                allocator,
                account_store.reader(),
                epoch_info.ticks_per_slot,
                parent_slot,
                parent_info.constants,
                parent_info.state,
                slot_leaders.get(slot) orelse return error.UnknownLeader,
                slot,
            );
            errdefer constants.deinit(allocator);
            errdefer state.deinit(allocator);

            try updateSysvarsForNewSlot(
                allocator,
                account_store,
                epoch_info,
                epoch_tracker.schedule,
                &constants,
                &state,
                slot,
                hard_forks,
            );

            try slot_tracker.put(allocator, slot, .{ .constants = constants, .state = state });

            // TODO: update_fork_propagated_threshold_from_votes
        }
    }
}

/// Initializes the SlotConstants and SlotState from their parents and other
/// dependencies.
///
/// This is analogous to the *portion* of agave's Bank::new_from_parent that is
/// responsible for creating the actual bank struct.
///
/// For the relevant updates to accountsdb to set sysvars, see
/// updateSysvarsForNewSlot
fn newSlotFromParent(
    allocator: Allocator,
    account_reader: AccountReader,
    ticks_in_slot: u64,
    parent_slot: Slot,
    parent_constants: *const sig.core.SlotConstants,
    parent_state: *SlotState,
    leader: Pubkey,
    slot: Slot,
) !struct { sig.core.SlotConstants, SlotState } {
    var state = try SlotState.fromFrozenParent(allocator, parent_state);
    errdefer state.deinit(allocator);

    const epoch_reward_status = try parent_constants.epoch_reward_status
        .clone(allocator);
    errdefer epoch_reward_status.deinit(allocator);

    var ancestors = try parent_constants.ancestors.clone(allocator);
    errdefer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, slot, {});

    var feature_set = try getActiveFeatures(allocator, account_reader.forSlot(&ancestors), slot);

    const parent_hash = parent_state.hash.readCopy().?;

    const constants = sig.core.SlotConstants{
        .parent_slot = parent_slot,
        .parent_hash = parent_hash,
        .parent_lt_hash = parent_state.accounts_lt_hash.readCopy().?,
        .block_height = parent_constants.block_height + 1,
        .collector_id = leader,
        .max_tick_height = (slot + 1) * ticks_in_slot,
        .fee_rate_governor = .initDerived(
            &parent_constants.fee_rate_governor,
            parent_state.signature_count.load(.monotonic),
        ),
        .epoch_reward_status = epoch_reward_status,
        .ancestors = ancestors,
        .feature_set = feature_set,
        // This is inefficient, reserved accounts could live in epoch constants along with
        // the feature set since feature activations are only applied at epoch boundaries.
        // Then we only need to clone the map and update the reserved accounts once per epoch.
        .reserved_accounts = try sig.core.reserved_accounts.initForSlot(
            allocator,
            &feature_set,
            slot,
        ),
    };

    return .{ constants, state };
}

// TODO: epoch boundary - handle feature activations
pub fn getActiveFeatures(
    allocator: Allocator,
    account_reader: SlotAccountReader,
    slot: Slot,
) !sig.core.FeatureSet {
    var features: sig.core.FeatureSet = .ALL_DISABLED;
    for (0..sig.core.features.NUM_FEATURES) |i| {
        const possible_feature: sig.core.features.Feature = @enumFromInt(i);
        const possible_feature_pubkey = sig.core.features.map.get(possible_feature);
        const feature_account = try account_reader.get(possible_feature_pubkey) orelse continue;
        if (!feature_account.owner.equals(&sig.runtime.ids.FEATURE_PROGRAM_ID)) {
            return error.FeatureNotOwnedByFeatureProgram;
        }

        var data_iterator = feature_account.data.iterator();
        const reader = data_iterator.reader();
        const feature = try sig.bincode.read(allocator, struct { activated_at: ?u64 }, reader, .{});
        if (feature.activated_at) |activation_slot| {
            if (activation_slot <= slot) {
                features.setSlot(possible_feature, activation_slot);
            }
        }
    }
    return features;
}

test "getActiveFeatures rejects wrong ownership" {
    const allocator = std.testing.allocator;
    var accounts = std.AutoArrayHashMapUnmanaged(Pubkey, sig.core.Account).empty;
    defer accounts.deinit(allocator);

    var acct: sig.core.Account = undefined;
    acct.owner = Pubkey.ZEROES;

    try accounts.put(
        allocator,
        sig.core.features.map.get(.system_transfer_zero_check),
        acct,
    );

    try std.testing.expectError(
        error.FeatureNotOwnedByFeatureProgram,
        getActiveFeatures(allocator, .{ .single_version_map = &accounts }, 0),
    );
}

test trackNewSlots {
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(0);

    var blockstore_db = try sig.ledger.tests.TestDB.init(@src());
    defer blockstore_db.deinit();
    //     0
    //     1
    //    / \
    //   2   4
    //  [3]  6
    //   5
    // no shreds received from 0 or 3
    inline for (.{
        .{ 0, 0, &.{1} },
        .{ 1, 0, &.{ 2, 4 } },
        .{ 2, 1, &.{} },
        .{ 3, null, &.{5} },
        .{ 5, 3, &.{} },
        .{ 4, 1, &.{6} },
        .{ 6, 4, &.{} },
    }) |item| {
        const slot, const parent, const children = item;
        var meta = sig.ledger.meta.SlotMeta.init(allocator, slot, parent);
        defer meta.deinit();
        try meta.child_slots.appendSlice(children);
        try blockstore_db.put(sig.ledger.schema.schema.slot_meta, slot, meta);
    }

    var slot_tracker: SlotTracker = try .init(allocator, 0, .{
        .state = try .genesis(allocator),
        .constants = try .genesis(allocator, .DEFAULT),
    });
    defer slot_tracker.deinit(allocator);
    slot_tracker.get(0).?.state.hash.set(.ZEROES);

    var epoch_tracker: EpochTracker = .{ .schedule = .DEFAULT };
    defer epoch_tracker.deinit(allocator);
    try epoch_tracker.epochs.put(allocator, 0, .{
        .hashes_per_tick = 1,
        .ticks_per_slot = 1,
        .ns_per_slot = 1,
        .genesis_creation_time = 1,
        .slots_per_year = 1,
        .stakes = try .initEmptyWithGenesisStakeHistoryEntry(allocator),
        .rent_collector = .DEFAULT,
    });

    const leader_schedule = sig.core.leader_schedule.LeaderSchedule{
        .allocator = undefined,
        .slot_leaders = &.{
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
        },
    };

    var lsc = sig.core.leader_schedule.LeaderScheduleCache.init(allocator, .DEFAULT);
    defer {
        var map = lsc.leader_schedules.write();
        map.mut().deinit();
        map.unlock();
    }
    try lsc.put(0, leader_schedule);
    const slot_leaders = lsc.slotLeaders();

    // slot tracker should start with only 0
    try expectSlotTracker(&slot_tracker, leader_schedule, &.{.{ 0, 0 }}, &.{ 1, 2, 3, 4, 5, 6 });

    const hard_forks = sig.core.HardForks{};

    // only the root (0) is considered frozen, so only 0 and 1 should be added at first.
    try trackNewSlots(
        allocator,
        .noop,
        &blockstore_db,
        &slot_tracker,
        &epoch_tracker,
        slot_leaders,
        &hard_forks,
        undefined,
    );
    try expectSlotTracker(
        &slot_tracker,
        leader_schedule,
        &.{ .{ 0, 0 }, .{ 1, 0 } },
        &.{ 2, 3, 4, 5, 6 },
    );

    // doing nothing should result in the same tracker state
    try trackNewSlots(
        allocator,
        .noop,
        &blockstore_db,
        &slot_tracker,
        &epoch_tracker,
        slot_leaders,
        &hard_forks,
        undefined,
    );
    try expectSlotTracker(
        &slot_tracker,
        leader_schedule,
        &.{ .{ 0, 0 }, .{ 1, 0 } },
        &.{ 2, 3, 4, 5, 6 },
    );

    // freezing 1 should result in 2 and 4 being added
    slot_tracker.get(1).?.state.hash.set(.ZEROES);
    try trackNewSlots(
        allocator,
        .noop,
        &blockstore_db,
        &slot_tracker,
        &epoch_tracker,
        slot_leaders,
        &hard_forks,
        undefined,
    );
    try expectSlotTracker(
        &slot_tracker,
        leader_schedule,
        &.{ .{ 0, 0 }, .{ 1, 0 }, .{ 2, 1 }, .{ 4, 1 } },
        &.{ 3, 5, 6 },
    );

    // freezing 2 and 4 should only result in 6 being added since 3's parent is unknown
    slot_tracker.get(2).?.state.hash.set(.ZEROES);
    slot_tracker.get(4).?.state.hash.set(.ZEROES);
    try trackNewSlots(
        allocator,
        .noop,
        &blockstore_db,
        &slot_tracker,
        &epoch_tracker,
        slot_leaders,
        &hard_forks,
        undefined,
    );
    try expectSlotTracker(
        &slot_tracker,
        leader_schedule,
        &.{ .{ 0, 0 }, .{ 1, 0 }, .{ 2, 1 }, .{ 4, 1 }, .{ 6, 4 } },
        &.{ 3, 5 },
    );
}

fn expectSlotTracker(
    slot_tracker: *SlotTracker,
    leader_schedule: sig.core.leader_schedule.LeaderSchedule,
    included_slots: []const [2]Slot,
    excluded_slots: []const Slot,
) !void {
    for (included_slots) |item| {
        const slot, const parent = item;
        const slot_info = slot_tracker.get(slot) orelse return error.Fail;
        try std.testing.expectEqual(parent, slot_info.constants.parent_slot);
        if (slot != 0) try std.testing.expectEqual(
            leader_schedule.slot_leaders[slot],
            slot_info.constants.collector_id,
        );
    }
    for (excluded_slots) |slot| {
        try std.testing.expectEqual(null, slot_tracker.get(slot));
    }
}
