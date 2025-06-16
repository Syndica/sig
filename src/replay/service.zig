const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const AccountsDB = sig.accounts_db.AccountsDB;
const BlockstoreDB = sig.ledger.BlockstoreDB;
const BlockstoreReader = sig.ledger.BlockstoreReader;
const ProgressMap = sig.consensus.ProgressMap;
const Slot = sig.core.Slot;
const SlotLeaders = sig.core.leader_schedule.SlotLeaders;
const SlotState = sig.core.bank.SlotState;

const ReplayExecutionState = replay.execution.ReplayExecutionState;
const SlotTracker = replay.trackers.SlotTracker;
const EpochTracker = replay.trackers.EpochTracker;

/// Number of threads to use in replay's thread pool
const NUM_THREADS = 4;

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
    /// Used to get the entries to validate them and execute the transactions
    accounts_db: *AccountsDB,
    slot_leaders: SlotLeaders,
    /// The slot to start replaying from.
    root_slot: Slot,
    root_slot_constants: sig.core.SlotConstants,
    root_slot_state: sig.core.SlotState,
};

const ReplayState = struct {
    allocator: Allocator,
    logger: sig.trace.ScopedLogger("replay"),
    thread_pool: *ThreadPool,
    slot_leaders: SlotLeaders,
    slot_tracker: *SlotTracker,
    epochs: *EpochTracker,
    blockstore_db: BlockstoreDB,
    execution: ReplayExecutionState,

    fn init(deps: ReplayDependencies) Allocator.Error!ReplayState {
        const thread_pool = try deps.allocator.create(ThreadPool);
        errdefer deps.allocator.destroy(thread_pool);
        thread_pool.* = ThreadPool.init(.{ .max_threads = NUM_THREADS });

        const slot_tracker = try deps.allocator.create(SlotTracker);
        errdefer deps.allocator.destroy(slot_tracker);
        slot_tracker.* = .init(deps.root_slot);
        try slot_tracker.put(
            deps.allocator,
            deps.root_slot,
            deps.root_slot_constants,
            deps.root_slot_state,
        );

        const epoch_tracker = try deps.allocator.create(EpochTracker);
        errdefer deps.allocator.destroy(epoch_tracker);
        epoch_tracker.* = .{ .schedule = deps.epoch_schedule };

        return .{
            .allocator = deps.allocator,
            .logger = .from(deps.logger),
            .thread_pool = thread_pool,
            .slot_leaders = deps.slot_leaders,
            .slot_tracker = slot_tracker,
            .epochs = epoch_tracker,
            .blockstore_db = deps.blockstore_reader.db,
            .execution = try ReplayExecutionState.init(
                deps.allocator,
                deps.logger,
                deps.my_identity,
                thread_pool,
                deps.accounts_db,
                deps.blockstore_reader,
                slot_tracker,
                epoch_tracker,
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
    try trackNewSlots(
        state.allocator,
        &state.blockstore_db,
        state.slot_tracker,
        state.epochs,
        state.slot_leaders,
        &state.execution.progress_map,
    );

    _ = try replay.execution.replayActiveSlots(&state.execution);

    handleEdgeCases();

    processConsensus();

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
    blockstore_db: *sig.ledger.BlockstoreDB,
    slot_tracker: *SlotTracker,
    epoch_tracker: *EpochTracker,
    slot_leaders: SlotLeaders,
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
        for (children.items) |child_slot| {
            if (slot_tracker.contains(child_slot)) continue;

            const epoch_info = epoch_tracker.getPtrForSlot(child_slot) orelse
                return error.MissingEpoch;

            var slot_state = try SlotState.fromFrozenParent(allocator, parent_info.state);
            errdefer slot_state.deinit(allocator);

            const epoch_reward_status = try parent_info.constants.epoch_reward_status
                .clone(allocator);
            errdefer epoch_reward_status.deinit(allocator);

            const leader = slot_leaders.get(child_slot) orelse return error.UnknownLeader;

            try slot_tracker.put(
                allocator,
                child_slot,
                .{
                    .slot = child_slot,
                    .parent_slot = parent_slot,
                    .parent_hash = parent_info.state.hash.readCopy().?,
                    .block_height = parent_info.constants.block_height + 1,
                    .collector_id = leader,
                    .max_tick_height = (child_slot + 1) * epoch_info.ticks_per_slot,
                    .fee_rate_governor = .initDerived(
                        &parent_info.constants.fee_rate_governor,
                        parent_info.state.signature_count.load(.monotonic),
                    ),
                    .epoch_reward_status = epoch_reward_status,
                },
                slot_state,
            );

            // TODO: update_fork_propagated_threshold_from_votes
        }
    }
}

fn handleEdgeCases() void {
    // TODO: process_ancestor_hashes_duplicate_slots

    // TODO: process_duplicate_confirmed_slots

    // TODO: process_gossip_verified_vote_hashes

    // TODO: process_popular_pruned_forks

    // TODO: process_duplicate_slots

}

fn processConsensus() void {
    // TODO: for each slot:
    //           tower_duplicate_confirmed_forks
    //           mark_slots_duplicate_confirmed

    // TODO: select_forks

    // TODO: check_for_vote_only_mode

    // TODO: select_vote_and_reset_forks

    // TODO: if vote_bank.is_none: maybe_refresh_last_vote

    // TODO: handle_votable_bank

    // TODO: if reset_bank: Reset onto a fork
}

test trackNewSlots {
    const Pubkey = sig.core.Pubkey;
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

    var slot_tracker = SlotTracker.init(0);
    defer slot_tracker.deinit(allocator);
    try slot_tracker.put(allocator, 0, .genesis(.DEFAULT), .GENESIS);
    slot_tracker.get(0).?.state.hash.set(.ZEROES);

    var epoch_tracker = EpochTracker{ .schedule = .DEFAULT };
    defer epoch_tracker.deinit(allocator);
    try epoch_tracker.epochs.put(allocator, 0, .{
        .hashes_per_tick = 1,
        .ticks_per_slot = 1,
        .ns_per_slot = 1,
        .genesis_creation_time = 1,
        .slots_per_year = 1,
        .stakes = try .initEmpty(allocator),
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

    // slot tracker should start with only 0
    try expectSlotTracker(&slot_tracker, leader_schedule, &.{.{ 0, 0 }}, &.{ 1, 2, 3, 4, 5, 6 });

    // only the root (0) is considered frozen, so only 0 and 1 should be added at first.
    try trackNewSlots(
        allocator,
        &blockstore_db,
        &slot_tracker,
        &epoch_tracker,
        leader_schedule.slotLeaders(0),
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
        &blockstore_db,
        &slot_tracker,
        &epoch_tracker,
        leader_schedule.slotLeaders(0),
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
        &blockstore_db,
        &slot_tracker,
        &epoch_tracker,
        leader_schedule.slotLeaders(0),
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
        &blockstore_db,
        &slot_tracker,
        &epoch_tracker,
        leader_schedule.slotLeaders(0),
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
