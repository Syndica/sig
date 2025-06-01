const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const AccountsDB = sig.accounts_db.AccountsDB;
const BlockstoreReader = sig.ledger.BlockstoreReader;
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
    slot_leaders: sig.core.leader_schedule.SlotLeaders,
    /// The slot to start replaying from.
    root_slot: Slot,
};

const ReplayState = struct {
    allocator: Allocator,
    logger: sig.trace.ScopedLogger("replay"),
    thread_pool: *ThreadPool,
    slot_leaders: sig.core.leader_schedule.SlotLeaders,
    slot_tracker: *SlotTracker,
    epochs: *EpochTracker,
    execution: ReplayExecutionState,

    fn init(deps: ReplayDependencies) Allocator.Error!ReplayState {
        const thread_pool = try deps.allocator.create(ThreadPool);
        errdefer deps.allocator.destroy(thread_pool);
        thread_pool.* = ThreadPool.init(.{ .max_threads = NUM_THREADS });

        const slot_tracker = try deps.allocator.create(SlotTracker);
        errdefer deps.allocator.destroy(slot_tracker);
        slot_tracker.* = .init(deps.root_slot);

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
        self.execution.deinit();
        self.thread_pool.shutdown();
        self.thread_pool.deinit();
        self.allocator.destroy(self.thread_pool);
        self.allocator.destroy(self.slot_tracker);
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
    try trackNewSlots(state);

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
fn trackNewSlots(state: *ReplayState) !void {
    const allocator = state.allocator;
    const blockstore_reader = state.execution.blockstore_reader;
    const slot_tracker = state.slot_tracker;
    const epoch_tracker = state.epochs;
    const slot_leaders = state.slot_leaders;
    _ = &state.execution.progress_map; // needed for update_fork_propagated_threshold_from_votes

    const root = slot_tracker.root.load(.monotonic);
    const frozen_slots = try slot_tracker.frozenSlots(allocator);

    var frozen_slots_since_root = try std.ArrayListUnmanaged(sig.core.Slot)
        .initCapacity(allocator, frozen_slots.count());
    defer frozen_slots_since_root.deinit(allocator);
    for (frozen_slots.keys()) |slot| if (slot >= root) {
        try frozen_slots_since_root.append(allocator, slot);
    };

    const next_slots = try blockstore_reader
        .getSlotsSince(allocator, frozen_slots_since_root.items);

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
