const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const AccountsDB = sig.accounts_db.AccountsDB;
const BlockstoreReader = sig.ledger.BlockstoreReader;

const ScopedLogger = sig.trace.ScopedLogger("replay");

const Slot = sig.core.Slot;
const SlotAndHash = sig.core.hash.SlotAndHash;

const ReplayTower = sig.consensus.replay_tower.ReplayTower;
const ProgressMap = sig.consensus.progress_map.ProgressMap;
const VotedStakes = sig.consensus.progress_map.consensus.VotedStakes;
const ForkChoice = sig.consensus.fork_choice.ForkChoice;

/// Number of threads to use in replay's thread pool
const NUM_THREADS = 4;

pub const ReplayDependencies = struct {
    /// Used for all allocations within the replay stage
    allocator: Allocator,
    logger: sig.trace.Logger,
    /// Tell replay when to exit
    exit: *std.atomic.Value(bool),
    /// Used in the EpochManager
    epoch_schedule: sig.core.EpochSchedule,
    /// Used to get the entries to validate them and execute the transactions
    blockstore_reader: *BlockstoreReader,
    /// Used to get the entries to validate them and execute the transactions
    accounts_db: *AccountsDB,
};

const ReplayState = struct {
    allocator: Allocator,
    logger: ScopedLogger,
    thread_pool: *ThreadPool,
    execution: ReplayExecutionState,

    fn init(deps: ReplayDependencies) Allocator.Error!ReplayState {
        const thread_pool = try deps.allocator.create(ThreadPool);
        errdefer deps.allocator.destroy(thread_pool);
        thread_pool.* = ThreadPool.init(.{ .max_threads = NUM_THREADS });

        return .{
            .allocator = deps.allocator,
            .logger = ScopedLogger.from(deps.logger),
            .thread_pool = thread_pool,
            .execution = try ReplayExecutionState.init(
                deps.allocator,
                deps.logger,
                thread_pool,
                deps.epoch_schedule,
                deps.accounts_db,
                deps.blockstore_reader,
            ),
        };
    }

    fn deinit(self: *ReplayState) void {
        self.execution.deinit();
        self.thread_pool.shutdown();
        self.thread_pool.deinit();
        self.allocator.destroy(self.thread_pool);
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
    _ = state; // autofix

    // TODO: generate_new_bank_forks

    // TODO: replay_active_banks
    // _ = try replay.execution.replayActiveSlots(&state.execution);
    std.time.sleep(100 * std.time.ns_per_ms);

    handleEdgeCases();

    var slots = [_]Slot{0};
    // TODO: Pass in the consensus deps
    try processConsensus(null, slots[0..]);

    // TODO: dump_then_repair_correct_slots

    // TODO: maybe_start_leader
}

fn handleEdgeCases() void {
    // TODO: process_ancestor_hashes_duplicate_slots

    // TODO: process_duplicate_confirmed_slots

    // TODO: process_gossip_verified_vote_hashes

    // TODO: process_popular_pruned_forks

    // TODO: process_duplicate_slots

}

const ConsensusDependencies = struct {
    replay_tower: *ReplayTower,
    progress_map: *ProgressMap,
    fork_choice: *ForkChoice,
    blockstore: *BlockstoreReader,
};

fn processConsensus(maybe_deps: ?ConsensusDependencies, newly_computed_slot_stats: []Slot) !void {
    const deps = if (maybe_deps) |deps|
        deps
    else
        return error.Todo;
    for (newly_computed_slot_stats) |slot| {
        const fork_stats = deps.progress_map.getForkStats(slot) orelse
            return error.Todo;
        const duplicate_confirmed_forks = towerDuplicateConfirmedForks(
            deps.replay_tower,
            deps.progress_map,
            slot,
            fork_stats.voted_stakes,
            fork_stats.total_stake,
        );
        markSlotsDuplicateConfirmed(
            deps.blockstore,
            deps.progress_map,
            deps.fork_choice,
            duplicate_confirmed_forks,
            0,
            .{},
            .{},
            .{},
            .{},
            .{},
            .{},
        );
    }

    // TODO: select_forks
    // TODO: check_for_vote_only_mode
    // TODO: select_vote_and_reset_forks
    // TODO: if vote_bank.is_none: maybe_refresh_last_vote
    // TODO: handle_votable_bank
    // TODO: if reset_bank: Reset onto a fork
}

fn towerDuplicateConfirmedForks(
    replay_tower: *const ReplayTower,
    progress_map: *const ProgressMap,
    slot: Slot,
    vote_stake: VotedStakes,
    total_stake: u64,
    // mising BankForks or alternative
) []SlotAndHash {
    _ = &replay_tower;
    _ = &progress_map;
    _ = &slot;
    _ = &vote_stake;
    _ = &total_stake;

    return &[0]SlotAndHash{};
}

// TODO Revisit
const stubs = struct {
    pub const DuplicateSlotsTracker = struct {};
    pub const EpochSlotsFrozenSlots = struct {};
    pub const DuplicateSlotsToRepair = struct {};
    pub const PurgeRepairSlotCounter = struct {};
    pub const DuplicateConfirmedSlots = struct {};
    pub const AncestorHashesReplayUpdateSender = struct {};
};

fn markSlotsDuplicateConfirmed(
    blockstore: *BlockstoreReader,
    progress_map: *ProgressMap,
    fork_choice: *ForkChoice,
    confirmed_slots: []SlotAndHash,
    root_slot: Slot,
    duplicate_slot_tracker: stubs.DuplicateSlotsTracker,
    epoch_slots_frozen_slots: stubs.EpochSlotsFrozenSlots,
    duplicate_slots_to_repair: stubs.DuplicateSlotsToRepair,
    ancestor_hashes_replay_update_sender: stubs.AncestorHashesReplayUpdateSender,
    purge_repair_slot_counter: stubs.PurgeRepairSlotCounter,
    duplicate_confirmed_slots: stubs.DuplicateConfirmedSlots,
) void {
    _ = &confirmed_slots;
    _ = &blockstore;
    _ = &root_slot;
    _ = &progress_map;
    _ = &duplicate_slot_tracker;
    _ = &fork_choice;
    _ = &epoch_slots_frozen_slots;
    _ = &duplicate_slots_to_repair;
    _ = &ancestor_hashes_replay_update_sender;
    _ = &purge_repair_slot_counter;
    _ = &duplicate_confirmed_slots;
}

/// stub to represent struct coming in the next pr (already implemented)
const ReplayExecutionState = struct {
    fn init(
        _: Allocator,
        _: sig.trace.Logger,
        _: *ThreadPool,
        _: sig.core.EpochSchedule,
        _: *AccountsDB,
        _: *BlockstoreReader,
    ) !ReplayExecutionState {
        return .{};
    }

    fn deinit(_: ReplayExecutionState) void {}
};
