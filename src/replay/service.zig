const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const AccountsDB = sig.accounts_db.AccountsDB;
const BlockstoreReader = sig.ledger.BlockstoreReader;

const ScopedLogger = sig.trace.ScopedLogger("replay");

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
    std.Thread.sleep(100 * std.time.ns_per_ms);

    handleEdgeCases();

    processConsensus();

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
