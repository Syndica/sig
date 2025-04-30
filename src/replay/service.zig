const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const deps = replay.deps;

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const Entry = sig.core.Entry;
const Hash = sig.core.Hash;
const Slot = sig.core.Slot;

const AccountsDB = sig.accounts_db.AccountsDB;
const BlockstoreReader = sig.ledger.BlockstoreReader;

const AccountLocks = deps.AccountLocks;
const Tower = deps.Tower;
const tower_storage = deps.tower_storage;

const ReplayExecutionState = replay.execution.ReplayExecutionState;
const EntryVerifier = replay.verifiers.EntryVerifier;
const ListRecycler = replay.verifiers.ListRecycler;
const RuntimeSanitizedTransaction = replay.verifiers.RuntimeSanitizedTransaction;
const TransactionVerifyAndHasher = replay.verifiers.TransactionVerifyAndHasher;

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
    tower: Tower,

    fn init(dependencies: ReplayDependencies) Allocator.Error!ReplayState {
        const tower = try tower_storage.load() orelse Tower.init();

        const thread_pool = try dependencies.allocator.create(ThreadPool);
        errdefer dependencies.allocator.destroy(thread_pool);
        thread_pool.* = ThreadPool.init(.{ .max_threads = NUM_THREADS });

        return .{
            .allocator = dependencies.allocator,
            .logger = ScopedLogger.from(dependencies.logger),
            .thread_pool = thread_pool,
            .execution = try ReplayExecutionState.init(
                dependencies.allocator,
                dependencies.logger,
                thread_pool,
                dependencies.epoch_schedule,
                dependencies.accounts_db,
                dependencies.blockstore_reader,
            ),
            .tower = tower,
        };
    }

    fn deinit(self: *ReplayState) void {
        self.execution.deinit();
    }
};

/// Run the replay service indefinitely.
pub fn run(dependencies: ReplayDependencies) !void {
    var state = try ReplayState.init(dependencies);
    defer state.deinit();

    while (!dependencies.exit.load(.monotonic)) try advanceReplay(&state);
}

/// Run a single iteration of the entire replay process. Includes:
/// - replay all active slots that have not been replayed yet
/// - running concensus on the latest updates
fn advanceReplay(state: *ReplayState) !void {
    // TODO: generate_new_bank_forks

    // TODO: replay_active_banks
    _ = try replay.execution.replayActiveSlots(&state.execution);

    // TODO: process_ancestor_hashes_duplicate_slots

    // TODO: process_duplicate_confirmed_slots

    // TODO: process_gossip_verified_vote_hashes

    // TODO: process_popular_pruned_forks

    // TODO: process_duplicate_slots

    // TODO: for each slot:
    //           tower_duplicate_confirmed_forks
    //           mark_slots_duplicate_confirmed

    // TODO: select_forks

    // TODO: check_for_vote_only_mode

    // TODO: select_vote_and_reset_forks

    // TODO: if vote_bank.is_none: maybe_refresh_last_vote

    // TODO: handle_votable_bank

    // TODO: if reset_bank: Reset onto a fork

    // TODO: dump_then_repair_correct_slots

    // TODO: maybe_start_leader
}

// // Analogous to [replay_active_banks](https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3356)
// fn replayActiveSlots(state: *ReplayState.ExecutionState) Allocator.Error!bool {
//     // TODO: parallel processing: https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3401

//     const active_slots = try state.slot_tracker.activeSlots(state.allocator);
//     if (active_slots.len == 0) {
//         return false;
//     }

//     for (active_slots) |slot| {
//         _ = slot; // autofix
//         replayActiveSlot();
//     }

//     // TODO: process_replay_results: https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3443

//     return undefined;
// }

// const ReplaySlotFromBlockstore = struct {
//     is_slot_dead: bool,
//     bank_slot: Slot,
//     replay_result: ?BlockstoreProcessorError!usize,
// };

// const ReplayActiveBankError = Allocator.Error | error{BankNotFound};

// fn replayActiveSlot(state: ReplayState.ExecutionState, bank_slot: Slot) ReplayActiveBankError!void {
//     var replay_result = ReplaySlotFromBlockstore{
//         .is_slot_dead = false,
//         .bank_slot = bank_slot,
//         .replay_result = null,
//     };
//     const fork_progress = try state.progress.map.getOrPut(state.allocator, bank_slot);
//     if (fork_progress.found_existing and fork_progress.value_ptr.is_dead) {
//         replay_result.is_slot_dead = true;
//         return replay_result;
//     }

//     const slot_info = state.slot_tracker.slots.get(bank_slot) orelse return error.MissingSlot;
//     const epoch_info = state.epochs.getForSlot(bank_slot) orelse return error.MissingEpoch;
//     const verify_ticks_config = VerifyTicksConfig{
//         .tick_height = slot_info.state.tickHeight(),
//         .max_tick_height = slot_info.constants.max_tick_height,
//         .hashes_per_tick = epoch_info.hashes_per_tick,
//     };

//     const slot = bank_slot;
//     const start_shred = 0; // TODO: progress.num_shreds;
//     // TODO: measure time
//     const entries, const num_shreds, const slot_is_full =
//         try state.blockstore_reader.getSlotEntriesWithShredInfo(bank_slot, start_shred, false);
//     _ = num_shreds; // autofix

//     try state.entry_confirmer.confirmSlotEntries(verify_ticks_config, entries, slot, slot_is_full);
// }

// const ConfirmationProgress = struct {
//     last_entry: Hash,
//     tick_hash_count: u64,
//     num_shreds: u64,
//     num_entries: usize,
//     num_txs: usize,
// };

// /// Maintains the state that is used by confirmSlotEntries and must be persisted
// /// across calls.
// const EntryConfirmer = struct {
//     allocator: Allocator,
//     logger: ScopedLogger,
//     entry_verifier: EntryVerifier,
//     transaction_verifier: TransactionVerifyAndHasher,
//     /// NOTE: in the future, this may be needed in other contexts, at which
//     /// point the lifetime should be re-evaluated.
//     list_recycler: *ListRecycler(RuntimeSanitizedTransaction),
//     account_locks: AccountLocks,

//     const list_recycler_size = 100; // TODO tune

//     pub fn init(
//         allocator: Allocator,
//         logger: ScopedLogger,
//         thread_pool: *ThreadPool,
//     ) Allocator.Error!EntryConfirmer {
//         const entry_verifier = try EntryVerifier
//             .init(allocator, thread_pool, thread_pool.max_threads);
//         errdefer entry_verifier.deinit();

//         var list_recycler = try allocator.create(ListRecycler(RuntimeSanitizedTransaction));
//         list_recycler.* = try ListRecycler(RuntimeSanitizedTransaction)
//             .init(allocator, list_recycler_size);
//         errdefer list_recycler.deinit();

//         const transaction_verifier = try TransactionVerifyAndHasher
//             .init(allocator, thread_pool, list_recycler, thread_pool.max_threads);
//         errdefer transaction_verifier.deinit();

//         return .{
//             .allocator = allocator,
//             .logger = logger,
//             .entry_verifier = entry_verifier,
//             .transaction_verifier = transaction_verifier,
//             .list_recycler = list_recycler,
//             .account_locks = .{},
//         };
//     }

//     pub fn deinit(self: EntryConfirmer) void {
//         _ = self; // autofix
//     }

//     /// Validate and execute the entries.
//     ///
//     /// agave: confirm_slot
//     /// fd: runtime_process_txns_in_microblock_stream
//     fn confirmSlotEntries(
//         self: *EntryConfirmer,
//         progress: *ConfirmationProgress,
//         entries: []const Entry,
//         config: VerifyTicksConfig,
//         slot: Slot,
//         slot_is_full: bool,
//     ) BlockstoreProcessorError!void {
//         _ = slot; // autofix
//         // TODO: send each entry to entry notification sender
//         try verifyTicks(self.logger, config, entries, slot_is_full, progress.tick_hash_count);
//         self.transaction_verifier.start(entries);
//         try self.transaction_verifier.finish(self.replay_transactions);
//         self.entry_verifier.start(progress.last_entry, entries);

//         // TODO: executes entry transactions and verify results
//         //     TODO: call process_entries
//         var batches = std.ArrayListUnmanaged(void){};
//         var accounts = std.ArrayListUnmanaged(void){};
//         _ = batches; // autofix
//         for (entries) |entry| {
//             if (entry.transactions.items.len > 0) {
//                 for (entry.transactions.items) |tx| {
//                     for (tx.msg.account_keys) |key| {
//                         try accounts.append(self.allocator, .{key});
//                     }
//                 }
//                 self.account_locks.lockAll(self.list_recycler.allocator, accounts);
//             }
//         }

//         if (self.entry_verifier.finish()) {
//             return error.PohVerificationFailed;
//         }
//     }
// };

// const BlockstoreProcessorError = BlockError;

// const VerifyTicksConfig = struct {
//     /// slot-scoped state
//     tick_height: u64,
//     /// slot-scoped constant
//     max_tick_height: u64,
//     /// epoch-scoped constant
//     hashes_per_tick: u64,
// };

// /// Verify that a segment of entries has the correct number of ticks and hashes
// /// analogous to [verify_ticks](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/ledger/src/blockstore_processor.rs#L1097)
// fn verifyTicks(
//     logger: ScopedLogger,
//     config: VerifyTicksConfig,
//     entries: []const Entry,
//     slot_full: bool,
//     tick_hash_count: *u64,
// ) BlockError!void {
//     const next_bank_tick_height = config.tick_height + Entry.slice.tickCount(entries);
//     const max_bank_tick_height = config.max_tick_height;

//     if (next_bank_tick_height > max_bank_tick_height) {
//         logger.warn().logf("Too many entry ticks found in slot: {}", .{config.slot});
//         return error.TooManyTicks;
//     }

//     if (next_bank_tick_height < max_bank_tick_height and slot_full) {
//         logger.info().logf("Too few entry ticks found in slot: {}", .{config.slot});
//         return error.TooFewTicks;
//     }

//     if (next_bank_tick_height == max_bank_tick_height) {
//         if (entries.len == 0 or !entries[entries.len - 1].isTick()) {
//             logger.warn().logf("Slot: {} did not end with a tick entry", .{config.slot});
//             return error.TrailingEntry;
//         }

//         if (!slot_full) {
//             logger.warn().logf("Slot: {} was not marked full", .{config.slot});
//             return error.InvalidLastTick;
//         }
//     }

//     const hashes_per_tick = config.hashes_per_tick orelse 0;
//     if (!Entry.slice.verifyTickHashCount(tick_hash_count, hashes_per_tick)) {
//         logger.warn().logf("Tick with invalid number of hashes found in slot: {}", config.slot);
//         return error.InvalidTickHashCount;
//     }
// }

// pub const BlockError = error{
//     /// Block did not have enough ticks was not marked full
//     /// and no shred with is_last was seen.
//     Incomplete,

//     /// Block entries hashes must all be valid
//     InvalidEntryHash,

//     /// Blocks must end in a tick that has been marked as the last tick.
//     InvalidLastTick,

//     /// Blocks can not have missing ticks
//     /// Usually indicates that the node was interrupted with a more valuable block during
//     /// production and abandoned it for that more-favorable block. Leader sent data to indicate
//     /// the end of the block.
//     TooFewTicks,

//     /// Blocks can not have extra ticks
//     TooManyTicks,

//     /// All ticks must contain the same number of hashes within a block
//     InvalidTickHashCount,

//     /// Blocks must end in a tick entry, trailing transaction entries are not allowed to guarantee
//     /// that each block has the same number of hashes
//     TrailingEntry,

//     DuplicateBlock,
// };

// fn @"Reset onto a fork"() void {
//     // if last reset is last blockhash, get active descendants and set them
//     // else, do the rest...

//     // load new tower if identity changed

//     // reset_poh_recorder

//     // update partition info
// }

// fn generate_new_bank_forks() void {}
