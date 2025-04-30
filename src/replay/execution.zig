const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const deps = replay.deps;

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const Entry = sig.core.Entry;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Transaction = sig.core.Transaction;

const AccountsDB = sig.accounts_db.AccountsDB;
const BlockstoreReader = sig.ledger.BlockstoreReader;

const AccountLocks = deps.AccountLocks;
const EpochTracker = deps.EpochTracker;
const ProgressMap = deps.ProgressMap;
const SlotTracker = deps.SlotTracker;

const EntryVerifier = replay.verifiers.EntryVerifier;
const ListRecycler = replay.verifiers.ListRecycler;
const RuntimeSanitizedTransaction = replay.verifiers.RuntimeSanitizedTransaction;
const ReplayEntry = replay.verifiers.ReplayEntry;
const TransactionVerifyAndHasher = replay.verifiers.TransactionVerifyAndHasher;

const ScopedLogger = sig.trace.ScopedLogger("replay-execution");

/// State used for replaying and validating data from blockstore/accountsdb/svm
pub const ReplayExecutionState = struct {
    allocator: Allocator,
    logger: ScopedLogger,
    accounts_db: *AccountsDB,
    blockstore_reader: *BlockstoreReader,
    slot_tracker: SlotTracker,
    entry_confirmer: EntryConfirmer,
    epochs: EpochTracker,
    progress_map: ProgressMap,

    pub fn init(
        allocator: Allocator,
        logger: sig.trace.Logger,
        thread_pool: *ThreadPool,
        epoch_schedule: sig.core.EpochSchedule,
        accounts_db: *AccountsDB,
        blockstore_reader: *BlockstoreReader,
    ) Allocator.Error!ReplayExecutionState {
        const entry_confirmer = try EntryConfirmer.init(
            allocator,
            ScopedLogger.from(logger),
            thread_pool,
        );
        errdefer entry_confirmer.deinit();

        return .{
            .allocator = allocator,
            .logger = ScopedLogger.from(logger),
            .accounts_db = accounts_db,
            .blockstore_reader = blockstore_reader,
            .slot_tracker = .{},
            .entry_confirmer = entry_confirmer,
            .epochs = .{ .schedule = epoch_schedule },
            .progress_map = .{},
        };
    }

    pub fn deinit(self: ReplayExecutionState) void {
        self.entry_confirmer.deinit();
        self.epochs.deinit(self.allocator);
    }
};

/// Analogous to [replay_active_banks](https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3356)
pub fn replayActiveSlots(state: *ReplayExecutionState) !bool {
    // TODO: parallel processing: https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3401

    const active_slots = try state.slot_tracker.activeSlots(state.allocator);
    if (active_slots.len == 0) {
        return false;
    }

    for (active_slots) |slot| {
        _ = try replaySlot(state, slot);
    }

    // TODO: process_replay_results: https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3443

    return undefined;
}

/// Analogous to [ReplaySlotFromBlockstore](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/core/src/replay_stage.rs#L175)
const ReplayResult = union(enum) {
    /// Replay succeeded with this many transactions.
    success: struct { transaction_count: usize },
    /// The slot was previously marked as dead, so it was not replayed.
    dead,
    /// Replay failed due to this error.
    failure: BlockstoreProcessorError,
};

/// replay_active_bank
fn replaySlot(
    state: *ReplayExecutionState,
    bank_slot: Slot,
) !ReplayResult {
    const fork_progress = try state.progress_map.map.getOrPut(state.allocator, bank_slot);
    if (fork_progress.found_existing and fork_progress.value_ptr.is_dead) {
        return .dead;
    }

    const slot_info = state.slot_tracker.slots.get(bank_slot) orelse return error.MissingSlot;
    const epoch_info = state.epochs.getForSlot(bank_slot) orelse return error.MissingEpoch;
    const verify_ticks_config = VerifyTicksConfig{
        .tick_height = slot_info.state.tickHeight(),
        .max_tick_height = slot_info.constants.max_tick_height,
        .hashes_per_tick = epoch_info.hashes_per_tick,
    };

    const slot = bank_slot;
    const start_shred = 0; // TODO: progress.num_shreds;
    // TODO: measure time
    const entries, const num_shreds, const slot_is_full =
        try state.blockstore_reader.getSlotEntriesWithShredInfo(bank_slot, start_shred, false);
    _ = num_shreds; // autofix

    return try state.entry_confirmer.confirmSlotEntries(
        &fork_progress.value_ptr.confirmation_progress,
        entries.items,
        verify_ticks_config,
        slot,
        slot_is_full,
    );
}

/// Maintains the state that is used by confirmSlotEntries and must be persisted
/// across calls.
///
/// NOT safe to share across threads.
const EntryConfirmer = struct {
    allocator: Allocator,
    logger: ScopedLogger,
    entry_verifier: EntryVerifier,
    transaction_verifier: TransactionVerifyAndHasher,
    /// NOTE: in the future, this may be needed in other contexts, at which
    /// point the lifetime should be re-evaluated.
    list_recycler: *ListRecycler(RuntimeSanitizedTransaction),
    account_locks: AccountLocks,
    /// reused buffer to minimize allocations
    replay_entries: std.ArrayListUnmanaged(ReplayEntry),

    const list_recycler_size = 100; // TODO tune

    pub fn init(
        allocator: Allocator,
        logger: ScopedLogger,
        thread_pool: *ThreadPool,
    ) Allocator.Error!EntryConfirmer {
        const entry_verifier = try EntryVerifier
            .init(allocator, thread_pool, thread_pool.max_threads);
        errdefer entry_verifier.deinit();

        var list_recycler = try allocator.create(ListRecycler(RuntimeSanitizedTransaction));
        list_recycler.* = try ListRecycler(RuntimeSanitizedTransaction)
            .init(allocator, list_recycler_size);
        errdefer list_recycler.deinit();

        const transaction_verifier = try TransactionVerifyAndHasher
            .init(allocator, thread_pool, list_recycler, thread_pool.max_threads);
        errdefer transaction_verifier.deinit();

        return .{
            .allocator = allocator,
            .logger = logger,
            .entry_verifier = entry_verifier,
            .transaction_verifier = transaction_verifier,
            .list_recycler = list_recycler,
            .account_locks = .{},
            .replay_entries = .{},
        };
    }

    pub fn deinit(self: EntryConfirmer) void {
        _ = self; // autofix
    }

    /// Validate and execute the entries.
    ///
    /// agave: confirm_slot and confirm_slot_entries
    /// fd: runtime_process_txns_in_microblock_stream
    fn confirmSlotEntries(
        self: *EntryConfirmer,
        progress: *deps.ForkProgress.ConfirmationProgress,
        entries: []const Entry,
        config: VerifyTicksConfig,
        slot: Slot,
        slot_is_full: bool,
    ) !ReplayResult {
        // TODO: send each entry to entry notification sender
        if (verifyTicks(
            self.logger,
            config,
            slot,
            entries,
            slot_is_full,
            &progress.tick_hash_count,
        )) |block_error| {
            return .{ .failure = .{ .InvalidBlock = block_error } };
        }

        self.replay_entries.clearRetainingCapacity();
        try self.replay_entries.ensureTotalCapacity(self.allocator, entries.len);
        self.transaction_verifier.start(entries, self.replay_entries.items);
        try self.transaction_verifier.finish(); // TODO accountsdb for lookup tables

        self.entry_verifier.start(progress.last_entry, entries);

        // TODO: executes entry transactions and verify results
        //     TODO: call process_entries
        // var batches = std.ArrayListUnmanaged(void){};
        var accounts = std.ArrayListUnmanaged(struct { Pubkey, bool }){};
        var num_transactions: usize = 0;
        for (entries) |entry| {
            if (entry.transactions.items.len > 0) {
                for (entry.transactions.items) |tx| {
                    num_transactions += 1;
                    for (tx.msg.account_keys, 0..) |key, i| {
                        // TODO: fix broken account locking
                        try accounts.append(self.allocator, .{ key, tx.msg.isWritable(i) });
                    }
                }
                try self.account_locks.lock(self.list_recycler.allocator, accounts.items);
            }
        }

        if (!try self.entry_verifier.finish()) {
            return .{ .failure = .{ .InvalidBlock = .InvalidEntryHash } };
        }

        return .{ .success = .{ .transaction_count = num_transactions } };
    }
};

// const BlockstoreProcessorError = Allocator.Error || BlockError || Transaction.VerifyError;

const VerifyTicksConfig = struct {
    /// slot-scoped state
    tick_height: u64,
    /// slot-scoped constant
    max_tick_height: u64,
    /// epoch-scoped constant
    hashes_per_tick: ?u64,
};

/// Verify that a segment of entries has the correct number of ticks and hashes
/// analogous to [verify_ticks](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/ledger/src/blockstore_processor.rs#L1097)
fn verifyTicks(
    logger: ScopedLogger,
    config: VerifyTicksConfig,
    slot: Slot,
    entries: []const Entry,
    slot_full: bool,
    tick_hash_count: *u64,
) ?BlockError {
    const next_bank_tick_height = config.tick_height + Entry.slice.tickCount(entries);
    const max_bank_tick_height = config.max_tick_height;

    if (next_bank_tick_height > max_bank_tick_height) {
        logger.warn().logf("Too many entry ticks found in slot: {}", .{slot});
        return .TooManyTicks;
    }

    if (next_bank_tick_height < max_bank_tick_height and slot_full) {
        logger.info().logf("Too few entry ticks found in slot: {}", .{slot});
        return .TooFewTicks;
    }

    if (next_bank_tick_height == max_bank_tick_height) {
        if (entries.len == 0 or !entries[entries.len - 1].isTick()) {
            logger.warn().logf("Slot: {} did not end with a tick entry", .{slot});
            return .TrailingEntry;
        }

        if (!slot_full) {
            logger.warn().logf("Slot: {} was not marked full", .{slot});
            return .InvalidLastTick;
        }
    }

    const hashes_per_tick = config.hashes_per_tick orelse 0;
    if (!Entry.slice.verifyTickHashCount(logger, entries, tick_hash_count, hashes_per_tick)) {
        logger.warn().logf("Tick with invalid number of hashes found in slot: {}", .{slot});
        return .InvalidTickHashCount;
    }

    return null;
}

/// Analogous to [BlockstoreProcessorError](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/ledger/src/blockstore_processor.rs#L779)
pub const BlockstoreProcessorError = union(enum) {
    FailedToLoadEntries: anyerror,
    FailedToLoadMeta,
    /// failed to replay bank 0, did you forget to provide a snapshot
    FailedToReplayBank0,
    InvalidBlock: BlockError,
    InvalidTransaction: sig.ledger.transaction_status.TransactionError, // TODO move to core?
    NoValidForksFound,
    InvalidHardFork: Slot,
    RootBankWithMismatchedCapitalization: Slot,
    SetRootError,
    IncompleteFinalFecSet,
    InvalidRetransmitterSignatureFinalFecSet,
};

pub const BlockError = enum {
    /// Block did not have enough ticks was not marked full
    /// and no shred with is_last was seen.
    Incomplete,

    /// Block entries hashes must all be valid
    InvalidEntryHash,

    /// Blocks must end in a tick that has been marked as the last tick.
    InvalidLastTick,

    /// Blocks can not have missing ticks
    /// Usually indicates that the node was interrupted with a more valuable block during
    /// production and abandoned it for that more-favorable block. Leader sent data to indicate
    /// the end of the block.
    TooFewTicks,

    /// Blocks can not have extra ticks
    TooManyTicks,

    /// All ticks must contain the same number of hashes within a block
    InvalidTickHashCount,

    /// Blocks must end in a tick entry, trailing transaction entries are not allowed to guarantee
    /// that each block has the same number of hashes
    TrailingEntry,

    DuplicateBlock,
};
