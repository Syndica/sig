const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const core = sig.core;

const Allocator = std.mem.Allocator;

const ReturnType = sig.utils.types.ReturnType;
const HomogeneousThreadPool = sig.utils.thread.HomogeneousThreadPool;
const ThreadPool = sig.sync.ThreadPool;

const Entry = core.Entry;
const Hash = core.Hash;
const Pubkey = core.Pubkey;
const Slot = core.Slot;
const TransactionError = sig.ledger.transaction_status.TransactionError;

const AccountsDB = sig.accounts_db.AccountsDB;
const ConfirmationProgress = sig.consensus.progress_map.blockstore_processor.ConfirmationProgress;

const TransactionScheduler = replay.scheduler.TransactionScheduler;
const ResolvedTransaction = replay.resolve.ResolvedTransaction;
const resolveBatch = replay.resolve.resolveBatch;

const assert = std.debug.assert;

const ScopedLogger = sig.trace.ScopedLogger("replay-confirm-slot");

/// Asynchronously validate and execute entries from a slot.
///
/// Return: ConfirmSlotFuture which you can poll periodically to await a result.
///
/// Analogous to:
/// - agave: confirm_slot_entries
/// - fd: runtime_process_txns_in_microblock_stream
pub fn confirmSlot(
    allocator: Allocator,
    logger: ScopedLogger,
    thread_pool: *ThreadPool,
    entries: []const Entry,
    last_entry: Hash,
    verify_ticks_params: VerifyTicksParams,
) Allocator.Error!*ConfirmSlotFuture {
    const future = try ConfirmSlotFuture.create(allocator, thread_pool, entries.len);
    errdefer future.destroy();

    if (verifyTicks(logger, entries, verify_ticks_params)) |block_error| {
        future.status = .{ .failure = .{ .InvalidBlock = block_error } };
        return future;
    }

    try startPohVerify(allocator, &future.poh_verifier, last_entry, entries);
    try scheduleBatches(future, entries);

    _ = future.poll(); // starts batch execution. poll result is cached inside future

    return future;
}

/// schedule poh verification asynchronously
fn startPohVerify(
    allocator: Allocator,
    pool: *HomogeneousThreadPool(PohTask),
    initial_hash: Hash,
    entries: []const Entry,
) Allocator.Error!void {
    if (entries.len == 0) return;
    const num_tasks = @min(pool.max_concurrent_tasks, entries.len);
    const entries_per_task = entries.len / num_tasks;
    var batch_initial_hash = initial_hash;
    for (0..num_tasks) |i| {
        const end = if (i == num_tasks + 1) entries.len else i * entries_per_task;
        assert(try pool.trySchedule(allocator, .{
            .allocator = allocator,
            .initial_hash = batch_initial_hash,
            .entries = entries[i..end],
        }));
        batch_initial_hash = entries[end - 1].hash;
    }
}

/// schedule transaction verification/execution asynchronously
fn scheduleBatches(
    allocator: Allocator,
    accounts_db: *AccountsDB,
    batcher: *TransactionScheduler,
    entries: []const Entry,
) !void {
    var total_transactions: usize = 0;
    for (entries) |entry| {
        total_transactions += entry.transactions.items.len;

        const batch = try resolveBatch(allocator, accounts_db, entry.transactions.items);
        errdefer batch.deinit(allocator);

        batcher.addBatchAssumeCapacity(batch);
    }
}

pub const ConfirmSlotStatus = union(enum) {
    done,
    pending,
    err: ConfirmSlotError,
};

/// Tracks the state of a slot confirmation execution.
///
/// Do not share across threads.
///
/// agave: confirm_slot and confirm_slot_entries
/// fd: runtime_process_txns_in_microblock_stream
pub const ConfirmSlotFuture = struct {
    allocator: Allocator,
    batcher: TransactionScheduler,
    poh_verifier: HomogeneousThreadPool(PohTask),

    /// The current status to return on poll, unless something has changed.
    status: ConfirmSlotStatus,
    /// Temporarily stores errors that occur before completion that need to be
    /// returned when all tasks are complete.
    status_when_done: ConfirmSlotStatus = .done,

    fn create(
        allocator: Allocator,
        thread_pool: *ThreadPool,
        num_entries: usize,
    ) !*ConfirmSlotFuture {
        const batcher = TransactionScheduler.initCapacity(allocator, num_entries, thread_pool);
        errdefer batcher.deinit(allocator);

        const poh_verifier = try HomogeneousThreadPool(PohTask)
            .initBorrowed(allocator, thread_pool, thread_pool.max_threads);
        errdefer poh_verifier.deinit(allocator);

        const future = try allocator.create(ConfirmSlotFuture);
        errdefer allocator.free(future);

        future.* = ConfirmSlotFuture{
            .allocator = allocator,
            .poh_verifier = poh_verifier,
            .batcher = batcher,
            .status = .pending,
        };

        return future;
    }

    fn destroy(self: *ConfirmSlotFuture) void {
        self.batcher.deinit();
        self.poh_verifier.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn poll(self: *ConfirmSlotFuture) ConfirmSlotStatus {
        switch (self.status) {
            .pending => {
                var pending = false;
                for (self.pollEach()) |status| switch (status) {
                    .pending => pending = true,
                    .err => |err| if (self.status_when_done == .done) {
                        // TODO: notify threads to exit
                        self.status_when_done = .{ .err = err };
                    },
                    .done => {},
                };
                if (!pending) self.state = self.status_when_done;
            },
            else => {},
        }

        return self.status;
    }

    fn pollEach(self: *ConfirmSlotFuture) [2]ConfirmSlotStatus {
        return .{
            switch (self.poh_verifier.pollFallible()) {
                .done => .done,
                .pending => .pending,
                .err => .{ .err = .SignatureFailure },
            },
            self.batcher.poll(),
        };
    }
};

const PohTask = struct {
    allocator: Allocator,
    initial_hash: Hash,
    entries: []const Entry,

    pub fn run(self: *PohTask) Allocator.Error!bool {
        return try core.entry.verifyPoh(self.entries, self.allocator, null, self.initial_hash);
    }
};

pub const VerifyTicksParams = struct {
    /// epoch-scoped constant
    hashes_per_tick: ?u64,

    // slot-scoped constants
    slot: u64,
    max_tick_height: u64,

    // slot-scoped state (constant during lifetime of this struct)
    tick_height: u64,
    slot_is_full: bool,

    /// slot-scoped state (expected to be mutated while verifying ticks)
    tick_hash_count: ?*u64,
};

/// Verify that a segment of entries has the correct number of ticks and hashes
/// analogous to [verify_ticks](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/ledger/src/blockstore_processor.rs#L1097)
fn verifyTicks(
    logger: ScopedLogger,
    entries: []const Entry,
    params: VerifyTicksParams,
) ?BlockError {
    const next_bank_tick_height = params.tick_height + core.entry.tickCount(entries);
    const max_bank_tick_height = params.max_tick_height;

    if (next_bank_tick_height > max_bank_tick_height) {
        logger.warn().logf("Too many entry ticks found in slot: {}", .{params.slot});
        return .TooManyTicks;
    }

    if (next_bank_tick_height < max_bank_tick_height and params.slot_full) {
        logger.info().logf("Too few entry ticks found in slot: {}", .{params.slot});
        return .TooFewTicks;
    }

    if (next_bank_tick_height == max_bank_tick_height) {
        if (entries.len == 0 or !entries[entries.len - 1].isTick()) {
            logger.warn().logf("Slot: {} did not end with a tick entry", .{params.slot});
            return .TrailingEntry;
        }

        if (!params.slot_full) {
            logger.warn().logf("Slot: {} was not marked full", .{params.slot});
            return .InvalidLastTick;
        }
    }

    const hashes_per_tick = params.hashes_per_tick orelse 0;
    if (!core.entry.verifyTickHashCount(entries, logger, params.tick_hash_count, hashes_per_tick)) {
        logger.warn().logf("Tick with invalid number of hashes found in slot: {}", .{params.slot});
        return .InvalidTickHashCount;
    }

    return null;
}

/// Analogous to [BlockstoreProcessorError](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/ledger/src/blockstore_processor.rs#L779)
pub const ConfirmSlotError = union(enum) {
    failed_to_load_entries: anyerror,
    failed_to_load_meta,
    /// failed to replay bank 0, did you forget to provide a snapshot
    failed_to_replay_bank_0,
    invalid_block: BlockError,
    invalid_transaction: TransactionError, // TODO move to core?
    no_valid_forks_found,
    invalid_hard_fork: Slot,
    root_bank_with_mismatched_capitalization: Slot,
    set_root_error,
    incomplete_final_fec_set,
    invalid_retransmitter_signature_final_fec_set,
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
