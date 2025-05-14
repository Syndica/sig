const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const core = sig.core;

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const Entry = core.Entry;
const Hash = core.Hash;
const Pubkey = core.Pubkey;
const Slot = core.Slot;
const TransactionError = sig.ledger.transaction_status.TransactionError;

const AccountsDB = sig.accounts_db.AccountsDB;

const ConfirmationProgress = sig.consensus.progress_map.blockstore_processor.ConfirmationProgress;

const ReplayBatcher = replay.batcher.ReplayBatcher;
const ResolvedTransaction = replay.resolve.ResolvedTransaction;

const assert = std.debug.assert;

const ScopedLogger = sig.trace.ScopedLogger("replay-confirm-slot");

/// Asynchronously validate and execute entries from a slot.
///
/// Returns: a SlotConfirmer which you can poll periodically to await a result.
///
/// Analogous to:
/// - agave: confirm_slot and confirm_slot_entries
/// - fd: runtime_process_txns_in_microblock_stream
pub fn confirmSlot(
    allocator: Allocator,
    logger: ScopedLogger,
    thread_pool: *ThreadPool,
    entries: []const Entry,
    progress: *ConfirmationProgress,
    config: VerifyTicksConfig,
    slot: Slot,
    slot_is_full: bool,
) Allocator.Error!ConfirmSlotFuture {
    const batcher = ReplayBatcher.initCapacity(allocator, entries.len, thread_pool);
    errdefer batcher.deinit(allocator);

    const slot_confirmer = ConfirmSlotFuture{
        .allocator = allocator,
        .logger = logger,
        .poh_verifier = try sig.utils.thread.HomogeneousThreadPool(PohTask)
            .initBorrowed(allocator, thread_pool, thread_pool.max_threads),
        .batcher = batcher,
        .state = .init,
    };

    if (verifyTicks(
        slot_confirmer.logger,
        config,
        slot,
        entries,
        slot_is_full,
        &progress.tick_hash_count,
    )) |block_error| {
        slot_confirmer.status = .{ .failure = .{ .InvalidBlock = block_error } };
        return slot_confirmer;
    }

    try schedulePohTasks(slot_confirmer, progress.last_entry, entries);
    const initial_tx_result = try scheduleTransactions(slot_confirmer, entries);

    if (.pending != initial_tx_result) {
        slot_confirmer.status_when_done = initial_tx_result;
    }
}

/// schedule poh verification asynchronously into a ConfirmSlotFuture
fn schedulePohTasks(
    self: *ConfirmSlotFuture,
    initial_hash: Hash,
    entries: []const Entry,
) Allocator.Error!void {
    if (entries.len == 0) return;
    const num_tasks = @min(self.poh_verifier.max_concurrent_tasks, entries.len);
    const entries_per_task = entries.len / num_tasks;
    var batch_initial_hash = initial_hash;
    for (0..num_tasks) |i| {
        const end = if (i == num_tasks + 1) entries.len else i * entries_per_task;
        assert(try self.poh_verifier.trySchedule(self.allocator, .{
            .allocator = self.allocator,
            .preallocated_nodes = &self.preallocated_nodes[i],
            .initial_hash = batch_initial_hash,
            .entries = entries[i..end],
        }));
        batch_initial_hash = entries[end - 1].hash;
    }
}

/// schedule transaction verification/execution asynchronously into a ConfirmSlotFuture
fn scheduleTransactions(
    self: *ConfirmSlotFuture,
    entries: []const Entry,
) !ConfirmSlotStatus {
    var total_transactions: usize = 0;
    for (entries) |entry| {
        total_transactions += entry.transactions.items.len;
        var accounts_to_lock = try std.ArrayListUnmanaged(struct { Pubkey, bool })
            .initCapacity(self.allocator, core.entry.numAccounts(entries));
        defer unreachable; // TODO
        const resolved_txns =
            try self.allocator.alloc(ResolvedTransaction, entry.transactions.items.len);
        for (entry.transactions.items, resolved_txns) |transaction, *resolved| {
            resolved.* = try ResolvedTransaction
                .init(self.allocator, self.accounts_db, transaction, &accounts_to_lock);
        }
        self.batcher.addBatchAssumeCapacity(.{
            .accounts_to_lock = accounts_to_lock.toOwnedSlice(self.allocator),
            .transactions = resolved_txns,
        });

        switch (try self.batcher.poll()) {
            .done, .pending => {},
            .err => |err| return .{ .failure = .{ .InvalidTransaction = err } },
        }
    }
    return .pending;
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
    logger: ScopedLogger,
    accounts_db: AccountsDB,
    batcher: ReplayBatcher,
    poh_verifier: sig.utils.thread.HomogeneousThreadPool(PohTask),

    /// The current status to return on poll, unless something has changed.
    status: ConfirmSlotStatus,
    /// Temporarily stores errors that occur before completion that need to be
    /// returned when all tasks are complete.
    status_when_done: ConfirmSlotStatus = .done,

    pub fn poll(self: *ConfirmSlotFuture) ConfirmSlotStatus {
        switch (self.status) {
            .pending => {
                var pending = false;
                for (self.pollEach()) |status| switch (status) {
                    .pending => pending = true,
                    .err => |err| if (self.status_when_done == .done) {
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

    fn pollEach(self: *ConfirmSlotFuture) [2]?ConfirmSlotStatus {
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
    preallocated_nodes: *std.ArrayListUnmanaged(Hash),
    initial_hash: Hash,
    entries: []const Entry,

    pub fn run(self: *PohTask) Allocator.Error!bool {
        return try core.entry.verifyPoh(
            self.entries,
            self.allocator,
            self.preallocated_nodes,
            self.initial_hash,
        );
    }
};

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
    const next_bank_tick_height = config.tick_height + core.entry.tickCount(entries);
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
    if (!core.entry.verifyTickHashCount(entries, logger, tick_hash_count, hashes_per_tick)) {
        logger.warn().logf("Tick with invalid number of hashes found in slot: {}", .{slot});
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
