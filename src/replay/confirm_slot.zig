const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const core = sig.core;

const Allocator = std.mem.Allocator;

const HomogeneousThreadPool = sig.utils.thread.HomogeneousThreadPool;
const ThreadPool = sig.sync.ThreadPool;

const Entry = core.Entry;
const Hash = core.Hash;
const Slot = core.Slot;
const TransactionError = sig.ledger.transaction_status.TransactionError;

const AccountsDB = sig.accounts_db.AccountsDB;

const SvmSlot = replay.svm_gateway.SvmSlot;
const TransactionScheduler = replay.scheduler.TransactionScheduler;

const resolveBatch = replay.resolve_lookup.resolveBatch;

const assert = std.debug.assert;

const ScopedLogger = sig.trace.ScopedLogger("replay-confirm-slot");

/// Asynchronously validate and execute entries from a slot.
///
/// Return: ConfirmSlotFuture which you can poll periodically to await a result.
///
/// Takes ownership of the entries. Pass the same allocator that was used for
/// the entry allocation.
///
/// Analogous to:
/// - agave: confirm_slot_entries
/// - fd: runtime_process_txns_in_microblock_stream
pub fn confirmSlot(
    allocator: Allocator,
    logger: ScopedLogger,
    accounts_db: *AccountsDB,
    thread_pool: *ThreadPool,
    entries: []const Entry,
    last_entry: Hash,
    svm_params: SvmSlot.Params,
    verify_ticks_params: VerifyTicksParams,
) !*ConfirmSlotFuture {
    logger.info().log("confirming slot");
    const future = try ConfirmSlotFuture.create(allocator, thread_pool, entries);
    errdefer future.destroy(allocator);

    if (verifyTicks(logger, entries, verify_ticks_params)) |block_error| {
        future.status = .{ .err = .{ .invalid_block = block_error } };
        return future;
    }

    try startPohVerify(allocator, &future.poh_verifier, last_entry, entries);
    try scheduleTransactionBatches(allocator, &future.scheduler, accounts_db, entries, svm_params);

    _ = try future.poll(); // starts batch execution. poll result is cached inside future

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
    const num_tasks = if (pool.max_concurrent_tasks) |max| @min(max, entries.len) else entries.len;
    const entries_per_task = entries.len / num_tasks;
    var batch_initial_hash = initial_hash;
    for (0..num_tasks) |i| {
        const end = if (i == num_tasks - 1) entries.len else (i + 1) * entries_per_task;
        assert(try pool.trySchedule(allocator, .{
            .allocator = allocator,
            .initial_hash = batch_initial_hash,
            .entries = entries[i * entries_per_task .. end],
        }));
        batch_initial_hash = entries[end - 1].hash;
    }
}

/// schedule transaction verification/execution asynchronously
fn scheduleTransactionBatches(
    allocator: Allocator,
    scheduler: *TransactionScheduler,
    accounts_db: *AccountsDB,
    entries: []const Entry,
    svm_params: SvmSlot.Params,
) !void {
    var total_transactions: usize = 0;
    for (entries) |entry| {
        total_transactions += entry.transactions.len;

        const batch = try resolveBatch(allocator, accounts_db, entry.transactions);
        errdefer batch.deinit(allocator);

        scheduler.addBatchAssumeCapacity(batch);
    }

    // TODO: cleaner way of adding this
    scheduler.svm_state = try SvmSlot.init(
        allocator,
        accounts_db,
        scheduler.batches.items,
        total_transactions,
        svm_params,
    );
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
    scheduler: TransactionScheduler,
    poh_verifier: HomogeneousThreadPool(PohTask),
    entries: []const Entry,

    /// The current status to return on poll, unless something has changed.
    status: ConfirmSlotStatus,
    /// Temporarily stores errors that occur before completion that need to be
    /// returned when all tasks are complete.
    status_when_done: ConfirmSlotStatus = .done,

    fn create(
        allocator: Allocator,
        thread_pool: *ThreadPool,
        entries: []const Entry,
    ) !*ConfirmSlotFuture {
        var scheduler = try TransactionScheduler.initCapacity(allocator, entries.len, thread_pool);
        errdefer scheduler.deinit();

        const poh_verifier = try HomogeneousThreadPool(PohTask)
            .initBorrowed(allocator, thread_pool, thread_pool.max_threads);
        errdefer poh_verifier.deinit(allocator);

        const future = try allocator.create(ConfirmSlotFuture);
        errdefer allocator.free(future);

        future.* = ConfirmSlotFuture{
            .poh_verifier = poh_verifier,
            .scheduler = scheduler,
            .entries = entries,
            .status = .pending,
        };

        return future;
    }

    pub fn destroy(self: *ConfirmSlotFuture, allocator: Allocator) void {
        self.scheduler.deinit();
        self.poh_verifier.deinit(allocator);
        for (self.entries) |entry| entry.deinit(allocator);
        allocator.free(self.entries);
        allocator.destroy(self);
    }

    pub fn poll(self: *ConfirmSlotFuture) !ConfirmSlotStatus {
        switch (self.status) {
            .pending => {
                var pending = false;
                for (try self.pollEach()) |status| switch (status) {
                    .pending => pending = true,
                    .err => |err| if (self.status_when_done == .done) {
                        // TODO: notify poh threads to exit
                        self.scheduler.exit.store(true, .monotonic);
                        self.status_when_done = .{ .err = err };
                    },
                    .done => {},
                };
                if (!pending) self.status = self.status_when_done;
            },
            else => {},
        }

        return self.status;
    }

    fn pollEach(self: *ConfirmSlotFuture) ![2]ConfirmSlotStatus {
        return .{
            switch (self.poh_verifier.pollFallible()) {
                .done => .done,
                .pending => .pending,
                .err => .{ .err = .{ .invalid_block = .InvalidEntryHash } },
            },
            try self.scheduler.poll(),
        };
    }
};

const PohTask = struct {
    allocator: Allocator,
    initial_hash: Hash,
    entries: []const Entry,

    pub fn run(self: *PohTask) !void {
        if (!try core.entry.verifyPoh(self.entries, self.allocator, null, self.initial_hash)) {
            return error.PohVerifyFailed;
        }
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
    tick_hash_count: *u64,
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

    if (next_bank_tick_height < max_bank_tick_height and params.slot_is_full) {
        logger.info().logf("Too few entry ticks found in slot: {}", .{params.slot});
        return .TooFewTicks;
    }

    if (next_bank_tick_height == max_bank_tick_height) {
        if (entries.len == 0 or !entries[entries.len - 1].isTick()) {
            logger.warn().logf("Slot: {} did not end with a tick entry", .{params.slot});
            return .TrailingEntry;
        }

        if (!params.slot_is_full) {
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
    /// Payload is a statically lived string that provides some context on the
    /// failure to load entries, normally the name of an error.
    failed_to_load_entries: []const u8,
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

test "happy path: trivial case" {
    var thread_pool = ThreadPool.init(.{});
    var tick_hash_count: u64 = 0;

    const future = try confirmSlot(
        std.testing.allocator,
        .FOR_TESTS,
        undefined,
        &thread_pool,
        &.{},
        .ZEROES,
        undefined, // TODO
        .{
            .hashes_per_tick = 0,
            .slot = 0,
            .max_tick_height = 1,
            .tick_height = 0,
            .slot_is_full = false,
            .tick_hash_count = &tick_hash_count,
        },
    );
    defer future.destroy(std.testing.allocator);

    const result = try testAwait(future);
    errdefer std.log.err("failed with: {any}\n", .{result});
    try std.testing.expectEqual(.done, result);
}

test "happy path: partial slot" {
    const allocator = std.testing.allocator;

    var thread_pool = ThreadPool.init(.{});
    var tick_hash_count: u64 = 0;

    const poh, const entry_array = try sig.core.poh.testPoh(true);
    const entries: []const sig.core.Entry = entry_array.slice();
    errdefer for (entries) |entry| entry.deinit(allocator);

    const future = try confirmSlot(
        std.testing.allocator,
        .FOR_TESTS,
        undefined,
        &thread_pool,
        try allocator.dupe(Entry, entries[0 .. entries.len - 1]),
        .ZEROES,
        undefined, // TODO
        .{
            .hashes_per_tick = poh.hashes_per_tick,
            .slot = 0,
            .max_tick_height = poh.tick_count,
            .tick_height = 0,
            .slot_is_full = false,
            .tick_hash_count = &tick_hash_count,
        },
    );
    defer future.destroy(std.testing.allocator);

    const result = try testAwait(future);
    errdefer std.log.err("failed with: {any}\n", .{result});
    try std.testing.expectEqual(.done, result);
}

test "happy path: full slot" {
    const allocator = std.testing.allocator;

    var thread_pool = ThreadPool.init(.{});
    var tick_hash_count: u64 = 0;

    const poh, const entry_array = try sig.core.poh.testPoh(true);
    const entries: []const sig.core.Entry = entry_array.slice();
    errdefer for (entries) |entry| entry.deinit(allocator);

    const future = try confirmSlot(
        std.testing.allocator,
        .FOR_TESTS,
        undefined,
        &thread_pool,
        try allocator.dupe(Entry, entries),
        .ZEROES,
        undefined, // TODO
        .{
            .hashes_per_tick = poh.hashes_per_tick,
            .slot = 0,
            .max_tick_height = poh.tick_count,
            .tick_height = 0,
            .slot_is_full = true,
            .tick_hash_count = &tick_hash_count,
        },
    );
    defer future.destroy(std.testing.allocator);

    const result = try testAwait(future);
    errdefer std.log.err("failed with: {any}\n", .{result});
    try std.testing.expectEqual(.done, result);
}

test "fail: full slot not marked full -> .InvalidLastTick" {
    const allocator = std.testing.allocator;

    var thread_pool = ThreadPool.init(.{});
    var tick_hash_count: u64 = 0;

    const poh, const entry_array = try sig.core.poh.testPoh(true);
    const entries: []const sig.core.Entry = entry_array.slice();
    errdefer for (entries) |entry| entry.deinit(allocator);

    const future = try confirmSlot(
        std.testing.allocator,
        .noop,
        undefined,
        &thread_pool,
        try allocator.dupe(Entry, entries),
        .ZEROES,
        undefined, // TODO
        .{
            .hashes_per_tick = poh.hashes_per_tick,
            .slot = 0,
            .max_tick_height = poh.tick_count,
            .tick_height = 0,
            .slot_is_full = false,
            .tick_hash_count = &tick_hash_count,
        },
    );
    defer future.destroy(std.testing.allocator);

    const result = try testAwait(future);
    errdefer std.log.err("failed with: {any}\n", .{result});
    try std.testing.expectEqual(
        ConfirmSlotStatus{ .err = .{ .invalid_block = .InvalidLastTick } },
        result,
    );
}

test "fail: no trailing tick at max height -> .TrailingEntry" {
    const allocator = std.testing.allocator;

    var thread_pool = ThreadPool.init(.{});
    var tick_hash_count: u64 = 0;

    const poh, const entry_array = try sig.core.poh.testPoh(true);
    const entries: []const sig.core.Entry = entry_array.slice();
    errdefer for (entries) |entry| entry.deinit(allocator);

    const future = try confirmSlot(
        std.testing.allocator,
        .noop,
        undefined,
        &thread_pool,
        try allocator.dupe(Entry, entries[0 .. entries.len - 1]),
        .ZEROES,
        undefined, // TODO
        .{
            .hashes_per_tick = poh.hashes_per_tick,
            .slot = 0,
            .max_tick_height = poh.tick_count - 1,
            .tick_height = 0,
            .slot_is_full = false,
            .tick_hash_count = &tick_hash_count,
        },
    );
    defer future.destroy(std.testing.allocator);

    const result = try testAwait(future);
    errdefer std.log.err("failed with: {any}\n", .{result});
    try std.testing.expectEqual(
        ConfirmSlotStatus{ .err = .{ .invalid_block = .TrailingEntry } },
        result,
    );
}

test "fail: invalid poh chain" {
    const allocator = std.testing.allocator;

    var thread_pool = ThreadPool.init(.{});
    var tick_hash_count: u64 = 0;

    const poh, var entry_array = try sig.core.poh.testPoh(true);
    const entries: []sig.core.Entry = entry_array.slice();
    errdefer for (entries) |entry| entry.deinit(allocator);

    // break the hash chain
    entries[0].hash.data[0] +%= 1;

    const future = try confirmSlot(
        std.testing.allocator,
        .FOR_TESTS,
        undefined,
        &thread_pool,
        try allocator.dupe(Entry, entries),
        .ZEROES,
        undefined, // TODO
        .{
            .hashes_per_tick = poh.hashes_per_tick,
            .slot = 0,
            .max_tick_height = poh.tick_count,
            .tick_height = 0,
            .slot_is_full = true,
            .tick_hash_count = &tick_hash_count,
        },
    );
    defer future.destroy(std.testing.allocator);

    const result = try testAwait(future);
    errdefer std.log.err("failed with: {any}\n", .{result});
    try std.testing.expectEqual(
        ConfirmSlotStatus{ .err = .{ .invalid_block = .InvalidEntryHash } },
        result,
    );
}

test "fail: sigverify" {
    const allocator = std.testing.allocator;

    var thread_pool = ThreadPool.init(.{});
    var tick_hash_count: u64 = 0;

    const poh, var entry_array = try sig.core.poh.testPoh(false);
    const entries: []sig.core.Entry = entry_array.slice();
    errdefer for (entries) |entry| entry.deinit(allocator);

    const future = try confirmSlot(
        std.testing.allocator,
        .FOR_TESTS,
        undefined,
        &thread_pool,
        try allocator.dupe(Entry, entries),
        .ZEROES,
        undefined, // TODO
        .{
            .hashes_per_tick = poh.hashes_per_tick,
            .slot = 0,
            .max_tick_height = poh.tick_count,
            .tick_height = 0,
            .slot_is_full = true,
            .tick_hash_count = &tick_hash_count,
        },
    );
    defer future.destroy(std.testing.allocator);

    const result = try testAwait(future);
    errdefer std.log.err("failed with: {any}\n", .{result});
    try std.testing.expectEqual(
        ConfirmSlotStatus{ .err = .{ .invalid_transaction = .SignatureFailure } },
        result,
    );
}

pub fn testAwait(future: anytype) !@TypeOf(future.poll()) {
    var i: usize = 0;
    while (try future.poll() == .pending) {
        std.time.sleep(std.time.ns_per_ms);
        i += 1;
        if (i > 100) return error.TooSlow;
    }
    return try future.poll();
}
