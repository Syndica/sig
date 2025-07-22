const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const Allocator = std.mem.Allocator;

const Channel = sig.sync.Channel;
const HomogeneousThreadPool = sig.utils.thread.HomogeneousThreadPool;
const ThreadPool = sig.sync.ThreadPool;

const Hash = sig.core.Hash;

const TransactionError = sig.ledger.transaction_status.TransactionError;

const AccountLocks = replay.account_locks.AccountLocks;
const Committer = replay.commit.Committer;
const ConfirmSlotStatus = replay.confirm_slot.ConfirmSlotStatus;
const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;
const ResolvedBatch = replay.resolve_lookup.ResolvedBatch;
const SvmSlot = replay.svm_gateway.SvmSlot;

const ProcessedTransaction = sig.runtime.transaction_execution.ProcessedTransaction;

const executeTransaction = replay.svm_gateway.executeTransaction;

const ScopedLogger = sig.trace.ScopedLogger("replay-batcher");

const assert = std.debug.assert;

/// Processes a batch of transactions by verifying their signatures and
/// executing them with the SVM.
pub fn processBatch(
    allocator: Allocator,
    svm_params: SvmSlot.Params,
    committer: Committer,
    transactions: []const ResolvedTransaction,
    exit: *std.atomic.Value(bool),
) !?TransactionError {
    const results = try allocator.alloc(struct { Hash, ProcessedTransaction }, transactions.len);
    defer allocator.free(results);

    var svm_slot = try SvmSlot.init(allocator, transactions, svm_params);
    defer svm_slot.deinit(allocator);

    for (transactions, 0..) |transaction, i| {
        if (exit.load(.monotonic)) {
            return null;
        }
        const hash = transaction.transaction.verifyAndHashMessage() catch return .SignatureFailure;
        const runtime_transaction = transaction.toRuntimeTransaction(hash);

        switch (try executeTransaction(allocator, &svm_slot, &runtime_transaction)) {
            .ok => |result| results[i] = .{ hash, result },
            .err => |err| return err,
        }
    }
    try committer.commitTransactions(allocator, svm_slot.params.slot, transactions, results);

    return null;
}

/// Batches transactions and executes them on a thread pool.
///
/// Only intended for execution of transactions from a single slot.
///
/// Internally, transaction results are communicated on a channel instead of
/// collecting the return values through HomogeneousThreadPool to allow faster
/// identification of failed transactions when batches are completed out of
/// order.
///
/// Transaction errors are not returned by the task. If a task returns an error,
/// that indicates fatal/unexpected errors like OOM, and the error will
/// propagate up when polling.
///
/// This should only be used in a single thread at a time.
pub const TransactionScheduler = struct {
    allocator: Allocator,
    committer: Committer,
    batches: std.ArrayListUnmanaged(ResolvedBatch),
    thread_pool: HomogeneousThreadPool(ProcessBatchTask),
    results: Channel(BatchResult),
    locks: AccountLocks,
    /// The number of batches that have been scheduled with thread_pool.trySchedule.
    batches_started: usize,
    /// The number of batches that a result has been received over the channel for.
    batches_finished: usize,
    /// triggered as soon as a single transaction fails
    exit: std.atomic.Value(bool),
    /// if non-null, a failure was already recorded and will be returned for every poll
    failure: ?replay.confirm_slot.ConfirmSlotError,
    svm_params: SvmSlot.Params,

    const BatchResult = struct { batch_index: usize, maybe_err: ?TransactionError };

    pub fn initCapacity(
        allocator: Allocator,
        committer: Committer,
        batch_capacity: usize,
        thread_pool: *ThreadPool,
        svm_params: SvmSlot.Params,
    ) !TransactionScheduler {
        var batches = try std.ArrayListUnmanaged(ResolvedBatch)
            .initCapacity(allocator, batch_capacity);
        errdefer batches.deinit(allocator);

        const pool = try HomogeneousThreadPool(ProcessBatchTask)
            .initBorrowed(allocator, thread_pool, null);
        errdefer pool.deinit(allocator);

        var channel = try Channel(BatchResult).init(allocator);
        errdefer channel.deinit();

        return .{
            .allocator = allocator,
            .committer = committer,
            .batches = batches,
            .thread_pool = pool,
            .results = channel,
            .locks = .{},
            .batches_started = 0,
            .batches_finished = 0,
            .exit = std.atomic.Value(bool).init(false),
            .failure = null,
            .svm_params = svm_params,
        };
    }

    pub fn deinit(self: TransactionScheduler) void {
        var batches = self.batches;
        for (batches.items) |batch| batch.deinit(self.allocator);
        batches.deinit(self.allocator);

        var channel = self.results;
        channel.deinit();

        self.thread_pool.deinit(self.allocator);
        self.locks.deinit(self.allocator);
    }

    pub fn addBatch(self: *TransactionScheduler, batch: ResolvedBatch) Allocator.Error!void {
        try self.batches.append(self.allocator, batch);
    }

    pub fn addBatchAssumeCapacity(self: *TransactionScheduler, batch: ResolvedBatch) void {
        self.batches.appendAssumeCapacity(batch);
    }

    pub fn poll(self: *TransactionScheduler) !ConfirmSlotStatus {
        // collect results
        while (self.results.tryReceive()) |result| {
            assert(0 == self.locks.unlock(self.batches.items[result.batch_index].accounts));
            self.batches_finished += 1;
            if (result.maybe_err) |err| {
                self.exit.store(true, .monotonic);
                self.failure = .{ .invalid_transaction = err };
            }
        }

        // process results
        switch (self.thread_pool.pollFallible()) {
            .done => {
                assert(self.batches_started == self.batches_finished);
                if (self.failure) |f| {
                    return .{ .err = f };
                } else if (self.batches.items.len != self.batches_started) {
                    if (try self.tryScheduleSome()) |err| {
                        self.exit.store(true, .monotonic);
                        self.failure = .{ .invalid_transaction = err };
                    }
                    return .pending;
                } else {
                    assert(self.batches.items.len == self.batches_finished);
                    return .done;
                }
            },
            .pending => return .pending,
            .err => |err| return err,
        }
    }

    fn tryScheduleSome(self: *TransactionScheduler) !?TransactionError {
        while (self.batches.items.len > self.batches_started) {
            const batch = self.batches.items[self.batches_started];
            self.locks.lockStrict(self.allocator, batch.accounts) catch |e| switch (e) {
                error.LockFailed => if (self.batches_started == self.batches_finished) {
                    return .AccountInUse;
                } else {
                    break;
                },
                else => return e,
            };
            // trySchedule will always return true, meaning the task was
            // scheduled successfully, because the thread pool does not have a
            // maximum number of tasks. See the `null` value passed into
            // HomogeneousThreadPool.initBorrowed
            assert(try self.thread_pool.trySchedule(self.allocator, .{
                .allocator = self.allocator,
                .committer = self.committer,
                .svm_slot = self.svm_params,
                .batch_index = self.batches_started,
                .transactions = batch.transactions,
                .results = &self.results,
                .exit = &self.exit,
            }));
            self.batches_started += 1;
        }
        return null;
    }
};

const ProcessBatchTask = struct {
    allocator: Allocator,
    svm_slot: SvmSlot.Params,
    committer: Committer,
    batch_index: usize,
    transactions: []const ResolvedTransaction,
    results: *Channel(TransactionScheduler.BatchResult),
    exit: *std.atomic.Value(bool),

    pub fn run(self: *ProcessBatchTask) !void {
        const result = try processBatch(
            self.allocator,
            self.svm_slot,
            self.committer,
            self.transactions,
            self.exit,
        );

        if (result != null) self.exit.store(true, .monotonic);
        try self.results.send(.{ .batch_index = self.batch_index, .maybe_err = result });
    }
};

test "TransactionScheduler: happy path" {
    const allocator = std.testing.allocator;
    const Transaction = sig.core.Transaction;
    const resolveBatch = replay.resolve_lookup.resolveBatch;

    var rng = std.Random.DefaultPrng.init(123);

    var thread_pool = ThreadPool.init(.{});
    defer {
        thread_pool.shutdown();
        thread_pool.deinit();
    }

    // TODO fix undefined
    var scheduler = try TransactionScheduler
        .initCapacity(allocator, undefined, 10, &thread_pool, undefined);
    defer scheduler.deinit();

    var tx_arena = std.heap.ArenaAllocator.init(allocator);
    defer tx_arena.deinit();
    const transactions = [_]Transaction{
        try .initRandom(tx_arena.allocator(), rng.random()),
        try .initRandom(tx_arena.allocator(), rng.random()),
        try .initRandom(tx_arena.allocator(), rng.random()),
        try .initRandom(tx_arena.allocator(), rng.random()),
        try .initRandom(tx_arena.allocator(), rng.random()),
        try .initRandom(tx_arena.allocator(), rng.random()),
    };

    {
        const batch1 = try resolveBatch(
            allocator,
            .noop,
            transactions[0..3],
            &.{ .ancestors = .empty },
        );
        errdefer batch1.deinit(allocator);

        const batch1_dupe = try resolveBatch(
            allocator,
            .noop,
            transactions[0..3],
            &.{ .ancestors = .empty },
        );
        errdefer batch1_dupe.deinit(allocator);

        const batch2 = try resolveBatch(
            allocator,
            .noop,
            transactions[3..6],
            &.{ .ancestors = .empty },
        );
        errdefer batch2.deinit(allocator);

        scheduler.addBatchAssumeCapacity(batch1);
        scheduler.addBatchAssumeCapacity(batch2);

        // should be no failures on account collision with the first time this batch was scheduled.
        // scheduler should just know to run it separately
        scheduler.addBatchAssumeCapacity(batch1_dupe);
    }

    try std.testing.expectEqual(.done, try replay.confirm_slot.testAwait(&scheduler));
}

test "TransactionScheduler: failed account locks" {
    const allocator = std.testing.allocator;
    const Transaction = sig.core.Transaction;
    const resolveBatch = replay.resolve_lookup.resolveBatch;

    var rng = std.Random.DefaultPrng.init(0);

    var thread_pool = ThreadPool.init(.{});
    defer {
        thread_pool.shutdown();
        thread_pool.deinit();
    }

    // TODO fix undefined
    var scheduler = try TransactionScheduler
        .initCapacity(allocator, undefined, 10, &thread_pool, undefined);
    defer scheduler.deinit();

    const tx = try Transaction.initRandom(allocator, rng.random());
    defer tx.deinit(allocator);

    const unresolved_batch = [_]Transaction{ tx, tx };

    {
        const batch1 = try resolveBatch(
            allocator,
            .noop,
            &unresolved_batch,
            &.{ .ancestors = .empty },
        );
        errdefer batch1.deinit(allocator);

        scheduler.addBatchAssumeCapacity(batch1);
    }

    try std.testing.expectEqual(
        ConfirmSlotStatus{ .err = .{ .invalid_transaction = .AccountInUse } },
        try replay.confirm_slot.testAwait(&scheduler),
    );
}

test "TransactionScheduler: signature verification failure" {
    const allocator = std.testing.allocator;
    const Transaction = sig.core.Transaction;
    const resolveBatch = replay.resolve_lookup.resolveBatch;

    var rng = std.Random.DefaultPrng.init(0);

    var thread_pool = ThreadPool.init(.{});
    defer {
        thread_pool.shutdown();
        thread_pool.deinit();
    }

    // TODO fix undefined
    var scheduler = try TransactionScheduler
        .initCapacity(allocator, undefined, 10, &thread_pool, undefined);
    defer scheduler.deinit();

    var tx_arena = std.heap.ArenaAllocator.init(allocator);
    defer tx_arena.deinit();
    var transactions = [_]Transaction{
        try .initRandom(tx_arena.allocator(), rng.random()),
        try .initRandom(tx_arena.allocator(), rng.random()),
        try .initRandom(tx_arena.allocator(), rng.random()),
        try .initRandom(tx_arena.allocator(), rng.random()),
        try .initRandom(tx_arena.allocator(), rng.random()),
        try .initRandom(tx_arena.allocator(), rng.random()),
    };

    const replaced_sigs = try tx_arena.allocator()
        .dupe(sig.core.Signature, transactions[5].signatures);
    replaced_sigs[0].data[0] +%= 1;
    transactions[5].signatures = replaced_sigs;

    {
        const batch1 = try resolveBatch(
            allocator,
            .noop,
            transactions[0..3],
            &.{ .ancestors = .empty },
        );
        errdefer batch1.deinit(allocator);

        const batch2 = try resolveBatch(
            allocator,
            .noop,
            transactions[3..6],
            &.{ .ancestors = .empty },
        );
        errdefer batch2.deinit(allocator);

        scheduler.addBatchAssumeCapacity(batch1);
        scheduler.addBatchAssumeCapacity(batch2);
    }

    try std.testing.expectEqual(
        ConfirmSlotStatus{ .err = .{ .invalid_transaction = .SignatureFailure } },
        try replay.confirm_slot.testAwait(&scheduler),
    );
}
