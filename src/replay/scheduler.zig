const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const Allocator = std.mem.Allocator;

const Channel = sig.sync.Channel;
const HomogeneousThreadPool = sig.utils.thread.HomogeneousThreadPool;
const ThreadPool = sig.sync.ThreadPool;

const TransactionError = sig.ledger.transaction_status.TransactionError;

const AccountLocks = replay.account_locks.AccountLocks;
const ConfirmSlotStatus = replay.confirm_slot.ConfirmSlotStatus;
const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;
const ResolvedBatch = replay.resolve_lookup.ResolvedBatch;

const ScopedLogger = sig.trace.ScopedLogger("replay-batcher");

const assert = std.debug.assert;

/// Batches transactions and executes them on a thread pool.
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
    batches: ResizeableRingBuffer(ResolvedBatch),
    thread_pool: HomogeneousThreadPool(ProcessBatchTask),
    results: Channel(?TransactionError),
    locks: AccountLocks,
    /// The number of batches that have been planned for execution.
    batches_added: usize,
    /// The number of batches that have been scheduled with thread_pool.trySchedule.
    batches_started: usize,
    /// The number of batches that a result has been received over the channel for.
    batches_finished: usize,
    /// triggered as soon as a single transaction fails
    exit: std.atomic.Value(bool),
    /// if non-null, a failure was already recorded and will be returned for every poll
    failure: ?replay.confirm_slot.ConfirmSlotError,

    pub fn initCapacity(
        allocator: Allocator,
        batch_capacity: usize,
        thread_pool: *ThreadPool,
    ) !TransactionScheduler {
        return .{
            .allocator = allocator,
            .batches = try ResizeableRingBuffer(ResolvedBatch)
                .initCapacity(allocator, batch_capacity),
            .thread_pool = try HomogeneousThreadPool(ProcessBatchTask)
                .initBorrowed(allocator, thread_pool, null),
            .results = try Channel(?TransactionError).init(allocator),
            .locks = .{},
            .batches_added = 0,
            .batches_started = 0,
            .batches_finished = 0,
            .exit = std.atomic.Value(bool).init(false),
            .failure = null,
        };
    }

    pub fn deinit(self: TransactionScheduler) void {
        self.batches.deinit(self.allocator);
        self.thread_pool.deinit(self.allocator);
        var channel = self.results;
        channel.deinit();
        self.locks.deinit(self.allocator);
    }

    pub fn addBatch(self: *TransactionScheduler, batch: ResolvedBatch) Allocator.Error!void {
        self.batches_added += 1;
        try self.batches.push(batch);
    }

    pub fn addBatchAssumeCapacity(self: *TransactionScheduler, batch: ResolvedBatch) void {
        self.batches_added += 1;
        self.batches.pushAssumeCapacity(batch);
    }

    pub fn poll(self: *TransactionScheduler) !ConfirmSlotStatus {
        // collect results
        while (self.results.tryReceive()) |maybe_err| {
            self.batches_finished += 1;
            if (maybe_err) |err| {
                self.exit.store(true, .monotonic);
                self.failure = .{ .invalid_transaction = err };
            }
        }

        // process results
        switch (self.thread_pool.pollFallible()) {
            .done => {
                assert(self.batches_started == self.batches_finished);
                if (self.failure == null and self.batches.len() != 0) {
                    if (try self.tryScheduleSome()) |err| {
                        self.exit.store(true, .monotonic);
                        self.failure = .{ .invalid_transaction = err };
                    }
                    return .pending;
                } else if (self.failure) |f| {
                    return .{ .err = f };
                } else {
                    assert(self.batches_added == self.batches_finished);
                    return .done;
                }
            },
            .pending => return .pending,
            .err => |err| return err,
        }
    }

    fn tryScheduleSome(self: *TransactionScheduler) !?TransactionError {
        while (self.batches.peek()) |peeked_batch| {
            self.locks.lockStrict(self.allocator, peeked_batch.accounts) catch |e| {
                switch (e) {
                    error.LockFailed => if (self.batches_started == self.batches_finished) {
                        return .AccountInUse;
                    } else {
                        break;
                    },
                    else => return e,
                }
            };
            const batch = self.batches.pop().?;
            assert(try self.thread_pool.trySchedule(self.allocator, .{
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
    transactions: []const ResolvedTransaction,
    results: *Channel(?TransactionError),
    exit: *std.atomic.Value(bool),

    pub fn run(self: *ProcessBatchTask) !void {
        const result = processBatch(self.transactions, self.exit);
        if (result != null) self.exit.store(true, .monotonic);
        try self.results.send(result);
    }
};

pub fn processBatch(
    transactions: []const ResolvedTransaction,
    exit: *std.atomic.Value(bool),
) ?TransactionError {
    for (transactions) |transaction| {
        if (exit.load(.monotonic)) {
            return null;
        }
        const hash = transaction.transaction.verifyAndHashMessage() catch
            return .SignatureFailure;
        _ = hash; // autofix
        // TODO: call svm
    }
    // TODO: commit results

    return null;
}

/// Ring buffer that grows when it's full.
///
/// Not thread safe.
fn ResizeableRingBuffer(T: type) type {
    return struct {
        buffer: []T = &.{},
        head: usize = 0,
        tail: usize = 0,

        pub fn initCapacity(
            allocator: Allocator,
            capacity: usize,
        ) Allocator.Error!ResizeableRingBuffer(T) {
            return .{ .buffer = try allocator.alloc(T, capacity) };
        }

        pub fn deinit(self: ResizeableRingBuffer(T), allocator: Allocator) void {
            allocator.free(self.buffer);
        }

        pub fn push(
            self: *ResizeableRingBuffer(T),
            allocator: Allocator,
            item: T,
        ) Allocator.Error!void {
            if (self.head == self.tail + self.buffer.len) {
                try self.ensureTotalCapacity(allocator, @max(8, self.buffer.len * 2));
            }
            self.pushAssumeCapacity(item);
        }

        pub fn pushAssumeCapacity(self: *ResizeableRingBuffer(T), item: T) void {
            self.assertSane(1);
            self.buffer[self.head % self.buffer.len] = item;
            self.head += 1;
        }

        pub fn pop(self: *ResizeableRingBuffer(T)) ?T {
            self.assertSane(0);
            if (self.head == self.tail) {
                return null;
            }
            defer self.tail += 1;
            return self.buffer[self.tail % self.buffer.len];
        }

        /// Pointer is invalidated when `put` is called.
        pub fn peek(self: *ResizeableRingBuffer(T)) ?*const T {
            self.assertSane(0);
            if (self.head == self.tail) {
                return null;
            }
            return &self.buffer[self.tail % self.buffer.len];
        }

        pub fn len(self: *const ResizeableRingBuffer(T)) usize {
            return self.head - self.tail;
        }

        pub fn ensureTotalCapacity(
            self: *ResizeableRingBuffer(T),
            allocator: Allocator,
            capacity: usize,
        ) Allocator.Error!void {
            self.assertSane(0);
            const old_len = self.buffer.len;
            if (capacity < old_len) return;

            const new_len = std.math.ceilPowerOfTwo(
                usize,
                @max(capacity, @max(8, old_len * 2)),
            ) catch return error.OutOfMemory;

            self.buffer = try allocator.realloc(self.buffer, new_len);

            if (old_len != 0) {
                const old_head_index = self.head % old_len;
                @memcpy(
                    self.buffer[old_len..][0..old_head_index],
                    self.buffer[0..old_head_index],
                );
                const num_items = self.head - self.tail;
                self.tail = self.tail % old_len;
                self.head = self.tail + num_items;
            }
        }

        fn assertSane(self: ResizeableRingBuffer(T), min_free_space: usize) void {
            assert(self.head - self.tail <= self.buffer.len - min_free_space);
            assert(self.head >= self.tail);
        }
    };
}

test "TransactionScheduler: happy path" {
    const allocator = std.testing.allocator;
    const Transaction = sig.core.Transaction;
    var rng = std.Random.DefaultPrng.init(123);

    var thread_pool = ThreadPool.init(.{});
    var scheduler = try TransactionScheduler.initCapacity(allocator, 10, &thread_pool);
    defer scheduler.deinit();

    const transactions = [_]Transaction{
        try Transaction.initRandom(allocator, rng.random()),
        try Transaction.initRandom(allocator, rng.random()),
        try Transaction.initRandom(allocator, rng.random()),
        try Transaction.initRandom(allocator, rng.random()),
        try Transaction.initRandom(allocator, rng.random()),
        try Transaction.initRandom(allocator, rng.random()),
    };
    defer for (transactions) |tx| {
        allocator.free(tx.signatures);
        allocator.free(tx.msg.account_keys);
    };

    const batch1 = try replay.resolve_lookup
        .resolveBatch(allocator, undefined, transactions[0..3]);
    defer batch1.deinit(allocator);

    const batch2 = try replay.resolve_lookup
        .resolveBatch(allocator, undefined, transactions[3..6]);
    defer batch2.deinit(allocator);

    scheduler.addBatchAssumeCapacity(batch1);
    scheduler.addBatchAssumeCapacity(batch2);

    // should be no failures on account collision with the first time this batch was scheduled
    // scheduler.addBatchAssumeCapacity(batch1);

    var i: usize = 0;
    while (try scheduler.poll() == .pending) {
        std.time.sleep(std.time.ns_per_ms);
        i += 1;
        if (i > 1000) return error.TooSlow;
    }
    try std.testing.expectEqual(.done, try scheduler.poll());
}

test "TransactionScheduler: failed account locks" {
    const allocator = std.testing.allocator;
    const Transaction = sig.core.Transaction;
    var rng = std.Random.DefaultPrng.init(0);

    var thread_pool = ThreadPool.init(.{});
    var scheduler = try TransactionScheduler.initCapacity(allocator, 10, &thread_pool);
    defer scheduler.deinit();

    const tx = try Transaction.initRandom(allocator, rng.random());
    defer {
        allocator.free(tx.signatures);
        allocator.free(tx.msg.account_keys);
    }
    const unresolved_batch = .{ tx, tx };

    const batch1 = try replay.resolve_lookup
        .resolveBatch(allocator, undefined, &unresolved_batch);
    defer batch1.deinit(allocator);

    scheduler.addBatchAssumeCapacity(batch1);

    var i: usize = 0;
    while (try scheduler.poll() == .pending) {
        std.time.sleep(std.time.ns_per_ms);
        i += 1;
        if (i > 1000) return error.TooSlow;
    }
    try std.testing.expectEqual(
        ConfirmSlotStatus{ .err = .{ .invalid_transaction = .AccountInUse } },
        try scheduler.poll(),
    );
}

test "TransactionScheduler: signature verification failure" {
    const allocator = std.testing.allocator;
    const Transaction = sig.core.Transaction;
    var rng = std.Random.DefaultPrng.init(0);

    var thread_pool = ThreadPool.init(.{});
    var scheduler = try TransactionScheduler.initCapacity(allocator, 10, &thread_pool);
    defer scheduler.deinit();

    var transactions = [_]Transaction{
        try Transaction.initRandom(allocator, rng.random()),
        try Transaction.initRandom(allocator, rng.random()),
        try Transaction.initRandom(allocator, rng.random()),
        try Transaction.initRandom(allocator, rng.random()),
        try Transaction.initRandom(allocator, rng.random()),
        try Transaction.initRandom(allocator, rng.random()),
    };
    defer for (transactions) |tx| {
        allocator.free(tx.signatures);
        allocator.free(tx.msg.account_keys);
    };
    const replaced_sigs = try allocator.dupe(sig.core.Signature, transactions[5].signatures);
    replaced_sigs[0].data[0] +%= 1;
    allocator.free(transactions[5].signatures);
    transactions[5].signatures = replaced_sigs;

    const batch1 = try replay.resolve_lookup
        .resolveBatch(allocator, undefined, transactions[0..3]);
    defer batch1.deinit(allocator);

    const batch2 = try replay.resolve_lookup
        .resolveBatch(allocator, undefined, transactions[3..6]);
    defer batch2.deinit(allocator);

    scheduler.addBatchAssumeCapacity(batch1);
    scheduler.addBatchAssumeCapacity(batch2);

    while (try scheduler.poll() == .pending) std.time.sleep(std.time.ns_per_ms);
    try std.testing.expectEqual(
        ConfirmSlotStatus{ .err = .{ .invalid_transaction = .SignatureFailure } },
        try scheduler.poll(),
    );
}

test ResizeableRingBuffer {
    const allocator = std.testing.allocator;
    const expectEqual = std.testing.expectEqual;

    var buffer = try ResizeableRingBuffer(usize).initCapacity(allocator, 0);
    defer buffer.deinit(allocator);

    try expectEqual(null, buffer.pop());
    try expectEqual(null, buffer.peek());

    try buffer.push(allocator, 1);
    try expectEqual(1, buffer.pop());
    try expectEqual(null, buffer.pop());
    try expectEqual(null, buffer.peek());

    try buffer.push(allocator, 2);
    try buffer.push(allocator, 3);
    try buffer.push(allocator, 4);

    try expectEqual(2, buffer.pop());
    try expectEqual(3, buffer.peek().?.*);
    try expectEqual(3, buffer.pop());
    try expectEqual(4, buffer.pop());
    try expectEqual(null, buffer.pop());
    try expectEqual(null, buffer.peek());

    for (5..300) |i| {
        try buffer.push(allocator, i);
    }
    for (5..123) |i| {
        try expectEqual(i, buffer.peek().?.*);
        try expectEqual(i, buffer.pop());
    }
    for (300..600) |i| {
        try buffer.push(allocator, i);
    }
    for (123..600) |i| {
        try expectEqual(i, buffer.peek().?.*);
        try expectEqual(i, buffer.pop());
    }
    try expectEqual(null, buffer.pop());
    try expectEqual(null, buffer.peek());
}
