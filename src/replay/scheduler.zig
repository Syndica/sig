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
    /// The number of batches that have been scheduled with thread_pool.trySchedule.
    batches_scheduled: usize,
    /// The number of batches that a result has been received over the channel for.
    batches_finished: usize,
    /// triggered as soon as a single transaction fails
    exit: std.atomic.Value(bool),

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
            .batches_scheduled = 0,
            .batches_finished = 0,
            .exit = std.atomic.Value(bool).init(false),
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
        try self.batches.put(batch);
    }

    pub fn addBatchAssumeCapacity(self: *TransactionScheduler, batch: ResolvedBatch) void {
        self.batches.putAssumeCapacity(batch);
    }

    pub fn poll(self: *TransactionScheduler) !ConfirmSlotStatus {
        const batches_len = self.batches.len();
        assert(self.batches_scheduled <= batches_len);
        assert(self.batches_finished <= batches_len);

        if (self.batches_finished == batches_len) {
            return switch (self.thread_pool.pollFallible()) {
                .done => .done,
                .pending => .pending,
                .err => |err| return err,
            };
        }
        if (self.batches_scheduled < batches_len) {
            if (try self.tryScheduleSome()) |err| {
                self.exit.store(true, .monotonic);
                return .{ .err = .{ .invalid_transaction = err } };
            }
        }
        if (self.results.tryReceive()) |maybe_err| {
            self.batches_finished += 1;
            if (maybe_err) |err| {
                self.exit.store(true, .monotonic);
                return .{ .err = .{ .invalid_transaction = err } };
            }
        }

        return .pending;
    }

    fn tryScheduleSome(self: *TransactionScheduler) !?TransactionError {
        while (self.batches.peek()) |peeked_batch| {
            self.locks.lockStrict(self.allocator, peeked_batch.accounts) catch |e| {
                switch (e) {
                    error.LockFailed => if (self.batches_scheduled - self.batches_finished == 0) {
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
                .results = self.results,
                .exit = &self.exit,
            }));
            self.batches_scheduled += 1;
        }
        return null;
    }
};

const ProcessBatchTask = struct {
    transactions: []const ResolvedTransaction,
    results: Channel(?TransactionError),
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

        pub fn put(
            self: *ResizeableRingBuffer(T),
            allocator: Allocator,
            item: T,
        ) Allocator.Error!void {
            if (self.head == self.tail + self.buffer.len) {
                self.ensureTotalCapacity(allocator);
            }
            self.putAssumeCapacity(item);
        }

        pub fn putAssumeCapacity(self: *ResizeableRingBuffer(T), item: T) void {
            assert(self.head < self.tail + self.buffer.len);
            assert(self.head >= self.tail);
            self.buffer[self.head] = item;
            self.head += 1;
        }

        pub fn pop(self: *ResizeableRingBuffer(T)) ?T {
            self.assertSane();
            if (self.head == self.tail) {
                return null;
            }
            defer self.tail += 1;
            return self.buffer[self.tail % self.buffer.len];
        }

        /// Pointer is invalidated when `put` is called.
        pub fn peek(self: *ResizeableRingBuffer(T)) ?*const T {
            self.assertSane();
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
            const old_len = self.buffer.len;
            if (capacity < old_len) return;
            const new_len = @max(std.math.ceilPowerOfTwo(usize, capacity), @max(8, old_len * 2));
            try allocator.realloc(T, new_len);
            self.head = self.head % old_len;
            self.tail = self.tail % old_len;
        }

        fn assertSane(self: ResizeableRingBuffer(T)) void {
            assert(self.head < self.tail + self.buffer.len + 1);
            assert(self.head >= self.tail);
        }
    };
}
