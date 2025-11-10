const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const core = sig.core;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const ThreadPool = sig.sync.ThreadPool;

const Pubkey = core.Pubkey;
const Entry = core.Entry;
const Hash = core.Hash;

const Committer = replay.Committer;
const ReplayResult = replay.execution.ReplayResult;
const ReplaySlotError = replay.execution.ReplaySlotError;
const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;
const SlotResolver = replay.resolve_lookup.SlotResolver;
const SvmGateway = replay.svm_gateway.SvmGateway;

const assert = std.debug.assert;

const verifyTicks = replay.execution.verifyTicks;
const verifyPoh = core.entry.verifyPoh;
const resolveTransaction = replay.resolve_lookup.resolveTransaction;
const replayBatch = replay.execution.replayBatch;

const Logger = sig.trace.Logger("replay-async2");

/// Tracks the state of a slot confirmation execution.
///
/// agave: confirm_slot and confirm_slot_entries
/// fd: runtime_process_txns_in_microblock_stream
pub const ReplaySlotFuture = struct {
    // Shared state for workers.
    allocator: Allocator,
    logger: Logger,
    entries: []const Entry,

    // Worker schedulers.
    poh_verifier: PohVerifier,
    txn_scheduler: TransactionScheduler,

    // Completion state.
    slot: sig.core.Slot,
    result_ptr: Atomic(?*Result),

    // Threading state.
    exit: Atomic(bool),
    pending: Atomic(usize),
    wait_group: *std.Thread.WaitGroup,
    thread_pool: *ThreadPool,

    pub const Result = Error!ReplayResult;
    pub const Error =
        PohVerifier.Error ||
        TransactionScheduler.Error;

    pub fn startAsync(
        allocator: Allocator,
        logger: Logger,
        thread_pool: *ThreadPool,
        wait_group: *std.Thread.WaitGroup,
        params: replay.execution.ReplaySlotParams,
        result_ptr: *Result,
    ) void {
        if (verifyTicks(.from(logger), params.entries, params.verify_ticks_params)) |block_err| {
            finishSync(allocator, params, result_ptr, .{ .err = .{ .invalid_block = block_err } });
            return;
        }

        // TODO: what is the correct thing to do here?
        if (params.entries.len == 0) {
            finishSync(allocator, params, result_ptr, .{ .last_entry_hash = params.last_entry });
            return;
        }

        const self = allocator.create(ReplaySlotFuture) catch {
            finishSync(allocator, params, result_ptr, error.OutOfMemory);
            return;
        };

        self.* = .{
            .allocator = allocator,
            .logger = logger,
            .entries = params.entries,
            .poh_verifier = .{ .future = self },
            .txn_scheduler = .{
                .future = self,
                .svm_params = params.svm_params,
                .committer = params.committer,
            },
            .slot = params.svm_params.slot,
            .result_ptr = .init(result_ptr),
            .exit = .init(false),
            .pending = .init(1), // start with 1 for this scope's self.finish()
            .wait_group = wait_group,
            .thread_pool = thread_pool,
        };

        wait_group.start();
        defer self.finish(); // if no tasks scheduled, this immediately completes the Future.

        // Start poh verifier.
        self.poh_verifier.start(params.last_entry) catch |e| {
            self.setError(e);
            return;
        };

        // Start transaction scheduler.
        self.txn_scheduler.start(params.slot_resolver) catch |e| {
            self.setError(e);
            return;
        };
    }

    fn finishSync(
        allocator: Allocator,
        params: replay.execution.ReplaySlotParams,
        result_ptr: *Result,
        err_or_output: Error!ReplayResult.Output,
    ) void {
        result_ptr.* = if (err_or_output) |output|
            .{ .slot = params.svm_params.slot, .output = output }
        else |err|
            err;

        for (params.entries) |entry| entry.deinit(allocator);
        allocator.free(params.entries);
    }

    fn schedule(self: *ReplaySlotFuture, task_batch: ThreadPool.Batch) void {
        if (task_batch.len > 0) {
            _ = self.pending.fetchAdd(task_batch.len, .monotonic);
            self.thread_pool.schedule(task_batch);
        }
    }

    fn setError(self: *ReplaySlotFuture, err_or_sloterr: Error!ReplaySlotError) void {
        self.exit.store(true, .monotonic);

        if (self.result_ptr.swap(null, .release)) |result_ptr| {
            result_ptr.* = if (err_or_sloterr) |slot_err|
                .{ .slot = self.slot, .output = .{ .err = slot_err } }
            else |err|
                err;
        }
    }

    fn finish(self: *ReplaySlotFuture) void {
        if (self.pending.fetchSub(1, .acq_rel) - 1 == 0) {
            @branchHint(.unlikely);

            // Read the wait gruop out of self, as self will be freed at the end.
            const wg = self.wait_group;
            defer wg.finish();

            if (self.result_ptr.load(.acquire)) |result_ptr| {
                result_ptr.* = .{
                    .slot = self.slot,
                    .output = .{ .last_entry_hash = self.entries[self.entries.len - 1].hash },
                };
            } else assert(self.exit.load(.monotonic)); // a setError() occured & consumed the result

            for (self.entries) |entry| entry.deinit(self.allocator);
            self.allocator.free(self.entries);

            self.txn_scheduler.deinit();
            self.poh_verifier.deinit();
            self.allocator.destroy(self);
        }
    }
};

const PohVerifier = struct {
    future: *ReplaySlotFuture,
    workers: std.ArrayListUnmanaged(Worker) = .{},

    const Error = Allocator.Error;

    fn deinit(const_self: PohVerifier) void {
        var self = const_self;
        const allocator = self.future.allocator;

        self.workers.deinit(allocator);
    }

    fn start(self: *PohVerifier, last_entry: Hash) !void {
        const future = self.future;
        const entries = future.entries;

        var task_batch = ThreadPool.Batch{};
        defer future.schedule(task_batch);

        const num_workers = @min(future.thread_pool.max_threads, entries.len);
        try self.workers.ensureTotalCapacity(future.allocator, num_workers);
        const entries_per_worker = entries.len / num_workers;

        var batch_initial_hash = last_entry;
        for (0..num_workers) |i| {
            const end = if (i == num_workers - 1) entries.len else (i + 1) * entries_per_worker;
            defer batch_initial_hash = entries[end - 1].hash;

            const worker = self.workers.addOneAssumeCapacity();
            worker.* = .{
                .future = self.future,
                .entries = entries[i * entries_per_worker .. end],
                .initial_hash = batch_initial_hash,
            };
            task_batch.push(.from(&worker.task));
        }
    }

    const Worker = struct {
        task: ThreadPool.Task = .{ .callback = run },
        future: *ReplaySlotFuture,
        entries: []const Entry,
        initial_hash: Hash,

        fn run(task: *ThreadPool.Task) void {
            const zone = tracy.Zone.init(@src(), .{ .name = "replayPohWorker" });
            defer zone.deinit();

            const self: *Worker = @alignCast(@fieldParentPtr("task", task));
            defer self.future.finish();

            const success = verifyPoh(
                self.entries,
                self.future.allocator,
                self.initial_hash,
                .{ .exit = &self.future.exit },
            ) catch |e| switch (e) {
                error.Exit => return,
                error.OutOfMemory => {
                    self.future.logger.err().log("poh verification failed with OutOfMemory");
                    self.future.setError(error.OutOfMemory);
                    return;
                },
            };

            if (!success) {
                self.future.logger.err().log("poh verification failed");
                self.future.setError(.{ .invalid_block = .InvalidEntryHash });
            }
        }
    };
};

const TransactionScheduler = struct {
    future: *ReplaySlotFuture,
    svm_params: SvmGateway.Params,
    committer: Committer,

    workers: std.SegmentedList(Worker, 0) = .{},
    done: Atomic(?*Worker) = .init(null),
    free: ?*Worker = null,

    next_txn: usize = 0,
    transactions: std.ArrayListUnmanaged(ResolvedTransaction) = .{},
    account_locks: std.AutoArrayHashMapUnmanaged(Pubkey, struct {
        count: u32 = 0,

        fn tryLock(self: *@This(), writable: bool) bool {
            const inc: u32 = if (writable) std.math.maxInt(u32) else 1;
            self.count = std.math.add(u32, self.count, inc) catch return false;
            return true;
        }

        fn unlock(self: *@This(), writable: bool) void {
            const dec: u32 = if (writable) std.math.maxInt(u32) else 1;
            self.count -= dec;
        }
    }) = .{},

    // zig fmt: off
    const Error =
        Allocator.Error ||
        @typeInfo(@typeInfo(@TypeOf(resolveTransaction)).@"fn".return_type.?).error_union.error_set ||
        @typeInfo(@typeInfo(@TypeOf(replayBatch)).@"fn".return_type.?).error_union.error_set;
    // zig fmt: on

    fn deinit(const_self: TransactionScheduler) void {
        var self = const_self;
        const allocator = self.future.allocator;

        self.workers.deinit(allocator);
        for (self.transactions.items) |transaction| transaction.deinit(allocator);
        self.transactions.deinit(allocator);
        self.account_locks.deinit(allocator);
    }

    fn start(self: *TransactionScheduler, slot_resolver: SlotResolver) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "replayBatchStart" });
        defer zone.deinit();

        const allocator = self.future.allocator;
        const entries = self.future.entries;

        for (entries) |entry| {
            if (entry.isTick()) continue;

            try self.transactions.ensureUnusedCapacity(allocator, entry.transactions.len);
            for (entry.transactions) |tx| {
                const transaction = try resolveTransaction(allocator, tx, slot_resolver);
                self.transactions.appendAssumeCapacity(transaction);
            }
        }

        var task_batch = ThreadPool.Batch{};
        try self.scheduleBatch(&task_batch);
        self.future.schedule(task_batch);
    }

    fn scheduleBatch(self: *TransactionScheduler, task_batch: *ThreadPool.Batch) !void {
        while (self.next_txn < self.transactions.items.len) : (self.next_txn += 1) {
            const transaction = &self.transactions.items[self.next_txn];
            const pubkeys = transaction.accounts.items(.pubkey);
            const writables = transaction.accounts.items(.is_writable);

            for (pubkeys, writables, 0..) |pubkey, writable, i| {
                const gop = try self.account_locks.getOrPut(self.future.allocator, pubkey);
                if (!gop.found_existing) gop.value_ptr.* = .{};
                if (self.future.exit.load(.monotonic)) return;

                if (!gop.value_ptr.tryLock(writable)) {
                    for (pubkeys[0..i], writables[0..i]) |pk, wr| {
                        self.account_locks.getPtr(pk).?.unlock(wr);
                    }
                    return;
                }
            }

            const worker = if (self.free) |worker| blk: {
                self.free = worker.next;
                break :blk worker;
            } else try self.workers.addOne(self.future.allocator);
            worker.* = .{
                .scheduler = self,
                .txn_index = self.next_txn,
            };
            task_batch.push(.from(&worker.task));
        }
    }

    const Worker = struct {
        task: ThreadPool.Task = .{ .callback = run },
        next: ?*Worker = null,
        scheduler: *TransactionScheduler,
        txn_index: usize,

        fn run(task: *ThreadPool.Task) void {
            const zone = tracy.Zone.init(@src(), .{ .name = "replayBatchWorker" });
            defer zone.deinit();

            const self: *Worker = @alignCast(@fieldParentPtr("task", task));
            defer self.scheduler.future.finish();

            const future = self.scheduler.future;
            const result = replayBatch(
                future.allocator,
                self.scheduler.svm_params,
                self.scheduler.committer,
                &.{self.scheduler.transactions.items[self.txn_index]},
                &future.exit,
            ) catch |err| {
                future.logger.err().logf("replayBatch failed with error: {}", .{err});
                future.setError(err);
                return;
            };

            if (result == .failure) {
                future.logger.err().logf(
                    "batch failed due to transaction error: {}",
                    .{result.failure},
                );
                future.setError(.{ .invalid_transaction = result.failure });
                return;
            }

            self.scheduler.finish(self);
        }
    };

    // BCS queue into account locking + batch scheduling:
    // https://kprotty.me/2025/09/08/batched-critical-sections.html#is-there-a-fix
    fn finish(self: *TransactionScheduler, worker: *Worker) void {
        // Push worker on done stack.
        var done = self.done.load(.monotonic);
        while (true) {
            worker.next = done;
            done = self.done.cmpxchgWeak(done, worker, .acq_rel, .monotonic) orelse break;
        }

        // first to push on empty becomes the owner of the account locks
        if (done == null) {
            const zone = tracy.Zone.init(@src(), .{ .name = "replayBatchSchedule" });
            defer zone.deinit();

            var top = worker;
            var bottom: ?*Worker = null;
            var task_batch = ThreadPool.Batch{};

            const future = self.future;
            while (true) {
                // Unlock all Worker accounts that have completed in done stack so far.
                var node = top;
                while (true) {
                    const next = node.next; // add worker to free list.
                    node.next = self.free;
                    self.free = node;

                    const transaction = &self.transactions.items[node.txn_index];
                    for (
                        transaction.accounts.items(.pubkey),
                        transaction.accounts.items(.is_writable),
                    ) |pubkey, writable| {
                        if (future.exit.load(.monotonic)) return;
                        self.account_locks.getPtr(pubkey).?.unlock(writable);
                    }

                    if (next == bottom) break;
                    node = next.?;
                }

                // Schedule any new batches waiting on account locks.
                self.scheduleBatch(&task_batch) catch |e| {
                    future.setError(e);
                    return;
                };

                // Try to mark as done stack as consumed. Retries loop if more were pushed.
                bottom = top;
                top = (self.done.cmpxchgStrong(top, null, .release, .acquire) orelse {
                    if (!future.exit.load(.monotonic)) future.schedule(task_batch);
                    break;
                }).?;
            }
        }
    }
};
