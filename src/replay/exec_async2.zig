const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const core = sig.core;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const ThreadPool = sig.sync.ThreadPool;

const Entry = core.Entry;
const Hash = core.Hash;

const AccountLocks = replay.AccountLocks;
const Committer = replay.Committer;
const ReplayResult = replay.execution.ReplayResult;
const ReplaySlotError = replay.execution.ReplaySlotError;
const ResolvedBatch = replay.resolve_lookup.ResolvedBatch;
const SlotResolver = replay.resolve_lookup.SlotResolver;
const SvmGateway = replay.svm_gateway.SvmGateway;

const assert = std.debug.assert;

const verifyTicks = replay.execution.verifyTicks;
const verifyPoh = core.entry.verifyPoh;
const resolveBatch = replay.resolve_lookup.resolveBatch;
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
        var task_batch = ThreadPool.Batch{};
        self.poh_verifier.start(&task_batch, params.last_entry) catch |e| {
            self.setError(e);
            return;
        };
        self.schedule(task_batch);

        // Start transaction scheduler.
        task_batch = ThreadPool.Batch{};
        self.txn_scheduler.start(&task_batch, params.slot_resolver) catch |e| {
            self.setError(e);
            return;
        };
        self.schedule(task_batch);
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

    fn start(self: *PohVerifier, task_batch: *ThreadPool.Batch, last_entry: Hash) Error!void {
        const future = self.future;
        const entries = future.entries;

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

    workers: std.ArrayListUnmanaged(Worker) = .{},
    locks: AccountLocks = .{},
    waiting: ?*Worker = null,
    done: Atomic(?*Worker) = .init(null),

    const Error =
        Allocator.Error ||
        @typeInfo(@typeInfo(@TypeOf(resolveBatch)).@"fn".return_type.?).error_union.error_set ||
        @typeInfo(@typeInfo(@TypeOf(replayBatch)).@"fn".return_type.?).error_union.error_set;

    fn deinit(const_self: TransactionScheduler) void {
        var self = const_self;
        const allocator = self.future.allocator;

        self.locks.deinit(allocator);
        for (self.workers.items) |worker| worker.batch.deinit(allocator);
        self.workers.deinit(allocator);
    }

    fn start(
        self: *TransactionScheduler,
        task_batch: *ThreadPool.Batch,
        slot_resolver: SlotResolver,
    ) Error!void {
        const zone = tracy.Zone.init(@src(), .{ .name = "replayBatchStart" });
        defer zone.deinit();

        const allocator = self.future.allocator;
        const entries = self.future.entries;

        try self.workers.ensureTotalCapacity(allocator, entries.len);
        for (entries) |entry| {
            if (entry.isTick()) continue;

            const worker = self.workers.addOneAssumeCapacity();
            worker.* = .{
                .scheduler = self,
                .batch = try resolveBatch(allocator, entry.transactions, slot_resolver),
            };

            self.locks.lockStrict(allocator, worker.batch.accounts) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                error.LockFailed => { // couldnt schedule immediately, add to waiting list.
                    worker.next = self.waiting;
                    self.waiting = worker;
                    continue;
                },
            };
            task_batch.push(.from(&worker.task));
        }
    }

    const Worker = struct {
        task: ThreadPool.Task = .{ .callback = run },
        next: ?*Worker = null,
        scheduler: *TransactionScheduler,
        batch: ResolvedBatch,

        fn run(task: *ThreadPool.Task) void {
            const zone = tracy.Zone.init(@src(), .{ .name = "replayBatchWorker" });
            defer zone.deinit();

            const self: *Worker = @alignCast(@fieldParentPtr("task", task));
            defer self.scheduler.finish(self);

            const future = self.scheduler.future;
            const result = replay.execution.replayBatch(
                future.allocator,
                self.scheduler.svm_params,
                self.scheduler.committer,
                self.batch.transactions,
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
            }
        }
    };

    // BCS queue into account locking + batch scheduling:
    // https://kprotty.me/2025/09/08/batched-critical-sections.html#is-there-a-fix
    fn finish(self: *TransactionScheduler, worker: *Worker) void {
        const future = self.future;
        defer future.finish();

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
            defer future.schedule(task_batch);

            while (true) {
                // Unlock all Worker accounts that have completed in done stack so far.
                var node = top;
                while (true) {
                    assert(0 == self.locks.unlock(node.batch.accounts));
                    if (node.next == bottom) break;
                    node = node.next.?;
                }

                // Schedule any batches waiting on account locks.
                var waiting = self.waiting;
                self.waiting = null;
                while (waiting) |w| : (waiting = w.next) {
                    self.locks.lockStrict(future.allocator, w.batch.accounts) catch |e| switch (e) {
                        error.OutOfMemory => future.setError(error.OutOfMemory),
                        error.LockFailed => { // add back to waiters list.
                            w.next = self.waiting;
                            self.waiting = w;
                            continue;
                        },
                    };
                    task_batch.push(.from(&w.task));
                }

                // Try to mark as done stack as consumed. Retries loop if more were pushed.
                bottom = top;
                top = (self.done.cmpxchgStrong(top, null, .release, .acquire) orelse break).?;
            }
        }
    }
};
