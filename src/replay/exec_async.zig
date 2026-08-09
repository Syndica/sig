const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const core = sig.core;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const ThreadPool = sig.sync.ThreadPool;

const Transaction = core.Transaction;
const Pubkey = core.Pubkey;
const Entry = core.Entry;
const Hash = core.Hash;

const Committer = replay.Committer;
const ReplayResult = replay.execution.ReplayResult;
const ReplaySlotError = replay.execution.ReplaySlotError;
const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;
const SvmGateway = replay.svm_gateway.SvmGateway;

const SlotHashes = sig.runtime.sysvar.SlotHashes;

const assert = std.debug.assert;

const verifyTicks = replay.execution.verifyTicks;
const verifyPoh = core.entry.verifyPoh;
const replayBatch = replay.execution.replayBatch;
const preprocessTransaction = replay.preprocess_transaction.preprocessTransaction;
const PreprocessedTransaction = replay.execution.PreprocessedTransaction;

const Logger = sig.trace.Logger("replay-async");

/// Tracks the state of a slot confirmation execution.
///
/// agave: confirm_slot and confirm_slot_entries
/// fd: runtime_process_txns_in_microblock_stream
pub const ReplaySlotFuture = struct {
    // Shared state for workers.
    allocator: Allocator,
    arena: std.heap.ArenaAllocator,
    logger: Logger,
    entries: []const Entry,

    // Worker schedulers.
    poh_verifier: PohVerifier,
    txn_scheduler: TransactionScheduler,
    metrics: replay.service.Metrics,
    slot_timer: sig.time.Timer,
    slot_account_cache: ?*replay.execution.SlotAccountCache,

    // Threading state.
    pending: Atomic(usize),
    thread_pool: *ThreadPool,

    // Completion state.
    exit: Atomic(bool),
    result_ptr: Atomic(?*Result),
    wait_group: *std.Thread.WaitGroup,

    pub const Result = Error!ReplayResult;
    pub const Error = PohVerifier.Error || TransactionScheduler.Error;

    pub fn startAsync(
        allocator: Allocator,
        logger: Logger,
        thread_pool: *ThreadPool,
        wait_group: *std.Thread.WaitGroup,
        metrics: replay.service.Metrics,
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
            .arena = .init(allocator),
            .logger = logger,
            .entries = params.entries,
            .poh_verifier = .{
                .future = self,
                .initial_hash = params.last_entry,
                .timer = .start(),
            },
            .metrics = metrics,
            .slot_timer = .start(),
            .slot_account_cache = params.slot_account_cache,
            .txn_scheduler = .{
                .future = self,
                .transactions = params.transactions,
                .svm_gateway = params.svm_gateway,
                .committer = params.committer,
                .execute_timer = .start(),
                .preprocess_timer = .start(),
            },
            .pending = .init(1), // start with 1 for this scope's self.finish()
            .thread_pool = thread_pool,
            .exit = .init(false),
            .result_ptr = .init(result_ptr),
            .wait_group = wait_group,
        };

        wait_group.start();
        defer self.finish(); // if no tasks scheduled, this immediately completes the Future.

        // Start poh verifier before txn scheduler so it runs while txn-sched builds dag.
        self.poh_verifier.start() catch |e| return self.setError(e);

        // Start transaction scheduler.
        self.txn_scheduler.start() catch |e| return self.setError(e);
    }

    fn finishSync(
        allocator: Allocator,
        params: replay.execution.ReplaySlotParams,
        result_ptr: *Result,
        err_or_output: Error!ReplayResult.Output,
    ) void {
        result_ptr.* = if (err_or_output) |output|
            .{ .slot = params.svm_gateway.params.slot, .output = output }
        else |err|
            err;

        params.deinit(allocator);
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
            result_ptr.* = if (err_or_sloterr) |slot_err| .{
                .slot = self.txn_scheduler.svm_gateway.params.slot,
                .output = .{ .err = slot_err },
            } else |err| err;
        }
    }

    fn finish(self: *ReplaySlotFuture) void {
        const zone = tracy.Zone.init(@src(), .{ .name = "ReplaySlotFuture.finish" });
        defer zone.deinit();

        if (self.pending.fetchSub(1, .acq_rel) - 1 == 0) {
            @branchHint(.unlikely);

            // Read the wait gruop out of self, as self will be freed at the end.
            const wg = self.wait_group;
            defer wg.finish();
            const allocator = self.allocator;
            const logger = self.logger;
            const slot = self.txn_scheduler.svm_gateway.params.slot;
            var finish_timer = sig.time.Timer.start();
            var phase_timer = sig.time.Timer.start();

            const poh_stats = self.poh_verifier.stats();
            const scheduler_stats = self.txn_scheduler.stats();
            if (self.txn_scheduler.stats_sink) |stats_sink| stats_sink.* = scheduler_stats;
            self.metrics.poh_verify_wall_time.observe(poh_stats.wall_ns);
            self.metrics.poh_verify_cpu_time.observe(poh_stats.cpu_ns);
            self.metrics.transaction_scheduler_build_time.observe(scheduler_stats.build_ns);
            self.metrics.transaction_preprocess_wall_time.observe(scheduler_stats.preprocess_wall_ns);
            self.metrics.transaction_preprocess_cpu_time.observe(scheduler_stats.preprocess_cpu_ns);
            self.metrics.transaction_preprocess_tasks.set(scheduler_stats.preprocess_tasks);
            self.metrics.transaction_scheduler_execute_wall_time.observe(scheduler_stats.execute_wall_ns);
            self.metrics.transaction_scheduler_workers.set(scheduler_stats.workers);
            self.metrics.transaction_scheduler_dependency_edges.set(scheduler_stats.dependency_edges);
            self.metrics.transaction_scheduler_initial_ready.set(scheduler_stats.initial_ready);
            self.metrics.transaction_scheduler_max_dependencies.set(scheduler_stats.max_dependencies);
            self.metrics.transaction_scheduler_critical_path.set(scheduler_stats.critical_path);
            self.metrics.transaction_scheduler_inline_ready_continuations.set(
                scheduler_stats.inline_ready_continuations,
            );
            self.logger.info().logf(
                "slot_replay_scheduler_stats slot={} poh_entries={} poh_tasks={} poh_wall={D} poh_cpu={D} scheduler_build={D} preprocess_tasks={} preprocess_wall={D} preprocess_cpu={D} scheduler_execute_wall={D} workers={} dependency_edges={} initial_ready={} max_dependencies={} critical_path={} overlap_preprocess={} inline_ready_continuations={}",
                .{
                    slot,
                    poh_stats.entries,
                    poh_stats.tasks,
                    poh_stats.wall_ns,
                    poh_stats.cpu_ns,
                    scheduler_stats.build_ns,
                    scheduler_stats.preprocess_tasks,
                    scheduler_stats.preprocess_wall_ns,
                    scheduler_stats.preprocess_cpu_ns,
                    scheduler_stats.execute_wall_ns,
                    scheduler_stats.workers,
                    scheduler_stats.dependency_edges,
                    scheduler_stats.initial_ready,
                    scheduler_stats.max_dependencies,
                    scheduler_stats.critical_path,
                    scheduler_stats.overlap_preprocess,
                    scheduler_stats.inline_ready_continuations,
                },
            );

            replay.execution.logReplayBatchStats(
                self.logger,
                slot,
                "async",
                self.slot_timer.read().asNanos(),
                self.txn_scheduler.batch_stats.snapshot(),
            );
            replay.execution.logProgramLoadStats(
                self.logger,
                self.metrics,
                slot,
                self.txn_scheduler.svm_gateway.programLoadStats(),
            );
            const stats_log_ns = phase_timer.read().asNanos();
            phase_timer.reset();
            if (self.result_ptr.load(.acquire) != null) {
                replay.execution.flushDeferredSlotAccountCacheWrites(
                    self.logger,
                    self.slot_account_cache,
                ) catch |err| {
                    self.logger.err().logf(
                        "deferred slot account cache flush failed: {}",
                        .{err},
                    );
                    self.setError(Error.ReplayBatchFailed);
                };
            }
            const deferred_flush_ns = phase_timer.read().asNanos();
            phase_timer.reset();
            if (self.slot_account_cache) |cache| {
                replay.execution.logSlotAccountCacheStats(
                    self.logger,
                    slot,
                    cache.stats.snapshot(),
                );
            }
            const cache_stats_log_ns = phase_timer.read().asNanos();
            phase_timer.reset();

            if (self.result_ptr.load(.acquire)) |result_ptr| {
                result_ptr.* = .{
                    .slot = slot,
                    .output = .{ .last_entry_hash = self.entries[self.entries.len - 1].hash },
                };
            } else assert(self.exit.load(.monotonic)); // a setError() occured & consumed the result
            const publish_result_ns = phase_timer.read().asNanos();
            phase_timer.reset();

            for (self.entries) |entry| entry.deinit(self.allocator);
            self.allocator.free(self.entries);
            const entries_deinit_ns = phase_timer.read().asNanos();
            phase_timer.reset();

            self.txn_scheduler.deinit();
            const scheduler_deinit_ns = phase_timer.read().asNanos();
            phase_timer.reset();
            self.poh_verifier.deinit();
            const poh_deinit_ns = phase_timer.read().asNanos();
            phase_timer.reset();
            replay.execution.destroySlotAccountCache(self.allocator, self.slot_account_cache);
            const slot_cache_deinit_ns = phase_timer.read().asNanos();
            phase_timer.reset();

            self.arena.deinit();
            const arena_deinit_ns = phase_timer.read().asNanos();
            const total_ns = finish_timer.read().asNanos();
            const known_ns = stats_log_ns + deferred_flush_ns + cache_stats_log_ns +
                publish_result_ns + entries_deinit_ns + scheduler_deinit_ns + poh_deinit_ns +
                slot_cache_deinit_ns + arena_deinit_ns;
            const unattributed_ns = total_ns -| known_ns;
            logger.info().logf(
                "replay_future_finish_timing slot={} stats_log_ns={} deferred_flush_ns={} cache_stats_log_ns={} publish_result_ns={} entries_deinit_ns={} scheduler_deinit_ns={} poh_deinit_ns={} slot_cache_deinit_ns={} arena_deinit_ns={} unattributed_ns={} total_ns={}",
                .{
                    slot,
                    stats_log_ns,
                    deferred_flush_ns,
                    cache_stats_log_ns,
                    publish_result_ns,
                    entries_deinit_ns,
                    scheduler_deinit_ns,
                    poh_deinit_ns,
                    slot_cache_deinit_ns,
                    arena_deinit_ns,
                    unattributed_ns,
                    total_ns,
                },
            );
            allocator.destroy(self);
        }
    }
};

const PohVerifier = struct {
    future: *ReplaySlotFuture,
    initial_hash: Hash,
    workers: std.ArrayListUnmanaged(Worker) = .{},
    timer: sig.time.Timer,
    task_count: u64 = 0,
    remaining: Atomic(u64) = .init(0),
    cpu_ns: Atomic(u64) = .init(0),
    wall_ns: Atomic(u64) = .init(0),

    const Error = Allocator.Error;

    const Stats = struct {
        entries: u64,
        tasks: u64,
        wall_ns: u64,
        cpu_ns: u64,
    };

    fn deinit(const_self: PohVerifier) void {
        var self = const_self;
        const allocator = self.future.arena.allocator();

        self.workers.deinit(allocator);
    }

    fn start(self: *PohVerifier) Error!void {
        const future = self.future;
        const entries = future.entries;
        const allocator = self.future.arena.allocator();

        self.timer.reset();
        self.task_count = entries.len;
        self.remaining.store(entries.len, .monotonic);

        var task_batch = ThreadPool.Batch{};
        defer future.schedule(task_batch);

        try self.workers.ensureTotalCapacity(allocator, entries.len);
        for (entries) |_| {
            const index: u32 = @intCast(self.workers.items.len);
            const worker = self.workers.addOneAssumeCapacity();
            worker.* = .{ .future = future, .index = index };
            task_batch.push(.from(&worker.task));
        }
    }

    fn finishWorker(self: *PohVerifier, elapsed_ns: u64) void {
        _ = self.cpu_ns.fetchAdd(elapsed_ns, .monotonic);
        if (self.remaining.fetchSub(1, .acq_rel) == 1) {
            self.wall_ns.store(self.timer.read().asNanos(), .release);
        }
    }

    fn stats(self: *const PohVerifier) Stats {
        return .{
            .entries = self.future.entries.len,
            .tasks = self.task_count,
            .wall_ns = self.wall_ns.load(.acquire),
            .cpu_ns = self.cpu_ns.load(.acquire),
        };
    }

    const Worker = struct {
        task: ThreadPool.Task = .{ .callback = run },
        future: *ReplaySlotFuture,
        index: u32,

        fn run(task: *ThreadPool.Task) void {
            const zone = tracy.Zone.init(@src(), .{ .name = "pohVerify" });
            defer zone.deinit();

            const self: *Worker = @alignCast(@fieldParentPtr("task", task));
            var timer = sig.time.Timer.start();
            defer {
                self.future.poh_verifier.finishWorker(timer.read().asNanos());
                self.future.finish();
            }
            if (self.future.exit.load(.acquire)) return;

            const initial_hash = switch (self.index) {
                0 => self.future.poh_verifier.initial_hash,
                else => self.future.entries[self.index - 1].hash,
            };

            const success = verifyPoh((&self.future.entries[self.index])[0..1], initial_hash);
            if (!success) {
                self.future.logger.err().log("poh verification failed");
                self.future.setError(.{ .invalid_block = .InvalidEntryHash });
            }
        }
    };
};

const TransactionScheduler = struct {
    future: *ReplaySlotFuture,
    transactions: []const ResolvedTransaction,
    svm_gateway: SvmGateway,
    committer: Committer,
    workers: std.ArrayListUnmanaged(Worker) = .{},
    preprocess_workers: std.ArrayListUnmanaged(PreprocessWorker) = .{},
    batch_stats: replay.execution.AtomicReplayBatchStats = .{},
    build_ns: u64 = 0,
    dependency_edges: u64 = 0,
    initial_ready: u64 = 0,
    max_dependencies: u64 = 0,
    critical_path: u64 = 0,
    critical_worker: ?u32 = null,
    execute_timer: sig.time.Timer,
    preprocess_timer: sig.time.Timer,
    preprocess_next: Atomic(usize) = .init(0),
    preprocess_remaining: Atomic(u64) = .init(0),
    preprocess_wall_ns: Atomic(u64) = .init(0),
    preprocess_cpu_ns: Atomic(u64) = .init(0),
    remaining: Atomic(u64) = .init(0),
    execute_wall_ns: Atomic(u64) = .init(0),
    overlap_preprocess: bool = false,
    inline_ready_continuation: bool = false,
    inline_ready_continuations: Atomic(u64) = .init(0),
    stats_sink: ?*Stats = null,

    const Error = Allocator.Error || error{ReplayBatchFailed};

    const AccountLock = struct {
        last_writer: ?u32 = null,
        readers: std.ArrayListUnmanaged(u32) = .{},
        readonly_accesses: u64 = 0,
        writable_accesses: u64 = 0,
        conflict_refs: u64 = 0,
        max_reader_fanout: u64 = 0,
    };

    const AccountLockMap = std.AutoArrayHashMapUnmanaged(Pubkey, AccountLock);

    const DependencyReason = struct {
        pubkey: Pubkey,
        writable: bool,
    };

    const CriticalAccount = struct {
        pubkey: Pubkey,
        critical_edges: u64,
        readonly_accesses: u64,
        writable_accesses: u64,
        conflict_refs: u64,
        max_reader_fanout: u64,

        fn lessThan(_: void, lhs: CriticalAccount, rhs: CriticalAccount) bool {
            if (lhs.critical_edges != rhs.critical_edges) {
                return lhs.critical_edges > rhs.critical_edges;
            }
            if (lhs.conflict_refs != rhs.conflict_refs) {
                return lhs.conflict_refs > rhs.conflict_refs;
            }
            return lhs.pubkey.order(rhs.pubkey) == .lt;
        }
    };

    const Stats = struct {
        build_ns: u64,
        preprocess_tasks: u64,
        preprocess_wall_ns: u64,
        preprocess_cpu_ns: u64,
        execute_wall_ns: u64,
        workers: u64,
        dependency_edges: u64,
        initial_ready: u64,
        max_dependencies: u64,
        critical_path: u64,
        overlap_preprocess: bool,
        inline_ready_continuations: u64,
    };

    const StartOptions = struct {
        overlap_preprocess: ?bool = null,
        inline_ready_continuation: ?bool = null,
        stats_sink: ?*Stats = null,
    };

    fn deinit(const_self: TransactionScheduler) void {
        var self = const_self;

        var allocator = self.future.allocator; // these came from SlotParams.
        for (self.transactions) |transaction| transaction.deinit(allocator);
        allocator.free(self.transactions);
        self.svm_gateway.deinit(allocator);

        allocator = self.future.arena.allocator(); // this came from Future's local arena.
        self.workers.deinit(allocator);
        self.preprocess_workers.deinit(allocator);
    }

    fn start(self: *TransactionScheduler) Error!void {
        return self.startWithOptions(.{});
    }

    fn startWithOptions(self: *TransactionScheduler, options: StartOptions) Error!void {
        const zone = tracy.Zone.init(@src(), .{ .name = "TransactionScheduler.start" });
        defer zone.deinit();
        var build_timer = sig.time.Timer.start();

        self.overlap_preprocess = options.overlap_preprocess orelse
            envBool("SIG_REPLAY_SCHEDULER_OVERLAP_PREPROCESS", false);
        self.inline_ready_continuation = options.inline_ready_continuation orelse
            envBool("SIG_REPLAY_SCHEDULER_INLINE_READY_CONTINUATION", false);
        self.stats_sink = options.stats_sink;

        const allocator = self.future.arena.allocator();
        const entries = self.future.entries;
        const slot = self.svm_gateway.params.slot;
        const hotspot_slot = envU64(
            "SIG_REPLAY_SCHEDULER_DEPENDENCY_HOTSPOTS_SLOT",
            0,
        );
        const dependency_hotspots_enabled =
            envBool("SIG_REPLAY_SCHEDULER_DEPENDENCY_HOTSPOTS", false) and
            (hotspot_slot == 0 or hotspot_slot == slot);

        // Account locking across all sequential transactions.
        var account_locks = AccountLockMap{};
        defer {
            for (account_locks.values()) |*lock| lock.readers.deinit(allocator);
            account_locks.deinit(allocator);
        }

        // Within an entry batch of transactions, account locking writers for verification.
        var batch_locks = std.AutoHashMapUnmanaged(Pubkey, bool){};
        defer batch_locks.deinit(allocator);

        // Within a transaction, dependencies on previous transactions.
        var txn_deps = std.AutoArrayHashMapUnmanaged(u32, void){};
        defer txn_deps.deinit(allocator);

        // Populated only for the requested diagnostic slot. The scheduler still
        // uses txn_deps as its sole source of ordering truth.
        var dependency_reasons = std.AutoArrayHashMapUnmanaged(u32, DependencyReason){};
        defer dependency_reasons.deinit(allocator);

        var expected_transaction_count: usize = 0;
        for (entries) |entry| {
            if (!entry.isTick()) expected_transaction_count += entry.transactions.len;
        }
        const resolved_transaction_count_mismatch =
            expected_transaction_count != self.transactions.len;
        if (resolved_transaction_count_mismatch) {
            self.future.logger.warn().logf(
                "resolved transaction count mismatch: entries={} resolved={}; skipping async intra-entry lock checks",
                .{ expected_transaction_count, self.transactions.len },
            );
        }

        var i: usize = 0;
        for (entries) |entry| {
            if (entry.isTick()) continue;

            batch_locks.clearRetainingCapacity();
            const remaining_transaction_count = self.transactions.len - i;
            if (remaining_transaction_count == 0) break;
            const entry_transaction_count = @min(
                entry.transactions.len,
                remaining_transaction_count,
            );
            for (self.transactions[i..][0..entry_transaction_count]) |transaction| {
                i += 1;

                const id: u32 = @intCast(self.workers.items.len);
                txn_deps.clearRetainingCapacity();
                dependency_reasons.clearRetainingCapacity();
                for (
                    transaction.accounts.items(.pubkey),
                    transaction.accounts.items(.is_writable),
                ) |pubkey, writable| {
                    // Verify that there's no conflicting writer accounts within a batch of txns.
                    if (!resolved_transaction_count_mismatch and !self.svm_gateway.params.feature_set.active(
                        .relax_intrabatch_account_locks,
                        self.svm_gateway.params.slot,
                    )) {
                        const gop = try batch_locks.getOrPut(allocator, pubkey);
                        if (gop.found_existing and (gop.value_ptr.* or writable)) {
                            // Within batch: existing writer, or existing reader when writing.
                            self.future.setError(.{ .invalid_transaction = .AccountInUse });
                            return;
                        }
                        gop.value_ptr.* = writable;
                    }

                    const gop = try account_locks.getOrPut(allocator, pubkey);
                    const lock = gop.value_ptr;
                    if (!gop.found_existing) lock.* = .{};

                    if (writable) {
                        if (dependency_hotspots_enabled) lock.writable_accesses += 1;
                        // if we write, we depend on last writer, or the readers who depend on it.
                        if (lock.readers.items.len > 0) {
                            if (dependency_hotspots_enabled) {
                                lock.max_reader_fanout = @max(
                                    lock.max_reader_fanout,
                                    lock.readers.items.len,
                                );
                            }
                            for (lock.readers.items) |reader_id| {
                                if (reader_id != id) {
                                    if (dependency_hotspots_enabled) lock.conflict_refs += 1;
                                    try recordDependency(
                                        allocator,
                                        &txn_deps,
                                        &dependency_reasons,
                                        dependency_hotspots_enabled,
                                        reader_id,
                                        pubkey,
                                        true,
                                    );
                                }
                            }
                            lock.readers.clearRetainingCapacity();
                        } else if (lock.last_writer) |writer_id| {
                            if (writer_id != id) {
                                if (dependency_hotspots_enabled) lock.conflict_refs += 1;
                                try recordDependency(
                                    allocator,
                                    &txn_deps,
                                    &dependency_reasons,
                                    dependency_hotspots_enabled,
                                    writer_id,
                                    pubkey,
                                    true,
                                );
                            }
                        }

                        // We also become the writer for others later.
                        lock.last_writer = id;
                    } else {
                        if (dependency_hotspots_enabled) lock.readonly_accesses += 1;
                        // if we read, we depend on last writer & becomes readers for next writer
                        try lock.readers.append(allocator, id);
                        if (lock.last_writer) |writer_id| {
                            if (writer_id != id) {
                                if (dependency_hotspots_enabled) lock.conflict_refs += 1;
                                try recordDependency(
                                    allocator,
                                    &txn_deps,
                                    &dependency_reasons,
                                    dependency_hotspots_enabled,
                                    writer_id,
                                    pubkey,
                                    false,
                                );
                            }
                        }
                    }
                }

                // Tell our dependencies to decrement our ref_count when done executing.
                for (txn_deps.keys()) |writer_id| {
                    try self.workers.items[writer_id].waiters.append(allocator, id);
                }
                const dependency_count = txn_deps.count();
                self.dependency_edges += dependency_count;
                self.max_dependencies = @max(self.max_dependencies, dependency_count);
                var critical_depth: u64 = 1;
                var critical_parent: ?u32 = null;
                var critical_account: ?Pubkey = null;
                for (txn_deps.keys()) |dependency_id| {
                    const candidate_depth =
                        self.workers.items[dependency_id].critical_depth + 1;
                    if (candidate_depth > critical_depth) {
                        critical_depth = candidate_depth;
                        critical_parent = dependency_id;
                        if (dependency_hotspots_enabled) {
                            critical_account = dependency_reasons.get(dependency_id).?.pubkey;
                        }
                    }
                }
                if (critical_depth > self.critical_path) {
                    self.critical_path = critical_depth;
                    self.critical_worker = id;
                }
                // Create job with a ref_count for each dependency.
                try self.workers.append(allocator, .{
                    .scheduler = self,
                    .transaction = transaction,
                    .ref_count = .init(@intCast(dependency_count)),
                    .waiters = .{},
                    .critical_depth = critical_depth,
                    .critical_parent = critical_parent,
                    .critical_account = critical_account,
                });
            }
        }

        // Count the workers that can execute as soon as preprocessing completes.
        for (self.workers.items) |*worker| {
            if (worker.ref_count.raw == 0) {
                self.initial_ready += 1;
            }
        }

        if (dependency_hotspots_enabled) {
            try self.logDependencyHotspots(allocator, &account_locks);
        }

        self.build_ns = build_timer.read().asNanos();
        self.remaining.store(self.workers.items.len, .monotonic);
        if (self.workers.items.len == 0) return;

        const max_threads: usize = @intCast(self.future.thread_pool.max_threads);
        const preprocess_thread_limit = if (self.overlap_preprocess and max_threads > 1)
            max_threads - @max(@as(usize, 1), max_threads / 3)
        else
            max_threads;
        const preprocess_task_count = @min(
            self.workers.items.len,
            @max(@as(usize, 1), preprocess_thread_limit),
        );
        try self.preprocess_workers.ensureTotalCapacity(allocator, preprocess_task_count);
        var task_batch = ThreadPool.Batch{};
        for (0..preprocess_task_count) |_| {
            const worker = self.preprocess_workers.addOneAssumeCapacity();
            worker.* = .{ .scheduler = self };
            task_batch.push(.from(&worker.task));
        }

        self.preprocess_next.store(0, .monotonic);
        self.preprocess_remaining.store(preprocess_task_count, .monotonic);
        self.execute_timer.reset();
        self.preprocess_timer.reset();
        self.future.schedule(task_batch);
    }

    fn recordDependency(
        allocator: Allocator,
        txn_deps: *std.AutoArrayHashMapUnmanaged(u32, void),
        dependency_reasons: *std.AutoArrayHashMapUnmanaged(u32, DependencyReason),
        capture_reason: bool,
        dependency_id: u32,
        pubkey: Pubkey,
        writable: bool,
    ) Allocator.Error!void {
        if (txn_deps.contains(dependency_id)) return;
        try txn_deps.put(allocator, dependency_id, {});
        if (capture_reason) {
            try dependency_reasons.put(allocator, dependency_id, .{
                .pubkey = pubkey,
                .writable = writable,
            });
        }
    }

    fn logDependencyHotspots(
        self: *const TransactionScheduler,
        allocator: Allocator,
        account_locks: *const AccountLockMap,
    ) Allocator.Error!void {
        var path_accounts = std.AutoArrayHashMapUnmanaged(Pubkey, u64){};
        defer path_accounts.deinit(allocator);

        var traced_edges: u64 = 0;
        var cursor = self.critical_worker;
        while (cursor) |worker_id| {
            const worker = &self.workers.items[worker_id];
            const pubkey = worker.critical_account orelse break;
            const gop = try path_accounts.getOrPut(allocator, pubkey);
            if (!gop.found_existing) gop.value_ptr.* = 0;
            gop.value_ptr.* += 1;
            traced_edges += 1;
            cursor = worker.critical_parent;
        }

        var ranked = std.ArrayListUnmanaged(CriticalAccount){};
        defer ranked.deinit(allocator);
        try ranked.ensureTotalCapacity(allocator, path_accounts.count());
        for (path_accounts.keys(), path_accounts.values()) |pubkey, critical_edges| {
            const lock = account_locks.get(pubkey).?;
            ranked.appendAssumeCapacity(.{
                .pubkey = pubkey,
                .critical_edges = critical_edges,
                .readonly_accesses = lock.readonly_accesses,
                .writable_accesses = lock.writable_accesses,
                .conflict_refs = lock.conflict_refs,
                .max_reader_fanout = lock.max_reader_fanout,
            });
        }
        std.mem.sort(CriticalAccount, ranked.items, {}, CriticalAccount.lessThan);

        self.future.logger.info().logf(
            "slot_replay_scheduler_critical_path slot={} path_nodes={} traced_edges={} unique_accounts={} terminal_tx={?}",
            .{
                self.svm_gateway.params.slot,
                self.critical_path,
                traced_edges,
                path_accounts.count(),
                self.critical_worker,
            },
        );
        for (ranked.items[0..@min(ranked.items.len, 8)], 0..) |account, rank| {
            const pubkey = account.pubkey.base58String();
            self.future.logger.info().logf(
                "slot_replay_scheduler_dependency_hotspot slot={} rank={} account={s} critical_edges={} writable_accesses={} readonly_accesses={} conflict_refs={} max_reader_fanout={}",
                .{
                    self.svm_gateway.params.slot,
                    rank + 1,
                    pubkey.constSlice(),
                    account.critical_edges,
                    account.writable_accesses,
                    account.readonly_accesses,
                    account.conflict_refs,
                    account.max_reader_fanout,
                },
            );
        }
    }

    fn finishPreprocessWorker(self: *TransactionScheduler, elapsed_ns: u64) void {
        _ = self.preprocess_cpu_ns.fetchAdd(elapsed_ns, .monotonic);
        if (self.preprocess_remaining.fetchSub(1, .acq_rel) == 1) {
            self.preprocess_wall_ns.store(self.preprocess_timer.read().asNanos(), .release);
            if (self.future.exit.load(.acquire)) return;

            var task_batch = ThreadPool.Batch{};
            for (self.workers.items) |*worker| {
                if (self.overlap_preprocess) {
                    if (worker.tryClaimReady()) task_batch.push(.from(&worker.task));
                } else if (worker.ref_count.raw == 0) {
                    task_batch.push(.from(&worker.task));
                }
            }
            self.future.schedule(task_batch);
        }
    }

    fn finishWorker(self: *TransactionScheduler) void {
        if (self.remaining.fetchSub(1, .acq_rel) == 1) {
            self.execute_wall_ns.store(self.execute_timer.read().asNanos(), .release);
        }
    }

    fn stats(self: *const TransactionScheduler) Stats {
        return .{
            .build_ns = self.build_ns,
            .preprocess_tasks = self.preprocess_workers.items.len,
            .preprocess_wall_ns = self.preprocess_wall_ns.load(.acquire),
            .preprocess_cpu_ns = self.preprocess_cpu_ns.load(.acquire),
            .execute_wall_ns = self.execute_wall_ns.load(.acquire),
            .workers = self.workers.items.len,
            .dependency_edges = self.dependency_edges,
            .initial_ready = self.initial_ready,
            .max_dependencies = self.max_dependencies,
            .critical_path = self.critical_path,
            .overlap_preprocess = self.overlap_preprocess,
            .inline_ready_continuations = self.inline_ready_continuations.load(.acquire),
        };
    }

    const PreprocessWorker = struct {
        task: ThreadPool.Task = .{ .callback = run },
        scheduler: *TransactionScheduler,

        fn run(task: *ThreadPool.Task) void {
            const zone = tracy.Zone.init(@src(), .{ .name = "replayPreprocess" });
            defer zone.deinit();

            const self: *PreprocessWorker = @alignCast(@fieldParentPtr("task", task));
            var worker_timer = sig.time.Timer.start();
            defer {
                self.scheduler.finishPreprocessWorker(worker_timer.read().asNanos());
                self.scheduler.future.finish();
            }

            const future = self.scheduler.future;
            var ready_batch = ThreadPool.Batch{};
            defer future.schedule(ready_batch);
            const instruction_limit = self.scheduler.svm_gateway.params.feature_set.active(
                .static_instruction_limit,
                self.scheduler.svm_gateway.params.slot,
            );
            while (!future.exit.load(.acquire)) {
                const index = self.scheduler.preprocess_next.fetchAdd(1, .monotonic);
                if (index >= self.scheduler.workers.items.len) break;

                const worker = &self.scheduler.workers.items[index];
                var preprocess_timer = sig.time.Timer.start();
                worker.preprocessed = .{
                    .result = preprocessTransaction(
                        worker.transaction.transaction,
                        .run_sig_verify,
                        instruction_limit,
                    ),
                    .elapsed_ns = preprocess_timer.read().asNanos(),
                };
                // Publish the non-atomic preprocessed payload before either this worker or a
                // dependency releaser may claim its execution task.
                worker.preprocess_ready.store(true, .release);
                if (self.scheduler.overlap_preprocess and worker.tryClaimReady()) {
                    ready_batch.push(.from(&worker.task));
                    if (ready_batch.len >= 8) {
                        future.schedule(ready_batch);
                        ready_batch = .{};
                    }
                }
            }
        }
    };

    const Worker = struct {
        task: ThreadPool.Task = .{ .callback = run },
        scheduler: *TransactionScheduler,
        transaction: ResolvedTransaction,
        ref_count: Atomic(u32),
        waiters: std.ArrayListUnmanaged(u32),
        critical_depth: u64,
        critical_parent: ?u32,
        critical_account: ?Pubkey,
        preprocessed: ?PreprocessedTransaction = null,
        preprocess_ready: Atomic(bool) = .init(false),
        ready_scheduled: Atomic(bool) = .init(false),

        fn deinit(const_self: Worker, allocator: Allocator) void {
            var self = const_self;
            self.transaction.deinit(allocator);
            self.waiters.deinit(allocator);
        }

        fn run(task: *ThreadPool.Task) void {
            const self: *Worker = @alignCast(@fieldParentPtr("task", task));
            defer self.scheduler.future.finish();

            var current: ?*Worker = self;
            while (current) |worker| {
                current = worker.executeAndReleaseWaiters();
                worker.scheduler.finishWorker();
            }
        }

        fn executeAndReleaseWaiters(self: *Worker) ?*Worker {
            const zone = tracy.Zone.init(@src(), .{ .name = "replayExecute" });
            defer zone.deinit();

            const future = self.scheduler.future;
            if (!self.preprocess_ready.load(.acquire)) {
                future.logger.err().log("transaction execution scheduled before preprocessing");
                future.setError(Error.ReplayBatchFailed);
                return null;
            }
            const preprocessed = self.preprocessed orelse {
                future.logger.err().log("transaction execution scheduled before preprocessing");
                future.setError(Error.ReplayBatchFailed);
                return null;
            };
            const preprocessed_batch = [_]PreprocessedTransaction{preprocessed};
            const outcome = replayBatch(
                future.allocator, // cant use future's arena here as its multi-threaded
                future.metrics,
                &self.scheduler.svm_gateway,
                self.scheduler.committer,
                &.{self.transaction},
                &preprocessed_batch,
                &future.exit,
            ) catch |err| {
                future.logger.err().logf("replayBatch failed with error: {}", .{err});
                future.setError(Error.ReplayBatchFailed);
                return null;
            };
            self.scheduler.batch_stats.add(outcome.stats);
            const result = outcome.result;

            if (result == .failure) {
                future.logger.err().logf(
                    "batch failed due to transaction error: {}",
                    .{result.failure},
                );
                future.setError(.{ .invalid_transaction = result.failure });
                return null;
            }

            var task_batch = ThreadPool.Batch{};
            var inline_waiter: ?*Worker = null;

            // Try to schedule the other workers waiting for us
            for (self.waiters.items) |id| {
                const waiter = &self.scheduler.workers.items[id];
                if (waiter.ref_count.fetchSub(1, .acq_rel) - 1 == 0) {
                    if (self.scheduler.overlap_preprocess and !waiter.tryClaimReady()) continue;
                    if (self.scheduler.inline_ready_continuation and inline_waiter == null) {
                        inline_waiter = waiter;
                    } else {
                        task_batch.push(.from(&waiter.task));
                    }
                }
            }

            // Preserve all existing parallelism: queue every additional ready worker before
            // continuing one dependency-chain successor on this already-running pool thread.
            future.schedule(task_batch);
            if (inline_waiter != null) {
                _ = self.scheduler.inline_ready_continuations.fetchAdd(1, .monotonic);
            }
            return inline_waiter;
        }

        fn tryClaimReady(self: *Worker) bool {
            // Preprocessing and dependency release may make the worker runnable in either
            // order. The final CAS is the single scheduling claim shared by both paths.
            if (!self.preprocess_ready.load(.acquire)) return false;
            if (self.ref_count.load(.acquire) != 0) return false;
            return self.ready_scheduled.cmpxchgStrong(
                false,
                true,
                .acq_rel,
                .monotonic,
            ) == null;
        }
    };
};

fn envBool(key: []const u8, default_value: bool) bool {
    const allocator = std.heap.page_allocator;
    const raw = std.process.getEnvVarOwned(allocator, key) catch return default_value;
    defer allocator.free(raw);

    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return default_value;
    if (std.ascii.eqlIgnoreCase(trimmed, "1") or
        std.ascii.eqlIgnoreCase(trimmed, "true") or
        std.ascii.eqlIgnoreCase(trimmed, "yes") or
        std.ascii.eqlIgnoreCase(trimmed, "on"))
    {
        return true;
    }
    if (std.ascii.eqlIgnoreCase(trimmed, "0") or
        std.ascii.eqlIgnoreCase(trimmed, "false") or
        std.ascii.eqlIgnoreCase(trimmed, "no") or
        std.ascii.eqlIgnoreCase(trimmed, "off"))
    {
        return false;
    }
    return default_value;
}

fn envU64(key: []const u8, default_value: u64) u64 {
    const allocator = std.heap.page_allocator;
    const raw = std.process.getEnvVarOwned(allocator, key) catch return default_value;
    defer allocator.free(raw);

    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return default_value;
    return std.fmt.parseUnsigned(u64, trimmed, 10) catch default_value;
}

fn testSchedulerForBatches(
    allocator: Allocator,
    state: *replay.execution.TestState,
    batches: []const []const Transaction,
) !?ReplaySlotError {
    return testSchedulerForBatchesWithOptions(allocator, state, batches, .{});
}

fn testSchedulerForBatchesWithOptions(
    allocator: Allocator,
    state: *replay.execution.TestState,
    batches: []const []const Transaction,
    options: TransactionScheduler.StartOptions,
) !?ReplaySlotError {
    comptime std.debug.assert(@import("builtin").is_test);

    var resolved: std.ArrayListUnmanaged(replay.resolve_lookup.ResolvedTransaction) = .{};
    errdefer {
        for (resolved.items) |tx| {
            for (tx.instructions) |instr| instr.deinit(allocator);
            tx.deinit(allocator);
        }
        resolved.deinit(allocator);
    }

    for (batches) |transactions| {
        try state.makeTransactionsPassable(allocator, transactions);
        try resolved.ensureUnusedCapacity(allocator, transactions.len);
        for (transactions) |tx| resolved.appendAssumeCapacity(
            try replay.resolve_lookup.resolveTransaction(allocator, tx, .{
                .slot = 0,
                .account_reader = .noop,
                .reserved_accounts = &.empty,
                .slot_hashes = .INIT,
            }),
        );
    }

    var thread_pool = ThreadPool.init(.{});
    defer {
        thread_pool.shutdown();
        thread_pool.deinit();
    }
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();
    const metrics = try registry.initStruct(replay.service.Metrics);

    var result: ReplaySlotFuture.Result = undefined;
    {
        var wg = std.Thread.WaitGroup{};
        defer wg.wait();

        const entries = try allocator.alloc(Entry, batches.len);
        errdefer allocator.free(entries);
        for (batches, 0..) |transactions, i| {
            errdefer for (entries[0..i]) |e| e.deinit(allocator);

            const duped = try allocator.alloc(Transaction, transactions.len);
            errdefer allocator.free(duped);
            for (transactions, 0..) |tx, j| {
                errdefer for (duped[0..j]) |duped_tx| duped_tx.deinit(allocator);
                duped[j] = try tx.clone(allocator);
            }

            entries[i] = .{
                .num_hashes = 0,
                .hash = .ZEROES,
                .transactions = duped,
            };
        }

        const future = try allocator.create(ReplaySlotFuture);
        errdefer allocator.destroy(future);

        const committer = state.committer();
        const resolved_transactions = try resolved.toOwnedSlice(allocator);

        const svm_params = state.svmParams();
        const svm_gateway = try SvmGateway.init(allocator, svm_params);
        errdefer svm_gateway.deinit(allocator);

        future.* = .{
            .allocator = allocator,
            .arena = .init(allocator),
            .logger = .noop,
            .entries = entries,
            .poh_verifier = .{
                .future = future,
                .initial_hash = .ZEROES, // poh_verifier not used.
                .timer = .start(),
            },
            .metrics = metrics,
            .slot_timer = .start(),
            .slot_account_cache = null,
            .txn_scheduler = .{
                .future = future,
                .transactions = resolved_transactions,
                .svm_gateway = svm_gateway,
                .committer = committer,
                .execute_timer = .start(),
                .preprocess_timer = .start(),
            },
            .pending = .init(1), // start with 1 for this scope's future.finish()
            .thread_pool = &thread_pool,
            .exit = .init(false),
            .result_ptr = .init(&result),
            .wait_group = &wg,
        };

        wg.start();
        defer future.finish();

        future.txn_scheduler.startWithOptions(options) catch |e| future.setError(e);
    }

    return switch ((try result).output) {
        .last_entry_hash => null,
        .err => |err| err,
    };
}

fn initSchedulerAccessTransaction(
    allocator: Allocator,
    random: std.Random,
    payer_seed_value: u64,
    shared_account: Pubkey,
    shared_writable: bool,
) !Transaction {
    comptime std.debug.assert(@import("builtin").is_test);

    var payer_seed: [32]u8 = @splat(0);
    std.mem.writeInt(u64, payer_seed[0..8], payer_seed_value, .little);
    const payer = try sig.identity.KeyPair.generateDeterministic(payer_seed);
    const accounts = try allocator.dupe(core.instruction.InstructionAccount, &.{.{
        .pubkey = shared_account,
        .is_signer = false,
        .is_writable = shared_writable,
    }});
    var instruction: core.Instruction = .{
        .program_id = Pubkey.initRandom(random),
        .accounts = accounts,
        .data = &.{},
        .owned_data = false,
    };
    defer instruction.deinit(allocator);

    const message: core.transaction.Message = try .initCompile(
        allocator,
        &.{instruction},
        Pubkey.fromPublicKey(&payer.public_key),
        Hash.initRandom(random),
        null,
    );
    errdefer message.deinit(allocator);
    return Transaction.initOwnedMessageWithSigningKeypairs(
        allocator,
        .legacy,
        message,
        &.{payer},
    );
}

test "TransactionScheduler: inline ready continuation preserves fanout and fanin" {
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const shared_account = Pubkey.initRandom(rng.random());

    var transactions = [_]Transaction{
        try initSchedulerAccessTransaction(allocator, rng.random(), 1, shared_account, true),
        try initSchedulerAccessTransaction(allocator, rng.random(), 2, shared_account, false),
        try initSchedulerAccessTransaction(allocator, rng.random(), 3, shared_account, false),
        try initSchedulerAccessTransaction(allocator, rng.random(), 4, shared_account, true),
    };
    defer for (transactions) |transaction| transaction.deinit(allocator);

    const batches = [_][]const Transaction{
        transactions[0..1],
        transactions[1..2],
        transactions[2..3],
        transactions[3..4],
    };

    {
        var state = try replay.execution.TestState.init(allocator);
        defer state.deinit(allocator);
        var scheduler_stats: TransactionScheduler.Stats = undefined;

        try std.testing.expectEqual(
            null,
            try testSchedulerForBatchesWithOptions(
                allocator,
                &state,
                &batches,
                .{
                    .inline_ready_continuation = false,
                    .stats_sink = &scheduler_stats,
                },
            ),
        );
        try std.testing.expectEqual(0, scheduler_stats.inline_ready_continuations);
    }

    {
        var state = try replay.execution.TestState.init(allocator);
        defer state.deinit(allocator);
        var scheduler_stats: TransactionScheduler.Stats = undefined;

        try std.testing.expectEqual(
            null,
            try testSchedulerForBatchesWithOptions(
                allocator,
                &state,
                &batches,
                .{
                    .inline_ready_continuation = true,
                    .stats_sink = &scheduler_stats,
                },
            ),
        );
        try std.testing.expectEqual(2, scheduler_stats.inline_ready_continuations);
    }
}

test "TransactionScheduler: overlap preprocessing preserves fanout and fanin" {
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const shared_account = Pubkey.initRandom(rng.random());

    var transactions = [_]Transaction{
        try initSchedulerAccessTransaction(allocator, rng.random(), 1, shared_account, true),
        try initSchedulerAccessTransaction(allocator, rng.random(), 2, shared_account, false),
        try initSchedulerAccessTransaction(allocator, rng.random(), 3, shared_account, false),
        try initSchedulerAccessTransaction(allocator, rng.random(), 4, shared_account, true),
    };
    defer for (transactions) |transaction| transaction.deinit(allocator);

    const batches = [_][]const Transaction{
        transactions[0..1],
        transactions[1..2],
        transactions[2..3],
        transactions[3..4],
    };

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);
    var scheduler_stats: TransactionScheduler.Stats = undefined;

    try std.testing.expectEqual(
        null,
        try testSchedulerForBatchesWithOptions(
            allocator,
            &state,
            &batches,
            .{
                .overlap_preprocess = true,
                .inline_ready_continuation = false,
                .stats_sink = &scheduler_stats,
            },
        ),
    );
    try std.testing.expect(scheduler_stats.overlap_preprocess);
    try std.testing.expectEqual(0, scheduler_stats.inline_ready_continuations);
    try std.testing.expectEqual(4, scheduler_stats.workers);
    try std.testing.expectEqual(1, scheduler_stats.initial_ready);
    try std.testing.expectEqual(3, scheduler_stats.critical_path);
}

test "TransactionScheduler: inline ready continuation handles a long writable chain" {
    const allocator = std.testing.allocator;
    const transaction_count = 1024;
    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const shared_account = Pubkey.initRandom(rng.random());

    const transactions = try allocator.alloc(Transaction, transaction_count);
    defer allocator.free(transactions);
    var initialized_count: usize = 0;
    defer for (transactions[0..initialized_count]) |transaction| transaction.deinit(allocator);
    for (transactions, 0..) |*transaction, index| {
        transaction.* = try initSchedulerAccessTransaction(
            allocator,
            rng.random(),
            @intCast(index + 1),
            shared_account,
            true,
        );
        initialized_count += 1;
    }

    const batches = try allocator.alloc([]const Transaction, transaction_count);
    defer allocator.free(batches);
    for (batches, 0..) |*batch, index| batch.* = transactions[index .. index + 1];

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);
    var scheduler_stats: TransactionScheduler.Stats = undefined;

    try std.testing.expectEqual(
        null,
        try testSchedulerForBatchesWithOptions(
            allocator,
            &state,
            batches,
            .{
                .inline_ready_continuation = true,
                .stats_sink = &scheduler_stats,
            },
        ),
    );
    try std.testing.expectEqual(transaction_count, scheduler_stats.workers);
    try std.testing.expectEqual(transaction_count - 1, scheduler_stats.dependency_edges);
    try std.testing.expectEqual(1, scheduler_stats.initial_ready);
    try std.testing.expectEqual(1, scheduler_stats.max_dependencies);
    try std.testing.expectEqual(transaction_count, scheduler_stats.critical_path);
    try std.testing.expectEqual(
        transaction_count - 1,
        scheduler_stats.inline_ready_continuations,
    );
}

test "TransactionScheduler: overlap preprocessing handles a long writable chain" {
    const allocator = std.testing.allocator;
    const transaction_count = 1024;
    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const shared_account = Pubkey.initRandom(rng.random());

    const transactions = try allocator.alloc(Transaction, transaction_count);
    defer allocator.free(transactions);
    var initialized_count: usize = 0;
    defer for (transactions[0..initialized_count]) |transaction| transaction.deinit(allocator);
    for (transactions, 0..) |*transaction, index| {
        transaction.* = try initSchedulerAccessTransaction(
            allocator,
            rng.random(),
            @intCast(index + 1),
            shared_account,
            true,
        );
        initialized_count += 1;
    }

    const batches = try allocator.alloc([]const Transaction, transaction_count);
    defer allocator.free(batches);
    for (batches, 0..) |*batch, index| batch.* = transactions[index .. index + 1];

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);
    var scheduler_stats: TransactionScheduler.Stats = undefined;

    try std.testing.expectEqual(
        null,
        try testSchedulerForBatchesWithOptions(
            allocator,
            &state,
            batches,
            .{
                .overlap_preprocess = true,
                .inline_ready_continuation = false,
                .stats_sink = &scheduler_stats,
            },
        ),
    );
    try std.testing.expect(scheduler_stats.overlap_preprocess);
    try std.testing.expectEqual(transaction_count, scheduler_stats.workers);
    try std.testing.expectEqual(transaction_count - 1, scheduler_stats.dependency_edges);
    try std.testing.expectEqual(1, scheduler_stats.initial_ready);
    try std.testing.expectEqual(1, scheduler_stats.max_dependencies);
    try std.testing.expectEqual(transaction_count, scheduler_stats.critical_path);
    try std.testing.expectEqual(0, scheduler_stats.inline_ready_continuations);
}

test "TransactionScheduler: happy path" {
    const allocator = std.testing.allocator;

    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var tx_arena = std.heap.ArenaAllocator.init(allocator);
    defer tx_arena.deinit();

    const transactions = [_]Transaction{
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
    };

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);

    try std.testing.expectEqual(
        null,
        try testSchedulerForBatches(allocator, &state, &.{
            transactions[0..3],
            transactions[3..6],
        }),
    );
}

test "TransactionScheduler: duplicate batch passes through to svm" {
    const allocator = std.testing.allocator;

    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var tx_arena = std.heap.ArenaAllocator.init(allocator);
    defer tx_arena.deinit();

    const transactions = [_]Transaction{
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
    };

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);

    try std.testing.expectEqual(
        ReplaySlotError{ .invalid_transaction = .AlreadyProcessed },
        try testSchedulerForBatches(allocator, &state, &.{
            transactions[0..3],
            // should be no failures on account collision with  first time this batch was scheduled.
            // scheduler should just know to run it separately
            transactions[0..3],
        }),
    );
}

test "TransactionScheduler: failed account locks" {
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const tx = try Transaction.initRandom(allocator, rng.random(), null);
    defer tx.deinit(allocator);

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);

    try std.testing.expectEqual(
        ReplaySlotError{ .invalid_transaction = .AccountInUse },
        try testSchedulerForBatches(allocator, &state, &.{
            &.{ tx, tx }, // same txn in same batch
        }),
    );
}

test "TransactionScheduler: signature verification failure" {
    const allocator = std.testing.allocator;

    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var tx_arena = std.heap.ArenaAllocator.init(allocator);
    defer tx_arena.deinit();

    var transactions = [_]Transaction{
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
        try .initRandom(tx_arena.allocator(), rng.random(), null),
    };

    const replaced_sigs = try tx_arena.allocator()
        .dupe(sig.core.Signature, transactions[5].signatures);
    replaced_sigs[0].r[0] +%= 1;
    transactions[5].signatures = replaced_sigs;

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);

    try std.testing.expectEqual(
        ReplaySlotError{ .invalid_transaction = .SignatureFailure },
        try testSchedulerForBatches(allocator, &state, &.{
            transactions[0..3],
            transactions[3..6],
        }),
    );
}

test "TransactionScheduler: does not send replay vote for failed execution" {
    const allocator = std.testing.allocator;
    const vote_program = sig.runtime.program.vote;
    const vote_instruction = vote_program.vote_instruction;

    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var tx_arena = std.heap.ArenaAllocator.init(allocator);
    defer tx_arena.deinit();

    // Build a simple vote transaction (first instruction is vote program)
    const node_kp = try sig.identity.KeyPair.generateDeterministic(@splat(1));
    const auth_kp = try sig.identity.KeyPair.generateDeterministic(@splat(2));
    const vote_pubkey = sig.core.Pubkey.initRandom(rng.random());
    const vote_state_inner = vote_program.state.Vote{
        .slots = &.{42},
        .hash = sig.core.Hash.ZEROES,
        .timestamp = null,
    };
    const vote_state = vote_instruction.Vote{ .vote = vote_state_inner };
    var vote_ix = try vote_instruction.createVote(
        allocator,
        vote_pubkey,
        sig.core.Pubkey.fromPublicKey(&auth_kp.public_key),
        vote_state,
    );
    defer vote_ix.deinit(allocator);

    const tx_msg: sig.core.transaction.Message = try .initCompile(
        allocator,
        &.{vote_ix},
        sig.core.Pubkey.fromPublicKey(&node_kp.public_key),
        sig.core.Hash.ZEROES,
        null,
    );

    const vote_tx = try Transaction.initOwnedMessageWithSigningKeypairs(
        allocator,
        .legacy,
        tx_msg,
        &.{ node_kp, auth_kp },
    );
    defer vote_tx.deinit(allocator);

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);

    // Make transaction passable (valid recent blockhash and fees)
    var txs = [_]Transaction{vote_tx};
    try std.testing.expectEqual(
        null,
        try testSchedulerForBatches(allocator, &state, &.{
            &txs,
        }),
    );

    try std.testing.expectEqual(null, state.replay_votes_channel.tryReceive());
}

test "TransactionScheduler: sends replay vote after successful execution" {
    const allocator = std.testing.allocator;
    const vote_program = sig.runtime.program.vote;
    const vote_instruction = vote_program.vote_instruction;

    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);
    const account_store = state.accountStore();

    // Keys
    const node_kp = try sig.identity.KeyPair.generateDeterministic(@splat(11));
    const auth_kp = try sig.identity.KeyPair.generateDeterministic(@splat(12));
    const node_pubkey = sig.core.Pubkey.fromPublicKey(&node_kp.public_key);
    const authorized_voter = sig.core.Pubkey.fromPublicKey(&auth_kp.public_key);
    const vote_pubkey = sig.core.Pubkey.initRandom(rng.random());

    // 1) Create and store a valid on-chain vote account with owner set
    // and initialized vote state authorizing auth_kp.
    {
        var account = sig.runtime.AccountSharedData.NEW;
        account.owner = sig.runtime.program.vote.ID;
        account.data = try allocator.alloc(u8, vote_program.state.VoteStateV3.MAX_VOTE_STATE_SIZE);
        defer allocator.free(account.data);
        @memset(account.data, 0);

        var vote_state = try vote_program.state.createTestVoteStateV3(
            allocator,
            node_pubkey,
            authorized_voter,
            node_pubkey,
            0,
        );
        defer vote_state.deinit(allocator);

        // Seed the vote state with a prior slot so lastVotedSlot() can be non-null after process
        try vote_program.state.processSlotVoteUnchecked(allocator, &vote_state, 1);

        _ = try sig.bincode.writeToSlice(
            account.data,
            vote_program.state.VoteStateVersions{ .v3 = vote_state },
            .{},
        );
        // Ensure rent-exempt balance
        const rent = sig.runtime.sysvar.Rent.INIT;
        account.lamports = rent.minimumBalance(account.data.len);

        // Insert account into the test map so committer can update stakes
        try account_store.put(state.slot, vote_pubkey, account);
    }

    // 2) Make a Vote instruction (includes SlotHashes and Clock accounts)
    const vote_hash = sig.core.Hash.initRandom(rng.random());
    const vote_state_inner = vote_program.state.Vote{
        .slots = &.{2},
        .hash = vote_hash,
        .timestamp = null,
    };
    const vote_state_ix = vote_instruction.Vote{ .vote = vote_state_inner };
    var vote_ix = try vote_instruction.createVote(
        allocator,
        vote_pubkey,
        authorized_voter,
        vote_state_ix,
    );
    defer vote_ix.deinit(allocator);

    // 3) Ensure SlotHashes contains the voted slot so vote processor accepts it
    var slot_hashes: SlotHashes = .INIT;
    slot_hashes.add(1, sig.core.Hash.initRandom(rng.random()));
    slot_hashes.add(2, vote_hash);

    // Insert SlotHashes sysvar account so SVM's sysvar_cache sees these entries
    {
        const sysvar_len = SlotHashes.STORAGE_SIZE;
        var sysvar_account = sig.runtime.AccountSharedData.NEW;
        sysvar_account.data = try allocator.alloc(u8, sysvar_len);
        @memset(sysvar_account.data, 0);
        _ = try sig.bincode.writeToSlice(sysvar_account.data, slot_hashes, .{});
        const rent = sig.runtime.sysvar.Rent.INIT;
        sysvar_account.lamports = rent.minimumBalance(sysvar_account.data.len);
        sysvar_account.owner = sig.runtime.sysvar.OWNER_ID;
        try account_store.put(state.slot, SlotHashes.ID, sysvar_account);
        allocator.free(sysvar_account.data);
    }

    // Insert Clock sysvar account to satisfy vote processor's clock access
    {
        const clock = sig.runtime.sysvar.Clock{
            .slot = 3,
            .epoch_start_timestamp = 0,
            .epoch = 0,
            .leader_schedule_epoch = 0,
            .unix_timestamp = 0,
        };
        const sysvar_len = sig.runtime.sysvar.Clock.STORAGE_SIZE;
        var sysvar_account = sig.runtime.AccountSharedData.NEW;
        sysvar_account.data = try allocator.alloc(u8, sysvar_len);
        @memset(sysvar_account.data, 0);
        _ = try sig.bincode.writeToSlice(sysvar_account.data, clock, .{});
        const rent = sig.runtime.sysvar.Rent.INIT;
        sysvar_account.lamports = rent.minimumBalance(sysvar_account.data.len);
        sysvar_account.owner = sig.runtime.sysvar.OWNER_ID;
        try account_store.put(state.slot, sig.runtime.sysvar.Clock.ID, sysvar_account);
        allocator.free(sysvar_account.data);
    }

    // Insert builtin program accounts for loader checks
    {
        var vote_prog_acc = sig.runtime.AccountSharedData.NEW;
        vote_prog_acc.lamports = 1;
        vote_prog_acc.owner = sig.runtime.ids.NATIVE_LOADER_ID;
        vote_prog_acc.executable = true;
        try account_store.put(state.slot, sig.runtime.program.vote.ID, vote_prog_acc);

        var native_loader_acc = sig.runtime.AccountSharedData.NEW;
        native_loader_acc.lamports = 1;
        native_loader_acc.owner = sig.runtime.ids.NATIVE_LOADER_ID;
        native_loader_acc.executable = true;
        try account_store.put(state.slot, sig.runtime.ids.NATIVE_LOADER_ID, native_loader_acc);
    }

    // Insert Rent sysvar account
    {
        const rent = sig.runtime.sysvar.Rent.INIT;
        const sysvar_len = sig.runtime.sysvar.Rent.STORAGE_SIZE;
        var sysvar_account = sig.runtime.AccountSharedData.NEW;
        sysvar_account.data = try allocator.alloc(u8, sysvar_len);
        @memset(sysvar_account.data, 0);
        _ = try sig.bincode.writeToSlice(sysvar_account.data, rent, .{});
        sysvar_account.lamports = rent.minimumBalance(sysvar_account.data.len);
        sysvar_account.owner = sig.runtime.sysvar.OWNER_ID;
        try account_store.put(state.slot, sig.runtime.sysvar.Rent.ID, sysvar_account);
        allocator.free(sysvar_account.data);
    }

    // Build and sign the transaction with the authorized voter; fund fee payer
    const tx_msg: sig.core.transaction.Message = try .initCompile(
        allocator,
        &.{vote_ix},
        node_pubkey,
        sig.core.Hash.ZEROES,
        null,
    );

    const vote_tx = try Transaction.initOwnedMessageWithSigningKeypairs(
        allocator,
        .legacy,
        tx_msg,
        &.{ node_kp, auth_kp },
    );
    defer vote_tx.deinit(allocator);

    var txs = [_]Transaction{vote_tx};

    // Await completion and assert a replay vote was emitted
    try std.testing.expectEqual(
        null,
        try testSchedulerForBatches(allocator, &state, &.{&txs}),
    );
    const maybe_vote = state.replay_votes_channel.tryReceive();
    try std.testing.expect(maybe_vote != null);
    if (maybe_vote) |pv| pv.deinit(allocator);
}
