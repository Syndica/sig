//! Core logic for replaying slots by executing transactions.

const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const core = sig.core;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const ThreadPool = sig.sync.ThreadPool;

const Ancestors = core.Ancestors;
const Entry = core.Entry;
const Hash = core.Hash;
const Slot = core.Slot;

const AccountStore = sig.accounts_db.AccountStore;
const AccountSharedData = sig.runtime.AccountSharedData;
const bpf_loader = sig.runtime.program.bpf_loader;

const ForkProgress = sig.consensus.progress_map.ForkProgress;
const ParsedVote = sig.consensus.vote_listener.vote_parser.ParsedVote;
const ProcessedTransaction = sig.runtime.transaction_execution.ProcessedTransaction;
const SlotHashes = sig.runtime.sysvar.SlotHashes;
const TransactionError = sig.ledger.transaction_status.TransactionError;

const Committer = replay.Committer;
const ReplaySlotFuture = replay.exec_async.ReplaySlotFuture;
const ReplayState = replay.service.ReplayState;
const pumpfun_parser = sig.geyser.pumpfun_parser;
const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;
const SlotResolver = replay.resolve_lookup.SlotResolver;
const SlotTracker = replay.trackers.SlotTracker;
const SvmGateway = replay.svm_gateway.SvmGateway;

const executeTransaction = replay.svm_gateway.executeTransaction;
const preprocessTransaction = replay.preprocess_transaction.preprocessTransaction;
const PreprocessTransactionResult =
    replay.preprocess_transaction.PreprocessTransactionResult;
const verifyPoh = core.entry.verifyPoh;

const Logger = sig.trace.Logger("replay.execution");
const failing_allocator = sig.utils.allocators.failing.allocator(.{});

/// The result of replaying an individual slot.
pub const ReplayResult = struct {
    slot: Slot,
    output: Output,

    pub const Output = union(enum) {
        last_entry_hash: sig.core.Hash,
        err: ReplaySlotError,
    };
};

/// 1. Replays transactions from all the slots that need to be replayed.
/// 2. Store the replay results into the relevant data structures.
///
/// Analogous to [replay_active_banks](https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3356)
pub fn replayActiveSlots(state: *ReplayState, metrics: replay.service.Metrics) ![]const ReplayResult {
    const can_multi_thread = state.thread_pool.max_threads > 1;
    return if (can_multi_thread)
        try replayActiveSlotsAsync(state, metrics)
    else
        try replayActiveSlotsSync(state, metrics);
}

fn replayActiveSlotsAsync(state: *ReplayState, metrics: replay.service.Metrics) ![]const ReplayResult {
    const zone = tracy.Zone.init(@src(), .{ .name = "replayActiveSlotsAsync" });
    defer zone.deinit();
    var total_timer = sig.time.Timer.start();

    const slot_tracker = &state.slot_tracker;
    const epoch_tracker = state.epoch_tracker;

    var results = std.ArrayListUnmanaged(ReplaySlotFuture.Result){};
    defer results.deinit(state.allocator);

    var active_slots_ns: u64 = 0;
    var prepare_slots_ns: u64 = 0;
    var dispatch_ns: u64 = 0;
    var wait_ns: u64 = 0;
    var first_slot: Slot = 0;
    var last_slot: Slot = 0;
    var active_slot_count: usize = 0;

    {
        var wait_group = std.Thread.WaitGroup{};
        var wait_complete = false;
        defer if (!wait_complete) wait_group.wait();

        var phase_timer = sig.time.Timer.start();
        const active_slots = try slot_tracker.activeSlots(state.allocator);
        defer state.allocator.free(active_slots);
        state.execution_log_helper.logActiveSlots(active_slots);
        active_slots_ns = phase_timer.read().asNanos();
        active_slot_count = active_slots.len;

        if (active_slots.len == 0) {
            return &.{};
        }
        const persistent_program_cache =
            envBool("SIG_REPLAY_PERSISTENT_PROGRAM_CACHE", false);
        const use_persistent_program_cache =
            persistent_program_cache and active_slots.len == 1;
        if (persistent_program_cache and active_slots.len > 1) {
            state.resetPersistentProgramMap(null, null);
            state.logger.info().logf(
                "persistent_program_cache disabled_for_iteration active_slots={}",
                .{active_slots.len},
            );
        }
        first_slot = active_slots[0];
        last_slot = active_slots[active_slots.len - 1];

        try results.ensureTotalCapacity(state.allocator, active_slots.len);
        for (active_slots) |slot| {
            state.logger.debug().logf("replaying slot: {}", .{slot});

            phase_timer.reset();
            const prepared = try prepareSlot(
                state,
                metrics,
                slot_tracker,
                epoch_tracker,
                slot,
                use_persistent_program_cache,
            );
            prepare_slots_ns += phase_timer.read().asNanos();
            const params = switch (prepared) {
                .confirm => |params| params,
                .empty, .dead, .leader => continue,
            };

            const result_ptr = results.addOneAssumeCapacity();
            phase_timer.reset();
            ReplaySlotFuture.startAsync(
                state.allocator,
                .from(state.logger),
                &state.thread_pool,
                &wait_group,
                metrics,
                params,
                result_ptr,
            );
            dispatch_ns += phase_timer.read().asNanos();
        }

        phase_timer.reset();
        wait_group.wait();
        wait_complete = true;
        wait_ns = phase_timer.read().asNanos();
    }

    var result_timer = sig.time.Timer.start();
    const replay_results = try state.allocator.alloc(ReplayResult, results.items.len);
    errdefer state.allocator.free(replay_results);

    for (replay_results, results.items) |*replay_result, result| {
        replay_result.* = try result;
    }

    const result_copy_ns = result_timer.read().asNanos();
    const total_ns = total_timer.read().asNanos();
    const known_ns = active_slots_ns + prepare_slots_ns + dispatch_ns + wait_ns + result_copy_ns;
    const unattributed_ns = total_ns -| known_ns;
    state.logger.info().logf(
        "replay_active_async_timing first_slot={} last_slot={} active_slots={} confirmed_slots={} active_slot_scan_ns={} prepare_slots_ns={} dispatch_ns={} wait_ns={} result_copy_ns={} unattributed_ns={} total_ns={}",
        .{
            first_slot,
            last_slot,
            active_slot_count,
            results.items.len,
            active_slots_ns,
            prepare_slots_ns,
            dispatch_ns,
            wait_ns,
            result_copy_ns,
            unattributed_ns,
            total_ns,
        },
    );

    return replay_results;
}

/// Fully synchronous version of replayActiveSlotsAsync that does not use
/// multithreading or async execution in any way.
fn replayActiveSlotsSync(state: *ReplayState, metrics: replay.service.Metrics) ![]const ReplayResult {
    const allocator = state.allocator;
    var zone = tracy.Zone.init(@src(), .{ .name = "replayActiveSlotsSync" });
    defer zone.deinit();

    const slot_tracker = &state.slot_tracker;
    const epoch_tracker = state.epoch_tracker;

    const active_slots = try slot_tracker.activeSlots(allocator);
    defer allocator.free(active_slots);
    state.execution_log_helper.logActiveSlots(active_slots);

    if (active_slots.len == 0) {
        return &.{};
    }
    const persistent_program_cache = envBool("SIG_REPLAY_PERSISTENT_PROGRAM_CACHE", false);
    const use_persistent_program_cache = persistent_program_cache and active_slots.len == 1;
    if (persistent_program_cache and active_slots.len > 1) {
        state.resetPersistentProgramMap(null, null);
        state.logger.info().logf(
            "persistent_program_cache disabled_for_iteration active_slots={}",
            .{active_slots.len},
        );
    }

    var results = try std.ArrayListUnmanaged(ReplayResult)
        .initCapacity(allocator, active_slots.len);
    defer results.deinit(allocator);

    for (active_slots) |slot| {
        state.logger.debug().logf("replaying slot: {}", .{slot});

        const params = switch (try prepareSlot(
            state,
            metrics,
            slot_tracker,
            epoch_tracker,
            slot,
            use_persistent_program_cache,
        )) {
            .confirm => |params| params,
            .empty, .dead, .leader => continue,
        };
        const last_entry_hash = params.entries[params.entries.len - 1].hash;

        const maybe_err = try replaySlotSync(allocator, .from(state.logger), metrics, params);
        results.appendAssumeCapacity(.{
            .slot = slot,
            .output = if (maybe_err) |err|
                .{ .err = err }
            else
                .{ .last_entry_hash = last_entry_hash },
        });
    }

    return results.toOwnedSlice(allocator);
}

/// Inputs required to replay a single slot.
pub const ReplaySlotParams = struct {
    /// confirm slot takes ownership of this
    entries: []const Entry,
    /// confirm slot takes ownership of this
    transactions: []const replay.resolve_lookup.ResolvedTransaction,
    /// confirm slot takes ownership of this
    svm_gateway: SvmGateway,

    last_entry: Hash,
    committer: Committer,
    verify_ticks_params: VerifyTicksParams,
    account_store: AccountStore,
    slot_account_cache: ?*SlotAccountCache = null,

    pub fn deinit(self: ReplaySlotParams, allocator: Allocator) void {
        for (self.entries) |entry| entry.deinit(allocator);
        allocator.free(self.entries);
        for (self.transactions) |transaction| transaction.deinit(allocator);
        allocator.free(self.transactions);
        self.svm_gateway.deinit(allocator);
        if (self.slot_account_cache) |cache| {
            cache.deinit();
            allocator.destroy(cache);
        }
    }
};

pub const SlotAccountCache = struct {
    allocator: Allocator,
    lock: sig.sync.RwLock = .{},
    stats: sig.accounts_db.SlotAccountCacheStats = .{},
    accounts: sig.utils.collections.PubkeyMap(AccountSharedData) = .{},
    borrowed_accounts: sig.utils.collections.PubkeyMap(*const AccountSharedData) = .{},
    account_data_lens: sig.utils.collections.PubkeyMap(?usize) = .{},
    deferred_dirty: sig.utils.collections.PubkeyMap(void) = .{},
    defer_writes: bool = false,
    deferred_db: ?*sig.accounts_db.Db = null,
    deferred_slot: Slot = 0,

    pub fn init(allocator: Allocator) SlotAccountCache {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *SlotAccountCache) void {
        for (self.accounts.values()) |*account| account.deinit(self.allocator);
        self.accounts.deinit(self.allocator);
        self.borrowed_accounts.deinit(self.allocator);
        self.account_data_lens.deinit(self.allocator);
        self.deferred_dirty.deinit(self.allocator);
        self.* = undefined;
    }

    fn containsAccount(self: *const SlotAccountCache, pubkey: sig.core.Pubkey) bool {
        return self.accounts.contains(pubkey) or self.borrowed_accounts.contains(pubkey);
    }
};

/// Synchronous version of replaySlotAsync -- The main benefit of this function
/// is to simplify debugging when the multithreading overhead causes issues. It
/// can also be used when there is no concern for performance and you'd just
/// like to reduce the number of moving pieces.
///
/// Validate and execute entries from a single slot.
///
/// Returns an error if the slot failed to replay.
///
/// Takes ownership of the entries. Pass the same allocator that was used for
/// the entry allocation.
///
/// Analogous to:
/// - agave: confirm_slot_entries
/// - fd: runtime_process_txns_in_microblock_stream
pub fn replaySlotSync(
    allocator: Allocator,
    logger: Logger,
    metrics: replay.service.Metrics,
    params: ReplaySlotParams,
) !?ReplaySlotError {
    var zone = tracy.Zone.init(@src(), .{ .name = "replaySlotSync" });
    zone.value(params.svm_gateway.params.slot);
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    defer params.deinit(allocator);

    logger.info().log("confirming slot");

    if (verifyTicks(logger, params.entries, params.verify_ticks_params)) |block_error| {
        return .{ .invalid_block = block_error };
    }

    if (!verifyPoh(params.entries, params.last_entry)) {
        return .{ .invalid_block = .InvalidEntryHash };
    }

    var svm_gateway = params.svm_gateway;
    if (!svm_gateway.params.feature_set.active(
        .relax_intrabatch_account_locks,
        svm_gateway.params.slot,
    )) {
        var locks: sig.replay.AccountLocks = .{};
        defer locks.deinit(allocator);

        var accounts: std.ArrayListUnmanaged(sig.replay.AccountLocks.LockableAccount) = .{};
        defer accounts.deinit(allocator);

        var i: usize = 0;
        for (params.entries) |entry| {
            if (i + entry.transactions.len > params.transactions.len) {
                break; // spy node: bounds mismatch due to account filter, skip remaining lock checks
            }
            const transactions = params.transactions[i..][0..entry.transactions.len];
            i += entry.transactions.len;

            accounts.clearRetainingCapacity();
            for (transactions) |transaction| {
                for (
                    transaction.accounts.items(.pubkey),
                    transaction.accounts.items(.is_writable),
                ) |pubkey, is_writable| {
                    try accounts.append(allocator, .{ .address = pubkey, .writable = is_writable });
                }
            }

            locks.lockStrict(allocator, accounts.items) catch |e| switch (e) {
                error.LockFailed => continue, // spy node: skip entries with lock conflicts
                error.OutOfMemory => return error.OutOfMemory,
            };
            std.debug.assert(0 == locks.unlock(accounts.items));
        }
    }

    var replay_timer = sig.time.Timer.start();
    var replay_stats = ReplayBatchStats{};
    for (params.transactions) |transaction| {
        var exit = Atomic(bool).init(false);

        const outcome = try replayBatch(
            allocator,
            metrics,
            &svm_gateway,
            params.committer,
            &.{transaction},
            null,
            &exit,
        );
        replay_stats.add(outcome.stats);

        switch (outcome.result) {
            .success => {},
            .failure => {}, // spy node: skip failed txs, let slot complete + geyser write
            .exit => unreachable,
        }
    }
    logReplayBatchStats(
        logger,
        svm_gateway.params.slot,
        "sync",
        replay_timer.read().asNanos(),
        replay_stats,
    );
    logProgramLoadStats(
        logger,
        metrics,
        svm_gateway.params.slot,
        svm_gateway.programLoadStats(),
    );
    try flushDeferredSlotAccountCacheWrites(logger, params.slot_account_cache);
    if (params.slot_account_cache) |cache| {
        logSlotAccountCacheStats(logger, svm_gateway.params.slot, cache.stats.snapshot());
    }

    return null;
}

/// The result of processing a transaction batch (entry).
pub const BatchResult = union(enum) {
    /// The batch completed with acceptable results.
    success,
    /// This batch had an error that indicates an invalid block
    failure: TransactionError,
    /// Termination was exited due to a failure in another thread.
    exit,
};

pub const ReplayBatchStats = struct {
    transactions: u64 = 0,
    preprocessed: u64 = 0,
    preprocess_errors: u64 = 0,
    execution_ok: u64 = 0,
    execution_err: u64 = 0,
    committed: u64 = 0,
    preprocess_ns: u64 = 0,
    geyser_parse_ns: u64 = 0,
    execute_ns: u64 = 0,
    commit_ns: u64 = 0,
    total_ns: u64 = 0,

    pub fn add(self: *ReplayBatchStats, other: ReplayBatchStats) void {
        self.transactions += other.transactions;
        self.preprocessed += other.preprocessed;
        self.preprocess_errors += other.preprocess_errors;
        self.execution_ok += other.execution_ok;
        self.execution_err += other.execution_err;
        self.committed += other.committed;
        self.preprocess_ns += other.preprocess_ns;
        self.geyser_parse_ns += other.geyser_parse_ns;
        self.execute_ns += other.execute_ns;
        self.commit_ns += other.commit_ns;
        self.total_ns += other.total_ns;
    }
};

pub const AtomicReplayBatchStats = struct {
    transactions: Atomic(u64) = Atomic(u64).init(0),
    preprocessed: Atomic(u64) = Atomic(u64).init(0),
    preprocess_errors: Atomic(u64) = Atomic(u64).init(0),
    execution_ok: Atomic(u64) = Atomic(u64).init(0),
    execution_err: Atomic(u64) = Atomic(u64).init(0),
    committed: Atomic(u64) = Atomic(u64).init(0),
    preprocess_ns: Atomic(u64) = Atomic(u64).init(0),
    geyser_parse_ns: Atomic(u64) = Atomic(u64).init(0),
    execute_ns: Atomic(u64) = Atomic(u64).init(0),
    commit_ns: Atomic(u64) = Atomic(u64).init(0),
    total_ns: Atomic(u64) = Atomic(u64).init(0),

    pub fn add(self: *AtomicReplayBatchStats, stats: ReplayBatchStats) void {
        _ = self.transactions.fetchAdd(stats.transactions, .monotonic);
        _ = self.preprocessed.fetchAdd(stats.preprocessed, .monotonic);
        _ = self.preprocess_errors.fetchAdd(stats.preprocess_errors, .monotonic);
        _ = self.execution_ok.fetchAdd(stats.execution_ok, .monotonic);
        _ = self.execution_err.fetchAdd(stats.execution_err, .monotonic);
        _ = self.committed.fetchAdd(stats.committed, .monotonic);
        _ = self.preprocess_ns.fetchAdd(stats.preprocess_ns, .monotonic);
        _ = self.geyser_parse_ns.fetchAdd(stats.geyser_parse_ns, .monotonic);
        _ = self.execute_ns.fetchAdd(stats.execute_ns, .monotonic);
        _ = self.commit_ns.fetchAdd(stats.commit_ns, .monotonic);
        _ = self.total_ns.fetchAdd(stats.total_ns, .monotonic);
    }

    pub fn snapshot(self: *const AtomicReplayBatchStats) ReplayBatchStats {
        return .{
            .transactions = self.transactions.load(.monotonic),
            .preprocessed = self.preprocessed.load(.monotonic),
            .preprocess_errors = self.preprocess_errors.load(.monotonic),
            .execution_ok = self.execution_ok.load(.monotonic),
            .execution_err = self.execution_err.load(.monotonic),
            .committed = self.committed.load(.monotonic),
            .preprocess_ns = self.preprocess_ns.load(.monotonic),
            .geyser_parse_ns = self.geyser_parse_ns.load(.monotonic),
            .execute_ns = self.execute_ns.load(.monotonic),
            .commit_ns = self.commit_ns.load(.monotonic),
            .total_ns = self.total_ns.load(.monotonic),
        };
    }
};

pub const ReplayBatchOutcome = struct {
    result: BatchResult,
    stats: ReplayBatchStats,
};

pub const PreprocessedTransaction = struct {
    result: PreprocessTransactionResult,
    elapsed_ns: u64,
};

pub fn logReplayBatchStats(
    logger: anytype,
    slot: Slot,
    mode: []const u8,
    total_ns: u64,
    stats: ReplayBatchStats,
) void {
    logger.info().logf(
        "slot_replay_timings slot={} mode={s} total={D} replay_batch_total={D} preprocess={D} geyser_parse={D} execute={D} commit={D} transactions={} preprocessed={} preprocess_errors={} execution_ok={} execution_err={} committed={}",
        .{
            slot,
            mode,
            total_ns,
            stats.total_ns,
            stats.preprocess_ns,
            stats.geyser_parse_ns,
            stats.execute_ns,
            stats.commit_ns,
            stats.transactions,
            stats.preprocessed,
            stats.preprocess_errors,
            stats.execution_ok,
            stats.execution_err,
            stats.committed,
        },
    );
}

pub fn logProgramLoadStats(
    logger: anytype,
    metrics: replay.service.Metrics,
    slot: Slot,
    stats: sig.runtime.program_loader.ProgramLoadStats.Snapshot,
) void {
    metrics.program_cache_hits.set(stats.cache_hits);
    metrics.program_cache_misses.set(stats.cache_misses);
    metrics.program_load_attempts.set(stats.load_attempts);
    metrics.program_load_successes.set(stats.load_successes);
    metrics.program_load_failures.set(stats.load_failures);
    metrics.program_load_races.set(stats.load_races);
    metrics.program_executable_bytes.set(stats.executable_bytes);
    metrics.programdata_reads.set(stats.programdata_reads);
    metrics.programdata_bytes.set(stats.programdata_bytes);
    metrics.programdata_read_time.observe(stats.programdata_read_ns);
    metrics.program_elf_load_time.observe(stats.elf_load_ns);
    metrics.program_verify_time.observe(stats.verify_ns);
    metrics.program_load_total_time.observe(stats.load_total_ns);

    logger.info().logf(
        "slot_program_load_stats slot={} cache_hits={} cache_misses={} load_attempts={} load_successes={} load_failures={} load_races={} executable_bytes={} programdata_reads={} borrowed_direct_programdata_reads={} programdata_bytes={} programdata_read={D} elf_load={D} verify={D} load_total={D}",
        .{
            slot,
            stats.cache_hits,
            stats.cache_misses,
            stats.load_attempts,
            stats.load_successes,
            stats.load_failures,
            stats.load_races,
            stats.executable_bytes,
            stats.programdata_reads,
            stats.borrowed_direct_programdata_reads,
            stats.programdata_bytes,
            stats.programdata_read_ns,
            stats.elf_load_ns,
            stats.verify_ns,
            stats.load_total_ns,
        },
    );
}

pub fn logSlotAccountCacheStats(
    logger: anytype,
    slot: Slot,
    stats: sig.accounts_db.SlotAccountCacheStats.Snapshot,
) void {
    logger.info().logf(
        "slot_account_cache_stats slot={} get_calls={} cache_hits={} cache_misses={} fallback_found={} fallback_missing={} fallback_time={D} fallback_cache_fills={} fallback_cache_fill_races={} fallback_tombstone_fills={} cache_puts={} cache_put_replacements={} deferred_puts={} deferred_unique_writes={} deferred_flush_writes={} deferred_flush_missing={} deferred_flush_time={D}",
        .{
            slot,
            stats.get_calls,
            stats.cache_hits,
            stats.cache_misses,
            stats.fallback_found,
            stats.fallback_missing,
            stats.fallback_ns,
            stats.fallback_cache_fills,
            stats.fallback_cache_fill_races,
            stats.fallback_tombstone_fills,
            stats.cache_puts,
            stats.cache_put_replacements,
            stats.deferred_puts,
            stats.deferred_unique_writes,
            stats.deferred_flush_writes,
            stats.deferred_flush_missing,
            stats.deferred_flush_ns,
        },
    );
}

pub fn flushDeferredSlotAccountCacheWrites(
    logger: anytype,
    maybe_cache: ?*SlotAccountCache,
) !void {
    const cache = maybe_cache orelse return;
    if (!cache.defer_writes) return;

    const db = cache.deferred_db orelse return;
    const slot = cache.deferred_slot;
    var timer = sig.time.Timer.start();
    var flush_writes: u64 = 0;
    var missing: u64 = 0;

    cache.lock.lockShared();
    defer cache.lock.unlockShared();

    for (cache.deferred_dirty.keys()) |pubkey| {
        const account = cache.accounts.get(pubkey) orelse {
            missing += 1;
            continue;
        };
        try db.put(slot, pubkey, account);
        flush_writes += 1;
    }

    const elapsed_ns = timer.read().asNanos();
    _ = cache.stats.deferred_flush_writes.fetchAdd(flush_writes, .monotonic);
    _ = cache.stats.deferred_flush_missing.fetchAdd(missing, .monotonic);
    _ = cache.stats.deferred_flush_ns.fetchAdd(elapsed_ns, .monotonic);

    logger.info().logf(
        "slot_account_cache_deferred_flush slot={} dirty_pubkeys={} writes={} missing={} time={D}",
        .{
            slot,
            cache.deferred_dirty.count(),
            flush_writes,
            missing,
            elapsed_ns,
        },
    );
}

/// Processes a batch of transactions by verifying their signatures and
/// executing them with the SVM.
pub fn replayBatch(
    persistent_allocator: Allocator,
    metrics: replay.service.Metrics,
    svm_gateway: *SvmGateway,
    committer: Committer,
    transactions: []const ResolvedTransaction,
    preprocessed_transactions: ?[]const PreprocessedTransaction,
    exit: *Atomic(bool),
) !ReplayBatchOutcome {
    return replayBatchWithArenaChild(
        persistent_allocator,
        persistent_allocator,
        metrics,
        svm_gateway,
        committer,
        transactions,
        preprocessed_transactions,
        exit,
    );
}

/// Uses a small stack-backed child allocator for the temporary replay arena.
/// The persistent allocator remains unchanged for state that outlives this call.
pub fn replayBatchWithTempStackArena(
    persistent_allocator: Allocator,
    metrics: replay.service.Metrics,
    svm_gateway: *SvmGateway,
    committer: Committer,
    transactions: []const ResolvedTransaction,
    preprocessed_transactions: ?[]const PreprocessedTransaction,
    exit: *Atomic(bool),
) !ReplayBatchOutcome {
    var stack_fallback = std.heap.stackFallback(64 * 1024, persistent_allocator);
    return replayBatchWithArenaChild(
        persistent_allocator,
        stack_fallback.get(),
        metrics,
        svm_gateway,
        committer,
        transactions,
        preprocessed_transactions,
        exit,
    );
}

fn replayBatchWithArenaChild(
    persistent_allocator: Allocator,
    arena_child_allocator: Allocator,
    metrics: replay.service.Metrics,
    svm_gateway: *SvmGateway,
    committer: Committer,
    transactions: []const ResolvedTransaction,
    preprocessed_transactions: ?[]const PreprocessedTransaction,
    exit: *Atomic(bool),
) !ReplayBatchOutcome {
    var zone = tracy.Zone.init(@src(), .{ .name = "replayBatch" });
    zone.value(transactions.len);
    defer zone.deinit();
    errdefer zone.color(0xFF0000);
    var batch_timer = sig.time.Timer.start();
    defer metrics.replay_batch_time.observe(batch_timer.read().asNanos());
    var stats = ReplayBatchStats{ .transactions = @intCast(transactions.len) };
    if (preprocessed_transactions) |preprocessed| {
        std.debug.assert(preprocessed.len == transactions.len);
    }

    // `gpa` allocations may be persisted to data structures, e.g.
    // - votes
    // - status_cache
    // - stakes_cache
    // - ProgramMap programs
    // Use this for all other allocations.
    var arena = std.heap.ArenaAllocator.init(arena_child_allocator);
    defer arena.deinit();
    const tmp_allocator = arena.allocator();

    // TODO: maybe do a MultiArrayList {Hash, ProcessedTransaction, ResolvedTransaction}

    const results = try tmp_allocator.alloc(
        struct { Hash, ProcessedTransaction },
        transactions.len,
    );
    // spy node: track only successful txs so commitTransactions always fires per slot
    const successful_txs = try tmp_allocator.alloc(ResolvedTransaction, transactions.len);
    var populated_count: usize = 0;
    defer {
        // Only deinit elements that were actually populated
        // TODO Better way to do this? Instead of tracking populated count. Maybe switch to array list?
        for (results[0..populated_count]) |*result| {
            result.*[1].deinit(tmp_allocator);
        }
        tmp_allocator.free(results);
        tmp_allocator.free(successful_txs);
    }

    for (transactions, 0..) |transaction, transaction_index| {
        if (exit.load(.monotonic)) {
            stats.total_ns = batch_timer.read().asNanos() +
                if (preprocessed_transactions != null) stats.preprocess_ns else 0;
            return .{ .result = .exit, .stats = stats };
        }

        const instruction_limit = svm_gateway.params.feature_set.active(
            .static_instruction_limit,
            svm_gateway.params.slot,
        );
        const preprocess_result = if (preprocessed_transactions) |preprocessed| blk: {
            const result = preprocessed[transaction_index];
            stats.preprocess_ns += result.elapsed_ns;
            break :blk result.result;
        } else blk: {
            var preprocess_timer = sig.time.Timer.start();
            const result = preprocessTransaction(
                transaction.transaction,
                .run_sig_verify,
                instruction_limit,
            );
            stats.preprocess_ns += preprocess_timer.read().asNanos();
            break :blk result;
        };
        const hash, const compute_budget_details = switch (preprocess_result) {
            .ok => |res| blk: {
                stats.preprocessed += 1;
                break :blk res;
            },
            .err => {
                stats.preprocess_errors += 1;
                continue; // spy node: skip tx with preprocess error, let slot complete
            },
        };

        const runtime_transaction = transaction.toRuntimeTransaction(hash, compute_budget_details);

        {
            var phase_timer = sig.time.Timer.start();
            pumpfun_parser.parseTransaction(
                &transaction.transaction,
                svm_gateway.params.slot,
                committer.geyser_writer,
            );
            pumpfun_parser.emitResolvedAccountMap(
                &transaction,
                svm_gateway.params.slot,
                committer.geyser_writer,
            );
            stats.geyser_parse_ns += phase_timer.read().asNanos();
        }

        const transaction_result = blk: {
            var phase_timer = sig.time.Timer.start();
            const result = try executeTransaction(
                persistent_allocator,
                tmp_allocator,
                svm_gateway,
                &runtime_transaction,
            );
            const elapsed_ns = phase_timer.read().asNanos();
            stats.execute_ns += elapsed_ns;
            metrics.execute_transaction_time.observe(elapsed_ns);
            break :blk result;
        };

        switch (transaction_result) {
            .ok => |result| {
                successful_txs[populated_count] = transaction;
                results[populated_count] = .{ hash, result };
                populated_count += 1;
                stats.execution_ok += 1;
            },
            .err => {
                stats.execution_err += 1;
                continue; // spy node: skip failed tx, let slot complete
            },
        }
    }
    {
        var phase_timer = sig.time.Timer.start();
        try committer.commitTransactions(
            persistent_allocator,
            tmp_allocator,
            svm_gateway.params.slot,
            successful_txs[0..populated_count],
            results[0..populated_count],
        );
        const elapsed_ns = phase_timer.read().asNanos();
        stats.commit_ns += elapsed_ns;
        stats.committed += populated_count;
        metrics.commit_transactions_time.observe(elapsed_ns);
    }

    stats.total_ns = batch_timer.read().asNanos() +
        if (preprocessed_transactions != null) stats.preprocess_ns else 0;
    return .{ .result = .success, .stats = stats };
}

const PreparedSlot = union(enum) {
    /// We have no entries available to verify for this slot. No work was done.
    empty,

    /// The slot was previously marked as dead (not this time), which means we
    /// don't need to do anything. see here that agave also does nothing:
    /// - [replay_active_bank](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/core/src/replay_stage.rs#L3005-L3007)
    /// - [process_replay_results](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/core/src/replay_stage.rs#L3088-L3091)
    dead,

    /// This validator is the leader for the slot, so there is nothing to
    /// replay.
    ///
    /// In agave, the `bank.is_complete()` path of process_replay_results is
    /// still potentially called even when leader, whereas dead slots skip that
    /// step. TODO: verify that it's actually possible/meaningful to reach that
    /// step. Maybe dead and leader can be treated the same way when processing
    /// replay results?
    leader,

    /// The slot may be confirmed using these inputs.
    confirm: ReplaySlotParams,
};

/// Collects all the data necessary to confirm a slot with replaySlot
///
/// - Initializes the ForkProgress in the progress map for the slot if necessary.
/// - Extracts the inputs for replaySlot from the ledger and the slot and epoch trackers.
///
/// Combines the logic of these agave functions, just without actually executing
/// the slot. So, where agave's `confirm_slot` calls `confirm_slot_entries`,
/// at that point, we just return all the prepared data, which can be passed
/// into replaySlot or replaySlotSync.
/// - [replay_active_bank](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/core/src/replay_stage.rs#L2979)
/// - [replay_blockstore_into_bank](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/core/src/replay_stage.rs#L2232)
/// - [confirm_slot](https://github.com/anza-xyz/agave/blob/d79257e5f4afca4d092793f7a1e854cd5ccd6be9/ledger/src/blockstore_processor.rs#L1486)
fn prepareSlot(
    state: *ReplayState,
    metrics: replay.service.Metrics,
    slot_tracker: *SlotTracker,
    epoch_tracker: *sig.core.EpochTracker,
    slot: Slot,
    use_persistent_program_cache: bool,
) !PreparedSlot {
    var zone = tracy.Zone.init(@src(), .{ .name = "prepareSlot" });
    zone.value(slot);
    defer zone.deinit();
    errdefer zone.color(0xFF0000);
    var prepare_timer = sig.time.Timer.start();
    defer metrics.prepare_slot_time.observe(prepare_timer.read().asNanos());
    var phase_timer = sig.time.Timer.start();

    const progress_get_or_put = try state.progress_map.map.getOrPut(state.allocator, slot);
    if (progress_get_or_put.found_existing and progress_get_or_put.value_ptr.is_dead) {
        state.logger.info().logf("slot is dead: {}", .{slot});
        return .dead;
    }

    const epoch_info = try epoch_tracker.getEpochInfo(slot);
    defer epoch_info.release();
    const slot_info = slot_tracker.get(slot) orelse return error.MissingSlot;
    defer slot_info.release();

    const i_am_leader = slot_info.constants().collector_id.equals(&state.identity.validator);

    if (!progress_get_or_put.found_existing) {
        const parent_slot = slot_info.constants().parent_slot;
        const parent = state.progress_map.getForkProgress(parent_slot) orelse
            return error.MissingParentProgress;

        progress_get_or_put.value_ptr.* = try ForkProgress.initFromParent(state.allocator, .{
            .slot = slot,
            .parent_slot = parent_slot,
            .parent = parent,
            .slot_hash = slot_info.state().hash.readCopy(),
            .last_entry = slot_info.state().blockhash_queue.readField("last_hash") orelse
                return error.MissingLastHash,
            .i_am_leader = i_am_leader,
            .epoch_stakes = &epoch_info.stakes,
            .now = sig.time.Instant.now(),
            .validator_vote_pubkey = null, // voting not currently supported
        });
    }
    const fork_progress = progress_get_or_put.value_ptr;

    if (i_am_leader) {
        return .leader;
    }

    // NOTE: Agave acquires the confirmation_progress lock for the entirety of
    // confirm_slot execution, and then increments the values at the end of the
    // process. I don't think it matters that we're doing it all eagerly, but
    // it's worth reconsidering once we introduce actual locking here and flesh
    // out more usages of this struct.
    const confirmation_progress = &fork_progress.replay_progress.arc_ed.rwlock_ed;
    const progress_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    const previous_last_entry = confirmation_progress.last_entry;
    const entries, const slot_is_full = blk: {
        const entries, const num_shreds, const slot_is_full =
            state.ledger.reader().getSlotEntriesWithShredInfo(
                state.allocator,
                slot,
                confirmation_progress.num_shreds,
                false,
            ) catch |err| switch (err) {
                error.DeadSlot => {
                    state.logger.info().logf("slot is dead: {}", .{slot});
                    return .dead;
                },
                else => return err,
            };
        errdefer {
            for (entries) |entry| entry.deinit(state.allocator);
            state.allocator.free(entries);
        }

        state.execution_log_helper.logEntryCount(entries.len, slot);

        if (entries.len == 0) {
            return .empty;
        }

        confirmation_progress.last_entry = entries[entries.len - 1].hash;
        confirmation_progress.num_shreds += num_shreds;
        confirmation_progress.num_entries += entries.len;
        for (entries) |e| confirmation_progress.num_txs += e.transactions.len;

        break :blk .{ entries, slot_is_full };
    };
    const ledger_entries_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    const tick_height =
        slot_info.state().tick_height.fetchAdd(core.entry.tickCount(entries), .monotonic);

    const new_rate_activation_epoch =
        if (slot_info.constants().feature_set.get(.reduce_stake_warmup_cooldown)) |active_slot|
            epoch_tracker.epoch_schedule.getEpoch(active_slot)
        else
            null;

    const slot_account_reader = state.account_store.reader()
        .forSlot(&slot_info.constants().ancestors);

    const batch_compressed_accounts = envBool("SIG_REPLAY_BATCH_COMPRESSED_ACCOUNTS", false);
    if (batch_compressed_accounts and
        envBool("SIG_REPLAY_BATCH_COMPRESSED_ACCOUNTS_PRE_RESOLVE", true))
    {
        try batchDecodeCompressedAccountsFromEntries(
            state.allocator,
            metrics,
            slot,
            slot_account_reader,
            entries,
            envBool("SIG_REPLAY_BATCH_COMPRESSED_ACCOUNTS_PRE_RESOLVE_STATIC_KEYS", true),
        );
    }
    const pre_resolve_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    // TODO: Avoid the need to read this from accountsdb. We could broaden the
    // scope of the sysvar cache, add this to slot constants, or implement
    // additional mechanisms for lookup tables to detect slot age (e.g. block height).
    const slot_hashes = blk: {
        var metric_timer = sig.time.Timer.start();
        const hashes = try replay.update_sysvar.getSysvarFromAccount(
            SlotHashes,
            state.allocator,
            slot_account_reader,
        ) orelse return error.MissingSlotHashesSysvar;
        metrics.load_slot_hashes_time.observe(metric_timer.read().asNanos());
        break :blk hashes;
    };
    const slot_hashes_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    const parallel_resolve_block = envBool("SIG_REPLAY_PARALLEL_RESOLVE_BLOCK", false);
    const parallel_resolve_workers = blk: {
        const configured = envU64("SIG_REPLAY_PARALLEL_RESOLVE_BLOCK_WORKERS", 0);
        if (configured == 0) break :blk @as(usize, @intCast(state.thread_pool.max_threads));
        break :blk std.math.cast(usize, configured) orelse std.math.maxInt(usize);
    };
    const resolved_txns = blk: {
        var metric_timer = sig.time.Timer.start();
        const resolver: replay.resolve_lookup.SlotResolver = .{
            .slot = slot,
            .account_reader = slot_account_reader,
            .reserved_accounts = &slot_info.constants().reserved_accounts,
            .slot_hashes = slot_hashes,
            .logger = state.logger.withScope("replay-resolve"),
        };
        const txns = if (parallel_resolve_block)
            try replay.resolve_lookup.resolveBlockParallel(
                state.allocator,
                &state.thread_pool,
                parallel_resolve_workers,
                entries,
                resolver,
            )
        else
            try replay.resolve_lookup.resolveBlock(state.allocator, entries, resolver);
        metrics.resolve_block_time.observe(metric_timer.read().asNanos());
        break :blk txns;
    };
    const resolve_block_ns = phase_timer.read().asNanos();
    phase_timer.reset();
    errdefer {
        for (resolved_txns) |transaction| transaction.deinit(state.allocator);
        state.allocator.free(resolved_txns);
    }
    if (envBool("SIG_REPLAY_MEASURE_COMPRESSED_ACCOUNT_FANOUT", false)) {
        try measureCompressedAccountFanout(
            state.allocator,
            metrics,
            slot,
            slot_account_reader,
            resolved_txns,
        );
    }
    if (batch_compressed_accounts and
        envBool("SIG_REPLAY_BATCH_COMPRESSED_ACCOUNTS_POST_RESOLVE", true))
    {
        try batchDecodeCompressedAccountsFromResolved(
            state.allocator,
            metrics,
            slot,
            slot_account_reader,
            resolved_txns,
            envBool("SIG_REPLAY_BATCH_COMPRESSED_ACCOUNTS_POST_RESOLVE_WRITABLE", true),
        );
    }
    if (envBool("SIG_REPLAY_PREFETCH_COMPRESSED_CHUNKS", false)) {
        try prefetchCompressedAccountChunks(
            state.allocator,
            metrics,
            slot,
            slot_account_reader,
            resolved_txns,
        );
    }
    const post_resolve_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    const persistent_program_map = if (use_persistent_program_cache) blk: {
        const parent_slot = slot_info.constants().parent_slot;
        const epoch = epoch_tracker.epoch_schedule.getEpoch(slot);
        const preparation = state.preparePersistentProgramMap(slot, parent_slot, epoch);
        state.logger.info().logf(
            "persistent_program_cache slot={} parent_slot={} epoch={} source={s} entries_before={} failed_entries_removed={}",
            .{
                slot,
                parent_slot,
                epoch,
                if (preparation.reused_parent) "parent" else "empty",
                preparation.entries_before,
                preparation.failed_entries_removed,
            },
        );
        break :blk preparation.map;
    } else null;
    const programdata_program_map = if (envBool("SIG_REPLAY_SLOT_READ_FRAME_SKIP_CACHED_PROGRAMDATA", false)) persistent_program_map else null;

    var slot_account_cache: ?*SlotAccountCache = null;
    errdefer destroySlotAccountCache(state.allocator, slot_account_cache);

    const execution_account_store = if (envBool("SIG_REPLAY_SLOT_READ_FRAME", false))
        try buildSlotReadFrameAccountStore(
            state.allocator,
            .from(state.logger),
            metrics,
            slot,
            state.account_store,
            &slot_info.constants().ancestors,
            slot_account_reader,
            resolved_txns,
            programdata_program_map,
            &slot_account_cache,
        )
    else if (envBool("SIG_REPLAY_SLOT_ACCOUNT_CACHE", false))
        try buildCachedSlotAccountStore(
            state.allocator,
            metrics,
            slot,
            state.account_store,
            &slot_info.constants().ancestors,
            slot_account_reader,
            resolved_txns,
            &slot_account_cache,
        )
    else
        state.account_store.forSlot(slot, &slot_info.constants().ancestors);
    const read_frame_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    var svm_gateway = try SvmGateway.init(state.allocator, .{
        .slot = slot,
        .max_age = sig.core.BlockhashQueue.MAX_RECENT_BLOCKHASHES / 2,
        .lamports_per_signature = slot_info.constants().fee_rate_governor.lamports_per_signature,
        .blockhash_queue = &slot_info.state().blockhash_queue,
        .account_store = execution_account_store,
        .ancestors = &slot_info.constants().ancestors,
        .feature_set = slot_info.constants().feature_set,
        .rent_collector = &slot_info.constants().rent_collector,
        .epoch_stakes = &epoch_info.stakes,
        .status_cache = &state.status_cache,
        .program_map = persistent_program_map,
    });
    errdefer svm_gateway.deinit(state.allocator);
    const svm_gateway_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    const committer = replay.Committer{
        .logger = .from(state.logger),
        .slot_state = slot_info.state(),
        .status_cache = &state.status_cache,
        .stakes_cache = &slot_info.state().stakes_cache,
        .new_rate_activation_epoch = new_rate_activation_epoch,
        .replay_votes_sender = state.replay_votes_channel,
        .ledger = state.ledger,
        .disable_transaction_status_writes = state.disable_transaction_status_writes,
        .account_store = svm_gateway.params.account_store,
        .geyser_writer = state.geyser_writer,
    };

    const verify_ticks_params = replay.execution.VerifyTicksParams{
        .tick_height = tick_height,
        .max_tick_height = slot_info.constants().max_tick_height,
        .hashes_per_tick = epoch_tracker.cluster.hashes_per_tick,
        .slot = slot,
        .slot_is_full = slot_is_full,
        // TODO: come up with a better approach
        .tick_hash_count = &confirmation_progress.tick_hash_count,
    };

    const prepared: PreparedSlot = .{ .confirm = .{
        .entries = entries,
        .transactions = resolved_txns,
        .last_entry = previous_last_entry,
        .svm_gateway = svm_gateway,
        .committer = committer,
        .verify_ticks_params = verify_ticks_params,
        .account_store = state.account_store,
        .slot_account_cache = slot_account_cache,
    } };
    const finalize_ns = phase_timer.read().asNanos();
    const total_ns = prepare_timer.read().asNanos();
    const known_ns = progress_ns + ledger_entries_ns + pre_resolve_ns + slot_hashes_ns +
        resolve_block_ns + post_resolve_ns + read_frame_ns + svm_gateway_ns + finalize_ns;
    const unattributed_ns = total_ns -| known_ns;
    state.logger.info().logf(
        "slot_prepare_timing slot={} resolve_mode={s} progress_ns={} ledger_entries_ns={} pre_resolve_ns={} slot_hashes_ns={} resolve_block_ns={} post_resolve_ns={} read_frame_ns={} svm_gateway_ns={} finalize_ns={} unattributed_ns={} total_ns={}",
        .{
            slot,
            if (parallel_resolve_block) "parallel" else "serial",
            progress_ns,
            ledger_entries_ns,
            pre_resolve_ns,
            slot_hashes_ns,
            resolve_block_ns,
            post_resolve_ns,
            read_frame_ns,
            svm_gateway_ns,
            finalize_ns,
            unattributed_ns,
            total_ns,
        },
    );
    return prepared;
}

pub fn destroySlotAccountCache(allocator: Allocator, maybe_cache: ?*SlotAccountCache) void {
    if (maybe_cache) |cache| {
        cache.deinit();
        allocator.destroy(cache);
    }
}

fn buildSlotReadFrameAccountStore(
    allocator: Allocator,
    logger: Logger,
    metrics: replay.service.Metrics,
    slot: Slot,
    account_store: AccountStore,
    ancestors: *const Ancestors,
    account_reader: sig.accounts_db.SlotAccountReader,
    transactions: []const ResolvedTransaction,
    programdata_program_map: ?*sig.runtime.program_loader.ProgramMap,
    slot_account_cache: *?*SlotAccountCache,
) !sig.accounts_db.SlotAccountStore {
    const base_slot_account_store = account_store.forSlot(slot, ancestors);
    const db = switch (account_store) {
        .accounts_db => |db| db,
        else => return base_slot_account_store,
    };

    const cache = try allocator.create(SlotAccountCache);
    cache.* = SlotAccountCache.init(allocator);
    configureDeferredSlotAccountWrites(cache, db, slot);
    errdefer {
        cache.deinit();
        allocator.destroy(cache);
    }

    try populateSlotReadFrame(
        allocator,
        logger,
        metrics,
        slot,
        cache,
        account_reader,
        transactions,
        programdata_program_map,
    );

    slot_account_cache.* = cache;
    return .{ .cached_accounts_db = .{
        db,
        slot,
        ancestors,
        allocator,
        &cache.lock,
        &cache.accounts,
        &cache.borrowed_accounts,
        &cache.account_data_lens,
        &cache.stats,
        &cache.deferred_dirty,
        cache.defer_writes,
    } };
}

fn populateSlotReadFrame(
    allocator: Allocator,
    logger: Logger,
    metrics: replay.service.Metrics,
    slot: Slot,
    cache: *SlotAccountCache,
    account_reader: sig.accounts_db.SlotAccountReader,
    transactions: []const ResolvedTransaction,
    programdata_program_map: ?*sig.runtime.program_loader.ProgramMap,
) !void {
    var timer = sig.time.Timer.start();
    var phase_timer = sig.time.Timer.start();

    const PubkeyNeed = struct {
        refs: u32 = 0,
        writable: bool = false,
    };

    const WritableCandidate = struct {
        pubkey: sig.core.Pubkey,
        refs: u32,

        fn lessThan(_: void, a: @This(), b: @This()) bool {
            if (a.refs == b.refs) return comparePubkey(a.pubkey, b.pubkey) < 0;
            return a.refs > b.refs;
        }
    };

    var unique_pubkeys: sig.utils.collections.PubkeyMap(PubkeyNeed) = .{};
    defer unique_pubkeys.deinit(allocator);

    var account_refs: u64 = 0;
    for (transactions) |transaction| {
        for (
            transaction.accounts.items(.pubkey),
            transaction.accounts.items(.is_writable),
        ) |pubkey, is_writable| {
            account_refs += 1;
            const pubkey_gop = try unique_pubkeys.getOrPut(allocator, pubkey);
            if (!pubkey_gop.found_existing) pubkey_gop.value_ptr.* = .{};
            pubkey_gop.value_ptr.refs +|= 1;
            pubkey_gop.value_ptr.writable = pubkey_gop.value_ptr.writable or is_writable;
        }
    }
    const collect_needs_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    var selected_pubkeys: std.ArrayListUnmanaged(sig.core.Pubkey) = .{};
    defer selected_pubkeys.deinit(allocator);
    try selected_pubkeys.ensureTotalCapacity(allocator, unique_pubkeys.count());

    const include_writable =
        envBool("SIG_REPLAY_SLOT_READ_FRAME_INCLUDE_WRITABLE", false);
    const writable_min_refs =
        envU64("SIG_REPLAY_SLOT_READ_FRAME_WRITABLE_MIN_REFS", 0);
    const writable_max_pubkeys =
        envU64("SIG_REPLAY_SLOT_READ_FRAME_MAX_WRITABLE_PUBKEYS", 0);

    var selected_writable_pubkeys: sig.utils.collections.PubkeyMap(void) = .{};
    defer selected_writable_pubkeys.deinit(allocator);
    var writable_hot_candidates: u64 = 0;
    if (!include_writable and writable_min_refs > 0) {
        var writable_candidates: std.ArrayListUnmanaged(WritableCandidate) = .{};
        defer writable_candidates.deinit(allocator);

        for (unique_pubkeys.keys(), unique_pubkeys.values()) |pubkey, need| {
            if (!need.writable) continue;
            if (need.refs < writable_min_refs) continue;
            writable_hot_candidates += 1;
            try writable_candidates.append(allocator, .{
                .pubkey = pubkey,
                .refs = need.refs,
            });
        }

        std.mem.sort(WritableCandidate, writable_candidates.items, {}, WritableCandidate.lessThan);
        const selected_count: usize =
            if (writable_max_pubkeys == 0 or writable_max_pubkeys > writable_candidates.items.len)
                writable_candidates.items.len
            else
                @intCast(writable_max_pubkeys);
        try selected_writable_pubkeys.ensureTotalCapacity(allocator, selected_count);
        for (writable_candidates.items[0..selected_count]) |candidate| {
            selected_writable_pubkeys.putAssumeCapacity(candidate.pubkey, {});
        }
    }

    var readonly_included: u64 = 0;
    var writable_included: u64 = 0;
    var writable_skipped: u64 = 0;
    for (unique_pubkeys.keys(), unique_pubkeys.values()) |pubkey, need| {
        const is_writable = need.writable;
        const include_this_writable =
            include_writable or selected_writable_pubkeys.contains(pubkey);
        if (is_writable and !include_this_writable) {
            writable_skipped += 1;
            continue;
        }
        if (is_writable) {
            writable_included += 1;
        } else {
            readonly_included += 1;
        }
        selected_pubkeys.appendAssumeCapacity(pubkey);
    }

    std.mem.sort(sig.core.Pubkey, selected_pubkeys.items, {}, struct {
        fn lessThan(_: void, a: sig.core.Pubkey, b: sig.core.Pubkey) bool {
            return comparePubkey(a, b) < 0;
        }
    }.lessThan);
    const select_pubkeys_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    const batch_unrooted =
        envBool("SIG_REPLAY_SLOT_READ_FRAME_BATCH_UNROOTED", false);
    const borrow_decoded_account_cache =
        envBool("SIG_REPLAY_SLOT_READ_FRAME_BORROW_DECODED_ACCOUNT_CACHE", false);
    const unrooted_result = if (batch_unrooted)
        try account_reader.batchLoadUnrootedAccounts(
            allocator,
            selected_pubkeys.items,
            &cache.accounts,
        )
    else
        sig.accounts_db.Unrooted.BatchLoadResult{
            .pubkeys = @intCast(selected_pubkeys.items.len),
        };
    const unrooted_preload_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    var frame_pubkeys: std.ArrayListUnmanaged(sig.core.Pubkey) = .{};
    defer frame_pubkeys.deinit(allocator);
    try frame_pubkeys.ensureTotalCapacity(allocator, selected_pubkeys.items.len);
    for (selected_pubkeys.items) |pubkey| {
        if (!cache.containsAccount(pubkey)) frame_pubkeys.appendAssumeCapacity(pubkey);
    }
    const frame_filter_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    const chunk_hotness = if (envBool("SIG_REPLAY_SLOT_READ_FRAME_MEASURE_CHUNK_HOTNESS", false))
        try measureSlotReadFrameChunkHotness(allocator, account_reader, frame_pubkeys.items)
    else
        SlotReadFrameChunkHotness{};
    const chunk_hotness_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    const result = if (borrow_decoded_account_cache)
        try account_reader.batchLoadCompressedAccountsBorrowed(
            allocator,
            frame_pubkeys.items,
            &cache.accounts,
            &cache.borrowed_accounts,
        )
    else
        try account_reader.batchLoadCompressedAccounts(
            allocator,
            frame_pubkeys.items,
            &cache.accounts,
        );
    const compressed_load_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    const unrooted_skipped = unrooted_result.resolved;
    const unrooted_accounts_loaded = unrooted_result.loaded;
    const unrooted_accounts_missing = unrooted_result.tombstones;
    var tombstone_pubkeys: u64 = unrooted_result.tombstones;
    for (frame_pubkeys.items) |pubkey| {
        if (cache.containsAccount(pubkey)) continue;
        try cache.accounts.put(allocator, pubkey, AccountSharedData.EMPTY);
        tombstone_pubkeys += 1;
    }
    const tombstone_fill_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    var programdata_seen: sig.utils.collections.PubkeyMap(void) = .{};
    defer programdata_seen.deinit(allocator);
    var programdata_pubkeys: std.ArrayListUnmanaged(sig.core.Pubkey) = .{};
    defer programdata_pubkeys.deinit(allocator);
    var cached_programs_skipped: u64 = 0;
    try collectLoaderV3ProgramDataPubkeys(
        allocator,
        cache,
        programdata_program_map,
        &cached_programs_skipped,
        &programdata_seen,
        &programdata_pubkeys,
    );

    var programdata_missing_pubkeys: std.ArrayListUnmanaged(sig.core.Pubkey) = .{};
    defer programdata_missing_pubkeys.deinit(allocator);
    try programdata_missing_pubkeys.ensureTotalCapacity(allocator, programdata_pubkeys.items.len);

    for (programdata_pubkeys.items) |pubkey| {
        if (cache.containsAccount(pubkey)) continue;
        programdata_missing_pubkeys.appendAssumeCapacity(pubkey);
    }

    std.mem.sort(sig.core.Pubkey, programdata_missing_pubkeys.items, {}, struct {
        fn lessThan(_: void, a: sig.core.Pubkey, b: sig.core.Pubkey) bool {
            return comparePubkey(a, b) < 0;
        }
    }.lessThan);
    const programdata_collect_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    const preload_programdata_accounts =
        envBool("SIG_REPLAY_SLOT_READ_FRAME_PRELOAD_PROGRAMDATA_ACCOUNTS", true);
    var programdata_data_len_found: u64 = 0;
    var programdata_data_len_missing: u64 = 0;
    if (!preload_programdata_accounts) {
        for (programdata_missing_pubkeys.items) |pubkey| {
            const data_len = try account_reader.accountDataLen(allocator, pubkey);
            try cache.account_data_lens.put(allocator, pubkey, data_len);
            if (data_len != null) {
                programdata_data_len_found += 1;
            } else {
                programdata_data_len_missing += 1;
            }
        }
    }
    const programdata_data_len_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    const programdata_unrooted_result = if (preload_programdata_accounts and batch_unrooted)
        try account_reader.batchLoadUnrootedAccounts(
            allocator,
            programdata_missing_pubkeys.items,
            &cache.accounts,
        )
    else
        sig.accounts_db.Unrooted.BatchLoadResult{
            .pubkeys = if (preload_programdata_accounts)
                @intCast(programdata_missing_pubkeys.items.len)
            else
                0,
        };
    const programdata_unrooted_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    var programdata_rooted_pubkeys: std.ArrayListUnmanaged(sig.core.Pubkey) = .{};
    defer programdata_rooted_pubkeys.deinit(allocator);
    try programdata_rooted_pubkeys.ensureTotalCapacity(allocator, programdata_missing_pubkeys.items.len);
    if (preload_programdata_accounts) {
        for (programdata_missing_pubkeys.items) |pubkey| {
            if (!cache.containsAccount(pubkey)) programdata_rooted_pubkeys.appendAssumeCapacity(pubkey);
        }
    }
    const programdata_filter_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    const programdata_result = if (preload_programdata_accounts and borrow_decoded_account_cache)
        try account_reader.batchLoadCompressedAccountsBorrowedPriority(
            allocator,
            programdata_rooted_pubkeys.items,
            &cache.accounts,
            &cache.borrowed_accounts,
        )
    else if (preload_programdata_accounts)
        try account_reader.batchLoadCompressedAccounts(
            allocator,
            programdata_rooted_pubkeys.items,
            &cache.accounts,
        )
    else
        sig.accounts_db.CompressedAccountStore.BatchDecodeResult{};
    const programdata_compressed_load_ns = phase_timer.read().asNanos();
    phase_timer.reset();

    var programdata_tombstone_pubkeys: u64 = programdata_unrooted_result.tombstones;
    for (programdata_rooted_pubkeys.items) |pubkey| {
        if (cache.containsAccount(pubkey)) continue;
        try cache.accounts.put(allocator, pubkey, AccountSharedData.EMPTY);
        tombstone_pubkeys += 1;
        programdata_tombstone_pubkeys += 1;
    }
    const programdata_tombstone_fill_ns = phase_timer.read().asNanos();

    if (try replay.warm_manifest.maybeRecordFromEnv(
        allocator,
        slot,
        frame_pubkeys.items,
        programdata_rooted_pubkeys.items,
    )) |recorded| {
        logger.info().logf(
            "replay_warm_manifest_recorded status=pass root_slot={} target_slot={} pubkeys={}",
            .{ recorded.root_slot, recorded.target_slot, recorded.pubkeys },
        );
    }

    const programdata_unrooted_loaded = programdata_unrooted_result.loaded;
    const programdata_unrooted_missing = programdata_unrooted_result.tombstones;

    const programdata_metadata_pubkeys = if (preload_programdata_accounts)
        0
    else
        programdata_missing_pubkeys.items.len;
    const programdata_preload_pubkeys = if (preload_programdata_accounts)
        programdata_missing_pubkeys.items.len
    else
        0;

    metrics.slot_read_frame_slot.set(slot);
    metrics.slot_read_frame_account_refs.set(account_refs);
    metrics.slot_read_frame_unique_pubkeys.set(@intCast(unique_pubkeys.count()));
    metrics.slot_read_frame_readonly_pubkeys.set(readonly_included);
    metrics.slot_read_frame_writable_skipped_pubkeys.set(writable_skipped);
    metrics.slot_read_frame_unrooted_skipped_pubkeys.set(unrooted_skipped);
    metrics.slot_read_frame_compressed_pubkeys.set(result.compressed_pubkeys);
    metrics.slot_read_frame_missing_pubkeys.set(result.missing_pubkeys);
    metrics.slot_read_frame_unique_chunks.set(result.unique_chunks);
    metrics.slot_read_frame_chunks_hot_before_load.set(chunk_hotness.hot_chunks);
    metrics.slot_read_frame_chunks_cold_before_load.set(chunk_hotness.cold_chunks);
    metrics.slot_read_frame_chunks_decoded.set(result.chunks_decoded);
    metrics.slot_read_frame_chunks_cached.set(result.chunks_cached);
    metrics.slot_read_frame_accounts_loaded.set(result.accounts_loaded);
    metrics.slot_read_frame_accounts_cached.set(result.accounts_cached);
    metrics.slot_read_frame_accounts_skipped.set(result.accounts_skipped);

    const elapsed_ns = timer.read().asNanos();
    metrics.slot_read_frame_time.observe(elapsed_ns);
    logger.info().logf(
        "slot_read_frame slot={} time={D} account_refs={} unique_pubkeys={} preload_pubkeys={} readonly_pubkeys={} writable_included_pubkeys={} writable_skipped_pubkeys={} writable_hot_min_refs={} writable_hot_max_pubkeys={} writable_hot_candidates={} unrooted_skipped_pubkeys={} unrooted_preload_pubkeys={} unrooted_accounts_loaded={} unrooted_accounts_missing={} tombstone_pubkeys={} compressed_pubkeys={} missing_pubkeys={} unique_chunks={} chunks_hot_before_load={} chunks_cold_before_load={} chunks_decoded={} chunks_cached={} accounts_loaded={} accounts_cached={} accounts_borrowed={} accounts_skipped={}",
        .{
            slot,
            elapsed_ns,
            account_refs,
            unique_pubkeys.count(),
            selected_pubkeys.items.len + programdata_preload_pubkeys,
            readonly_included,
            writable_included,
            writable_skipped,
            writable_min_refs,
            writable_max_pubkeys,
            writable_hot_candidates,
            unrooted_skipped,
            unrooted_result.resolved,
            unrooted_accounts_loaded,
            unrooted_accounts_missing,
            tombstone_pubkeys,
            result.compressed_pubkeys,
            result.missing_pubkeys,
            result.unique_chunks,
            chunk_hotness.hot_chunks,
            chunk_hotness.cold_chunks,
            result.chunks_decoded,
            result.chunks_cached,
            result.accounts_loaded,
            result.accounts_cached,
            result.accounts_borrowed,
            result.accounts_skipped,
        },
    );
    logger.info().logf(
        "slot_read_frame_programdata slot={} program_cache_filter_enabled={} cached_programs_skipped={} metadata_pubkeys={} metadata_found={} metadata_missing={} preload_enabled={} preload_pubkeys={} unrooted_pubkeys={} unrooted_loaded={} unrooted_missing={} tombstone_pubkeys={} compressed_pubkeys={} missing_pubkeys={} unique_chunks={} chunks_decoded={} chunks_cached={} accounts_loaded={} accounts_cached={} accounts_borrowed={} accounts_skipped={}",
        .{
            slot,
            programdata_program_map != null,
            cached_programs_skipped,
            programdata_metadata_pubkeys,
            programdata_data_len_found,
            programdata_data_len_missing,
            preload_programdata_accounts,
            programdata_preload_pubkeys,
            programdata_unrooted_result.resolved,
            programdata_unrooted_loaded,
            programdata_unrooted_missing,
            programdata_tombstone_pubkeys,
            programdata_result.compressed_pubkeys,
            programdata_result.missing_pubkeys,
            programdata_result.unique_chunks,
            programdata_result.chunks_decoded,
            programdata_result.chunks_cached,
            programdata_result.accounts_loaded,
            programdata_result.accounts_cached,
            programdata_result.accounts_borrowed,
            programdata_result.accounts_skipped,
        },
    );
    logger.info().logf(
        "slot_read_frame_phases slot={} total={D} collect_needs={D} select_pubkeys={D} unrooted_preload={D} frame_filter={D} chunk_hotness={D} compressed_load={D} tombstone_fill={D} programdata_collect={D} programdata_data_len={D} programdata_unrooted={D} programdata_filter={D} programdata_compressed_load={D} programdata_tombstone_fill={D}",
        .{
            slot,
            elapsed_ns,
            collect_needs_ns,
            select_pubkeys_ns,
            unrooted_preload_ns,
            frame_filter_ns,
            chunk_hotness_ns,
            compressed_load_ns,
            tombstone_fill_ns,
            programdata_collect_ns,
            programdata_data_len_ns,
            programdata_unrooted_ns,
            programdata_filter_ns,
            programdata_compressed_load_ns,
            programdata_tombstone_fill_ns,
        },
    );
    logSlotReadFrameCompressedPhases(logger, slot, "main", result);
    logSlotReadFrameCompressedPhases(logger, slot, "programdata", programdata_result);
}

fn logSlotReadFrameCompressedPhases(
    logger: Logger,
    slot: Slot,
    scope: []const u8,
    result: sig.accounts_db.CompressedAccountStore.BatchDecodeResult,
) void {
    logger.info().logf(
        "slot_read_frame_compressed_phases slot={} scope={s} total={D} index_lookup={D} index_records_read={} chunk_plan={D} cached_chunk_load={D} cold_chunk_load={D} cold_decompress_wall={D} cold_account_materialize={D} chunk_cache_insert={D} materialized_data_bytes={} borrowed_data_bytes={} decoded_cache_entries={} decoded_cache_bytes={} decoded_cache_max_entries={} decoded_cache_priority_entries={} decoded_cache_priority_reserve_entries={} decoded_cache_effective_max_entries={} decoded_cache_max_bytes={} decoded_cache_move_borrowed={} persistent_batch_pool={} decoded_cache_priority_insert_total={} decoded_cache_priority_skip_total={} decoded_cache_skip_entry_limit_total={} decoded_cache_skip_byte_limit_total={} decoded_cache_skip_oversize_total={} decoded_cache_skip_allocation_total={}",
        .{
            slot,
            scope,
            result.total_ns,
            result.index_lookup_ns,
            result.index_records_read,
            result.chunk_plan_ns,
            result.cached_chunk_load_ns,
            result.cold_chunk_load_ns,
            result.cold_decompress_wall_ns,
            result.cold_account_materialize_ns,
            result.chunk_cache_insert_ns,
            result.materialized_data_bytes,
            result.borrowed_data_bytes,
            result.decoded_cache_entries,
            result.decoded_cache_bytes,
            result.decoded_cache_max_entries,
            result.decoded_cache_priority_entries,
            result.decoded_cache_priority_reserve_entries,
            result.decoded_cache_effective_max_entries,
            result.decoded_cache_max_bytes,
            result.decoded_cache_move_borrowed,
            result.persistent_batch_pool,
            result.decoded_cache_priority_insert_total,
            result.decoded_cache_priority_skip_total,
            result.decoded_cache_skip_entry_limit_total,
            result.decoded_cache_skip_byte_limit_total,
            result.decoded_cache_skip_oversize_total,
            result.decoded_cache_skip_allocation_total,
        },
    );
    logger.info().logf(
        "slot_read_frame_chunk_cache slot={} scope={s} entries={} bytes={} max_entries={} max_bytes={} insert_total={} eviction_total={} byte_limit_eviction_total={} entry_limit_eviction_total={}",
        .{
            slot,
            scope,
            result.chunk_cache_entries,
            result.chunk_cache_bytes,
            result.chunk_cache_max_entries,
            result.chunk_cache_max_bytes,
            result.chunk_cache_insert_total,
            result.chunk_cache_eviction_total,
            result.chunk_cache_byte_limit_eviction_total,
            result.chunk_cache_entry_limit_eviction_total,
        },
    );
}

fn collectLoaderV3ProgramDataPubkeys(
    allocator: Allocator,
    cache: *const SlotAccountCache,
    program_map: ?*sig.runtime.program_loader.ProgramMap,
    cached_programs_skipped: *u64,
    seen: *sig.utils.collections.PubkeyMap(void),
    out: *std.ArrayListUnmanaged(sig.core.Pubkey),
) !void {
    for (cache.accounts.keys(), cache.accounts.values()) |program_address, *account| {
        try collectLoaderV3ProgramDataPubkey(
            allocator,
            cache,
            program_map,
            cached_programs_skipped,
            program_address,
            account,
            seen,
            out,
        );
    }
    for (cache.borrowed_accounts.keys(), cache.borrowed_accounts.values()) |program_address, account| {
        try collectLoaderV3ProgramDataPubkey(
            allocator,
            cache,
            program_map,
            cached_programs_skipped,
            program_address,
            account,
            seen,
            out,
        );
    }
}

fn collectLoaderV3ProgramDataPubkey(
    allocator: Allocator,
    cache: *const SlotAccountCache,
    program_map: ?*sig.runtime.program_loader.ProgramMap,
    cached_programs_skipped: *u64,
    program_address: sig.core.Pubkey,
    account: *const AccountSharedData,
    seen: *sig.utils.collections.PubkeyMap(void),
    out: *std.ArrayListUnmanaged(sig.core.Pubkey),
) !void {
    if (account.lamports == 0) return;
    if (!account.executable) return;
    if (!account.owner.equals(&bpf_loader.v3.ID)) return;
    // Transaction-listed ProgramData accounts are already part of the main
    // read frame. This only suppresses the derived secondary preload when the
    // fork-aware map already owns a successfully compiled program.
    if (program_map) |programs| {
        if (programs.containsLoaded(program_address)) {
            cached_programs_skipped.* += 1;
            return;
        }
    }

    const state = sig.bincode.readFromSlice(
        failing_allocator,
        bpf_loader.v3.State,
        account.data,
        .{},
    ) catch return;

    const programdata_address = switch (state) {
        .program => |program| program.programdata_address,
        else => return,
    };
    if (cache.containsAccount(programdata_address)) return;

    const gop = try seen.getOrPut(allocator, programdata_address);
    if (gop.found_existing) return;
    gop.value_ptr.* = {};
    try out.append(allocator, programdata_address);
}

test "slot read frame skips ProgramData only for loaded persistent programs" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0x4348494d455241);
    const random = prng.random();
    const program_address = sig.core.Pubkey.initRandom(random);
    const programdata_address = sig.core.Pubkey.initRandom(random);

    const program_elf = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
        std.math.maxInt(usize),
    );
    defer allocator.free(program_elf);
    const program_bytes, const programdata_bytes =
        try sig.runtime.program_loader.createV3ProgramAccountData(
            allocator,
            programdata_address,
            42,
            null,
            program_elf,
        );
    defer allocator.free(program_bytes);
    defer allocator.free(programdata_bytes);

    const program_account = AccountSharedData{
        .lamports = 1,
        .owner = bpf_loader.v3.ID,
        .data = program_bytes,
        .executable = true,
        .rent_epoch = std.math.maxInt(u64),
    };
    const programdata_account = AccountSharedData{
        .lamports = 1,
        .owner = program_address,
        .data = programdata_bytes,
        .executable = false,
        .rent_epoch = std.math.maxInt(u64),
    };

    var source_accounts = sig.utils.collections.PubkeyMap(AccountSharedData){};
    defer source_accounts.deinit(allocator);
    try source_accounts.put(allocator, program_address, program_account);
    try source_accounts.put(allocator, programdata_address, programdata_account);

    var loaded_programs = try sig.runtime.program_loader.testLoad(
        allocator,
        &source_accounts,
        &.ALL_ENABLED,
        43,
    );
    defer loaded_programs.deinit(allocator);
    try std.testing.expect(loaded_programs.containsLoaded(program_address));

    var cache = SlotAccountCache.init(allocator);
    defer cache.deinit();
    try cache.borrowed_accounts.put(allocator, program_address, &program_account);

    var seen: sig.utils.collections.PubkeyMap(void) = .{};
    defer seen.deinit(allocator);
    var out: std.ArrayListUnmanaged(sig.core.Pubkey) = .{};
    defer out.deinit(allocator);

    var skipped: u64 = 0;
    try collectLoaderV3ProgramDataPubkeys(
        allocator,
        &cache,
        &loaded_programs,
        &skipped,
        &seen,
        &out,
    );
    try std.testing.expectEqual(1, skipped);
    try std.testing.expectEqual(0, out.items.len);

    var failed_programs = sig.runtime.program_loader.ProgramMap.empty;
    defer failed_programs.deinit(allocator);
    try std.testing.expect(try failed_programs.putIfAbsent(
        allocator,
        program_address,
        .failed,
    ));
    seen.clearRetainingCapacity();
    out.clearRetainingCapacity();
    skipped = 0;
    try collectLoaderV3ProgramDataPubkeys(
        allocator,
        &cache,
        &failed_programs,
        &skipped,
        &seen,
        &out,
    );
    try std.testing.expectEqual(0, skipped);
    try std.testing.expectEqualSlices(
        sig.core.Pubkey,
        &.{programdata_address},
        out.items,
    );

    try cache.borrowed_accounts.put(
        allocator,
        programdata_address,
        &programdata_account,
    );
    seen.clearRetainingCapacity();
    out.clearRetainingCapacity();
    skipped = 0;
    try collectLoaderV3ProgramDataPubkeys(
        allocator,
        &cache,
        null,
        &skipped,
        &seen,
        &out,
    );
    try std.testing.expectEqual(0, skipped);
    try std.testing.expectEqual(0, out.items.len);
}

const SlotReadFrameChunkHotness = struct {
    compressed_pubkeys: u64 = 0,
    missing_pubkeys: u64 = 0,
    unique_chunks: u64 = 0,
    hot_chunks: u64 = 0,
    cold_chunks: u64 = 0,
};

fn measureSlotReadFrameChunkHotness(
    allocator: Allocator,
    account_reader: sig.accounts_db.SlotAccountReader,
    readonly_pubkeys: []const sig.core.Pubkey,
) !SlotReadFrameChunkHotness {
    var result: SlotReadFrameChunkHotness = .{};

    var unique_chunks: std.AutoHashMapUnmanaged(u32, void) = .{};
    defer unique_chunks.deinit(allocator);

    for (readonly_pubkeys) |pubkey| {
        const chunk_id = try account_reader.compressedAccountChunkId(pubkey) orelse {
            result.missing_pubkeys += 1;
            continue;
        };
        result.compressed_pubkeys += 1;

        const gop = try unique_chunks.getOrPut(allocator, chunk_id);
        if (gop.found_existing) continue;
        gop.value_ptr.* = {};

        if (account_reader.compressedAccountChunkCached(chunk_id)) {
            result.hot_chunks += 1;
        } else {
            result.cold_chunks += 1;
        }
    }

    result.unique_chunks = @intCast(unique_chunks.count());
    return result;
}

fn buildCachedSlotAccountStore(
    allocator: Allocator,
    metrics: replay.service.Metrics,
    slot: Slot,
    account_store: AccountStore,
    ancestors: *const Ancestors,
    account_reader: sig.accounts_db.SlotAccountReader,
    transactions: []const ResolvedTransaction,
    slot_account_cache: *?*SlotAccountCache,
) !sig.accounts_db.SlotAccountStore {
    const base_slot_account_store = account_store.forSlot(slot, ancestors);
    const db = switch (account_store) {
        .accounts_db => |db| db,
        else => return base_slot_account_store,
    };

    const cache = try allocator.create(SlotAccountCache);
    cache.* = SlotAccountCache.init(allocator);
    configureDeferredSlotAccountWrites(cache, db, slot);
    errdefer {
        cache.deinit();
        allocator.destroy(cache);
    }

    try populateSlotAccountCache(
        allocator,
        metrics,
        slot,
        cache,
        account_reader,
        transactions,
    );

    slot_account_cache.* = cache;
    return .{ .cached_accounts_db = .{
        db,
        slot,
        ancestors,
        allocator,
        &cache.lock,
        &cache.accounts,
        &cache.borrowed_accounts,
        &cache.account_data_lens,
        &cache.stats,
        &cache.deferred_dirty,
        cache.defer_writes,
    } };
}

fn configureDeferredSlotAccountWrites(
    cache: *SlotAccountCache,
    db: *sig.accounts_db.Db,
    slot: Slot,
) void {
    if (!envBool("SIG_REPLAY_DEFER_SLOT_ACCOUNT_WRITES", false)) return;
    cache.defer_writes = true;
    cache.deferred_db = db;
    cache.deferred_slot = slot;
}

fn populateSlotAccountCache(
    allocator: Allocator,
    metrics: replay.service.Metrics,
    slot: Slot,
    cache: *SlotAccountCache,
    account_reader: sig.accounts_db.SlotAccountReader,
    transactions: []const ResolvedTransaction,
) !void {
    var timer = sig.time.Timer.start();
    defer metrics.slot_account_cache_time.observe(timer.read().asNanos());

    const Candidate = struct {
        pubkey: sig.core.Pubkey,
        chunk_id: u32,

        fn lessThan(_: void, a: @This(), b: @This()) bool {
            if (a.chunk_id == b.chunk_id) {
                return comparePubkey(a.pubkey, b.pubkey) < 0;
            }
            return a.chunk_id < b.chunk_id;
        }
    };

    var unique_pubkeys: sig.utils.collections.PubkeyMap(void) = .{};
    defer unique_pubkeys.deinit(allocator);

    var account_refs: u64 = 0;
    for (transactions) |transaction| {
        for (transaction.accounts.items(.pubkey)) |pubkey| {
            account_refs += 1;
            const gop = try unique_pubkeys.getOrPut(allocator, pubkey);
            if (!gop.found_existing) gop.value_ptr.* = {};
        }
    }

    var candidates: std.ArrayListUnmanaged(Candidate) = .{};
    defer candidates.deinit(allocator);
    try candidates.ensureTotalCapacity(allocator, unique_pubkeys.count());

    for (unique_pubkeys.keys()) |pubkey| {
        const chunk_id = (try account_reader.compressedAccountChunkId(pubkey)) orelse
            std.math.maxInt(u32);
        candidates.appendAssumeCapacity(.{
            .pubkey = pubkey,
            .chunk_id = chunk_id,
        });
    }

    std.mem.sort(Candidate, candidates.items, {}, Candidate.lessThan);

    const max_pubkeys = envU64("SIG_REPLAY_SLOT_ACCOUNT_CACHE_MAX_PUBKEYS", 0);
    const candidate_count_u64: u64 = @intCast(candidates.items.len);
    const load_count: usize = if (max_pubkeys == 0 or max_pubkeys > candidate_count_u64)
        candidates.items.len
    else
        @intCast(max_pubkeys);

    var loaded_pubkeys: u64 = 0;
    var missing_pubkeys: u64 = 0;

    for (candidates.items[0..load_count]) |candidate| {
        var account = try account_reader.get(allocator, candidate.pubkey) orelse {
            missing_pubkeys += 1;
            continue;
        };
        var account_shared_data = AccountSharedData.fromAccount(allocator, &account) catch |err| {
            account.deinit(allocator);
            return err;
        };
        account.deinit(allocator);

        var owns_account = true;
        errdefer if (owns_account) account_shared_data.deinit(allocator);

        const gop = try cache.accounts.getOrPut(allocator, candidate.pubkey);
        if (gop.found_existing) gop.value_ptr.deinit(allocator);
        gop.value_ptr.* = account_shared_data;
        owns_account = false;
        loaded_pubkeys += 1;
    }

    metrics.slot_account_cache_slot.set(slot);
    metrics.slot_account_cache_account_refs.set(account_refs);
    metrics.slot_account_cache_unique_pubkeys.set(@intCast(unique_pubkeys.count()));
    metrics.slot_account_cache_loaded_pubkeys.set(loaded_pubkeys);
    metrics.slot_account_cache_missing_pubkeys.set(missing_pubkeys);
    metrics.slot_account_cache_limited_pubkeys.set(@intCast(candidates.items.len - load_count));
}

fn measureCompressedAccountFanout(
    allocator: Allocator,
    metrics: replay.service.Metrics,
    slot: Slot,
    account_reader: sig.accounts_db.SlotAccountReader,
    transactions: []const ResolvedTransaction,
) !void {
    var timer = sig.time.Timer.start();
    defer metrics.compressed_account_fanout_time.observe(timer.read().asNanos());

    var unique_pubkeys: sig.utils.collections.PubkeyMap(void) = .{};
    defer unique_pubkeys.deinit(allocator);

    var unique_chunks: std.AutoHashMapUnmanaged(u32, void) = .{};
    defer unique_chunks.deinit(allocator);

    var account_refs: u64 = 0;
    var compressed_pubkeys: u64 = 0;
    var missing_pubkeys: u64 = 0;

    for (transactions) |transaction| {
        for (transaction.accounts.items(.pubkey)) |pubkey| {
            account_refs += 1;
            const pubkey_gop = try unique_pubkeys.getOrPut(allocator, pubkey);
            if (pubkey_gop.found_existing) continue;
            pubkey_gop.value_ptr.* = {};

            if (try account_reader.compressedAccountChunkId(pubkey)) |chunk_id| {
                compressed_pubkeys += 1;
                try unique_chunks.put(allocator, chunk_id, {});
            } else {
                missing_pubkeys += 1;
            }
        }
    }

    metrics.compressed_account_fanout_slot.set(slot);
    metrics.compressed_account_fanout_account_refs.set(account_refs);
    metrics.compressed_account_fanout_unique_pubkeys.set(@intCast(unique_pubkeys.count()));
    metrics.compressed_account_fanout_compressed_pubkeys.set(compressed_pubkeys);
    metrics.compressed_account_fanout_unique_chunks.set(@intCast(unique_chunks.count()));
    metrics.compressed_account_fanout_missing_pubkeys.set(missing_pubkeys);
}

fn prefetchCompressedAccountChunks(
    allocator: Allocator,
    metrics: replay.service.Metrics,
    slot: Slot,
    account_reader: sig.accounts_db.SlotAccountReader,
    transactions: []const ResolvedTransaction,
) !void {
    var timer = sig.time.Timer.start();
    defer metrics.compressed_account_prefetch_time.observe(timer.read().asNanos());

    var unique_pubkeys: sig.utils.collections.PubkeyMap(void) = .{};
    defer unique_pubkeys.deinit(allocator);

    for (transactions) |transaction| {
        for (transaction.accounts.items(.pubkey)) |pubkey| {
            const gop = try unique_pubkeys.getOrPut(allocator, pubkey);
            if (!gop.found_existing) gop.value_ptr.* = {};
        }
    }

    const result = try account_reader.prefetchCompressedChunks(allocator, unique_pubkeys.keys());
    metrics.compressed_account_prefetch_slot.set(slot);
    metrics.compressed_account_prefetch_unique_pubkeys.set(@intCast(unique_pubkeys.count()));
    metrics.compressed_account_prefetch_compressed_pubkeys.set(result.compressed_pubkeys);
    metrics.compressed_account_prefetch_missing_pubkeys.set(result.missing_pubkeys);
    metrics.compressed_account_prefetch_unique_chunks.set(result.unique_chunks);
    metrics.compressed_account_prefetch_chunks_loaded.set(result.chunks_loaded);
    metrics.compressed_account_prefetch_chunks_cached.set(result.chunks_cached);
    metrics.compressed_account_prefetch_chunks_skipped.set(result.chunks_skipped);
}

fn batchDecodeCompressedAccountsFromEntries(
    allocator: Allocator,
    metrics: replay.service.Metrics,
    slot: Slot,
    account_reader: sig.accounts_db.SlotAccountReader,
    entries: []const Entry,
    include_static_keys: bool,
) !void {
    var unique_pubkeys: sig.utils.collections.PubkeyMap(void) = .{};
    defer unique_pubkeys.deinit(allocator);

    for (entries) |entry| {
        for (entry.transactions) |transaction| {
            if (include_static_keys) {
                for (transaction.msg.account_keys) |pubkey| {
                    const gop = try unique_pubkeys.getOrPut(allocator, pubkey);
                    if (!gop.found_existing) gop.value_ptr.* = {};
                }
            }
            for (transaction.msg.address_lookups) |lookup| {
                const gop = try unique_pubkeys.getOrPut(allocator, lookup.table_address);
                if (!gop.found_existing) gop.value_ptr.* = {};
            }
        }
    }

    try batchDecodeCompressedAccountPubkeys(
        allocator,
        metrics,
        slot,
        account_reader,
        unique_pubkeys.keys(),
    );
}

fn batchDecodeCompressedAccountsFromResolved(
    allocator: Allocator,
    metrics: replay.service.Metrics,
    slot: Slot,
    account_reader: sig.accounts_db.SlotAccountReader,
    transactions: []const ResolvedTransaction,
    include_writable_accounts: bool,
) !void {
    var unique_pubkeys: sig.utils.collections.PubkeyMap(void) = .{};
    defer unique_pubkeys.deinit(allocator);

    var writable_pubkeys: sig.utils.collections.PubkeyMap(void) = .{};
    defer writable_pubkeys.deinit(allocator);
    if (!include_writable_accounts) {
        for (transactions) |transaction| {
            for (
                transaction.accounts.items(.pubkey),
                transaction.accounts.items(.is_writable),
            ) |pubkey, is_writable| {
                if (!is_writable) continue;
                const gop = try writable_pubkeys.getOrPut(allocator, pubkey);
                if (!gop.found_existing) gop.value_ptr.* = {};
            }
        }
    }

    for (transactions) |transaction| {
        for (
            transaction.accounts.items(.pubkey),
            transaction.accounts.items(.is_writable),
        ) |pubkey, is_writable| {
            if (is_writable and !include_writable_accounts) continue;
            if (!include_writable_accounts and writable_pubkeys.contains(pubkey)) continue;
            const gop = try unique_pubkeys.getOrPut(allocator, pubkey);
            if (!gop.found_existing) gop.value_ptr.* = {};
        }
    }

    try batchDecodeCompressedAccountPubkeys(
        allocator,
        metrics,
        slot,
        account_reader,
        unique_pubkeys.keys(),
    );
}

fn batchDecodeCompressedAccountPubkeys(
    allocator: Allocator,
    metrics: replay.service.Metrics,
    slot: Slot,
    account_reader: sig.accounts_db.SlotAccountReader,
    pubkeys: []const sig.core.Pubkey,
) !void {
    var timer = sig.time.Timer.start();
    defer metrics.compressed_account_batch_decode_time.observe(timer.read().asNanos());

    const result = try account_reader.batchDecodeCompressedAccounts(allocator, pubkeys);
    metrics.compressed_account_batch_decode_slot.set(slot);
    metrics.compressed_account_batch_decode_unique_pubkeys.set(result.pubkeys);
    metrics.compressed_account_batch_decode_compressed_pubkeys.set(result.compressed_pubkeys);
    metrics.compressed_account_batch_decode_missing_pubkeys.set(result.missing_pubkeys);
    metrics.compressed_account_batch_decode_unique_chunks.set(result.unique_chunks);
    metrics.compressed_account_batch_decode_chunks_decoded.set(result.chunks_decoded);
    metrics.compressed_account_batch_decode_chunks_cached.set(result.chunks_cached);
    metrics.compressed_account_batch_decode_accounts_loaded.set(result.accounts_loaded);
    metrics.compressed_account_batch_decode_accounts_cached.set(result.accounts_cached);
    metrics.compressed_account_batch_decode_accounts_skipped.set(result.accounts_skipped);
}

fn comparePubkey(a: sig.core.Pubkey, b: sig.core.Pubkey) i8 {
    for (a.data, b.data) |x, y| {
        if (x < y) return -1;
        if (x > y) return 1;
    }
    return 0;
}

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

pub const VerifyTicksParams = struct {
    /// epoch-scoped constant
    hashes_per_tick: ?u64,

    // slot-scoped constants
    slot: u64,
    max_tick_height: u64,

    // slot-scoped state (constant during lifetime of this struct)
    /// the starting tick height before processing entries
    tick_height: u64,
    slot_is_full: bool,

    /// slot-scoped state (expected to be mutated while verifying ticks)
    tick_hash_count: *u64,
};

/// Verify that a segment of entries has the correct number of ticks and hashes
/// analogous to [verify_ticks](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/ledger/src/blockstore_processor.rs#L1097)
pub fn verifyTicks(
    logger: Logger,
    entries: []const Entry,
    params: VerifyTicksParams,
) ?BlockError {
    const next_tick_height = params.tick_height + sig.core.entry.tickCount(entries);

    if (next_tick_height > params.max_tick_height) {
        logger.warn().logf("Too many entry ticks found in slot: {}", .{params.slot});
        return .TooManyTicks;
    }

    if (next_tick_height < params.max_tick_height and params.slot_is_full) {
        logger.info().logf("Too few entry ticks found in slot: {}", .{params.slot});
        return .TooFewTicks;
    }

    if (next_tick_height == params.max_tick_height) {
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
pub const ReplaySlotError = union(enum) {
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

pub const LogHelper = struct {
    logger: Logger,
    // we store a hash of the previous set of active slots, to avoid printing duplicate sets
    last_active_slots_hash: ?Hash,
    slots_are_the_same: bool,

    pub fn init(logger: Logger) LogHelper {
        return .{
            .logger = logger,
            .last_active_slots_hash = null,
            .slots_are_the_same = false,
        };
    }

    pub fn logActiveSlots(self: *LogHelper, active_slots: []const u64) void {
        const active_slots_hash = Hash.init(std.mem.sliceAsBytes(active_slots));

        self.slots_are_the_same = if (self.last_active_slots_hash) |last_slots|
            active_slots_hash.eql(last_slots)
        else
            false;
        self.last_active_slots_hash = active_slots_hash;

        self.logger
            .entry(if (self.slots_are_the_same) .debug else .info)
            .logf("{} active slots to replay: {any}", .{ active_slots.len, active_slots });
    }

    pub fn logEntryCount(self: *LogHelper, entry_count: usize, slot: Slot) void {
        self.logger
            .entry(if (self.slots_are_the_same and entry_count == 0) .debug else .info)
            .logf("got {} entries for slot {}", .{ entry_count, slot });
    }
};

test "replaySlot - happy path: trivial case" {
    const allocator = std.testing.allocator;

    var tick_hash_count: u64 = 0;

    const params = VerifyTicksParams{
        .hashes_per_tick = 0,
        .slot = 0,
        .max_tick_height = 1,
        .tick_height = 0,
        .slot_is_full = false,
        .tick_hash_count = &tick_hash_count,
    };
    try testReplaySlot(allocator, null, &.{}, params, .ALL_DISABLED);
}

test "replaySlot - happy path: partial slot" {
    const allocator = std.testing.allocator;

    var tick_hash_count: u64 = 0;

    const poh, const entry_array = try sig.core.poh.testPoh(true, false);
    defer for (entry_array.slice()) |e| e.deinit(allocator);
    const entries: []const sig.core.Entry = entry_array.slice();

    const params = VerifyTicksParams{
        .hashes_per_tick = poh.hashes_per_tick,
        .slot = 0,
        .max_tick_height = poh.tick_count,
        .tick_height = 0,
        .slot_is_full = false,
        .tick_hash_count = &tick_hash_count,
    };
    try testReplaySlot(allocator, null, entries[0 .. entries.len - 1], params, .ALL_DISABLED);
}

test "replaySlot - conflicting accounts should fail until relax_intrabatch_account_locks is set" {
    const allocator = std.testing.allocator;

    const poh, var entry_array = try sig.core.poh.testPoh(true, true);
    defer for (entry_array.slice()) |e| e.deinit(allocator);
    const entries: []sig.core.Entry = entry_array.slice();

    var features = sig.core.FeatureSet.ALL_DISABLED;
    features.setSlot(.relax_intrabatch_account_locks, 0);

    for ([2]struct { sig.core.FeatureSet, ?ReplaySlotError }{
        .{ .ALL_DISABLED, .{ .invalid_transaction = .AccountInUse } },
        .{ features, null },
    }) |test_case| {
        const feature_set, const expected_error = test_case;
        var tick_hash_count: u64 = 0;

        const params = VerifyTicksParams{
            .hashes_per_tick = poh.hashes_per_tick,
            .slot = 0,
            .max_tick_height = poh.tick_count,
            .tick_height = 0,
            .slot_is_full = false,
            .tick_hash_count = &tick_hash_count,
        };
        try testReplaySlot(
            allocator,
            expected_error,
            entries[0 .. entries.len - 1],
            params,
            feature_set,
        );
    }
}

test "replaySlot - happy path: full slot" {
    const allocator = std.testing.allocator;

    var tick_hash_count: u64 = 0;

    const poh, const entry_array = try sig.core.poh.testPoh(true, false);
    defer for (entry_array.slice()) |e| e.deinit(allocator);
    const entries: []const sig.core.Entry = entry_array.slice();

    const params = VerifyTicksParams{
        .hashes_per_tick = poh.hashes_per_tick,
        .slot = 0,
        .max_tick_height = poh.tick_count,
        .tick_height = 0,
        .slot_is_full = true,
        .tick_hash_count = &tick_hash_count,
    };
    try testReplaySlot(allocator, null, entries, params, .ALL_DISABLED);
}

test "replaySlot - fail: full slot not marked full -> .InvalidLastTick" {
    const allocator = std.testing.allocator;

    var tick_hash_count: u64 = 0;

    const poh, const entry_array = try sig.core.poh.testPoh(true, false);
    defer for (entry_array.slice()) |e| e.deinit(allocator);
    const entries: []const sig.core.Entry = entry_array.slice();

    const params = VerifyTicksParams{
        .hashes_per_tick = poh.hashes_per_tick,
        .slot = 0,
        .max_tick_height = poh.tick_count,
        .tick_height = 0,
        .slot_is_full = false,
        .tick_hash_count = &tick_hash_count,
    };
    try testReplaySlot(
        allocator,
        ReplaySlotError{ .invalid_block = .InvalidLastTick },
        entries,
        params,
        .ALL_DISABLED,
    );
}

test "replaySlot - fail: no trailing tick at max height -> .TrailingEntry" {
    const allocator = std.testing.allocator;

    var tick_hash_count: u64 = 0;

    const poh, const entry_array = try sig.core.poh.testPoh(true, false);
    defer for (entry_array.slice()) |e| e.deinit(allocator);
    const entries: []const sig.core.Entry = entry_array.slice();

    const params = VerifyTicksParams{
        .hashes_per_tick = poh.hashes_per_tick,
        .slot = 0,
        .max_tick_height = poh.tick_count - 1,
        .tick_height = 0,
        .slot_is_full = false,
        .tick_hash_count = &tick_hash_count,
    };
    try testReplaySlot(
        allocator,
        ReplaySlotError{ .invalid_block = .TrailingEntry },
        entries[0 .. entries.len - 1],
        params,
        .ALL_DISABLED,
    );
}

test "replaySlot - fail: invalid poh chain" {
    const allocator = std.testing.allocator;

    var tick_hash_count: u64 = 0;

    const poh, var entry_array = try sig.core.poh.testPoh(true, false);
    defer for (entry_array.slice()) |e| e.deinit(allocator);
    const entries: []sig.core.Entry = entry_array.slice();

    // break the hash chain
    entries[0].hash.data[0] +%= 1;
    const params = VerifyTicksParams{
        .hashes_per_tick = poh.hashes_per_tick,
        .slot = 0,
        .max_tick_height = poh.tick_count,
        .tick_height = 0,
        .slot_is_full = true,
        .tick_hash_count = &tick_hash_count,
    };
    try testReplaySlot(
        allocator,
        ReplaySlotError{ .invalid_block = .InvalidEntryHash },
        entries,
        params,
        .ALL_DISABLED,
    );
}

test "replaySlot - fail: sigverify" {
    const allocator = std.testing.allocator;

    var tick_hash_count: u64 = 0;

    const poh, var entry_array = try sig.core.poh.testPoh(false, false);
    defer for (entry_array.slice()) |e| e.deinit(allocator);
    const entries: []sig.core.Entry = entry_array.slice();

    const params = VerifyTicksParams{
        .hashes_per_tick = poh.hashes_per_tick,
        .slot = 0,
        .max_tick_height = poh.tick_count,
        .tick_height = 0,
        .slot_is_full = true,
        .tick_hash_count = &tick_hash_count,
    };
    try testReplaySlot(
        allocator,
        ReplaySlotError{ .invalid_transaction = .SignatureFailure },
        entries,
        params,
        .ALL_DISABLED,
    );
}

test "prepareSlot: empty and dead slots are handled correctly" {
    const allocator = std.testing.allocator;

    var dep_stubs = try sig.replay.service.DependencyStubs.init(allocator, .FOR_TESTS);
    defer dep_stubs.deinit();

    var state = try dep_stubs.stubbedState(allocator, .FOR_TESTS);
    defer {
        state.deinit();
        state.epoch_tracker.deinit();
        allocator.destroy(state.epoch_tracker);
    }

    const root = state.slot_tracker.get(0);
    defer if (root) |r| r.release();

    const constants, const slot_state = try sig.replay.service.newSlotFromParent(
        allocator,
        .{ .accounts_db = &dep_stubs.accounts_db_state.db },
        state.epoch_tracker.cluster.ticks_per_slot,
        0,
        root.?.constants(),
        root.?.state(),
        .ZEROES,
        1,
        false,
        null,
    );

    try state.slot_tracker.put(allocator, 1, .{
        .constants = constants,
        .state = slot_state,
        .allocator = allocator,
    });

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();
    const metrics = try registry.initStruct(replay.service.Metrics);

    try std.testing.expectEqual(
        .empty,
        try prepareSlot(&state, metrics, &state.slot_tracker, state.epoch_tracker, 1, false),
    );

    try dep_stubs.ledger.resultWriter().setDeadSlot(1);

    try std.testing.expectEqual(
        .dead,
        try prepareSlot(&state, metrics, &state.slot_tracker, state.epoch_tracker, 1, false),
    );
}

fn testReplaySlot(
    allocator: Allocator,
    expected: ?ReplaySlotError,
    entries: []const Entry,
    verify_ticks_params: VerifyTicksParams,
    feature_set: sig.core.FeatureSet,
) !void {
    const logger: Logger = if (expected == null) .FOR_TESTS else .noop;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();
    const metrics = try registry.initStruct(replay.service.Metrics);

    const sync_result = result: {
        var state = try TestState.init(allocator);
        defer state.deinit(allocator);
        state.feature_set = feature_set;

        const params = try state.prepareSlotParams(allocator, entries, verify_ticks_params);
        break :result try replaySlotSync(allocator, logger, metrics, params);
    };

    verify_ticks_params.tick_hash_count.* = 0;

    const async_result = result: {
        var state = try TestState.init(allocator);
        defer state.deinit(allocator);
        state.feature_set = feature_set;

        const params = try state.prepareSlotParams(allocator, entries, verify_ticks_params);

        var thread_pool = ThreadPool.init(.{});
        defer {
            thread_pool.shutdown();
            thread_pool.deinit();
        }

        var result: ReplaySlotFuture.Result = undefined;
        {
            var wg = std.Thread.WaitGroup{};
            defer wg.wait();

            ReplaySlotFuture.startAsync(
                allocator,
                .from(logger),
                &thread_pool,
                &wg,
                metrics,
                params,
                &result,
            );
        }

        break :result switch ((try result).output) {
            .err => |e| e,
            .last_entry_hash => null,
        };
    };

    errdefer std.log.err("failed with: {any} - {any}\n", .{ async_result, sync_result });

    try std.testing.expectEqual(expected, async_result);
    try std.testing.expectEqual(expected, sync_result);
}

pub const TestState = struct {
    // shared for multiple things
    accounts_db: sig.accounts_db.Db.TestContext,
    status_cache: sig.core.StatusCache,
    ancestors: Ancestors,

    // svm params
    slot: u64,
    max_age: u64,
    lamports_per_signature: u64,
    blockhash_queue: sig.sync.RwMux(sig.core.BlockhashQueue),
    feature_set: sig.core.FeatureSet,
    rent_collector: sig.core.RentCollector,
    epoch_stakes: sig.core.EpochStakes,

    // committer
    slot_state: sig.core.SlotState,
    stakes_cache: sig.core.StakesCache,

    // resolver
    slot_hashes: SlotHashes,

    replay_votes_channel: *sig.sync.Channel(ParsedVote),
    exit: Atomic(bool),

    pub fn init(allocator: Allocator) !TestState {
        const epoch_stakes: sig.core.EpochStakes = .EMPTY;
        errdefer epoch_stakes.deinit(allocator);

        var slot_state: sig.core.SlotState = .GENESIS;
        errdefer slot_state.deinit(allocator);

        var stakes_cache = sig.core.StakesCache.EMPTY;
        errdefer stakes_cache.deinit(allocator);

        const max_age = sig.core.BlockhashQueue.MAX_RECENT_BLOCKHASHES / 2;
        var blockhash_queue = sig.core.BlockhashQueue.init(max_age);
        errdefer blockhash_queue.deinit(allocator);
        try blockhash_queue.insertGenesisHash(allocator, .ZEROES, 1);

        var ancestors: Ancestors = .{};
        errdefer ancestors.deinit(allocator);
        try ancestors.addSlot(allocator, 0);

        const replay_votes_channel: *sig.sync.Channel(ParsedVote) = try .create(allocator);

        var test_context = try sig.accounts_db.Db.initTest(allocator);
        errdefer test_context.deinit();

        return .{
            .accounts_db = test_context,
            .status_cache = .DEFAULT,
            .ancestors = ancestors,
            .slot = 0,
            .max_age = max_age,
            .lamports_per_signature = 5000,
            .blockhash_queue = .init(blockhash_queue),
            .feature_set = .ALL_DISABLED,
            .rent_collector = .DEFAULT,
            .epoch_stakes = epoch_stakes,
            .slot_state = slot_state,
            .stakes_cache = stakes_cache,
            .slot_hashes = .INIT,
            .replay_votes_channel = replay_votes_channel,
            .exit = .init(false),
        };
    }

    pub fn deinit(self: *TestState, allocator: Allocator) void {
        self.accounts_db.deinit();
        self.status_cache.deinit(allocator);
        self.ancestors.deinit(allocator);
        var bhq = self.blockhash_queue.tryWrite() orelse unreachable;
        bhq.get().deinit(allocator);
        bhq.unlock();
        self.epoch_stakes.deinit(allocator);
        self.slot_state.deinit(allocator);
        self.stakes_cache.deinit(allocator);
        while (self.replay_votes_channel.tryReceive()) |pv| pv.deinit(allocator);
        self.replay_votes_channel.destroy();
    }

    pub fn accountStore(self: *TestState) AccountStore {
        return .{ .accounts_db = &self.accounts_db.db };
    }

    pub fn svmParams(self: *TestState) SvmGateway.Params {
        return .{
            .slot = self.slot,
            .max_age = self.max_age,
            .lamports_per_signature = self.lamports_per_signature,
            .blockhash_queue = &self.blockhash_queue,
            .account_store = self.accountStore().forSlot(self.slot, &self.ancestors),
            .ancestors = &self.ancestors,
            .feature_set = self.feature_set,
            .rent_collector = &self.rent_collector,
            .epoch_stakes = &self.epoch_stakes,
            .status_cache = &self.status_cache,
        };
    }

    pub fn committer(self: *TestState) Committer {
        return .{
            .logger = .FOR_TESTS,
            .slot_state = &self.slot_state,
            .status_cache = &self.status_cache,
            .stakes_cache = &self.stakes_cache,
            .new_rate_activation_epoch = null,
            .replay_votes_sender = self.replay_votes_channel,
            .ledger = null,
            .account_store = null,
        };
    }

    pub fn resolver(self: *TestState) SlotResolver {
        return .{
            .slot = self.slot,
            .account_reader = .{ .accounts_db = .{ &self.accounts_db.db, &self.ancestors } },
            .reserved_accounts = &.empty,
            .slot_hashes = .INIT,
        };
    }

    pub fn prepareSlotParams(
        self: *TestState,
        allocator: Allocator,
        entries: []const Entry,
        verify_ticks_params: VerifyTicksParams,
    ) !ReplaySlotParams {
        const entries_copy = try allocator.dupe(Entry, entries);
        errdefer allocator.free(entries_copy);

        for (entries_copy, 0..) |*entry, i| {
            errdefer for (entries_copy[0..i]) |e| e.deinit(allocator);
            entry.* = try entries[i].clone(allocator);
            try self.makeTransactionsPassable(allocator, entry.transactions);
        }
        errdefer for (entries_copy) |e| e.deinit(allocator);

        const transactions =
            try replay.resolve_lookup.resolveBlock(allocator, entries_copy, self.resolver());
        errdefer {
            for (transactions) |t| t.deinit(allocator);
            allocator.free(transactions);
        }

        const svm_gateway = try SvmGateway.init(allocator, self.svmParams());
        errdefer svm_gateway.deinit(allocator);

        return .{
            .entries = entries_copy,
            .transactions = transactions,
            .last_entry = .ZEROES,
            .svm_gateway = svm_gateway,
            .committer = self.committer(),
            .verify_ticks_params = verify_ticks_params,
            .account_store = self.accountStore(),
        };
    }

    /// This makes it so the transactions could legally be included in a block.
    /// The transactions may fail, but at least the block containing this
    /// transaction would be valid, since the fees are paid and the recent
    /// blockhash is valid.
    ///
    /// With the the existing SVM code, this means the TransactionResult
    /// returned by loadAndExecuteTransaction will be `ok` instead of `err`
    pub fn makeTransactionsPassable(
        self: *TestState,
        allocator: Allocator,
        transactions: []const sig.core.Transaction,
    ) !void {
        var bhq = self.blockhash_queue.write();
        defer bhq.unlock();
        for (transactions) |transaction| {
            try bhq.mut().insertHash(allocator, transaction.msg.recent_blockhash, 1);
            var account = sig.runtime.AccountSharedData.EMPTY;
            account.lamports = 100_000;
            try self.accounts_db.db.put(self.slot, transaction.msg.account_keys[0], account);
        }
    }
};

test "SvmGateway borrows persistent ProgramMap and reports per-slot deltas" {
    const allocator = std.testing.allocator;
    var state = try TestState.init(allocator);
    defer state.deinit(allocator);

    var persistent_programs = sig.runtime.program_loader.ProgramMap.empty;
    defer persistent_programs.deinit(allocator);

    var params = state.svmParams();
    params.program_map = &persistent_programs;
    var first = try SvmGateway.init(allocator, params);
    var key_data = [_]u8{0} ** sig.core.Pubkey.SIZE;
    key_data[0] = 1;
    try std.testing.expect(try first.programMap().putIfAbsent(
        allocator,
        .{ .data = key_data },
        .failed,
    ));
    _ = first.programMap().load_stats.cache_hits.fetchAdd(3, .monotonic);
    try std.testing.expectEqual(3, first.programLoadStats().cache_hits);
    first.deinit(allocator);

    try std.testing.expectEqual(1, persistent_programs.entryCount());
    var second = try SvmGateway.init(allocator, params);
    _ = second.programMap().load_stats.cache_hits.fetchAdd(2, .monotonic);
    try std.testing.expectEqual(2, second.programLoadStats().cache_hits);
    second.deinit(allocator);
    try std.testing.expectEqual(1, persistent_programs.entryCount());
}
