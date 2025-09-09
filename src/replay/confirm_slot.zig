const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const core = sig.core;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const HomogeneousThreadPool = sig.utils.thread.HomogeneousThreadPool;
const ThreadPool = sig.sync.ThreadPool;

const Ancestors = core.Ancestors;
const Entry = core.Entry;
const Hash = core.Hash;
const Slot = core.Slot;
const TransactionError = sig.ledger.transaction_status.TransactionError;

const AccountStore = sig.accounts_db.AccountStore;
const ParsedVote = sig.consensus.vote_listener.vote_parser.ParsedVote;
const SlotHashes = sig.runtime.sysvar.SlotHashes;

const Committer = replay.commit.Committer;
const SlotResolver = replay.resolve_lookup.SlotResolver;
const SvmGateway = replay.svm_gateway.SvmGateway;
const TransactionScheduler = replay.scheduler.TransactionScheduler;

const verifyPoh = core.entry.verifyPoh;
const resolveBatch = replay.resolve_lookup.resolveBatch;

const assert = std.debug.assert;

const Logger = sig.trace.Logger("replay-confirm-slot");

pub const ConfirmSlotParams = struct {
    /// confirm slot takes ownership of this
    entries: []const Entry,
    last_entry: Hash,
    svm_params: SvmGateway.Params,
    committer: Committer,
    verify_ticks_params: VerifyTicksParams,
    /// confirm slot takes ownership of this
    slot_resolver: SlotResolver,
};

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
    logger: Logger,
    thread_pool: *ThreadPool,
    params: ConfirmSlotParams,
) !*ConfirmSlotFuture {
    const entries = params.entries;
    const last_entry = params.last_entry;
    const svm_params = params.svm_params;
    const committer = params.committer;
    const verify_ticks_params = params.verify_ticks_params;
    const slot_resolver = params.slot_resolver;

    var zone = tracy.Zone.init(@src(), .{ .name = "confirmSlot" });
    zone.value(svm_params.slot);
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    logger.info().log("confirming slot");

    const future = fut: {
        errdefer {
            for (entries) |entry| entry.deinit(allocator);
            allocator.free(entries);
        }
        break :fut try ConfirmSlotFuture.create(
            allocator,
            logger,
            thread_pool,
            committer,
            entries,
            svm_params,
            slot_resolver,
        );
    };
    errdefer future.destroy(allocator);

    if (verifyTicks(logger, entries, verify_ticks_params)) |block_error| {
        future.status = .{ .done = .{ .invalid_block = block_error } };
        return future;
    }

    try startPohVerify(allocator, logger, &future.poh_verifier, last_entry, entries, &future.exit);
    try scheduleTransactionBatches(allocator, &future.scheduler, entries, slot_resolver);

    _ = try future.poll(); // starts batch execution. poll result is cached inside future

    return future;
}

/// Synchronous version of confirmSlot.
///
/// The main benefit of this function is to simplify debugging when the
/// multithreading overhead causes issues. It can also be used when there is no
/// concern for performance and you'd just like to reduce the number of moving
/// pieces.
pub fn confirmSlotSync(
    allocator: Allocator,
    logger: Logger,
    params: ConfirmSlotParams,
) !?ConfirmSlotError {
    var zone = tracy.Zone.init(@src(), .{ .name = "confirmSlotSync" });
    zone.value(params.svm_params.slot);
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    defer {
        params.slot_resolver.deinit(allocator);
        for (params.entries) |entry| entry.deinit(allocator);
        allocator.free(params.entries);
    }

    logger.info().log("confirming slot");

    if (verifyTicks(logger, params.entries, params.verify_ticks_params)) |block_error| {
        return .{ .invalid_block = block_error };
    }

    if (!try verifyPoh(params.entries, allocator, params.last_entry, .{})) {
        return .{ .invalid_block = .InvalidEntryHash };
    }

    for (params.entries) |entry| {
        if (entry.isTick()) continue;

        const batch = try resolveBatch(allocator, entry.transactions, params.slot_resolver);
        defer batch.deinit(allocator);

        var exit = Atomic(bool).init(false);
        switch (try replay.scheduler.processBatch(
            allocator,
            params.svm_params,
            params.committer,
            batch.transactions,
            &exit,
        )) {
            .success => {},
            .failure => |err| return .{ .invalid_transaction = err },
            .exit => unreachable,
        }
    }

    return null;
}

/// schedule poh verification asynchronously
fn startPohVerify(
    allocator: Allocator,
    logger: Logger,
    pool: *HomogeneousThreadPool(PohTask),
    initial_hash: Hash,
    entries: []const Entry,
    exit: *Atomic(bool),
) Allocator.Error!void {
    if (entries.len == 0) return;
    const num_tasks = if (pool.max_concurrent_tasks) |max| @min(max, entries.len) else entries.len;
    const entries_per_task = entries.len / num_tasks;
    var batch_initial_hash = initial_hash;
    for (0..num_tasks) |i| {
        const end = if (i == num_tasks - 1) entries.len else (i + 1) * entries_per_task;
        assert(try pool.trySchedule(allocator, .{
            .allocator = allocator,
            .logger = logger,
            .initial_hash = batch_initial_hash,
            .entries = entries[i * entries_per_task .. end],
            .exit = exit,
        }));
        batch_initial_hash = entries[end - 1].hash;
    }
}

/// schedule transaction verification/execution asynchronously
fn scheduleTransactionBatches(
    allocator: Allocator,
    scheduler: *TransactionScheduler,
    entries: []const Entry,
    slot_resolver: SlotResolver,
) !void {
    for (entries) |entry| {
        if (entry.isTick()) continue;

        const batch = try resolveBatch(allocator, entry.transactions, slot_resolver);
        errdefer batch.deinit(allocator);

        scheduler.addBatchAssumeCapacity(batch);
    }
}

pub const ConfirmSlotStatus = FutureStatus(?ConfirmSlotError);

fn FutureStatus(T: type) type {
    return union(enum) {
        done: T,
        pending,

        pub const Result = T;
    };
}

/// Tracks the state of a slot confirmation execution.
///
/// Do not share across threads.
///
/// agave: confirm_slot and confirm_slot_entries
/// fd: runtime_process_txns_in_microblock_stream
pub const ConfirmSlotFuture = struct {
    scheduler: TransactionScheduler,
    poh_verifier: HomogeneousThreadPool(PohTask),
    /// Set to true as soon as something fails.
    exit: Atomic(bool),
    /// just here to be deinitted on completion
    slot_resolver: SlotResolver,

    entries: []const Entry,

    /// The current status to return on poll, unless something has changed.
    status: ConfirmSlotStatus,
    /// Temporarily stores errors that occur before completion that need to be
    /// returned when all tasks are complete.
    status_when_done: ?ConfirmSlotError = null,

    fn create(
        allocator: Allocator,
        logger: Logger,
        thread_pool: *ThreadPool,
        committer: Committer,
        entries: []const Entry,
        svm_params: SvmGateway.Params,
        slot_resolver: SlotResolver,
    ) !*ConfirmSlotFuture {
        const poh_verifier = try HomogeneousThreadPool(PohTask)
            .initBorrowed(allocator, thread_pool, thread_pool.max_threads);
        errdefer poh_verifier.deinit(allocator);

        const future = try allocator.create(ConfirmSlotFuture);
        errdefer allocator.destroy(future);

        future.* = ConfirmSlotFuture{
            .poh_verifier = poh_verifier,
            .scheduler = undefined,
            .entries = entries,
            .status = .pending,
            .exit = .init(false),
            .slot_resolver = slot_resolver,
        };

        future.scheduler = try TransactionScheduler.initCapacity(
            allocator,
            .from(logger),
            committer,
            entries.len,
            thread_pool,
            svm_params,
            &future.exit,
        );

        return future;
    }

    pub fn destroy(self: *ConfirmSlotFuture, allocator: Allocator) void {
        // tell threads to exit (they shouldn't be running unless there was an unexpected error)
        self.exit.store(true, .monotonic);

        // join threads
        const exited_scheduler = self.scheduler.thread_pool.joinForDeinit(.fromMillis(100));
        const exited_poh = self.poh_verifier.joinForDeinit(.fromMillis(100));
        if (!exited_scheduler or !exited_poh) {
            @panic("Failed to deinit ConfirmSlotFuture due to hanging threads.");
        }

        // deinit contained items
        self.slot_resolver.deinit(allocator);
        self.scheduler.deinit();
        self.poh_verifier.deinit(allocator);
        for (self.entries) |entry| entry.deinit(allocator);
        allocator.free(self.entries);

        // destroy self
        allocator.destroy(self);
    }

    pub fn awaitBlocking(self: *ConfirmSlotFuture) !?ConfirmSlotError {
        while (true) {
            const poll_result = try self.poll();
            switch (poll_result) {
                .done => |val| return val,
                // TODO: consider futex-based wait like ResetEvent
                .pending => std.time.sleep(100 * std.time.ns_per_ms),
            }
        }
    }

    pub fn poll(self: *ConfirmSlotFuture) !ConfirmSlotStatus {
        switch (self.status) {
            .pending => {
                var pending = false;
                for (try self.pollEach()) |status| switch (status) {
                    .pending => pending = true,
                    .done => |maybe_err| if (maybe_err) |err| {
                        if (self.status_when_done == null) {
                            self.exit.store(true, .monotonic);
                            self.status_when_done = err;
                        }
                    },
                };
                if (!pending) self.status = .{ .done = self.status_when_done };
            },
            else => {},
        }

        return self.status;
    }

    fn pollEach(self: *ConfirmSlotFuture) ![2]ConfirmSlotStatus {
        return .{
            switch (self.poh_verifier.pollFallible()) {
                .done => .{ .done = null },
                .err => .{ .done = .{ .invalid_block = .InvalidEntryHash } },
                .pending => .pending,
            },
            try self.scheduler.poll(),
        };
    }
};

pub const PohTask = struct {
    allocator: Allocator,
    logger: Logger,
    initial_hash: Hash,
    entries: []const Entry,
    exit: *Atomic(bool),

    pub fn run(self: *PohTask) !void {
        const success = verifyPoh(
            self.entries,
            self.allocator,
            self.initial_hash,
            .{ .exit = self.exit },
        ) catch |e| {
            if (e != error.Exit) {
                self.logger.err().logf("poh verification failed with error: {}", .{e});
            }
            self.exit.store(true, .monotonic);
            return e;
        };
        if (!success) {
            self.logger.err().log("poh verification failed");
            self.exit.store(true, .monotonic);
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
    logger: Logger,
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
    const allocator = std.testing.allocator;

    var state = try TestState.init(allocator);
    defer state.deinit(allocator);

    var tick_hash_count: u64 = 0;

    const params = VerifyTicksParams{
        .hashes_per_tick = 0,
        .slot = 0,
        .max_tick_height = 1,
        .tick_height = 0,
        .slot_is_full = false,
        .tick_hash_count = &tick_hash_count,
    };
    try testConfirmSlot(allocator, null, &.{}, params);
}

test "happy path: partial slot" {
    const allocator = std.testing.allocator;

    var state = try TestState.init(allocator);
    defer state.deinit(allocator);

    var tick_hash_count: u64 = 0;

    const poh, const entry_array = try sig.core.poh.testPoh(true);
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
    try testConfirmSlot(allocator, null, entries[0 .. entries.len - 1], params);
}

test "happy path: full slot" {
    const allocator = std.testing.allocator;

    var state = try TestState.init(allocator);
    defer state.deinit(allocator);

    var tick_hash_count: u64 = 0;

    const poh, const entry_array = try sig.core.poh.testPoh(true);
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
    try testConfirmSlot(allocator, null, entries, params);
}

test "fail: full slot not marked full -> .InvalidLastTick" {
    const allocator = std.testing.allocator;

    var state = try TestState.init(allocator);
    defer state.deinit(allocator);

    var tick_hash_count: u64 = 0;

    const poh, const entry_array = try sig.core.poh.testPoh(true);
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
    try testConfirmSlot(
        allocator,
        ConfirmSlotError{ .invalid_block = .InvalidLastTick },
        entries,
        params,
    );
}

test "fail: no trailing tick at max height -> .TrailingEntry" {
    const allocator = std.testing.allocator;

    var state = try TestState.init(allocator);
    defer state.deinit(allocator);

    var tick_hash_count: u64 = 0;

    const poh, const entry_array = try sig.core.poh.testPoh(true);
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
    try testConfirmSlot(
        allocator,
        ConfirmSlotError{ .invalid_block = .TrailingEntry },
        entries[0 .. entries.len - 1],
        params,
    );
}

test "fail: invalid poh chain" {
    const allocator = std.testing.allocator;

    var state = try TestState.init(allocator);
    defer state.deinit(allocator);

    var tick_hash_count: u64 = 0;

    const poh, var entry_array = try sig.core.poh.testPoh(true);
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
    try testConfirmSlot(
        allocator,
        ConfirmSlotError{ .invalid_block = .InvalidEntryHash },
        entries,
        params,
    );
}

test "fail: sigverify" {
    const allocator = std.testing.allocator;

    var state = try TestState.init(allocator);
    defer state.deinit(allocator);

    var tick_hash_count: u64 = 0;

    const poh, var entry_array = try sig.core.poh.testPoh(false);
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
    try testConfirmSlot(
        allocator,
        ConfirmSlotError{ .invalid_transaction = .SignatureFailure },
        entries,
        params,
    );
}

fn testConfirmSlot(
    allocator: Allocator,
    expected: ?ConfirmSlotError,
    entries: []const Entry,
    verify_ticks_params: VerifyTicksParams,
) !void {
    const logger: Logger = if (expected == null) .FOR_TESTS else .noop;

    const sync_result = result: {
        var state = try TestState.init(allocator);
        defer state.deinit(allocator);

        const entries_copy = try allocator.dupe(Entry, entries);
        errdefer allocator.free(entries_copy);
        for (entries_copy, 0..) |*entry, i| {
            errdefer for (entries_copy, 0..i) |e, _| e.deinit(allocator);
            entry.* = try entry.clone(allocator);
        }

        for (entries_copy) |e| try state.makeTransactionsPassable(allocator, e.transactions);

        const params = ConfirmSlotParams{
            .entries = entries_copy,
            .last_entry = .ZEROES,
            .svm_params = state.svmParams(),
            .committer = state.committer(),
            .verify_ticks_params = verify_ticks_params,
            .slot_resolver = try state.resolver(allocator),
        };

        break :result try confirmSlotSync(allocator, logger, params);
    };

    verify_ticks_params.tick_hash_count.* = 0;

    const async_result = result: {
        var state = try TestState.init(allocator);
        defer state.deinit(allocator);

        const entries_copy = try allocator.dupe(Entry, entries);
        errdefer allocator.free(entries_copy);
        for (entries_copy, 0..) |*entry, i| {
            errdefer for (entries_copy, 0..i) |e, _| e.deinit(allocator);
            entry.* = try entry.clone(allocator);
        }

        for (entries_copy) |e| try state.makeTransactionsPassable(allocator, e.transactions);

        const params = ConfirmSlotParams{
            .entries = entries_copy,
            .last_entry = .ZEROES,
            .svm_params = state.svmParams(),
            .committer = state.committer(),
            .verify_ticks_params = verify_ticks_params,
            .slot_resolver = try state.resolver(allocator),
        };

        var thread_pool = ThreadPool.init(.{});
        defer {
            thread_pool.shutdown();
            thread_pool.deinit();
        }

        const future = try confirmSlot(allocator, logger, &thread_pool, params);
        defer future.destroy(allocator);

        break :result try testAwait(future);
    };

    errdefer std.log.err("failed with: {any} - {any}\n", .{ async_result, sync_result });

    try std.testing.expectEqual(expected, async_result);
    try std.testing.expectEqual(expected, sync_result);
}

pub fn testAwait(future: anytype) !@typeInfo(@TypeOf(future.poll())).error_union.payload.Result {
    var i: usize = 0;
    while (try future.poll() == .pending) {
        std.time.sleep(std.time.ns_per_ms);
        i += 1;
        if (i > 100) return error.TooSlow;
    }
    return (try future.poll()).done;
}

pub const TestState = struct {
    // shared for multiple things
    account_map: sig.accounts_db.ThreadSafeAccountMap,
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

    // Channels.
    replay_votes_channel: *sig.sync.Channel(ParsedVote),

    // scheduler
    exit: Atomic(bool),

    pub fn init(allocator: Allocator) !TestState {
        const epoch_stakes = try sig.core.EpochStakes.init(allocator);
        errdefer epoch_stakes.deinit(allocator);

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);

        var stakes_cache = try sig.core.StakesCache.init(allocator);
        errdefer stakes_cache.deinit(allocator);

        const max_age = sig.core.BlockhashQueue.MAX_RECENT_BLOCKHASHES / 2;
        var blockhash_queue = sig.core.BlockhashQueue.init(max_age);
        errdefer blockhash_queue.deinit(allocator);
        try blockhash_queue.insertGenesisHash(allocator, .ZEROES, 1);

        var ancestors = Ancestors{};
        try ancestors.addSlot(0);

        const replay_votes_channel: *sig.sync.Channel(ParsedVote) = try .create(allocator);

        return .{
            .account_map = sig.accounts_db.ThreadSafeAccountMap.init(allocator),
            .status_cache = .DEFAULT,
            .ancestors = ancestors,
            .slot = 0,
            .max_age = max_age,
            .lamports_per_signature = 1,
            .blockhash_queue = .init(blockhash_queue),
            .feature_set = .ALL_DISABLED,
            .rent_collector = .DEFAULT,
            .epoch_stakes = epoch_stakes,
            .slot_state = slot_state,
            .stakes_cache = stakes_cache,
            .replay_votes_channel = replay_votes_channel,
            .exit = .init(false),
        };
    }

    pub fn deinit(self: *TestState, allocator: Allocator) void {
        self.account_map.deinit();
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
        return self.account_map.accountStore();
    }

    pub fn svmParams(self: *TestState) SvmGateway.Params {
        return .{
            .slot = self.slot,
            .max_age = self.max_age,
            .lamports_per_signature = self.lamports_per_signature,
            .blockhash_queue = &self.blockhash_queue,
            .account_reader = self.account_map.accountReader().forSlot(self.ancestors),
            .ancestors = self.ancestors,
            .feature_set = self.feature_set,
            .rent_collector = &self.rent_collector,
            .epoch_stakes = &self.epoch_stakes,
            .status_cache = &self.status_cache,
        };
    }

    pub fn committer(self: *TestState) Committer {
        return .{
            .logger = .FOR_TESTS,
            .account_store = self.account_map.accountStore(),
            .slot_state = &self.slot_state,
            .status_cache = &self.status_cache,
            .stakes_cache = &self.stakes_cache,
            .new_rate_activation_epoch = null,
            .replay_votes_sender = self.replay_votes_channel,
        };
    }

    pub fn resolver(self: *TestState, allocator: Allocator) !SlotResolver {
        return .{
            .slot = self.slot,
            .account_reader = self.account_map.accountReader().forSlot(self.ancestors),
            .reserved_accounts = .empty,
            .slot_hashes = try SlotHashes.init(allocator),
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
    ) Allocator.Error!void {
        var bhq = self.blockhash_queue.write();
        defer bhq.unlock();
        for (transactions) |transaction| {
            try bhq.mut().insertHash(allocator, transaction.msg.recent_blockhash, 1);
            var account = sig.runtime.AccountSharedData.EMPTY;
            account.lamports = 1_000;
            try self.account_map.put(self.slot, transaction.msg.account_keys[0], account);
        }
    }
};
