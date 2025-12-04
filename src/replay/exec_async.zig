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
            .poh_verifier = .{ .future = self },
            .txn_scheduler = .{
                .future = self,
                .transactions = params.transactions,
                .svm_gateway = params.svm_gateway,
                .committer = params.committer,
            },
            .pending = .init(1), // start with 1 for this scope's self.finish()
            .thread_pool = thread_pool,
            .exit = .init(false),
            .result_ptr = .init(result_ptr),
            .wait_group = wait_group,
        };

        wait_group.start();
        defer self.finish(); // if no tasks scheduled, this immediately completes the Future.

        // Start poh verifier.
        self.poh_verifier.start(params.last_entry) catch |e| return self.setError(e);

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
        if (self.pending.fetchSub(1, .acq_rel) - 1 == 0) {
            @branchHint(.unlikely);

            // Read the wait gruop out of self, as self will be freed at the end.
            const wg = self.wait_group;
            defer wg.finish();

            if (self.result_ptr.load(.acquire)) |result_ptr| {
                result_ptr.* = .{
                    .slot = self.txn_scheduler.svm_gateway.params.slot,
                    .output = .{ .last_entry_hash = self.entries[self.entries.len - 1].hash },
                };
            } else assert(self.exit.load(.monotonic)); // a setError() occured & consumed the result

            for (self.entries) |entry| entry.deinit(self.allocator);
            self.allocator.free(self.entries);

            self.txn_scheduler.deinit();
            self.poh_verifier.deinit();

            self.arena.deinit();
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
        const allocator = self.future.arena.allocator();

        self.workers.deinit(allocator);
    }

    fn start(self: *PohVerifier, last_entry: Hash) Error!void {
        const future = self.future;
        const entries = future.entries;

        var task_batch = ThreadPool.Batch{};
        defer future.schedule(task_batch);

        // TODO: investigate if this can just be 1 as it runs concurrently to TransactionScheduler
        const num_workers = @min(future.thread_pool.max_threads, entries.len);

        try self.workers.ensureTotalCapacity(self.future.arena.allocator(), num_workers);
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
            const zone = tracy.Zone.init(@src(), .{ .name = "replayVerify" });
            defer zone.deinit();

            const self: *Worker = @alignCast(@fieldParentPtr("task", task));
            defer self.future.finish();

            const success = verifyPoh(
                self.entries,
                self.future.allocator, // cant use future's arena here as its multi-threaded.
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
    transactions: []const ResolvedTransaction,
    svm_gateway: SvmGateway,
    committer: Committer,
    workers: std.ArrayListUnmanaged(Worker) = .{},

    const Error = Allocator.Error || error{ReplayBatchFailed};

    fn deinit(const_self: TransactionScheduler) void {
        var self = const_self;

        var allocator = self.future.allocator; // these came from SlotParams.
        for (self.transactions) |transaction| transaction.deinit(allocator);
        allocator.free(self.transactions);
        self.svm_gateway.deinit(allocator);

        allocator = self.future.arena.allocator(); // this came from Future's local arena.
        self.workers.deinit(allocator);
    }

    fn start(self: *TransactionScheduler) Error!void {
        const zone = tracy.Zone.init(@src(), .{ .name = "replaySchedule" });
        defer zone.deinit();

        const allocator = self.future.arena.allocator();
        const entries = self.future.entries;

        // Account locking across all sequential transactions.
        var account_locks = std.AutoArrayHashMapUnmanaged(Pubkey, struct {
            last_writer: ?u32 = null,
            readers: std.ArrayListUnmanaged(u32) = .{},
        }){};
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

        var i: usize = 0;
        for (entries) |entry| {
            if (entry.isTick()) continue;

            batch_locks.clearRetainingCapacity();
            for (self.transactions[i..][0..entry.transactions.len]) |transaction| {
                i += 1;

                const id: u32 = @intCast(self.workers.items.len);
                txn_deps.clearRetainingCapacity();
                for (
                    transaction.accounts.items(.pubkey),
                    transaction.accounts.items(.is_writable),
                ) |pubkey, writable| {
                    // Verify that there's no conflicting writer accounts within a batch of txns.
                    if (!self.svm_gateway.params.feature_set.active(
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
                        // if we write, we depend on last writer, or the readers who depend on it.
                        if (lock.readers.items.len > 0) {
                            for (lock.readers.items) |reader_id|
                                try txn_deps.put(allocator, reader_id, {});
                            lock.readers.clearRetainingCapacity();
                        } else if (lock.last_writer) |writer_id| {
                            try txn_deps.put(allocator, writer_id, {});
                        }

                        // We also become the writer for others later.
                        lock.last_writer = id;
                    } else {
                        // if we read, we depend on last writer & becomes readers for next writer
                        try lock.readers.append(allocator, id);
                        if (lock.last_writer) |writer_id| {
                            try txn_deps.put(allocator, writer_id, {});
                        }
                    }
                }

                // Tell our dependencies to decrement our ref_count when done executing.
                for (txn_deps.keys()) |writer_id| {
                    try self.workers.items[writer_id].waiters.append(allocator, id);
                }
                // Create job with a ref_count for each dependency.
                try self.workers.append(allocator, .{
                    .scheduler = self,
                    .transaction = transaction,
                    .ref_count = .init(@intCast(txn_deps.count())),
                    .waiters = .{},
                });
            }
        }

        var task_batch = ThreadPool.Batch{};
        defer self.future.schedule(task_batch);

        // Once workers have stable pointers, schedule the ones with no dependencies.
        for (self.workers.items) |*worker| {
            if (worker.ref_count.raw == 0) {
                task_batch.push(.from(&worker.task));
            }
        }
    }

    const Worker = struct {
        task: ThreadPool.Task = .{ .callback = run },
        scheduler: *TransactionScheduler,
        transaction: ResolvedTransaction,
        ref_count: Atomic(u32),
        waiters: std.ArrayListUnmanaged(u32),

        fn deinit(const_self: Worker, allocator: Allocator) void {
            var self = const_self;
            self.transaction.deinit(allocator);
            self.waiters.deinit(allocator);
        }

        fn run(task: *ThreadPool.Task) void {
            const zone = tracy.Zone.init(@src(), .{ .name = "replayExecute" });
            defer zone.deinit();

            const self: *Worker = @alignCast(@fieldParentPtr("task", task));
            defer self.scheduler.future.finish();

            const future = self.scheduler.future;
            const result = replayBatch(
                future.allocator, // cant use future's arena here as its multi-threaded
                &self.scheduler.svm_gateway,
                self.scheduler.committer,
                &.{self.transaction},
                &future.exit,
            ) catch |err| {
                future.logger.err().logf("replayBatch failed with error: {}", .{err});
                future.setError(Error.ReplayBatchFailed);
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

            var task_batch = ThreadPool.Batch{};
            defer future.schedule(task_batch);

            // Try to schedule the other workers waiting for us
            for (self.waiters.items) |id| {
                const waiter = &self.scheduler.workers.items[id];
                if (waiter.ref_count.fetchSub(1, .acq_rel) - 1 == 0) {
                    task_batch.push(.from(&waiter.task));
                }
            }
        }
    };
};

fn testSchedulerForBatches(
    allocator: Allocator,
    state: *replay.execution.TestState,
    batches: []const []const Transaction,
) !?ReplaySlotError {
    comptime std.debug.assert(@import("builtin").is_test);

    var resolved: std.ArrayListUnmanaged(replay.resolve_lookup.ResolvedTransaction) = .{};
    defer {
        for (resolved.items) |tx| tx.deinit(allocator);
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
            .poh_verifier = .{ .future = future },
            .txn_scheduler = .{
                .future = future,
                .transactions = resolved_transactions,
                .svm_gateway = svm_gateway,
                .committer = committer,
            },
            .pending = .init(1), // start with 1 for this scope's future.finish()
            .thread_pool = &thread_pool,
            .exit = .init(false),
            .result_ptr = .init(&result),
            .wait_group = &wg,
        };

        wg.start();
        defer future.finish();

        future.txn_scheduler.start() catch |e| future.setError(e);
    }

    return switch ((try result).output) {
        .last_entry_hash => null,
        .err => |err| err,
    };
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
        account.data = try allocator.alloc(u8, vote_program.state.VoteState.MAX_VOTE_STATE_SIZE);
        defer allocator.free(account.data);
        @memset(account.data, 0);

        var vote_state = try vote_program.state.createTestVoteState(
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
            vote_program.state.VoteStateVersions{ .current = vote_state },
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
