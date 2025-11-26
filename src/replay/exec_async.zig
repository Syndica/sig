//! Helper Structs and functions used in execution.zig when asynchronously
//! executing slots

const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const core = sig.core;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const Channel = sig.sync.Channel;
const HomogeneousThreadPool = sig.utils.thread.HomogeneousThreadPool;
const ThreadPool = sig.sync.ThreadPool;

const Entry = core.Entry;
const Hash = core.Hash;
const Transaction = sig.core.Transaction;

const ParsedVote = sig.consensus.vote_listener.vote_parser.ParsedVote;
const SlotHashes = sig.runtime.sysvar.SlotHashes;
const TransactionError = sig.ledger.transaction_status.TransactionError;

const AccountLocks = replay.AccountLocks;
const BatchResult = replay.execution.BatchResult;
const Committer = replay.Committer;
const ReplaySlotError = replay.execution.ReplaySlotError;
const ResolvedBatch = replay.resolve_lookup.ResolvedBatch;
const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;
const SvmGateway = replay.svm_gateway.SvmGateway;

const verifyPoh = core.entry.verifyPoh;

const assert = std.debug.assert;

const Logger = sig.trace.Logger("replay-async");

/// schedule poh verification asynchronously
pub fn startPohVerify(
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

pub const ReplaySlotStatus = FutureStatus(?ReplaySlotError);

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
pub const ReplaySlotFuture = struct {
    scheduler: TransactionScheduler,
    poh_verifier: HomogeneousThreadPool(PohTask),
    /// Set to true as soon as something fails.
    exit: Atomic(bool),

    entries: []const Entry,
    account_store: sig.accounts_db.AccountStore,

    /// The current status to return on poll, unless something has changed.
    status: ReplaySlotStatus,
    /// Temporarily stores errors that occur before completion that need to be
    /// returned when all tasks are complete.
    status_when_done: ?ReplaySlotError = null,

    pub fn create(
        allocator: Allocator,
        logger: Logger,
        thread_pool: *ThreadPool,
        committer: Committer,
        entries: []const Entry,
        batches: []const ResolvedBatch,
        svm_gateway: SvmGateway,
        account_store: sig.accounts_db.AccountStore,
    ) !*ReplaySlotFuture {
        const poh_verifier = try HomogeneousThreadPool(PohTask)
            .initBorrowed(allocator, thread_pool, thread_pool.max_threads);
        errdefer poh_verifier.deinit(allocator);

        const future = try allocator.create(ReplaySlotFuture);
        errdefer allocator.destroy(future);

        future.* = ReplaySlotFuture{
            .poh_verifier = poh_verifier,
            .scheduler = undefined,
            .entries = entries,
            .account_store = account_store,
            .status = .pending,
            .exit = .init(false),
        };

        future.scheduler = try TransactionScheduler.init(
            allocator,
            .from(logger),
            committer,
            batches,
            thread_pool,
            svm_gateway,
            &future.exit,
        );

        return future;
    }

    pub fn destroy(self: *ReplaySlotFuture, allocator: Allocator) void {
        // tell threads to exit (they shouldn't be running unless there was an unexpected error)
        self.exit.store(true, .monotonic);

        // join threads
        const exited_scheduler = self.scheduler.thread_pool.joinForDeinit(.fromMillis(100));
        const exited_poh = self.poh_verifier.joinForDeinit(.fromMillis(100));
        if (!exited_scheduler or !exited_poh) {
            @panic("Failed to deinit ReplaySlotFuture due to hanging threads.");
        }

        // deinit contained items
        self.scheduler.deinit();
        self.poh_verifier.deinit(allocator);
        for (self.entries) |entry| entry.deinit(allocator);
        allocator.free(self.entries);

        // destroy self
        allocator.destroy(self);
    }

    pub fn awaitBlocking(self: *ReplaySlotFuture) !?ReplaySlotError {
        while (true) {
            const poll_result = try self.poll();
            switch (poll_result) {
                .done => |val| return val,
                // TODO: consider futex-based wait like ResetEvent
                .pending => std.time.sleep(0),
            }
        }
    }

    pub fn poll(self: *ReplaySlotFuture) !ReplaySlotStatus {
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
                if (!pending) {
                    self.status = .{ .done = self.status_when_done };
                }
            },
            else => {},
        }

        return self.status;
    }

    fn pollEach(self: *ReplaySlotFuture) ![2]ReplaySlotStatus {
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
const TransactionScheduler = struct {
    allocator: Allocator,
    logger: Logger,
    committer: Committer,
    batches: []const ResolvedBatch,
    thread_pool: HomogeneousThreadPool(ReplayBatchTask),
    results: Channel(BatchMessage),
    locks: AccountLocks,
    /// The number of batches that have been scheduled with thread_pool.trySchedule.
    batches_started: usize,
    /// The number of batches that a result has been received over the channel for.
    batches_finished: usize,
    /// triggered as soon as a single transaction fails
    exit: *Atomic(bool),
    /// if non-null, a failure was already recorded and will be returned for every poll
    failure: ?replay.execution.ReplaySlotError,
    svm_gateway: SvmGateway,
    replay_votes_sender: ?*Channel(ParsedVote),

    const BatchMessage = struct {
        batch_index: usize,
        result: BatchResult,
    };

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        committer: Committer,
        batches: []const ResolvedBatch,
        thread_pool: *ThreadPool,
        svm_gateway: SvmGateway,
        exit: *Atomic(bool),
    ) !TransactionScheduler {
        const pool = try HomogeneousThreadPool(ReplayBatchTask)
            .initBorrowed(allocator, thread_pool, null);
        errdefer pool.deinit(allocator);

        var channel = try Channel(BatchMessage).init(allocator);
        errdefer channel.deinit();

        return .{
            .allocator = allocator,
            .logger = logger,
            .committer = committer,
            .batches = batches,
            .thread_pool = pool,
            .results = channel,
            .locks = .{},
            .batches_started = 0,
            .batches_finished = 0,
            .exit = exit,
            .failure = null,
            .svm_gateway = svm_gateway,
            .replay_votes_sender = committer.replay_votes_sender,
        };
    }

    pub fn deinit(self: TransactionScheduler) void {
        for (self.batches) |batch| batch.deinit(self.allocator);
        self.allocator.free(self.batches);

        var channel = self.results;
        channel.deinit();

        self.svm_gateway.deinit(self.allocator);
        self.thread_pool.deinit(self.allocator);
        self.locks.deinit(self.allocator);
    }

    fn collectResults(self: *TransactionScheduler) void {
        while (self.results.tryReceive()) |message| {
            assert(0 == self.locks.unlock(self.batches[message.batch_index].accounts));
            self.batches_finished += 1;
            tracy.plot(u32, "batches_finished", @intCast(self.batches_finished));
            switch (message.result) {
                .success => {},
                .failure => |err| {
                    self.exit.store(true, .monotonic);
                    self.failure = .{ .invalid_transaction = err };
                },
                .exit => {},
            }
        }
    }

    pub fn poll(self: *TransactionScheduler) !ReplaySlotStatus {
        // process results
        switch (self.thread_pool.pollFallible()) {
            .done => {
                self.collectResults();

                if (self.batches_started != self.batches_finished) std.debug.panic(
                    "batches started: {}, batches finished: {}\n",
                    .{ self.batches_started, self.batches_finished },
                );

                if (self.failure) |f| {
                    return .{ .done = f };
                } else if (self.batches.len != self.batches_started) {
                    if (try self.tryScheduleSome()) |err| {
                        self.exit.store(true, .monotonic);
                        self.failure = .{ .invalid_transaction = err };
                    }
                    return .pending;
                } else {
                    assert(self.batches.len == self.batches_finished);
                    return .{ .done = null };
                }
            },
            .pending => {
                self.collectResults();

                return .pending;
            },
            .err => |err| {
                self.collectResults();

                self.logger.err().logf("transaction batch processor failed with error: {}", .{err});
                return err;
            },
        }
    }

    fn tryScheduleSome(self: *TransactionScheduler) !?TransactionError {
        const zone = tracy.Zone.init(@src(), .{ .name = "tryScheduleSome" });
        defer zone.deinit();

        while (self.batches.len > self.batches_started) {
            const batch = self.batches[self.batches_started];

            const lock_result = if (self.svm_gateway.params.feature_set.active(
                .relax_intrabatch_account_locks,
                self.svm_gateway.params.slot,
            ))
                self.locks.lockPermissive(self.allocator, batch.accounts)
            else
                self.locks.lockStrict(self.allocator, batch.accounts);

            lock_result catch |e| switch (e) {
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
                .logger = self.logger,
                .committer = self.committer,
                .svm_gateway = &self.svm_gateway,
                .batch_index = self.batches_started,
                .transactions = batch.transactions,
                .results = &self.results,
                .exit = self.exit,
            }));
            self.batches_started += 1;
            tracy.plot(u32, "batches_started", @intCast(self.batches_started));
        }
        return null;
    }
};

const ReplayBatchTask = struct {
    allocator: Allocator,
    logger: Logger,
    svm_gateway: *SvmGateway,
    committer: Committer,
    batch_index: usize,
    transactions: []const ResolvedTransaction,
    results: *Channel(TransactionScheduler.BatchMessage),
    exit: *Atomic(bool),

    pub fn run(self: *ReplayBatchTask) !void {
        const result = try replay.execution.replayBatch(
            self.allocator,
            self.svm_gateway,
            self.committer,
            self.transactions,
            self.exit,
        );

        if (result == .failure) {
            self.logger.err().logf("batch failed due to transaction error: {}", .{result.failure});
            self.exit.store(true, .monotonic);
        }
        try self.results.send(.{ .batch_index = self.batch_index, .result = result });
    }
};

test "TransactionScheduler: happy path" {
    const allocator = std.testing.allocator;

    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);

    var thread_pool = ThreadPool.init(.{});
    defer {
        thread_pool.shutdown();
        thread_pool.deinit();
    }

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
    try state.makeTransactionsPassable(allocator, &transactions);

    const batches = try resolveForTest(allocator, .noop, &.{
        transactions[0..3],
        transactions[3..6],
    });

    const svm_params = state.svmParams();
    const svm_gateway = try SvmGateway.init(allocator, svm_params);
    var scheduler = try TransactionScheduler.init(
        allocator,
        .FOR_TESTS,
        try state.committer(allocator),
        batches,
        &thread_pool,
        svm_gateway,
        &state.exit,
    );
    defer scheduler.deinit();

    try std.testing.expectEqual(null, try replay.execution.testAwait(&scheduler));
}

test "TransactionScheduler: duplicate batch passes through to svm" {
    const allocator = std.testing.allocator;

    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);

    var thread_pool = ThreadPool.init(.{});
    defer {
        thread_pool.shutdown();
        thread_pool.deinit();
    }

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
    try state.makeTransactionsPassable(allocator, &transactions);

    const batches = try resolveForTest(allocator, .noop, &.{
        transactions[0..3],
        // should be no failures on account collision with the first time this batch was scheduled.
        // scheduler should just know to run it separately
        transactions[0..3],
    });

    const svm_params = state.svmParams();
    const svm_gateway = try SvmGateway.init(allocator, svm_params);
    var scheduler = try TransactionScheduler.init(
        allocator,
        .noop,
        try state.committer(allocator),
        batches,
        &thread_pool,
        svm_gateway,
        &state.exit,
    );
    defer scheduler.deinit();

    try std.testing.expectEqual(
        ReplaySlotError{ .invalid_transaction = .AlreadyProcessed },
        try replay.execution.testAwait(&scheduler),
    );
}

test "TransactionScheduler: failed account locks" {
    const allocator = std.testing.allocator;

    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);

    var thread_pool = ThreadPool.init(.{});
    defer {
        thread_pool.shutdown();
        thread_pool.deinit();
    }

    const tx = try Transaction.initRandom(allocator, rng.random(), null);
    defer tx.deinit(allocator);

    const unresolved_batch = [_]Transaction{ tx, tx };
    try state.makeTransactionsPassable(allocator, &unresolved_batch);

    const batches = try resolveForTest(allocator, .noop, &.{&unresolved_batch});

    const svm_params = state.svmParams();
    const svm_gateway = try SvmGateway.init(allocator, svm_params);
    var scheduler = try TransactionScheduler.init(
        allocator,
        .FOR_TESTS,
        try state.committer(allocator),
        batches,
        &thread_pool,
        svm_gateway,
        &state.exit,
    );
    defer scheduler.deinit();

    try std.testing.expectEqual(
        ReplaySlotError{ .invalid_transaction = .AccountInUse },
        try replay.execution.testAwait(&scheduler),
    );
}

test "TransactionScheduler: signature verification failure" {
    const allocator = std.testing.allocator;

    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);

    var thread_pool = ThreadPool.init(.{});
    defer {
        thread_pool.shutdown();
        thread_pool.deinit();
    }

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
    try state.makeTransactionsPassable(allocator, &transactions);

    const replaced_sigs = try tx_arena.allocator()
        .dupe(sig.core.Signature, transactions[5].signatures);
    replaced_sigs[0].r[0] +%= 1;
    transactions[5].signatures = replaced_sigs;

    const batches = try resolveForTest(allocator, .noop, &.{
        transactions[0..3],
        transactions[3..6],
    });

    const svm_params = state.svmParams();
    const svm_gateway = try SvmGateway.init(allocator, svm_params);
    var scheduler = try TransactionScheduler.init(
        allocator,
        .noop,
        try state.committer(allocator),
        batches,
        &thread_pool,
        svm_gateway,
        &state.exit,
    );
    defer scheduler.deinit();

    try std.testing.expectEqual(
        ReplaySlotError{ .invalid_transaction = .SignatureFailure },
        try replay.execution.testAwait(&scheduler),
    );
}

test "TransactionScheduler: does not send replay vote for failed execution" {
    const allocator = std.testing.allocator;
    const vote_program = sig.runtime.program.vote;
    const vote_instruction = vote_program.vote_instruction;

    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);

    var thread_pool = ThreadPool.init(.{});
    defer {
        thread_pool.shutdown();
        thread_pool.deinit();
    }

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

    // Make transaction passable (valid recent blockhash and fees)
    var txs = [_]Transaction{vote_tx};
    try state.makeTransactionsPassable(allocator, &txs);

    // Resolve batch
    const batches = try resolveForTest(allocator, .noop, &.{&txs});

    // Channel to receive parsed votes
    const votes_ch = try sig.sync.Channel(ParsedVote).create(allocator);
    defer {
        while (votes_ch.tryReceive()) |pv| pv.deinit(allocator);
        votes_ch.destroy();
    }

    const svm_params = state.svmParams();
    const svm_gateway = try SvmGateway.init(allocator, svm_params);
    var scheduler = try TransactionScheduler.init(
        allocator,
        .FOR_TESTS,
        try state.committer(allocator),
        batches,
        &thread_pool,
        svm_gateway,
        &state.exit,
    );
    defer scheduler.deinit();

    // Await completion
    try std.testing.expectEqual(null, try replay.execution.testAwait(&scheduler));

    const maybe_vote = votes_ch.tryReceive();
    try std.testing.expect(maybe_vote == null);
}

test "TransactionScheduler: sends replay vote after successful execution" {
    const allocator = std.testing.allocator;
    const vote_program = sig.runtime.program.vote;
    const vote_instruction = vote_program.vote_instruction;

    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var state = try replay.execution.TestState.init(allocator);
    defer state.deinit(allocator);

    var thread_pool = ThreadPool.init(.{});
    defer {
        thread_pool.shutdown();
        thread_pool.deinit();
    }

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
        try state.account_map.put(state.slot, vote_pubkey, account);
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
        try state.account_map.put(state.slot, SlotHashes.ID, sysvar_account);
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
        try state.account_map.put(state.slot, sig.runtime.sysvar.Clock.ID, sysvar_account);
        allocator.free(sysvar_account.data);
    }

    // Insert builtin program accounts for loader checks
    {
        var vote_prog_acc = sig.runtime.AccountSharedData.NEW;
        vote_prog_acc.lamports = 1;
        vote_prog_acc.owner = sig.runtime.ids.NATIVE_LOADER_ID;
        vote_prog_acc.executable = true;
        try state.account_map.put(state.slot, sig.runtime.program.vote.ID, vote_prog_acc);

        var native_loader_acc = sig.runtime.AccountSharedData.NEW;
        native_loader_acc.lamports = 1;
        native_loader_acc.owner = sig.runtime.ids.NATIVE_LOADER_ID;
        native_loader_acc.executable = true;
        try state.account_map.put(state.slot, sig.runtime.ids.NATIVE_LOADER_ID, native_loader_acc);
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
        try state.account_map.put(state.slot, sig.runtime.sysvar.Rent.ID, sysvar_account);
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
    try state.makeTransactionsPassable(allocator, &txs);

    // Resolve and run through scheduler
    const batches = try resolveForTest(allocator, .noop, &.{&txs});

    const svm_params = state.svmParams();
    const svm_gateway = try SvmGateway.init(allocator, svm_params);
    var scheduler = try TransactionScheduler.init(
        allocator,
        .FOR_TESTS,
        try state.committer(allocator),
        batches,
        &thread_pool,
        svm_gateway,
        &state.exit,
    );
    defer scheduler.deinit();

    // Await completion and assert a replay vote was emitted
    try std.testing.expectEqual(null, try replay.execution.testAwait(&scheduler));
    const maybe_vote = state.replay_votes_channel.tryReceive();
    try std.testing.expect(maybe_vote != null);
    if (maybe_vote) |pv| pv.deinit(allocator);
}

fn resolveForTest(
    allocator: Allocator,
    account_reader: sig.accounts_db.SlotAccountReader,
    batches: []const []const Transaction,
) ![]const ResolvedBatch {
    const entries = try allocator.alloc(Entry, batches.len);
    defer allocator.free(entries);

    for (batches, entries) |batch, *entry| {
        entry.* = .{
            .hash = .ZEROES,
            .num_hashes = 1,
            .transactions = batch,
        };
    }

    return try replay.resolve_lookup.resolveBlock(allocator, entries, .{
        .slot = 0,
        .account_reader = account_reader,
        .reserved_accounts = &.empty,
        .slot_hashes = .INIT,
    });
}
