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

const ForkProgress = sig.consensus.progress_map.ForkProgress;
const ParsedVote = sig.consensus.vote_listener.vote_parser.ParsedVote;
const ProcessedTransaction = sig.runtime.transaction_execution.ProcessedTransaction;
const SlotHashes = sig.runtime.sysvar.SlotHashes;
const TransactionError = sig.ledger.transaction_status.TransactionError;

const Committer = replay.Committer;
const EpochTracker = replay.trackers.EpochTracker;
const ReplaySlotFuture = replay.exec_async.ReplaySlotFuture;
const ReplayState = replay.service.ReplayState;
const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;
const SlotResolver = replay.resolve_lookup.SlotResolver;
const SlotTracker = replay.trackers.SlotTracker;
const SvmGateway = replay.svm_gateway.SvmGateway;

const executeTransaction = replay.svm_gateway.executeTransaction;
const preprocessTransaction = replay.preprocess_transaction.preprocessTransaction;
const verifyPoh = core.entry.verifyPoh;

const Logger = sig.trace.Logger("replay.execution");

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
pub fn replayActiveSlots(state: *ReplayState) ![]const ReplayResult {
    const can_multi_thread = state.thread_pool.max_threads > 1;
    return if (can_multi_thread)
        try replayActiveSlotsAsync(state)
    else
        try replayActiveSlotsSync(state);
}

fn replayActiveSlotsAsync(state: *ReplayState) ![]const ReplayResult {
    const zone = tracy.Zone.init(@src(), .{ .name = "replayActiveSlotsAsync" });
    defer zone.deinit();

    const slot_tracker = &state.slot_tracker;
    const epoch_tracker = &state.epoch_tracker;

    var results = std.ArrayListUnmanaged(ReplaySlotFuture.Result){};
    defer results.deinit(state.allocator);

    {
        var wait_group = std.Thread.WaitGroup{};
        defer wait_group.wait();

        const active_slots = try slot_tracker.activeSlots(state.allocator);
        defer state.allocator.free(active_slots);
        state.execution_log_helper.logActiveSlots(active_slots);

        if (active_slots.len == 0) {
            return &.{};
        }

        try results.ensureTotalCapacity(state.allocator, active_slots.len);
        for (active_slots) |slot| {
            state.logger.debug().logf("replaying slot: {}", .{slot});

            const params = switch (try prepareSlot(state, slot_tracker, epoch_tracker, slot)) {
                .confirm => |params| params,
                .empty, .dead, .leader => continue,
            };

            const result_ptr = results.addOneAssumeCapacity();
            ReplaySlotFuture.startAsync(
                state.allocator,
                .from(state.logger),
                &state.thread_pool,
                &wait_group,
                params,
                result_ptr,
            );
        }
    }

    const replay_results = try state.allocator.alloc(ReplayResult, results.items.len);
    errdefer state.allocator.free(replay_results);

    for (replay_results, results.items) |*replay_result, result| {
        replay_result.* = try result;
    }

    return replay_results;
}

/// Fully synchronous version of replayActiveSlotsAsync that does not use
/// multithreading or async execution in any way.
fn replayActiveSlotsSync(state: *ReplayState) ![]const ReplayResult {
    const allocator = state.allocator;
    var zone = tracy.Zone.init(@src(), .{ .name = "replayActiveSlotsSync" });
    defer zone.deinit();

    const slot_tracker = &state.slot_tracker;
    const epoch_tracker = &state.epoch_tracker;

    const active_slots = try slot_tracker.activeSlots(allocator);
    defer allocator.free(active_slots);
    state.execution_log_helper.logActiveSlots(active_slots);

    if (active_slots.len == 0) {
        return &.{};
    }

    var results = try std.ArrayListUnmanaged(ReplayResult)
        .initCapacity(allocator, active_slots.len);
    defer results.deinit(allocator);

    for (active_slots) |slot| {
        state.logger.debug().logf("replaying slot: {}", .{slot});

        const params = switch (try prepareSlot(state, slot_tracker, epoch_tracker, slot)) {
            .confirm => |params| params,
            .empty, .dead, .leader => continue,
        };
        const last_entry_hash = params.entries[params.entries.len - 1].hash;

        const maybe_err = try replaySlotSync(allocator, .from(state.logger), params);
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

    pub fn deinit(self: ReplaySlotParams, allocator: Allocator) void {
        for (self.entries) |entry| entry.deinit(allocator);
        allocator.free(self.entries);
        for (self.transactions) |transaction| transaction.deinit(allocator);
        allocator.free(self.transactions);
        self.svm_gateway.deinit(allocator);
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

    if (!try verifyPoh(params.entries, allocator, params.last_entry, .{})) {
        return .{ .invalid_block = .InvalidEntryHash };
    }

    var svm_gateway = params.svm_gateway;
    if (!svm_gateway.params.feature_set.active(
        .relax_intrabatch_account_locks,
        svm_gateway.params.slot,
    )) {
        var locks = sig.replay.AccountLocks{};
        defer locks.deinit(allocator);

        var accounts = std.ArrayListUnmanaged(sig.replay.AccountLocks.LockableAccount){};
        defer accounts.deinit(allocator);

        var i: usize = 0;
        for (params.entries) |entry| {
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
                error.LockFailed => return .{ .invalid_transaction = .AccountInUse },
                error.OutOfMemory => return error.OutOfMemory,
            };
            std.debug.assert(0 == locks.unlock(accounts.items));
        }
    }

    for (params.transactions) |transaction| {
        var exit = Atomic(bool).init(false);

        switch (try replayBatch(
            allocator,
            &svm_gateway,
            params.committer,
            &.{transaction},
            &exit,
        )) {
            .success => {},
            .failure => |err| return .{ .invalid_transaction = err },
            .exit => unreachable,
        }
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

/// Processes a batch of transactions by verifying their signatures and
/// executing them with the SVM.
pub fn replayBatch(
    gpa: Allocator,
    svm_gateway: *SvmGateway,
    committer: Committer,
    transactions: []const ResolvedTransaction,
    exit: *Atomic(bool),
) !BatchResult {
    var zone = tracy.Zone.init(@src(), .{ .name = "replayBatch" });
    zone.value(transactions.len);
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    // `gpa` allocations may be persisted to data structures, e.g.
    // - votes
    // - status_cache
    // - stakes_cache
    // - ProgramMap programs
    // Use this for all other allocations.
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    // TODO: maybe do a MultiArrayList {Hash, ProcessedTransaction, ResolvedTransaction}

    const results = try allocator.alloc(struct { Hash, ProcessedTransaction }, transactions.len);
    var populated_count: usize = 0;
    defer {
        // Only deinit elements that were actually populated
        // TODO Better way to do this? Instead of tracking populated count. Maybe switch to array list?
        for (results[0..populated_count]) |*result| {
            result.*[1].deinit(allocator);
        }
        allocator.free(results);
    }

    for (transactions, 0..) |transaction, i| {
        if (exit.load(.monotonic)) {
            return .exit;
        }

        const hash, const compute_budget_details =
            switch (preprocessTransaction(transaction.transaction, .run_sig_verify)) {
                .ok => |res| res,
                .err => |err| return .{ .failure = err },
            };

        const runtime_transaction = transaction.toRuntimeTransaction(hash, compute_budget_details);

        switch (try executeTransaction(gpa, allocator, svm_gateway, &runtime_transaction)) {
            .ok => |result| {
                results[i] = .{ hash, result };
                populated_count += 1;
            },
            .err => |err| return .{ .failure = err },
        }
    }
    try committer.commitTransactions(
        gpa,
        allocator,
        svm_gateway.params.slot,
        transactions,
        results,
    );

    return .success;
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
    slot_tracker: *const SlotTracker,
    epoch_tracker: *const EpochTracker,
    slot: Slot,
) !PreparedSlot {
    var zone = tracy.Zone.init(@src(), .{ .name = "prepareSlot" });
    zone.value(slot);
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    const progress_get_or_put = try state.progress_map.map.getOrPut(state.allocator, slot);
    if (progress_get_or_put.found_existing and progress_get_or_put.value_ptr.is_dead) {
        state.logger.info().logf("slot is dead: {}", .{slot});
        return .dead;
    }

    const epoch_constants = epoch_tracker.getPtrForSlot(slot) orelse return error.MissingEpoch;
    const slot_info = slot_tracker.get(slot) orelse return error.MissingSlot;

    const i_am_leader = slot_info.constants.collector_id.equals(&state.identity.validator);

    if (!progress_get_or_put.found_existing) {
        const parent_slot = slot_info.constants.parent_slot;
        const parent = state.progress_map.getForkProgress(parent_slot) orelse
            return error.MissingParentProgress;

        progress_get_or_put.value_ptr.* = try ForkProgress.initFromParent(state.allocator, .{
            .slot = slot,
            .parent_slot = parent_slot,
            .parent = parent,
            .slot_hash = slot_info.state.hash.readCopy(),
            .last_entry = slot_info.state.blockhash_queue.readField("last_hash") orelse
                return error.MissingLastHash,
            .i_am_leader = i_am_leader,
            .epoch_stakes = &epoch_constants.stakes,
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

    const tick_height =
        slot_info.state.tick_height.fetchAdd(core.entry.tickCount(entries), .monotonic);

    const new_rate_activation_epoch =
        if (slot_info.constants.feature_set.get(.reduce_stake_warmup_cooldown)) |active_slot|
            epoch_tracker.schedule.getEpoch(active_slot)
        else
            null;

    const slot_account_reader = state.account_store.reader()
        .forSlot(&slot_info.constants.ancestors);

    // TODO: Avoid the need to read this from accountsdb. We could broaden the
    // scope of the sysvar cache, add this to slot constants, or implement
    // additional mechanisms for lookup tables to detect slot age (e.g. block height).
    const slot_hashes = try replay.update_sysvar.getSysvarFromAccount(
        SlotHashes,
        state.allocator,
        slot_account_reader,
    ) orelse return error.MissingSlotHashesSysvar;

    const resolved_txns = try replay.resolve_lookup.resolveBlock(state.allocator, entries, .{
        .slot = slot,
        .account_reader = slot_account_reader,
        .reserved_accounts = &slot_info.constants.reserved_accounts,
        .slot_hashes = slot_hashes,
    });
    errdefer {
        for (resolved_txns) |transaction| transaction.deinit(state.allocator);
        state.allocator.free(resolved_txns);
    }

    var svm_gateway = try SvmGateway.init(state.allocator, .{
        .slot = slot,
        .max_age = sig.core.BlockhashQueue.MAX_RECENT_BLOCKHASHES / 2,
        .lamports_per_signature = slot_info.constants.fee_rate_governor.lamports_per_signature,
        .blockhash_queue = &slot_info.state.blockhash_queue,
        .account_store = state.account_store.forSlot(slot, &slot_info.constants.ancestors),
        .ancestors = &slot_info.constants.ancestors,
        .feature_set = slot_info.constants.feature_set,
        .rent_collector = &epoch_constants.rent_collector,
        .epoch_stakes = &epoch_constants.stakes,
        .status_cache = &state.status_cache,
    });
    errdefer svm_gateway.deinit(state.allocator);

    const committer = replay.Committer{
        .logger = .from(state.logger),
        .slot_state = slot_info.state,
        .status_cache = &state.status_cache,
        .stakes_cache = &slot_info.state.stakes_cache,
        .new_rate_activation_epoch = new_rate_activation_epoch,
        .replay_votes_sender = state.replay_votes_channel,
    };

    const verify_ticks_params = replay.execution.VerifyTicksParams{
        .tick_height = tick_height,
        .max_tick_height = slot_info.constants.max_tick_height,
        .hashes_per_tick = epoch_constants.hashes_per_tick,
        .slot = slot,
        .slot_is_full = slot_is_full,
        // TODO: come up with a better approach
        .tick_hash_count = &confirmation_progress.tick_hash_count,
    };

    return .{ .confirm = .{
        .entries = entries,
        .transactions = resolved_txns,
        .last_entry = previous_last_entry,
        .svm_gateway = svm_gateway,
        .committer = committer,
        .verify_ticks_params = verify_ticks_params,
        .account_store = state.account_store,
    } };
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
    defer state.deinit();

    const root = state.slot_tracker.get(0);
    const epoch = state.epoch_tracker.getForSlot(0);

    const constants, const slot_state = try sig.replay.service.newSlotFromParent(
        allocator,
        dep_stubs.accountsdb.accountReader(),
        epoch.?.ticks_per_slot,
        0,
        root.?.constants,
        root.?.state,
        .ZEROES,
        1,
    );

    try state.slot_tracker.put(allocator, 1, .{ .constants = constants, .state = slot_state });

    try std.testing.expectEqual(
        .empty,
        try prepareSlot(&state, &state.slot_tracker, &state.epoch_tracker, 1),
    );

    try dep_stubs.ledger.resultWriter().setDeadSlot(1);

    try std.testing.expectEqual(
        .dead,
        try prepareSlot(&state, &state.slot_tracker, &state.epoch_tracker, 1),
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

    const sync_result = result: {
        var state = try TestState.init(allocator);
        defer state.deinit(allocator);
        state.feature_set = feature_set;

        const params = try state.prepareSlotParams(allocator, entries, verify_ticks_params);
        break :result try replaySlotSync(allocator, logger, params);
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

    // resolver
    slot_hashes: SlotHashes,

    // Channels.
    replay_votes_channel: *sig.sync.Channel(ParsedVote),

    // scheduler
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

        var ancestors = Ancestors{};
        errdefer ancestors.deinit(allocator);
        try ancestors.addSlot(allocator, 0);

        const replay_votes_channel: *sig.sync.Channel(ParsedVote) = try .create(allocator);

        return .{
            .account_map = sig.accounts_db.ThreadSafeAccountMap.init(allocator),
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
            .account_store = self.account_map.accountStore().forSlot(self.slot, &self.ancestors),
            .ancestors = &self.ancestors,
            .feature_set = self.feature_set,
            .rent_collector = &self.rent_collector,
            .epoch_stakes = &self.epoch_stakes,
            .status_cache = &self.status_cache,
        };
    }

    pub fn committer(self: *TestState, allocator: Allocator) !Committer {
        _ = allocator; // autofix
        return .{
            .logger = .FOR_TESTS,
            .slot_state = &self.slot_state,
            .status_cache = &self.status_cache,
            .stakes_cache = &self.stakes_cache,
            .new_rate_activation_epoch = null,
            .replay_votes_sender = self.replay_votes_channel,
        };
    }

    pub fn resolver(self: *TestState) SlotResolver {
        return .{
            .slot = self.slot,
            .account_reader = self.account_map.accountReader().forSlot(&self.ancestors),
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
            .committer = try self.committer(allocator),
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
    ) sig.accounts_db.ThreadSafeAccountMap.PutError!void {
        var bhq = self.blockhash_queue.write();
        defer bhq.unlock();
        for (transactions) |transaction| {
            try bhq.mut().insertHash(allocator, transaction.msg.recent_blockhash, 1);
            var account = sig.runtime.AccountSharedData.EMPTY;
            account.lamports = 100_000;
            try self.account_map.put(self.slot, transaction.msg.account_keys[0], account);
        }
    }
};
