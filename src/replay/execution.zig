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

const Committer = replay.commit.Committer;
const EpochTracker = replay.trackers.EpochTracker;
const ReplaySlotFuture = replay.exec_async.ReplaySlotFuture;
const ReplayState = replay.service.ReplayState;
const ResolvedTransaction = replay.resolve_lookup.ResolvedTransaction;
const SlotResolver = replay.resolve_lookup.SlotResolver;
const SlotTracker = replay.trackers.SlotTracker;
const SvmGateway = replay.svm_gateway.SvmGateway;

const executeTransaction = replay.svm_gateway.executeTransaction;
const preprocessTransaction = replay.preprocess_transaction.preprocessTransaction;
const resolveBatch = replay.resolve_lookup.resolveBatch;
const verifyPoh = core.entry.verifyPoh;

const Logger = sig.trace.Logger("replay.execution");

/// The result of replaying an individual slot.
pub const ReplayResult = struct {
    slot: Slot,
    output: union(enum) {
        last_entry_hash: sig.core.Hash,
        err: ReplaySlotError,
    },
};

/// 1. Replays transactions from all the slots that need to be replayed.
/// 2. Store the replay results into the relevant data structures.
///
/// Analogous to [replay_active_banks](https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3356)
pub fn replayActiveSlots(state: *ReplayState, num_threads: u32) ![]const ReplayResult {
    return if (num_threads > 1)
        try awaitResults(state.allocator, try replayActiveSlotsAsync(state))
    else
        try replayActiveSlotsSync(state);
}

fn replayActiveSlotsAsync(state: *ReplayState) ![]struct { Slot, *ReplaySlotFuture } {
    var zone = tracy.Zone.init(@src(), .{ .name = "replayActiveSlotsAsync" });
    defer zone.deinit();

    const slot_tracker, var slot_lock = state.slot_tracker.readWithLock();
    defer slot_lock.unlock();

    const active_slots = try slot_tracker.activeSlots(state.allocator);
    state.execution_log_helper.logActiveSlots(active_slots, state.allocator);

    if (active_slots.len == 0) {
        return &.{};
    }

    var slot_statuses = std.ArrayListUnmanaged(struct { Slot, *ReplaySlotFuture }).empty;
    errdefer {
        for (slot_statuses.items) |status| status[1].destroy(state.allocator);
        slot_statuses.deinit(state.allocator);
    }

    const epoch_tracker_inner, var epoch_lock = state.epoch_tracker.readWithLock();
    defer epoch_lock.unlock();

    for (active_slots) |slot| {
        state.logger.debug().logf("replaying slot: {}", .{slot});

        const params = switch (try prepareSlot(state, slot_tracker, epoch_tracker_inner, slot)) {
            .confirm => |params| params,
            .empty, .dead, .leader => continue,
        };

        const future = try replaySlotAsync(
            state.allocator,
            .from(state.logger),
            &state.thread_pool,
            params,
        );

        errdefer future.destroy(state.allocator);
        try slot_statuses.append(state.allocator, .{ slot, future });
    }

    return slot_statuses.toOwnedSlice(state.allocator);
}

/// Takes ownership over the futures and destroys them
fn awaitResults(
    allocator: Allocator,
    /// takes ownership and frees with allocator
    slot_futures: []struct { Slot, *ReplaySlotFuture },
) ![]const ReplayResult {
    defer {
        for (slot_futures) |sf| sf[1].destroy(allocator);
        allocator.free(slot_futures);
    }
    const results = try allocator.alloc(ReplayResult, slot_futures.len);
    errdefer allocator.free(results);
    for (results, slot_futures) |*result, slot_future| {
        const slot, const future = slot_future;
        result.* = .{
            .slot = slot,
            .output = if (try future.awaitBlocking()) |err|
                .{ .err = err }
            else
                .{ .last_entry_hash = future.entries[future.entries.len - 1].hash },
        };
    }
    return results;
}

/// Fully synchronous version of replayActiveSlotsAsync that does not use
/// multithreading or async execution in any way.
fn replayActiveSlotsSync(state: *ReplayState) ![]const ReplayResult {
    const allocator = state.allocator;
    var zone = tracy.Zone.init(@src(), .{ .name = "replayActiveSlotsSync" });
    defer zone.deinit();

    const slot_tracker, var slot_lock = state.slot_tracker.readWithLock();
    defer slot_lock.unlock();

    const active_slots = try slot_tracker.activeSlots(allocator);
    state.execution_log_helper.logActiveSlots(active_slots, allocator);

    if (active_slots.len == 0) {
        return &.{};
    }

    var results = try std.ArrayListUnmanaged(ReplayResult)
        .initCapacity(allocator, active_slots.len);
    errdefer results.deinit(allocator);

    const epoch_tracker, var epoch_lock = state.epoch_tracker.readWithLock();
    defer epoch_lock.unlock();

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
    last_entry: Hash,
    svm_params: SvmGateway.Params,
    committer: Committer,
    verify_ticks_params: VerifyTicksParams,
    /// confirm slot takes ownership of this
    slot_resolver: SlotResolver,
};

/// Asynchronously validate and execute entries from a single slot.
///
/// Return: ReplaySlotFuture which you can poll periodically to await a result.
///
/// Takes ownership of the entries. Pass the same allocator that was used for
/// the entry allocation.
///
/// Analogous to:
/// - agave: confirm_slot_entries
/// - fd: runtime_process_txns_in_microblock_stream
pub fn replaySlotAsync(
    allocator: Allocator,
    logger: Logger,
    thread_pool: *ThreadPool,
    params: ReplaySlotParams,
) !*ReplaySlotFuture {
    const entries = params.entries;
    const last_entry = params.last_entry;
    const svm_params = params.svm_params;
    const committer = params.committer;
    const verify_ticks_params = params.verify_ticks_params;
    const slot_resolver = params.slot_resolver;

    var zone = tracy.Zone.init(@src(), .{ .name = "replaySlot" });
    zone.value(svm_params.slot);
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    logger.info().log("confirming slot");

    const future = fut: {
        errdefer {
            for (entries) |entry| entry.deinit(allocator);
            allocator.free(entries);
        }
        break :fut try ReplaySlotFuture.create(
            allocator,
            .from(logger),
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

    try replay.exec_async.startPohVerify(
        allocator,
        .from(logger),
        &future.poh_verifier,
        last_entry,
        entries,
        &future.exit,
    );

    for (entries) |entry| {
        if (entry.isTick()) continue;

        const batch = try resolveBatch(allocator, entry.transactions, slot_resolver);
        errdefer batch.deinit(allocator);

        future.scheduler.addBatchAssumeCapacity(batch);
    }

    _ = try future.poll(); // starts batch execution. poll result is cached inside future

    return future;
}

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
        switch (try replayBatch(
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
    allocator: Allocator,
    svm_params: SvmGateway.Params,
    committer: Committer,
    transactions: []const ResolvedTransaction,
    exit: *Atomic(bool),
) !BatchResult {
    var zone = tracy.Zone.init(@src(), .{ .name = "replayBatch" });
    zone.value(transactions.len);
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

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

    var svm_gateway = try SvmGateway.init(allocator, transactions, svm_params);
    defer svm_gateway.deinit(allocator);

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

        switch (try executeTransaction(allocator, &svm_gateway, &runtime_transaction)) {
            .ok => |result| {
                results[i] = .{ hash, result };
                populated_count += 1;
            },
            .err => |err| return .{ .failure = err },
        }
    }
    try committer.commitTransactions(
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
    var zone = tracy.Zone.init(@src(), .{ .name = "replaySlot" });
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

    const i_am_leader = slot_info.constants.collector_id.equals(&state.my_identity);

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
            try state.ledger.reader.getSlotEntriesWithShredInfo(
                state.allocator,
                slot,
                confirmation_progress.num_shreds,
                false,
            );
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
        sig.runtime.sysvar.SlotHashes,
        state.allocator,
        slot_account_reader,
    ) orelse return error.MissingSlotHashesSysvar;
    errdefer slot_hashes.deinit(state.allocator);

    const slot_resolver = replay.resolve_lookup.SlotResolver{
        .slot = slot,
        .account_reader = slot_account_reader,
        .reserved_accounts = &slot_info.constants.reserved_accounts,
        .slot_hashes = slot_hashes,
    };

    const svm_params = SvmGateway.Params{
        .slot = slot,
        .max_age = sig.core.BlockhashQueue.MAX_RECENT_BLOCKHASHES / 2,
        .lamports_per_signature = slot_info.constants.fee_rate_governor.lamports_per_signature,
        .blockhash_queue = &slot_info.state.blockhash_queue,
        .account_reader = slot_account_reader,
        .ancestors = &slot_info.constants.ancestors,
        .feature_set = slot_info.constants.feature_set,
        .rent_collector = &epoch_constants.rent_collector,
        .epoch_stakes = &epoch_constants.stakes,
        .status_cache = &state.status_cache,
    };

    const committer = replay.commit.Committer{
        .logger = .from(state.logger),
        .account_store = state.account_store,
        .slot_state = slot_info.state,
        .status_cache = &state.status_cache,
        .stakes_cache = &slot_info.state.stakes_cache,
        .new_rate_activation_epoch = new_rate_activation_epoch,
        .replay_votes_sender = state.replay_votes_channel,
    };

    const verify_ticks_params = replay.execution.VerifyTicksParams{
        .tick_height = slot_info.state.tickHeight(),
        .max_tick_height = slot_info.constants.max_tick_height,
        .hashes_per_tick = epoch_constants.hashes_per_tick,
        .slot = slot,
        .slot_is_full = slot_is_full,
        .tick_hash_count = &confirmation_progress.tick_hash_count,
    };

    var num_ticks: u64 = 0;
    for (entries) |entry| {
        if (entry.isTick()) num_ticks += 1;
    }
    _ = slot_info.state.tick_height.fetchAdd(num_ticks, .monotonic);

    return .{ .confirm = .{
        .entries = entries,
        .last_entry = previous_last_entry,
        .svm_params = svm_params,
        .committer = committer,
        .verify_ticks_params = verify_ticks_params,
        .slot_resolver = slot_resolver,
    } };
}

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
    last_active_slots: ?[]const Slot,
    slots_are_the_same: bool,

    pub fn init(logger: Logger) LogHelper {
        return .{
            .logger = logger,
            .last_active_slots = null,
            .slots_are_the_same = false,
        };
    }

    pub fn deinit(self: *LogHelper, deinit_allocator: Allocator) void {
        if (self.last_active_slots) |slots| deinit_allocator.free(slots);
        self.last_active_slots = null;
    }

    /// takes ownership of active_slots,
    pub fn logActiveSlots(
        self: *LogHelper,
        active_slots: []const u64,
        deinit_allocator: Allocator,
    ) void {
        self.slots_are_the_same = if (self.last_active_slots) |last_slots|
            std.mem.eql(u64, active_slots, last_slots)
        else
            false;

        if (self.last_active_slots) |slots| deinit_allocator.free(slots);
        self.last_active_slots = active_slots;

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
    try testReplaySlot(allocator, null, &.{}, params);
}

test "replaySlot - happy path: partial slot" {
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
    try testReplaySlot(allocator, null, entries[0 .. entries.len - 1], params);
}

test "replaySlot - happy path: full slot" {
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
    try testReplaySlot(allocator, null, entries, params);
}

test "replaySlot - fail: full slot not marked full -> .InvalidLastTick" {
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
    try testReplaySlot(
        allocator,
        ReplaySlotError{ .invalid_block = .InvalidLastTick },
        entries,
        params,
    );
}

test "replaySlot - fail: no trailing tick at max height -> .TrailingEntry" {
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
    try testReplaySlot(
        allocator,
        ReplaySlotError{ .invalid_block = .TrailingEntry },
        entries[0 .. entries.len - 1],
        params,
    );
}

test "replaySlot - fail: invalid poh chain" {
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
    try testReplaySlot(
        allocator,
        ReplaySlotError{ .invalid_block = .InvalidEntryHash },
        entries,
        params,
    );
}

test "replaySlot - fail: sigverify" {
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
    try testReplaySlot(
        allocator,
        ReplaySlotError{ .invalid_transaction = .SignatureFailure },
        entries,
        params,
    );
}

fn testReplaySlot(
    allocator: Allocator,
    expected: ?ReplaySlotError,
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

        const params = ReplaySlotParams{
            .entries = entries_copy,
            .last_entry = .ZEROES,
            .svm_params = state.svmParams(),
            .committer = state.committer(),
            .verify_ticks_params = verify_ticks_params,
            .slot_resolver = try state.resolver(allocator),
        };

        break :result try replaySlotSync(allocator, logger, params);
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

        const params = ReplaySlotParams{
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

        const future = try replaySlotAsync(allocator, logger, &thread_pool, params);
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
        try ancestors.addSlot(allocator, 0);

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
            .account_reader = self.account_map.accountReader().forSlot(&self.ancestors),
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
            .account_reader = self.account_map.accountReader().forSlot(&self.ancestors),
            .reserved_accounts = &.empty,
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
    ) sig.accounts_db.ThreadSafeAccountMap.PutError!void {
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
