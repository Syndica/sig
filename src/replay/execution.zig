const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const core = sig.core;

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const Pubkey = core.Pubkey;
const Slot = core.Slot;

const AccountStore = sig.accounts_db.AccountStore;
const LedgerReader = sig.ledger.LedgerReader;

const ForkProgress = sig.consensus.progress_map.ForkProgress;
const ProgressMap = sig.consensus.ProgressMap;

const ConfirmSlotError = replay.confirm_slot.ConfirmSlotError;
const ConfirmSlotFuture = replay.confirm_slot.ConfirmSlotFuture;
const ConfirmSlotParams = replay.confirm_slot.ConfirmSlotParams;

const EpochTracker = replay.trackers.EpochTracker;
const ReplayState = replay.service.ReplayState;
const SlotTracker = replay.trackers.SlotTracker;
const SvmGateway = replay.svm_gateway.SvmGateway;

const Logger = sig.trace.Logger("replay.execution");

const vote_listener = sig.consensus.vote_listener;
const ParsedVote = vote_listener.vote_parser.ParsedVote;

const confirmSlot = replay.confirm_slot.confirmSlot;
const confirmSlotSync = replay.confirm_slot.confirmSlotSync;

/// 1. Replays transactions from all the slots that need to be replayed.
/// 2. Store the replay results into the relevant data structures.
///
/// Analogous to [replay_active_banks](https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3356)
pub fn replayActiveSlots(state: *ReplayState) ![]struct { Slot, *ConfirmSlotFuture } {
    var zone = tracy.Zone.init(@src(), .{ .name = "replayActiveSlots" });
    defer zone.deinit();

    const slot_tracker, var slot_lock = state.slot_tracker.readWithLock();
    defer slot_lock.unlock();

    const active_slots = try slot_tracker.activeSlots(state.allocator);
    defer state.allocator.free(active_slots);
    state.execution_log_helper.logActiveSlots(active_slots, state.allocator);

    if (active_slots.len == 0) {
        return &.{};
    }

    var slot_statuses = std.ArrayListUnmanaged(struct { Slot, *ConfirmSlotFuture }).empty;
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

        const future = try confirmSlot(
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
pub fn awaitResults(
    allocator: Allocator,
    /// takes ownership and frees with allocator
    slot_futures: []struct { Slot, *ConfirmSlotFuture },
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

pub const ReplayResult = struct {
    slot: Slot,
    output: union(enum) {
        last_entry_hash: sig.core.Hash,
        err: ConfirmSlotError,
    },
};

/// Fully synchronous version of replayActiveSlots that does not use
/// multithreading or async execution in any way.
pub fn replayActiveSlotsSync(state: *ReplayState) ![]const ReplayResult {
    const allocator = state.allocator;
    var zone = tracy.Zone.init(@src(), .{ .name = "replayActiveSlotsSync" });
    defer zone.deinit();

    const slot_tracker, var slot_lock = state.slot_tracker.readWithLock();
    defer slot_lock.unlock();

    const active_slots = try slot_tracker.activeSlots(allocator);
    defer allocator.free(active_slots);
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

        const maybe_err = try confirmSlotSync(allocator, .from(state.logger), params);
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
    confirm: ConfirmSlotParams,
};

/// Collects all the data necessary to confirm a slot with confirmSlot
///
/// - Initializes the ForkProgress in the progress map for the slot if necessary.
/// - Extracts the inputs for confirmSlot from the ledger and the slot and epoch trackers.
///
/// Combines the logic of these agave functions, just without actually executing
/// the slot. So, where agave's `confirm_slot` calls `confirm_slot_entries`,
/// at that point, we just return all the prepared data, which can be passed
/// into confirmSlot or confirmSlotSync.
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

    const verify_ticks_params = replay.confirm_slot.VerifyTicksParams{
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
