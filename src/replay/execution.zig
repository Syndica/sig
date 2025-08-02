const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const core = sig.core;

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const Pubkey = core.Pubkey;
const Slot = core.Slot;
const Hash = sig.core.Hash;

const AccountStore = sig.accounts_db.AccountStore;
const BlockstoreReader = sig.ledger.BlockstoreReader;

const ForkProgress = sig.consensus.progress_map.ForkProgress;
const ProgressMap = sig.consensus.ProgressMap;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;

const ConfirmSlotFuture = replay.confirm_slot.ConfirmSlotFuture;
const EpochTracker = replay.trackers.EpochTracker;
const SlotTracker = replay.trackers.SlotTracker;
const DuplicateSlots = replay.edge_cases.DuplicateSlots;
const DuplicateState = replay.edge_cases.DuplicateState;
const DuplicateConfirmedSlots = replay.edge_cases.DuplicateConfirmedSlots;

const check_slot_agrees_with_cluster = replay.edge_cases.check_slot_agrees_with_cluster;

const SvmGateway = replay.svm_gateway.SvmGateway;

const confirmSlot = replay.confirm_slot.confirmSlot;

/// State used for replaying and validating data from blockstore/accountsdb/svm
pub const ReplayExecutionState = struct {
    allocator: Allocator,
    logger: sig.trace.ScopedLogger("replay-execution"),
    my_identity: Pubkey,
    vote_account: ?Pubkey,

    // borrows
    account_store: AccountStore,
    thread_pool: *ThreadPool,
    blockstore_reader: *BlockstoreReader,
    slot_tracker: *SlotTracker,
    epochs: *EpochTracker,
    progress_map: *ProgressMap,
    fork_choice: *HeaviestSubtreeForkChoice,
    duplicate_slots_tracker: *DuplicateSlots,
    duplicate_confirmed_slots: *DuplicateConfirmedSlots,

    // owned
    status_cache: sig.core.StatusCache,

    pub fn init(
        allocator: Allocator,
        logger: sig.trace.Logger,
        my_identity: Pubkey,
        thread_pool: *ThreadPool,
        account_store: AccountStore,
        blockstore_reader: *BlockstoreReader,
        slot_tracker: *SlotTracker,
        epochs: *EpochTracker,
        progress_map: *ProgressMap,
        fork_choice: *HeaviestSubtreeForkChoice,
        duplicate_slots_tracker: *DuplicateSlots,
        duplicate_confirmed_slots: *DuplicateConfirmedSlots,
    ) Allocator.Error!ReplayExecutionState {
        return .{
            .allocator = allocator,
            .logger = .from(logger),
            .my_identity = my_identity,
            .vote_account = null, // voting not currently supported
            .account_store = account_store,
            .thread_pool = thread_pool,
            .blockstore_reader = blockstore_reader,
            .slot_tracker = slot_tracker,
            .epochs = epochs,
            .progress_map = progress_map,
            .fork_choice = fork_choice,
            .duplicate_slots_tracker = duplicate_slots_tracker,
            .duplicate_confirmed_slots = duplicate_confirmed_slots,
            .status_cache = .DEFAULT,
        };
    }
};

/// 1. Replays transactions from all the slots that need to be replayed.
/// 2. Store the replay results into the relevant data structures.
///
/// Analogous to [replay_active_banks](https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3356)
pub fn replayActiveSlots(state: *ReplayExecutionState) !bool {
    const active_slots = try state.slot_tracker.activeSlots(state.allocator);
    state.logger.info().logf("{} active slots to replay", .{active_slots.len});
    if (active_slots.len == 0) {
        return false;
    }

    var slot_statuses = std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }).empty;
    defer {
        for (slot_statuses.items) |status| status[1].deinit(state.allocator);
        slot_statuses.deinit(state.allocator);
    }
    for (active_slots) |slot| {
        state.logger.info().logf("replaying slot: {}", .{slot});
        const result = try replaySlot(state, slot);
        errdefer result.deinit(state.allocator);
        try slot_statuses.append(state.allocator, .{ slot, result });
    }
    var processed_a_slot = false;
    // TODO this should be part of processReplayResults
    // for (slot_statuses.items) |slot_status| {
    //     // NOTE: currently this just awaits the futures and discards the
    //     // results. this will change once we call the svm and process the
    //     // results of execution.
    //     const slot, const status = slot_status;
    //     if (status != .confirm) continue;

    //     const slot_info = state.slot_tracker.get(slot) orelse unreachable;
    //     const epoch_info = state.epochs.getForSlot(slot) orelse unreachable;

    //     const future = status.confirm;
    //     // NOTE: agave does this a bit differently, it indicates that a slot
    //     // was *finished*, not just processed partially.
    //     processed_a_slot = true;
    //     while (try status.confirm.poll() == .pending) {
    //         // TODO: consider futex-based wait like ResetEvent
    //         std.time.sleep(std.time.ns_per_ms);
    //     }

    //     if (slot_info.state.tickHeight() == slot_info.constants.max_tick_height) {
    //         state.logger.info().logf("confirmed entire slot {}", .{slot});
    //         try replay.freeze.freezeSlot(state.allocator, .init(
    //             .from(state.logger),
    //             state.account_store,
    //             &epoch_info,
    //             slot_info.state,
    //             slot_info.constants,
    //             slot,
    //             future.entries[future.entries.len - 1].hash,
    //         ));
    //     } else {
    //         state.logger.info().logf("partially confirmed slot {}", .{slot});
    //     }
    // }

    processed_a_slot = try processReplayResults(state, &slot_statuses);
    return processed_a_slot;
}

const ReplaySlotStatus = union(enum) {
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

    /// The slot is being confirmed, poll this to await the result.
    confirm: *ConfirmSlotFuture,

    fn deinit(self: ReplaySlotStatus, allocator: Allocator) void {
        switch (self) {
            .confirm => |future| future.destroy(allocator),
            else => {},
        }
    }
};

/// Replay the transactions from any entries in the slot that we've received but
/// haven't yet replayed. Integrates with accountsdb and blockstore.
///
/// - Calls confirmSlot to verify/execute a slot's transactions.
/// - Initializes the ForkProgress in the progress map for the slot if necessary.
/// - Extracts the inputs for those functions from the ledger and the slot and epoch trackers.
///
/// Combines the logic of three agave functions:
/// - [replay_active_bank](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/core/src/replay_stage.rs#L2979)
/// - [replay_blockstore_into_bank](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/core/src/replay_stage.rs#L2232)
/// - [confirm_slot](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/ledger/src/blockstore_processor.rs#L1494)
fn replaySlot(state: *ReplayExecutionState, slot: Slot) !ReplaySlotStatus {
    const progress_get_or_put = try state.progress_map.map.getOrPut(state.allocator, slot);
    if (progress_get_or_put.found_existing and progress_get_or_put.value_ptr.is_dead) {
        return .dead;
    }

    const epoch_info = state.epochs.getForSlot(slot) orelse return error.MissingEpoch;
    const slot_info = state.slot_tracker.get(slot) orelse return error.MissingSlot;

    const i_am_leader = slot_info.constants.collector_id.equals(&state.my_identity);

    if (!progress_get_or_put.found_existing) {
        const parent_slot = slot_info.constants.parent_slot;
        const parent = state.progress_map.map.getPtr(parent_slot) orelse
            return error.MissingParentProgress;

        progress_get_or_put.value_ptr.* = try ForkProgress.initFromParent(state.allocator, .{
            .slot = slot,
            .parent_slot = parent_slot,
            .parent = parent,
            .slot_hash = slot_info.state.hash.readCopy(),
            .last_entry = slot_info.state.blockhash_queue.readField("last_hash") orelse
                return error.MissingLastHash,
            .i_am_leader = i_am_leader,
            .epoch_stakes = &epoch_info.stakes,
            .now = sig.time.Instant.now(),
            .validator_vote_pubkey = state.vote_account,
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

    const entries, const slot_is_full, const blockhash_queue = blk: {
        const entries, const num_shreds, const slot_is_full =
            try state.blockstore_reader.getSlotEntriesWithShredInfo(
                state.allocator,
                slot,
                confirmation_progress.num_shreds,
                false,
            );
        errdefer {
            for (entries) |entry| entry.deinit(state.allocator);
            state.allocator.free(entries);
        }
        state.logger.info().logf("got {} entries for slot {}", .{ entries.len, slot });

        if (entries.len == 0) {
            for (entries) |entry| entry.deinit(state.allocator);
            state.allocator.free(entries);
            return .empty;
        }

        confirmation_progress.num_shreds += num_shreds;
        confirmation_progress.num_entries += entries.len;
        for (entries) |e| confirmation_progress.num_txs += e.transactions.len;

        const blockhash_queue = bhq: {
            var bhq = slot_info.state.blockhash_queue.read();
            defer bhq.unlock();
            break :bhq try bhq.get().clone(state.allocator);
        };
        errdefer blockhash_queue.deinit(state.allocator);

        break :blk .{ entries, slot_is_full, blockhash_queue };
    };

    const svm_params = SvmGateway.Params{
        .slot = slot,
        .max_age = sig.core.BlockhashQueue.MAX_RECENT_BLOCKHASHES / 2,
        .lamports_per_signature = slot_info.constants.fee_rate_governor.lamports_per_signature,
        .blockhash_queue = blockhash_queue,
        .account_reader = state.account_store.reader().forSlot(&slot_info.constants.ancestors),
        .ancestors = &slot_info.constants.ancestors,
        .feature_set = slot_info.constants.feature_set,
        .rent_collector = &epoch_info.rent_collector,
        .epoch_stakes = &epoch_info.stakes,
        .status_cache = &state.status_cache,
    };

    const committer = replay.commit.Committer{
        .account_store = state.account_store,
        .slot_state = slot_info.state,
        .status_cache = &state.status_cache,
        .stakes_cache = &slot_info.state.stakes_cache,
    };

    const verify_ticks_params = replay.confirm_slot.VerifyTicksParams{
        .tick_height = slot_info.state.tickHeight(),
        .max_tick_height = slot_info.constants.max_tick_height,
        .hashes_per_tick = epoch_info.hashes_per_tick,
        .slot = slot,
        .slot_is_full = slot_is_full,
        .tick_hash_count = &confirmation_progress.tick_hash_count,
    };

    var num_ticks: u64 = 0;
    for (entries) |entry| {
        if (entry.isTick()) num_ticks += 1;
    }
    _ = slot_info.state.tick_height.fetchAdd(num_ticks, .monotonic);

    return .{ .confirm = try confirmSlot(
        state.allocator,
        .from(state.logger),
        state.account_store,
        state.thread_pool,
        entries,
        confirmation_progress.last_entry,
        svm_params,
        committer,
        verify_ticks_params,
        &slot_info.constants.ancestors,
    ) };
}

fn processReplayResults(
    replay_state: *ReplayExecutionState,
    slot_statuses: *const std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }),
) !bool {
    var processed_a_slot = false;
    var tx_count: usize = 0;
    for (slot_statuses.items) |slot_status| {
        const slot, const status = slot_status;
        var slot_info = replay_state.slot_tracker.get(slot) orelse
            return error.MissingSlotInTracker;

        switch (status) {
            .confirm => |confirm_slot_future| {
                while (try confirm_slot_future.poll() == .pending) {
                    std.time.sleep(std.time.ns_per_ms);
                }
                for (confirm_slot_future.entries) |entry| {
                    tx_count += entry.transactions.len;
                }
            },
            // QA: Should mark_dead_slot be called here?
            else => return false,
        }

        if (slot_info.state.tickHeight() == slot_info.constants.max_tick_height) {
            // TODO add bank.wait_for_completed_scheduler()

            // Get bank progress from progress map
            var progress = replay_state.progress_map.map.getPtr(slot) orelse
                return error.MissingBankProgress;

            // TODO Update bank_progress.replay_stats
            // TODO Also update mark_dead_slot in an error path?

            // Check if we are the leader for this block
            const is_leader_block =
                slot_info.constants.collector_id.equals(&replay_state.my_identity);

            const block_id: ?Hash = if (!is_leader_block) blk: {
                // If the block does not have at least DATA_SHREDS_PER_FEC_BLOCK correctly retransmitted
                // shreds in the last FEC set, mark it dead. No reason to perform this check on our leader block.
                // TODO Also update mark_dead_slot in an error path?
                break :blk null;
            } else null;

            slot_info.state.hash = .init(block_id);

            // Freeze the bank before sending to any auxiliary threads
            // that may expect to be operating on a frozen bank
            try replay.freeze.freezeSlot(replay_state.allocator, .init(
                .from(replay_state.logger),
                replay_state.account_store,
                &(replay_state.epochs.getForSlot(slot) orelse return error.MissingEpoch),
                slot_info.state,
                slot_info.constants,
                slot,
                status.confirm.entries[status.confirm.entries.len - 1].hash,
            ));

            processed_a_slot = true;

            // TODO Send things out via a couple of senders
            // TODO cluster_slots_update_sender;
            // TODO transaction_status_sender;
            // TODO cost_update_sender;

            std.debug.assert(!slot_info.state.hash.readCopy().?.eql(Hash.ZEROES));

            // Needs to be updated before `check_slot_agrees_with_cluster()` so that
            // any updates in `check_slot_agrees_with_cluster()` on fork choice take
            // effect
            try replay_state.fork_choice.addNewLeafSlot(
                .{
                    .slot = slot,
                    .hash = slot_info.state.hash.readCopy() orelse return error.MissingHash,
                },
                .{
                    .slot = slot_info.constants.parent_slot,
                    .hash = slot_info.constants.parent_hash,
                },
            );

            progress.fork_stats.bank_hash = slot_info.state.hash.readCopy() orelse
                return error.MissingHash;
            // TODO check_slot_agrees_with_cluster: BankFrozen

            // If we previously marked this slot as duplicate in blockstore, let the state machine know
            if (replay_state.duplicate_slots_tracker.contains(slot) and
                try replay_state.blockstore_reader.getDuplicateSlot(slot) != null)
            {
                const duplicate_state: DuplicateState = .fromState(
                    .from(replay_state.logger),
                    slot,
                    replay_state.duplicate_confirmed_slots,
                    replay_state.fork_choice,
                    .fromHash(slot_info.state.hash.readCopy()),
                );

                try check_slot_agrees_with_cluster.duplicate(
                    replay_state.allocator,
                    .from(replay_state.logger),
                    slot,
                    slot_info.constants.parent_slot,
                    replay_state.duplicate_slots_tracker,
                    replay_state.fork_choice,
                    duplicate_state,
                );
            }

            // TODO bank_notification_sender
            // TODO Move unfrozen_gossip_verified_vote_hashes to latest_validator_votes_for_frozen_banks
            // TODO block_metadata_notifier
        }
    }

    return processed_a_slot;
}
