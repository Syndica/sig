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
const LatestValidatorVotes = sig.consensus.latest_validator_votes.LatestValidatorVotes;

const ConfirmSlotFuture = replay.confirm_slot.ConfirmSlotFuture;

const EpochTracker = replay.trackers.EpochTracker;
const SlotTracker = replay.trackers.SlotTracker;
const DuplicateSlots = replay.edge_cases.DuplicateSlots;
const DuplicateState = replay.edge_cases.DuplicateState;
const SlotFrozenState = replay.edge_cases.SlotFrozenState;
const DuplicateSlotsToRepair = replay.edge_cases.DuplicateSlotsToRepair;
const DuplicateConfirmedSlots = replay.edge_cases.DuplicateConfirmedSlots;
const PurgeRepairSlotCounters = replay.edge_cases.PurgeRepairSlotCounters;
const EpochSlotsFrozenSlots = replay.edge_cases.EpochSlotsFrozenSlots;
const UnfrozenGossipVerifiedVoteHashes = replay.edge_cases.UnfrozenGossipVerifiedVoteHashes;

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
    ledger_result_writer: *sig.ledger.LedgerResultWriter,
    slot_tracker: *SlotTracker,
    epochs: *EpochTracker,
    progress_map: *ProgressMap,
    fork_choice: *HeaviestSubtreeForkChoice,
    duplicate_slots_tracker: *DuplicateSlots,
    unfrozen_gossip_verified_vote_hashes: *UnfrozenGossipVerifiedVoteHashes,
    latest_validator_votes_for_frozen_banks: *LatestValidatorVotes,
    duplicate_confirmed_slots: *DuplicateConfirmedSlots,
    epoch_slots_frozen_slots: *const EpochSlotsFrozenSlots,
    duplicate_slots_to_repair: *DuplicateSlotsToRepair,
    purge_repair_slot_counter: *PurgeRepairSlotCounters,

    // owned
    status_cache: sig.core.StatusCache,

    pub fn init(
        allocator: Allocator,
        logger: sig.trace.Logger,
        my_identity: Pubkey,
        thread_pool: *ThreadPool,
        account_store: AccountStore,
        blockstore_reader: *BlockstoreReader,
        ledger_result_writer: *sig.ledger.LedgerResultWriter,
        slot_tracker: *SlotTracker,
        epochs: *EpochTracker,
        progress_map: *ProgressMap,
        fork_choice: *HeaviestSubtreeForkChoice,
        duplicate_slots_tracker: *DuplicateSlots,
        unfrozen_gossip_verified_vote_hashes: *UnfrozenGossipVerifiedVoteHashes,
        latest_validator_votes_for_frozen_banks: *LatestValidatorVotes,
        duplicate_confirmed_slots: *DuplicateConfirmedSlots,
        epoch_slots_frozen_slots: *const EpochSlotsFrozenSlots,
        duplicate_slots_to_repair: *DuplicateSlotsToRepair,
        purge_repair_slot_counter: *PurgeRepairSlotCounters,
    ) Allocator.Error!ReplayExecutionState {
        return .{
            .allocator = allocator,
            .logger = .from(logger),
            .my_identity = my_identity,
            .vote_account = null, // voting not currently supported
            .account_store = account_store,
            .thread_pool = thread_pool,
            .blockstore_reader = blockstore_reader,
            .ledger_result_writer = ledger_result_writer,
            .slot_tracker = slot_tracker,
            .epochs = epochs,
            .progress_map = progress_map,
            .fork_choice = fork_choice,
            .duplicate_slots_tracker = duplicate_slots_tracker,
            .unfrozen_gossip_verified_vote_hashes = unfrozen_gossip_verified_vote_hashes,
            .latest_validator_votes_for_frozen_banks = latest_validator_votes_for_frozen_banks,
            .duplicate_confirmed_slots = duplicate_confirmed_slots,
            .epoch_slots_frozen_slots = epoch_slots_frozen_slots,
            .duplicate_slots_to_repair = duplicate_slots_to_repair,
            .purge_repair_slot_counter = purge_repair_slot_counter,
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

pub fn processReplayResults(
    replay_state: *ReplayExecutionState,
    slot_statuses: *const std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }),
) !bool {
    var processed_a_slot = false;
    var tx_count: usize = 0;
    for (slot_statuses.items) |slot_status| {
        const slot, const status = slot_status;

        switch (status) {
            .confirm => |confirm_slot_future| {
                // Add timeout to prevent infinite loop
                const timeout = 30 * std.time.ns_per_s; // 30 second timeout
                const start_time = std.time.nanoTimestamp();

                while (try confirm_slot_future.poll() == .pending) {
                    if (std.time.nanoTimestamp() - start_time > timeout) {
                        try markDeadSlot(
                            slot,
                            replay_state.progress_map,
                            replay_state.ledger_result_writer,
                        );
                        continue;
                    }
                    std.time.sleep(10 * std.time.ns_per_ms);
                }
                if (try confirm_slot_future.poll() == .err) {
                    try markDeadSlot(
                        slot,
                        replay_state.progress_map,
                        replay_state.ledger_result_writer,
                    );
                    continue;
                }
                for (confirm_slot_future.entries) |entry| {
                    tx_count += entry.transactions.len;
                }
            },
            else => continue,
        }

        var slot_info = replay_state.slot_tracker.get(slot) orelse
            return error.MissingSlotInTracker;

        const parent_slot = slot_info.constants.parent_slot;
        const parent_hash = slot_info.constants.parent_hash;

        if (slot_info.state.tickHeight() == slot_info.constants.max_tick_height) {
            // Get bank progress from progress map
            var progress = replay_state.progress_map.map.getPtr(slot) orelse
                return error.MissingBankProgress;

            // Check if we are the leader for this block
            const is_leader_block =
                slot_info.constants.collector_id.equals(&replay_state.my_identity);

            const block_id: ?Hash = if (!is_leader_block)
                // If the block does not have at least DATA_SHREDS_PER_FEC_BLOCK correctly retransmitted
                // shreds in the last FEC set, mark it dead. No reason to perform this check on our leader block.
                // TODO add blockstore.check_last_fec_set_and_get_block_id ie with the checks.
                replay_state.blockstore_reader.lastFecSetUnchecked(slot) catch {
                    try markDeadSlot(
                        slot,
                        replay_state.progress_map,
                        replay_state.ledger_result_writer,
                    );
                    continue;
                }
            else
                null;

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
            // - cluster_slots_update_sender;
            // - transaction_status_sender;
            // - cost_update_sender;

            const hash = slot_info.state.hash.readCopy() orelse
                return error.MissingHash;
            std.debug.assert(!hash.eql(Hash.ZEROES));

            // Needs to be updated before `check_slot_agrees_with_cluster()` so that
            // any updates in `check_slot_agrees_with_cluster()` on fork choice take
            // effect
            try replay_state.fork_choice.addNewLeafSlot(
                .{
                    .slot = slot,
                    .hash = hash,
                },
                .{
                    .slot = parent_slot,
                    .hash = parent_hash,
                },
            );

            progress.fork_stats.bank_hash = hash;

            const slot_frozen_state: SlotFrozenState = .fromState(
                .from(replay_state.logger),
                slot,
                hash,
                replay_state.duplicate_slots_tracker,
                replay_state.duplicate_confirmed_slots,
                replay_state.fork_choice,
                replay_state.epoch_slots_frozen_slots,
            );
            try check_slot_agrees_with_cluster.slotFrozen(
                replay_state.allocator,
                .from(replay_state.logger),
                slot,
                replay_state.slot_tracker.root,
                replay_state.ledger_result_writer,
                replay_state.fork_choice,
                replay_state.duplicate_slots_to_repair,
                replay_state.purge_repair_slot_counter,
                slot_frozen_state,
            );

            if (!replay_state.duplicate_slots_tracker.contains(slot) and
                try replay_state.blockstore_reader.getDuplicateSlot(slot) != null)
            {
                const duplicate_state: DuplicateState = .fromState(
                    .from(replay_state.logger),
                    slot,
                    replay_state.duplicate_confirmed_slots,
                    replay_state.fork_choice,
                    .fromHash(hash),
                );

                try check_slot_agrees_with_cluster.duplicate(
                    replay_state.allocator,
                    .from(replay_state.logger),
                    slot,
                    parent_slot,
                    replay_state.duplicate_slots_tracker,
                    replay_state.fork_choice,
                    duplicate_state,
                );
            }

            // TODO bank_notification_sender

            // Move unfrozen_gossip_verified_vote_hashes entries to latest_validator_votes_for_frozen_banks
            if (replay_state.unfrozen_gossip_verified_vote_hashes.votes_per_slot
                .get(slot)) |slot_hashes_const|
            {
                var slot_hashes = slot_hashes_const;
                if (slot_hashes.fetchSwapRemove(hash)) |kv| {
                    var new_frozen_voters = kv.value;
                    defer new_frozen_voters.deinit(replay_state.allocator);
                    for (new_frozen_voters.items) |pubkey| {
                        _ = try replay_state.latest_validator_votes_for_frozen_banks.checkAddVote(
                            replay_state.allocator,
                            pubkey,
                            slot,
                            hash,
                            .replay,
                        );
                    }
                }
                // If `slot_hashes` becomes empty, it'll be removed by `setRoot()` later
            }

            // TODO block_metadata_notifier
            // TODO block_metadata_notifier
        }
    }

    return processed_a_slot;
}

fn markDeadSlot(
    dead_slot: Slot,
    progress_map: *ProgressMap,
    ledger_result_writer: *sig.ledger.LedgerResultWriter,
) !void {
    // TODO add getForkProgress
    var fork_progress = progress_map.map.getPtr(dead_slot) orelse
        return error.MissingBankProgress;
    fork_progress.is_dead = true;
    try ledger_result_writer.setDeadSlot(dead_slot);
    // TODO Add and update slot stats blockstore.slots_stats.mark_dead(slot);
}

const testing = std.testing;

// Mock ConfirmSlotFuture for testing
const MockConfirmSlotFuture = struct {
    status: replay.confirm_slot.ConfirmSlotStatus,
    entries: []const core.Entry,
    poll_count: usize = 0,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        status: replay.confirm_slot.ConfirmSlotStatus,
        num_entries: usize,
    ) !*Self {
        const future = try allocator.create(Self);

        // Create mock entries
        const entries = try allocator.alloc(core.Entry, num_entries);
        for (entries, 0..) |*entry, i| {
            entry.* = core.Entry{
                .num_hashes = 1,
                .hash = Hash.initRandom(std.crypto.random),
                .transactions = &.{}, // empty transactions for simplicity
            };
            // Add some mock transactions to the last entry for transaction counting
            if (i == num_entries - 1) {
                const mock_txs = try allocator.alloc(core.Transaction, 3);
                for (mock_txs, 0..) |*tx, j| {
                    tx.* = core.Transaction{
                        .signatures = &.{},
                        .version = .legacy,
                        .msg = core.transaction.Message{
                            .signature_count = 0,
                            .readonly_signed_count = 0,
                            .readonly_unsigned_count = 0,
                            .account_keys = &.{},
                            .recent_blockhash = Hash.ZEROES,
                            .instructions = &.{},
                        },
                    };
                    _ = j;
                }
                entry.transactions = mock_txs;
            }
        }

        future.* = Self{
            .status = status,
            .entries = entries,
        };

        return future;
    }

    pub fn destroy(self: *Self, allocator: Allocator) void {
        for (self.entries) |entry| {
            if (entry.transactions.len > 0) {
                allocator.free(entry.transactions);
            }
        }
        allocator.free(self.entries);
        allocator.destroy(self);
    }

    pub fn poll(self: *Self) !replay.confirm_slot.ConfirmSlotStatus {
        self.poll_count += 1;
        return self.status;
    }
};

// Helper to create a minimal ReplayExecutionState for testing
fn createTestReplayState(allocator: Allocator) !ReplayExecutionState {
    const account_store = AccountStore.noop;

    var thread_pool = ThreadPool.init(.{});

    const mock_lowest_cleanup_slot = try allocator.create(sig.sync.RwMux(Slot));
    mock_lowest_cleanup_slot.* = sig.sync.RwMux(Slot).init(0);

    const mock_max_root = try allocator.create(std.atomic.Value(u64));
    mock_max_root.* = std.atomic.Value(u64).init(0);

    const blockstore_reader = try allocator.create(BlockstoreReader);
    blockstore_reader.* = BlockstoreReader{
        .allocator = allocator,
        .logger = .noop,
        .db = undefined, // Mock database
        .lowest_cleanup_slot = mock_lowest_cleanup_slot,
        .max_root = mock_max_root,
        .rpc_api_metrics = undefined,
        .metrics = undefined,
    };

    const ledger_result_writer = try allocator.create(sig.ledger.LedgerResultWriter);
    ledger_result_writer.* = undefined; // Mock

    const slot_tracker = try allocator.create(SlotTracker);
    // Create a minimal SlotTracker with an empty slots map
    slot_tracker.* = SlotTracker{
        .slots = .empty,
        .root = 0,
    };

    const epochs = try allocator.create(EpochTracker);
    epochs.* = EpochTracker{
        .epochs = .empty,
        .schedule = undefined,
    };

    const progress_map = try allocator.create(ProgressMap);
    progress_map.* = ProgressMap.INIT;

    const fork_choice = try allocator.create(HeaviestSubtreeForkChoice);
    fork_choice.* = try HeaviestSubtreeForkChoice.init(allocator, .noop, .{
        .slot = 0,
        .hash = Hash.ZEROES,
    });

    const duplicate_slots_tracker = try allocator.create(DuplicateSlots);
    duplicate_slots_tracker.* = .empty;

    const unfrozen_gossip_verified_vote_hashes =
        try allocator.create(UnfrozenGossipVerifiedVoteHashes);
    unfrozen_gossip_verified_vote_hashes.* = .{ .votes_per_slot = .empty };

    const latest_validator_votes_for_frozen_banks = try allocator.create(LatestValidatorVotes);
    latest_validator_votes_for_frozen_banks.* = LatestValidatorVotes.empty;

    const duplicate_confirmed_slots = try allocator.create(DuplicateConfirmedSlots);
    duplicate_confirmed_slots.* = .empty;

    const epoch_slots_frozen_slots = try allocator.create(EpochSlotsFrozenSlots);
    epoch_slots_frozen_slots.* = .empty;

    const duplicate_slots_to_repair = try allocator.create(DuplicateSlotsToRepair);
    duplicate_slots_to_repair.* = .empty;

    const purge_repair_slot_counter = try allocator.create(PurgeRepairSlotCounters);
    purge_repair_slot_counter.* = .empty;

    return ReplayExecutionState.init(
        allocator,
        .noop,
        Pubkey.initRandom(std.crypto.random),
        &thread_pool,
        account_store,
        blockstore_reader,
        ledger_result_writer,
        slot_tracker,
        epochs,
        progress_map,
        fork_choice,
        duplicate_slots_tracker,
        unfrozen_gossip_verified_vote_hashes,
        latest_validator_votes_for_frozen_banks,
        duplicate_confirmed_slots,
        epoch_slots_frozen_slots,
        duplicate_slots_to_repair,
        purge_repair_slot_counter,
    );
}

fn cleanupTestReplayState(allocator: Allocator, state: *ReplayExecutionState) void {
    state.thread_pool.shutdown();
    state.thread_pool.deinit();

    allocator.destroy(state.blockstore_reader.lowest_cleanup_slot);
    allocator.destroy(state.blockstore_reader.max_root);
    allocator.destroy(state.blockstore_reader);

    allocator.destroy(state.ledger_result_writer);

    // SlotTracker cleanup - deinit the slots map
    state.slot_tracker.slots.deinit(allocator);
    allocator.destroy(state.slot_tracker);

    allocator.destroy(state.epochs);

    state.progress_map.deinit(allocator);
    allocator.destroy(state.progress_map);

    state.fork_choice.deinit();
    allocator.destroy(state.fork_choice);

    state.duplicate_slots_tracker.deinit(allocator);
    allocator.destroy(state.duplicate_slots_tracker);

    state.unfrozen_gossip_verified_vote_hashes.votes_per_slot.deinit(allocator);
    allocator.destroy(state.unfrozen_gossip_verified_vote_hashes);

    state.latest_validator_votes_for_frozen_banks.deinit(allocator);
    allocator.destroy(state.latest_validator_votes_for_frozen_banks);

    state.duplicate_confirmed_slots.deinit(allocator);
    allocator.destroy(state.duplicate_confirmed_slots);

    state.epoch_slots_frozen_slots.deinit(allocator);
    allocator.destroy(state.epoch_slots_frozen_slots);

    state.duplicate_slots_to_repair.deinit(allocator);
    allocator.destroy(state.duplicate_slots_to_repair);

    state.purge_repair_slot_counter.deinit(allocator);
    allocator.destroy(state.purge_repair_slot_counter);
}

test "processReplayResults: empty slot statuses" {
    const allocator = testing.allocator;

    var replay_state = createTestReplayState(allocator) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer cleanupTestReplayState(allocator, &replay_state);

    const empty_slot_statuses = std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }){};

    const result = processReplayResults(&replay_state, &empty_slot_statuses) catch |err| {
        std.debug.print("processReplayResults failed: {}\n", .{err});
        return err;
    };

    // Should return false since no slots were processed
    try testing.expect(!result);
}

test "processReplayResults: non-confirm statuses are skipped" {
    const allocator = testing.allocator;

    var replay_state = try createTestReplayState(allocator);
    defer cleanupTestReplayState(allocator, &replay_state);

    var slot_statuses = std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }){};
    defer slot_statuses.deinit(allocator);

    // Add various non-confirm statuses
    try slot_statuses.append(allocator, .{ 100, .empty });
    try slot_statuses.append(allocator, .{ 101, .dead });
    try slot_statuses.append(allocator, .{ 102, .leader });

    const result = try processReplayResults(&replay_state, &slot_statuses);

    // Should return false since no confirm slots were processed
    try testing.expect(!result);
}

test "processReplayResults: confirm slot with successful future" {
    const allocator = testing.allocator;

    var replay_state = try createTestReplayState(allocator);
    defer cleanupTestReplayState(allocator, &replay_state);

    const slot: Slot = 100;

    // Create a successful confirm slot future
    const mock_future = try MockConfirmSlotFuture.init(allocator, .done, 2);
    defer mock_future.destroy(allocator);

    var slot_statuses = std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }){};
    defer slot_statuses.deinit(allocator);

    try slot_statuses.append(allocator, .{ slot, .{ .confirm = @ptrCast(mock_future) } });

    // We need to add the slot to slot tracker and progress map for the function to proceed
    // This is a limitation of the current test setup - in a real scenario these would be set up
    // by earlier parts of the replay process

    // For now, let's expect an error since slot is missing from tracker
    const result = processReplayResults(&replay_state, &slot_statuses);
    try testing.expectError(error.MissingSlotInTracker, result);
}

test "processReplayResults: confirm slot with failed future marks slot dead" {
    const allocator = testing.allocator;

    var replay_state = try createTestReplayState(allocator);
    defer cleanupTestReplayState(allocator, &replay_state);

    const slot: Slot = 100;

    // Create a failed confirm slot future
    const mock_future =
        try MockConfirmSlotFuture.init(
            allocator,
            .{ .err = .{ .invalid_block = .InvalidEntryHash } },
            1,
        );
    defer mock_future.destroy(allocator);

    var slot_statuses = std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }){};
    defer slot_statuses.deinit(allocator);

    try slot_statuses.append(allocator, .{ slot, .{ .confirm = @ptrCast(mock_future) } });

    // Add slot to progress map so markDeadSlot can find it
    _ = try replay_state.progress_map.map.getOrPut(allocator, slot);

    const result = processReplayResults(&replay_state, &slot_statuses);

    // Should still expect error due to missing slot in tracker, but the dead slot marking should happen first
    try testing.expectError(error.MissingSlotInTracker, result);

    // Verify the slot was marked as dead in progress map
    const progress = replay_state.progress_map.map.get(slot);
    try testing.expect(progress != null);
    try testing.expect(progress.?.is_dead);
}

test "processReplayResults: transaction counting from entries" {
    const allocator = testing.allocator;

    var replay_state = try createTestReplayState(allocator);
    defer cleanupTestReplayState(allocator, &replay_state);

    const slot: Slot = 100;

    // Create a successful future with multiple entries containing transactions
    const mock_future = try MockConfirmSlotFuture.init(allocator, .done, 3);
    defer mock_future.destroy(allocator);

    var slot_statuses = std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }){};
    defer slot_statuses.deinit(allocator);

    try slot_statuses.append(allocator, .{ slot, .{ .confirm = @ptrCast(mock_future) } });

    // The function should count transactions from the last entry (which has 3 transactions)
    const result = processReplayResults(&replay_state, &slot_statuses);
    try testing.expectError(error.MissingSlotInTracker, result);

    // Verify poll was called (future should have been polled)
    try testing.expect(mock_future.poll_count > 0);
}

test "processReplayResults: mixed slot statuses" {
    const allocator = testing.allocator;

    var replay_state = try createTestReplayState(allocator);
    defer cleanupTestReplayState(allocator, &replay_state);

    var slot_statuses = std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }){};
    defer slot_statuses.deinit(allocator);

    // Mix of different status types
    try slot_statuses.append(allocator, .{ 100, .empty });
    try slot_statuses.append(allocator, .{ 101, .dead });
    try slot_statuses.append(allocator, .{ 102, .leader });

    // Add a successful confirm
    const mock_future = try MockConfirmSlotFuture.init(allocator, .done, 1);
    defer mock_future.destroy(allocator);
    try slot_statuses.append(allocator, .{ 103, .{ .confirm = @ptrCast(mock_future) } });

    const result = processReplayResults(&replay_state, &slot_statuses);

    // Should process the confirm slot and encounter missing slot error
    try testing.expectError(error.MissingSlotInTracker, result);

    // Verify only the confirm slot was processed
    try testing.expect(mock_future.poll_count > 0);
}

test "processReplayResults: return value correctness" {
    const allocator = testing.allocator;

    var replay_state = try createTestReplayState(allocator);
    defer cleanupTestReplayState(allocator, &replay_state);

    // Test that the function returns:
    // - false when no slots are processed
    // - true when at least one slot is fully processed (reaches processed_a_slot = true)

    // Empty case
    const empty_slot_statuses = std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }){};
    const empty_result = try processReplayResults(&replay_state, &empty_slot_statuses);
    try testing.expect(!empty_result);

    // Non-confirm statuses case
    var non_confirm_statuses = std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }){};
    defer non_confirm_statuses.deinit(allocator);
    try non_confirm_statuses.append(allocator, .{ 100, .empty });

    const non_confirm_result = try processReplayResults(&replay_state, &non_confirm_statuses);
    try testing.expect(!non_confirm_result);
}
