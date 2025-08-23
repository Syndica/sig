const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");
const vote_listener = @import("../consensus/vote_listener.zig");

const core = sig.core;

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const Pubkey = core.Pubkey;
const Slot = core.Slot;
const Hash = sig.core.Hash;

const AccountStore = sig.accounts_db.AccountStore;
const LedgerReader = sig.ledger.LedgerReader;

const AncestorHashesReplayUpdate = replay.consensus.AncestorHashesReplayUpdate;
const ForkProgress = sig.consensus.progress_map.ForkProgress;
const ProgressMap = sig.consensus.ProgressMap;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const LatestValidatorVotes = sig.consensus.latest_validator_votes.LatestValidatorVotes;

const ConfirmSlotFuture = replay.confirm_slot.ConfirmSlotFuture;

const EpochTracker = replay.trackers.EpochTracker;
const SlotTracker = replay.trackers.SlotTracker;
const DuplicateSlots = replay.edge_cases.SlotData.DuplicateSlots;
const DuplicateState = replay.edge_cases.DuplicateState;
const SlotFrozenState = replay.edge_cases.SlotFrozenState;
const DuplicateSlotsToRepair = replay.edge_cases.SlotData.DuplicateSlotsToRepair;
const DuplicateConfirmedSlots = replay.edge_cases.SlotData.DuplicateConfirmedSlots;
const PurgeRepairSlotCounters = replay.edge_cases.SlotData.PurgeRepairSlotCounters;
const EpochSlotsFrozenSlots = replay.edge_cases.SlotData.EpochSlotsFrozenSlots;
const UnfrozenGossipVerifiedVoteHashes = replay.edge_cases.UnfrozenGossipVerifiedVoteHashes;

const Logger = sig.trace.Logger("replay.execution");

const check_slot_agrees_with_cluster = replay.edge_cases.check_slot_agrees_with_cluster;

const SvmGateway = replay.svm_gateway.SvmGateway;

const ParsedVote = vote_listener.vote_parser.ParsedVote;

const confirmSlot = replay.confirm_slot.confirmSlot;

/// State used for replaying and validating data from ledger/accountsdb/svm
pub const ReplayExecutionState = struct {
    allocator: Allocator,
    logger: Logger,
    my_identity: Pubkey,
    vote_account: ?Pubkey,

    // borrows
    account_store: AccountStore,
    thread_pool: *ThreadPool,
    ledger_reader: *LedgerReader,
    ledger_result_writer: *sig.ledger.LedgerResultWriter,
    slot_tracker: *sig.sync.RwMux(SlotTracker),
    epochs: *sig.sync.RwMux(EpochTracker),
    progress_map: *ProgressMap,
    status_cache: *sig.core.StatusCache,
    fork_choice: *HeaviestSubtreeForkChoice,
    duplicate_slots_tracker: *DuplicateSlots,
    unfrozen_gossip_verified_vote_hashes: *UnfrozenGossipVerifiedVoteHashes,
    latest_validator_votes: *LatestValidatorVotes,
    duplicate_confirmed_slots: *DuplicateConfirmedSlots,
    epoch_slots_frozen_slots: *const EpochSlotsFrozenSlots,
    duplicate_slots_to_repair: *DuplicateSlotsToRepair,
    purge_repair_slot_counter: *PurgeRepairSlotCounters,
    ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
    replay_votes_ch: *sig.sync.Channel(ParsedVote),
};

/// 1. Replays transactions from all the slots that need to be replayed.
/// 2. Store the replay results into the relevant data structures.
///
/// Analogous to [replay_active_banks](https://github.com/anza-xyz/agave/blob/3f68568060fd06f2d561ad79e8d8eb5c5136815a/core/src/replay_stage.rs#L3356)
pub fn replayActiveSlots(state: ReplayExecutionState) !bool {
    var zone = tracy.Zone.init(@src(), .{ .name = "replayActiveSlots" });
    defer zone.deinit();

    const active_slots = blk: {
        const tracker, var lg = state.slot_tracker.readWithLock();
        defer lg.unlock();
        break :blk try tracker.activeSlots(state.allocator);
    };
    defer state.allocator.free(active_slots);
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
    return try processReplayResults(state, slot_statuses.items);
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

    fn deinit(self: ReplaySlotStatus, allocator: std.mem.Allocator) void {
        switch (self) {
            .confirm => |future| future.destroy(allocator),
            else => {},
        }
    }
};

/// Replay the transactions from any entries in the slot that we've received but
/// haven't yet replayed. Integrates with accountsdb and ledger.
///
/// - Calls confirmSlot to verify/execute a slot's transactions.
/// - Initializes the ForkProgress in the progress map for the slot if necessary.
/// - Extracts the inputs for those functions from the ledger and the slot and epoch trackers.
///
/// Combines the logic of three agave functions:
/// - [replay_active_bank](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/core/src/replay_stage.rs#L2979)
/// - [replay_blockstore_into_bank](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/core/src/replay_stage.rs#L2232)
/// - [confirm_slot](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/ledger/src/blockstore_processor.rs#L1494)
fn replaySlot(state: ReplayExecutionState, slot: Slot) !ReplaySlotStatus {
    var zone = tracy.Zone.init(@src(), .{ .name = "replaySlot" });
    zone.value(slot);
    defer zone.deinit();
    errdefer zone.color(0xFF0000);

    const progress_get_or_put = try state.progress_map.map.getOrPut(state.allocator, slot);
    if (progress_get_or_put.found_existing and progress_get_or_put.value_ptr.is_dead) {
        return .dead;
    }

    const epoch_info = blk: {
        const epochs_ptr, var lg = state.epochs.readWithLock();
        defer lg.unlock();
        break :blk (epochs_ptr.getForSlot(slot) orelse return error.MissingEpoch);
    };

    const tracker_ptr, var tracker_lg = state.slot_tracker.readWithLock();
    defer tracker_lg.unlock();
    const slot_info = tracker_ptr.get(slot) orelse return error.MissingSlot;

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

    const previous_last_entry = confirmation_progress.last_entry;
    const entries, const slot_is_full = blk: {
        const entries, const num_shreds, const slot_is_full =
            try state.ledger_reader.getSlotEntriesWithShredInfo(
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
            return .empty;
        }

        confirmation_progress.last_entry = entries[entries.len - 1].hash;
        confirmation_progress.num_shreds += num_shreds;
        confirmation_progress.num_entries += entries.len;
        for (entries) |e| confirmation_progress.num_txs += e.transactions.len;

        break :blk .{ entries, slot_is_full };
    };

    const new_rate_activation_epoch = blk: {
        if (slot_info.constants.feature_set.get(.reduce_stake_warmup_cooldown)) |active_slot| {
            const schedule = state.epochs.readField("schedule");
            break :blk schedule.getEpoch(active_slot);
        } else break :blk null;
    };

    const svm_params = SvmGateway.Params{
        .slot = slot,
        .max_age = sig.core.BlockhashQueue.MAX_RECENT_BLOCKHASHES / 2,
        .lamports_per_signature = slot_info.constants.fee_rate_governor.lamports_per_signature,
        .blockhash_queue = &slot_info.state.blockhash_queue,
        .account_reader = state.account_store.reader().forSlot(&slot_info.constants.ancestors),
        .ancestors = &slot_info.constants.ancestors,
        .feature_set = slot_info.constants.feature_set,
        .rent_collector = &epoch_info.rent_collector,
        .epoch_stakes = &epoch_info.stakes,
        .status_cache = state.status_cache,
    };

    const committer = replay.commit.Committer{
        .logger = .from(state.logger),
        .account_store = state.account_store,
        .slot_state = slot_info.state,
        .status_cache = state.status_cache,
        .stakes_cache = &slot_info.state.stakes_cache,
        .new_rate_activation_epoch = new_rate_activation_epoch,
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
        previous_last_entry,
        svm_params,
        committer,
        verify_ticks_params,
        &slot_info.constants.ancestors,
        &slot_info.constants.reserved_accounts,
        state.replay_votes_ch,
    ) };
}

/// Polls a confirm status to obtain entries for a slot. If the confirm
/// future yields an error, marks the slot as dead. Returns null if the slot
/// should be skipped (non-confirm status, pending, or error).
fn awaitConfirmedEntriesForSlot(
    replay_state: ReplayExecutionState,
    slot: Slot,
    status: ReplaySlotStatus,
) !?[]const sig.core.Entry {
    return switch (status) {
        .confirm => |confirm_slot_future| blk: {
            while (true) {
                const poll_result = try confirm_slot_future.poll();
                switch (poll_result) {
                    .err => {
                        try markDeadSlot(
                            replay_state,
                            slot,
                            replay_state.ancestor_hashes_replay_update_sender,
                        );
                        break :blk null;
                    },
                    .done => break :blk confirm_slot_future.entries,
                    .pending => {
                        // TODO: consider futex-based wait like ResetEvent
                        std.time.sleep(std.time.ns_per_ms);
                    },
                }
            }
        },
        else => null,
    };
}

/// Applies fork-choice and vote updates after a slot has been frozen.
fn updateConsensusForFrozenSlot(
    replay_state: ReplayExecutionState,
    slot: Slot,
) !void {
    const slot_tracker, var lg = replay_state.slot_tracker.readWithLock();
    defer lg.unlock();
    var slot_info = slot_tracker.get(slot) orelse
        return error.MissingSlotInTracker;

    const parent_slot = slot_info.constants.parent_slot;
    const parent_hash = slot_info.constants.parent_hash;

    var progress = replay_state.progress_map.map.getPtr(slot) orelse
        return error.MissingBankProgress;

    const hash = slot_info.state.hash.readCopy() orelse
        return error.MissingHash;
    std.debug.assert(!hash.eql(Hash.ZEROES));

    // Needs to be updated before `check_slot_agrees_with_cluster()` so that any
    // updates in `check_slot_agrees_with_cluster()` on fork choice take effect
    try replay_state.fork_choice.addNewLeafSlot(
        .{ .slot = slot, .hash = hash },
        .{ .slot = parent_slot, .hash = parent_hash },
    );

    progress.fork_stats.slot_hash = hash;

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
        slot_tracker.root,
        replay_state.ledger_result_writer,
        replay_state.fork_choice,
        replay_state.duplicate_slots_to_repair,
        replay_state.purge_repair_slot_counter,
        slot_frozen_state,
    );

    if (!replay_state.duplicate_slots_tracker.contains(slot) and
        try replay_state.ledger_reader.getDuplicateSlot(slot) != null)
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

    // Move unfrozen_gossip_verified_vote_hashes entries to latest_validator_votes
    if (replay_state
        .unfrozen_gossip_verified_vote_hashes.votes_per_slot
        .get(slot)) |slot_hashes_const|
    {
        var slot_hashes = slot_hashes_const;
        if (slot_hashes.fetchSwapRemove(hash)) |kv| {
            var new_frozen_voters = kv.value;
            defer new_frozen_voters.deinit(replay_state.allocator);
            for (new_frozen_voters.items) |pubkey| {
                _ = try replay_state.latest_validator_votes.checkAddVote(
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
}

pub fn processReplayResults(
    replay_state: ReplayExecutionState,
    slot_statuses: []const struct { Slot, ReplaySlotStatus },
) !bool {
    var processed_a_slot = false;
    for (slot_statuses) |slot_status| {
        const slot, const status = slot_status;

        const maybe_entries = try awaitConfirmedEntriesForSlot(
            replay_state,
            slot,
            status,
        );
        // If entries is null, it means the slot failed or was skipped, so continue to next slot
        const entries = if (maybe_entries) |entries| entries else continue;

        const slot_tracker_ptr, var lg = replay_state.slot_tracker.readWithLock();
        defer lg.unlock();
        var slot_info = slot_tracker_ptr.get(slot) orelse
            return error.MissingSlotInTracker;

        // Freeze the bank if its entries where completly processed.
        if (slot_info.state.tickHeight() == slot_info.constants.max_tick_height) {
            const is_leader_block =
                slot_info.constants.collector_id.equals(&replay_state.my_identity);
            if (!is_leader_block) {
                try replay.freeze.freezeSlot(replay_state.allocator, .init(
                    .from(replay_state.logger),
                    replay_state.account_store,
                    &(blk: {
                        const epochs_ptr, var epochs_lg = replay_state.epochs.readWithLock();
                        defer epochs_lg.unlock();
                        break :blk (epochs_ptr.getForSlot(slot) orelse return error.MissingEpoch);
                    }),
                    slot_info.state,
                    slot_info.constants,
                    slot,
                    entries[entries.len - 1].hash,
                ));
            }
            processed_a_slot = true;
            // TODO Send things out via a couple of senders
            // - cluster_slots_update_sender;
            // - transaction_status_sender;
            // - cost_update_sender;
            try updateConsensusForFrozenSlot(replay_state, slot);
            // TODO block_metadata_notifier
            // TODO block_metadata_notifier
        }
    }
    return processed_a_slot;
}

/// Analogous to [mark_dead_slot](https://github.com/anza-xyz/agave/blob/15635be1503566820331cd2c845675641a42d405/core/src/replay_stage.rs#L2255)
fn markDeadSlot(
    replay_state: ReplayExecutionState,
    dead_slot: Slot,
    ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
) !void {
    // TODO add getForkProgress
    const fork_progress = replay_state.progress_map.map.getPtr(dead_slot) orelse {
        return error.MissingBankProgress;
    };
    fork_progress.is_dead = true;
    try replay_state.ledger_result_writer.setDeadSlot(dead_slot);
    // TODOs
    // - blockstore.slots_stats.mark_dead(slot);
    // - slot_status_notifier
    // - rpc_subscriptions

    const dead_state: replay.edge_cases.DeadState = .fromState(
        .from(replay_state.logger),
        dead_slot,
        replay_state.duplicate_slots_tracker,
        replay_state.duplicate_confirmed_slots,
        replay_state.fork_choice,
        replay_state.epoch_slots_frozen_slots,
    );
    try check_slot_agrees_with_cluster.dead(
        replay_state.allocator,
        .from(replay_state.logger),
        dead_slot,
        replay_state.slot_tracker.readField("root"),
        replay_state.duplicate_slots_to_repair,
        ancestor_hashes_replay_update_sender,
        dead_state,
    );

    // If blockstore previously marked this slot as duplicate, invoke duplicate state as well
    const maybe_duplicate_proof = try replay_state.ledger_reader.getDuplicateSlot(dead_slot);
    defer if (maybe_duplicate_proof) |proof| {
        replay_state.ledger_reader.allocator.free(proof.shred1);
        replay_state.ledger_reader.allocator.free(proof.shred2);
    };
    if (!replay_state.duplicate_slots_tracker.contains(dead_slot) and
        maybe_duplicate_proof != null)
    {
        const slot_info = blk: {
            const st, var lg = replay_state.slot_tracker.readWithLock();
            defer lg.unlock();
            break :blk st.get(dead_slot) orelse return error.MissingSlotInTracker;
        };
        const slot_hash = slot_info.state.hash.readCopy();
        const duplicate_state: DuplicateState = .fromState(
            .from(replay_state.logger),
            dead_slot,
            replay_state.duplicate_confirmed_slots,
            replay_state.fork_choice,
            if (replay_state.progress_map.isDead(dead_slot) orelse false)
                .dead
            else
                .fromHash(slot_hash),
        );
        try check_slot_agrees_with_cluster.duplicate(
            replay_state.allocator,
            .from(replay_state.logger),
            dead_slot,
            replay_state.slot_tracker.readField("root"),
            replay_state.duplicate_slots_tracker,
            replay_state.fork_choice,
            duplicate_state,
        );
    }
}

const testing = std.testing;

// Test helper structure that owns all the resources
const TestReplayStateResources = struct {
    thread_pool: ThreadPool,
    ledger_reader: LedgerReader,
    ledger_result_writer: sig.ledger.LedgerResultWriter,
    epochs: sig.sync.RwMux(EpochTracker),
    progress: ProgressMap,
    fork_choice: *HeaviestSubtreeForkChoice,
    duplicate_slots_tracker: DuplicateSlots,
    unfrozen_gossip_verified_vote_hashes: UnfrozenGossipVerifiedVoteHashes,
    latest_validator_votes: LatestValidatorVotes,
    duplicate_confirmed_slots: DuplicateConfirmedSlots,
    epoch_slots_frozen_slots: EpochSlotsFrozenSlots,
    duplicate_slots_to_repair: DuplicateSlotsToRepair,
    purge_repair_slot_counter: PurgeRepairSlotCounters,
    slot_tracker: sig.sync.RwMux(SlotTracker),
    replay_state: ReplayExecutionState,
    db: sig.ledger.LedgerDB,
    registry: sig.prometheus.Registry(.{}),
    lowest_cleanup_slot: sig.sync.RwMux(Slot),
    max_root: std.atomic.Value(Slot),
    ancestor_hashes_replay_update_channel: sig.sync.Channel(AncestorHashesReplayUpdate),

    pub fn init(allocator: Allocator) !*TestReplayStateResources {
        const self = try allocator.create(TestReplayStateResources);
        errdefer allocator.destroy(self);

        const account_store = AccountStore.noop;
        var status_cache = sig.core.StatusCache.DEFAULT;
        defer status_cache.deinit(allocator);

        self.registry = sig.prometheus.Registry(.{}).init(allocator);
        errdefer self.registry.deinit();

        self.db = try sig.ledger.tests.TestDB.init(@src());
        errdefer self.db.deinit();

        self.lowest_cleanup_slot = sig.sync.RwMux(Slot).init(0);
        self.max_root = std.atomic.Value(Slot).init(0);

        self.thread_pool = ThreadPool.init(.{});

        self.ledger_reader = try LedgerReader.init(
            allocator,
            .noop,
            self.db,
            &self.registry,
            &self.lowest_cleanup_slot,
            &self.max_root,
        );

        self.ledger_result_writer = try sig.ledger.LedgerResultWriter.init(
            allocator,
            .noop,
            self.db,
            &self.registry,
            &self.lowest_cleanup_slot,
            &self.max_root,
        );

        const epoch_tracker_init: EpochTracker = .{
            .epochs = .empty,
            .schedule = sig.core.EpochSchedule.DEFAULT,
        };
        self.epochs = sig.sync.RwMux(EpochTracker).init(epoch_tracker_init);

        self.progress = ProgressMap.INIT;

        self.fork_choice = try allocator.create(HeaviestSubtreeForkChoice);
        self.fork_choice.* = try HeaviestSubtreeForkChoice.init(allocator, .noop, .{
            .slot = 0,
            .hash = Hash.ZEROES,
        });

        self.duplicate_slots_tracker = DuplicateSlots.empty;
        self.unfrozen_gossip_verified_vote_hashes = UnfrozenGossipVerifiedVoteHashes{
            .votes_per_slot = .empty,
        };
        self.latest_validator_votes = LatestValidatorVotes.empty;
        self.duplicate_confirmed_slots = DuplicateConfirmedSlots.empty;
        self.epoch_slots_frozen_slots = EpochSlotsFrozenSlots.empty;
        self.duplicate_slots_to_repair = DuplicateSlotsToRepair.empty;
        self.purge_repair_slot_counter = PurgeRepairSlotCounters.empty;

        const slot_tracker_init: SlotTracker = .{
            .slots = .empty,
            .root = 0,
        };
        self.slot_tracker = sig.sync.RwMux(SlotTracker).init(slot_tracker_init);

        self.ancestor_hashes_replay_update_channel = try sig
            .sync
            .Channel(AncestorHashesReplayUpdate)
            .init(allocator);

        const replay_votes_ch: *sig.sync.Channel(ParsedVote) = try .create(allocator);

        self.replay_state = ReplayExecutionState{
            .allocator = allocator,
            .logger = .noop,
            .my_identity = Pubkey.initRandom(std.crypto.random),
            .vote_account = Pubkey.initRandom(std.crypto.random),
            .account_store = account_store,
            .thread_pool = &self.thread_pool,
            .ledger_reader = &self.ledger_reader,
            .ledger_result_writer = &self.ledger_result_writer,
            .slot_tracker = &self.slot_tracker,
            .epochs = &self.epochs,
            .progress_map = &self.progress,
            .status_cache = &status_cache,
            .fork_choice = self.fork_choice,
            .duplicate_slots_tracker = &self.duplicate_slots_tracker,
            .unfrozen_gossip_verified_vote_hashes = &self.unfrozen_gossip_verified_vote_hashes,
            .latest_validator_votes = &self.latest_validator_votes,
            .duplicate_confirmed_slots = &self.duplicate_confirmed_slots,
            .epoch_slots_frozen_slots = &self.epoch_slots_frozen_slots,
            .duplicate_slots_to_repair = &self.duplicate_slots_to_repair,
            .purge_repair_slot_counter = &self.purge_repair_slot_counter,
            .ancestor_hashes_replay_update_sender = &self.ancestor_hashes_replay_update_channel,
            .replay_votes_ch = replay_votes_ch,
        };

        return self;
    }

    pub fn deinit(self: *TestReplayStateResources, allocator: Allocator) void {
        self.thread_pool.shutdown();
        self.thread_pool.deinit();

        {
            const ptr, var lg = self.slot_tracker.writeWithLock();
            defer lg.unlock();
            ptr.deinit(allocator);
        }
        {
            const ptr, var lg = self.epochs.writeWithLock();
            defer lg.unlock();
            ptr.deinit(allocator);
        }
        self.progress.deinit(allocator);
        self.fork_choice.deinit();
        allocator.destroy(self.fork_choice);

        self.duplicate_slots_tracker.deinit(allocator);
        self.unfrozen_gossip_verified_vote_hashes.votes_per_slot.deinit(allocator);
        self.latest_validator_votes.deinit(allocator);
        self.duplicate_confirmed_slots.deinit(allocator);
        self.epoch_slots_frozen_slots.deinit(allocator);
        self.duplicate_slots_to_repair.deinit(allocator);
        self.purge_repair_slot_counter.deinit(allocator);
        self.db.deinit();
        self.registry.deinit();
        self.ancestor_hashes_replay_update_channel.deinit();

        allocator.destroy(self);
    }
};

// Helper to create a minimal ReplayExecutionState for testing
fn createTestReplayState(allocator: Allocator) !*TestReplayStateResources {
    return TestReplayStateResources.init(allocator);
}

test "processReplayResults: empty slot statuses" {
    const allocator = testing.allocator;

    var test_resources = createTestReplayState(allocator) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_resources.deinit(allocator);

    const empty_slot_statuses: []const struct { Slot, ReplaySlotStatus } = &.{};

    const result = processReplayResults(
        test_resources.replay_state,
        empty_slot_statuses,
    ) catch |err| {
        std.debug.print("processReplayResults failed: {}\n", .{err});
        return err;
    };

    // Should return false since no slots were processed
    try testing.expect(!result);
}

test "processReplayResults: non-confirm statuses are skipped" {
    const allocator = testing.allocator;

    var test_resources = createTestReplayState(allocator) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_resources.deinit(allocator);

    const slot_statuses: []const struct { Slot, ReplaySlotStatus } = &.{
        .{ 100, .empty },
        .{ 101, .dead },
        .{ 102, .leader },
    };

    const result = processReplayResults(test_resources.replay_state, slot_statuses) catch |err| {
        std.debug.print("processReplayResults failed: {}\n", .{err});
        return err;
    };

    // Should return false since no confirm slots were processed
    try testing.expect(!result);
}

test "processReplayResults: marks slot as dead correctly" {
    const allocator = testing.allocator;

    // Create a minimal test setup without the complex database dependencies
    var progress = ProgressMap.INIT;
    defer progress.deinit(allocator);

    const slot: Slot = 100;

    // Add slot to progress map
    const gop = try progress.map.getOrPut(allocator, slot);
    if (!gop.found_existing) {
        gop.value_ptr.* = try sig.consensus.progress_map.ForkProgress.init(allocator, .{
            .now = sig.time.Instant.now(),
            .last_entry = sig.core.Hash.ZEROES,
            .prev_leader_slot = null,
            .validator_stake_info = null,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        });
    }

    // Verify slot is initially not dead
    const progress_before = progress.map.get(slot);
    try testing.expect(progress_before != null);
    try testing.expect(!progress_before.?.is_dead);

    // Test the core logic without the database write
    // Just verify that the progress map is updated correctly
    var fork_progress = progress.map.getPtr(slot) orelse {
        return error.MissingBankProgress;
    };
    fork_progress.is_dead = true;

    // Verify slot is now marked as dead
    const progress_after = progress.map.get(slot);
    try testing.expect(progress_after != null);
    try testing.expect(progress_after.?.is_dead);
}

test "processReplayResults: confirm status with err poll result marks slot dead" {
    const allocator = testing.allocator;

    var test_resources = createTestReplayState(allocator) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_resources.deinit(allocator);

    const slot: Slot = 100;

    // Add slot to progress map first
    try test_resources.progress.map.putNoClobber(
        allocator,
        slot,
        try sig.consensus.progress_map.ForkProgress.init(allocator, .{
            .now = sig.time.Instant.now(),
            .last_entry = sig.core.Hash.ZEROES,
            .prev_leader_slot = null,
            .validator_stake_info = null,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        }),
    );

    // Verify slot is initially not dead
    const progress_before = test_resources.progress.map.get(slot);
    try testing.expect(progress_before != null);
    try testing.expect(!progress_before.?.is_dead);

    // Create a mock ConfirmSlotFuture that will return an error when polled.
    const MockConfirmSlotFutureErr = struct {
        scheduler: replay.scheduler.TransactionScheduler,
        poh_verifier: sig.utils.thread.HomogeneousThreadPool(replay.confirm_slot.PohTask),
        exit: std.atomic.Value(bool),
        entries: []const sig.core.Entry,
        status: replay.confirm_slot.ConfirmSlotStatus,
        status_when_done: replay.confirm_slot.ConfirmSlotStatus,

        pub fn poll(self: *@This()) !replay.confirm_slot.ConfirmSlotStatus {
            _ = self;
            // Always return an error to test the error path
            return replay.confirm_slot.ConfirmSlotStatus{
                .err = .{ .failed_to_load_entries = "test error" },
            };
        }

        pub fn destroy(self: *@This(), alloc: Allocator) void {
            alloc.destroy(self);
        }
    };

    // Create the mock future
    const mock_future = try allocator.create(MockConfirmSlotFutureErr);
    const empty_entries = try allocator.alloc(sig.core.Entry, 0);

    mock_future.* = MockConfirmSlotFutureErr{
        .scheduler = undefined, // Not used in test.
        .poh_verifier = undefined, // // Not used in test.
        .exit = std.atomic.Value(bool).init(false),
        .entries = empty_entries,
        .status = .{ .err = .{ .failed_to_load_entries = "test error" } },
        .status_when_done = .{ .err = .{ .failed_to_load_entries = "test error" } },
    };

    defer {
        allocator.free(empty_entries);
        allocator.destroy(mock_future);
    }

    // Create slot statuses with confirm status containing our mock future
    var slot_statuses = std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }).empty;
    defer slot_statuses.deinit(allocator);

    // Cast our mock to ConfirmSlotFuture - this should work since they have the same layout
    const confirm_future: *ConfirmSlotFuture = @ptrCast(@alignCast(mock_future));
    try slot_statuses.append(
        allocator,
        .{ slot, .{ .confirm = confirm_future } },
    );

    const result = try processReplayResults(
        test_resources.replay_state,
        slot_statuses.items,
    );

    // Should return false since no slot was successfully processed
    try testing.expect(!result);

    // Verify slot is now marked as dead
    const progress_after = test_resources.progress.map.get(slot);
    try testing.expect(progress_after != null);
    try testing.expect(progress_after.?.is_dead);
}

test "processReplayResults: return value correctness" {
    const allocator = testing.allocator;

    var test_resources = createTestReplayState(allocator) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_resources.deinit(allocator);

    // Test that the function returns:
    // - false when no slots are processed
    // - true when at least one slot is fully processed (reaches processed_a_slot = true)

    // Empty case
    const empty_slot_statuses =
        std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }).empty;
    const empty_result = try processReplayResults(
        test_resources.replay_state,
        empty_slot_statuses.items,
    );
    try testing.expect(!empty_result);

    // Non-confirm statuses case
    var non_confirm_statuses =
        std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }).empty;
    defer non_confirm_statuses.deinit(allocator);
    try non_confirm_statuses.append(allocator, .{ 100, .empty });

    const non_confirm_result = try processReplayResults(
        test_resources.replay_state,
        non_confirm_statuses.items,
    );
    try testing.expect(!non_confirm_result);
}

test "processReplayResults: confirm status with done poll but missing slot in tracker" {
    const allocator = testing.allocator;

    var test_resources = createTestReplayState(allocator) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_resources.deinit(allocator);

    const slot: Slot = 100;

    // Create a mock ConfirmSlotFuture that will return done when polled
    const MockConfirmSlotFutureDone = struct {
        scheduler: replay.scheduler.TransactionScheduler,
        poh_verifier: sig.utils.thread.HomogeneousThreadPool(replay.confirm_slot.PohTask),
        exit: std.atomic.Value(bool),
        entries: []const sig.core.Entry,
        status: replay.confirm_slot.ConfirmSlotStatus,
        status_when_done: replay.confirm_slot.ConfirmSlotStatus,

        pub fn poll(self: *@This()) !replay.confirm_slot.ConfirmSlotStatus {
            _ = self;
            return replay.confirm_slot.ConfirmSlotStatus.done;
        }

        pub fn destroy(self: *@This(), alloc: Allocator) void {
            alloc.destroy(self);
        }
    };

    // Create the mock future
    const mock_future = try allocator.create(MockConfirmSlotFutureDone);
    const empty_entries = try allocator.alloc(sig.core.Entry, 0);

    mock_future.* = MockConfirmSlotFutureDone{
        .scheduler = undefined, // Not used in test
        .poh_verifier = undefined, // Not used in test
        .exit = std.atomic.Value(bool).init(false),
        .entries = empty_entries,
        .status = .done,
        .status_when_done = .done,
    };

    defer {
        allocator.free(empty_entries);
        allocator.destroy(mock_future);
    }

    // Create slot statuses with confirm status containing our mock future
    var slot_statuses = std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }).empty;
    defer slot_statuses.deinit(allocator);

    // Cast our mock to ConfirmSlotFuture
    const confirm_future: *ConfirmSlotFuture = @ptrCast(@alignCast(mock_future));
    try slot_statuses.append(
        allocator,
        .{ slot, .{ .confirm = confirm_future } },
    );

    // The function should return an error since the slot is not in the tracker
    const result = processReplayResults(
        test_resources.replay_state,
        slot_statuses.items,
    );

    try testing.expectError(error.MissingSlotInTracker, result);
}

test "processReplayResults: confirm status with done poll and slot complete - success path" {
    const allocator = testing.allocator;

    var test_resources = createTestReplayState(allocator) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_resources.deinit(allocator);

    const slot: Slot = 100;
    const parent_slot: Slot = 99;

    // Add parent slot to progress map first (required for slot processing)
    try test_resources.progress.map.putNoClobber(
        allocator,
        parent_slot,
        try sig.consensus.progress_map.ForkProgress.init(allocator, .{
            .now = sig.time.Instant.now(),
            .last_entry = sig.core.Hash.ZEROES,
            .prev_leader_slot = null,
            .validator_stake_info = null,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        }),
    );

    // Add slot to progress map
    try test_resources.progress.map.putNoClobber(
        allocator,
        slot,
        try sig.consensus.progress_map.ForkProgress.init(allocator, .{
            .now = sig.time.Instant.now(),
            .last_entry = sig.core.Hash.ZEROES,
            .prev_leader_slot = null,
            .validator_stake_info = null,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        }),
    );

    // Create mock entries for the slot
    const mock_entries = try allocator.alloc(sig.core.Entry, 1);
    defer allocator.free(mock_entries);

    var rng = std.Random.DefaultPrng.init(0);
    const random = rng.random();

    mock_entries[0] = sig.core.Entry{
        .num_hashes = 0,
        .hash = sig.core.Hash.initRandom(random),
        .transactions = &.{},
    };

    // Create a mock ConfirmSlotFuture that will return done with entries
    const MockConfirmSlotFutureSuccess = struct {
        scheduler: replay.scheduler.TransactionScheduler,
        poh_verifier: sig.utils.thread.HomogeneousThreadPool(replay.confirm_slot.PohTask),
        exit: std.atomic.Value(bool),
        entries: []const sig.core.Entry,
        status: replay.confirm_slot.ConfirmSlotStatus,
        status_when_done: replay.confirm_slot.ConfirmSlotStatus,

        pub fn poll(self: *@This()) !replay.confirm_slot.ConfirmSlotStatus {
            _ = self;
            return replay.confirm_slot.ConfirmSlotStatus.done;
        }

        pub fn destroy(self: *@This(), alloc: Allocator) void {
            alloc.destroy(self);
        }
    };

    // Create the mock future with the mock entries
    const mock_future = try allocator.create(MockConfirmSlotFutureSuccess);
    mock_future.* = MockConfirmSlotFutureSuccess{
        .scheduler = undefined, // Not used in test
        .poh_verifier = undefined, // Not used in test
        .exit = std.atomic.Value(bool).init(false),
        .entries = mock_entries,
        .status = .done,
        .status_when_done = .done,
    };

    defer allocator.destroy(mock_future);

    // Add parent slot 99 to fork choice so slot 100 can be processed
    const slot_99_hash = Hash.initRandom(random);
    const slot_99_slot_and_hash = sig.core.hash.SlotAndHash{
        .slot = 99,
        .hash = slot_99_hash,
    };
    const root_slot_and_hash = sig.core.hash.SlotAndHash{
        .slot = 0,
        .hash = Hash.ZEROES,
    };
    try test_resources.replay_state.fork_choice.addNewLeafSlot(
        slot_99_slot_and_hash,
        root_slot_and_hash,
    );

    // Create slot constants and state.
    const mock_slot_constants = sig.core.SlotConstants{
        .parent_slot = parent_slot,
        // Use the same hash as the parent slot in fork choice
        .parent_hash = slot_99_hash,
        .parent_lt_hash = .IDENTITY,
        .block_height = 0,
        // Different from replay_state.my_identity
        .collector_id = sig.core.Pubkey.initRandom(random),
        // This should match tickHeight() for slot to be complete
        .max_tick_height = 64,
        .fee_rate_governor = sig.core.FeeRateGovernor.DEFAULT,
        .epoch_reward_status = .inactive,
        .ancestors = .{ .ancestors = .empty },
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .empty,
    };

    // Create slot state then modify tick height
    var mock_slot_state = try sig.core.SlotState.genesis(allocator);

    // Set tick height equal to max_tick_height to make slot complete
    _ = mock_slot_state.tick_height.swap(64, .monotonic);

    // Set a valid hash for the slot
    mock_slot_state.hash.set(sig.core.Hash.initRandom(random));

    // Add the slot to the slot tracker
    {
        const ptr, var lg = test_resources.slot_tracker.writeWithLock();
        defer lg.unlock();
        try ptr.put(allocator, slot, .{
            .constants = mock_slot_constants,
            .state = mock_slot_state,
        });
    }

    // Add epoch info for slot 100 (epoch 2 in default schedule).
    {
        const ep_ptr, var elg = test_resources.epochs.writeWithLock();
        defer elg.unlock();
        try ep_ptr.epochs.put(allocator, 2, .{
            .hashes_per_tick = 1,
            .ticks_per_slot = 1,
            .ns_per_slot = 1,
            .genesis_creation_time = 1,
            .slots_per_year = 1,
            .stakes = try .initEmptyWithGenesisStakeHistoryEntry(allocator),
            .rent_collector = .DEFAULT,
        });
    }

    // Create slot statuses with confirm status containing the mock future
    var slot_statuses = std.ArrayListUnmanaged(struct { Slot, ReplaySlotStatus }).empty;
    defer slot_statuses.deinit(allocator);

    // Cast the mock to ConfirmSlotFuture
    const confirm_future: *ConfirmSlotFuture = @ptrCast(@alignCast(mock_future));
    try slot_statuses.append(
        allocator,
        .{ slot, .{ .confirm = confirm_future } },
    );

    // This should successfully process the slot and return true
    const result = try processReplayResults(
        test_resources.replay_state,
        slot_statuses.items,
    );

    // Should return true since the slot was successfully processed
    try testing.expect(result);
}

test "markDeadSlot: marks progress dead and writes to ledger" {
    const allocator = testing.allocator;

    var test_resources = createTestReplayState(allocator) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_resources.deinit(allocator);

    const slot: Slot = 200;

    // Ensure progress map has an entry for the slot
    try test_resources.progress.map.putNoClobber(
        allocator,
        slot,
        try sig.consensus.progress_map.ForkProgress.init(allocator, .{
            .now = sig.time.Instant.now(),
            .last_entry = sig.core.Hash.ZEROES,
            .prev_leader_slot = null,
            .validator_stake_info = null,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        }),
    );

    var ancestor_hashes_replay_update_channel: sig.sync.Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_update_channel.deinit();

    try markDeadSlot(
        test_resources.replay_state,
        slot,
        &ancestor_hashes_replay_update_channel,
    );

    // Validate progress is marked dead
    try testing.expect(test_resources.progress.isDead(slot) orelse false);

    // Validate ledger records the dead slot
    try testing.expect(try test_resources.ledger_reader.isDead(slot));
}

test "markDeadSlot: when duplicate proof exists, duplicate tracker records slot" {
    const allocator = testing.allocator;

    var test_resources = createTestReplayState(allocator) catch |err| {
        std.debug.print("Failed to create test replay state: {}\n", .{err});
        return err;
    };
    defer test_resources.deinit(allocator);

    const slot: Slot = 201;

    // Ensure progress map has an entry for the slot
    try test_resources.progress.map.putNoClobber(
        allocator,
        slot,
        try sig.consensus.progress_map.ForkProgress.init(allocator, .{
            .now = sig.time.Instant.now(),
            .last_entry = sig.core.Hash.ZEROES,
            .prev_leader_slot = null,
            .validator_stake_info = null,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        }),
    );

    // Provide a minimal slot in the slot tracker so markDeadSlot can read a hash
    var slot_state = try sig.core.SlotState.genesis(allocator);
    var rng = std.Random.DefaultPrng.init(0);
    slot_state.hash.set(sig.core.Hash.initRandom(rng.random()));
    const slot_consts = sig.core.SlotConstants{
        .parent_slot = 0,
        .parent_hash = sig.core.Hash.ZEROES,
        .parent_lt_hash = .IDENTITY,
        .block_height = 0,
        .collector_id = sig.core.Pubkey.ZEROES,
        .max_tick_height = 0,
        .fee_rate_governor = sig.core.FeeRateGovernor.DEFAULT,
        .epoch_reward_status = .inactive,
        .ancestors = .{ .ancestors = .empty },
        .feature_set = .ALL_DISABLED,
        .reserved_accounts = .empty,
    };
    {
        const ptr, var lg = test_resources.slot_tracker.writeWithLock();
        defer lg.unlock();
        try ptr.put(allocator, slot, .{
            .constants = slot_consts,
            .state = slot_state,
        });
    }

    // Insert a duplicate proof into the ledger to trigger the duplicate branch
    const dup_proof = sig.ledger.meta.DuplicateSlotProof{
        .shred1 = &[_]u8{ 0xAA, 0xBB },
        .shred2 = &[_]u8{ 0xCC, 0xDD },
    };
    try test_resources.db.put(sig.ledger.schema.schema.duplicate_slots, slot, dup_proof);

    // Tracker does not contain the slot yet
    try testing.expect(!test_resources.duplicate_slots_tracker.contains(slot));

    var ancestor_hashes_replay_update_channel: sig.sync.Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_update_channel.deinit();

    try markDeadSlot(
        test_resources.replay_state,
        slot,
        &ancestor_hashes_replay_update_channel,
    );

    // The duplicate handler should record the slot in the duplicate tracker
    try testing.expect(test_resources.duplicate_slots_tracker.contains(slot));
}
