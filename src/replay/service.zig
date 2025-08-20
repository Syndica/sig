const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const Ancestors = sig.core.Ancestors;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SlotLeaders = sig.core.leader_schedule.SlotLeaders;
const SlotState = sig.core.bank.SlotState;

const AccountStore = sig.accounts_db.AccountStore;
const AccountReader = sig.accounts_db.AccountReader;

const LedgerDB = sig.ledger.LedgerDB;
const LedgerReader = sig.ledger.LedgerReader;

const ProgressMap = sig.consensus.ProgressMap;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const AncestorHashesReplayUpdate = sig.replay.consensus.AncestorHashesReplayUpdate;
const AncestorDuplicateSlotToRepair = replay.edge_cases.AncestorDuplicateSlotToRepair;
const ThresholdConfirmedSlot = sig.consensus.vote_listener.ThresholdConfirmedSlot;
const GossipVerifiedVoteHash = sig.consensus.vote_listener.GossipVerifiedVoteHash;
const LatestValidatorVotes = sig.consensus.latest_validator_votes.LatestValidatorVotes;
const SlotHistoryAccessor = sig.consensus.replay_tower.SlotHistoryAccessor;

const ReplayExecutionState = replay.execution.ReplayExecutionState;
const SlotTracker = replay.trackers.SlotTracker;
const EpochTracker = replay.trackers.EpochTracker;

const updateSysvarsForNewSlot = replay.update_sysvar.updateSysvarsForNewSlot;

const LatestValidatorVotesForFrozenSlots =
    sig.consensus.latest_validator_votes.LatestValidatorVotes;

pub const Logger = sig.trace.Logger("replay");

/// Number of threads to use in replay's thread pool
const NUM_THREADS = 4;

const SWITCH_FORK_THRESHOLD: f64 = 0.38;
const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days
const DUPLICATE_LIVENESS_THRESHOLD: f64 = 0.1;
pub const DUPLICATE_THRESHOLD: f64 = 1.0 - SWITCH_FORK_THRESHOLD - DUPLICATE_LIVENESS_THRESHOLD;

pub const ReplayDependencies = struct {
    /// Used for all allocations within the replay stage
    allocator: Allocator,
    logger: Logger,
    my_identity: Pubkey,
    vote_identity: Pubkey,
    /// Tell replay when to exit
    exit: *std.atomic.Value(bool),
    /// Used in the EpochManager
    epoch_schedule: sig.core.EpochSchedule,
    account_store: sig.accounts_db.AccountStore,
    /// Reader used to get the entries to validate them and execute the transactions
    /// Writer used to update the ledger with consensus results
    ledger: LedgerRef,
    /// Used to get the entries to validate them and execute the transactions
    slot_leaders: SlotLeaders,
    senders: Senders,
    receivers: Receivers,

    /// The slot to start replaying from.
    root: struct {
        slot: Slot,
        constants: sig.core.SlotConstants,
        state: sig.core.SlotState,
    },
    current_epoch: sig.core.Epoch,
    current_epoch_constants: sig.core.EpochConstants,
    hard_forks: sig.core.HardForks,
};

pub const LedgerRef = struct {
    db: LedgerDB,
    reader: *sig.ledger.LedgerReader,
    writer: *sig.ledger.LedgerResultWriter,
};

pub const Senders = struct {
    /// Received by repair [ancestor_hashes_service](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/repair/ancestor_hashes_service.rs#L589)
    ancestor_hashes_replay_update: *sig.sync.Channel(AncestorHashesReplayUpdate),

    pub fn destroy(self: Senders) void {
        self.ancestor_hashes_replay_update.destroy();
    }

    pub fn create(allocator: std.mem.Allocator) std.mem.Allocator.Error!Senders {
        return .{
            .ancestor_hashes_replay_update = try .create(allocator),
        };
    }
};

pub const Receivers = struct {
    /// Sent by repair [ancestor_hashes_service](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/repair/ancestor_hashes_service.rs#L240)
    ancestor_duplicate_slots: *sig.sync.Channel(AncestorDuplicateSlotToRepair),
    /// Sent by vote_listener:
    /// - `Senders`'s `duplicate_confirmed_slot` field.
    /// - agave's [vote listener](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/cluster_info_vote_listener.rs#L204)
    duplicate_confirmed_slots: *sig.sync.Channel(ThresholdConfirmedSlot),
    /// Sent by vote_listener:
    /// - `Sender`'s `gossip_verified_vote_hash` field.
    /// - agave's [vote listener](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/cluster_info_vote_listener.rs#L200)
    gossip_verified_vote_hash: *sig.sync.Channel(GossipVerifiedVoteHash),
    /// Sent by [repair service](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/repair/repair_service.rs#L423)
    popular_pruned_forks: *sig.sync.Channel(Slot),
    /// Sent by two things:
    ///   - [WindowService](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/window_service.rs#L275)
    ///   - DuplicateShredListener/DuplicateShredHandler:
    ///       - [intialization](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/tvu.rs#L368)
    ///       - [direct implementation usage](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/gossip/src/duplicate_shred_handler.rs#L150)
    ///       - [indirect interface usage](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/gossip/src/duplicate_shred_handler.rs#L61)
    ///       - [relevant interface invokation](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/gossip/src/duplicate_shred_listener.rs#L31)
    duplicate_slots: *sig.sync.Channel(Slot),

    pub fn destroy(self: Receivers) void {
        self.ancestor_duplicate_slots.destroy();
        self.duplicate_confirmed_slots.destroy();
        self.gossip_verified_vote_hash.destroy();
        self.popular_pruned_forks.destroy();
        self.duplicate_slots.destroy();
    }

    pub fn create(allocator: std.mem.Allocator) std.mem.Allocator.Error!Receivers {
        const ancestor_duplicate_slots: *sig.sync.Channel(AncestorDuplicateSlotToRepair) =
            try .create(allocator);
        errdefer ancestor_duplicate_slots.destroy();

        const duplicate_confirmed_slots: *sig.sync.Channel(ThresholdConfirmedSlot) =
            try .create(allocator);
        errdefer duplicate_confirmed_slots.destroy();

        const gossip_verified_vote_hash: *sig.sync.Channel(GossipVerifiedVoteHash) =
            try .create(allocator);
        errdefer gossip_verified_vote_hash.destroy();

        const popular_pruned_forks: *sig.sync.Channel(Slot) = try .create(allocator);
        errdefer popular_pruned_forks.destroy();

        const duplicate_slots: *sig.sync.Channel(Slot) = try .create(allocator);
        errdefer duplicate_slots.destroy();

        return .{
            .ancestor_duplicate_slots = ancestor_duplicate_slots,
            .duplicate_confirmed_slots = duplicate_confirmed_slots,
            .gossip_verified_vote_hash = gossip_verified_vote_hash,
            .popular_pruned_forks = popular_pruned_forks,
            .duplicate_slots = duplicate_slots,
        };
    }
};

const ReplayState = struct {
    allocator: Allocator,
    my_identity: Pubkey,
    logger: Logger,
    thread_pool: ThreadPool,
    slot_leaders: SlotLeaders,
    slot_tracker: SlotTracker,
    epochs: EpochTracker,
    hard_forks: sig.core.HardForks,
    account_store: AccountStore,
    progress_map: ProgressMap,
    ledger: LedgerRef,

    fork_choice: HeaviestSubtreeForkChoice,
    replay_tower: sig.consensus.ReplayTower,
    latest_validator_votes: LatestValidatorVotes,
    status_cache: sig.core.StatusCache,
    slot_data: replay.edge_cases.SlotData,

    arena_state: std.heap.ArenaAllocator.State,

    senders: Senders,
    receivers: Receivers,

    fn deinit(self: *ReplayState) void {
        self.thread_pool.shutdown();
        self.thread_pool.deinit();

        self.slot_tracker.deinit(self.allocator);

        self.epochs.deinit(self.allocator);

        self.progress_map.deinit(self.allocator);

        self.fork_choice.deinit();
        self.latest_validator_votes.deinit(self.allocator);
        self.slot_data.deinit(self.allocator);
    }

    fn init(deps: ReplayDependencies) !ReplayState {
        const zone = tracy.Zone.init(@src(), .{ .name = "ReplayState init" });
        defer zone.deinit();

        var slot_tracker: SlotTracker = try .init(deps.allocator, deps.root.slot, .{
            .constants = deps.root.constants,
            .state = deps.root.state,
        });
        errdefer slot_tracker.deinit(deps.allocator);

        var epoch_tracker: EpochTracker = .{ .schedule = deps.epoch_schedule };
        errdefer epoch_tracker.deinit(deps.allocator);

        try epoch_tracker.epochs
            .put(deps.allocator, deps.current_epoch, deps.current_epoch_constants);

        const progress_map, const fork_choice = try initProgressAndForkChoiceWithLockedSlotForks(
            deps.allocator,
            deps.logger,
            &slot_tracker,
            &epoch_tracker,
            deps.my_identity,
            deps.vote_identity,
            deps.ledger.reader.*,
        );
        errdefer progress_map.deinit(deps.allocator);
        errdefer fork_choice.deinit();

        // NOTE(ink): in agave replay_tower isn't created directly in replay,
        // however its lifetime does end up being tied to it. This seems to be
        // because it is used once to query it for `last_vote`, for "wen_restart",
        // before being moved (fully by value, not by reference) down into replay.
        // It's not clear whether this is something we should or need to care
        // about. This comment can be removed when this is resolved.
        // - moved here:
        //     - from validator [to tvu](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/validator.rs#L1486)
        //     - from tvu to [replay_config](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/tvu.rs#L311)
        //     - replay_config to [ReplayStage](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L563)
        const replay_tower: sig.consensus.ReplayTower = try .init(
            deps.allocator,
            .from(deps.logger),
            deps.my_identity,
            deps.vote_identity,
            deps.root.slot,
            deps.account_store.reader().forSlot(&deps.root.constants.ancestors),
        );
        errdefer replay_tower.deinit(deps.allocator);

        return .{
            .allocator = deps.allocator,
            .logger = .from(deps.logger),
            .thread_pool = .init(.{ .max_threads = NUM_THREADS }),
            .my_identity = deps.my_identity,
            .slot_leaders = deps.slot_leaders,
            .slot_tracker = slot_tracker,
            .epochs = epoch_tracker,
            .hard_forks = deps.hard_forks,
            .account_store = deps.account_store,
            .ledger = deps.ledger,
            .progress_map = progress_map,
            .fork_choice = fork_choice,
            .replay_tower = replay_tower,
            .latest_validator_votes = .empty,
            .status_cache = .DEFAULT,
            .slot_data = .empty,

            .arena_state = .{},

            .senders = deps.senders,
            .receivers = deps.receivers,
        };
    }

    pub fn executionState(self: *ReplayState) ReplayExecutionState {
        return .{
            .allocator = self.allocator,
            .logger = .from(self.logger),
            .my_identity = self.my_identity,
            .vote_account = null, // voting not currently supported

            .account_store = self.account_store,
            .thread_pool = &self.thread_pool,
            .ledger_reader = self.ledger.reader,
            .ledger_result_writer = self.ledger.writer,
            .slot_tracker = &self.slot_tracker,
            .epochs = &self.epochs,
            .progress_map = &self.progress_map,
            .status_cache = &self.status_cache,
            .fork_choice = &self.fork_choice,
            .duplicate_slots_tracker = &self.slot_data.duplicate_slots,
            .unfrozen_gossip_verified_vote_hashes = &self
                .slot_data.unfrozen_gossip_verified_vote_hashes,
            .latest_validator_votes = &self.slot_data.latest_validator_votes,
            .duplicate_confirmed_slots = &self.slot_data.duplicate_confirmed_slots,
            .epoch_slots_frozen_slots = &self.slot_data.epoch_slots_frozen_slots,
            .duplicate_slots_to_repair = &self.slot_data.duplicate_slots_to_repair,
            .purge_repair_slot_counter = &self.slot_data.purge_repair_slot_counter,
            .ancestor_hashes_replay_update_sender = self.senders.ancestor_hashes_replay_update,
        };
    }
};

/// Analogous to [`initialize_progress_and_fork_choice_with_locked_bank_forks`](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L637)
fn initProgressAndForkChoiceWithLockedSlotForks(
    allocator: std.mem.Allocator,
    logger: Logger,
    slot_tracker: *const SlotTracker,
    epoch_tracker: *const EpochTracker,
    my_pubkey: Pubkey,
    vote_account: Pubkey,
    ledger_reader: LedgerReader,
) !struct { ProgressMap, HeaviestSubtreeForkChoice } {
    const root_slot, const root_hash = blk: {
        const root = slot_tracker.getRoot();
        const root_slot = slot_tracker.root;
        const root_hash = root.state.hash.readCopy();
        break :blk .{ root_slot, root_hash.? };
    };

    var frozen_slots = try slot_tracker.frozenSlots(allocator);
    defer frozen_slots.deinit(allocator);
    const FrozenSlotsSortCtx = struct {
        slots: []const Slot,
        pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
            return ctx.slots[a_index] < ctx.slots[b_index];
        }
    };
    frozen_slots.sort(FrozenSlotsSortCtx{ .slots = frozen_slots.keys() });

    var progress: ProgressMap = .INIT;
    errdefer progress.deinit(allocator);

    // Initialize progress map with any root slots
    for (frozen_slots.keys(), frozen_slots.values()) |slot, ref| {
        const prev_leader_slot = progress.getSlotPrevLeaderSlot(ref.constants.parent_slot);
        try progress.map.ensureUnusedCapacity(allocator, 1);
        progress.map.putAssumeCapacity(slot, try .initFromInfo(allocator, .{
            .slot_info = ref,
            .epoch_stakes = &epoch_tracker.getPtrForSlot(slot).?.stakes,
            .now = .now(),
            .validator_identity = &my_pubkey,
            .validator_vote_pubkey = &vote_account,
            .prev_leader_slot = prev_leader_slot,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        }));
    }

    // Given a root and a list of `frozen_slots` sorted smallest to greatest by slot,
    // initialize a new HeaviestSubtreeForkChoice
    //
    // Analogous to [`new_from_frozen_banks`](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/consensus/heaviest_subtree_fork_choice.rs#L235)
    var heaviest_subtree_fork_choice = fork_choice: {
        var heaviest_subtree_fork_choice: HeaviestSubtreeForkChoice =
            try .init(allocator, .from(logger), .{
                .slot = root_slot,
                .hash = root_hash,
            });

        var prev_slot = root_slot;
        for (frozen_slots.keys(), frozen_slots.values()) |slot, info| {
            const frozen_hash = info.state.hash.readCopy().?;
            if (slot > root_slot) {
                // Make sure the list is sorted
                std.debug.assert(slot > prev_slot);
                prev_slot = slot;
                const parent_bank_hash = info.constants.parent_hash;
                try heaviest_subtree_fork_choice.addNewLeafSlot(
                    .{ .slot = slot, .hash = frozen_hash },
                    .{ .slot = info.constants.parent_slot, .hash = parent_bank_hash },
                );
            }
        }

        break :fork_choice heaviest_subtree_fork_choice;
    };
    errdefer heaviest_subtree_fork_choice.deinit();

    var duplicate_slots = try ledger_reader.db.iterator(
        sig.ledger.schema.schema.duplicate_slots,
        .forward,
        // It is important that the root bank is not marked as duplicate on initialization.
        // Although this bank could contain a duplicate proof, the fact that it was rooted
        // either during a previous run or artificially means that we should ignore any
        // duplicate proofs for the root slot, thus we start consuming duplicate proofs
        // from the root slot + 1
        root_slot +| 1,
    );
    defer duplicate_slots.deinit();

    while (try duplicate_slots.nextKey()) |slot| {
        const ref = slot_tracker.get(slot) orelse continue;
        try heaviest_subtree_fork_choice.markForkInvalidCandidate(&.{
            .slot = slot,
            .hash = ref.state.hash.readCopy().?,
        });
    }

    return .{ progress, heaviest_subtree_fork_choice };
}

/// Run the replay service indefinitely.
pub fn run(deps: ReplayDependencies) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "run (replay service)" });
    defer zone.deinit();

    var state = try ReplayState.init(deps);
    defer state.deinit();

    while (!deps.exit.load(.monotonic)) {
        try advanceReplay(&state);
    }
}

/// Run a single iteration of the entire replay process. Includes:
/// - replay all active slots that have not been replayed yet
/// - running concensus on the latest updates
fn advanceReplay(state: *ReplayState) !void {
    const allocator = state.allocator;
    const logger = state.logger;

    const zone = tracy.Zone.init(@src(), .{ .name = "advanceReplay" });
    defer zone.deinit();

    state.logger.info().log("advancing replay");

    var arena_state = state.arena_state.promote(allocator);
    defer {
        _ = arena_state.reset(.retain_capacity);
        state.arena_state = arena_state.state;
    }
    const arena = arena_state.allocator();

    try trackNewSlots(
        allocator,
        state.account_store,
        &state.ledger.db,
        &state.slot_tracker,
        &state.epochs,
        state.slot_leaders,
        &state.hard_forks,
        &state.progress_map,
    );

    const processed_a_slot = try replay.execution.replayActiveSlots(state.executionState());
    if (!processed_a_slot) std.time.sleep(100 * std.time.ns_per_ms);

    _ = try replay.edge_cases.processEdgeCases(allocator, logger, .{
        .my_pubkey = state.my_identity,
        .tpu_has_bank = false,

        .fork_choice = &state.fork_choice,
        .ledger = state.ledger.writer,

        .slot_tracker = &state.slot_tracker,
        .progress = &state.progress_map,
        .latest_validator_votes = &state.latest_validator_votes,
        .slot_data = &state.slot_data,

        .senders = state.senders,
        .receivers = state.receivers,
    });

    const SlotSet = sig.utils.collections.SortedSetUnmanaged(Slot);

    // arena-allocated
    var ancestors: std.AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
    var descendants: std.AutoArrayHashMapUnmanaged(Slot, SlotSet) = .empty;
    for (
        state.slot_tracker.slots.keys(),
        state.slot_tracker.slots.values(),
    ) |slot, info| {
        const slot_ancestors = &info.constants.ancestors.ancestors;
        const ancestor_gop = try ancestors.getOrPutValue(arena, slot, .EMPTY);
        try ancestor_gop.value_ptr.ancestors.ensureUnusedCapacity(arena, slot_ancestors.count());
        for (slot_ancestors.keys()) |ancestor_slot| {
            try ancestor_gop.value_ptr.addSlot(arena, ancestor_slot);
            const descendants_gop = try descendants.getOrPutValue(arena, ancestor_slot, .empty);
            try descendants_gop.value_ptr.put(arena, slot);
        }
    }

    const slot_history_accessor = SlotHistoryAccessor
        .init(state.account_store.reader());

    replay.consensus.processConsensus(.{
        .allocator = allocator,
        .replay_tower = &state.replay_tower,
        .progress_map = &state.progress_map,
        .slot_tracker = &state.slot_tracker,
        .epoch_tracker = &state.epochs,
        .fork_choice = &state.fork_choice,
        .ledger_reader = state.ledger.reader,
        .ledger_result_writer = state.ledger.writer,
        .ancestors = &ancestors,
        .descendants = &descendants,
        .vote_account = state.my_identity, // TODO: use explicitly distinct vote authority
        .slot_history_accessor = &slot_history_accessor,
        .latest_validator_votes_for_frozen_banks = &state.latest_validator_votes,
    }) catch |e| {
        // ignore errors in consensus since they are expected until the inputs are provided
        state.logger.err().logf("consensus failed with an error: {}", .{e});
    };

    // TODO: dump_then_repair_correct_slots

    // TODO: maybe_start_leader
}

/// Identifies new slots in the ledger and starts tracking them in the slot
/// tracker.
///
/// Analogous to
/// [generate_new_bank_forks](https://github.com/anza-xyz/agave/blob/146ebd8be3857d530c0946003fcd58be220c3290/core/src/replay_stage.rs#L4149)
fn trackNewSlots(
    allocator: Allocator,
    account_store: AccountStore,
    ledger_db: *LedgerDB,
    slot_tracker: *SlotTracker,
    epoch_tracker: *EpochTracker,
    slot_leaders: SlotLeaders,
    hard_forks: *const sig.core.HardForks,
    /// needed for update_fork_propagated_threshold_from_votes
    _: *ProgressMap,
) !void {
    var zone = tracy.Zone.init(@src(), .{ .name = "trackNewSlots" });
    defer zone.deinit();

    const root = slot_tracker.root;
    var frozen_slots = try slot_tracker.frozenSlots(allocator);
    defer frozen_slots.deinit(allocator);

    var frozen_slots_since_root = try std.ArrayListUnmanaged(sig.core.Slot)
        .initCapacity(allocator, frozen_slots.count());
    defer frozen_slots_since_root.deinit(allocator);
    for (frozen_slots.keys()) |slot| if (slot >= root) {
        frozen_slots_since_root.appendAssumeCapacity(slot);
    };

    var next_slots = try LedgerReader
        .getSlotsSince(allocator, ledger_db, frozen_slots_since_root.items);
    defer {
        for (next_slots.values()) |*list| list.deinit(allocator);
        next_slots.deinit(allocator);
    }

    for (next_slots.keys(), next_slots.values()) |parent_slot, children| {
        const parent_info = frozen_slots.get(parent_slot) orelse return error.MissingParent;

        for (children.items) |slot| {
            if (slot_tracker.contains(slot)) continue;

            const epoch_info = epoch_tracker.getPtrForSlot(slot) orelse
                return error.MissingEpoch;

            const constants, var state = try newSlotFromParent(
                allocator,
                account_store.reader(),
                epoch_info.ticks_per_slot,
                parent_slot,
                parent_info.constants,
                parent_info.state,
                slot_leaders.get(slot) orelse return error.UnknownLeader,
                slot,
            );
            errdefer constants.deinit(allocator);
            errdefer state.deinit(allocator);

            try updateSysvarsForNewSlot(
                allocator,
                account_store,
                epoch_info,
                epoch_tracker.schedule,
                &constants,
                &state,
                slot,
                hard_forks,
            );

            try slot_tracker.put(allocator, slot, .{ .constants = constants, .state = state });

            // TODO: update_fork_propagated_threshold_from_votes
        }
    }
}

/// Initializes the SlotConstants and SlotState from their parents and other
/// dependencies.
///
/// This is analogous to the *portion* of agave's Bank::new_from_parent that is
/// responsible for creating the actual bank struct.
///
/// For the relevant updates to accountsdb to set sysvars, see
/// updateSysvarsForNewSlot
fn newSlotFromParent(
    allocator: Allocator,
    account_reader: AccountReader,
    ticks_in_slot: u64,
    parent_slot: Slot,
    parent_constants: *const sig.core.SlotConstants,
    parent_state: *SlotState,
    leader: Pubkey,
    slot: Slot,
) !struct { sig.core.SlotConstants, SlotState } {
    var zone = tracy.Zone.init(@src(), .{ .name = "newSlotFromParent" });
    defer zone.deinit();

    var state = try SlotState.fromFrozenParent(allocator, parent_state);
    errdefer state.deinit(allocator);

    const epoch_reward_status = try parent_constants.epoch_reward_status
        .clone(allocator);
    errdefer epoch_reward_status.deinit(allocator);

    var ancestors = try parent_constants.ancestors.clone(allocator);
    errdefer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, slot, {});

    var feature_set = try getActiveFeatures(allocator, account_reader.forSlot(&ancestors), slot);

    const parent_hash = parent_state.hash.readCopy().?;

    // This is inefficient, reserved accounts could live in epoch constants along with
    // the feature set since feature activations are only applied at epoch boundaries.
    // Then we only need to clone the map and update the reserved accounts once per epoch.
    const reserved_accounts = try sig.core.reserved_accounts.initForSlot(
        allocator,
        &feature_set,
        slot,
    );
    errdefer reserved_accounts.deinit(allocator);

    const constants = sig.core.SlotConstants{
        .parent_slot = parent_slot,
        .parent_hash = parent_hash,
        .parent_lt_hash = parent_state.accounts_lt_hash.readCopy().?,
        .block_height = parent_constants.block_height + 1,
        .collector_id = leader,
        .max_tick_height = (slot + 1) * ticks_in_slot,
        .fee_rate_governor = .initDerived(
            &parent_constants.fee_rate_governor,
            parent_state.signature_count.load(.monotonic),
        ),
        .epoch_reward_status = epoch_reward_status,
        .ancestors = ancestors,
        .feature_set = feature_set,
        .reserved_accounts = reserved_accounts,
    };

    return .{ constants, state };
}

// TODO: epoch boundary - handle feature activations
pub fn getActiveFeatures(
    allocator: Allocator,
    account_reader: sig.accounts_db.SlotAccountReader,
    slot: Slot,
) !sig.core.FeatureSet {
    var features: sig.core.FeatureSet = .ALL_DISABLED;
    for (0..sig.core.features.NUM_FEATURES) |i| {
        const possible_feature: sig.core.features.Feature = @enumFromInt(i);
        const possible_feature_pubkey = sig.core.features.map.get(possible_feature).key;
        const feature_account = try account_reader.get(possible_feature_pubkey) orelse continue;
        if (!feature_account.owner.equals(&sig.runtime.ids.FEATURE_PROGRAM_ID)) {
            return error.FeatureNotOwnedByFeatureProgram;
        }

        var data_iterator = feature_account.data.iterator();
        const reader = data_iterator.reader();
        const feature = try sig.bincode.read(allocator, struct { activated_at: ?u64 }, reader, .{});
        if (feature.activated_at) |activation_slot| {
            if (activation_slot <= slot) {
                features.setSlot(possible_feature, activation_slot);
            }
        }
    }
    return features;
}

test "getActiveFeatures rejects wrong ownership" {
    const allocator = std.testing.allocator;
    var accounts = std.AutoArrayHashMapUnmanaged(Pubkey, sig.core.Account).empty;
    defer accounts.deinit(allocator);

    var acct: sig.core.Account = undefined;
    acct.owner = Pubkey.ZEROES;

    try accounts.put(
        allocator,
        sig.core.features.map.get(.system_transfer_zero_check).key,
        acct,
    );

    try std.testing.expectError(
        error.FeatureNotOwnedByFeatureProgram,
        getActiveFeatures(allocator, .{ .single_version_map = &accounts }, 0),
    );
}

test trackNewSlots {
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(0);

    var ledger_db = try sig.ledger.tests.TestDB.init(@src());
    defer ledger_db.deinit();
    //     0
    //     1
    //    / \
    //   2   4
    //  [3]  6
    //   5
    // no shreds received from 0 or 3
    inline for (.{
        .{ 0, 0, &.{1} },
        .{ 1, 0, &.{ 2, 4 } },
        .{ 2, 1, &.{} },
        .{ 3, null, &.{5} },
        .{ 5, 3, &.{} },
        .{ 4, 1, &.{6} },
        .{ 6, 4, &.{} },
    }) |item| {
        const slot, const parent, const children = item;
        var meta = sig.ledger.meta.SlotMeta.init(allocator, slot, parent);
        defer meta.deinit();
        try meta.child_slots.appendSlice(children);
        try ledger_db.put(sig.ledger.schema.schema.slot_meta, slot, meta);
    }

    var slot_tracker: SlotTracker = try .init(allocator, 0, .{
        .state = try .genesis(allocator),
        .constants = try .genesis(allocator, .DEFAULT),
    });
    defer slot_tracker.deinit(allocator);
    slot_tracker.get(0).?.state.hash.set(.ZEROES);

    var epoch_tracker: EpochTracker = .{ .schedule = .DEFAULT };
    defer epoch_tracker.deinit(allocator);
    try epoch_tracker.epochs.put(allocator, 0, .{
        .hashes_per_tick = 1,
        .ticks_per_slot = 1,
        .ns_per_slot = 1,
        .genesis_creation_time = 1,
        .slots_per_year = 1,
        .stakes = try .initEmptyWithGenesisStakeHistoryEntry(allocator),
        .rent_collector = .DEFAULT,
    });

    const leader_schedule = sig.core.leader_schedule.LeaderSchedule{
        .allocator = undefined,
        .slot_leaders = &.{
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
        },
    };

    var lsc = sig.core.leader_schedule.LeaderScheduleCache.init(allocator, .DEFAULT);
    defer {
        var map = lsc.leader_schedules.write();
        map.mut().deinit();
        map.unlock();
    }
    try lsc.put(0, leader_schedule);
    const slot_leaders = lsc.slotLeaders();

    // slot tracker should start with only 0
    try expectSlotTracker(&slot_tracker, leader_schedule, &.{.{ 0, 0 }}, &.{ 1, 2, 3, 4, 5, 6 });

    const hard_forks = sig.core.HardForks{};

    // only the root (0) is considered frozen, so only 0 and 1 should be added at first.
    try trackNewSlots(
        allocator,
        .noop,
        &ledger_db,
        &slot_tracker,
        &epoch_tracker,
        slot_leaders,
        &hard_forks,
        undefined,
    );
    try expectSlotTracker(
        &slot_tracker,
        leader_schedule,
        &.{ .{ 0, 0 }, .{ 1, 0 } },
        &.{ 2, 3, 4, 5, 6 },
    );

    // doing nothing should result in the same tracker state
    try trackNewSlots(
        allocator,
        .noop,
        &ledger_db,
        &slot_tracker,
        &epoch_tracker,
        slot_leaders,
        &hard_forks,
        undefined,
    );
    try expectSlotTracker(
        &slot_tracker,
        leader_schedule,
        &.{ .{ 0, 0 }, .{ 1, 0 } },
        &.{ 2, 3, 4, 5, 6 },
    );

    // freezing 1 should result in 2 and 4 being added
    slot_tracker.get(1).?.state.hash.set(.ZEROES);
    try trackNewSlots(
        allocator,
        .noop,
        &ledger_db,
        &slot_tracker,
        &epoch_tracker,
        slot_leaders,
        &hard_forks,
        undefined,
    );
    try expectSlotTracker(
        &slot_tracker,
        leader_schedule,
        &.{ .{ 0, 0 }, .{ 1, 0 }, .{ 2, 1 }, .{ 4, 1 } },
        &.{ 3, 5, 6 },
    );

    // freezing 2 and 4 should only result in 6 being added since 3's parent is unknown
    slot_tracker.get(2).?.state.hash.set(.ZEROES);
    slot_tracker.get(4).?.state.hash.set(.ZEROES);
    try trackNewSlots(
        allocator,
        .noop,
        &ledger_db,
        &slot_tracker,
        &epoch_tracker,
        slot_leaders,
        &hard_forks,
        undefined,
    );
    try expectSlotTracker(
        &slot_tracker,
        leader_schedule,
        &.{ .{ 0, 0 }, .{ 1, 0 }, .{ 2, 1 }, .{ 4, 1 }, .{ 6, 4 } },
        &.{ 3, 5 },
    );
}

fn expectSlotTracker(
    slot_tracker: *SlotTracker,
    leader_schedule: sig.core.leader_schedule.LeaderSchedule,
    included_slots: []const [2]Slot,
    excluded_slots: []const Slot,
) !void {
    for (included_slots) |item| {
        const slot, const parent = item;
        const slot_info = slot_tracker.get(slot) orelse return error.Fail;
        try std.testing.expectEqual(parent, slot_info.constants.parent_slot);
        if (slot != 0) try std.testing.expectEqual(
            leader_schedule.slot_leaders[slot],
            slot_info.constants.collector_id,
        );
    }
    for (excluded_slots) |slot| {
        try std.testing.expectEqual(null, slot_tracker.get(slot));
    }
}
