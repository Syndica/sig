const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const Allocator = std.mem.Allocator;
const ThreadPool = sig.sync.ThreadPool;

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SlotLeaders = sig.core.leader_schedule.SlotLeaders;
const SlotState = sig.core.bank.SlotState;

const AccountStore = sig.accounts_db.account_store.AccountStore;
const AccountReader = sig.accounts_db.account_store.AccountReader;
const SlotAccountReader = sig.accounts_db.account_store.SlotAccountReader;

const BlockstoreDB = sig.ledger.BlockstoreDB;
const BlockstoreReader = sig.ledger.BlockstoreReader;

const ProgressMap = sig.consensus.ProgressMap;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const AncestorHashesReplayUpdate = sig.replay.consensus.AncestorHashesReplayUpdate;
const AncestorDuplicateSlotToRepair = replay.edge_cases.AncestorDuplicateSlotToRepair;
const ThresholdConfirmedSlot = sig.consensus.vote_listener.ThresholdConfirmedSlot;
const GossipVerifiedVoteHash = sig.consensus.vote_listener.GossipVerifiedVoteHash;
const LatestValidatorVotes = sig.consensus.latest_validator_votes.LatestValidatorVotes;

const ReplayExecutionState = replay.execution.ReplayExecutionState;
const SlotTracker = replay.trackers.SlotTracker;
const EpochTracker = replay.trackers.EpochTracker;

/// Number of threads to use in replay's thread pool
const NUM_THREADS = 4;

const SWITCH_FORK_THRESHOLD: f64 = 0.38;
const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days
const DUPLICATE_LIVENESS_THRESHOLD: f64 = 0.1;
pub const DUPLICATE_THRESHOLD: f64 = 1.0 - SWITCH_FORK_THRESHOLD - DUPLICATE_LIVENESS_THRESHOLD;

pub const Logger = sig.trace.ScopedLogger("replay");

pub const ReplayDependencies = struct {
    /// Used for all allocations within the replay stage
    allocator: Allocator,
    logger: sig.trace.Logger,
    my_identity: sig.core.Pubkey,
    vote_identity: sig.core.Pubkey,
    /// Tell replay when to exit
    exit: *std.atomic.Value(bool),
    /// Used in the EpochManager
    epoch_schedule: sig.core.EpochSchedule,
    account_store: AccountStore,
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
};

pub const LedgerRef = struct {
    db: BlockstoreDB,
    reader: *sig.ledger.BlockstoreReader,
    writer: *sig.ledger.LedgerResultWriter,
};

pub const Senders = struct {
    /// Received by repair [ancestor_hashes_service](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/repair/ancestor_hashes_service.rs#L589)
    ancestor_hashes_replay_update: *sig.sync.Channel(AncestorHashesReplayUpdate),

    pub fn create(allocator: std.mem.Allocator) std.mem.Allocator.Error!Senders {
        return .{
            .ancestor_hashes_replay_update = try .create(allocator),
        };
    }

    pub fn destroy(self: Senders) void {
        self.ancestor_hashes_replay_update.destroy();
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

pub const SlotData = struct {
    duplicate_confirmed_slots: replay.edge_cases.DuplicateConfirmedSlots,
    epoch_slots_frozen_slots: replay.edge_cases.EpochSlotsFrozenSlots,
    duplicate_slots_to_repair: replay.edge_cases.DuplicateSlotsToRepair,
    purge_repair_slot_counter: replay.edge_cases.PurgeRepairSlotCounters,
    unfrozen_gossip_verified_vote_hashes: replay.edge_cases.UnfrozenGossipVerifiedVoteHashes,
    duplicate_slots: replay.edge_cases.DuplicateSlots,

    pub const empty: SlotData = .{
        .duplicate_confirmed_slots = .empty,
        .epoch_slots_frozen_slots = .empty,
        .duplicate_slots_to_repair = .empty,
        .purge_repair_slot_counter = .empty,
        .unfrozen_gossip_verified_vote_hashes = .empty,
        .duplicate_slots = .empty,
    };

    pub fn deinit(self: SlotData, allocator: std.mem.Allocator) void {
        self.duplicate_confirmed_slots.deinit(allocator);
        self.epoch_slots_frozen_slots.deinit(allocator);

        var duplicate_slots_to_repair = self.duplicate_slots_to_repair;
        duplicate_slots_to_repair.deinit(allocator);

        self.purge_repair_slot_counter.deinit(allocator);
        self.unfrozen_gossip_verified_vote_hashes.deinit(allocator);
        self.duplicate_slots.deinit(allocator);
    }
};

const ReplayState = struct {
    allocator: Allocator,
    logger: Logger,
    slot_leaders: SlotLeaders,
    ledger: LedgerRef,
    account_store: AccountStore,

    my_identity: Pubkey,

    slot_tracker: SlotTracker,
    epochs: EpochTracker,
    progress: ProgressMap,
    fork_choice: HeaviestSubtreeForkChoice,
    replay_tower: sig.consensus.ReplayTower,
    latest_validator_votes: LatestValidatorVotes,
    status_cache: sig.core.StatusCache,
    slot_data: SlotData,

    thread_pool: ThreadPool,
    senders: Senders,
    receivers: Receivers,

    fn deinit(self: *ReplayState) void {
        self.thread_pool.shutdown();
        self.thread_pool.deinit();

        self.slot_tracker.deinit(self.allocator);

        self.epochs.deinit(self.allocator);

        self.progress.deinit(self.allocator);

        self.fork_choice.deinit();
        self.latest_validator_votes.deinit(self.allocator);
        self.slot_data.deinit(self.allocator);
    }

    fn init(deps: ReplayDependencies) !ReplayState {
        const allocator = deps.allocator;

        var slot_tracker: SlotTracker = try .init(allocator, deps.root.slot, .{
            .constants = deps.root.constants,
            .state = deps.root.state,
        });
        errdefer slot_tracker.deinit(allocator);
        const root_slot_ref = slot_tracker.get(deps.root.slot).?;

        // TODO: need to initialize progress and fork_choice properly:
        // both initialized inside replay, outside the mainloop, at the same time
        // using [`initialize_progress_and_fork_choice_with_locked_bank_forks`](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L637)
        const progress: ProgressMap = .INIT;
        errdefer progress.deinit(allocator);

        const fork_choice: HeaviestSubtreeForkChoice = try .init(allocator, deps.logger, .{
            .slot = deps.root.slot,
            .hash = root_slot_ref.state.hash.readCopy().?,
        });
        errdefer fork_choice.deinit();

        // TODO(ink): in agave replay_tower isn't created directly in replay,
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
            allocator,
            deps.logger,
            deps.my_identity,
            deps.vote_identity,
            deps.root.slot,
            deps.account_store.reader(),
        );
        errdefer replay_tower.deinit(allocator);

        return .{
            .allocator = allocator,
            .logger = .from(deps.logger),
            .slot_leaders = deps.slot_leaders,
            .ledger = deps.ledger,
            .account_store = deps.account_store,

            .my_identity = deps.my_identity,

            .thread_pool = .init(.{ .max_threads = NUM_THREADS }),

            .slot_tracker = slot_tracker,
            .epochs = .{ .schedule = deps.epoch_schedule },

            .progress = progress,
            .fork_choice = fork_choice,
            .replay_tower = replay_tower,
            .latest_validator_votes = .empty,
            .status_cache = .empty,
            .slot_data = .empty,

            .senders = deps.senders,
            .receivers = deps.receivers,
        };
    }

    fn executionState(self: *ReplayState) ReplayExecutionState {
        return .{
            .allocator = self.allocator,
            .logger = .from(self.logger),
            .my_identity = self.my_identity,
            .vote_account = null, // voting not currently supported

            .account_store = self.account_store,
            .thread_pool = &self.thread_pool,
            .blockstore_reader = self.ledger.reader,
            .slot_tracker = &self.slot_tracker,
            .epochs = &self.epochs,
            .progress_map = &self.progress,
            .status_cache = &self.status_cache,
        };
    }
};

/// Run the replay service indefinitely.
pub fn run(deps: ReplayDependencies) !void {
    var state = try ReplayState.init(deps);
    defer state.deinit();

    while (!deps.exit.load(.monotonic)) {
        try advanceReplay(&state, deps.my_identity);
    }
}

/// Run a single iteration of the entire replay process. Includes:
/// - replay all active slots that have not been replayed yet
/// - running concensus on the latest updates
fn advanceReplay(
    state: *ReplayState,
    my_pubkey: sig.core.Pubkey,
) !void {
    try trackNewSlots(
        state.allocator,
        state.account_store,
        &state.ledger.db,
        &state.slot_tracker,
        &state.epochs,
        state.slot_leaders,
        &state.progress,
    );

    _ = try replay.execution.replayActiveSlots(state.executionState());

    _ = try replay.edge_cases.processEdgeCases(state.allocator, state.logger, .{
        .my_pubkey = my_pubkey,
        .tpu_has_bank = false,

        .fork_choice = &state.fork_choice,
        .ledger = state.ledger.writer,

        .slot_tracker = &state.slot_tracker,
        .progress = &state.progress,
        .latest_validator_votes = &state.latest_validator_votes,
        .slot_data = &state.slot_data,

        .senders = state.senders,
        .receivers = state.receivers,
    });

    // ignore errors in consensus since they are expected until the inputs are provided
    replay.consensus.processConsensus(null) catch |e|
        state.logger.err().logf("consensus failed with an error: {}", .{e});

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
    const root = slot_tracker.root;
    var frozen_slots = try slot_tracker.frozenSlots(allocator);
    defer frozen_slots.deinit(allocator);

    var frozen_slots_since_root: std.ArrayListUnmanaged(Slot) =
        try .initCapacity(allocator, frozen_slots.count());
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
    var state = try SlotState.fromFrozenParent(allocator, parent_state);
    errdefer state.deinit(allocator);

    const epoch_reward_status = try parent_constants.epoch_reward_status
        .clone(allocator);
    errdefer epoch_reward_status.deinit(allocator);

    var ancestors = try parent_constants.ancestors.clone(allocator);
    errdefer ancestors.deinit(allocator);
    try ancestors.ancestors.put(allocator, slot, {});

    var feature_set = try getActiveFeatures(allocator, account_reader.forSlot(&ancestors), slot);
    errdefer feature_set.deinit(allocator);

    const parent_hash = parent_state.hash.readCopy().?;

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
    };

    return .{ constants, state };
}

// TODO: epoch boundary - handle feature activations
pub fn getActiveFeatures(
    allocator: Allocator,
    account_reader: SlotAccountReader,
    slot: Slot,
) !sig.core.FeatureSet {
    var features: sig.core.FeatureSet = .ALL_DISABLED;
    for (0..sig.core.features.NUM_FEATURES) |i| {
        const possible_feature: sig.core.features.Feature = @enumFromInt(i);
        const possible_feature_pubkey = sig.core.features.map.get(possible_feature);
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
        sig.core.features.map.get(.system_transfer_zero_check),
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
