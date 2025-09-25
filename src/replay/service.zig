const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;

const Channel = sig.sync.Channel;
const RwMux = sig.sync.RwMux;
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
const AncestorHashesReplayUpdate = replay.consensus.AncestorHashesReplayUpdate;
const ConsensusState = replay.consensus.ConsensusState;
const AncestorDuplicateSlotToRepair = replay.edge_cases.AncestorDuplicateSlotToRepair;
const ThresholdConfirmedSlot = sig.consensus.vote_listener.ThresholdConfirmedSlot;
const GossipVerifiedVoteHash = sig.consensus.vote_listener.GossipVerifiedVoteHash;
const ParsedVote = sig.consensus.vote_listener.vote_parser.ParsedVote;
const LatestValidatorVotes = sig.consensus.latest_validator_votes.LatestValidatorVotes;
const SlotHistoryAccessor = sig.consensus.replay_tower.SlotHistoryAccessor;
const VerifiedVote = sig.consensus.vote_listener.VerifiedVote;
const VoteListener = sig.consensus.vote_listener.VoteListener;

const ProcessResultState = replay.process_result.ProcessResultState;
const ReplayExecutionState = replay.execution.ReplayExecutionState;
const ReplayResult = replay.execution.ReplayResult;

const EpochTracker = replay.trackers.EpochTracker;
const SlotTracker = replay.trackers.SlotTracker;
const SlotTree = replay.trackers.SlotTree;

const awaitResults = replay.execution.awaitResults;
const processResult = replay.process_result.processResult;
const updateSysvarsForNewSlot = replay.update_sysvar.updateSysvarsForNewSlot;

const LatestValidatorVotesForFrozenSlots =
    sig.consensus.latest_validator_votes.LatestValidatorVotes;

pub const Logger = sig.trace.Logger("replay");

const SWITCH_FORK_THRESHOLD: f64 = 0.38;
const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days
const DUPLICATE_LIVENESS_THRESHOLD: f64 = 0.1;
pub const DUPLICATE_THRESHOLD: f64 = 1.0 - SWITCH_FORK_THRESHOLD - DUPLICATE_LIVENESS_THRESHOLD;

pub const Service = struct {
    replay: ReplayState,
    consensus: ?ConsensusState,
    num_threads: u32,

    pub fn init(
        deps: *Dependencies,
        enable_consensus: ?ConsensusState.ChannelDependencies,
        num_threads: u32,
    ) !Service {
        var state = try ReplayState.init(deps, num_threads);
        errdefer state.deinit();

        var consensus: ?ConsensusState = if (enable_consensus) |consensus_deps| blk: {
            const slot_tracker, var slot_tracker_lock = state.slot_tracker.readWithLock();
            defer slot_tracker_lock.unlock();

            // Build the consolidated dependencies for ConsensusState
            const consensus_state_deps: ConsensusState.Dependencies = .{
                .allocator = deps.allocator,
                .logger = .from(deps.logger),
                .my_identity = deps.my_identity,
                .vote_identity = deps.vote_identity,
                .root_slot = deps.root.slot,
                .root_hash = slot_tracker.get(slot_tracker.root).?.state.hash.readCopy().?,
                .account_store = deps.account_store,
                .ledger_reader = deps.ledger.reader,
                .ledger_writer = deps.ledger.writer,
                .exit = deps.exit,
                .replay_votes_channel = state.replay_votes_channel,
                .slot_tracker_rw = &state.slot_tracker,
                .epoch_tracker_rw = &state.epoch_tracker,
                .senders = consensus_deps.senders,
                .receivers = consensus_deps.receivers,
                .gossip_table = consensus_deps.gossip_table,
            };

            break :blk try ConsensusState.init(consensus_state_deps);
        } else null;
        errdefer if (consensus) |*c| c.deinit(deps.allocator);

        return .{
            .replay = state,
            .consensus = consensus,
            .num_threads = num_threads,
        };
    }

    pub fn deinit(self: *Service, allocator: Allocator) void {
        if (self.consensus) |*c| c.deinit(allocator);
        self.replay.deinit();
    }

    pub fn advance(self: *Service) !void {
        try advanceReplay(&self.replay, &self.consensus, self.num_threads > 1);
    }
};

/// Create one instance and always pass by pointer.
pub const Dependencies = struct {
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
    /// The slot to start replaying from.
    root: struct {
        slot: Slot,
        /// ownership transferred to replay
        constants: Owned(sig.core.SlotConstants),
        /// ownership transferred to replay
        state: Owned(sig.core.SlotState),
    },
    current_epoch: sig.core.Epoch,
    /// ownership transferred to replay
    current_epoch_constants: Owned(sig.core.EpochConstants),
    /// ownership transferred to replay
    hard_forks: Owned(sig.core.HardForks),

    pub fn deinit(self: *Dependencies, allocator: Allocator) void {
        if (self.current_epoch_constants.tryBorrowMut()) |x| x.deinit(allocator);
        if (self.root.constants.tryBorrowMut()) |x| x.deinit(allocator);
        if (self.root.state.tryBorrowMut()) |x| x.deinit(allocator);
        if (self.hard_forks.tryBorrowMut()) |x| x.deinit(allocator);
    }

    pub fn Owned(T: type) type {
        return struct {
            /// do not access directly
            private: ?T,

            pub fn init(item: T) Owned(T) {
                return .{ .private = item };
            }

            /// asserts that the item has not been taken yet
            pub fn take(self: *Owned(T)) T {
                defer self.private = null;
                return self.private.?;
            }

            pub fn tryBorrowMut(self: *Owned(T)) ?*T {
                return if (self.private) |*item| item else null;
            }

            /// asserts that the item has not been taken yet
            pub fn borrow(self: *const Owned(T)) *const T {
                return &self.private.?;
            }
        };
    }
};

pub const LedgerRef = struct {
    db: LedgerDB,
    reader: *sig.ledger.LedgerReader,
    writer: *sig.ledger.LedgerResultWriter,
};

const ReplayState = struct {
    allocator: Allocator,
    my_identity: Pubkey,
    logger: Logger,
    thread_pool: ThreadPool,
    slot_leaders: SlotLeaders,
    /// Lifetime: owned by `ReplayState`.
    /// Borrowed across multiple threads (replay, vote_listener).
    /// These RwMuxes are deinitialized in `ReplayState.deinit()` only
    /// after all dependent threads have been joined based on defer order in `run`.
    slot_tracker: RwMux(SlotTracker),
    /// Lifetime rules are the same as `slot_tracker`.
    epoch_tracker: RwMux(EpochTracker),
    slot_tree: SlotTree,
    hard_forks: sig.core.HardForks,
    account_store: AccountStore,
    progress_map: ProgressMap,
    ledger: LedgerRef,
    status_cache: sig.core.StatusCache,
    execution_log_helper: replay.execution.LogHelper,
    replay_votes_channel: *Channel(ParsedVote),

    fn deinit(self: *ReplayState) void {
        self.thread_pool.shutdown();
        self.thread_pool.deinit();

        var slots = self.slot_tracker.tryRead() orelse
            @panic("Slot tracker deinit while in use");
        slots.get().deinit(self.allocator);

        var epoch_tracker = self.epoch_tracker.tryRead() orelse
            @panic("Epoch tracker deinit while in use");
        epoch_tracker.get().deinit(self.allocator);

        self.progress_map.deinit(self.allocator);
        self.replay_votes_channel.destroy();
        self.slot_tree.deinit(self.allocator);
        self.status_cache.deinit(self.allocator);
        self.hard_forks.deinit(self.allocator);
    }

    fn init(deps: *Dependencies, num_threads: u32) !ReplayState {
        const zone = tracy.Zone.init(@src(), .{ .name = "ReplayState init" });
        defer zone.deinit();

        var slot_tracker: SlotTracker = try .init(deps.allocator, deps.root.slot, .{
            .constants = deps.root.constants.take(),
            .state = deps.root.state.take(),
        });
        errdefer slot_tracker.deinit(deps.allocator);

        const replay_votes_channel = try Channel(ParsedVote).create(deps.allocator);
        errdefer replay_votes_channel.destroy();

        var epoch_tracker: EpochTracker = .{ .schedule = deps.epoch_schedule };
        errdefer epoch_tracker.deinit(deps.allocator);

        {
            const epoch_constants = deps.current_epoch_constants.take();
            errdefer epoch_constants.deinit(deps.allocator);
            try epoch_tracker.epochs.put(deps.allocator, deps.current_epoch, epoch_constants);
        }

        const progress_map = try initProgressMap(
            deps.allocator,
            &slot_tracker,
            &epoch_tracker,
            deps.my_identity,
            deps.vote_identity,
        );
        errdefer progress_map.deinit(deps.allocator);

        const slot_tree = try SlotTree.init(deps.allocator, deps.root.slot);
        errdefer slot_tree.deinit(deps.allocator);

        return .{
            .allocator = deps.allocator,
            .logger = .from(deps.logger),
            .thread_pool = .init(.{ .max_threads = num_threads }),
            .my_identity = deps.my_identity,
            .slot_leaders = deps.slot_leaders,
            .slot_tracker = .init(slot_tracker),
            .epoch_tracker = .init(epoch_tracker),
            .slot_tree = slot_tree,
            .hard_forks = deps.hard_forks.take(),
            .account_store = deps.account_store,
            .ledger = deps.ledger,
            .progress_map = progress_map,
            .status_cache = .DEFAULT,
            .execution_log_helper = .init(.from(deps.logger)),
            .replay_votes_channel = replay_votes_channel,
        };
    }

    pub fn executionState(self: *ReplayState) struct {
        ReplayExecutionState,
        RwMux(SlotTracker).RLockGuard,
        RwMux(EpochTracker).RLockGuard,
    } {
        const slot_tracker, const slot_tracker_lg = self.slot_tracker.readWithLock();
        const epoch_tracker, const epoch_tracker_lg = self.epoch_tracker.readWithLock();
        const execution_state: ReplayExecutionState = .{
            .allocator = self.allocator,
            .logger = .from(self.logger),
            .my_identity = self.my_identity,
            .vote_account = null, // voting not currently supported
            .log_helper = &self.execution_log_helper,
            .account_store = self.account_store,
            .thread_pool = &self.thread_pool,
            .ledger_reader = self.ledger.reader,
            .slot_tracker = slot_tracker,
            .epoch_tracker = epoch_tracker,
            .progress_map = &self.progress_map,
            .status_cache = &self.status_cache,
            .replay_votes_channel = self.replay_votes_channel,
        };

        return .{
            execution_state,
            slot_tracker_lg,
            epoch_tracker_lg,
        };
    }
};

/// Analogous to [`initialize_progress_and_fork_choice_with_locked_bank_forks`](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L637)
pub fn initProgressMap(
    allocator: std.mem.Allocator,
    slot_tracker: *const SlotTracker,
    epoch_tracker: *const EpochTracker,
    my_pubkey: Pubkey,
    vote_account: Pubkey,
) !ProgressMap {
    var frozen_slots = try slot_tracker.frozenSlots(allocator);
    defer frozen_slots.deinit(allocator);

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

    return progress;
}

const FrozenSlotsSortCtx = struct {
    slots: []const Slot,
    pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
        return ctx.slots[a_index] < ctx.slots[b_index];
    }
};

/// Analogous to [`initialize_progress_and_fork_choice_with_locked_bank_forks`](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L637)
pub fn initForkChoice(
    allocator: std.mem.Allocator,
    logger: Logger,
    slot_tracker: *const SlotTracker,
    ledger_reader: LedgerReader,
) !HeaviestSubtreeForkChoice {
    const root_slot, const root_hash = blk: {
        const root = slot_tracker.getRoot();
        const root_slot = slot_tracker.root;
        const root_hash = root.state.hash.readCopy();
        break :blk .{ root_slot, root_hash.? };
    };

    var frozen_slots = try slot_tracker.frozenSlots(allocator);
    defer frozen_slots.deinit(allocator);

    frozen_slots.sort(FrozenSlotsSortCtx{ .slots = frozen_slots.keys() });

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

    return heaviest_subtree_fork_choice;
}

/// Run a single iteration of the entire replay process. Includes:
/// - replay all active slots that have not been replayed yet
/// - running consensus on the latest updates (if present)
fn advanceReplay(state: *ReplayState, maybe_consensus: *?ConsensusState, multithread: bool) !void {
    const allocator = state.allocator;

    const zone = tracy.Zone.init(@src(), .{ .name = "advanceReplay" });
    defer zone.deinit();

    state.logger.debug().log("advancing replay");

    try trackNewSlots(
        allocator,
        state.logger,
        state.account_store,
        &state.ledger.db,
        &state.slot_tracker,
        &state.epoch_tracker,
        &state.slot_tree,
        state.slot_leaders,
        &state.hard_forks,
        &state.progress_map,
    );

    const slot_results = execution: {
        const execution_state, var epochs_lock, var slots_lock = state.executionState();
        defer epochs_lock.unlock();
        defer slots_lock.unlock();

        break :execution if (multithread)
            try awaitResults(allocator, try replay.execution.replayActiveSlots(execution_state))
        else
            try replay.execution.replayActiveSlotsSync(execution_state);
    };
    defer allocator.free(slot_results);

    const processed_a_slot = if (maybe_consensus.*) |*consensus|
        try consensus.doConsensus(
            allocator,
            .from(state.logger),
            state.my_identity,
            state.account_store,
            state.ledger.reader,
            state.ledger.writer,
            &state.slot_tracker,
            &state.epoch_tracker,
            &state.progress_map,
            slot_results,
        )
    else
        try bypassConsensus(state, slot_results);

    if (!processed_a_slot) std.time.sleep(100 * std.time.ns_per_ms);
}

/// bypass executing consensus, simply freezing slots and counting how many were
/// completed.
fn bypassConsensus(state: *ReplayState, results: []const ReplayResult) !bool {
    const epoch_tracker, var epoch_tracker_lg = state.epoch_tracker.readWithLock();
    defer epoch_tracker_lg.unlock();

    var processed_a_slot = false;
    {
        const slot_tracker, var slot_tracker_lg = state.slot_tracker.readWithLock();
        defer slot_tracker_lg.unlock();

        for (results) |result| switch (result.output) {
            .err => |err| state.logger.err().logf(
                "replayed slot {} with error: {}",
                .{ result.slot, err },
            ),
            .last_entry_hash => |last_entry_hash| {
                const slot = result.slot;
                const slot_info = slot_tracker.get(slot) orelse return error.MissingSlotInTracker;
                if (slot_info.state.tickHeight() == slot_info.constants.max_tick_height) {
                    state.logger.info().logf("finished replaying slot: {}", .{slot});
                    const epoch = epoch_tracker.getForSlot(slot) orelse return error.MissingEpoch;
                    try replay.freeze.freezeSlot(state.allocator, .init(
                        .from(state.logger),
                        state.account_store,
                        &epoch,
                        slot_info.state,
                        slot_info.constants,
                        slot,
                        last_entry_hash,
                    ));
                    processed_a_slot = true;
                } else {
                    state.logger.info().logf("partially replayed slot: {}", .{slot});
                }
            },
        };
    }

    if (state.slot_tree.reRoot(state.allocator)) |new_root| {
        const slot_tracker, var slot_tracker_lg = state.slot_tracker.writeWithLock();
        defer slot_tracker_lg.unlock();

        state.logger.info().logf("rooting slot with SlotTree.reRoot: {}", .{new_root});
        slot_tracker.root = new_root;
        slot_tracker.pruneNonRooted(state.allocator);
    }

    return processed_a_slot;
}

/// Identifies new slots in the ledger and starts tracking them in the slot
/// tracker.
///
/// Analogous to
/// [generate_new_bank_forks](https://github.com/anza-xyz/agave/blob/146ebd8be3857d530c0946003fcd58be220c3290/core/src/replay_stage.rs#L4149)
pub fn trackNewSlots(
    allocator: Allocator,
    logger: Logger,
    account_store: AccountStore,
    ledger_db: *LedgerDB,
    slot_tracker_rw: *RwMux(SlotTracker),
    epoch_tracker_rw: *RwMux(EpochTracker),
    slot_tree: *SlotTree,
    slot_leaders: SlotLeaders,
    hard_forks: *const sig.core.HardForks,
    /// needed for update_fork_propagated_threshold_from_votes
    _: *ProgressMap,
) !void {
    var zone = tracy.Zone.init(@src(), .{ .name = "trackNewSlots" });
    defer zone.deinit();

    const slot_tracker, var slot_tracker_lg = slot_tracker_rw.writeWithLock();
    defer slot_tracker_lg.unlock();
    const epoch_tracker, var epoch_tracker_lg = epoch_tracker_rw.readWithLock();
    defer epoch_tracker_lg.unlock();

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
            logger.info().logf("tracking new slot: {}", .{slot});

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
            try slot_tree.record(allocator, slot, constants.parent_slot);

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

/// Determines which features are active for this slot by looking up the feature
/// accounts in accountsdb.
///
/// Analogous to [compute_active_feature_set](https://github.com/anza-xyz/agave/blob/785455b5a3e2d8a95f878d6c80d5361dea9256db/runtime/src/bank.rs#L5338-L5339)
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
        defer feature_account.deinit(account_reader.allocator());
        if (!feature_account.owner.equals(&sig.runtime.ids.FEATURE_PROGRAM_ID)) {
            continue;
        }

        var data_iterator = feature_account.data.iterator();
        const reader = data_iterator.reader();
        const activated_at = try sig.bincode.read(allocator, ?u64, reader, .{});
        if (activated_at) |activation_slot| {
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
    // bincode for a feature that activated at slot 0
    var slot_0_bytes: [9]u8 = .{ 1, 0, 0, 0, 0, 0, 0, 0, 0 };
    var acct: sig.core.Account = undefined;
    acct.owner = Pubkey.ZEROES;
    acct.data = .{ .unowned_allocation = &slot_0_bytes };

    try accounts.put(
        allocator,
        sig.core.features.map.get(.system_transfer_zero_check).key,
        acct,
    );

    const features = try getActiveFeatures(allocator, .{ .single_version_map = &accounts }, 0);
    try std.testing.expect(!features.active(.system_transfer_zero_check, 1));

    acct.owner = sig.runtime.ids.FEATURE_PROGRAM_ID;
    try accounts.put(
        allocator,
        sig.core.features.map.get(.system_transfer_zero_check).key,
        acct,
    );

    const features2 = try getActiveFeatures(allocator, .{ .single_version_map = &accounts }, 0);
    try std.testing.expect(features2.active(.system_transfer_zero_check, 1));
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

    const slot_tracker_val: SlotTracker = try .init(allocator, 0, .{
        .state = try .genesis(allocator),
        .constants = try .genesis(allocator, .DEFAULT),
    });
    var slot_tracker = RwMux(SlotTracker).init(slot_tracker_val);
    defer {
        const ptr, var lg = slot_tracker.writeWithLock();
        defer lg.unlock();
        ptr.deinit(allocator);
    }
    {
        const ptr, var lg = slot_tracker.writeWithLock();
        defer lg.unlock();
        ptr.get(0).?.state.hash.set(.ZEROES);
    }

    const epoch_tracker_val: EpochTracker = .{ .schedule = .DEFAULT };
    var epoch_tracker = RwMux(EpochTracker).init(epoch_tracker_val);
    defer {
        const ptr, var lg = epoch_tracker.writeWithLock();
        defer lg.unlock();
        ptr.deinit(allocator);
    }
    {
        const ptr, var lg = epoch_tracker.writeWithLock();
        defer lg.unlock();
        try ptr.epochs.put(allocator, 0, .{
            .hashes_per_tick = 1,
            .ticks_per_slot = 1,
            .ns_per_slot = 1,
            .genesis_creation_time = 1,
            .slots_per_year = 1,
            .stakes = try .initEmptyWithGenesisStakeHistoryEntry(allocator),
            .rent_collector = .DEFAULT,
        });
    }

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
    {
        const ptr, var lg = slot_tracker.readWithLock();
        defer lg.unlock();
        try expectSlotTracker(ptr, leader_schedule, &.{.{ 0, 0 }}, &.{ 1, 2, 3, 4, 5, 6 });
    }

    const hard_forks = sig.core.HardForks{};

    var slot_tree = try SlotTree.init(allocator, 0);
    defer slot_tree.deinit(allocator);

    // only the root (0) is considered frozen, so only 0 and 1 should be added at first.
    try trackNewSlots(
        allocator,
        .FOR_TESTS,
        .noop,
        &ledger_db,
        &slot_tracker,
        &epoch_tracker,
        &slot_tree,
        slot_leaders,
        &hard_forks,
        undefined,
    );
    {
        const ptr, var lg = slot_tracker.readWithLock();
        defer lg.unlock();
        try expectSlotTracker(
            ptr,
            leader_schedule,
            &.{ .{ 0, 0 }, .{ 1, 0 } },
            &.{ 2, 3, 4, 5, 6 },
        );
    }

    // doing nothing should result in the same tracker state
    try trackNewSlots(
        allocator,
        .FOR_TESTS,
        .noop,
        &ledger_db,
        &slot_tracker,
        &epoch_tracker,
        &slot_tree,
        slot_leaders,
        &hard_forks,
        undefined,
    );
    {
        const ptr, var lg = slot_tracker.readWithLock();
        defer lg.unlock();
        try expectSlotTracker(
            ptr,
            leader_schedule,
            &.{ .{ 0, 0 }, .{ 1, 0 } },
            &.{ 2, 3, 4, 5, 6 },
        );
    }

    // freezing 1 should result in 2 and 4 being added
    {
        const ptr, var lg = slot_tracker.writeWithLock();
        defer lg.unlock();
        ptr.get(1).?.state.hash.set(.ZEROES);
    }
    try trackNewSlots(
        allocator,
        .FOR_TESTS,
        .noop,
        &ledger_db,
        &slot_tracker,
        &epoch_tracker,
        &slot_tree,
        slot_leaders,
        &hard_forks,
        undefined,
    );
    {
        const ptr, var lg = slot_tracker.readWithLock();
        defer lg.unlock();
        try expectSlotTracker(
            ptr,
            leader_schedule,
            &.{ .{ 0, 0 }, .{ 1, 0 }, .{ 2, 1 }, .{ 4, 1 } },
            &.{ 3, 5, 6 },
        );
    }

    // freezing 2 and 4 should only result in 6 being added since 3's parent is unknown
    {
        const ptr, var lg = slot_tracker.writeWithLock();
        defer lg.unlock();
        ptr.get(2).?.state.hash.set(.ZEROES);
        ptr.get(4).?.state.hash.set(.ZEROES);
    }
    try trackNewSlots(
        allocator,
        .FOR_TESTS,
        .noop,
        &ledger_db,
        &slot_tracker,
        &epoch_tracker,
        &slot_tree,
        slot_leaders,
        &hard_forks,
        undefined,
    );
    {
        const ptr, var lg = slot_tracker.readWithLock();
        defer lg.unlock();
        try expectSlotTracker(
            ptr,
            leader_schedule,
            &.{ .{ 0, 0 }, .{ 1, 0 }, .{ 2, 1 }, .{ 4, 1 }, .{ 6, 4 } },
            &.{ 3, 5 },
        );
    }
}

fn expectSlotTracker(
    slot_tracker: *const SlotTracker,
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

test "Service clean init and deinit" {
    const ns = struct {
        pub fn run(allocator: Allocator) !void {
            var dep_stubs = try DependencyStubs.init(allocator, .noop);
            defer dep_stubs.deinit(allocator);

            var service = try dep_stubs.stubbedService(allocator, .FOR_TESTS);
            defer service.deinit(allocator);

            dep_stubs.exit.store(true, .monotonic);
        }
    };
    try ns.run(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ns.run, .{});
}

test "doConsensus runs without error with no replay results" {
    const allocator = std.testing.allocator;

    var dep_stubs = try DependencyStubs.init(allocator, .FOR_TESTS);
    defer dep_stubs.deinit(allocator);

    var service = try dep_stubs.stubbedService(allocator, .FOR_TESTS);
    defer service.deinit(allocator);

    // TODO: run consensus in the tests that actually execute blocks for better
    // coverage. currently consensus panics or hangs if you run it with actual data
    _ = try service.consensus.?.doConsensus(
        allocator,
        .FOR_TESTS,
        service.replay.my_identity,
        service.replay.account_store,
        service.replay.ledger.reader,
        service.replay.ledger.writer,
        &service.replay.slot_tracker,
        &service.replay.epoch_tracker,
        &service.replay.progress_map,
        &.{},
    );

    dep_stubs.exit.store(true, .monotonic);
}

test "Execute testnet block single threaded" {
    if (!sig.build_options.long_tests) return error.SkipZigTest;

    try testExecuteBlock(std.testing.allocator, .{
        .num_threads = 1,
        .manifest_path = sig.TEST_DATA_DIR ++ "blocks/testnet-356797362/manifest.bin.gz",
        .shreds_path = sig.TEST_DATA_DIR ++ "blocks/testnet-356797362/shreds.json.gz",
        .accounts_path = sig.TEST_DATA_DIR ++ "blocks/testnet-356797362/accounts.json.gz",
    });
}

test "Execute testnet block multi threaded" {
    if (!sig.build_options.long_tests) return error.SkipZigTest;

    try testExecuteBlock(std.testing.allocator, .{
        .num_threads = 2,
        .manifest_path = sig.TEST_DATA_DIR ++ "blocks/testnet-356797362/manifest.bin.gz",
        .shreds_path = sig.TEST_DATA_DIR ++ "blocks/testnet-356797362/shreds.json.gz",
        .accounts_path = sig.TEST_DATA_DIR ++ "blocks/testnet-356797362/accounts.json.gz",
    });
}

fn testExecuteBlock(allocator: Allocator, config: struct {
    num_threads: u32,
    manifest_path: []const u8,
    shreds_path: []const u8,
    accounts_path: []const u8,
}) !void {
    var dep_stubs = try DependencyStubs.init(allocator, .FOR_TESTS);
    defer dep_stubs.deinit(allocator);

    // get snapshot manifest
    const fba_buf = try allocator.alloc(u8, 175_000_000);
    defer allocator.free(fba_buf);
    var fba = std.heap.FixedBufferAllocator.init(fba_buf);
    // TODO: figure out why `Manifest.deinit` doesn't work for a Manifest that
    // was deserialized with bincode.
    var manifest = try parseBincodeFromGzipFile(
        sig.accounts_db.snapshot.Manifest,
        fba.allocator(),
        config.manifest_path,
    );
    defer manifest.deinit(fba.allocator());

    // insert shreds
    const shred_bytes = try parseJsonFromGzipFile(
        []const []const u8,
        allocator,
        config.shreds_path,
    );
    defer shred_bytes.deinit();
    var shreds = std.MultiArrayList(struct { shred: sig.ledger.shred.Shred, is_repair: bool }).empty;
    defer {
        for (shreds.items(.shred)) |shred| shred.deinit();
        shreds.deinit(allocator);
    }
    try shreds.ensureTotalCapacity(allocator, shred_bytes.value.len);
    for (shred_bytes.value) |payload| {
        shreds.appendAssumeCapacity(.{
            .shred = try sig.ledger.shred.Shred.fromPayload(allocator, payload),
            .is_repair = false,
        });
    }
    var shred_inserter = try sig.ledger.ShredInserter.init(
        allocator,
        .FOR_TESTS,
        &dep_stubs.registry,
        dep_stubs.ledger.db.*,
    );
    const result = try shred_inserter.insertShreds(
        shreds.items(.shred),
        shreds.items(.is_repair),
        .{},
    );
    result.deinit();

    // get data about this test from snapshot + shreds
    const epoch = manifest.bank_fields.epoch;
    const snapshot_slot = manifest.bank_fields.slot;
    const execution_slot = shreds.items(.shred)[0].commonHeader().slot;

    // insert accounts
    const accounts = try parseJsonFromGzipFile(
        []const TestAccount,
        allocator,
        config.accounts_path,
    );
    defer accounts.deinit();
    for (accounts.value) |test_account| {
        _, const address, const account = try test_account.toAccount();
        try dep_stubs.accountsdb.put(snapshot_slot, address, account);
    }

    // calculate leader schedule
    const leader_schedule = try sig.core.leader_schedule.LeaderSchedule.fromVoteAccounts(
        allocator,
        epoch,
        manifest.bank_fields.epoch_schedule.slots_per_epoch,
        try manifest.epochVoteAccounts(epoch),
    );
    defer allocator.free(leader_schedule);
    var slot_leaders = sig.core.leader_schedule.SingleEpochSlotLeaders{
        .slot_leaders = leader_schedule,
        .start_slot = manifest.bank_fields.epoch_schedule.getFirstSlotInEpoch(epoch),
    };

    // init replay
    var service = try dep_stubs.mockedService(
        allocator,
        epoch,
        &manifest,
        slot_leaders.slotLeaders(),
        config.num_threads,
    );
    defer {
        while (service.replay.replay_votes_channel.tryReceive()) |item| item.deinit(allocator);
        service.deinit(allocator);
    }

    // replay the block
    try service.advance();

    // get slot hash
    const actual_slot_hash = tracker_lock: {
        var slot_tracker = service.replay.slot_tracker.tryRead() orelse unreachable;
        defer slot_tracker.unlock();
        break :tracker_lock slot_tracker.get().get(execution_slot).?.state.hash.readCopy().?;
    };

    const expected_slot_hash = sig.core.Hash.parse("4UeCbit4YGY42p9KrDzoD1LL21Vn3htb5N5G9w6L1kUE");

    try std.testing.expectEqual(expected_slot_hash, actual_slot_hash);
}

fn parseJsonFromGzipFile(
    comptime T: type,
    allocator: Allocator,
    path: []const u8,
) !std.json.Parsed(T) {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var decompressor = std.compress.gzip.decompressor(file.reader());

    var decompressor_reader = std.json.reader(allocator, decompressor.reader());
    defer decompressor_reader.deinit();

    return try std.json.parseFromTokenSource(T, allocator, &decompressor_reader, .{});
}

fn parseBincodeFromGzipFile(
    comptime T: type,
    allocator: Allocator,
    path: []const u8,
) !T {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var decompressor = std.compress.gzip.decompressor(file.reader());

    return try sig.bincode.read(
        allocator,
        T,
        decompressor.reader(),
        .{ .allocation_limit = 1 << 31 },
    );
}

/// Basic stubs for state that's supposed to be initialized outside replay,
/// outlive replay, and is used by replay.
const DependencyStubs = struct {
    accountsdb: sig.accounts_db.ThreadSafeAccountMap,
    exit: std.atomic.Value(bool),
    registry: sig.prometheus.Registry(.{}),
    dir: std.testing.TmpDir,
    ledger_path: []const u8,
    ledger: sig.ledger.UnifiedLedger,
    senders: ConsensusState.Senders,
    receivers: ConsensusState.Receivers,

    fn deinit(self: *DependencyStubs, allocator: Allocator) void {
        self.accountsdb.deinit();
        self.registry.deinit();
        self.dir.cleanup();
        allocator.free(self.ledger_path);
        self.ledger.deinit(allocator);
        self.senders.destroy();
        self.receivers.destroy();
    }

    fn init(allocator: Allocator, logger: Logger) !DependencyStubs {
        var accountsdb = sig.accounts_db.ThreadSafeAccountMap.init(allocator);
        errdefer accountsdb.deinit();

        var exit = std.atomic.Value(bool).init(false);

        var registry = sig.prometheus.Registry(.{}).init(allocator);
        errdefer registry.deinit();

        var dir = std.testing.tmpDir(.{});
        errdefer dir.cleanup();

        const ledger_path = try dir.dir.realpathAlloc(allocator, ".");
        errdefer allocator.free(ledger_path);

        var ledger = try sig.ledger.UnifiedLedger
            .init(allocator, .from(logger), ledger_path, &registry, &exit, null);
        errdefer ledger.deinit(allocator);

        var senders = try ConsensusState.Senders.create(allocator);
        errdefer senders.destroy();

        var receivers = try ConsensusState.Receivers.create(allocator);
        errdefer receivers.destroy();

        return .{
            .accountsdb = accountsdb,
            .exit = .init(false),
            .registry = registry,
            .dir = dir,
            .ledger_path = ledger_path,
            .ledger = ledger,
            .senders = senders,
            .receivers = receivers,
        };
    }

    /// Initialize replay service with stubbed inputs.
    /// (some inputs from this struct, some just stubbed directly)
    ///
    /// these inputs are "stubbed" with potentially garbage/meaningless data,
    /// rather than being "mocked" with meaningful data.
    fn stubbedService(self: *DependencyStubs, allocator: Allocator, logger: Logger) !Service {
        var rng = std.Random.DefaultPrng.init(0);
        const random = rng.random();

        var deps: Dependencies = deps: {
            var leader = Pubkey.initRandom(random);

            const root_slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
            errdefer root_slot_constants.deinit(allocator);

            var root_slot_state = try SlotState.genesis(allocator);
            errdefer root_slot_state.deinit(allocator);

            { // this is to essentially root the slot
                root_slot_state.hash.set(.ZEROES);
                var bhq = root_slot_state.blockhash_queue.write();
                defer bhq.unlock();
                try bhq.mut().insertGenesisHash(allocator, .ZEROES, 0);
            }

            const epoch = try sig.core.EpochConstants.genesis(allocator, .default(allocator));
            errdefer epoch.deinit(allocator);

            break :deps .{
                .allocator = allocator,
                .logger = logger,
                .my_identity = .initRandom(random),
                .vote_identity = .initRandom(random),
                .exit = &self.exit,
                .epoch_schedule = .DEFAULT,
                .account_store = self.accountsdb.accountStore(),
                .ledger = .{
                    .db = self.ledger.db.*,
                    .reader = self.ledger.reader,
                    .writer = self.ledger.result_writer,
                },
                .slot_leaders = SlotLeaders.init(&leader, struct {
                    pub fn get(pubkey: *Pubkey, _: Slot) ?Pubkey {
                        return pubkey.*;
                    }
                }.get),
                .root = .{
                    .slot = 0,
                    .constants = .init(root_slot_constants),
                    .state = .init(root_slot_state),
                },
                .current_epoch = 0,
                .current_epoch_constants = .init(epoch),
                .hard_forks = .init(.{}),
            };
        };
        defer deps.deinit(allocator);

        const consensus_deps = ConsensusState.ChannelDependencies{
            .senders = self.senders,
            .receivers = self.receivers,
            .gossip_table = null,
        };

        return try Service.init(&deps, consensus_deps, 1);
    }

    // TODO: consider deduplicating with above and similar function in cmd.zig
    /// "mocked" with meaningful data as opposed to "stubbed" with garbage data
    fn mockedService(
        self: *DependencyStubs,
        allocator: std.mem.Allocator,
        epoch: sig.core.Epoch,
        collapsed_manifest: *const sig.accounts_db.snapshot.Manifest,
        slot_leaders: sig.core.leader_schedule.SlotLeaders,
        num_threads: u32,
    ) !Service {
        var deps: Dependencies = deps: {
            const bank_fields = &collapsed_manifest.bank_fields;
            const epoch_stakes_map = &collapsed_manifest.bank_extra.versioned_epoch_stakes;
            const epoch_stakes = epoch_stakes_map.get(epoch) orelse
                return error.EpochStakesMissingFromSnapshot;

            const feature_set = try sig.replay.service.getActiveFeatures(
                allocator,
                self.accountsdb.accountReader().forSlot(&bank_fields.ancestors),
                bank_fields.slot,
            );

            const root_slot_constants = try sig.core.SlotConstants.fromBankFields(
                allocator,
                bank_fields,
                feature_set,
            );
            errdefer root_slot_constants.deinit(allocator);

            const lt_hash = if (collapsed_manifest.bank_extra.accounts_lt_hash) |lt_hash|
                sig.core.LtHash{ .data = lt_hash }
            else
                null;

            var root_slot_state =
                try sig.core.SlotState.fromBankFields(allocator, bank_fields, lt_hash);
            errdefer root_slot_state.deinit(allocator);

            const hard_forks = try bank_fields.hard_forks.clone(allocator);
            errdefer hard_forks.deinit(allocator);

            break :deps .{
                .allocator = allocator,
                .logger = .FOR_TESTS,
                .my_identity = .ZEROES,
                .vote_identity = .ZEROES,
                .exit = &self.exit,
                .account_store = self.accountsdb.accountStore(),
                .ledger = .{
                    .db = self.ledger.db.*,
                    .reader = self.ledger.reader,
                    .writer = self.ledger.result_writer,
                },
                .epoch_schedule = bank_fields.epoch_schedule,
                .slot_leaders = slot_leaders,
                .root = .{
                    .slot = bank_fields.slot,
                    .constants = .init(root_slot_constants),
                    .state = .init(root_slot_state),
                },
                .current_epoch = epoch,
                .current_epoch_constants = .init(try .fromBankFields(
                    bank_fields,
                    try epoch_stakes.current.convert(allocator, .delegation),
                )),
                .hard_forks = .init(hard_forks),
            };
        };
        defer deps.deinit(allocator);

        return try Service.init(&deps, null, num_threads);
    }
};

const TestAccount = struct {
    slot: Slot,
    pubkey: []const u8,
    lamports: u64,
    owner: []const u8,
    executable: bool,
    rent_epoch: u64,
    data: []u8,

    pub fn deinit(self: @This(), allocator: std.mem.Allocator) void {
        allocator.free(self.pubkey);
        allocator.free(self.owner);
        allocator.free(self.data);
    }

    pub fn toAccount(self: @This()) !struct { Slot, Pubkey, sig.runtime.AccountSharedData } {
        return .{
            self.slot,
            try .parseRuntime(self.pubkey),
            .{
                .lamports = self.lamports,
                .owner = try .parseRuntime(self.owner),
                .executable = self.executable,
                .rent_epoch = self.rent_epoch,
                .data = self.data,
            },
        };
    }
};
