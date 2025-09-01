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

const State = struct {
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

    status_cache: sig.core.StatusCache,

    execution_log_helper: replay.execution.LogHelper,

    fn deinit(self: *State) void {
        self.thread_pool.shutdown();
        self.thread_pool.deinit();

        self.slot_tracker.deinit(self.allocator);

        self.epochs.deinit(self.allocator);

        self.progress_map.deinit(self.allocator);
    }

    fn init(deps: Dependencies) !State {
        const zone = tracy.Zone.init(@src(), .{ .name = "State init" });
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

        const progress_map, const fork_choice =
            try replay.service.initProgressAndForkChoiceWithLockedSlotForks(
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

            .status_cache = .DEFAULT,

            .execution_log_helper = .init(.from(deps.logger)),
        };
    }

    pub fn executionState(self: *State) ReplayExecutionState {
        return .{
            .allocator = self.allocator,
            .logger = .from(self.logger),
            .my_identity = self.my_identity,
            .vote_account = null, // voting not currently supported
            .log_helper = &self.execution_log_helper,
            .account_store = self.account_store,
            .thread_pool = &self.thread_pool,
            .ledger_reader = self.ledger.reader,
            .slot_tracker = &self.slot_tracker,
            .epochs = &self.epochs,
            .progress_map = &self.progress_map,
            .status_cache = &self.status_cache,
        };
    }
};

/// Run the replay service indefinitely.
pub fn run(deps: Dependencies) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "run (replay service)" });
    defer zone.deinit();

    var state = try State.init(deps);
    defer state.deinit();

    while (!deps.exit.load(.monotonic)) {
        try advanceReplay(&state);
    }
}

/// Run a single iteration of the entire replay process. Includes:
/// - replay all active slots that have not been replayed yet
/// - running concensus on the latest updates
fn advanceReplay(state: *State) !void {
    const allocator = state.allocator;

    const zone = tracy.Zone.init(@src(), .{ .name = "advanceReplay" });
    defer zone.deinit();

    state.logger.debug().log("advancing replay");

    try sig.replay.service.trackNewSlots(
        allocator,
        state.logger,
        state.account_store,
        &state.ledger.db,
        &state.slot_tracker,
        &state.epochs,
        state.slot_leaders,
        &state.hard_forks,
        &state.progress_map,
    );

    const slot_results = try replay.execution.replayActiveSlotsSync(state.executionState());

    var processed_a_slot = false;
    for (slot_results) |result| {
        const slot = result.slot;
        const slot_info = state.slot_tracker.get(slot) orelse return error.MissingSlotInTracker;
        if (slot_info.state.tickHeight() == slot_info.constants.max_tick_height) {
            state.logger.info().logf("finished replaying slot: {}", .{slot});
            try replay.freeze.freezeSlot(state.allocator, .init(
                .from(state.logger),
                state.account_store,
                &(state.epochs.getForSlot(slot) orelse return error.MissingEpoch),
                slot_info.state,
                slot_info.constants,
                slot,
                result.entries[result.entries.len - 1].hash,
            ));
            processed_a_slot = true;
        } else {
            state.logger.info().logf("partially replayed slot: {}", .{slot});
        }
    }

    if (!processed_a_slot) std.time.sleep(100 * std.time.ns_per_ms);
}
