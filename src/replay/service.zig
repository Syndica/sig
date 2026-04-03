const std = @import("std");
const std14 = @import("std14");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");
const jrpc_types = sig.rpc.jrpc_websockets.types;

const Allocator = std.mem.Allocator;

const Channel = sig.sync.Channel;
const ThreadPool = sig.sync.ThreadPool;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SlotConstants = sig.core.SlotConstants;
const SlotLeaders = sig.core.leader_schedule.SlotLeaders;
const SlotState = sig.core.bank.SlotState;
const StatusCache = sig.core.StatusCache;

const AccountStore = sig.accounts_db.AccountStore;
const AccountReader = sig.accounts_db.AccountReader;

const Ledger = sig.ledger.Ledger;

const ProgressMap = sig.consensus.ProgressMap;
const TowerConsensus = replay.consensus.TowerConsensus;
const ParsedVote = sig.consensus.vote_listener.vote_parser.ParsedVote;

const ReplayResult = replay.execution.ReplayResult;

const CommitmentStakes = replay.trackers.CommitmentStakes;
const SlotTracker = replay.trackers.SlotTracker;
const SlotTree = replay.trackers.SlotTree;

const GossipVerifiedVoteHash = sig.consensus.vote_listener.GossipVerifiedVoteHash;
const ThresholdConfirmedSlot = sig.consensus.vote_listener.ThresholdConfirmedSlot;

const schema = sig.ledger.schema.schema;

const updateSysvarsForNewSlot = replay.update_sysvar.updateSysvarsForNewSlot;

pub const Logger = sig.trace.Logger("replay");

pub const Metrics = struct {
    slot_execution_time: *sig.prometheus.Histogram,
    voted_slot_update_count: *sig.prometheus.Counter,
    optimistically_confirmed_update_count: *sig.prometheus.Counter,
    root_update_count: *sig.prometheus.Counter,
    state_root_update_count: *sig.prometheus.Counter,
    consensus_root: *sig.prometheus.Gauge(u64),
    state_root: *sig.prometheus.Gauge(u64),
    slot_tracker_count: *sig.prometheus.Gauge(u64),
    epoch_tracker_state_root: *sig.prometheus.Gauge(u64),
    commitment_processed: *sig.prometheus.Gauge(u64),
    commitment_confirmed: *sig.prometheus.Gauge(u64),
    commitment_finalized: *sig.prometheus.Gauge(u64),

    pub const prefix = "replay";
    pub const histogram_buckets = b: {
        const base = 100 * std.time.ns_per_ms;
        var buckets: [20]f64 = undefined;
        for (&buckets, 0..) |*bucket, i| bucket.* = i * base;
        break :b buckets;
    };
};

pub const AdvanceReplayConsensusParams = struct {
    tower: *TowerConsensus,
    gossip_votes: ?*sig.sync.Channel(sig.gossip.data.Vote),
    senders: TowerConsensus.Senders,
    receivers: TowerConsensus.Receivers,
    vote_sockets: ?*const sig.replay.consensus.core.VoteSockets,
    gossip_table: ?*sig.sync.RwMux(sig.gossip.GossipTable),
};

/// Run a single iteration of the entire replay process. Includes:
/// - replay all active slots that have not been replayed yet
/// - running consensus on the latest updates (if present)
pub fn advanceReplay(
    replay_state: *ReplayState,
    metrics: Metrics,
    consensus_params: ?AdvanceReplayConsensusParams,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "advanceReplay" });
    defer zone.deinit();

    const allocator = replay_state.allocator;

    var start_time = sig.time.Timer.start();
    replay_state.logger.debug().log("advancing replay");

    var leader_schedules_with_epoch_infos = try replay_state.epoch_tracker.getLeaderSchedules();
    defer leader_schedules_with_epoch_infos.release();
    var leader_schedules = leader_schedules_with_epoch_infos.leader_schedules;
    const slot_leaders = SlotLeaders.init(
        &leader_schedules,
        sig.core.leader_schedule.LeaderSchedules.getLeaderOrNull,
    );

    // find slots in the ledger
    try trackNewSlots(
        allocator,
        replay_state.logger,
        replay_state.account_store,
        replay_state.ledger,
        &replay_state.slot_tracker,
        replay_state.epoch_tracker,
        &replay_state.slot_tree,
        slot_leaders,
        &replay_state.hard_forks,
        &replay_state.progress_map,
    );

    // replay slots
    const slot_results = try replay.execution.replayActiveSlots(replay_state);
    defer allocator.free(slot_results);

    // freeze slots
    const processed_a_slot: bool = try freezeCompletedSlots(replay_state, slot_results);

    // prepare data used for communication between consensus and RPC
    var recent_processed_ancestors: ?[]const Slot = null;
    var commitment_txn: ?*CommitmentStakes.Transaction = null;
    defer if (recent_processed_ancestors) |r| allocator.free(r);
    if (replay_state.commitments) |*commitments| {
        recent_processed_ancestors = try sortedRecentProcessedAncestors(
            allocator,
            &replay_state.slot_tracker,
            commitments,
            &replay_state.status_cache,
        );
        commitment_txn = commitments.stakes.beginTransaction(recent_processed_ancestors.?);
    }
    defer if (commitment_txn) |t| t.reset();

    // run consensus
    const slot_update = if (consensus_params) |consensus| slot_update: {
        var gossip_verified_vote_hashes: std.ArrayListUnmanaged(GossipVerifiedVoteHash) = .empty;
        defer gossip_verified_vote_hashes.deinit(allocator);

        var duplicate_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
        defer duplicate_confirmed_slots.deinit(allocator);

        break :slot_update try consensus.tower.process(allocator, .{
            .account_store = replay_state.account_store,
            .gossip_votes = consensus.gossip_votes,
            .gossip_table = consensus.gossip_table,
            .ledger = replay_state.ledger,
            .slot_tracker = &replay_state.slot_tracker,
            .epoch_tracker = replay_state.epoch_tracker,
            .progress_map = &replay_state.progress_map,
            .senders = consensus.senders,
            .receivers = consensus.receivers,
            .vote_sockets = consensus.vote_sockets,
            .slot_leaders = slot_leaders,
            .duplicate_confirmed_slots = &duplicate_confirmed_slots,
            .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
            .results = slot_results,
            .vote_account_visitor = if (commitment_txn) |t| t.voteAccountVisitor() else null,
        });
    } else slot_update: {
        // NOTE: Processed slot semantics differ from Agave when Sig is in bypass-consensus mode.
        // In bypass mode, `latest_processed_slot` is set to the highest slot among all fork
        // leaves (SlotTree.tip()).
        //
        // This differs from Agave's behavior: the processed slot is only updated
        // when `vote_bank.is_some()` (i.e., when the validator has selected a bank
        // to vote on after passing all consensus checks like lockout, threshold, and
        // switch proof). If the validator is locked out or fails
        // threshold checks, the processed slot is NOT updated and can go stale.
        // See: https://github.com/anza-xyz/agave/blob/5e900421520a10933642d5e9a21e191a70f9b125/core/src/replay_stage.rs#L2683
        //
        // TowerConsensus implements Agave's processed slot semantics when consensus is enabled.
        const slot_update = replay_state.slot_tree.reRoot(replay_state.allocator);
        if (slot_update.root) |new_root|
            replay_state.logger.info().logf("rooting slot with SlotTree.reRoot: {}", .{new_root});
        break :slot_update slot_update;
    };

    try handleSlotUpdate(allocator, replay_state, slot_update, commitment_txn, metrics);
    recordSlotMetrics(replay_state, metrics);

    if (slot_results.len != 0) {
        const elapsed = start_time.read().asNanos();
        metrics.slot_execution_time.observe(elapsed);
        replay_state.logger.info().logf("advanced in {D}", .{elapsed});
    }

    if (replay_state.stop_at_slot) |stop_slot| {
        for (slot_results) |result| if (result.slot >= stop_slot) {
            replay_state.logger.info().logf("Reached end slot {}, exiting replay", .{stop_slot});
            return error.ReachedEndSlot;
        };
    }

    if (!processed_a_slot) try std.Thread.yield();
}

pub const SlotUpdate = struct {
    root: ?Slot,
    voted: ?Slot,
    optimistically_confirmed: ?Slot,
};

/// Extract StatusCache's sorted root slots so that the accumulator only tracks
/// commitment for recent ancestor slots, matching Agave's
/// `aggregate_commitment_for_vote_account` semantics.
///
/// Combines this with the processed slot's unrooted ancestors.
///
/// analogous to agave's usage of Bank::status_cache_ancestors when populating
/// the block commitment cache.
pub fn sortedRecentProcessedAncestors(
    allocator: std.mem.Allocator,
    slot_tracker: *SlotTracker,
    commitments: *const replay.trackers.CommitmentTracker,
    status_cache: *StatusCache,
) ![]const Slot {
    const processed_reader = slot_tracker.get(commitments.get(.processed)) orelse
        return error.MissingProcessedSlot;
    defer processed_reader.release();

    const processed_ancestors = &processed_reader.constants().ancestors;

    var state = status_cache.state.read();
    defer state.unlock();

    const roots = state.get().roots;
    const keys = roots.keys();

    var sorted_recent_processed_ancestors: std.ArrayList(Slot) = .empty;
    try sorted_recent_processed_ancestors.ensureTotalCapacity(allocator, keys.len);
    sorted_recent_processed_ancestors.items.len = keys.len;
    @memcpy(sorted_recent_processed_ancestors.items, keys);

    var max_root: Slot = 0;
    for (sorted_recent_processed_ancestors.items) |slot| max_root = @max(slot, max_root);

    for (processed_ancestors.ancestors.keys()) |slot| {
        if (slot > max_root) try sorted_recent_processed_ancestors.append(allocator, slot);
    }

    std.mem.sort(Slot, sorted_recent_processed_ancestors.items, {}, std.sort.asc(Slot));

    return try sorted_recent_processed_ancestors.toOwnedSlice(allocator);
}

pub const Dependencies = struct {
    /// Used for all allocations within the replay stage
    allocator: Allocator,
    logger: Logger,
    identity: sig.identity.ValidatorIdentity,
    signing: sig.identity.SigningKeys,
    account_store: sig.accounts_db.AccountStore,
    /// Reader used to get the entries to validate them and execute the transactions
    /// Writer used to update the ledger with consensus results
    ledger: *Ledger,
    epoch_tracker: *sig.core.EpochTracker,
    /// The slot info to start replaying from.
    root: struct {
        slot: Slot,
        /// ownership transferred to replay; won't be freed if `ReplayState.init` returns an error.
        constants: sig.core.SlotConstants,
        /// ownership transferred to replay; won't be freed if `ReplayState.init` returns an error.
        state: sig.core.SlotState,
    },
    /// ownership transferred to replay
    hard_forks: sig.core.HardForks,
    replay_threads: u32,
    stop_at_slot: ?Slot,
    event_sink: ?*jrpc_types.EventSink = null,
    prioritization_fee_cache: ?*sig.rpc.hook_contexts.PrioritizationFeeCache = null,
};

pub const ConsensusStatus = enum {
    enabled,
    disabled,
};

pub const RPCStatus = enum {
    enabled,
    disabled,
};

pub const ReplayState = struct {
    allocator: Allocator,
    logger: Logger,
    identity: sig.identity.ValidatorIdentity,
    signing: sig.identity.SigningKeys,
    thread_pool: ThreadPool,
    slot_tracker: SlotTracker,
    epoch_tracker: *sig.core.EpochTracker,
    slot_tree: SlotTree,
    hard_forks: sig.core.HardForks,
    account_store: AccountStore,
    progress_map: ProgressMap,
    ledger: *Ledger,
    status_cache: sig.core.StatusCache,
    commitments: ?replay.trackers.CommitmentTracker,
    execution_log_helper: replay.execution.LogHelper,
    replay_votes_channel: ?*Channel(ParsedVote),
    event_sink: ?*jrpc_types.EventSink,
    stop_at_slot: ?sig.core.Slot,
    prioritization_fee_cache: ?*sig.rpc.hook_contexts.PrioritizationFeeCache = null,

    pub fn deinit(self: *ReplayState) void {
        self.slot_tracker.deinit(self.allocator);
        self.progress_map.deinit(self.allocator);

        if (self.replay_votes_channel) |channel| {
            while (channel.tryReceive()) |item| item.deinit(self.allocator);
            channel.destroy();
        }

        self.slot_tree.deinit(self.allocator);
        self.status_cache.deinit(self.allocator);
        if (self.commitments) |*tracker| tracker.deinit(self.allocator);
        self.hard_forks.deinit(self.allocator);

        self.thread_pool.shutdown();
        self.thread_pool.deinit();
    }

    pub fn init(
        deps: Dependencies,
        consensus_status: ConsensusStatus,
        rpc_status: RPCStatus,
    ) !ReplayState {
        const zone = tracy.Zone.init(@src(), .{ .name = "ReplayState init" });
        defer zone.deinit();

        var slot_tracker: SlotTracker = try .init(
            deps.allocator,
            deps.root.slot,
            .{
                .constants = deps.root.constants,
                .state = deps.root.state,
                .allocator = deps.allocator,
            },
        );
        errdefer slot_tracker.deinit(deps.allocator);
        errdefer {
            // do not free the root slot data parameter, we don't own it unless the function returns successfully
            var slots_lg = slot_tracker.slots.write();
            defer slots_lg.unlock();
            deps.allocator.destroy(slots_lg.mut().fetchSwapRemove(deps.root.slot).?.value);
        }

        const replay_votes_channel: ?*Channel(ParsedVote) = if (consensus_status == .enabled)
            try Channel(ParsedVote).create(deps.allocator)
        else
            null;
        errdefer if (replay_votes_channel) |ch| ch.destroy();

        const progress_map = try initProgressMap(
            deps.allocator,
            &slot_tracker,
            deps.epoch_tracker,
            deps.identity.validator,
            deps.identity.vote_account,
        );
        errdefer progress_map.deinit(deps.allocator);

        const slot_tree = try SlotTree.init(deps.allocator, deps.root.slot);
        errdefer slot_tree.deinit(deps.allocator);

        return .{
            .allocator = deps.allocator,
            .logger = .from(deps.logger),
            .identity = deps.identity,
            .signing = deps.signing,
            .thread_pool = .init(.{ .max_threads = deps.replay_threads }),
            .slot_tracker = slot_tracker,
            .epoch_tracker = deps.epoch_tracker,
            .slot_tree = slot_tree,
            .hard_forks = deps.hard_forks,
            .account_store = deps.account_store,
            .ledger = deps.ledger,
            .progress_map = progress_map,
            .status_cache = .DEFAULT,
            .commitments = switch (rpc_status) {
                .enabled => .init(deps.allocator, deps.root.slot),
                .disabled => null,
            },
            .execution_log_helper = .init(.from(deps.logger)),
            .replay_votes_channel = replay_votes_channel,
            .event_sink = deps.event_sink,
            .stop_at_slot = deps.stop_at_slot,
            .prioritization_fee_cache = deps.prioritization_fee_cache,
        };
    }
};

/// Analogous to [`initialize_progress_and_fork_choice_with_locked_bank_forks`](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L637)
pub fn initProgressMap(
    allocator: std.mem.Allocator,
    slot_tracker: *SlotTracker,
    epoch_tracker: *sig.core.EpochTracker,
    my_pubkey: Pubkey,
    vote_account: ?Pubkey,
) !ProgressMap {
    var frozen_slots = try slot_tracker.frozenSlots(allocator);
    defer frozen_slots.deinit(allocator);
    defer for (frozen_slots.values()) |ref| ref.release();

    frozen_slots.sort(FrozenSlotsSortCtx{ .slots = frozen_slots.keys() });

    var progress: ProgressMap = .INIT;
    errdefer progress.deinit(allocator);

    // Initialize progress map with any root slots
    for (frozen_slots.keys(), frozen_slots.values()) |slot, ref| {
        const epoch_info = try epoch_tracker.getEpochInfo(slot);
        defer epoch_info.release();
        const prev_leader_slot = progress.getSlotPrevLeaderSlot(ref.constants().parent_slot);
        try progress.map.ensureUnusedCapacity(allocator, 1);
        progress.map.putAssumeCapacity(slot, try .initFromInfo(allocator, .{
            .slot_info = ref,
            .epoch_stakes = &epoch_info.stakes,
            .now = .now(),
            .validator_identity = &my_pubkey,
            .validator_vote_pubkey = vote_account,
            .prev_leader_slot = prev_leader_slot,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        }));
    }

    return progress;
}

/// This is pub because it's used both in this file and consensus/core.zig. In
/// the future we'll probably stop using this in at least one of those places,
/// and at that point it should be deleted or moved and made non-pub.
pub const FrozenSlotsSortCtx = struct {
    slots: []const Slot,
    pub fn lessThan(ctx: @This(), a_index: usize, b_index: usize) bool {
        return ctx.slots[a_index] < ctx.slots[b_index];
    }
};

/// Identifies new slots in the ledger and starts tracking them in the slot
/// tracker.
///
/// Analogous to
/// [generate_new_bank_forks](https://github.com/anza-xyz/agave/blob/146ebd8be3857d530c0946003fcd58be220c3290/core/src/replay_stage.rs#L4149)
pub fn trackNewSlots(
    allocator: Allocator,
    logger: Logger,
    account_store: AccountStore,
    ledger: *Ledger,
    slot_tracker: *SlotTracker,
    epoch_tracker: *sig.core.EpochTracker,
    slot_tree: *SlotTree,
    slot_leaders: SlotLeaders,
    hard_forks: *const sig.core.HardForks,
    /// needed for update_fork_propagated_threshold_from_votes
    _: *ProgressMap,
) !void {
    var zone = tracy.Zone.init(@src(), .{ .name = "trackNewSlots" });
    defer zone.deinit();

    const root = slot_tracker.consensus_root.load(.monotonic);
    var frozen_slots = try slot_tracker.frozenSlots(allocator);
    defer frozen_slots.deinit(allocator);
    defer for (frozen_slots.values()) |ref| ref.release();

    var frozen_slots_since_root = try std.ArrayListUnmanaged(sig.core.Slot)
        .initCapacity(allocator, frozen_slots.count());
    defer frozen_slots_since_root.deinit(allocator);
    for (frozen_slots.keys()) |slot| if (slot >= root) {
        frozen_slots_since_root.appendAssumeCapacity(slot);
    };

    var next_slots = try ledger.reader().getSlotsSince(allocator, frozen_slots_since_root.items);
    defer {
        for (next_slots.values()) |*list| list.deinit(allocator);
        next_slots.deinit(allocator);
    }

    for (next_slots.keys(), next_slots.values()) |parent_slot, children| {
        const parent_info = frozen_slots.get(parent_slot) orelse return error.MissingParent;

        for (children.items) |slot| {
            if (slot_tracker.contains(slot)) continue;
            logger.info().logf("tracking new slot: {}", .{slot});

            // Constants are not constant at this point since processing new epochs
            // may modify the feature set.
            var constants, var state = try newSlotFromParent(
                allocator,
                account_store.reader(),
                epoch_tracker.cluster.ticks_per_slot,
                parent_slot,
                parent_info.constants(),
                parent_info.state(),
                slot_leaders.get(slot) orelse return error.UnknownLeader,
                slot,
            );
            errdefer constants.deinit(allocator);
            errdefer state.deinit(allocator);

            const parent_epoch = epoch_tracker.epoch_schedule.getEpoch(parent_slot);
            const slot_epoch = epoch_tracker.epoch_schedule.getEpoch(slot);
            const store = account_store.forSlot(slot, &constants.ancestors);

            if (parent_epoch < slot_epoch) {
                try replay.epoch_transitions.processNewEpoch(
                    allocator,
                    slot,
                    &constants,
                    &state,
                    store,
                    epoch_tracker,
                    .from(logger),
                );
            } else {
                try replay.epoch_transitions.updateEpochStakes(
                    allocator,
                    slot,
                    &constants.ancestors,
                    &constants.feature_set,
                    &state.stakes_cache,
                    epoch_tracker,
                );
            }

            try replay.rewards.distribution.distributePartitionedEpochRewards(
                allocator,
                slot,
                slot_epoch,
                constants.block_height,
                epoch_tracker.epoch_schedule,
                &state.reward_status,
                &state.stakes_cache,
                &state.capitalization,
                &constants.rent_collector.rent,
                store,
                constants.feature_set.newWarmupCooldownRateEpoch(
                    &epoch_tracker.epoch_schedule,
                ),
            );

            const clock = try updateSysvarsForNewSlot(
                allocator,
                account_store,
                epoch_tracker,
                &constants,
                &state,
                slot,
                hard_forks,
            );
            try ledger.db.put(schema.blocktime, slot, clock.unix_timestamp);
            try ledger.db.put(schema.block_height, slot, constants.block_height);

            try slot_tracker.put(allocator, slot, .{
                .constants = constants,
                .state = state,
                .allocator = allocator,
            });
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
pub fn newSlotFromParent(
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

    var ancestors = try parent_constants.ancestors.clone(allocator);
    errdefer ancestors.deinit(allocator);

    try ancestors.addSlot(allocator, slot);
    ancestors.cleanup();

    var feature_set = try getActiveFeatures(allocator, account_reader.forSlot(&ancestors), slot);

    const parent_hash = parent_state.hash.readCopy().?;

    // This is inefficient, reserved accounts could live in epoch constants along with
    // the feature set since feature activations are only applied at epoch boundaries.
    // Then we only need to clone the map and update the reserved accounts once per epoch.
    const reserved_accounts = try sig.core.ReservedAccounts.initForSlot(
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
        .ancestors = ancestors,
        .feature_set = feature_set,
        .reserved_accounts = reserved_accounts,
        .inflation = parent_constants.inflation,
        .rent_collector = parent_constants.rent_collector,
    };

    return .{ constants, state };
}

/// Determines which features are active for this slot by looking up the feature
/// accounts in accountsdb.
///
/// Analogous to [compute_active_feature_set](https://github.com/anza-xyz/agave/blob/785455b5a3e2d8a95f878d6c80d5361dea9256db/runtime/src/bank.rs#L5338-L5339)
// TODO: epoch boundary - handle feature activations
pub fn getActiveFeatures(
    gpa: Allocator,
    account_reader: sig.accounts_db.SlotAccountReader,
    slot: Slot,
) !sig.core.FeatureSet {
    const zone = tracy.Zone.init(@src(), .{ .name = "getActiveFeatures" });
    defer zone.deinit();

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const allocator = arena.allocator();

    var features: sig.core.FeatureSet = .ALL_DISABLED;
    for (0..sig.core.features.NUM_FEATURES) |i| {
        defer _ = arena.reset(.retain_capacity);

        const possible_feature: sig.core.features.Feature = @enumFromInt(i);
        const possible_feature_pubkey = sig.core.features.map.get(possible_feature).key;

        const feature_account = try account_reader.get(allocator, possible_feature_pubkey) orelse
            continue;
        defer feature_account.deinit(allocator);

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

/// freezes any slots that were completed according to these replay results
fn freezeCompletedSlots(state: *ReplayState, results: []const ReplayResult) !bool {
    const slot_tracker = &state.slot_tracker;

    var processed_a_slot = false;
    for (results) |result| switch (result.output) {
        .err => |err| {
            state.logger.logf(
                switch (err) {
                    // invalid_block may be a non-issue and simply indicate that
                    // the leader produced a malformed block that will be
                    // skipped. To be safe/thorough, we're logging them all as
                    // error, unless we observe it often and confirm it to
                    // routinely not be a problem.
                    .invalid_block => |e| switch (e) {
                        // TooFewTicks is typical during forks and should not require intervention.
                        .TooFewTicks => .warn,
                        else => .@"error",
                    },
                    else => .@"error",
                },
                "replayed slot {} with error: {}",
                .{ result.slot, err },
            );
        },
        .last_entry_hash => |last_entry_hash| {
            const slot = result.slot;
            const slot_info = slot_tracker.get(slot) orelse return error.MissingSlotInTracker;
            defer slot_info.release();
            if (slot_info.state().tickHeight() == slot_info.constants().max_tick_height) {
                state.logger.info().logf("finished replaying slot: {}", .{slot});
                try replay.freeze.freezeSlot(state.allocator, .init(
                    .from(state.logger),
                    state.account_store,
                    &state.thread_pool,
                    slot_info.state(),
                    slot_info.constants(),
                    slot,
                    last_entry_hash,
                    state.ledger,
                ));
                if (state.prioritization_fee_cache) |cache| {
                    cache.finalizeSlot(state.allocator, slot);
                }
                processed_a_slot = true;

                if (state.event_sink) |event_sink| {
                    var accounts = try event_sink.materializeSlotModifiedAccounts(
                        state.logger,
                        state.account_store.reader(),
                        slot,
                    );
                    errdefer accounts.deinit();

                    try event_sink.send(.{ .slot_frozen = .{
                        .slot = slot,
                        .parent = slot_info.constants().parent_slot,
                        .root = slot_tracker.state_root.load(.monotonic),
                        .accounts = accounts,
                    } });
                }
            } else {
                state.logger.info().logf("partially replayed slot: {}", .{slot});
            }
        },
    };

    return processed_a_slot;
}

/// Processes a slot update from consensus. This has three responsibilities:
///
/// 1. Update replay's internal state to reflect a new root slot (slot tracker,
///    status cache)
///
/// 2. Notify downstream consumers of the slot update. (i.e. RPC, via
///    CommitmentTracker, ledger, and event sink)
///
/// 3. When the "state root" advances (could be either the consensus root, or
///    the supermajority-finalized slot when RPC is enabled), prunes stale data
///    from the slot tracker, progress map, epoch tracker, and account store via
///    `pruneStaleData`.
pub fn handleSlotUpdate(
    allocator: Allocator,
    replay_state: *ReplayState,
    slot_update: SlotUpdate,
    commitment_txn: ?*CommitmentStakes.Transaction,
    metrics: Metrics,
) !void {
    const old_state_root = replay_state.slot_tracker.state_root.load(.monotonic);
    var old_processed: ?Slot = null;
    var old_confirmed: ?Slot = null;
    var old_finalized: Slot = 0;
    if (replay_state.commitments) |*c| {
        old_processed = c.get(.processed);
        old_confirmed = c.get(.confirmed);
        old_finalized = c.get(.finalized);
    }

    // update commitment levels
    if (replay_state.commitments) |*c| c.commit(slot_update, commitment_txn.?);

    if (slot_update.root) |new_root| {
        // update replay's internal state to reflect the newly rooted slot
        replay_state.slot_tracker.consensus_root.store(new_root, .monotonic);
        try replay_state.status_cache.addRoot(allocator, new_root);

        // Pass along consensus updates to downstream consumers. None of this fed back into replay.
        const rooted_slots = try replay_state.slot_tracker.parents(allocator, new_root);
        defer allocator.free(rooted_slots);
        try replay_state.ledger.resultWriter().setRoots(rooted_slots);
    }

    var newly_rooted_slots: ?[]const Slot = null;
    defer if (newly_rooted_slots) |slots| allocator.free(slots);

    // determine what slot to use as the state root. either the tower's root or
    // the finalized slot, whatever is older.
    var maybe_new_state_root: ?Slot = null;
    if (replay_state.commitments) |*c| {
        const finalized_slot = c.get(.finalized);
        const proposed_state_root = @min(
            finalized_slot,
            replay_state.slot_tracker.consensus_root.load(.monotonic),
        );

        if (finalized_slot > old_finalized) {
            newly_rooted_slots = try replay_state.slot_tracker.rootedPathForward(
                allocator,
                old_finalized,
                finalized_slot,
            );
        }

        if (proposed_state_root > old_state_root) {
            maybe_new_state_root = proposed_state_root;
        }
    } else {
        maybe_new_state_root = slot_update.root;
    }

    if (maybe_new_state_root) |new_state_root| {
        // clean up old data from replay's internal state
        try pruneStaleData(
            allocator,
            &replay_state.slot_tracker,
            &replay_state.progress_map,
            replay_state.epoch_tracker,
            replay_state.account_store,
            &replay_state.thread_pool,
            new_state_root,
        );
    }

    if (replay_state.event_sink) |sink| {
        if (slot_update.voted) |voted_slot| {
            if (old_processed == null or voted_slot != old_processed.?) {
                try sink.send(.{ .tip_changed = voted_slot });
            }
        }
        if (old_confirmed) |previous_confirmed| {
            if (slot_update.optimistically_confirmed) |confirmed_slot| {
                if (confirmed_slot > previous_confirmed) {
                    try sink.send(.{ .slot_confirmed = confirmed_slot });
                }
            }
        }
        if (newly_rooted_slots) |rooted_slots| {
            for (rooted_slots) |rooted_slot| {
                try sink.send(.{ .slot_rooted = rooted_slot });
            }
        }
    }

    // Record update in logs + metrics
    replay_state.logger.info().logf("slot state update from consensus: {any}", .{slot_update});
    if (slot_update.voted != null) metrics.voted_slot_update_count.inc();
    if (slot_update.optimistically_confirmed != null) metrics.optimistically_confirmed_update_count.inc();
    if (slot_update.root != null) metrics.root_update_count.inc();
    if (maybe_new_state_root != null) metrics.state_root_update_count.inc();
}

/// Removes all slot-scoped data for slots that do not branch off the specified root.
pub fn pruneStaleData(
    allocator: std.mem.Allocator,
    slot_tracker: *SlotTracker,
    progress: *ProgressMap,
    epoch_tracker: *sig.core.EpochTracker,
    account_store: AccountStore,
    maybe_thread_pool: ?*ThreadPool,
    /// We'll only keep around data that's a descendant of this slot. This can
    /// be the tower's root, or it can be an ancestor of the tower's root, if
    /// we'd like to keep around some older state. For example, if we're running
    /// rpc, it should be the supermajority root, so rpc can access data about
    /// slots older than the tower's root.
    state_root: Slot,
) !void {
    {
        const consensus_root_info = slot_tracker
            .get(slot_tracker.consensus_root.load(.monotonic)) orelse return error.MissingRoot;
        defer consensus_root_info.release();

        if (!consensus_root_info.constants().ancestors.containsSlot(state_root)) {
            return error.StateRootIsNotAncestorOfConsensusRoot;
        }
    }

    const state_root_info = slot_tracker.get(state_root) orelse return error.MissingRoot;
    defer state_root_info.release();

    // clean up the unrooted slot stores
    slot_tracker.prune(maybe_thread_pool, state_root);
    try epoch_tracker.updateRoot(allocator, state_root, &state_root_info.constants().ancestors);
    try account_store.updateRoot(state_root, &state_root_info.constants().ancestors);

    // Remove entries from the progress map no longer in the slot tracker.
    var progress_keys = progress.map.keys();
    var index: usize = 0;
    while (index < progress_keys.len) {
        const progress_slot = progress_keys[index];
        const maybe_ref = slot_tracker.get(progress_slot);
        if (maybe_ref) |ref| ref.release();
        if (maybe_ref == null) {
            const removed_value = progress.map.fetchSwapRemove(progress_slot) orelse continue;
            defer removed_value.value.deinit(allocator);
            progress_keys = progress.map.keys();
        } else {
            index += 1;
        }
    }
}

/// publishes logs and metrics to reflect a snapshot of the current slots being tracked by replay
pub fn recordSlotMetrics(replay_state: *ReplayState, metrics: Metrics) void {
    // Record current state as gauges
    const current_consensus_root = replay_state.slot_tracker.consensus_root.load(.monotonic);
    const current_state_root = replay_state.slot_tracker.state_root.load(.monotonic);
    const current_slot_tracker_count = replay_state.slot_tracker.count();
    const current_epoch_tracker_state_root = replay_state.epoch_tracker.state_root.load(.monotonic);

    metrics.consensus_root.set(current_consensus_root);
    metrics.state_root.set(current_state_root);
    metrics.slot_tracker_count.set(current_slot_tracker_count);
    metrics.epoch_tracker_state_root.set(current_epoch_tracker_state_root);

    // Log the same state for debugging
    replay_state.logger.debug().logf(
        \\slot_tracker.consensus_root = {}
        \\slot_tracker.state_root = {}
        \\slot_tracker.count = {}
        \\epoch_tracker.state_root = {}
    ,
        .{
            current_consensus_root,
            current_state_root,
            current_slot_tracker_count,
            current_epoch_tracker_state_root,
        },
    );

    // Apply the same pattern (log + metrics) to commitment levels if they are being recorded
    if (replay_state.commitments) |commitments| {
        const processed = commitments.get(.processed);
        const confirmed = commitments.get(.confirmed);
        const finalized = commitments.get(.finalized);

        metrics.commitment_processed.set(processed);
        metrics.commitment_confirmed.set(confirmed);
        metrics.commitment_finalized.set(finalized);

        replay_state.logger.info()
            .field("processed", processed)
            .field("confirmed", confirmed)
            .field("finalized", finalized)
            .field("behind", confirmed -| processed)
            .log("Commitments");
    }
}

test "pruneStaleData - missing root in tracker" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    // Empty slot tracker: root is set to 0 but no entry exists for it.
    var slot_tracker: SlotTracker = try .initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    var progress: ProgressMap = .INIT;
    defer progress.deinit(allocator);

    var epoch_tracker = try sig.core.EpochTracker.initForTest(allocator, random, 0, .INIT);
    defer epoch_tracker.deinit();

    const result = pruneStaleData(
        allocator,
        &slot_tracker,
        &progress,
        &epoch_tracker,
        .noop,
        null,
        0,
    );

    try std.testing.expectError(error.MissingRoot, result);
}

test "pruneStaleData - state root not in root ancestors" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var slot_tracker: SlotTracker = try .initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    try putTestSlot(allocator, random, &slot_tracker, 0, 0, &.{});

    var progress: ProgressMap = .INIT;
    defer progress.deinit(allocator);

    var epoch_tracker = try sig.core.EpochTracker.initForTest(allocator, random, 0, .INIT);
    defer epoch_tracker.deinit();

    // Root is 0 (ancestors = {0}), but state_root 123 is not in those ancestors.
    const result = pruneStaleData(
        allocator,
        &slot_tracker,
        &progress,
        &epoch_tracker,
        .noop,
        null,
        123,
    );

    try std.testing.expectError(error.StateRootIsNotAncestorOfConsensusRoot, result);
}

test "pruneStaleData - prunes non-descendant slots and stale progress" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const ForkProgress = sig.consensus.progress_map.ForkProgress;

    // Fork structure (slots tracked: 0, 2, 3, 4):
    //
    //   0 -> 1 -> 2 -> 3 (root)
    //        |-> 4    (fork)
    //
    // After pruneStaleData(state_root=3), only slot 3 should remain because
    // it is the only slot whose ancestors include 3.

    var slot_tracker: SlotTracker = try .initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    try putTestSlot(allocator, random, &slot_tracker, 0, 0, &.{});
    try putTestSlot(allocator, random, &slot_tracker, 2, 1, &.{ 1, 2 });
    try putTestSlot(allocator, random, &slot_tracker, 3, 2, &.{ 1, 2, 3 });
    try putTestSlot(allocator, random, &slot_tracker, 4, 1, &.{ 1, 4 });
    slot_tracker.consensus_root.store(3, .monotonic);

    // Progress map with entries for slots 0, 1, 2, 3 (slot 1 is only in
    // progress, never in the tracker — it should also get cleaned up).
    var progress: ProgressMap = .INIT;
    defer progress.deinit(allocator);
    try progress.map.put(allocator, 0, try ForkProgress.zeroes(allocator));
    try progress.map.put(allocator, 1, try ForkProgress.zeroes(allocator));
    try progress.map.put(allocator, 2, try ForkProgress.zeroes(allocator));
    try progress.map.put(allocator, 3, try ForkProgress.zeroes(allocator));

    var epoch_tracker = try sig.core.EpochTracker.initForTest(allocator, random, 0, .INIT);
    defer epoch_tracker.deinit();

    // Pre-conditions
    try std.testing.expectEqual(4, progress.map.count());
    try std.testing.expect(slot_tracker.contains(0));
    try std.testing.expect(slot_tracker.contains(2));
    try std.testing.expect(slot_tracker.contains(3));
    try std.testing.expect(slot_tracker.contains(4));

    try pruneStaleData(
        allocator,
        &slot_tracker,
        &progress,
        &epoch_tracker,
        .noop,
        null,
        3,
    );

    // Only slot 3 remains in tracker (the others' ancestors don't include 3)
    try std.testing.expect(!slot_tracker.contains(0));
    try std.testing.expect(!slot_tracker.contains(2));
    try std.testing.expect(slot_tracker.contains(3));
    try std.testing.expect(!slot_tracker.contains(4));

    // Progress entries for slots no longer in the tracker are removed
    try std.testing.expectEqual(1, progress.map.count());
    try std.testing.expect(progress.map.contains(3));
    try std.testing.expect(!progress.map.contains(0));
    try std.testing.expect(!progress.map.contains(1));
    try std.testing.expect(!progress.map.contains(2));

    // Epoch tracker state root is updated
    try std.testing.expectEqual(3, epoch_tracker.state_root.load(.monotonic));
}

test "pruneStaleData - state root older than root keeps more slots" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    // When state_root is an ancestor of root (e.g. the supermajority-finalized
    // slot for RPC), descendant slots of state_root are kept even if they are
    // ancestors of root.
    //
    // Fork structure (slots tracked: 0, 2, 3, 4):
    //
    //   0 -> 1 -> 2 -> 3 (root)
    //        |-> 4    (fork)
    //
    // state_root = 1, root = 3
    //  - slot 0 ancestors = {0}        -> no 1 -> pruned
    //  - slot 2 ancestors = {0, 1, 2}  -> has 1 -> kept
    //  - slot 3 ancestors = {0,1,2,3}  -> has 1 -> kept
    //  - slot 4 ancestors = {0, 1, 4}  -> has 1 -> kept

    var slot_tracker: SlotTracker = try .initEmpty(allocator, 0);
    defer slot_tracker.deinit(allocator);

    try putTestSlot(allocator, random, &slot_tracker, 0, 0, &.{0});
    try putTestSlot(allocator, random, &slot_tracker, 1, 0, &.{ 0, 1 });
    try putTestSlot(allocator, random, &slot_tracker, 2, 1, &.{ 1, 2 });
    try putTestSlot(allocator, random, &slot_tracker, 3, 2, &.{ 1, 2, 3 });
    try putTestSlot(allocator, random, &slot_tracker, 4, 1, &.{ 1, 4 });
    try putTestSlot(allocator, random, &slot_tracker, 5, 2, &.{ 1, 2, 5 });
    slot_tracker.consensus_root.store(3, .monotonic);

    var progress: ProgressMap = .INIT;
    defer progress.deinit(allocator);

    var epoch_tracker = try sig.core.EpochTracker.initForTest(allocator, random, 0, .INIT);
    defer epoch_tracker.deinit();

    try pruneStaleData(
        allocator,
        &slot_tracker,
        &progress,
        &epoch_tracker,
        .noop,
        null,
        2, // state_root is older than root — keep descendants of slot 2
    );

    // Slots 0 and 4 are pruned (ancestors don't include 2)
    try std.testing.expect(!slot_tracker.contains(0));
    try std.testing.expect(!slot_tracker.contains(1));
    try std.testing.expect(!slot_tracker.contains(4));
    // Slots 2, 3 and 5 are all descendants of slot 2, so they survive
    try std.testing.expect(slot_tracker.contains(2));
    try std.testing.expect(slot_tracker.contains(3));
    try std.testing.expect(slot_tracker.contains(5));

    try std.testing.expectEqual(2, epoch_tracker.state_root.load(.monotonic));
}

fn putTestSlot(
    allocator: Allocator,
    random: std.Random,
    slot_tracker: *SlotTracker,
    slot: Slot,
    parent_slot: Slot,
    ancestors: []const Slot,
) !void {
    var constants = try SlotConstants.genesis(allocator, .initRandom(random));
    errdefer constants.deinit(allocator);

    constants.parent_slot = parent_slot;
    for (ancestors) |ancestor| try constants.ancestors.addSlot(allocator, ancestor);

    try slot_tracker.put(allocator, slot, .{
        .allocator = allocator,
        .constants = constants,
        .state = .GENESIS,
    });
}

test "getActiveFeatures rejects wrong ownership" {
    const allocator = std.testing.allocator;
    var accounts = sig.utils.collections.PubkeyMap(sig.core.Account).empty;
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

    const features = try getActiveFeatures(allocator, .{ .account_map = &accounts }, 0);
    try std.testing.expect(!features.active(.system_transfer_zero_check, 1));

    acct.owner = sig.runtime.ids.FEATURE_PROGRAM_ID;
    try accounts.put(
        allocator,
        sig.core.features.map.get(.system_transfer_zero_check).key,
        acct,
    );

    const features2 = try getActiveFeatures(allocator, .{ .account_map = &accounts }, 0);
    try std.testing.expect(features2.active(.system_transfer_zero_check, 1));
}

test trackNewSlots {
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer ledger.deinit();
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
        try ledger.db.put(sig.ledger.schema.schema.slot_meta, slot, meta);
    }

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var state: SlotState = .GENESIS;
    state.stakes_cache.stakes.private.v = try sig.core.stakes.randomStakes(
        allocator,
        prng.random(),
        .{ .epoch = 0 },
    );
    var slot_tracker: SlotTracker = try .init(allocator, 0, .{
        .state = state,
        .constants = try .genesis(allocator, .DEFAULT),
        .allocator = allocator,
    });
    defer slot_tracker.deinit(allocator);
    {
        const ref = slot_tracker.get(0).?;
        defer ref.release();
        ref.state().hash.set(.ZEROES);
    }

    var leader_schedule = sig.core.leader_schedule.LeaderSchedule{
        .start = 0,
        .end = 6,
        .leaders = &.{
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
            Pubkey.initRandom(rng.random()),
        },
    };

    var epoch_tracker = try sig.core.EpochTracker.initForTest(
        allocator,
        rng.random(),
        0,
        .INIT,
    );
    defer epoch_tracker.deinit();

    const slot_leaders = SlotLeaders.init(
        &leader_schedule,
        sig.core.leader_schedule.LeaderSchedule.getLeaderOrNull,
    );

    // slot tracker should start with only 0
    try expectSlotTracker(&slot_tracker, leader_schedule, &.{.{ 0, 0 }}, &.{ 1, 2, 3, 4, 5, 6 });

    const hard_forks = sig.core.HardForks{};

    var slot_tree = try SlotTree.init(allocator, 0);
    defer slot_tree.deinit(allocator);

    // only the root (0) is considered frozen, so only 0 and 1 should be added at first.
    try trackNewSlots(
        allocator,
        .FOR_TESTS,
        .noop,
        &ledger,
        &slot_tracker,
        &epoch_tracker,
        &slot_tree,
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
        .FOR_TESTS,
        .noop,
        &ledger,
        &slot_tracker,
        &epoch_tracker,
        &slot_tree,
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
    {
        const ref = slot_tracker.get(1).?;
        defer ref.release();
        ref.state().hash.set(.ZEROES);
    }

    try trackNewSlots(
        allocator,
        .FOR_TESTS,
        .noop,
        &ledger,
        &slot_tracker,
        &epoch_tracker,
        &slot_tree,
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
    {
        const ref2 = slot_tracker.get(2).?;
        defer ref2.release();
        ref2.state().hash.set(.ZEROES);
    }
    {
        const ref4 = slot_tracker.get(4).?;
        defer ref4.release();
        ref4.state().hash.set(.ZEROES);
    }

    try trackNewSlots(
        allocator,
        .FOR_TESTS,
        .noop,
        &ledger,
        &slot_tracker,
        &epoch_tracker,
        &slot_tree,
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
        defer slot_info.release();
        try std.testing.expectEqual(parent, slot_info.constants().parent_slot);
        if (slot != 0) try std.testing.expectEqual(
            leader_schedule.leaders[slot],
            slot_info.constants().collector_id,
        );
    }
    for (excluded_slots) |slot| {
        const maybe_ref = slot_tracker.get(slot);
        if (maybe_ref) |ref| ref.release();
        try std.testing.expectEqual(null, maybe_ref);
    }
}

test "Service clean init and deinit" {
    const ns = struct {
        pub fn run(allocator: Allocator) !void {
            var dep_stubs = try DependencyStubs.init(allocator, .noop);
            defer dep_stubs.deinit();

            var service = try dep_stubs.stubbedState(allocator, .FOR_TESTS, .disabled);
            defer {
                service.deinit();
                service.epoch_tracker.deinit();
                allocator.destroy(service.epoch_tracker);
            }
        }
    };
    try ns.run(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ns.run, .{});
}

test "Service clean init and deinit with RPC enabled" {
    const allocator = std.testing.allocator;

    var dep_stubs = try DependencyStubs.init(allocator, .noop);
    defer dep_stubs.deinit();

    var service = try dep_stubs.stubbedState(allocator, .FOR_TESTS, .enabled);
    defer {
        service.deinit();
        service.epoch_tracker.deinit();
        allocator.destroy(service.epoch_tracker);
    }

    // commitments should be initialised when rpc_status is .enabled.
    try std.testing.expect(service.commitments != null);
}

test "process runs without error with no replay results" {
    const allocator = std.testing.allocator;

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var dep_stubs = try DependencyStubs.init(allocator, .FOR_TESTS);
    defer dep_stubs.deinit();

    var replay_state = try dep_stubs.stubbedState(allocator, .FOR_TESTS, .disabled);
    defer {
        replay_state.deinit();
        replay_state.epoch_tracker.deinit();
        allocator.destroy(replay_state.epoch_tracker);
    }

    var consensus: TowerConsensus = try .init(allocator, .{
        .logger = .FOR_TESTS,
        .identity = replay_state.identity,
        .signing = replay_state.signing,
        .account_reader = replay_state.account_store.reader(),
        .ledger = replay_state.ledger,
        .slot_tracker = &replay_state.slot_tracker,
        .registry = &registry,
        .now = .EPOCH_ZERO,
    });
    defer consensus.deinit(allocator);

    const vc_senders: sig.consensus.vote_listener.Senders = try .createForTest(allocator, .{
        .bank_notification = false,
    });
    defer vc_senders.destroyForTest(allocator);

    const consensus_senders: TowerConsensus.Senders = try .create(allocator);
    defer consensus_senders.destroy();

    const replay_votes_channel: *Channel(ParsedVote) = try .create(allocator);
    defer replay_votes_channel.destroy();
    defer while (replay_votes_channel.tryReceive()) |pv| pv.deinit(allocator);

    const consensus_receivers: TowerConsensus.Receivers =
        try .create(allocator, replay_votes_channel);
    defer consensus_receivers.destroy();

    // TODO: run consensus in the tests that actually execute blocks for better
    // coverage. currently consensus panics or hangs if you run it with actual data
    _ = try consensus.process(allocator, .{
        .account_store = dep_stubs.accountStore(),
        .ledger = &dep_stubs.ledger,
        .gossip_votes = null,
        .gossip_table = null,
        .slot_tracker = &replay_state.slot_tracker,
        .epoch_tracker = replay_state.epoch_tracker,
        .progress_map = &replay_state.progress_map,
        .senders = consensus_senders,
        .receivers = consensus_receivers,
        .vote_sockets = null,
        .slot_leaders = null,
        .duplicate_confirmed_slots = vc_senders.duplicate_confirmed_slots,
        .gossip_verified_vote_hashes = vc_senders.gossip_verified_vote_hashes,
        .results = &.{},
    });
}

test "advance calls consensus.process with empty replay results" {
    const allocator = std.testing.allocator;

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var dep_stubs = try DependencyStubs.init(allocator, .FOR_TESTS);
    defer dep_stubs.deinit();

    var replay_state = try dep_stubs.stubbedState(allocator, .FOR_TESTS, .disabled);
    defer {
        replay_state.deinit();
        replay_state.epoch_tracker.deinit();
        allocator.destroy(replay_state.epoch_tracker);
    }

    try advanceReplay(&replay_state, try registry.initStruct(Metrics), null);

    // No slots were replayed
    try std.testing.expectEqual(0, replay_state.slot_tracker.consensus_root.load(.monotonic));
}

test "advance with RPC enabled passes block commitment cache" {
    const allocator = std.testing.allocator;

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var dep_stubs = try DependencyStubs.init(allocator, .FOR_TESTS);
    defer dep_stubs.deinit();

    var replay_state = try dep_stubs.stubbedState(allocator, .FOR_TESTS, .enabled);
    defer {
        replay_state.deinit();
        replay_state.epoch_tracker.deinit();
        allocator.destroy(replay_state.epoch_tracker);
    }

    // commitments should be initialised.
    try std.testing.expect(replay_state.commitments != null);

    try advanceReplay(&replay_state, try registry.initStruct(Metrics), null);

    // No slots were replayed
    try std.testing.expectEqual(0, replay_state.slot_tracker.consensus_root.load(.monotonic));
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

fn addReplayStateSlotForTest(
    replay_state: *ReplayState,
    slot: Slot,
    parent_slot: Slot,
    leader: Pubkey,
    frozen_hash: ?Hash,
) !void {
    const parent_ref = replay_state.slot_tracker.get(parent_slot) orelse
        return error.MissingParentSlot;
    defer parent_ref.release();

    const constants, var state = try newSlotFromParent(
        replay_state.allocator,
        replay_state.account_store.reader(),
        1,
        parent_slot,
        parent_ref.constants(),
        parent_ref.state(),
        leader,
        slot,
    );
    errdefer constants.deinit(replay_state.allocator);
    errdefer state.deinit(replay_state.allocator);

    if (frozen_hash) |slot_hash| {
        state.hash.set(slot_hash);
    }

    try replay_state.slot_tracker.put(replay_state.allocator, slot, .{
        .allocator = replay_state.allocator,
        .constants = constants,
        .state = state,
    });
    try replay_state.slot_tree.record(replay_state.allocator, slot, parent_slot);
}

test "handleSlotUpdate emits rooted events from finalized commitment, not consensus root" {
    const allocator = std.testing.allocator;

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var dep_stubs = try DependencyStubs.init(allocator, .FOR_TESTS);
    defer dep_stubs.deinit();

    var replay_state = try dep_stubs.stubbedState(allocator, .FOR_TESTS, .enabled);
    defer {
        replay_state.deinit();
        replay_state.epoch_tracker.deinit();
        allocator.destroy(replay_state.epoch_tracker);
    }

    const event_sink = try jrpc_types.EventSink.create(allocator);
    defer event_sink.destroy();
    replay_state.event_sink = event_sink;

    try addReplayStateSlotForTest(&replay_state, 1, 0, Pubkey.ZEROES, Hash.ZEROES);
    try addReplayStateSlotForTest(&replay_state, 2, 1, Pubkey.ZEROES, Hash.ZEROES);

    replay_state.commitments.?.update(.finalized, 1);
    const metrics = try registry.initStruct(Metrics);

    {
        const commitment_txn = replay_state.commitments.?.stakes.beginTransaction(&.{});
        defer commitment_txn.reset();

        try handleSlotUpdate(
            allocator,
            &replay_state,
            .{
                .root = 2,
                .voted = null,
                .optimistically_confirmed = null,
            },
            commitment_txn,
            metrics,
        );
    }

    try std.testing.expect(event_sink.channel.tryReceive() == null);

    {
        const commitment_txn = replay_state.commitments.?.stakes.beginTransaction(&.{});
        defer commitment_txn.reset();
        commitment_txn.total_stake = 100;
        try commitment_txn.rooted_stake.append(allocator, .{ .slot = 2, .stake = 100 });

        try handleSlotUpdate(
            allocator,
            &replay_state,
            .{
                .root = null,
                .voted = null,
                .optimistically_confirmed = null,
            },
            commitment_txn,
            metrics,
        );
    }

    const event = event_sink.channel.tryReceive() orelse return error.TestUnexpectedResult;
    defer event.deinit(event_sink.channel.allocator);
    switch (event) {
        .slot_rooted => |rooted_slot| {
            try std.testing.expectEqual(2, rooted_slot);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(event_sink.channel.tryReceive() == null);
}

test "handleSlotUpdate emits tip_changed when voted slot decreases" {
    const allocator = std.testing.allocator;

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var dep_stubs = try DependencyStubs.init(allocator, .FOR_TESTS);
    defer dep_stubs.deinit();

    var replay_state = try dep_stubs.stubbedState(allocator, .FOR_TESTS, .enabled);
    defer {
        replay_state.deinit();
        replay_state.epoch_tracker.deinit();
        allocator.destroy(replay_state.epoch_tracker);
    }

    const event_sink = try jrpc_types.EventSink.create(allocator);
    defer event_sink.destroy();
    replay_state.event_sink = event_sink;

    replay_state.commitments.?.update(.processed, 5);

    const commitment_txn = replay_state.commitments.?.stakes.beginTransaction(&.{});
    defer commitment_txn.reset();

    try handleSlotUpdate(
        allocator,
        &replay_state,
        .{
            .root = null,
            .voted = 4,
            .optimistically_confirmed = null,
        },
        commitment_txn,
        try registry.initStruct(Metrics),
    );

    const event = event_sink.channel.tryReceive() orelse return error.TestUnexpectedResult;
    defer event.deinit(event_sink.channel.allocator);
    switch (event) {
        .tip_changed => |tip_slot| {
            try std.testing.expectEqual(4, tip_slot);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(event_sink.channel.tryReceive() == null);
}

test "freezeCompletedSlots handles errors correctly" {
    const allocator = std.testing.allocator;

    var logger = sig.trace.log.TestLogger.init(allocator);
    defer logger.deinit();

    var dep_stubs = try DependencyStubs.init(allocator, .from(logger.logger("", .warn)));
    defer dep_stubs.deinit();

    var replay_state = try dep_stubs.stubbedState(
        allocator,
        .from(logger.logger("", .warn)),
        .disabled,
    );
    defer {
        replay_state.deinit();
        replay_state.epoch_tracker.deinit();
        allocator.destroy(replay_state.epoch_tracker);
    }

    const processed_a_slot = try freezeCompletedSlots(&replay_state, &.{
        .{ .slot = 1, .output = .{ .err = .{ .invalid_block = .TooFewTicks } } },
        .{ .slot = 2, .output = .{ .err = .failed_to_load_meta } },
    });

    try std.testing.expectEqual(sig.trace.Level.warn, logger.messages.items[0].level);
    try std.testing.expectEqualSlices(u8,
        \\replayed slot 1 with error: .{ .invalid_block = .TooFewTicks }
    , logger.messages.items[0].content);
    try std.testing.expectEqual(sig.trace.Level.@"error", logger.messages.items[1].level);
    try std.testing.expectEqualSlices(u8,
        \\replayed slot 2 with error: .{ .failed_to_load_meta = void }
    , logger.messages.items[1].content);

    try std.testing.expectEqual(false, processed_a_slot);
}

test "freezeCompletedSlots emits slot_frozen event with slot metadata" {
    const allocator = std.testing.allocator;

    var dep_stubs = try DependencyStubs.init(allocator, .FOR_TESTS);
    defer dep_stubs.deinit();

    var replay_state = try dep_stubs.stubbedState(allocator, .FOR_TESTS, .enabled);
    defer {
        replay_state.deinit();
        replay_state.epoch_tracker.deinit();
        allocator.destroy(replay_state.epoch_tracker);
    }

    const event_sink = try jrpc_types.EventSink.create(allocator);
    defer event_sink.destroy();
    replay_state.event_sink = event_sink;

    try addReplayStateSlotForTest(&replay_state, 1, 0, Pubkey.ZEROES, null);
    const slot_ref = replay_state.slot_tracker.get(1) orelse return error.MissingSlotInTracker;
    defer slot_ref.release();
    slot_ref.state().tick_height.store(slot_ref.constants().max_tick_height, .monotonic);

    const processed_a_slot = try freezeCompletedSlots(&replay_state, &.{.{
        .slot = 1,
        .output = .{ .last_entry_hash = Hash.ZEROES },
    }});

    try std.testing.expect(processed_a_slot);
    const event = event_sink.channel.tryReceive() orelse return error.TestUnexpectedResult;
    defer event.deinit(event_sink.channel.allocator);
    switch (event) {
        .slot_frozen => |slot_frozen| {
            try std.testing.expectEqual(1, slot_frozen.slot);
            try std.testing.expectEqual(0, slot_frozen.parent);
            try std.testing.expectEqual(0, slot_frozen.root);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(event_sink.channel.tryReceive() == null);
}

fn testExecuteBlock(allocator: Allocator, config: struct {
    num_threads: u32,
    manifest_path: []const u8,
    shreds_path: []const u8,
    accounts_path: []const u8,
}) !void {
    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var dep_stubs = try DependencyStubs.init(allocator, .FOR_TESTS);
    defer dep_stubs.deinit();

    // get snapshot manifest
    const fba_buf = try allocator.alloc(u8, 350_000_000);
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
    const result = try dep_stubs.ledger.shredInserter().insertShreds(
        allocator,
        shreds.items(.shred),
        shreds.items(.is_repair),
        .{},
    );
    result.deinit();

    // get data about this test from snapshot + shreds
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
        try dep_stubs.accounts_db_state.db.put(snapshot_slot, address, account);
    }

    // NOTE: The manifests used to run this unit have empty `stakes` and a single epoch stakes for
    // the current epoch. As a result, when we call `updateEpochStakes` in `trackNewSlots` we will
    // attempt to create a new `EpochInfo` for the next epoch. This involves a leader schedule
    // calculation which will fail if `stakes` is empty.
    //
    // To get around this for the existing manifests, we copy the current epoch stakes into an entry
    // for the next epoch in `bank_extra.versioned_epoch_stakes`. This is loaded into `EpochInfo`
    // in the EpochTracker when initialised from the snapshot, thus preventing `updateEpochStakes`
    // from attempting to compute an `EpochInfo` entry with empty `stakes`.
    var epoch_stakes = manifest.bank_extra.versioned_epoch_stakes.get(
        manifest.bank_fields.epoch,
    ).?.current;
    epoch_stakes.stakes.epoch += 1;
    try manifest.bank_extra.versioned_epoch_stakes.put(
        fba.allocator(),
        manifest.bank_fields.epoch + 1,
        .{ .current = try epoch_stakes.clone(fba.allocator()) },
    );

    // init replay
    var replay_state = try dep_stubs.mockedState(
        allocator,
        &manifest,
        config.num_threads,
    );
    defer {
        replay_state.deinit();
        replay_state.epoch_tracker.deinit();
        allocator.destroy(replay_state.epoch_tracker);
    }

    // replay the block
    replay_state.stop_at_slot = execution_slot;
    try std.testing.expectError(
        error.ReachedEndSlot,
        advanceReplay(&replay_state, try registry.initStruct(Metrics), null),
    );

    // get slot hash
    const actual_slot_hash = tracker_lock: {
        const ref = replay_state.slot_tracker.get(execution_slot).?;
        defer ref.release();
        break :tracker_lock ref.state().hash.readCopy().?;
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

    var read_buf: [4096]u8 = undefined;
    var file_reader = file.reader(&read_buf);
    var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor: std.compress.flate.Decompress =
        .init(&file_reader.interface, .gzip, &decompress_buf);

    var json_reader = std.json.Reader.init(allocator, &decompressor.reader);
    defer json_reader.deinit();

    return try std.json.parseFromTokenSource(T, allocator, &json_reader, .{});
}

fn parseBincodeFromGzipFile(
    comptime T: type,
    allocator: Allocator,
    path: []const u8,
) !T {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var read_buf: [4096]u8 = undefined;
    var file_reader = file.reader(&read_buf);
    var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor: std.compress.flate.Decompress =
        .init(&file_reader.interface, .gzip, &decompress_buf);

    return try sig.bincode.read(
        allocator,
        T,
        std14.deprecatedReader(&decompressor.reader),
        .{ .allocation_limit = 1 << 31 },
    );
}

/// Basic stubs for state that's supposed to be initialized outside replay,
/// outlive replay, and is used by replay.
pub const DependencyStubs = struct {
    allocator: Allocator,
    accounts_db_state: sig.accounts_db.Db.TestContext,
    ledger: Ledger,
    senders: TowerConsensus.Senders,
    receivers: TowerConsensus.Receivers,
    replay_votes_channel: *Channel(ParsedVote),

    pub fn deinit(self: *DependencyStubs) void {
        self.accounts_db_state.deinit();
        self.ledger.deinit();
        self.senders.destroy();
        self.receivers.destroy();
        while (self.replay_votes_channel.tryReceive()) |pv| pv.deinit(self.allocator);
        self.replay_votes_channel.destroy();
    }

    pub fn init(allocator: Allocator, logger: Logger) !DependencyStubs {
        var test_state = try sig.accounts_db.Db.initTest(allocator);
        errdefer test_state.deinit();

        try test_state.tmp.dir.makeDir("ledger");
        const ledger_path = try test_state.tmp.dir.realpathAlloc(allocator, "ledger/");
        defer allocator.free(ledger_path);

        var ledger = try Ledger.init(allocator, .from(logger), ledger_path, null);
        errdefer ledger.deinit();

        const senders: TowerConsensus.Senders = try .create(allocator);
        errdefer senders.destroy();

        const replay_votes_channel: *Channel(ParsedVote) = try .create(allocator);
        errdefer replay_votes_channel.destroy();

        const receivers: TowerConsensus.Receivers = try .create(allocator, replay_votes_channel);
        errdefer receivers.destroy();

        return .{
            .allocator = allocator,
            .accounts_db_state = test_state,
            .ledger = ledger,
            .senders = senders,
            .receivers = receivers,
            .replay_votes_channel = replay_votes_channel,
        };
    }

    pub fn accountStore(self: *DependencyStubs) AccountStore {
        return .{ .accounts_db = &self.accounts_db_state.db };
    }

    pub fn accountReader(self: *DependencyStubs) AccountReader {
        return .{ .accounts_db = &self.accounts_db_state.db };
    }

    /// Initialize replay service with stubbed inputs.
    /// (some inputs from this struct, some just stubbed directly)
    ///
    /// these inputs are "stubbed" with potentially garbage/meaningless data,
    /// rather than being "mocked" with meaningful data.
    pub fn stubbedState(
        self: *DependencyStubs,
        allocator: Allocator,
        logger: Logger,
        rpc_status: RPCStatus,
    ) !ReplayState {
        const root_slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer root_slot_constants.deinit(allocator);

        var root_slot_state: SlotState = .GENESIS;
        errdefer root_slot_state.deinit(allocator);

        { // this is to essentially root the slot
            root_slot_state.hash.set(.ZEROES);
            var bhq = root_slot_state.blockhash_queue.write();
            defer bhq.unlock();
            try bhq.mut().insertGenesisHash(allocator, .ZEROES, 0);
        }

        var prng_state = std.Random.DefaultPrng.init(24659);
        const prng = prng_state.random();

        var epoch_tracker = try allocator.create(sig.core.EpochTracker);
        errdefer allocator.destroy(epoch_tracker);

        epoch_tracker.* = try sig.core.EpochTracker.initForTest(
            allocator,
            prng,
            0,
            .INIT,
        );
        errdefer epoch_tracker.deinit();

        return try .init(.{
            .allocator = allocator,
            .logger = logger,
            .identity = .{
                .validator = .initRandom(prng),
                .vote_account = null,
            },
            .signing = .{
                .node = null,
                .authorized_voters = &.{},
            },
            .account_store = self.accountStore(),
            .ledger = &self.ledger,
            .epoch_tracker = epoch_tracker,
            .root = .{
                .slot = 0,
                .constants = root_slot_constants,
                .state = root_slot_state,
            },
            .hard_forks = .{},

            .replay_threads = 1,
            .stop_at_slot = null,
        }, .enabled, rpc_status);
    }

    // TODO: consider deduplicating with above and similar function in cmd.zig
    /// "mocked" with meaningful data as opposed to "stubbed" with garbage data
    fn mockedState(
        self: *DependencyStubs,
        allocator: std.mem.Allocator,
        collapsed_manifest: *const sig.accounts_db.snapshot.Manifest,
        num_threads: u32,
    ) !ReplayState {
        const bank_fields = &collapsed_manifest.bank_fields;

        const feature_set = try sig.replay.service.getActiveFeatures(
            allocator,
            .{ .accounts_db = .{ &self.accounts_db_state.db, &bank_fields.ancestors } },
            bank_fields.slot,
        );

        var epoch_tracker = try allocator.create(sig.core.EpochTracker);
        errdefer allocator.destroy(epoch_tracker);

        epoch_tracker.* = try sig.core.EpochTracker.initFromManifest(
            allocator,
            collapsed_manifest,
            &feature_set,
        );
        errdefer epoch_tracker.deinit();

        const root_slot_constants = try sig.core.SlotConstants.fromBankFields(
            allocator,
            bank_fields,
            feature_set,
        );
        errdefer root_slot_constants.deinit(allocator);

        const lt_hash = collapsed_manifest.bank_extra.accounts_lt_hash;

        const account_store = sig.accounts_db.AccountStore{
            .accounts_db = &self.accounts_db_state.db,
        };
        const account_reader = account_store.reader().forSlot(&bank_fields.ancestors);
        var root_slot_state =
            try sig.core.SlotState.fromBankFields(allocator, bank_fields, lt_hash, account_reader);
        errdefer root_slot_state.deinit(allocator);

        const hard_forks = try bank_fields.hard_forks.clone(allocator);
        errdefer hard_forks.deinit(allocator);

        return try .init(.{
            .allocator = allocator,
            .logger = .FOR_TESTS,
            .identity = .{
                .validator = .ZEROES,
                .vote_account = .ZEROES,
            },
            .signing = .{
                .node = null,
                .authorized_voters = &.{},
            },
            .account_store = self.accountStore(),
            .ledger = &self.ledger,
            .epoch_tracker = epoch_tracker,
            .root = .{
                .slot = bank_fields.slot,
                .constants = root_slot_constants,
                .state = root_slot_state,
            },
            .hard_forks = hard_forks,

            .replay_threads = num_threads,
            .stop_at_slot = null,
        }, .enabled, .disabled);
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

    pub fn deinit(self: TestAccount, allocator: std.mem.Allocator) void {
        allocator.free(self.pubkey);
        allocator.free(self.owner);
        allocator.free(self.data);
    }

    pub fn toAccount(self: TestAccount) !struct { Slot, Pubkey, sig.runtime.AccountSharedData } {
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
