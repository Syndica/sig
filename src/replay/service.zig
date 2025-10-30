const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;

const Channel = sig.sync.Channel;
const ThreadPool = sig.sync.ThreadPool;

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SlotLeaders = sig.core.leader_schedule.SlotLeaders;
const SlotState = sig.core.bank.SlotState;

const AccountStore = sig.accounts_db.AccountStore;
const AccountReader = sig.accounts_db.AccountReader;

const Ledger = sig.ledger.Ledger;

const ProgressMap = sig.consensus.ProgressMap;
const TowerConsensus = replay.consensus.TowerConsensus;
const ParsedVote = sig.consensus.vote_listener.vote_parser.ParsedVote;

const ReplayResult = replay.execution.ReplayResult;

const EpochTracker = replay.trackers.EpochTracker;
const SlotTracker = replay.trackers.SlotTracker;
const SlotTree = replay.trackers.SlotTree;

const GossipVerifiedVoteHash = sig.consensus.vote_listener.GossipVerifiedVoteHash;
const ThresholdConfirmedSlot = sig.consensus.vote_listener.ThresholdConfirmedSlot;

const updateSysvarsForNewSlot = replay.update_sysvar.updateSysvarsForNewSlot;

pub const Logger = sig.trace.Logger("replay");

pub const Metrics = struct {
    slot_execution_time: *sig.prometheus.Histogram,

    pub const prefix = "replay";
    pub const histogram_buckets = b: {
        const base = 100 * std.time.ns_per_ms;
        var buckets: [20]f64 = undefined;
        for (&buckets, 0..) |*bucket, i| bucket.* = i * base;
        break :b buckets;
    };
};

pub const AvanceReplayConsensusParams = struct {
    tower: *TowerConsensus,
    gossip_votes: ?*sig.sync.Channel(sig.gossip.data.Vote),
    senders: TowerConsensus.Senders,
    receivers: TowerConsensus.Receivers,
    vote_sockets: ?*const sig.replay.consensus.core.VoteSockets,
};

/// Run a single iteration of the entire replay process. Includes:
/// - replay all active slots that have not been replayed yet
/// - running consensus on the latest updates (if present)
pub fn advanceReplay(
    replay_state: *ReplayState,
    metrics: Metrics,
    consensus_params: ?AvanceReplayConsensusParams,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "advanceReplay" });
    defer zone.deinit();

    const allocator = replay_state.allocator;

    var start_time = sig.time.Timer.start();
    replay_state.logger.debug().log("advancing replay");

    // find slots in the ledger
    try trackNewSlots(
        allocator,
        replay_state.logger,
        replay_state.account_store,
        replay_state.ledger,
        &replay_state.slot_tracker,
        &replay_state.epoch_tracker,
        &replay_state.slot_tree,
        replay_state.slot_leaders,
        &replay_state.hard_forks,
        &replay_state.progress_map,
    );

    // replay slots
    const slot_results = try replay.execution.replayActiveSlots(replay_state);
    defer allocator.free(slot_results);

    // freeze slots
    const processed_a_slot: bool = try freezeCompletedSlots(replay_state, slot_results);

    // run consensus
    if (consensus_params) |consensus| {
        var gossip_verified_vote_hashes: std.ArrayListUnmanaged(GossipVerifiedVoteHash) = .empty;
        defer gossip_verified_vote_hashes.deinit(allocator);

        var duplicate_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
        defer duplicate_confirmed_slots.deinit(allocator);

        try consensus.tower.process(allocator, .{
            .account_store = replay_state.account_store,
            .gossip_votes = consensus.gossip_votes,
            .ledger = replay_state.ledger,
            .slot_tracker = &replay_state.slot_tracker,
            .epoch_tracker = &replay_state.epoch_tracker,
            .progress_map = &replay_state.progress_map,
            .status_cache = &replay_state.status_cache,
            .senders = consensus.senders,
            .receivers = consensus.receivers,
            .vote_sockets = consensus.vote_sockets,
            .slot_leaders = replay_state.slot_leaders,
            .duplicate_confirmed_slots = &duplicate_confirmed_slots,
            .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
            .results = slot_results,
        });
    } else try bypassConsensus(replay_state);

    if (slot_results.len != 0) {
        const elapsed = start_time.read().asNanos();
        metrics.slot_execution_time.observe(elapsed);
        replay_state.logger.info().logf("advanced in {}", .{std.fmt.fmtDuration(elapsed)});
    }

    if (replay_state.stop_at_slot) |stop_slot| {
        for (slot_results) |result| if (result.slot >= stop_slot) {
            replay_state.logger.info().logf("Reached end slot {}, exiting replay", .{stop_slot});
            return error.ReachedEndSlot;
        };
    }

    if (!processed_a_slot) try std.Thread.yield();
}

pub const Dependencies = struct {
    /// Used for all allocations within the replay stage
    allocator: Allocator,
    logger: Logger,
    identity: sig.identity.ValidatorIdentity,
    signing: sig.identity.SigningKeys,
    /// Used in the EpochManager
    epoch_schedule: sig.core.EpochSchedule,
    account_store: sig.accounts_db.AccountStore,
    /// Reader used to get the entries to validate them and execute the transactions
    /// Writer used to update the ledger with consensus results
    ledger: *Ledger,
    /// Used to get the entries to validate them and execute the transactions
    slot_leaders: SlotLeaders,
    /// The slot info to start replaying from.
    root: struct {
        slot: Slot,
        /// ownership transferred to replay; won't be freed if `ReplayState.init` returns an error.
        constants: sig.core.SlotConstants,
        /// ownership transferred to replay; won't be freed if `ReplayState.init` returns an error.
        state: sig.core.SlotState,
    },
    current_epoch: sig.core.Epoch,
    /// ownership transferred to replay; won't be freed if `ReplayState.init` returns an error.
    current_epoch_constants: sig.core.EpochConstants,
    /// ownership transferred to replay; won't be freed if `ReplayState.init` returns an error.
    hard_forks: sig.core.HardForks,

    replay_threads: u32,
    stop_at_slot: ?Slot,
};

pub const ConsensusStatus = enum {
    enabled,
    disabled,
};

pub const ReplayState = struct {
    allocator: Allocator,
    logger: Logger,
    identity: sig.identity.ValidatorIdentity,
    signing: sig.identity.SigningKeys,
    thread_pool: ThreadPool,
    slot_leaders: SlotLeaders,
    slot_tracker: SlotTracker,
    epoch_tracker: EpochTracker,
    slot_tree: SlotTree,
    hard_forks: sig.core.HardForks,
    account_store: AccountStore,
    progress_map: ProgressMap,
    ledger: *Ledger,
    status_cache: sig.core.StatusCache,
    execution_log_helper: replay.execution.LogHelper,
    replay_votes_channel: ?*Channel(ParsedVote),
    stop_at_slot: ?sig.core.Slot,

    pub fn deinit(self: *ReplayState) void {
        self.thread_pool.shutdown();
        self.thread_pool.deinit();

        self.slot_tracker.deinit(self.allocator);
        self.epoch_tracker.deinit(self.allocator);
        self.progress_map.deinit(self.allocator);

        if (self.replay_votes_channel) |channel| {
            while (channel.tryReceive()) |item| item.deinit(self.allocator);
            channel.destroy();
        }

        self.slot_tree.deinit(self.allocator);
        self.status_cache.deinit(self.allocator);
        self.hard_forks.deinit(self.allocator);
    }

    pub fn init(deps: Dependencies, consensus_status: ConsensusStatus) !ReplayState {
        const zone = tracy.Zone.init(@src(), .{ .name = "ReplayState init" });
        defer zone.deinit();

        var slot_tracker: SlotTracker = try .init(deps.allocator, deps.root.slot, .{
            .constants = deps.root.constants,
            .state = deps.root.state,
        });
        errdefer slot_tracker.deinit(deps.allocator);
        errdefer {
            // do not free the root slot data parameter, we don't own it unless the function returns successfully
            deps.allocator.destroy(slot_tracker.slots.fetchSwapRemove(deps.root.slot).?.value);
        }

        const replay_votes_channel: ?*Channel(ParsedVote) = if (consensus_status == .enabled)
            try Channel(ParsedVote).create(deps.allocator)
        else
            null;
        errdefer if (replay_votes_channel) |ch| ch.destroy();

        var epoch_tracker: EpochTracker = .{ .schedule = deps.epoch_schedule };
        try epoch_tracker.epochs.put(
            deps.allocator,
            deps.current_epoch,
            deps.current_epoch_constants,
        );
        errdefer epoch_tracker.deinit(deps.allocator);
        errdefer {
            // do not free the current epoch constants parameter, we don't own it unless the function returns successfully
            std.debug.assert(epoch_tracker.epochs.swapRemove(deps.current_epoch));
        }

        const progress_map = try initProgressMap(
            deps.allocator,
            &slot_tracker,
            &epoch_tracker,
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
            .slot_leaders = deps.slot_leaders,
            .slot_tracker = slot_tracker,
            .epoch_tracker = epoch_tracker,
            .slot_tree = slot_tree,
            .hard_forks = deps.hard_forks,
            .account_store = deps.account_store,
            .ledger = deps.ledger,
            .progress_map = progress_map,
            .status_cache = .DEFAULT,
            .execution_log_helper = .init(.from(deps.logger)),
            .replay_votes_channel = replay_votes_channel,
            .stop_at_slot = deps.stop_at_slot,
        };
    }
};

/// Analogous to [`initialize_progress_and_fork_choice_with_locked_bank_forks`](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L637)
pub fn initProgressMap(
    allocator: std.mem.Allocator,
    slot_tracker: *const SlotTracker,
    epoch_tracker: *const EpochTracker,
    my_pubkey: Pubkey,
    vote_account: ?Pubkey,
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
    epoch_tracker: *EpochTracker,
    slot_tree: *SlotTree,
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

    const epoch_reward_status = try parent_constants.epoch_reward_status.clone(allocator);
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
    const zone = tracy.Zone.init(@src(), .{ .name = "getActiveFeatures" });
    defer zone.deinit();

    var features: sig.core.FeatureSet = .ALL_DISABLED;
    for (0..sig.core.features.NUM_FEATURES) |i| {
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
    const epoch_tracker = &state.epoch_tracker;

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
            if (slot_info.state.tickHeight() == slot_info.constants.max_tick_height) {
                state.logger.info().logf("finished replaying slot: {}", .{slot});
                const epoch = epoch_tracker.getForSlot(slot) orelse return error.MissingEpoch;
                try replay.freeze.freezeSlot(state.allocator, .init(
                    .from(state.logger),
                    state.account_store,
                    &state.thread_pool,
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

    return processed_a_slot;
}

/// bypass the tower bft consensus protocol, simply rooting slots with SlotTree.reRoot
fn bypassConsensus(state: *ReplayState) !void {
    if (state.slot_tree.reRoot(state.allocator)) |new_root| {
        const slot_tracker = &state.slot_tracker;

        state.logger.info().logf("rooting slot with SlotTree.reRoot: {}", .{new_root});
        slot_tracker.root = new_root;
        slot_tracker.pruneNonRooted(state.allocator);

        try state.status_cache.addRoot(state.allocator, new_root);

        try state.account_store.onSlotRooted(
            state.allocator,
            new_root,
            slot_tracker.get(new_root).?.constants.fee_rate_governor.lamports_per_signature,
        );
    }
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

    var slot_tracker: SlotTracker = try .init(allocator, 0, .{
        .state = .GENESIS,
        .constants = try .genesis(allocator, .DEFAULT),
    });
    defer slot_tracker.deinit(allocator);
    slot_tracker.get(0).?.state.hash.set(.ZEROES);

    var epoch_tracker: EpochTracker = .{ .schedule = .INIT };
    defer epoch_tracker.deinit(allocator);
    try epoch_tracker.epochs.put(allocator, 0, .{
        .hashes_per_tick = 1,
        .ticks_per_slot = 1,
        .ns_per_slot = 1,
        .genesis_creation_time = 1,
        .slots_per_year = 1,
        .stakes = .EMPTY_WITH_GENESIS,
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

    var lsc = sig.core.leader_schedule.LeaderScheduleCache.init(allocator, .INIT);
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
    slot_tracker.get(1).?.state.hash.set(.ZEROES);

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
    slot_tracker.get(2).?.state.hash.set(.ZEROES);
    slot_tracker.get(4).?.state.hash.set(.ZEROES);

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
            defer dep_stubs.deinit();

            var service = try dep_stubs.stubbedState(allocator, .FOR_TESTS);
            defer service.deinit();
        }
    };
    try ns.run(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ns.run, .{});
}

test "process runs without error with no replay results" {
    const allocator = std.testing.allocator;

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var dep_stubs = try DependencyStubs.init(allocator, .FOR_TESTS);
    defer dep_stubs.deinit();

    var replay_state = try dep_stubs.stubbedState(allocator, .FOR_TESTS);
    defer replay_state.deinit();

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
    try consensus.process(allocator, .{
        .account_store = .{ .thread_safe_map = &dep_stubs.accountsdb },
        .ledger = &dep_stubs.ledger,
        .gossip_votes = null,
        .slot_tracker = &replay_state.slot_tracker,
        .epoch_tracker = &replay_state.epoch_tracker,
        .progress_map = &replay_state.progress_map,
        .status_cache = &replay_state.status_cache,
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

    var replay_state = try dep_stubs.stubbedState(allocator, .FOR_TESTS);
    defer replay_state.deinit();

    try advanceReplay(&replay_state, try registry.initStruct(Metrics), null);

    // No slots were replayed
    try std.testing.expectEqual(0, replay_state.slot_tracker.root);
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

test "freezeCompletedSlots handles errors correctly" {
    const allocator = std.testing.allocator;

    var logger = sig.trace.log.TestLogger.init(allocator);
    defer logger.deinit();

    var dep_stubs = try DependencyStubs.init(allocator, .from(logger.logger("", .warn)));
    defer dep_stubs.deinit();

    var replay_state = try dep_stubs.stubbedState(allocator, .from(logger.logger("", .warn)));
    defer replay_state.deinit();

    const processed_a_slot = try freezeCompletedSlots(&replay_state, &.{
        .{ .slot = 1, .output = .{ .err = .{ .invalid_block = .TooFewTicks } } },
        .{ .slot = 2, .output = .{ .err = .failed_to_load_meta } },
    });

    try std.testing.expectEqual(sig.trace.Level.warn, logger.messages.items[0].level);
    try std.testing.expectEqualSlices(u8,
        \\replayed slot 1 with error: replay.execution.ReplaySlotError{ .invalid_block = replay.execution.BlockError.TooFewTicks }
    , logger.messages.items[0].content);
    try std.testing.expectEqual(sig.trace.Level.@"error", logger.messages.items[1].level);
    try std.testing.expectEqualSlices(u8,
        \\replayed slot 2 with error: replay.execution.ReplaySlotError{ .failed_to_load_meta = void }
    , logger.messages.items[1].content);

    try std.testing.expectEqual(false, processed_a_slot);
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
    const result = try dep_stubs.ledger.shredInserter().insertShreds(
        allocator,
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
    var replay_state = try dep_stubs.mockedState(
        allocator,
        epoch,
        &manifest,
        slot_leaders.slotLeaders(),
        config.num_threads,
    );
    defer replay_state.deinit();

    // replay the block
    replay_state.stop_at_slot = execution_slot;
    try std.testing.expectError(
        error.ReachedEndSlot,
        advanceReplay(&replay_state, try registry.initStruct(Metrics), null),
    );

    // get slot hash
    const actual_slot_hash = tracker_lock: {
        const ref = replay_state.slot_tracker.get(execution_slot).?;
        break :tracker_lock ref.state.hash.readCopy().?;
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
pub const DependencyStubs = struct {
    allocator: Allocator,
    accountsdb: sig.accounts_db.ThreadSafeAccountMap,
    dir: std.testing.TmpDir,
    ledger: Ledger,
    senders: TowerConsensus.Senders,
    receivers: TowerConsensus.Receivers,
    replay_votes_channel: *Channel(ParsedVote),

    pub fn deinit(self: *DependencyStubs) void {
        self.accountsdb.deinit();
        self.dir.cleanup();
        self.ledger.deinit();
        self.senders.destroy();
        self.receivers.destroy();
        while (self.replay_votes_channel.tryReceive()) |pv| pv.deinit(self.allocator);
        self.replay_votes_channel.destroy();
    }

    pub fn init(allocator: Allocator, logger: Logger) !DependencyStubs {
        var accountsdb = sig.accounts_db.ThreadSafeAccountMap.init(allocator);
        errdefer accountsdb.deinit();

        var dir = std.testing.tmpDir(.{});
        errdefer dir.cleanup();

        const ledger_path = try dir.dir.realpathAlloc(allocator, ".");
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
            .accountsdb = accountsdb,
            .dir = dir,
            .ledger = ledger,
            .senders = senders,
            .receivers = receivers,
            .replay_votes_channel = replay_votes_channel,
        };
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

        const epoch: sig.core.EpochConstants = .genesis(.default(allocator));
        errdefer epoch.deinit(allocator);

        var prng_state = std.Random.DefaultPrng.init(24659);
        const prng = prng_state.random();

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
            .epoch_schedule = .INIT,
            .account_store = self.accountsdb.accountStore(),
            .ledger = &self.ledger,
            .slot_leaders = .{
                .state = undefined,
                .getFn = struct {
                    pub fn get(_: *anyopaque, slot: Slot) ?Pubkey {
                        const four_slot: [4]Slot = @splat(slot +| 1);
                        return .{ .data = @bitCast(four_slot) };
                    }
                }.get,
            },
            .root = .{
                .slot = 0,
                .constants = root_slot_constants,
                .state = root_slot_state,
            },
            .current_epoch = 0,
            .current_epoch_constants = epoch,
            .hard_forks = .{},

            .replay_threads = 1,
            .stop_at_slot = null,
        }, .enabled);
    }

    // TODO: consider deduplicating with above and similar function in cmd.zig
    /// "mocked" with meaningful data as opposed to "stubbed" with garbage data
    fn mockedState(
        self: *DependencyStubs,
        allocator: std.mem.Allocator,
        epoch: sig.core.Epoch,
        collapsed_manifest: *const sig.accounts_db.snapshot.Manifest,
        slot_leaders: sig.core.leader_schedule.SlotLeaders,
        num_threads: u32,
    ) !ReplayState {
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

        const lt_hash = collapsed_manifest.bank_extra.accounts_lt_hash;

        var root_slot_state =
            try sig.core.SlotState.fromBankFields(allocator, bank_fields, lt_hash);
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
            .account_store = self.accountsdb.accountStore(),
            .ledger = &self.ledger,
            .epoch_schedule = bank_fields.epoch_schedule,
            .slot_leaders = slot_leaders,
            .root = .{
                .slot = bank_fields.slot,
                .constants = root_slot_constants,
                .state = root_slot_state,
            },
            .current_epoch = epoch,
            .current_epoch_constants = try .fromBankFields(
                bank_fields,
                try epoch_stakes.current.convert(allocator, .delegation),
            ),
            .hard_forks = hard_forks,

            .replay_threads = num_threads,
            .stop_at_slot = null,
        }, .enabled);
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
