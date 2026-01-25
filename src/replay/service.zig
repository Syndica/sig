const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");
const tracy = @import("tracy");
const builtin = @import("builtin");

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
    magic_tracker: *sig.core.magic_info.MagicTracker,
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
    /// Optional context for RPC hooks
    rpc_context: ?*sig.rpc.methods.HookContext,
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
    slot_tracker: SlotTracker,
    magic_tracker: *sig.core.magic_info.MagicTracker,
    slot_tree: SlotTree,
    hard_forks: sig.core.HardForks,
    account_store: AccountStore,
    progress_map: ProgressMap,
    ledger: *Ledger,
    status_cache: sig.core.StatusCache,
    execution_log_helper: replay.execution.LogHelper,
    replay_votes_channel: ?*Channel(ParsedVote),
    stop_at_slot: ?sig.core.Slot,
    rpc_context: ?*sig.rpc.methods.HookContext,

    pub fn deinit(self: *ReplayState) void {
        self.thread_pool.shutdown();
        self.thread_pool.deinit();

        self.slot_tracker.deinit(self.allocator);
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

        const progress_map = try initProgressMap(
            deps.allocator,
            &slot_tracker,
            deps.magic_tracker,
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
            .magic_tracker = deps.magic_tracker,
            .slot_tree = slot_tree,
            .hard_forks = deps.hard_forks,
            .account_store = deps.account_store,
            .ledger = deps.ledger,
            .progress_map = progress_map,
            .status_cache = .DEFAULT,
            .execution_log_helper = .init(.from(deps.logger)),
            .replay_votes_channel = replay_votes_channel,
            .stop_at_slot = deps.stop_at_slot,
            .rpc_context = deps.rpc_context,
        };
    }

    pub fn initForTest(deps: struct {
        allocator: std.mem.Allocator,
        ledger: *Ledger,
        slot_tracker: SlotTracker,
        magic_tracker: *sig.core.magic_info.MagicTracker,
        slot_tree: SlotTree,
        hard_forks: sig.core.HardForks,
    }) ReplayState {
        if (!builtin.is_test) @compileError("initForTests should only be used in tests");
        var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
        return .{
            .allocator = deps.allocator,
            .logger = .FOR_TESTS,
            .identity = .{
                .validator = Pubkey.initRandom(rng.random()),
                .vote_account = null,
            },
            .signing = .{
                .authorized_voters = &[_]std.crypto.sign.Ed25519.KeyPair{},
                .node = null,
            },
            .thread_pool = ThreadPool.init(.{}),
            .slot_tracker = deps.slot_tracker,
            .magic_tracker = deps.magic_tracker,
            .slot_tree = deps.slot_tree,
            .hard_forks = deps.hard_forks,
            .account_store = .noop,
            .progress_map = ProgressMap.INIT,
            .ledger = deps.ledger,
            .status_cache = sig.core.StatusCache.DEFAULT,
            .execution_log_helper = replay.execution.LogHelper.init(.FOR_TESTS),
            .replay_votes_channel = null,
            .stop_at_slot = null,
            .rpc_context = null,
        };
    }

    /// Run a single iteration of the entire replay process. Includes:
    /// - replay all active slots that have not been replayed yet
    /// - running consensus on the latest updates (if present)
    pub fn advance(
        self: *@This(),
        metrics: Metrics,
        consensus_params: ?AvanceReplayConsensusParams,
    ) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "advanceReplay" });
        defer zone.deinit();

        const allocator = self.allocator;

        var start_time = sig.time.Timer.start();
        self.logger.debug().log("advancing replay");

        var leader_schedules = try self.magic_tracker.getLeaderSchedules();
        const slot_leaders = SlotLeaders.init(
            &leader_schedules,
            sig.core.magic_leader_schedule.LeaderSchedules.getLeaderOrNull,
        );

        // find slots in the ledger
        try self.trackNewSlots(&slot_leaders);

        // replay slots
        const slot_results = try replay.execution.replayActiveSlots(self);
        defer allocator.free(slot_results);

        // freeze slots
        const processed_a_slot: bool = try self.freezeCompletedSlots(slot_results);

        // run consensus
        if (consensus_params) |consensus| {
            var gossip_verified_vote_hashes: std.ArrayListUnmanaged(GossipVerifiedVoteHash) = .empty;
            defer gossip_verified_vote_hashes.deinit(allocator);

            var duplicate_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
            defer duplicate_confirmed_slots.deinit(allocator);

            try consensus.tower.process(allocator, .{
                .account_store = self.account_store,
                .gossip_votes = consensus.gossip_votes,
                .ledger = self.ledger,
                .slot_tracker = &self.slot_tracker,
                .magic_tracker = self.magic_tracker,
                .progress_map = &self.progress_map,
                .status_cache = &self.status_cache,
                .senders = consensus.senders,
                .receivers = consensus.receivers,
                .vote_sockets = consensus.vote_sockets,
                .slot_leaders = slot_leaders,
                .duplicate_confirmed_slots = &duplicate_confirmed_slots,
                .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
                .results = slot_results,
            });
        } else try self.bypassConsensus();

        if (slot_results.len != 0) {
            const elapsed = start_time.read().asNanos();
            metrics.slot_execution_time.observe(elapsed);
            self.logger.info().logf("advanced in {}", .{std.fmt.fmtDuration(elapsed)});
        }

        if (self.stop_at_slot) |stop_slot| {
            for (slot_results) |result| if (result.slot >= stop_slot) {
                self.logger.info().logf("Reached end slot {}, exiting replay", .{stop_slot});
                return error.ReachedEndSlot;
            };
        }

        if (!processed_a_slot) try std.Thread.yield();
    }

    /// Identifies new slots in the ledger and starts tracking them in the slot
    /// tracker.
    ///
    /// Analogous to
    /// [generate_new_bank_forks](https://github.com/anza-xyz/agave/blob/146ebd8be3857d530c0946003fcd58be220c3290/core/src/replay_stage.rs#L4149)
    pub fn trackNewSlots(
        self: *@This(),
        slot_leaders: *const SlotLeaders,
    ) !void {
        var zone = tracy.Zone.init(@src(), .{ .name = "trackNewSlots" });
        defer zone.deinit();

        const root = self.slot_tracker.root;
        var frozen_slots = try self.slot_tracker.frozenSlots(self.allocator);
        defer frozen_slots.deinit(self.allocator);

        var frozen_slots_since_root = try std.ArrayListUnmanaged(sig.core.Slot)
            .initCapacity(self.allocator, frozen_slots.count());
        defer frozen_slots_since_root.deinit(self.allocator);
        for (frozen_slots.keys()) |slot| if (slot >= root) {
            frozen_slots_since_root.appendAssumeCapacity(slot);
        };

        var next_slots = try self.ledger.reader().getSlotsSince(
            self.allocator,
            frozen_slots_since_root.items,
        );
        defer {
            for (next_slots.values()) |*list| list.deinit(self.allocator);
            next_slots.deinit(self.allocator);
        }

        for (next_slots.keys(), next_slots.values()) |parent_slot, children| {
            const parent_info = frozen_slots.get(parent_slot) orelse return error.MissingParent;

            for (children.items) |slot| {
                if (self.slot_tracker.contains(slot)) continue;
                self.logger.info().logf("tracking new slot: {}", .{slot});

                // Constants are not constant at this point since processing new epochs
                // may modify the feature set.
                var constants, var state = try newSlotFromParent(
                    self.allocator,
                    self.account_store.reader(),
                    self.magic_tracker.cluster.ticks_per_slot,
                    parent_slot,
                    parent_info.constants,
                    parent_info.state,
                    slot_leaders.get(slot) orelse return error.UnknownLeader,
                    slot,
                );
                errdefer constants.deinit(self.allocator);
                errdefer state.deinit(self.allocator);

                const parent_epoch = self.magic_tracker.epoch_schedule.getEpoch(parent_slot);
                const slot_epoch = self.magic_tracker.epoch_schedule.getEpoch(slot);
                const store = self.account_store.forSlot(slot, &constants.ancestors);

                if (parent_epoch < slot_epoch) {
                    try replay.epoch_transitions.processNewEpoch(
                        self.allocator,
                        slot,
                        &constants,
                        &state,
                        store,
                        self.magic_tracker,
                    );
                } else {
                    try replay.epoch_transitions.updateEpochStakes(
                        self.allocator,
                        slot,
                        &constants.ancestors,
                        &constants.feature_set,
                        &state.stakes_cache,
                        self.magic_tracker,
                    );
                }

                try replay.rewards.distribution.distributePartitionedEpochRewards(
                    self.allocator,
                    slot,
                    slot_epoch,
                    constants.block_height,
                    self.magic_tracker.epoch_schedule,
                    &state.reward_status,
                    &state.stakes_cache,
                    &state.capitalization,
                    &constants.rent_collector.rent,
                    store,
                );

                try updateSysvarsForNewSlot(
                    self.allocator,
                    self.account_store,
                    self.magic_tracker,
                    &constants,
                    &state,
                    slot,
                    &self.hard_forks,
                );

                if (self.rpc_context) |ctx| {
                    ctx.setLatestConfirmedSlot(slot);
                }

                try self.slot_tracker.put(self.allocator, slot, .{
                    .constants = constants,
                    .state = state
                });
                try self.slot_tree.record(self.allocator, slot, constants.parent_slot);

                // TODO: update_fork_propagated_threshold_from_votes
            }
        }
    }

    /// freezes any slots that were completed according to these replay results
    fn freezeCompletedSlots(self: *@This(), results: []const ReplayResult) !bool {
        const slot_tracker = &self.slot_tracker;

        var processed_a_slot = false;
        for (results) |result| switch (result.output) {
            .err => |err| {
                self.logger.logf(
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
                    self.logger.info().logf("finished replaying slot: {}", .{slot});
                    try replay.freeze.freezeSlot(self.allocator, .init(
                        .from(self.logger),
                        self.account_store,
                        &self.thread_pool,
                        slot_info.state,
                        slot_info.constants,
                        slot,
                        last_entry_hash,
                    ));
                    if (self.rpc_context) |ctx| {
                        ctx.setLatestProcessedSlot(slot);
                    }
                    processed_a_slot = true;
                } else {
                    self.logger.info().logf("partially replayed slot: {}", .{slot});
                }
            },
        };

        return processed_a_slot;
    }

    /// bypass the tower bft consensus protocol, simply rooting slots with SlotTree.reRoot
    fn bypassConsensus(self: *@This()) !void {
        if (self.slot_tree.reRoot(self.allocator)) |new_root| {
            const slot_tracker = &self.slot_tracker;

            self.logger.info().logf("rooting slot with SlotTree.reRoot: {}", .{new_root});
            slot_tracker.root = new_root;
            slot_tracker.pruneNonRooted(self.allocator);

            try self.status_cache.addRoot(self.allocator, new_root);

            const slot_constants = slot_tracker.get(new_root).?;
            try self.account_store.onSlotRooted(
                new_root,
                &slot_constants.constants.ancestors,
            );
        }
    }
};

/// Analogous to [`initialize_progress_and_fork_choice_with_locked_bank_forks`](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L637)
pub fn initProgressMap(
    allocator: std.mem.Allocator,
    slot_tracker: *const SlotTracker,
    magic_tracker: *const sig.core.magic_info.MagicTracker,
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
        const epoch_info = try magic_tracker.getEpochInfo(slot);
        const prev_leader_slot = progress.getSlotPrevLeaderSlot(ref.constants.parent_slot);
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

    const epoch_reward_status = parent_state.reward_status.clone();
    errdefer epoch_reward_status.deinit(allocator);

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

test "trackNewSlots" {
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
    });
    slot_tracker.get(0).?.state.hash.set(.ZEROES);

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

    var magic_tracker = try sig.core.magic_info.MagicTracker.initForTest(
        allocator,
        rng.random(),
        0,
        .INIT,
    );
    defer magic_tracker.deinit(allocator);

    var lsc = sig.core.leader_schedule.LeaderScheduleCache.init(allocator, .INIT);
    defer {
        var map = lsc.leader_schedules.write();
        map.mut().deinit();
        map.unlock();
    }
    try lsc.put(0, leader_schedule);
    const slot_leaders = lsc.slotLeaders();

    const slot_tree = try SlotTree.init(allocator, 0);

    const hard_forks = sig.core.HardForks{};

    var replay_state = ReplayState.initForTest(.{
        .allocator = allocator,
        .ledger = &ledger,
        .slot_tracker = slot_tracker,
        .magic_tracker = &magic_tracker,
        .slot_tree = slot_tree,
        .hard_forks = hard_forks,
    });
    defer replay_state.deinit();

    // slot tracker should start with only 0
    try expectSlotTracker(
        &replay_state.slot_tracker,
        leader_schedule,
        &.{.{ 0, 0 }},
        &.{ 1, 2, 3, 4, 5, 6 }
    );

    // only the root (0) is considered frozen, so only 0 and 1 should be added at first.
    try replay_state.trackNewSlots(&slot_leaders);
    try expectSlotTracker(
        &replay_state.slot_tracker,
        leader_schedule,
        &.{ .{ 0, 0 }, .{ 1, 0 } },
        &.{ 2, 3, 4, 5, 6 },
    );

    // doing nothing should result in the same tracker state
    try replay_state.trackNewSlots(&slot_leaders);
    try expectSlotTracker(
        &replay_state.slot_tracker,
        leader_schedule,
        &.{ .{ 0, 0 }, .{ 1, 0 } },
        &.{ 2, 3, 4, 5, 6 },
    );

    // freezing 1 should result in 2 and 4 being added
    replay_state.slot_tracker.get(1).?.state.hash.set(.ZEROES);

    try replay_state.trackNewSlots(&slot_leaders);
    try expectSlotTracker(
        &replay_state.slot_tracker,
        leader_schedule,
        &.{ .{ 0, 0 }, .{ 1, 0 }, .{ 2, 1 }, .{ 4, 1 } },
        &.{ 3, 5, 6 },
    );

    // freezing 2 and 4 should only result in 6 being added since 3's parent is unknown
    replay_state.slot_tracker.get(2).?.state.hash.set(.ZEROES);
    replay_state.slot_tracker.get(4).?.state.hash.set(.ZEROES);

    try replay_state.trackNewSlots(&slot_leaders);
    try expectSlotTracker(
        &replay_state.slot_tracker,
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
            defer {
                service.deinit();
                service.magic_tracker.deinit(allocator);
                allocator.destroy(service.magic_tracker);
            }
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
    defer {
        replay_state.deinit();
        replay_state.magic_tracker.deinit(allocator);
        allocator.destroy(replay_state.magic_tracker);
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
    try consensus.process(allocator, .{
        .account_store = dep_stubs.accountStore(),
        .ledger = &dep_stubs.ledger,
        .gossip_votes = null,
        .slot_tracker = &replay_state.slot_tracker,
        .magic_tracker = replay_state.magic_tracker,
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
    defer {
        replay_state.deinit();
        replay_state.magic_tracker.deinit(allocator);
        allocator.destroy(replay_state.magic_tracker);
    }

    try replay_state.advance(try registry.initStruct(Metrics), null);

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
    defer {
        replay_state.deinit();
        replay_state.magic_tracker.deinit(allocator);
        allocator.destroy(replay_state.magic_tracker);
    }

    const processed_a_slot = try replay_state.freezeCompletedSlots(&.{
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

    var epoch_stakes = manifest.bank_extra.versioned_epoch_stakes.get(
        manifest.bank_fields.epoch,
    ).?.current;

    epoch_stakes.stakes.epoch += 1;
    try manifest.bank_extra.versioned_epoch_stakes.put(
        fba.allocator(),
        manifest.bank_fields.epoch + 1,
        .{ .current = try epoch_stakes.clone(fba.allocator()) },
    );

    manifest.bank_fields.stakes.deinit(fba.allocator());
    manifest.bank_fields.stakes = try epoch_stakes.stakes.convert(fba.allocator(), .delegation);

    // init replay
    var replay_state = try dep_stubs.mockedState(
        allocator,
        &manifest,
        config.num_threads,
    );
    defer {
        replay_state.deinit();
        replay_state.magic_tracker.deinit(allocator);
        allocator.destroy(replay_state.magic_tracker);
    }

    // replay the block
    replay_state.stop_at_slot = execution_slot;
    try std.testing.expectError(
        error.ReachedEndSlot,
        replay_state.advance(try registry.initStruct(Metrics), null),
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
    accounts_db_state: sig.accounts_db.Two.TestContext,
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
        var test_state = try sig.accounts_db.Two.initTest(allocator);
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
        return .{ .accounts_db_two = &self.accounts_db_state.db };
    }

    pub fn accountReader(self: *DependencyStubs) AccountReader {
        return .{ .accounts_db_two = &self.accounts_db_state.db };
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

        var prng_state = std.Random.DefaultPrng.init(24659);
        const prng = prng_state.random();

        var magic_tracker = try allocator.create(sig.core.magic_info.MagicTracker);
        errdefer allocator.destroy(magic_tracker);

        magic_tracker.* = try sig.core.magic_info.MagicTracker.initForTest(
            allocator,
            prng,
            0,
            .INIT,
        );
        errdefer magic_tracker.deinit(allocator);

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
            .magic_tracker = magic_tracker,
            .root = .{
                .slot = 0,
                .constants = root_slot_constants,
                .state = root_slot_state,
            },
            .hard_forks = .{},

            .replay_threads = 1,
            .stop_at_slot = null,
            .rpc_context = null,
        }, .enabled);
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
            .{ .accounts_db_two = .{ &self.accounts_db_state.db, &bank_fields.ancestors } },
            bank_fields.slot,
        );

        var magic_tracker = try allocator.create(sig.core.magic_info.MagicTracker);
        errdefer allocator.destroy(magic_tracker);

        magic_tracker.* = try sig.core.magic_info.MagicTracker.initFromManifest(
            allocator,
            collapsed_manifest,
            &feature_set,
        );
        errdefer magic_tracker.deinit(allocator);

        const root_slot_constants = try sig.core.SlotConstants.fromBankFields(
            allocator,
            bank_fields,
            feature_set,
        );
        errdefer root_slot_constants.deinit(allocator);

        const lt_hash = collapsed_manifest.bank_extra.accounts_lt_hash;

        const account_store = sig.accounts_db.AccountStore{
            .accounts_db_two = &self.accounts_db_state.db,
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
            .magic_tracker = magic_tracker,
            .root = .{
                .slot = bank_fields.slot,
                .constants = root_slot_constants,
                .state = root_slot_state,
            },
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
