const std = @import("std");
const sig = @import("../../sig.zig");
const replay = @import("../lib.zig");
const tracy = @import("tracy");

const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);

pub const Logger = sig.trace.Logger("consensus");

const Channel = sig.sync.Channel;
const RwMux = sig.sync.RwMux;
const SortedSetUnmanaged = sig.utils.collections.SortedSetUnmanaged;

const Ancestors = sig.core.Ancestors;
const Epoch = sig.core.Epoch;
const EpochSchedule = sig.core.EpochSchedule;
const EpochStakesMap = sig.core.EpochStakesMap;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SlotAndHash = sig.core.hash.SlotAndHash;
const SlotConstants = sig.core.SlotConstants;
const SlotState = sig.core.SlotState;
const Transaction = sig.core.transaction.Transaction;

const AccountReader = sig.accounts_db.AccountReader;

const Ledger = sig.ledger.Ledger;

const ForkChoice = sig.consensus.fork_choice.ForkChoice;
const GossipVerifiedVoteHash = sig.consensus.vote_listener.GossipVerifiedVoteHash;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const LatestValidatorVotes = sig.consensus.latest_validator_votes.LatestValidatorVotes;
const ParsedVote = sig.consensus.vote_listener.vote_parser.ParsedVote;
const ProgressMap = sig.consensus.progress_map.ProgressMap;
const ReplayTower = sig.consensus.replay_tower.ReplayTower;
const ThresholdConfirmedSlot = sig.consensus.vote_listener.ThresholdConfirmedSlot;
const VerifiedVote = sig.consensus.vote_listener.VerifiedVote;
const VoteListener = sig.consensus.vote_listener.VoteListener;

const SlotTracker = sig.replay.trackers.SlotTracker;
const EpochTracker = sig.replay.trackers.EpochTracker;

const AncestorDuplicateSlotToRepair = replay.consensus.edge_cases.AncestorDuplicateSlotToRepair;
const DuplicateConfirmedState = sig.replay.consensus.edge_cases.DuplicateConfirmedState;
const SlotData = sig.replay.consensus.edge_cases.SlotData;
const SlotStatus = sig.replay.consensus.edge_cases.SlotStatus;

const ReplayResult = replay.execution.ReplayResult;
const ProcessResultParams = replay.consensus.process_result.ProcessResultParams;

const collectVoteLockouts = sig.consensus.replay_tower.collectVoteLockouts;
const isDuplicateSlotConfirmed = sig.consensus.replay_tower.isDuplicateSlotConfirmed;
const check_slot_agrees_with_cluster =
    sig.replay.consensus.edge_cases.check_slot_agrees_with_cluster;

const MAX_VOTE_REFRESH_INTERVAL_MILLIS: usize = 5000;

/// TowerConsensus contains all the state needed for operating the Tower BFT
/// consensus mechanism in sig.
pub const TowerConsensus = struct {
    logger: Logger,
    my_identity: Pubkey,

    // Core consensus state
    fork_choice: HeaviestSubtreeForkChoice,
    replay_tower: ReplayTower,
    latest_validator_votes: LatestValidatorVotes,
    status_cache: sig.core.StatusCache,
    slot_data: SlotData,
    /// this is used for some temporary allocations that don't outlive
    /// functions; ie, it isn't used for any persistent data
    arena_state: std.heap.ArenaAllocator.State,

    // Data sources
    account_reader: AccountReader,
    ledger: *Ledger,

    // Communication channels
    senders: Senders,
    receivers: Receivers,
    verified_vote_channel: *Channel(VerifiedVote),

    // Supporting services
    vote_listener: ?VoteListener,

    pub fn deinit(self: *TowerConsensus, allocator: Allocator) void {
        if (self.vote_listener) |vl| vl.joinAndDeinit();
        self.replay_tower.deinit(allocator);
        self.fork_choice.deinit();
        self.latest_validator_votes.deinit(allocator);
        self.slot_data.deinit(allocator);
        self.arena_state.promote(allocator).deinit();
        self.verified_vote_channel.destroy();
    }

    /// All parameters needed for initialization
    pub const Dependencies = struct {
        // Basic parameters
        logger: Logger,
        my_identity: Pubkey,
        vote_identity: Pubkey,
        root_slot: Slot,
        root_hash: Hash,

        // Data sources
        account_reader: AccountReader,
        ledger: *sig.ledger.Ledger,

        // channels/signals/communication
        exit: *AtomicBool,
        replay_votes_channel: *Channel(ParsedVote),
        slot_tracker_rw: *RwMux(SlotTracker),
        epoch_tracker_rw: *RwMux(EpochTracker),
        external: External,

        /// Data that comes from outside replay
        pub const External = struct {
            senders: Senders,
            receivers: Receivers,
            gossip_table: ?*RwMux(sig.gossip.GossipTable),
            run_vote_listener: bool = true,

            pub fn deinit(self: External) void {
                self.senders.destroy();
                self.receivers.destroy();
            }
        };

        pub fn deinit(self: Dependencies) void {
            self.external.deinit();
        }
    };

    /// Channels where consensus sends messages to other services
    pub const Senders = struct {
        /// Received by repair ancestor_hashes_service
        ancestor_hashes_replay_update: *Channel(AncestorHashesReplayUpdate),

        pub fn destroy(self: Senders) void {
            self.ancestor_hashes_replay_update.destroy();
        }

        pub fn create(allocator: std.mem.Allocator) std.mem.Allocator.Error!Senders {
            return .{ .ancestor_hashes_replay_update = try .create(allocator) };
        }
    };

    /// Channels where consensus receives messages from other services
    pub const Receivers = struct {
        /// Sent by repair ancestor_hashes_service
        ancestor_duplicate_slots: *Channel(AncestorDuplicateSlotToRepair),
        /// Sent by vote_listener
        duplicate_confirmed_slots: *Channel(ThresholdConfirmedSlot),
        /// Sent by vote_listener
        gossip_verified_vote_hash: *Channel(GossipVerifiedVoteHash),
        /// Sent by repair service
        popular_pruned_forks: *Channel(Slot),
        /// Sent by WindowService and DuplicateShred handlers
        duplicate_slots: *Channel(Slot),

        pub fn destroy(self: Receivers) void {
            self.ancestor_duplicate_slots.destroy();
            self.duplicate_confirmed_slots.destroy();
            self.gossip_verified_vote_hash.destroy();
            self.popular_pruned_forks.destroy();
            self.duplicate_slots.destroy();
        }

        pub fn create(allocator: std.mem.Allocator) std.mem.Allocator.Error!Receivers {
            const ancestor_duplicate_slots: *Channel(AncestorDuplicateSlotToRepair) =
                try .create(allocator);
            errdefer ancestor_duplicate_slots.destroy();

            const duplicate_confirmed_slots: *Channel(ThresholdConfirmedSlot) =
                try .create(allocator);
            errdefer duplicate_confirmed_slots.destroy();

            const gossip_verified_vote_hash: *Channel(GossipVerifiedVoteHash) =
                try .create(allocator);
            errdefer gossip_verified_vote_hash.destroy();

            const popular_pruned_forks: *Channel(Slot) = try .create(allocator);
            errdefer popular_pruned_forks.destroy();

            const duplicate_slots: *Channel(Slot) = try .create(allocator);
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

    pub fn init(allocator: Allocator, deps: Dependencies) !TowerConsensus {
        const zone = tracy.Zone.init(@src(), .{ .name = "TowerConsensus.init" });
        defer zone.deinit();

        const slot_tracker, var slot_tracker_lock = deps.slot_tracker_rw.readWithLock();
        defer slot_tracker_lock.unlock();

        var fork_choice = try initForkChoice(
            allocator,
            deps.logger,
            slot_tracker,
            deps.ledger,
        );
        errdefer fork_choice.deinit();

        const replay_tower: ReplayTower = try .init(
            allocator,
            .from(deps.logger),
            deps.my_identity,
            deps.vote_identity,
            deps.root_slot,
            deps.account_reader.forSlot(&slot_tracker.get(slot_tracker.root).?.constants.ancestors),
            sig.prometheus.globalRegistry(),
        );
        errdefer replay_tower.deinit(allocator);

        const slot_data_provider: sig.consensus.vote_listener.SlotDataProvider = .{
            .slot_tracker_rw = deps.slot_tracker_rw,
            .epoch_tracker_rw = deps.epoch_tracker_rw,
        };

        const verified_vote_channel = try Channel(VerifiedVote).create(allocator);
        errdefer verified_vote_channel.destroy();

        const vote_listener: ?VoteListener = if (deps.external.run_vote_listener) try .init(
            allocator,
            .{ .unordered = deps.exit },
            .from(deps.logger),
            sig.prometheus.globalRegistry(),
            .{
                .slot_data_provider = slot_data_provider,
                .gossip_table_rw = deps.external.gossip_table,
                .ledger = deps.ledger,
                .receivers = .{ .replay_votes_channel = deps.replay_votes_channel },
                .senders = .{
                    .verified_vote = verified_vote_channel,
                    .gossip_verified_vote_hash = deps.external.receivers.gossip_verified_vote_hash,
                    .bank_notification = null,
                    .duplicate_confirmed_slots = deps.external.receivers.duplicate_confirmed_slots,
                    .subscriptions = .{},
                },
            },
        ) else null;

        return .{
            .fork_choice = fork_choice,
            .replay_tower = replay_tower,
            .latest_validator_votes = .empty,
            .status_cache = .DEFAULT,
            .slot_data = .empty,
            .arena_state = .{},
            .logger = deps.logger,
            .my_identity = deps.my_identity,
            .account_reader = deps.account_reader,
            .ledger = deps.ledger,
            .senders = deps.external.senders,
            .receivers = deps.external.receivers,
            .vote_listener = vote_listener,
            .verified_vote_channel = verified_vote_channel,
        };
    }

    /// Analogous to [`initialize_progress_and_fork_choice_with_locked_bank_forks`](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L637)
    pub fn initForkChoice(
        allocator: std.mem.Allocator,
        logger: Logger,
        slot_tracker: *const SlotTracker,
        ledger: *Ledger,
    ) !HeaviestSubtreeForkChoice {
        const root_slot, const root_hash = blk: {
            const root = slot_tracker.getRoot();
            const root_slot = slot_tracker.root;
            const root_hash = root.state.hash.readCopy();
            break :blk .{ root_slot, root_hash.? };
        };

        var frozen_slots = try slot_tracker.frozenSlots(allocator);
        defer frozen_slots.deinit(allocator);

        frozen_slots.sort(replay.service.FrozenSlotsSortCtx{ .slots = frozen_slots.keys() });

        // Given a root and a list of `frozen_slots` sorted smallest to greatest by slot,
        // initialize a new HeaviestSubtreeForkChoice
        //
        // Analogous to [`new_from_frozen_banks`](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/consensus/heaviest_subtree_fork_choice.rs#L235)
        var heaviest_subtree_fork_choice: HeaviestSubtreeForkChoice =
            try .init(
                allocator,
                .from(logger),
                .{
                    .slot = root_slot,
                    .hash = root_hash,
                },
                sig.prometheus.globalRegistry(),
            );
        errdefer heaviest_subtree_fork_choice.deinit();

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

        var duplicate_slots = try ledger.db.iterator(
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

    /// Run all phases of consensus:
    /// - process replay results
    /// - edge cases
    /// - actual consensus protocol.
    pub fn process(
        self: *TowerConsensus,
        allocator: Allocator,
        slot_tracker_rw: *RwMux(SlotTracker),
        epoch_tracker_rw: *RwMux(EpochTracker),
        progress_map: *ProgressMap,
        results: []const ReplayResult,
    ) !void {
        var arena_state = self.arena_state.promote(allocator);
        defer {
            _ = arena_state.reset(.retain_capacity);
            self.arena_state = arena_state.state;
        }
        const arena = arena_state.allocator();

        { // Process replay results
            const slot_tracker, var lock = slot_tracker_rw.readWithLock();
            defer lock.unlock();
            for (results) |r| try self.processResult(allocator, progress_map, slot_tracker, r);
        }

        // Process edge cases and prepare ancestors/descendants
        const ancestors, const descendants = edge_cases_and_ancestors_descendants: {
            const slot_tracker, var slot_tracker_lg = slot_tracker_rw.readWithLock();
            defer slot_tracker_lg.unlock();

            _ = try replay.consensus.edge_cases.processEdgeCases(allocator, .from(self.logger), .{
                .my_pubkey = self.my_identity,
                .tpu_has_bank = false,
                .fork_choice = &self.fork_choice,
                .result_writer = self.ledger.resultWriter(),
                .slot_tracker = slot_tracker,
                .progress = progress_map,
                .latest_validator_votes = &self.latest_validator_votes,
                .slot_data = &self.slot_data,
                .senders = self.senders,
                .receivers = self.receivers,
            });

            const SlotSet = SortedSetUnmanaged(Slot);

            // arena-allocated
            var ancestors: std.AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
            var descendants: std.AutoArrayHashMapUnmanaged(Slot, SlotSet) = .empty;
            for (slot_tracker.slots.keys(), slot_tracker.slots.values()) |slot, info| {
                const slot_ancestors = &info.constants.ancestors.ancestors;
                const ancestor_gop = try ancestors.getOrPutValue(arena, slot, .EMPTY);
                try ancestor_gop.value_ptr.ancestors
                    .ensureUnusedCapacity(arena, slot_ancestors.count());
                for (slot_ancestors.keys()) |ancestor_slot| {
                    try ancestor_gop.value_ptr.addSlot(arena, ancestor_slot);
                    const descendants_gop =
                        try descendants.getOrPutValue(arena, ancestor_slot, .empty);
                    try descendants_gop.value_ptr.put(arena, slot);
                }
            }
            break :edge_cases_and_ancestors_descendants .{ ancestors, descendants };
        };

        const epoch_tracker, var epoch_tracker_lg = epoch_tracker_rw.readWithLock();
        defer epoch_tracker_lg.unlock();

        const slot_tracker_mut, var slot_tracker_mut_lg = slot_tracker_rw.writeWithLock();
        defer slot_tracker_mut_lg.unlock();

        try self.executeProtocol(
            allocator,
            &ancestors,
            &descendants,
            slot_tracker_mut,
            epoch_tracker,
            progress_map,
            self.account_reader,
            self.my_identity, // vote_account
        );
    }

    fn processResult(
        self: *TowerConsensus,
        allocator: Allocator,
        progress_map: *ProgressMap,
        slot_tracker: *const SlotTracker,
        result: ReplayResult,
    ) !void {
        const process_state: ProcessResultParams = .{
            .allocator = allocator,
            .logger = .from(self.logger),
            .my_identity = self.my_identity,
            .ledger = self.ledger,
            .slot_tracker = slot_tracker,
            .progress_map = progress_map,
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

        try replay.consensus.process_result.processResult(process_state, result);
    }

    /// runs the core consensus protocol: select fork, vote, and update internal state
    fn executeProtocol(
        self: *TowerConsensus,
        allocator: Allocator,
        ancestors: *const std.AutoArrayHashMapUnmanaged(Slot, Ancestors),
        descendants: *const std.AutoArrayHashMapUnmanaged(Slot, SortedSetUnmanaged(Slot)),
        slot_tracker: *SlotTracker,
        epoch_tracker: *const EpochTracker,
        progress_map: *ProgressMap,
        /// For reading the slot history account
        account_reader: AccountReader,
        vote_account: Pubkey,
    ) !void {
        var epoch_stakes_map: EpochStakesMap = .empty;
        defer epoch_stakes_map.deinit(allocator);

        try epoch_stakes_map.ensureTotalCapacity(allocator, epoch_tracker.epochs.count());

        for (epoch_tracker.epochs.keys(), epoch_tracker.epochs.values()) |key, constants| {
            epoch_stakes_map.putAssumeCapacity(key, constants.stakes);
        }

        const newly_computed_slot_stats = try computeBankStats(
            allocator,
            self.logger,
            vote_account,
            ancestors,
            slot_tracker,
            &epoch_tracker.schedule,
            &epoch_stakes_map,
            progress_map,
            &self.fork_choice,
            &self.replay_tower,
            &self.latest_validator_votes,
        );
        defer allocator.free(newly_computed_slot_stats);

        for (newly_computed_slot_stats) |slot_stat| {
            const fork_stats = progress_map.getForkStats(slot_stat) orelse
                return error.MissingSlotInForkStats;
            // Analogous to [ReplayStage::tower_duplicate_confirmed_forks](https://github.com/anza-xyz/agave/blob/47c0383f2301e5a739543c1af9992ae182b7e06c/core/src/replay_stage.rs#L3928)
            var duplicate_confirmed_forks: std.ArrayListUnmanaged(SlotAndHash) = .empty;
            defer duplicate_confirmed_forks.deinit(allocator);
            try duplicate_confirmed_forks.ensureTotalCapacity(
                allocator,
                progress_map.map.count(),
            );
            for (progress_map.map.keys(), progress_map.map.values()) |slot, prog| {
                if (prog.fork_stats.duplicate_confirmed_hash != null) {
                    continue;
                }

                const slot_info = slot_tracker.get(slot) orelse
                    return error.MissingSlotInSlotTracker;
                if (!slot_info.state.isFrozen()) {
                    continue;
                }
                if (isDuplicateSlotConfirmed(
                    slot,
                    &fork_stats.voted_stakes,
                    fork_stats.total_stake,
                )) {
                    duplicate_confirmed_forks.appendAssumeCapacity(
                        .{
                            .slot = slot,
                            .hash = slot_info.state.hash.readCopy() orelse return error.MissingHash,
                        },
                    );
                }
            }

            // Analogous to [ReplayStage::mark_slots_duplicate_confirmed](https://github.com/anza-xyz/agave/blob/47c0383f2301e5a739543c1af9992ae182b7e06c/core/src/replay_stage.rs#L3876)
            const root_slot = slot_tracker.root;
            for (duplicate_confirmed_forks.items) |duplicate_confirmed_fork| {
                const slot, const frozen_hash = duplicate_confirmed_fork.tuple();
                try self.handleDuplicateConfirmedFork(
                    allocator,
                    progress_map,
                    root_slot,
                    slot,
                    frozen_hash,
                );
            }
        }

        const heaviest_slot = self.fork_choice.heaviestOverallSlot().slot;
        const heaviest_slot_on_same_voted_fork =
            (try self.fork_choice.heaviestSlotOnSameVotedFork(&self.replay_tower)) orelse null;

        const heaviest_epoch: Epoch = epoch_tracker.schedule.getEpoch(heaviest_slot);

        const now = sig.time.Instant.now();
        var last_vote_refresh_time: LastVoteRefreshTime = .{
            .last_refresh_time = now,
            .last_print_time = now,
        };

        var vote_and_reset_forks = try self.replay_tower.selectVoteAndResetForks(
            allocator,
            heaviest_slot,
            if (heaviest_slot_on_same_voted_fork) |h| h.slot else null,
            heaviest_epoch,
            ancestors,
            descendants,
            progress_map,
            &self.latest_validator_votes,
            &self.fork_choice,
            &epoch_stakes_map,
            account_reader,
        );
        defer vote_and_reset_forks.deinit(allocator);
        const maybe_voted_slot = vote_and_reset_forks.vote_slot;
        const maybe_reset_slot = vote_and_reset_forks.reset_slot;

        if (maybe_voted_slot == null) {
            _ = maybeRefreshLastVote(
                &self.replay_tower,
                progress_map,
                if (heaviest_slot_on_same_voted_fork) |h| h.slot else null,
                &last_vote_refresh_time,
            );
        }

        if (self.replay_tower.tower.isRecent(heaviest_slot) and
            vote_and_reset_forks.heaviest_fork_failures.items.len != 0)
        {
            // TODO Implemented the Self::log_heaviest_fork_failures
        }

        // Vote on the fork
        if (maybe_voted_slot) |voted| {
            const found_slot_info = slot_tracker.get(voted.slot) orelse
                return error.MissingSlot;

            const voted_hash = found_slot_info.state.hash.readCopy() orelse
                return error.MissingSlotInTracker;

            try handleVotableBank(
                allocator,
                self.ledger.resultWriter(),
                voted.slot,
                voted_hash,
                slot_tracker,
                &self.replay_tower,
                progress_map,
                &self.fork_choice,
            );
        }

        // Reset onto a fork
        if (maybe_reset_slot) |reset_slot| {
            // TODO implement
            _ = reset_slot;
        }
    }

    fn handleDuplicateConfirmedFork(
        self: *TowerConsensus,
        allocator: Allocator,
        progress_map: *const ProgressMap,
        root: Slot,
        slot: Slot,
        frozen_hash: Hash,
    ) !void {
        std.debug.assert(!frozen_hash.eql(Hash.ZEROES));
        if (slot <= root) return;

        var f_stats = progress_map.getForkStats(slot) orelse
            return error.MissingForkStats;
        f_stats.duplicate_confirmed_hash = frozen_hash;

        if (try self.slot_data.duplicate_confirmed_slots.fetchPut(
            allocator,
            slot,
            frozen_hash,
        )) |prev_entry| {
            std.debug.assert(prev_entry.value.eql(frozen_hash));
            // Already processed this signal
            return;
        }

        const duplicate_confirmed_state: DuplicateConfirmedState = .{
            .duplicate_confirmed_hash = frozen_hash,
            .slot_status = SlotStatus.fromHash(frozen_hash),
        };
        try check_slot_agrees_with_cluster.duplicateConfirmed(
            allocator,
            .noop,
            slot,
            root,
            self.ledger.resultWriter(),
            &self.fork_choice,
            &self.slot_data.duplicate_slots_to_repair,
            self.senders.ancestor_hashes_replay_update,
            &self.slot_data.purge_repair_slot_counter,
            duplicate_confirmed_state,
        );
    }
};

const LastVoteRefreshTime = struct {
    last_refresh_time: sig.time.Instant,
    last_print_time: sig.time.Instant,
};

/// Determines whether to refresh and submit an updated version of the last vote based on several conditions.
///
/// A vote refresh is performed when all of the following conditions are met:
/// 1. Validator Status:
///    - Not operating as a hotspare or non-voting validator
///    - Has attempted to vote at least once previously
/// 2. Fork Status:
///    - There exists a heaviest slot (`heaviest_slot_on_same_fork`) on our previously voted fork
///    - We've successfully landed at least one vote (`latest_landed_vote_slot`) on this fork
/// 3. Vote Progress:
///    - Our latest vote attempt (`last_vote_slot`) is still tracked in the progress map
///    - The latest landed vote is older than our last vote attempt (`latest_landed_vote_slot` < `last_vote_slot`)
/// 4. Block Progress:
///    - The heaviest bank is sufficiently ahead of our last vote (by at least `REFRESH_VOTE_BLOCKHEIGHT` blocks)
/// 5. Timing:
///    - At least `MAX_VOTE_REFRESH_INTERVAL_MILLIS` milliseconds have passed since last refresh attempt
///
/// If all conditions are satisfied:
/// - Creates a new vote transaction for the same slot (`last_vote_slot`) with:
///   * Current timestamp
///   * New blockhash from `heaviest_bank_on_same_fork`
///   * Fresh signature
/// - Submits this refreshed vote to the cluster
///
/// Returns:
/// - `true` if a refreshed vote was successfully created and submitted
/// - `false` if any condition was not met or the refresh failed
///
/// Note: This is not simply resending the same vote, but creating a new distinct transaction that:
/// - Votes for the same slot
/// - Contains updated metadata (timestamp/blockhash)
/// - Generates a new signature
/// - Will be processed as a separate transaction by the network
///
/// Analogous to [maybe_refresh_last_vote](https://github.com/anza-xyz/agave/blob/ccdcdbe9b6ff7dbd583d2101fe57b7cc41a6f863/core/src/replay_stage.rs#L2606)
fn maybeRefreshLastVote(
    replay_tower: *ReplayTower,
    progress: *const ProgressMap,
    maybe_heaviest_slot_on_same_fork: ?Slot,
    last_vote_refresh_time: *LastVoteRefreshTime,
) bool {
    const heaviest_bank_on_same_fork = maybe_heaviest_slot_on_same_fork orelse {
        // Only refresh if blocks have been built on our last vote
        return false;
    };

    // Need to land at least one vote in order to refresh
    const latest_landed_vote_slot = blk: {
        const fork_stat = progress.getForkStats(heaviest_bank_on_same_fork) orelse return false;
        break :blk fork_stat.my_latest_landed_vote orelse return false;
    };

    const last_voted_slot = replay_tower.lastVotedSlot() orelse {
        // Need to have voted in order to refresh
        return false;
    };

    // If our last landed vote on this fork is greater than the vote recorded in our tower
    // this means that our tower is old AND on chain adoption has failed. Warn the operator
    // as they could be submitting slashable votes.
    if (latest_landed_vote_slot > last_voted_slot and
        last_vote_refresh_time.last_print_time.elapsed().asSecs() >= 1)
    {
        last_vote_refresh_time.last_print_time = sig.time.Instant.now();
        // TODO log
    }

    if (latest_landed_vote_slot >= last_voted_slot) {
        // Our vote or a subsequent vote landed do not refresh
        return false;
    }

    const maybe_last_vote_tx_blockhash: ?Hash = switch (replay_tower.last_vote_tx_blockhash) {
        // Since the checks in vote generation are deterministic, if we were non voting or hot spare
        // on the original vote, the refresh will also fail. No reason to refresh.
        // On the fly adjustments via the cli will be picked up for the next vote.
        .non_voting, .hot_spare => return false,
        // In this case we have not voted since restart, our setup is unclear.
        // We have a vote from our previous restart that is eligible for refresh, we must refresh.
        .uninitialized => null,
        .blockhash => |blockhash| blockhash,
    };

    // TODO Need need a FIFO queue of `recent_blockhash` items
    // Add after transaction scheduling.
    if (maybe_last_vote_tx_blockhash) |last_vote_tx_blockhash| {
        // Check the blockhash queue to see if enough blocks have been built on our last voted fork
        _ = last_vote_tx_blockhash;
    }

    if (last_vote_refresh_time.last_refresh_time.elapsed().asMillis() <
        MAX_VOTE_REFRESH_INTERVAL_MILLIS)
    {
        // This avoids duplicate refresh in case there are multiple forks descending from our last voted fork
        // It also ensures that if the first refresh fails we will continue attempting to refresh at an interval no less
        // than MAX_VOTE_REFRESH_INTERVAL_MILLIS
        return false;
    }

    // All criteria are met, refresh the last vote using the blockhash of `heaviest_bank_on_same_fork`
    // Update timestamp for refreshed vote
    // AUDIT: Rest of code replaces Self::refresh_last_vote in Agave
    replay_tower.refreshLastVoteTimestamp(heaviest_bank_on_same_fork);

    // TODO Transaction generation to be implemented.
    // Currently hardcoding to non voting transaction.
    const vote_tx_result: GenerateVoteTxResult = .non_voting;

    return switch (vote_tx_result) {
        .tx => |_| {
            // TODO to be implemented
            return true;
        },
        .non_voting => {
            replay_tower.markLastVoteTxBlockhashNonVoting();
            return true;
        },
        .hot_spare => {
            replay_tower.markLastVoteTxBlockhashHotSpare();
            return false;
        },
        else => false,
    };
}

pub const AncestorHashesReplayUpdate = union(enum) {
    dead: Slot,
    dead_duplicate_confirmed: Slot,
    /// `Slot` belongs to a fork we have pruned. We have observed that this fork is "popular" aka
    /// reached 52+% stake through votes in turbine/gossip including votes for descendants. These
    /// votes are hash agnostic since we have not replayed `Slot` so we can never say for certainty
    /// that this fork has reached duplicate confirmation, but it is suspected to have. This
    /// indicates that there is most likely a block with invalid ancestry present and thus we
    /// collect an ancestor sample to resolve this issue. `Slot` is the deepest slot in this fork
    /// that is popular, so any duplicate problems will be for `Slot` or one of it's ancestors.
    popular_pruned_fork: Slot,
};

pub const GenerateVoteTxResult = union(enum) {
    // non voting validator, not eligible for refresh
    // until authorized keypair is overriden
    non_voting,
    // hot spare validator, not eligble for refresh
    // until set identity is invoked
    hot_spare,
    // failed generation, eligible for refresh
    fails,
    // TODO add Transaction
    tx: Transaction,
};

/// Handles a votable bank by recording the vote, update commitment cache,
/// potentially processing a new root, and pushing the vote.
///
/// Analogous to [handle_votable_bank](https://github.com/anza-xyz/agave/blob/ccdcdbe9b6ff7dbd583d2101fe57b7cc41a6f863/core/src/replay_stage.rs#L2388)
fn handleVotableBank(
    allocator: std.mem.Allocator,
    ledger_result_writer: Ledger.ResultWriter,
    vote_slot: Slot,
    vote_hash: Hash,
    slot_tracker: *SlotTracker,
    replay_tower: *ReplayTower,
    progress: *ProgressMap,
    fork_choice: *ForkChoice,
) !void {
    const maybe_new_root = try replay_tower.recordBankVote(
        allocator,
        vote_slot,
        vote_hash,
    );

    if (maybe_new_root) |new_root| {
        // TODO: consider returning this data from consensus and actually
        // handling the rooting in the caller
        try checkAndHandleNewRoot(
            allocator,
            ledger_result_writer,
            slot_tracker,
            progress,
            fork_choice,
            new_root,
        );
    }

    // TODO update_commitment_cache

    try pushVote(
        replay_tower,
    );
}

/// Pushes a new vote transaction to the network and updates tower state.
///
/// - Generates a new vote transaction.
/// - Updates the tower's last vote blockhash.
/// - Creates a saved tower state.
/// - Sends the vote operation to the voting sender.
///
/// Analogous to [push_vote](https://github.com/anza-xyz/agave/blob/ccdcdbe9b6ff7dbd583d2101fe57b7cc41a6f863/core/src/replay_stage.rs#L2775)
fn pushVote(
    replay_tower: *ReplayTower,
) !void {

    // TODO Transaction generation to be implemented.
    // Currently hardcoding to non voting transaction.
    const vote_tx_result: GenerateVoteTxResult = .non_voting;

    switch (vote_tx_result) {
        .tx => |vote_tx| {
            _ = vote_tx;
            // TODO to be implemented
        },
        .non_voting => {
            replay_tower.markLastVoteTxBlockhashNonVoting();
        },
        else => {
            // Do nothing
        },
    }
}

/// Processes a new root slot by updating various system components to reflect the new root.
///
/// - Validates the new root exists and has a hash.
/// - Gets all slots rooted at the new root.
/// - Updates ledger state with the new roots.
/// - Cleans up progress map for non-existent slots.
/// - Updates fork choice with the new root.
///
/// Analogous to [check_and_handle_new_root](https://github.com/anza-xyz/agave/blob/ccdcdbe9b6ff7dbd583d2101fe57b7cc41a6f863/core/src/replay_stage.rs#L4002)
fn checkAndHandleNewRoot(
    allocator: std.mem.Allocator,
    ledger: Ledger.ResultWriter,
    slot_tracker: *SlotTracker,
    progress: *ProgressMap,
    fork_choice: *ForkChoice,
    new_root: Slot,
) !void {
    // get the root bank before squash.
    if (slot_tracker.slots.count() == 0) return error.EmptySlotTracker;
    const root_tracker = slot_tracker.get(new_root) orelse return error.MissingSlot;
    const maybe_root_hash = root_tracker.state.hash.readCopy();
    const root_hash = maybe_root_hash orelse return error.MissingHash;

    const rooted_slots = try slot_tracker.parents(allocator, new_root);
    defer allocator.free(rooted_slots);

    try ledger.setRoots(rooted_slots);

    // Audit: The rest of the code maps to Self::handle_new_root in Agave.
    // Update the slot tracker.
    // Set new root.
    slot_tracker.root = new_root;
    // Prune non rooted slots
    slot_tracker.pruneNonRooted(allocator);

    // TODO
    // - Prune program cache bank_forks.read().unwrap().prune_program_cache(new_root);
    // - Extra operations as part of setting new root:
    //   - cleare reward cache root_bank.clear_epoch_rewards_cache
    //   - extend banks banks.extend(parents.iter());
    //   - operations around snapshot_controller
    //   - After setting a new root, prune the banks that are no longer on rooted paths self.prune_non_rooted(root, highest_super_majority_root);

    // Update the progress map.
    // Remove entries from the progress map no longer in the slot tracker.
    var progress_keys = progress.map.keys();
    var index: usize = 0;
    while (index < progress_keys.len) {
        const progress_slot = progress_keys[index];
        if (slot_tracker.get(progress_slot) == null) {
            const removed_value = progress.map.fetchSwapRemove(progress_slot) orelse continue;
            defer removed_value.value.deinit(allocator);
            progress_keys = progress.map.keys();
        } else {
            index += 1;
        }
    }

    // Update forkchoice
    try fork_choice.setTreeRoot(&.{
        .slot = new_root,
        .hash = root_hash,
    });
}

/// Analogous to https://github.com/anza-xyz/agave/blob/234afe489aa20a04a51b810213b945e297ef38c7/core/src/replay_stage.rs#L1029-L1118
///
/// Handle fork resets in specific circumstances:
/// - When a validator needs to switch to a different fork after voting on a fork that becomes invalid
/// - When a block producer needs to reset their fork choice after detecting a better fork
/// - When handling cases where the validator's current fork becomes less optimal than an alternative fork
///
/// TODO: Currently a placeholder function. Would be implemened when voting and producing blocks is supported.
fn resetFork(
    progress: *const ProgressMap,
    ledger: *const Ledger,
    reset_slot: Slot,
    last_reset_hash: Hash,
    last_blockhash: Hash,
    last_reset_bank_descendants: std.ArrayList(Slot),
) !void {
    _ = progress;
    _ = ledger;
    _ = reset_slot;
    _ = last_reset_hash;
    _ = last_blockhash;
    _ = last_reset_bank_descendants;
}

fn computeBankStats(
    allocator: std.mem.Allocator,
    logger: Logger,
    my_vote_pubkey: Pubkey,
    ancestors: *const std.AutoArrayHashMapUnmanaged(u64, Ancestors),
    slot_tracker: *SlotTracker,
    epoch_schedule: *const EpochSchedule,
    epoch_stakes_map: *const EpochStakesMap,
    progress: *ProgressMap,
    fork_choice: *ForkChoice,
    replay_tower: *const ReplayTower,
    latest_validator_votes: *LatestValidatorVotes,
) ![]Slot {
    var new_stats = std.ArrayListUnmanaged(Slot).empty;
    errdefer new_stats.deinit(allocator);

    var frozen_slots = try slot_tracker.frozenSlots(allocator);
    defer frozen_slots.deinit(allocator);
    // TODO agave sorts this by the slot first. Is this needed for the implementation to be correct?
    // If not, then we can avoid sorting here which may be verbose given frozen_slots is a map.
    for (frozen_slots.keys()) |slot| {
        const fork_stat = progress.getForkStats(slot) orelse return error.MissingSlot;
        if (!fork_stat.computed) {
            // TODO Self::adopt_on_chain_tower_if_behind
            // Gather voting information from all vote accounts to understand the current consensus state.
            const slot_info_for_stakes = slot_tracker.get(slot) orelse return error.MissingSlot;

            const computed_bank_state = blk: {
                const stakes, var stakes_lg =
                    slot_info_for_stakes.state.stakes_cache.stakes.readWithLock();
                defer stakes_lg.unlock();

                break :blk try collectVoteLockouts(
                    allocator,
                    .from(logger),
                    &my_vote_pubkey,
                    slot,
                    &stakes.vote_accounts.vote_accounts,
                    ancestors,
                    progress,
                    latest_validator_votes,
                );
            };

            try fork_choice.computeBankStats(
                allocator,
                epoch_stakes_map,
                epoch_schedule,
                latest_validator_votes,
            );
            const fork_stats = progress.getForkStats(slot) orelse return error.MissingForkStats;
            fork_stats.fork_stake = computed_bank_state.fork_stake;
            fork_stats.total_stake = computed_bank_state.total_stake;

            fork_stats.voted_stakes.deinit(allocator);
            fork_stats.voted_stakes = computed_bank_state.voted_stakes;

            fork_stats.lockout_intervals.deinit(allocator);
            fork_stats.lockout_intervals = computed_bank_state.lockout_intervals;

            fork_stats.block_height = blk: {
                const slot_info = slot_tracker.get(slot) orelse return error.MissingSlots;
                break :blk slot_info.constants.block_height;
            };
            fork_stats.my_latest_landed_vote = computed_bank_state.my_latest_landed_vote;
            fork_stats.computed = true;
            try new_stats.append(allocator, slot);
        }
        try cacheTowerStats(
            allocator,
            progress,
            replay_tower,
            slot,
            ancestors,
        );
    }
    return try new_stats.toOwnedSlice(allocator);
}

fn cacheTowerStats(
    allocator: std.mem.Allocator,
    progress: *ProgressMap,
    replay_tower: *const ReplayTower,
    slot: Slot,
    ancestors: *const std.AutoArrayHashMapUnmanaged(Slot, Ancestors),
) !void {
    const stats = progress.getForkStats(slot) orelse return error.MissingSlot;

    const slice = try replay_tower.checkVoteStakeThresholds(
        allocator,
        slot,
        &stats.voted_stakes,
        stats.total_stake,
    );
    // Free old vote_threshold before replacing it to avoid memory leak
    stats.vote_threshold.deinit(allocator);
    stats.vote_threshold = .fromOwnedSlice(slice);

    const slot_ancestors = ancestors.get(slot) orelse return error.MissingAncestor;

    stats.is_locked_out = try replay_tower.tower.isLockedOut(slot, &slot_ancestors);
    stats.has_voted = replay_tower.tower.hasVoted(slot);
    stats.is_recent = replay_tower.tower.isRecent(slot);
}

const testing = std.testing;
const TreeNode = sig.consensus.fork_choice.TreeNode;
const testEpochStakes = sig.consensus.fork_choice.testEpochStakes;
const TestFixture = sig.consensus.replay_tower.TestFixture;
const MAX_TEST_TREE_LEN = sig.consensus.replay_tower.MAX_TEST_TREE_LEN;
const Lockout = sig.runtime.program.vote.state.Lockout;
const MAX_LOCKOUT_HISTORY = sig.consensus.tower.MAX_LOCKOUT_HISTORY;

const createTestReplayTower = sig.consensus.replay_tower.createTestReplayTower;

test "processResult and handleDuplicateConfirmedFork" {
    // TODO add assertions to this test
    const allocator = std.testing.allocator;

    var stubs = try replay.service.DependencyStubs.init(allocator, .FOR_TESTS);
    defer stubs.deinit(allocator);

    var service = try stubs.stubbedService(allocator, .FOR_TESTS, false);
    defer service.deinit(allocator);

    const consensus = &service.consensus.?;
    {
        const slot_tracker, var slock = service.replay.slot_tracker.writeWithLock();
        defer slock.unlock();

        slot_tracker.get(0).?.state.hash.set(.{ .data = @splat(1) });
    }

    {
        const slot_tracker, var slock = service.replay.slot_tracker.readWithLock();
        defer slock.unlock();

        try consensus.processResult(
            allocator,
            &service.replay.progress_map,
            slot_tracker,
            .{
                .slot = 0,
                .output = .{ .last_entry_hash = .ZEROES },
            },
        );
    }

    const stats = service.replay.progress_map.map.get(0).?;
    try service.replay.progress_map.map.put(allocator, 1, stats);

    const slot_hash = SlotAndHash{
        .slot = 1,
        .hash = .parse("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"),
    };
    const children = sig.utils.collections.SortedMap(SlotAndHash, void).init(allocator);
    defer children.deinit();

    try consensus.fork_choice.fork_infos.put(slot_hash, .{
        .logger = .FOR_TESTS,
        .stake_for_slot = 0,
        .stake_for_subtree = 0,
        .height = 0,
        .heaviest_subtree_slot = slot_hash,
        .deepest_slot = slot_hash,
        .parent = null,
        .children = children,
        .latest_duplicate_ancestor = null,
        .is_duplicate_confirmed = false,
    });

    try consensus.handleDuplicateConfirmedFork(
        allocator,
        &service.replay.progress_map,
        0,
        1,
        .{ .data = @splat(1) },
    );
}

test "cacheTowerStats - missing ancestor" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    // Ensure the slot exists in the progress map so cacheTowerStats
    // progresses far enough to check ancestors.
    const trees = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    try fixture.fillFork(
        testing.allocator,
        .{ .root = root, .data = trees },
        .active,
    );

    // Provide an empty ancestors map so the slot has no recorded ancestors entry
    // and cacheTowerStats should return error.MissingAncestor.
    var empty_ancestors: std.AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;

    const result = cacheTowerStats(
        testing.allocator,
        &fixture.progress,
        &replay_tower,
        root.slot,
        &empty_ancestors,
    );

    try testing.expectError(error.MissingAncestor, result);
}

test "cacheTowerStats - missing slot" {
    var prng = std.Random.DefaultPrng.init(92);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    // Do not populate progress for root.slot; ensure getForkStats returns null.
    const empty_ancestors: std.AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;

    const result = cacheTowerStats(
        testing.allocator,
        &fixture.progress,
        &replay_tower,
        root.slot,
        &empty_ancestors,
    );

    try testing.expectError(error.MissingSlot, result);
}

test "cacheTowerStats - success sets flags and empty thresholds" {
    var prng = std.Random.DefaultPrng.init(93);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    // Ensure slot exists in progress and ancestors are populated for the root
    const trees = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    try fixture.fillFork(
        testing.allocator,
        .{ .root = root, .data = trees },
        .active,
    );

    var replay_tower = try createTestReplayTower(10, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    try cacheTowerStats(
        testing.allocator,
        &fixture.progress,
        &replay_tower,
        root.slot,
        &fixture.ancestors,
    );

    const stats = fixture.progress.getForkStats(root.slot).?;
    try testing.expectEqual(0, stats.vote_threshold.items.len);
    try testing.expectEqual(false, stats.is_locked_out);
    try testing.expectEqual(false, stats.has_voted);
    try testing.expectEqual(true, stats.is_recent);
}

test "cacheTowerStats - records failed threshold at depth 0" {
    var prng = std.Random.DefaultPrng.init(94);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    // Ensure slot exists in progress and ancestors populated
    const trees = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    try fixture.fillFork(
        testing.allocator,
        .{ .root = root, .data = trees },
        .active,
    );

    // Configure threshold_depth = 0 so the new vote is checked at depth 0,
    // and leave voted_stakes empty so the threshold check fails.
    var replay_tower = try createTestReplayTower(0, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    try cacheTowerStats(
        testing.allocator,
        &fixture.progress,
        &replay_tower,
        root.slot,
        &fixture.ancestors,
    );

    const stats = fixture.progress.getForkStats(root.slot).?;
    try testing.expectEqual(1, stats.vote_threshold.items.len);
    const t = stats.vote_threshold.items[0];
    try testing.expect(t == .failed_threshold);
    try testing.expectEqual(0, t.failed_threshold.vote_depth);
    try testing.expectEqual(false, stats.is_locked_out);
    try testing.expectEqual(false, stats.has_voted);
    try testing.expectEqual(true, stats.is_recent);
}

test "maybeRefreshLastVote - no heaviest slot on same fork" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    defer replay_tower.deinit(std.testing.allocator);

    const now = sig.time.Instant.now();
    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = now,
        .last_print_time = now,
    };

    const result = sig.replay.consensus.core.maybeRefreshLastVote(
        &replay_tower,
        &fixture.progress,
        null,
        &last_vote_refresh_time,
    );

    try testing.expectEqual(false, result);
}

test "maybeRefreshLastVote - no landed vote" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    defer replay_tower.deinit(std.testing.allocator);

    const now = sig.time.Instant.now();
    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = now,
        .last_print_time = now,
    };

    // not vote in progress map.
    try testing.expectEqual(0, fixture.progress.map.count());
    const result = sig.replay.consensus.core.maybeRefreshLastVote(
        &replay_tower,
        &fixture.progress,
        10, // Not in progress map.
        &last_vote_refresh_time,
    );

    try testing.expectEqual(false, result);
}

test "maybeRefreshLastVote - latest landed vote newer than last vote" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };
    const hash3 = SlotAndHash{
        .slot = 3,
        .hash = Hash.initRandom(random),
    };
    const hash2 = SlotAndHash{
        .slot = 2,
        .hash = Hash.initRandom(random),
    };
    const hash1 = SlotAndHash{
        .slot = 1,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[3]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
        .{ hash3, hash2 },
    });

    try fixture.fillFork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = .fromOwnedSlice(try std.testing.allocator.dupe(Lockout, &.{
                .{ .slot = 3, .confirmation_count = 3 },
                .{ .slot = 4, .confirmation_count = 2 },
                .{ .slot = 5, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    const now = sig.time.Instant.now();
    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = now,
        .last_print_time = now,
    };

    const result = sig.replay.consensus.core.maybeRefreshLastVote(
        &replay_tower,
        &fixture.progress,
        hash3.slot,
        &last_vote_refresh_time,
    );

    try testing.expectEqual(false, result);
}

test "maybeRefreshLastVote - non voting validator" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };
    const hash3 = SlotAndHash{
        .slot = 3,
        .hash = Hash.initRandom(random),
    };
    const hash2 = SlotAndHash{
        .slot = 2,
        .hash = Hash.initRandom(random),
    };
    const hash1 = SlotAndHash{
        .slot = 1,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[3]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
        .{ hash3, hash2 },
    });

    try fixture.fillFork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = .fromOwnedSlice(try std.testing.allocator.dupe(Lockout, &.{
                .{ .slot = 3, .confirmation_count = 3 },
                .{ .slot = 4, .confirmation_count = 2 },
                .{ .slot = 5, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    replay_tower.last_vote_tx_blockhash = .non_voting;

    const now = sig.time.Instant.now();
    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = now,
        .last_print_time = now,
    };

    const result = sig.replay.consensus.core.maybeRefreshLastVote(
        &replay_tower,
        &fixture.progress,
        hash3.slot,
        &last_vote_refresh_time,
    );

    try testing.expectEqual(false, result);
}

test "maybeRefreshLastVote - hotspare validator" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };
    const hash3 = SlotAndHash{
        .slot = 3,
        .hash = Hash.initRandom(random),
    };
    const hash2 = SlotAndHash{
        .slot = 2,
        .hash = Hash.initRandom(random),
    };
    const hash1 = SlotAndHash{
        .slot = 1,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[3]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
        .{ hash3, hash2 },
    });

    try fixture.fillFork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = .fromOwnedSlice(try std.testing.allocator.dupe(Lockout, &.{
                .{ .slot = 3, .confirmation_count = 3 },
                .{ .slot = 4, .confirmation_count = 2 },
                .{ .slot = 5, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    replay_tower.last_vote_tx_blockhash = .hot_spare;

    const now = sig.time.Instant.now();
    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = now,
        .last_print_time = now,
    };

    const result = sig.replay.consensus.core.maybeRefreshLastVote(
        &replay_tower,
        &fixture.progress,
        hash3.slot,
        &last_vote_refresh_time,
    );

    try testing.expectEqual(false, result);
}

test "maybeRefreshLastVote - refresh interval not elapsed" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };
    const hash3 = SlotAndHash{
        .slot = 3,
        .hash = Hash.initRandom(random),
    };
    const hash2 = SlotAndHash{
        .slot = 2,
        .hash = Hash.initRandom(random),
    };
    const hash1 = SlotAndHash{
        .slot = 1,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[3]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
        .{ hash3, hash2 },
    });

    try fixture.fillFork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = .fromOwnedSlice(try std.testing.allocator.dupe(Lockout, &.{
                .{ .slot = 3, .confirmation_count = 3 },
                .{ .slot = 4, .confirmation_count = 2 },
                .{ .slot = 5, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    replay_tower.last_vote_tx_blockhash = .{ .blockhash = Hash.ZEROES };

    const now = sig.time.Instant.now();
    var last_vote_refresh_time: LastVoteRefreshTime = .{
        // Will last_vote_refresh_time.last_refresh_time.elapsed().asMillis() as zero
        // thereby satisfying the test condition of that value being
        // less than MAX_VOTE_REFRESH_INTERVAL_MILLIS
        .last_refresh_time = now,
        .last_print_time = now,
    };

    const result = sig.replay.consensus.core.maybeRefreshLastVote(
        &replay_tower,
        &fixture.progress,
        hash3.slot,
        &last_vote_refresh_time,
    );

    try testing.expectEqual(false, result);
}

test "maybeRefreshLastVote - successfully refreshed and mark last_vote_tx_blockhash as non voting" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const hash3 = SlotAndHash{
        .slot = 3,
        .hash = Hash.initRandom(random),
    };
    const hash2 = SlotAndHash{
        .slot = 2,
        .hash = Hash.initRandom(random),
    };
    const hash1 = SlotAndHash{
        .slot = 1,
        .hash = Hash.initRandom(random),
    };
    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[3]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
        .{ hash3, hash2 },
    });

    try fixture.fillFork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    // Update fork stat
    if (fixture.progress.getForkStats(hash3.slot)) |fork_stat| {
        fork_stat.*.my_latest_landed_vote = hash2.slot;
    }

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    defer replay_tower.deinit(std.testing.allocator);

    replay_tower.last_vote = sig.consensus.vote_transaction.VoteTransaction{
        .tower_sync = sig.runtime.program.vote.state.TowerSync{
            .lockouts = .fromOwnedSlice(try std.testing.allocator.dupe(Lockout, &.{
                .{ .slot = 3, .confirmation_count = 3 },
                .{ .slot = 4, .confirmation_count = 2 },
                .{ .slot = 5, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    replay_tower.last_vote_tx_blockhash = .{ .blockhash = Hash.ZEROES };

    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = sig.time.Instant.now().sub(
            sig.time.Duration.fromMillis(MAX_VOTE_REFRESH_INTERVAL_MILLIS),
        ),
        .last_print_time = sig.time.Instant.now(),
    };

    const result = sig.replay.consensus.core.maybeRefreshLastVote(
        &replay_tower,
        &fixture.progress,
        hash3.slot,
        &last_vote_refresh_time,
    );

    try testing.expectEqual(true, result);
    try testing.expectEqual(.non_voting, replay_tower.last_vote_tx_blockhash);
}

test "checkAndHandleNewRoot - missing slot" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    // Build a tracked slot set wrapped in RwMux
    const slot_tracker_val: SlotTracker = SlotTracker{ .root = root.slot, .slots = .{} };
    var slot_tracker = RwMux(SlotTracker).init(slot_tracker_val);
    defer {
        const ptr, var lg = slot_tracker.writeWithLock();
        defer lg.unlock();
        ptr.deinit(testing.allocator);
    }

    {
        const constants = try SlotConstants.genesis(testing.allocator, .initRandom(random));
        errdefer constants.deinit(testing.allocator);
        var state = try SlotState.genesis(testing.allocator);
        errdefer state.deinit(testing.allocator);
        const ptr, var lg = slot_tracker.writeWithLock();
        defer lg.unlock();
        try ptr.put(testing.allocator, root.slot, .{
            .constants = constants,
            .state = state,
        });
    }

    const logger = .noop;
    var registry = sig.prometheus.Registry(.{}).init(testing.allocator);
    defer registry.deinit();

    var test_state = try sig.ledger.tests.initTestLedger(testing.allocator, @src(), logger);
    defer test_state.deinit();

    // Try to check a slot that doesn't exist in the tracker
    const slot_tracker_ptr, var slot_tracker_lg = slot_tracker.writeWithLock();
    defer slot_tracker_lg.unlock();
    const result = checkAndHandleNewRoot(
        testing.allocator,
        test_state.resultWriter(),
        slot_tracker_ptr,
        &fixture.progress,
        &fixture.fork_choice,
        123, // Non-existent slot
    );

    try testing.expectError(error.MissingSlot, result);
}

test "checkAndHandleNewRoot - missing hash" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    const slot_tracker_val2: SlotTracker = SlotTracker{ .root = root.slot, .slots = .{} };
    var slot_tracker2 = RwMux(SlotTracker).init(slot_tracker_val2);
    defer {
        const ptr, var lg = slot_tracker2.writeWithLock();
        defer lg.unlock();
        ptr.deinit(testing.allocator);
    }
    {
        const constants = try SlotConstants.genesis(testing.allocator, .initRandom(random));
        errdefer constants.deinit(testing.allocator);
        var state = try SlotState.genesis(testing.allocator);
        errdefer state.deinit(testing.allocator);
        const ptr, var lg = slot_tracker2.writeWithLock();
        defer lg.unlock();
        try ptr.put(testing.allocator, root.slot, .{
            .constants = constants,
            .state = state,
        });
    }

    const logger = .noop;
    var registry = sig.prometheus.Registry(.{}).init(testing.allocator);
    defer registry.deinit();

    var test_state = try sig.ledger.tests.initTestLedger(testing.allocator, @src(), logger);
    defer test_state.deinit();

    // Try to check a slot that doesn't exist in the tracker
    const slot_tracker2_ptr, var slot_tracker2_lg = slot_tracker2.writeWithLock();
    defer slot_tracker2_lg.unlock();
    const result = checkAndHandleNewRoot(
        testing.allocator,
        test_state.resultWriter(),
        slot_tracker2_ptr,
        &fixture.progress,
        &fixture.fork_choice,
        root.slot, // Non-existent hash
    );

    try testing.expectError(error.MissingHash, result);
}

test "checkAndHandleNewRoot - empty slot tracker" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    const slot_tracker_val3: SlotTracker = SlotTracker{ .root = root.slot, .slots = .{} };
    var slot_tracker3 = RwMux(SlotTracker).init(slot_tracker_val3);
    defer {
        const ptr, var lg = slot_tracker3.writeWithLock();
        defer lg.unlock();
        ptr.deinit(testing.allocator);
    }
    const logger = .noop;
    var registry = sig.prometheus.Registry(.{}).init(testing.allocator);
    defer registry.deinit();

    var test_state = try sig.ledger.tests.initTestLedger(testing.allocator, @src(), logger);
    defer test_state.deinit();

    // Try to check a slot that doesn't exist in the tracker
    const slot_tracker3_ptr, var slot_tracker3_lg = slot_tracker3.writeWithLock();
    defer slot_tracker3_lg.unlock();
    const result = checkAndHandleNewRoot(
        testing.allocator,
        test_state.resultWriter(),
        slot_tracker3_ptr,
        &fixture.progress,
        &fixture.fork_choice,
        root.slot,
    );

    try testing.expectError(error.EmptySlotTracker, result);
}

test "checkAndHandleNewRoot - success" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    const hash3 = SlotAndHash{
        .slot = 3,
        .hash = Hash.initRandom(random),
    };
    const hash2 = SlotAndHash{
        .slot = 2,
        .hash = Hash.initRandom(random),
    };
    const hash1 = SlotAndHash{
        .slot = 1,
        .hash = Hash.initRandom(random),
    };
    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    const slot_tracker_val4: SlotTracker = SlotTracker{ .root = root.slot, .slots = .{} };
    var slot_tracker4 = RwMux(SlotTracker).init(slot_tracker_val4);
    defer {
        const ptr, var lg = slot_tracker4.writeWithLock();
        defer lg.unlock();
        ptr.deinit(testing.allocator);
    }

    {
        var constants2 = try SlotConstants.genesis(testing.allocator, .initRandom(random));
        errdefer constants2.deinit(testing.allocator);
        var constants3 = try SlotConstants.genesis(testing.allocator, .initRandom(random));
        errdefer constants3.deinit(testing.allocator);
        var state2 = try SlotState.genesis(testing.allocator);
        errdefer state2.deinit(testing.allocator);
        var state3 = try SlotState.genesis(testing.allocator);
        errdefer state3.deinit(testing.allocator);
        constants2.parent_slot = hash1.slot;
        constants3.parent_slot = hash2.slot;
        state2.hash = .init(hash2.hash);
        state3.hash = .init(hash3.hash);
        const ptr, var lg = slot_tracker4.writeWithLock();
        defer lg.unlock();
        try ptr.put(testing.allocator, hash2.slot, .{
            .constants = constants2,
            .state = state2,
        });
        try ptr.put(testing.allocator, hash3.slot, .{
            .constants = constants3,
            .state = state3,
        });
    }

    // Add some entries to progress map that should be removed
    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[3]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
        .{ hash3, hash2 },
    });

    try fixture.fillFork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    var registry = sig.prometheus.Registry(.{}).init(testing.allocator);
    defer registry.deinit();

    var test_state = try sig.ledger.tests.initTestLedger(testing.allocator, @src(), .noop);
    defer test_state.deinit();

    try testing.expectEqual(4, fixture.progress.map.count());
    try testing.expect(fixture.progress.map.contains(hash1.slot));
    {
        const slot_tracker4_ptr, var slot_tracker4_lg = slot_tracker4.writeWithLock();
        defer slot_tracker4_lg.unlock();
        try checkAndHandleNewRoot(
            testing.allocator,
            test_state.resultWriter(),
            slot_tracker4_ptr,
            &fixture.progress,
            &fixture.fork_choice,
            hash3.slot,
        );
    }

    try testing.expectEqual(1, fixture.progress.map.count());
    // Now the write lock is released, we can acquire a read lock
    {
        const ptr, var lg = slot_tracker4.readWithLock();
        defer lg.unlock();
        for (ptr.slots.keys()) |remaining_slots| {
            try testing.expect(remaining_slots >= hash3.slot);
        }
    }
    try testing.expect(!fixture.progress.map.contains(hash1.slot));
}

test "computeBankStats - child bank heavier" {
    var prng = std.Random.DefaultPrng.init(91);
    const random = prng.random();

    // Set up slots and hashes for the fork tree: 0 -> 1 -> 2
    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    const hash1 = SlotAndHash{ .slot = 1, .hash = Hash.initRandom(random) };
    const hash2 = SlotAndHash{ .slot = 2, .hash = Hash.initRandom(random) };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    try fixture.fill_keys(testing.allocator, random, 1);

    // Create the tree of banks in a BankForks object
    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[2]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
    });
    try fixture.fillFork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    const my_node_pubkey = fixture.node_pubkeys.items[0];
    const votes = [_]u64{2};
    for (votes) |vote| {
        _ = vote;
        // const result = fixture.simulate_vote(vote, my_vote_pubkey, &fixture.tower);
        // try testing.expectEqual(@as(usize, 0), result.len);
    }

    var frozen_slots = try fixture.slot_tracker.frozenSlots(
        testing.allocator,
    );
    defer frozen_slots.deinit(testing.allocator);
    errdefer frozen_slots.deinit(testing.allocator);

    // TODO move this into fixture?
    const versioned_stakes = try testEpochStakes(
        testing.allocator,
        fixture.vote_pubkeys.items,
        10000,
        random,
    );
    defer versioned_stakes.deinit(testing.allocator);

    const keys = versioned_stakes.stakes.vote_accounts.vote_accounts.keys();
    for (keys) |key| {
        var vote_account = versioned_stakes.stakes.vote_accounts.vote_accounts.getPtr(key).?;
        const LandedVote = sig.runtime.program.vote.state.LandedVote;
        try vote_account.account.state.votes.append(LandedVote{
            .latency = 0,
            .lockout = Lockout{
                .slot = 1,
                .confirmation_count = 4,
            },
        });
    }

    var epoch_stakes = EpochStakesMap.empty;
    defer epoch_stakes.deinit(testing.allocator);
    try epoch_stakes.put(testing.allocator, 0, versioned_stakes);

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    const epoch_schedule = EpochSchedule.DEFAULT;
    var slot_tracker_rw1 = RwMux(SlotTracker).init(fixture.slot_tracker);
    const slot_tracker_rw1_ptr, var slot_tracker_rw1_lg = slot_tracker_rw1.writeWithLock();
    defer slot_tracker_rw1_lg.unlock();
    const newly_computed_slot_stats = try computeBankStats(
        testing.allocator,
        .noop,
        my_node_pubkey,
        &fixture.ancestors,
        slot_tracker_rw1_ptr,
        &epoch_schedule,
        &epoch_stakes,
        &fixture.progress,
        &fixture.fork_choice,
        &replay_tower,
        &fixture.latest_validator_votes_for_frozen_banks,
    );
    defer testing.allocator.free(newly_computed_slot_stats);

    // Sort frozen slots by slot number
    const slot_list = try testing.allocator.alloc(u64, frozen_slots.count());
    defer testing.allocator.free(slot_list);
    var i: usize = 0;
    for (frozen_slots.keys()) |slot| {
        slot_list[i] = slot;
        i += 1;
    }
    std.mem.sort(u64, slot_list, {}, std.sort.asc(u64));

    // Check that fork weights are non-decreasing
    for (slot_list, 0..) |_, idx| {
        if (idx + 1 < slot_list.len) {
            const first = fixture.progress.getForkStats(slot_list[idx]) orelse
                return error.MissingForkStats;
            const second = fixture.progress.getForkStats(slot_list[idx + 1]) orelse
                return error.MissingForkStats;
            try testing.expect(second.fork_stake >= first.fork_stake);
        }
    }

    // Check that the heaviest slot is always the leaf (slot 3)
    for (slot_list) |slot| {
        const slot_info = fixture.slot_tracker.get(slot) orelse
            return error.MissingSlot;
        const best = fixture.fork_choice.heaviestSlot(
            .{ .slot = slot, .hash = slot_info.state.hash.readCopy().? },
        ) orelse
            return error.MissingSlot;
        try testing.expectEqual(2, best.slot);
    }
}

test "computeBankStats - same weight selects lower slot" {
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();

    // Set up slots and hashes for the fork tree: 0 -> 1, 0 -> 2
    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    const hash1 = SlotAndHash{ .slot = 1, .hash = Hash.initRandom(random) };
    const hash2 = SlotAndHash{ .slot = 2, .hash = Hash.initRandom(random) };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    try fixture.fill_keys(testing.allocator, random, 1);
    const my_vote_pubkey = fixture.vote_pubkeys.items[0];

    // Create the tree: root -> 1, root -> 2
    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[_]TreeNode{
        .{ hash1, root },
        .{ hash2, root },
    });
    try fixture.fillFork(
        testing.allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    const versioned_stakes = try testEpochStakes(
        testing.allocator,
        fixture.vote_pubkeys.items,
        10000,
        random,
    );
    defer versioned_stakes.deinit(testing.allocator);

    var epoch_stakes = EpochStakesMap.empty;
    defer epoch_stakes.deinit(testing.allocator);
    try epoch_stakes.put(testing.allocator, 0, versioned_stakes);
    try epoch_stakes.put(testing.allocator, 1, versioned_stakes);

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );

    const epoch_schedule = EpochSchedule.DEFAULT;
    var slot_tracker_rw2 = RwMux(SlotTracker).init(fixture.slot_tracker);
    const slot_tracker_rw2_ptr, var slot_tracker_rw2_lg = slot_tracker_rw2.writeWithLock();
    defer slot_tracker_rw2_lg.unlock();
    const newly_computed_slot_stats = try computeBankStats(
        testing.allocator,
        .noop,
        my_vote_pubkey,
        &fixture.ancestors,
        slot_tracker_rw2_ptr,
        &epoch_schedule,
        &epoch_stakes,
        &fixture.progress,
        &fixture.fork_choice,
        &replay_tower,
        &fixture.latest_validator_votes_for_frozen_banks,
    );
    defer testing.allocator.free(newly_computed_slot_stats);

    // Check that stake for slot 1 and slot 2 is equal
    const bank1 = fixture.slot_tracker.get(1).?;
    const bank2 = fixture.slot_tracker.get(2).?;

    const stake1 = fixture.fork_choice.stakeForSubtree(
        &.{ .slot = 1, .hash = bank1.state.hash.readCopy().? },
    ).?;
    const stake2 = fixture.fork_choice.stakeForSubtree(
        &.{ .slot = 2, .hash = bank2.state.hash.readCopy().? },
    ).?;
    try testing.expectEqual(stake1, stake2);

    // Select the heaviest bank
    const heaviest = fixture.fork_choice.heaviestOverallSlot();
    // Should pick the lower of the two equally weighted banks
    try testing.expectEqual(@as(u64, 1), heaviest.slot);
}

// TODO: Re-implement tests for the new consolidated API

// ====================== "Component" tests================================== //
// Does it make sense to come up with a lib/harness like tool that allows:
//
// Have a test fixture state that can easily be mutated prior to calling consensus.process
// ie:
// test_fixture.setRoot(...)
// test_fixture.setFroozenRoot(...)
// test_fixture.updateSlotTracker(...)
// test_fixture.updateSProgress(...)
// etc
//
// the idea is to have easy methods to setup the state.
// ...
//
// Then executed the test:
//
// consensus.process(alloc, test_fixture.slot_tracker_rw, test_fixture.epoch_tracker_rw etc)
//
// Then assert:
//
// assert test_fixture

// State setup
// - Set root
//   - Set slot constants
//   - Set slot states
//   - freeze root
//      - set blockhash queue on root state
//
// - Set slot tracker
// - Do above for slot 1
//
// - Set up the epoch tracker
//   - with empty/genesis state
// - Set up the progress map
test "vote on heaviest frozen descendant with no switch" {
    const allocator = std.testing.allocator;

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit(allocator);

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state = try sig.core.SlotState.genesis(allocator);

    // Freeze root.
    root_state.hash.set(Hash.ZEROES);
    {
        var bhq = root_state.blockhash_queue.write();
        defer bhq.unlock();
        try bhq.mut().insertGenesisHash(allocator, root_state.hash.readCopy().?, 0);
    }

    var slot_tracker = try SlotTracker.init(
        allocator,
        root_slot,
        .{
            .constants = root_consts,
            .state = root_state,
        },
    );
    defer slot_tracker.deinit(allocator);

    // Add frozen descendant slot 1
    const slot_1: u64 = 1;
    const slot1_hash = Hash{ .data = .{slot_1} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = root_slot;
        slot_constants.parent_hash = root_state.hash.readCopy().?;
        slot_constants.block_height = 1;

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash = .init(slot1_hash);

        try slot_tracker.put(
            allocator,
            slot_1,
            .{
                .constants = slot_constants,
                .state = slot_state,
            },
        );
    }

    var slot_tracker_rw = RwMux(SlotTracker).init(slot_tracker);

    var epoch_tracker: EpochTracker = .{
        .epochs = .empty,
        .schedule = sig.core.EpochSchedule.DEFAULT,
    };
    {
        const epoch_consts = try sig.core.EpochConstants.genesis(allocator, .default(allocator));
        errdefer epoch_consts.deinit(allocator);
        try epoch_tracker.epochs.put(allocator, root_slot, epoch_consts);
    }
    defer epoch_tracker.deinit(allocator);
    var epoch_tracker_rw = RwMux(EpochTracker).init(epoch_tracker);

    // Add root and slot 1 entries into progress map.
    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);
    {
        var fork_progress0 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fork_progress0.fork_stats.computed = true;
        const fork_progress1 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        try progress.map.put(allocator, root_slot, fork_progress0);
        try progress.map.put(allocator, slot_1, fork_progress1);
    }

    // Include a ReplayResult for slot 1 to drive processResult/fork-choice
    const results = [_]ReplayResult{
        .{
            .slot = slot_1,
            .output = .{
                .last_entry_hash = Hash{ .data = .{9} ** Hash.SIZE },
            },
        },
    };

    var replay_votes_channel = try Channel(ParsedVote).create(allocator);
    defer replay_votes_channel.destroy();

    const external = TowerConsensus.Dependencies.External{
        .senders = stubs.senders,
        .receivers = stubs.receivers,
        .gossip_table = null,
        .run_vote_listener = false,
    };

    // Build consensus dependencies
    const deps = TowerConsensus.Dependencies{
        .logger = .noop,
        .my_identity = Pubkey.initRandom(std.crypto.random),
        .vote_identity = Pubkey.initRandom(std.crypto.random),
        .root_slot = root_slot,
        .root_hash = root_state.hash.readCopy().?,
        .account_reader = stubs.accountsdb.accountReader(),
        .ledger = &stubs.ledger,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    try std.testing.expectEqual(null, consensus.replay_tower.lastVotedSlot());
    try std.testing.expectEqual(false, progress.getForkStats(slot_1).?.computed);
    try std.testing.expectEqual(0, progress.getForkStats(1).?.block_height);
    try std.testing.expectEqual(.uninitialized, consensus.replay_tower.last_vote_tx_blockhash);

    // Component entry point being tested
    try consensus.process(
        allocator,
        &slot_tracker_rw,
        &epoch_tracker_rw,
        &progress,
        &results,
    );

    // 1. Assert fork stat in progress map
    const stats1 = progress.getForkStats(slot_1).?;
    try std.testing.expectEqual(0, stats1.fork_stake);
    try std.testing.expectEqual(0, stats1.total_stake);
    try std.testing.expectEqual(1, stats1.block_height);
    try std.testing.expectEqual(slot1_hash, stats1.slot_hash);
    try std.testing.expectEqual(true, stats1.computed);
    // Check voted_stakes
    try std.testing.expect(stats1.voted_stakes.count() == 0);
    // Verify my_latest_landed_vote
    // It should be null (vote hasn't landed on-chain yet)
    try std.testing.expectEqual(null, stats1.my_latest_landed_vote);

    // 2. Assert the replay tower
    try std.testing.expectEqual(slot_1, consensus.replay_tower.lastVotedSlot());
    // Check that root has not changed (no vote is old enough to advance root)
    try std.testing.expectEqual(root_slot, consensus.replay_tower.tower.vote_state.root_slot.?);
    try std.testing.expectEqual(.non_voting, consensus.replay_tower.last_vote_tx_blockhash);

    // 3. Check lockout intervals.
    try std.testing.expect(stats1.lockout_intervals.map.count() == 0);

    // 4. Check propagated stats in progress map
    // Not propagated in minimal test
    const prop_stats = progress.getPropagatedStats(slot_1).?;
    try std.testing.expectEqual(false, prop_stats.is_propagated);

    // 5. Assert forkchoice
    try std.testing.expectEqual(slot_1, consensus.fork_choice.heaviestOverallSlot().slot);
    try std.testing.expectEqual(slot1_hash, consensus.fork_choice.heaviestOverallSlot().hash);
}

// State setup
// - Set root
//   - Set slot constants
//   - Set slot states
//   - freeze root
//      - set blockhash queue on root state
//
// - Set slot tracker
// - Do above for slot 1
//
// - Set up the epoch tracker
//   - non-empty
// - Set up the progress map
test "vote accounts with landed votes populate bank stats" {
    const allocator = std.testing.allocator;

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit(allocator);

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state = try sig.core.SlotState.genesis(allocator);

    // Freeze root.
    root_state.hash.set(Hash.ZEROES);
    {
        var bhq = root_state.blockhash_queue.write();
        defer bhq.unlock();
        try bhq.mut().insertGenesisHash(allocator, root_state.hash.readCopy().?, 0);
    }

    var slot_tracker = try SlotTracker.init(
        allocator,
        root_slot,
        .{
            .constants = root_consts,
            .state = root_state,
        },
    );
    defer slot_tracker.deinit(allocator);

    // Add frozen descendant slot 1
    const slot_1: u64 = 1;
    const slot1_hash = Hash{ .data = .{2} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = root_slot;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 1;

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash = .init(slot1_hash);

        try slot_tracker.put(
            allocator,
            slot_1,
            .{ .constants = slot_constants, .state = slot_state },
        );
    }

    var slot_tracker_rw = RwMux(SlotTracker).init(slot_tracker);

    var epoch_tracker: EpochTracker = .{
        .epochs = .empty,
        .schedule = sig.core.EpochSchedule.DEFAULT,
    };

    // NOTE: The core setup for this test
    // Seed epoch 0 constants with 6 vote accounts and landed votes
    {
        var prng = std.Random.DefaultPrng.init(12345);
        const random = prng.random();
        const stake_per_account = 1000;

        const pubkey_count = 6;
        const vote_pubkeys = try allocator.alloc(Pubkey, pubkey_count);
        defer allocator.free(vote_pubkeys);
        for (vote_pubkeys) |*k| k.* = Pubkey.initRandom(random);

        // Build EpochStakes with those vote accounts
        var epoch_stakes = try sig.consensus.fork_choice.testEpochStakes(
            allocator,
            vote_pubkeys,
            stake_per_account,
            random,
        );
        errdefer epoch_stakes.deinit(allocator);

        // Inject landed votes for slot 1 into each vote account
        //
        // This affects the lockouts:
        // Voted slot: 1 (slot_1)
        // Confirmation count: 2
        // Lockout duration: 2² = 4 slots
        // Expiration slot: 1 + 4 = 5
        {
            var vote_accounts = &epoch_stakes.stakes.vote_accounts.vote_accounts;

            for (vote_accounts.values()) |*vote_account| {
                try vote_account.account.state.votes.append(.{
                    .latency = 0,
                    .lockout = .{ .slot = slot_1, .confirmation_count = 2 },
                });
            }
        }

        var epoch_consts = try sig.core.EpochConstants.genesis(allocator, .default(allocator));
        errdefer epoch_consts.deinit(allocator);
        epoch_consts.stakes.deinit(allocator);

        epoch_consts.stakes = epoch_stakes;
        try epoch_tracker.epochs.put(allocator, 0, epoch_consts);
    }
    defer epoch_tracker.deinit(allocator);

    var epoch_tracker_rw = RwMux(EpochTracker).init(epoch_tracker);

    {
        const epochs_ptr, var epochs_lg = epoch_tracker_rw.readWithLock();
        defer epochs_lg.unlock();
        const epoch_consts_ptr = epochs_ptr.epochs.getPtr(0).?;

        const slot_tracker_ptr, var st_lg = slot_tracker_rw.writeWithLock();
        defer st_lg.unlock();
        const slot1_ref = slot_tracker_ptr.get(1).?;
        const stakes_ptr, var stakes_guard = slot1_ref.state.stakes_cache.stakes.writeWithLock();
        defer stakes_guard.unlock();
        stakes_ptr.deinit(allocator);
        stakes_ptr.* = try epoch_consts_ptr.stakes.stakes.clone(allocator);
    }

    // Progress map for root and slot 1
    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);
    {
        var fork_progress0 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fork_progress0.fork_stats.computed = true;
        const fork_progress1 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        try progress.map.put(allocator, root_slot, fork_progress0);
        try progress.map.put(allocator, slot_1, fork_progress1);
    }

    // ReplayResult for slot 1
    const results = [_]ReplayResult{
        .{ .slot = 1, .output = .{ .last_entry_hash = Hash{ .data = .{7} ** Hash.SIZE } } },
    };

    var replay_votes_channel = try Channel(ParsedVote).create(allocator);
    defer replay_votes_channel.destroy();

    const external = TowerConsensus.Dependencies.External{
        .senders = stubs.senders,
        .receivers = stubs.receivers,
        .gossip_table = null,
        .run_vote_listener = false,
    };

    const deps = TowerConsensus.Dependencies{
        .logger = .noop,
        .my_identity = Pubkey.initRandom(std.crypto.random),
        .vote_identity = Pubkey.initRandom(std.crypto.random),
        .root_slot = root_slot,
        .root_hash = Hash.ZEROES,
        .account_reader = stubs.accountsdb.accountReader(),
        .ledger = &stubs.ledger,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    try std.testing.expect(progress.getForkStats(1).?.voted_stakes.count() == 0);

    try consensus.process(
        allocator,
        &slot_tracker_rw,
        &epoch_tracker_rw,
        &progress,
        &results,
    );

    const stats1 = progress.getForkStats(1).?;
    try std.testing.expect(stats1.computed);
    try std.testing.expectEqual(1, stats1.block_height);

    // With seeded landed votes, these should be populated
    // Landed votes were seeded for slot 1 in consensus.process updateAncestorVotedStakes
    // ensures the stake is also applied to ancestors: slot 0 hence 2.
    try std.testing.expect(stats1.voted_stakes.count() == 2);
    try std.testing.expectEqual(1, stats1.lockout_intervals.map.count());
    // Expected total stake: 6 * 1000
    try std.testing.expectEqual(6000, stats1.total_stake);

    // Voted slot: 1 (slot_1)
    // Confirmation count: 2
    // Lockout duration: 2² = 4 slots
    // Expiration slot: 1 + 4 = 5
    //
    // lockout_intervals.map = {
    //     5 => [  // Key: Expiration slot
    //         (1, validator1_pubkey),  // Voted on slot 1
    //         (1, validator2_pubkey),  // Voted on slot 1
    //         (1, validator3_pubkey),  // Voted on slot 1
    //         (1, validator4_pubkey),  // Voted on slot 1
    //         (1, validator5_pubkey),  // Voted on slot 1
    //         (1, validator6_pubkey),  // Voted on slot 1
    //     ]
    // }
    try std.testing.expectEqual(6, stats1.lockout_intervals.map.get(5).?.items.len);
    try std.testing.expectEqual(slot_1, consensus.fork_choice.heaviestOverallSlot().slot);
}

// Test case:
// This test simulates a validator voting on a chain of blocks (slots 0-33) and
// verifies that the root automatically advances as the tower accumulates enough
// votes to satisfy lockout requirements.
//
// - Pre-populate tower with votes on slots 1-31 (simulating past voting history)
// - Tower is at MAX_LOCKOUT_HISTORY capacity, root is still 0
// - Sync internal state by processing slots 30-31 via consensus.process()
// - Process slot 32 via consensus.process() → should trigger vote, pop oldest, advance root
// - Process slot 33 via consensus.process() → should trigger vote, pop oldest, advance root again
//
// States updated (setup):
// - SlotHistory sysvar: created and added to accounts (required by consensus)
// - SlotTracker: initialized with root slot 0 (constants, state with hash=Hash.ZEROES, blockhash_queue)
// - SlotTracker: slots 1-31 added with constants (parent_slot, parent_hash, block_height, ancestors)
//   and state (hash) before consensus init
// - EpochTracker: initialized with epochs 0 and 1, each with validator stake=1000
// - ProgressMap: initialized with root slot entry (fork_stats: computed=true)
// - ProgressMap: slots 1-31 added with ForkProgress (fork_stats: computed=true, total_stake=1000)
// - TowerConsensus: initialized with dependencies (builds fork_choice from frozen slots 1-31)
// - Tower: pre-populated with 31 votes on slots 1-31 via recordBankVote (simulating past voting)
// - ProgressMap: each of slots 1-31 has fork_stats.voted_stakes updated with single entry (slot, 1000)
//   representing our validator's vote on that slot
// - Slots 30-31: fork_stats marked computed=false, propagated_stats set (is_leader_slot=true,
//   is_propagated=true), then processed via consensus.process() to sync internal state
//   (computeBankStats, cacheTowerStats)
//
// States updated (via consensus.process for testing):
// - Slot 32: added to SlotTracker (with ancestors) and ProgressMap (with fork_stats.computed=true,
//   fork_stats.total_stake=1000, fork_stats.voted_stakes containing entries {1: 1000, 2: 1000, ..., 31: 1000},
//   propagated_stats.is_leader_slot=true, propagated_stats.is_propagated=true),
//   then processed via consensus.process()
// - Slot 33: added to SlotTracker (with ancestors) and ProgressMap (with fork_stats.computed=true,
//   fork_stats.total_stake=1000, fork_stats.voted_stakes containing entries {1: 1000, 2: 1000, ..., 32: 1000},
//   propagated_stats.is_leader_slot=true, propagated_stats.is_propagated=true),
//   then processed via consensus.process()
//
// States asserted:
// - After pre-population: tower has 31 votes, root is 0
// - After processing slot 32:
//   - Root advances from 0 to 1
//   - Tower maintains 31 votes (oldest popped, new added)
//   - Pruning on root update:
//     - Slot 0 (old root) is pruned from slot_tracker
//     - Slot 1 (new root) and descendants remain in slot_tracker
//     - Progress map entry for slot 0 is removed
//     - Fork choice heaviest (slot 32) is on the rooted path
// - After processing slot 33:
//   - Root advances from 1 to 2
//   - Tower maintains 31 votes
//   - Pruning on root update:
//     - Slots 0 and 1 (old roots) are pruned from slot_tracker
//     - Slot 2 (new root) and descendants remain in slot_tracker
//     - Progress map entries for slots 0 and 1 are removed
//     - Fork choice heaviest (slot 33) is on the rooted path
// - Final: lastVotedSlot() == 33 (most recent vote tracked correctly)
test "root advances after vote satisfies lockouts" {
    const allocator = std.testing.allocator;

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit(allocator);

    {
        const SlotHistory = sig.runtime.sysvar.SlotHistory;
        const slot_history = try SlotHistory.init(allocator);
        defer slot_history.deinit(allocator);
        const data = try allocator.alloc(u8, SlotHistory.STORAGE_SIZE);
        defer allocator.free(data);
        @memset(data, 0);
        _ = try sig.bincode.writeToSlice(data, slot_history, .{});
        const account = sig.runtime.AccountSharedData{
            .lamports = 1,
            .data = data,
            .owner = sig.runtime.sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        };
        const account_store = stubs.accountsdb.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    const initial_root: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);

    var root_state = try sig.core.SlotState.genesis(allocator);
    root_state.hash.set(Hash.ZEROES);
    {
        var bhq = root_state.blockhash_queue.write();
        defer bhq.unlock();
        try bhq.mut().insertGenesisHash(allocator, root_state.hash.readCopy().?, 0);
    }
    // 34 because slots 0..33
    const chain_length = 34;
    var hashes: [chain_length]Hash = undefined;
    hashes[0] = Hash.ZEROES;
    for (1..chain_length) |i| {
        hashes[i] = Hash{ .data = .{@as(u8, @intCast(i % 256))} ** Hash.SIZE };
    }

    var slot_tracker_rw = RwMux(SlotTracker).init(try SlotTracker.init(allocator, initial_root, .{
        .constants = root_consts,
        .state = root_state,
    }));
    defer {
        const st_ptr, var st_lock = slot_tracker_rw.writeWithLock();
        defer st_lock.unlock();
        st_ptr.deinit(allocator);
    }

    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();
    const validator_vote_pubkey = Pubkey.initRandom(random);
    const validator_identity_pubkey = Pubkey.initRandom(random);

    var epoch_tracker: EpochTracker = .{
        .epochs = .empty,
        .schedule = sig.core.EpochSchedule.DEFAULT,
    };

    {
        const vote_pubkeys = try allocator.alloc(Pubkey, 1);
        defer allocator.free(vote_pubkeys);
        vote_pubkeys[0] = validator_vote_pubkey; // Use our validator's vote pubkey

        var epoch_stakes = try sig.consensus.fork_choice.testEpochStakes(
            allocator,
            vote_pubkeys,
            1000,
            random,
        );
        errdefer epoch_stakes.deinit(allocator);

        var epoch_consts = try sig.core.EpochConstants.genesis(allocator, .default(allocator));
        errdefer epoch_consts.deinit(allocator);
        epoch_consts.stakes.deinit(allocator);
        epoch_consts.stakes = epoch_stakes;

        try epoch_tracker.epochs.put(allocator, 0, epoch_consts);
    }
    {
        const vote_pubkeys = try allocator.alloc(Pubkey, 1);
        defer allocator.free(vote_pubkeys);
        vote_pubkeys[0] = validator_vote_pubkey; // Use our validator's vote pubkey

        var epoch_stakes = try sig.consensus.fork_choice.testEpochStakes(
            allocator,
            vote_pubkeys,
            1000,
            random,
        );
        errdefer epoch_stakes.deinit(allocator);

        var epoch_consts = try sig.core.EpochConstants.genesis(allocator, .default(allocator));
        errdefer epoch_consts.deinit(allocator);
        epoch_consts.stakes.deinit(allocator);
        epoch_consts.stakes = epoch_stakes;

        try epoch_tracker.epochs.put(allocator, 1, epoch_consts);
    }
    defer epoch_tracker.deinit(allocator);
    var epoch_tracker_rw = RwMux(EpochTracker).init(epoch_tracker);

    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);

    {
        var fp = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp.fork_stats.computed = true;
        try progress.map.put(allocator, initial_root, fp);
    }

    var replay_votes_channel = try Channel(ParsedVote).create(allocator);
    defer replay_votes_channel.destroy();

    const external = TowerConsensus.Dependencies.External{
        .senders = stubs.senders,
        .receivers = stubs.receivers,
        .gossip_table = null,
        .run_vote_listener = false,
    };

    const deps = TowerConsensus.Dependencies{
        .logger = .noop,
        .my_identity = validator_identity_pubkey,
        .vote_identity = validator_vote_pubkey,
        .root_slot = initial_root,
        .root_hash = Hash.ZEROES,
        .account_reader = stubs.accountsdb.accountReader(),
        .ledger = &stubs.ledger,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    const our_validator_stake: u64 = 1000;

    for (1..32) |i| {
        const slot: Slot = @intCast(i);

        {
            const st, var st_lock = slot_tracker_rw.writeWithLock();
            defer st_lock.unlock();

            const parent_slot: Slot = slot - 1;
            const parent_hash = hashes[parent_slot];
            const slot_hash = hashes[slot];

            var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
            slot_constants.parent_slot = parent_slot;
            slot_constants.parent_hash = parent_hash;
            slot_constants.block_height = slot;

            slot_constants.ancestors.deinit(allocator);
            slot_constants.ancestors = .{};
            for (0..slot + 1) |ancestor_slot| {
                try slot_constants.ancestors.ancestors.put(allocator, @intCast(ancestor_slot), {});
            }

            var slot_state = try sig.core.SlotState.genesis(allocator);
            slot_state.hash = .init(slot_hash);

            try st.put(allocator, slot, .{ .constants = slot_constants, .state = slot_state });
        }

        {
            var fp = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
            fp.fork_stats.computed = true;
            fp.fork_stats.total_stake = our_validator_stake; // Set total stake to match epoch stakes
            try progress.map.put(allocator, slot, fp);
        }
    }

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    for (1..32) |i| {
        const slot: Slot = @intCast(i);
        _ = try consensus.replay_tower.recordBankVote(allocator, slot, hashes[slot]);

        if (progress.map.getPtr(slot)) |prog| {
            try prog.fork_stats.voted_stakes.put(allocator, slot, our_validator_stake);
        }
    }

    {
        try std.testing.expectEqual(31, consensus.replay_tower.tower.vote_state.votes.len);
        try std.testing.expectEqual(0, try consensus.replay_tower.tower.getRoot());
    }

    {
        for ([_]Slot{ 29, 30, 31 }) |slot| {
            if (progress.map.getPtr(slot)) |prog| {
                // Mark as not computed so consensus will process it
                prog.fork_stats.computed = false;
                prog.propagated_stats.is_leader_slot = true;
                prog.propagated_stats.is_propagated = true;
            }
        }

        const sync_results = [_]ReplayResult{
            .{ .slot = 29, .output = .{ .last_entry_hash = hashes[29] } },
            .{ .slot = 30, .output = .{ .last_entry_hash = hashes[30] } },
            .{ .slot = 31, .output = .{ .last_entry_hash = hashes[31] } },
        };
        try consensus.process(
            allocator,
            &slot_tracker_rw,
            &epoch_tracker_rw,
            &progress,
            &sync_results,
        );
    }

    {
        const slot: Slot = 32;
        const st, var st_lock = slot_tracker_rw.writeWithLock();
        defer st_lock.unlock();

        const parent_slot: Slot = slot - 1;
        const parent_hash = hashes[parent_slot];
        const slot_hash = hashes[slot];

        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        slot_constants.parent_slot = parent_slot;
        slot_constants.parent_hash = parent_hash;
        slot_constants.block_height = slot;

        // Set up ancestors: slot 32 should have ancestors 0 umtil 32
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        for (0..slot + 1) |ancestor_slot| {
            try slot_constants.ancestors.ancestors.put(allocator, @intCast(ancestor_slot), {});
        }

        var slot_state = try sig.core.SlotState.genesis(allocator);
        slot_state.hash = .init(slot_hash);

        try st.put(allocator, slot, .{ .constants = slot_constants, .state = slot_state });
    }
    {
        var fp = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp.fork_stats.computed = true;
        fp.fork_stats.total_stake = our_validator_stake;

        for (1..32) |prev_slot| {
            try fp.fork_stats.voted_stakes.put(allocator, @intCast(prev_slot), our_validator_stake);
        }
        fp.propagated_stats.is_leader_slot = true;
        fp.propagated_stats.is_propagated = true;
        try progress.map.put(allocator, 32, fp);
    }

    // Test
    {
        const old_root = try consensus.replay_tower.tower.getRoot();

        const results = [_]ReplayResult{
            .{ .slot = 32, .output = .{ .last_entry_hash = hashes[32] } },
        };

        try consensus.process(
            allocator,
            &slot_tracker_rw,
            &epoch_tracker_rw,
            &progress,
            &results,
        );

        const new_root = try consensus.replay_tower.tower.getRoot();
        try std.testing.expect(new_root > old_root);
        try std.testing.expectEqual(0, old_root);
        try std.testing.expectEqual(1, new_root);
        try std.testing.expectEqual(
            MAX_LOCKOUT_HISTORY,
            consensus.replay_tower.tower.vote_state.votes.len,
        );

        {
            const st, var st_lock = slot_tracker_rw.readWithLock();
            defer st_lock.unlock();
            try std.testing.expectEqual(1, st.root);
            // No longer tracking slot 0
            try std.testing.expect(!st.contains(0));
            // Still tracking slot 1
            try std.testing.expect(st.contains(1));
            try std.testing.expect(st.contains(32));
        }
        // No longer tracking slot 0
        try std.testing.expect(progress.map.get(0) == null);
        // Still tracking slot 1
        try std.testing.expect(progress.map.get(1) != null);
        try std.testing.expectEqual(32, consensus.fork_choice.heaviestOverallSlot().slot);
    }

    {
        const slot: Slot = 33;
        const st, var st_lock = slot_tracker_rw.writeWithLock();
        defer st_lock.unlock();

        const parent_slot: Slot = slot - 1;
        const parent_hash = hashes[parent_slot];
        const slot_hash = hashes[slot];

        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        slot_constants.parent_slot = parent_slot;
        slot_constants.parent_hash = parent_hash;
        slot_constants.block_height = slot;

        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        for (0..slot + 1) |ancestor_slot| {
            try slot_constants.ancestors.ancestors.put(allocator, @intCast(ancestor_slot), {});
        }

        var slot_state = try sig.core.SlotState.genesis(allocator);
        slot_state.hash = .init(slot_hash);

        try st.put(allocator, slot, .{ .constants = slot_constants, .state = slot_state });
    }
    {
        var fp = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp.fork_stats.computed = true;
        fp.fork_stats.total_stake = our_validator_stake;

        for (1..33) |prev_slot| {
            try fp.fork_stats.voted_stakes.put(allocator, @intCast(prev_slot), our_validator_stake);
        }
        fp.propagated_stats.is_leader_slot = true;
        fp.propagated_stats.is_propagated = true;
        try progress.map.put(allocator, 33, fp);
    }

    // Test
    {
        const old_root = try consensus.replay_tower.tower.getRoot();

        const results = [_]ReplayResult{
            .{ .slot = 33, .output = .{ .last_entry_hash = hashes[33] } },
        };
        try consensus.process(
            allocator,
            &slot_tracker_rw,
            &epoch_tracker_rw,
            &progress,
            &results,
        );

        const new_root = try consensus.replay_tower.tower.getRoot();
        try std.testing.expect(new_root > old_root);
        try std.testing.expectEqual(1, old_root);
        try std.testing.expectEqual(2, new_root);
        try std.testing.expectEqual(
            MAX_LOCKOUT_HISTORY,
            consensus.replay_tower.tower.vote_state.votes.len,
        );

        try std.testing.expect(new_root > initial_root);
        const last_voted = consensus.replay_tower.tower.vote_state.lastVotedSlot();
        try std.testing.expectEqual(33, last_voted);

        {
            const st, var st_lock = slot_tracker_rw.readWithLock();
            defer st_lock.unlock();
            try std.testing.expectEqual(2, st.root);
            // No longer tracking slot 0
            try std.testing.expect(!st.contains(0));
            // No longer tracking slot 1
            try std.testing.expect(!st.contains(1));
            // Still tracking slot 2
            try std.testing.expect(st.contains(2));
            try std.testing.expect(st.contains(33));
        }
        // No longer tracking slot 0
        try std.testing.expect(progress.map.get(0) == null);
        // No longer tracking slot 1
        try std.testing.expect(progress.map.get(1) == null);
        // Still tracking slot 2
        try std.testing.expect(progress.map.get(2) != null);
        try std.testing.expectEqual(33, consensus.fork_choice.heaviestOverallSlot().slot);
    }
}

// Test case:
// - Setup: Validator has already voted on slot 1
// - No new votable slots available (heaviest == last vote, no descendants)
// - Process is called with no new replay results
//
// States updated (setup):
// - SlotTracker: root slot 0 and slot 1 (both frozen)
// - EpochTracker: epoch 0 with validator stake
// - ProgressMap: entries for slots 0 and 1 (both computed)
// - TowerConsensus: initialized and has voted on slot 1
// - last_vote_tx_blockhash: set to non_voting initially
//
// States updated (via consensus.process):
// - Called with empty replay results (no new slots to process)
// - Consensus attempts to find votable bank but finds none (heaviest == last vote)
//
// States asserted:
// - lastVotedSlot() remains unchanged (still slot 1)
// - No new vote was recorded in the tower
// - last_vote_tx_blockhash remains .non_voting
test "vote refresh when no new vote available" {
    const allocator = std.testing.allocator;

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit(allocator);

    {
        const SlotHistory = sig.runtime.sysvar.SlotHistory;
        const slot_history = try SlotHistory.init(allocator);
        defer slot_history.deinit(allocator);
        const data = try allocator.alloc(u8, SlotHistory.STORAGE_SIZE);
        defer allocator.free(data);
        @memset(data, 0);
        _ = try sig.bincode.writeToSlice(data, slot_history, .{});
        const account = sig.runtime.AccountSharedData{
            .lamports = 1,
            .data = data,
            .owner = sig.runtime.sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        };
        const account_store = stubs.accountsdb.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state = try sig.core.SlotState.genesis(allocator);

    root_state.hash.set(Hash.ZEROES);
    {
        var bhq = root_state.blockhash_queue.write();
        defer bhq.unlock();
        try bhq.mut().insertGenesisHash(allocator, Hash.ZEROES, 0);
    }

    var slot_tracker = try SlotTracker.init(allocator, root_slot, .{
        .constants = root_consts,
        .state = root_state,
    });
    defer slot_tracker.deinit(allocator);

    const slot1_hash = Hash{ .data = .{1} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = root_slot;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 1;

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash = .init(slot1_hash);

        try slot_tracker.put(allocator, 1, .{ .constants = slot_constants, .state = slot_state });
    }

    var slot_tracker_rw = RwMux(SlotTracker).init(slot_tracker);

    var epoch_tracker: EpochTracker = .{
        .epochs = .empty,
        .schedule = sig.core.EpochSchedule.DEFAULT,
    };
    {
        const epoch_consts = try sig.core.EpochConstants.genesis(allocator, .default(allocator));
        errdefer epoch_consts.deinit(allocator);
        try epoch_tracker.epochs.put(allocator, 0, epoch_consts);
    }
    defer epoch_tracker.deinit(allocator);
    var epoch_tracker_rw = RwMux(EpochTracker).init(epoch_tracker);

    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);
    {
        var fork_progress0 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fork_progress0.fork_stats.computed = true;
        var fork_progress1 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fork_progress1.fork_stats.computed = true;
        try progress.map.put(allocator, 0, fork_progress0);
        try progress.map.put(allocator, 1, fork_progress1);
    }

    var replay_votes_channel = try Channel(ParsedVote).create(allocator);
    defer replay_votes_channel.destroy();

    const external = TowerConsensus.Dependencies.External{
        .senders = stubs.senders,
        .receivers = stubs.receivers,
        .gossip_table = null,
        .run_vote_listener = false,
    };

    const deps = TowerConsensus.Dependencies{
        .logger = .noop,
        .my_identity = Pubkey.initRandom(std.crypto.random),
        .vote_identity = Pubkey.initRandom(std.crypto.random),
        .root_slot = root_slot,
        .root_hash = Hash.ZEROES,
        .account_reader = stubs.accountsdb.accountReader(),
        .ledger = &stubs.ledger,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    {
        const results = [_]ReplayResult{
            .{ .slot = 1, .output = .{ .last_entry_hash = slot1_hash } },
        };
        try consensus.process(allocator, &slot_tracker_rw, &epoch_tracker_rw, &progress, &results);
    }

    const initial_last_voted = consensus.replay_tower.lastVotedSlot();
    try std.testing.expectEqual(1, initial_last_voted);
    const initial_tx_blockhash = consensus.replay_tower.last_vote_tx_blockhash;
    try std.testing.expect(initial_tx_blockhash == .non_voting);

    // The Test
    {
        const empty_results: []const ReplayResult = &.{};
        try consensus.process(
            allocator,
            &slot_tracker_rw,
            &epoch_tracker_rw,
            &progress,
            empty_results,
        );
    }

    // Assert: No new vote recorded
    const final_last_voted = consensus.replay_tower.lastVotedSlot();
    try std.testing.expectEqual(initial_last_voted, final_last_voted);
    try std.testing.expectEqual(1, final_last_voted);

    // Assert: blockhash status remains non_voting (current stub behavior)
    const final_tx_blockhash = consensus.replay_tower.last_vote_tx_blockhash;
    try std.testing.expect(final_tx_blockhash == .non_voting);

    // The vote count in tower should remain the same (1 vote)
    try std.testing.expectEqual(1, consensus.replay_tower.tower.vote_state.votes.len);

    try std.testing.expectEqual(1, consensus.fork_choice.heaviestOverallSlot().slot);
}

// Test case:
// - Setup: Validator votes on a frozen slot, and enough other validators also vote
//   on the same slot such that the stake exceeds DUPLICATE_THRESHOLD (52%)
// - Action: Call consensus.process() which will compute bank stats and detect
//   the duplicate-confirmed condition
//
// NOTE: This test exercises the FALLBACK duplicate-confirmed detection mechanism in
// consensus.process() -> computeBankStats() -> isDuplicateSlotConfirmed().
// In a running validator, duplicate-confirmed is normally detected by:
//   1. vote_listener observing votes from gossip -> trackOptimisticConfirmationVote()
//   2. When stake threshold reached, sends to duplicate_confirmed_slot channel
//   3. consensus.process() -> processEdgeCases() -> processDuplicateConfirmedSlots()
//      reads from channel and marks the slot
// This test bypasses the vote listener and directly tests the bank stats computation path.
//
// States updated (setup):
// - SlotTracker: root slot 0 and slot 1 (both frozen)
// - EpochTracker: epoch 0 with multiple validators (total stake = 600)
// - ProgressMap: entries for slots 0, 1, and 2
// - Vote accounts: seeded with votes on slots 0 and 1 (simulating what block replay would update)
//
// States asserted:
// - progress_map.getForkStats(1).?.duplicate_confirmed_hash == slot 1's hash
// - consensus.slot_data.duplicate_confirmed_slots.get(1) == slot 1's hash
test "detect and mark duplicate confirmed fork" {
    const allocator = std.testing.allocator;

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit(allocator);

    {
        const SlotHistory = sig.runtime.sysvar.SlotHistory;
        const slot_history = try SlotHistory.init(allocator);
        defer slot_history.deinit(allocator);
        const data = try allocator.alloc(u8, SlotHistory.STORAGE_SIZE);
        defer allocator.free(data);
        @memset(data, 0);
        _ = try sig.bincode.writeToSlice(data, slot_history, .{});
        const account = sig.runtime.AccountSharedData{
            .lamports = 1,
            .data = data,
            .owner = sig.runtime.sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        };
        const account_store = stubs.accountsdb.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state = try sig.core.SlotState.genesis(allocator);

    root_state.hash.set(Hash.ZEROES);
    {
        var bhq = root_state.blockhash_queue.write();
        defer bhq.unlock();
        try bhq.mut().insertGenesisHash(allocator, Hash.ZEROES, 0);
    }

    var slot_tracker = try SlotTracker.init(allocator, root_slot, .{
        .constants = root_consts,
        .state = root_state,
    });
    defer slot_tracker.deinit(allocator);

    // Add frozen slot 1
    const slot1_hash = Hash{ .data = .{1} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = root_slot;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 1;

        // Set up ancestors (slot 1 has ancestors 0 and 1)
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 1, {});

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot1_hash);

        try slot_tracker.put(allocator, 1, .{ .constants = slot_constants, .state = slot_state });
    }

    const slot2_hash = Hash{ .data = .{2} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = 1;
        slot_constants.parent_hash = slot1_hash;
        slot_constants.block_height = 2;

        // Set up ancestors (slot 2 has ancestors 0, 1, and 2)
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 1, {});
        try slot_constants.ancestors.ancestors.put(allocator, 2, {});

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot2_hash);

        try slot_tracker.put(allocator, 2, .{ .constants = slot_constants, .state = slot_state });
    }

    var slot_tracker_rw = RwMux(SlotTracker).init(slot_tracker);

    var epoch_tracker: EpochTracker = .{
        .epochs = .empty,
        .schedule = sig.core.EpochSchedule.DEFAULT,
    };

    {
        var prng = std.Random.DefaultPrng.init(12345);
        const random = prng.random();

        // Create enough vote accounts to exceed duplicate threshold (53% of 1000)
        const pubkey_count = 6;
        const stake_per_account = 100; // Total = 600, but we'll have 5.3 accounts vote = 530 stake
        const vote_pubkeys = try allocator.alloc(Pubkey, pubkey_count);
        defer allocator.free(vote_pubkeys);
        for (vote_pubkeys) |*k| k.* = Pubkey.initRandom(random);

        var epoch_stakes = try sig.consensus.fork_choice.testEpochStakes(
            allocator,
            vote_pubkeys,
            stake_per_account,
            random,
        );
        errdefer epoch_stakes.deinit(allocator);

        // SIMULATES BLOCK REPLAY: Inject landed votes for slot 1 into all 6 vote accounts
        // In a real validator, vote account state would be updated during:
        //   1. Block replay processes vote transactions
        //   2. executeProcessVoteWithAccount() -> processVoteWithAccount()
        //   3. vote_state.processVote() -> processNextVoteSlot()
        //   4. self.votes.append(landed_vote) updates the vote account state
        // Here we directly inject the votes into vote account state.
        {
            var vote_accounts = &epoch_stakes.stakes.vote_accounts.vote_accounts;

            for (vote_accounts.values()) |*vote_account| {
                try vote_account.account.state.votes.append(.{
                    .latency = 0,
                    .lockout = .{ .slot = 0, .confirmation_count = 2 },
                });
                try vote_account.account.state.votes.append(.{
                    .latency = 0,
                    .lockout = .{ .slot = 1, .confirmation_count = 2 },
                });
            }
        }

        var epoch_consts = try sig.core.EpochConstants.genesis(allocator, .default(allocator));
        errdefer epoch_consts.deinit(allocator);
        epoch_consts.stakes.deinit(allocator);
        epoch_consts.stakes = epoch_stakes;

        try epoch_tracker.epochs.put(allocator, 0, epoch_consts);
    }
    defer epoch_tracker.deinit(allocator);

    var epoch_tracker_rw = RwMux(EpochTracker).init(epoch_tracker);

    {
        const epochs_ptr, var epochs_lg = epoch_tracker_rw.readWithLock();
        defer epochs_lg.unlock();
        const epoch_consts_ptr = epochs_ptr.epochs.getPtr(0).?;

        const slot_tracker_ptr, var st_lg = slot_tracker_rw.writeWithLock();
        defer st_lg.unlock();

        {
            const slot1_ref = slot_tracker_ptr.get(1).?;
            const stakes_ptr, var stakes_guard = slot1_ref.state.stakes_cache.stakes.writeWithLock();
            defer stakes_guard.unlock();
            stakes_ptr.deinit(allocator);
            stakes_ptr.* = try epoch_consts_ptr.stakes.stakes.clone(allocator);
        }

        {
            const slot2_ref = slot_tracker_ptr.get(2).?;
            const stakes_ptr, var stakes_guard = slot2_ref.state.stakes_cache.stakes.writeWithLock();
            defer stakes_guard.unlock();
            stakes_ptr.deinit(allocator);
            stakes_ptr.* = try epoch_consts_ptr.stakes.stakes.clone(allocator);
        }
    }

    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);

    {
        var fork_progress0 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fork_progress0.fork_stats.computed = true;
        const fork_progress1 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        const fork_progress2 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        try progress.map.put(allocator, 0, fork_progress0);
        try progress.map.put(allocator, 1, fork_progress1);
        try progress.map.put(allocator, 2, fork_progress2);
    }

    var replay_votes_channel = try Channel(ParsedVote).create(allocator);
    defer replay_votes_channel.destroy();

    const external = TowerConsensus.Dependencies.External{
        .senders = stubs.senders,
        .receivers = stubs.receivers,
        .gossip_table = null,
        .run_vote_listener = false,
    };

    const deps = TowerConsensus.Dependencies{
        .logger = .noop,
        .my_identity = Pubkey.initRandom(std.crypto.random),
        .vote_identity = Pubkey.initRandom(std.crypto.random),
        .root_slot = root_slot,
        .root_hash = Hash.ZEROES,
        .account_reader = stubs.accountsdb.accountReader(),
        .ledger = &stubs.ledger,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    // Verify slot 1 is not yet marked as duplicate-confirmed
    try std.testing.expect(progress.getForkStats(1).?.duplicate_confirmed_hash == null);
    try std.testing.expect(consensus.slot_data.duplicate_confirmed_slots.get(1) == null);

    // Process slot 2 - should detect duplicate-confirmed condition for slot 1
    // (When processing slot 2, the votes on slot 1 become nth(1) lockouts, which populates voted_stakes[1])
    {
        const results = [_]ReplayResult{
            .{ .slot = 2, .output = .{ .last_entry_hash = slot2_hash } },
        };
        try consensus.process(allocator, &slot_tracker_rw, &epoch_tracker_rw, &progress, &results);
    }

    // Assert: slot 1 is now marked as duplicate-confirmed
    const stats1 = progress.getForkStats(1).?;
    try std.testing.expect(stats1.duplicate_confirmed_hash != null);
    try std.testing.expect(stats1.duplicate_confirmed_hash.?.eql(slot1_hash));

    // Assert: slot_data tracks the duplicate-confirmed slot
    const dup_hash = consensus.slot_data.duplicate_confirmed_slots.get(1);
    try std.testing.expect(dup_hash != null);
    try std.testing.expect(dup_hash.?.eql(slot1_hash));

    // Assert fork choice: heaviest slot should be slot 2 (the processed slot)
    try std.testing.expectEqual(2, consensus.fork_choice.heaviestOverallSlot().slot);
}

// Test case:
// - Setup: A duplicate slot is detected (e.g., via shred verification, different hash for same slot)
//   and sent to the duplicate_slots channel
// - Action: Call consensus.process() which will read from the channel via processDuplicateSlots()
//   and mark the slot as duplicate
//
// NOTE: This test exercises the duplicate slot detection mechanism where:
//   1. ShredInserter detects conflicting shreds for the same slot (different hashes)
//   2. Stores duplicate slot proof in database and sends slot to duplicate_slots channel
//   3. consensus.process() -> processEdgeCases() -> processDuplicateSlots() reads from channel
//   4. Marks slot in duplicate_slots_tracker and updates fork_choice to mark fork invalid
//
// States updated (setup):
// - SlotTracker: root slot 0 and slot 1 (both frozen)
// - EpochTracker: epoch 0 with validators
// - ProgressMap: entries for slots 0 and 1
// - duplicate_slots channel: slot 1 is sent to the channel (simulating duplicate detection)
//
// States asserted:
// - consensus.slot_data.duplicate_slots contains slot 1
// - Fork choice marks slot 1 as invalid candidate (checked via fork_choice state)
test "detect and mark duplicate slot" {
    const allocator = std.testing.allocator;

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit(allocator);

    {
        const SlotHistory = sig.runtime.sysvar.SlotHistory;
        const slot_history = try SlotHistory.init(allocator);
        defer slot_history.deinit(allocator);
        const data = try allocator.alloc(u8, SlotHistory.STORAGE_SIZE);
        defer allocator.free(data);
        @memset(data, 0);
        _ = try sig.bincode.writeToSlice(data, slot_history, .{});
        const account = sig.runtime.AccountSharedData{
            .lamports = 1,
            .data = data,
            .owner = sig.runtime.sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        };
        const account_store = stubs.accountsdb.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state = try sig.core.SlotState.genesis(allocator);

    root_state.hash.set(Hash.ZEROES);
    {
        var bhq = root_state.blockhash_queue.write();
        defer bhq.unlock();
        try bhq.mut().insertGenesisHash(allocator, Hash.ZEROES, 0);
    }

    var slot_tracker = try SlotTracker.init(allocator, root_slot, .{
        .constants = root_consts,
        .state = root_state,
    });
    defer slot_tracker.deinit(allocator);

    const slot1_hash = Hash{ .data = .{1} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = root_slot;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 1;

        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 1, {});

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot1_hash);

        try slot_tracker.put(allocator, 1, .{ .constants = slot_constants, .state = slot_state });
    }

    var slot_tracker_rw = RwMux(SlotTracker).init(slot_tracker);

    var epoch_tracker: EpochTracker = .{
        .epochs = .empty,
        .schedule = sig.core.EpochSchedule.DEFAULT,
    };
    {
        const epoch_consts = try sig.core.EpochConstants.genesis(allocator, .default(allocator));
        errdefer epoch_consts.deinit(allocator);
        try epoch_tracker.epochs.put(allocator, 0, epoch_consts);
    }
    defer epoch_tracker.deinit(allocator);
    var epoch_tracker_rw = RwMux(EpochTracker).init(epoch_tracker);

    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);
    {
        var fork_progress0 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fork_progress0.fork_stats.computed = true;
        const fork_progress1 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        try progress.map.put(allocator, 0, fork_progress0);
        try progress.map.put(allocator, 1, fork_progress1);
    }

    var replay_votes_channel = try Channel(ParsedVote).create(allocator);
    defer replay_votes_channel.destroy();

    const external = TowerConsensus.Dependencies.External{
        .senders = stubs.senders,
        .receivers = stubs.receivers,
        .gossip_table = null,
        .run_vote_listener = false,
    };

    const deps = TowerConsensus.Dependencies{
        .logger = .noop,
        .my_identity = Pubkey.initRandom(std.crypto.random),
        .vote_identity = Pubkey.initRandom(std.crypto.random),
        .root_slot = root_slot,
        .root_hash = Hash.ZEROES,
        .account_reader = stubs.accountsdb.accountReader(),
        .ledger = &stubs.ledger,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    try std.testing.expect(!consensus.slot_data.duplicate_slots.contains(1));

    // SIMULATE DUPLICATE DETECTION: Send slot 1 to duplicate_slots channel
    // In a real validator, this would happen when:
    //   1. ShredInserter receives conflicting shreds for slot 1 (different hashes)
    //   2. Detects the conflict and stores duplicate slot proof in database
    //   3. Sends slot 1 to the duplicate_slots channel
    try stubs.receivers.duplicate_slots.send(1);

    {
        const results = [_]ReplayResult{
            .{ .slot = 1, .output = .{ .last_entry_hash = slot1_hash } },
        };
        try consensus.process(allocator, &slot_tracker_rw, &epoch_tracker_rw, &progress, &results);
    }

    // Assert: slot 1 is now marked as duplicate
    try std.testing.expect(consensus.slot_data.duplicate_slots.contains(1));

    // Assert: fork choice should have marked the fork as invalid
    // (The slot should be marked as invalid candidate in fork_choice)
    // A fork is considered invalid if latest_duplicate_ancestor is not null
    const fork_info = consensus.fork_choice.fork_infos.get(.{ .slot = 1, .hash = slot1_hash });
    try std.testing.expect(fork_info != null);
    try std.testing.expect(fork_info.?.latest_duplicate_ancestor != null);
}

// Test case: Fork switch behavior under lockout and stake thresholds
//
// Setup:
// - Root and sysvars:
//   - root = 0, with genesis `SlotConstants` and frozen `SlotState(hash=ZEROES)` (recent blockhash queue seeded)
//   - SlotHistory sysvar account installed in the account store
//
// - Forks tracked in `SlotTracker`:
//
//     slot 0
//     |   \
//     |    \
//     |     +-- slot 2 (B)
//     +-- slot 1 (A)
//           \
//            +-- slot 4 (B')  [heavier sibling via votes]
//            \
//             +-- slot 5      [sibling with insufficient stake]
//
// - Stakes and progress:
//   - Epoch stakes: 5 validators, 100 stake each (total_stake=500)
//   - Stakes cache installed for slots 1, 2 and 4 (and later 5)
//   - `ProgressMap` entries for slots 0,1,2,4 (and later 5), with `slot_hash` set for 2 and 4
//   - Latest validator votes seeded for slot 4 from 3 validators, via both gossip and replay
//
// - Initial tower state:
//   - Record a vote on slot 1 (fork A). With a single lockout (confirmation_count=1),
//     lastLockedOutSlot = 1 + 2 = 3; any sibling <=3 is locked out; 4 and 5 are not
//
// Actions and Expected Results:
// 1) Attempt to switch to slot 2 (sibling):
//    - Check: makeCheckSwitchThresholdDecision(2) returns switch_proof (requires proof)
//    - Process slot 2: due to lockout, vote is not cast on 2
//
// 2) Attempt to switch to slot 4 (heavier sibling):
//    - Check: decision is switch_proof or same_fork (depending on state)
//    - Process slot 4: 4 > lastLockedOutSlot (3), voting on 4 is allowed; lastVotedSlot == 4
//
// 3) Attempt to switch to slot 5 (insufficient stake):
//    - Slot 5 is added without seeding supporting votes; recompute stats
//    - Check: makeCheckSwitchThresholdDecision(5) returns failed_switch_threshold
//    - Process slot 5: no vote is recorded; lastVotedSlot remains 4
//
// Notes:
// - The switch proof hash is Hash.ZEROES (generation not implemented, same as Agave).
test "successful fork switch (switch_proof)" {
    const allocator = std.testing.allocator;

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit(allocator);

    {
        const SlotHistory = sig.runtime.sysvar.SlotHistory;
        const slot_history = try SlotHistory.init(allocator);
        defer slot_history.deinit(allocator);

        const data = try allocator.alloc(u8, SlotHistory.STORAGE_SIZE);
        defer allocator.free(data);

        @memset(data, 0);

        _ = try sig.bincode.writeToSlice(data, slot_history, .{});
        const account = sig.runtime.AccountSharedData{
            .lamports = 1,
            .data = data,
            .owner = sig.runtime.sysvar.OWNER_ID,
            .executable = false,
            .rent_epoch = 0,
        };
        const account_store = stubs.accountsdb.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    // Root 0
    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state = try sig.core.SlotState.genesis(allocator);
    root_state.hash.set(Hash.ZEROES);
    {
        var bhq = root_state.blockhash_queue.write();
        defer bhq.unlock();
        try bhq.mut().insertGenesisHash(allocator, Hash.ZEROES, 0);
    }

    var slot_tracker = try SlotTracker.init(
        allocator,
        root_slot,
        .{ .constants = root_consts, .state = root_state },
    );

    // Build first child of root:
    //
    //     slot 0
    //     |
    //     +-- slot 1 (A)
    const slot1_hash = Hash{ .data = .{1} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = 0;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 1;
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 1, {});

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot1_hash);
        try slot_tracker.put(
            allocator,
            1,
            .{ .constants = slot_constants, .state = slot_state },
        );
    }

    // Add a sibling of slot 1:
    //
    //     slot 0
    //     |   \
    //     |    \
    //     |     +-- slot 2 (B)
    //     +-- slot 1 (A)
    const slot2_hash = Hash{ .data = .{2} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = 0;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 2;
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 2, {});

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot2_hash);
        try slot_tracker.put(allocator, 2, .{ .constants = slot_constants, .state = slot_state });
    }

    // Add heavier sibling we’ll vote on:
    //
    //     slot 0
    //     |   \
    //     |    \
    //     |     +-- slot 2 (B)
    //     +-- slot 1 (A)
    //           \
    //            +-- slot 4 (B')  [heavier sibling via votes]
    //
    // With one prior vote on slot 1, lastLockedOutSlot = 1 + 2 = 3, so 4 is not locked out.
    const slot4_hash = Hash{ .data = .{4} ** Hash.SIZE };
    {
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = 0;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 4;
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 4, {});

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot4_hash);
        try slot_tracker.put(allocator, 4, .{ .constants = slot_constants, .state = slot_state });
    }

    var slot_tracker_rw = RwMux(SlotTracker).init(slot_tracker);

    var epoch_tracker: EpochTracker = .{
        .epochs = .empty,
        .schedule = sig.core.EpochSchedule.DEFAULT,
    };
    var vote_pubkeys = try allocator.alloc(Pubkey, 5);
    defer allocator.free(vote_pubkeys);
    {
        var prng = std.Random.DefaultPrng.init(98765);
        const random = prng.random();
        for (vote_pubkeys) |*k| k.* = Pubkey.initRandom(random);

        var epoch_stakes = try sig.consensus.fork_choice.testEpochStakes(
            allocator,
            vote_pubkeys,
            100, // stake per account; total = 500
            random,
        );
        errdefer epoch_stakes.deinit(allocator);

        var epoch_consts = try sig.core.EpochConstants.genesis(allocator, .default(allocator));
        errdefer epoch_consts.deinit(allocator);
        epoch_consts.stakes.deinit(allocator);
        epoch_consts.stakes = epoch_stakes;
        try epoch_tracker.epochs.put(allocator, 0, epoch_consts);

        const epoch_consts_ptr = epoch_tracker.epochs.getPtr(0).?;

        const slot_tracker_ptr, var st_lg = slot_tracker_rw.writeWithLock();
        defer st_lg.unlock();
        {
            const s1 = slot_tracker_ptr.get(1).?;
            const stakes_ptr1, var g1 = s1.state.stakes_cache.stakes.writeWithLock();
            defer g1.unlock();
            stakes_ptr1.deinit(allocator);
            stakes_ptr1.* = try epoch_consts_ptr.stakes.stakes.clone(allocator);
        }
        {
            const s2 = slot_tracker_ptr.get(2).?;
            const stakes_ptr2, var g2 = s2.state.stakes_cache.stakes.writeWithLock();
            defer g2.unlock();
            stakes_ptr2.deinit(allocator);
            stakes_ptr2.* = try epoch_consts_ptr.stakes.stakes.clone(allocator);
        }
        {
            const s4 = slot_tracker_ptr.get(4).?;
            const stakes_ptr4, var g4 = s4.state.stakes_cache.stakes.writeWithLock();
            defer g4.unlock();
            stakes_ptr4.deinit(allocator);
            stakes_ptr4.* = try epoch_consts_ptr.stakes.stakes.clone(allocator);
        }
    }
    defer epoch_tracker.deinit(allocator);
    var epoch_tracker_rw = RwMux(EpochTracker).init(epoch_tracker);

    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);
    {
        var fp0 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp0.fork_stats.computed = true;
        const fp1 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        var fp2 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp2.fork_stats.slot_hash = slot2_hash;
        var fp4 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp4.fork_stats.slot_hash = slot4_hash;
        try progress.map.put(allocator, 0, fp0);
        try progress.map.put(allocator, 1, fp1);
        try progress.map.put(allocator, 2, fp2);
        try progress.map.put(allocator, 4, fp4);
    }

    var replay_votes_channel = try Channel(ParsedVote).create(allocator);
    defer replay_votes_channel.destroy();

    const external = TowerConsensus.Dependencies.External{
        .senders = stubs.senders,
        .receivers = stubs.receivers,
        .gossip_table = null,
        .run_vote_listener = false,
    };

    const deps = TowerConsensus.Dependencies{
        .logger = .noop,
        .my_identity = Pubkey.initRandom(std.crypto.random),
        .vote_identity = Pubkey.initRandom(std.crypto.random),
        .root_slot = root_slot,
        .root_hash = Hash.ZEROES,
        .account_reader = stubs.accountsdb.accountReader(),
        .ledger = &stubs.ledger,
        .exit = &stubs.exit,
        .replay_votes_channel = replay_votes_channel,
        .slot_tracker_rw = &slot_tracker_rw,
        .epoch_tracker_rw = &epoch_tracker_rw,
        .external = external,
    };

    var consensus = try TowerConsensus.init(allocator, deps);
    defer consensus.deinit(allocator);

    _ = try consensus.replay_tower.recordBankVote(allocator, 1, slot1_hash);

    // Seed latest validator votes to support slot 4 (>38% of 500 = 190)
    for (vote_pubkeys[0..3]) |pk| {
        // Record the vote gotten via gossip.
        _ = try consensus.latest_validator_votes.checkAddVote(
            allocator,
            pk,
            4,
            slot4_hash,
            .gossip,
        );
        // Record the vote gotten via replay.
        _ = try consensus.latest_validator_votes.checkAddVote(
            allocator,
            pk,
            4,
            slot4_hash,
            .replay,
        );
    }

    var ancestors_map = std.AutoArrayHashMapUnmanaged(Slot, sig.core.Ancestors).empty;
    var descendants_map =
        std.AutoArrayHashMapUnmanaged(Slot, sig.utils.collections.SortedSetUnmanaged(Slot)).empty;
    defer {
        var it = ancestors_map.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        ancestors_map.deinit(allocator);
        var it2 = descendants_map.iterator();
        while (it2.next()) |entry| entry.value_ptr.deinit(allocator);
        descendants_map.deinit(allocator);
    }
    {
        const st_ptr, var lg = slot_tracker_rw.readWithLock();
        defer lg.unlock();
        try ancestors_map.ensureTotalCapacity(allocator, st_ptr.slots.count());
        try descendants_map.ensureTotalCapacity(allocator, st_ptr.slots.count());
        for (st_ptr.slots.keys(), st_ptr.slots.values()) |slot, info| {
            const slot_ancestors = &info.constants.ancestors.ancestors;
            const gop = try ancestors_map.getOrPutValue(allocator, slot, .EMPTY);
            if (!gop.found_existing) {
                try gop.value_ptr.ancestors.ensureUnusedCapacity(allocator, slot_ancestors.count());
            }
            for (slot_ancestors.keys()) |a| {
                try gop.value_ptr.addSlot(allocator, a);
                const dg = try descendants_map.getOrPutValue(allocator, a, .empty);
                try dg.value_ptr.put(allocator, slot);
            }
        }
    }

    const epoch_consts_ptr = blk: {
        const epochs_ptr, var epochs_lg = epoch_tracker_rw.readWithLock();
        defer epochs_lg.unlock();
        break :blk epochs_ptr.epochs.getPtr(0).?;
    };
    const vote_accounts_map = &epoch_consts_ptr.stakes.stakes.vote_accounts.vote_accounts;
    const total_stake: u64 = 500;

    // First, verify that we cannot switch to sibling slot 2 due to lockout
    // (with a single prior vote on 1, lastLockedOutSlot = 3, so 2 is locked out).
    {
        const decision2 = try consensus.replay_tower.makeCheckSwitchThresholdDecision(
            allocator,
            2,
            &ancestors_map,
            &descendants_map,
            &progress,
            total_stake,
            vote_accounts_map,
            &consensus.latest_validator_votes,
            &consensus.fork_choice,
        );
        switch (decision2) {
            .switch_proof => |h| try std.testing.expect(h.eql(Hash.ZEROES)),
            else => try std.testing.expect(false),
        }

        // Process slot 2 and assert no vote is cast on slot 2. With slot 4 present and eligible,
        // the vote may proceed to 4 instead (still demonstrates inability to switch to 2).
        const results2 = [_]ReplayResult{
            .{ .slot = 2, .output = .{ .last_entry_hash = slot2_hash } },
        };
        try consensus.process(allocator, &slot_tracker_rw, &epoch_tracker_rw, &progress, &results2);
        try std.testing.expectEqual(4, consensus.replay_tower.lastVotedSlot());
    }

    const decision = try consensus.replay_tower.makeCheckSwitchThresholdDecision(
        allocator,
        4,
        &ancestors_map,
        &descendants_map,
        &progress,
        total_stake,
        vote_accounts_map,
        &consensus.latest_validator_votes,
        &consensus.fork_choice,
    );
    switch (decision) {
        .switch_proof => |h| try std.testing.expect(h.eql(Hash.ZEROES)),
        .same_fork => {},
        else => try std.testing.expect(false),
    }

    // Now process slot 4; lockout for vote on 1 (lastLockedOutSlot = 3) does not prevent voting 4.
    {
        const results = [_]ReplayResult{
            .{ .slot = 4, .output = .{ .last_entry_hash = slot4_hash } },
        };
        try consensus.process(
            allocator,
            &slot_tracker_rw,
            &epoch_tracker_rw,
            &progress,
            &results,
        );
    }
    try std.testing.expectEqual(4, consensus.replay_tower.lastVotedSlot());

    // Add another sibling slot 5 with very small supporting stake so it fails switch threshold
    // without relying on lockout.
    const slot5_hash = Hash{ .data = .{5} ** Hash.SIZE };
    {
        // Add a new sibling with insufficient stake:
        //
        //     slot 0
        //     |   \
        //     |    \
        //     |     +-- slot 2 (B)
        //     +-- slot 1 (A)
        //           \
        //            +-- slot 4 (B')  [heavier sibling via votes]
        //            \
        //             +-- slot 5      [sibling with insufficient stake]
        //
        var slot_constants = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
        errdefer slot_constants.deinit(allocator);
        slot_constants.parent_slot = 0;
        slot_constants.parent_hash = Hash.ZEROES;
        slot_constants.block_height = 5;
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 5, {});

        var slot_state = try sig.core.SlotState.genesis(allocator);
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot5_hash);
        {
            const st_ptr, var st_lg = slot_tracker_rw.writeWithLock();
            defer st_lg.unlock();
            try st_ptr.put(allocator, 5, .{ .constants = slot_constants, .state = slot_state });
        }
    }
    // Progress map entry for slot 5
    {
        var fp5 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp5.fork_stats.slot_hash = slot5_hash;
        try progress.map.put(allocator, 5, fp5);
    }
    // Not seeding sufficient votes for slot 5.
    // This ensures it is below threshold so it cannot be switched to
    // Recompute bank stats for new frozen slot 5
    {
        const empty_results: []const ReplayResult = &.{};
        try consensus.process(
            allocator,
            &slot_tracker_rw,
            &epoch_tracker_rw,
            &progress,
            empty_results,
        );
    }
    // Build fresh ancestors/descendants for slot 5 decision
    var ancestors_map2 =
        std.AutoArrayHashMapUnmanaged(Slot, sig.core.Ancestors).empty;
    var descendants_map2 =
        std.AutoArrayHashMapUnmanaged(Slot, sig.utils.collections.SortedSetUnmanaged(Slot)).empty;
    defer {
        var it = ancestors_map2.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        ancestors_map2.deinit(allocator);
        var it2 = descendants_map2.iterator();
        while (it2.next()) |entry| entry.value_ptr.deinit(allocator);
        descendants_map2.deinit(allocator);
    }
    {
        const st_ptr, var lg = slot_tracker_rw.readWithLock();
        defer lg.unlock();
        try ancestors_map2.ensureTotalCapacity(allocator, st_ptr.slots.count());
        try descendants_map2.ensureTotalCapacity(allocator, st_ptr.slots.count());
        for (st_ptr.slots.keys(), st_ptr.slots.values()) |slot, info| {
            const slot_ancestors = &info.constants.ancestors.ancestors;
            const gop = try ancestors_map2.getOrPutValue(allocator, slot, .EMPTY);
            if (!gop.found_existing) {
                try gop.value_ptr.ancestors.ensureUnusedCapacity(allocator, slot_ancestors.count());
            }
            for (slot_ancestors.keys()) |a| {
                try gop.value_ptr.addSlot(allocator, a);
                const dg = try descendants_map2.getOrPutValue(allocator, a, .empty);
                try dg.value_ptr.put(allocator, slot);
            }
        }
    }
    // Check switch threshold decision for slot 5 fails due to insufficient stake
    const decision5 = try consensus.replay_tower.makeCheckSwitchThresholdDecision(
        allocator,
        5,
        &ancestors_map2,
        &descendants_map2,
        &progress,
        total_stake,
        vote_accounts_map,
        &consensus.latest_validator_votes,
        &consensus.fork_choice,
    );
    switch (decision5) {
        .failed_switch_threshold => |d| {
            // Observed stake should be less than total (definitely below threshold)
            try std.testing.expect(d.switch_proof_stake < d.total_stake);
        },
        else => try std.testing.expect(false),
    }
    // Attempt to process slot 5; should not change last voted slot due to threshold failure
    {
        const results5 = [_]ReplayResult{
            .{
                .slot = 5,
                .output = .{ .last_entry_hash = slot5_hash },
            },
        };
        try consensus.process(
            allocator,
            &slot_tracker_rw,
            &epoch_tracker_rw,
            &progress,
            &results5,
        );
        try std.testing.expectEqual(4, consensus.replay_tower.lastVotedSlot());
    }

    // Cleanup: free SlotTracker elements owned via slot_tracker_rw
    {
        const st, var st_lock = slot_tracker_rw.writeWithLock();
        defer st_lock.unlock();

        var it = st.slots.iterator();
        while (it.next()) |entry| {
            const element = entry.value_ptr.*;
            element.state.deinit(allocator);
            element.constants.deinit(allocator);
            allocator.destroy(element);
        }
        st.slots.deinit(allocator);
    }
}
