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
const EpochStakesMap = sig.core.EpochStakesMap;
const EpochSchedule = sig.core.EpochSchedule;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SlotAndHash = sig.core.hash.SlotAndHash;
const SlotState = sig.core.SlotState;
const SlotConstants = sig.core.SlotConstants;
const Transaction = sig.core.transaction.Transaction;

const AccountStore = sig.accounts_db.AccountStore;

const LedgerReader = sig.ledger.LedgerReader;
const LedgerResultWriter = sig.ledger.result_writer.LedgerResultWriter;

const SlotHistoryAccessor = sig.consensus.replay_tower.SlotHistoryAccessor;
const ReplayTower = sig.consensus.replay_tower.ReplayTower;
const ProgressMap = sig.consensus.progress_map.ProgressMap;
const ForkChoice = sig.consensus.fork_choice.ForkChoice;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const LatestValidatorVotes = sig.consensus.latest_validator_votes.LatestValidatorVotes;
const ThresholdConfirmedSlot = sig.consensus.vote_listener.ThresholdConfirmedSlot;
const GossipVerifiedVoteHash = sig.consensus.vote_listener.GossipVerifiedVoteHash;
const VerifiedVote = sig.consensus.vote_listener.VerifiedVote;
const VoteListener = sig.consensus.vote_listener.VoteListener;

const SlotTracker = sig.replay.trackers.SlotTracker;
const EpochTracker = sig.replay.trackers.EpochTracker;
const SlotData = sig.replay.consensus.edge_cases.SlotData;
const AncestorDuplicateSlotToRepair = replay.consensus.edge_cases.AncestorDuplicateSlotToRepair;

const ReplayResult = replay.execution.ReplayResult;
const ProcessResultParams = replay.consensus.process_result.ProcessResultParams;

const processResult = replay.consensus.process_result.processResult;

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
    arena_state: std.heap.ArenaAllocator.State,

    // Data sources
    account_store: AccountStore,
    ledger_reader: *LedgerReader,
    ledger_writer: *sig.ledger.LedgerResultWriter,

    // Communication channels
    senders: Senders,
    receivers: Receivers,
    verified_vote_channel: *Channel(VerifiedVote),

    // Supporting services
    vote_listener: ?VoteListener,

    pub fn deinit(self: *TowerConsensus, allocator: Allocator) void {
        self.vote_listener.joinAndDeinit();
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
        account_store: AccountStore,
        ledger_reader: *LedgerReader,
        ledger_writer: *sig.ledger.LedgerResultWriter,

        // channels/signals/communication
        exit: *AtomicBool,
        replay_votes_channel: *Channel(sig.consensus.vote_listener.vote_parser.ParsedVote),
        slot_tracker_rw: *RwMux(SlotTracker),
        epoch_tracker_rw: *RwMux(EpochTracker),
        external: External,

        /// Channels that extend outside of replay
        pub const External = struct {
            senders: Senders,
            receivers: Receivers,
            gossip_table: ?*RwMux(sig.gossip.GossipTable),

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

        // Initialize fork choice from root
        var fork_choice = try HeaviestSubtreeForkChoice.init(allocator, .from(deps.logger), .{
            .slot = deps.root_slot,
            .hash = deps.root_hash,
        });
        errdefer fork_choice.deinit();

        // Initialize replay tower
        const slot_tracker, var slot_tracker_lock = deps.slot_tracker_rw.readWithLock();
        defer slot_tracker_lock.unlock();

        const replay_tower: ReplayTower = try .init(
            allocator,
            .from(deps.logger),
            deps.my_identity,
            deps.vote_identity,
            deps.root_slot,
            deps.account_store.reader()
                .forSlot(&slot_tracker.get(slot_tracker.root).?.constants.ancestors),
        );
        errdefer replay_tower.deinit(allocator);

        const slot_data_provider: sig.consensus.vote_listener.SlotDataProvider = .{
            .slot_tracker_rw = deps.slot_tracker_rw,
            .epoch_tracker_rw = deps.epoch_tracker_rw,
        };

        const verified_vote_channel = try Channel(VerifiedVote).create(allocator);
        errdefer verified_vote_channel.destroy();

        const vote_listener: VoteListener = try .init(
            allocator,
            .{ .unordered = deps.exit },
            .from(deps.logger),
            .{
                .slot_data_provider = slot_data_provider,
                .gossip_table_rw = deps.external.gossip_table,
                .ledger_ref = .{
                    .reader = deps.ledger_reader,
                    .writer = deps.ledger_writer,
                },
                .receivers = .{ .replay_votes_channel = deps.replay_votes_channel },
                .senders = .{
                    .verified_vote = verified_vote_channel,
                    .gossip_verified_vote_hash = deps.external.receivers.gossip_verified_vote_hash,
                    .bank_notification = null,
                    .duplicate_confirmed_slot = deps.external.receivers.duplicate_confirmed_slots,
                    .subscriptions = .{},
                },
            },
        );

        return .{
            .fork_choice = fork_choice,
            .replay_tower = replay_tower,
            .latest_validator_votes = .empty,
            .status_cache = .DEFAULT,
            .slot_data = .empty,
            .arena_state = .{},
            .logger = deps.logger,
            .my_identity = deps.my_identity,
            .account_store = deps.account_store,
            .ledger_reader = deps.ledger_reader,
            .ledger_writer = deps.ledger_writer,
            .senders = deps.external.senders,
            .receivers = deps.external.receivers,
            .vote_listener = vote_listener,
            .verified_vote_channel = verified_vote_channel,
        };
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

        for (results) |result| {
            const slot_tracker, var slot_lock = slot_tracker_rw.readWithLock();
            defer slot_lock.unlock();

            const process_state: ProcessResultParams = .{
                .allocator = allocator,
                .logger = .from(self.logger),
                .my_identity = self.my_identity,
                .account_store = self.account_store,
                .ledger_reader = self.ledger_reader,
                .ledger_result_writer = self.ledger_writer,
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

            try processResult(process_state, result);
        }

        // Process edge cases and prepare ancestors/descendants
        const ancestors, const descendants = edge_cases_and_ancestors_descendants: {
            const slot_tracker, var slot_tracker_lg = slot_tracker_rw.readWithLock();
            defer slot_tracker_lg.unlock();

            _ = try replay.consensus.edge_cases.processEdgeCases(allocator, .from(self.logger), .{
                .my_pubkey = self.my_identity,
                .tpu_has_bank = false,
                .fork_choice = &self.fork_choice,
                .ledger = self.ledger_writer,
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
            {
                for (
                    slot_tracker.slots.keys(),
                    slot_tracker.slots.values(),
                ) |slot, info| {
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
            }
            break :edge_cases_and_ancestors_descendants .{ ancestors, descendants };
        };

        const slot_history_accessor = SlotHistoryAccessor.init(self.account_store.reader());

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
            &slot_history_accessor,
            self.my_identity, // vote_account
        );
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
        slot_history_accessor: *const SlotHistoryAccessor,
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
                std.debug.assert(!frozen_hash.eql(Hash.ZEROES));
                if (slot <= root_slot) {
                    continue;
                }
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
                    continue;
                }

                const duplicate_confirmed_state: sig.replay.consensus.edge_cases.DuplicateConfirmedState = .{
                    .duplicate_confirmed_hash = frozen_hash,
                    .slot_status = sig.replay.consensus.edge_cases.SlotStatus.fromHash(frozen_hash),
                };
                try check_slot_agrees_with_cluster.duplicateConfirmed(
                    allocator,
                    .noop,
                    slot,
                    root_slot,
                    self.ledger_writer,
                    &self.fork_choice,
                    &self.slot_data.duplicate_slots_to_repair,
                    self.senders.ancestor_hashes_replay_update,
                    &self.slot_data.purge_repair_slot_counter,
                    duplicate_confirmed_state,
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
            slot_history_accessor,
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
                self.ledger_writer,
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
    ledger_result_writer: *LedgerResultWriter,
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
    ledger_result_writer: *LedgerResultWriter,
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

    try ledger_result_writer.setRoots(rooted_slots);

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
    ledger: *const LedgerReader,
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
            fork_stats.voted_stakes = computed_bank_state.voted_stakes;
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
    stats.vote_threshold = .fromOwnedSlice(slice);

    const slot_ancestors = ancestors.get(slot) orelse return error.MissingAncestor;

    stats.is_locked_out = try replay_tower.tower.isLockedOut(slot, &slot_ancestors);
    stats.has_voted = replay_tower.tower.hasVoted(slot);
    stats.is_recent = replay_tower.tower.isRecent(slot);
}

const testing = std.testing;
const TreeNode = sig.consensus.fork_choice.TreeNode;
const testEpochStakes = sig.consensus.fork_choice.testEpochStakes;
const TestDB = sig.ledger.tests.TestDB;
const TestFixture = sig.consensus.replay_tower.TestFixture;
const MAX_TEST_TREE_LEN = sig.consensus.replay_tower.MAX_TEST_TREE_LEN;
const Lockout = sig.runtime.program.vote.state.Lockout;

const createTestReplayTower = sig.consensus.replay_tower.createTestReplayTower;

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

    var db = try TestDB.init(@src());
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);

    var ledger_result_writer = try LedgerResultWriter.init(
        testing.allocator,
        logger,
        db,
        &registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    // Try to check a slot that doesn't exist in the tracker
    const slot_tracker_ptr, var slot_tracker_lg = slot_tracker.writeWithLock();
    defer slot_tracker_lg.unlock();
    const result = checkAndHandleNewRoot(
        testing.allocator,
        &ledger_result_writer,
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

    var db = try TestDB.init(@src());
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);

    var ledger_result_writer = try LedgerResultWriter.init(
        testing.allocator,
        logger,
        db,
        &registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    // Try to check a slot that doesn't exist in the tracker
    const slot_tracker2_ptr, var slot_tracker2_lg = slot_tracker2.writeWithLock();
    defer slot_tracker2_lg.unlock();
    const result = checkAndHandleNewRoot(
        testing.allocator,
        &ledger_result_writer,
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

    var db = try TestDB.init(@src());
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);

    var ledger_result_writer = try LedgerResultWriter.init(
        testing.allocator,
        logger,
        db,
        &registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    // Try to check a slot that doesn't exist in the tracker
    const slot_tracker3_ptr, var slot_tracker3_lg = slot_tracker3.writeWithLock();
    defer slot_tracker3_lg.unlock();
    const result = checkAndHandleNewRoot(
        testing.allocator,
        &ledger_result_writer,
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

    var db = try TestDB.init(@src());
    defer db.deinit();

    var registry = sig.prometheus.Registry(.{}).init(testing.allocator);
    defer registry.deinit();
    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);

    var ledger_result_writer = try LedgerResultWriter.init(
        testing.allocator,
        .noop,
        db,
        &registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    try testing.expectEqual(4, fixture.progress.map.count());
    try testing.expect(fixture.progress.map.contains(hash1.slot));
    {
        const slot_tracker4_ptr, var slot_tracker4_lg = slot_tracker4.writeWithLock();
        defer slot_tracker4_lg.unlock();
        try checkAndHandleNewRoot(
            testing.allocator,
            &ledger_result_writer,
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
