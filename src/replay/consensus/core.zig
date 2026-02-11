const std = @import("std");
const sig = @import("../../sig.zig");
const replay = @import("../lib.zig");
const tracy = @import("tracy");

const cluster_sync = replay.consensus.cluster_sync;
const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);

const vote_program = sig.runtime.program.vote;
const vote_instruction = vote_program.vote_instruction;

pub const Logger = sig.trace.Logger("consensus");

const Channel = sig.sync.Channel;
const RwMux = sig.sync.RwMux;
const SortedSetUnmanaged = sig.utils.collections.SortedSetUnmanaged;

const Ancestors = sig.core.Ancestors;
const Epoch = sig.core.Epoch;
const EpochSchedule = sig.core.EpochSchedule;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SlotAndHash = sig.core.hash.SlotAndHash;
const SlotConstants = sig.core.SlotConstants;
const SlotState = sig.core.SlotState;
const Transaction = sig.core.transaction.Transaction;
const SocketAddr = sig.net.SocketAddr;

const Tower = sig.consensus.tower.Tower;
const VoteStateVersions = sig.runtime.program.vote.state.VoteStateVersions;

/// UDP sockets used to send vote transactions.
pub const VoteSockets = struct {
    ipv4: sig.net.UdpSocket,
    ipv6: sig.net.UdpSocket,

    pub fn init() !VoteSockets {
        const s4: sig.net.UdpSocket = try .create(.ipv4);
        errdefer s4.close();
        const s6: sig.net.UdpSocket = try .create(.ipv6);
        errdefer s6.close();
        return .{ .ipv4 = s4, .ipv6 = s6 };
    }

    pub fn deinit(self: *const VoteSockets) void {
        var mut = self.*;
        mut.ipv4.close();
        mut.ipv6.close();
    }
};

const AccountReader = sig.accounts_db.AccountReader;
const AccountStore = sig.accounts_db.AccountStore;

/// Transaction forwarding, which leader to forward to and how long to hold
const FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET: u64 = 2;

const Ledger = sig.ledger.Ledger;

const ForkChoice = sig.consensus.fork_choice.ForkChoice;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const LatestValidatorVotes = sig.consensus.latest_validator_votes.LatestValidatorVotes;
const ParsedVote = sig.consensus.vote_listener.vote_parser.ParsedVote;
const ProgressMap = sig.consensus.progress_map.ProgressMap;
const ReplayTower = sig.consensus.replay_tower.ReplayTower;
const SwitchForkDecision = sig.consensus.replay_tower.SwitchForkDecision;
const ThresholdConfirmedSlot = sig.consensus.vote_listener.ThresholdConfirmedSlot;

const SlotTracker = sig.replay.trackers.SlotTracker;

const AncestorDuplicateSlotToRepair = replay.consensus.cluster_sync.AncestorDuplicateSlotToRepair;
const DuplicateConfirmedState = sig.replay.consensus.cluster_sync.DuplicateConfirmedState;
const SlotData = sig.replay.consensus.cluster_sync.SlotData;
const SlotStatus = sig.replay.consensus.cluster_sync.SlotStatus;

const ReplayResult = replay.execution.ReplayResult;
const ProcessResultParams = replay.consensus.process_result.ProcessResultParams;
const GossipVerifiedVoteHash = sig.consensus.vote_listener.GossipVerifiedVoteHash;

const collectClusterVoteState = sig.consensus.replay_tower.collectClusterVoteState;
const isDuplicateSlotConfirmed = sig.consensus.replay_tower.isDuplicateSlotConfirmed;
const check_slot_agrees_with_cluster =
    sig.replay.consensus.cluster_sync.check_slot_agrees_with_cluster;

const MAX_VOTE_REFRESH_INTERVAL_MILLIS: usize = 5000;

pub const VoteOp = union(enum) {
    push_vote: struct {
        tx: Transaction,
        last_tower_slot: ?Slot,
    },
    refresh_vote: struct {
        tx: Transaction,
        last_voted_slot: Slot,
    },
};

/// TowerConsensus contains all the state needed for operating the Tower BFT
/// consensus mechanism in sig.
pub const TowerConsensus = struct {
    logger: Logger,
    identity: sig.identity.ValidatorIdentity,
    signing: sig.identity.SigningKeys,

    // Core consensus state
    fork_choice: HeaviestSubtreeForkChoice,
    replay_tower: ReplayTower,
    latest_validator_votes: LatestValidatorVotes,
    status_cache: sig.core.StatusCache,
    slot_data: SlotData,

    vote_collector: sig.consensus.VoteCollector,

    /// this is used for some temporary allocations that don't outlive
    /// functions; ie, it isn't used for any persistent data
    arena_state: std.heap.ArenaAllocator.State,

    pub fn deinit(self: TowerConsensus, allocator: Allocator) void {
        self.replay_tower.deinit(allocator);
        self.fork_choice.deinit(allocator);

        var latest_validator_votes = self.latest_validator_votes;
        latest_validator_votes.deinit(allocator);

        self.slot_data.deinit(allocator);
        self.arena_state.promote(allocator).deinit();
    }

    pub fn init(
        allocator: Allocator,
        deps: struct {
            logger: Logger,
            identity: sig.identity.ValidatorIdentity,
            signing: sig.identity.SigningKeys,
            account_reader: AccountReader,
            ledger: *sig.ledger.Ledger,
            slot_tracker: *const SlotTracker,
            /// Usually `.now()`.
            now: sig.time.Instant,
            registry: *sig.prometheus.Registry(.{}),
        },
    ) !TowerConsensus {
        const zone = tracy.Zone.init(@src(), .{ .name = "TowerConsensus.init" });
        defer zone.deinit();

        var fork_choice = try initForkChoice(
            allocator,
            deps.logger,
            deps.slot_tracker,
            deps.ledger,
        );
        errdefer fork_choice.deinit(allocator);

        const root_ref = deps.slot_tracker.get(deps.slot_tracker.root).?;
        const root_ancestors = &root_ref.constants.ancestors;

        var tower: Tower = if (deps.identity.vote_account) |vote_account_address|
            try loadTower(
                allocator,
                deps.logger,
                deps.account_reader.forSlot(root_ancestors),
                vote_account_address,
            )
        else
            .{ .root = deps.slot_tracker.root };
        tower.setRoot(deps.slot_tracker.root);

        const replay_tower: ReplayTower = try .init(
            .from(deps.logger),
            deps.identity.validator,
            tower,
            deps.registry,
        );
        errdefer replay_tower.deinit(allocator);

        var vote_collector: sig.consensus.VoteCollector =
            try .init(deps.now, deps.slot_tracker.root, deps.registry);
        errdefer vote_collector.deinit(allocator);

        return .{
            .logger = deps.logger,
            .identity = deps.identity,
            .signing = deps.signing,

            .fork_choice = fork_choice,
            .replay_tower = replay_tower,
            .latest_validator_votes = .empty,
            .status_cache = .DEFAULT,
            .slot_data = .empty,

            .vote_collector = vote_collector,

            .arena_state = .{},
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
        var heaviest_subtree_fork_choice: HeaviestSubtreeForkChoice = try .init(
            allocator,
            .from(logger),
            .{ .slot = root_slot, .hash = root_hash },
            sig.prometheus.globalRegistry(),
        );
        errdefer heaviest_subtree_fork_choice.deinit(allocator);

        var prev_slot = root_slot;
        for (frozen_slots.keys(), frozen_slots.values()) |slot, info| {
            const frozen_hash = info.state.hash.readCopy().?;
            if (slot > root_slot) {
                // Make sure the list is sorted
                std.debug.assert(slot > prev_slot);
                prev_slot = slot;
                const parent_bank_hash = info.constants.parent_hash;
                try heaviest_subtree_fork_choice.addNewLeafSlot(
                    allocator,
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
            try heaviest_subtree_fork_choice.markForkInvalidCandidate(allocator, &.{
                .slot = slot,
                .hash = ref.state.hash.readCopy().?,
            });
        }

        return heaviest_subtree_fork_choice;
    }

    /// Channels where consensus sends messages to other services
    pub const Senders = struct {
        /// Received by repair ancestor_hashes_service
        ancestor_hashes_replay_update: *Channel(AncestorHashesReplayUpdate),
        /// The vote collector sends verified votes through this channel.
        verified_vote: *sig.sync.Channel(sig.consensus.vote_listener.VerifiedVote),

        pub fn destroy(self: Senders) void {
            self.ancestor_hashes_replay_update.destroy();
            self.verified_vote.destroy();
        }

        pub fn create(allocator: std.mem.Allocator) std.mem.Allocator.Error!Senders {
            const ancestor_hashes_replay_update: *Channel(AncestorHashesReplayUpdate) =
                try .create(allocator);
            errdefer ancestor_hashes_replay_update.destroy();
            const verified_vote: *sig.sync.Channel(sig.consensus.vote_listener.VerifiedVote) =
                try .create(allocator);
            errdefer verified_vote.destroy();

            return .{
                .ancestor_hashes_replay_update = ancestor_hashes_replay_update,
                .verified_vote = verified_vote,
            };
        }
    };

    /// Channels where consensus receives messages from other services
    pub const Receivers = struct {
        /// Sent by repair ancestor_hashes_service
        ancestor_duplicate_slots: *Channel(AncestorDuplicateSlotToRepair),
        /// Sent by repair service
        popular_pruned_forks: *Channel(Slot),
        /// Sent by WindowService and DuplicateShred handlers
        duplicate_slots: *Channel(Slot),
        /// Sent by `replayActiveSlots`, received by the vote collector.
        /// Optional - null when consensus is disabled.
        replay_votes: ?*Channel(ParsedVote),

        // Note: replay_votes is owned by ReplayState, not destroyed here
        pub fn destroy(self: Receivers) void {
            self.ancestor_duplicate_slots.destroy();
            self.popular_pruned_forks.destroy();
            self.duplicate_slots.destroy();
        }

        pub fn create(
            allocator: std.mem.Allocator,
            replay_votes: ?*Channel(ParsedVote),
        ) std.mem.Allocator.Error!Receivers {
            const ancestor_duplicate_slots: *Channel(AncestorDuplicateSlotToRepair) =
                try .create(allocator);
            errdefer ancestor_duplicate_slots.destroy();

            const popular_pruned_forks: *Channel(Slot) = try .create(allocator);
            errdefer popular_pruned_forks.destroy();

            const duplicate_slots: *Channel(Slot) = try .create(allocator);
            errdefer duplicate_slots.destroy();

            return .{
                .ancestor_duplicate_slots = ancestor_duplicate_slots,
                .popular_pruned_forks = popular_pruned_forks,
                .duplicate_slots = duplicate_slots,
                .replay_votes = replay_votes,
            };
        }
    };

    /// Run all phases of consensus:
    /// - process replay results
    /// - cluster sync
    /// - actual consensus protocol.
    pub fn process(
        self: *TowerConsensus,
        allocator: Allocator,
        params: struct {
            account_store: AccountStore,
            ledger: *Ledger,
            /// Scanned by the vote collector if provided.
            gossip_votes: ?*sig.sync.Channel(sig.gossip.data.Vote),
            slot_tracker: *SlotTracker,
            epoch_tracker: *sig.core.EpochTracker,
            progress_map: *ProgressMap,
            status_cache: ?*sig.core.StatusCache,
            senders: Senders,
            receivers: Receivers,
            vote_sockets: ?*const VoteSockets,
            slot_leaders: ?sig.core.leader_schedule.SlotLeaders,
            /// Generally expected to be empty, but can be non-empty for testing purposes.
            /// Will be appended to, and then cleared after being used as an input to consensus.
            duplicate_confirmed_slots: *std.ArrayListUnmanaged(ThresholdConfirmedSlot),
            /// Same comments on `duplicate_confirmed_slots` apply.
            gossip_verified_vote_hashes: *std.ArrayListUnmanaged(GossipVerifiedVoteHash),
            results: []const ReplayResult,
        },
    ) !void {
        var zone = tracy.Zone.init(@src(), .{ .name = "TowerConsensus.process" });
        defer zone.deinit();

        var arena_state = self.arena_state.promote(allocator);
        defer {
            _ = arena_state.reset(.retain_capacity);
            self.arena_state = arena_state.state;
        }
        const arena = arena_state.allocator();

        try self.vote_collector.collectAndProcessVotes(allocator, .from(self.logger), .{
            .slot_data_provider = .{
                .slot_tracker = params.slot_tracker,
                .epoch_tracker = params.epoch_tracker,
            },
            .senders = .{
                .verified_vote = params.senders.verified_vote,
                .gossip_verified_vote_hashes = params.gossip_verified_vote_hashes,
                .duplicate_confirmed_slots = params.duplicate_confirmed_slots,
                .bank_notification = null,
                .subscriptions = .{},
            },
            .receivers = .{ .replay_votes = params.receivers.replay_votes },
            .ledger = params.ledger,
            .gossip_votes = params.gossip_votes,
        });

        // Process replay results
        for (params.results) |r| {
            try self.processResult(
                allocator,
                params.ledger,
                params.progress_map,
                params.slot_tracker,
                params.senders.ancestor_hashes_replay_update,
                r,
            );
        }

        // Process cluster sync and prepare ancestors/descendants
        const ancestors, const descendants = cluster_sync_and_ancestors_descendants: {
            _ = try cluster_sync.processClusterSync(allocator, .from(self.logger), .{
                .my_pubkey = self.identity.validator,
                .tpu_has_bank = false,
                .fork_choice = &self.fork_choice,
                .result_writer = params.ledger.resultWriter(),
                .slot_tracker = params.slot_tracker,
                .progress = params.progress_map,
                .latest_validator_votes = &self.latest_validator_votes,
                .slot_data = &self.slot_data,
                .duplicate_confirmed_slots = params.duplicate_confirmed_slots.items,
                .gossip_verified_vote_hashes = params.gossip_verified_vote_hashes.items,
                .senders = params.senders,
                .receivers = params.receivers,
            });
            params.duplicate_confirmed_slots.clearRetainingCapacity();
            params.gossip_verified_vote_hashes.clearRetainingCapacity();

            const SlotSet = SortedSetUnmanaged(Slot);

            const asc_desc_zone = tracy.Zone.init(
                @src(),
                .{ .name = "TowerConsensus.process: ancestors/descendants" },
            );
            defer asc_desc_zone.deinit();

            // arena-allocated
            var ancestors: std.AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;
            var descendants: std.AutoArrayHashMapUnmanaged(Slot, SlotSet) = .empty;
            for (params.slot_tracker.slots.keys(), params.slot_tracker.slots.values()) |slot, info| {
                const slot_ancestors = &info.constants.ancestors.ancestors;
                const ancestor_gop = try ancestors.getOrPutValue(arena, slot, .EMPTY);
                // Ensure every slot has a descendants entry (even if empty)
                _ = try descendants.getOrPutValue(arena, slot, .empty);
                try ancestor_gop.value_ptr.ancestors
                    .ensureUnusedCapacity(arena, slot_ancestors.count());
                for (slot_ancestors.keys()) |ancestor_slot| {
                    // Exclude the slot itself from ancestors.
                    if (ancestor_slot == slot) continue;
                    try ancestor_gop.value_ptr.addSlot(arena, ancestor_slot);
                    const descendants_gop =
                        try descendants.getOrPutValue(arena, ancestor_slot, .empty);
                    try descendants_gop.value_ptr.put(arena, slot);
                }
            }
            break :cluster_sync_and_ancestors_descendants .{ ancestors, descendants };
        };

        try self.executeProtocol(
            allocator,
            params.ledger,
            null, // TODO
            &ancestors,
            &descendants,
            params.slot_tracker,
            params.epoch_tracker,
            params.progress_map,
            params.status_cache,
            params.account_store,
            params.slot_leaders,
            params.vote_sockets,
            self.identity.vote_account,
            params.senders,
        );
    }

    fn processResult(
        self: *TowerConsensus,
        allocator: Allocator,
        ledger: *Ledger,
        progress_map: *ProgressMap,
        slot_tracker: *const SlotTracker,
        ancestor_hashes_replay_update_sender: *Channel(AncestorHashesReplayUpdate),
        result: ReplayResult,
    ) !void {
        const process_state: ProcessResultParams = .{
            .allocator = allocator,
            .logger = .from(self.logger),
            .my_identity = self.identity.validator,
            .ledger = ledger,
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
            .ancestor_hashes_replay_update_sender = ancestor_hashes_replay_update_sender,
        };

        try replay.consensus.process_result.processResult(process_state, result);
    }

    /// runs the core consensus protocol: select fork, vote, and update internal state
    fn executeProtocol(
        self: *TowerConsensus,
        allocator: Allocator,
        ledger: *Ledger,
        gossip_table: ?*sig.sync.RwMux(sig.gossip.GossipTable),
        ancestors: *const std.AutoArrayHashMapUnmanaged(Slot, Ancestors),
        descendants: *const std.AutoArrayHashMapUnmanaged(Slot, SortedSetUnmanaged(Slot)),
        slot_tracker: *SlotTracker,
        epoch_tracker: *sig.core.EpochTracker,
        progress_map: *ProgressMap,
        status_cache: ?*sig.core.StatusCache,
        /// For reading the slot history account
        account_store: AccountStore,
        slot_leaders: ?sig.core.leader_schedule.SlotLeaders,
        vote_sockets: ?*const VoteSockets,
        vote_account: ?Pubkey,
        senders: Senders,
    ) !void {
        const newly_computed_consensus_slots = try computeConsensusInputs(
            allocator,
            self.logger,
            vote_account,
            ancestors,
            slot_tracker,
            epoch_tracker,
            progress_map,
            &self.fork_choice,
            &self.replay_tower,
            &self.latest_validator_votes,
        );
        defer allocator.free(newly_computed_consensus_slots);
        // For each of the newly computed consensus slots,
        // check their duplicate confirmation status and updates the data structures that
        // needs this information.
        for (newly_computed_consensus_slots) |slot_stat| {
            const fork_stats = progress_map.getForkStats(slot_stat) orelse
                return error.MissingSlotInForkStats;
            // Checking the duplicate confirmation status.
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
            // Update cluster with the duplicate confirmation status.
            // Analogous to [ReplayStage::mark_slots_duplicate_confirmed](https://github.com/anza-xyz/agave/blob/47c0383f2301e5a739543c1af9992ae182b7e06c/core/src/replay_stage.rs#L3876)
            const root_slot = slot_tracker.root;
            for (duplicate_confirmed_forks.items) |duplicate_confirmed_fork| {
                const slot, const frozen_hash = duplicate_confirmed_fork.tuple();
                try self.handleDuplicateConfirmedFork(
                    allocator,
                    ledger,
                    progress_map,
                    root_slot,
                    slot,
                    frozen_hash,
                    senders.ancestor_hashes_replay_update,
                );
            }
        }

        const heaviest_slot = self.fork_choice.heaviestOverallSlot().slot;
        const heaviest_slot_on_same_voted_fork =
            (try self.fork_choice.heaviestSlotOnSameVotedFork(&self.replay_tower)) orelse null;

        const now = sig.time.Instant.now();
        var last_vote_refresh_time: LastVoteRefreshTime = .{
            .last_refresh_time = now,
            .last_print_time = now,
        };

        var vote_and_reset_forks = try self.replay_tower.selectVoteAndResetForks(
            allocator,
            heaviest_slot,
            if (heaviest_slot_on_same_voted_fork) |h| h.slot else null,
            ancestors,
            descendants,
            progress_map,
            &self.latest_validator_votes,
            &self.fork_choice,
            epoch_tracker,
            account_store.reader(),
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
                self.logger,
                allocator,
                ledger.resultWriter(),
                voted.slot,
                voted_hash,
                slot_tracker,
                &epoch_tracker.epoch_schedule,
                epoch_tracker,
                &self.replay_tower,
                progress_map,
                &self.fork_choice,
                account_store,
                status_cache,
                self.signing.node,
                self.signing.authorized_voters,
                self.identity.vote_account,
                voted.decision,
                gossip_table,
                slot_leaders,
                vote_sockets,
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
        ledger: *Ledger,
        progress_map: *const ProgressMap,
        root: Slot,
        slot: Slot,
        frozen_hash: Hash,
        ancestor_hashes_replay_update_sender: *Channel(AncestorHashesReplayUpdate),
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
            ledger.resultWriter(),
            &self.fork_choice,
            &self.slot_data.duplicate_slots_to_repair,
            ancestor_hashes_replay_update_sender,
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

/// Returns the Tower derived from the vote account at the provided address or
/// returns an error if a Tower cannot be initialized.
fn loadTower(
    allocator: std.mem.Allocator,
    logger: Logger,
    slot_account_reader: sig.accounts_db.SlotAccountReader,
    vote_account_address: Pubkey,
) !Tower {
    const vote_account = try slot_account_reader.get(allocator, vote_account_address) orelse {
        logger.info().logf("Vote account not found", .{});
        return error.VoteAccountNotFound;
    };
    defer vote_account.deinit(allocator);

    // Validate that the account is owned by the vote program
    if (!vote_account.owner.equals(&sig.runtime.program.vote.ID)) {
        logger.err().logf(
            "Invalid vote account owner. Expected: {}, Got: {}",
            .{ sig.runtime.program.vote.ID, vote_account.owner },
        );
        return error.InvalidVoteAccountOwner;
    }

    logger.debug().logf(
        "Vote account loaded: Pubkey={?}, Lamports={}, Owner={}, Data length={}",
        .{
            vote_account_address,
            vote_account.lamports,
            vote_account.owner,
            vote_account.data.len(),
        },
    );

    var iter = vote_account.data.iterator();
    const versioned_state = sig.bincode.read(
        allocator,
        VoteStateVersions,
        iter.reader(),
        .{},
    ) catch return error.BincodeError;

    var vote_state = try versioned_state.convertToCurrent(allocator, null);
    defer vote_state.deinit(allocator);

    return try Tower.fromAccount(&vote_state);
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
    failed,
    // TODO add Transaction
    tx: Transaction,
};

/// Handles a votable bank by recording the vote, update commitment cache,
/// potentially processing a new root, and pushing the vote.
///
/// Analogous to [handle_votable_bank](https://github.com/anza-xyz/agave/blob/ccdcdbe9b6ff7dbd583d2101fe57b7cc41a6f863/core/src/replay_stage.rs#L2388)
fn handleVotableBank(
    logger: Logger,
    allocator: std.mem.Allocator,
    ledger_result_writer: Ledger.ResultWriter,
    vote_slot: Slot,
    vote_hash: Hash,
    slot_tracker: *SlotTracker,
    epoch_schedule: *const EpochSchedule,
    epoch_tracker: *sig.core.EpochTracker,
    replay_tower: *ReplayTower,
    progress: *ProgressMap,
    fork_choice: *ForkChoice,
    account_store: AccountStore,
    status_cache: ?*sig.core.StatusCache,
    node_keypair: ?sig.identity.KeyPair,
    authorized_voter_keypairs: []const sig.identity.KeyPair,
    vote_account_pubkey: ?Pubkey,
    switch_fork_decision: SwitchForkDecision,
    gossip_table_rw: ?*sig.sync.RwMux(sig.gossip.GossipTable),
    slot_leaders: ?sig.core.leader_schedule.SlotLeaders,
    maybe_sockets: ?*const VoteSockets,
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
            epoch_tracker,
            account_store,
            status_cache,
            new_root,
        );
    }

    // TODO update_commitment_cache

    // Skip vote generation and sending if not configured to vote
    // Note: When voting is disabled, `authorized_voter_keypairs` is set to an empty slice
    if (authorized_voter_keypairs.len == 0 or node_keypair == null or vote_account_pubkey == null) {
        replay_tower.markLastVoteTxBlockhashNonVoting();
        return;
    }

    // - Generates a new vote transaction.
    // - Updates the tower's last vote blockhash.
    // - Sends the vote operation to the voting sender.
    //
    // Analogous to [push_vote](https://github.com/anza-xyz/agave/blob/ccdcdbe9b6ff7dbd583d2101fe57b7cc41a6f863/core/src/replay_stage.rs#L2775)
    const vote_tx_result = try generateVoteTx(
        allocator,
        vote_account_pubkey,
        authorized_voter_keypairs,
        node_keypair,
        switch_fork_decision,
        replay_tower,
        account_store.reader(),
        slot_tracker,
        epoch_schedule,
    );

    switch (vote_tx_result) {
        .tx => |vote_tx| {
            // Update the tower's last vote blockhash
            replay_tower.refreshLastVoteTxBlockhash(vote_tx.msg.recent_blockhash);

            const last_tower_slot = replay_tower.tower.lastVotedSlot();
            try sendVote(
                logger,
                allocator,
                vote_slot,
                .{
                    .push_vote = .{
                        .last_tower_slot = last_tower_slot,
                        .tx = vote_tx,
                    },
                },
                gossip_table_rw,
                slot_leaders,
                node_keypair,
                sig.time.getWallclockMs(),
                maybe_sockets,
            );
        },
        .non_voting => {
            replay_tower.markLastVoteTxBlockhashNonVoting();
        },
        else => {
            // Do nothing
        },
    }
}

/// Returns an owned slice of tpu vote sockets for the leaders of the next N fanout
/// slots. Leaders and sockets are deduped. Caller owns the returned slice.
fn upcomingLeaderTpuVoteSockets(
    allocator: Allocator,
    current_slot: Slot,
    slot_leaders: sig.core.leader_schedule.SlotLeaders,
    gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
    fanout_slots: u64,
) ![]SocketAddr {
    var seen_leaders: std.AutoHashMapUnmanaged(Pubkey, void) = .empty;
    defer seen_leaders.deinit(allocator);

    for (0..fanout_slots) |n_slots| {
        const target_slot = current_slot + n_slots;
        if (slot_leaders.get(target_slot)) |leader| {
            try seen_leaders.put(allocator, leader, {});
        }
    }

    var seen_sockets: std.AutoArrayHashMapUnmanaged(SocketAddr, void) = .empty;
    try seen_sockets.ensureTotalCapacity(allocator, seen_leaders.count());
    defer seen_sockets.deinit(allocator);
    {
        const gossip_table, var gossip_table_lg = gossip_table_rw.readWithLock();
        defer gossip_table_lg.unlock();
        var leader_iter = seen_leaders.keyIterator();
        while (leader_iter.next()) |leader_pubkey_ptr| {
            const leader_pubkey = leader_pubkey_ptr.*;
            const contact_info =
                gossip_table.getThreadSafeContactInfo(leader_pubkey) orelse continue;
            const socket_addr = contact_info.tpu_addr orelse continue;
            seen_sockets.putAssumeCapacity(socket_addr, {});
        }
    }

    return try allocator.dupe(SocketAddr, seen_sockets.keys());
}

fn sendVoteTransaction(
    logger: Logger,
    vote_tx: Transaction,
    tpu_address: SocketAddr,
    sockets: *const VoteSockets,
) !void {
    var buf: [sig.net.Packet.DATA_SIZE]u8 = undefined;
    const serialized = try sig.bincode.writeToSlice(&buf, vote_tx, .{});

    const socket = switch (tpu_address) {
        .V4 => sockets.ipv4,
        .V6 => sockets.ipv6,
    };

    _ = socket.sendTo(tpu_address.toAddress(), serialized) catch |err| {
        logger.err().logf("Failed to send vote transaction: {}", .{err});
        return err;
    };
}

fn sendVoteToLeaders(
    logger: Logger,
    allocator: Allocator,
    vote_slot: Slot,
    vote_tx: Transaction,
    slot_leaders: sig.core.leader_schedule.SlotLeaders,
    gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
    maybe_my_pubkey: ?Pubkey,
    sockets: *const VoteSockets,
) !void {
    const UPCOMING_LEADER_FANOUT_SLOTS: u64 =
        FORWARD_TRANSACTIONS_TO_LEADER_AT_SLOT_OFFSET + 1;

    const upcoming_leader_sockets = try upcomingLeaderTpuVoteSockets(
        allocator,
        vote_slot,
        slot_leaders,
        gossip_table_rw,
        UPCOMING_LEADER_FANOUT_SLOTS,
    );
    defer allocator.free(upcoming_leader_sockets);

    if (upcoming_leader_sockets.len > 0) {
        for (upcoming_leader_sockets) |tpu_vote_socket| {
            sendVoteTransaction(
                logger,
                vote_tx,
                tpu_vote_socket,
                sockets,
            ) catch |err| {
                logger.err().logf("Failed to send vote to leader: {}", .{err});
            };
        }
    } else {
        // Fallback: send to our own TPU address if no leaders were found
        if (maybe_my_pubkey) |my_pubkey| {
            const gossip_table, var gossip_table_lg = gossip_table_rw.readWithLock();
            defer gossip_table_lg.unlock();

            const self_contact =
                gossip_table.getThreadSafeContactInfo(my_pubkey) orelse {
                    logger.warn().log("No self contact info available for vote fallback");
                    return;
                };

            const self_tpu_addr = self_contact.tpu_addr orelse {
                logger.warn().log("No self TPU address for vote fallback");
                return;
            };

            sendVoteTransaction(
                logger,
                vote_tx,
                self_tpu_addr,
                sockets,
            ) catch |err| {
                logger.err().logf("Failed to send vote to self TPU: {}", .{err});
            };
        } else {
            logger.warn().log("Missing my_pubkey; cannot send vote to self TPU");
        }
    }
}

fn findVoteIndexToEvict(
    gossip_table: *sig.gossip.GossipTable,
    my_pubkey: Pubkey,
    tower_last: Slot,
) ?u8 {
    const MAX_VOTES: u8 = sig.gossip.data.MAX_VOTES;
    var my_vote_count: usize = 0;
    var oldest_ts: u64 = std.math.maxInt(u64);
    var oldest_index: u8 = 0;
    var oldest_index_is_valid: bool = false;
    var exists_newer_vote: bool = false;

    var iter = gossip_table.store.iterator();
    while (iter.next()) |entry| {
        if (entry.tag() != .Vote) continue;
        const key = entry.key_ptr.*;
        if (key != .Vote) continue;
        const key_index: u8 = key.Vote[0];
        const key_from = key.Vote[1];
        if (!key_from.equals(&my_pubkey)) continue;

        my_vote_count += 1;

        const vote_data = entry.getGossipData().Vote;
        const vote_slot = vote_data[1].slot;
        const is_evictable = (vote_slot == 0 or vote_slot < tower_last);
        const is_newer_or_equal = (vote_slot != 0 and vote_slot >= tower_last);
        if (is_newer_or_equal) {
            exists_newer_vote = true;
        }

        if (is_evictable) {
            const ts = entry.metadata_ptr.timestamp_on_insertion;
            if (!oldest_index_is_valid or ts < oldest_ts) {
                oldest_ts = ts;
                oldest_index = key_index;
                oldest_index_is_valid = true;
            }
        }
    }

    if (exists_newer_vote) {
        return null;
    }

    if (my_vote_count < MAX_VOTES) {
        return @intCast(my_vote_count);
    } else {
        if (!oldest_index_is_valid) return null;
        return oldest_index;
    }
}

fn sendVoteToGossip(
    vote_op: VoteOp,
    gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
    my_keypair: sig.identity.KeyPair,
    now: u64,
) !void {
    const gossip_table, var gossip_table_lock = gossip_table_rw.writeWithLock();
    defer gossip_table_lock.unlock();

    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);

    switch (vote_op) {
        .push_vote => |push_vote_data| {
            const tower_last = push_vote_data.last_tower_slot orelse return;
            // Find the oldest crds vote by wallclock that has a lower slot than `tower`
            // and recycle its vote-index. If the crds buffer is not full we instead add a new vote-index.
            const vote_index: u8 =
                findVoteIndexToEvict(gossip_table, my_pubkey, tower_last) orelse return;

            const vote_data = sig.gossip.data.GossipData{
                .Vote = .{
                    vote_index,
                    .{
                        .from = my_pubkey,
                        .transaction = push_vote_data.tx,
                        .wallclock = now,
                        .slot = 0, // will be set from transaction
                    },
                },
            };

            const signed_vote_data = sig.gossip.data.SignedGossipData.initSigned(
                &my_keypair,
                vote_data,
            );
            _ = try gossip_table.insert(signed_vote_data, now);
        },
        .refresh_vote => |refresh_vote_data| {
            const vote_data = sig.gossip.data.GossipData{
                .Vote = .{
                    0, // tag
                    .{
                        .from = my_pubkey,
                        .transaction = refresh_vote_data.tx,
                        .wallclock = now,
                        .slot = refresh_vote_data.last_voted_slot,
                    },
                },
            };

            const signed_vote_data = sig.gossip.data.SignedGossipData.initSigned(
                &my_keypair,
                vote_data,
            );
            _ = try gossip_table.insert(signed_vote_data, now);
        },
    }
}

// This processing currently runs on the same thread. If it proves to be a bottleneck
// in practice, we can offload it to a dedicated thread.
fn sendVote(
    logger: Logger,
    allocator: Allocator,
    vote_slot: Slot,
    vote_op: VoteOp,
    maybe_gossip_table_rw: ?*sig.sync.RwMux(sig.gossip.GossipTable),
    maybe_slot_leaders: ?sig.core.leader_schedule.SlotLeaders,
    maybe_my_keypair: ?sig.identity.KeyPair,
    now: u64,
    maybe_sockets: ?*const VoteSockets,
) !void {
    const gossip_table_rw = maybe_gossip_table_rw orelse {
        logger.warn().log("Cannot send vote: gossip table not provided");
        return;
    };

    const vote_tx = switch (vote_op) {
        .push_vote => |push_vote_data| push_vote_data.tx,
        .refresh_vote => |refresh_vote_data| refresh_vote_data.tx,
    };

    // Send to upcoming leaders
    if (maybe_slot_leaders) |slot_leaders| {
        const maybe_my_pubkey = if (maybe_my_keypair) |kp|
            Pubkey.fromPublicKey(&kp.public_key)
        else
            null;
        if (maybe_sockets) |sockets| {
            try sendVoteToLeaders(
                logger,
                allocator,
                vote_slot,
                vote_tx,
                slot_leaders,
                gossip_table_rw,
                maybe_my_pubkey,
                sockets,
            );
        }
    }

    // Send to gossip
    if (maybe_my_keypair) |my_keypair| {
        try sendVoteToGossip(
            vote_op,
            gossip_table_rw,
            my_keypair,
            now,
        );
    }
}

/// Generates a vote transaction
///
/// TODO Investigate newly added &mut tracked_vote_transactions parameter in Agave
/// Also the existing wait_to_vote_slot parameter
///
/// Analogous to [generate_vote_tx](https://github.com/anza-xyz/agave/blob/8e696b9a6ec1dc84a9add834f25325b9e39cbcb4/core/src/replay_stage.rs#L2561)
fn generateVoteTx(
    allocator: std.mem.Allocator,
    maybe_vote_account_pubkey: ?Pubkey,
    authorized_voter_keypairs: []const sig.identity.KeyPair,
    node_keypair: ?sig.identity.KeyPair,
    switch_fork_decision: SwitchForkDecision,
    replay_tower: *ReplayTower,
    account_reader: AccountReader,
    slot_tracker: *const SlotTracker,
    epoch_schedule: *const EpochSchedule,
) !GenerateVoteTxResult {
    const logger = replay_tower.logger;
    if (authorized_voter_keypairs.len == 0) {
        logger.debug().log("No authorized voter keypairs");
        return .non_voting;
    }

    const node_kp = node_keypair orelse {
        logger.debug().log("No node keypair");
        return .non_voting;
    };

    const vote_account_pubkey = maybe_vote_account_pubkey orelse {
        logger.debug().log("No vote account address");
        return .non_voting;
    };

    const last_voted_slot = replay_tower.lastVotedSlot() orelse {
        logger.info().log("No last voted slot");
        return .failed;
    };

    const slot_info = slot_tracker.get(last_voted_slot) orelse {
        logger.warn().logf(
            "Slot info not found in slot_tracker for last_voted_slot {}",
            .{last_voted_slot},
        );
        return .failed;
    };

    const vote_account_result = account_reader.forSlot(&slot_info.constants.ancestors)
        .get(allocator, vote_account_pubkey) catch |err| {
        logger.err().logf("Failed to read vote account: {}", .{err});
        return err;
    };

    const vote_account = vote_account_result orelse {
        logger.err().log("Vote account not found");
        return .failed;
    };
    defer vote_account.deinit(allocator);

    const vote_account_data = vote_account.data.readAllAllocate(allocator) catch |err| {
        logger.err().logf("Failed to read vote account data: {}", .{err});
        return err;
    };
    defer allocator.free(vote_account_data);

    var vote_state_versions = sig.bincode.readFromSlice(
        allocator,
        VoteStateVersions,
        vote_account_data,
        .{},
    ) catch |err| {
        logger.err().logf("Failed to deserialize vote state versions: {}", .{err});
        return .failed;
    };
    defer vote_state_versions.deinit(allocator);

    var vote_state = vote_state_versions.convertToCurrent(allocator, null) catch |err| {
        logger.err().logf("Failed to convert vote state to current: {}", .{err});
        return .failed;
    };
    defer vote_state.deinit(allocator);

    const node_pubkey = Pubkey.fromPublicKey(&node_kp.public_key);
    if (!vote_state.node_pubkey.equals(&node_pubkey)) {
        return .hot_spare;
    }

    const current_epoch = epoch_schedule.getEpoch(last_voted_slot);

    const authorized_voter_pubkey = vote_state.authorized_voters.getAuthorizedVoter(current_epoch) orelse {
        logger.err().logf("No authorized voter for epoch {}", .{current_epoch});
        return .failed;
    };

    const auth_voter_kp = blk: {
        for (authorized_voter_keypairs) |voter_keypair| {
            const pubkey = Pubkey.fromPublicKey(&voter_keypair.public_key);
            if (pubkey.equals(&authorized_voter_pubkey)) {
                break :blk voter_keypair;
            }
        }
        return .non_voting;
    };

    // Send our last few votes along with the new one
    // Compact the vote state update before sending
    const vote = switch (replay_tower.last_vote) {
        .vote_state_update => |vsu| sig.consensus.vote_transaction.VoteTransaction{
            .compact_vote_state_update = vsu,
        },
        else => replay_tower.last_vote,
    };

    const maybe_switch_proof_hash: ?Hash = switch (switch_fork_decision) {
        .switch_proof => |hash| hash,
        .same_fork => null,
        else => {
            logger.warn().logf("switch_fork_decision is {s}, cannot generate vote tx", .{
                @tagName(switch_fork_decision),
            });
            return .failed;
        },
    };

    const vote_ix = try createVoteInstruction(
        allocator,
        vote,
        vote_account_pubkey,
        authorized_voter_pubkey,
        maybe_switch_proof_hash,
    );
    defer vote_ix.deinit(allocator);

    const blockhash = slot_info.state.hash.readCopy() orelse {
        logger.warn().logf("Blockhash is null for slot {}", .{last_voted_slot});
        return .failed;
    };

    const vote_tx_msg = try sig.core.transaction.Message.initCompile(
        allocator,
        &.{vote_ix},
        Pubkey.fromPublicKey(&node_kp.public_key),
        blockhash,
        null,
    );
    errdefer vote_tx_msg.deinit(allocator);

    const vote_tx = try Transaction.initOwnedMessageWithSigningKeypairs(
        allocator,
        .legacy,
        vote_tx_msg,
        &.{ node_kp, auth_voter_kp },
    );

    return GenerateVoteTxResult{ .tx = vote_tx };
}

fn createVoteInstruction(
    allocator: std.mem.Allocator,
    vote: sig.consensus.vote_transaction.VoteTransaction,
    vote_pubkey: Pubkey,
    authorized_voter_pubkey: Pubkey,
    maybe_switch_proof_hash: ?Hash,
) !sig.core.Instruction {
    return switch (vote) {
        .vote => |v| {
            if (maybe_switch_proof_hash) |switch_hash| {
                return try vote_instruction.createVoteSwitch(
                    allocator,
                    vote_pubkey,
                    authorized_voter_pubkey,
                    .{
                        .vote = v,
                        .hash = switch_hash,
                    },
                );
            } else {
                return try vote_instruction.createVote(
                    allocator,
                    vote_pubkey,
                    authorized_voter_pubkey,
                    .{ .vote = v },
                );
            }
        },
        .vote_state_update => |vsu| {
            if (maybe_switch_proof_hash) |switch_hash| {
                return try vote_instruction.createUpdateVoteStateSwitch(
                    allocator,
                    vote_pubkey,
                    authorized_voter_pubkey,
                    .{
                        .vote_state_update = vsu,
                        .hash = switch_hash,
                    },
                );
            } else {
                return try vote_instruction.createUpdateVoteState(
                    allocator,
                    vote_pubkey,
                    authorized_voter_pubkey,
                    .{ .vote_state_update = vsu },
                );
            }
        },
        .compact_vote_state_update => |vsu| {
            if (maybe_switch_proof_hash) |switch_hash| {
                return try vote_instruction.createCompactUpdateVoteStateSwitch(
                    allocator,
                    vote_pubkey,
                    authorized_voter_pubkey,
                    .{
                        .vote_state_update = vsu,
                        .hash = switch_hash,
                    },
                );
            } else {
                return try vote_instruction.createCompactUpdateVoteState(
                    allocator,
                    vote_pubkey,
                    authorized_voter_pubkey,
                    .{ .vote_state_update = vsu },
                );
            }
        },
        .tower_sync => |ts| {
            if (maybe_switch_proof_hash) |switch_hash| {
                return try vote_instruction.createTowerSyncSwitch(
                    allocator,
                    vote_pubkey,
                    authorized_voter_pubkey,
                    .{
                        .tower_sync = ts,
                        .hash = switch_hash,
                    },
                );
            } else {
                return try vote_instruction.createTowerSync(
                    allocator,
                    vote_pubkey,
                    authorized_voter_pubkey,
                    .{ .tower_sync = ts },
                );
            }
        },
    };
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
    epoch_tracker: *sig.core.EpochTracker,
    account_store: AccountStore,
    status_cache: ?*sig.core.StatusCache,
    new_root: Slot,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "checkAndHandleNewRoot" });
    defer zone.deinit();

    // get the root bank before squash.
    if (slot_tracker.slots.count() == 0) return error.EmptySlotTracker;
    const root_tracker = slot_tracker.get(new_root) orelse return error.MissingSlot;
    const maybe_root_hash = root_tracker.state.hash.readCopy();
    const root_hash = maybe_root_hash orelse return error.MissingHash;

    const rooted_slots = try slot_tracker.parents(allocator, new_root);
    defer allocator.free(rooted_slots);

    try ledger.setRoots(rooted_slots);

    try epoch_tracker.onSlotRooted(
        allocator,
        new_root,
        &root_tracker.constants.ancestors,
    );

    // Audit: The rest of the code maps to Self::handle_new_root in Agave.
    // Update the slot tracker.
    // Set new root.
    slot_tracker.root = new_root;
    // Prune non rooted slots
    slot_tracker.pruneNonRooted(allocator);

    // Tell the status_cache about it for its tracking.
    if (status_cache) |sc| try sc.addRoot(allocator, new_root);
    // Tell the account_store about it for its unrooted accounts
    const slot_constants = slot_tracker.get(new_root).?;
    try account_store.onSlotRooted(new_root, &slot_constants.constants.ancestors);

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
    try fork_choice.setTreeRoot(allocator, &.{
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

/// Compute consensus inputs for frozen slots that haven't been processed yet (where fork_stats.computed = false).
/// The computed consensus inputs are needed for voting decisions and fork selection.
///
/// Consensus inputs computed:
/// - Stake distribution inputs (via collectClusterVoteState)
/// - Fork choice state (via fork_choice.processLatestVotes)
/// - Safety checks (via cacheVotingSafetyChecks)
///
/// All computed consensus inputs are updated in the fork choice and
/// cached in the ProgressMap (fork_stats field)
///
/// Returns the list of slots that had their consensus inputs freshly computed.
///
/// Analogous to [compute_bank_stats](https://github.com/anza-xyz/agave/blob/401ddc200b299a181b1437160189075958df49dd/core/src/replay_stage.rs#L3585)
fn computeConsensusInputs(
    allocator: std.mem.Allocator,
    logger: Logger,
    my_vote_pubkey: ?Pubkey,
    ancestors: *const std.AutoArrayHashMapUnmanaged(u64, Ancestors),
    slot_tracker: *const SlotTracker,
    epoch_tracker: *const sig.core.EpochTracker,
    progress: *ProgressMap,
    fork_choice: *ForkChoice,
    replay_tower: *const ReplayTower,
    latest_validator_votes: *LatestValidatorVotes,
) ![]Slot {
    var zone = tracy.Zone.init(@src(), .{ .name = "computeConsensusInputs" });
    defer zone.deinit();

    var new_stats = std.ArrayListUnmanaged(Slot).empty;
    errdefer new_stats.deinit(allocator);

    var frozen_slots = try slot_tracker.frozenSlots(allocator);
    defer frozen_slots.deinit(allocator);

    frozen_slots.sort(replay.service.FrozenSlotsSortCtx{ .slots = frozen_slots.keys() });

    for (frozen_slots.keys()) |slot| {
        const fork_stat = progress.getForkStats(slot) orelse return error.MissingSlot;
        if (!fork_stat.computed) {
            // TODO Self::adopt_on_chain_tower_if_behind
            // Gather voting information from all vote accounts to understand the current consensus state.
            const slot_info_for_stakes = slot_tracker.get(slot) orelse return error.MissingSlot;

            const cluster_vote_state = blk: {
                const stakes, var stakes_lg =
                    slot_info_for_stakes.state.stakes_cache.stakes.readWithLock();
                defer stakes_lg.unlock();

                break :blk try collectClusterVoteState(
                    allocator,
                    .from(logger),
                    my_vote_pubkey,
                    slot,
                    &stakes.vote_accounts.vote_accounts,
                    ancestors,
                    progress,
                    latest_validator_votes,
                );
            };
            // Update the fork choice tree with new votes discovered during collectClusterVoteState.
            // This updates the internal state of fork_choice with the determined heaviest (best) fork to build on.
            try fork_choice.processLatestVotes(
                allocator,
                epoch_tracker,
                latest_validator_votes,
            );
            const fork_stats = progress.getForkStats(slot) orelse return error.MissingForkStats;
            fork_stats.fork_stake = cluster_vote_state.fork_stake;
            fork_stats.total_stake = cluster_vote_state.total_stake;

            fork_stats.voted_stakes.deinit(allocator);
            fork_stats.voted_stakes = cluster_vote_state.voted_stakes;

            fork_stats.lockout_intervals.deinit(allocator);
            fork_stats.lockout_intervals = cluster_vote_state.lockout_intervals;

            fork_stats.block_height = blk: {
                const slot_info = slot_tracker.get(slot) orelse return error.MissingSlots;
                break :blk slot_info.constants.block_height;
            };
            fork_stats.my_latest_landed_vote = cluster_vote_state.my_latest_landed_vote;
            fork_stats.computed = true;
            try new_stats.append(allocator, slot);
        }
        try cacheVotingSafetyChecks(
            allocator,
            progress,
            replay_tower,
            slot,
            ancestors,
        );
    }
    return try new_stats.toOwnedSlice(allocator);
}

/// This pre-computes and updates the ProgressMap with voting safety checks
/// based on the tower for a frozen slot.
///
/// The critical checks are:
/// 1. `vote_threshold` - Verifies sufficient stake has voted at each lockout depth
/// 2. `is_locked_out` - Checks if prior votes on conflicting forks prevent voting here
/// 3. `has_voted` - Determines if we've already cast a vote for this slot
/// 4. `is_recent` - Ensures slot is newer than our last vote or root
///
/// These computed values are used in canVoteOnCandidateSlot during fork selection.
///
/// Analogous to [cache_tower_stats](https://github.com/anza-xyz/agave/blob/3572983cc28393e3c39a971c274cdac9b2eb902a/core/src/replay_stage.rs#L3799)
fn cacheVotingSafetyChecks(
    allocator: std.mem.Allocator,
    progress: *ProgressMap,
    replay_tower: *const ReplayTower,
    slot: Slot,
    ancestors: *const std.AutoArrayHashMapUnmanaged(Slot, Ancestors),
) !void {
    var zone = tracy.Zone.init(@src(), .{ .name = "cacheVotingSafetyChecks" });
    defer zone.deinit();

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

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var stubs = try replay.service.DependencyStubs.init(allocator, .FOR_TESTS);
    defer stubs.deinit();

    var replay_state = try stubs.stubbedState(allocator, .FOR_TESTS);
    defer {
        replay_state.deinit();
        replay_state.epoch_tracker.deinit(allocator);
        allocator.destroy(replay_state.epoch_tracker);
    }
    replay_state.slot_tracker.get(0).?.state.hash.set(.{ .data = @splat(1) });

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

    var ancestor_hashes_replay_updates: Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_updates.deinit();
    try consensus.processResult(
        allocator,
        &stubs.ledger,
        &replay_state.progress_map,
        &replay_state.slot_tracker,
        &ancestor_hashes_replay_updates,
        .{
            .slot = 0,
            .output = .{ .last_entry_hash = .ZEROES },
        },
    );

    const stats = replay_state.progress_map.map.get(0).?;
    try replay_state.progress_map.map.put(allocator, 1, stats);

    const slot_hash = SlotAndHash{
        .slot = 1,
        .hash = .parse("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"),
    };

    try consensus.fork_choice.fork_infos.put(allocator, slot_hash, .{
        .stake_for_slot = 0,
        .stake_for_subtree = 0,
        .height = 0,
        .heaviest_subtree_slot = slot_hash,
        .deepest_slot = slot_hash,
        .parent = null,
        .children = .empty,
        .latest_duplicate_ancestor = null,
        .is_duplicate_confirmed = false,
    });

    try consensus.handleDuplicateConfirmedFork(
        allocator,
        &stubs.ledger,
        &replay_state.progress_map,
        0,
        1,
        .{ .data = @splat(1) },
        &ancestor_hashes_replay_updates,
    );
}

test "cacheTowerStats - missing ancestor" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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

    const result = cacheVotingSafetyChecks(
        testing.allocator,
        &fixture.progress,
        &replay_tower,
        root.slot,
        &empty_ancestors,
    );

    try testing.expectError(error.MissingAncestor, result);
}

test "cacheTowerStats - missing slot" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };

    var fixture = try TestFixture.init(testing.allocator, root);
    defer fixture.deinit(testing.allocator);

    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(std.testing.allocator);

    // Do not populate progress for root.slot; ensure getForkStats returns null.
    const empty_ancestors: std.AutoArrayHashMapUnmanaged(Slot, Ancestors) = .empty;

    const result = cacheVotingSafetyChecks(
        testing.allocator,
        &fixture.progress,
        &replay_tower,
        root.slot,
        &empty_ancestors,
    );

    try testing.expectError(error.MissingSlot, result);
}

test "cacheTowerStats - success sets flags and empty thresholds" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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

    try cacheVotingSafetyChecks(
        testing.allocator,
        &fixture.progress,
        &replay_tower,
        root.slot,
        &fixture.ancestors,
    );

    const stats = fixture.progress.getForkStats(root.slot).?;
    try testing.expectEqual(0, stats.vote_threshold.items.len);
    try testing.expectEqual(true, stats.is_locked_out);
    try testing.expectEqual(false, stats.has_voted);
    try testing.expectEqual(false, stats.is_recent);
}

test "cacheTowerStats - records failed threshold at depth 0" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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

    try cacheVotingSafetyChecks(
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
    try testing.expectEqual(true, stats.is_locked_out);
    try testing.expectEqual(false, stats.has_voted);
    try testing.expectEqual(false, stats.is_recent);
}

test "maybeRefreshLastVote - no heaviest slot on same fork" {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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

    replay_tower.last_vote = .{
        .tower_sync = .{
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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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

    replay_tower.last_vote = .{
        .tower_sync = .{
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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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

    replay_tower.last_vote = .{
        .tower_sync = .{
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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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

    replay_tower.last_vote = .{
        .tower_sync = .{
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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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

    replay_tower.last_vote = .{
        .tower_sync = .{
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
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    // Build a tracked slot set wrapped in RwMux
    var slot_tracker: SlotTracker = .{
        .root = root.slot,
        .slots = .empty,
    };
    defer slot_tracker.deinit(testing.allocator);

    {
        const constants: SlotConstants = try .genesis(allocator, .initRandom(random));
        errdefer constants.deinit(allocator);
        try slot_tracker.put(testing.allocator, root.slot, .{
            .constants = constants,
            .state = .GENESIS,
        });
    }

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var test_state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer test_state.deinit();

    var epoch_tracker = try sig.core.EpochTracker.initForTest(
        allocator,
        random,
        0,
        .INIT,
    );
    defer epoch_tracker.deinit(allocator);

    // Try to check a slot that doesn't exist in the tracker
    const result = checkAndHandleNewRoot(
        allocator,
        test_state.resultWriter(),
        &slot_tracker,
        &fixture.progress,
        &fixture.fork_choice,
        &epoch_tracker,
        .noop,
        null, // no need to update a StatusCache,
        123, // Non-existent slot
    );

    try testing.expectError(error.MissingSlot, result);
}

test "checkAndHandleNewRoot - missing hash" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    const root = SlotAndHash{
        .slot = 0,
        .hash = Hash.initRandom(random),
    };

    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    var slot_tracker2 = RwMux(SlotTracker).init(.{ .root = root.slot, .slots = .empty });
    defer {
        const ptr, var lg = slot_tracker2.writeWithLock();
        defer lg.unlock();
        ptr.deinit(allocator);
    }
    {
        const constants = try SlotConstants.genesis(allocator, .initRandom(random));
        errdefer constants.deinit(allocator);

        var state: SlotState = .GENESIS;
        errdefer state.deinit(allocator);

        const ptr, var lg = slot_tracker2.writeWithLock();
        defer lg.unlock();
        try ptr.put(allocator, root.slot, .{
            .constants = constants,
            .state = state,
        });
    }

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var test_state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer test_state.deinit();

    var epoch_tracker = try sig.core.EpochTracker.initForTest(
        allocator,
        random,
        0,
        .INIT,
    );
    defer epoch_tracker.deinit(allocator);

    // Try to check a slot that doesn't exist in the tracker
    const slot_tracker2_ptr, var slot_tracker2_lg = slot_tracker2.writeWithLock();
    defer slot_tracker2_lg.unlock();
    const result = checkAndHandleNewRoot(
        allocator,
        test_state.resultWriter(),
        slot_tracker2_ptr,
        &fixture.progress,
        &fixture.fork_choice,
        &epoch_tracker,
        .noop,
        null, // no need to update a StatusCache,
        root.slot, // Non-existent hash
    );

    try testing.expectError(error.MissingHash, result);
}

test "checkAndHandleNewRoot - empty slot tracker" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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
    var registry = sig.prometheus.Registry(.{}).init(testing.allocator);
    defer registry.deinit();

    var test_state = try sig.ledger.tests.initTestLedger(testing.allocator, @src(), .noop);
    defer test_state.deinit();

    var epoch_tracker = try sig.core.EpochTracker.initForTest(
        allocator,
        random,
        0,
        .INIT,
    );
    defer epoch_tracker.deinit(allocator);

    // Try to check a slot that doesn't exist in the tracker
    const slot_tracker3_ptr, var slot_tracker3_lg = slot_tracker3.writeWithLock();
    defer slot_tracker3_lg.unlock();
    const result = checkAndHandleNewRoot(
        testing.allocator,
        test_state.resultWriter(),
        slot_tracker3_ptr,
        &fixture.progress,
        &fixture.fork_choice,
        &epoch_tracker,
        .noop,
        null, // no need to update a StatusCache,
        root.slot,
    );

    try testing.expectError(error.EmptySlotTracker, result);
}

test "checkAndHandleNewRoot - success" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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

    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    var slot_tracker4 = RwMux(SlotTracker).init(.{ .root = root.slot, .slots = .empty });
    defer {
        const ptr, var lg = slot_tracker4.writeWithLock();
        defer lg.unlock();
        ptr.deinit(allocator);
    }

    {
        var constants2 = try SlotConstants.genesis(allocator, .initRandom(random));
        errdefer constants2.deinit(allocator);

        var constants3 = try SlotConstants.genesis(allocator, .initRandom(random));
        errdefer constants3.deinit(allocator);

        var state2: SlotState = .GENESIS;
        errdefer state2.deinit(allocator);

        var state3: SlotState = .GENESIS;
        errdefer state3.deinit(allocator);

        constants2.parent_slot = hash1.slot;
        constants3.parent_slot = hash2.slot;
        state2.hash = .init(hash2.hash);
        state3.hash = .init(hash3.hash);

        const ptr, var lg = slot_tracker4.writeWithLock();
        defer lg.unlock();
        try ptr.put(allocator, hash2.slot, .{
            .constants = constants2,
            .state = state2,
        });
        try ptr.put(allocator, hash3.slot, .{
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
        allocator,
        .{ .root = root, .data = trees1 },
        .active,
    );

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var test_state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer test_state.deinit();

    var epoch_tracker = try sig.core.EpochTracker.initForTest(
        allocator,
        random,
        0,
        .INIT,
    );
    defer epoch_tracker.deinit(allocator);

    try testing.expectEqual(4, fixture.progress.map.count());
    try testing.expect(fixture.progress.map.contains(hash1.slot));
    {
        const slot_tracker4_ptr, var slot_tracker4_lg = slot_tracker4.writeWithLock();
        defer slot_tracker4_lg.unlock();
        try checkAndHandleNewRoot(
            allocator,
            test_state.resultWriter(),
            slot_tracker4_ptr,
            &fixture.progress,
            &fixture.fork_choice,
            &epoch_tracker,
            .noop,
            null, // no need to update a StatusCache,
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
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    // Set up slots and hashes for the fork tree: 0 -> 1 -> 2
    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    const hash1 = SlotAndHash{ .slot = 1, .hash = Hash.initRandom(random) };
    const hash2 = SlotAndHash{ .slot = 2, .hash = Hash.initRandom(random) };

    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    try fixture.fill_keys(allocator, random, 1);

    // Create the tree of banks in a BankForks object
    var trees1 = try std.BoundedArray(TreeNode, MAX_TEST_TREE_LEN).init(0);
    trees1.appendSliceAssumeCapacity(&[2]TreeNode{
        .{ hash1, root },
        .{ hash2, hash1 },
    });
    try fixture.fillFork(
        allocator,
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
        allocator,
    );
    defer frozen_slots.deinit(allocator);
    errdefer frozen_slots.deinit(allocator);

    // TODO move this into fixture?
    const versioned_stakes = try testEpochStakes(
        allocator,
        fixture.vote_pubkeys.items,
        10000,
        random,
    );

    const keys = versioned_stakes.stakes.vote_accounts.vote_accounts.keys();
    for (keys) |key| {
        var vote_account = versioned_stakes.stakes.vote_accounts.vote_accounts.getPtr(key).?;
        try vote_account.account.state.votes.append(allocator, .{
            .latency = 0,
            .lockout = .{
                .slot = 1,
                .confirmation_count = 4,
            },
        });
    }

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{versioned_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );
    var slot_tracker_rw1 = RwMux(SlotTracker).init(fixture.slot_tracker);
    const slot_tracker_rw1_ptr, var slot_tracker_rw1_lg = slot_tracker_rw1.writeWithLock();
    defer slot_tracker_rw1_lg.unlock();
    const newly_computed_consensus_slots = try computeConsensusInputs(
        allocator,
        .noop,
        my_node_pubkey,
        &fixture.ancestors,
        slot_tracker_rw1_ptr,
        &epoch_tracker,
        &fixture.progress,
        &fixture.fork_choice,
        &replay_tower,
        &fixture.latest_validator_votes_for_frozen_banks,
    );
    defer allocator.free(newly_computed_consensus_slots);

    // Sort frozen slots by slot number
    const slot_list = try allocator.alloc(u64, frozen_slots.count());
    defer allocator.free(slot_list);
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
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
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

    const versioned_stakes_0 = try testEpochStakes(
        testing.allocator,
        fixture.vote_pubkeys.items,
        10000,
        random,
    );
    var versioned_stakes_1 = try versioned_stakes_0.clone(testing.allocator);
    versioned_stakes_1.stakes.epoch = 1;

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        testing.allocator,
        &.{ versioned_stakes_0, versioned_stakes_1 },
    );
    defer epoch_tracker.deinit(testing.allocator);

    var replay_tower = try createTestReplayTower(
        1,
        0.67,
    );

    var slot_tracker_rw2 = RwMux(SlotTracker).init(fixture.slot_tracker);
    const slot_tracker_rw2_ptr, var slot_tracker_rw2_lg = slot_tracker_rw2.writeWithLock();
    defer slot_tracker_rw2_lg.unlock();
    const newly_computed_consensus_slots = try computeConsensusInputs(
        testing.allocator,
        .noop,
        my_vote_pubkey,
        &fixture.ancestors,
        slot_tracker_rw2_ptr,
        &epoch_tracker,
        &fixture.progress,
        &fixture.fork_choice,
        &replay_tower,
        &fixture.latest_validator_votes_for_frozen_banks,
    );
    defer testing.allocator.free(newly_computed_consensus_slots);

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

test "generateVoteTx - empty authorized voter keypairs returns non_voting" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(42);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    fixture.slot_tracker.get(0).?.state.hash.set(root.hash);

    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(allocator);

    const node_kp = sig.identity.KeyPair.generate();
    const vote_account_pubkey = Pubkey.initRandom(random);

    const empty_keypairs = &[_]sig.identity.KeyPair{};

    const account_reader: AccountReader = .noop;

    const result = try generateVoteTx(
        allocator,
        vote_account_pubkey,
        empty_keypairs,
        node_kp,
        .same_fork,
        &replay_tower,
        account_reader,
        &fixture.slot_tracker,
        &.INIT,
    );
    errdefer switch (result) {
        .tx => |tx| tx.deinit(allocator),
        else => {},
    };

    try testing.expectEqual(.non_voting, result);
}

test "generateVoteTx - no node keypair returns non_voting" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(43);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    fixture.slot_tracker.get(0).?.state.hash.set(root.hash);

    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(allocator);

    const auth_voter_kp = sig.identity.KeyPair.generate();
    const vote_account_pubkey = Pubkey.initRandom(random);

    const account_reader: AccountReader = .noop;

    const result = try generateVoteTx(
        allocator,
        vote_account_pubkey,
        &.{auth_voter_kp},
        null,
        .same_fork,
        &replay_tower,
        account_reader,
        &fixture.slot_tracker,
        &.INIT,
    );
    errdefer switch (result) {
        .tx => |tx| tx.deinit(allocator),
        else => {},
    };

    try testing.expectEqual(.non_voting, result);
}

test "generateVoteTx - no last voted slot returns failed" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(44);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    fixture.slot_tracker.get(0).?.state.hash.set(root.hash);

    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(allocator);
    replay_tower.last_vote = .{ .vote = .{ .slots = &.{}, .hash = Hash.ZEROES, .timestamp = null } };

    const node_kp = sig.identity.KeyPair.generate();
    const auth_voter_kp = sig.identity.KeyPair.generate();
    const vote_account_pubkey = Pubkey.initRandom(random);

    const account_reader: AccountReader = .noop;

    const result = try generateVoteTx(
        allocator,
        vote_account_pubkey,
        &.{auth_voter_kp},
        node_kp,
        .same_fork,
        &replay_tower,
        account_reader,
        &fixture.slot_tracker,
        &.INIT,
    );
    errdefer switch (result) {
        .tx => |tx| tx.deinit(allocator),
        else => {},
    };

    try testing.expectEqual(.failed, result);
}

test "generateVoteTx - slot not in tracker returns failed" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(45);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    fixture.slot_tracker.get(0).?.state.hash.set(root.hash);

    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(allocator);

    replay_tower.last_vote = .{
        .tower_sync = .{
            .lockouts = .fromOwnedSlice(try allocator.dupe(Lockout, &.{
                .{ .slot = 999, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    const node_kp = sig.identity.KeyPair.generate();
    const auth_voter_kp = sig.identity.KeyPair.generate();
    const vote_account_pubkey = Pubkey.initRandom(random);

    const account_reader: AccountReader = .noop;

    const result = try generateVoteTx(
        allocator,
        vote_account_pubkey,
        &.{auth_voter_kp},
        node_kp,
        .same_fork,
        &replay_tower,
        account_reader,
        &fixture.slot_tracker,
        &.INIT,
    );
    errdefer switch (result) {
        .tx => |tx| tx.deinit(allocator),
        else => {},
    };

    try testing.expectEqual(.failed, result);
}

test "generateVoteTx - vote account not found returns failed" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(46);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    fixture.slot_tracker.get(0).?.state.hash.set(root.hash);

    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(allocator);

    replay_tower.last_vote = .{
        .tower_sync = .{
            .lockouts = .fromOwnedSlice(try allocator.dupe(Lockout, &.{
                .{ .slot = 0, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    const node_kp = sig.identity.KeyPair.generate();
    const auth_voter_kp = sig.identity.KeyPair.generate();
    const vote_account_pubkey = Pubkey.initRandom(random);

    const account_reader: AccountReader = .noop;

    const result = try generateVoteTx(
        allocator,
        vote_account_pubkey,
        &.{auth_voter_kp},
        node_kp,
        .same_fork,
        &replay_tower,
        account_reader,
        &fixture.slot_tracker,
        &.INIT,
    );
    errdefer switch (result) {
        .tx => |tx| tx.deinit(allocator),
        else => {},
    };

    try testing.expectEqual(.failed, result);
}

test "generateVoteTx - invalid switch fork decision returns failed" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(52);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    fixture.slot_tracker.get(0).?.state.hash.set(root.hash);

    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(allocator);

    replay_tower.last_vote = .{
        .tower_sync = .{
            .lockouts = .fromOwnedSlice(try allocator.dupe(Lockout, &.{
                .{ .slot = 0, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    const node_kp = sig.identity.KeyPair.generate();
    const auth_voter_kp = sig.identity.KeyPair.generate();
    const vote_account_pubkey = Pubkey.initRandom(random);

    const account_reader: AccountReader = .noop;

    const result = try generateVoteTx(
        allocator,
        vote_account_pubkey,
        &.{auth_voter_kp},
        node_kp,
        .{ .failed_switch_threshold = .{ .switch_proof_stake = 0, .total_stake = 100 } },
        &replay_tower,
        account_reader,
        &fixture.slot_tracker,
        &.INIT,
    );
    errdefer switch (result) {
        .tx => |tx| tx.deinit(allocator),
        else => {},
    };

    try testing.expectEqual(.failed, result);
}

test "generateVoteTx - success with tower_sync vote" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(100);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    fixture.slot_tracker.get(0).?.state.hash.set(root.hash);

    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(allocator);

    replay_tower.last_vote = .{
        .tower_sync = .{
            .lockouts = .fromOwnedSlice(try allocator.dupe(Lockout, &.{
                .{ .slot = 0, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    const node_kp = sig.identity.KeyPair.generate();
    const auth_voter_kp = sig.identity.KeyPair.generate();
    const vote_account_pubkey = Pubkey.initRandom(random);

    var test_state = try sig.accounts_db.Two.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var vote_state = try sig.runtime.program.vote.state.createTestVoteState(
        allocator,
        Pubkey.fromPublicKey(&node_kp.public_key),
        Pubkey.fromPublicKey(&auth_voter_kp.public_key),
        Pubkey.fromPublicKey(&auth_voter_kp.public_key),
        0,
    );
    defer vote_state.deinit(allocator);

    const vote_account_data_buf = try allocator.alloc(
        u8,
        sig.runtime.program.vote.state.VoteState.MAX_VOTE_STATE_SIZE,
    );
    defer allocator.free(vote_account_data_buf);
    const vote_account_data = try sig.bincode.writeToSlice(
        vote_account_data_buf,
        VoteStateVersions{ .current = vote_state },
        .{},
    );
    const vote_account = sig.runtime.AccountSharedData{
        .lamports = 1000000,
        .data = vote_account_data,
        .owner = sig.runtime.program.vote.ID,
        .executable = false,
        .rent_epoch = 0,
    };

    var ancestors: Ancestors = try .initWithSlots(allocator, &.{0});
    defer ancestors.deinit(allocator);

    try db.put(0, vote_account_pubkey, vote_account);
    db.onSlotRooted(0, &ancestors);

    const result = try generateVoteTx(
        allocator,
        vote_account_pubkey,
        &.{auth_voter_kp},
        node_kp,
        .same_fork,
        &replay_tower,
        .{ .accounts_db_two = db },
        &fixture.slot_tracker,
        &.INIT,
    );
    errdefer switch (result) {
        .tx => |tx| tx.deinit(allocator),
        else => {},
    };

    switch (result) {
        .tx => |tx| {
            defer tx.deinit(allocator);
            try testing.expect(tx.signatures.len > 0);
            try testing.expect(tx.msg.instructions.len > 0);
            try testing.expectEqual(2, tx.signatures.len);
        },
        else => try testing.expect(false),
    }
}

test "generateVoteTx - success with vote_state_update compacted" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(101);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    fixture.slot_tracker.get(0).?.state.hash.set(root.hash);

    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(allocator);

    const lockouts = try allocator.dupe(Lockout, &.{
        .{ .slot = 0, .confirmation_count = 1 },
    });
    replay_tower.last_vote = .{
        .vote_state_update = sig.runtime.program.vote.state.VoteStateUpdate{
            .lockouts = .fromOwnedSlice(lockouts),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
        },
    };

    const node_kp = sig.identity.KeyPair.generate();
    const auth_voter_kp = sig.identity.KeyPair.generate();
    const vote_account_pubkey = Pubkey.initRandom(random);

    var test_state = try sig.accounts_db.Two.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var vote_state = try sig.runtime.program.vote.state.createTestVoteState(
        allocator,
        Pubkey.fromPublicKey(&node_kp.public_key),
        Pubkey.fromPublicKey(&auth_voter_kp.public_key),
        Pubkey.fromPublicKey(&auth_voter_kp.public_key),
        0,
    );
    defer vote_state.deinit(allocator);

    const vote_account_data_buf = try allocator.alloc(
        u8,
        sig.runtime.program.vote.state.VoteState.MAX_VOTE_STATE_SIZE,
    );
    defer allocator.free(vote_account_data_buf);
    const vote_account_data = try sig.bincode.writeToSlice(
        vote_account_data_buf,
        VoteStateVersions{ .current = vote_state },
        .{},
    );

    const vote_account = sig.runtime.AccountSharedData{
        .lamports = 1000000,
        .data = vote_account_data,
        .owner = sig.runtime.program.vote.ID,
        .executable = false,
        .rent_epoch = 0,
    };

    var ancestors: Ancestors = try .initWithSlots(allocator, &.{0});
    defer ancestors.deinit(allocator);

    try db.put(0, vote_account_pubkey, vote_account);
    db.onSlotRooted(0, &ancestors);

    const result = try generateVoteTx(
        allocator,
        vote_account_pubkey,
        &.{auth_voter_kp},
        node_kp,
        .same_fork,
        &replay_tower,
        .{ .accounts_db_two = db },
        &fixture.slot_tracker,
        &.INIT,
    );
    errdefer switch (result) {
        .tx => |tx| tx.deinit(allocator),
        else => {},
    };

    switch (result) {
        .tx => |tx| {
            defer tx.deinit(allocator);
            try testing.expect(tx.signatures.len > 0);
            try testing.expect(tx.msg.instructions.len > 0);
        },
        else => try testing.expect(false),
    }
}

test "generateVoteTx - success with switch proof" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(102);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    fixture.slot_tracker.get(0).?.state.hash.set(root.hash);

    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(allocator);

    replay_tower.last_vote = .{
        .tower_sync = .{
            .lockouts = .fromOwnedSlice(try allocator.dupe(Lockout, &.{
                .{ .slot = 0, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    const node_kp = sig.identity.KeyPair.generate();
    const auth_voter_kp = sig.identity.KeyPair.generate();
    const vote_account_pubkey = Pubkey.initRandom(random);

    var test_state = try sig.accounts_db.Two.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var vote_state = try sig.runtime.program.vote.state.createTestVoteState(
        allocator,
        Pubkey.fromPublicKey(&node_kp.public_key),
        Pubkey.fromPublicKey(&auth_voter_kp.public_key),
        Pubkey.fromPublicKey(&auth_voter_kp.public_key),
        0,
    );
    defer vote_state.deinit(allocator);

    const vote_account_data_buf = try allocator.alloc(
        u8,
        sig.runtime.program.vote.state.VoteState.MAX_VOTE_STATE_SIZE,
    );
    defer allocator.free(vote_account_data_buf);
    const vote_account_data = try sig.bincode.writeToSlice(
        vote_account_data_buf,
        VoteStateVersions{ .current = vote_state },
        .{},
    );

    const vote_account = sig.runtime.AccountSharedData{
        .lamports = 1000000,
        .data = vote_account_data,
        .owner = sig.runtime.program.vote.ID,
        .executable = false,
        .rent_epoch = 0,
    };

    var ancestors: Ancestors = try .initWithSlots(allocator, &.{0});
    defer ancestors.deinit(allocator);

    try db.put(0, vote_account_pubkey, vote_account);
    db.onSlotRooted(0, &ancestors);

    const switch_proof_hash = Hash.initRandom(random);
    const result = try generateVoteTx(
        allocator,
        vote_account_pubkey,
        &.{auth_voter_kp},
        node_kp,
        .{ .switch_proof = switch_proof_hash },
        &replay_tower,
        .{ .accounts_db_two = db },
        &fixture.slot_tracker,
        &.INIT,
    );
    errdefer switch (result) {
        .tx => |tx| tx.deinit(allocator),
        else => {},
    };

    switch (result) {
        .tx => |tx| {
            defer tx.deinit(allocator);
            try testing.expect(tx.signatures.len > 0);
            try testing.expect(tx.msg.instructions.len > 0);
        },
        else => try testing.expect(false),
    }
}

test "generateVoteTx - hot spare validator returns hot_spare" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(103);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    fixture.slot_tracker.get(0).?.state.hash.set(root.hash);

    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(allocator);

    replay_tower.last_vote = .{
        .tower_sync = .{
            .lockouts = .fromOwnedSlice(try allocator.dupe(Lockout, &.{
                .{ .slot = 0, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    const node_kp = sig.identity.KeyPair.generate();
    const different_node_kp = sig.identity.KeyPair.generate();
    const auth_voter_kp = sig.identity.KeyPair.generate();
    const vote_account_pubkey = Pubkey.initRandom(random);

    var test_state = try sig.accounts_db.Two.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var vote_state = try sig.runtime.program.vote.state.createTestVoteState(
        allocator,
        Pubkey.fromPublicKey(&different_node_kp.public_key),
        Pubkey.fromPublicKey(&auth_voter_kp.public_key),
        Pubkey.fromPublicKey(&auth_voter_kp.public_key),
        0,
    );
    defer vote_state.deinit(allocator);

    const vote_account_data_buf = try allocator.alloc(
        u8,
        sig.runtime.program.vote.state.VoteState.MAX_VOTE_STATE_SIZE,
    );
    defer allocator.free(vote_account_data_buf);
    const vote_account_data = try sig.bincode.writeToSlice(
        vote_account_data_buf,
        VoteStateVersions{ .current = vote_state },
        .{},
    );

    const vote_account = sig.runtime.AccountSharedData{
        .lamports = 1000000,
        .data = vote_account_data,
        .owner = sig.runtime.program.vote.ID,
        .executable = false,
        .rent_epoch = 0,
    };

    var ancestors: Ancestors = try .initWithSlots(allocator, &.{0});
    defer ancestors.deinit(allocator);

    try db.put(0, vote_account_pubkey, vote_account);
    db.onSlotRooted(0, &ancestors);

    const result = try generateVoteTx(
        allocator,
        vote_account_pubkey,
        &.{auth_voter_kp},
        node_kp,
        .same_fork,
        &replay_tower,
        .{ .accounts_db_two = db },
        &fixture.slot_tracker,
        &.INIT,
    );
    errdefer switch (result) {
        .tx => |tx| tx.deinit(allocator),
        else => {},
    };

    try testing.expectEqual(.hot_spare, result);
}

test "generateVoteTx - wrong authorized voter returns non_voting" {
    const allocator = testing.allocator;
    var prng = std.Random.DefaultPrng.init(104);
    const random = prng.random();

    const root = SlotAndHash{ .slot = 0, .hash = Hash.initRandom(random) };
    var fixture = try TestFixture.init(allocator, root);
    defer fixture.deinit(allocator);

    fixture.slot_tracker.get(0).?.state.hash.set(root.hash);

    var replay_tower = try createTestReplayTower(1, 0.67);
    defer replay_tower.deinit(allocator);

    replay_tower.last_vote = .{
        .tower_sync = .{
            .lockouts = .fromOwnedSlice(try allocator.dupe(Lockout, &.{
                .{ .slot = 0, .confirmation_count = 1 },
            })),
            .root = null,
            .hash = Hash.ZEROES,
            .timestamp = null,
            .block_id = Hash.ZEROES,
        },
    };

    const node_kp = sig.identity.KeyPair.generate();
    const wrong_auth_voter_kp = sig.identity.KeyPair.generate();
    const actual_auth_voter_kp = sig.identity.KeyPair.generate();
    const vote_account_pubkey = Pubkey.initRandom(random);

    var test_state = try sig.accounts_db.Two.initTest(allocator);
    defer test_state.deinit();
    const db = &test_state.db;

    var vote_state = try sig.runtime.program.vote.state.createTestVoteState(
        allocator,
        Pubkey.fromPublicKey(&node_kp.public_key),
        Pubkey.fromPublicKey(&actual_auth_voter_kp.public_key),
        Pubkey.fromPublicKey(&actual_auth_voter_kp.public_key),
        0,
    );
    defer vote_state.deinit(allocator);

    const vote_account_data_buf = try allocator.alloc(
        u8,
        sig.runtime.program.vote.state.VoteState.MAX_VOTE_STATE_SIZE,
    );
    defer allocator.free(vote_account_data_buf);
    const vote_account_data = try sig.bincode.writeToSlice(
        vote_account_data_buf,
        VoteStateVersions{ .current = vote_state },
        .{},
    );

    const vote_account = sig.runtime.AccountSharedData{
        .lamports = 1000000,
        .data = vote_account_data,
        .owner = sig.runtime.program.vote.ID,
        .executable = false,
        .rent_epoch = 0,
    };

    var ancestors: Ancestors = try .initWithSlots(allocator, &.{0});
    defer ancestors.deinit(allocator);

    try db.put(0, vote_account_pubkey, vote_account);
    db.onSlotRooted(0, &ancestors);

    const result = try generateVoteTx(
        allocator,
        vote_account_pubkey,
        &.{wrong_auth_voter_kp},
        node_kp,
        .same_fork,
        &replay_tower,
        .{ .accounts_db_two = db },
        &fixture.slot_tracker,
        &.INIT,
    );
    errdefer switch (result) {
        .tx => |tx| tx.deinit(allocator),
        else => {},
    };

    try testing.expectEqual(.non_voting, result);
}

test "sendVote - without gossip table does not send and does not throw" {
    const allocator = testing.allocator;

    var leader_schedule = sig.core.leader_schedule.LeaderSchedule{
        .leaders = &[_]Pubkey{},
        .start = 0,
        .end = 0,
    };
    const slot_leaders = sig.core.leader_schedule.SlotLeaders.init(
        &leader_schedule,
        sig.core.leader_schedule.LeaderSchedule.getLeaderOrNull,
    );

    const vote_op = VoteOp{
        .push_vote = .{
            .tx = Transaction.EMPTY,
            .last_tower_slot = 200,
        },
    };

    sendVote(
        .noop,
        allocator,
        0,
        vote_op,
        null,
        slot_leaders,
        sig.identity.KeyPair.generate(),
        100,
        null,
    ) catch unreachable; // sendVote does not throw
}

test "sendVote - without keypair does not send and does not throw" {
    const allocator = testing.allocator;

    var leader_schedule = sig.core.leader_schedule.LeaderSchedule{
        .leaders = &[_]Pubkey{},
        .start = 0,
        .end = 0,
    };
    const slot_leaders = sig.core.leader_schedule.SlotLeaders.init(
        &leader_schedule,
        sig.core.leader_schedule.LeaderSchedule.getLeaderOrNull,
    );

    var gossip_table = try sig.gossip.GossipTable.init(allocator, allocator);
    defer gossip_table.deinit();
    var gossip_table_rw = sig.sync.RwMux(sig.gossip.GossipTable).init(gossip_table);

    const vote_op = VoteOp{
        .push_vote = .{
            .tx = Transaction.EMPTY,
            .last_tower_slot = 200,
        },
    };

    sendVote(
        .noop,
        allocator,
        0,
        vote_op,
        &gossip_table_rw,
        slot_leaders,
        null,
        200,
        null,
    ) catch unreachable; // sendVote does not throw
}

test "sendVote - without leader schedule does not send and does not throw" {
    const allocator = testing.allocator;

    var gossip_table = try sig.gossip.GossipTable.init(allocator, allocator);
    defer gossip_table.deinit();
    var gossip_table_rw = sig.sync.RwMux(sig.gossip.GossipTable).init(gossip_table);

    const vote_op = VoteOp{
        .push_vote = .{
            .tx = Transaction.EMPTY,
            .last_tower_slot = 200,
        },
    };

    sendVote(
        .noop,
        allocator,
        0,
        vote_op,
        &gossip_table_rw,
        null,
        null,
        300,
        null,
    ) catch unreachable; // sendVote does not throw
}

test "sendVote - sends to both gossip and upcoming leaders" {
    const allocator = testing.allocator;

    const vote_slot: Slot = 100;

    const vote_op = VoteOp{
        .push_vote = .{
            .tx = Transaction.EMPTY,
            .last_tower_slot = vote_slot,
        },
    };

    const leader_pubkey = Pubkey.initRandom(std.crypto.random);

    const leaders = try allocator.alloc(Pubkey, 5);
    for (leaders) |*leader| leader.* = leader_pubkey;
    var leader_schedule = sig.core.leader_schedule.LeaderSchedule{
        .leaders = leaders,
        .start = 0,
        .end = 4,
    };
    defer leader_schedule.deinit(allocator);
    const slot_leaders = sig.core.leader_schedule.SlotLeaders.init(
        &leader_schedule,
        sig.core.leader_schedule.LeaderSchedule.getLeaderOrNull,
    );

    const gossip_table = try sig.gossip.GossipTable.init(allocator, allocator);
    var gossip_table_rw = sig.sync.RwMux(sig.gossip.GossipTable).init(gossip_table);
    defer sig.sync.mux.deinitMux(&gossip_table_rw);

    var contact_info = sig.gossip.data.ContactInfo.init(
        allocator,
        leader_pubkey,
        sig.time.getWallclockMs(),
        0,
    );
    try contact_info.setSocket(.tpu_vote, sig.net.SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8001));

    const leader_keypair = sig.identity.KeyPair.generate();
    const signed_gossip_data = sig.gossip.data.SignedGossipData.initSigned(
        &leader_keypair,
        sig.gossip.data.GossipData{ .ContactInfo = contact_info },
    );

    {
        const gossip_table_write, var lock = gossip_table_rw.writeWithLock();
        defer lock.unlock();
        _ = try gossip_table_write.insert(
            signed_gossip_data,
            sig.time.getWallclockMs(),
        );
    }

    const my_keypair: sig.identity.KeyPair = .generate();
    const my_pubkey: Pubkey = .fromPublicKey(&my_keypair.public_key);

    {
        const gossip_table_read, var lock = gossip_table_rw.readWithLock();
        defer lock.unlock();
        // 1 entry: leader's ContactInfo with tpu_vote socket needed for sendVoteToLeaders
        try testing.expectEqual(1, gossip_table_read.len());
    }

    try sendVote(
        .noop,
        allocator,
        vote_slot,
        vote_op,
        &gossip_table_rw,
        slot_leaders,
        my_keypair,
        400,
        null,
    );

    {
        const gossip_table_read, var lock = gossip_table_rw.readWithLock();
        defer lock.unlock();

        // 2 entries: leader's ContactInfo + vote added by sendVote
        try testing.expectEqual(2, gossip_table_read.len());

        const vote_key = sig.gossip.data.GossipKey{ .Vote = .{ 0, my_pubkey } };
        const gossip_data = gossip_table_read.getData(vote_key).?;

        try testing.expectEqual(.Vote, std.meta.activeTag(gossip_data));

        const vote_data = gossip_data.Vote[1];
        try testing.expectEqual(my_pubkey, vote_data.from);
        try testing.expectEqual(Transaction.EMPTY, vote_data.transaction);
    }
}

test "sendVote - refresh_vote sends to both gossip and upcoming leaders" {
    const allocator = testing.allocator;

    const vote_slot: Slot = 100;

    const vote_op = VoteOp{
        .refresh_vote = .{
            .tx = Transaction.EMPTY,
            .last_voted_slot = vote_slot,
        },
    };

    const leader_pubkey = Pubkey.initRandom(std.crypto.random);

    const leaders = try allocator.alloc(Pubkey, 5);
    for (leaders) |*leader| leader.* = leader_pubkey;
    var leader_schedule = sig.core.leader_schedule.LeaderSchedule{
        .leaders = leaders,
        .start = 0,
        .end = 4,
    };
    defer leader_schedule.deinit(allocator);
    const slot_leaders = sig.core.leader_schedule.SlotLeaders.init(
        &leader_schedule,
        sig.core.leader_schedule.LeaderSchedule.getLeaderOrNull,
    );

    const gossip_table = try sig.gossip.GossipTable.init(allocator, allocator);
    var gossip_table_rw = sig.sync.RwMux(sig.gossip.GossipTable).init(gossip_table);
    defer sig.sync.mux.deinitMux(&gossip_table_rw);

    var contact_info = sig.gossip.data.ContactInfo.init(
        allocator,
        leader_pubkey,
        sig.time.getWallclockMs(),
        0,
    );
    try contact_info.setSocket(.tpu_vote, sig.net.SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8001));

    const leader_keypair = sig.identity.KeyPair.generate();
    const signed_gossip_data = sig.gossip.data.SignedGossipData.initSigned(
        &leader_keypair,
        sig.gossip.data.GossipData{ .ContactInfo = contact_info },
    );

    {
        const gossip_table_write, var lock = gossip_table_rw.writeWithLock();
        defer lock.unlock();
        _ = try gossip_table_write.insert(
            signed_gossip_data,
            sig.time.getWallclockMs(),
        );
    }

    const my_keypair: sig.identity.KeyPair = .generate();
    const my_pubkey: Pubkey = .fromPublicKey(&my_keypair.public_key);

    {
        const gossip_table_read, var lock = gossip_table_rw.readWithLock();
        defer lock.unlock();
        // 1 entry: leader's ContactInfo with tpu_vote socket needed for sendVoteToLeaders
        try testing.expectEqual(1, gossip_table_read.len());
    }

    try sendVote(
        .noop,
        allocator,
        vote_slot,
        vote_op,
        &gossip_table_rw,
        slot_leaders,
        my_keypair,
        500,
        null,
    );

    {
        const gossip_table_read, var lock = gossip_table_rw.readWithLock();
        defer lock.unlock();

        // 2 entries: leader's ContactInfo + vote added by sendVote
        try testing.expectEqual(2, gossip_table_read.len());

        const vote_key = sig.gossip.data.GossipKey{ .Vote = .{ 0, my_pubkey } };
        const maybe_gossip_data = gossip_table_read.getData(vote_key);
        try testing.expect(maybe_gossip_data != null);

        const gossip_data = maybe_gossip_data.?;
        try testing.expectEqual(.Vote, std.meta.activeTag(gossip_data));

        const vote_data = gossip_data.Vote[1];
        try testing.expectEqual(my_pubkey, vote_data.from);
        try testing.expectEqual(Transaction.EMPTY, vote_data.transaction);
    }
}

test "sendVote - falls back to self TPU when no leader sockets found" {
    const allocator = testing.allocator;

    const vote_slot: Slot = 42;

    const vote_op = VoteOp{
        .push_vote = .{
            .tx = Transaction.EMPTY,
            .last_tower_slot = vote_slot,
        },
    };

    const unknown_leader = Pubkey.initRandom(std.crypto.random);

    const leaders = try allocator.alloc(Pubkey, 5);
    for (leaders) |*leader| leader.* = unknown_leader;
    var leader_schedule = sig.core.leader_schedule.LeaderSchedule{
        .leaders = leaders,
        .start = 0,
        .end = 4,
    };
    defer leader_schedule.deinit(allocator);
    const slot_leaders = sig.core.leader_schedule.SlotLeaders.init(
        &leader_schedule,
        sig.core.leader_schedule.LeaderSchedule.getLeaderOrNull,
    );

    const my_keypair = sig.identity.KeyPair.generate();
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);

    const gossip_table = try sig.gossip.GossipTable.init(allocator, allocator);
    var gossip_table_rw = sig.sync.RwMux(sig.gossip.GossipTable).init(gossip_table);
    defer sig.sync.mux.deinitMux(&gossip_table_rw);

    var my_contact_info = sig.gossip.data.ContactInfo.init(
        allocator,
        my_pubkey,
        sig.time.getWallclockMs(),
        0,
    );
    try my_contact_info.setSocket(.tpu, sig.net.SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8101));

    const signed_my_contact = sig.gossip.data.SignedGossipData.initSigned(
        &my_keypair,
        sig.gossip.data.GossipData{ .ContactInfo = my_contact_info },
    );

    {
        const gossip_table_write, var lock = gossip_table_rw.writeWithLock();
        defer lock.unlock();
        _ = try gossip_table_write.insert(
            signed_my_contact,
            sig.time.getWallclockMs(),
        );
    }

    {
        const gossip_table_read, var lock = gossip_table_rw.readWithLock();
        defer lock.unlock();
        // 1 entry: our ContactInfo only
        try testing.expectEqual(1, gossip_table_read.len());
    }

    // This should attempt to send to upcoming leaders (none found), then
    // fall back to sending to our own TPU address, and finally insert the vote into gossip.
    // NOTE: This test does not assert that a UDP packet was sent to the self TPU address;
    // it only validates the control flow indirectly by checking that the vote was inserted
    // into gossip. A socket capture or injection hook would be needed to assert the send.
    try sendVote(
        .noop,
        allocator,
        vote_slot,
        vote_op,
        &gossip_table_rw,
        slot_leaders,
        my_keypair,
        600,
        null,
    );

    {
        const gossip_table_read, var lock = gossip_table_rw.readWithLock();
        defer lock.unlock();

        // 2 entries: our ContactInfo + vote added by sendVote
        try testing.expectEqual(2, gossip_table_read.len());

        const vote_key = sig.gossip.data.GossipKey{ .Vote = .{ 0, my_pubkey } };
        const maybe_gossip_data = gossip_table_read.getData(vote_key);
        try testing.expect(maybe_gossip_data != null);

        const gossip_data = maybe_gossip_data.?;
        try testing.expectEqual(.Vote, std.meta.activeTag(gossip_data));

        const vote_data = gossip_data.Vote[1];
        try testing.expectEqual(my_pubkey, vote_data.from);
        try testing.expectEqual(Transaction.EMPTY, vote_data.transaction);
    }
}

test "sendVote - leaders path uses sockets (exercises sendVoteToLeaders)" {
    const allocator = testing.allocator;

    const vote_slot: Slot = 100;

    const vote_op: VoteOp = .{
        .push_vote = .{
            .tx = .EMPTY,
            .last_tower_slot = vote_slot,
        },
    };

    // Prepare a leader schedule with a single repeating leader
    const leader_pubkey: Pubkey = .initRandom(std.crypto.random);

    const leaders = try allocator.alloc(Pubkey, 5);
    for (leaders) |*leader| leader.* = leader_pubkey;
    var leader_schedule = sig.core.leader_schedule.LeaderSchedule{
        .leaders = leaders,
        .start = 0,
        .end = 4,
    };
    defer leader_schedule.deinit(allocator);
    const slot_leaders = sig.core.leader_schedule.SlotLeaders.init(
        &leader_schedule,
        sig.core.leader_schedule.LeaderSchedule.getLeaderOrNull,
    );

    // Gossip table with leader ContactInfo having tpu_vote socket
    const gossip_table: sig.gossip.GossipTable = try .init(allocator, allocator);
    var gossip_table_rw = sig.sync.RwMux(sig.gossip.GossipTable).init(gossip_table);
    defer sig.sync.mux.deinitMux(&gossip_table_rw);

    var leader_contact = sig.gossip.data.ContactInfo.init(
        allocator,
        leader_pubkey,
        sig.time.getWallclockMs(),
        0,
    );
    try leader_contact.setSocket(.tpu_vote, sig.net.SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8002));

    const leader_keypair = sig.identity.KeyPair.generate();
    const leader_ci = sig.gossip.data.SignedGossipData.initSigned(
        &leader_keypair,
        sig.gossip.data.GossipData{ .ContactInfo = leader_contact },
    );

    {
        const gossip_table_write, var lock = gossip_table_rw.writeWithLock();
        defer lock.unlock();
        _ = try gossip_table_write.insert(leader_ci, sig.time.getWallclockMs());
    }

    const my_keypair: sig.identity.KeyPair = .generate();
    const my_pubkey: Pubkey = .fromPublicKey(&my_keypair.public_key);

    // Provide sockets so sendVoteToLeaders is executed
    const sockets: VoteSockets = try .init();
    defer sockets.deinit();

    try sendVote(
        .noop,
        allocator,
        vote_slot,
        vote_op,
        &gossip_table_rw,
        slot_leaders,
        my_keypair,
        700,
        &sockets,
    );

    // Validate gossip received the vote
    {
        const gossip_table_read, var lock = gossip_table_rw.readWithLock();
        defer lock.unlock();
        try testing.expectEqual(2, gossip_table_read.len());
        const vote_key = sig.gossip.data.GossipKey{
            .Vote = .{ 0, my_pubkey },
        };
        try testing.expect(gossip_table_read.getData(vote_key) != null);
    }
}

test "sendVote - sendVoteToLeaders fallback to self TPU when leaders empty" {
    const allocator = testing.allocator;

    const vote_slot: Slot = 55;

    const vote_op = VoteOp{
        .push_vote = .{
            .tx = Transaction.EMPTY,
            .last_tower_slot = vote_slot,
        },
    };

    // Leader schedule points to an unknown leader; no leader ContactInfo in gossip
    const unknown_leader = Pubkey.initRandom(std.crypto.random);

    const leaders = try allocator.alloc(Pubkey, 5);
    for (leaders) |*leader| leader.* = unknown_leader;
    var leader_schedule = sig.core.leader_schedule.LeaderSchedule{
        .leaders = leaders,
        .start = 0,
        .end = 4,
    };
    defer leader_schedule.deinit(allocator);
    const slot_leaders = sig.core.leader_schedule.SlotLeaders.init(
        &leader_schedule,
        sig.core.leader_schedule.LeaderSchedule.getLeaderOrNull,
    );

    // Gossip table with our own ContactInfo having a TPU address
    const my_keypair = sig.identity.KeyPair.generate();
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);

    const gossip_table = try sig.gossip.GossipTable.init(allocator, allocator);
    var gossip_table_rw = sig.sync.RwMux(sig.gossip.GossipTable).init(gossip_table);
    defer sig.sync.mux.deinitMux(&gossip_table_rw);

    var my_contact = sig.gossip.data.ContactInfo.init(
        allocator,
        my_pubkey,
        sig.time.getWallclockMs(),
        0,
    );
    try my_contact.setSocket(.tpu, sig.net.SocketAddr.initIpv4(.{ 127, 0, 0, 1 }, 8102));

    const signed_my_ci = sig.gossip.data.SignedGossipData.initSigned(
        &my_keypair,
        sig.gossip.data.GossipData{ .ContactInfo = my_contact },
    );
    {
        const gossip_table_write, var lock = gossip_table_rw.writeWithLock();
        defer lock.unlock();
        _ = try gossip_table_write.insert(signed_my_ci, sig.time.getWallclockMs());
    }

    // Provide sockets so sendVoteToLeaders is called and triggers fallback to self TPU
    const sockets: VoteSockets = try .init();
    defer sockets.deinit();

    try sendVote(
        .noop,
        allocator,
        vote_slot,
        vote_op,
        &gossip_table_rw,
        slot_leaders,
        my_keypair,
        800,
        &sockets,
    );

    {
        const gossip_table_read, var lock = gossip_table_rw.readWithLock();
        defer lock.unlock();
        try testing.expectEqual(2, gossip_table_read.len());
        const vote_key = sig.gossip.data.GossipKey{ .Vote = .{ 0, my_pubkey } };
        try testing.expect(gossip_table_read.getData(vote_key) != null);
    }
}

test "sendVoteToLeaders - sends to multiple upcoming leaders" {
    const allocator = testing.allocator;

    var prng_state: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const prng = prng_state.random();

    const vote_slot: Slot = 100;
    const vote_tx = Transaction.EMPTY;

    // Create three different leaders for consecutive slots
    const leader1_pubkey: Pubkey = .initRandom(prng);
    const leader2_pubkey: Pubkey = .initRandom(prng);
    const leader3_pubkey: Pubkey = .initRandom(prng);

    const leaders = try allocator.alloc(Pubkey, 150);
    for (leaders, 0..) |*leader, i| {
        if (i >= vote_slot and i < vote_slot + 3) {
            leader.* = switch (i - vote_slot) {
                0 => leader1_pubkey,
                1 => leader2_pubkey,
                2 => leader3_pubkey,
                else => unreachable,
            };
        } else {
            leader.* = Pubkey.initRandom(std.crypto.random);
        }
    }
    var leader_schedule = sig.core.leader_schedule.LeaderSchedule{
        .leaders = leaders,
        .start = 0,
        .end = 4,
    };
    defer leader_schedule.deinit(allocator);
    const slot_leaders = sig.core.leader_schedule.SlotLeaders.init(
        &leader_schedule,
        sig.core.leader_schedule.LeaderSchedule.getLeaderOrNull,
    );

    const gossip_table = try sig.gossip.GossipTable.init(allocator, allocator);
    var gossip_table_rw = sig.sync.RwMux(sig.gossip.GossipTable).init(gossip_table);
    defer sig.sync.mux.deinitMux(&gossip_table_rw);

    {
        var leader1_contact: sig.gossip.data.ContactInfo = .init(
            allocator,
            leader1_pubkey,
            sig.time.getWallclockMs(),
            0,
        );
        try leader1_contact.setSocket(
            .tpu_vote,
            .initIpv4(.{ 127, 0, 0, 1 }, 8001),
        );

        const leader1_keypair = sig.identity.KeyPair.generate();
        const leader1_ci = sig.gossip.data.SignedGossipData.initSigned(
            &leader1_keypair,
            sig.gossip.data.GossipData{ .ContactInfo = leader1_contact },
        );

        const gossip_table_write, var lock = gossip_table_rw.writeWithLock();
        defer lock.unlock();
        _ = try gossip_table_write.insert(leader1_ci, sig.time.getWallclockMs());
    }

    {
        var leader2_contact: sig.gossip.data.ContactInfo = .init(
            allocator,
            leader2_pubkey,
            sig.time.getWallclockMs(),
            0,
        );
        try leader2_contact.setSocket(
            .tpu_vote,
            .initIpv4(.{ 127, 0, 0, 2 }, 8002),
        );

        const leader2_keypair = sig.identity.KeyPair.generate();
        const leader2_ci = sig.gossip.data.SignedGossipData.initSigned(
            &leader2_keypair,
            sig.gossip.data.GossipData{ .ContactInfo = leader2_contact },
        );

        const gossip_table_write, var lock = gossip_table_rw.writeWithLock();
        defer lock.unlock();
        _ = try gossip_table_write.insert(leader2_ci, sig.time.getWallclockMs());
    }

    {
        var leader3_contact: sig.gossip.data.ContactInfo = .init(
            allocator,
            leader3_pubkey,
            sig.time.getWallclockMs(),
            0,
        );
        try leader3_contact.setSocket(
            .tpu_vote,
            .initIpv4(.{ 127, 0, 0, 3 }, 8003),
        );

        const leader3_keypair = sig.identity.KeyPair.generate();
        const leader3_ci = sig.gossip.data.SignedGossipData.initSigned(
            &leader3_keypair,
            sig.gossip.data.GossipData{ .ContactInfo = leader3_contact },
        );

        const gossip_table_write, var lock = gossip_table_rw.writeWithLock();
        defer lock.unlock();
        _ = try gossip_table_write.insert(leader3_ci, sig.time.getWallclockMs());
    }

    const my_pubkey = Pubkey.initRandom(std.crypto.random);

    const sockets: VoteSockets = try .init();
    defer sockets.deinit();

    try sendVoteToLeaders(
        .noop,
        allocator,
        vote_slot,
        vote_tx,
        slot_leaders,
        &gossip_table_rw,
        my_pubkey,
        &sockets,
    );

    {
        const gossip_table_read, var lock = gossip_table_rw.readWithLock();
        defer lock.unlock();
        try testing.expectEqual(3, gossip_table_read.len());
    }
}

test "sendVoteToLeaders - continues when sendVoteTransaction fails" {
    const allocator = testing.allocator;

    const vote_slot: Slot = 75;
    const vote_tx: Transaction = .EMPTY;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const leader_pubkey: Pubkey = .initRandom(prng.random());

    const leaders = try allocator.alloc(Pubkey, 10);
    for (leaders) |*leader| leader.* = leader_pubkey;
    var leader_schedule = sig.core.leader_schedule.LeaderSchedule{
        .leaders = leaders,
        .start = 0,
        .end = 4,
    };
    defer leader_schedule.deinit(allocator);
    const slot_leaders = sig.core.leader_schedule.SlotLeaders.init(
        &leader_schedule,
        sig.core.leader_schedule.LeaderSchedule.getLeaderOrNull,
    );

    const gossip_table: sig.gossip.GossipTable = try .init(allocator, allocator);
    var gossip_table_rw: sig.sync.RwMux(sig.gossip.GossipTable) = .init(gossip_table);
    defer sig.sync.mux.deinitMux(&gossip_table_rw);

    var leader_contact: sig.gossip.data.ContactInfo = .init(
        allocator,
        leader_pubkey,
        sig.time.getWallclockMs(),
        0,
    );
    try leader_contact.setSocket(
        .tpu_vote,
        sig.net.SocketAddr.initIpv4(.{ 127, 0, 0, 10 }, 9001),
    );

    const leader_keypair = sig.identity.KeyPair.generate();
    const leader_ci: sig.gossip.data.SignedGossipData = .initSigned(
        &leader_keypair,
        sig.gossip.data.GossipData{ .ContactInfo = leader_contact },
    );

    {
        const gossip_table_write, var lock = gossip_table_rw.writeWithLock();
        defer lock.unlock();
        _ = try gossip_table_write.insert(leader_ci, sig.time.getWallclockMs());
    }

    var sockets: VoteSockets = try .init();
    sockets.ipv4.close();
    defer sockets.ipv6.close();

    try sendVoteToLeaders(
        .noop,
        allocator,
        vote_slot,
        vote_tx,
        slot_leaders,
        &gossip_table_rw,
        null,
        &sockets,
    );

    {
        const gossip_table_read, var lock = gossip_table_rw.readWithLock();
        defer lock.unlock();
        try testing.expectEqual(1, gossip_table_read.len());
    }
}

test "sendVoteToLeaders - fallback handles missing self TPU data" {
    const allocator = testing.allocator;

    const vote_slot: Slot = 88;
    const vote_tx: Transaction = .EMPTY;

    const EmptySlotLeaders = struct {
        const Self = @This();

        fn get(_: *Self, _: Slot) ?Pubkey {
            return null;
        }

        pub const empty: Self = .{};
    };
    var slot_state = EmptySlotLeaders.empty;
    const slot_leaders: sig.core.leader_schedule.SlotLeaders = .init(
        &slot_state,
        EmptySlotLeaders.get,
    );

    const gossip_table: sig.gossip.GossipTable = try .init(allocator, allocator);
    var gossip_table_rw: sig.sync.RwMux(sig.gossip.GossipTable) = .init(gossip_table);
    defer sig.sync.mux.deinitMux(&gossip_table_rw);

    var sockets: VoteSockets = try .init();
    defer sockets.deinit();

    const my_keypair: sig.identity.KeyPair = .generate();
    const my_pubkey: Pubkey = .fromPublicKey(&my_keypair.public_key);

    // No self contact info recorded in gossip.
    try sendVoteToLeaders(
        .noop,
        allocator,
        vote_slot,
        vote_tx,
        slot_leaders,
        &gossip_table_rw,
        my_pubkey,
        &sockets,
    );

    {
        const gossip_table_read, var lock = gossip_table_rw.readWithLock();
        defer lock.unlock();
        try testing.expectEqual(0, gossip_table_read.len());
    }

    { // Insert self contact that lacks a TPU address.
        const gossip_table_write, var lock = gossip_table_rw.writeWithLock();
        defer lock.unlock();
        _ = try gossip_table_write.insert(
            .initSigned(
                &my_keypair,
                .{ .ContactInfo = .init(allocator, my_pubkey, sig.time.getWallclockMs(), 0) },
            ),
            sig.time.getWallclockMs(),
        );
    }

    try sendVoteToLeaders(
        .noop,
        allocator,
        vote_slot,
        vote_tx,
        slot_leaders,
        &gossip_table_rw,
        my_pubkey,
        &sockets,
    );

    {
        const gossip_table_read, var lock = gossip_table_rw.readWithLock();
        defer lock.unlock();
        try testing.expectEqual(1, gossip_table_read.len());
    }

    // Finally, ensure the branch that lacks my_pubkey executes.
    try sendVoteToLeaders(
        .noop,
        allocator,
        vote_slot,
        vote_tx,
        slot_leaders,
        &gossip_table_rw,
        null, // my_pubkey sent to null
        &sockets,
    );

    {
        const gossip_table_read, var lock = gossip_table_rw.readWithLock();
        defer lock.unlock();
        try testing.expectEqual(1, gossip_table_read.len());
    }
}

test "findVoteIndexToEvict - no newer vote returns next index" {
    const allocator = testing.allocator;

    var gossip_table = try sig.gossip.GossipTable.init(allocator, allocator);
    defer gossip_table.deinit();

    const my_keypair = sig.identity.KeyPair.generate();
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);

    const now: u64 = 1_000;
    const tower_last: Slot = 10;

    {
        const vote_data = sig.gossip.data.GossipData{
            .Vote = .{
                0,
                .{
                    .from = my_pubkey,
                    .transaction = Transaction.EMPTY,
                    .wallclock = now,
                    .slot = 0,
                },
            },
        };
        const signed = sig.gossip.data.SignedGossipData.initSigned(&my_keypair, vote_data);
        _ = try gossip_table.insert(signed, now);
    }

    {
        const vote_data = sig.gossip.data.GossipData{
            .Vote = .{
                1,
                .{
                    .from = my_pubkey,
                    .transaction = Transaction.EMPTY,
                    .wallclock = now + 1,
                    .slot = 5,
                },
            },
        };
        const signed = sig.gossip.data.SignedGossipData.initSigned(&my_keypair, vote_data);
        _ = try gossip_table.insert(signed, now + 1);
    }

    const maybe_index = findVoteIndexToEvict(&gossip_table, my_pubkey, tower_last);
    try testing.expectEqual(2, maybe_index);
}

test "findVoteIndexToEvict - newer-or-equal vote returns null" {
    const allocator = testing.allocator;

    var gossip_table = try sig.gossip.GossipTable.init(allocator, allocator);
    defer gossip_table.deinit();

    const my_keypair = sig.identity.KeyPair.generate();
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);

    const base: u64 = 2_000;
    const tower_last: Slot = 10;

    {
        const vote_data = sig.gossip.data.GossipData{
            .Vote = .{
                0,
                .{
                    .from = my_pubkey,
                    .transaction = Transaction.EMPTY,
                    .wallclock = base,
                    .slot = 5,
                },
            },
        };
        const signed = sig.gossip.data.SignedGossipData.initSigned(&my_keypair, vote_data);
        _ = try gossip_table.insert(signed, base);
    }

    {
        const vote_data = sig.gossip.data.GossipData{
            .Vote = .{
                1,
                .{
                    .from = my_pubkey,
                    .transaction = Transaction.EMPTY,
                    .wallclock = base + 1,
                    .slot = tower_last,
                },
            },
        };
        const signed = sig.gossip.data.SignedGossipData.initSigned(&my_keypair, vote_data);
        _ = try gossip_table.insert(signed, base + 1);
    }

    const maybe_index = findVoteIndexToEvict(&gossip_table, my_pubkey, tower_last);
    try testing.expect(maybe_index == null);
}

test "findVoteIndexToEvict - full buffer evicts oldest index" {
    const allocator = testing.allocator;

    var gossip_table = try sig.gossip.GossipTable.init(allocator, allocator);
    defer gossip_table.deinit();

    const my_keypair = sig.identity.KeyPair.generate();
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);

    const tower_last: Slot = 100;
    const chosen_oldest_index: u8 = 5;

    const base: u64 = 10_000;
    for (0..sig.gossip.data.MAX_VOTES) |j| {
        const i: u8 = @intCast(j);
        const ts: u64 = if (i == chosen_oldest_index) 100 else base + @as(u64, i);
        const vote_data = sig.gossip.data.GossipData{
            .Vote = .{
                i,
                .{ .from = my_pubkey, .transaction = Transaction.EMPTY, .wallclock = ts, .slot = 0 },
            },
        };
        const signed = sig.gossip.data.SignedGossipData.initSigned(&my_keypair, vote_data);
        _ = try gossip_table.insert(signed, ts);
    }

    const maybe_index = findVoteIndexToEvict(&gossip_table, my_pubkey, tower_last);
    try testing.expectEqual(chosen_oldest_index, maybe_index);
}

test "edge cases - duplicate slot" {
    // -- set up state -- //
    const gpa = std.testing.allocator;

    var prng_state: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const prng = prng_state.random();

    var registry: sig.prometheus.Registry(.{}) = .init(gpa);
    defer registry.deinit();

    var dep_stubs: sig.replay.service.DependencyStubs = try .init(gpa, .FOR_TESTS);
    defer dep_stubs.deinit();

    var replay_state = try dep_stubs.stubbedState(gpa, .FOR_TESTS);
    defer {
        replay_state.deinit();
        replay_state.epoch_tracker.deinit(gpa);
        gpa.destroy(replay_state.epoch_tracker);
    }

    const slot_tracker = &replay_state.slot_tracker;
    const progress_map = &replay_state.progress_map;
    std.debug.assert(slot_tracker.root == 0);

    const root_slot0 = slot_tracker.root;
    const root_slot0_hash = slot_tracker.getRoot().state.hash.readCopy().?;

    std.debug.assert(root_slot0 == 0); // assert initial root value
    std.debug.assert(root_slot0_hash.eql(.ZEROES)); // assert initial root hash

    // -- slot1 -- //
    const slot1: Slot = 1;
    const slot1_hash: Hash = .initRandom(prng);
    {
        var slot_constants: sig.core.SlotConstants = try .genesis(gpa, .DEFAULT);
        errdefer slot_constants.deinit(gpa);
        slot_constants.parent_slot = root_slot0;
        slot_constants.parent_hash = root_slot0_hash;

        var slot_state: sig.core.SlotState = .GENESIS;
        errdefer slot_state.deinit(gpa);
        slot_state.hash.set(slot1_hash);

        try slot_tracker.put(gpa, slot1, .{
            .constants = slot_constants,
            .state = slot_state,
        });
    }
    {
        var fp: sig.consensus.progress_map.ForkProgress = try .zeroes(gpa);
        errdefer fp.deinit(gpa);
        try progress_map.map.put(gpa, slot1, fp);
    }
    // -- slot1 -- //

    // -- slot2 -- //
    const slot2: Slot = 2;
    const slot2_hash: Hash = .initRandom(prng);
    {
        var slot_constants: sig.core.SlotConstants = try .genesis(gpa, .DEFAULT);
        errdefer slot_constants.deinit(gpa);
        slot_constants.parent_slot = root_slot0;
        slot_constants.parent_hash = root_slot0_hash;

        var slot_state: sig.core.SlotState = .GENESIS;
        errdefer slot_state.deinit(gpa);
        slot_state.hash.set(slot2_hash);

        try slot_tracker.put(gpa, slot2, .{
            .constants = slot_constants,
            .state = slot_state,
        });
    }
    {
        var fp: sig.consensus.progress_map.ForkProgress = try .zeroes(gpa);
        errdefer fp.deinit(gpa);
        try progress_map.map.put(gpa, slot2, fp);
    }
    // -- slot2 -- //

    var tower_consensus: TowerConsensus = try .init(gpa, .{
        .logger = .FOR_TESTS,
        .identity = replay_state.identity,
        .signing = replay_state.signing,
        .account_reader = replay_state.account_store.reader(),
        .ledger = replay_state.ledger,
        .slot_tracker = slot_tracker,
        .now = .EPOCH_ZERO,
        .registry = &registry,
    });
    defer tower_consensus.deinit(gpa);
    slot_tracker.getRoot().state.hash.set(null); // freeze the root slot (only after initializing consensus, because it needs a non-null hash initially)

    // -- I/O state -- //

    const tc_output_channels: TowerConsensus.Senders = try .create(gpa);
    defer tc_output_channels.destroy();

    const replay_votes_channel: *sig.sync.Channel(ParsedVote) = try .create(gpa);
    defer replay_votes_channel.destroy();
    defer while (replay_votes_channel.tryReceive()) |pv| pv.deinit(gpa);

    const tc_input_channels: TowerConsensus.Receivers = try .create(gpa, replay_votes_channel);
    defer tc_input_channels.destroy();

    var duplicate_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
    defer duplicate_confirmed_slots.deinit(gpa);

    var gossip_verified_vote_hashes: std.ArrayListUnmanaged(GossipVerifiedVoteHash) = .empty;
    defer gossip_verified_vote_hashes.deinit(gpa);

    // -- input state -- //

    try tc_input_channels.duplicate_slots.send(slot1);

    const replay_slot_results = [_]ReplayResult{
        .{
            .slot = slot1,
            .output = .{
                .last_entry_hash = .initRandom(prng),
            },
        },
        .{
            .slot = slot2,
            .output = .{
                .last_entry_hash = .initRandom(prng),
            },
        },
    };

    // run consensus

    var epoch_tracker = try sig.core.EpochTracker.initForTest(
        std.testing.allocator,
        prng_state.random(),
        0,
        .INIT,
    );
    defer epoch_tracker.deinit(std.testing.allocator);

    try tower_consensus.process(gpa, .{
        .account_store = replay_state.account_store,
        .ledger = replay_state.ledger,
        .gossip_votes = null,
        .slot_tracker = &replay_state.slot_tracker,
        .epoch_tracker = &epoch_tracker,
        .progress_map = &replay_state.progress_map,
        .status_cache = &replay_state.status_cache,
        .senders = tc_output_channels,
        .receivers = tc_input_channels,
        .vote_sockets = null,
        .slot_leaders = null,
        .duplicate_confirmed_slots = &duplicate_confirmed_slots,
        .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
        .results = &replay_slot_results,
    });

    // test outputs

    const last_vote_slots = try gpa.alloc(Slot, tower_consensus.replay_tower.last_vote.slotCount());
    defer gpa.free(last_vote_slots);
    tower_consensus.replay_tower.last_vote.copyAllSlotsTo(last_vote_slots);

    const expected_slot_hash: SlotAndHash = .{ .slot = slot2, .hash = slot2_hash };
    try std.testing.expectEqualSlices(Slot, &.{expected_slot_hash.slot}, last_vote_slots);
    try std.testing.expectEqual(
        expected_slot_hash.hash,
        tower_consensus.replay_tower.last_vote.getHash(),
    );
}

test "edge cases - duplicate confirmed slot" {
    // -- set up state -- //
    const gpa = std.testing.allocator;

    var prng_state: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const prng = prng_state.random();

    var registry: sig.prometheus.Registry(.{}) = .init(gpa);
    defer registry.deinit();

    var dep_stubs: sig.replay.service.DependencyStubs = try .init(gpa, .FOR_TESTS);
    defer dep_stubs.deinit();

    var replay_state = try dep_stubs.stubbedState(gpa, .FOR_TESTS);
    defer {
        replay_state.deinit();
        replay_state.epoch_tracker.deinit(gpa);
        gpa.destroy(replay_state.epoch_tracker);
    }

    const slot_tracker = &replay_state.slot_tracker;
    const progress_map = &replay_state.progress_map;
    std.debug.assert(slot_tracker.root == 0);

    const root_slot0 = slot_tracker.root;
    const root_slot0_hash = slot_tracker.getRoot().state.hash.readCopy().?;

    std.debug.assert(root_slot0 == 0); // assert initial root value
    std.debug.assert(root_slot0_hash.eql(.ZEROES)); // assert initial root hash

    // -- slot1 -- //
    const slot1: Slot = 1;
    const slot1_hash: Hash = .initRandom(prng);
    {
        var slot_constants: sig.core.SlotConstants = try .genesis(gpa, .DEFAULT);
        errdefer slot_constants.deinit(gpa);
        slot_constants.parent_slot = root_slot0;
        slot_constants.parent_hash = root_slot0_hash;

        var slot_state: sig.core.SlotState = .GENESIS;
        errdefer slot_state.deinit(gpa);
        slot_state.hash.set(slot1_hash);

        try slot_tracker.put(gpa, slot1, .{
            .constants = slot_constants,
            .state = slot_state,
        });
    }
    {
        var fp: sig.consensus.progress_map.ForkProgress = try .zeroes(gpa);
        errdefer fp.deinit(gpa);
        try progress_map.map.put(gpa, slot1, fp);
    }
    // -- slot1 -- //

    // -- slot2 -- //
    const slot2: Slot = 2;
    const slot2_hash: Hash = .initRandom(prng);
    {
        var slot_constants: sig.core.SlotConstants = try .genesis(gpa, .DEFAULT);
        errdefer slot_constants.deinit(gpa);
        slot_constants.parent_slot = root_slot0;
        slot_constants.parent_hash = root_slot0_hash;

        var slot_state: sig.core.SlotState = .GENESIS;
        errdefer slot_state.deinit(gpa);
        slot_state.hash.set(slot2_hash);

        try slot_tracker.put(gpa, slot2, .{
            .constants = slot_constants,
            .state = slot_state,
        });
    }
    {
        var fp: sig.consensus.progress_map.ForkProgress = try .zeroes(gpa);
        errdefer fp.deinit(gpa);
        try progress_map.map.put(gpa, slot2, fp);
    }
    // -- slot2 -- //

    var tower_consensus: TowerConsensus = try .init(gpa, .{
        .logger = .FOR_TESTS,
        .identity = replay_state.identity,
        .signing = replay_state.signing,
        .account_reader = replay_state.account_store.reader(),
        .ledger = replay_state.ledger,
        .slot_tracker = slot_tracker,
        .now = .EPOCH_ZERO,
        .registry = &registry,
    });
    defer tower_consensus.deinit(gpa);
    slot_tracker.getRoot().state.hash.set(null); // freeze the root slot (only after initializing consensus, because it needs a non-null hash initially)

    // -- I/O state -- //

    const tc_output_channels: TowerConsensus.Senders = try .create(gpa);
    defer tc_output_channels.destroy();

    const replay_votes_channel: *sig.sync.Channel(ParsedVote) = try .create(gpa);
    defer replay_votes_channel.destroy();
    defer while (replay_votes_channel.tryReceive()) |pv| pv.deinit(gpa);

    const tc_input_channels: TowerConsensus.Receivers = try .create(gpa, replay_votes_channel);
    defer tc_input_channels.destroy();

    var duplicate_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
    defer duplicate_confirmed_slots.deinit(gpa);

    var gossip_verified_vote_hashes: std.ArrayListUnmanaged(GossipVerifiedVoteHash) = .empty;
    defer gossip_verified_vote_hashes.deinit(gpa);

    // -- input state -- //

    try tc_input_channels.duplicate_slots.send(slot1);
    try duplicate_confirmed_slots.append(gpa, .{ .slot = slot1, .hash = slot1_hash });

    const replay_slot_results = [_]ReplayResult{
        .{
            .slot = slot1,
            .output = .{
                .last_entry_hash = .initRandom(prng),
            },
        },
        .{
            .slot = slot2,
            .output = .{
                .last_entry_hash = .initRandom(prng),
            },
        },
    };

    // run consensus

    var epoch_tracker = try sig.core.EpochTracker.initForTest(
        std.testing.allocator,
        prng_state.random(),
        0,
        .INIT,
    );
    defer epoch_tracker.deinit(std.testing.allocator);

    try tower_consensus.process(gpa, .{
        .account_store = replay_state.account_store,
        .ledger = replay_state.ledger,
        .gossip_votes = null,
        .slot_tracker = &replay_state.slot_tracker,
        .epoch_tracker = &epoch_tracker,
        .progress_map = &replay_state.progress_map,
        .status_cache = &replay_state.status_cache,
        .senders = tc_output_channels,
        .receivers = tc_input_channels,
        .vote_sockets = null,
        .slot_leaders = null,
        .duplicate_confirmed_slots = &duplicate_confirmed_slots,
        .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
        .results = &replay_slot_results,
    });

    // test outputs

    const last_vote_slots = try gpa.alloc(Slot, tower_consensus.replay_tower.last_vote.slotCount());
    defer gpa.free(last_vote_slots);
    tower_consensus.replay_tower.last_vote.copyAllSlotsTo(last_vote_slots);

    const expected_slot_hash: SlotAndHash = .{ .slot = slot1, .hash = slot1_hash };
    try std.testing.expectEqualSlices(Slot, &.{expected_slot_hash.slot}, last_vote_slots);
    try std.testing.expectEqual(
        expected_slot_hash.hash,
        tower_consensus.replay_tower.last_vote.getHash(),
    );
}

test "edge cases - gossip verified vote hashes" {
    // -- set up state -- //
    const gpa = std.testing.allocator;

    var prng_state: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const prng = prng_state.random();

    var registry: sig.prometheus.Registry(.{}) = .init(gpa);
    defer registry.deinit();

    var dep_stubs: sig.replay.service.DependencyStubs = try .init(gpa, .FOR_TESTS);
    defer dep_stubs.deinit();

    var replay_state = try dep_stubs.stubbedState(gpa, .FOR_TESTS);
    defer {
        replay_state.deinit();
        replay_state.epoch_tracker.deinit(gpa);
        gpa.destroy(replay_state.epoch_tracker);
    }

    const slot_tracker = &replay_state.slot_tracker;
    const progress_map = &replay_state.progress_map;
    std.debug.assert(slot_tracker.root == 0);

    var vote_collector: sig.consensus.vote_listener.VoteCollector =
        try .init(.EPOCH_ZERO, slot_tracker.root, &registry);
    defer vote_collector.deinit(gpa);

    const root_slot0 = slot_tracker.root;
    const root_slot0_hash = slot_tracker.getRoot().state.hash.readCopy().?;

    std.debug.assert(root_slot0 == 0); // assert initial root value
    std.debug.assert(root_slot0_hash.eql(.ZEROES)); // assert initial root hash

    // -- slot1 -- //
    const slot1: Slot = 1;
    const slot1_hash: Hash = .initRandom(prng);
    {
        var slot_constants: sig.core.SlotConstants = try .genesis(gpa, .DEFAULT);
        errdefer slot_constants.deinit(gpa);
        slot_constants.parent_slot = root_slot0;
        slot_constants.parent_hash = root_slot0_hash;

        var slot_state: sig.core.SlotState = .GENESIS;
        errdefer slot_state.deinit(gpa);
        slot_state.hash.set(slot1_hash);

        try slot_tracker.put(gpa, slot1, .{
            .constants = slot_constants,
            .state = slot_state,
        });
    }
    {
        var fp: sig.consensus.progress_map.ForkProgress = try .zeroes(gpa);
        errdefer fp.deinit(gpa);
        try progress_map.map.put(gpa, slot1, fp);
    }
    // -- slot1 -- //

    // -- slot2 -- //
    const slot2: Slot = 2;
    const slot2_hash: Hash = .initRandom(prng);
    {
        var slot_constants: sig.core.SlotConstants = try .genesis(gpa, .DEFAULT);
        errdefer slot_constants.deinit(gpa);
        slot_constants.parent_slot = root_slot0;
        slot_constants.parent_hash = root_slot0_hash;

        var slot_state: sig.core.SlotState = .GENESIS;
        errdefer slot_state.deinit(gpa);
        slot_state.hash.set(slot2_hash);

        try slot_tracker.put(gpa, slot2, .{
            .constants = slot_constants,
            .state = slot_state,
        });
    }
    {
        var fp: sig.consensus.progress_map.ForkProgress = try .zeroes(gpa);
        errdefer fp.deinit(gpa);
        try progress_map.map.put(gpa, slot2, fp);
    }
    // -- slot2 -- //

    var tower_consensus: TowerConsensus = try .init(gpa, .{
        .logger = .FOR_TESTS,
        .identity = replay_state.identity,
        .signing = replay_state.signing,
        .account_reader = replay_state.account_store.reader(),
        .ledger = replay_state.ledger,
        .slot_tracker = slot_tracker,
        .now = .EPOCH_ZERO,
        .registry = &registry,
    });
    defer tower_consensus.deinit(gpa);
    slot_tracker.getRoot().state.hash.set(null); // freeze the root slot (only after initializing consensus, because it needs a non-null hash initially)

    // -- I/O state -- //

    var verified_vote_channel: sig.sync.Channel(sig.consensus.vote_listener.VerifiedVote) =
        try .init(gpa);
    defer verified_vote_channel.deinit();
    defer while (verified_vote_channel.tryReceive()) |verified_vote| verified_vote.deinit(gpa);

    const tc_output_channels: TowerConsensus.Senders = try .create(gpa);
    defer tc_output_channels.destroy();

    const replay_votes_channel: *sig.sync.Channel(ParsedVote) = try .create(gpa);
    defer replay_votes_channel.destroy();
    defer while (replay_votes_channel.tryReceive()) |pv| pv.deinit(gpa);

    const tc_input_channels: TowerConsensus.Receivers = try .create(gpa, replay_votes_channel);
    defer tc_input_channels.destroy();

    var duplicate_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
    defer duplicate_confirmed_slots.deinit(gpa);

    var gossip_verified_vote_hashes: std.ArrayListUnmanaged(GossipVerifiedVoteHash) = .empty;
    defer gossip_verified_vote_hashes.deinit(gpa);

    // -- input state -- //

    const pk1: Pubkey = .initRandom(prng);
    try gossip_verified_vote_hashes.append(gpa, .{ pk1, slot1, slot1_hash });

    const pk2: Pubkey = .initRandom(prng);
    try gossip_verified_vote_hashes.append(gpa, .{ pk2, slot2, slot2_hash });

    const replay_slot_results = [_]ReplayResult{
        .{
            .slot = slot1,
            .output = .{
                .last_entry_hash = .initRandom(prng),
            },
        },
        .{
            .slot = slot2,
            .output = .{
                .last_entry_hash = .initRandom(prng),
            },
        },
    };

    // run consensus

    var epoch_tracker = try sig.core.EpochTracker.initForTest(
        std.testing.allocator,
        prng_state.random(),
        0,
        .INIT,
    );
    defer epoch_tracker.deinit(std.testing.allocator);

    try tower_consensus.process(gpa, .{
        .account_store = replay_state.account_store,
        .ledger = replay_state.ledger,
        .gossip_votes = null,
        .slot_tracker = &replay_state.slot_tracker,
        .epoch_tracker = &epoch_tracker,
        .progress_map = &replay_state.progress_map,
        .status_cache = &replay_state.status_cache,
        .senders = tc_output_channels,
        .receivers = tc_input_channels,
        .vote_sockets = null,
        .slot_leaders = null,
        .duplicate_confirmed_slots = &duplicate_confirmed_slots,
        .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
        .results = &replay_slot_results,
    });

    // test outputs

    // TODO: test the effect of gossip verified vote hashes on the dependents
    // of `tower_consensus.latest_validator_votes`.
    try std.testing.expectEqualSlices(
        Pubkey,
        &.{ pk1, pk2 },
        tower_consensus.latest_validator_votes.max_gossip_frozen_votes.keys(),
    );
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

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit();

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state: sig.core.SlotState = .GENESIS;

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

        var slot_state: sig.core.SlotState = .GENESIS;
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

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{.EMPTY_WITH_GENESIS},
    );
    defer epoch_tracker.deinit(allocator);

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

    var consensus = try TowerConsensus.init(allocator, .{
        .logger = .noop,
        .identity = .{
            .vote_account = null,
            .validator = .initRandom(std.crypto.random),
        },
        .signing = .{
            .node = null,
            .authorized_voters = &.{},
        },
        .account_reader = stubs.accountReader(),
        .ledger = &stubs.ledger,
        .slot_tracker = &slot_tracker,
        .now = .EPOCH_ZERO,
        .registry = &registry,
    });
    defer consensus.deinit(allocator);

    try std.testing.expectEqual(null, consensus.replay_tower.lastVotedSlot());
    try std.testing.expectEqual(false, progress.getForkStats(slot_1).?.computed);
    try std.testing.expectEqual(0, progress.getForkStats(1).?.block_height);
    try std.testing.expectEqual(.uninitialized, consensus.replay_tower.last_vote_tx_blockhash);

    var duplicate_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var gossip_verified_vote_hashes: std.ArrayListUnmanaged(GossipVerifiedVoteHash) = .empty;
    defer gossip_verified_vote_hashes.deinit(allocator);

    // Component entry point being tested
    try consensus.process(allocator, .{
        .account_store = stubs.accountStore(),
        .ledger = &stubs.ledger,
        .gossip_votes = null,
        .slot_tracker = &slot_tracker,
        .epoch_tracker = &epoch_tracker,
        .progress_map = &progress,
        .status_cache = null,
        .senders = stubs.senders,
        .receivers = stubs.receivers,
        .vote_sockets = null,
        .slot_leaders = null,
        .duplicate_confirmed_slots = &duplicate_confirmed_slots,
        .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
        .results = &results,
    });

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
    try std.testing.expectEqual(root_slot, consensus.replay_tower.tower.root.?);
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

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit();

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state: sig.core.SlotState = .GENESIS;

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

        var slot_state: sig.core.SlotState = .GENESIS;
        errdefer slot_state.deinit(allocator);
        slot_state.hash = .init(slot1_hash);

        try slot_tracker.put(
            allocator,
            slot_1,
            .{ .constants = slot_constants, .state = slot_state },
        );
    }

    // NOTE: The core setup for this test
    // Seed epoch 0 constants with 6 vote accounts and landed votes
    const epoch_stakes = blk: {
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
                try vote_account.account.state.votes.append(allocator, .{
                    .latency = 0,
                    .lockout = .{ .slot = slot_1, .confirmation_count = 2 },
                });
            }
        }

        break :blk epoch_stakes;
    };
    errdefer epoch_stakes.deinit(allocator);

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{epoch_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    {
        const epoch_info = try epoch_tracker.getEpochInfo(0);
        const slot1_ref = slot_tracker.get(1).?;
        const stakes_ptr, var stakes_guard = slot1_ref.state.stakes_cache.stakes.writeWithLock();
        defer stakes_guard.unlock();
        stakes_ptr.deinit(allocator);
        stakes_ptr.* = try sig.core.bank.parseStakesForTest(
            allocator,
            &epoch_info.stakes.stakes,
        );
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

    var consensus = try TowerConsensus.init(allocator, .{
        .logger = .noop,
        .identity = .{
            .vote_account = null,
            .validator = .initRandom(std.crypto.random),
        },
        .signing = .{
            .node = null,
            .authorized_voters = &.{},
        },
        .account_reader = stubs.accountReader(),
        .ledger = &stubs.ledger,
        .slot_tracker = &slot_tracker,
        .now = .EPOCH_ZERO,
        .registry = &registry,
    });
    defer consensus.deinit(allocator);

    try std.testing.expectEqual(0, progress.getForkStats(1).?.voted_stakes.count());

    var duplicate_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var gossip_verified_vote_hashes: std.ArrayListUnmanaged(GossipVerifiedVoteHash) = .empty;
    defer gossip_verified_vote_hashes.deinit(allocator);

    // Component entry point being tested
    try consensus.process(allocator, .{
        .account_store = stubs.accountStore(),
        .ledger = &stubs.ledger,
        .gossip_votes = null,
        .slot_tracker = &slot_tracker,
        .epoch_tracker = &epoch_tracker,
        .progress_map = &progress,
        .status_cache = null,
        .senders = stubs.senders,
        .receivers = stubs.receivers,
        .vote_sockets = null,
        .slot_leaders = null,
        .duplicate_confirmed_slots = &duplicate_confirmed_slots,
        .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
        .results = &results,
    });

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

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit();

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
        const account_store = stubs.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    const initial_root: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);

    var root_state: sig.core.SlotState = .GENESIS;
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

    var slot_tracker: SlotTracker = try .init(allocator, initial_root, .{
        .constants = root_consts,
        .state = root_state,
    });
    defer slot_tracker.deinit(allocator);

    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();
    const validator_vote_pubkey = Pubkey.initRandom(random);

    const epoch_stakes_0 = blk: {
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

        break :blk epoch_stakes;
    };

    const epoch_stakes_1 = blk: {
        const vote_pubkeys = try allocator.alloc(Pubkey, 1);
        defer allocator.free(vote_pubkeys);
        vote_pubkeys[0] = validator_vote_pubkey; // Use our validator's vote pubkey

        var epoch_stakes = try sig.consensus.fork_choice.testEpochStakes(
            allocator,
            vote_pubkeys,
            1000,
            random,
        );
        epoch_stakes.stakes.epoch = 1;
        errdefer epoch_stakes.deinit(allocator);

        break :blk epoch_stakes;
    };

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{ epoch_stakes_0, epoch_stakes_1 },
    );
    defer epoch_tracker.deinit(allocator);

    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);

    {
        var fp = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fp.fork_stats.computed = true;
        try progress.map.put(allocator, initial_root, fp);
    }

    var replay_votes_channel = try Channel(ParsedVote).create(allocator);
    defer replay_votes_channel.destroy();

    const our_validator_stake: u64 = 1000;

    for (1..32) |i| {
        const slot: Slot = @intCast(i);

        {
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

            var slot_state: sig.core.SlotState = .GENESIS;
            slot_state.hash = .init(slot_hash);

            try slot_tracker.put(allocator, slot, .{
                .constants = slot_constants,
                .state = slot_state,
            });
        }

        {
            var fp = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
            fp.fork_stats.computed = true;
            fp.fork_stats.total_stake = our_validator_stake; // Set total stake to match epoch stakes
            try progress.map.put(allocator, slot, fp);
        }
    }

    var consensus = try TowerConsensus.init(allocator, .{
        .logger = .noop,
        .identity = .{
            .vote_account = null,
            .validator = Pubkey.initRandom(std.crypto.random),
        },
        .signing = .{
            .node = null,
            .authorized_voters = &.{},
        },
        .account_reader = stubs.accountReader(),
        .ledger = &stubs.ledger,
        .slot_tracker = &slot_tracker,
        .now = .EPOCH_ZERO,
        .registry = &registry,
    });
    defer consensus.deinit(allocator);

    var duplicate_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var gossip_verified_vote_hashes: std.ArrayListUnmanaged(GossipVerifiedVoteHash) = .empty;
    defer gossip_verified_vote_hashes.deinit(allocator);

    for (1..32) |i| {
        const slot: Slot = @intCast(i);
        _ = try consensus.replay_tower.recordBankVote(allocator, slot, hashes[slot]);

        if (progress.map.getPtr(slot)) |prog| {
            try prog.fork_stats.voted_stakes.put(allocator, slot, our_validator_stake);
        }
    }

    {
        try std.testing.expectEqual(31, consensus.replay_tower.tower.votes.len);
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

        try consensus.process(allocator, .{
            .account_store = stubs.accountStore(),
            .ledger = &stubs.ledger,
            .gossip_votes = null,
            .slot_tracker = &slot_tracker,
            .epoch_tracker = &epoch_tracker,
            .progress_map = &progress,
            .status_cache = null,
            .senders = stubs.senders,
            .receivers = stubs.receivers,
            .vote_sockets = null,
            .slot_leaders = null,
            .duplicate_confirmed_slots = &duplicate_confirmed_slots,
            .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
            .results = &sync_results,
        });
    }

    {
        const slot: Slot = 32;
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

        var slot_state: sig.core.SlotState = .GENESIS;
        slot_state.hash = .init(slot_hash);

        try slot_tracker.put(allocator, slot, .{ .constants = slot_constants, .state = slot_state });
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

        try consensus.process(allocator, .{
            .account_store = stubs.accountStore(),
            .ledger = &stubs.ledger,
            .gossip_votes = null,
            .slot_tracker = &slot_tracker,
            .epoch_tracker = &epoch_tracker,
            .progress_map = &progress,
            .status_cache = null,
            .senders = stubs.senders,
            .receivers = stubs.receivers,
            .vote_sockets = null,
            .slot_leaders = null,
            .duplicate_confirmed_slots = &duplicate_confirmed_slots,
            .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
            .results = &results,
        });

        const new_root = try consensus.replay_tower.tower.getRoot();
        try std.testing.expect(new_root > old_root);
        try std.testing.expectEqual(0, old_root);
        try std.testing.expectEqual(1, new_root);
        try std.testing.expectEqual(
            MAX_LOCKOUT_HISTORY,
            consensus.replay_tower.tower.votes.len,
        );

        try std.testing.expectEqual(1, slot_tracker.root);
        // No longer tracking slot 0
        try std.testing.expect(!slot_tracker.contains(0));
        // Still tracking slot 1
        try std.testing.expect(slot_tracker.contains(1));
        try std.testing.expect(slot_tracker.contains(32));

        // No longer tracking slot 0
        try std.testing.expect(progress.map.get(0) == null);
        // Still tracking slot 1
        try std.testing.expect(progress.map.get(1) != null);
        try std.testing.expectEqual(32, consensus.fork_choice.heaviestOverallSlot().slot);
    }

    {
        const slot: Slot = 33;
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

        var slot_state: sig.core.SlotState = .GENESIS;
        slot_state.hash = .init(slot_hash);

        try slot_tracker.put(allocator, slot, .{ .constants = slot_constants, .state = slot_state });
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

        try consensus.process(allocator, .{
            .account_store = stubs.accountStore(),
            .ledger = &stubs.ledger,
            .gossip_votes = null,
            .slot_tracker = &slot_tracker,
            .epoch_tracker = &epoch_tracker,
            .progress_map = &progress,
            .status_cache = null,
            .senders = stubs.senders,
            .receivers = stubs.receivers,
            .vote_sockets = null,
            .slot_leaders = null,
            .duplicate_confirmed_slots = &duplicate_confirmed_slots,
            .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
            .results = &results,
        });

        const new_root = try consensus.replay_tower.tower.getRoot();
        try std.testing.expect(new_root > old_root);
        try std.testing.expectEqual(1, old_root);
        try std.testing.expectEqual(2, new_root);
        try std.testing.expectEqual(
            MAX_LOCKOUT_HISTORY,
            consensus.replay_tower.tower.votes.len,
        );

        try std.testing.expect(new_root > initial_root);
        const last_voted = consensus.replay_tower.tower.lastVotedSlot();
        try std.testing.expectEqual(33, last_voted);

        try std.testing.expectEqual(2, slot_tracker.root);
        // No longer tracking slot 0
        try std.testing.expect(!slot_tracker.contains(0));
        // No longer tracking slot 1
        try std.testing.expect(!slot_tracker.contains(1));
        // Still tracking slot 2
        try std.testing.expect(slot_tracker.contains(2));
        try std.testing.expect(slot_tracker.contains(33));

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

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit();

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
        const account_store = stubs.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state: sig.core.SlotState = .GENESIS;

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

        var slot_state: sig.core.SlotState = .GENESIS;
        errdefer slot_state.deinit(allocator);
        slot_state.hash = .init(slot1_hash);

        try slot_tracker.put(allocator, 1, .{ .constants = slot_constants, .state = slot_state });
    }

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{.EMPTY_WITH_GENESIS},
    );
    defer epoch_tracker.deinit(allocator);

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

    var consensus = try TowerConsensus.init(allocator, .{
        .logger = .noop,
        .identity = .{
            .vote_account = null,
            .validator = .initRandom(std.crypto.random),
        },
        .signing = .{
            .node = null,
            .authorized_voters = &.{},
        },
        .account_reader = stubs.accountReader(),
        .ledger = &stubs.ledger,
        .slot_tracker = &slot_tracker,
        .now = .EPOCH_ZERO,
        .registry = &registry,
    });
    defer consensus.deinit(allocator);

    var duplicate_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var gossip_verified_vote_hashes: std.ArrayListUnmanaged(GossipVerifiedVoteHash) = .empty;
    defer gossip_verified_vote_hashes.deinit(allocator);

    {
        const results = [_]ReplayResult{
            .{ .slot = 1, .output = .{ .last_entry_hash = slot1_hash } },
        };

        try consensus.process(allocator, .{
            .account_store = stubs.accountStore(),
            .ledger = &stubs.ledger,
            .gossip_votes = null,
            .slot_tracker = &slot_tracker,
            .epoch_tracker = &epoch_tracker,
            .progress_map = &progress,
            .status_cache = null,
            .senders = stubs.senders,
            .receivers = stubs.receivers,
            .vote_sockets = null,
            .slot_leaders = null,
            .duplicate_confirmed_slots = &duplicate_confirmed_slots,
            .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
            .results = &results,
        });
    }

    const initial_last_voted = consensus.replay_tower.lastVotedSlot();
    try std.testing.expectEqual(1, initial_last_voted);
    const initial_tx_blockhash = consensus.replay_tower.last_vote_tx_blockhash;
    try std.testing.expect(initial_tx_blockhash == .non_voting);

    // The Test
    {
        const empty_results: []const ReplayResult = &.{};

        try consensus.process(allocator, .{
            .account_store = stubs.accountStore(),
            .ledger = &stubs.ledger,
            .gossip_votes = null,
            .slot_tracker = &slot_tracker,
            .epoch_tracker = &epoch_tracker,
            .progress_map = &progress,
            .status_cache = null,
            .senders = stubs.senders,
            .receivers = stubs.receivers,
            .vote_sockets = null,
            .slot_leaders = null,
            .duplicate_confirmed_slots = &duplicate_confirmed_slots,
            .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
            .results = empty_results,
        });
    }

    // Assert: No new vote recorded
    const final_last_voted = consensus.replay_tower.lastVotedSlot();
    try std.testing.expectEqual(initial_last_voted, final_last_voted);
    try std.testing.expectEqual(1, final_last_voted);

    // Assert: blockhash status remains non_voting (current stub behavior)
    const final_tx_blockhash = consensus.replay_tower.last_vote_tx_blockhash;
    try std.testing.expect(final_tx_blockhash == .non_voting);

    // The vote count in tower should remain the same (1 vote)
    try std.testing.expectEqual(1, consensus.replay_tower.tower.votes.len);

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

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit();

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
        const account_store = stubs.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state: sig.core.SlotState = .GENESIS;

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

        // Set up ancestors (include root for lockout logic)
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 1, {});

        var slot_state: sig.core.SlotState = .GENESIS;
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

        // Set up ancestors (include root for lockout logic)
        slot_constants.ancestors.deinit(allocator);
        slot_constants.ancestors = .{};
        try slot_constants.ancestors.ancestors.put(allocator, 0, {});
        try slot_constants.ancestors.ancestors.put(allocator, 1, {});
        try slot_constants.ancestors.ancestors.put(allocator, 2, {});

        var slot_state: sig.core.SlotState = .GENESIS;
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot2_hash);

        try slot_tracker.put(allocator, 2, .{ .constants = slot_constants, .state = slot_state });
    }

    const epoch_stakes = blk: {
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
                try vote_account.account.state.votes.append(allocator, .{
                    .latency = 0,
                    .lockout = .{ .slot = 1, .confirmation_count = 2 },
                });
            }
        }

        break :blk epoch_stakes;
    };

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{epoch_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    {
        {
            const slot1_ref = slot_tracker.get(1).?;
            const stakes_ptr, var stakes_guard = slot1_ref.state.stakes_cache.stakes.writeWithLock();
            defer stakes_guard.unlock();
            stakes_ptr.deinit(allocator);
            stakes_ptr.* = try sig.core.bank.parseStakesForTest(
                allocator,
                &epoch_stakes.stakes,
            );
        }

        {
            const slot2_ref = slot_tracker.get(2).?;
            const stakes_ptr, var stakes_guard = slot2_ref.state.stakes_cache.stakes.writeWithLock();
            defer stakes_guard.unlock();
            stakes_ptr.deinit(allocator);
            stakes_ptr.* = try sig.core.bank.parseStakesForTest(
                allocator,
                &epoch_stakes.stakes,
            );
        }
    }

    var progress = sig.consensus.ProgressMap.INIT;
    defer progress.deinit(allocator);

    {
        var fork_progress0 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        fork_progress0.fork_stats.computed = true;
        // Mark root as already duplicate-confirmed to skip it in detection loop
        fork_progress0.fork_stats.duplicate_confirmed_hash = Hash.ZEROES;
        const fork_progress1 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        const fork_progress2 = try sig.consensus.progress_map.ForkProgress.zeroes(allocator);
        try progress.map.put(allocator, 0, fork_progress0);
        try progress.map.put(allocator, 1, fork_progress1);
        try progress.map.put(allocator, 2, fork_progress2);
    }

    var replay_votes_channel = try Channel(ParsedVote).create(allocator);
    defer replay_votes_channel.destroy();

    var consensus = try TowerConsensus.init(allocator, .{
        .logger = .noop,
        .identity = .{
            .vote_account = null,
            .validator = Pubkey.initRandom(std.crypto.random),
        },
        .signing = .{
            .node = null,
            .authorized_voters = &.{},
        },
        .account_reader = stubs.accountReader(),
        .ledger = &stubs.ledger,
        .slot_tracker = &slot_tracker,
        .now = .EPOCH_ZERO,
        .registry = &registry,
    });
    defer consensus.deinit(allocator);

    var duplicate_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var gossip_verified_vote_hashes: std.ArrayListUnmanaged(GossipVerifiedVoteHash) = .empty;
    defer gossip_verified_vote_hashes.deinit(allocator);

    // Verify slot 1 is not yet marked as duplicate-confirmed
    try std.testing.expect(progress.getForkStats(1).?.duplicate_confirmed_hash == null);
    try std.testing.expect(consensus.slot_data.duplicate_confirmed_slots.get(1) == null);

    // Process slot 2 - should detect duplicate-confirmed condition for slot 1
    // (When processing slot 2, the votes on slot 1 become nth(1) lockouts, which populates voted_stakes[1])
    {
        const results = [_]ReplayResult{
            .{ .slot = 2, .output = .{ .last_entry_hash = slot2_hash } },
        };

        try consensus.process(allocator, .{
            .account_store = stubs.accountStore(),
            .ledger = &stubs.ledger,
            .gossip_votes = null,
            .slot_tracker = &slot_tracker,
            .epoch_tracker = &epoch_tracker,
            .progress_map = &progress,
            .status_cache = null,
            .senders = stubs.senders,
            .receivers = stubs.receivers,
            .vote_sockets = null,
            .slot_leaders = null,
            .duplicate_confirmed_slots = &duplicate_confirmed_slots,
            .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
            .results = &results,
        });
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

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit();

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
        const account_store = stubs.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state: sig.core.SlotState = .GENESIS;

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

        var slot_state: sig.core.SlotState = .GENESIS;
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot1_hash);

        try slot_tracker.put(allocator, 1, .{ .constants = slot_constants, .state = slot_state });
    }

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{.EMPTY_WITH_GENESIS},
    );
    defer epoch_tracker.deinit(allocator);

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

    var consensus = try TowerConsensus.init(allocator, .{
        .logger = .noop,
        .identity = .{
            .vote_account = null,
            .validator = Pubkey.initRandom(std.crypto.random),
        },
        .signing = .{
            .node = null,
            .authorized_voters = &.{},
        },
        .account_reader = stubs.accountReader(),
        .ledger = &stubs.ledger,
        .slot_tracker = &slot_tracker,
        .now = .EPOCH_ZERO,
        .registry = &registry,
    });
    defer consensus.deinit(allocator);

    var duplicate_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var gossip_verified_vote_hashes: std.ArrayListUnmanaged(GossipVerifiedVoteHash) = .empty;
    defer gossip_verified_vote_hashes.deinit(allocator);

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

        try consensus.process(allocator, .{
            .account_store = stubs.accountStore(),
            .ledger = &stubs.ledger,
            .gossip_votes = null,
            .slot_tracker = &slot_tracker,
            .epoch_tracker = &epoch_tracker,
            .progress_map = &progress,
            .status_cache = null,
            .senders = stubs.senders,
            .receivers = stubs.receivers,
            .vote_sockets = null,
            .slot_leaders = null,
            .duplicate_confirmed_slots = &duplicate_confirmed_slots,
            .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
            .results = &results,
        });
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

    var registry: sig.prometheus.Registry(.{}) = .init(allocator);
    defer registry.deinit();

    var stubs = try sig.replay.service.DependencyStubs.init(allocator, .noop);
    defer stubs.deinit();

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
        const account_store = stubs.accountStore();
        try account_store.put(0, SlotHistory.ID, account);
    }

    // Root 0
    const root_slot: Slot = 0;
    const root_consts = try sig.core.SlotConstants.genesis(allocator, .DEFAULT);
    var root_state: sig.core.SlotState = .GENESIS;
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

        var slot_state: sig.core.SlotState = .GENESIS;
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

        var slot_state: sig.core.SlotState = .GENESIS;
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

        var slot_state: sig.core.SlotState = .GENESIS;
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot4_hash);
        try slot_tracker.put(allocator, 4, .{ .constants = slot_constants, .state = slot_state });
    }

    var vote_pubkeys = try allocator.alloc(Pubkey, 5);
    defer allocator.free(vote_pubkeys);
    const epoch_stakes = blk: {
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

        break :blk epoch_stakes;
    };

    var epoch_tracker = try sig.core.EpochTracker.initWithEpochStakesOnlyForTest(
        allocator,
        &.{epoch_stakes},
    );
    defer epoch_tracker.deinit(allocator);

    {
        {
            const s1 = slot_tracker.get(1).?;
            const stakes_ptr1, var g1 = s1.state.stakes_cache.stakes.writeWithLock();
            defer g1.unlock();
            stakes_ptr1.deinit(allocator);
            stakes_ptr1.* = try sig.core.bank.parseStakesForTest(
                allocator,
                &epoch_stakes.stakes,
            );
        }
        {
            const s2 = slot_tracker.get(2).?;
            const stakes_ptr2, var g2 = s2.state.stakes_cache.stakes.writeWithLock();
            defer g2.unlock();
            stakes_ptr2.deinit(allocator);
            stakes_ptr2.* = try sig.core.bank.parseStakesForTest(
                allocator,
                &epoch_stakes.stakes,
            );
        }
        {
            const s4 = slot_tracker.get(4).?;
            const stakes_ptr4, var g4 = s4.state.stakes_cache.stakes.writeWithLock();
            defer g4.unlock();
            stakes_ptr4.deinit(allocator);
            stakes_ptr4.* = try sig.core.bank.parseStakesForTest(
                allocator,
                &epoch_stakes.stakes,
            );
        }
    }

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

    var consensus = try TowerConsensus.init(allocator, .{
        .logger = .noop,
        .identity = .{
            .vote_account = null,
            .validator = Pubkey.initRandom(std.crypto.random),
        },
        .signing = .{
            .node = null,
            .authorized_voters = &.{},
        },
        .account_reader = stubs.accountReader(),
        .ledger = &stubs.ledger,
        .slot_tracker = &slot_tracker,
        .now = .EPOCH_ZERO,
        .registry = &registry,
    });
    defer consensus.deinit(allocator);

    var duplicate_confirmed_slots: std.ArrayListUnmanaged(ThresholdConfirmedSlot) = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var gossip_verified_vote_hashes: std.ArrayListUnmanaged(GossipVerifiedVoteHash) = .empty;
    defer gossip_verified_vote_hashes.deinit(allocator);

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

    try ancestors_map.ensureTotalCapacity(allocator, slot_tracker.slots.count());
    try descendants_map.ensureTotalCapacity(allocator, slot_tracker.slots.count());
    for (slot_tracker.slots.keys(), slot_tracker.slots.values()) |slot, info| {
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

    const epoch_info = try epoch_tracker.getEpochInfo(0);
    const vote_accounts_map = &epoch_info.stakes.stakes.vote_accounts.vote_accounts;
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

        try consensus.process(allocator, .{
            .account_store = stubs.accountStore(),
            .ledger = &stubs.ledger,
            .gossip_votes = null,
            .slot_tracker = &slot_tracker,
            .epoch_tracker = &epoch_tracker,
            .progress_map = &progress,
            .status_cache = null,
            .senders = stubs.senders,
            .receivers = stubs.receivers,
            .vote_sockets = null,
            .slot_leaders = null,
            .duplicate_confirmed_slots = &duplicate_confirmed_slots,
            .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
            .results = &results2,
        });
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

        try consensus.process(allocator, .{
            .account_store = stubs.accountStore(),
            .ledger = &stubs.ledger,
            .gossip_votes = null,
            .slot_tracker = &slot_tracker,
            .epoch_tracker = &epoch_tracker,
            .progress_map = &progress,
            .status_cache = null,
            .senders = stubs.senders,
            .receivers = stubs.receivers,
            .vote_sockets = null,
            .slot_leaders = null,
            .duplicate_confirmed_slots = &duplicate_confirmed_slots,
            .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
            .results = &results,
        });
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

        var slot_state: sig.core.SlotState = .GENESIS;
        errdefer slot_state.deinit(allocator);
        slot_state.hash.set(slot5_hash);
        try slot_tracker.put(allocator, 5, .{ .constants = slot_constants, .state = slot_state });
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

        try consensus.process(allocator, .{
            .account_store = stubs.accountStore(),
            .ledger = &stubs.ledger,
            .gossip_votes = null,
            .slot_tracker = &slot_tracker,
            .epoch_tracker = &epoch_tracker,
            .progress_map = &progress,
            .status_cache = null,
            .senders = stubs.senders,
            .receivers = stubs.receivers,
            .vote_sockets = null,
            .slot_leaders = null,
            .duplicate_confirmed_slots = &duplicate_confirmed_slots,
            .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
            .results = empty_results,
        });
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

    try ancestors_map2.ensureTotalCapacity(allocator, slot_tracker.slots.count());
    try descendants_map2.ensureTotalCapacity(allocator, slot_tracker.slots.count());
    for (slot_tracker.slots.keys(), slot_tracker.slots.values()) |slot, info| {
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

        try consensus.process(allocator, .{
            .account_store = stubs.accountStore(),
            .ledger = &stubs.ledger,
            .gossip_votes = null,
            .slot_tracker = &slot_tracker,
            .epoch_tracker = &epoch_tracker,
            .progress_map = &progress,
            .status_cache = null,
            .senders = stubs.senders,
            .receivers = stubs.receivers,
            .vote_sockets = null,
            .slot_leaders = null,
            .duplicate_confirmed_slots = &duplicate_confirmed_slots,
            .gossip_verified_vote_hashes = &gossip_verified_vote_hashes,
            .results = &results5,
        });
        try std.testing.expectEqual(4, consensus.replay_tower.lastVotedSlot());
    }

    // Cleanup: free SlotTracker elements owned via slot_tracker_rw
    for (slot_tracker.slots.values()) |element| {
        element.state.deinit(allocator);
        element.constants.deinit(allocator);
        allocator.destroy(element);
    }
    slot_tracker.slots.deinit(allocator);
}

test "loadTower handles missing vote account" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const vote_pubkey: Pubkey = .initRandom(prng.random());

    try std.testing.expectError(
        error.VoteAccountNotFound,
        loadTower(allocator, .noop, .{ .account_map = &.empty }, vote_pubkey),
    );
}

test "loadTower handles invalid vote account owner" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const vote_pubkey: Pubkey = .initRandom(prng.random());
    const wrong_owner: Pubkey = Pubkey.initRandom(prng.random());

    // Create an account with wrong owner
    const account_with_wrong_owner = sig.core.Account{
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocated(&[_]u8{}),
        .executable = false,
        .lamports = 1000,
        .owner = wrong_owner,
        .rent_epoch = 0,
    };

    var account_map: sig.utils.collections.PubkeyMap(sig.core.Account) = .empty;
    defer {
        var iter = account_map.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit(allocator);
        }
        account_map.deinit(allocator);
    }
    try account_map.put(allocator, vote_pubkey, account_with_wrong_owner);

    // Should return InvalidVoteAccountOwner error
    const result = loadTower(allocator, .noop, .{ .account_map = &account_map }, vote_pubkey);

    try std.testing.expectError(error.InvalidVoteAccountOwner, result);
}

test "loadTower handles invalid vote state" {
    const allocator = std.testing.allocator;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const vote_pubkey: Pubkey = .initRandom(prng.random());

    // Create an account with invalid vote state data (garbage bytes)
    const invalid_data_bytes = try allocator.alloc(u8, 4);
    defer allocator.free(invalid_data_bytes);
    @memcpy(invalid_data_bytes, &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF });

    const invalid_account = sig.core.Account{
        .data = sig.accounts_db.buffer_pool.AccountDataHandle.initAllocated(invalid_data_bytes),
        .executable = false,
        .lamports = 1000,
        .owner = vote_program.ID,
        .rent_epoch = 0,
    };

    var account_map: sig.utils.collections.PubkeyMap(sig.core.Account) = .empty;
    defer {
        var iter = account_map.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit(allocator);
        }
        account_map.deinit(allocator);
    }
    try account_map.put(allocator, vote_pubkey, invalid_account);

    // Should return BincodeError when trying to deserialize invalid vote state
    const result = loadTower(allocator, .noop, .{ .account_map = &account_map }, vote_pubkey);

    try std.testing.expectError(error.BincodeError, result);
}
