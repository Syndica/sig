const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const AccountsDB = sig.accounts_db.AccountsDB;
const BlockstoreDB = sig.ledger.BlockstoreDB;
const BlockstoreReader = sig.ledger.BlockstoreReader;
const ProgressMap = sig.consensus.ProgressMap;
const Slot = sig.core.Slot;
const SlotLeaders = sig.core.leader_schedule.SlotLeaders;
const SlotState = sig.core.bank.SlotState;
const LedgerResultWriter = sig.ledger.result_writer.LedgerResultWriter;
const ReplayExecutionState = replay.execution.ReplayExecutionState;
const SlotTracker = replay.trackers.SlotTracker;
const EpochTracker = replay.trackers.EpochTracker;

const GossipVerifiedVoteHash = sig.consensus.vote_listener.GossipVerifiedVoteHash;
const ThresholdConfirmedSlot = sig.consensus.vote_listener.ThresholdConfirmedSlot;
const LatestValidatorVotesForFrozenSlots =
    sig.consensus.unimplemented.LatestValidatorVotesForFrozenBanks;

/// Number of threads to use in replay's thread pool
const NUM_THREADS = 4;

const SWITCH_FORK_THRESHOLD: f64 = 0.38;
const MAX_ENTRIES: u64 = 1024 * 1024; // 1 million slots is about 5 days
const DUPLICATE_LIVENESS_THRESHOLD: f64 = 0.1;
pub const DUPLICATE_THRESHOLD: f64 = 1.0 - SWITCH_FORK_THRESHOLD - DUPLICATE_LIVENESS_THRESHOLD;

pub const ReplayDependencies = struct {
    /// Used for all allocations within the replay stage
    allocator: Allocator,
    logger: sig.trace.Logger,
    my_identity: sig.core.Pubkey,
    /// Tell replay when to exit
    exit: *std.atomic.Value(bool),
    /// Used in the EpochManager
    epoch_schedule: sig.core.EpochSchedule,
    /// Used to get the entries to validate them and execute the transactions
    blockstore_reader: *BlockstoreReader,
    /// Used to update the ledger with consensus results
    ledger_result_writer: *LedgerResultWriter,
    /// Used to get the entries to validate them and execute the transactions
    accounts_db: *AccountsDB,
    slot_leaders: SlotLeaders,
    /// The slot to start replaying from.
    root_slot: Slot,
    root_slot_constants: sig.core.SlotConstants,
    root_slot_state: sig.core.SlotState,
};

const ReplayState = struct {
    allocator: Allocator,
    logger: sig.trace.ScopedLogger("replay"),
    thread_pool: *ThreadPool,
    slot_leaders: SlotLeaders,
    slot_tracker: *SlotTracker,
    epochs: *EpochTracker,
    blockstore_db: BlockstoreDB,
    execution: ReplayExecutionState,

    fn init(deps: ReplayDependencies) Allocator.Error!ReplayState {
        const thread_pool = try deps.allocator.create(ThreadPool);
        errdefer deps.allocator.destroy(thread_pool);
        thread_pool.* = ThreadPool.init(.{ .max_threads = NUM_THREADS });

        const slot_tracker = try deps.allocator.create(SlotTracker);
        errdefer deps.allocator.destroy(slot_tracker);
        slot_tracker.* = .init(deps.root_slot);
        try slot_tracker.put(
            deps.allocator,
            deps.root_slot,
            deps.root_slot_constants,
            deps.root_slot_state,
        );

        const epoch_tracker = try deps.allocator.create(EpochTracker);
        errdefer deps.allocator.destroy(epoch_tracker);
        epoch_tracker.* = .{ .schedule = deps.epoch_schedule };

        return .{
            .allocator = deps.allocator,
            .logger = .from(deps.logger),
            .thread_pool = thread_pool,
            .slot_leaders = deps.slot_leaders,
            .slot_tracker = slot_tracker,
            .epochs = epoch_tracker,
            .blockstore_db = deps.blockstore_reader.db,
            .execution = try ReplayExecutionState.init(
                deps.allocator,
                deps.logger,
                deps.my_identity,
                thread_pool,
                deps.accounts_db,
                deps.blockstore_reader,
                slot_tracker,
                epoch_tracker,
            ),
        };
    }

    fn deinit(self: *ReplayState) void {
        self.thread_pool.shutdown();
        self.thread_pool.deinit();
        self.allocator.destroy(self.thread_pool);
        self.slot_tracker.deinit(self.allocator);
        self.allocator.destroy(self.slot_tracker);
        self.epochs.deinit(self.allocator);
        self.allocator.destroy(self.epochs);
    }
};

/// Run the replay service indefinitely.
pub fn run(deps: ReplayDependencies) !void {
    var state = try ReplayState.init(deps);
    defer state.deinit();

    while (!deps.exit.load(.monotonic)) try advanceReplay(&state);
}

/// Run a single iteration of the entire replay process. Includes:
/// - replay all active slots that have not been replayed yet
/// - running concensus on the latest updates
fn advanceReplay(state: *ReplayState) !void {
    try trackNewSlots(
        state.allocator,
        &state.blockstore_db,
        state.slot_tracker,
        state.epochs,
        state.slot_leaders,
        &state.execution.progress_map,
    );

    _ = try replay.execution.replayActiveSlots(&state.execution);

    handleEdgeCases();

    processConsensus();

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
    blockstore_db: *sig.ledger.BlockstoreDB,
    slot_tracker: *SlotTracker,
    epoch_tracker: *EpochTracker,
    slot_leaders: SlotLeaders,
    /// needed for update_fork_propagated_threshold_from_votes
    _: *ProgressMap,
) !void {
    const root = slot_tracker.root;
    var frozen_slots = try slot_tracker.frozenSlots(allocator);
    defer frozen_slots.deinit(allocator);

    var frozen_slots_since_root = try std.ArrayListUnmanaged(sig.core.Slot)
        .initCapacity(allocator, frozen_slots.count());
    defer frozen_slots_since_root.deinit(allocator);
    for (frozen_slots.keys()) |slot| if (slot >= root) {
        frozen_slots_since_root.appendAssumeCapacity(slot);
    };

    var next_slots = try BlockstoreReader
        .getSlotsSince(allocator, blockstore_db, frozen_slots_since_root.items);
    defer {
        for (next_slots.values()) |*list| list.deinit(allocator);
        next_slots.deinit(allocator);
    }

    for (next_slots.keys(), next_slots.values()) |parent_slot, children| {
        const parent_info = frozen_slots.get(parent_slot) orelse return error.MissingParent;
        for (children.items) |child_slot| {
            if (slot_tracker.contains(child_slot)) continue;

            const epoch_info = epoch_tracker.getPtrForSlot(child_slot) orelse
                return error.MissingEpoch;

            var slot_state = try SlotState.fromFrozenParent(allocator, parent_info.state);
            errdefer slot_state.deinit(allocator);

            const epoch_reward_status = try parent_info.constants.epoch_reward_status
                .clone(allocator);
            errdefer epoch_reward_status.deinit(allocator);

            const leader = slot_leaders.get(child_slot) orelse return error.UnknownLeader;

            try slot_tracker.put(
                allocator,
                child_slot,
                .{
                    .parent_slot = parent_slot,
                    .parent_hash = parent_info.state.hash.readCopy().?,
                    .block_height = parent_info.constants.block_height + 1,
                    .collector_id = leader,
                    .max_tick_height = (child_slot + 1) * epoch_info.ticks_per_slot,
                    .fee_rate_governor = .initDerived(
                        &parent_info.constants.fee_rate_governor,
                        parent_info.state.signature_count.load(.monotonic),
                    ),
                    .epoch_reward_status = epoch_reward_status,
                },
                slot_state,
            );

            // TODO: update_fork_propagated_threshold_from_votes
        }
    }
}

// -- handleEdgeCases START -- //
fn handleEdgeCases() void {
    _ = &processAncestorHashesDuplicateSlots; // TODO:

    _ = &processDuplicateConfirmedSlots; // TODO:

    _ = &processGossipVerifiedVoteHashes; // TODO:

    _ = &processPopularPrunedForks; // TODO:

    _ = &processDuplicateSlots; // TODO:
}

const DuplicateSlotsToRepair = std.AutoArrayHashMapUnmanaged(
    sig.core.Slot,
    sig.core.Hash,
);
const DuplicateSlot = sig.utils.collections.SortedMapUnmanaged(
    sig.core.Slot,
    void,
);
const EpochSlotsFrozenSlots = sig.utils.collections.SortedMapUnmanaged(
    sig.core.Slot,
    sig.core.Hash,
);
const DuplicateConfirmedSlots = sig.utils.collections.SortedMapUnmanaged(
    sig.core.Slot,
    sig.core.Hash,
);
const PurgeRepairSlotCounters = sig.utils.collections.SortedMapUnmanaged(
    sig.core.Slot,
    usize,
);

const AncestorHashesReplayUpdate = struct {
    slot: sig.core.Slot,
    kind: Kind,
    pub const Kind = enum {
        dead,
        dead_duplicate_confirmed,
        /// `Slot` belongs to a fork we have pruned. We have observed that this fork is "popular" aka
        /// reached 52+% stake through votes in turbine/gossip including votes for descendants. These
        /// votes are hash agnostic since we have not replayed `Slot` so we can never say for certainty
        /// that this fork has reached duplicate confirmation, but it is suspected to have. This
        /// indicates that there is most likely a block with invalid ancestry present and thus we
        /// collect an ancestor sample to resolve this issue. `Slot` is the deepest slot in this fork
        /// that is popular, so any duplicate problems will be for `Slot` or one of it's ancestors.
        popular_pruned_fork,
    };
};

const AncestorDuplicateSlotToRepair = struct {
    /// Slot that `ancestor_hashes_service` found that needs to be repaired
    slot_to_repair: struct { sig.core.Slot, sig.core.Hash },
    /// Condition that initiated this request
    request_type: AncestorRequestType,
};

const AncestorRequestType = enum {
    dead_duplicate_confirmed,
    popular_pruned,

    pub const default: AncestorRequestType = .dead_duplicate_confirmed;
};

pub const ClusterConfirmedHash = struct {
    kind: Kind,
    hash: sig.core.Hash,

    /// Ordered from strongest confirmation to weakest. Stronger
    /// confirmations take precedence over weaker ones.
    pub const Kind = enum {
        duplicate_confirmed,
        epoch_slots_frozen,
    };
};

pub const SlotStatus = union(enum) {
    frozen: sig.core.Hash,
    dead,
    unprocessed,

    /// Returns `.frozen` or `.unprocessed`.
    pub fn fromHash(maybe_hash: ?sig.core.Hash) SlotStatus {
        if (maybe_hash) |hash| {
            return .{ .frozen = hash };
        } else {
            return .unprocessed;
        }
    }

    fn slotHash(self: SlotStatus) ?sig.core.Hash {
        return switch (self) {
            .frozen => |hash| hash,
            .dead => null,
            .unprocessed => null,
        };
    }
};

const SlotFrozenState = struct {
    frozen_hash: sig.core.Hash,
    cluster_confirmed_hash: ?ClusterConfirmedHash,
    is_slot_duplicate: bool,

    pub fn fromState(
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        frozen_hash: sig.core.Hash,
        duplicate_slots_tracker: *const DuplicateSlot,
        duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
        fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
        epoch_slots_frozen_slots: *const EpochSlotsFrozenSlots,
    ) SlotFrozenState {
        const cluster_confirmed_hash = getClusterConfirmedHashFromState(
            logger,
            slot,
            duplicate_confirmed_slots,
            epoch_slots_frozen_slots,
            fork_choice,
            frozen_hash,
        );
        const is_slot_duplicate = duplicate_slots_tracker.contains(slot);
        return .{
            .frozen_hash = frozen_hash,
            .cluster_confirmed_hash = cluster_confirmed_hash,
            .is_slot_duplicate = is_slot_duplicate,
        };
    }
};

pub const DuplicateConfirmedState = struct {
    duplicate_confirmed_hash: sig.core.Hash,
    slot_status: SlotStatus,
};

pub const DeadState = struct {
    cluster_confirmed_hash: ?ClusterConfirmedHash,
    is_slot_duplicate: bool,

    pub fn fromState(
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        duplicate_slots_tracker: *const DuplicateSlot,
        duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
        fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
        epoch_slots_frozen_slots: *const EpochSlotsFrozenSlots,
    ) DeadState {
        const cluster_confirmed_hash = getClusterConfirmedHashFromState(
            logger,
            slot,
            duplicate_confirmed_slots,
            epoch_slots_frozen_slots,
            fork_choice,
            null,
        );
        const is_slot_duplicate = duplicate_slots_tracker.contains(slot);
        return .{
            .cluster_confirmed_hash = cluster_confirmed_hash,
            .is_slot_duplicate = is_slot_duplicate,
        };
    }
};

pub const DuplicateState = struct {
    duplicate_confirmed_hash: ?sig.core.Hash,
    slot_status: SlotStatus,

    pub fn fromState(
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
        fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
        slot_status: SlotStatus,
    ) DuplicateState {
        // We can only skip marking duplicate if this slot has already been
        // duplicate confirmed, any weaker confirmation levels are not sufficient
        // to skip marking the slot as duplicate.
        const duplicate_confirmed_hash = getDuplicateConfirmedHashFromState(
            logger,
            slot,
            duplicate_confirmed_slots,
            fork_choice,
            slot_status.slotHash(),
        );
        return .{
            .duplicate_confirmed_hash = duplicate_confirmed_hash,
            .slot_status = slot_status,
        };
    }
};

pub const EpochSlotsFrozenState = struct {
    epoch_slots_frozen_hash: sig.core.Hash,
    duplicate_confirmed_hash: ?sig.core.Hash,
    slot_status: SlotStatus,
    is_popular_pruned: bool,

    pub fn fromState(
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        epoch_slots_frozen_hash: sig.core.Hash,
        duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
        fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
        slot_status: SlotStatus,
        is_popular_pruned: bool,
    ) EpochSlotsFrozenState {
        const duplicate_confirmed_hash = getDuplicateConfirmedHashFromState(
            logger,
            slot,
            duplicate_confirmed_slots,
            fork_choice,
            slot_status.slotHash(),
        );
        return .{
            .epoch_slots_frozen_hash = epoch_slots_frozen_hash,
            .duplicate_confirmed_hash = duplicate_confirmed_hash,
            .slot_status = slot_status,
            .is_popular_pruned = is_popular_pruned,
        };
    }
};

/// Analogous to [process_ancestor_hashes_duplicate_slots](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L1627)
fn processAncestorHashesDuplicateSlots(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    pubkey: sig.core.Pubkey,
    ancestor_duplicate_slots_receiver: *sig.sync.Channel(AncestorDuplicateSlotToRepair),
    duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
    epoch_slots_frozen_slots: *EpochSlotsFrozenSlots,
    progress: *const sig.consensus.ProgressMap,
    fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
    slot_tracker_rwmux: *sig.sync.RwMux(sig.replay.trackers.SlotTracker),
    duplicate_slots_to_repair: *DuplicateSlotsToRepair,
) !void {
    const root = root: {
        const slot_tracker, var slot_tracker_lg = slot_tracker_rwmux.readWithLock();
        defer slot_tracker_lg.unlock();
        break :root slot_tracker.root;
    };

    while (ancestor_duplicate_slots_receiver.tryReceive()) |ancestor_dupe_slot_to_repair| {
        const request_type = ancestor_dupe_slot_to_repair.request_type;
        const slot_to_repair = ancestor_dupe_slot_to_repair.slot_to_repair;
        const epoch_slots_frozen_slot, const epoch_slots_frozen_hash = slot_to_repair;
        logger.warn().logf(
            "{} ReplayStage notified of duplicate slot from ancestor hashes service but we " ++
                "observed as {s}: {}",
            .{ pubkey, if (request_type == .popular_pruned)
                "pruned"
            else
                "dead", slot_to_repair },
        );

        const slot_status: SlotStatus = status: {
            if (progress.isDead(epoch_slots_frozen_slot) orelse false) break :status .dead;
            const slot_tracker, var slot_tracker_lg = slot_tracker_rwmux.readWithLock();
            defer slot_tracker_lg.unlock();
            break :status .fromHash(
                if (slot_tracker.slots.get(epoch_slots_frozen_slot)) |slot_info|
                    slot_info.state.hash.readCopy()
                else
                    null,
            );
        };

        const epoch_slots_frozen_state: EpochSlotsFrozenState = .fromState(
            logger,
            epoch_slots_frozen_slot,
            epoch_slots_frozen_hash,
            duplicate_confirmed_slots,
            fork_choice,
            slot_status,
            request_type == .popular_pruned,
        );
        try check_slot_agrees_with_cluster.epochSlotsFrozen(
            allocator,
            logger,
            epoch_slots_frozen_slot,
            root,
            fork_choice,
            duplicate_slots_to_repair,
            epoch_slots_frozen_slots,
            epoch_slots_frozen_state,
        );
    }
}

/// Check for any newly duplicate confirmed slots by the cluster.
/// This only tracks duplicate slot confirmations on the exact
/// single slots and does not account for votes on their descendants. Used solely
/// for duplicate slot recovery.
/// Analogous to [process_duplicate_confirmed_slots](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L1866)
fn processDuplicateConfirmedSlots(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    duplicate_confirmed_slots_receiver: *sig.sync.Channel(ThresholdConfirmedSlot),
    blockstore: *sig.ledger.LedgerResultWriter,
    duplicate_confirmed_slots: *DuplicateConfirmedSlots,
    slot_tracker_rwmux: *sig.sync.RwMux(sig.replay.trackers.SlotTracker),
    progress: *const sig.consensus.ProgressMap,
    fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
    duplicate_slots_to_repair: *DuplicateSlotsToRepair,
    ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
    purge_repair_slot_counter: *PurgeRepairSlotCounters,
) !void {
    const root = root: {
        const slot_tracker, var slot_tracker_lg = slot_tracker_rwmux.readWithLock();
        defer slot_tracker_lg.unlock();
        break :root slot_tracker.root;
    };
    while (duplicate_confirmed_slots_receiver.tryReceive()) |new_duplicate_confirmed_slot| {
        const confirmed_slot, const duplicate_confirmed_hash = new_duplicate_confirmed_slot;
        if (confirmed_slot <= root) {
            continue;
        } else if (try duplicate_confirmed_slots.fetchPut(
            allocator,
            confirmed_slot,
            duplicate_confirmed_hash,
        )) |kv| {
            const prev_hash = kv.value;
            if (!prev_hash.eql(duplicate_confirmed_hash)) {
                std.debug.panic(
                    "Additional duplicate confirmed notification for slot {} with a different hash",
                    .{confirmed_slot},
                );
            }
            // Already processed this signal
            continue;
        }

        const duplicate_confirmed_state: DuplicateConfirmedState = .{
            .duplicate_confirmed_hash = duplicate_confirmed_hash,
            .slot_status = status: {
                if (progress.isDead(confirmed_slot) orelse false) break :status .dead;
                const slot_tracker, var slot_tracker_lg = slot_tracker_rwmux.readWithLock();
                defer slot_tracker_lg.unlock();
                break :status .fromHash(
                    slot_tracker.get(confirmed_slot).?.state.hash.readCopy(),
                );
            },
        };
        try check_slot_agrees_with_cluster.duplicateConfirmed(
            allocator,
            logger,
            confirmed_slot,
            root,
            blockstore,
            fork_choice,
            duplicate_slots_to_repair,
            ancestor_hashes_replay_update_sender,
            purge_repair_slot_counter,
            duplicate_confirmed_state,
        );
    }
}

pub const UnfrozenGossipVerifiedVoteHashes = struct {
    votes_per_slot: sig.utils.collections.SortedMapUnmanaged(sig.core.Slot, HashToVotesMap),

    const HashToVotesMap = std.AutoArrayHashMapUnmanaged(sig.core.Hash, VoteList);
    const VoteList = std.ArrayListUnmanaged(sig.core.Pubkey);

    /// Update `latest_validator_votes_for_frozen_slots` if gossip has seen a newer vote for a frozen slot.
    pub fn addVote(
        self: *UnfrozenGossipVerifiedVoteHashes,
        allocator: std.mem.Allocator,
        pubkey: sig.core.Pubkey,
        vote_slot: sig.core.Slot,
        hash: sig.core.Hash,
        is_frozen: bool,
        latest_validator_votes_for_frozen_slots: *LatestValidatorVotesForFrozenSlots,
    ) !void {
        // If this is a frozen slot, then we need to update the `latest_validator_votes_for_frozen_slots`
        const frozen_hash = if (is_frozen) hash else null;
        const was_added, const maybe_latest_frozen_vote_slot =
            latest_validator_votes_for_frozen_slots.checkAddVote(
                pubkey,
                vote_slot,
                frozen_hash,
                false,
            );

        const vote_slot_gt_latest_frozen_slot: bool = blk: {
            const latest_frozen_vote_slot = maybe_latest_frozen_vote_slot orelse {
                // If there's no latest frozen vote slot yet, then we should also insert
                break :blk true;
            };
            break :blk vote_slot >= latest_frozen_vote_slot;
        };
        if (!was_added and vote_slot_gt_latest_frozen_slot) {
            // At this point it must be that:
            // 1) `vote_slot` was not yet frozen
            // 2) and `vote_slot` >= than the latest frozen vote slot.

            // Thus we want to record this vote for later, in case a slot with this `vote_slot` + hash gets
            // frozen later
            const vps_gop = try self.votes_per_slot.getOrPut(allocator, vote_slot);
            errdefer if (!vps_gop.found_existing) {
                std.debug.assert(self.votes_per_slot.orderedRemove(vps_gop.key_ptr.*));
            };
            const hash_to_votes: *HashToVotesMap = vps_gop.value_ptr;

            if (!vps_gop.found_existing) {
                hash_to_votes.* = .empty;
            }

            const htv_gop = try hash_to_votes.getOrPut(allocator, hash);
            errdefer if (!htv_gop.found_existing) {
                std.debug.assert(hash_to_votes.swapRemove(htv_gop.key_ptr.*));
            };

            try htv_gop.value_ptr.append(allocator, pubkey);
        }
    }
};

/// Analogous to [process_gossip_verified_vote_hashes](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L1917)
fn processGossipVerifiedVoteHashes(
    allocator: std.mem.Allocator,
    gossip_verified_vote_hash_receiver: *sig.sync.Channel(GossipVerifiedVoteHash),
    unfrozen_gossip_verified_vote_hashes: *UnfrozenGossipVerifiedVoteHashes,
    heaviest_subtree_fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
    latest_validator_votes_for_frozen_slots: *LatestValidatorVotesForFrozenSlots,
) !void {
    while (gossip_verified_vote_hash_receiver.tryReceive()) |pubkey_slot_hash| {
        const pubkey, const slot, const hash = pubkey_slot_hash;
        const is_frozen = heaviest_subtree_fork_choice.containsBlock(&.{
            .slot = slot,
            .hash = hash,
        });
        // cluster_info_vote_listener will ensure it doesn't push duplicates
        try unfrozen_gossip_verified_vote_hashes.addVote(
            allocator,
            pubkey,
            slot,
            hash,
            is_frozen,
            latest_validator_votes_for_frozen_slots,
        );
    }
}

/// Analogous to [process_popular_pruned_forks](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L1828)
fn processPopularPrunedForks(
    logger: sig.trace.Logger,
    popular_pruned_forks_receiver: *sig.sync.Channel(sig.core.Slot),
    slot_tracker_rwmux: *sig.sync.RwMux(sig.replay.trackers.SlotTracker),
    ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
) void {
    const root = root: {
        const slot_tracker, var slot_tracker_lg = slot_tracker_rwmux.readWithLock();
        defer slot_tracker_lg.unlock();
        break :root slot_tracker.root;
    };
    while (popular_pruned_forks_receiver.tryReceive()) |new_popular_pruned_slot| {
        if (new_popular_pruned_slot <= root) {
            continue;
        }
        check_slot_agrees_with_cluster.popularPrunedFork(
            logger,
            new_popular_pruned_slot,
            root,
            ancestor_hashes_replay_update_sender,
        );
    }
}

/// Checks for and handle forks with duplicate slots.
/// Analogous to [process_duplicate_slots](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L1938)
fn processDuplicateSlots(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    duplicate_slots_receiver: *sig.sync.Channel(sig.core.Slot),
    duplicate_slots_tracker: *DuplicateSlot,
    duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
    slot_tracker_rwmux: *sig.sync.RwMux(sig.replay.trackers.SlotTracker),
    progress: *const sig.consensus.ProgressMap,
    fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
) !void {
    const MAX_BATCH_SIZE = 1024;

    var new_duplicate_slots: std.BoundedArray(sig.core.Slot, MAX_BATCH_SIZE) = .{};
    while (new_duplicate_slots.unusedCapacitySlice().len != 0) {
        const new_duplicate_slot = duplicate_slots_receiver.tryReceive() orelse break;
        new_duplicate_slots.appendAssumeCapacity(new_duplicate_slot);
    }

    const root_slot, const slots_hashes = blk: {
        const slot_tracker, var slot_tracker_lg = slot_tracker_rwmux.readWithLock();
        defer slot_tracker_lg.unlock();

        var slots_hashes: std.BoundedArray(?sig.core.Hash, MAX_BATCH_SIZE) = .{};
        for (new_duplicate_slots.constSlice()) |duplicate_slot| {
            slots_hashes.appendAssumeCapacity(hash: {
                const bf_elem = slot_tracker.slots.get(duplicate_slot) orelse break :hash null;
                break :hash bf_elem.state.hash.readCopy();
            });
        }

        break :blk .{ slot_tracker.root, slots_hashes };
    };
    for (new_duplicate_slots.constSlice(), slots_hashes.constSlice()) |duplicate_slot, slot_hash| {
        // WindowService should only send the signal once per slot
        const duplicate_state: DuplicateState = .fromState(
            logger,
            duplicate_slot,
            duplicate_confirmed_slots,
            fork_choice,
            if (progress.isDead(duplicate_slot) orelse false) .dead else .fromHash(slot_hash),
        );
        try check_slot_agrees_with_cluster.duplicate(
            allocator,
            logger,
            duplicate_slot,
            root_slot,
            duplicate_slots_tracker,
            fork_choice,
            duplicate_state,
        );
    }
}

/// Finds the cluster confirmed hash
///
/// 1) If we have a frozen hash, check if it's been duplicate confirmed by cluster
///    in turbine or gossip
/// 2) Otherwise poll `epoch_slots_frozen_slots` to see if we have a hash
///
/// Note `epoch_slots_frozen_slots` is not populated from `EpochSlots` in gossip but actually
/// aggregated through hashes sent in response to requests from `ancestor_hashes_service`
fn getClusterConfirmedHashFromState(
    logger: sig.trace.Logger,
    slot: sig.core.Slot,
    duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
    epoch_slots_frozen_slots: *const EpochSlotsFrozenSlots,
    fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
    maybe_slot_frozen_hash: ?sig.core.Hash,
) ?ClusterConfirmedHash {
    const duplicate_confirmed_hash = duplicate_confirmed_slots.get(slot);
    if (getDuplicateConfirmedHash(
        logger,
        fork_choice,
        slot,
        duplicate_confirmed_hash,
        maybe_slot_frozen_hash,
    )) |hash| return .{
        .kind = .duplicate_confirmed,
        .hash = hash,
    };
    const hash = epoch_slots_frozen_slots.get(slot) orelse return null;
    return .{
        .kind = .epoch_slots_frozen,
        .hash = hash,
    };
}

fn getDuplicateConfirmedHashFromState(
    logger: sig.trace.Logger,
    slot: sig.core.Slot,
    duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
    fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
    maybe_slot_frozen_hash: ?sig.core.Hash,
) ?sig.core.Hash {
    const duplicate_confirmed_hash = duplicate_confirmed_slots.get(slot);
    return getDuplicateConfirmedHash(
        logger,
        fork_choice,
        slot,
        duplicate_confirmed_hash,
        maybe_slot_frozen_hash,
    );
}

/// Finds the duplicate confirmed hash for a slot.
///
/// 1) If `maybe_slot_frozen_hash != null and isDuplicateConfirmed(maybe_slot_frozen_hash.?)`, `return maybe_slot_frozen_hash.?`
/// 2) If `maybe_duplicate_confirmed_hash != null`, `return maybe_duplicate_confirmed_hash.?`
/// 3) Else return null
fn getDuplicateConfirmedHash(
    logger: sig.trace.Logger,
    fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
    slot: sig.core.Slot,
    maybe_duplicate_confirmed_hash: ?sig.core.Hash,
    maybe_slot_frozen_hash: ?sig.core.Hash,
) ?sig.core.Hash {
    const slot_frozen_hash =
        maybe_slot_frozen_hash orelse
        return maybe_duplicate_confirmed_hash;

    // If the slot hasn't been frozen yet, then we haven't duplicate
    // confirmed a local version this slot through replay yet.
    const is_local_replay_duplicate_confirmed =
        fork_choice.isDuplicateConfirmed(&.{
            .slot = slot,
            .hash = slot_frozen_hash,
        }) orelse false;

    if (!is_local_replay_duplicate_confirmed) {
        return maybe_duplicate_confirmed_hash;
    } else {
        // slot_frozen_hash is local, duplicate, and confirmed
    }

    if (maybe_duplicate_confirmed_hash) |duplicate_confirmed_hash| {
        if (!slot_frozen_hash.eql(duplicate_confirmed_hash)) {
            logger.err().logf(
                "For slot {}, the gossip duplicate confirmed hash {}, is not equal" ++
                    "to the confirmed hash we replayed: {}",
                .{ slot, duplicate_confirmed_hash, slot_frozen_hash },
            );
        }
    }

    return slot_frozen_hash;
}

/// Analogous to [check_slot_agrees_with_cluster](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/repair/cluster_slot_state_verifier.rs#L848)
/// NOTE: Where in agave the different modes of operation are represented as tagged union variants, here they're simply different functions inside this namespace.
const check_slot_agrees_with_cluster = struct {
    /// aka `BankFrozen` in agave.
    fn slotFrozen(
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        root: sig.core.Slot,
        blockstore: *sig.ledger.LedgerResultWriter,
        fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: *DuplicateSlotsToRepair,
        purge_repair_slot_counter: *PurgeRepairSlotCounters,
        slot_frozen_state: SlotFrozenState,
    ) !void {
        logger.info().logf(
            "check_slot_agrees_with_cluster() slot: {}, root: {}, slot_state_update: {}",
            .{ slot, root, slot_frozen_state },
        );

        if (slot <= root) {
            return;
        }

        const frozen_hash = slot_frozen_state.frozen_hash;
        const maybe_cluster_confirmed_hash = slot_frozen_state.cluster_confirmed_hash;
        const is_slot_duplicate = slot_frozen_state.is_slot_duplicate;

        // Handle cases where the slot is frozen, but not duplicate confirmed yet.
        var not_dupe_confirmed_frozen_hash: state_change.NotDupeConfirmedFrozenHash = .init;

        state_change.slotFrozen(
            slot,
            fork_choice,
            &not_dupe_confirmed_frozen_hash,
            frozen_hash,
        );

        if (maybe_cluster_confirmed_hash) |cluster_confirmed_hash| {
            switch (cluster_confirmed_hash.kind) {
                // If the cluster duplicate_confirmed some version of this slot, then
                // check if our version agrees with the cluster,
                .duplicate_confirmed => {
                    const duplicate_confirmed_hash = cluster_confirmed_hash.hash;
                    if (duplicate_confirmed_hash.eql(frozen_hash)) {
                        // If the versions match, then add the slot to the candidate
                        // set to account for the case where it was removed earlier
                        // by the `on_duplicate_slot()` handler
                        try state_change.duplicateConfirmedSlotMatchesCluster(
                            slot,
                            fork_choice,
                            duplicate_slots_to_repair,
                            blockstore,
                            purge_repair_slot_counter,
                            &not_dupe_confirmed_frozen_hash,
                            frozen_hash,
                        );
                    } else {
                        // The duplicate confirmed slot hash does not match our frozen hash.
                        // Modify fork choice rule to exclude our version from being voted
                        // on and also repair the correct version
                        logger.warn().logf(
                            "Cluster duplicate confirmed slot {} with hash {}, " ++
                                "but our version has hash {}",
                            .{ slot, duplicate_confirmed_hash, frozen_hash },
                        );
                        try state_change.markSlotDuplicate(slot, fork_choice, frozen_hash);
                        try state_change.repairDuplicateConfirmedVersion(
                            allocator,
                            slot,
                            duplicate_slots_to_repair,
                            duplicate_confirmed_hash,
                        );
                    }
                },

                // Lower priority than having seen an actual duplicate confirmed hash in the
                // match arm above.
                .epoch_slots_frozen => check: {
                    const epoch_slots_frozen_hash = cluster_confirmed_hash.hash;
                    if (epoch_slots_frozen_hash.eql(frozen_hash)) {
                        // Matches, nothing to do
                        break :check;
                    } else {
                        // The epoch slots hash does not match our frozen hash.
                        logger.warn().logf(
                            "EpochSlots sample returned slot {} with hash {}, " ++
                                "but our version has hash {}",
                            .{ slot, epoch_slots_frozen_hash, frozen_hash },
                        );
                        // If the slot is not already pruned notify fork choice to mark as invalid
                        try state_change.markSlotDuplicate(slot, fork_choice, frozen_hash);
                    }
                    try state_change.repairDuplicateConfirmedVersion(
                        allocator,
                        slot,
                        duplicate_slots_to_repair,
                        epoch_slots_frozen_hash,
                    );
                },
            }
        } else if (is_slot_duplicate) {
            // If `cluster_confirmed_hash` is Some above we should have already pushed a
            // `MarkSlotDuplicate` state change
            try state_change.markSlotDuplicate(slot, fork_choice, frozen_hash);
        }

        try not_dupe_confirmed_frozen_hash.finalize(slot, blockstore);
    }

    fn duplicateConfirmed(
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        root: sig.core.Slot,
        blockstore: *sig.ledger.LedgerResultWriter,
        fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: *DuplicateSlotsToRepair,
        ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
        purge_repair_slot_counter: *PurgeRepairSlotCounters,
        duplicate_confirmed_state: DuplicateConfirmedState,
    ) !void {
        logger.info().logf(
            "check_slot_agrees_with_cluster() slot: {}, root: {}, slot_state_update: {}",
            .{ slot, root, duplicate_confirmed_state },
        );

        if (slot <= root) {
            return;
        }

        const slot_status = duplicate_confirmed_state.slot_status;
        const duplicate_confirmed_hash = duplicate_confirmed_state.duplicate_confirmed_hash;

        // Avoid duplicate work from multiple of the same DuplicateConfirmed signal. This can
        // happen if we get duplicate confirmed from gossip and from local replay.
        if (slot_status.slotHash()) |hash| {
            if (fork_choice.isDuplicateConfirmed(&.{ .slot = slot, .hash = hash }) == true) {
                return;
            }
        }

        // datapoint_info!(
        //     "duplicate_confirmed_slot",
        //     ("slot", slot, i64),
        //     (
        //         "duplicate_confirmed_hash",
        //         duplicate_confirmed_state
        //             .duplicate_confirmed_hash
        //             .to_string(),
        //         String
        //     ),
        //     (
        //         "my_hash",
        //         bank_status
        //             .bank_hash()
        //             .unwrap_or_default()
        //             .to_string(),
        //         String
        //     ),
        // );

        // Handle cases where the slot is frozen, but not duplicate confirmed yet.
        var not_dupe_confirmed_frozen_hash: state_change.NotDupeConfirmedFrozenHash = .init;

        switch (slot_status) {
            // No action to be taken yet
            .unprocessed => {},

            .dead => {
                state_change.sendAncestorHashesReplayUpdate(
                    ancestor_hashes_replay_update_sender,
                    .{ .kind = .dead_duplicate_confirmed, .slot = slot },
                );

                // If the cluster duplicate confirmed some version of this slot, then
                // there's another version of our dead slot
                logger.warn().logf(
                    "Cluster duplicate confirmed slot {} with hash {}, but we marked slot dead",
                    .{ slot, duplicate_confirmed_hash },
                );
                try state_change.repairDuplicateConfirmedVersion(
                    allocator,
                    slot,
                    duplicate_slots_to_repair,
                    duplicate_confirmed_hash,
                );
            },

            .frozen => |frozen_hash| {
                if (duplicate_confirmed_hash.eql(frozen_hash)) {
                    // If the versions match, then add the slot to the candidate
                    // set to account for the case where it was removed earlier
                    // by the `on_duplicate_slot()` handler
                    try state_change.duplicateConfirmedSlotMatchesCluster(
                        slot,
                        fork_choice,
                        duplicate_slots_to_repair,
                        blockstore,
                        purge_repair_slot_counter,
                        &not_dupe_confirmed_frozen_hash,
                        frozen_hash,
                    );
                } else {
                    // The duplicate confirmed slot hash does not match our frozen hash.
                    // Modify fork choice rule to exclude our version from being voted
                    // on and also repair the correct version
                    logger.warn().logf(
                        "Cluster duplicate confirmed slot {} with hash {}," ++
                            " but our version has hash {}",
                        .{ slot, duplicate_confirmed_hash, frozen_hash },
                    );
                    try state_change.markSlotDuplicate(slot, fork_choice, frozen_hash);
                    try state_change.repairDuplicateConfirmedVersion(
                        allocator,
                        slot,
                        duplicate_slots_to_repair,
                        duplicate_confirmed_hash,
                    );
                }
            },
        }

        try not_dupe_confirmed_frozen_hash.finalize(slot, blockstore);
    }

    fn dead(
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        root: sig.core.Slot,
        duplicate_slots_to_repair: *DuplicateSlotsToRepair,
        ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
        dead_state: DeadState,
    ) !void {
        logger.info().logf(
            "check_slot_agrees_with_cluster() slot: {}, root: {}, slot_state_update: {}",
            .{ slot, root, dead_state },
        );

        if (slot <= root) {
            return;
        }

        if (dead_state.cluster_confirmed_hash) |cluster_confirmed_hash| {
            switch (cluster_confirmed_hash.kind) {
                .duplicate_confirmed => |duplicate_confirmed_hash| {
                    // If the cluster duplicate_confirmed some version of this slot, then
                    // check if our version agrees with the cluster,
                    state_change.sendAncestorHashesReplayUpdate(
                        ancestor_hashes_replay_update_sender,
                        .{ .kind = .dead_duplicate_confirmed, .slot = slot },
                    );

                    // If the cluster duplicate confirmed some version of this slot, then
                    // there's another version of our dead slot
                    logger.warn().logf(
                        "Cluster duplicate confirmed slot {} with hash {}, " ++
                            "but we marked slot dead",
                        .{ slot, duplicate_confirmed_hash },
                    );
                    try state_change.repairDuplicateConfirmedVersion(
                        allocator,
                        slot,
                        duplicate_slots_to_repair,
                        duplicate_confirmed_hash,
                    );
                },
                // Lower priority than having seen an actual duplicate confirmed hash in the
                // match arm above.
                .epoch_slots_frozen => |epoch_slots_frozen_hash| {
                    // Cluster sample found a hash for our dead slot, we must have the wrong version
                    logger.warn().logf(
                        "EpochSlots sample returned slot {} with hash {}, " ++
                            "but we marked slot dead",
                        .{ slot, epoch_slots_frozen_hash },
                    );
                    try state_change.repairDuplicateConfirmedVersion(
                        slot,
                        duplicate_slots_to_repair,
                        epoch_slots_frozen_hash,
                    );
                },
            }
        } else {
            state_change.sendAncestorHashesReplayUpdate(
                ancestor_hashes_replay_update_sender,
                .{ .kind = .dead, .slot = slot },
            );
        }
    }

    fn duplicate(
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        root: sig.core.Slot,
        duplicate_slots_tracker: *DuplicateSlot,
        fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
        duplicate_state: DuplicateState,
    ) !void {
        logger.info().logf(
            "check_slot_agrees_with_cluster() slot: {}, root: {}, slot_state_update: {}",
            .{ slot, root, duplicate_state },
        );

        if (slot <= root) {
            return;
        }

        // Needs to happen before the slot_frozen_hash == null check below to account for duplicate
        // signals arriving before the bank is constructed in replay.
        if (try duplicate_slots_tracker.fetchPut(allocator, slot, {})) |_| {
            // If this slot has already been processed before, return
            return;
        }

        // datapoint_info!(
        //     "duplicate_slot",
        //     ("slot", slot, i64),
        //     (
        //         "duplicate_confirmed_hash",
        //         duplicate_state
        //             .duplicate_confirmed_hash
        //             .unwrap_or_default()
        //             .to_string(),
        //         String
        //     ),
        //     (
        //         "my_hash",
        //         duplicate_state
        //             .bank_status
        //             .bank_hash()
        //             .unwrap_or_default()
        //             .to_string(),
        //         String
        //     ),
        // );

        const slot_status = duplicate_state.slot_status;
        const duplicate_confirmed_hash = duplicate_state.duplicate_confirmed_hash;

        switch (slot_status) {
            .dead, .frozen => {},
            // No action to be taken yet
            .unprocessed => return,
        }

        // If the cluster duplicate_confirmed some version of this slot
        // then either the `SlotStateUpdate::DuplicateConfirmed`, `SlotStateUpdate::BankFrozen`,
        // or `SlotStateUpdate::Dead` state transitions will take care of marking the fork as
        // duplicate if there's a mismatch with our local version.
        if (duplicate_confirmed_hash == null) {
            // If we have not yet seen any version of the slot duplicate confirmed, then mark
            // the slot as duplicate
            if (slot_status.slotHash()) |slot_hash| {
                try state_change.markSlotDuplicate(slot, fork_choice, slot_hash);
            }
        }
    }

    fn epochSlotsFrozen(
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        root: sig.core.Slot,
        fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: *DuplicateSlotsToRepair,
        epoch_slots_frozen_slots: *EpochSlotsFrozenSlots,
        epoch_slots_frozen_state: EpochSlotsFrozenState,
    ) !void {
        logger.info().logf(
            "check_slot_agrees_with_cluster() slot: {}, root: {}, slot_state_update: {}",
            .{ slot, root, epoch_slots_frozen_state },
        );

        if (slot <= root) {
            return;
        }

        const slot_status = epoch_slots_frozen_state.slot_status;
        const epoch_slots_frozen_hash = epoch_slots_frozen_state.epoch_slots_frozen_hash;
        const maybe_duplicate_confirmed_hash = epoch_slots_frozen_state.duplicate_confirmed_hash;
        const is_popular_pruned = epoch_slots_frozen_state.is_popular_pruned;

        if (try epoch_slots_frozen_slots.fetchPut(
            allocator,
            slot,
            epoch_slots_frozen_hash,
        )) |old_epoch_slots_frozen_hash_kv| {
            const old_epoch_slots_frozen_hash = old_epoch_slots_frozen_hash_kv.value;
            if (old_epoch_slots_frozen_hash.eql(epoch_slots_frozen_hash)) {
                // If EpochSlots has already told us this same hash was frozen, return
                return;
            }
        }

        switch (slot_status) {
            .unprocessed => {
                // If we have the slot pruned then it will never be replayed
                if (!is_popular_pruned) {
                    return;
                }
            },
            .dead, .frozen => {},
        }

        // If `slot` has already been duplicate confirmed, `epoch_slots_frozen` becomes redundant as
        // one of the following triggers would have already processed `slot`:
        //
        // 1) If the slot was replayed and then duplicate confirmed through turbine/gossip, the
        //    corresponding 'duplicate confirmed'.
        // 2) If the slot was first duplicate confirmed through gossip and then replayed, the
        //    corresponding 'slot frozen' or 'dead'.
        //
        // However if `slot` was first duplicate confirmed through gossip and then pruned before
        // we got a chance to replay, there was no trigger that would have processed `slot`.
        // The original `SlotStateUpdate::DuplicateConfirmed` is a no-op when the slot has not been
        // replayed yet, and unlike 2) there is no upcoming 'slot frozen' or 'dead', as `slot`
        // is pruned and will not be replayed.
        //
        // Thus if we have a duplicate confirmation, but `slot` is pruned, we continue
        // processing it as `epoch_slots_frozen`.
        if (!is_popular_pruned) {
            if (maybe_duplicate_confirmed_hash) |duplicate_confirmed_hash| {
                if (!epoch_slots_frozen_hash.eql(duplicate_confirmed_hash)) {
                    logger.warn().logf(
                        "EpochSlots sample returned slot {} with hash {}, " ++
                            "but we already saw duplicate confirmation on hash: {}",
                        .{ slot, epoch_slots_frozen_hash, duplicate_confirmed_hash },
                    );
                }
                return;
            }
        }

        switch (slot_status) {
            .frozen => |slot_frozen_hash| {
                if (slot_frozen_hash.eql(epoch_slots_frozen_hash)) {
                    // Matches, nothing to do
                    return;
                } else {
                    // The epoch slots hash does not match our frozen hash.
                    logger.warn().logf(
                        "EpochSlots sample returned slot {} with hash {}, " ++
                            "but our version has hash {}",
                        .{ slot, epoch_slots_frozen_hash, slot_frozen_hash },
                    );
                    if (!is_popular_pruned) {
                        // If the slot is not already pruned notify fork choice to mark as invalid
                        try state_change.markSlotDuplicate(slot, fork_choice, slot_frozen_hash);
                    }
                }
            },
            .dead => {
                // Cluster sample found a hash for our dead slot, we must have the wrong version
                logger.warn().logf(
                    "EpochSlots sample returned slot {} with hash {}, " ++
                        "but we marked slot dead",
                    .{ slot, epoch_slots_frozen_hash },
                );
            },
            .unprocessed => {
                // If the slot was not popular pruned, we would never have made it here, as the slot is
                // yet to be replayed
                std.debug.assert(is_popular_pruned);
                // The cluster sample found the troublesome slot which caused this fork to be pruned
                logger.warn().logf(
                    "EpochSlots sample returned slot {} with hash {}, " ++
                        "but we have pruned it due to incorrect ancestry",
                    .{ slot, epoch_slots_frozen_hash },
                );
            },
        }

        try state_change.repairDuplicateConfirmedVersion(
            allocator,
            slot,
            duplicate_slots_to_repair,
            epoch_slots_frozen_hash,
        );
    }

    fn popularPrunedFork(
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        root: sig.core.Slot,
        ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
    ) void {
        logger.info().logf(
            "check_slot_agrees_with_cluster() slot: {}, root: {}, slot_state_update: {s}",
            .{ slot, root, "popular_pruned_fork" },
        );

        if (slot <= root) {
            return;
        }

        logger.warn().logf(
            "{} is part of a pruned fork which has reached the DUPLICATE_THRESHOLD " ++
                "aggregating across descendants and slot versions. It is suspected " ++
                "to be duplicate or have an ancestor that is duplicate. " ++
                "Notifying ancestor_hashes_service",
            .{slot},
        );
        state_change.sendAncestorHashesReplayUpdate(
            ancestor_hashes_replay_update_sender,
            .{ .kind = .popular_pruned_fork, .slot = slot },
        );
    }
};

/// Analogous to [apply_state_change](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/repair/cluster_slot_state_verifier.rs#L793),
/// or more concretely, each function is analogous to a variant in the `ResultingStateChange` tagged union, a list of which is supplied to the function, representing
/// a list of these function calls.
const state_change = struct {
    const NotDupeConfirmedFrozenHash = struct {
        frozen_hash: ?sig.core.Hash,
        finalized: bool,

        const init: NotDupeConfirmedFrozenHash = .{ .frozen_hash = null, .finalized = false };

        fn update(
            self: *NotDupeConfirmedFrozenHash,
            frozen_hash: ?sig.core.Hash,
        ) void {
            self.frozen_hash = frozen_hash;
        }

        fn finalize(
            self: *NotDupeConfirmedFrozenHash,
            slot: sig.core.Slot,
            blockstore: *sig.ledger.LedgerResultWriter,
        ) !void {
            std.debug.assert(!self.finalized);
            self.finalized = true;
            if (self.frozen_hash) |frozen_hash| {
                try blockstore.insertBankHash(slot, frozen_hash, false);
            }
        }
    };

    /// aka `BankFrozen` in agave.
    fn slotFrozen(
        slot: u64,
        fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
        not_dupe_confirmed_frozen_hash: *NotDupeConfirmedFrozenHash,
        slot_frozen_hash: sig.core.Hash,
    ) void {
        const is_duplicate_confirmed =
            fork_choice.isDuplicateConfirmed(&.{ .slot = slot, .hash = slot_frozen_hash }) orelse
            std.debug.panic("frozen slot must exist in fork choice", .{});
        if (!is_duplicate_confirmed) {
            not_dupe_confirmed_frozen_hash.update(slot_frozen_hash);
        }
    }

    fn markSlotDuplicate(
        slot: u64,
        fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
        slot_frozen_hash: sig.core.Hash,
    ) !void {
        try fork_choice.markForkInvalidCandidate(&.{ .slot = slot, .hash = slot_frozen_hash });
    }

    fn repairDuplicateConfirmedVersion(
        allocator: std.mem.Allocator,
        slot: u64,
        duplicate_slots_to_repair: *DuplicateSlotsToRepair,
        duplicate_confirmed_hash: sig.core.Hash,
    ) !void {
        try duplicate_slots_to_repair.put(allocator, slot, duplicate_confirmed_hash);
    }

    fn duplicateConfirmedSlotMatchesCluster(
        slot: u64,
        fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: *DuplicateSlotsToRepair,
        blockstore: *sig.ledger.LedgerResultWriter,
        purge_repair_slot_counter: *PurgeRepairSlotCounters,
        not_dupe_confirmed_frozen_hash: *NotDupeConfirmedFrozenHash,
        slot_frozen_hash: sig.core.Hash,
    ) !void {
        not_dupe_confirmed_frozen_hash.update(null);
        // When we detect that our frozen slot matches the cluster version (note this
        // will catch both slot frozen first -> confirmation, or confirmation first ->
        // slot frozen), mark all the newly duplicate confirmed slots in blockstore
        const new_duplicate_confirmed_slot_hashes = try fork_choice.markForkValidCandidate(&.{
            .slot = slot,
            .hash = slot_frozen_hash,
        });
        defer new_duplicate_confirmed_slot_hashes.deinit();

        {
            var setter = try blockstore.setDuplicateConfirmedSlotsAndHashesIncremental();
            defer setter.deinit();
            for (new_duplicate_confirmed_slot_hashes.items) |confirmed| {
                try setter.addSlotAndHash(confirmed.slot, confirmed.hash);
            }
            try setter.commit();
        }

        _ = duplicate_slots_to_repair.swapRemove(slot);
        _ = purge_repair_slot_counter.orderedRemove(slot);
    }

    fn sendAncestorHashesReplayUpdate(
        ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
        ancestor_hashes_replay_update: AncestorHashesReplayUpdate,
    ) void {
        ancestor_hashes_replay_update_sender.send(ancestor_hashes_replay_update) catch {
            // TODO: agave just ignores this error, is that alright?
        };
    }
};

const Descendants = std.AutoArrayHashMapUnmanaged(
    sig.core.Slot,
    sig.utils.collections.SortedMapUnmanaged(sig.core.Slot, void),
);
fn descendantsDeinit(allocator: std.mem.Allocator, descendants: Descendants) void {
    for (descendants.values()) |*child_set| child_set.deinit(allocator);
    var copy = descendants;
    copy.deinit(allocator);
}

const TestData = struct {
    slot_tracker: sig.replay.trackers.SlotTracker,
    heaviest_subtree_fork_choice: sig.consensus.HeaviestSubtreeForkChoice,
    progress: ProgressMap,
    descendants: Descendants,

    fn deinit(self: TestData, allocator: std.mem.Allocator) void {
        self.slot_tracker.deinit(allocator);

        var fork_choice = self.heaviest_subtree_fork_choice;
        fork_choice.deinit();

        descendantsDeinit(allocator, self.descendants);

        self.progress.deinit(allocator);
    }

    fn init(
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger,
        random: std.Random,
    ) !TestData {
        const SlotInfo = struct {
            parent_slot: ?sig.core.Slot,
            slot: sig.core.Slot,
            hash: sig.core.Hash,
            fork_progress_init: sig.consensus.progress_map.ForkProgress.InitParams,

            fn initRandom(
                _random: std.Random,
                parent_slot: ?sig.core.Slot,
                slot: sig.core.Slot,
                fork_progress_init: sig.consensus.progress_map.ForkProgress.InitParams,
            ) @This() {
                return .{
                    .parent_slot = parent_slot,
                    .slot = slot,
                    .hash = .initRandom(_random),
                    .fork_progress_init = fork_progress_init,
                };
            }
        };

        const slot_infos = [_]SlotInfo{
            .initRandom(random, null, 0, .{
                .now = .now(),
                .last_entry = try .parseBase58String(
                    "5NjW2CAV6MBQYxpL4oK2CESrpdj6tkcvxP3iigAgrHyR",
                ),
                .prev_leader_slot = null,
                .validator_stake_info = .{
                    .validator_vote_pubkey = try .parseBase58String(
                        "11111111111111111111111111111111",
                    ),
                    .stake = 0,
                    .total_epoch_stake = 10_000,
                },
                .num_blocks_on_fork = 0,
                .num_dropped_blocks_on_fork = 0,
            }),
            .initRandom(random, 0, 1, .{
                .now = .now(),
                .last_entry = try .parseBase58String("11111111111111111111111111111111"),
                .prev_leader_slot = null,
                .validator_stake_info = null,
                .num_blocks_on_fork = 0,
                .num_dropped_blocks_on_fork = 0,
            }),
            .initRandom(random, 1, 2, .{
                .now = .now(),
                .last_entry = try .parseBase58String("11111111111111111111111111111111"),
                .prev_leader_slot = null,
                .validator_stake_info = null,
                .num_blocks_on_fork = 0,
                .num_dropped_blocks_on_fork = 0,
            }),
            .initRandom(random, 2, 3, .{
                .now = .now(),
                .last_entry = try .parseBase58String("11111111111111111111111111111111"),
                .prev_leader_slot = null,
                .validator_stake_info = null,
                .num_blocks_on_fork = 0,
                .num_dropped_blocks_on_fork = 0,
            }),
        };

        var slot_tracker: sig.replay.trackers.SlotTracker = .init(0);
        errdefer slot_tracker.deinit(allocator);

        var fork_choice: sig.consensus.HeaviestSubtreeForkChoice = try .init(allocator, logger, .{
            .slot = 0,
            .hash = slot_infos[0].hash,
        });
        errdefer fork_choice.deinit();

        var progress: ProgressMap = .INIT;
        errdefer progress.deinit(allocator);

        for (slot_infos) |slot_info| {
            try progress.map.ensureUnusedCapacity(allocator, 1);
            progress.map.putAssumeCapacity(
                slot_info.slot,
                try .init(allocator, slot_info.fork_progress_init),
            );

            try fork_choice.addNewLeafSlot(
                .{ .slot = slot_info.slot, .hash = slot_info.hash },
                if (slot_info.parent_slot) |parent_slot| .{
                    .slot = parent_slot,
                    .hash = slot_infos[parent_slot].hash,
                } else null,
            );

            const parent_slot = slot_info.parent_slot orelse (slot_info.slot -| 1);
            try slot_tracker.put(
                allocator,
                slot_info.slot,
                .{
                    .parent_slot = parent_slot,
                    .parent_hash = slot_infos[parent_slot].hash,
                    .block_height = 1,
                    .collector_id = .initRandom(random),
                    .max_tick_height = 1,
                    .fee_rate_governor = .initRandom(random),
                    .epoch_reward_status = .inactive,
                },
                .{
                    .blockhash_queue = .init(try .initRandom(random, allocator, 0)),
                    .hash = .init(slot_info.hash),
                    .capitalization = .init(random.int(u64)),
                    .transaction_count = .init(random.int(u64)),
                    .signature_count = .init(1),
                    .tick_height = .init(random.int(u64)),
                    .collected_rent = .init(random.int(u64)),
                    .accounts_lt_hash = .init(.{ .data = @splat(random.int(u16)) }),
                },
            );
        }

        var descendants: Descendants = .empty;
        errdefer descendants.deinit(allocator);
        errdefer for (descendants.values()) |*child_set| child_set.deinit(allocator);
        try descendants.ensureUnusedCapacity(allocator, 4);
        descendants.putAssumeCapacity(0, try .init(allocator, &.{ 1, 2, 3 }, &.{}));
        descendants.putAssumeCapacity(1, try .init(allocator, &.{ 3, 2 }, &.{}));
        descendants.putAssumeCapacity(2, try .init(allocator, &.{3}, &.{}));
        descendants.putAssumeCapacity(3, .empty);
        for (descendants.values()) |*slot_set| slot_set.sort();

        return .{
            .slot_tracker = slot_tracker,
            .heaviest_subtree_fork_choice = fork_choice,
            .descendants = descendants,
            .progress = progress,
        };
    }
};

const TestLedgerRwState = struct {
    registry: sig.prometheus.Registry(.{}),
    lowest_cleanup_slot: sig.sync.RwMux(Slot),
    max_root: std.atomic.Value(Slot),

    fn init() TestLedgerRwState {
        return .{
            .registry = .init(std.testing.allocator),
            .lowest_cleanup_slot = .init(0),
            .max_root = .init(0),
        };
    }

    fn deinit(self: *TestLedgerRwState) void {
        self.registry.deinit();
    }
};

fn testLedgerRw(
    comptime src_loc: std.builtin.SourceLocation,
    logger: sig.trace.Logger,
    state: *TestLedgerRwState,
) !struct {
    sig.ledger.BlockstoreDB,
    sig.ledger.BlockstoreReader,
    sig.ledger.LedgerResultWriter,
} {
    var ledger_db = try sig.ledger.tests.TestDB.init(src_loc);
    errdefer ledger_db.deinit();

    const reader: sig.ledger.BlockstoreReader = try .init(
        std.testing.allocator,
        logger,
        ledger_db,
        &state.registry,
        &state.lowest_cleanup_slot,
        &state.max_root,
    );
    const writer: sig.ledger.LedgerResultWriter = try .init(
        std.testing.allocator,
        logger,
        ledger_db,
        &state.registry,
        &state.lowest_cleanup_slot,
        &state.max_root,
    );

    return .{
        ledger_db,
        reader,
        writer,
    };
}

test "apply state changes" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(7353);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const descendants = test_data.descendants;

    // MarkSlotDuplicate should mark progress map and remove
    // the slot from fork choice
    const duplicate_slot = slot_tracker.root + 1;
    const duplicate_slot_hash = slot_tracker.get(duplicate_slot).?.state.hash.readCopy().?;
    try state_change.markSlotDuplicate(
        duplicate_slot,
        heaviest_subtree_fork_choice,
        duplicate_slot_hash,
    );
    try std.testing.expect(!heaviest_subtree_fork_choice.isCandidate(&.{
        .slot = duplicate_slot,
        .hash = duplicate_slot_hash,
    }).?);
    for ([_][]const sig.core.Slot{
        descendants.getPtr(duplicate_slot).?.keys(),
        &.{duplicate_slot},
    }) |child_slot_set| {
        for (child_slot_set) |child_slot| {
            try std.testing.expectEqual(
                duplicate_slot,
                heaviest_subtree_fork_choice.latestInvalidAncestor(&.{
                    .slot = child_slot,
                    .hash = slot_tracker.slots.get(child_slot).?.state.hash.readCopy().?,
                }).?,
            );
        }
    }

    var duplicate_slots_to_repair: DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    try std.testing.expect(duplicate_slots_to_repair.count() == 0);

    // Simulate detecting another hash that is the correct version,
    // RepairDuplicateConfirmedVersion should add the slot to repair
    // to `duplicate_slots_to_repair`
    try std.testing.expect(duplicate_slots_to_repair.count() == 0);
    const correct_hash: sig.core.Hash = .initRandom(random);
    try state_change.repairDuplicateConfirmedVersion(
        allocator,
        duplicate_slot,
        &duplicate_slots_to_repair,
        correct_hash,
    );
    try std.testing.expectEqual(1, duplicate_slots_to_repair.count());
    try std.testing.expectEqual(
        correct_hash,
        duplicate_slots_to_repair.get(duplicate_slot),
    );
}

test "apply state changes slot frozen" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(7353);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;

    var ledger_state: TestLedgerRwState = .init();
    defer ledger_state.deinit();

    var ledger, var ledger_reader, var ledger_writer =
        try testLedgerRw(@src(), .noop, &ledger_state);
    defer ledger.deinit();

    const duplicate_slot = slot_tracker.root + 1;
    const duplicate_slot_hash = slot_tracker.get(duplicate_slot).?.state.hash.readCopy().?;

    // Simulate ReplayStage freezing a Slot with the given hash.
    // 'slot frozen' should mark it down in Blockstore.
    try std.testing.expectEqual(null, ledger_reader.getBankHash(duplicate_slot));

    {
        // Handle cases where the slot is frozen, but not duplicate confirmed yet.
        var not_duplicate_confirmed_frozen_hash: state_change.NotDupeConfirmedFrozenHash = .init;
        state_change.slotFrozen(
            duplicate_slot,
            heaviest_subtree_fork_choice,
            &not_duplicate_confirmed_frozen_hash,
            duplicate_slot_hash,
        );
        try not_duplicate_confirmed_frozen_hash.finalize(duplicate_slot, &ledger_writer);
    }

    try std.testing.expectEqual(duplicate_slot_hash, ledger_reader.getBankHash(duplicate_slot));
    try std.testing.expectEqual(false, ledger_reader.isDuplicateConfirmed(duplicate_slot));

    // If we freeze another version of the slot, it should overwrite the first
    // version in blockstore.
    const new_slot_hash: sig.core.Hash = .initRandom(random);
    const root_slot_hash: sig.core.hash.SlotAndHash = rsh: {
        const root_slot_info = slot_tracker.get(slot_tracker.root).?;
        break :rsh .{
            .slot = slot_tracker.root,
            .hash = root_slot_info.state.hash.readCopy().?,
        };
    };
    try heaviest_subtree_fork_choice.addNewLeafSlot(
        .{
            .slot = duplicate_slot,
            .hash = new_slot_hash,
        },
        root_slot_hash,
    );
    {
        // Handle cases where the slot is frozen, but not duplicate confirmed yet.
        var not_duplicate_confirmed_frozen_hash: state_change.NotDupeConfirmedFrozenHash = .init;
        state_change.slotFrozen(
            duplicate_slot,
            heaviest_subtree_fork_choice,
            &not_duplicate_confirmed_frozen_hash,
            new_slot_hash,
        );
        try not_duplicate_confirmed_frozen_hash.finalize(duplicate_slot, &ledger_writer);
    }
    try std.testing.expectEqual(new_slot_hash, ledger_reader.getBankHash(duplicate_slot));
    try std.testing.expectEqual(false, ledger_reader.isDuplicateConfirmed(duplicate_slot));
}

test "apply state changes duplicate confirmed matches frozen" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(7353);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const descendants = &test_data.descendants;

    var ledger_state: TestLedgerRwState = .init();
    defer ledger_state.deinit();

    var ledger, var ledger_reader, var ledger_writer =
        try testLedgerRw(@src(), .noop, &ledger_state);
    defer ledger.deinit();

    const duplicate_slot = slot_tracker.root + 1;
    const our_duplicate_slot_hash = slot_tracker.get(duplicate_slot).?.state.hash.readCopy().?;

    var duplicate_slots_to_repair: DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var purge_repair_slot_counter: PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    // Setup and check the state that is about to change.
    try duplicate_slots_to_repair.put(allocator, duplicate_slot, .initRandom(random));
    try purge_repair_slot_counter.put(allocator, duplicate_slot, 1);
    try std.testing.expectEqual(null, ledger_reader.getBankHash(duplicate_slot));
    try std.testing.expectEqual(false, ledger_reader.isDuplicateConfirmed(duplicate_slot));

    // DuplicateConfirmedSlotMatchesCluster should:
    // 1) Re-enable fork choice
    // 2) Clear any pending repairs from `duplicate_slots_to_repair` since we have the
    //    right version now
    // 3) Clear the slot from `purge_repair_slot_counter`
    // 3) Set the status to duplicate confirmed in Blockstore
    {
        // Handle cases where the slot is frozen, but not duplicate confirmed yet.
        var not_duplicate_confirmed_frozen_hash: state_change.NotDupeConfirmedFrozenHash = .init;
        try state_change.duplicateConfirmedSlotMatchesCluster(
            duplicate_slot,
            heaviest_subtree_fork_choice,
            &duplicate_slots_to_repair,
            &ledger_writer,
            &purge_repair_slot_counter,
            &not_duplicate_confirmed_frozen_hash,
            our_duplicate_slot_hash,
        );

        try not_duplicate_confirmed_frozen_hash.finalize(duplicate_slot, &ledger_writer);
    }

    for ([_][]const sig.core.Slot{
        descendants.getPtr(duplicate_slot).?.keys(),
        &.{duplicate_slot},
    }) |child_slot_set| {
        for (child_slot_set) |child_slot| {
            try std.testing.expectEqual(
                null,
                heaviest_subtree_fork_choice.latestInvalidAncestor(&.{
                    .slot = child_slot,
                    .hash = slot_tracker.slots.get(child_slot).?.state.hash.readCopy().?,
                }),
            );
        }
    }
    try std.testing.expectEqual(true, heaviest_subtree_fork_choice.isCandidate(&.{
        .slot = duplicate_slot,
        .hash = our_duplicate_slot_hash,
    }));
    try std.testing.expectEqual(0, duplicate_slots_to_repair.count());
    try std.testing.expectEqual(0, purge_repair_slot_counter.count());
    try std.testing.expectEqual(our_duplicate_slot_hash, ledger_reader.getBankHash(duplicate_slot));
    try std.testing.expectEqual(true, ledger_reader.isDuplicateConfirmed(duplicate_slot));
}

test "apply state changes slot frozen and duplicate confirmed matches frozen" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(7353);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const descendants = &test_data.descendants;

    var ledger_state: TestLedgerRwState = .init();
    defer ledger_state.deinit();

    var ledger, var ledger_reader, var ledger_writer =
        try testLedgerRw(@src(), .noop, &ledger_state);
    defer ledger.deinit();

    var duplicate_slots_to_repair: DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var purge_repair_slot_counter: PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    const duplicate_slot = slot_tracker.root + 1;
    const our_duplicate_slot_hash = slot_tracker.get(duplicate_slot).?.state.hash.readCopy().?;

    // Setup and check the state that is about to change.
    try duplicate_slots_to_repair.put(allocator, duplicate_slot, .initRandom(random));
    try purge_repair_slot_counter.put(allocator, duplicate_slot, 1);
    try std.testing.expectEqual(null, ledger_reader.getBankHash(duplicate_slot));
    try std.testing.expectEqual(false, ledger_reader.isDuplicateConfirmed(duplicate_slot));

    // DuplicateConfirmedSlotMatchesCluster should:
    // 1) Re-enable fork choice
    // 2) Clear any pending repairs from `duplicate_slots_to_repair` since we have the
    //    right version now
    // 3) Clear the slot from `purge_repair_slot_counter`
    // 3) Set the status to duplicate confirmed in Blockstore
    {
        // Handle cases where the slot is frozen, but not duplicate confirmed yet.
        var not_duplicate_confirmed_frozen_hash: state_change.NotDupeConfirmedFrozenHash = .init;

        try state_change.duplicateConfirmedSlotMatchesCluster(
            duplicate_slot,
            heaviest_subtree_fork_choice,
            &duplicate_slots_to_repair,
            &ledger_writer,
            &purge_repair_slot_counter,
            &not_duplicate_confirmed_frozen_hash,
            our_duplicate_slot_hash,
        );

        state_change.slotFrozen(
            duplicate_slot,
            heaviest_subtree_fork_choice,
            &not_duplicate_confirmed_frozen_hash,
            our_duplicate_slot_hash,
        );

        try not_duplicate_confirmed_frozen_hash.finalize(duplicate_slot, &ledger_writer);
    }

    for ([_][]const sig.core.Slot{
        descendants.getPtr(duplicate_slot).?.keys(),
        &.{duplicate_slot},
    }) |child_slot_set| {
        for (child_slot_set) |child_slot| {
            try std.testing.expectEqual(
                null,
                heaviest_subtree_fork_choice.latestInvalidAncestor(&.{
                    .slot = child_slot,
                    .hash = slot_tracker.get(child_slot).?.state.hash.readCopy().?,
                }),
            );
        }
    }

    try std.testing.expectEqual(true, heaviest_subtree_fork_choice.isCandidate(&.{
        .slot = duplicate_slot,
        .hash = our_duplicate_slot_hash,
    }));
    try std.testing.expectEqual(0, duplicate_slots_to_repair.count());
    try std.testing.expectEqual(0, purge_repair_slot_counter.count());
    try std.testing.expectEqual(our_duplicate_slot_hash, ledger_reader.getBankHash(duplicate_slot));
    try std.testing.expectEqual(true, ledger_reader.isDuplicateConfirmed(duplicate_slot));
}

fn testStateDuplicateThenSlotFrozen(initial_slot_hash: ?sig.core.Hash) !void {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(7353);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger_state: TestLedgerRwState = .init();
    defer ledger_state.deinit();

    var ledger, _, var ledger_writer =
        try testLedgerRw(@src(), .noop, &ledger_state);
    defer ledger.deinit();

    // Setup a duplicate slot state transition with the initial slot state of the duplicate slot
    // determined by `initial_slot_hash`, which can be:
    // 1) A default hash (unfrozen slot),
    // 2) None (a slot that hasn't even started replay yet).
    const root: Slot = 0;

    var duplicate_slots_tracker: DuplicateSlot = .empty;
    defer duplicate_slots_tracker.deinit(allocator);

    const duplicate_confirmed_slots: DuplicateConfirmedSlots = .empty;

    var epoch_slots_frozen_slots: EpochSlotsFrozenSlots = .empty;
    var duplicate_slots_to_repair: DuplicateSlotsToRepair = .empty;
    var purge_repair_slot_counter: PurgeRepairSlotCounters = .empty;

    const duplicate_slot: Slot = 2;
    const duplicate_state: DuplicateState = .fromState(
        .noop,
        duplicate_slot,
        &duplicate_confirmed_slots,
        heaviest_subtree_fork_choice,
        if (progress.isDead(duplicate_slot) orelse false) .dead else .fromHash(initial_slot_hash),
    );
    try check_slot_agrees_with_cluster.duplicate(
        allocator,
        .noop,
        duplicate_slot,
        root,
        &duplicate_slots_tracker,
        heaviest_subtree_fork_choice,
        duplicate_state,
    );
    try std.testing.expect(duplicate_slots_tracker.contains(duplicate_slot));
    // Nothing should be applied yet to fork choice, since slot was not yet frozen
    for (2..3 + 1) |slot| {
        const slot_hash = slot_tracker.get(slot).?.state.hash.readCopy().?;
        try std.testing.expectEqual(null, heaviest_subtree_fork_choice.latestInvalidAncestor(&.{
            .slot = slot,
            .hash = slot_hash,
        }));
    }

    // Now freeze the slot
    const frozen_duplicate_slot_hash = slot_tracker.get(duplicate_slot).?.state.hash.readCopy().?;
    const slot_frozen_state: SlotFrozenState = .fromState(
        .noop,
        duplicate_slot,
        frozen_duplicate_slot_hash,
        &duplicate_slots_tracker,
        &duplicate_confirmed_slots,
        heaviest_subtree_fork_choice,
        &epoch_slots_frozen_slots,
    );
    try check_slot_agrees_with_cluster.slotFrozen(
        allocator,
        .noop,
        duplicate_slot,
        root,
        &ledger_writer,
        heaviest_subtree_fork_choice,
        &duplicate_slots_to_repair,
        &purge_repair_slot_counter,
        slot_frozen_state,
    );

    // Progress map should have the correct updates, fork choice should mark duplicate
    // as unvotable
    try std.testing.expectEqual(true, heaviest_subtree_fork_choice.isUnconfirmedDuplicate(&.{
        .slot = duplicate_slot,
        .hash = frozen_duplicate_slot_hash,
    }));

    // The ancestor of the duplicate slot should be the best slot now
    const duplicate_ancestor, const duplicate_parent_hash = blk: {
        const slot_consts = slot_tracker.get(duplicate_slot).?.constants;
        break :blk .{ slot_consts.parent_slot, slot_consts.parent_hash };
    };
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = duplicate_ancestor, .hash = duplicate_parent_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );
}

test "state unfrozen slot duplicate then slot frozen" {
    try testStateDuplicateThenSlotFrozen(.ZEROES);
}

test "state unreplayed slot duplicate then slot frozen" {
    try testStateDuplicateThenSlotFrozen(null);
}

test "state ancestor confirmed descendant duplicate" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(7353);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger_state: TestLedgerRwState = .init();
    defer ledger_state.deinit();

    var ledger, _, var ledger_writer =
        try testLedgerRw(@src(), .noop, &ledger_state);
    defer ledger.deinit();

    const slot3_hash = slot_tracker.get(3).?.state.hash.readCopy().?;
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );
    const root = 0;

    var duplicate_slots_tracker: DuplicateSlot = .empty;
    defer duplicate_slots_tracker.deinit(allocator);

    var purge_repair_slot_counter: PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    var duplicate_confirmed_slots: DuplicateConfirmedSlots = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    // Mark slot 2 as duplicate confirmed
    const slot2_hash = slot_tracker.get(2).?.state.hash.readCopy().?;
    try duplicate_confirmed_slots.put(allocator, 2, slot2_hash);
    const duplicate_confirmed_state: DuplicateConfirmedState = .{
        .duplicate_confirmed_hash = slot2_hash,
        .slot_status = if (progress.isDead(2) orelse false) .dead else .fromHash(slot2_hash),
    };
    var ancestor_hashes_replay_update_channel: sig.sync.Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_update_channel.deinit();
    {
        var duplicate_slots_to_repair: DuplicateSlotsToRepair = .empty;
        defer duplicate_slots_to_repair.deinit(allocator);
        try check_slot_agrees_with_cluster.duplicateConfirmed(
            allocator,
            .noop,
            2,
            root,
            &ledger_writer,
            heaviest_subtree_fork_choice,
            &duplicate_slots_to_repair,
            &ancestor_hashes_replay_update_channel,
            &purge_repair_slot_counter,
            duplicate_confirmed_state,
        );
    }
    try std.testing.expectEqual(
        true,
        heaviest_subtree_fork_choice.isDuplicateConfirmed(&.{
            .slot = 2,
            .hash = slot2_hash,
        }),
    );
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );
    for (0..2 + 1) |slot| {
        const slot_hash = slot_tracker.get(slot).?.state.hash.readCopy().?;
        try std.testing.expectEqual(
            true,
            heaviest_subtree_fork_choice.isDuplicateConfirmed(&.{
                .slot = slot,
                .hash = slot_hash,
            }),
        );
        try std.testing.expectEqual(
            null,
            heaviest_subtree_fork_choice.latestInvalidAncestor(&.{
                .slot = slot,
                .hash = slot_hash,
            }),
        );
    }

    // Mark 3 as duplicate, should not remove the duplicate confirmed slot 2 from fork choice
    const duplicate_state = DuplicateState.fromState(
        .noop,
        3,
        &duplicate_confirmed_slots,
        heaviest_subtree_fork_choice,
        if (progress.isDead(3) orelse false) .dead else .fromHash(slot3_hash),
    );
    try check_slot_agrees_with_cluster.duplicate(
        allocator,
        .noop,
        3,
        root,
        &duplicate_slots_tracker,
        heaviest_subtree_fork_choice,
        duplicate_state,
    );
    try std.testing.expect(duplicate_slots_tracker.contains(3));
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 2, .hash = slot2_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );
    for (0..3 + 1) |slot| {
        const slot_hash = slot_tracker.get(slot).?.state.hash.readCopy().?;
        if (slot <= 2) {
            try std.testing.expectEqual(
                true,
                heaviest_subtree_fork_choice.isDuplicateConfirmed(&.{
                    .slot = slot,
                    .hash = slot_hash,
                }),
            );
            try std.testing.expectEqual(
                null,
                heaviest_subtree_fork_choice.latestInvalidAncestor(&.{
                    .slot = slot,
                    .hash = slot_hash,
                }),
            );
        } else {
            try std.testing.expectEqual(
                false,
                heaviest_subtree_fork_choice.isDuplicateConfirmed(&.{
                    .slot = slot,
                    .hash = slot_hash,
                }),
            );
            try std.testing.expectEqual(
                3,
                heaviest_subtree_fork_choice.latestInvalidAncestor(&.{
                    .slot = slot,
                    .hash = slot_hash,
                }),
            );
        }
    }
}

test "state ancestor duplicate descendant confirmed" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(7353);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger_state: TestLedgerRwState = .init();
    defer ledger_state.deinit();

    var ledger, _, var ledger_writer =
        try testLedgerRw(@src(), .noop, &ledger_state);
    defer ledger.deinit();

    const slot3_hash = slot_tracker.get(3).?.state.hash.readCopy().?;
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );
    const root = 0;

    var duplicate_slots_tracker: DuplicateSlot = .empty;
    defer duplicate_slots_tracker.deinit(allocator);

    var duplicate_confirmed_slots: DuplicateConfirmedSlots = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var purge_repair_slot_counter: PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    // Mark 2 as duplicate
    const slot2_hash = slot_tracker.get(2).?.state.hash.readCopy().?;
    const duplicate_state: DuplicateState = .fromState(
        .noop,
        2,
        &duplicate_confirmed_slots,
        heaviest_subtree_fork_choice,
        if (progress.isDead(2) orelse false) .dead else .fromHash(slot2_hash),
    );
    var ancestor_hashes_replay_update_sender: sig.sync.Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_update_sender.deinit();
    try check_slot_agrees_with_cluster.duplicate(
        allocator,
        .noop,
        2,
        root,
        &duplicate_slots_tracker,
        heaviest_subtree_fork_choice,
        duplicate_state,
    );
    try std.testing.expect(duplicate_slots_tracker.contains(2));
    for (2..3 + 1) |slot| {
        const slot_hash = slot_tracker.get(slot).?.state.hash.readCopy().?;
        try std.testing.expectEqual(
            2,
            heaviest_subtree_fork_choice.latestInvalidAncestor(&.{
                .slot = slot,
                .hash = slot_hash,
            }),
        );
    }

    const slot1_hash = slot_tracker.get(1).?.state.hash.readCopy().?;
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 1, .hash = slot1_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );

    // Mark slot 3 as duplicate confirmed, should mark slot 2 as duplicate confirmed as well
    try duplicate_confirmed_slots.put(allocator, 3, slot3_hash);
    const duplicate_confirmed_state: DuplicateConfirmedState = .{
        .duplicate_confirmed_hash = slot3_hash,
        .slot_status = if (progress.isDead(3) orelse false) .dead else .fromHash(slot3_hash),
    };
    {
        var duplicate_slots_to_repair: DuplicateSlotsToRepair = .empty;
        defer duplicate_slots_to_repair.deinit(allocator);
        try check_slot_agrees_with_cluster.duplicateConfirmed(
            allocator,
            .noop,
            3,
            root,
            &ledger_writer,
            heaviest_subtree_fork_choice,
            &duplicate_slots_to_repair,
            &ancestor_hashes_replay_update_sender,
            &purge_repair_slot_counter,
            duplicate_confirmed_state,
        );
    }
    for (0..3 + 1) |slot| {
        const slot_hash = slot_tracker.get(slot).?.state.hash.readCopy().?;
        try std.testing.expectEqual(
            true,
            heaviest_subtree_fork_choice.isDuplicateConfirmed(&.{
                .slot = slot,
                .hash = slot_hash,
            }),
        );
        try std.testing.expectEqual(
            null,
            heaviest_subtree_fork_choice.latestInvalidAncestor(&.{
                .slot = slot,
                .hash = slot_hash,
            }),
        );
    }
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );
}

fn verifyAllSlotsDuplicateConfirmed(
    slot_tracker: *sig.replay.trackers.SlotTracker,
    heaviest_subtree_fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
    upper_bound: Slot,
    expected_is_duplicate_confirmed: bool,
) !void {
    for (0..upper_bound) |slot| {
        const slot_hash = slot_tracker.get(slot).?.state.hash.readCopy().?;
        const expected_is_duplicate_confirmed_or_slot0 =
            expected_is_duplicate_confirmed or
            // root is always duplicate confirmed
            slot == 0;
        try std.testing.expectEqual(
            expected_is_duplicate_confirmed_or_slot0,
            heaviest_subtree_fork_choice.isDuplicateConfirmed(&.{
                .slot = slot,
                .hash = slot_hash,
            }),
        );
        try std.testing.expectEqual(
            null,
            heaviest_subtree_fork_choice.latestInvalidAncestor(&.{
                .slot = slot,
                .hash = slot_hash,
            }),
        );
    }
}

test "state descendant confirmed ancestor duplicate" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(7353);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = &test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger_state: TestLedgerRwState = .init();
    defer ledger_state.deinit();

    var ledger, _, var ledger_writer =
        try testLedgerRw(@src(), .noop, &ledger_state);
    defer ledger.deinit();

    const slot3_hash = slot_tracker.get(3).?.state.hash.readCopy().?;
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );

    const root: Slot = 0;

    var duplicate_slots_tracker: DuplicateSlot = .empty;
    defer duplicate_slots_tracker.deinit(allocator);

    var duplicate_confirmed_slots: DuplicateConfirmedSlots = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var epoch_slots_frozen_slots: EpochSlotsFrozenSlots = .empty;
    defer epoch_slots_frozen_slots.deinit(allocator);

    var duplicate_slots_to_repair: DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var purge_repair_slot_counter: PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    // Mark 3 as duplicate confirmed
    try duplicate_confirmed_slots.put(allocator, 3, slot3_hash);
    const duplicate_confirmed_state: DuplicateConfirmedState = .{
        .duplicate_confirmed_hash = slot3_hash,
        .slot_status = if (progress.isDead(3) orelse false) .dead else .fromHash(slot3_hash),
    };
    var ancestor_hashes_replay_update_sender: sig.sync.Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_update_sender.deinit();
    try check_slot_agrees_with_cluster.duplicateConfirmed(
        allocator,
        .noop,
        3,
        root,
        &ledger_writer,
        heaviest_subtree_fork_choice,
        &duplicate_slots_to_repair,
        &ancestor_hashes_replay_update_sender,
        &purge_repair_slot_counter,
        duplicate_confirmed_state,
    );
    try verifyAllSlotsDuplicateConfirmed(slot_tracker, heaviest_subtree_fork_choice, 3, true);
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );

    // Mark ancestor 1 as duplicate, fork choice should be unaffected since
    // slot 1 was duplicate confirmed by the confirmation on its
    // descendant, 3.
    const slot1_hash = slot_tracker.get(1).?.state.hash.readCopy().?;
    const duplicate_state: DuplicateState = .fromState(
        .noop,
        1,
        &duplicate_confirmed_slots,
        heaviest_subtree_fork_choice,
        if (progress.isDead(1) orelse false) .dead else .fromHash(slot1_hash),
    );
    try check_slot_agrees_with_cluster.duplicate(
        allocator,
        .noop,
        1,
        root,
        &duplicate_slots_tracker,
        heaviest_subtree_fork_choice,
        duplicate_state,
    );
    try std.testing.expect(duplicate_slots_tracker.contains(1));
    try verifyAllSlotsDuplicateConfirmed(slot_tracker, heaviest_subtree_fork_choice, 3, true);
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );
}

test "duplicate confirmed and epoch slots frozen" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(7353);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = &test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger_state: TestLedgerRwState = .init();
    defer ledger_state.deinit();

    var ledger, _, var ledger_writer =
        try testLedgerRw(@src(), .noop, &ledger_state);
    defer ledger.deinit();

    const slot3_hash = slot_tracker.get(3).?.state.hash.readCopy().?;
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );

    const root: Slot = 0;

    var duplicate_slots_tracker: DuplicateSlot = .empty;
    defer duplicate_slots_tracker.deinit(allocator);

    var duplicate_confirmed_slots: DuplicateConfirmedSlots = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var epoch_slots_frozen_slots: EpochSlotsFrozenSlots = .empty;
    defer epoch_slots_frozen_slots.deinit(allocator);

    var duplicate_slots_to_repair: DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var purge_repair_slot_counter: PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    // Mark 3 as only epoch slots frozen, matching our `slot3_hash`, should not duplicate
    // confirm the slot
    var expected_is_duplicate_confirmed = false;
    const epoch_slots_frozen_state: EpochSlotsFrozenState = .fromState(
        .noop,
        3,
        slot3_hash,
        &duplicate_confirmed_slots,
        heaviest_subtree_fork_choice,
        if (progress.isDead(3) orelse false) .dead else .fromHash(slot3_hash),
        false,
    );
    var ancestor_hashes_replay_update_sender: sig.sync.Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_update_sender.deinit();
    try check_slot_agrees_with_cluster.epochSlotsFrozen(
        allocator,
        .noop,
        3,
        root,
        heaviest_subtree_fork_choice,
        &duplicate_slots_to_repair,
        &epoch_slots_frozen_slots,
        epoch_slots_frozen_state,
    );
    try verifyAllSlotsDuplicateConfirmed(
        slot_tracker,
        heaviest_subtree_fork_choice,
        3,
        expected_is_duplicate_confirmed,
    );

    // Mark 3 as duplicate confirmed and epoch slots frozen with the same hash. Should
    // duplicate confirm all descendants of 3
    try duplicate_confirmed_slots.put(allocator, 3, slot3_hash);
    expected_is_duplicate_confirmed = true;
    const duplicate_confirmed_state: DuplicateConfirmedState = .{
        .duplicate_confirmed_hash = slot3_hash,
        .slot_status = if (progress.isDead(2) orelse false) .dead else .fromHash(slot3_hash),
    };
    try check_slot_agrees_with_cluster.duplicateConfirmed(
        allocator,
        .noop,
        3,
        root,
        &ledger_writer,
        heaviest_subtree_fork_choice,
        &duplicate_slots_to_repair,
        &ancestor_hashes_replay_update_sender,
        &purge_repair_slot_counter,
        duplicate_confirmed_state,
    );
    try std.testing.expectEqual(
        slot3_hash,
        epoch_slots_frozen_slots.get(3),
    );
    try verifyAllSlotsDuplicateConfirmed(
        slot_tracker,
        heaviest_subtree_fork_choice,
        3,
        expected_is_duplicate_confirmed,
    );
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );
}

test "duplicate confirmed and epoch slots frozen mismatched" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(7353);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = &test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger_state: TestLedgerRwState = .init();
    defer ledger_state.deinit();

    var ledger, _, var ledger_writer =
        try testLedgerRw(@src(), .noop, &ledger_state);
    defer ledger.deinit();

    const slot3_hash = slot_tracker.get(3).?.state.hash.readCopy().?;
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );

    const root: Slot = 0;

    var duplicate_slots_tracker: DuplicateSlot = .empty;
    defer duplicate_slots_tracker.deinit(allocator);

    var duplicate_confirmed_slots: DuplicateConfirmedSlots = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var epoch_slots_frozen_slots: EpochSlotsFrozenSlots = .empty;
    defer epoch_slots_frozen_slots.deinit(allocator);

    var duplicate_slots_to_repair: DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var purge_repair_slot_counter: PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    // Mark 3 as only epoch slots frozen with different hash than the our
    // locally replayed `slot3_hash`. This should not duplicate confirm the slot,
    // but should add the epoch slots frozen hash to the repair set
    const mismatched_hash: sig.core.Hash = .initRandom(random);
    var expected_is_duplicate_confirmed = false;
    const epoch_slots_frozen_state: EpochSlotsFrozenState = .fromState(
        .noop,
        3,
        mismatched_hash,
        &duplicate_confirmed_slots,
        heaviest_subtree_fork_choice,
        if (progress.isDead(3) orelse false) .dead else .fromHash(slot3_hash),
        false,
    );

    var ancestor_hashes_replay_update_sender: sig.sync.Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_update_sender.deinit();
    try check_slot_agrees_with_cluster.epochSlotsFrozen(
        allocator,
        .noop,
        3,
        root,
        heaviest_subtree_fork_choice,
        &duplicate_slots_to_repair,
        &epoch_slots_frozen_slots,
        epoch_slots_frozen_state,
    );
    try std.testing.expectEqual(mismatched_hash, duplicate_slots_to_repair.get(3).?);
    try verifyAllSlotsDuplicateConfirmed(
        slot_tracker,
        heaviest_subtree_fork_choice,
        3,
        expected_is_duplicate_confirmed,
    );

    // Mark our version of slot 3 as duplicate confirmed with a hash different than
    // the epoch slots frozen hash above. Should duplicate confirm all descendants of
    // 3 and remove the mismatched hash from `duplicate_slots_to_repair`, since we
    // have the right version now, no need to repair
    try duplicate_confirmed_slots.put(allocator, 3, slot3_hash);
    expected_is_duplicate_confirmed = true;
    const duplicate_confirmed_state: DuplicateConfirmedState = .{
        .duplicate_confirmed_hash = slot3_hash,
        .slot_status = if (progress.isDead(3) orelse false) .dead else .fromHash(slot3_hash),
    };
    try check_slot_agrees_with_cluster.duplicateConfirmed(
        allocator,
        .noop,
        3,
        root,
        &ledger_writer,
        heaviest_subtree_fork_choice,
        &duplicate_slots_to_repair,
        &ancestor_hashes_replay_update_sender,
        &purge_repair_slot_counter,
        duplicate_confirmed_state,
    );
    try std.testing.expectEqual(0, duplicate_slots_to_repair.count());
    try std.testing.expectEqual(mismatched_hash, epoch_slots_frozen_slots.get(3).?);
    try verifyAllSlotsDuplicateConfirmed(
        slot_tracker,
        heaviest_subtree_fork_choice,
        3,
        expected_is_duplicate_confirmed,
    );
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );
}

// -- handleEdgeCases END -- //

fn processConsensus() void {
    // TODO: for each slot:
    //           tower_duplicate_confirmed_forks
    //           mark_slots_duplicate_confirmed

    // TODO: select_forks

    // TODO: check_for_vote_only_mode

    // TODO: select_vote_and_reset_forks

    // TODO: if vote_bank.is_none: maybe_refresh_last_vote

    // TODO: handle_votable_bank

    // TODO: if reset_bank: Reset onto a fork
}

test trackNewSlots {
    const Pubkey = sig.core.Pubkey;
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(0);

    var blockstore_db = try sig.ledger.tests.TestDB.init(@src());
    defer blockstore_db.deinit();
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
        try blockstore_db.put(sig.ledger.schema.schema.slot_meta, slot, meta);
    }

    var slot_tracker = SlotTracker.init(0);
    defer slot_tracker.deinit(allocator);
    try slot_tracker.put(allocator, 0, .genesis(.DEFAULT), .GENESIS);
    slot_tracker.get(0).?.state.hash.set(.ZEROES);

    var epoch_tracker = EpochTracker{ .schedule = .DEFAULT };
    defer epoch_tracker.deinit(allocator);
    try epoch_tracker.epochs.put(allocator, 0, .{
        .hashes_per_tick = 1,
        .ticks_per_slot = 1,
        .ns_per_slot = 1,
        .genesis_creation_time = 1,
        .slots_per_year = 1,
        .stakes = try .initEmpty(allocator),
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

    // only the root (0) is considered frozen, so only 0 and 1 should be added at first.
    try trackNewSlots(
        allocator,
        &blockstore_db,
        &slot_tracker,
        &epoch_tracker,
        slot_leaders,
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
        &blockstore_db,
        &slot_tracker,
        &epoch_tracker,
        slot_leaders,
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
        &blockstore_db,
        &slot_tracker,
        &epoch_tracker,
        slot_leaders,
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
        &blockstore_db,
        &slot_tracker,
        &epoch_tracker,
        slot_leaders,
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
