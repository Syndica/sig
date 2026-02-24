const std = @import("std");
const sig = @import("../../sig.zig");
const replay = @import("../lib.zig");
const tracy = @import("tracy");

const collections = sig.utils.collections;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

const SlotTracker = sig.replay.trackers.SlotTracker;

const ProgressMap = sig.consensus.ProgressMap;
const HeaviestSubtreeForkChoice = sig.consensus.HeaviestSubtreeForkChoice;
const AncestorHashesReplayUpdate = replay.consensus.core.AncestorHashesReplayUpdate;
const GossipVerifiedVoteHash = sig.consensus.vote_listener.GossipVerifiedVoteHash;
const ThresholdConfirmedSlot = sig.consensus.vote_listener.ThresholdConfirmedSlot;
const LatestValidatorVotes = sig.consensus.latest_validator_votes.LatestValidatorVotes;

const ledger_tests = sig.ledger.tests;

pub const ProcessClusterSyncTimings = struct {
    ancestor_hashes_duplicate_slots: sig.time.Duration,
    duplicate_confirmed_slots: sig.time.Duration,
    unfrozen_gossip_verified_vote_hashes: sig.time.Duration,
    popular_pruned_forks: sig.time.Duration,
    duplicate_slots: sig.time.Duration,
};

pub fn processClusterSync(
    allocator: std.mem.Allocator,
    logger: replay.service.Logger,
    params: struct {
        my_pubkey: sig.core.Pubkey,
        tpu_has_bank: bool,

        slot_tracker: *const SlotTracker,
        progress: *const ProgressMap,
        fork_choice: *HeaviestSubtreeForkChoice,
        result_writer: sig.ledger.Ledger.ResultWriter,

        latest_validator_votes: *LatestValidatorVotes,
        slot_data: *SlotData,

        duplicate_confirmed_slots: []const ThresholdConfirmedSlot,
        gossip_verified_vote_hashes: []const GossipVerifiedVoteHash,

        senders: replay.TowerConsensus.Senders,
        receivers: replay.TowerConsensus.Receivers,
    },
) !ProcessClusterSyncTimings {
    const zone = tracy.Zone.init(@src(), .{ .name = "processClusterSync" });
    defer zone.deinit();

    var timer = sig.time.Timer.start();

    // Process cluster-agreed versions of duplicate slots for which we potentially
    // have the wrong version. Our version was dead or pruned.
    // Signalled by ancestor_hashes_service.
    timer.reset();
    const slot_tracker = params.slot_tracker;

    try processAncestorHashesDuplicateSlots(
        allocator,
        logger,
        params.my_pubkey,
        params.receivers.ancestor_duplicate_slots,
        &params.slot_data.duplicate_confirmed_slots,
        &params.slot_data.epoch_slots_frozen_slots,
        params.progress,
        params.fork_choice,
        slot_tracker,
        &params.slot_data.duplicate_slots_to_repair,
    );
    const ancestor_hashes_duplicate_slots_time = timer.lap();

    // Check for any newly duplicate confirmed slots detected from gossip / replay
    // Note: since this is tracked using both gossip & replay votes, stake is not
    // rolled up from descendants.
    timer.reset();
    try processDuplicateConfirmedSlots(
        allocator,
        logger,
        params.duplicate_confirmed_slots,
        params.result_writer,
        &params.slot_data.duplicate_confirmed_slots,
        slot_tracker,
        params.progress,
        params.fork_choice,
        &params.slot_data.duplicate_slots_to_repair,
        params.senders.ancestor_hashes_replay_update,
        &params.slot_data.purge_repair_slot_counter,
    );
    const duplicate_confirmed_slots_time = timer.lap();

    // Ingest any new verified votes from gossip. Important for fork choice
    // and switching proofs because these may be votes that haven't yet been
    // included in a block, so we may not have yet observed these votes just
    // by replaying blocks.
    timer.reset();
    try processGossipVerifiedVoteHashes(
        allocator,
        params.gossip_verified_vote_hashes,
        &params.slot_data.unfrozen_gossip_verified_vote_hashes,
        params.fork_choice,
        params.latest_validator_votes,
    );
    const unfrozen_gossip_verified_vote_hashes_time = timer.lap();

    // Check for "popular" (52+% stake aggregated across versions/descendants) forks
    // that are pruned, which would not be detected by normal means.
    // Signalled by `repair_service`.
    timer.reset();
    try processPrunedButPopularForks(
        logger,
        params.receivers.popular_pruned_forks,
        slot_tracker,
        params.senders.ancestor_hashes_replay_update,
    );
    const popular_pruned_forks_time = timer.lap();

    // Check to remove any duplicated slots from fork choice
    timer.reset();
    if (!params.tpu_has_bank) {
        try processDuplicateSlots(
            allocator,
            logger,
            params.receivers.duplicate_slots,
            &params.slot_data.duplicate_slots,
            &params.slot_data.duplicate_confirmed_slots,
            slot_tracker,
            params.progress,
            params.fork_choice,
        );
    }
    const duplicate_slots_time = timer.lap();

    return .{
        .ancestor_hashes_duplicate_slots = ancestor_hashes_duplicate_slots_time,
        .duplicate_confirmed_slots = duplicate_confirmed_slots_time,
        .unfrozen_gossip_verified_vote_hashes = unfrozen_gossip_verified_vote_hashes_time,
        .popular_pruned_forks = popular_pruned_forks_time,
        .duplicate_slots = duplicate_slots_time,
    };
}

pub const SlotData = struct {
    duplicate_confirmed_slots: DuplicateConfirmedSlots,
    epoch_slots_frozen_slots: EpochSlotsFrozenSlots,
    duplicate_slots_to_repair: DuplicateSlotsToRepair,
    purge_repair_slot_counter: PurgeRepairSlotCounters,
    unfrozen_gossip_verified_vote_hashes: UnfrozenGossipVerifiedVoteHashes,
    duplicate_slots: DuplicateSlots,
    latest_validator_votes: LatestValidatorVotes,

    /// Analogous to [DuplicateSlotsTracker](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/repair/cluster_slot_state_verifier.rs#L18)
    pub const DuplicateSlots = collections.SortedSetUnmanaged(Slot);

    /// Analogous to [DuplicateSlotsToRepair](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/repair/cluster_slot_state_verifier.rs#L19)
    pub const DuplicateSlotsToRepair = std.AutoArrayHashMapUnmanaged(Slot, Hash);

    /// Analogous to [PurgeRepairSlotCounter](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/repair/cluster_slot_state_verifier.rs#L20)
    pub const PurgeRepairSlotCounters = collections.SortedMapUnmanaged(Slot, usize);

    /// Analogous to [EpochSlotsFrozenSlots](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/repair/cluster_slot_state_verifier.rs#L22)
    pub const EpochSlotsFrozenSlots = collections.SortedMapUnmanaged(Slot, Hash);

    /// Analogous to [DuplicateConfirmedSlots](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/repair/cluster_slot_state_verifier.rs#L24)
    pub const DuplicateConfirmedSlots = collections.SortedMapUnmanaged(Slot, Hash);

    pub const empty: SlotData = .{
        .duplicate_confirmed_slots = .empty,
        .epoch_slots_frozen_slots = .empty,
        .duplicate_slots_to_repair = .empty,
        .purge_repair_slot_counter = .empty,
        .unfrozen_gossip_verified_vote_hashes = .empty,
        .duplicate_slots = .empty,
        .latest_validator_votes = .empty,
    };

    pub fn deinit(self: SlotData, allocator: std.mem.Allocator) void {
        self.duplicate_confirmed_slots.deinit(allocator);
        self.epoch_slots_frozen_slots.deinit(allocator);

        var duplicate_slots_to_repair = self.duplicate_slots_to_repair;
        duplicate_slots_to_repair.deinit(allocator);

        self.purge_repair_slot_counter.deinit(allocator);
        self.unfrozen_gossip_verified_vote_hashes.deinit(allocator);
        self.duplicate_slots.deinit(allocator);

        var latest_validator_votes = self.latest_validator_votes;
        latest_validator_votes.deinit(allocator);
    }
};

/// Analogous to [UnfrozenGossipVerifiedVoteHashes](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/unfrozen_gossip_verified_vote_hashes.rs#L8)
pub const UnfrozenGossipVerifiedVoteHashes = struct {
    votes_per_slot: sig.utils.collections.SortedMapUnmanaged(Slot, HashToVotesMap),

    const HashToVotesMap = std.AutoArrayHashMapUnmanaged(Hash, VoteList);
    const VoteList = std.ArrayListUnmanaged(Pubkey);

    pub const empty: UnfrozenGossipVerifiedVoteHashes = .{ .votes_per_slot = .empty };

    pub fn deinit(self: UnfrozenGossipVerifiedVoteHashes, allocator: std.mem.Allocator) void {
        var votes_per_slot = self.votes_per_slot;
        for (votes_per_slot.values()) |*htvm| {
            for (htvm.values()) |*vl| vl.deinit(allocator);
            htvm.deinit(allocator);
        }
        votes_per_slot.deinit(allocator);
    }

    /// Update `latest_validator_votes_for_frozen_slots` if gossip has seen a newer vote for a frozen slot.
    pub fn addVote(
        self: *UnfrozenGossipVerifiedVoteHashes,
        allocator: std.mem.Allocator,
        vote_pubkey: Pubkey,
        vote_slot: Slot,
        hash: Hash,
        is_frozen: bool,
        latest_validator_votes_for_frozen_slots: *LatestValidatorVotes,
    ) !void {
        // If this is a frozen slot, then we need to update the `latest_validator_votes_for_frozen_slots`
        const was_added, //
        const maybe_latest_frozen_vote_slot //
        = if (is_frozen) try latest_validator_votes_for_frozen_slots.checkAddVote(
            allocator,
            vote_pubkey,
            vote_slot,
            hash, // is_frozen
            .gossip,
        ) else blk: {
            // Non-frozen banks are not inserted because
            // we only track frozen votes in this struct
            const vote_map = latest_validator_votes_for_frozen_slots.latestVotes(.gossip);
            const slot = if (vote_map.get(vote_pubkey)) |entry| entry.slot else null;
            break :blk .{ false, slot };
        };

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

            if (!htv_gop.found_existing) {
                htv_gop.value_ptr.* = .empty;
            }

            try htv_gop.value_ptr.append(allocator, vote_pubkey);
        }
    }
};

pub const AncestorDuplicateSlotToRepair = struct {
    /// Slot that `ancestor_hashes_service` found that needs to be repaired
    slot_to_repair: sig.core.hash.SlotAndHash,
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
    hash: Hash,

    /// Ordered from strongest confirmation to weakest. Stronger
    /// confirmations take precedence over weaker ones.
    pub const Kind = enum {
        duplicate_confirmed,
        epoch_slots_frozen,
    };

    /// Finds the cluster confirmed hash
    ///
    /// 1) If we have a frozen hash, check if it's been duplicate confirmed by cluster
    ///    in turbine or gossip
    /// 2) Otherwise poll `epoch_slots_frozen_slots` to see if we have a hash
    ///
    /// Note `epoch_slots_frozen_slots` is not populated from `EpochSlots` in gossip but actually
    /// aggregated through hashes sent in response to requests from `ancestor_hashes_service`
    ///
    /// AKA: `getClusterConfirmedHashFromState` in agave.
    fn fromState(
        logger: replay.service.Logger,
        slot: Slot,
        duplicate_confirmed_slots: *const SlotData.DuplicateConfirmedSlots,
        epoch_slots_frozen_slots: *const SlotData.EpochSlotsFrozenSlots,
        fork_choice: *const HeaviestSubtreeForkChoice,
        maybe_slot_frozen_hash: ?Hash,
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
};

pub const SlotStatus = union(enum) {
    frozen: Hash,
    dead,
    unprocessed,

    /// Returns `.frozen` or `.unprocessed`.
    pub fn fromHash(maybe_hash: ?Hash) SlotStatus {
        if (maybe_hash) |hash| {
            return .{ .frozen = hash };
        } else {
            return .unprocessed;
        }
    }

    fn slotHash(self: SlotStatus) ?Hash {
        return switch (self) {
            .frozen => |hash| hash,
            .dead => null,
            .unprocessed => null,
        };
    }
};

pub const SlotFrozenState = struct {
    frozen_hash: sig.core.Hash,
    cluster_confirmed_hash: ?ClusterConfirmedHash,
    is_slot_duplicate: bool,

    pub fn fromState(
        logger: replay.service.Logger,
        slot: Slot,
        frozen_hash: Hash,
        duplicate_slots_tracker: *const SlotData.DuplicateSlots,
        duplicate_confirmed_slots: *const SlotData.DuplicateConfirmedSlots,
        fork_choice: *const HeaviestSubtreeForkChoice,
        epoch_slots_frozen_slots: *const SlotData.EpochSlotsFrozenSlots,
    ) SlotFrozenState {
        return .{
            .frozen_hash = frozen_hash,
            .is_slot_duplicate = duplicate_slots_tracker.contains(slot),
            .cluster_confirmed_hash = .fromState(
                logger,
                slot,
                duplicate_confirmed_slots,
                epoch_slots_frozen_slots,
                fork_choice,
                frozen_hash,
            ),
        };
    }
};

pub const DuplicateConfirmedState = struct {
    duplicate_confirmed_hash: Hash,
    slot_status: SlotStatus,
};

pub const DeadState = struct {
    cluster_confirmed_hash: ?ClusterConfirmedHash,
    is_slot_duplicate: bool,

    pub fn fromState(
        logger: replay.service.Logger,
        slot: Slot,
        duplicate_slots_tracker: *const SlotData.DuplicateSlots,
        duplicate_confirmed_slots: *const SlotData.DuplicateConfirmedSlots,
        fork_choice: *const HeaviestSubtreeForkChoice,
        epoch_slots_frozen_slots: *const SlotData.EpochSlotsFrozenSlots,
    ) DeadState {
        return .{
            .is_slot_duplicate = duplicate_slots_tracker.contains(slot),
            .cluster_confirmed_hash = .fromState(
                logger,
                slot,
                duplicate_confirmed_slots,
                epoch_slots_frozen_slots,
                fork_choice,
                null,
            ),
        };
    }
};

pub const DuplicateState = struct {
    duplicate_confirmed_hash: ?Hash,
    slot_status: SlotStatus,

    pub fn fromState(
        logger: replay.service.Logger,
        slot: Slot,
        duplicate_confirmed_slots: *const SlotData.DuplicateConfirmedSlots,
        fork_choice: *const HeaviestSubtreeForkChoice,
        slot_status: SlotStatus,
    ) DuplicateState {
        // We can only skip marking duplicate if this slot has already been
        // duplicate confirmed, any weaker confirmation levels are not sufficient
        // to skip marking the slot as duplicate.
        const duplicate_confirmed_hash = getDuplicateConfirmedHash(
            logger,
            fork_choice,
            slot,
            duplicate_confirmed_slots.get(slot),
            slot_status.slotHash(),
        );
        return .{
            .duplicate_confirmed_hash = duplicate_confirmed_hash,
            .slot_status = slot_status,
        };
    }
};

pub const EpochSlotsFrozenState = struct {
    epoch_slots_frozen_hash: Hash,
    duplicate_confirmed_hash: ?Hash,
    slot_status: SlotStatus,
    is_popular_pruned: bool,

    pub fn fromState(
        logger: replay.service.Logger,
        slot: Slot,
        epoch_slots_frozen_hash: Hash,
        duplicate_confirmed_slots: *const SlotData.DuplicateConfirmedSlots,
        fork_choice: *const HeaviestSubtreeForkChoice,
        slot_status: SlotStatus,
        is_popular_pruned: bool,
    ) EpochSlotsFrozenState {
        const duplicate_confirmed_hash = getDuplicateConfirmedHash(
            logger,
            fork_choice,
            slot,
            duplicate_confirmed_slots.get(slot),
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
    logger: replay.service.Logger,
    pubkey: sig.core.Pubkey,
    ancestor_duplicate_slots_receiver: *sig.sync.Channel(AncestorDuplicateSlotToRepair),
    duplicate_confirmed_slots: *const SlotData.DuplicateConfirmedSlots,
    epoch_slots_frozen_slots: *SlotData.EpochSlotsFrozenSlots,
    progress: *const ProgressMap,
    fork_choice: *HeaviestSubtreeForkChoice,
    slot_tracker: *const SlotTracker,
    duplicate_slots_to_repair: *SlotData.DuplicateSlotsToRepair,
) !void {
    const root = slot_tracker.root.load(.monotonic);

    while (ancestor_duplicate_slots_receiver.tryReceive()) |ancestor_dupe_slot_to_repair| {
        const request_type = ancestor_dupe_slot_to_repair.request_type;
        const slot_to_repair = ancestor_dupe_slot_to_repair.slot_to_repair;
        const epoch_slots_frozen_slot, const epoch_slots_frozen_hash = slot_to_repair.tuple();
        logger.warn().logf(
            "{} ReplayStage notified of duplicate slot from ancestor hashes service but we " ++
                "observed as {s}: {}",
            .{
                pubkey,
                if (request_type == .popular_pruned) "pruned" else "dead",
                slot_to_repair,
            },
        );

        const slot_status: SlotStatus = status: {
            if (progress.isDead(epoch_slots_frozen_slot) orelse false) {
                break :status .dead;
            }
            break :status .fromHash(hash: {
                const slot_info =
                    slot_tracker.slots.get(epoch_slots_frozen_slot) orelse
                    break :hash null;
                break :hash slot_info.state.hash.readCopy();
            });
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
    logger: replay.service.Logger,
    duplicate_confirmed_slots_received: []const ThresholdConfirmedSlot,
    result_writer: sig.ledger.Ledger.ResultWriter,
    duplicate_confirmed_slots: *SlotData.DuplicateConfirmedSlots,
    slot_tracker: *const SlotTracker,
    progress: *const ProgressMap,
    fork_choice: *HeaviestSubtreeForkChoice,
    duplicate_slots_to_repair: *SlotData.DuplicateSlotsToRepair,
    ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
    purge_repair_slot_counter: *SlotData.PurgeRepairSlotCounters,
) !void {
    const root = slot_tracker.root.load(.monotonic);
    for (duplicate_confirmed_slots_received) |new_duplicate_confirmed_slot| {
        const confirmed_slot, const duplicate_confirmed_hash = new_duplicate_confirmed_slot.tuple();
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
                    \\Additional duplicate confirmed notification for slot {} with a different hash.
                    \\prev_hash: {} duplicate_confirmed_hash {}
                ,
                    .{ confirmed_slot, prev_hash, duplicate_confirmed_hash },
                );
            }
            // Already processed this signal
            continue;
        }

        const duplicate_confirmed_state: DuplicateConfirmedState = .{
            .duplicate_confirmed_hash = duplicate_confirmed_hash,
            .slot_status = status: {
                if (progress.isDead(confirmed_slot) orelse false) break :status .dead;
                const slot_hash = if (slot_tracker.get(confirmed_slot)) |ref|
                    ref.state.hash.readCopy()
                else
                    null;
                break :status .fromHash(slot_hash);
            },
        };
        try check_slot_agrees_with_cluster.duplicateConfirmed(
            allocator,
            logger,
            confirmed_slot,
            root,
            result_writer,
            fork_choice,
            duplicate_slots_to_repair,
            ancestor_hashes_replay_update_sender,
            purge_repair_slot_counter,
            duplicate_confirmed_state,
        );
    }
}

/// Analogous to [process_gossip_verified_vote_hashes](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L1917)
fn processGossipVerifiedVoteHashes(
    allocator: std.mem.Allocator,
    gossip_verified_vote_hashes: []const GossipVerifiedVoteHash,
    unfrozen_gossip_verified_vote_hashes: *UnfrozenGossipVerifiedVoteHashes,
    heaviest_subtree_fork_choice: *const HeaviestSubtreeForkChoice,
    latest_validator_votes_for_frozen_slots: *LatestValidatorVotes,
) !void {
    for (gossip_verified_vote_hashes) |pubkey_slot_hash| {
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
fn processPrunedButPopularForks(
    logger: replay.service.Logger,
    pruned_but_popular_forks_receiver: *sig.sync.Channel(Slot),
    slot_tracker: *const SlotTracker,
    ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
) !void {
    const root = slot_tracker.root.load(.monotonic);
    while (pruned_but_popular_forks_receiver.tryReceive()) |new_popular_pruned_slot| {
        if (new_popular_pruned_slot <= root) {
            continue;
        }

        logger.info().logf(
            "check_slot_agrees_with_cluster() slot: {}, root: {}, slot_state_update: {s}",
            .{ new_popular_pruned_slot, root, "popular_pruned_fork" },
        );

        if (new_popular_pruned_slot <= root) {
            continue;
        }

        logger.warn().logf(
            "{} is part of a pruned fork which has reached the DUPLICATE_THRESHOLD " ++
                "aggregating across descendants and slot versions. It is suspected " ++
                "to be duplicate or have an ancestor that is duplicate. " ++
                "Notifying ancestor_hashes_service",
            .{new_popular_pruned_slot},
        );
        // AKA: `ResultingStateChange::SendAncestorHashesReplayUpdate` in agave.
        try ancestor_hashes_replay_update_sender.send(.{
            .popular_pruned_fork = new_popular_pruned_slot,
        });
    }
}

/// Checks for and handle forks with duplicate slots.
/// Analogous to [process_duplicate_slots](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/replay_stage.rs#L1938)
fn processDuplicateSlots(
    allocator: std.mem.Allocator,
    logger: replay.service.Logger,
    duplicate_slots_receiver: *sig.sync.Channel(Slot),
    duplicate_slots_tracker: *SlotData.DuplicateSlots,
    duplicate_confirmed_slots: *const SlotData.DuplicateConfirmedSlots,
    slot_tracker: *const SlotTracker,
    progress: *const ProgressMap,
    fork_choice: *HeaviestSubtreeForkChoice,
) !void {
    const MAX_BATCH_SIZE = 1024;

    var new_duplicate_slots: std.BoundedArray(Slot, MAX_BATCH_SIZE) = .{};
    while (new_duplicate_slots.unusedCapacitySlice().len != 0) {
        const new_duplicate_slot = duplicate_slots_receiver.tryReceive() orelse break;
        new_duplicate_slots.appendAssumeCapacity(new_duplicate_slot);
    }

    const root_slot, const slots_hashes = blk: {
        var slots_hashes: std.BoundedArray(?Hash, MAX_BATCH_SIZE) = .{};
        for (new_duplicate_slots.constSlice()) |duplicate_slot| {
            slots_hashes.appendAssumeCapacity(hash: {
                const bf_elem = slot_tracker.slots.get(duplicate_slot) orelse break :hash null;
                break :hash bf_elem.state.hash.readCopy();
            });
        }

        break :blk .{ slot_tracker.root.load(.monotonic), slots_hashes };
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

/// Finds the duplicate confirmed hash for a slot.
///
/// 1) If `maybe_slot_frozen_hash != null and isDuplicateConfirmed(maybe_slot_frozen_hash.?)`, `return maybe_slot_frozen_hash.?`
/// 2) If `maybe_duplicate_confirmed_hash != null`, `return maybe_duplicate_confirmed_hash.?`
/// 3) Else return null
///
/// NOTE: the agave version of this is always called the same way, so the duplicated logic has been
/// deduplicated into this function, which is why it is not quite the same.
fn getDuplicateConfirmedHash(
    logger: replay.service.Logger,
    fork_choice: *const HeaviestSubtreeForkChoice,
    slot: Slot,
    maybe_duplicate_confirmed_hash: ?Hash,
    maybe_slot_frozen_hash: ?Hash,
) ?Hash {
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
pub const check_slot_agrees_with_cluster = struct {
    /// aka `BankFrozen` in agave.
    pub fn slotFrozen(
        allocator: std.mem.Allocator,
        logger: replay.service.Logger,
        slot: Slot,
        root: Slot,
        result_writer: sig.ledger.Ledger.ResultWriter,
        fork_choice: *HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: *SlotData.DuplicateSlotsToRepair,
        purge_repair_slot_counter: *SlotData.PurgeRepairSlotCounters,
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
        var confirmed_non_dupe_frozen_hash: state_change.ConfirmedNonDupeFrozenHash = .init;

        try state_change.maybeUpdateConfirmedAndNotDupeFrozenHash(
            logger,
            fork_choice,
            &confirmed_non_dupe_frozen_hash,
            slot,
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
                        try state_change.markAllNewConfirmedAndDuplicateSlots(
                            allocator,
                            slot,
                            fork_choice,
                            duplicate_slots_to_repair,
                            result_writer,
                            purge_repair_slot_counter,
                            &confirmed_non_dupe_frozen_hash,
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
                        // AKA: `ResultingStateChange::MarkSlotDuplicate` in agave
                        try fork_choice.markForkInvalidCandidate(allocator, &.{
                            .slot = slot,
                            .hash = frozen_hash,
                        });
                        // AKA: `ResultingStateChange::RepairDuplicateConfirmedVersion` in agave
                        try duplicate_slots_to_repair.put(
                            allocator,
                            slot,
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
                        // AKA: `ResultingStateChange::MarkSlotDuplicate` in agave
                        try fork_choice.markForkInvalidCandidate(allocator, &.{
                            .slot = slot,
                            .hash = frozen_hash,
                        });
                    }
                    // AKA: `ResultingStateChange::RepairDuplicateConfirmedVersion` in agave
                    try duplicate_slots_to_repair.put(allocator, slot, epoch_slots_frozen_hash);
                },
            }
        } else if (is_slot_duplicate) {
            // If `cluster_confirmed_hash` is Some above we should have already pushed a
            // `MarkSlotDuplicate` state change
            // AKA: `ResultingStateChange::MarkSlotDuplicate` in agave
            try fork_choice.markForkInvalidCandidate(allocator, &.{
                .slot = slot,
                .hash = frozen_hash,
            });
        }

        try confirmed_non_dupe_frozen_hash.finalize(slot, result_writer);
    }

    pub fn duplicateConfirmed(
        allocator: std.mem.Allocator,
        logger: replay.service.Logger,
        slot: Slot,
        root: Slot,
        result_writer: sig.ledger.Ledger.ResultWriter,
        fork_choice: *HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: *SlotData.DuplicateSlotsToRepair,
        ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
        purge_repair_slot_counter: *SlotData.PurgeRepairSlotCounters,
        duplicate_confirmed_state: DuplicateConfirmedState,
    ) !void {
        logger.debug().logf(
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

        // TODO: consider putting a prometheus metric here, similar to how agave
        // has a datapoint_info here. Specifically one bound to "duplicate_confirmed_slots",
        // with fields:
        // .{
        //     .slot = slot,
        //     .duplicate_confirmed_hash = duplicate_confirmed_hash,
        //     .my_hash = slot_status.slotHash(),
        // }

        // Handle cases where the slot is frozen, but not duplicate confirmed yet.
        var confirmed_non_dupe_frozen_hash: state_change.ConfirmedNonDupeFrozenHash = .init;

        switch (slot_status) {
            // No action to be taken yet
            .unprocessed => {},

            .dead => {
                // AKA: `ResultingStateChange::SendAncestorHashesReplayUpdate` in agave.
                try ancestor_hashes_replay_update_sender.send(.{
                    .dead_duplicate_confirmed = slot,
                });

                // If the cluster duplicate confirmed some version of this slot, then
                // there's another version of our dead slot
                logger.warn().logf(
                    "Cluster duplicate confirmed slot {} with hash {}, but we marked slot dead",
                    .{ slot, duplicate_confirmed_hash },
                );
                // AKA: `ResultingStateChange::RepairDuplicateConfirmedVersion` in agave
                try duplicate_slots_to_repair.put(allocator, slot, duplicate_confirmed_hash);
            },

            .frozen => |frozen_hash| {
                if (duplicate_confirmed_hash.eql(frozen_hash)) {
                    // If the versions match, then add the slot to the candidate
                    // set to account for the case where it was removed earlier
                    // by the `on_duplicate_slot()` handler
                    try state_change.markAllNewConfirmedAndDuplicateSlots(
                        allocator,
                        slot,
                        fork_choice,
                        duplicate_slots_to_repair,
                        result_writer,
                        purge_repair_slot_counter,
                        &confirmed_non_dupe_frozen_hash,
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
                    // AKA: `ResultingStateChange::MarkSlotDuplicate` in agave
                    try fork_choice.markForkInvalidCandidate(allocator, &.{
                        .slot = slot,
                        .hash = frozen_hash,
                    });
                    // AKA: `ResultingStateChange::RepairDuplicateConfirmedVersion` in agave
                    try duplicate_slots_to_repair.put(allocator, slot, duplicate_confirmed_hash);
                }
            },
        }

        try confirmed_non_dupe_frozen_hash.finalize(slot, result_writer);
    }

    pub fn dead(
        allocator: std.mem.Allocator,
        logger: replay.service.Logger,
        slot: Slot,
        root: Slot,
        duplicate_slots_to_repair: *SlotData.DuplicateSlotsToRepair,
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
                    // AKA: `ResultingStateChange::SendAncestorHashesReplayUpdate` in agave.
                    try ancestor_hashes_replay_update_sender.send(
                        .{ .dead_duplicate_confirmed = slot },
                    );

                    // If the cluster duplicate confirmed some version of this slot, then
                    // there's another version of our dead slot
                    logger.warn().logf(
                        "Cluster duplicate confirmed slot {} with hash {}, " ++
                            "but we marked slot dead",
                        .{ slot, duplicate_confirmed_hash },
                    );
                    // AKA: `ResultingStateChange::RepairDuplicateConfirmedVersion` in agave
                    try duplicate_slots_to_repair.put(allocator, slot, cluster_confirmed_hash.hash);
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
                    // AKA: `ResultingStateChange::RepairDuplicateConfirmedVersion` in agave
                    try duplicate_slots_to_repair.put(allocator, slot, cluster_confirmed_hash.hash);
                },
            }
        } else {
            // AKA: `ResultingStateChange::SendAncestorHashesReplayUpdate` in agave.
            try ancestor_hashes_replay_update_sender.send(.{ .dead = slot });
        }
    }

    pub fn duplicate(
        allocator: std.mem.Allocator,
        logger: replay.service.Logger,
        slot: Slot,
        root: Slot,
        duplicate_slots_tracker: *SlotData.DuplicateSlots,
        fork_choice: *HeaviestSubtreeForkChoice,
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
        if (duplicate_slots_tracker.contains(slot)) {
            // If this slot has already been processed before, return.
            return;
        } else {
            // Otherwise, add it to the set of processed slots, and proceed.
            try duplicate_slots_tracker.put(allocator, slot);
        }

        // TODO: consider putting a prometheus metric here, similar to how agave
        // has a datapoint_info here. Specifically one bound to "duplicate_slot",
        // with fields:
        // .{
        //     .slot = slot,
        //     .duplicate_confirmed_hash = duplicate_confirmed_hash,
        //     .my_hash = slot_status.slotHash(),
        // }

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
            if (slot_status.slotHash()) |hash| {
                // AKA: `ResultingStateChange::MarkSlotDuplicate` in agave
                try fork_choice.markForkInvalidCandidate(allocator, &.{
                    .slot = slot,
                    .hash = hash,
                });
            }
        }
    }

    fn epochSlotsFrozen(
        allocator: std.mem.Allocator,
        logger: replay.service.Logger,
        slot: Slot,
        root: Slot,
        fork_choice: *HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: *SlotData.DuplicateSlotsToRepair,
        epoch_slots_frozen_slots: *SlotData.EpochSlotsFrozenSlots,
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
                        // AKA: `ResultingStateChange::MarkSlotDuplicate` in agave
                        try fork_choice.markForkInvalidCandidate(allocator, &.{
                            .slot = slot,
                            .hash = slot_frozen_hash,
                        });
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

        // AKA: `ResultingStateChange::RepairDuplicateConfirmedVersion` in agave
        try duplicate_slots_to_repair.put(allocator, slot, epoch_slots_frozen_hash);
    }
};

/// Analogous to [apply_state_change](https://github.com/anza-xyz/agave/blob/0315eb6adc87229654159448344972cbe484d0c7/core/src/repair/cluster_slot_state_verifier.rs#L793),
/// or more concretely, each function is analogous to a variant in the `ResultingStateChange`
/// tagged union, a list of which is supplied to the function, representing a list of these
/// function calls.
const state_change = struct {
    /// CONTEXT: Across certain series of operations, a hash may be identified for a slot, and
    /// then invalidated by a subsequent operation, and then replaced by a new one or nullified
    /// entirely, repeatedly. A naive approach would have each of those operations result in a
    /// mutation of the ledger to update the slot hash pair's status as a non-duplicate confirmed
    /// frozen slot, which would result in multiple costly operations to update the ledger.
    ///
    /// Instead of committing multiple ledger updates which may cancel out or overwrite each
    /// other, this struct is used to represent the transient hash for the slot that is `update`d
    /// across a series of operations, before being `finalize`d, committing just one update at
    /// most (no update if by the end the frozen hash is null).
    const ConfirmedNonDupeFrozenHash = struct {
        frozen_hash: ?Hash,
        finalized: bool,

        const init: ConfirmedNonDupeFrozenHash = .{
            .frozen_hash = null,
            .finalized = false,
        };

        fn update(self: *ConfirmedNonDupeFrozenHash, frozen_hash: ?Hash) void {
            self.frozen_hash = frozen_hash;
        }

        fn finalize(
            self: *ConfirmedNonDupeFrozenHash,
            slot: Slot,
            result_writer: sig.ledger.Ledger.ResultWriter,
        ) !void {
            std.debug.assert(!self.finalized);
            self.finalized = true;
            if (self.frozen_hash) |frozen_hash| {
                try result_writer.insertBankHash(slot, frozen_hash, false);
            }
        }
    };

    /// Checks if `.{ frozen_slot, frozen_hash }` is duplicate confirmed in fork_choice,
    /// and updates `confirmed_non_dupe_frozen_hash` accordingly.
    /// Logs and returns an error if it doesn't exist in `fork_choice.`
    ///
    /// AKA: `ResultingStateChange::BankFrozen` in agave.
    fn maybeUpdateConfirmedAndNotDupeFrozenHash(
        logger: replay.service.Logger,
        fork_choice: *const HeaviestSubtreeForkChoice,
        confirmed_non_dupe_frozen_hash: *ConfirmedNonDupeFrozenHash,
        frozen_slot: u64,
        frozen_hash: Hash,
    ) error{FrozenSlotNotInForkChoice}!void {
        const is_duplicate_and_confirmed = fork_choice.isDuplicateConfirmed(&.{
            .slot = frozen_slot,
            .hash = frozen_hash,
        }) orelse {
            logger.err().logf(
                "frozen '{{ .slot = {}, .hash = {} }}' must exist in fork choice",
                .{ frozen_slot, frozen_hash },
            );
            return error.FrozenSlotNotInForkChoice;
        };
        if (!is_duplicate_and_confirmed) {
            confirmed_non_dupe_frozen_hash.update(frozen_hash);
        }
    }

    /// AKA: `ResultingStateChange::DuplicateConfirmedSlotMatchesCluster` in agave.
    fn markAllNewConfirmedAndDuplicateSlots(
        allocator: std.mem.Allocator,
        slot: u64,
        fork_choice: *HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: *SlotData.DuplicateSlotsToRepair,
        result_writer: sig.ledger.Ledger.ResultWriter,
        purge_repair_slot_counter: *SlotData.PurgeRepairSlotCounters,
        confirmed_non_dupe_frozen_hash: *ConfirmedNonDupeFrozenHash,
        slot_frozen_hash: Hash,
    ) !void {
        confirmed_non_dupe_frozen_hash.update(null);
        // When we detect that our frozen slot matches the cluster version (note this
        // will catch both slot frozen first -> confirmation, or confirmation first ->
        // slot frozen), mark all the newly duplicate confirmed slots in ledger

        {
            var setter = try result_writer.setDuplicateConfirmedSlotsAndHashesIncremental();
            defer setter.deinit();

            const newly_duplicate_confirmed_ancestors_ctx: struct {
                setter: *@TypeOf(setter),

                pub fn register(ctx: @This(), slot_hash: sig.core.hash.SlotAndHash) !void {
                    try ctx.setter.addSlotAndHash(slot_hash.slot, slot_hash.hash);
                }
            } = .{ .setter = &setter };

            try fork_choice.markForkValidCandidate(
                allocator,
                &.{ .slot = slot, .hash = slot_frozen_hash },
                newly_duplicate_confirmed_ancestors_ctx,
            );

            try setter.commit();
        }

        _ = duplicate_slots_to_repair.swapRemove(slot);
        _ = purge_repair_slot_counter.orderedRemove(slot);
    }
};

const Descendants = std.AutoArrayHashMapUnmanaged(
    Slot,
    sig.utils.collections.SortedMapUnmanaged(Slot, void),
);
fn descendantsDeinit(allocator: std.mem.Allocator, descendants: Descendants) void {
    for (descendants.values()) |*child_set| child_set.deinit(allocator);
    var copy = descendants;
    copy.deinit(allocator);
}

const TestData = struct {
    slot_tracker: SlotTracker,
    heaviest_subtree_fork_choice: HeaviestSubtreeForkChoice,
    progress: ProgressMap,
    descendants: Descendants,

    comptime {
        std.debug.assert(@import("builtin").is_test);
    }

    fn deinit(self: TestData, allocator: std.mem.Allocator) void {
        self.slot_tracker.deinit(allocator);

        var fork_choice = self.heaviest_subtree_fork_choice;
        fork_choice.deinit(allocator);

        descendantsDeinit(allocator, self.descendants);

        self.progress.deinit(allocator);
    }

    const SlotInfo = struct {
        parent_slot: ?Slot,
        slot: Slot,
        hash: Hash,
        fork_progress_init: sig.consensus.progress_map.ForkProgress.InitParams,

        fn parentSlot(self: SlotInfo) Slot {
            return self.parent_slot orelse (self.slot -| 1);
        }

        fn initRandom(
            random: std.Random,
            parent_slot: ?Slot,
            slot: Slot,
            fork_progress_init: sig.consensus.progress_map.ForkProgress.InitParams,
        ) SlotInfo {
            return .{
                .parent_slot = parent_slot orelse (slot -| 1),
                .slot = slot,
                .hash = .initRandom(random),
                .fork_progress_init = fork_progress_init,
            };
        }

        /// Generates an element with a bunch of dummy data, aside from
        /// anything described by `self`.
        fn toDummyElem(
            self: SlotInfo,
            slot_infos: []const SlotInfo,
            random: std.Random,
        ) !SlotTracker.Element {
            return .{
                .constants = .{
                    .parent_slot = self.parentSlot(),
                    .parent_lt_hash = .initRandom(random),
                    .parent_hash = slot_infos[self.parentSlot()].hash,
                    .block_height = random.int(u64),
                    .collector_id = .initRandom(random),
                    .max_tick_height = random.int(u64),
                    .fee_rate_governor = .initRandom(random),
                    .ancestors = .{ .ancestors = .empty },
                    .feature_set = .ALL_DISABLED,
                    .reserved_accounts = .empty,
                    .inflation = .DEFAULT,
                    .rent_collector = .DEFAULT,
                },
                .state = .{
                    .blockhash_queue = .init(.DEFAULT),
                    .hash = .init(slot_infos[self.slot].hash),
                    .capitalization = .init(random.int(u64)),
                    .transaction_count = .init(random.int(u64)),
                    .signature_count = .init(random.int(u64)),
                    .tick_height = .init(random.int(u64)),
                    .collected_rent = .init(random.int(u64)),
                    .accounts_lt_hash = .init(.{ .data = @splat(random.int(u16)) }),
                    .stakes_cache = .EMPTY,
                    .collected_transaction_fees = .init(random.int(u64)),
                    .collected_priority_fees = .init(random.int(u64)),
                    .reward_status = .inactive,
                },
            };
        }
    };

    fn init(
        allocator: std.mem.Allocator,
        logger: replay.service.Logger,
        random: std.Random,
    ) !TestData {
        const root_slot: Slot = 0;
        const slot_infos = [_]SlotInfo{
            .initRandom(random, null, root_slot, .{
                .now = .now(),
                .last_entry = .parse("5NjW2CAV6MBQYxpL4oK2CESrpdj6tkcvxP3iigAgrHyR"),
                .prev_leader_slot = null,
                .validator_stake_info = .{
                    .validator_vote_pubkey = .parse("11111111111111111111111111111111"),
                    .stake = 0,
                    .total_epoch_stake = 10_000,
                },
                .num_blocks_on_fork = 0,
                .num_dropped_blocks_on_fork = 0,
            }),
            .initRandom(random, root_slot, 1, .{
                .now = .now(),
                .last_entry = .parse("11111111111111111111111111111111"),
                .prev_leader_slot = null,
                .validator_stake_info = null,
                .num_blocks_on_fork = 0,
                .num_dropped_blocks_on_fork = 0,
            }),
            .initRandom(random, 1, 2, .{
                .now = .now(),
                .last_entry = .parse("11111111111111111111111111111111"),
                .prev_leader_slot = null,
                .validator_stake_info = null,
                .num_blocks_on_fork = 0,
                .num_dropped_blocks_on_fork = 0,
            }),
            .initRandom(random, 2, 3, .{
                .now = .now(),
                .last_entry = .parse("11111111111111111111111111111111"),
                .prev_leader_slot = null,
                .validator_stake_info = null,
                .num_blocks_on_fork = 0,
                .num_dropped_blocks_on_fork = 0,
            }),
        };

        var slot_tracker: SlotTracker = try .init(
            allocator,
            root_slot,
            try slot_infos[root_slot].toDummyElem(&slot_infos, random),
        );
        errdefer slot_tracker.deinit(allocator);

        var fork_choice: HeaviestSubtreeForkChoice = try .init(
            allocator,
            .from(logger),
            .{
                .slot = root_slot,
                .hash = slot_infos[root_slot].hash,
            },
            sig.prometheus.globalRegistry(),
        );
        errdefer fork_choice.deinit(allocator);

        var progress: ProgressMap = .INIT;
        errdefer progress.deinit(allocator);

        for (slot_infos) |slot_info| {
            try progress.map.ensureUnusedCapacity(allocator, 1);
            progress.map.putAssumeCapacity(
                slot_info.slot,
                try .init(allocator, slot_info.fork_progress_init),
            );

            try fork_choice.addNewLeafSlot(
                allocator,
                .{ .slot = slot_info.slot, .hash = slot_info.hash },
                if (slot_info.parent_slot) |parent_slot| .{
                    .slot = parent_slot,
                    .hash = slot_infos[parent_slot].hash,
                } else null,
            );

            var elem = try slot_info.toDummyElem(slot_infos[0..], random);
            const gop = try slot_tracker.getOrPut(allocator, slot_info.slot, elem);
            if (gop.found_existing) {
                std.debug.assert(slot_info.slot == root_slot);
                elem.state.deinit(allocator);
                elem.constants.deinit(allocator);
            }
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

test "apply state changes" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const descendants = test_data.descendants;

    // MarkSlotDuplicate should mark progress map and remove
    // the slot from fork choice
    const duplicate_slot = slot_tracker.root.load(.monotonic) + 1;
    const duplicate_slot_hash = slot_tracker.get(duplicate_slot).?.state.hash.readCopy().?;
    // AKA: `ResultingStateChange::MarkSlotDuplicate` in agave
    try heaviest_subtree_fork_choice.markForkInvalidCandidate(allocator, &.{
        .slot = duplicate_slot,
        .hash = duplicate_slot_hash,
    });
    try std.testing.expect(!heaviest_subtree_fork_choice.isCandidate(&.{
        .slot = duplicate_slot,
        .hash = duplicate_slot_hash,
    }).?);
    for ([_][]const Slot{
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

    var duplicate_slots_to_repair: SlotData.DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    try std.testing.expect(duplicate_slots_to_repair.count() == 0);

    // Simulate detecting another hash that is the correct version,
    // RepairDuplicateConfirmedVersion should add the slot to repair
    // to `duplicate_slots_to_repair`
    try std.testing.expect(duplicate_slots_to_repair.count() == 0);
    const correct_hash: Hash = .initRandom(random);
    // AKA: `ResultingStateChange::RepairDuplicateConfirmedVersion` in agave
    try duplicate_slots_to_repair.put(allocator, duplicate_slot, correct_hash);
    try std.testing.expectEqual(1, duplicate_slots_to_repair.count());
    try std.testing.expectEqual(
        correct_hash,
        duplicate_slots_to_repair.get(duplicate_slot),
    );
}

test "apply state changes slot frozen" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;

    var ledger = try ledger_tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const duplicate_slot = slot_tracker.root.load(.monotonic) + 1;
    const duplicate_slot_hash = slot_tracker.get(duplicate_slot).?.state.hash.readCopy().?;

    // Simulate ReplayStage freezing a Slot with the given hash.
    // 'slot frozen' should mark it down in Ledger.
    try std.testing.expectEqual(
        null,
        ledger.reader().getBankHash(allocator, duplicate_slot),
    );

    {
        // Handle cases where the slot is frozen, but not duplicate confirmed yet.
        var confirmed_non_dupe_frozen_hash: state_change.ConfirmedNonDupeFrozenHash = .init;
        try state_change.maybeUpdateConfirmedAndNotDupeFrozenHash(
            .noop,
            heaviest_subtree_fork_choice,
            &confirmed_non_dupe_frozen_hash,
            duplicate_slot,
            duplicate_slot_hash,
        );
        try confirmed_non_dupe_frozen_hash.finalize(duplicate_slot, ledger.resultWriter());
    }

    try std.testing.expectEqual(
        duplicate_slot_hash,
        ledger.reader().getBankHash(allocator, duplicate_slot),
    );
    try std.testing.expectEqual(
        false,
        ledger.reader().isDuplicateConfirmed(allocator, duplicate_slot),
    );

    // If we freeze another version of the slot, it should overwrite the first
    // version in blockstore.
    const new_slot_hash: Hash = .initRandom(random);
    const root_slot_hash: sig.core.hash.SlotAndHash = rsh: {
        const root_slot = slot_tracker.root.load(.monotonic);
        const root_slot_info = slot_tracker.get(root_slot).?;
        break :rsh .{
            .slot = root_slot,
            .hash = root_slot_info.state.hash.readCopy().?,
        };
    };
    try heaviest_subtree_fork_choice.addNewLeafSlot(
        allocator,
        .{
            .slot = duplicate_slot,
            .hash = new_slot_hash,
        },
        root_slot_hash,
    );
    {
        // Handle cases where the slot is frozen, but not duplicate confirmed yet.
        var confirmed_non_dupe_frozen_hash: state_change.ConfirmedNonDupeFrozenHash = .init;
        try state_change.maybeUpdateConfirmedAndNotDupeFrozenHash(
            .noop,
            heaviest_subtree_fork_choice,
            &confirmed_non_dupe_frozen_hash,
            duplicate_slot,
            new_slot_hash,
        );
        try confirmed_non_dupe_frozen_hash.finalize(duplicate_slot, ledger.resultWriter());
    }
    try std.testing.expectEqual(
        new_slot_hash,
        ledger.reader().getBankHash(allocator, duplicate_slot),
    );
    try std.testing.expectEqual(
        false,
        ledger.reader().isDuplicateConfirmed(allocator, duplicate_slot),
    );
}

test "apply state changes duplicate confirmed matches frozen" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const descendants = &test_data.descendants;

    var ledger = try ledger_tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const duplicate_slot = slot_tracker.root.load(.monotonic) + 1;
    const our_duplicate_slot_hash = slot_tracker.get(duplicate_slot).?.state.hash.readCopy().?;

    var duplicate_slots_to_repair: SlotData.DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var purge_repair_slot_counter: SlotData.PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    // Setup and check the state that is about to change.
    try duplicate_slots_to_repair.put(allocator, duplicate_slot, .initRandom(random));
    try purge_repair_slot_counter.put(allocator, duplicate_slot, 1);
    try std.testing.expectEqual(
        null,
        ledger.reader().getBankHash(allocator, duplicate_slot),
    );
    try std.testing.expectEqual(
        false,
        ledger.reader().isDuplicateConfirmed(allocator, duplicate_slot),
    );

    // DuplicateConfirmedSlotMatchesCluster should:
    // 1) Re-enable fork choice
    // 2) Clear any pending repairs from `duplicate_slots_to_repair` since we have the
    //    right version now
    // 3) Clear the slot from `purge_repair_slot_counter`
    // 3) Set the status to duplicate confirmed in Ledger
    {
        // Handle cases where the slot is frozen, but not duplicate confirmed yet.
        var confirmed_non_dupe_frozen_hash: state_change.ConfirmedNonDupeFrozenHash = .init;
        try state_change.markAllNewConfirmedAndDuplicateSlots(
            allocator,
            duplicate_slot,
            heaviest_subtree_fork_choice,
            &duplicate_slots_to_repair,
            ledger.resultWriter(),
            &purge_repair_slot_counter,
            &confirmed_non_dupe_frozen_hash,
            our_duplicate_slot_hash,
        );

        try confirmed_non_dupe_frozen_hash.finalize(duplicate_slot, ledger.resultWriter());
    }

    for ([_][]const Slot{
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
    try std.testing.expectEqual(
        our_duplicate_slot_hash,
        ledger.reader().getBankHash(allocator, duplicate_slot),
    );
    try std.testing.expectEqual(
        true,
        ledger.reader().isDuplicateConfirmed(allocator, duplicate_slot),
    );
}

test "apply state changes slot frozen and duplicate confirmed matches frozen" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const descendants = &test_data.descendants;

    var ledger = try ledger_tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var duplicate_slots_to_repair: SlotData.DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var purge_repair_slot_counter: SlotData.PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    const duplicate_slot = slot_tracker.root.load(.monotonic) + 1;
    const our_duplicate_slot_hash = slot_tracker.get(duplicate_slot).?.state.hash.readCopy().?;

    // Setup and check the state that is about to change.
    try duplicate_slots_to_repair.put(allocator, duplicate_slot, .initRandom(random));
    try purge_repair_slot_counter.put(allocator, duplicate_slot, 1);
    try std.testing.expectEqual(
        null,
        ledger.reader().getBankHash(allocator, duplicate_slot),
    );
    try std.testing.expectEqual(
        false,
        ledger.reader().isDuplicateConfirmed(allocator, duplicate_slot),
    );

    // DuplicateConfirmedSlotMatchesCluster should:
    // 1) Re-enable fork choice
    // 2) Clear any pending repairs from `duplicate_slots_to_repair` since we have the
    //    right version now
    // 3) Clear the slot from `purge_repair_slot_counter`
    // 3) Set the status to duplicate confirmed in Ledger
    {
        // Handle cases where the slot is frozen, but not duplicate confirmed yet.
        var confirmed_non_dupe_frozen_hash: state_change.ConfirmedNonDupeFrozenHash = .init;

        try state_change.markAllNewConfirmedAndDuplicateSlots(
            allocator,
            duplicate_slot,
            heaviest_subtree_fork_choice,
            &duplicate_slots_to_repair,
            ledger.resultWriter(),
            &purge_repair_slot_counter,
            &confirmed_non_dupe_frozen_hash,
            our_duplicate_slot_hash,
        );

        try state_change.maybeUpdateConfirmedAndNotDupeFrozenHash(
            .noop,
            heaviest_subtree_fork_choice,
            &confirmed_non_dupe_frozen_hash,
            duplicate_slot,
            our_duplicate_slot_hash,
        );

        try confirmed_non_dupe_frozen_hash.finalize(duplicate_slot, ledger.resultWriter());
    }

    for ([_][]const Slot{
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
    try std.testing.expectEqual(
        our_duplicate_slot_hash,
        ledger.reader().getBankHash(allocator, duplicate_slot),
    );
    try std.testing.expectEqual(
        true,
        ledger.reader().isDuplicateConfirmed(allocator, duplicate_slot),
    );
}

test "check slot agrees with cluster dead duplicate confirmed" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger = try ledger_tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const root = 0;

    var purge_repair_slot_counter: SlotData.PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    // Mark slot 2 as duplicate confirmed
    const slot2_hash = slot_tracker.get(2).?.state.hash.readCopy().?;

    var duplicate_slots_to_repair: SlotData.DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var ancestor_hashes_replay_update_channel: sig.sync.Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_update_channel.deinit();

    progress.getForkProgress(2).?.is_dead = true;
    try check_slot_agrees_with_cluster.duplicateConfirmed(
        allocator,
        .noop,
        2,
        root,
        ledger.resultWriter(),
        heaviest_subtree_fork_choice,
        &duplicate_slots_to_repair,
        &ancestor_hashes_replay_update_channel,
        &purge_repair_slot_counter,
        .{
            .duplicate_confirmed_hash = slot2_hash,
            .slot_status = if (progress.isDead(2) orelse false) .dead else .fromHash(slot2_hash),
        },
    );

    try std.testing.expectEqual(
        AncestorHashesReplayUpdate{ .dead_duplicate_confirmed = 2 },
        ancestor_hashes_replay_update_channel.tryReceive(),
    );
    try std.testing.expectEqual(
        slot2_hash,
        duplicate_slots_to_repair.get(2),
    );
}

fn testStateDuplicateThenSlotFrozen(initial_slot_hash: ?Hash) !void {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger = try ledger_tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    // Setup a duplicate slot state transition with the initial slot state of the duplicate slot
    // determined by `initial_slot_hash`, which can be:
    // 1) A default hash (unfrozen slot),
    // 2) None (a slot that hasn't even started replay yet).
    const root: Slot = 0;

    var duplicate_slots_tracker: SlotData.DuplicateSlots = .empty;
    defer duplicate_slots_tracker.deinit(allocator);

    var duplicate_slots_to_repair: SlotData.DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var purge_repair_slot_counter: SlotData.PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    const duplicate_confirmed_slots: SlotData.DuplicateConfirmedSlots = .empty;
    const epoch_slots_frozen_slots: SlotData.EpochSlotsFrozenSlots = .empty;

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
        ledger.resultWriter(),
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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger = try ledger_tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const slot3_hash = slot_tracker.get(3).?.state.hash.readCopy().?;
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );
    const root = 0;

    var duplicate_slots_tracker: SlotData.DuplicateSlots = .empty;
    defer duplicate_slots_tracker.deinit(allocator);

    var purge_repair_slot_counter: SlotData.PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    var duplicate_confirmed_slots: SlotData.DuplicateConfirmedSlots = .empty;
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
        var duplicate_slots_to_repair: SlotData.DuplicateSlotsToRepair = .empty;
        defer duplicate_slots_to_repair.deinit(allocator);
        try check_slot_agrees_with_cluster.duplicateConfirmed(
            allocator,
            .noop,
            2,
            root,
            ledger.resultWriter(),
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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger = try ledger_tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const slot3_hash = slot_tracker.get(3).?.state.hash.readCopy().?;
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );
    const root = 0;

    var duplicate_slots_tracker: SlotData.DuplicateSlots = .empty;
    defer duplicate_slots_tracker.deinit(allocator);

    var duplicate_confirmed_slots: SlotData.DuplicateConfirmedSlots = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var purge_repair_slot_counter: SlotData.PurgeRepairSlotCounters = .empty;
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
        var duplicate_slots_to_repair: SlotData.DuplicateSlotsToRepair = .empty;
        defer duplicate_slots_to_repair.deinit(allocator);
        try check_slot_agrees_with_cluster.duplicateConfirmed(
            allocator,
            .noop,
            3,
            root,
            ledger.resultWriter(),
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
    slot_tracker: *SlotTracker,
    heaviest_subtree_fork_choice: *HeaviestSubtreeForkChoice,
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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = &test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger = try ledger_tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const slot3_hash = slot_tracker.get(3).?.state.hash.readCopy().?;
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );

    const root: Slot = 0;

    var duplicate_slots_tracker: SlotData.DuplicateSlots = .empty;
    defer duplicate_slots_tracker.deinit(allocator);

    var duplicate_confirmed_slots: SlotData.DuplicateConfirmedSlots = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var epoch_slots_frozen_slots: SlotData.EpochSlotsFrozenSlots = .empty;
    defer epoch_slots_frozen_slots.deinit(allocator);

    var duplicate_slots_to_repair: SlotData.DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var purge_repair_slot_counter: SlotData.PurgeRepairSlotCounters = .empty;
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
        ledger.resultWriter(),
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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = &test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger = try ledger_tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const slot3_hash = slot_tracker.get(3).?.state.hash.readCopy().?;
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );

    const root: Slot = 0;

    var duplicate_slots_tracker: SlotData.DuplicateSlots = .empty;
    defer duplicate_slots_tracker.deinit(allocator);

    var duplicate_confirmed_slots: SlotData.DuplicateConfirmedSlots = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var epoch_slots_frozen_slots: SlotData.EpochSlotsFrozenSlots = .empty;
    defer epoch_slots_frozen_slots.deinit(allocator);

    var duplicate_slots_to_repair: SlotData.DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var purge_repair_slot_counter: SlotData.PurgeRepairSlotCounters = .empty;
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
        ledger.resultWriter(),
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

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = &test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger = try ledger_tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const slot3_hash = slot_tracker.get(3).?.state.hash.readCopy().?;
    try std.testing.expectEqual(
        sig.core.hash.SlotAndHash{ .slot = 3, .hash = slot3_hash },
        heaviest_subtree_fork_choice.heaviestOverallSlot(),
    );

    const root: Slot = 0;

    var duplicate_slots_tracker: SlotData.DuplicateSlots = .empty;
    defer duplicate_slots_tracker.deinit(allocator);

    var duplicate_confirmed_slots: SlotData.DuplicateConfirmedSlots = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var epoch_slots_frozen_slots: SlotData.EpochSlotsFrozenSlots = .empty;
    defer epoch_slots_frozen_slots.deinit(allocator);

    var duplicate_slots_to_repair: SlotData.DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var purge_repair_slot_counter: SlotData.PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    // Mark 3 as only epoch slots frozen with different hash than the our
    // locally replayed `slot3_hash`. This should not duplicate confirm the slot,
    // but should add the epoch slots frozen hash to the repair set
    const mismatched_hash: Hash = .initRandom(random);
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
        ledger.resultWriter(),
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

test "processDuplicateConfirmedSlots with dead slot" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = &test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger = try ledger_tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var duplicate_confirmed_slots: SlotData.DuplicateConfirmedSlots = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var duplicate_slots_to_repair: SlotData.DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var purge_repair_slot_counter: SlotData.PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    var ancestor_hashes_replay_update_channel: sig.sync.Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_update_channel.deinit();

    // Mark slot 2 as dead
    progress.getForkProgress(2).?.is_dead = true;

    const slot2_hash = slot_tracker.get(2).?.state.hash.readCopy().?;

    // Process the duplicate confirmed slot
    try processDuplicateConfirmedSlots(
        allocator,
        .noop,
        &.{.{ .slot = 2, .hash = slot2_hash }},
        ledger.resultWriter(),
        &duplicate_confirmed_slots,
        slot_tracker,
        progress,
        heaviest_subtree_fork_choice,
        &duplicate_slots_to_repair,
        &ancestor_hashes_replay_update_channel,
        &purge_repair_slot_counter,
    );

    // Verify the dead slot was processed
    try std.testing.expectEqual(
        AncestorHashesReplayUpdate{ .dead_duplicate_confirmed = 2 },
        ancestor_hashes_replay_update_channel.tryReceive(),
    );
}

test "processDuplicateConfirmedSlots with non dead slot in tracker" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = &test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger = try ledger_tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var duplicate_confirmed_slots: SlotData.DuplicateConfirmedSlots = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var duplicate_slots_to_repair: SlotData.DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var purge_repair_slot_counter: SlotData.PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    var ancestor_hashes_replay_update_channel: sig.sync.Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_update_channel.deinit();

    // Slot 2 is in the tracker and not dead
    const slot2_hash = slot_tracker.get(2).?.state.hash.readCopy().?;

    // Process the duplicate confirmed slot
    try processDuplicateConfirmedSlots(
        allocator,
        .noop,
        &.{.{ .slot = 2, .hash = slot2_hash }},
        ledger.resultWriter(),
        &duplicate_confirmed_slots,
        slot_tracker,
        progress,
        heaviest_subtree_fork_choice,
        &duplicate_slots_to_repair,
        &ancestor_hashes_replay_update_channel,
        &purge_repair_slot_counter,
    );

    // Verify the slot was recorded in duplicate_confirmed_slots
    try std.testing.expectEqual(
        slot2_hash,
        duplicate_confirmed_slots.get(2),
    );
}

test "processDuplicateConfirmedSlots with slot not in tracker" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = prng.random();

    var test_data: TestData = try .init(allocator, .noop, random);
    defer test_data.deinit(allocator);

    const slot_tracker = &test_data.slot_tracker;
    const heaviest_subtree_fork_choice = &test_data.heaviest_subtree_fork_choice;
    const progress = &test_data.progress;

    var ledger = try ledger_tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var duplicate_confirmed_slots: SlotData.DuplicateConfirmedSlots = .empty;
    defer duplicate_confirmed_slots.deinit(allocator);

    var duplicate_slots_to_repair: SlotData.DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    var purge_repair_slot_counter: SlotData.PurgeRepairSlotCounters = .empty;
    defer purge_repair_slot_counter.deinit(allocator);

    var ancestor_hashes_replay_update_channel: sig.sync.Channel(AncestorHashesReplayUpdate) =
        try .init(allocator);
    defer ancestor_hashes_replay_update_channel.deinit();

    // Use a slot that doesn't exist in the tracker (slot 100)
    // This slot is not dead and not in tracker
    const unknown_slot_hash: Hash = .initRandom(random);

    // Process the duplicate confirmed slot
    try processDuplicateConfirmedSlots(
        allocator,
        .noop,
        &.{.{ .slot = 100, .hash = unknown_slot_hash }},
        ledger.resultWriter(),
        &duplicate_confirmed_slots,
        slot_tracker,
        progress,
        heaviest_subtree_fork_choice,
        &duplicate_slots_to_repair,
        &ancestor_hashes_replay_update_channel,
        &purge_repair_slot_counter,
    );

    // Verify the slot was recorded in duplicate_confirmed_slots
    try std.testing.expectEqual(unknown_slot_hash, duplicate_confirmed_slots.get(100));
}
