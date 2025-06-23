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

const ReplayExecutionState = replay.execution.ReplayExecutionState;
const SlotTracker = replay.trackers.SlotTracker;
const EpochTracker = replay.trackers.EpochTracker;

const GossipVerifiedVoteHash = sig.consensus.vote_listener.GossipVerifiedVoteHash;
const ThresholdConfirmedSlot = sig.consensus.vote_listener.ThresholdConfirmedSlot;
const LatestValidatorVotesForFrozenBanks =
    sig.consensus.unimplemented.LatestValidatorVotesForFrozenBanks;

/// Number of threads to use in replay's thread pool
const NUM_THREADS = 4;

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

const DuplicateSlotsToRepair = std.AutoArrayHashMapUnmanaged(sig.core.Slot, sig.core.Hash);
const DuplicateSlotsTracker = SortedMapStub(sig.core.Slot, void);
const EpochSlotsFrozenSlots = SortedMapStub(sig.core.Slot, sig.core.Hash);
const DuplicateConfirmedSlots = SortedMapStub(sig.core.Slot, sig.core.Hash);

const PurgeRepairSlotCounter = SortedMapStub(sig.core.Slot, usize);

fn SortedMapStub(comptime K: type, comptime V: type) type {
    return struct {
        /// Should be replaced with a sorted data structure or something at some point.
        sorted_map: SortedMap,

        const SortedMap = std.AutoArrayHashMapUnmanaged(K, V);

        pub const empty: SortedMapStub(K, V) = .{ .sorted_map = .empty };

        /// Use before accessing `sorted_map` in a way where it's expected to be sorted.
        pub fn sort(self: *PurgeRepairSlotCounter) void {
            const sort_ctx: SortCtx = .{ .sorted_map = &self.sorted_map };
            self.sorted_map.sort(sort_ctx);
        }

        const SortCtx = struct {
            sorted_map: *const SortedMap,
            pub fn lessThan(self: @This(), a_idx: usize, b_idx: usize) bool {
                const keys = self.sorted_map.keys();
                return keys[a_idx] < keys[b_idx];
            }
        };
    };
}

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

pub const BankStatus = union(enum) {
    frozen: sig.core.Hash,
    dead,
    unprocessed,

    pub const Init = union(enum) {
        is_dead,
        hash: ?sig.core.Hash,
    };

    /// Instead of taking two callbacks `is_dead` and `get_hash`,
    /// just re-construct the logic more simply at the callsite:
    /// ```zig
    /// const bank_status: BankStatus = .init(if (is_dead()) .is_dead else .{ .hash = get_hash() });
    /// ```
    /// The agave equivalent being:
    /// ```rust
    /// const bank_status = BankStatus::init(|| is_dead(), || get_hash());
    /// ```
    /// With the `is_dead` and `get_hash` often being passed as callback parameters
    /// to higher level functions, which are then used internally to construct the BankStatus.
    pub fn init(param: Init) BankStatus {
        return switch (param) {
            .is_dead => .dead,
            .hash => |maybe_hash| .fromHash(maybe_hash),
        };
    }

    /// Returns `.frozen` or `.unprocessed`.
    pub fn fromHash(maybe_hash: ?sig.core.Hash) BankStatus {
        if (maybe_hash) |hash| {
            if (hash.eql(.ZEROES)) {
                return .unprocessed;
            } else {
                return .{ .frozen = hash };
            }
        } else {
            return .unprocessed;
        }
    }

    fn bankHash(self: BankStatus) ?sig.core.Hash {
        return switch (self) {
            .frozen => |hash| hash,
            .dead => null,
            .unprocessed => null,
        };
    }
};

const BankFrozenState = struct {
    frozen_hash: sig.core.Hash,
    cluster_confirmed_hash: ?ClusterConfirmedHash,
    is_slot_duplicate: bool,

    pub fn fromState(
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        frozen_hash: sig.core.Hash,
        duplicate_slots_tracker: *const DuplicateSlotsTracker,
        duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
        fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
        epoch_slots_frozen_slots: *const EpochSlotsFrozenSlots,
    ) BankFrozenState {
        const cluster_confirmed_hash = getClusterConfirmedHashFromState(
            logger,
            slot,
            duplicate_confirmed_slots,
            epoch_slots_frozen_slots,
            fork_choice,
            frozen_hash,
        );
        const is_slot_duplicate = duplicate_slots_tracker.sorted_map.contains(slot);
        return .{
            .frozen_hash = frozen_hash,
            .cluster_confirmed_hash = cluster_confirmed_hash,
            .is_slot_duplicate = is_slot_duplicate,
        };
    }
};

pub const DuplicateConfirmedState = struct {
    duplicate_confirmed_hash: sig.core.Hash,
    bank_status: BankStatus,
};

pub const DeadState = struct {
    cluster_confirmed_hash: ?ClusterConfirmedHash,
    is_slot_duplicate: bool,

    pub fn fromState(
        slot: sig.core.Slot,
        duplicate_slots_tracker: *const DuplicateSlotsTracker,
        duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
        fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
        epoch_slots_frozen_slots: *const EpochSlotsFrozenSlots,
    ) DeadState {
        _ = slot; // autofix
        _ = duplicate_slots_tracker; // autofix
        _ = duplicate_confirmed_slots; // autofix
        _ = fork_choice; // autofix
        _ = epoch_slots_frozen_slots; // autofix
    }
};

pub const DuplicateState = struct {
    duplicate_confirmed_hash: ?sig.core.Hash,
    bank_status: BankStatus,

    pub fn fromState(
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
        fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
        bank_status: BankStatus,
    ) DuplicateState {
        // We can only skip marking duplicate if this slot has already been
        // duplicate confirmed, any weaker confirmation levels are not sufficient
        // to skip marking the slot as duplicate.
        const duplicate_confirmed_hash = getDuplicateConfirmedHashFromState(
            logger,
            slot,
            duplicate_confirmed_slots,
            fork_choice,
            bank_status.bankHash(),
        );
        return .{
            .duplicate_confirmed_hash = duplicate_confirmed_hash,
            .bank_status = bank_status,
        };
    }
};

pub const EpochSlotsFrozenState = struct {
    epoch_slots_frozen_hash: sig.core.Hash,
    duplicate_confirmed_hash: ?sig.core.Hash,
    bank_status: BankStatus,
    is_popular_pruned: bool,

    pub fn fromState(
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        epoch_slots_frozen_hash: sig.core.Hash,
        duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
        fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
        bank_status: BankStatus,
        is_popular_pruned: bool,
    ) EpochSlotsFrozenState {
        const duplicate_confirmed_hash = getDuplicateConfirmedHashFromState(
            logger,
            slot,
            duplicate_confirmed_slots,
            fork_choice,
            bank_status.bankHash(),
        );
        return .{
            .epoch_slots_frozen_hash = epoch_slots_frozen_hash,
            .duplicate_confirmed_hash = duplicate_confirmed_hash,
            .bank_status = bank_status,
            .is_popular_pruned = is_popular_pruned,
        };
    }
};

fn processAncestorHashesDuplicateSlots(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    pubkey: sig.core.Pubkey,
    ancestor_duplicate_slots_receiver: *sig.sync.Channel(AncestorDuplicateSlotToRepair),
    duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
    epoch_slots_frozen_slots: *EpochSlotsFrozenSlots,
    progress: *const sig.consensus.ProgressMap,
    fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
    bank_forks_rwmux: *sig.sync.RwMux(sig.replay.trackers.SlotTracker),
    duplicate_slots_to_repair: *DuplicateSlotsToRepair,
) !void {
    const root = root: {
        const bank_forks, var bank_forks_lg = bank_forks_rwmux.readWithLock();
        defer bank_forks_lg.unlock();
        break :root bank_forks.root;
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

        const bank_status: BankStatus = .init(
            if (progress.isDead(epoch_slots_frozen_slot) orelse false)
                .is_dead
            else
                .{ .hash = hash: {
                    const bank_forks, var bank_forks_lg = bank_forks_rwmux.readWithLock();
                    defer bank_forks_lg.unlock();

                    const bank = bank_forks.slots.get(epoch_slots_frozen_slot) orelse
                        break :hash null;
                    const hash_ptr, var hash_lg = bank.state.hash.readWithLock();
                    defer hash_lg.unlock();
                    break :hash hash_ptr.*;
                } },
        );

        const epoch_slots_frozen_state: EpochSlotsFrozenState = .fromState(
            logger,
            epoch_slots_frozen_slot,
            epoch_slots_frozen_hash,
            duplicate_confirmed_slots,
            fork_choice,
            bank_status,
            request_type == .popular_pruned,
        );
        try check_slot_agrees_with_cluster.epochSlotsFrozen(
            allocator,
            logger,
            epoch_slots_frozen_slot,
            root,
            epoch_slots_frozen_slots,
            fork_choice,
            duplicate_slots_to_repair,
            epoch_slots_frozen_state,
        );
    }
}

/// Check for any newly duplicate confirmed slots by the cluster.
/// This only tracks duplicate slot confirmations on the exact
/// single slots and does not account for votes on their descendants. Used solely
/// for duplicate slot recovery.
fn processDuplicateConfirmedSlots(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    duplicate_confirmed_slots_receiver: *sig.sync.Channel(ThresholdConfirmedSlot),
    blockstore: *sig.ledger.LedgerResultWriter,
    duplicate_confirmed_slots: *DuplicateConfirmedSlots,
    bank_forks_rwmux: *sig.sync.RwMux(sig.replay.trackers.SlotTracker),
    progress: *const sig.consensus.ProgressMap,
    fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
    duplicate_slots_to_repair: *DuplicateSlotsToRepair,
    ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
    purge_repair_slot_counter: *PurgeRepairSlotCounter,
) !void {
    const root = root: {
        const bank_forks, var bank_forks_lg = bank_forks_rwmux.readWithLock();
        defer bank_forks_lg.unlock();
        break :root bank_forks.root;
    };
    while (duplicate_confirmed_slots_receiver.tryReceive()) |new_duplicate_confirmed_slot| {
        const confirmed_slot, const duplicate_confirmed_hash = new_duplicate_confirmed_slot;
        if (confirmed_slot <= root) {
            continue;
        } else if (try duplicate_confirmed_slots.sorted_map.fetchPut(
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
            .bank_status = .init(
                if (progress.isDead(confirmed_slot) orelse false)
                    .is_dead
                else
                    .{ .hash = hash: {
                        const bank_forks, var bank_forks_lg = bank_forks_rwmux.readWithLock();
                        defer bank_forks_lg.unlock();
                        const bf_elem = bank_forks.slots.get(confirmed_slot).?;
                        const bf_hash, var bf_hash_lg = bf_elem.state.hash.readWithLock();
                        defer bf_hash_lg.unlock();
                        break :hash bf_hash.*;
                    } },
            ),
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
    votes_per_slot: SortedMapStub(sig.core.Slot, HashToVotesMap),

    const HashToVotesMap = std.AutoArrayHashMapUnmanaged(sig.core.Hash, VoteList);
    const VoteList = std.ArrayListUnmanaged(sig.core.Pubkey);

    /// Update `latest_validator_votes_for_frozen_banks` if gossip has seen a newer vote
    /// for a frozen bank.
    pub fn addVote(
        self: *UnfrozenGossipVerifiedVoteHashes,
        allocator: std.mem.Allocator,
        pubkey: sig.core.Pubkey,
        vote_slot: sig.core.Slot,
        hash: sig.core.Hash,
        is_frozen: bool,
        latest_validator_votes_for_frozen_banks: *LatestValidatorVotesForFrozenBanks,
    ) !void {
        // If this is a frozen bank, then we need to update the `latest_validator_votes_for_frozen_banks`
        const frozen_hash = if (is_frozen) hash else null;
        const was_added, const maybe_latest_frozen_vote_slot =
            latest_validator_votes_for_frozen_banks.checkAddVote(
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
            const vps_gop = try self.votes_per_slot.sorted_map.getOrPut(allocator, vote_slot);
            errdefer if (!vps_gop.found_existing) {
                std.debug.assert(self.votes_per_slot.sorted_map.orderedRemove(vps_gop.key_ptr.*));
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

fn processGossipVerifiedVoteHashes(
    allocator: std.mem.Allocator,
    gossip_verified_vote_hash_receiver: *sig.sync.Channel(GossipVerifiedVoteHash),
    unfrozen_gossip_verified_vote_hashes: *UnfrozenGossipVerifiedVoteHashes,
    heaviest_subtree_fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
    latest_validator_votes_for_frozen_banks: *LatestValidatorVotesForFrozenBanks,
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
            latest_validator_votes_for_frozen_banks,
        );
    }
}

fn processPopularPrunedForks(
    logger: sig.trace.Logger,
    popular_pruned_forks_receiver: *sig.sync.Channel(sig.core.Slot),
    bank_forks_rwmux: *sig.sync.RwMux(sig.replay.trackers.SlotTracker),
    ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
) void {
    const root = root: {
        const bank_forks, var bank_forks_lg = bank_forks_rwmux.readWithLock();
        defer bank_forks_lg.unlock();
        break :root bank_forks.root;
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
fn processDuplicateSlots(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    duplicate_slots_receiver: *sig.sync.Channel(sig.core.Slot),
    duplicate_slots_tracker: *DuplicateSlotsTracker,
    duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
    bank_forks_rwmux: *sig.sync.RwMux(sig.replay.trackers.SlotTracker),
    progress: *const sig.consensus.ProgressMap,
    fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
) !void {
    const MAX_BATCH_SIZE = 1024;

    var new_duplicate_slots: std.BoundedArray(sig.core.Slot, MAX_BATCH_SIZE) = .{};
    while (new_duplicate_slots.unusedCapacitySlice().len != 0) {
        const new_duplicate_slot = duplicate_slots_receiver.tryReceive() orelse break;
        new_duplicate_slots.appendAssumeCapacity(new_duplicate_slot);
    }

    const root_slot, const bank_hashes = blk: {
        const r_bank_forks, var bank_forks_lg = bank_forks_rwmux.readWithLock();
        defer bank_forks_lg.unlock();

        var bank_hashes: std.BoundedArray(?sig.core.Hash, MAX_BATCH_SIZE) = .{};
        for (new_duplicate_slots.constSlice()) |duplicate_slot| {
            bank_hashes.appendAssumeCapacity(hash: {
                const bf_elem = r_bank_forks.slots.get(duplicate_slot) orelse break :hash null;
                const hash, var hash_lg = bf_elem.state.hash.readWithLock();
                defer hash_lg.unlock();
                break :hash hash.*;
            });
        }

        break :blk .{ r_bank_forks.root, bank_hashes };
    };
    for (new_duplicate_slots.constSlice(), bank_hashes.constSlice()) |duplicate_slot, bank_hash| {
        // WindowService should only send the signal once per slot
        const duplicate_state: DuplicateState = .fromState(
            logger,
            duplicate_slot,
            duplicate_confirmed_slots,
            fork_choice,
            .init(if (progress.isDead(duplicate_slot) orelse false)
                .is_dead
            else
                .{ .hash = bank_hash }),
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
    maybe_bank_frozen_hash: ?sig.core.Hash,
) ?ClusterConfirmedHash {
    const duplicate_confirmed_hash = duplicate_confirmed_slots.sorted_map.get(slot);
    // If the bank hasn't been frozen yet, then we haven't duplicate confirmed a local version
    // this slot through replay yet.
    const is_local_replay_duplicate_confirmed = if (maybe_bank_frozen_hash) |bank_frozen_hash|
        fork_choice.isDuplicateConfirmed(&.{ .slot = slot, .hash = bank_frozen_hash }) orelse false
    else
        false;

    if (getDuplicateConfirmedHash(
        logger,
        slot,
        duplicate_confirmed_hash,
        maybe_bank_frozen_hash,
        is_local_replay_duplicate_confirmed,
    )) |hash| return .{
        .kind = .duplicate_confirmed,
        .hash = hash,
    };
    const hash = epoch_slots_frozen_slots.sorted_map.get(slot) orelse return null;
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
    maybe_bank_frozen_hash: ?sig.core.Hash,
) ?sig.core.Hash {
    const duplicate_confirmed_hash = duplicate_confirmed_slots.sorted_map.get(slot);
    // If the bank hasn't been frozen yet, then we haven't duplicate confirmed a local version
    // this slot through replay yet.
    const is_local_replay_duplicate_confirmed = if (maybe_bank_frozen_hash) |bank_frozen_hash|
        fork_choice.isDuplicateConfirmed(&.{ .slot = slot, .hash = bank_frozen_hash }) orelse false
    else
        false;

    return getDuplicateConfirmedHash(
        logger,
        slot,
        duplicate_confirmed_hash,
        maybe_bank_frozen_hash,
        is_local_replay_duplicate_confirmed,
    );
}

/// Finds the duplicate confirmed hash for a slot.
///
/// 1) If `is_local_replay_duplicate_confirmed`, return Some(local frozen hash)
/// 2) If we have a `duplicate_confirmed_hash`, return Some(duplicate_confirmed_hash)
/// 3) Else return None
///
/// Assumes that if `is_local_replay_duplicate_confirmed`, `bank_frozen_hash` is not None
fn getDuplicateConfirmedHash(
    logger: sig.trace.Logger,
    slot: sig.core.Slot,
    maybe_duplicate_confirmed_hash: ?sig.core.Hash,
    maybe_bank_frozen_hash: ?sig.core.Hash,
    is_local_replay_duplicate_confirmed: bool,
) ?sig.core.Hash {
    // the following code is simply ported in order to match the logic of the equivalent match statement
    // TODO: maybe simplify all of this if possible?

    const maybe_local_duplicate_confirmed_hash = if (is_local_replay_duplicate_confirmed) blk: {
        // If local replay has duplicate_confirmed this slot, this slot must have
        // descendants with votes for this slot, hence this slot must be
        // frozen.
        break :blk maybe_bank_frozen_hash.?;
    } else null;

    if (maybe_local_duplicate_confirmed_hash) |local_duplicate_confirmed_hash| {
        if (maybe_duplicate_confirmed_hash) |duplicate_confirmed_hash| {
            if (!local_duplicate_confirmed_hash.eql(duplicate_confirmed_hash)) {
                logger.err().logf(
                    "For slot {}, the gossip duplicate confirmed hash {}, is not equal" ++
                        "to the confirmed hash we replayed: {}",
                    .{ slot, duplicate_confirmed_hash, local_duplicate_confirmed_hash },
                );
            }
            return local_duplicate_confirmed_hash;
        }
    }

    if (maybe_local_duplicate_confirmed_hash) |bank_frozen_hash| {
        std.debug.assert(maybe_duplicate_confirmed_hash == null);
        return bank_frozen_hash;
    }

    std.debug.assert(maybe_local_duplicate_confirmed_hash == null);
    return maybe_duplicate_confirmed_hash;
}

const check_slot_agrees_with_cluster = struct {
    fn bankFrozen(
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        root: sig.core.Slot,
        blockstore: *sig.ledger.LedgerResultWriter,
        fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: *DuplicateSlotsToRepair,
        purge_repair_slot_counter: *PurgeRepairSlotCounter,
        bank_frozen_state: BankFrozenState,
    ) !void {
        logger.info().logf(
            "check_slot_agrees_with_cluster() slot: {}, root: {}, slot_state_update: {}",
            .{ slot, root, bank_frozen_state },
        );

        if (slot <= root) {
            return;
        }

        const frozen_hash = bank_frozen_state.frozen_hash;
        const maybe_cluster_confirmed_hash = bank_frozen_state.cluster_confirmed_hash;
        const is_slot_duplicate = bank_frozen_state.is_slot_duplicate;

        // Handle cases where the bank is frozen, but not duplicate confirmed yet.
        var not_dupe_confirmed_frozen_hash: state_change.NotDupeConfirmedFrozenHash = .init;

        state_change.bankFrozen(
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
        purge_repair_slot_counter: *PurgeRepairSlotCounter,
        duplicate_confirmed_state: DuplicateConfirmedState,
    ) !void {
        logger.info().logf(
            "check_slot_agrees_with_cluster() slot: {}, root: {}, slot_state_update: {}",
            .{ slot, root, duplicate_confirmed_state },
        );

        if (slot <= root) {
            return;
        }

        const bank_status = duplicate_confirmed_state.bank_status;
        const duplicate_confirmed_hash = duplicate_confirmed_state.duplicate_confirmed_hash;

        // Avoid duplicate work from multiple of the same DuplicateConfirmed signal. This can
        // happen if we get duplicate confirmed from gossip and from local replay.
        // if let Some(bank_hash) = bank_status.bank_hash() {
        if (bank_status.bankHash()) |bank_hash| {
            if (fork_choice.isDuplicateConfirmed(&.{ .slot = slot, .hash = bank_hash }) == true) {
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

        // Handle cases where the bank is frozen, but not duplicate confirmed yet.
        var not_dupe_confirmed_frozen_hash: state_change.NotDupeConfirmedFrozenHash = .init;

        switch (bank_status) {
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
        duplicate_slots_tracker: *DuplicateSlotsTracker,
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

        // Needs to happen before the bank_frozen_hash.is_none() check below to account for duplicate
        // signals arriving before the bank is constructed in replay.
        if (try duplicate_slots_tracker.sorted_map.fetchPut(allocator, slot, {})) |_| {
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

        const bank_status = duplicate_state.bank_status;
        const duplicate_confirmed_hash = duplicate_state.duplicate_confirmed_hash;

        switch (bank_status) {
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
            if (bank_status.bankHash()) |bank_hash| {
                try state_change.markSlotDuplicate(slot, fork_choice, bank_hash);
            }
        }
    }

    fn epochSlotsFrozen(
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        root: sig.core.Slot,
        epoch_slots_frozen_slots: *EpochSlotsFrozenSlots,
        fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: *DuplicateSlotsToRepair,
        epoch_slots_frozen_state: EpochSlotsFrozenState,
    ) !void {
        logger.info().logf(
            "check_slot_agrees_with_cluster() slot: {}, root: {}, slot_state_update: {}",
            .{ slot, root, epoch_slots_frozen_state },
        );

        if (slot <= root) {
            return;
        }

        const bank_status = epoch_slots_frozen_state.bank_status;
        const epoch_slots_frozen_hash = epoch_slots_frozen_state.epoch_slots_frozen_hash;
        const maybe_duplicate_confirmed_hash = epoch_slots_frozen_state.duplicate_confirmed_hash;
        const is_popular_pruned = epoch_slots_frozen_state.is_popular_pruned;

        if (try epoch_slots_frozen_slots.sorted_map.fetchPut(
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

        switch (bank_status) {
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
        // 1) If the bank was replayed and then duplicate confirmed through turbine/gossip, the
        //    corresponding `SlotStateUpdate::DuplicateConfirmed`
        // 2) If the slot was first duplicate confirmed through gossip and then replayed, the
        //    corresponding `SlotStateUpdate::BankFrozen` or `SlotStateUpdate::Dead`
        //
        // However if `slot` was first duplicate confirmed through gossip and then pruned before
        // we got a chance to replay, there was no trigger that would have processed `slot`.
        // The original `SlotStateUpdate::DuplicateConfirmed` is a no-op when the bank has not been
        // replayed yet, and unlike 2) there is no upcoming `SlotStateUpdate::BankFrozen` or
        // `SlotStateUpdate::Dead`, as `slot` is pruned and will not be replayed.
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

        switch (bank_status) {
            .frozen => |bank_frozen_hash| {
                if (bank_frozen_hash.eql(epoch_slots_frozen_hash)) {
                    // Matches, nothing to do
                    return;
                } else {
                    // The epoch slots hash does not match our frozen hash.
                    logger.warn().logf(
                        "EpochSlots sample returned slot {} with hash {}, " ++
                            "but our version has hash {}",
                        .{ slot, epoch_slots_frozen_hash, bank_frozen_hash },
                    );
                    if (!is_popular_pruned) {
                        // If the slot is not already pruned notify fork choice to mark as invalid
                        try state_change.markSlotDuplicate(slot, fork_choice, bank_frozen_hash);
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
                // If the bank was not popular pruned, we would never have made it here, as the bank is
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

    fn bankFrozen(
        slot: u64,
        fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
        not_dupe_confirmed_frozen_hash: *NotDupeConfirmedFrozenHash,
        bank_frozen_hash: sig.core.Hash,
    ) void {
        const is_duplicate_confirmed = fork_choice
            .isDuplicateConfirmed(&.{ .slot = slot, .hash = bank_frozen_hash }) orelse
            std.debug.panic("frozen bank must exist in fork choice", .{});
        if (!is_duplicate_confirmed) {
            not_dupe_confirmed_frozen_hash.update(bank_frozen_hash);
        }
    }

    fn markSlotDuplicate(
        slot: u64,
        fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
        bank_frozen_hash: sig.core.Hash,
    ) !void {
        try fork_choice.markForkInvalidCandidate(&.{ .slot = slot, .hash = bank_frozen_hash });
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
        purge_repair_slot_counter: *PurgeRepairSlotCounter,
        not_dupe_confirmed_frozen_hash: *NotDupeConfirmedFrozenHash,
        bank_frozen_hash: sig.core.Hash,
    ) !void {
        not_dupe_confirmed_frozen_hash.update(null);
        // When we detect that our frozen slot matches the cluster version (note this
        // will catch both bank frozen first -> confirmation, or confirmation first ->
        // bank frozen), mark all the newly duplicate confirmed slots in blockstore
        const new_duplicate_confirmed_slot_hashes = try fork_choice.markForkValidCandidate(&.{
            .slot = slot,
            .hash = bank_frozen_hash,
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
        _ = purge_repair_slot_counter.sorted_map.orderedRemove(slot);
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

const Descendants = std.AutoArrayHashMapUnmanaged(sig.core.Slot, SortedMapStub(sig.core.Slot, void));

fn testSetup(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    random: std.Random,
) !struct {
    sig.replay.trackers.SlotTracker,
    sig.consensus.HeaviestSubtreeForkChoice,
    Descendants,
} {
    const SlotInfo = struct {
        parent_slot: ?sig.core.Slot,
        slot: sig.core.Slot,
        hash: sig.core.Hash,

        fn initRandom(
            parent_slot: ?sig.core.Slot,
            slot: sig.core.Slot,
            _random: std.Random,
        ) @This() {
            return .{
                .parent_slot = parent_slot,
                .slot = slot,
                .hash = .initRandom(_random),
            };
        }
    };

    const slot_infos = [_]SlotInfo{
        .initRandom(null, 0, random),
        .initRandom(0, 1, random),
        .initRandom(1, 2, random),
        .initRandom(2, 3, random),
    };

    var bank_forks: sig.replay.trackers.SlotTracker = .init(0);
    errdefer bank_forks.deinit(allocator);

    var fork_choice: sig.consensus.HeaviestSubtreeForkChoice = try .init(allocator, logger, .{
        .slot = 0,
        .hash = try .parseBase58String("Ck2ViMTVdaFQAmaSnE3zKzmBsaaWD2jvduRZmev89VXq"),
    });
    errdefer fork_choice.deinit();

    for (slot_infos) |slot_info| {
        try fork_choice.addNewLeafSlot(
            .{ .slot = slot_info.slot, .hash = slot_info.hash },
            if (slot_info.parent_slot) |parent_slot| .{
                .slot = parent_slot,
                .hash = slot_infos[parent_slot].hash,
            } else null,
        );

        try bank_forks.put(
            allocator,
            slot_info.slot,
            .{
                .parent_slot = slot_info.parent_slot orelse (slot_info.slot -| 1),
                .parent_hash = slot_infos[slot_info.parent_slot orelse (slot_info.slot -| 1)].hash,
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
    errdefer for (descendants.values()) |*child_set| child_set.sorted_map.deinit(allocator);
    try descendants.ensureUnusedCapacity(allocator, 4);
    descendants.putAssumeCapacity(0, .{ .sorted_map = try .init(allocator, &.{ 1, 2, 3 }, &.{}) });
    descendants.putAssumeCapacity(1, .{ .sorted_map = try .init(allocator, &.{ 3, 2 }, &.{}) });
    descendants.putAssumeCapacity(2, .{ .sorted_map = try .init(allocator, &.{3}, &.{}) });
    descendants.putAssumeCapacity(3, .empty);

    return .{ bank_forks, fork_choice, descendants };
}

test "apply state changes" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(7353);
    const random = prng.random();

    // Common state
    var bank_forks, //
    var heaviest_subtree_fork_choice, //
    var descendants: Descendants //
    = try testSetup(allocator, .noop, random);
    defer bank_forks.deinit(allocator);
    defer heaviest_subtree_fork_choice.deinit();
    defer {
        for (descendants.values()) |*child_set| child_set.sorted_map.deinit(allocator);
        descendants.deinit(allocator);
    }

    var duplicate_slots_to_repair: DuplicateSlotsToRepair = .empty;
    defer duplicate_slots_to_repair.deinit(allocator);

    // MarkSlotDuplicate should mark progress map and remove
    // the slot from fork choice
    const duplicate_slot = bank_forks.root + 1;
    const duplicate_slot_hash = hash: {
        const hash, var hash_lg = bank_forks.slots.get(duplicate_slot).?.state.hash.readWithLock();
        defer hash_lg.unlock();
        break :hash hash.*.?;
    };
    try state_change.markSlotDuplicate(
        duplicate_slot,
        &heaviest_subtree_fork_choice,
        duplicate_slot_hash,
    );
    try std.testing.expect(!heaviest_subtree_fork_choice.isCandidate(&.{
        .slot = duplicate_slot,
        .hash = duplicate_slot_hash,
    }).?);
    for ([_][]const sig.core.Slot{
        descendants.get(duplicate_slot).?.sorted_map.keys(),
        &.{duplicate_slot},
    }) |child_slot_set| {
        for (child_slot_set) |child_slot| {
            try std.testing.expectEqual(
                duplicate_slot,
                heaviest_subtree_fork_choice.latestInvalidAncestor(&.{
                    .slot = child_slot,
                    .hash = hash: {
                        const hash, var hash_lg =
                            bank_forks.slots.get(child_slot).?.state.hash.readWithLock();
                        defer hash_lg.unlock();
                        break :hash hash.*.?;
                    },
                }).?,
            );
        }
    }
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
        duplicate_slots_to_repair.get(duplicate_slot).?,
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
