const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const Allocator = std.mem.Allocator;

const ThreadPool = sig.sync.ThreadPool;

const AccountsDB = sig.accounts_db.AccountsDB;
const BlockstoreReader = sig.ledger.BlockstoreReader;

const ScopedLogger = sig.trace.ScopedLogger("replay");

/// Number of threads to use in replay's thread pool
const NUM_THREADS = 4;

pub const ReplayDependencies = struct {
    /// Used for all allocations within the replay stage
    allocator: Allocator,
    logger: sig.trace.Logger,
    /// Tell replay when to exit
    exit: *std.atomic.Value(bool),
    /// Used in the EpochManager
    epoch_schedule: sig.core.EpochSchedule,
    /// Used to get the entries to validate them and execute the transactions
    blockstore_reader: *BlockstoreReader,
    /// Used to get the entries to validate them and execute the transactions
    accounts_db: *AccountsDB,
};

const ReplayState = struct {
    allocator: Allocator,
    logger: ScopedLogger,
    thread_pool: *ThreadPool,
    execution: ReplayExecutionState,

    fn init(deps: ReplayDependencies) Allocator.Error!ReplayState {
        const thread_pool = try deps.allocator.create(ThreadPool);
        errdefer deps.allocator.destroy(thread_pool);
        thread_pool.* = ThreadPool.init(.{ .max_threads = NUM_THREADS });

        return .{
            .allocator = deps.allocator,
            .logger = ScopedLogger.from(deps.logger),
            .thread_pool = thread_pool,
            .execution = try ReplayExecutionState.init(
                deps.allocator,
                deps.logger,
                thread_pool,
                deps.epoch_schedule,
                deps.accounts_db,
                deps.blockstore_reader,
            ),
        };
    }

    fn deinit(self: *ReplayState) void {
        self.execution.deinit();
        self.thread_pool.shutdown();
        self.thread_pool.deinit();
        self.allocator.destroy(self.thread_pool);
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
    _ = state; // autofix

    // TODO: generate_new_bank_forks

    // TODO: replay_active_banks
    // _ = try replay.execution.replayActiveSlots(&state.execution);
    std.time.sleep(100 * std.time.ns_per_ms);

    handleEdgeCases();

    processConsensus();

    // TODO: dump_then_repair_correct_slots

    // TODO: maybe_start_leader
}

// -- handleEdgeCases START -- //
fn handleEdgeCases() void {
    _ = &process_ancestor_hashes_duplicate_slots; // TODO:

    // TODO: process_duplicate_confirmed_slots

    // TODO: process_gossip_verified_vote_hashes

    // TODO: process_popular_pruned_forks

    // TODO: process_duplicate_slots
}

const DuplicateSlotsToRepair = std.AutoArrayHashMapUnmanaged(sig.core.Slot, sig.core.Hash);
const DuplicateSlotsTracker = SortedMapStub(sig.core.Slot, void);
const EpochSlotsFrozenSlots = SortedMapStub(sig.core.Slot, sig.core.Hash);
const DuplicateConfirmedSlots = SortedMapStub(sig.core.Slot, sig.core.Hash);

const NotDuplicateConfirmedFrozenHash = ?sig.core.Hash;
const PurgeRepairSlotCounter = SortedMapStub(sig.core.Slot, usize);

fn SortedMapStub(comptime K: type, comptime V: type) type {
    return struct {
        /// Should be replaced with a sorted data structure or something at some point.
        sorted_map: SortedMap,

        const SortedMap = std.AutoArrayHashMapUnmanaged(K, V);

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

fn process_ancestor_hashes_duplicate_slots(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    pubkey: sig.core.Pubkey,
    // blockstore: *const sig.ledger.LedgerResultWriter,
    ancestor_duplicate_slots_receiver: *sig.sync.Channel(AncestorDuplicateSlotToRepair),
    // duplicate_slots_tracker: *DuplicateSlotsTracker,
    duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
    epoch_slots_frozen_slots: *EpochSlotsFrozenSlots,
    progress: *const sig.consensus.ProgressMap,
    fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
    bank_forks_rwmux: *sig.sync.RwMux(sig.replay.trackers.SlotTracker),
    duplicate_slots_to_repair: *DuplicateSlotsToRepair,
    // ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
    // purge_repair_slot_counter: *PurgeRepairSlotCounter,
) !void {
    // const root, var root_lg = bank_forks.readWithLock();
    // defer root_lg.unlock();
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
            if (progress.isDead(epoch_slots_frozen_slot) orelse false) .is_dead else .{
                .hash = hash: {
                    const bank_forks, var bank_forks_lg = bank_forks_rwmux.readWithLock();
                    defer bank_forks_lg.unlock();

                    const bank = bank_forks.slots.getPtr(epoch_slots_frozen_slot) orelse break :hash null;
                    const hash_ptr, var hash_lg = bank.state.hash.readWithLock();
                    defer hash_lg.unlock();
                    break :hash hash_ptr.*;
                },
            },
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
        try check_slot_agrees_with_cluster_.epoch_slots_frozen(
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

pub const BankFrozenState = struct {
    frozen_hash: sig.core.Hash,
    cluster_confirmed_hash: ?ClusterConfirmedHash,
    is_slot_duplicate: bool,

    pub fn fromState(
        slot: sig.core.Slot,
        frozen_hash: sig.core.Hash,
        duplicate_slots_tracker: *const DuplicateSlotsTracker,
        duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
        fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
        epoch_slots_frozen_slots: *const EpochSlotsFrozenSlots,
    ) BankFrozenState {
        _ = slot; // autofix
        _ = frozen_hash; // autofix
        _ = duplicate_slots_tracker; // autofix
        _ = duplicate_confirmed_slots; // autofix
        _ = fork_choice; // autofix
        _ = epoch_slots_frozen_slots; // autofix
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
        slot: sig.core.Slot,
        duplicate_confirmed_slots: *const DuplicateConfirmedSlots,
        fork_choice: *const sig.consensus.HeaviestSubtreeForkChoice,
        bank_status: BankStatus,
    ) DuplicateState {
        _ = slot; // autofix
        _ = duplicate_confirmed_slots; // autofix
        _ = fork_choice; // autofix
        _ = bank_status; // autofix
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
        const duplicate_confirmed_hash = get_duplicate_confirmed_hash_from_state(
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

fn get_duplicate_confirmed_hash_from_state(
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

    return get_duplicate_confirmed_hash(
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
fn get_duplicate_confirmed_hash(
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

pub const SlotStateUpdate = union(enum) {
    bank_frozen: BankFrozenState,
    duplicate_confirmed: DuplicateConfirmedState,
    dead: DeadState,
    duplicate: DuplicateState,
    epoch_slots_frozen: EpochSlotsFrozenState,
    /// The fork is pruned but has reached `DUPLICATE_THRESHOLD` from votes aggregated across
    /// descendants and all versions of the slots on this fork.
    popular_pruned_fork,
};

pub fn check_slot_agrees_with_cluster(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    slot: sig.core.Slot,
    root: sig.core.Slot,
    blockstore: *const sig.ledger.LedgerResultWriter,
    duplicate_slots_tracker: *DuplicateSlotsTracker,
    epoch_slots_frozen_slots: *EpochSlotsFrozenSlots,
    fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
    duplicate_slots_to_repair: *DuplicateSlotsToRepair,
    ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
    purge_repair_slot_counter: *PurgeRepairSlotCounter,
    slot_state_update: SlotStateUpdate,
) !void {
    switch (slot_state_update) {
        .bank_frozen => |bank_frozen_state| {
            try check_slot_agrees_with_cluster_.bank_frozen(
                allocator,
                logger,
                slot,
                root,
                blockstore,
                fork_choice,
                duplicate_slots_to_repair,
                purge_repair_slot_counter,
                bank_frozen_state,
            );
        },
        .duplicate_confirmed => |duplicate_confirmed_state| {
            try check_slot_agrees_with_cluster_.duplicate_confirmed(
                allocator,
                logger,
                slot,
                root,
                blockstore,
                fork_choice,
                duplicate_slots_to_repair,
                ancestor_hashes_replay_update_sender,
                purge_repair_slot_counter,
                duplicate_confirmed_state,
            );
        },
        .dead => |dead_state| {
            try check_slot_agrees_with_cluster_.dead(
                allocator,
                logger,
                slot,
                root,
                duplicate_slots_to_repair,
                ancestor_hashes_replay_update_sender,
                dead_state,
            );
        },
        .duplicate => |duplicate_state| {
            try check_slot_agrees_with_cluster_.duplicate(
                allocator,
                logger,
                slot,
                root,
                duplicate_slots_tracker,
                fork_choice,
                duplicate_state,
            );
        },
        .epoch_slots_frozen => |epoch_slots_frozen_state| {
            try check_slot_agrees_with_cluster_.epoch_slots_frozen(
                allocator,
                logger,
                slot,
                root,
                epoch_slots_frozen_slots,
                fork_choice,
                duplicate_slots_to_repair,
                epoch_slots_frozen_state,
            );
        },
        .popular_pruned_fork => {
            check_slot_agrees_with_cluster_.popular_pruned_fork(
                logger,
                slot,
                root,
                ancestor_hashes_replay_update_sender,
            );
        },
    }
}

const check_slot_agrees_with_cluster_ = struct {
    fn bank_frozen(
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        root: sig.core.Slot,
        blockstore: *const sig.ledger.LedgerResultWriter,
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
        var not_duplicate_confirmed_frozen_hash: NotDuplicateConfirmedFrozenHash = null;

        resulting_change.bank_frozen(
            slot,
            fork_choice,
            &not_duplicate_confirmed_frozen_hash,
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
                        try resulting_change.duplicate_confirmed_slot_matches_cluster(
                            slot,
                            fork_choice,
                            duplicate_slots_to_repair,
                            blockstore,
                            purge_repair_slot_counter,
                            &not_duplicate_confirmed_frozen_hash,
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
                        try resulting_change.mark_slot_duplicate(slot, fork_choice, frozen_hash);
                        try resulting_change.repair_duplicate_confirmed_version(
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
                        try resulting_change.mark_slot_duplicate(slot, fork_choice, frozen_hash);
                    }
                    try resulting_change.repair_duplicate_confirmed_version(
                        slot,
                        duplicate_slots_to_repair,
                        epoch_slots_frozen_hash,
                    );
                },
            }
        } else if (is_slot_duplicate) {
            // If `cluster_confirmed_hash` is Some above we should have already pushed a
            // `MarkSlotDuplicate` state change
            resulting_change.mark_slot_duplicate(slot, fork_choice, frozen_hash);
        }

        if (not_duplicate_confirmed_frozen_hash) |ndcf_hash| {
            try blockstore.insertBankHash(slot, ndcf_hash, false);
        }
    }

    fn duplicate_confirmed(
        allocator: std.mem.Allocator,
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        root: sig.core.Slot,
        blockstore: *const sig.ledger.LedgerResultWriter,
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
        var not_duplicate_confirmed_frozen_hash: NotDuplicateConfirmedFrozenHash = null;

        switch (bank_status) {
            // No action to be taken yet
            .unprocessed => {},

            .dead => {
                resulting_change.send_ancestor_hashes_replay_update(
                    ancestor_hashes_replay_update_sender,
                    .{ .kind = .dead_duplicate_confirmed, .slot = slot },
                );

                // If the cluster duplicate confirmed some version of this slot, then
                // there's another version of our dead slot
                logger.warn().logf(
                    "Cluster duplicate confirmed slot {} with hash {}, but we marked slot dead",
                    .{ slot, duplicate_confirmed_hash },
                );
                try resulting_change.repair_duplicate_confirmed_version(
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
                    try resulting_change.duplicate_confirmed_slot_matches_cluster(
                        slot,
                        fork_choice,
                        duplicate_slots_to_repair,
                        blockstore,
                        purge_repair_slot_counter,
                        &not_duplicate_confirmed_frozen_hash,
                        *frozen_hash,
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
                    try resulting_change.mark_slot_duplicate(slot, fork_choice, *frozen_hash);
                    try resulting_change.repair_duplicate_confirmed_version(
                        slot,
                        duplicate_slots_to_repair,
                        duplicate_confirmed_hash,
                    );
                }
            },
        }

        if (not_duplicate_confirmed_frozen_hash) |ndcf_hash| {
            try blockstore.insertBankHash(slot, ndcf_hash, false);
        }
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
                    resulting_change.send_ancestor_hashes_replay_update(
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
                    try resulting_change.repair_duplicate_confirmed_version(
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
                    try resulting_change.repair_duplicate_confirmed_version(
                        slot,
                        duplicate_slots_to_repair,
                        epoch_slots_frozen_hash,
                    );
                },
            }
        } else {
            resulting_change.send_ancestor_hashes_replay_update(
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
                try resulting_change.mark_slot_duplicate(slot, fork_choice, bank_hash);
            }
        }
    }

    fn epoch_slots_frozen(
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
                        try resulting_change.mark_slot_duplicate(slot, fork_choice, bank_frozen_hash);
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

        try resulting_change.repair_duplicate_confirmed_version(
            allocator,
            slot,
            duplicate_slots_to_repair,
            epoch_slots_frozen_hash,
        );
    }

    fn popular_pruned_fork(
        logger: sig.trace.Logger,
        slot: sig.core.Slot,
        root: sig.core.Slot,
        ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
    ) void {
        logger.info().logf(
            "check_slot_agrees_with_cluster() slot: {}, root: {}, slot_state_update: {}",
            .{ slot, root, SlotStateUpdate.popular_pruned_fork },
        );

        if (slot <= root) {
            return;
        }

        logger.warn().logf(
            "{slot} is part of a pruned fork which has reached the DUPLICATE_THRESHOLD aggregating " ++
                "across descendants and slot versions. It is suspected to be duplicate or have an " ++
                "ancestor that is duplicate. Notifying ancestor_hashes_service",
        );
        resulting_change.send_ancestor_hashes_replay_update(
            ancestor_hashes_replay_update_sender,
            .{ .kind = .popular_pruned_fork, .slot = slot },
        );
    }
};

const resulting_change = struct {
    fn bank_frozen(
        slot: u64,
        fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
        not_duplicate_confirmed_frozen_hash: *NotDuplicateConfirmedFrozenHash,
        bank_frozen_hash: sig.core.Hash,
    ) void {
        const is_duplicate_confirmed = fork_choice
            .isDuplicateConfirmed(&.{ .slot = slot, .hash = bank_frozen_hash }) orelse
            std.debug.panic("frozen bank must exist in fork choice", .{});
        if (!is_duplicate_confirmed) {
            not_duplicate_confirmed_frozen_hash.* = bank_frozen_hash;
        }
    }

    fn mark_slot_duplicate(
        slot: u64,
        fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
        bank_frozen_hash: sig.core.Hash,
    ) !void {
        try fork_choice.markForkInvalidCandidate(&.{ .slot = slot, .hash = bank_frozen_hash });
    }

    fn repair_duplicate_confirmed_version(
        allocator: std.mem.Allocator,
        slot: u64,
        duplicate_slots_to_repair: *DuplicateSlotsToRepair,
        duplicate_confirmed_hash: sig.core.Hash,
    ) !void {
        try duplicate_slots_to_repair.put(allocator, slot, duplicate_confirmed_hash);
    }

    fn duplicate_confirmed_slot_matches_cluster(
        slot: u64,
        fork_choice: *sig.consensus.HeaviestSubtreeForkChoice,
        duplicate_slots_to_repair: *DuplicateSlotsToRepair,
        blockstore: *const sig.ledger.LedgerResultWriter,
        purge_repair_slot_counter: *PurgeRepairSlotCounter,
        not_duplicate_confirmed_frozen_hash: *NotDuplicateConfirmedFrozenHash,
        bank_frozen_hash: sig.core.Hash,
    ) !void {
        not_duplicate_confirmed_frozen_hash.* = null;
        // When we detect that our frozen slot matches the cluster version (note this
        // will catch both bank frozen first -> confirmation, or confirmation first ->
        // bank frozen), mark all the newly duplicate confirmed slots in blockstore
        const new_duplicate_confirmed_slot_hashes = try fork_choice.markForkValidCandidate(&.{
            .slot = slot,
            .hash = bank_frozen_hash,
        });
        defer new_duplicate_confirmed_slot_hashes.deinit();

        try blockstore.setDuplicateConfirmedSlotsAndHashes(
            new_duplicate_confirmed_slot_hashes.items,
        );
        _ = duplicate_slots_to_repair.swapRemove(slot);
        _ = purge_repair_slot_counter.sorted_map.orderedRemove(slot);
    }

    fn send_ancestor_hashes_replay_update(
        ancestor_hashes_replay_update_sender: *sig.sync.Channel(AncestorHashesReplayUpdate),
        ancestor_hashes_replay_update: AncestorHashesReplayUpdate,
    ) void {
        ancestor_hashes_replay_update_sender.send(ancestor_hashes_replay_update) catch {
            // TODO: agave just ignores this error, is that alright?
        };
    }
};

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

/// stub to represent struct coming in the next pr (already implemented)
const ReplayExecutionState = struct {
    fn init(
        _: Allocator,
        _: sig.trace.Logger,
        _: *ThreadPool,
        _: sig.core.EpochSchedule,
        _: *AccountsDB,
        _: *BlockstoreReader,
    ) !ReplayExecutionState {
        return .{};
    }

    fn deinit(_: ReplayExecutionState) void {}
};
