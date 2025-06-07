const std = @import("std");
const sig = @import("../sig.zig");
const replay = @import("lib.zig");

const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const ArrayListUnmanaged = std.ArrayListUnmanaged;

const ThreadPool = sig.sync.ThreadPool;

const AccountsDB = sig.accounts_db.AccountsDB;
const BlockstoreReader = sig.ledger.BlockstoreReader;

const ScopedLogger = sig.trace.ScopedLogger("replay");

const Signature = sig.core.Signature;
const Keypair = sig.identity.KeyPair;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const Hash = sig.core.Hash;
const SlotAndHash = sig.core.hash.SlotAndHash;
const LeaderScheduleCache = sig.core.leader_schedule.LeaderScheduleCache;

const SlotTracker = sig.replay.trackers.SlotTracker;
const SlotHistory = sig.runtime.sysvar.SlotHistory;
const SortedSet = sig.utils.collections.SortedSet;

const ReplayTower = sig.consensus.replay_tower.ReplayTower;
const ProgressMap = sig.consensus.progress_map.ProgressMap;
const VotedStakes = sig.consensus.progress_map.consensus.VotedStakes;
const ForkChoice = sig.consensus.fork_choice.ForkChoice;
const LatestValidatorVotesForFrozenBanks =
    sig.consensus.unimplemented.LatestValidatorVotesForFrozenBanks;
const SwitchForkDecision = sig.consensus.replay_tower.SwitchForkDecision;

/// Number of threads to use in replay's thread pool
const NUM_THREADS = 4;

pub const DUPLICATE_LIVENESS_THRESHOLD: f64 = 0.1;
pub const SWITCH_FORK_THRESHOLD: f64 = 0.38;
pub const DUPLICATE_THRESHOLD: f64 = 1.0 - SWITCH_FORK_THRESHOLD - DUPLICATE_LIVENESS_THRESHOLD;

pub const isSlotDuplicateConfirmed = sig.consensus.tower.isSlotDuplicateConfirmed;

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

    var slots = [_]Slot{0};
    // TODO: Pass in the consensus deps
    try processConsensus(null, slots[0..]);

    // TODO: dump_then_repair_correct_slots

    // TODO: maybe_start_leader
}

fn handleEdgeCases() void {
    // TODO: process_ancestor_hashes_duplicate_slots

    // TODO: process_duplicate_confirmed_slots

    // TODO: process_gossip_verified_vote_hashes

    // TODO: process_popular_pruned_forks

    // TODO: process_duplicate_slots

}

const ConsensusDependencies = struct {
    allocator: Allocator,
    replay_tower: *ReplayTower,
    progress_map: *ProgressMap,
    slot_tracker: *SlotTracker,
    fork_choice: *ForkChoice,
    blockstore: *BlockstoreReader,
};

fn processConsensus(maybe_deps: ?ConsensusDependencies, newly_computed_slot_stats: []Slot) !void {
    const deps = if (maybe_deps) |deps|
        deps
    else
        return error.Todo;
    for (newly_computed_slot_stats) |slot| {
        const fork_stats = deps.progress_map.getForkStats(slot) orelse
            return error.MissingSlot;

        const duplicate_confirmed_forks = try towerDuplicateConfirmedForks(
            deps.allocator,
            deps.progress_map,
            deps.slot_tracker,
            fork_stats.voted_stakes,
            fork_stats.total_stake,
            slot,
        );

        try markSlotsDuplicateConfirmed(
            deps.blockstore,
            deps.progress_map,
            deps.fork_choice,
            duplicate_confirmed_forks,
            0,
            .{},
            .{},
            .{},
            .{},
            .{},
            .{},
        );
    }

    const heaviest_slot = deps.fork_choice.heaviestOverallSlot().slot;
    const heaviest_slot_on_same_voted_fork =
        (try deps.fork_choice.heaviestSlotOnSameVotedFork(deps.replay_tower)) orelse null;

    // TODO replace hardcoded value.
    const forks_root: Slot = 0;
    var in_vote_only_mode = AtomicBool.init(false);
    const heaviest_epoch: Epoch = 0;
    const ancestors: std.AutoHashMapUnmanaged(u64, SortedSet(u64)) = .{};
    const descendants: std.AutoArrayHashMapUnmanaged(u64, SortedSet(u64)) = .{};
    const vote_account_pubkey = Pubkey.ZEROES;
    const identity_pair = Keypair.generate();
    var authorized_voter_keypairs = [_]Keypair{Keypair.generate()};
    var vote_signatures =
        std.ArrayList(Signature).init(deps.allocator);
    const has_new_vote_been_rooted = true;
    const last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = sig.time.Instant.now(),
        .last_print_time = sig.time.Instant.now(),
    };
    const voting_sender: stubs.Sender(VoteOp) = .{};
    const latest_validator_votes_for_frozen_banks = LatestValidatorVotesForFrozenBanks{
        .max_gossip_frozen_votes = .{},
    };
    const bits = try sig.bloom.bit_set.DynamicArrayBitSet(u64).initEmpty(deps.allocator, 10);
    defer bits.deinit(deps.allocator);
    const slot_history = SlotHistory{ .bits = bits, .next_slot = 0 };
    const wait_till_vote_slot = null;

    // Looks like this is mostly used for logging? So maybe it can be skipped?
    checkForVoteOnlyMode(
        heaviest_slot,
        forks_root,
        &in_vote_only_mode,
    );

    const result = try deps.replay_tower.selectVoteAndResetForks(
        deps.allocator,
        heaviest_slot,
        if (heaviest_slot_on_same_voted_fork) |h| h.slot else null,
        heaviest_epoch,
        &ancestors,
        &descendants,
        deps.progress_map,
        &latest_validator_votes_for_frozen_banks,
        deps.fork_choice,
        .{},
        &slot_history,
    );
    const maybe_voted_slot = result.vote_slot;
    const reset_slot = result.reset_slot;
    const heaviest_fork_failures = result.heaviest_fork_failures;
    _ = &heaviest_fork_failures;
    _ = &reset_slot;

    if (maybe_voted_slot == null) {
        _ = maybeRefreshLastVote(
            deps.replay_tower,
            deps.progress_map,
            if (heaviest_slot_on_same_voted_fork) |h| h.slot else null,
            &vote_account_pubkey,
            &identity_pair,
            &authorized_voter_keypairs,
            &vote_signatures,
            has_new_vote_been_rooted,
            &last_vote_refresh_time,
            &voting_sender,
            wait_till_vote_slot,
        );
    }

    if (deps.replay_tower.tower.isRecent(heaviest_slot) and
        result.heaviest_fork_failures.items.len != 0)
    {
        // Implemented the log
    }

    // Vote on the fork
    if (maybe_voted_slot) |voted_slot| {
        _ = &voted_slot;
    }

    // TODO: if reset_bank: Reset onto a fork
}

const LastVoteRefreshTime = struct {
    last_refresh_time: sig.time.Instant,
    last_print_time: sig.time.Instant,
};

fn maybeRefreshLastVote(
    replay_tower: *ReplayTower,
    progress: *const ProgressMap,
    heaviest_slot_on_same_fork: ?Slot,
    vote_account_pubkey: *const Pubkey,
    identity_keypair: *const Keypair,
    authorized_voter_keypairs: []Keypair, // TODO Arc
    vote_signatures: *std.ArrayList(Signature),
    has_new_vote_been_rooted: bool,
    last_vote_refresh_time: *const LastVoteRefreshTime,
    voting_sender: *const stubs.Sender(VoteOp),
    wait_to_vote_slot: ?Slot,
) bool {
    _ = &replay_tower;
    _ = &progress;
    _ = &heaviest_slot_on_same_fork;
    _ = &vote_account_pubkey;
    _ = &identity_keypair;
    _ = &authorized_voter_keypairs;
    _ = &vote_signatures;
    _ = &has_new_vote_been_rooted;
    _ = &last_vote_refresh_time;
    _ = &voting_sender;
    _ = &wait_to_vote_slot;
    return true;
}

/// Identifies and returns slots that should be marked as "duplicate confirmed" based on
/// the validator's voting state and stake distribution.
///
/// "Duplicate confirmed" means the slot has received enough stake-weighted votes
/// from validators to be considered definitively confirmed by the network,
/// even if there are multiple competing versions of that slot.
///
/// This means the slot becomes a valid candidate for fork selection and
/// can influence which chain the validator builds upon.
///
/// Note: 1. This is "duplicate confirmed", which is different from "regular" confirmation,
/// where a slot is simply processed and frozen.
/// Note: 2. The slot is skipped if it is already duplicate confirmed in the progress map's fork state
///          or if the slot is not already frozen.
fn towerDuplicateConfirmedForks(
    allocator: std.mem.Allocator,
    progress_map: *const ProgressMap,
    slot_tracker: *const SlotTracker,
    vote_stakes: VotedStakes,
    total_stake: u64,
    slot: Slot,
) ![]const SlotAndHash {
    var duplicate_confirmed_forks: ArrayListUnmanaged(SlotAndHash) = .{};

    var it = progress_map.map.iterator();
    while (it.next()) |entry| {
        const entry_slot = entry.key_ptr.*;
        const fork_progress = entry.value_ptr.*;
        if (fork_progress.fork_stats.duplicate_confirmed_hash != null) continue;

        var found_slot = slot_tracker.slots.get(entry_slot) orelse
            return error.MissingSlot;

        //TODO should found_slot.state.hash be a mutex
        const found_slot_hash = found_slot.state.hash.read().get().* orelse
            return error.MissingSlotInTracker;
        var state = found_slot.state;
        if (!state.isFrozen()) {
            continue;
        }

        const is_slot_duplicate_confirmed = isSlotDuplicateConfirmed(
            slot,
            &vote_stakes,
            total_stake,
        );

        if (is_slot_duplicate_confirmed) {
            try duplicate_confirmed_forks.append(
                allocator,
                SlotAndHash{
                    .slot = slot,
                    .hash = found_slot_hash,
                },
            );
        }
    }
    return try duplicate_confirmed_forks.toOwnedSlice(allocator);
}

// TODO complete
const VoteOp = union(enum) {
    push_vote,
    refresh_vote,
};

// TODO Revisit
const stubs = struct {
    pub const DuplicateSlotsTracker = struct {};
    pub const EpochSlotsFrozenSlots = struct {};
    pub const DuplicateSlotsToRepair = struct {};
    pub const PurgeRepairSlotCounter = struct {};
    pub const DuplicateConfirmedSlots = struct {};
    pub const UnfrozenGossipVerifiedVoteHashes = struct {};
    pub const ReplayLoopTiming = struct {};
    pub const AncestorHashesReplayUpdateSender = struct {};
    pub const BankForks = struct {};
    pub const PohRecorder = struct {};
    pub const ClusterInfo = struct {};
    pub const PartitionInfo = struct {};
    pub const CommitmentAggregationData = struct {};
    pub const RpcSubscriptions = struct {};
    pub const SnapshotController = struct {};
    pub const BlockCommitmentCache = struct {};
    pub const BankNotificationSenderConfig = struct {};
    pub const BankWithScheduler = struct {};
    pub fn Sender(t: type) type {
        _ = &t;
        return struct {};
    }
};

pub const SlotStatus = union(enum) {
    /// Bank has completed processing and been frozen with a specific hash.
    /// The hash represents the local validator's view of what the slot's hash should be.
    frozen: Hash,
    /// Slot failed to process correctly and should not be considered for consensus.
    dead,
    /// The bank/slot has not yet been processed or is still in progress.
    unprocessed,

    fn canBeFurtherReplayed(self: SlotStatus) bool {
        return switch (self) {
            .frozen => |_| true,
            .dead => false,
            .unprocessed => false,
        };
    }
};

pub const DuplicateConfirmedState = struct {
    /// Hash of the slot that has been confirmed as duplicate.
    /// Note: This hash is cluster-agreed hash for the duplicate confirmed slot
    /// while the hash in SlotStatus.Frozen(Hash) is local validator's view of
    /// what the slot's hash should be.
    duplicate_confirmed_hash: Hash,
    /// The current status of the bank/slot from the validator's perspective.
    slot_status: SlotStatus,
};

pub const SlotStateUpdate = union(enum) {
    duplicate_confirmed: DuplicateConfirmedState,
    pub fn canBeFurtherReplayed(self: SlotStateUpdate) bool {
        switch (self) {
            .duplicate_confirmed => |duplicate_confirmed_state| {
                return duplicate_confirmed_state.slot_status.canBeFurtherReplayed();
            },
        }
    }
};

/// This function helps maintain the validator's view of which slots
/// have been duplicate confirmed by the cluster.
fn markSlotsDuplicateConfirmed(
    blockstore: *BlockstoreReader,
    progress_map: *ProgressMap,
    fork_choice: *ForkChoice,
    confirmed_duplicates: []const SlotAndHash,
    root_slot: Slot,
    duplicate_slot_tracker: stubs.DuplicateSlotsTracker,
    epoch_slots_frozen_slots: stubs.EpochSlotsFrozenSlots,
    duplicate_slots_to_repair: stubs.DuplicateSlotsToRepair,
    ancestor_hashes_replay_update_sender: stubs.AncestorHashesReplayUpdateSender,
    purge_repair_slot_counter: stubs.PurgeRepairSlotCounter,
    duplicate_confirmed_slots: stubs.DuplicateConfirmedSlots,
) !void {
    for (confirmed_duplicates) |confirmed| {
        const slot = confirmed.slot;
        const hash = confirmed.hash;
        if (slot <= root_slot) {
            continue;
        }

        const slot_progress = progress_map.map.getEntry(slot) orelse
            return error.MissingSlot;

        slot_progress.value_ptr.*.fork_stats.duplicate_confirmed_hash = hash;
        // TODO Track slot and hash in duplicate_confirmed_slots?
        // TODO Create DuplicateConfirmedState
        const duplicate_confirmed_state = DuplicateConfirmedState{
            .duplicate_confirmed_hash = hash,
            .slot_status = SlotStatus{ .frozen = hash },
        };

        checkSlotAgreesWithCluster(
            root_slot,
            slot,
            SlotStateUpdate{
                .duplicate_confirmed = duplicate_confirmed_state,
            },
            fork_choice,
        );
    }

    _ = &blockstore;
    _ = &root_slot;
    _ = &progress_map;
    _ = &duplicate_slot_tracker;
    _ = &fork_choice;
    _ = &epoch_slots_frozen_slots;
    _ = &duplicate_slots_to_repair;
    _ = &ancestor_hashes_replay_update_sender;
    _ = &purge_repair_slot_counter;
    _ = &duplicate_confirmed_slots;
}

fn checkSlotAgreesWithCluster(
    root: Slot,
    slot: Slot,
    slot_state_update: SlotStateUpdate,
    fork_choice: *ForkChoice,
) void {
    // Currently implements SlotStateUpdate::DuplicateConfirmed
    if (slot <= root) {
        return;
    }

    switch (slot_state_update) {
        .duplicate_confirmed => |state| {
            switch (state.slot_status) {
                .frozen => |hash| {
                    // Avoid duplicate work from multiple of the same DuplicateConfirmed signal. This can
                    // happen if we get duplicate confirmed from gossip and from local replay.
                    if (fork_choice.isDuplicateConfirmed(
                        &.{ .slot = slot, .hash = hash },
                    ) orelse false) {
                        return;
                    }
                },
                else => {},
            }
        },
    }

    if (slot_state_update.canBeFurtherReplayed()) {
        // If the bank is still awaiting replay, then there's nothing to do yet
        return;
    }

    // Generate state changes
    const state_changes = generateStateChanges(
        slot,
        slot_state_update,
    );

    _ = &state_changes;
}

pub const AncestorHashesReplayUpdate = union(enum) {
    dead: Slot,
    dead_duplicate_confirmed: Slot,
    popular_pruned_fork: Slot,
};

pub const ResultingStateChange = union(enum) {
    /// Bank was frozen
    bank_frozen: Hash,
    /// Hash of our current frozen version of the slot
    mark_slot_duplicate: Hash,
    /// Hash of the either:
    /// 1) Cluster duplicate confirmed slot
    /// 2) Epoch Slots frozen sampled slot
    /// that is not equivalent to our frozen version of the slot
    repair_duplicate_confirmed_version: Hash,
    /// Hash of our current frozen version of the slot
    duplicate_confirmed_slot_matches_cluster: Hash,
    send_ancestor_hashes_replay_update: AncestorHashesReplayUpdate,
};

fn generateStateChanges(
    slot: Slot,
    slot_state_update: SlotStateUpdate,
) std.BoundedArray(ResultingStateChange, 5) {
    var state_changes: std.BoundedArray(ResultingStateChange, 5) = .{};
    switch (slot_state_update) {
        .duplicate_confirmed => |duplicate_confirmed_state| {
            switch (duplicate_confirmed_state.slot_status) {
                .unprocessed => {
                    return state_changes;
                },
                .dead => {
                    state_changes.appendAssumeCapacity(
                        ResultingStateChange{
                            .send_ancestor_hashes_replay_update = .{
                                .dead_duplicate_confirmed = slot,
                            },
                        },
                    );
                },
                .frozen => |_| {},
            }
            generateStateChangesBasedOnBankStatus(
                &state_changes,
                duplicate_confirmed_state.duplicate_confirmed_hash,
                duplicate_confirmed_state.slot_status,
            );
        },
    }
    return state_changes;
}

/// Generates state changes needed to be applied to the forkchoice
/// based on checking the duplicate confirmed hash we observed against our local bank status
///
/// 1) If we haven't replayed locally do nothing
/// 2) If our local bank is dead, mark for dump and repair
/// 3) If our local bank is replayed but mismatch hash, notify fork choice of duplicate and dump and
///    repair
/// 4) If our local bank is replayed and matches the `duplicate_confirmed_hash`, notify fork choice
///    that we have the correct version
fn generateStateChangesBasedOnBankStatus(
    state_changes: *std.BoundedArray(ResultingStateChange, 5),
    duplicate_confirmed_hash: Hash,
    slot_status: SlotStatus,
) void {
    switch (slot_status) {
        .unprocessed => {},
        .dead => {
            state_changes.*.appendAssumeCapacity(
                .{
                    .repair_duplicate_confirmed_version = duplicate_confirmed_hash,
                },
            );
        },
        .frozen => |frozen_hash| {
            if (duplicate_confirmed_hash.eql(frozen_hash)) {
                state_changes.*.appendAssumeCapacity(
                    .{
                        .duplicate_confirmed_slot_matches_cluster = frozen_hash,
                    },
                );
            }
            // The duplicate confirmed slot hash does not match our frozen hash.
            // Modify fork choice rule to exclude our version from being voted
            // on and also repair the correct version
            state_changes.*.appendAssumeCapacity(
                .{ .mark_slot_duplicate = frozen_hash },
            );
            state_changes.*.appendAssumeCapacity(
                .{ .repair_duplicate_confirmed_version = duplicate_confirmed_hash },
            );
        },
    }
}

// Looks like this is mostly used for logging? So maybe it can be skipped?
fn checkForVoteOnlyMode(
    heaviest_bank_slot: Slot,
    forks_root: Slot,
    in_vote_only_mode: *AtomicBool,
) void {
    _ = &heaviest_bank_slot;
    _ = &forks_root;
    _ = &in_vote_only_mode;
}

// TODO The parameter list is humongous. Try to simplify
fn handleVotableBank(
    allocator: std.mem.Allocator,
    vote_slot: Slot,
    vote_hash: Hash, // vote_slot and vote_hash replaces Bank
    switch_fork_decision: *const SwitchForkDecision,
    bank_forks: *const stubs.BankForks, // TODO replace with alternative, have ref counted
    tower: *ReplayTower,
    progress: *ProgressMap,
    vote_account_pubkey: *const Pubkey,
    identity_keypair: *const Keypair,
    authorized_voter_keypairs: []Keypair, // TODO Arc
    blockstore: *const BlockstoreReader,
    leader_schedule_cache: *const LeaderScheduleCache, // TODO Arc
    lockouts_sender: *const stubs.Sender(stubs.CommitmentAggregationData),
    snapshot_controller: ?*const stubs.SnapshotController,
    rpc_subscriptions: *const stubs.RpcSubscriptions, // TODO Arc
    block_commitment_cache: *const stubs.BlockCommitmentCache, // TODO Arc/RwLock
    heaviest_subtree_fork_choice: *ForkChoice,
    bank_notification_sender: *const ?stubs.BankNotificationSenderConfig,
    duplicate_slots_tracker: *stubs.DuplicateSlotsTracker,
    duplicate_confirmed_slots: *stubs.DuplicateConfirmedSlots,
    unfrozen_gossip_verified_vote_hashes: *stubs.UnfrozenGossipVerifiedVoteHashes,
    vote_signatures: *std.ArrayList(Signature),
    has_new_vote_been_rooted: *bool,
    replay_timing: *stubs.ReplayLoopTiming,
    voting_sender: *stubs.Sender(VoteOp),
    epoch_slots_frozen_slots: *const stubs.EpochSlotsFrozenSlots,
    drop_bank_sender: *const stubs.Sender(std.ArrayList(stubs.BankWithScheduler)),
    wait_to_vote_slot: ?Slot,
) !void {
    const maybe_new_root = try tower.recordBankVote(
        allocator,
        vote_slot,
        vote_hash,
    );

    if (maybe_new_root) |new_root| {
        _ = &new_root;
        // TODO check_and_handle_new_root
    }

    // TODO update_commitment_cache
    // TODO push_vote
    _ = &vote_slot;
    _ = &vote_hash;
    _ = &switch_fork_decision;
    _ = &bank_forks;
    _ = &tower;
    _ = &progress;
    _ = &vote_account_pubkey;
    _ = &identity_keypair;
    _ = &authorized_voter_keypairs;
    _ = &blockstore;
    _ = &leader_schedule_cache;
    _ = &lockouts_sender;
    _ = &snapshot_controller;
    _ = &rpc_subscriptions;
    _ = &block_commitment_cache;
    _ = &heaviest_subtree_fork_choice;
    _ = &bank_notification_sender;
    _ = &duplicate_slots_tracker;
    _ = &duplicate_confirmed_slots;
    _ = &unfrozen_gossip_verified_vote_hashes;
    _ = &vote_signatures;
    _ = &has_new_vote_been_rooted;
    _ = &replay_timing;
    _ = &voting_sender;
    _ = &epoch_slots_frozen_slots;
    _ = &drop_bank_sender;
    _ = &wait_to_vote_slot;
}

fn resetFork(
    progress: *const ProgressMap,
    blockstore: *const BlockstoreReader,
    reset_slot: Slot,
    last_reset_hash: Hash,
    last_blockhash: Hash,
    last_reset_bank_descendants: std.ArrayList(Slot),
    poh_recorder: stubs.PohRecorder,
    cluster_info: stubs.ClusterInfo,
    partition_info: stubs.PartitionInfo,
    leader_schedule_cache: LeaderScheduleCache,
) !void {
    _ = &progress;
    _ = &blockstore;
    _ = &reset_slot;
    _ = &last_reset_hash;
    _ = &last_blockhash;
    _ = &last_reset_bank_descendants;
    _ = &poh_recorder;
    _ = &cluster_info;
    _ = &partition_info;
    _ = &leader_schedule_cache;
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
