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

const Transaction = sig.core.transaction.Transaction;
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
// Give at least 4 leaders the chance to pack our vote
const REFRESH_VOTE_BLOCKHEIGHT: usize = 16;
const MAX_VOTE_REFRESH_INTERVAL_MILLIS: usize = 5000;

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
    leader_schedule_cache: LeaderScheduleCache,
    vote_account: Pubkey,
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

        var duplicate_slots_to_repair: replay.service.stubs.DuplicateSlotsToRepair = .{};
        var purge_repair_slot_counter: replay.service.stubs.PurgeRepairSlotCounter = .{};
        try markSlotsDuplicateConfirmed(
            deps.blockstore,
            deps.progress_map,
            deps.fork_choice,
            duplicate_confirmed_forks,
            0,
            .{},
            .{},
            &duplicate_slots_to_repair,
            .{},
            &purge_repair_slot_counter,
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
    const identity_keypair = Keypair.generate();
    var authorized_voter_keypairs = [_]Keypair{Keypair.generate()};
    var vote_signatures =
        std.ArrayList(Signature).init(deps.allocator);
    const has_new_vote_been_rooted = true;
    var last_vote_refresh_time: LastVoteRefreshTime = .{
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

    const vote_and_reset_forks = try deps.replay_tower.selectVoteAndResetForks(
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
    const maybe_voted_slot = vote_and_reset_forks.vote_slot;
    const maybe_reset_slot = vote_and_reset_forks.reset_slot;
    const heaviest_fork_failures = vote_and_reset_forks.heaviest_fork_failures;

    if (maybe_voted_slot == null) {
        _ = maybeRefreshLastVote(
            deps.replay_tower,
            deps.progress_map,
            if (heaviest_slot_on_same_voted_fork) |h| h.slot else null,
            &vote_account_pubkey,
            &identity_keypair,
            &authorized_voter_keypairs,
            &vote_signatures,
            has_new_vote_been_rooted,
            &last_vote_refresh_time,
            &voting_sender,
            wait_till_vote_slot,
        );
    }

    if (deps.replay_tower.tower.isRecent(heaviest_slot) and
        heaviest_fork_failures.items.len != 0)
    {
        // Implemented the log
    }

    // Vote on the fork
    if (maybe_voted_slot) |voted| {
        var leader_schedule_cache = deps.leader_schedule_cache;
        if (leader_schedule_cache.slotLeader(voted.slot)) |votable_leader| {
            // TODO implement Self::log_leader_change
            _ = &votable_leader;
            try handleVotableBank(
                deps.allocator,
                voted.slot,
                Hash.ZEROES, // TODO get the hash associated with the slot
                &voted.decision,
                deps.slot_tracker,
                deps.replay_tower,
                deps.progress_map,
                &deps.vote_account,
                &identity_keypair,
                &authorized_voter_keypairs,
                &deps.blockstore.*,
                &leader_schedule_cache,
                &.{},
                &.{},
                &.{},
                &.{},
                deps.fork_choice,
                &.{},
                &.{},
                &.{},
                &.{},
                .{},
                false,
                &.{},
                &.{},
                &.{},
                &.{},
                null,
            );
        }
    }

    // Reset onto a fork
    if (maybe_reset_slot) |reset_slot| {
        // TODO implement
        _ = &reset_slot;
    }
}

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
fn maybeRefreshLastVote(
    replay_tower: *ReplayTower,
    progress: *const ProgressMap,
    maybe_heaviest_slot_on_same_fork: ?Slot,
    vote_account_pubkey: *const Pubkey,
    identity_keypair: *const Keypair,
    authorized_voter_keypairs: []Keypair, // TODO Arc
    vote_signatures: *std.ArrayList(Signature),
    has_new_vote_been_rooted: bool,
    last_vote_refresh_time: *LastVoteRefreshTime,
    voting_sender: *const stubs.Sender(VoteOp),
    wait_to_vote_slot: ?Slot,
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
    if (maybe_last_vote_tx_blockhash) |last_vote_tx_blockhash| {
        // Check the blockhash queue to see if enough blocks have been built on our last voted fork
        _ = &last_vote_tx_blockhash;
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
    replay_tower.refreshLastVoteTimestamp(heaviest_bank_on_same_fork);

    // TODO generate_vote_tx
    _ = &vote_account_pubkey;
    _ = &identity_keypair;
    _ = &authorized_voter_keypairs;
    _ = &vote_signatures;
    _ = &has_new_vote_been_rooted;
    _ = &wait_to_vote_slot;
    const vote_tx_result: GenerateVoteTxResult = .{
        .tx = Transaction.EMPTY,
    };

    return switch (vote_tx_result) {
        .tx => |vote_tx| {
            const recent_blockhash = vote_tx.msg.recent_blockhash;
            replay_tower.refreshLastVoteTxBlockhash(recent_blockhash);
            // TODO send vote
            _ = &voting_sender;
            last_vote_refresh_time.last_refresh_time = sig.time.Instant.now();
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
    pub const DuplicateSlotsToRepair = struct {
        pub fn insert(self: @This(), slot: Slot, hash: Hash) void {
            _ = &self;
            _ = &slot;
            _ = &hash;
        }
        pub fn remove(self: @This(), slot: Slot) void {
            _ = &self;
            _ = &slot;
        }
    };
    pub const PurgeRepairSlotCounter = struct {
        pub fn remove(self: @This(), slot: Slot) void {
            _ = &self;
            _ = &slot;
        }
    };
    pub const DuplicateConfirmedSlots = struct {};
    pub const UnfrozenGossipVerifiedVoteHashes = struct {};
    pub const ReplayLoopTiming = struct {};
    pub const AncestorHashesReplayUpdateSender = struct {
        pub fn send(self: @This(), update: AncestorHashesReplayUpdate) void {
            _ = &self;
            _ = &update;
        }
    };
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
    duplicate_slots_to_repair: *stubs.DuplicateSlotsToRepair,
    ancestor_hashes_replay_update_sender: stubs.AncestorHashesReplayUpdateSender,
    purge_repair_slot_counter: *stubs.PurgeRepairSlotCounter,
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

        try checkSlotAgreesWithCluster(
            root_slot,
            slot,
            SlotStateUpdate{
                .duplicate_confirmed = duplicate_confirmed_state,
            },
            fork_choice,
            duplicate_slots_to_repair,
            blockstore,
            &ancestor_hashes_replay_update_sender,
            purge_repair_slot_counter,
        );
    }

    _ = &duplicate_slot_tracker;
    _ = &epoch_slots_frozen_slots;
    _ = &duplicate_confirmed_slots;
}

fn checkSlotAgreesWithCluster(
    root: Slot,
    slot: Slot,
    slot_state_update: SlotStateUpdate,
    fork_choice: *ForkChoice,
    duplicate_slots_to_repair: *stubs.DuplicateSlotsToRepair,
    blockstore: *const BlockstoreReader,
    ancestor_hashes_replay_update_sender: *const stubs.AncestorHashesReplayUpdateSender,
    purge_repair_slot_counter: *stubs.PurgeRepairSlotCounter,
) !void {
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

    try applyStateChanges(
        slot,
        fork_choice,
        duplicate_slots_to_repair,
        blockstore,
        ancestor_hashes_replay_update_sender,
        purge_repair_slot_counter,
        state_changes,
    );
}

pub const AncestorHashesReplayUpdate = union(enum) {
    dead: Slot,
    dead_duplicate_confirmed: Slot,
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

const ResultingStateChanges = std.BoundedArray(ResultingStateChange, 5);

fn generateStateChanges(
    slot: Slot,
    slot_state_update: SlotStateUpdate,
) ResultingStateChanges {
    var state_changes: ResultingStateChanges = .{};
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

fn applyStateChanges(
    slot: Slot,
    fork_choice: *ForkChoice,
    duplicate_slots_to_repair: *stubs.DuplicateSlotsToRepair,
    blockstore: *const BlockstoreReader,
    ancestor_hashes_replay_update_sender: *const stubs.AncestorHashesReplayUpdateSender,
    purge_repair_slot_counter: *stubs.PurgeRepairSlotCounter,
    state_changes: ResultingStateChanges,
) !void {
    var maybe_not_duplicate_confirmed_frozen_hash: ?Hash = null;
    for (state_changes.constSlice()) |state_change| {
        switch (state_change) {
            .bank_frozen => |frozen_hash| {
                if (!(fork_choice.isDuplicateConfirmed(
                    &.{ .slot = slot, .hash = frozen_hash },
                ) orelse
                    return error.MissingSlot))
                {
                    maybe_not_duplicate_confirmed_frozen_hash = frozen_hash;
                }
            },
            .mark_slot_duplicate => |frozen_hash| {
                try fork_choice.markForkInvalidCandidate(
                    &.{ .slot = slot, .hash = frozen_hash },
                );
            },
            .repair_duplicate_confirmed_version => |duplicate_confirmed_hash| {
                duplicate_slots_to_repair.insert(slot, duplicate_confirmed_hash);
            },
            .duplicate_confirmed_slot_matches_cluster => |frozen_hash| {
                maybe_not_duplicate_confirmed_frozen_hash = null;
                // When we detect that our frozen slot matches the cluster version (note this
                // will catch both bank frozen first -> confirmation, or confirmation first ->
                // bank frozen), mark all the newly duplicate confirmed slots in blockstore
                const new_duplicate_confirmed_slot_hashes =
                    try fork_choice.markForkValidCandidate(
                        &.{
                            .slot = slot,
                            .hash = frozen_hash,
                        },
                    );
                // TODO
                // blockstore
                // .set_duplicate_confirmed_slots_and_hashes(
                //     new_duplicate_confirmed_slot_hashes.into_iter(),
                // )
                // .unwrap();
                _ = &new_duplicate_confirmed_slot_hashes;
                _ = &blockstore;
                duplicate_slots_to_repair.remove(slot);
                purge_repair_slot_counter.remove(slot);
            },
            .send_ancestor_hashes_replay_update => |ancestor_hashes_replay_update| {
                ancestor_hashes_replay_update_sender.send(ancestor_hashes_replay_update);
            },
        }
    }

    if (maybe_not_duplicate_confirmed_frozen_hash) |not_duplicate_confirmed_frozen_hash| {
        // TODO
        // blockstore.insert_bank_hash(slot, frozen_hash, false);
        _ = &not_duplicate_confirmed_frozen_hash;
    }
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
    slot_tracker: *SlotTracker,
    replay_tower: *ReplayTower,
    progress: *ProgressMap,
    vote_account_pubkey: *const Pubkey,
    identity_keypair: *const Keypair,
    authorized_voter_keypairs: []Keypair,
    blockstore: *const BlockstoreReader,
    leader_schedule_cache: *const LeaderScheduleCache,
    lockouts_sender: *const stubs.Sender(stubs.CommitmentAggregationData),
    snapshot_controller: ?*const stubs.SnapshotController,
    rpc_subscriptions: *const stubs.RpcSubscriptions,
    block_commitment_cache: *const stubs.BlockCommitmentCache,
    fork_choice: *ForkChoice,
    bank_notification_sender: *const stubs.BankNotificationSenderConfig,
    duplicate_slots_tracker: *const stubs.DuplicateSlotsTracker,
    duplicate_confirmed_slots: *const stubs.DuplicateConfirmedSlots,
    unfrozen_gossip_verified_vote_hashes: *const stubs.UnfrozenGossipVerifiedVoteHashes,
    vote_signatures: std.ArrayListUnmanaged(Signature),
    has_new_vote_been_rooted: bool,
    replay_timing: *const stubs.ReplayLoopTiming,
    voting_sender: *const stubs.Sender(VoteOp),
    epoch_slots_frozen_slots: *const stubs.EpochSlotsFrozenSlots,
    drop_bank_sender: *const stubs.Sender(std.ArrayList(stubs.BankWithScheduler)),
    wait_to_vote_slot: ?Slot,
) !void {
    const maybe_new_root = try replay_tower.recordBankVote(
        allocator,
        vote_slot,
        vote_hash,
    );

    if (maybe_new_root) |new_root| {
        try checkAndHandleNewRoot(
            allocator,
            slot_tracker,
            progress,
            fork_choice,
            new_root,
        );
    }

    // TODO update_commitment_cache

    try push_vote(
        allocator,
        replay_tower,
    );

    _ = &vote_slot;
    _ = &vote_hash;
    _ = &switch_fork_decision;
    _ = &slot_tracker;
    _ = &replay_tower;
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
    _ = &fork_choice;
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

fn push_vote(
    allocator: std.mem.Allocator,
    replay_tower: *ReplayTower,
) !void {
    // TODO generate_vote_tx
    const vote_tx_result: GenerateVoteTxResult = .{
        .tx = Transaction.EMPTY,
    };

    switch (vote_tx_result) {
        .tx => |vote_tx| {
            replay_tower.refreshLastVoteTxBlockhash(vote_tx.msg.recent_blockhash);
            // TODO save the tower
            const saved_tower = replay_tower;
            const lockouts = replay_tower.tower.vote_state.votes.constSlice();
            var tower_slots: ArrayListUnmanaged(Slot) = try ArrayListUnmanaged(Slot).initCapacity(
                allocator,
                lockouts.len,
            );
            for (lockouts) |lockout| {
                tower_slots.appendAssumeCapacity(lockout.slot);
            }
            // Use saved_tower and tower_slots in vote_sender
            _ = &saved_tower;
            _ = &tower_slots;
        },
        .non_voting => {
            replay_tower.markLastVoteTxBlockhashNonVoting();
        },
        else => {
            // Do nothing
        },
    }
}

fn checkAndHandleNewRoot(
    allocator: std.mem.Allocator,
    slot_tracker: *SlotTracker,
    progress: *ProgressMap,
    fork_choice: *ForkChoice,
    new_root: Slot,
) !void {
    // get the root bank before squash.
    var root_tracker = slot_tracker.slots.get(new_root) orelse return error.MissingSlot;
    const root_hash, var hash_lg = root_tracker.state.hash.readWithLock();
    defer hash_lg.unlock();
    // TODO need to get parents
    _ = &root_tracker;

    // Update the progress map.
    // TODO Move to its own function?
    {
        var to_remove = std.ArrayList(Slot).init(
            allocator,
        );
        defer to_remove.deinit();

        var it = progress.map.iterator();
        while (it.next()) |entry| {
            // TODO should frozen state be taking into consideration.
            if (slot_tracker.slots.get(entry.key_ptr.*) == null) {
                try to_remove.append(entry.key_ptr.*);
            }
        }

        for (to_remove.items) |key| {
            _ = progress.map.swapRemove(key);
        }
    }

    // Update forkchoice
    try fork_choice.setTreeRoot(&.{
        .slot = new_root,
        .hash = root_hash.* orelse return error.MissingHash,
    });
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
