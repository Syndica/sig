const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const AtomicBool = std.atomic.Value(bool);
const ArrayListUnmanaged = std.ArrayListUnmanaged;

const LedgerResultWriter = sig.ledger.result_writer.LedgerResultWriter;

const RwMux = sig.sync.RwMux;

const ThreadPool = sig.sync.ThreadPool;

const AccountsDB = sig.accounts_db.AccountsDB;
const BlockstoreReader = sig.ledger.BlockstoreReader;

const ScopedLogger = sig.trace.ScopedLogger("replay");

const Transaction = sig.core.transaction.Transaction;
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

    // TODO: Pass in the consensus deps
    try processConsensus(null);

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
    blockstore_reader: *BlockstoreReader,
    leader_schedule_cache: *LeaderScheduleCache,
    vote_account: Pubkey,
};

fn processConsensus(maybe_deps: ?ConsensusDependencies) !void {
    const deps = if (maybe_deps) |deps|
        deps
    else
        return error.Todo;

    const heaviest_slot = deps.fork_choice.heaviestOverallSlot().slot;
    const heaviest_slot_on_same_voted_fork =
        (try deps.fork_choice.heaviestSlotOnSameVotedFork(deps.replay_tower)) orelse null;

    // TODO replace hardcoded value.
    const forks_root: Slot = 0;
    var in_vote_only_mode = AtomicBool.init(false);
    const heaviest_epoch: Epoch = 0;
    const ancestors: std.AutoHashMapUnmanaged(u64, SortedSet(u64)) = .{};
    const descendants: std.AutoArrayHashMapUnmanaged(u64, SortedSet(u64)) = .{};

    var last_vote_refresh_time: LastVoteRefreshTime = .{
        .last_refresh_time = sig.time.Instant.now(),
        .last_print_time = sig.time.Instant.now(),
    };
    const latest_validator_votes_for_frozen_banks = LatestValidatorVotesForFrozenBanks{
        .max_gossip_frozen_votes = .{},
    };
    const bits = try sig.bloom.bit_set.DynamicArrayBitSet(u64).initEmpty(deps.allocator, 10);
    defer bits.deinit(deps.allocator);
    const slot_history = SlotHistory{ .bits = bits, .next_slot = 0 };

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
            &last_vote_refresh_time,
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
        const slot_tracker = deps.slot_tracker;
        if (leader_schedule_cache.slotLeader(voted.slot)) |votable_leader| {
            // TODO implement Self::log_leader_change
            _ = &votable_leader;
            var found_slot = slot_tracker.slots.get(voted.slot) orelse
                return error.MissingSlot;

            const voted_hash = found_slot.state.hash.read().get().* orelse
                return error.MissingSlotInTracker;

            try handleVotableBank(
                deps.allocator,
                deps.blockstore_reader,
                deps.leader_schedule_cache,
                voted.slot,
                voted_hash,
                deps.slot_tracker,
                deps.replay_tower,
                deps.progress_map,
                deps.fork_choice,
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

fn handleVotableBank(
    allocator: std.mem.Allocator,
    blockstore_reader: *BlockstoreReader,
    leader_schedule_cache: *LeaderScheduleCache,
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
            blockstore_reader,
            leader_schedule_cache,
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
    blockstore_reader: *BlockstoreReader,
    leader_schedule_cache: *LeaderScheduleCache,
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

    // TODO revisit this
    const rooted_slots = try slot_tracker.activeSlots(allocator);

    if (slot_tracker.slots.count() == 0) return error.EmptySlotTracker;
    // TODO implement leader_schedule_cache.set_root.
    _ = &leader_schedule_cache;

    // TODO have this a seperate function?
    {
        // TODO revisit these values.
        var lowest_cleanup_slot = RwMux(Slot).init(0);
        var max_root = std.atomic.Value(Slot).init(0);
        var registry = sig.prometheus.Registry(.{}).init(allocator);
        defer registry.deinit();

        var writer = LedgerResultWriter{
            .allocator = allocator,
            .db = blockstore_reader.db,
            .logger = .noop,
            .lowest_cleanup_slot = &lowest_cleanup_slot,
            .max_root = &max_root,
            .scan_and_fix_roots_metrics = try registry.initStruct(
                sig.ledger.result_writer.ScanAndFixRootsMetrics,
            ),
        };

        try writer.setRoots(rooted_slots);
    }

    // Audit: The rest of the code maps to Self::handle_new_root in Agave.
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
