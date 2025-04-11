const std = @import("std");
const sig = @import("../sig.zig");
const lib = sig.consensus;

const Slot = sig.core.Slot;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;

const PubkeyArraySet = std.AutoArrayHashMapUnmanaged(Pubkey, void);

/// TODO: any uses of these types are to be evaluated in their context, and
/// the actual required synchronization semantics are to be determined later.
const stubs = struct {
    fn Arc(comptime T: type) type {
        return struct { arc_ed: T };
    }
    fn RwLock(comptime T: type) type {
        return struct { rwlock_ed: T };
    }
};

// TODO: move this somewhere better?
/// NOTE: usage of this type indicates that the integer
/// must only be operated on using saturating arithmetic.
/// This is used to annotate types as saturating, to match
/// agave's type definitions.
fn Saturating(comptime T: type) type {
    return enum(T) {
        _,

        pub fn toInt(self: Saturating(T)) T {
            return @intFromEnum(self);
        }

        /// Returns `self`, casted to a pointer to `T`, retaining all attributes.
        pub fn asInt(self: anytype) AsInt(@TypeOf(self)) {
            return @ptrCast(self);
        }

        pub fn AsInt(comptime Self: type) type {
            const lazy = struct {
                fn nonMatchErr() noreturn {
                    @compileError("Expected single item pointer to " ++ @typeName(Saturating(T)));
                }
            };

            var info = switch (@typeInfo(Self)) {
                .Pointer => |info| info,
                .Optional => |info| switch (@typeInfo(info.child)) {
                    .Pointer => return ?AsInt(info.child),
                    else => lazy.nonMatchErr(),
                },
                else => lazy.nonMatchErr(),
            };
            if (info.size != .One) lazy.nonMatchErr();
            if (info.child != Saturating(T)) lazy.nonMatchErr();
            info.child = T;

            return @Type(.{ .Pointer = info });
        }
    };
}

/// TODO: replace this with an actually self-balancing data structure at some point;
/// for now, just assume it's sorted, and manually sort when that assumption cannot
/// be made and needs to be satisfied.
///
/// This serves as a centralized reminder, and can be removed once the
/// described use cases are satisfied.
fn BTreeMapStub(comptime K: type, comptime V: type) type {
    return struct {
        map: Map,
        const Map = std.AutoArrayHashMapUnmanaged(K, V);

        pub fn deinit(self: BTreeMapStub(K, V), allocator: std.mem.Allocator) void {
            var map = self.map;
            map.deinit(allocator);
        }

        pub fn clone(
            self: BTreeMapStub(K, V),
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!BTreeMapStub(K, V) {
            return .{ .map = try self.map.clone(allocator) };
        }
    };
}

pub const ProgressMap = struct {
    map: Map,

    pub const Map = std.AutoArrayHashMapUnmanaged(Slot, ForkProgress);

    pub const INIT: ProgressMap = .{ .map = .{} };

    pub fn deinit(self: ProgressMap, allocator: std.mem.Allocator) void {
        var map = self.map;
        for (map.values()) |fork_progress| fork_progress.deinit(allocator);
        map.deinit(allocator);
    }

    pub fn clone(
        self: ProgressMap,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!ProgressMap {
        var map: Map = .{};
        errdefer map.deinit(allocator);
        errdefer for (self.map.values()) |fork_progress| fork_progress.deinit(allocator);

        try map.ensureTotalCapacity(allocator, self.map.count());
        for (self.map.keys(), self.map.values()) |k, v| {
            map.putAssumeCapacityNoClobber(k, try v.clone(allocator));
        }

        return .{ .map = map };
    }
};

pub const ForkProgress = struct {
    is_dead: bool,
    fork_stats: ForkStats,
    propagated_stats: PropagatedStats,
    replay_stats: stubs.Arc(stubs.RwLock(blockstore_processor.ReplaySlotStats)),
    replay_progress: stubs.Arc(stubs.RwLock(blockstore_processor.ConfirmationProgress)),
    retransmit_info: RetransmitInfo,

    // NOTE: `num_blocks_on_fork` and `num_dropped_blocks_on_fork` only
    // count new blocks replayed since last restart, which won't include
    // blocks already existing in the ledger/before snapshot at start,
    // so these stats do not span all of time
    num_blocks_on_fork: u64,
    num_dropped_blocks_on_fork: u64,

    pub fn deinit(self: ForkProgress, allocator: std.mem.Allocator) void {
        self.fork_stats.deinit(allocator);
        self.propagated_stats.deinit(allocator);
    }

    pub fn clone(
        self: ForkProgress,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!ForkProgress {
        const fork_stats = try self.fork_stats.clone(allocator);
        errdefer fork_stats.deinit(allocator);

        const propagated_stats = try self.propagated_stats.clone(allocator);
        errdefer propagated_stats.deinit(allocator);

        const replay_stats = try self.replay_stats.arc_ed.rwlock_ed.clone(allocator);
        defer replay_stats.deinit(allocator);

        return .{
            .is_dead = self.is_dead,
            .fork_stats = fork_stats,
            .propagated_stats = propagated_stats,
            .replay_stats = .{ .arc_ed = .{ .rwlock_ed = replay_stats } },
            .replay_progress = self.replay_progress,
            .retransmit_info = self.retransmit_info,
            .num_blocks_on_fork = self.num_blocks_on_fork,
            .num_dropped_blocks_on_fork = self.num_dropped_blocks_on_fork,
        };
    }
};

pub const ForkStats = struct {
    fork_stake: consensus.Stake,
    total_stake: consensus.Stake,
    block_height: u64,
    has_voted: bool,
    is_recent: bool,
    is_empty: bool,
    vote_threshold: VoteThreshold,
    is_locked_out: bool,
    voted_stakes: consensus.VotedStakes,
    duplicate_confirmed_hash: Hash,
    computed: bool,
    lockout_intervals: LockoutIntervals,
    bank_hash: Hash,
    my_latest_landed_vote: Slot,

    pub const VoteThreshold = std.ArrayListUnmanaged(consensus.ThresholdDecision);

    pub fn deinit(
        self: ForkStats,
        allocator: std.mem.Allocator,
    ) void {
        var vote_threshold = self.vote_threshold;
        vote_threshold.deinit(allocator);

        var voted_stakes = self.voted_stakes;
        voted_stakes.deinit(allocator);

        const lockout_intervals = self.lockout_intervals;
        lockout_intervals.deinit(allocator);
    }

    pub fn clone(
        self: ForkStats,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!ForkStats {
        var vote_threshold = try self.vote_threshold.clone(allocator);
        errdefer vote_threshold.deinit(allocator);

        var voted_stakes = try self.voted_stakes.clone(allocator);
        errdefer voted_stakes.deinit(allocator);

        const lockout_intervals = try self.lockout_intervals.clone(allocator);
        errdefer lockout_intervals.deinit(allocator);

        return .{
            .fork_stake = self.fork_stake,
            .total_stake = self.total_stake,
            .block_height = self.block_height,
            .has_voted = self.has_voted,
            .is_recent = self.is_recent,
            .is_empty = self.is_empty,
            .vote_threshold = vote_threshold,
            .is_locked_out = self.is_locked_out,
            .voted_stakes = voted_stakes,
            .duplicate_confirmed_hash = self.duplicate_confirmed_hash,
            .computed = self.computed,
            .lockout_intervals = lockout_intervals,
            .bank_hash = self.bank_hash,
            .my_latest_landed_vote = self.my_latest_landed_vote,
        };
    }

    /// NOTE: Used in tests for generating dummy data.
    pub fn initRandom(
        allocator: std.mem.Allocator,
        random: std.Random,
        params: struct {
            vote_threshold_len: u32,
            voted_stakes_len: u32,
            lockout_intervals_len: u32,
            lockout_interval_entry_max_len: u32,
        },
    ) std.mem.Allocator.Error!ForkStats {
        const vote_threshold =
            try allocator.alloc(consensus.ThresholdDecision, params.vote_threshold_len);
        errdefer allocator.free(vote_threshold);
        for (vote_threshold) |*vt| vt.* = consensus.ThresholdDecision.initRandom(random);

        var voted_stakes: consensus.VotedStakes = .{};
        errdefer voted_stakes.deinit(allocator);
        try voted_stakes.ensureTotalCapacity(allocator, params.vote_threshold_len);
        for (0..params.voted_stakes_len) |_| voted_stakes.putAssumeCapacity(
            random.int(Slot),
            random.int(consensus.Stake),
        );

        var lockout_intervals: LockoutIntervals.Map = .{};
        errdefer lockout_intervals.deinit(allocator);
        try lockout_intervals.ensureTotalCapacity(allocator, params.lockout_intervals_len);
        for (0..params.lockout_intervals_len) |_| lockout_intervals.putAssumeCapacity(
            random.int(ExpirationSlot),
        );

        return .{
            .fork_stake = random.int(consensus.Stake),
            .total_stake = random.int(consensus.Stake),
            .block_height = random.int(u64),
            .has_voted = random.boolean(),
            .is_recent = random.boolean(),
            .is_empty = random.boolean(),
            .vote_threshold = ForkStats.VoteThreshold.fromOwnedSlice(vote_threshold),
            .is_locked_out = random.boolean(),
            .voted_stakes = voted_stakes,
            .duplicate_confirmed_hash = Hash.initRandom(random),
            .computed = random.boolean(),
            .lockout_intervals = lockout_intervals,
            .bank_hash = Hash.ZEROES,
            .my_latest_landed_vote = 123,
        };
    }
};

pub const PropagatedStats = struct {
    propagated_validators: PropagatedValidators,
    propagated_node_ids: PropagatedNodeIds,
    propagated_validators_stake: u64,
    is_propagated: bool,
    is_leader_slot: bool,
    prev_leader_slot: ?Slot,
    slot_vote_tracker: ?stubs.Arc(stubs.RwLock(cluster_info_vote_listener.SlotVoteTracker)),
    cluster_slot_pubkeys: ?stubs.Arc(stubs.RwLock(cluser_slots_service.SlotPubkeys)),
    total_epoch_stake: u64,

    pub const PropagatedValidators = PubkeyArraySet;
    pub const PropagatedNodeIds = PubkeyArraySet;

    pub fn deinit(self: PropagatedStats, allocator: std.mem.Allocator) void {
        var propagated_validators = self.propagated_validators;
        propagated_validators.deinit(allocator);

        var propagated_node_ids = self.propagated_node_ids;
        propagated_node_ids.deinit(allocator);
    }

    pub fn clone(
        self: PropagatedStats,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!PropagatedStats {
        var propagated_validators = try self.propagated_validators.clone(allocator);
        errdefer propagated_validators.deinit(allocator);

        var propagated_node_ids = try self.propagated_node_ids.clone(allocator);
        errdefer propagated_node_ids.deinit(allocator);

        const maybe_slot_vote_tracker: ?cluster_info_vote_listener.SlotVoteTracker = blk: {
            const svt = self.slot_vote_tracker orelse break :blk null;
            break :blk try svt.arc_ed.rwlock_ed.clone(allocator);
        };
        errdefer if (maybe_slot_vote_tracker) |svt| svt.deinit(allocator);

        var maybe_cluster_slot_pubkeys: ?cluser_slots_service.SlotPubkeys = blk: {
            const csp = self.cluster_slot_pubkeys orelse break :blk null;
            break :blk try csp.arc_ed.rwlock_ed.clone(allocator);
        };
        errdefer if (maybe_cluster_slot_pubkeys) |*svt| svt.deinit(allocator);

        return .{
            .propagated_validators = propagated_validators,
            .propagated_node_ids = propagated_node_ids,
            .propagated_validators_stake = self.propagated_validators_stake,
            .is_propagated = self.is_propagated,
            .is_leader_slot = self.is_leader_slot,
            .prev_leader_slot = self.prev_leader_slot,
            .slot_vote_tracker = if (maybe_slot_vote_tracker) |svt| .{
                .arc_ed = .{ .rwlock_ed = svt },
            } else null,
            .cluster_slot_pubkeys = if (maybe_cluster_slot_pubkeys) |csp| .{
                .arc_ed = .{ .rwlock_ed = csp },
            } else null,
            .total_epoch_stake = self.total_epoch_stake,
        };
    }
};

pub const RetransmitInfo = struct {
    retry_time: sig.time.Instant,
    retry_iteration: u32,
};

pub const VotedSlot = Slot;
pub const ExpirationSlot = Slot;
pub const LockoutIntervalEntry = std.ArrayListUnmanaged(struct { VotedSlot, Pubkey });
pub const LockoutIntervals = BTreeMapStub(ExpirationSlot, LockoutIntervalEntry);

pub const consensus = struct {
    pub const Stake = u64;
    pub const VotedStakes = std.AutoArrayHashMapUnmanaged(Slot, Stake);

    pub const ThresholdDecision = union(enum) {
        passed_threshold,
        failed_threshold: FailedThreshold,

        /// NOTE: this is a tuple in the original rust code
        pub const FailedThreshold = struct {
            vote_depth: u64,
            observed_stake: u64,

            /// NOTE: Used in tests for generating dummy data.
            pub fn initRandom(random: std.Random) FailedThreshold {
                return .{
                    .vote_depth = random.int(u64),
                    .observed_stake = random.int(u64),
                };
            }
        };

        /// #[default]
        pub const DEFAULT: ThresholdDecision = .passed_threshold;

        pub fn eql(self: ThresholdDecision, other: ThresholdDecision) bool {
            return std.meta.eql(self, other);
        }

        /// NOTE: Used in tests for generating dummy data.
        pub fn initRandom(random: std.Random) ThresholdDecision {
            const Tag = @typeInfo(ThresholdDecision).Enum.tag_type;
            return switch (random.enumValueWithIndex(Tag, u1)) {
                .passed_threshold => |tag| tag,
                .failed_threshold => |tag| @unionInit(
                    ThresholdDecision,
                    @tagName(tag),
                    FailedThreshold.initRandom(random),
                ),
            };
        }
    };

    pub const VoteStakeTracker = struct {
        voted: PubkeyArraySet,
        stake: u64,

        pub fn deinit(self: VoteStakeTracker, allocator: std.mem.Allocator) void {
            var voted = self.voted;
            voted.deinit(allocator);
        }

        pub fn clone(
            self: VoteStakeTracker,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!VoteStakeTracker {
            var voted = try self.voted.clone(allocator);
            errdefer voted.deinit(allocator);

            return .{
                .voted = voted,
                .stake = self.stake,
            };
        }
    };
};

pub const cluster_info_vote_listener = struct {
    pub const SlotVoteTracker = struct {
        /// Maps pubkeys that have voted for this slot
        /// to whether or not we've seen the vote on gossip.
        /// True if seen on gossip, false if only seen in replay.
        voted: Voted,
        optimistic_votes_tracker: OptimisticVotesTracker,
        voted_slot_updates: ?std.ArrayListUnmanaged(Pubkey),
        gossip_only_stake: u64,

        pub const Voted = std.AutoArrayHashMapUnmanaged(Pubkey, bool);
        pub const OptimisticVotesTracker =
            std.AutoArrayHashMapUnmanaged(Hash, consensus.VoteStakeTracker);

        pub fn deinit(self: SlotVoteTracker, allocator: std.mem.Allocator) void {
            var voted = self.voted;
            voted.deinit(allocator);

            var optimistic_votes_tracker = self.optimistic_votes_tracker;
            for (optimistic_votes_tracker.values()) |vst| vst.deinit(allocator);
            optimistic_votes_tracker.deinit(allocator);

            var maybe_voted_slot_updates = self.voted_slot_updates;
            if (maybe_voted_slot_updates) |*vsu| vsu.deinit(allocator);
        }

        pub fn clone(
            self: SlotVoteTracker,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!SlotVoteTracker {
            var voted = try self.voted.clone(allocator);
            errdefer voted.deinit(allocator);

            var optimistic_votes_tracker = try self.optimistic_votes_tracker.clone(allocator);
            errdefer optimistic_votes_tracker.deinit(allocator);

            var voted_slot_updates: ?std.ArrayListUnmanaged(Pubkey) = blk: {
                const vsu = self.voted_slot_updates orelse break :blk null;
                break :blk try vsu.clone(allocator);
            };
            errdefer if (voted_slot_updates) |*vsu| vsu.deinit(allocator);

            return .{
                .voted = voted,
                .optimistic_votes_tracker = optimistic_votes_tracker,
                .voted_slot_updates = voted_slot_updates,
                .gossip_only_stake = self.gossip_only_stake,
            };
        }
    };
};

pub const cluser_slots_service = struct {
    /// Node->Stake map
    pub const SlotPubkeys = std.AutoArrayHashMapUnmanaged(
        Pubkey, // node
        u64, // stake
    );
};

pub const blockstore_processor = struct {
    pub const ReplaySlotStats = ConfirmationTiming;

    /// Measures different parts of the slot confirmation processing pipeline.
    pub const ConfirmationTiming = struct {
        /// Moment when the `ConfirmationTiming` instance was created.  Used to track the total wall
        /// clock time from the moment the first shard for the slot is received and to the moment the
        /// slot is complete.
        started: sig.time.Instant,

        /// Wall clock time used by the slot confirmation code, including PoH/signature verification,
        /// and replay.  As replay can run in parallel with the verification, this value can not be
        /// recovered from the `replay_elapsed` and or `{poh,transaction}_verify_elapsed`.  This
        /// includes failed cases, when `confirm_slot_entries` exist with an error.  In microseconds.
        /// When unified scheduler is enabled, replay excludes the transaction execution, only
        /// accounting for task creation and submission to the scheduler.
        confirmation_elapsed: u64,

        /// Wall clock time used by the entry replay code.  Does not include the PoH or the transaction
        /// signature/precompiles verification, but can overlap with the PoH and signature verification.
        /// In microseconds.
        /// When unified scheduler is enabled, replay excludes the transaction execution, only
        /// accounting for task creation and submission to the scheduler.
        replay_elapsed: u64,

        /// Wall clock times, used for the PoH verification of entries.  In microseconds.
        poh_verify_elapsed: u64,

        /// Wall clock time, used for the signature verification as well as precompiles verification.
        /// In microseconds.
        transaction_verify_elapsed: u64,

        /// Wall clock time spent loading data sets (and entries) from the blockstore.  This does not
        /// include the case when the blockstore load failed.  In microseconds.
        fetch_elapsed: u64,

        /// Same as `fetch_elapsed` above, but for the case when the blockstore load fails.  In
        /// microseconds.
        fetch_fail_elapsed: u64,

        /// `batch_execute()` measurements.
        batch_execute: BatchExecutionTiming,

        pub fn deinit(self: ConfirmationTiming, allocator: std.mem.Allocator) void {
            self.batch_execute.deinit(allocator);
        }

        pub fn clone(
            self: ConfirmationTiming,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!ConfirmationTiming {
            var copy = self;
            copy.batch_execute = try self.batch_execute.clone(allocator);
            return copy;
        }
    };

    /// Measures times related to transaction execution in a slot.
    pub const BatchExecutionTiming = struct {
        /// Time used by transaction execution.  Accumulated across multiple threads that are running
        /// `execute_batch()`.
        totals: timings.ExecuteTimings,

        /// Wall clock time used by the transaction execution part of pipeline.
        /// [`ConfirmationTiming::replay_elapsed`] includes this time.  In microseconds.
        wall_clock_us: Saturating(u64),

        /// Time used to execute transactions, via `execute_batch()`, in the thread that consumed the
        /// most time (in terms of total_thread_us) among rayon threads. Note that the slowest thread
        /// is determined each time a given group of batches is newly processed. So, this is a coarse
        /// approximation of wall-time single-threaded linearized metrics, discarding all metrics other
        /// than the arbitrary set of batches mixed with various transactions, which replayed slowest
        /// as a whole for each rayon processing session.
        ///
        /// When unified scheduler is enabled, this field isn't maintained, because it's not batched at
        /// all.
        slowest_thread: ThreadExecuteTimings,

        pub fn deinit(self: BatchExecutionTiming, allocator: std.mem.Allocator) void {
            self.totals.deinit(allocator);
            self.slowest_thread.deinit(allocator);
        }

        pub fn clone(
            self: BatchExecutionTiming,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!BatchExecutionTiming {
            return .{
                .totals = try self.totals.clone(allocator),
                .wall_clock_us = self.wall_clock_us,
                .slowest_thread = try self.slowest_thread.clone(allocator),
            };
        }
    };

    pub const ThreadExecuteTimings = struct {
        total_thread_us: Saturating(u64),
        total_transactions_executed: Saturating(u64),
        execute_timings: timings.ExecuteTimings,

        pub fn deinit(self: ThreadExecuteTimings, allocator: std.mem.Allocator) void {
            self.execute_timings.deinit(allocator);
        }

        pub fn clone(
            self: ThreadExecuteTimings,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!ThreadExecuteTimings {
            return .{
                .total_thread_us = self.total_thread_us,
                .total_transactions_executed = self.total_transactions_executed,
                .execute_timings = try self.execute_timings.clone(allocator),
            };
        }
    };

    pub const ConfirmationProgress = struct {
        last_entry: Hash,
        tick_hash_count: u64,
        num_shreds: u64,
        num_entries: usize,
        num_txs: usize,
    };
};

pub const timings = struct {
    pub const ProgramTiming = struct {
        accumulated_us: Saturating(u64),
        accumulated_units: Saturating(u64),
        count: Saturating(u32),
        errored_txs_compute_consumed: std.ArrayListUnmanaged(u64),
        /// Sum of all units in `errored_txs_compute_consumed`
        total_errored_units: Saturating(u64),

        pub fn deinit(self: ProgramTiming, allocator: std.mem.Allocator) void {
            var errored_txs_compute_consumed = self.errored_txs_compute_consumed;
            errored_txs_compute_consumed.deinit(allocator);
        }

        pub fn clone(
            self: ProgramTiming,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!ProgramTiming {
            var errored_txs_compute_consumed =
                try self.errored_txs_compute_consumed.clone(allocator);
            errdefer errored_txs_compute_consumed.deinit(allocator);

            return .{
                .accumulated_us = self.accumulated_us,
                .accumulated_units = self.accumulated_units,
                .count = self.count,
                .errored_txs_compute_consumed = errored_txs_compute_consumed,
                .total_errored_units = self.total_errored_units,
            };
        }

        pub fn eql(self: *const ProgramTiming, other: *const ProgramTiming) bool {
            inline for (@typeInfo(ProgramTiming).Struct.fields) |field| {
                const self_field = &@field(self, field.name);
                const other_field = &@field(other, field.name);
                switch (field.type) {
                    Saturating(u32),
                    Saturating(u64),
                    => if (self_field.toInt() != other_field.toInt()) {
                        return false;
                    },
                    std.ArrayListUnmanaged(u64),
                    => if (!std.mem.eql(u64, self_field.items, other_field.items)) {
                        return false;
                    },
                    else => comptime unreachable,
                }
            }
            return true;
        }

        /// NOTE: Used in tests for generating dummy data.
        pub fn initRandom(
            allocator: std.mem.Allocator,
            random: std.Random,
            err_tx_compute_consume_len: usize,
        ) std.mem.Allocator.Error!ProgramTiming {
            const etcc = try allocator.alloc(u64, err_tx_compute_consume_len);
            errdefer allocator.free(etcc);
            random.bytes(std.mem.sliceAsBytes(etcc));
            return .{
                .accumulated_us = @enumFromInt(random.int(u64)),
                .accumulated_units = @enumFromInt(random.int(u64)),
                .count = @enumFromInt(random.int(u32)),
                .errored_txs_compute_consumed = std.ArrayListUnmanaged(u64).fromOwnedSlice(etcc),
                .total_errored_units = @enumFromInt(random.int(u64)),
            };
        }
    };

    /// Used as an index for `Metrics`.
    pub const ExecuteTimingType = enum(u8) {
        check_us,
        validate_fees_us,
        load_us,
        execute_us,
        store_us,
        update_stakes_cache_us,
        update_executors_us,
        num_execute_batches,
        collect_logs_us,
        total_batches_len,
        update_transaction_statuses,
        program_cache_us,
        check_block_limits_us,
        filter_executable_us,
    };

    pub const Metrics = std.EnumArray(ExecuteTimingType, Saturating(u64));

    pub const ExecuteTimings = struct {
        metrics: Metrics,
        details: ExecuteDetailsTimings,
        execute_accessories: ExecuteAccessoryTimings,

        pub fn deinit(self: ExecuteTimings, allocator: std.mem.Allocator) void {
            self.details.deinit(allocator);
        }

        pub fn clone(self: ExecuteTimings, allocator: std.mem.Allocator) std.mem.Allocator.Error!ExecuteTimings {
            const details = try self.details.clone(allocator);
            errdefer details.deinit(allocator);

            return .{
                .metrics = self.metrics,
                .details = details,
                .execute_accessories = self.execute_accessories,
            };
        }
    };

    pub const ExecuteDetailsTimings = struct {
        serialize_us: Saturating(u64),
        create_vm_us: Saturating(u64),
        execute_us: Saturating(u64),
        deserialize_us: Saturating(u64),
        get_or_create_executor_us: Saturating(u64),
        changed_account_count: Saturating(u64),
        total_account_count: Saturating(u64),
        create_executor_register_syscalls_us: Saturating(u64),
        create_executor_load_elf_us: Saturating(u64),
        create_executor_verify_code_us: Saturating(u64),
        create_executor_jit_compile_us: Saturating(u64),
        per_program_timings: PerProgramTimings,

        pub const PerProgramTimings = std.AutoArrayHashMapUnmanaged(Pubkey, ProgramTiming);

        pub fn deinit(self: ExecuteDetailsTimings, allocator: std.mem.Allocator) void {
            var per_program_timings = self.per_program_timings;
            per_program_timings.deinit(allocator);
        }

        pub fn clone(
            self: ExecuteDetailsTimings,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!ExecuteDetailsTimings {
            var ppt: PerProgramTimings = .{};
            errdefer ppt.deinit(allocator);
            errdefer for (ppt.values()) |program_timing| program_timing.deinit(allocator);
            try ppt.ensureTotalCapacity(allocator, self.per_program_timings.count());
            for (
                self.per_program_timings.keys(),
                self.per_program_timings.values(),
            ) |k, v| ppt.putAssumeCapacityNoClobber(k, try v.clone(allocator));

            var copy = self;
            copy.per_program_timings = ppt;
            return copy;
        }

        pub fn eql(self: *const ExecuteDetailsTimings, other: *const ExecuteDetailsTimings) bool {
            inline for (@typeInfo(ExecuteDetailsTimings).Struct.fields) |field| {
                const self_field = &@field(self, field.name);
                const other_field = &@field(other, field.name);
                switch (field.type) {
                    Saturating(u64),
                    => if (self_field.toInt() != other_field.toInt()) {
                        return false;
                    },
                    std.AutoArrayHashMapUnmanaged(Pubkey, ProgramTiming),
                    => {
                        if (self_field.count() != other_field.count()) {
                            return false;
                        }
                        for (self_field.keys(), self_field.values()) |self_k, self_v| {
                            const other_entry = other_field.getEntry(self_k) orelse return false;
                            if (!self_k.equals(other_entry.key_ptr)) return false;
                            if (!self_v.eql(other_entry.value_ptr)) return false;
                        }
                    },
                    else => comptime unreachable,
                }
            }
            return true;
        }
    };

    pub const ExecuteProcessInstructionTimings = struct {
        total_us: Saturating(u64),
        verify_caller_us: Saturating(u64),
        process_executable_chain_us: Saturating(u64),
        verify_callee_us: Saturating(u64),

        /// NOTE: Used in tests for generating dummy data.
        pub fn initRandom(random: std.Random) ExecuteProcessInstructionTimings {
            return .{
                .total_us = @enumFromInt(random.int(u64)),
                .verify_caller_us = @enumFromInt(random.int(u64)),
                .process_executable_chain_us = @enumFromInt(random.int(u64)),
                .verify_callee_us = @enumFromInt(random.int(u64)),
            };
        }
    };

    pub const ExecuteAccessoryTimings = struct {
        feature_set_clone_us: Saturating(u64),
        get_executors_us: Saturating(u64),
        process_message_us: Saturating(u64),
        process_instructions: ExecuteProcessInstructionTimings,

        /// NOTE: Used in tests for generating dummy data.
        pub fn initRandom(random: std.Random) ExecuteAccessoryTimings {
            return .{
                .feature_set_clone_us = @enumFromInt(random.int(u64)),
                .get_executors_us = @enumFromInt(random.int(u64)),
                .process_message_us = @enumFromInt(random.int(u64)),
                .process_instructions = ExecuteProcessInstructionTimings.initRandom(random),
            };
        }
    };
};

test "ProgressMap memory ownership" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(43125);
    const random = prng.random();

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    var gpa_state: std.heap.GeneralPurposeAllocator(.{}) = .{
        .backing_allocator = arena_state.allocator(),
    };
    const arena_gpa = gpa_state.allocator();
    try testAllocProgressMap(arena_gpa, random);
    try std.testing.expect(!gpa_state.detectLeaks());
}

fn testAllocProgressMap(
    arena: std.mem.Allocator,
    random: std.Random,
) !void {
    const lockout_intervals: LockoutIntervals = .{ .map = try LockoutIntervals.Map.init(
        arena,
        &.{ 7, 8 },
        &.{
            LockoutIntervalEntry.fromOwnedSlice(try arena.dupe(
                struct { VotedSlot, Pubkey },
                &.{.{ 55, Pubkey.ZEROES }},
            )),
            LockoutIntervalEntry.fromOwnedSlice(try arena.dupe(
                struct { VotedSlot, Pubkey },
                &.{.{ 6, Pubkey.ZEROES }},
            )),
        },
    ) };

    const fork_stats: ForkStats = .{
        .fork_stake = 83,
        .total_stake = 81,
        .block_height = 79,
        .has_voted = false,
        .is_recent = true,
        .is_empty = false,
        .vote_threshold = ForkStats.VoteThreshold.fromOwnedSlice(
            try arena.dupe(consensus.ThresholdDecision, &.{
                .passed_threshold,
                .{ .failed_threshold = .{ .vote_depth = 0, .observed_stake = 0 } },
            }),
        ),
        .is_locked_out = false,
        .voted_stakes = try consensus.VotedStakes.init(
            arena,
            &.{ 1, 2, 3 },
            &.{ 10, 20, 30 },
        ),
        .duplicate_confirmed_hash = Hash.ZEROES,
        .computed = false,
        .lockout_intervals = lockout_intervals,
        .bank_hash = Hash.ZEROES,
        .my_latest_landed_vote = 123,
    };

    const propagated_stats: PropagatedStats = .{
        .propagated_validators = try PropagatedStats.PropagatedValidators.init(
            arena,
            &.{ Pubkey.ZEROES, Pubkey.initRandom(random), Pubkey.initRandom(random) },
            &[_]void{{}} ** 3,
        ),
        .propagated_node_ids = try PropagatedStats.PropagatedNodeIds.init(
            arena,
            &.{ Pubkey.ZEROES, Pubkey.initRandom(random), Pubkey.initRandom(random) },
            &[_]void{{}} ** 3,
        ),
        .propagated_validators_stake = random.int(u64),
        .is_propagated = true,
        .is_leader_slot = true,
        .prev_leader_slot = 54321,
        .slot_vote_tracker = .{ .arc_ed = .{ .rwlock_ed = .{
            .voted = try cluster_info_vote_listener.SlotVoteTracker.Voted.init(
                arena,
                &.{Pubkey.initRandom(random)},
                &.{true},
            ),
            .optimistic_votes_tracker = try cluster_info_vote_listener
                .SlotVoteTracker.OptimisticVotesTracker.init(
                arena,
                &.{ Hash.initRandom(random), Hash.initRandom(random) },
                &.{
                    .{
                        .voted = try PubkeyArraySet.init(
                            arena,
                            &.{
                                Pubkey.initRandom(random),
                                Pubkey.initRandom(random),
                                Pubkey.initRandom(random),
                            },
                            &[_]void{{}} ** 3,
                        ),
                        .stake = 0,
                    },
                    .{
                        .voted = try PubkeyArraySet.init(
                            arena,
                            &.{
                                Pubkey.initRandom(random),
                                Pubkey.initRandom(random),
                                Pubkey.initRandom(random),
                            },
                            &[_]void{{}} ** 3,
                        ),
                        .stake = 0,
                    },
                },
            ),
            .voted_slot_updates = std.ArrayListUnmanaged(Pubkey).fromOwnedSlice(
                try arena.dupe(Pubkey, &.{
                    Pubkey.initRandom(random),
                    Pubkey.initRandom(random),
                    Pubkey.initRandom(random),
                }),
            ),
            .gossip_only_stake = 7730,
        } } },
        .cluster_slot_pubkeys = .{
            .arc_ed = .{ .rwlock_ed = try cluser_slots_service.SlotPubkeys.init(
                arena,
                &.{ Pubkey.initRandom(random), Pubkey.initRandom(random) },
                &.{ 23, 34 },
            ) },
        },
        .total_epoch_stake = 11111111,
    };

    const details: timings.ExecuteDetailsTimings = .{
        .serialize_us = @enumFromInt(1),
        .create_vm_us = @enumFromInt(2),
        .execute_us = @enumFromInt(3),
        .deserialize_us = @enumFromInt(4),
        .get_or_create_executor_us = @enumFromInt(5),
        .changed_account_count = @enumFromInt(6),
        .total_account_count = @enumFromInt(7),
        .create_executor_register_syscalls_us = @enumFromInt(8),
        .create_executor_load_elf_us = @enumFromInt(9),
        .create_executor_verify_code_us = @enumFromInt(10),
        .create_executor_jit_compile_us = @enumFromInt(11),
        .per_program_timings = try timings.ExecuteDetailsTimings.PerProgramTimings.init(
            arena,
            &.{ Pubkey.initRandom(random), Pubkey.initRandom(random) },
            &.{
                try timings.ProgramTiming.initRandom(arena, random, 4),
                try timings.ProgramTiming.initRandom(arena, random, 4),
            },
        ),
    };

    const totals: timings.ExecuteTimings = .{
        .metrics = timings.Metrics.initFill(@enumFromInt(79)),
        .details = details,
        .execute_accessories = timings.ExecuteAccessoryTimings.initRandom(random),
    };

    const execute_timings: timings.ExecuteTimings = .{
        .metrics = timings.Metrics.initFill(@enumFromInt(45110)),
        .details = .{
            .serialize_us = @enumFromInt(81663),
            .create_vm_us = @enumFromInt(22763),
            .execute_us = @enumFromInt(21867),
            .deserialize_us = @enumFromInt(11963),
            .get_or_create_executor_us = @enumFromInt(81063),
            .changed_account_count = @enumFromInt(21623),
            .total_account_count = @enumFromInt(21568),
            .create_executor_register_syscalls_us = @enumFromInt(91262),
            .create_executor_load_elf_us = @enumFromInt(19365),
            .create_executor_verify_code_us = @enumFromInt(463211),
            .create_executor_jit_compile_us = @enumFromInt(211563),
            .per_program_timings = try timings.ExecuteDetailsTimings.PerProgramTimings.init(
                arena,
                &.{ Pubkey.initRandom(random), Pubkey.initRandom(random) },
                &.{
                    try timings.ProgramTiming.initRandom(arena, random, 8),
                    try timings.ProgramTiming.initRandom(arena, random, 8),
                },
            ),
        },
        .execute_accessories = timings.ExecuteAccessoryTimings.initRandom(random),
    };

    const batch_execute: blockstore_processor.BatchExecutionTiming = .{
        .totals = totals,
        .wall_clock_us = @enumFromInt(257),
        .slowest_thread = .{
            .total_thread_us = @enumFromInt(5525),
            .total_transactions_executed = @enumFromInt(29286),
            .execute_timings = execute_timings,
        },
    };

    const replay_stats: stubs.Arc(stubs.RwLock(blockstore_processor.ReplaySlotStats)) = .{
        .arc_ed = .{ .rwlock_ed = .{
            .started = sig.time.Instant.UNIX_EPOCH,
            .confirmation_elapsed = 98,
            .replay_elapsed = 89,
            .poh_verify_elapsed = 68,
            .transaction_verify_elapsed = 27,
            .fetch_elapsed = 4097,
            .fetch_fail_elapsed = 987654321,
            .batch_execute = batch_execute,
        } },
    };

    var progress_map = ProgressMap.INIT;
    try progress_map.map.put(arena, 1, .{
        .is_dead = false,
        .fork_stats = fork_stats,
        .propagated_stats = propagated_stats,
        .replay_stats = replay_stats,
        .replay_progress = .{ .arc_ed = .{ .rwlock_ed = .{
            .last_entry = Hash.initRandom(random),
            .tick_hash_count = 84635,
            .num_shreds = 20394,
            .num_entries = 32206,
            .num_txs = 19911,
        } } },
        .retransmit_info = .{
            .retry_time = sig.time.Instant.UNIX_EPOCH,
            .retry_iteration = 3,
        },
        .num_blocks_on_fork = 3,
        .num_dropped_blocks_on_fork = 3,
    });

    const cloned = try progress_map.clone(arena);

    cloned.deinit(arena);
    progress_map.deinit(arena);
}
