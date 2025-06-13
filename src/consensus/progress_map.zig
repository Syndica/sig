const std = @import("std");
const sig = @import("../sig.zig");

const Slot = sig.core.Slot;
const Epoch = sig.core.Epoch;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const PubkeyArraySet = std.AutoArrayHashMapUnmanaged(Pubkey, void);

/// TODO: any uses of these types are to be evaluated in their context, and
/// the actual required semantics are to be determined later.
const stubs = struct {
    fn Arc(comptime T: type) type {
        return struct { arc_ed: T };
    }
    fn RwLock(comptime T: type) type {
        return struct { rwlock_ed: T };
    }

    const VoteAccountUnused = struct {};

    const Bank = struct {
        data: sig.core.BankFields,

        fn isFrozen(self: Bank) bool {
            return !self.data.hash.eql(Hash.ZEROES);
        }

        fn totalEpochStake(self: Bank) u64 {
            const epoch_stakes = self.data.epoch_stakes.get(self.data.epoch) orelse
                std.debug.panic("Epoch stakes for bank's own epoch must exist", .{});
            return epoch_stakes.total_stake;
        }

        /// Get the fixed stake of the given vote account for the current epoch
        fn epochVoteAccountStake(self: Bank, vote_account: Pubkey) u64 {
            const eva = self.epochVoteAccounts(self.data.epoch) orelse std.debug.panic(
                "Bank epoch vote accounts must contain entry for the bank's own epoch",
                .{},
            );
            const stake, _ = eva.get(vote_account) orelse return 0;
            return stake;
        }

        /// Get the fixed set of vote accounts for the given node id for the
        /// current epoch
        fn epochVoteAccountsForNodeId(
            self: Bank,
            node_id: Pubkey,
        ) ?*const sig.core.stake.NodeVoteAccounts {
            const epoch_stakes = self.data.epoch_stakes.getPtr(self.data.epoch) orelse
                std.debug.panic("Epoch stakes for bank's own epoch must exist", .{});
            return epoch_stakes.node_id_to_vote_accounts.getPtr(node_id);
        }

        /// vote accounts for the specific epoch along with the stake
        /// attributed to each account
        fn epochVoteAccounts(
            self: Bank,
            epoch: Epoch,
        ) ?*const sig.core.stake.StakeAndVoteAccountsMap {
            const epoch_stakes = self.data.epoch_stakes.getPtr(epoch) orelse return null;
            return &epoch_stakes.stakes.vote_accounts.accounts;
        }
    };
};

/// TODO: merge into real replay stage when it exists?
const replay_stage = struct {
    pub const SUPERMINORITY_THRESHOLD: struct {
        comptime numerator: comptime_int = 1,
        comptime denominator: comptime_int = 3,

        pub fn asFloat(self: @This(), comptime T: type) T {
            const num: T = @floatFromInt(self.numerator);
            const denom: T = @floatFromInt(self.denominator);
            return num / denom;
        }

        pub fn orderAgainstScalar(self: @This(), value: anytype) std.math.Order {
            const T = @TypeOf(value);
            switch (@typeInfo(T)) {
                .ComptimeInt,
                => std.math.order(self.numerator, self.denominator * value),
                .Int,
                => std.math.order(self.numerator, std.math.mulWide(T, self.denominator, value)),
                .ComptimeFloat,
                .Float,
                => std.math.order(self.asFloat(T), value),
                else => comptime unreachable,
            }
        }

        /// Order of threshold against `fraction_num / fraction_denom` without conversion to floating point.
        pub fn orderAgainstFraction(
            self: @This(),
            fraction_num: anytype,
            fraction_denom: anytype,
        ) std.math.Order {
            const Num = @TypeOf(fraction_num);
            const Denom = @TypeOf(fraction_denom);

            const NormalizedNum =
                std.math.IntFittingRange(0, self.numerator * std.math.maxInt(Denom));
            const self_norm_num = @as(NormalizedNum, self.numerator) * fraction_denom;

            const NormalizedDenom =
                std.math.IntFittingRange(0, std.math.maxInt(Num) * self.denominator);
            const frac_norm_num = fraction_num * @as(NormalizedDenom, self.denominator);

            return std.math.order(self_norm_num, frac_norm_num);
        }
    } = .{};
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
                .pointer => |info| info,
                .optional => |info| switch (@typeInfo(info.child)) {
                    .pointer => return ?AsInt(info.child),
                    else => lazy.nonMatchErr(),
                },
                else => lazy.nonMatchErr(),
            };
            if (info.size != .one) lazy.nonMatchErr();
            if (info.child != Saturating(T)) lazy.nonMatchErr();
            info.child = T;

            return @Type(.{ .pointer = info });
        }
    };
}

/// AUDIT: https://github.com/anza-xyz/agave/blob/cb32984a9b0d5c2c6f7775bed39b66d3a22e3c46/core/src/consensus/progress_map.rs
pub const ProgressMap = struct {
    map: std.AutoArrayHashMapUnmanaged(Slot, ForkProgress),

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
        var result: ProgressMap = INIT;
        errdefer result.deinit(allocator);

        try result.map.ensureTotalCapacity(allocator, self.map.count());
        for (self.map.keys(), self.map.values()) |k, v| {
            result.map.putAssumeCapacityNoClobber(k, try v.clone(allocator));
        }

        return result;
    }

    pub fn getForkStats(self: ProgressMap, slot: Slot) ?*ForkStats {
        const fork_progress = self.map.getPtr(slot) orelse return null;
        return &fork_progress.fork_stats;
    }

    pub fn getHash(self: *const ProgressMap, slot: Slot) ?Hash {
        const fork_progress = self.map.get(slot) orelse return null;
        return fork_progress.fork_stats.bank_hash;
    }

    pub fn getLeaderPropagationSlotMustExist(
        self: *const ProgressMap,
        slot: Slot,
    ) !struct { bool, ?Slot } {
        const fork_progress = self.map.get(slot) orelse {
            // Slot not found in progress map - leader is considered confirmed
            return .{ true, null };
        };

        const leader_slot = if (fork_progress.propagated_stats.is_leader_slot)
            slot
        else
            fork_progress.propagated_stats.prev_leader_slot;

        // If we got here, we have a leader slot
        const is_propagated = if (self.map.get(slot)) |stats|
            stats.propagated_stats.is_propagated
        else
            true;

        return .{ is_propagated, leader_slot };
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
        self.replay_stats.arc_ed.rwlock_ed.deinit(allocator);
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
        errdefer replay_stats.deinit(allocator);

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

    pub fn initFromBank(
        allocator: std.mem.Allocator,
        params: struct {
            bank: *const stubs.Bank,
            /// Should usually be `.now()`.
            now: std.time.Instant,
            validator_identity: *const Pubkey,
            validator_vote_pubkey: *const Pubkey,
            prev_leader_slot: ?Slot,
            num_blocks_on_fork: u64,
            num_dropped_blocks_on_fork: u64,
        },
    ) std.mem.Allocator.Error!ForkProgress {
        const validator_stake_info: ?ValidatorStakeInfo = if (Pubkey.equals(
            &params.bank.data.collector_id,
            params.validator_identity,
        )) .{
            .validator_vote_pubkey = params.validator_vote_pubkey.*,
            .stake = params.bank.epochVoteAccountStake(params.validator_vote_pubkey.*),
            .total_epoch_stake = params.bank.totalEpochStake(),
        } else null;

        var new_progress = try ForkProgress.init(allocator, .{
            .now = params.now,
            .last_entry = params.bank.data.blockhash_queue.last_hash orelse std.debug.panic(
                "no hash has been set",
                .{},
            ),
            .prev_leader_slot = params.prev_leader_slot,
            .validator_stake_info = validator_stake_info,
            .num_blocks_on_fork = params.num_blocks_on_fork,
            .num_dropped_blocks_on_fork = params.num_dropped_blocks_on_fork,
        });
        errdefer new_progress.deinit(allocator);

        if (params.bank.isFrozen()) {
            new_progress.fork_stats.bank_hash = params.bank.data.hash;
        }

        return new_progress;
    }

    pub const InitParams = struct {
        /// Should usually be `.now()`.
        now: std.time.Instant,
        last_entry: Hash,
        prev_leader_slot: ?Slot,
        validator_stake_info: ?ValidatorStakeInfo,
        num_blocks_on_fork: u64,
        num_dropped_blocks_on_fork: u64,
    };

    pub fn zeroes(
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!ForkProgress {
        return ForkProgress.init(allocator, .{
            .now = sig.time.clock.sample(),
            .last_entry = Hash.ZEROES,
            .prev_leader_slot = 0,
            .validator_stake_info = ValidatorStakeInfo.DEFAULT,
            .num_blocks_on_fork = 0,
            .num_dropped_blocks_on_fork = 0,
        });
    }

    pub fn init(
        allocator: std.mem.Allocator,
        params: InitParams,
    ) std.mem.Allocator.Error!ForkProgress {
        const is_leader_slot: bool, //
        const propagated_validators_stake: u64, //
        var propagated_validators: PubkeyArraySet, //
        const is_propagated: bool, //
        const total_epoch_stake: u64 //
        = if (params.validator_stake_info) |info| blk: {
            const propagated_validators =
                try PubkeyArraySet.init(allocator, &.{info.validator_vote_pubkey}, &.{});
            errdefer comptime unreachable;
            break :blk .{
                true,
                info.stake,
                propagated_validators,
                info.isPropagated(),
                info.total_epoch_stake,
            };
        } else .{ false, 0, .{}, false, 0 };
        errdefer propagated_validators.deinit(allocator);

        return .{
            .is_dead = false,
            .fork_stats = ForkStats.EMPTY_ZEROES,
            .replay_stats = .{ .arc_ed = .{
                .rwlock_ed = blockstore_processor.ReplaySlotStats.initEmptyZeroes(params.now),
            } },
            .replay_progress = .{ .arc_ed = .{
                .rwlock_ed = blockstore_processor.ConfirmationProgress.init(params.last_entry),
            } },
            .num_blocks_on_fork = params.num_blocks_on_fork,
            .num_dropped_blocks_on_fork = params.num_dropped_blocks_on_fork,
            .propagated_stats = .{
                .propagated_validators = propagated_validators,
                .propagated_validators_stake = propagated_validators_stake,
                .is_propagated = is_propagated,
                .is_leader_slot = is_leader_slot,
                .prev_leader_slot = params.prev_leader_slot,
                .total_epoch_stake = total_epoch_stake,

                .propagated_node_ids = .{},
                .slot_vote_tracker = null,
                .cluster_slot_pubkeys = null,
            },
            .retransmit_info = .{
                .retry_time = params.now,
                .retry_iteration = 0,
            },
        };
    }
};

pub const ValidatorStakeInfo = struct {
    validator_vote_pubkey: Pubkey,
    stake: u64,
    total_epoch_stake: u64,

    pub const DEFAULT: ValidatorStakeInfo = .{
        .stake = 0,
        .validator_vote_pubkey = Pubkey.ZEROES,
        .total_epoch_stake = 1,
    };

    pub fn isPropagated(self: ValidatorStakeInfo) bool {
        return self.total_epoch_stake == 0 or
            replay_stage.SUPERMINORITY_THRESHOLD
                .orderAgainstFraction(self.stake, self.total_epoch_stake) == .lt;
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
    my_latest_landed_vote: ?Slot,

    pub const VoteThreshold = std.ArrayListUnmanaged(consensus.ThresholdDecision);

    pub const EMPTY_ZEROES: ForkStats = .{
        .fork_stake = 0,
        .total_stake = 0,
        .block_height = 0,
        .has_voted = false,
        .is_recent = false,
        .is_empty = false,
        .vote_threshold = .{},
        .is_locked_out = false,
        .voted_stakes = .{},
        .duplicate_confirmed_hash = Hash.ZEROES,
        .computed = false,
        .lockout_intervals = LockoutIntervals.EMPTY,
        .bank_hash = Hash.ZEROES,
        .my_latest_landed_vote = 0,
    };

    pub fn deinit(self: ForkStats, allocator: std.mem.Allocator) void {
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

    pub fn forkWeight(self: *const ForkStats) f64 {
        return @as(f64, @floatFromInt(self.fork_stake)) / @as(f64, @floatFromInt(self.total_stake));
    }
};

pub const PropagatedStats = struct {
    propagated_validators: PubkeyArraySet,
    propagated_node_ids: PubkeyArraySet,
    propagated_validators_stake: u64,
    is_propagated: bool,
    is_leader_slot: bool,
    prev_leader_slot: ?Slot,
    slot_vote_tracker: ?stubs.Arc(stubs.RwLock(cluster_info_vote_listener.SlotVoteTracker)),
    cluster_slot_pubkeys: ?stubs.Arc(stubs.RwLock(cluser_slots_service.SlotPubkeys)),
    total_epoch_stake: u64,

    pub const EMPTY_ZEROES: PropagatedStats = .{
        .propagated_validators = .{},
        .propagated_node_ids = .{},
        .propagated_validators_stake = 0,
        .is_propagated = false,
        .is_leader_slot = false,
        .prev_leader_slot = null,
        .slot_vote_tracker = null,
        .cluster_slot_pubkeys = null,
        .total_epoch_stake = 0,
    };

    pub fn deinit(self: PropagatedStats, allocator: std.mem.Allocator) void {
        var propagated_validators = self.propagated_validators;
        propagated_validators.deinit(allocator);

        var propagated_node_ids = self.propagated_node_ids;
        propagated_node_ids.deinit(allocator);

        if (self.slot_vote_tracker) |svt| svt.arc_ed.rwlock_ed.deinit(allocator);
        var maybe_csp = if (self.cluster_slot_pubkeys) |csp| csp.arc_ed.rwlock_ed else null;
        if (maybe_csp) |*csp| csp.deinit(allocator);
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

    /// Same as `addVotePubkeyAssumeCapacity`, except it [re-]allocates if needed, instead of
    /// assuming capacity is sufficient.
    pub fn addVotePubkey(
        self: *PropagatedStats,
        allocator: std.mem.Allocator,
        vote_pubkey: Pubkey,
        stake: u64,
    ) std.mem.Allocator.Error!bool {
        const gop = try self.propagated_validators.getOrPut(allocator, vote_pubkey);
        gop.value_ptr.* = {};
        if (!gop.found_existing) self.propagated_validators_stake += stake;
        return !gop.found_existing;
    }

    /// Adds `vote_pubkey` to the propagated validator pubkey set, adding its associated `stake`
    /// to the total propagated validator stake.
    ///
    /// Returns a bool indicating whether or not `vote_pubkey` was inserted into the set, ie
    /// it returns `true` if `vote_pubkey` was inserted, and `false` if it already existed (and
    /// thus wouldn't have been inserted).
    ///
    /// This assumes that the capacity of `self.propagated_validators` is enough to hold at least
    /// one new entry, or that `vote_pubkey` is already an entry.
    pub fn addVotePubkeyAssumeCapacity(
        self: *PropagatedStats,
        vote_pubkey: Pubkey,
        stake: u64,
    ) bool {
        const gop = self.propagated_validators.getOrPutAssumeCapacity(vote_pubkey);
        gop.value_ptr.* = {};
        if (!gop.found_existing) self.propagated_validators_stake += stake;
        return !gop.found_existing;
    }

    pub fn addNodePubkey(
        self: *PropagatedStats,
        allocator: std.mem.Allocator,
        node_pubkey: Pubkey,
        bank: stubs.Bank,
    ) std.mem.Allocator.Error!void {
        if (self.propagated_node_ids.contains(node_pubkey)) return;
        const nva = bank.epochVoteAccountsForNodeId(node_pubkey) orelse return;
        const epoch_vote_accounts = bank.epochVoteAccounts(bank.data.epoch) orelse std.debug.panic(
            "Epoch stakes for bank's own epoch must exist",
            .{},
        );
        try self.addNodePubkeyInternal(
            allocator,
            node_pubkey,
            nva.vote_accounts,
            epoch_vote_accounts.*,
        );
    }

    fn addNodePubkeyInternal(
        self: *PropagatedStats,
        allocator: std.mem.Allocator,
        node_pubkey: Pubkey,
        vote_account_pubkeys: []const Pubkey,
        epoch_vote_accounts: sig.core.stake.StakeAndVoteAccountsMap,
    ) std.mem.Allocator.Error!void {
        try self.propagated_node_ids.put(allocator, node_pubkey, {});

        try self.propagated_validators.ensureUnusedCapacity(allocator, vote_account_pubkeys.len);
        for (vote_account_pubkeys) |vote_account_pubkey| {
            const stake = blk: {
                const stake, _ = epoch_vote_accounts.get(vote_account_pubkey) orelse break :blk 0;
                break :blk stake;
            };
            _ = self.addVotePubkeyAssumeCapacity(vote_account_pubkey, stake);
        }
    }
};

pub const RetransmitInfo = struct {
    retry_time: std.time.Instant,
    retry_iteration: u32,
};

pub const LockoutIntervals = struct {
    map: HashThatShouldBeMadeBTreeMap,

    /// TODO: replace this with a BTree map. In the meantime, just have to
    /// manually keep this sorted.
    pub const HashThatShouldBeMadeBTreeMap =
        std.AutoArrayHashMapUnmanaged(ExpirationSlot, EntryList);

    pub const EntryList = std.ArrayListUnmanaged(EntryElement);
    pub const EntryElement = struct { VotedSlot, Pubkey };
    pub const VotedSlot = Slot;
    pub const ExpirationSlot = Slot;

    pub const EMPTY: LockoutIntervals = .{ .map = .{} };

    pub fn deinit(self: LockoutIntervals, allocator: std.mem.Allocator) void {
        var btree = self.map;
        for (btree.values()) |*list| list.deinit(allocator);
        btree.deinit(allocator);
    }

    pub fn clone(
        self: LockoutIntervals,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!LockoutIntervals {
        var cloned: LockoutIntervals = EMPTY;
        errdefer cloned.deinit(allocator);

        try cloned.map.ensureTotalCapacity(allocator, self.map.count());
        for (self.map.keys(), self.map.values()) |k, v| {
            cloned.map.putAssumeCapacity(k, try v.clone(allocator));
        }

        return cloned;
    }
};

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
        };

        /// #[default]
        pub const DEFAULT: ThresholdDecision = .passed_threshold;

        pub fn eql(self: ThresholdDecision, other: ThresholdDecision) bool {
            return std.meta.eql(self, other);
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

        pub fn deinit(self: SlotVoteTracker, allocator: std.mem.Allocator) void {
            var voted = self.voted;
            voted.deinit(allocator);

            self.optimistic_votes_tracker.deinit(allocator);

            var maybe_voted_slot_updates = self.voted_slot_updates;
            if (maybe_voted_slot_updates) |*vsu| vsu.deinit(allocator);
        }

        pub fn clone(
            self: SlotVoteTracker,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!SlotVoteTracker {
            var voted = try self.voted.clone(allocator);
            errdefer voted.deinit(allocator);

            const optimistic_votes_tracker = try self.optimistic_votes_tracker.clone(allocator);
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

    pub const OptimisticVotesTracker = struct {
        map: std.AutoArrayHashMapUnmanaged(Hash, consensus.VoteStakeTracker),

        pub const EMPTY: OptimisticVotesTracker = .{ .map = .{} };

        pub fn deinit(self: OptimisticVotesTracker, allocator: std.mem.Allocator) void {
            for (self.map.values()) |vst| vst.deinit(allocator);
            var map = self.map;
            map.deinit(allocator);
        }

        pub fn clone(
            self: OptimisticVotesTracker,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!OptimisticVotesTracker {
            var cloned_ovt = OptimisticVotesTracker.EMPTY;
            errdefer cloned_ovt.deinit(allocator);

            try cloned_ovt.map.ensureTotalCapacity(allocator, self.map.count());
            for (self.map.keys(), self.map.values()) |k, v| {
                cloned_ovt.map.putAssumeCapacity(k, try v.clone(allocator));
            }

            return cloned_ovt;
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
        started: std.time.Instant,

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

        pub fn initEmptyZeroes(
            /// Should usually be `.now()`.
            started: std.time.Instant,
        ) ConfirmationTiming {
            return .{
                .started = started,
                .confirmation_elapsed = 0,
                .replay_elapsed = 0,
                .poh_verify_elapsed = 0,
                .transaction_verify_elapsed = 0,
                .fetch_elapsed = 0,
                .fetch_fail_elapsed = 0,
                .batch_execute = BatchExecutionTiming.EMPTY_ZEROES,
            };
        }

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

        pub const EMPTY_ZEROES: BatchExecutionTiming = .{
            .totals = timings.ExecuteTimings.EMPTY_ZEROES,
            .wall_clock_us = @enumFromInt(0),
            .slowest_thread = ThreadExecuteTimings.EMPTY_ZEROES,
        };

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

        pub const EMPTY_ZEROES: ThreadExecuteTimings = .{
            .total_thread_us = @enumFromInt(0),
            .total_transactions_executed = @enumFromInt(0),
            .execute_timings = timings.ExecuteTimings.EMPTY_ZEROES,
        };

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

        pub fn init(last_entry: Hash) ConfirmationProgress {
            return .{
                .last_entry = last_entry,

                .tick_hash_count = 0,
                .num_shreds = 0,
                .num_entries = 0,
                .num_txs = 0,
            };
        }
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
            inline for (@typeInfo(ProgramTiming).@"struct".fields) |field| {
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

        pub const EMPTY_ZEROES: ExecuteTimings = .{
            .metrics = Metrics.initFill(@enumFromInt(0)),
            .details = ExecuteDetailsTimings.EMPTY_ZEROES,
            .execute_accessories = ExecuteAccessoryTimings.ZEROES,
        };

        pub fn deinit(self: ExecuteTimings, allocator: std.mem.Allocator) void {
            self.details.deinit(allocator);
        }

        pub fn clone(
            self: ExecuteTimings,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!ExecuteTimings {
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

        pub const EMPTY_ZEROES: ExecuteDetailsTimings = .{
            .serialize_us = @enumFromInt(0),
            .create_vm_us = @enumFromInt(0),
            .execute_us = @enumFromInt(0),
            .deserialize_us = @enumFromInt(0),
            .get_or_create_executor_us = @enumFromInt(0),
            .changed_account_count = @enumFromInt(0),
            .total_account_count = @enumFromInt(0),
            .create_executor_register_syscalls_us = @enumFromInt(0),
            .create_executor_load_elf_us = @enumFromInt(0),
            .create_executor_verify_code_us = @enumFromInt(0),
            .create_executor_jit_compile_us = @enumFromInt(0),
            .per_program_timings = PerProgramTimings.EMPTY,
        };

        pub fn deinit(self: ExecuteDetailsTimings, allocator: std.mem.Allocator) void {
            self.per_program_timings.deinit(allocator);
        }

        pub fn clone(
            self: ExecuteDetailsTimings,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!ExecuteDetailsTimings {
            var copy = self;
            copy.per_program_timings = try self.per_program_timings.clone(allocator);
            return copy;
        }

        pub fn eql(self: *const ExecuteDetailsTimings, other: *const ExecuteDetailsTimings) bool {
            inline for (@typeInfo(ExecuteDetailsTimings).@"struct".fields) |field| {
                const self_field = &@field(self, field.name);
                const other_field = &@field(other, field.name);
                switch (field.type) {
                    Saturating(u64),
                    => if (self_field.toInt() != other_field.toInt()) {
                        return false;
                    },
                    PerProgramTimings,
                    => if (!self_field.eql(other_field.*)) {
                        return false;
                    },
                    else => comptime unreachable,
                }
            }
            return true;
        }
    };

    pub const PerProgramTimings = struct {
        map: std.AutoArrayHashMapUnmanaged(Pubkey, ProgramTiming),

        pub const EMPTY: PerProgramTimings = .{ .map = .{} };

        pub fn deinit(self: PerProgramTimings, allocator: std.mem.Allocator) void {
            for (self.map.values()) |pt| pt.deinit(allocator);
            var map = self.map;
            map.deinit(allocator);
        }

        pub fn clone(
            self: PerProgramTimings,
            allocator: std.mem.Allocator,
        ) std.mem.Allocator.Error!PerProgramTimings {
            var cloned = PerProgramTimings.EMPTY;
            errdefer cloned.deinit(allocator);

            try cloned.map.ensureTotalCapacity(allocator, self.map.count());
            for (self.map.keys(), self.map.values()) |k, v| {
                cloned.map.putAssumeCapacityNoClobber(k, try v.clone(allocator));
            }

            return cloned;
        }

        /// Compares the maps, unordered.
        pub fn eql(self: PerProgramTimings, other: PerProgramTimings) bool {
            if (self.map.count() != self.map.count()) {
                return false;
            }
            for (self.map.keys(), self.map.values()) |self_k, self_v| {
                const other_v = other.map.get(self_k) orelse return false;
                if (!self_v.eql(&other_v)) return false;
            }
            return true;
        }
    };

    pub const ExecuteProcessInstructionTimings = struct {
        total_us: Saturating(u64),
        verify_caller_us: Saturating(u64),
        process_executable_chain_us: Saturating(u64),
        verify_callee_us: Saturating(u64),

        pub const ZEROES: ExecuteProcessInstructionTimings = .{
            .total_us = @enumFromInt(0),
            .verify_caller_us = @enumFromInt(0),
            .process_executable_chain_us = @enumFromInt(0),
            .verify_callee_us = @enumFromInt(0),
        };
    };

    pub const ExecuteAccessoryTimings = struct {
        feature_set_clone_us: Saturating(u64),
        get_executors_us: Saturating(u64),
        process_message_us: Saturating(u64),
        process_instructions: ExecuteProcessInstructionTimings,

        pub const ZEROES: ExecuteAccessoryTimings = .{
            .feature_set_clone_us = @enumFromInt(0),
            .get_executors_us = @enumFromInt(0),
            .process_message_us = @enumFromInt(0),
            .process_instructions = ExecuteProcessInstructionTimings.ZEROES,
        };
    };
};

test "ProgressMap memory ownership" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(43125);
    const random = prng.random();

    var progress_map = ProgressMap.INIT;
    defer progress_map.deinit(allocator);

    {
        const fork_progress = try forkProgressInitRandom(allocator, random);
        errdefer fork_progress.deinit(allocator);
        try progress_map.map.put(allocator, random.int(Slot), fork_progress);
    }

    const cloned = try progress_map.clone(allocator);
    defer cloned.deinit(allocator);
}

test "ForkProgress.init" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(3744);
    const random = prng.random();

    const now = sig.time.clock.sample();
    var bank: stubs.Bank = .{
        .data = try sig.core.BankFields.initRandom(allocator, random, 128),
    };
    defer bank.data.deinit(allocator);
    bank.data.hash = Hash.ZEROES;

    const vsi: ValidatorStakeInfo = .{
        .validator_vote_pubkey = bank.data.collector_id,
        .stake = bank.epochVoteAccountStake(bank.data.collector_id),
        .total_epoch_stake = bank.totalEpochStake(),
    };

    var expected_propagated_validators: PubkeyArraySet = .{};
    defer expected_propagated_validators.deinit(allocator);
    try expected_propagated_validators.put(allocator, vsi.validator_vote_pubkey, {});

    const expected_fork_stats = stats: {
        var fork_stats = ForkStats.EMPTY_ZEROES;
        fork_stats.bank_hash = bank.data.hash;
        break :stats fork_stats;
    };

    const expected: ForkProgress = .{
        .is_dead = false,
        .fork_stats = expected_fork_stats,
        .replay_stats = .{ .arc_ed = .{
            .rwlock_ed = blockstore_processor
                .ReplaySlotStats.initEmptyZeroes(now),
        } },
        .replay_progress = .{ .arc_ed = .{
            .rwlock_ed = blockstore_processor
                .ConfirmationProgress.init(bank.data.blockhash_queue.last_hash.?),
        } },
        .num_blocks_on_fork = 15,
        .num_dropped_blocks_on_fork = 16,
        .propagated_stats = .{
            .propagated_validators = expected_propagated_validators,
            .propagated_validators_stake = vsi.stake,
            .is_propagated = vsi.isPropagated(),
            .is_leader_slot = true,
            .prev_leader_slot = null,
            .total_epoch_stake = vsi.total_epoch_stake,

            .propagated_node_ids = .{},
            .slot_vote_tracker = null,
            .cluster_slot_pubkeys = null,
        },
        .retransmit_info = .{
            .retry_time = now,
            .retry_iteration = 0,
        },
    };

    const actual_init = try ForkProgress.init(allocator, .{
        .now = now,
        .last_entry = bank.data.blockhash_queue.last_hash.?,
        .prev_leader_slot = null,
        .validator_stake_info = vsi,
        .num_blocks_on_fork = 15,
        .num_dropped_blocks_on_fork = 16,
    });
    defer actual_init.deinit(allocator);

    const actual_init_from_bank = try ForkProgress.initFromBank(allocator, .{
        .bank = &bank,
        .now = now,
        .validator_identity = &bank.data.collector_id,
        .validator_vote_pubkey = &vsi.validator_vote_pubkey,
        .prev_leader_slot = null,
        .num_blocks_on_fork = 15,
        .num_dropped_blocks_on_fork = 16,
    });
    defer actual_init_from_bank.deinit(allocator);

    for (0.., [_]ForkProgress{
        actual_init,
        actual_init_from_bank,
    }) |fp_i, actual| {
        errdefer std.log.err("Failure on ForkProgress [{d}]", .{fp_i});
        try sig.testing.expectEqualDeepWithOverrides(expected, actual, struct {
            pub fn compare(a: anytype, b: @TypeOf(a)) !bool {
                const T = @TypeOf(a);
                if (sig.utils.types.arrayListInfo(T)) |info| {
                    try std.testing.expectEqualSlices(info.Elem, a.items, b.items);
                    return true;
                }
                if (sig.utils.types.hashMapInfo(T)) |info| {
                    try std.testing.expectEqualSlices(info.Key, a.keys(), b.keys());
                    try std.testing.expectEqualSlices(info.Value, a.values(), b.values());
                    return true;
                }
                return false;
            }
        });
    }
}

test "timings.ExecuteDetailsTimings.eql" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(608159);
    const random = prng.random();

    const edt = try executeDetailsTimingsInitRandom(allocator, random, .{
        .per_program_timings_len = random.intRangeAtMost(u32, 1, 32),
        .program_timings_len = .{
            .min = 2,
            .max = 32,
        },
    });
    defer edt.deinit(allocator);

    var edt2 = try edt.clone(allocator);
    defer edt2.deinit(allocator);

    try std.testing.expect(edt.eql(&edt2));

    edt2.serialize_us.asInt().* +%= 1;
    try std.testing.expect(!edt.eql(&edt2));
    edt2.serialize_us.asInt().* -%= 1;
    try std.testing.expect(edt.eql(&edt2));
    const last_key = edt2.per_program_timings.map.keys()[edt2.per_program_timings.map.count() - 1];
    edt2.per_program_timings.map.fetchOrderedRemove(last_key).?.value.deinit(allocator);
    try std.testing.expect(!edt.eql(&edt2));
}

test "addVotePubkey" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(608159);
    const random = prng.random();

    var stats = PropagatedStats.EMPTY_ZEROES;
    defer stats.deinit(allocator);

    const vote_pubkey1 = Pubkey.initRandom(random);

    // Add a vote pubkey, the number of references in all_pubkeys
    // should be 2
    try std.testing.expectEqual(true, try stats.addVotePubkey(allocator, vote_pubkey1, 1));
    try std.testing.expectEqual(true, stats.propagated_validators.contains(vote_pubkey1));
    try std.testing.expectEqual(1, stats.propagated_validators_stake);

    // Adding it again should change no state since the key already existed
    try std.testing.expectEqual(false, try stats.addVotePubkey(allocator, vote_pubkey1, 1));
    try std.testing.expectEqual(true, stats.propagated_validators.contains(vote_pubkey1));
    try std.testing.expectEqual(1, stats.propagated_validators_stake);

    // Adding another pubkey should succeed
    const vote_pubkey2 = Pubkey.initRandom(random);
    try std.testing.expectEqual(true, try stats.addVotePubkey(allocator, vote_pubkey2, 2));
    try std.testing.expectEqual(true, stats.propagated_validators.contains(vote_pubkey2));
    try std.testing.expectEqual(3, stats.propagated_validators_stake);
}

test "addNodePubkeyInternal" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(608159);
    const random = prng.random();

    const num_vote_accounts = 10;
    const staked_vote_accounts = 5;

    const vote_account_pubkeys1: [num_vote_accounts]Pubkey = blk: {
        var pubkeys: [num_vote_accounts]Pubkey = undefined;
        for (&pubkeys) |*vap| vap.* = Pubkey.initRandom(random);
        break :blk pubkeys;
    };

    var epoch_vote_accounts: sig.core.stake.StakeAndVoteAccountsMap = .{};
    defer sig.core.stake.stakeAndVoteAccountsMapDeinit(epoch_vote_accounts, allocator);
    for (vote_account_pubkeys1[num_vote_accounts - staked_vote_accounts ..]) |pubkey| {
        try epoch_vote_accounts.ensureUnusedCapacity(allocator, 1);
        const VoteAccount = sig.core.stake.VoteAccount;
        const vote_account = try VoteAccount.initRandom(
            random,
            allocator,
            8,
            error{ RandomErrorA, RandomErrorB, RandomErrorC },
        );
        errdefer comptime unreachable;
        epoch_vote_accounts.putAssumeCapacity(pubkey, .{ 1, vote_account });
    }
    var stats = PropagatedStats.EMPTY_ZEROES;
    defer stats.deinit(allocator);

    const node_pubkey1 = Pubkey.initRandom(random);

    // Add a vote pubkey, the number of references in all_pubkeys
    // should be 2
    try stats.addNodePubkeyInternal(
        allocator,
        node_pubkey1,
        &vote_account_pubkeys1,
        epoch_vote_accounts,
    );
    try std.testing.expectEqual(true, stats.propagated_node_ids.contains(node_pubkey1));
    try std.testing.expectEqual(staked_vote_accounts, stats.propagated_validators_stake);

    // Adding it again should not change any state
    try stats.addNodePubkeyInternal(
        allocator,
        node_pubkey1,
        &vote_account_pubkeys1,
        epoch_vote_accounts,
    );
    try std.testing.expectEqual(true, stats.propagated_node_ids.contains(node_pubkey1));
    try std.testing.expectEqual(staked_vote_accounts, stats.propagated_validators_stake);

    // Adding another pubkey with same vote accounts should succeed, but stake
    // shouldn't increase
    const node_pubkey2 = Pubkey.initRandom(random);
    try stats.addNodePubkeyInternal(
        allocator,
        node_pubkey2,
        &vote_account_pubkeys1,
        epoch_vote_accounts,
    );
    try std.testing.expectEqual(true, stats.propagated_node_ids.contains(node_pubkey2));
    try std.testing.expectEqual(staked_vote_accounts, stats.propagated_validators_stake);

    // Adding another pubkey with different vote accounts should succeed
    // and increase stake
    const node_pubkey3 = Pubkey.initRandom(random);
    const vote_account_pubkeys2: [num_vote_accounts]Pubkey = blk: {
        var pubkeys: [num_vote_accounts]Pubkey = undefined;
        for (&pubkeys) |*vap| vap.* = Pubkey.initRandom(random);
        break :blk pubkeys;
    };

    sig.core.stake.stakeAndVoteAccountsMapClearRetainingCapacity(
        &epoch_vote_accounts,
        allocator,
    );
    for (vote_account_pubkeys2[num_vote_accounts - staked_vote_accounts ..]) |pubkey| {
        try epoch_vote_accounts.ensureUnusedCapacity(allocator, 1);
        const VoteAccount = sig.core.stake.VoteAccount;
        const vote_account = try VoteAccount.initRandom(
            random,
            allocator,
            8,
            error{ RandomErrorA, RandomErrorB, RandomErrorC },
        );
        errdefer comptime unreachable;
        epoch_vote_accounts.putAssumeCapacity(pubkey, .{ 1, vote_account });
    }

    try stats.addNodePubkeyInternal(
        allocator,
        node_pubkey3,
        &vote_account_pubkeys2,
        epoch_vote_accounts,
    );
    try std.testing.expectEqual(true, stats.propagated_node_ids.contains(node_pubkey3));
    try std.testing.expectEqual(2 * staked_vote_accounts, stats.propagated_validators_stake);
}

test testForkProgressIsPropagatedOnInit {
    // If the given validator_stake_info == null, then this is not
    // a leader slot and is_propagated == false
    try testForkProgressIsPropagatedOnInit(false, .{
        .now = sig.time.clock.sample(),
        .last_entry = Hash.ZEROES,
        .prev_leader_slot = 9,
        .validator_stake_info = null,
        .num_blocks_on_fork = 0,
        .num_dropped_blocks_on_fork = 0,
    });

    // If the stake is zero, then threshold is always achieved
    try testForkProgressIsPropagatedOnInit(true, .{
        .now = sig.time.clock.sample(),
        .last_entry = Hash.ZEROES,
        .prev_leader_slot = 9,
        .validator_stake_info = blk: {
            var validator_stake_info = ValidatorStakeInfo.DEFAULT;
            validator_stake_info.total_epoch_stake = 0;
            break :blk validator_stake_info;
        },
        .num_blocks_on_fork = 0,
        .num_dropped_blocks_on_fork = 0,
    });

    // If the stake is non zero, then threshold is not achieved unless
    // validator has enough stake by itself to pass threshold
    try testForkProgressIsPropagatedOnInit(false, .{
        .now = sig.time.clock.sample(),
        .last_entry = Hash.ZEROES,
        .prev_leader_slot = 9,
        .validator_stake_info = blk: {
            var validator_stake_info = ValidatorStakeInfo.DEFAULT;
            validator_stake_info.total_epoch_stake = 2;
            break :blk validator_stake_info;
        },
        .num_blocks_on_fork = 0,
        .num_dropped_blocks_on_fork = 0,
    });

    // Give the validator enough stake by itself to pass threshold
    try testForkProgressIsPropagatedOnInit(true, .{
        .now = sig.time.clock.sample(),
        .last_entry = Hash.ZEROES,
        .prev_leader_slot = 9,
        .validator_stake_info = blk: {
            var validator_stake_info = ValidatorStakeInfo.DEFAULT;
            validator_stake_info.stake = 1;
            validator_stake_info.total_epoch_stake = 2;
            break :blk validator_stake_info;
        },
        .num_blocks_on_fork = 0,
        .num_dropped_blocks_on_fork = 0,
    });

    // Check that the default ValidatorStakeInfo::default() constructs a ForkProgress
    // with is_propagated == false, otherwise propagation tests will fail to run
    // the proper checks (most will auto-pass without checking anything)
    try testForkProgressIsPropagatedOnInit(false, .{
        .now = sig.time.clock.sample(),
        .last_entry = Hash.ZEROES,
        .prev_leader_slot = 9,
        .validator_stake_info = ValidatorStakeInfo.DEFAULT,
        .num_blocks_on_fork = 0,
        .num_dropped_blocks_on_fork = 0,
    });
}

fn testForkProgressIsPropagatedOnInit(expected: bool, params: ForkProgress.InitParams) !void {
    const progress = try ForkProgress.init(std.testing.allocator, params);
    defer progress.deinit(std.testing.allocator);
    try std.testing.expectEqual(expected, progress.propagated_stats.is_propagated);
}

test "is_propagated" {
    // TODO: implement the "test_is_propagated" from agave after implementing missing methods
    return error.SkipZigTest;
}

/// NOTE: Used in tests for generating dummy data.
fn forkProgressInitRandom(
    allocator: std.mem.Allocator,
    random: std.Random,
) std.mem.Allocator.Error!ForkProgress {
    const fork_stats = try forkStatsInitRandom(allocator, random, .{
        .vote_threshold_len = 1 + random.uintAtMost(u32, 31),
        .voted_stakes_len = 1 + random.uintAtMost(u32, 31),
        .lockout_intervals_len = 1 + random.uintAtMost(u32, 31),
        .lockout_interval_entry_len = .{
            .min = 2,
            .max = 8,
        },
    });
    errdefer fork_stats.deinit(allocator);

    const propagated_stats: PropagatedStats = blk: {
        var propagated_validators = try pubkeyArraySetInitRandom(
            allocator,
            random,
            1 + random.uintAtMost(u32, 31),
        );
        errdefer propagated_validators.deinit(allocator);

        var propagated_node_ids = try pubkeyArraySetInitRandom(
            allocator,
            random,
            1 + random.uintAtMost(u32, 31),
        );
        errdefer propagated_node_ids.deinit(allocator);

        const slot_vote_tracker = try slotVoteTrackerInitRandom(allocator, random, .{
            .voted_len = 1 + random.uintAtMost(u32, 16),
            .optimistic_tracker_len = 1 + random.uintAtMost(u32, 16),
            .optimistic_tracker_entry_len = .{
                .min = 2,
                .max = 8,
            },
            .voted_slot_updates_len = 1 + random.uintAtMost(u32, 16),
        });
        errdefer slot_vote_tracker.deinit(allocator);

        var cluster_slot_pubkeys = try slotPubkeysInitRandom(allocator, random, 8);
        errdefer cluster_slot_pubkeys.deinit(allocator);

        break :blk .{
            .propagated_validators = propagated_validators,
            .propagated_node_ids = propagated_node_ids,
            .propagated_validators_stake = random.int(u64),
            .is_propagated = random.boolean(),
            .is_leader_slot = random.boolean(),
            .prev_leader_slot = if (random.boolean()) random.int(Slot) else null,
            .slot_vote_tracker = .{ .arc_ed = .{ .rwlock_ed = slot_vote_tracker } },
            .cluster_slot_pubkeys = .{ .arc_ed = .{ .rwlock_ed = cluster_slot_pubkeys } },
            .total_epoch_stake = random.int(u64),
        };
    };
    errdefer propagated_stats.deinit(allocator);

    const replay_stats = try replaySlotStatsInitRandom(allocator, random, .{
        .started = sig.time.Duration.zero.asInstant(),
        .totals = .{
            .per_program_timings_len = 4,
            .program_timings_len = .{
                .min = 2,
                .max = 8,
            },
        },
        .slowest_thread = .{
            .per_program_timings_len = 4,
            .program_timings_len = .{
                .min = 2,
                .max = 8,
            },
        },
    });
    errdefer replay_stats.deinit(allocator);

    const replay_progress: blockstore_processor.ConfirmationProgress = .{
        .last_entry = Hash.initRandom(random),
        .tick_hash_count = random.int(u64),
        .num_shreds = random.int(u64),
        .num_entries = random.int(usize),
        .num_txs = random.int(usize),
    };

    return .{
        .is_dead = random.boolean(),
        .fork_stats = fork_stats,
        .propagated_stats = propagated_stats,
        .replay_stats = .{ .arc_ed = .{ .rwlock_ed = replay_stats } },
        .replay_progress = .{ .arc_ed = .{ .rwlock_ed = replay_progress } },
        .retransmit_info = .{
            .retry_time = sig.time.Duration.zero.asInstant(),
            .retry_iteration = random.int(u32),
        },
        .num_blocks_on_fork = random.int(u64),
        .num_dropped_blocks_on_fork = random.int(u64),
    };
}

/// NOTE: Used in tests for generating dummy data.
fn pubkeyArraySetInitRandom(
    allocator: std.mem.Allocator,
    random: std.Random,
    len: u32,
) std.mem.Allocator.Error!PubkeyArraySet {
    var pubkey_set: PubkeyArraySet = .{};
    errdefer pubkey_set.deinit(allocator);
    try pubkey_set.ensureTotalCapacity(allocator, len);
    for (0..len) |_| while (true) {
        const new_key = Pubkey.initRandom(random);
        const gop = pubkey_set.getOrPutAssumeCapacity(new_key);
        if (gop.found_existing) continue;
        break;
    };
    return pubkey_set;
}

/// NOTE: Used in tests for generating dummy data.
fn forkStatsInitRandom(
    allocator: std.mem.Allocator,
    random: std.Random,
    params: struct {
        vote_threshold_len: u32,
        voted_stakes_len: u32,
        lockout_intervals_len: u32,
        lockout_interval_entry_len: struct {
            min: u32,
            max: u32,
        },
    },
) std.mem.Allocator.Error!ForkStats {
    const ThresholdDecision = consensus.ThresholdDecision;

    const vote_threshold = try allocator.alloc(ThresholdDecision, params.vote_threshold_len);
    errdefer allocator.free(vote_threshold);

    for (vote_threshold) |*vt| {
        const Tag = @typeInfo(ThresholdDecision).@"union".tag_type.?;
        vt.* = switch (random.enumValueWithIndex(Tag, u1)) {
            inline .passed_threshold => |tag| tag,
            inline .failed_threshold => |tag| @unionInit(ThresholdDecision, @tagName(tag), .{
                .vote_depth = random.int(u64),
                .observed_stake = random.int(u64),
            }),
        };
    }

    var voted_stakes: consensus.VotedStakes = .{};
    errdefer voted_stakes.deinit(allocator);
    try voted_stakes.ensureTotalCapacity(allocator, params.vote_threshold_len);
    for (0..params.voted_stakes_len) |_| voted_stakes.putAssumeCapacity(
        random.int(Slot),
        random.int(consensus.Stake),
    );

    const lockout_intervals = try lockoutIntervalsInitRandom(allocator, random, .{
        .entry_count = params.lockout_intervals_len,
        .min_entry_len = params.lockout_interval_entry_len.min,
        .max_entry_len = params.lockout_interval_entry_len.max,
    });
    errdefer lockout_intervals.deinit(allocator);

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

/// NOTE: Used in tests for generating dummy data.
fn lockoutIntervalsInitRandom(
    allocator: std.mem.Allocator,
    random: std.Random,
    params: struct {
        entry_count: u32,
        min_entry_len: u32,
        max_entry_len: u32,
    },
) std.mem.Allocator.Error!LockoutIntervals {
    var result = LockoutIntervals.EMPTY;
    errdefer result.deinit(allocator);

    try result.map.ensureTotalCapacity(allocator, params.entry_count);
    for (0..params.max_entry_len) |_| {
        const entry_len = random.intRangeAtMost(u32, params.min_entry_len, params.max_entry_len);
        const entry_list_buf = try allocator.alloc(LockoutIntervals.EntryElement, entry_len);
        errdefer allocator.free(entry_list_buf);

        for (entry_list_buf) |*elem| elem.* = .{
            random.int(LockoutIntervals.VotedSlot),
            Pubkey.initRandom(random),
        };

        result.map.putAssumeCapacity(
            random.int(LockoutIntervals.ExpirationSlot),
            LockoutIntervals.EntryList.fromOwnedSlice(entry_list_buf),
        );
    }

    return result;
}

/// NOTE: Used in tests for generating dummy data.
pub fn slotVoteTrackerInitRandom(
    allocator: std.mem.Allocator,
    random: std.Random,
    params: struct {
        voted_len: u32,
        optimistic_tracker_len: u32,
        optimistic_tracker_entry_len: struct {
            min: u32,
            max: u32,
        },
        voted_slot_updates_len: ?u32,
    },
) std.mem.Allocator.Error!cluster_info_vote_listener.SlotVoteTracker {
    const SlotVoteTracker = cluster_info_vote_listener.SlotVoteTracker;

    var voted: SlotVoteTracker.Voted = .{};
    errdefer voted.deinit(allocator);
    try voted.ensureTotalCapacity(allocator, params.voted_len);
    for (0..params.voted_len) |_| {
        voted.putAssumeCapacity(Pubkey.initRandom(random), random.boolean());
    }

    var ovt = cluster_info_vote_listener.OptimisticVotesTracker.EMPTY;
    errdefer ovt.deinit(allocator);
    try ovt.map.ensureTotalCapacity(allocator, params.optimistic_tracker_len);
    for (0..params.optimistic_tracker_len) |_| {
        const voted_len = random.intRangeAtMost(
            u32,
            params.optimistic_tracker_entry_len.min,
            params.optimistic_tracker_entry_len.max,
        );
        ovt.map.putAssumeCapacity(Hash.initRandom(random), .{
            .voted = try pubkeyArraySetInitRandom(allocator, random, voted_len),
            .stake = random.int(u64),
        });
    }

    var voted_slot_updates: ?std.ArrayListUnmanaged(Pubkey) = blk: {
        const vsu_len = params.voted_slot_updates_len orelse break :blk null;
        const vsu_buf = try allocator.alloc(Pubkey, vsu_len);
        for (vsu_buf) |*key| key.* = Pubkey.initRandom(random);
        break :blk std.ArrayListUnmanaged(Pubkey).fromOwnedSlice(vsu_buf);
    };
    errdefer if (voted_slot_updates) |*vsu| vsu.deinit(allocator);

    return .{
        .voted = voted,
        .optimistic_votes_tracker = ovt,
        .voted_slot_updates = voted_slot_updates,
        .gossip_only_stake = random.int(u64),
    };
}

/// NOTE: Used in tests for generating dummy data.
fn slotPubkeysInitRandom(
    allocator: std.mem.Allocator,
    random: std.Random,
    len: u32,
) std.mem.Allocator.Error!cluser_slots_service.SlotPubkeys {
    var slot_pubkeys: cluser_slots_service.SlotPubkeys = .{};
    errdefer slot_pubkeys.deinit(allocator);

    try slot_pubkeys.ensureTotalCapacity(allocator, len);
    for (0..len) |_| while (true) {
        const new_key = Pubkey.initRandom(random);
        const gop = slot_pubkeys.getOrPutAssumeCapacity(new_key);
        if (gop.found_existing) continue;
        gop.value_ptr.* = random.int(u64);
        break;
    };
    return slot_pubkeys;
}

/// NOTE: Used in tests for generating dummy data.
fn replaySlotStatsInitRandom(
    allocator: std.mem.Allocator,
    random: std.Random,
    params: struct {
        started: std.time.Instant,
        totals: ExecuteDetailsTimingsInitRandomParams,
        slowest_thread: ExecuteDetailsTimingsInitRandomParams,
    },
) std.mem.Allocator.Error!blockstore_processor.ReplaySlotStats {
    const batch_execute = try batchExecutionTimingInitRandom(allocator, random, .{
        .totals = params.totals,
        .slowest_thread = params.slowest_thread,
    });
    errdefer batch_execute.deinit(allocator);

    return .{
        .started = params.started,
        .confirmation_elapsed = random.int(u64),
        .replay_elapsed = random.int(u64),
        .poh_verify_elapsed = random.int(u64),
        .transaction_verify_elapsed = random.int(u64),
        .fetch_elapsed = random.int(u64),
        .fetch_fail_elapsed = random.int(u64),
        .batch_execute = batch_execute,
    };
}

/// NOTE: Used in tests for generating dummy data.
pub fn batchExecutionTimingInitRandom(
    allocator: std.mem.Allocator,
    random: std.Random,
    params: struct {
        totals: ExecuteDetailsTimingsInitRandomParams,
        slowest_thread: ExecuteDetailsTimingsInitRandomParams,
    },
) std.mem.Allocator.Error!blockstore_processor.BatchExecutionTiming {
    const totals = try executeTimingsInitRandom(allocator, random, params.totals);
    errdefer totals.deinit(allocator);

    const execute_timings = try executeTimingsInitRandom(allocator, random, params.slowest_thread);
    errdefer execute_timings.deinit(allocator);

    return .{
        .totals = totals,
        .wall_clock_us = @enumFromInt(random.int(u64)),
        .slowest_thread = .{
            .total_thread_us = @enumFromInt(random.int(u64)),
            .total_transactions_executed = @enumFromInt(random.int(u64)),
            .execute_timings = execute_timings,
        },
    };
}

/// NOTE: Used in tests for generating dummy data.
fn metricsInitRandom(random: std.Random) timings.Metrics {
    var metrics = timings.Metrics.initFill(undefined);
    for (&metrics.values) |*elem| elem.* = @enumFromInt(random.int(u64));
    return metrics;
}

fn executeTimingsInitRandom(
    allocator: std.mem.Allocator,
    random: std.Random,
    params: ExecuteDetailsTimingsInitRandomParams,
) std.mem.Allocator.Error!timings.ExecuteTimings {
    const details = try executeDetailsTimingsInitRandom(allocator, random, params);
    errdefer details.deinit(allocator);
    return .{
        .metrics = metricsInitRandom(random),
        .details = details,
        .execute_accessories = .{
            .feature_set_clone_us = @enumFromInt(random.int(u64)),
            .get_executors_us = @enumFromInt(random.int(u64)),
            .process_message_us = @enumFromInt(random.int(u64)),
            .process_instructions = .{
                .total_us = @enumFromInt(random.int(u64)),
                .verify_caller_us = @enumFromInt(random.int(u64)),
                .process_executable_chain_us = @enumFromInt(random.int(u64)),
                .verify_callee_us = @enumFromInt(random.int(u64)),
            },
        },
    };
}

const ExecuteDetailsTimingsInitRandomParams = struct {
    per_program_timings_len: u32,
    program_timings_len: struct {
        min: u32,
        max: u32,
    },
};

/// NOTE: Used in tests for generating dummy data.
fn executeDetailsTimingsInitRandom(
    allocator: std.mem.Allocator,
    random: std.Random,
    params: ExecuteDetailsTimingsInitRandomParams,
) std.mem.Allocator.Error!timings.ExecuteDetailsTimings {
    var result: timings.ExecuteDetailsTimings = .{
        .serialize_us = @enumFromInt(random.int(u64)),
        .create_vm_us = @enumFromInt(random.int(u64)),
        .execute_us = @enumFromInt(random.int(u64)),
        .deserialize_us = @enumFromInt(random.int(u64)),
        .get_or_create_executor_us = @enumFromInt(random.int(u64)),
        .changed_account_count = @enumFromInt(random.int(u64)),
        .total_account_count = @enumFromInt(random.int(u64)),
        .create_executor_register_syscalls_us = @enumFromInt(random.int(u64)),
        .create_executor_load_elf_us = @enumFromInt(random.int(u64)),
        .create_executor_verify_code_us = @enumFromInt(random.int(u64)),
        .create_executor_jit_compile_us = @enumFromInt(random.int(u64)),
        .per_program_timings = timings.PerProgramTimings.EMPTY,
    };
    errdefer result.deinit(allocator);

    const ppt = &result.per_program_timings;
    try ppt.map.ensureTotalCapacity(allocator, params.per_program_timings_len);
    for (0..params.per_program_timings_len) |_| {
        const value_ptr = while (true) {
            const gop = ppt.map.getOrPutAssumeCapacity(Pubkey.initRandom(random));
            if (gop.found_existing) continue;
            break gop.value_ptr;
        };
        value_ptr.* = try programTimingInitRandom(
            allocator,
            random,
            random.intRangeAtMost(
                u32,
                params.program_timings_len.min,
                params.program_timings_len.max,
            ),
        );
    }

    return result;
}

/// NOTE: Used in tests for generating dummy data.
fn programTimingInitRandom(
    allocator: std.mem.Allocator,
    random: std.Random,
    err_tx_compute_consume_len: u32,
) std.mem.Allocator.Error!timings.ProgramTiming {
    const etcc_buf = try allocator.alloc(u64, err_tx_compute_consume_len);
    errdefer allocator.free(etcc_buf);
    random.bytes(std.mem.sliceAsBytes(etcc_buf));
    return .{
        .accumulated_us = @enumFromInt(random.int(u64)),
        .accumulated_units = @enumFromInt(random.int(u64)),
        .count = @enumFromInt(random.int(u32)),
        .errored_txs_compute_consumed = std.ArrayListUnmanaged(u64).fromOwnedSlice(etcc_buf),
        .total_errored_units = @enumFromInt(random.int(u64)),
    };
}
