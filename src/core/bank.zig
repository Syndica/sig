//! This file represents the data stored in agave's `Bank` struct. Sig does not
//! have an analogous struct because `Bank` is a massive disorganized struct
//! without unbounded responsibilities that makes the code hard to understand
//! and makes dependencies difficult to manage.
//!
//! Instead we have more granular, digestible structs with clear scopes, like
//! SlotConstants, SlotState, and EpochConstants. These store much of the same
//! data that's stored in agave's Bank. Other heavyweight fields from agave's
//! Bank like like `BankRc` (containing a pointer to accountsdb) and
//! `TransactionBatchProcessor` are not included in any "bank" struct in sig.
//! Instead, those large dependencies are managed independently.
//!
//! The philosophy is that breaking the Bank into separate pieces will enable us
//! to write code with a more minimal, clearer set of dependencies, to make the
//! code easier to understand and maintain.

const std = @import("std");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const core = sig.core;
const reserved_accounts = sig.core.reserved_accounts;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const RwMux = sig.sync.RwMux;

const BlockhashQueue = core.BlockhashQueue;
const EpochSchedule = core.epoch_schedule.EpochSchedule;
const FeatureSet = core.FeatureSet;
const Hash = core.hash.Hash;
const HardForks = core.HardForks;
const LtHash = core.hash.LtHash;
const Pubkey = core.pubkey.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;
const ReservedAccounts = sig.core.ReservedAccounts;

const Epoch = core.time.Epoch;
const Slot = core.time.Slot;
const UnixTimestamp = core.time.UnixTimestamp;

const FeeRateGovernor = core.genesis_config.FeeRateGovernor;
const Inflation = core.genesis_config.Inflation;

const Ancestors = sig.core.Ancestors;
const EpochStakesMap = core.EpochStakesMap;
const Stakes = core.Stakes;

const deinitMapAndValues = sig.utils.collections.deinitMapAndValues;
const cloneMapAndValues = sig.utils.collections.cloneMapAndValues;

/// Information about a slot that is determined when the slot is initialized and
/// then never changes.
///
/// Contains the intersection of data from agave's Bank and firedancer's
/// fd_slot_bank, excluding data that is epoch-scoped or not constant during a
/// slot.
///
/// [Bank](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/runtime/src/bank.rs#L744)
/// [fd_slot_bank](https://github.com/firedancer-io/firedancer/blob/9a18101ee6e1094f27c7fb81da9ef3a7b9efb18b/src/flamenco/types/fd_types.h#L2270)
pub const SlotConstants = struct {
    /// The slot that this one builds off of. `parent_slot == slot - 1`, unless
    /// there is forking or skipped slots.
    parent_slot: Slot,

    /// Hash of this Bank's parent's state
    parent_hash: Hash,

    /// Lattice hash of the parent slot.
    ///
    /// Will be null for the first slot loaded from a snapshot, but that slot is
    /// already hashed so it doesn't matter.
    parent_lt_hash: ?LtHash,

    /// Total number of blocks produced up to this slot
    block_height: u64,

    /// The pubkey to send transactions fees to.
    collector_id: Pubkey,

    /// A tick height above this should not be allowed during this slot.
    max_tick_height: u64,

    /// The fees requirements to use for transactions in this slot.
    fee_rate_governor: FeeRateGovernor,

    /// Whether and how epoch rewards should be distributed in this slot.
    epoch_reward_status: EpochRewardStatus,

    /// Set of slots leading to this one.
    /// Includes the current slot.
    /// Does not go back to genesis, may prune slots beyond 8192 generations ago.
    ancestors: Ancestors,

    /// A map of activated features to the slot when they were activated.
    /// NOTE: Feature activations are only applied at epoch boundaries, so should be constant
    /// during an epoch, not just a slot. We should evaluate moving this and `reserved_accounts`
    /// to `EpochConstants`.
    feature_set: FeatureSet,

    /// A map of reserved accounts that are not allowed to acquire write locks
    /// in the current slot.
    reserved_accounts: ReservedAccounts,

    pub fn fromBankFields(
        allocator: Allocator,
        bank_fields: *const BankFields,
        feature_set: FeatureSet,
    ) Allocator.Error!SlotConstants {
        return .{
            .parent_slot = bank_fields.parent_slot,
            .parent_hash = bank_fields.parent_hash,
            .parent_lt_hash = null,
            .block_height = bank_fields.block_height,
            .collector_id = bank_fields.collector_id,
            .max_tick_height = bank_fields.max_tick_height,
            .fee_rate_governor = bank_fields.fee_rate_governor,
            .epoch_reward_status = .inactive,
            .ancestors = try bank_fields.ancestors.clone(allocator),
            .feature_set = feature_set,
            .reserved_accounts = try reserved_accounts.initForSlot(
                allocator,
                &feature_set,
                bank_fields.slot,
            ),
        };
    }

    pub fn genesis(
        allocator: Allocator,
        fee_rate_governor: sig.core.genesis_config.FeeRateGovernor,
    ) Allocator.Error!SlotConstants {
        var ancestors: Ancestors = .{};
        try ancestors.ancestors.put(allocator, 0, {});
        errdefer ancestors.deinit(allocator);

        const reserved_accounts_data = try reserved_accounts.init(allocator);
        errdefer reserved_accounts_data.deinit(allocator);

        return .{
            .parent_slot = 0,
            .parent_hash = sig.core.Hash.ZEROES,
            .parent_lt_hash = .IDENTITY,
            .block_height = 0,
            .collector_id = Pubkey.ZEROES,
            .max_tick_height = 0,
            .fee_rate_governor = fee_rate_governor,
            .epoch_reward_status = .inactive,
            .ancestors = ancestors,
            .feature_set = .ALL_DISABLED,
            .reserved_accounts = reserved_accounts_data,
        };
    }

    pub fn deinit(self_const: SlotConstants, allocator: Allocator) void {
        var self = self_const;
        self.epoch_reward_status.deinit(allocator);
        self.ancestors.deinit(allocator);
        self.reserved_accounts.deinit(allocator);
    }
};

/// Information about a slot that evolves as the slot is executed, but should
/// typically become frozen once execution is complete.
///
/// Contains the intersection of data from agave's Bank and firedancer's
/// fd_slot_bank, excluding data that is constant during a slot.
///
/// [Bank](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/runtime/src/bank.rs#L744)
/// [fd_slot_bank](https://github.com/firedancer-io/firedancer/blob/9a18101ee6e1094f27c7fb81da9ef3a7b9efb18b/src/flamenco/types/fd_types.h#L2270)
pub const SlotState = struct {
    /// FIFO queue of `recent_blockhash` items
    blockhash_queue: RwMux(BlockhashQueue),

    /// Hash of this Bank's state. Only meaningful after freezing.
    hash: RwMux(?Hash),

    /// Total capitalization, used to calculate inflation.
    capitalization: Atomic(u64),

    /// The number of committed transactions since genesis.
    transaction_count: Atomic(u64),

    /// The number of signatures from valid transactions in this slot
    signature_count: Atomic(u64),

    /// Total number of ticks in history including those from this slot.
    tick_height: Atomic(u64),

    /// Total amount of rent collected so far during this slot.
    collected_rent: Atomic(u64),

    /// The lattice hash of all accounts
    ///
    /// The value is only meaningful after freezing.
    accounts_lt_hash: sig.sync.Mux(?LtHash),

    stakes_cache: sig.core.StakesCache,

    /// 50% burned, 50% paid to leader
    collected_transaction_fees: Atomic(u64),

    /// 100% paid to leader
    collected_priority_fees: Atomic(u64),

    pub fn deinit(self: *SlotState, allocator: Allocator) void {
        self.stakes_cache.deinit(allocator);

        var blockhash_queue = self.blockhash_queue.tryWrite() orelse
            @panic("attempted to deinit SlotState.blockhash_queue while still in use");
        defer blockhash_queue.unlock();
        blockhash_queue.get().deinit(allocator);
    }

    pub const GENESIS: SlotState = .{
        .blockhash_queue = .init(.DEFAULT),
        .hash = .init(null),
        .capitalization = .init(0),
        .transaction_count = .init(0),
        .signature_count = .init(0),
        .tick_height = .init(0),
        .collected_rent = .init(0),
        .accounts_lt_hash = .init(.IDENTITY),
        .stakes_cache = .EMPTY,
        .collected_transaction_fees = .init(0),
        .collected_priority_fees = .init(0),
    };

    pub fn fromBankFields(
        allocator: Allocator,
        bank_fields: *const BankFields,
        lt_hash: ?LtHash,
    ) Allocator.Error!SlotState {
        const blockhash_queue = try bank_fields.blockhash_queue.clone(allocator);
        errdefer blockhash_queue.deinit(allocator);

        const stakes = try bank_fields.stakes.clone(allocator);
        errdefer stakes.deinit(allocator);

        return .{
            .blockhash_queue = .init(blockhash_queue),
            .hash = .init(bank_fields.hash),
            .capitalization = .init(bank_fields.capitalization),
            .transaction_count = .init(bank_fields.transaction_count),
            .signature_count = .init(bank_fields.signature_count),
            .tick_height = .init(bank_fields.tick_height),
            .collected_rent = .init(bank_fields.collected_rent),
            .accounts_lt_hash = .init(lt_hash),
            .stakes_cache = .{ .stakes = .init(stakes) },
            .collected_transaction_fees = .init(0),
            .collected_priority_fees = .init(0),
        };
    }

    pub fn fromFrozenParent(allocator: Allocator, parent: *SlotState) !SlotState {
        const zone = tracy.Zone.init(@src(), .{ .name = "fromFrozenParent" });
        defer zone.deinit();

        if (!parent.isFrozen()) return error.SlotNotFrozen;

        const blockhash_queue = foo: {
            var bhq = parent.blockhash_queue.read();
            defer bhq.unlock();
            break :foo try bhq.get().clone(allocator);
        };
        errdefer blockhash_queue.deinit(allocator);

        const stakes = foo: {
            var cache = parent.stakes_cache.stakes.read();
            defer cache.unlock();
            break :foo try cache.get().clone(allocator);
        };
        errdefer stakes.deinit(allocator);

        return .{
            .blockhash_queue = .init(blockhash_queue),
            .hash = .init(null),
            .capitalization = .init(parent.capitalization.load(.monotonic)),
            .transaction_count = .init(parent.transaction_count.load(.monotonic)),
            .signature_count = .init(0),
            .tick_height = .init(parent.tick_height.load(.monotonic)),
            .collected_rent = .init(0),
            .accounts_lt_hash = .init(parent.accounts_lt_hash.readCopy()),
            .stakes_cache = .{ .stakes = .init(stakes) },
            .collected_transaction_fees = .init(0),
            .collected_priority_fees = .init(0),
        };
    }

    pub fn isFrozen(self: *SlotState) bool {
        return self.hash.readCopy() != null;
    }

    pub fn tickHeight(self: *const SlotState) u64 {
        return self.tick_height.load(.monotonic);
    }
};

/// Constant information about an epoch that is determined before the epoch
/// starts.
///
/// Contains the intersection of epoch-scoped fields from agave's Bank and
/// firedancer's fd_epoch_bank.
///
/// [Bank](https://github.com/anza-xyz/agave/blob/161fc1965bdb4190aa2d7e36c7c745b4661b10ed/runtime/src/bank.rs#L744)
/// [fd_epoch_bank](https://github.com/firedancer-io/firedancer/blob/9a18101ee6e1094f27c7fb81da9ef3a7b9efb18b/src/flamenco/types/fd_types.h#L1906)
pub const EpochConstants = struct {
    /// The number of hashes in each tick. Null means hashing is disabled.
    hashes_per_tick: ?u64,

    /// The number of ticks for each slot in this epoch.
    ticks_per_slot: u64,

    /// target length of a slot, used to estimate timings.
    ns_per_slot: u128,

    /// genesis time, used for computed clock.
    genesis_creation_time: UnixTimestamp,

    /// The number of slots per year, used for inflation.
    slots_per_year: f64,

    /// The pre-determined stakes assigned to this epoch.
    stakes: sig.core.EpochStakes,

    rent_collector: RentCollector,

    pub fn deinit(self: EpochConstants, allocator: Allocator) void {
        self.stakes.deinit(allocator);
    }

    pub fn genesis(genesis_config: core.GenesisConfig) EpochConstants {
        return .{
            .hashes_per_tick = genesis_config.poh_config.hashes_per_tick,
            .ticks_per_slot = genesis_config.ticks_per_slot,
            .ns_per_slot = genesis_config.nsPerSlot(),
            .genesis_creation_time = genesis_config.creation_time,
            .slots_per_year = genesis_config.slotsPerYear(),
            .stakes = .EMPTY_WITH_GENESIS,
            .rent_collector = .DEFAULT,
        };
    }

    pub fn fromBankFields(
        bank_fields: *const BankFields,
        epoch_stakes: sig.core.EpochStakes,
    ) Allocator.Error!EpochConstants {
        return .{
            .hashes_per_tick = bank_fields.hashes_per_tick,
            .ticks_per_slot = bank_fields.ticks_per_slot,
            .ns_per_slot = bank_fields.ns_per_slot,
            .genesis_creation_time = bank_fields.genesis_creation_time,
            .slots_per_year = bank_fields.slots_per_year,
            .stakes = epoch_stakes,
            .rent_collector = bank_fields.rent_collector,
        };
    }

    pub fn clone(
        self: EpochConstants,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!EpochConstants {
        const stakes = try self.stakes.clone(allocator);

        return .{
            .hashes_per_tick = self.hashes_per_tick,
            .ticks_per_slot = self.ticks_per_slot,
            .ns_per_slot = self.ns_per_slot,
            .genesis_creation_time = self.genesis_creation_time,
            .slots_per_year = self.slots_per_year,
            .stakes = stakes,
            .rent_collector = self.rent_collector,
        };
    }
};

/// Used for serialization of aggregated bank data, for example in snapshots.
///
/// Analogous to [DeserializableVersionedBank](https://github.com/anza-xyz/agave/blob/9c899a72414993dc005f11afb5df10752b10810b/runtime/src/serde_snapshot.rs#L134).
pub const BankFields = struct {
    blockhash_queue: BlockhashQueue,
    ancestors: Ancestors,
    hash: Hash,
    parent_hash: Hash,
    parent_slot: Slot,
    hard_forks: HardForks,
    transaction_count: u64,
    tick_height: u64,
    signature_count: u64,
    // ie, total lamports
    capitalization: u64,
    max_tick_height: u64,
    hashes_per_tick: ?u64,
    ticks_per_slot: u64,
    ns_per_slot: u128,
    genesis_creation_time: UnixTimestamp,
    slots_per_year: f64,
    accounts_data_len: u64,
    slot: Slot,
    epoch: Epoch,
    block_height: u64,
    collector_id: Pubkey,
    collector_fees: u64,
    /// This is a FeeCalculator in Agave which is just a wrapped u64 containing lamports per signature.
    /// Lamports per signature is already stored in `fee_rate_governor`, so
    fee_calculator: u64,
    fee_rate_governor: FeeRateGovernor,
    collected_rent: u64,
    rent_collector: RentCollector,
    epoch_schedule: EpochSchedule,
    inflation: Inflation,
    stakes: Stakes(.delegation),
    unused_accounts: UnusedAccounts,
    epoch_stakes: EpochStakesMap,
    is_delta: bool,

    pub fn deinit(
        bank_fields: *const BankFields,
        allocator: std.mem.Allocator,
    ) void {
        bank_fields.blockhash_queue.deinit(allocator);

        var ancestors = bank_fields.ancestors;
        ancestors.deinit(allocator);

        bank_fields.hard_forks.deinit(allocator);
        bank_fields.stakes.deinit(allocator);
        bank_fields.unused_accounts.deinit(allocator);

        deinitMapAndValues(allocator, bank_fields.epoch_stakes);
    }

    pub fn clone(
        bank_fields: *const BankFields,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!BankFields {
        const blockhash_queue = try bank_fields.blockhash_queue.clone(allocator);
        errdefer blockhash_queue.deinit(allocator);

        var ancestors = try bank_fields.ancestors.clone(allocator);
        errdefer ancestors.deinit(allocator);

        const hard_forks = try bank_fields.hard_forks.clone(allocator);
        errdefer hard_forks.deinit(allocator);

        const stakes = try bank_fields.stakes.clone(allocator);
        errdefer stakes.deinit(allocator);

        const unused_accounts = try bank_fields.unused_accounts.clone(allocator);
        errdefer unused_accounts.deinit(allocator);

        const epoch_stakes = try cloneMapAndValues(allocator, bank_fields.epoch_stakes);
        errdefer deinitMapAndValues(allocator, epoch_stakes);

        var cloned = bank_fields.*;
        cloned.blockhash_queue = blockhash_queue;
        cloned.ancestors = ancestors;
        cloned.hard_forks = hard_forks;
        cloned.stakes = stakes;
        cloned.unused_accounts = unused_accounts;
        cloned.epoch_stakes = epoch_stakes;
        return cloned;
    }

    pub fn validate(
        self: *const BankFields,
        genesis_config: *const sig.core.GenesisConfig,
    ) !void {
        // self validation
        if (self.max_tick_height != (self.slot + 1) * self.ticks_per_slot) {
            return error.InvalidBankFields;
        }
        if (self.epoch_schedule.getEpoch(self.slot) != self.epoch) {
            return error.InvalidBankFields;
        }

        // cross validation against genesis
        if (genesis_config.creation_time != self.genesis_creation_time) {
            return error.BankAndGenesisMismatch;
        }
        if (genesis_config.ticks_per_slot != self.ticks_per_slot) {
            return error.BankAndGenesisMismatch;
        }
        const genesis_ns_per_slot = genesis_config.poh_config.target_tick_duration.nanos *
            @as(u128, genesis_config.ticks_per_slot);
        if (self.ns_per_slot != genesis_ns_per_slot) {
            return error.BankAndGenesisMismatch;
        }

        const genesis_slots_per_year = yearsAsSlots(1, //
            genesis_config.poh_config.target_tick_duration.nanos, self.ticks_per_slot);
        if (genesis_slots_per_year != self.slots_per_year) {
            return error.BankAndGenesisMismatch;
        }
        if (!std.meta.eql(self.epoch_schedule, genesis_config.epoch_schedule)) {
            return error.BankAndGenesisMismatch;
        }
    }

    fn yearsAsSlots(years: f64, tick_duration_ns: u32, ticks_per_slot: u64) f64 {
        const SECONDS_PER_YEAR: f64 = 365.242_199 * 24.0 * 60.0 * 60.0;
        return years * SECONDS_PER_YEAR *
            (1_000_000_000.0 / @as(f64, @floatFromInt(tick_duration_ns))) /
            @as(f64, @floatFromInt(ticks_per_slot));
    }

    pub fn initRandom(
        allocator: std.mem.Allocator,
        /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
        /// for commentary on the runtime of this function.
        random: std.Random,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!BankFields {
        var blockhash_queue = try BlockhashQueue.initRandom(allocator, random, max_list_entries);
        errdefer blockhash_queue.deinit(allocator);

        var ancestors = try ancestorsRandom(random, allocator, max_list_entries);
        errdefer ancestors.deinit(allocator);

        const hard_forks = try HardForks.initRandom(random, allocator, max_list_entries);
        errdefer hard_forks.deinit(allocator);

        const stakes = try Stakes(.delegation).initRandom(allocator, random, max_list_entries);
        errdefer stakes.deinit(allocator);

        const unused_accounts = try UnusedAccounts.initRandom(random, allocator, max_list_entries);
        errdefer unused_accounts.deinit(allocator);

        const epoch_stakes = try sig.core.epoch_stakes.epochStakeMapRandom(
            allocator,
            random,
            .delegation,
            1,
            max_list_entries,
        );
        errdefer deinitMapAndValues(allocator, epoch_stakes);

        return .{
            .blockhash_queue = blockhash_queue,
            .ancestors = ancestors,
            .hash = Hash.initRandom(random),
            .parent_hash = Hash.initRandom(random),
            .parent_slot = random.int(Slot),
            .hard_forks = hard_forks,
            .transaction_count = random.int(u64),
            .tick_height = random.int(u64),
            .signature_count = random.int(u64),
            .capitalization = random.int(u64),
            .max_tick_height = random.int(u64),
            .hashes_per_tick = if (random.boolean()) random.int(u64) else null,
            .ticks_per_slot = random.int(u64),
            .ns_per_slot = random.int(u128),
            .genesis_creation_time = random.int(sig.core.UnixTimestamp),
            .slots_per_year = random.float(f64),
            .accounts_data_len = random.int(u64),
            .slot = random.int(Slot),
            .epoch = epoch_stakes.keys()[random.uintLessThan(usize, epoch_stakes.count())],
            .block_height = random.int(u64),
            .collector_id = Pubkey.initRandom(random),
            .collector_fees = random.int(u64),
            .fee_calculator = random.int(u64),
            .fee_rate_governor = FeeRateGovernor.initRandom(random),
            .collected_rent = random.int(u64),
            .rent_collector = RentCollector.initRandom(random),
            .epoch_schedule = EpochSchedule.initRandom(random),
            .inflation = Inflation.initRandom(random),
            .stakes = stakes,
            .unused_accounts = unused_accounts,
            .epoch_stakes = epoch_stakes,
            .is_delta = random.boolean(),
        };
    }
};

pub fn ancestorsRandom(
    random: std.Random,
    allocator: std.mem.Allocator,
    max_list_entries: usize,
) std.mem.Allocator.Error!Ancestors {
    var ancestors: Ancestors = .{};
    errdefer ancestors.deinit(allocator);

    for (0..random.uintAtMost(usize, max_list_entries)) |_| {
        try ancestors.addSlot(allocator, random.int(Slot));
    }

    return ancestors;
}

/// Analogous to [UnusedAccounts](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L123)
pub const UnusedAccounts = struct {
    unused1: sig.utils.collections.PubkeyMap(void),
    unused2: sig.utils.collections.PubkeyMap(void),
    unused3: sig.utils.collections.PubkeyMap(u64),

    pub const EMPTY: UnusedAccounts = .{
        .unused1 = .{},
        .unused2 = .{},
        .unused3 = .{},
    };

    pub fn deinit(self: UnusedAccounts, allocator: std.mem.Allocator) void {
        var copy = self;
        copy.unused1.deinit(allocator);
        copy.unused2.deinit(allocator);
        copy.unused3.deinit(allocator);
    }

    pub fn clone(
        self: UnusedAccounts,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!UnusedAccounts {
        var unused1 = try self.unused1.clone(allocator);
        errdefer unused1.deinit(allocator);

        var unused2 = try self.unused2.clone(allocator);
        errdefer unused2.deinit(allocator);

        var unused3 = try self.unused3.clone(allocator);
        errdefer unused3.deinit(allocator);

        return .{
            .unused1 = unused1,
            .unused2 = unused2,
            .unused3 = unused3,
        };
    }

    pub fn initRandom(
        random: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!UnusedAccounts {
        var self: UnusedAccounts = .{
            .unused1 = .{},
            .unused2 = .{},
            .unused3 = .{},
        };
        errdefer self.deinit(allocator);

        inline for (@typeInfo(UnusedAccounts).@"struct".fields) |field| {
            const hm_info = sig.utils.types.hashMapInfo(field.type).?;

            const ptr = &@field(self, field.name);
            var managed = ptr.promote(allocator);
            defer ptr.* = managed.unmanaged;

            try sig.rand.fillHashmapWithRng(
                &managed,
                random,
                random.uintAtMost(usize, max_list_entries),
                struct {
                    pub fn randomKey(rand: std.Random) !Pubkey {
                        return Pubkey.initRandom(rand);
                    }
                    pub fn randomValue(rand: std.Random) !hm_info.Value {
                        return switch (hm_info.Value) {
                            u64 => rand.int(u64),
                            void => {},
                            else => @compileError(
                                "Unexpected value type: " ++ @typeName(hm_info.Value),
                            ),
                        };
                    }
                },
            );
        }

        return self;
    }
};

pub const EpochRewardStatus = union(enum) {
    /// this bank is in the reward phase.
    /// Contents are the start point for epoch reward calculation,
    /// i.e. parent_slot and parent_block height for the starting
    /// block of the current epoch.
    active: StartBlockHeightAndRewards,
    /// this bank is outside of the rewarding phase.
    inactive,

    pub fn deinit(self: EpochRewardStatus, allocator: Allocator) void {
        switch (self) {
            .active => |s| s.deinit(allocator),
            .inactive => {},
        }
    }

    pub fn clone(self: EpochRewardStatus, allocator: Allocator) Allocator.Error!EpochRewardStatus {
        return switch (self) {
            .active => |s| .{ .active = try s.clone(allocator) },
            .inactive => .inactive,
        };
    }
};

pub const StartBlockHeightAndRewards = struct {
    /// the block height of the slot at which rewards distribution began
    distribution_starting_block_height: u64,
    /// calculated epoch rewards pending distribution, outer Vec is by partition (one partition per block)
    stake_rewards_by_partition: []const []const PartitionedStakeReward,

    pub fn deinit(self: StartBlockHeightAndRewards, allocator: Allocator) void {
        for (self.stake_rewards_by_partition) |buf| {
            allocator.free(buf);
        }
        allocator.free(self.stake_rewards_by_partition);
    }

    pub fn clone(
        self: StartBlockHeightAndRewards,
        allocator: Allocator,
    ) Allocator.Error!StartBlockHeightAndRewards {
        const stake_rewards_by_partition = try allocator
            .alloc([]const PartitionedStakeReward, self.stake_rewards_by_partition.len);
        errdefer allocator.free(stake_rewards_by_partition);

        for (self.stake_rewards_by_partition, stake_rewards_by_partition, 0..) |old, *new, i| {
            errdefer for (stake_rewards_by_partition[0..i]) |x| allocator.free(x);
            const slice = try allocator.alloc(PartitionedStakeReward, old.len);
            @memcpy(slice, old);
            new.* = slice;
        }

        return .{
            .distribution_starting_block_height = self.distribution_starting_block_height,
            .stake_rewards_by_partition = stake_rewards_by_partition,
        };
    }
};

const PartitionedStakeRewards = []const PartitionedStakeReward;

pub const PartitionedStakeReward = struct {
    /// Stake account address
    stake_pubkey: Pubkey,
    /// `Stake` state to be stored in account
    stake: core.stake.Stake,
    /// Stake reward for recording in the Bank on distribution
    stake_reward: u64,
    /// Vote commission for recording reward info
    commission: u8,
};
