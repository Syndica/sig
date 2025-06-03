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

const core = sig.core;

const Allocator = std.heap.Allocator;
const Atomic = std.atomic.Value;

const EpochSchedule = core.epoch_schedule.EpochSchedule;
const Hash = core.hash.Hash;
const LtHash = core.hash.LtHash;
const Pubkey = core.pubkey.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;

const Epoch = core.time.Epoch;
const Slot = core.time.Slot;
const UnixTimestamp = core.time.UnixTimestamp;

const FeeRateGovernor = core.genesis_config.FeeRateGovernor;
const Inflation = core.genesis_config.Inflation;

const Stakes = core.stake.Stakes;
const EpochStakeMap = core.stake.EpochStakeMap;
const epochStakeMapClone = core.stake.epochStakeMapClone;
const epochStakeMapDeinit = core.stake.epochStakeMapDeinit;
const epochStakeMapRandom = core.stake.epochStakeMapRandom;

const Ancestors = sig.core.status_cache.Ancestors;

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
    /// The number of the slot this represents.
    slot: Slot,

    /// The slot that this one builds off of. `parent_slot == slot - 1`, unless
    /// there is forking or skipped slots.
    parent_slot: Slot,

    /// Hash of this Bank's parent's state
    parent_hash: Hash,

    /// Total number of blocks produced up to this slot
    block_height: u64,

    hard_forks: HardForks,

    /// A tick height above this should not be allowed during this slot.
    max_tick_height: u64,

    /// The fees requirements to use for transactions in this slot.
    fee_rate_governor: FeeRateGovernor,

    /// Whether and how epoch rewards should be distributed in this slot.
    epoch_reward_status: EpochRewardStatus,

    pub fn deinit(self: SlotConstants, allocator: Allocator) void {
        self.hard_forks.deinit(allocator);
        self.epoch_reward_status.deinit(allocator);
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
    /// Hash of this Bank's state. Only meaningful after freezing.
    hash: sig.sync.RwMux(?Hash),

    /// Total capitalization, used to calculate inflation.
    capitalization: Atomic(u64),

    /// The number of committed transactions since genesis.
    transaction_count: Atomic(u64),

    /// Total number of ticks in history including those from this slot.
    tick_height: Atomic(u64),

    /// Total amount of rent collected so far during this slot.
    collected_rent: Atomic(u64),

    /// The lattice hash of all accounts
    ///
    /// The value is only meaningful after freezing.
    accounts_lt_hash: sig.sync.Mux(LtHash),

    pub fn isFrozen(self: *const SlotState) bool {
        return self.hash.read().get() != null;
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

    /// The schedule describing all epochs.
    schedule: EpochSchedule,

    /// The pre-determined stakes assigned to this epoch.
    stakes: Stakes(.delegation),

    pub fn deinit(self: EpochConstants, allocator: Allocator) void {
        self.stakes.deinit(allocator);
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
    fee_calculator: FeeCalculator,
    fee_rate_governor: FeeRateGovernor,
    collected_rent: u64,
    rent_collector: RentCollector,
    epoch_schedule: EpochSchedule,
    inflation: Inflation,
    stakes: Stakes(.delegation),
    unused_accounts: UnusedAccounts,
    epoch_stakes: EpochStakeMap,
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

        epochStakeMapDeinit(bank_fields.epoch_stakes, allocator);
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

        const epoch_stakes = try epochStakeMapClone(bank_fields.epoch_stakes, allocator);
        errdefer epochStakeMapDeinit(epoch_stakes, allocator);

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

    pub fn getStakedNodes(
        self: *const BankFields,
        allocator: std.mem.Allocator,
        epoch: Epoch,
    ) !*const std.AutoArrayHashMapUnmanaged(Pubkey, u64) {
        const epoch_stakes = self.epoch_stakes.getPtr(epoch) orelse return error.NoEpochStakes;
        return epoch_stakes.stakes.vote_accounts.stakedNodes(allocator);
    }

    /// Returns the leader schedule for this bank's epoch
    pub fn leaderSchedule(
        self: *const BankFields,
        allocator: std.mem.Allocator,
    ) !core.leader_schedule.LeaderSchedule {
        return self.leaderScheduleForEpoch(allocator, self.epoch);
    }

    /// Returns the leader schedule for an arbitrary epoch.
    /// Only works if the bank is aware of the staked nodes for that epoch.
    pub fn leaderScheduleForEpoch(
        self: *const BankFields,
        allocator: std.mem.Allocator,
        epoch: Epoch,
    ) !core.leader_schedule.LeaderSchedule {
        const slots_in_epoch = self.epoch_schedule.getSlotsInEpoch(self.epoch);
        const staked_nodes = try self.getStakedNodes(allocator, epoch);
        return .{
            .allocator = allocator,
            .slot_leaders = try core.leader_schedule.LeaderSchedule.fromStakedNodes(
                allocator,
                epoch,
                slots_in_epoch,
                staked_nodes,
            ),
        };
    }

    pub fn initRandom(
        allocator: std.mem.Allocator,
        /// Should be a PRNG, not a true RNG. See the documentation on `std.Random.uintLessThan`
        /// for commentary on the runtime of this function.
        random: std.Random,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!BankFields {
        var blockhash_queue = try BlockhashQueue.initRandom(random, allocator, max_list_entries);
        errdefer blockhash_queue.deinit(allocator);

        var ancestors = try ancestorsRandom(random, allocator, max_list_entries);
        errdefer ancestors.deinit(allocator);

        const hard_forks = try HardForks.initRandom(random, allocator, max_list_entries);
        errdefer hard_forks.deinit(allocator);

        const stakes = try Stakes(.delegation).initRandom(allocator, random, max_list_entries);
        errdefer stakes.deinit(allocator);

        const unused_accounts = try UnusedAccounts.initRandom(random, allocator, max_list_entries);
        errdefer unused_accounts.deinit(allocator);

        const epoch_stakes = try epochStakeMapRandom(random, allocator, 1, max_list_entries);
        errdefer epochStakeMapDeinit(epoch_stakes, allocator);

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
            .fee_calculator = FeeCalculator.initRandom(random),
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
    var ancestors = Ancestors.Map.Managed.init(allocator);
    errdefer ancestors.deinit();

    try sig.rand.fillHashmapWithRng(
        &ancestors,
        random,
        random.uintAtMost(usize, max_list_entries),
        struct {
            pub fn randomKey(rand: std.Random) !Slot {
                return rand.int(Slot);
            }
            pub fn randomValue(rand: std.Random) !void {
                _ = rand;
                return {};
            }
        },
    );

    return .{ .ancestors = ancestors.unmanaged };
}

/// Analogous to [BlockhashQueue](https://github.com/anza-xyz/agave/blob/a79ba51741864e94a066a8e27100dfef14df835f/accounts-db/src/blockhash_queue.rs#L32)
pub const BlockhashQueue = struct {
    last_hash_index: u64,

    /// last hash to be registered
    last_hash: ?Hash,
    ages: BlockhashQueueAges,

    /// hashes older than `max_age` will be dropped from the queue
    max_age: usize,

    pub fn deinit(bhq: BlockhashQueue, allocator: std.mem.Allocator) void {
        var ages = bhq.ages;
        ages.deinit(allocator);
    }

    pub fn clone(
        bhq: BlockhashQueue,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!BlockhashQueue {
        var ages = try bhq.ages.clone(allocator);
        errdefer ages.deinit(allocator);
        return .{
            .last_hash_index = bhq.last_hash_index,
            .last_hash = bhq.last_hash,
            .ages = ages,
            .max_age = bhq.max_age,
        };
    }

    pub fn getHashInfoIfValid(self: BlockhashQueue, hash: *const Hash, max_age: usize) ?HashAge {
        const age = self.ages.get(hash.*) orelse return null;
        if (!isHashIndexValid(self.last_hash_index, max_age, age.hash_index)) return null;
        return age;
    }

    fn isHashIndexValid(last_hash_index: u64, max_age: usize, hash_index: u64) bool {
        return last_hash_index - hash_index <= @as(u64, max_age);
    }

    pub fn initRandom(
        random: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!BlockhashQueue {
        var ages = try blockhashQueueAgesRandom(random, allocator, max_list_entries);
        errdefer ages.deinit(allocator);

        return .{
            .last_hash_index = random.int(u64),
            .last_hash = if (random.boolean()) Hash.initRandom(random) else null,
            .ages = ages,
            .max_age = random.int(usize),
        };
    }
};

pub const BlockhashQueueAges = std.AutoArrayHashMapUnmanaged(Hash, HashAge);

pub fn blockhashQueueAgesRandom(
    random: std.Random,
    allocator: std.mem.Allocator,
    max_list_entries: usize,
) std.mem.Allocator.Error!BlockhashQueueAges {
    var ages = BlockhashQueueAges.Managed.init(allocator);
    errdefer ages.deinit();

    try sig.rand.fillHashmapWithRng(
        &ages,
        random,
        random.uintAtMost(usize, max_list_entries),
        struct {
            pub fn randomKey(rand: std.Random) !Hash {
                return Hash.initRandom(rand);
            }
            pub fn randomValue(rand: std.Random) !HashAge {
                return HashAge.initRandom(rand);
            }
        },
    );

    return ages.unmanaged;
}

/// Analogous to [HardForks](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/hard_forks.rs#L13)
pub const HardForks = struct {
    items: []const SlotAndCount,

    pub const SlotAndCount = struct { Slot, usize };

    pub fn deinit(self: HardForks, allocator: std.mem.Allocator) void {
        allocator.free(self.items);
    }

    pub fn clone(
        self: HardForks,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!HardForks {
        return .{ .items = try allocator.dupe(SlotAndCount, self.items) };
    }

    pub fn initRandom(
        random: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!HardForks {
        const hard_forks_len = random.uintAtMost(usize, max_list_entries);

        const self = try allocator.alloc(SlotAndCount, hard_forks_len);
        errdefer allocator.free(self);

        for (self) |*hard_fork| hard_fork.* = .{
            random.int(Slot),
            random.int(usize),
        };

        return .{ .items = self };
    }
};

/// Analogous to [HashInfo](https://github.com/anza-xyz/agave/blob/a79ba51741864e94a066a8e27100dfef14df835f/accounts-db/src/blockhash_queue.rs#L13)
pub const HashAge = struct {
    fee_calculator: FeeCalculator,
    hash_index: u64,
    timestamp: u64,

    pub fn initRandom(random: std.Random) HashAge {
        return .{
            .fee_calculator = FeeCalculator.initRandom(random),
            .hash_index = random.int(u64),
            .timestamp = random.int(u64),
        };
    }
};

pub const FeeCalculator = struct {
    /// The current cost of a signature.
    ///
    /// This amount may increase/decrease over time based on cluster processing
    /// load.
    lamports_per_signature: u64,

    pub fn initRandom(random: std.Random) FeeCalculator {
        return .{ .lamports_per_signature = random.int(u64) };
    }
};

/// Analogous to [UnusedAccounts](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L123)
pub const UnusedAccounts = struct {
    unused1: std.AutoArrayHashMapUnmanaged(Pubkey, void),
    unused2: std.AutoArrayHashMapUnmanaged(Pubkey, void),
    unused3: std.AutoArrayHashMapUnmanaged(Pubkey, u64),

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
};

pub const StartBlockHeightAndRewards = struct {
    /// the block height of the slot at which rewards distribution began
    distribution_starting_block_height: u64,
    /// calculated epoch rewards pending distribution, outer Vec is by partition (one partition per block)
    stake_rewards_by_partition: []const []const PartitionedStakeReward, // TODO lifetime

    pub fn deinit(self: StartBlockHeightAndRewards, allocator: Allocator) void {
        for (self.stake_rewards_by_partition) |buf| {
            allocator.free(buf);
        }
        allocator.free(self.stake_rewards_by_partition);
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
