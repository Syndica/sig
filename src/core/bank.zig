const std = @import("std");
const sig = @import("../sig.zig");

const core = sig.core;

const EpochSchedule = core.epoch_schedule.EpochSchedule;
const Hash = core.hash.Hash;
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

    pub fn getStakedNodes(self: *const BankFields, allocator: std.mem.Allocator, epoch: Epoch) !*const std.AutoArrayHashMapUnmanaged(Pubkey, u64) {
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

        const epoch_stakes = try epochStakeMapRandom(random, allocator, max_list_entries);
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
            .genesis_creation_time = random.int(sig.core.genesis_config.UnixTimestamp),
            .slots_per_year = random.float(f64),
            .accounts_data_len = random.int(u64),
            .slot = random.int(Slot),
            .epoch = random.int(Epoch),
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

/// Analogous to [AncestorsForSerialization](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/accounts-db/src/ancestors.rs#L8)
pub const Ancestors = std.AutoArrayHashMapUnmanaged(Slot, usize);

pub fn ancestorsRandom(
    random: std.Random,
    allocator: std.mem.Allocator,
    max_list_entries: usize,
) std.mem.Allocator.Error!Ancestors {
    var ancestors = Ancestors.Managed.init(allocator);
    errdefer ancestors.deinit();

    try sig.rand.fillHashmapWithRng(&ancestors, random, random.uintAtMost(usize, max_list_entries), struct {
        pub fn randomKey(rand: std.Random) !Slot {
            return rand.int(Slot);
        }
        pub fn randomValue(rand: std.Random) !usize {
            return rand.int(usize);
        }
    });

    return ancestors.unmanaged;
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

    try sig.rand.fillHashmapWithRng(&ages, random, random.uintAtMost(usize, max_list_entries), struct {
        pub fn randomKey(rand: std.Random) !Hash {
            return Hash.initRandom(rand);
        }
        pub fn randomValue(rand: std.Random) !HashAge {
            return HashAge.initRandom(rand);
        }
    });

    return ages.unmanaged;
}

/// Analogous to [HardForks](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/hard_forks.rs#L13)
pub const HardForks = struct {
    items: []const SlotAndCount,

    pub const SlotAndCount = struct { Slot, usize };

    pub fn deinit(hard_forks: HardForks, allocator: std.mem.Allocator) void {
        allocator.free(hard_forks.items);
    }

    pub fn clone(
        hard_forks: HardForks,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!HardForks {
        return .{ .items = try allocator.dupe(SlotAndCount, hard_forks.items) };
    }

    pub fn initRandom(
        random: std.Random,
        allocator: std.mem.Allocator,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!HardForks {
        const hard_forks_len = random.uintAtMost(usize, max_list_entries);

        const hard_forks = try allocator.alloc(SlotAndCount, hard_forks_len);
        errdefer allocator.free(hard_forks);

        for (hard_forks) |*hard_fork| hard_fork.* = .{
            random.int(Slot),
            random.int(usize),
        };

        return .{ .items = hard_forks };
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

    pub fn deinit(unused_accounts: UnusedAccounts, allocator: std.mem.Allocator) void {
        var copy = unused_accounts;
        copy.unused1.deinit(allocator);
        copy.unused2.deinit(allocator);
        copy.unused3.deinit(allocator);
    }

    pub fn clone(
        unused_accounts: UnusedAccounts,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!UnusedAccounts {
        var unused1 = try unused_accounts.unused1.clone(allocator);
        errdefer unused1.deinit(allocator);

        var unused2 = try unused_accounts.unused2.clone(allocator);
        errdefer unused2.deinit(allocator);

        var unused3 = try unused_accounts.unused3.clone(allocator);
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
        var unused_accounts: UnusedAccounts = .{
            .unused1 = .{},
            .unused2 = .{},
            .unused3 = .{},
        };
        errdefer unused_accounts.deinit(allocator);

        inline for (@typeInfo(UnusedAccounts).Struct.fields) |field| {
            const hm_info = sig.utils.types.hashMapInfo(field.type).?;

            const ptr = &@field(unused_accounts, field.name);
            var managed = ptr.promote(allocator);
            defer ptr.* = managed.unmanaged;

            try sig.rand.fillHashmapWithRng(&managed, random, random.uintAtMost(usize, max_list_entries), struct {
                pub fn randomKey(rand: std.Random) !Pubkey {
                    return Pubkey.initRandom(rand);
                }
                pub fn randomValue(rand: std.Random) !hm_info.Value {
                    return switch (hm_info.Value) {
                        u64 => rand.int(u64),
                        void => {},
                        else => @compileError("Unexpected value type: " ++ @typeName(hm_info.Value)),
                    };
                }
            });
        }

        return unused_accounts;
    }
};
