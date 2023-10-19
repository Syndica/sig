const std = @import("std");
const ArrayList = std.ArrayList;
const HashMap = std.AutoHashMap;

const _genesis_config = @import("./genesis_config.zig");
const UnixTimestamp = _genesis_config.UnixTimestamp;
const FeeRateGovernor = _genesis_config.FeeRateGovernor;
const EpochSchedule = _genesis_config.EpochSchedule;
const Rent = _genesis_config.Rent;
const Inflation = _genesis_config.Inflation;

const Account = @import("./account.zig").Account;
const Hash = @import("./hash.zig").Hash;
const Slot = @import("./clock.zig").Slot;
const Epoch = @import("./clock.zig").Epoch;
const Pubkey = @import("./pubkey.zig").Pubkey;
const bincode = @import("../bincode/bincode.zig");
const defaultArrayListOnEOFConfig = @import("../utils/arraylist.zig").defaultArrayListOnEOFConfig;

pub const StakeHistoryEntry = struct {
    effective: u64, // effective stake at this epoch
    activating: u64, // sum of portion of stakes not fully warmed up
    deactivating: u64, // requested to be cooled down, not fully deactivated yet
};

const StakeHistory = ArrayList(struct { Epoch, StakeHistoryEntry });

pub fn Stakes(comptime T: type) type {
    return struct {
        /// vote accounts
        vote_accounts: VoteAccounts,

        /// stake_delegations
        stake_delegations: HashMap(Pubkey, T),

        /// unused
        unused: u64,

        /// current epoch, used to calculate current stake
        epoch: Epoch,

        /// history of staking levels
        stake_history: StakeHistory,
    };
}

pub const VoteAccounts = struct {
    vote_accounts: HashMap(Pubkey, struct { u64, Account }),

    staked_nodes: ?HashMap(
        Pubkey, // VoteAccount.vote_state.node_pubkey.
        u64, // Total stake across all vote-accounts.
    ) = null,

    pub const @"!bincode-config:staked_nodes" = bincode.FieldConfig(?HashMap(Pubkey, u64)){ .skip = true };
};

pub const Delegation = struct {
    /// to whom the stake is delegated
    voter_pubkey: Pubkey,
    /// activated stake amount, set at delegate() time
    stake: u64,
    /// epoch at which this stake was activated, std::Epoch::MAX if is a bootstrap stake
    activation_epoch: Epoch,
    /// epoch the stake was deactivated, std::Epoch::MAX if not deactivated
    deactivation_epoch: Epoch,
    /// how much stake we can activate per-epoch as a fraction of currently effective stake
    /// depreciated!
    warmup_cooldown_rate: f64,
};

pub const RentCollector = struct {
    epoch: Epoch,
    epoch_schedule: EpochSchedule,
    slots_per_year: f64,
    rent: Rent,
};

pub const FeeCalculator = struct {
    /// The current cost of a signature.
    ///
    /// This amount may increase/decrease over time based on cluster processing
    /// load.
    lamports_per_signature: u64,
};

pub const HashAge = struct {
    fee_calculator: FeeCalculator,
    hash_index: u64,
    timestamp: u64,
};

pub const BlockhashQueue = struct {
    last_hash_index: u64,

    /// last hash to be registered
    last_hash: ?Hash,
    ages: HashMap(Hash, HashAge),

    /// hashes older than `max_age` will be dropped from the queue
    max_age: usize,
};

pub fn HashSet(comptime T: type) type {
    return HashMap(T, void);
}

pub const UnusedAccounts = struct {
    unused1: HashSet(Pubkey),
    unused2: HashSet(Pubkey),
    unused3: HashMap(Pubkey, u64),
};

pub const Ancestors = HashMap(Slot, usize);

pub const HardForks = struct {
    hard_forks: std.ArrayList(struct { Slot, usize }),
};

pub const NodeVoteAccounts = struct {
    vote_accounts: ArrayList(Pubkey),
    total_stake: u64,
};

pub const EpochStakes = struct {
    stakes: Stakes(Delegation),
    total_stake: u64,
    node_id_to_vote_accounts: HashMap(Pubkey, NodeVoteAccounts),
    epoch_authorized_voters: HashMap(Pubkey, Pubkey),
};

pub const BankIncrementalSnapshotPersistence = struct {
    /// slot of full snapshot
    full_slot: Slot,
    /// accounts hash from the full snapshot
    full_hash: Hash,
    /// capitalization from the full snapshot
    full_capitalization: u64,
    /// hash of the accounts in the incremental snapshot slot range, including zero-lamport accounts
    incremental_hash: Hash,
    /// capitalization of the accounts in the incremental snapshot slot range
    incremental_capitalization: u64,

    pub fn default() @This() { 
        return .{
            .full_slot = 0,
            .full_hash = Hash.default(),
            .full_capitalization = 0,
            .incremental_hash = Hash.default(),
            .incremental_capitalization = 0,
        };
    }
};

pub const StakeReward = struct {
    stake_pubkey: Pubkey,
    stake_reward_info: RewardInfo,
    stake_account: Account,
};

pub const RewardInfo = struct {
    reward_type: RewardType,
    lamports: i64, // Reward amount
    post_balance: u64, // Account balance in lamports after `lamports` was applied
    commission: ?u8, // Vote account commission when the reward was credited, only present for voting and staking rewards
};

pub const RewardType = enum {
    Fee,
    Rent,
    Staking,
    Voting,
};

pub const StartBlockHeightAndRewards = struct {
    /// the block height of the parent of the slot at which rewards distribution began
    parent_start_block_height: u64,
    /// calculated epoch rewards pending distribution
    calculated_epoch_stake_rewards: ArrayList(StakeReward),
};

pub const EpochRewardStatus = union(enum) {
    Active: StartBlockHeightAndRewards,
    Inactive: void,

    pub fn default() @This() { 
        return @This().Inactive;
    }
};

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
    stakes: Stakes(Delegation),
    unused_accounts: UnusedAccounts, // required for deserialization
    epoch_stakes: HashMap(Epoch, EpochStakes),
    is_delta: bool,

    // we skip these values now because they may be at 
    // the end of the snapshot (after account_db_fields)
    incremental_snapshot_persistence: BankIncrementalSnapshotPersistence = BankIncrementalSnapshotPersistence.default(),
    epoch_accounts_hash: Hash = Hash.default(),
    epoch_reward_status: EpochRewardStatus = EpochRewardStatus.default(),

    pub const @"!bincode-config:incremental_snapshot_persistence" = bincode.FieldConfig(BankIncrementalSnapshotPersistence){ .skip = true };
    pub const @"!bincode-config:epoch_accounts_hash" = bincode.FieldConfig(Hash){ .skip = true };
    pub const @"!bincode-config:epoch_reward_status" = bincode.FieldConfig(EpochRewardStatus){ .skip = true };
};

pub const SerializableAccountStorageEntry = struct { 
    id: usize,
    accounts_current_len: usize,
};

pub const BankHashInfo = struct {
    accounts_delta_hash: Hash,
    accounts_hash: Hash,
    stats: BankHashStats,
};

pub const BankHashStats = struct {
    num_updated_accounts: u64,
    num_removed_accounts: u64,
    num_lamports_stored: u64,
    total_data_len: u64,
    num_executable_accounts: u64,
};

pub const AccountsDbFields = struct { 
    map: HashMap(Slot, ArrayList(SerializableAccountStorageEntry)),
    stored_meta_write_version: u64, 
    slot: Slot, 
    bank_hash_info: BankHashInfo,

    // default on EOF
    rooted_slots: ArrayList(Slot),
    rooted_slot_hashes: ArrayList(SlotHash),

    pub const SlotHash = struct { Slot, Hash };
    pub const @"!bincode-config:rooted_slots" = defaultArrayListOnEOFConfig(Slot);
    pub const @"!bincode-config:rooted_slot_hashes" = defaultArrayListOnEOFConfig(SlotHash);
};

pub const SnapshotFields = struct {
    bank_fields: BankFields,
    accounts_db_fields: AccountsDbFields,

    // incremental snapshot fields (to be added to bank_fields)
    lamports_per_signature: u64 = 0,
    incremental_snapshot_persistence: BankIncrementalSnapshotPersistence = BankIncrementalSnapshotPersistence.default(),
    epoch_accounts_hash: Hash = Hash.default(),
    epoch_reward_status: EpochRewardStatus = EpochRewardStatus.default(),

    pub const @"!bincode-config:lamports_per_signature" = bincode.FieldConfig(u64){ .default_on_eof = true };
    pub const @"!bincode-config:incremental_snapshot_persistence" = bincode.FieldConfig(BankIncrementalSnapshotPersistence){ .default_on_eof = true };
    pub const @"!bincode-config:epoch_accounts_hash" = bincode.FieldConfig(Hash){ .default_on_eof = true };
    pub const @"!bincode-config:epoch_reward_status" = bincode.FieldConfig(EpochRewardStatus){ .default_on_eof = true };

    /// NOTE: should call this to get the correct bank_fields instead of accessing it directly
    /// due to the way snapshot deserialization works
    pub fn getFields(self: *@This()) struct {bank_fields: BankFields, accounts_db_fields: AccountsDbFields} {
        var bank_fields = &self.bank_fields;
        // if these are availabel they will be parsed (and likely not the default values)
        // so, we push them on the bank fields here 
        bank_fields.fee_rate_governor.lamports_per_signature = self.lamports_per_signature;
        bank_fields.incremental_snapshot_persistence = self.incremental_snapshot_persistence;
        bank_fields.epoch_accounts_hash = self.epoch_accounts_hash;
        bank_fields.epoch_reward_status = self.epoch_reward_status;

        return .{ .bank_fields = self.bank_fields, .accounts_db_fields = self.accounts_db_fields };
    }
};

test "core.bank_fields: tmp" {
    // steps:
    // 1) download a snapshot
    // 2) decompress snapshot
    // 3) untar snapshot to get accounts/ dir + other metdata files
    // 4) set the `root_snapshot_path` to point to the file with metadata
    // 4) run this
    const root_snapshot_path = "";
    const alloc = std.testing.allocator;

    // open file
    var file = std.fs.openFileAbsolute(root_snapshot_path, .{}) catch |err| {
        std.debug.print("failed to open bank/accounts-db fields file: {s} ... skipping test\n", .{@errorName(err)});
        return;
    };
    defer file.close();

    try file.seekFromEnd(0);
    const file_size = try file.getPos();
    try file.seekTo(0);

    var buf_reader = std.io.bufferedReader(file.reader());
    var in_stream = buf_reader.reader();

    var buf = try std.ArrayList(u8).initCapacity(alloc, file_size);
    defer buf.deinit();

    var snapshot_fields = try bincode.read(alloc, SnapshotFields, in_stream, .{});
    defer bincode.free(alloc, snapshot_fields);

    const fields = snapshot_fields.getFields();
    _ = fields;
}
