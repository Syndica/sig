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
const Slot = @import("./time.zig").Slot;
const Epoch = @import("./time.zig").Epoch;
const Pubkey = @import("./pubkey.zig").Pubkey;
const bincode = @import("../bincode/bincode.zig");
const defaultArrayListOnEOFConfig = @import("../utils/arraylist.zig").defaultArrayListOnEOFConfig;
pub const sysvars = @import("./sysvars.zig");

pub const MAXIMUM_APPEND_VEC_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB

pub const StakeHistoryEntry = struct {
    effective: u64, // effective stake at this epoch
    activating: u64, // sum of portion of stakes not fully warmed up
    deactivating: u64, // requested to be cooled down, not fully deactivated yet
};

const StakeHistory = ArrayList(struct { Epoch, StakeHistoryEntry });

pub const Stakes = struct {
    /// vote accounts
    vote_accounts: VoteAccounts,

    /// stake_delegations
    stake_delegations: HashMap(Pubkey, Delegation),

    /// unused
    unused: u64,

    /// current epoch, used to calculate current stake
    epoch: Epoch,

    /// history of staking levels
    stake_history: StakeHistory,
};

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
    stakes: Stakes,
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
    stakes: Stakes,
    unused_accounts: UnusedAccounts, // required for deserialization
    epoch_stakes: HashMap(Epoch, EpochStakes),
    is_delta: bool,

    // we skip these values now because they may be at
    // the end of the snapshot (after account_db_fields)
    incremental_snapshot_persistence: ?BankIncrementalSnapshotPersistence = null,
    epoch_accounts_hash: ?Hash = null,
    epoch_reward_status: ?EpochRewardStatus = null,

    pub const @"!bincode-config:incremental_snapshot_persistence" = bincode.FieldConfig(?BankIncrementalSnapshotPersistence){ .skip = true };
    pub const @"!bincode-config:epoch_accounts_hash" = bincode.FieldConfig(?Hash){ .skip = true };
    pub const @"!bincode-config:epoch_reward_status" = bincode.FieldConfig(?EpochRewardStatus){ .skip = true };
};

pub const AccountFileInfo = struct {
    // note: serialized id is a usize but in code its FileId (u32)
    id: usize,
    length: usize, // amount of bytes used

    pub fn sanitize(self: *const AccountFileInfo, file_size: usize) !void {
        if (file_size == 0) {
            return error.FileSizeTooSmall;
        } else if (file_size > @as(usize, MAXIMUM_APPEND_VEC_FILE_SIZE)) {
            return error.FileSizeTooLarge;
        } else if (self.length > file_size) {
            return error.OffsetOutOfBounds;
        }
    }
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
    file_map: HashMap(Slot, ArrayList(AccountFileInfo)),
    stored_meta_write_version: u64,
    slot: Slot,
    bank_hash_info: BankHashInfo,

    // default on EOF
    rooted_slots: ArrayList(Slot),
    rooted_slot_hashes: ArrayList(SlotHash),

    pub const SlotHash = struct { slot: Slot, hash: Hash };
    pub const @"!bincode-config:rooted_slots" = defaultArrayListOnEOFConfig(Slot);
    pub const @"!bincode-config:rooted_slot_hashes" = defaultArrayListOnEOFConfig(SlotHash);
};

pub const SnapshotFields = struct {
    bank_fields: BankFields,
    accounts_db_fields: AccountsDbFields,

    // incremental snapshot fields (to be added to bank_fields)
    lamports_per_signature: u64 = 0,
    incremental_snapshot_persistence: ?BankIncrementalSnapshotPersistence = null,
    epoch_accounts_hash: ?Hash = null,
    epoch_reward_status: ?EpochRewardStatus = null,

    pub const @"!bincode-config:lamports_per_signature" = bincode.FieldConfig(u64){ .default_on_eof = true };
    pub const @"!bincode-config:incremental_snapshot_persistence" = bincode.FieldConfig(?BankIncrementalSnapshotPersistence){ .default_on_eof = true };
    pub const @"!bincode-config:epoch_accounts_hash" = bincode.FieldConfig(?Hash){ .default_on_eof = true };
    pub const @"!bincode-config:epoch_reward_status" = bincode.FieldConfig(?EpochRewardStatus){ .default_on_eof = true };

    pub fn readFromFilePath(allocator: std.mem.Allocator, path: []const u8) !SnapshotFields {
        var file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        var snapshot_fields = try bincode.read(allocator, SnapshotFields, file.reader(), .{});

        // if these are available, we push them onto the banks
        var bank_fields = &snapshot_fields.bank_fields;
        bank_fields.fee_rate_governor.lamports_per_signature = snapshot_fields.lamports_per_signature;
        if (snapshot_fields.incremental_snapshot_persistence != null) {
            bank_fields.incremental_snapshot_persistence = snapshot_fields.incremental_snapshot_persistence.?;
        }
        if (snapshot_fields.epoch_accounts_hash != null) {
            bank_fields.epoch_accounts_hash = snapshot_fields.epoch_accounts_hash.?;
        }
        if (snapshot_fields.epoch_reward_status != null) {
            bank_fields.epoch_reward_status = snapshot_fields.epoch_reward_status.?;
        }

        return snapshot_fields;
    }

    pub fn deinit(self: SnapshotFields, allocator: std.mem.Allocator) void {
        bincode.free(allocator, self);
    }
};

pub const InstructionError = union(enum) {
    /// Deprecated! Use CustomError instead!
    /// The program instruction returned an error
    GenericError,

    /// The arguments provided to a program were invalid
    InvalidArgument,

    /// An instruction's data contents were invalid
    InvalidInstructionData,

    /// An account's data contents was invalid
    InvalidAccountData,

    /// An account's data was too small
    AccountDataTooSmall,

    /// An account's balance was too small to complete the instruction
    InsufficientFunds,

    /// The account did not have the expected program id
    IncorrectProgramId,

    /// A signature was required but not found
    MissingRequiredSignature,

    /// An initialize instruction was sent to an account that has already been initialized.
    AccountAlreadyInitialized,

    /// An attempt to operate on an account that hasn't been initialized.
    UninitializedAccount,

    /// Program's instruction lamport balance does not equal the balance after the instruction
    UnbalancedInstruction,

    /// Program illegally modified an account's program id
    ModifiedProgramId,

    /// Program spent the lamports of an account that doesn't belong to it
    ExternalAccountLamportSpend,

    /// Program modified the data of an account that doesn't belong to it
    ExternalAccountDataModified,

    /// Read-only account's lamports modified
    ReadonlyLamportChange,

    /// Read-only account's data was modified
    ReadonlyDataModified,

    /// An account was referenced more than once in a single instruction
    // Deprecated, instructions can now contain duplicate accounts
    DuplicateAccountIndex,

    /// Executable bit on account changed, but shouldn't have
    ExecutableModified,

    /// Rent_epoch account changed, but shouldn't have
    RentEpochModified,

    /// The instruction expected additional account keys
    NotEnoughAccountKeys,

    /// Program other than the account's owner changed the size of the account data
    AccountDataSizeChanged,

    /// The instruction expected an executable account
    AccountNotExecutable,

    /// Failed to borrow a reference to account data, already borrowed
    AccountBorrowFailed,

    /// Account data has an outstanding reference after a program's execution
    AccountBorrowOutstanding,

    /// The same account was multiply passed to an on-chain program's entrypoint, but the program
    /// modified them differently.  A program can only modify one instance of the account because
    /// the runtime cannot determine which changes to pick or how to merge them if both are modified
    DuplicateAccountOutOfSync,

    /// Allows on-chain programs to implement program-specific error types and see them returned
    /// by the Solana runtime. A program-specific error may be any type that is represented as
    /// or serialized to a u32 integer.
    Custom: u32,

    /// The return value from the program was invalid.  Valid errors are either a defined builtin
    /// error value or a user-defined error in the lower 32 bits.
    InvalidError,

    /// Executable account's data was modified
    ExecutableDataModified,

    /// Executable account's lamports modified
    ExecutableLamportChange,

    /// Executable accounts must be rent exempt
    ExecutableAccountNotRentExempt,

    /// Unsupported program id
    UnsupportedProgramId,

    /// Cross-program invocation call depth too deep
    CallDepth,

    /// An account required by the instruction is missing
    MissingAccount,

    /// Cross-program invocation reentrancy not allowed for this instruction
    ReentrancyNotAllowed,

    /// Length of the seed is too long for address generation
    MaxSeedLengthExceeded,

    /// Provided seeds do not result in a valid address
    InvalidSeeds,

    /// Failed to reallocate account data of this length
    InvalidRealloc,

    /// Computational budget exceeded
    ComputationalBudgetExceeded,

    /// Cross-program invocation with unauthorized signer or writable account
    PrivilegeEscalation,

    /// Failed to create program execution environment
    ProgramEnvironmentSetupFailure,

    /// Program failed to complete
    ProgramFailedToComplete,

    /// Program failed to compile
    ProgramFailedToCompile,

    /// Account is immutable
    Immutable,

    /// Incorrect authority provided
    IncorrectAuthority,

    /// Failed to serialize or deserialize account data
    ///
    /// Warning: This error should never be emitted by the runtime.
    ///
    /// This error includes strings from the underlying 3rd party Borsh crate
    /// which can be dangerous because the error strings could change across
    /// Borsh versions. Only programs can use this error because they are
    /// consistent across Solana software versions.
    ///
    BorshIoError: []const u8,

    /// An account does not have enough lamports to be rent-exempt
    AccountNotRentExempt,

    /// Invalid account owner
    InvalidAccountOwner,

    /// Program arithmetic overflowed
    ArithmeticOverflow,

    /// Unsupported sysvar
    UnsupportedSysvar,

    /// Illegal account owner
    IllegalOwner,

    /// Accounts data allocations exceeded the maximum allowed per transaction
    MaxAccountsDataAllocationsExceeded,

    /// Max accounts exceeded
    MaxAccountsExceeded,

    /// Max instruction trace length exceeded
    MaxInstructionTraceLengthExceeded,

    /// Builtin programs must consume compute units
    BuiltinProgramsMustConsumeComputeUnits,
    // Note: For any new error added here an equivalent ProgramError and its
    // conversions must also be added
};

const TransactionError = union(enum) {
    /// An account is already being processed in another transaction in a way
    /// that does not support parallelism
    AccountInUse,

    /// A `Pubkey` appears twice in the transaction's `account_keys`.  Instructions can reference
    /// `Pubkey`s more than once but the message must contain a list with no duplicate keys
    AccountLoadedTwice,

    /// Attempt to debit an account but found no record of a prior credit.
    AccountNotFound,

    /// Attempt to load a program that does not exist
    ProgramAccountNotFound,

    /// The from `Pubkey` does not have sufficient balance to pay the fee to schedule the transaction
    InsufficientFundsForFee,

    /// This account may not be used to pay transaction fees
    InvalidAccountForFee,

    /// The bank has seen this transaction before. This can occur under normal operation
    /// when a UDP packet is duplicated, as a user error from a client not updating
    /// its `recent_blockhash`, or as a double-spend attack.
    AlreadyProcessed,

    /// The bank has not seen the given `recent_blockhash` or the transaction is too old and
    /// the `recent_blockhash` has been discarded.
    BlockhashNotFound,

    /// An error occurred while processing an instruction. The first element of the tuple
    /// indicates the instruction index in which the error occurred.
    InstructionError: struct { instruction_index: u8, err: InstructionError },

    /// Loader call chain is too deep
    CallChainTooDeep,

    /// Transaction requires a fee but has no signature present
    MissingSignatureForFee,

    /// Transaction contains an invalid account reference
    InvalidAccountIndex,

    /// Transaction did not pass signature verification
    SignatureFailure,

    /// This program may not be used for executing instructions
    InvalidProgramForExecution,

    /// Transaction failed to sanitize accounts offsets correctly
    /// implies that account locks are not taken for this TX, and should
    /// not be unlocked.
    SanitizeFailure,

    ClusterMaintenance,

    /// Transaction processing left an account with an outstanding borrowed reference
    AccountBorrowOutstanding,

    /// Transaction would exceed max Block Cost Limit
    WouldExceedMaxBlockCostLimit,

    /// Transaction version is unsupported
    UnsupportedVersion,

    /// Transaction loads a writable account that cannot be written
    InvalidWritableAccount,

    /// Transaction would exceed max account limit within the block
    WouldExceedMaxAccountCostLimit,

    /// Transaction would exceed account data limit within the block
    WouldExceedAccountDataBlockLimit,

    /// Transaction locked too many accounts
    TooManyAccountLocks,

    /// Address lookup table not found
    AddressLookupTableNotFound,

    /// Attempted to lookup addresses from an account owned by the wrong program
    InvalidAddressLookupTableOwner,

    /// Attempted to lookup addresses from an invalid account
    InvalidAddressLookupTableData,

    /// Address table lookup uses an invalid index
    InvalidAddressLookupTableIndex,

    /// Transaction leaves an account with a lower balance than rent-exempt minimum
    InvalidRentPayingAccount,

    /// Transaction would exceed max Vote Cost Limit
    WouldExceedMaxVoteCostLimit,

    /// Transaction would exceed total account data limit
    WouldExceedAccountDataTotalLimit,

    /// Transaction contains a duplicate instruction that is not allowed
    DuplicateInstruction: u8,

    /// Transaction results in an account with insufficient funds for rent
    InsufficientFundsForRent: struct { account_index: u8 },

    /// Transaction exceeded max loaded accounts data size cap
    MaxLoadedAccountsDataSizeExceeded,

    /// LoadedAccountsDataSizeLimit set for transaction must be greater than 0.
    InvalidLoadedAccountsDataSizeLimit,

    /// Sanitized transaction differed before/after feature activiation. Needs to be resanitized.
    ResanitizationNeeded,

    /// Program execution is temporarily restricted on an account.
    ProgramExecutionTemporarilyRestricted: struct { account_index: u8 },
};

const Result = union(enum) {
    Ok,
    Error: TransactionError,
};

const CACHED_KEY_SIZE: usize = 20;
const Status = HashMap(Hash, struct { i: usize, j: ArrayList(struct {
    key_slice: [CACHED_KEY_SIZE]u8,
    result: Result,
}) });
const BankSlotDelta = struct { slot: Slot, is_root: bool, status: Status };

pub const StatusCache = struct {
    bank_slot_deltas: ArrayList(BankSlotDelta),

    pub fn init(allocator: std.mem.Allocator, path: []const u8) !StatusCache {
        var status_cache_file = try std.fs.cwd().openFile(path, .{});
        defer status_cache_file.close();

        var status_cache = try bincode.read(
            allocator,
            StatusCache,
            status_cache_file.reader(),
            .{},
        );
        return status_cache;
    }

    pub fn deinit(self: *StatusCache) void {
        bincode.free(self.bank_slot_deltas.allocator, self.*);
    }

    pub fn validate(
        self: *const StatusCache,
        allocator: std.mem.Allocator,
        bank_slot: Slot,
        slot_history: *const sysvars.SlotHistory,
    ) !void {
        // status cache validation
        const len = self.bank_slot_deltas.items.len;
        if (len > MAX_CACHE_ENTRIES) {
            return error.TooManyCacheEntries;
        }

        var slots_seen = std.AutoArrayHashMap(Slot, void).init(allocator);
        defer slots_seen.deinit();

        for (self.bank_slot_deltas.items) |slot_delta| {
            if (!slot_delta.is_root) {
                return error.NonRootSlot;
            }
            const slot = slot_delta.slot;
            if (slot > bank_slot) {
                return error.SlotTooHigh;
            }
            const entry = try slots_seen.getOrPut(slot);
            if (entry.found_existing) {
                return error.MultipleSlotEntries;
            }
        }

        // validate bank's slot_history matches the status cache
        if (slot_history.newest() != bank_slot) {
            return error.SlotHistoryMismatch;
        }
        for (slots_seen.keys()) |slot| {
            if (slot_history.check(slot) != sysvars.SlotCheckResult.Found) {
                return error.SlotNotFoundInHistory;
            }
        }
        for (slot_history.oldest()..slot_history.newest()) |slot| {
            if (!slots_seen.contains(slot)) {
                return error.SlotNotFoundInStatusCache;
            }
        }
    }
};

pub const MAX_RECENT_BLOCKHASHES: usize = 300;
pub const MAX_CACHE_ENTRIES: usize = MAX_RECENT_BLOCKHASHES;

test "core.snapshot_fields: parse status cache" {
    const allocator = std.testing.allocator;

    const status_cache_path = "test_data/status_cache";
    var status_cache = try StatusCache.init(allocator, status_cache_path);
    defer status_cache.deinit();

    try std.testing.expect(status_cache.bank_slot_deltas.items.len > 0);
}

test "core.snapshot_fields: parse snapshot fields" {
    const allocator = std.testing.allocator;
    const snapshot_path = "test_data/10";

    var snapshot_fields = try SnapshotFields.readFromFilePath(allocator, snapshot_path);
    defer snapshot_fields.deinit(allocator);
}

test "core.snapshot_fields: parse incremental snapshot fields" {
    const allocator = std.testing.allocator;
    const snapshot_path = "test_data/25";

    var snapshot_fields = try SnapshotFields.readFromFilePath(allocator, snapshot_path);
    defer snapshot_fields.deinit(allocator);

    try std.testing.expectEqual(snapshot_fields.lamports_per_signature, 5000);
    try std.testing.expectEqual(snapshot_fields.bank_fields.incremental_snapshot_persistence.?.full_slot, 10);
}
