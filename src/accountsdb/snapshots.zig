//! fields + data to deserialize snapshot metadata

const std = @import("std");
const zstd = @import("zstd");
const sig = @import("../lib.zig");

const bincode = sig.bincode;

const ArrayList = std.ArrayList;
const ZstdReader = zstd.Reader;

const Account = sig.core.account.Account;
const Hash = sig.core.hash.Hash;
const Slot = sig.core.time.Slot;
const Epoch = sig.core.time.Epoch;
const Pubkey = sig.core.pubkey.Pubkey;
const UnixTimestamp = sig.accounts_db.genesis_config.UnixTimestamp;
const FeeRateGovernor = sig.accounts_db.genesis_config.FeeRateGovernor;
const EpochSchedule = sig.accounts_db.genesis_config.EpochSchedule;
const Rent = sig.accounts_db.genesis_config.Rent;
const Inflation = sig.accounts_db.genesis_config.Inflation;
const SlotHistory = sig.accounts_db.sysvars.SlotHistory;

const defaultArrayListOnEOFConfig = bincode.arraylist.defaultArrayListOnEOFConfig;
const readDirectory = sig.utils.directory.readDirectory;
const parallelUntarToFileSystem = sig.utils.tar.parallelUntarToFileSystem;

pub const MAXIMUM_ACCOUNT_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB
pub const MAX_RECENT_BLOCKHASHES: usize = 300;
pub const MAX_CACHE_ENTRIES: usize = MAX_RECENT_BLOCKHASHES;
const CACHED_KEY_SIZE: usize = 20;

/// Analogous to [StakeHistoryEntry](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/sdk/program/src/stake_history.rs#L17)
pub const StakeHistoryEntry = struct {
    effective: u64, // effective stake at this epoch
    activating: u64, // sum of portion of stakes not fully warmed up
    deactivating: u64, // requested to be cooled down, not fully deactivated yet
};

/// Analogous to [StakeHistory](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/sdk/program/src/stake_history.rs#L62)
const StakeHistory = ArrayList(struct { Epoch, StakeHistoryEntry });

/// Analogous to [Stakes](https://github.com/anza-xyz/agave/blob/1f3ef3325fb0ce08333715aa9d92f831adc4c559/runtime/src/stakes.rs#L186)
pub const Stakes = struct {
    /// vote accounts
    vote_accounts: VoteAccounts,

    /// stake_delegations
    stake_delegations: std.AutoArrayHashMap(Pubkey, Delegation),

    /// unused
    unused: u64,

    /// current epoch, used to calculate current stake
    epoch: Epoch,

    /// history of staking levels
    stake_history: StakeHistory,
};

/// Analogous to [VoteAccounts](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/vote/src/vote_account.rs#L44)
pub const VoteAccounts = struct {
    vote_accounts: std.AutoArrayHashMap(Pubkey, struct { u64, VoteAccount }),

    staked_nodes: ?std.AutoArrayHashMap(
        Pubkey, // VoteAccount.vote_state.node_pubkey.
        u64, // Total stake across all vote-accounts.
    ) = null,

    pub const @"!bincode-config:staked_nodes" = bincode.FieldConfig(?std.AutoArrayHashMap(Pubkey, u64)){ .skip = true };

    const Self = @This();

    pub fn stakedNodes(self: *Self, allocator: std.mem.Allocator) !*const std.AutoArrayHashMap(Pubkey, u64) {
        if (self.staked_nodes) |*staked_nodes| {
            return staked_nodes;
        }
        const vote_accounts = self.vote_accounts;
        var staked_nodes = std.AutoArrayHashMap(Pubkey, u64).init(allocator);
        var iter = vote_accounts.iterator();
        while (iter.next()) |vote_entry| {
            const vote_state = try vote_entry.value_ptr[1].voteState();
            const node_entry = try staked_nodes.getOrPut(vote_state.node_pubkey);
            if (!node_entry.found_existing) {
                node_entry.value_ptr.* = 0;
            }
            node_entry.value_ptr.* += vote_entry.value_ptr[0];
        }
        self.staked_nodes = staked_nodes;
        return &self.staked_nodes.?;
    }
};

pub const VoteAccount = struct {
    account: Account,
    vote_state: ?anyerror!VoteState = null,

    pub const @"!bincode-config:vote_state" = bincode.FieldConfig(?anyerror!VoteState){ .skip = true };

    pub fn voteState(self: *@This()) !VoteState {
        if (self.vote_state) |vs| {
            return vs;
        }
        self.vote_state = bincode.readFromSlice(undefined, VoteState, self.account.data, .{});
        return self.vote_state.?;
    }
};

pub const VoteState = struct {
    /// The variant of the rust enum
    tag: u32, // TODO: consider varint bincode serialization (in rust this is enum)
    /// the node that votes in this account
    node_pubkey: Pubkey,
};

test "deserialize VoteState.node_pubkey" {
    const bytes = .{
        2,  0,   0,   0, 60,  155, 13,  144, 187, 252, 153, 72,  190, 35,  87,  94,  7,  178,
        90, 174, 158, 6, 199, 179, 134, 194, 112, 248, 166, 232, 144, 253, 128, 249, 67, 118,
    } ++ .{0} ** 1586 ++ .{ 31, 0, 0, 0, 0, 0, 0, 0, 1 } ++ .{0} ** 24;
    const vote_state = try bincode.readFromSlice(undefined, VoteState, &bytes, .{});
    const expected_pubkey = try Pubkey.fromString("55abJrqFnjm7ZRB1noVdh7BzBe3bBSMFT3pt16mw6Vad");
    try std.testing.expect(expected_pubkey.equals(&vote_state.node_pubkey));
}

/// Analogous to [Delegation](https://github.com/anza-xyz/agave/blob/f807911531359e0ae4cfcaf371bd3843ec52f1c6/sdk/program/src/stake/state.rs#L587)
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

/// Analogous to [RentCollector](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/rent_collector.rs#L16)
pub const RentCollector = struct {
    epoch: Epoch,
    epoch_schedule: EpochSchedule,
    slots_per_year: f64,
    rent: Rent,
};

/// Analogous to (FeeCalculator)[https://github.com/anza-xyz/agave/blob/ec9bd798492c3b15d62942f2d9b5923b99042350/sdk/program/src/fee_calculator.rs#L13]
pub const FeeCalculator = struct {
    /// The current cost of a signature.
    ///
    /// This amount may increase/decrease over time based on cluster processing
    /// load.
    lamports_per_signature: u64,
};

/// Analogous to [HashInfo](https://github.com/anza-xyz/agave/blob/a79ba51741864e94a066a8e27100dfef14df835f/accounts-db/src/blockhash_queue.rs#L13)
pub const HashAge = struct {
    fee_calculator: FeeCalculator,
    hash_index: u64,
    timestamp: u64,
};

/// Analogous to [BlockhashQueue](https://github.com/anza-xyz/agave/blob/a79ba51741864e94a066a8e27100dfef14df835f/accounts-db/src/blockhash_queue.rs#L32)
pub const BlockhashQueue = struct {
    last_hash_index: u64,

    /// last hash to be registered
    last_hash: ?Hash,
    ages: std.AutoArrayHashMap(Hash, HashAge),

    /// hashes older than `max_age` will be dropped from the queue
    max_age: usize,
};

// TODO: move this elsewhere
pub fn HashSet(comptime T: type) type {
    return std.AutoArrayHashMap(T, void);
}

/// Analogous to [UnusedAccounts](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L123)
pub const UnusedAccounts = struct {
    unused1: HashSet(Pubkey),
    unused2: HashSet(Pubkey),
    unused3: std.AutoArrayHashMap(Pubkey, u64),
};

/// Analogous to [AncestorsForSerialization](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/accounts-db/src/ancestors.rs#L8)
pub const Ancestors = std.AutoArrayHashMap(Slot, usize);

/// Analogous to [HardForks](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/hard_forks.rs#L13)
pub const HardForks = struct {
    hard_forks: std.ArrayList(struct { Slot, usize }),
};

/// Analogous to [NodeVoteAccounts](https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/runtime/src/epoch_stakes.rs#L14)
pub const NodeVoteAccounts = struct {
    vote_accounts: ArrayList(Pubkey),
    total_stake: u64,
};

/// Analogous to [EpochStakes](https://github.com/anza-xyz/agave/blob/574bae8fefc0ed256b55340b9d87b7689bcdf222/runtime/src/epoch_stakes.rs#L22)
pub const EpochStakes = struct {
    stakes: Stakes,
    total_stake: u64,
    node_id_to_vote_accounts: std.AutoArrayHashMap(Pubkey, NodeVoteAccounts),
    epoch_authorized_voters: std.AutoArrayHashMap(Pubkey, Pubkey),
};

/// Analogous to [BankIncrementalSnapshotPersistence](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L100)
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

/// Analogous to [StakeReward](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/accounts-db/src/stake_rewards.rs#L12)
pub const StakeReward = struct {
    stake_pubkey: Pubkey,
    stake_reward_info: RewardInfo,
    stake_account: Account,
};

/// Analogous to [RewardInfo](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/reward_info.rs#L5)
pub const RewardInfo = struct {
    reward_type: RewardType,
    lamports: i64, // Reward amount
    post_balance: u64, // Account balance in lamports after `lamports` was applied
    commission: ?u8, // Vote account commission when the reward was credited, only present for voting and staking rewards
};

/// Analogous to [RewardType](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/reward_type.rs#L7)
pub const RewardType = enum {
    Fee,
    Rent,
    Staking,
    Voting,
};

/// Analogous to [StartBlockHeightAndRewards](https://github.com/anza-xyz/agave/blob/034cd7396a1db2db21a3305b259a17a5fdea312c/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L60)
pub const StartBlockHeightAndRewards = struct {
    /// the block height of the parent of the slot at which rewards distribution began
    parent_start_block_height: u64,
    /// calculated epoch rewards pending distribution
    calculated_epoch_stake_rewards: ArrayList(StakeReward),
};

/// Analogous to [EpochRewardStatus](https://github.com/anza-xyz/agave/blob/034cd7396a1db2db21a3305b259a17a5fdea312c/runtime/src/bank/partitioned_epoch_rewards/mod.rs#L70)
pub const EpochRewardStatus = union(enum) {
    Active: StartBlockHeightAndRewards,
    Inactive: void,

    pub fn default() @This() {
        return @This().Inactive;
    }
};

/// Analogous to most of the fields of [Bank](https://github.com/anza-xyz/agave/blob/ad0a48c7311b08dbb6c81babaf66c136ac092e79/runtime/src/bank.rs#L718)
/// and [BankFieldsToDeserialize](https://github.com/anza-xyz/agave/blob/ad0a48c7311b08dbb6c81babaf66c136ac092e79/runtime/src/bank.rs#L459)
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
    epoch_stakes: std.AutoArrayHashMap(Epoch, EpochStakes),
    is_delta: bool,

    pub const Incremental = struct {
        snapshot_persistence: ?BankIncrementalSnapshotPersistence = null,
        epoch_accounts_hash: ?Hash = null,
        epoch_reward_status: ?EpochRewardStatus = null,

        pub const @"!bincode-config:incremental_snapshot_persistence" = bincode.FieldConfig(?BankIncrementalSnapshotPersistence){ .default_on_eof = true };
        pub const @"!bincode-config:epoch_accounts_hash" = bincode.FieldConfig(?Hash){ .default_on_eof = true };
        pub const @"!bincode-config:epoch_reward_status" = bincode.FieldConfig(?EpochRewardStatus){ .default_on_eof = true };
    };
};

/// Analogous to [SerializableAccountStorageEntry](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/runtime/src/serde_snapshot/storage.rs#L11)
pub const AccountFileInfo = struct {
    // note: serialized id is a usize but in code its FileId (u32)
    id: usize,
    length: usize, // amount of bytes used

    /// Analogous to [AppendVecError](https://github.com/anza-xyz/agave/blob/91a4ecfff78423433cc0001362cea8fed860dcb9/accounts-db/src/append_vec.rs#L74)
    pub const ValidateError = error{
        IdOverflow,
        FileSizeTooSmall,
        FileSizeTooLarge,
        OffsetOutOfBounds,
    };
    /// Analogous to [sanitize_len_and_size](https://github.com/anza-xyz/agave/blob/91a4ecfff78423433cc0001362cea8fed860dcb9/accounts-db/src/append_vec.rs#L376)
    pub fn validate(self: *const AccountFileInfo, file_size: usize) ValidateError!void {
        if (self.id > std.math.maxInt(u32)) {
            return error.IdOverflow;
        }
        if (file_size == 0) {
            return error.FileSizeTooSmall;
        } else if (file_size > @as(usize, MAXIMUM_ACCOUNT_FILE_SIZE)) {
            return error.FileSizeTooLarge;
        } else if (self.length > file_size) {
            return error.OffsetOutOfBounds;
        }
    }
};

/// Analogous to [BankHashInfo](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L115)
pub const BankHashInfo = struct {
    accounts_delta_hash: Hash,
    accounts_hash: Hash,
    stats: BankHashStats,
};

/// Analogous to [BankHashStats](https://github.com/anza-xyz/agave/blob/4c921ca276bbd5997f809dec1dd3937fb06463cc/accounts-db/src/accounts_db.rs#L1299)
pub const BankHashStats = struct {
    num_updated_accounts: u64,
    num_removed_accounts: u64,
    num_lamports_stored: u64,
    total_data_len: u64,
    num_executable_accounts: u64,
};

pub const SlotAndHash = struct { slot: Slot, hash: Hash };

/// Analogous to [AccountsDbFields](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L77)
pub const AccountsDbFields = struct {
    file_map: std.AutoArrayHashMap(Slot, ArrayList(AccountFileInfo)),
    stored_meta_write_version: u64,
    slot: Slot,
    bank_hash_info: BankHashInfo,

    // default on EOF
    rooted_slots: ArrayList(Slot),
    rooted_slot_hashes: ArrayList(SlotAndHash),

    pub const @"!bincode-config:rooted_slots" = defaultArrayListOnEOFConfig(Slot);
    pub const @"!bincode-config:rooted_slot_hashes" = defaultArrayListOnEOFConfig(SlotAndHash);
};

/// contains all the metadata from a snapshot.
/// this includes fields for accounts-db and the bank of the snapshots slots.
/// this does not include account-specific data.
pub const SnapshotFields = struct {
    bank_fields: BankFields,
    accounts_db_fields: AccountsDbFields,
    lamports_per_signature: u64 = 0,
    /// incremental snapshot fields (to accompany added to bank_fields)
    bank_fields_inc: BankFields.Incremental = .{},

    pub const @"!bincode-config:lamports_per_signature" = bincode.FieldConfig(u64){ .default_on_eof = true };

    pub fn readFromFilePath(allocator: std.mem.Allocator, path: []const u8) !SnapshotFields {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            switch (err) {
                error.FileNotFound => return error.SnapshotFieldsNotFound,
                else => return err,
            }
        };
        defer file.close();
        return try decodeFromBincode(allocator, file.reader());
    }

    pub fn decodeFromBincode(
        allocator: std.mem.Allocator,
        /// `std.io.GenericReader(...)` | `std.io.AnyReader`
        reader: anytype,
    ) !SnapshotFields {
        return try bincode.read(allocator, SnapshotFields, reader, .{});
    }

    pub fn deinit(self: SnapshotFields, allocator: std.mem.Allocator) void {
        bincode.free(allocator, self);
    }
};

/// Analogous to [InstructionError](https://github.com/anza-xyz/agave/blob/25ec30452c7d74e2aeb00f2fa35876de9ce718c6/sdk/program/src/instruction.rs#L36)
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

/// Analogous to [TransactionError](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/sdk/src/transaction/error.rs#L14)
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

/// Analogous to [Status](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/runtime/src/status_cache.rs#L24)
pub const Status = struct {
    i: usize,
    j: []const KeySliceResult,

    pub const KeySliceResult = struct {
        key_slice: [CACHED_KEY_SIZE]u8,
        result: Result,
    };
};
pub const HashStatusMap = std.AutoArrayHashMapUnmanaged(Hash, Status);
/// Analogous to [SlotDelta](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/runtime/src/status_cache.rs#L35)
pub const BankSlotDelta = struct {
    slot: Slot,
    is_root: bool,
    status: HashStatusMap,
};

/// Analogous to [StatusCache](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/runtime/src/status_cache.rs#L39)
pub const StatusCache = struct {
    bank_slot_deltas: []const BankSlotDelta,

    pub fn initFromPath(allocator: std.mem.Allocator, path: []const u8) !StatusCache {
        var status_cache_file = try std.fs.cwd().openFile(path, .{});
        defer status_cache_file.close();
        return try decodeFromBincode(allocator, status_cache_file.reader());
    }

    pub fn decodeFromBincode(
        allocator: std.mem.Allocator,
        /// `std.io.GenericReader(...)` | `std.io.AnyReader`
        reader: anytype,
    ) !StatusCache {
        return try bincode.read(allocator, StatusCache, reader, .{});
    }

    pub fn deinit(self: StatusCache, allocator: std.mem.Allocator) void {
        bincode.free(allocator, self);
    }

    /// [verify_slot_deltas](https://github.com/anza-xyz/agave/blob/ed500b5afc77bc78d9890d96455ea7a7f28edbf9/runtime/src/snapshot_bank_utils.rs#L709)
    pub fn validate(
        self: *const StatusCache,
        allocator: std.mem.Allocator,
        bank_slot: Slot,
        slot_history: *const SlotHistory,
    ) !void {
        // status cache validation
        const len = self.bank_slot_deltas.len;
        if (len > MAX_CACHE_ENTRIES) {
            return error.TooManyCacheEntries;
        }

        var slots_seen = std.AutoArrayHashMap(Slot, void).init(allocator);
        defer slots_seen.deinit();

        for (self.bank_slot_deltas) |slot_delta| {
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
            if (slot_history.check(slot) != .Found) {
                return error.SlotNotFoundInHistory;
            }
        }

        var slots_checked: u32 = 0;
        var slot = slot_history.newest();
        while (slot >= slot_history.oldest() and slots_checked != MAX_CACHE_ENTRIES) {
            if (slot_history.check(slot) == .Found) {
                slots_checked += 1;
                if (!slots_seen.contains(slot)) {
                    return error.SlotNotFoundInStatusCache;
                }
            }
            if (slot == 0) break;
            slot -= 1;
        }
    }
};

/// information on a full snapshot including the filename, slot, and hash
///
/// Analogous to [SnapshotArchiveInfo](https://github.com/anza-xyz/agave/blob/59bf1809fe5115f0fad51e80cc0a19da1496e2e9/runtime/src/snapshot_archive_info.rs#L44)
pub const FullSnapshotFileInfo = struct {
    filename: []const u8,
    slot: Slot,
    hash: []const u8,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.filename);
    }

    /// matches with the regex: r"^snapshot-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar\.zst)$";
    pub fn fromString(filename: []const u8) !Self {
        var ext_parts = std.mem.splitSequence(u8, filename, ".");
        const stem = ext_parts.next() orelse return error.InvalidSnapshotPath;

        const extn = ext_parts.rest();
        // only support tar.zst
        if (!std.mem.eql(u8, extn, "tar.zst"))
            return error.InvalidSnapshotPath;

        var parts = std.mem.splitSequence(u8, stem, "-");
        const header = parts.next() orelse return error.InvalidSnapshotPath;
        if (!std.mem.eql(u8, header, "snapshot"))
            return error.InvalidSnapshotPath;

        const slot_str = parts.next() orelse return error.InvalidSnapshotPath;
        const slot = std.fmt.parseInt(Slot, slot_str, 10) catch return error.InvalidSnapshotPath;

        const hash = parts.next() orelse return error.InvalidSnapshotPath;

        return .{ .filename = filename, .slot = slot, .hash = hash };
    }
};

/// information on an incremental snapshot including the filename, base slot (full snapshot), slot, and hash
///
/// Analogous to [IncrementalSnapshotArchiveInfo](https://github.com/anza-xyz/agave/blob/59bf1809fe5115f0fad51e80cc0a19da1496e2e9/runtime/src/snapshot_archive_info.rs#L103)
pub const IncrementalSnapshotFileInfo = struct {
    filename: []const u8,
    // this references the full snapshot slot
    base_slot: Slot,
    slot: Slot,
    hash: []const u8,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.filename);
    }

    /// matches against regex: r"^incremental-snapshot-(?P<base>[[:digit:]]+)-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar\.zst)$";
    pub fn fromString(filename: []const u8) !Self {
        var ext_parts = std.mem.splitSequence(u8, filename, ".");
        const stem = ext_parts.next() orelse return error.InvalidSnapshotPath;

        const extn = ext_parts.rest();
        // only support tar.zst
        if (!std.mem.eql(u8, extn, "tar.zst"))
            return error.InvalidSnapshotPath;

        var parts = std.mem.splitSequence(u8, stem, "-");
        var header = parts.next() orelse return error.InvalidSnapshotPath;
        if (!std.mem.eql(u8, header, "incremental"))
            return error.InvalidSnapshotPath;

        header = parts.next() orelse return error.InvalidSnapshotPath;
        if (!std.mem.eql(u8, header, "snapshot"))
            return error.InvalidSnapshotPath;

        const base_slot_str = parts.next() orelse return error.InvalidSnapshotPath;
        const base_slot = std.fmt.parseInt(Slot, base_slot_str, 10) catch return error.InvalidSnapshotPath;

        const slot_str = parts.next() orelse return error.InvalidSnapshotPath;
        const slot = std.fmt.parseInt(Slot, slot_str, 10) catch return error.InvalidSnapshotPath;

        const hash = parts.next() orelse return error.InvalidSnapshotPath;

        return .{
            .filename = filename,
            .slot = slot,
            .base_slot = base_slot,
            .hash = hash,
        };
    }
};

pub const SnapshotFiles = struct {
    full_snapshot: FullSnapshotFileInfo,
    incremental_snapshot: ?IncrementalSnapshotFileInfo,

    const Self = @This();

    /// finds existing snapshots (full and matching incremental) by looking for .tar.zstd files
    pub fn find(allocator: std.mem.Allocator, snapshot_dir: []const u8) !Self {
        var snapshot_directory = try std.fs.cwd().openDir(snapshot_dir, .{ .iterate = true });
        defer snapshot_directory.close();

        var snapshot_dir_iter = snapshot_directory.iterate();

        const files = try readDirectory(allocator, snapshot_dir_iter);
        var filenames = files.filenames;
        defer {
            filenames.deinit();
            allocator.free(files.filename_memory);
        }

        // find the snapshots
        var maybe_latest_full_snapshot: ?FullSnapshotFileInfo = null;
        var count: usize = 0;
        for (filenames.items) |filename| {
            const snapshot = FullSnapshotFileInfo.fromString(filename) catch continue;
            if (count == 0 or snapshot.slot > maybe_latest_full_snapshot.?.slot) {
                maybe_latest_full_snapshot = snapshot;
            }
            count += 1;
        }
        var latest_full_snapshot = maybe_latest_full_snapshot orelse return error.NoFullSnapshotFileInfoFound;
        // clone the name so we can deinit the full array
        latest_full_snapshot.filename = try snapshot_dir_iter.dir.realpathAlloc(allocator, latest_full_snapshot.filename);

        count = 0;
        var maybe_latest_incremental_snapshot: ?IncrementalSnapshotFileInfo = null;
        for (filenames.items) |filename| {
            const snapshot = IncrementalSnapshotFileInfo.fromString(filename) catch continue;
            // need to match the base slot
            if (snapshot.base_slot == latest_full_snapshot.slot and (count == 0 or
                // this unwrap is safe because count > 0
                snapshot.slot > maybe_latest_incremental_snapshot.?.slot))
            {
                maybe_latest_incremental_snapshot = snapshot;
            }
            count += 1;
        }
        if (maybe_latest_incremental_snapshot) |*latest_incremental_snapshot| {
            latest_incremental_snapshot.filename = try snapshot_dir_iter.dir.realpathAlloc(allocator, latest_incremental_snapshot.filename);
        }

        return .{
            .full_snapshot = latest_full_snapshot,
            .incremental_snapshot = maybe_latest_incremental_snapshot,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        self.full_snapshot.deinit(allocator);
        if (self.incremental_snapshot) |*incremental_snapshot| {
            incremental_snapshot.deinit(allocator);
        }
    }
};

pub const SnapshotFieldsAndPaths = struct {
    all_fields: AllSnapshotFields,
    full_path: []const u8,
    incremental_path: ?[]const u8,

    pub fn deinit(self: *SnapshotFieldsAndPaths, allocator: std.mem.Allocator) void {
        self.all_fields.deinit(allocator);
        allocator.free(self.full_path);
        if (self.incremental_path) |incremental_path| {
            allocator.free(incremental_path);
        }
    }
};

/// contains all fields from a snapshot (full and incremental)
///
/// Analogous to [SnapshotBankFields](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L299)
pub const AllSnapshotFields = struct {
    full: SnapshotFields,
    incremental: ?SnapshotFields,
    was_collapsed: bool = false, // used for deinit()

    const Self = @This();

    pub fn fromFiles(
        allocator: std.mem.Allocator,
        snapshot_dir_str: []const u8,
        files: SnapshotFiles,
    ) !SnapshotFieldsAndPaths {
        // unpack
        const full_metadata_path = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}/{d}/{d}",
            .{ snapshot_dir_str, "snapshots", files.full_snapshot.slot, files.full_snapshot.slot },
        );

        const full_fields = try SnapshotFields.readFromFilePath(
            allocator,
            full_metadata_path,
        );

        var incremental_fields: ?SnapshotFields = null;
        var incremental_metadata_path: ?[]const u8 = null;
        if (files.incremental_snapshot) |incremental_snapshot_path| {
            incremental_metadata_path = try std.fmt.allocPrint(
                allocator,
                "{s}/{s}/{d}/{d}",
                .{ snapshot_dir_str, "snapshots", incremental_snapshot_path.slot, incremental_snapshot_path.slot },
            );

            incremental_fields = try SnapshotFields.readFromFilePath(
                allocator,
                incremental_metadata_path.?,
            );
        }

        const fields: Self = .{
            .full = full_fields,
            .incremental = incremental_fields,
        };

        return .{
            .all_fields = fields,
            .full_path = full_metadata_path,
            .incremental_path = incremental_metadata_path,
        };
    }

    /// collapse all full and incremental snapshots into one.
    /// note: this works by stack copying the full snapshot and combining
    /// the accounts-db account file map.
    /// this will 1) modify the incremental snapshot account map
    /// and 2) the returned snapshot heap fields will still point to the incremental snapshot
    /// (so be sure not to deinit it while still using the returned snapshot)
    pub fn collapse(self: *Self) !SnapshotFields {
        // nothing to collapse
        if (self.incremental == null)
            return self.full;
        self.was_collapsed = true;

        // collapse bank fields into the
        // incremental =pushed into=> full
        var snapshot = self.incremental.?; // stack copy
        const full_slot = self.full.bank_fields.slot;

        // collapse accounts-db fields
        var storages_map = &self.incremental.?.accounts_db_fields.file_map;
        // make sure theres no overlap in slots between full and incremental and combine
        var storages_entry_iter = storages_map.iterator();
        while (storages_entry_iter.next()) |*incremental_entry| {
            const slot = incremental_entry.key_ptr.*;

            // only keep slots > full snapshot slot
            if (!(slot > full_slot)) {
                incremental_entry.value_ptr.deinit();
                _ = storages_map.swapRemove(slot);
                continue;
            }

            const slot_entry = try self.full.accounts_db_fields.file_map.getOrPut(slot);
            if (slot_entry.found_existing) {
                std.debug.panic("invalid incremental snapshot: slot {d} is in both full and incremental snapshots\n", .{slot});
            } else {
                slot_entry.value_ptr.* = incremental_entry.value_ptr.*;
            }
        }
        snapshot.accounts_db_fields = self.full.accounts_db_fields;

        return snapshot;
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        if (!self.was_collapsed) {
            self.full.deinit(allocator);
            if (self.incremental) |inc| {
                inc.deinit(allocator);
            }
        } else {
            self.full.deinit(allocator);
            if (self.incremental) |*inc| {
                inc.accounts_db_fields.file_map.deinit();
                bincode.free(allocator, inc.bank_fields);
                bincode.free(allocator, inc.accounts_db_fields.rooted_slots);
                bincode.free(allocator, inc.accounts_db_fields.rooted_slot_hashes);
            }
        }
    }
};

const Logger = @import("../trace/log.zig").Logger;

/// unpacks a .tar.zstd file into the given directory
pub fn parallelUnpackZstdTarBall(
    allocator: std.mem.Allocator,
    logger: Logger,
    path: []const u8,
    output_dir: std.fs.Dir,
    n_threads: usize,
    full_snapshot: bool,
) !void {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const file_stat = try file.stat();
    const file_size: u64 = @intCast(file_stat.size);
    const memory = try std.posix.mmap(
        null,
        file_size,
        std.posix.PROT.READ,
        std.posix.MAP{ .TYPE = .SHARED },
        file.handle,
        0,
    );
    var tar_stream = try ZstdReader.init(memory);
    defer tar_stream.deinit();
    const n_files_estimate: usize = if (full_snapshot) 421_764 else 100_000; // estimate

    try parallelUntarToFileSystem(
        allocator,
        logger,
        output_dir,
        tar_stream.reader(),
        n_threads,
        n_files_estimate,
    );
}

test "core.accounts_db.snapshots: test full snapshot path parsing" {
    const full_snapshot_path = "snapshot-269-EAHHZCVccCdAoCXH8RWxvv9edcwjY2boqni9MJuh3TCn.tar.zst";
    const snapshot_info = try FullSnapshotFileInfo.fromString(full_snapshot_path);

    try std.testing.expect(snapshot_info.slot == 269);
    try std.testing.expect(std.mem.eql(u8, snapshot_info.hash, "EAHHZCVccCdAoCXH8RWxvv9edcwjY2boqni9MJuh3TCn"));
    try std.testing.expect(std.mem.eql(u8, snapshot_info.filename, full_snapshot_path));
}

test "core.accounts_db.snapshots: test incremental snapshot path parsing" {
    const path = "incremental-snapshot-269-307-4JLFzdaaqkSrmHs55bBDhZrQjHYZvqU1vCcQ5mP22pdB.tar.zst";
    const snapshot_info = try IncrementalSnapshotFileInfo.fromString(path);

    try std.testing.expect(snapshot_info.base_slot == 269);
    try std.testing.expect(snapshot_info.slot == 307);
    try std.testing.expect(std.mem.eql(u8, snapshot_info.hash, "4JLFzdaaqkSrmHs55bBDhZrQjHYZvqU1vCcQ5mP22pdB"));
    try std.testing.expect(std.mem.eql(u8, snapshot_info.filename, path));
}

test "core.accounts_db.snapshotss: parse status cache" {
    const allocator = std.testing.allocator;

    const status_cache_path = "test_data/status_cache";
    var status_cache = try StatusCache.initFromPath(allocator, status_cache_path);
    defer status_cache.deinit(allocator);

    try std.testing.expect(status_cache.bank_slot_deltas.len > 0);
}

test "core.accounts_db.snapshotss: parse snapshot fields" {
    const allocator = std.testing.allocator;
    const snapshot_path = "test_data/10";

    var snapshot_fields = try SnapshotFields.readFromFilePath(allocator, snapshot_path);
    defer snapshot_fields.deinit(allocator);
}

test "core.accounts_db.snapshotss: parse incremental snapshot fields" {
    const allocator = std.testing.allocator;
    const snapshot_path = "test_data/25";

    var snapshot_fields = try SnapshotFields.readFromFilePath(allocator, snapshot_path);
    defer snapshot_fields.deinit(allocator);

    try std.testing.expectEqual(snapshot_fields.lamports_per_signature, 5000);
    try std.testing.expectEqual(snapshot_fields.bank_fields_inc.snapshot_persistence.?.full_slot, 10);
}
