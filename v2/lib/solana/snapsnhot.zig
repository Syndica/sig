const std = @import("std");
const bincode = @import("bincode.zig");

// ── Primitive aliases ──────────────────────────────────────────────────────────

pub const Slot = u64;
pub const Epoch = u64;
pub const Hash = [32]u8;
pub const Pubkey = [32]u8;

// ── Status Cache types ─────────────────────────────────────────────────────────

pub const KeySlice = [20]u8;

pub const InstructionError = union(Tag) {
    pub const Tag = enum(u32) {
        GenericError,
        InvalidArgument,
        InvalidInstructionData,
        InvalidAccountData,
        AccountDataTooSmall,
        InsufficientFunds,
        IncorrectProgramId,
        MissingRequiredSignature,
        AccountAlreadyInitialized,
        UninitializedAccount,
        UnbalancedInstruction,
        ModifiedProgramId,
        ExternalAccountLamportSpend,
        ExternalAccountDataModified,
        ReadonlyLamportChange,
        ReadonlyDataModified,
        DuplicateAccountIndex,
        ExecutableModified,
        RentEpochModified,
        NotEnoughAccountKeys,
        AccountDataSizeChanged,
        AccountNotExecutable,
        AccountBorrowFailed,
        AccountBorrowOutstanding,
        DuplicateAccountOutOfSync,
        Custom,
        InvalidError,
        ExecutableDataModified,
        ExecutableLamportChange,
        ExecutableAccountNotRentExempt,
        UnsupportedProgramId,
        CallDepth,
        MissingAccount,
        ReentrancyNotAllowed,
        MaxSeedLengthExceeded,
        InvalidSeeds,
        InvalidRealloc,
        ComputationalBudgetExceeded,
        PrivilegeEscalation,
        ProgramEnvironmentSetupFailure,
        ProgramFailedToComplete,
        ProgramFailedToCompile,
        Immutable,
        IncorrectAuthority,
        BorshIoError,
        AccountNotRentExempt,
        InvalidAccountOwner,
        ArithmeticOverflow,
        UnsupportedSysvar,
        IllegalOwner,
        MaxAccountsDataAllocationsExceeded,
        MaxAccountsExceeded,
        MaxInstructionTraceLengthExceeded,
        BuiltinProgramsMustConsumeComputeUnits,
    };

    GenericError: void,
    InvalidArgument: void,
    InvalidInstructionData: void,
    InvalidAccountData: void,
    AccountDataTooSmall: void,
    InsufficientFunds: void,
    IncorrectProgramId: void,
    MissingRequiredSignature: void,
    AccountAlreadyInitialized: void,
    UninitializedAccount: void,
    UnbalancedInstruction: void,
    ModifiedProgramId: void,
    ExternalAccountLamportSpend: void,
    ExternalAccountDataModified: void,
    ReadonlyLamportChange: void,
    ReadonlyDataModified: void,
    DuplicateAccountIndex: void,
    ExecutableModified: void,
    RentEpochModified: void,
    NotEnoughAccountKeys: void,
    AccountDataSizeChanged: void,
    AccountNotExecutable: void,
    AccountBorrowFailed: void,
    AccountBorrowOutstanding: void,
    DuplicateAccountOutOfSync: void,
    Custom: u32,
    InvalidError: void,
    ExecutableDataModified: void,
    ExecutableLamportChange: void,
    ExecutableAccountNotRentExempt: void,
    UnsupportedProgramId: void,
    CallDepth: void,
    MissingAccount: void,
    ReentrancyNotAllowed: void,
    MaxSeedLengthExceeded: void,
    InvalidSeeds: void,
    InvalidRealloc: void,
    ComputationalBudgetExceeded: void,
    PrivilegeEscalation: void,
    ProgramEnvironmentSetupFailure: void,
    ProgramFailedToComplete: void,
    ProgramFailedToCompile: void,
    Immutable: void,
    IncorrectAuthority: void,
    BorshIoError: bincode.Vec(u8), // String in Rust = Vec<u8> in bincode
    AccountNotRentExempt: void,
    InvalidAccountOwner: void,
    ArithmeticOverflow: void,
    UnsupportedSysvar: void,
    IllegalOwner: void,
    MaxAccountsDataAllocationsExceeded: void,
    MaxAccountsExceeded: void,
    MaxInstructionTraceLengthExceeded: void,
    BuiltinProgramsMustConsumeComputeUnits: void,
};

pub const TransactionError = union(Tag) {
    pub const Tag = enum(u32) {
        AccountInUse,
        AccountLoadedTwice,
        AccountNotFound,
        ProgramAccountNotFound,
        InsufficientFundsForFee,
        InvalidAccountForFee,
        AlreadyProcessed,
        BlockhashNotFound,
        InstructionError,
        CallChainTooDeep,
        MissingSignatureForFee,
        InvalidAccountIndex,
        SignatureFailure,
        InvalidProgramForExecution,
        SanitizeFailure,
        ClusterMaintenance,
        AccountBorrowOutstanding,
        WouldExceedMaxBlockCostLimit,
        UnsupportedVersion,
        InvalidWritableAccount,
        WouldExceedMaxAccountCostLimit,
        WouldExceedAccountDataBlockLimit,
        TooManyAccountLocks,
        AddressLookupTableNotFound,
        InvalidAddressLookupTableOwner,
        InvalidAddressLookupTableData,
        InvalidAddressLookupTableIndex,
        InvalidRentPayingAccount,
        WouldExceedMaxVoteCostLimit,
        WouldExceedAccountDataTotalLimit,
        DuplicateInstruction,
        InsufficientFundsForRent,
        MaxLoadedAccountsDataSizeExceeded,
        InvalidLoadedAccountsDataSizeLimit,
        ResanitizationNeeded,
        ProgramExecutionTemporarilyRestricted,
        UnbalancedTransaction,
        ProgramCacheHitMaxLimit,
        CommitCancelled,
    };

    AccountInUse: void,
    AccountLoadedTwice: void,
    AccountNotFound: void,
    ProgramAccountNotFound: void,
    InsufficientFundsForFee: void,
    InvalidAccountForFee: void,
    AlreadyProcessed: void,
    BlockhashNotFound: void,
    InstructionError: struct { index: u8, err: InstructionError },
    CallChainTooDeep: void,
    MissingSignatureForFee: void,
    InvalidAccountIndex: void,
    SignatureFailure: void,
    InvalidProgramForExecution: void,
    SanitizeFailure: void,
    ClusterMaintenance: void,
    AccountBorrowOutstanding: void,
    WouldExceedMaxBlockCostLimit: void,
    UnsupportedVersion: void,
    InvalidWritableAccount: void,
    WouldExceedMaxAccountCostLimit: void,
    WouldExceedAccountDataBlockLimit: void,
    TooManyAccountLocks: void,
    AddressLookupTableNotFound: void,
    InvalidAddressLookupTableOwner: void,
    InvalidAddressLookupTableData: void,
    InvalidAddressLookupTableIndex: void,
    InvalidRentPayingAccount: void,
    WouldExceedMaxVoteCostLimit: void,
    WouldExceedAccountDataTotalLimit: void,
    DuplicateInstruction: u8,
    InsufficientFundsForRent: u8, // account_index
    MaxLoadedAccountsDataSizeExceeded: void,
    InvalidLoadedAccountsDataSizeLimit: void,
    ResanitizationNeeded: void,
    ProgramExecutionTemporarilyRestricted: u8, // account_index
    UnbalancedTransaction: void,
    ProgramCacheHitMaxLimit: void,
    CommitCancelled: void,
};

/// Bincode serializes `Result<(), E>` as: u32 tag (0=Ok, 1=Err), then E if Err.
pub const TxResult = union(enum(u32)) {
    Ok: void,
    Err: TransactionError,
};

/// (KeySlice, Result<(), SerdeTransactionError>)
pub const StatusEntry = struct {
    key_slice: KeySlice,
    result: TxResult,
};

/// (usize, Vec<(KeySlice, Result<(), SerdeTransactionError>)>)
/// usize is serialized as u64 with fixint encoding.
pub const StatusMapValue = struct {
    fork_count: u64,
    entries: bincode.Vec(StatusEntry),
};

/// HashMap<Hash, (usize, Vec<(KeySlice, T)>)>
pub const StatusMap = HashMap(Hash, StatusMapValue);

/// Bincode bool: 1 byte, 0 = false, 1 = true.
pub const Bool = extern struct {
    value: u8,

    pub fn bincodeRead(_: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !Bool {
        return .{ .value = switch (try reader.takeByte()) {
            0 => 0,
            1 => 1,
            else => return error.InvalidBool,
        } };
    }

    pub fn bincodeWrite(self: *const Bool, writer: *std.Io.Writer) !void {
        try writer.writeByte(self.value);
    }
};

/// (Slot, bool, SerdeStatus)
pub const SlotDelta = struct {
    slot: Slot,
    is_root: Bool,
    status: StatusMap,
};

/// Vec<SerdeBankSlotDelta>
pub const StatusCache = bincode.Vec(SlotDelta);

// ── Bank fields types ──────────────────────────────────────────────────────────

pub const FeeCalculator = struct {
    lamports_per_signature: u64,
};

pub const HashInfo = struct {
    fee_calculator: FeeCalculator,
    hash_index: u64,
    timestamp: u64,
};

/// BlockhashQueue: HashMap<Hash, HashInfo> with extra fields.
/// Serialized as: last_hash_index(u64), last_hash(Option<Hash>),
///                hashes(HashMap<Hash, HashInfo>), max_age(u64)
pub const BlockhashQueue = struct {
    last_hash_index: u64,
    last_hash: ?Hash,
    hashes: HashMap(Hash, HashInfo),
    max_age: u64,
};

/// HardForks: Vec<(Slot, usize)>
/// usize serialized as u64 with fixint encoding
pub const HardForks = struct {
    hard_forks: bincode.Vec(HardFork),

    pub const HardFork = struct {
        slot: Slot,
        count: u64, // usize
    };
};

/// FeeRateGovernor with lamports_per_signature skipped (serde(skip))
pub const FeeRateGovernor = struct {
    target_lamports_per_signature: u64,
    target_signatures_per_slot: u64,
    min_lamports_per_signature: u64,
    max_lamports_per_signature: u64,
    burn_percent: u8,
};

pub const EpochSchedule = struct {
    slots_per_epoch: u64,
    leader_schedule_slot_offset: u64,
    warmup: Bool,
    first_normal_epoch: u64,
    first_normal_slot: u64,
};

pub const Inflation = struct {
    initial: f64,
    terminal: f64,
    taper: f64,
    foundation: f64,
    foundation_term: f64,
    __unused: f64,
};

pub const Rent = struct {
    lamports_per_byte: u64,
    exemption_threshold: [8]u8, // f64 as raw bytes
    burn_percent: u8,
};

pub const UnusedRentCollector = struct {
    epoch: Epoch,
    epoch_schedule: EpochSchedule,
    slots_per_year: f64,
    rent: Rent,
};

pub const UnusedAccounts = struct {
    unused1: HashSet(Pubkey),
    unused2: HashSet(Pubkey),
    unused3: HashMap(Pubkey, u64),
};

/// Account as serialized by bincode (serde_bytes for data).
pub const AccountSharedData = struct {
    lamports: u64,
    data: bincode.Vec(u8),
    owner: Pubkey,
    executable: Bool,
    rent_epoch: Epoch,
};

/// VoteAccounts: serialized as HashMap<Pubkey, (u64, AccountSharedData)>.
/// The staked_nodes field is serde(skip).
pub const VoteAccounts = HashMap(Pubkey, VoteAccountEntry);
pub const VoteAccountEntry = struct {
    stake: u64,
    account: AccountSharedData,
};

pub const StakeHistoryEntry = struct {
    effective: u64,
    activating: u64,
    deactivating: u64,
};

/// StakeHistory: Vec<(Epoch, StakeHistoryEntry)>, wrapped in Arc (transparent to serde).
pub const StakeHistory = bincode.Vec(StakeHistoryPair);
pub const StakeHistoryPair = struct {
    epoch: Epoch,
    entry: StakeHistoryEntry,
};

pub const Delegation = struct {
    voter_pubkey: Pubkey,
    stake: u64,
    activation_epoch: Epoch,
    deactivation_epoch: Epoch,
    warmup_cooldown_rate: f64,
};

/// DeserializableStakes<Delegation>: identical bincode layout to Stakes<Delegation>.
pub const Stakes = struct {
    vote_accounts: VoteAccounts,
    stake_delegations: bincode.Vec(StakeDelegationEntry),
    unused: u64,
    epoch: Epoch,
    stake_history: StakeHistory,

    pub const StakeDelegationEntry = struct {
        pubkey: Pubkey,
        delegation: Delegation,
    };
};

// ── AccountsDbFields types ─────────────────────────────────────────────────────

pub const BankHashStats = struct {
    num_updated_accounts: u64,
    num_removed_accounts: u64,
    num_lamports_stored: u64,
    total_data_len: u64,
    num_executable_accounts: u64,
};

pub const BankHashInfo = struct {
    unused_accounts_delta_hash: [32]u8,
    unused_accounts_hash: [32]u8,
    stats: BankHashStats,
};

pub const SerializableAccountStorageEntry = struct {
    id: u64, // usize
    accounts_current_len: u64, // usize
};

pub const StorageEntry = struct {
    slot: Slot,
    /// SmallVec<[T; 1]> serializes identically to Vec<T> in bincode.
    entries: bincode.Vec(SerializableAccountStorageEntry),
};

pub const RootedSlotHash = struct {
    slot: Slot,
    hash: Hash,
};

/// AccountsDbFields is a tuple struct. Fields 4 and 5 use default_on_eof.
pub const AccountsDbFields = struct {
    storage: bincode.Vec(StorageEntry),
    _unused_write_version: u64,
    slot: Slot,
    bank_hash_info: BankHashInfo,
    /// All slots that were roots within the last epoch (default_on_eof).
    rooted_slots: bincode.Vec(Slot),
    /// Slots that were roots within the last epoch for which we care about the hash value (default_on_eof).
    rooted_slot_hashes: bincode.Vec(RootedSlotHash),

    pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !AccountsDbFields {
        return .{
            .storage = try bincode.read(fba, reader, bincode.Vec(StorageEntry)),
            ._unused_write_version = try bincode.read(fba, reader, u64),
            .slot = try bincode.read(fba, reader, Slot),
            .bank_hash_info = try bincode.read(fba, reader, BankHashInfo),
            // Fields 4 and 5 use default_on_eof in Rust
            .rooted_slots = defaultOnEof(fba, reader, bincode.Vec(Slot)) orelse .{ .items = &.{} },
            .rooted_slot_hashes = defaultOnEof(fba, reader, bincode.Vec(RootedSlotHash)) orelse .{ .items = &.{} },
        };
    }
};

// ── ExtraFieldsToDeserialize types ─────────────────────────────────────────────

pub const UnusedIncrementalSnapshotPersistence = struct {
    full_slot: u64,
    full_hash: [32]u8,
    full_capitalization: u64,
    incremental_hash: [32]u8,
    incremental_capitalization: u64,
};

pub const Stake = struct {
    delegation: Delegation,
    credits_observed: u64,
};

pub const NodeVoteAccounts = struct {
    vote_accounts: bincode.Vec(Pubkey),
    total_stake: u64,
};

pub const NodeIdToVoteAccounts = HashMap(Pubkey, NodeVoteAccounts);
pub const EpochAuthorizedVoters = HashMap(Pubkey, Pubkey);

/// DeserializableStakes<Stake> (used inside VersionedEpochStakes)
pub const EpochStakes = struct {
    vote_accounts: VoteAccounts,
    stake_delegations: bincode.Vec(StakeDelegationWithStake),
    unused: u64,
    epoch: Epoch,
    stake_history: StakeHistory,

    pub const StakeDelegationWithStake = struct {
        pubkey: Pubkey,
        stake: Stake,
    };
};

/// DeserializableVersionedEpochStakes: enum with one variant (Current = 0).
pub const VersionedEpochStakes = struct {
    stakes: EpochStakes,
    total_stake: u64,
    node_id_to_vote_accounts: NodeIdToVoteAccounts,
    epoch_authorized_voters: EpochAuthorizedVoters,

    pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !VersionedEpochStakes {
        const variant = try bincode.read(fba, reader, u32);
        if (variant != 0) return error.InvalidEpochStakesVariant; // only "Current" variant
        return .{
            .stakes = try bincode.read(fba, reader, EpochStakes),
            .total_stake = try bincode.read(fba, reader, u64),
            .node_id_to_vote_accounts = try bincode.read(fba, reader, NodeIdToVoteAccounts),
            .epoch_authorized_voters = try bincode.read(fba, reader, EpochAuthorizedVoters),
        };
    }
};

pub const LT_HASH_NUM_ELEMENTS = 1024;

/// SerdeAccountsLtHash: [u16; 1024]
/// Serialized via serde_as as a fixed-size array (each element individually).
pub const SerdeAccountsLtHash = [LT_HASH_NUM_ELEMENTS]u16;

pub const EpochStakesPair = struct {
    epoch: u64,
    versioned_epoch_stakes: VersionedEpochStakes,
};

/// ExtraFieldsToDeserialize: every field uses default_on_eof.
pub const ExtraFields = struct {
    lamports_per_signature: u64,
    _unused_incremental_snapshot_persistence: ?UnusedIncrementalSnapshotPersistence,
    _unused_epoch_accounts_hash: ?Hash,
    versioned_epoch_stakes: bincode.Vec(EpochStakesPair),
    accounts_lt_hash: ?SerdeAccountsLtHash,
    block_id: ?Hash,

    pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !ExtraFields {
        return .{
            .lamports_per_signature = defaultOnEof(fba, reader, u64) orelse 0,
            ._unused_incremental_snapshot_persistence = defaultOnEof(fba, reader, ?UnusedIncrementalSnapshotPersistence) orelse null,
            ._unused_epoch_accounts_hash = defaultOnEof(fba, reader, ?Hash) orelse null,
            .versioned_epoch_stakes = defaultOnEof(fba, reader, bincode.Vec(EpochStakesPair)) orelse .{ .items = &.{} },
            .accounts_lt_hash = defaultOnEof(fba, reader, ?SerdeAccountsLtHash) orelse null,
            .block_id = defaultOnEof(fba, reader, ?Hash) orelse null,
        };
    }
};

// ── Top-level deserialized snapshot structures ─────────────────────────────────

pub const DeserializableVersionedBank = struct {
    blockhash_queue: BlockhashQueue,
    _unused_ancestors: HashMap(Slot, u64), // HashMap<Slot, usize>
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
    genesis_creation_time: i64, // UnixTimestamp = i64
    slots_per_year: f64,
    accounts_data_len: u64,
    slot: Slot,
    _unused_epoch: Epoch,
    block_height: u64,
    leader_id: Pubkey,
    _unused_collector_fees: u64,
    _unused_fee_calculator: u64,
    fee_rate_governor: FeeRateGovernor,
    _unused_collected_rent: u64,
    _unused_rent_collector: UnusedRentCollector,
    epoch_schedule: EpochSchedule,
    inflation: Inflation,
    stakes: Stakes,
    _unused_accounts: UnusedAccounts,
    unused_epoch_stakes: HashMap(Epoch, void),
    is_delta: Bool,
};

pub const BankFields = struct {
    bank: DeserializableVersionedBank,
    accounts_db: AccountsDbFields,
    extra: ExtraFields,
};

// ── HashMap / HashSet helpers ──────────────────────────────────────────────────

/// Bincode-compatible HashMap<K, V>: u64 length prefix, then (K, V) pairs.
pub fn HashMap(comptime K: type, comptime V: type) type {
    if (V == void) return HashSet(K);
    return struct {
        items: []const Entry,

        const Self = @This();
        pub const Entry = struct { key: K, value: V };

        pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !Self {
            const n = try reader.takeInt(u64, .little);
            const slice = try fba.allocator().alloc(Entry, n);
            for (slice) |*v| v.* = try bincode.read(fba, reader, Entry);
            return .{ .items = slice };
        }

        pub fn bincodeWrite(self: *const Self, writer: *std.Io.Writer) !void {
            try writer.writeInt(u64, self.items.len, .little);
            for (self.items) |v| try bincode.write(writer, v);
        }
    };
}

/// Bincode-compatible HashSet<T>: u64 length prefix, then T elements.
pub fn HashSet(comptime T: type) type {
    return struct {
        items: []const T,

        const Self = @This();

        pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !Self {
            const n = try reader.takeInt(u64, .little);
            const slice = try fba.allocator().alloc(T, n);
            if (@typeInfo(T) == .int) {
                try reader.readSliceAll(std.mem.sliceAsBytes(slice));
            } else {
                for (slice) |*v| v.* = try bincode.read(fba, reader, T);
            }
            return .{ .items = slice };
        }

        pub fn bincodeWrite(self: *const Self, writer: *std.Io.Writer) !void {
            try writer.writeInt(u64, self.items.len, .little);
            if (@typeInfo(T) == .int) {
                try writer.writeAll(std.mem.sliceAsBytes(self.items));
            } else {
                for (self.items) |v| try bincode.write(writer, v);
            }
        }
    };
}

// ── default_on_eof helper ──────────────────────────────────────────────────────

/// Reads a value of type T from the reader; returns null on EOF instead of error.
/// Mirrors Rust's `#[serde(deserialize_with = "default_on_eof")]`.
fn defaultOnEof(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader, comptime T: type) ?T {
    return bincode.read(fba, reader, T) catch return null;
}

// ── Top-level deserialization functions ─────────────────────────────────────────

/// Deserialize the bank fields file (`snapshots/<slot>/<slot>`) from a snapshot.
///
/// The file contains three bincode-encoded sections back-to-back:
/// 1. DeserializableVersionedBank
/// 2. AccountsDbFields<SerializableAccountStorageEntry>
/// 3. ExtraFieldsToDeserialize (each field default_on_eof)
///
/// All sections use bincode with fixint encoding (u64 length prefixes).
pub fn deserializeBankFields(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !BankFields {
    return .{
        .bank = try bincode.read(fba, reader, DeserializableVersionedBank),
        .accounts_db = try bincode.read(fba, reader, AccountsDbFields),
        .extra = try bincode.read(fba, reader, ExtraFields),
    };
}

/// Deserialize the status cache file (`snapshots/status_cache`) from a snapshot.
///
/// The file contains a single bincode-encoded value:
///   Vec<(Slot, bool, HashMap<Hash, (usize, Vec<(KeySlice, Result<(), SerdeTransactionError>)>)>)>
///
/// Uses bincode with fixint encoding (u64 length prefixes).
pub fn deserializeStatusCache(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !StatusCache {
    return bincode.read(fba, reader, StatusCache);
}
