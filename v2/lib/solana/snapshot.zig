const std = @import("std");
const lib = @import("../lib.zig");

const bincode = lib.solana.bincode;
const Slot = lib.solana.Slot;
const Hash = lib.solana.Hash;
const SlotAndHash = lib.solana.SlotAndHash;
const Epoch = lib.solana.Epoch;
const Pubkey = lib.solana.Pubkey;
const LtHash = lib.solana.LtHash;

fn HashSet(comptime T: type) type {
    return bincode.Vec(T);
}

fn HashMap(comptime K: type, comptime V: type) type {
    return bincode.Vec(struct { key: K, value: V });
}

/// The "snapshots/status_cache" file in the snapshot tar
pub const StatusCache = struct {
    slot_deltas: bincode.Vec(struct {
        slot: Slot,
        is_root: bool,
        status_map: StatusMap,
    }),
};
pub const StatusMap = HashMap(Hash, struct {
    fork_count: u64,
    entries: bincode.Vec(struct {
        key_slice: KeySlice,
        result: union(enum(u32)) {
            ok,
            err: TransactionError,
        },
    }),
});
pub const KeySlice = [20]u8;

pub const TransactionError = union(enum(u32)) {
    AccountInUse,
    AccountLoadedTwice,
    AccountNotFound,
    ProgramAccountNotFound,
    InsufficientFundsForFee,
    InvalidAccountForFee,
    AlreadyProcessed,
    BlockhashNotFound,
    InstructionError: struct { index: u8, err: InstructionError },
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
    DuplicateInstruction: u8,
    InsufficientFundsForRent: u8, // account_index
    MaxLoadedAccountsDataSizeExceeded,
    InvalidLoadedAccountsDataSizeLimit,
    ResanitizationNeeded,
    ProgramExecutionTemporarilyRestricted: u8, // account_index
    UnbalancedTransaction,
    ProgramCacheHitMaxLimit,
    CommitCancelled,
};

pub const InstructionError = union(enum(u32)) {
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
    Custom: u32,
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
    BorshIoError: bincode.Vec(u8), // String in Rust = Vec<u8> in bincode
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

/// The "snapshots/{slot}/{slot}" file in the snapshot tar
pub const Manifest = struct {
    bank_fields: BankFields,
    accounts_db_fields: AccountsDbFields,
    extra_fields: ExtraFields,
};

pub const BankFields = struct { // DeserializableVersionedBank
    blockhash_queue: struct {
        last_hash_index: u64,
        last_hash: ?Hash,
        hash_infos: HashMap(Hash, struct {
            fee_calculator: struct { lamports_per_signature: u64 },
            hash_index: u64,
            timestamp: u64,
        }),
        max_age: u64,
    },
    _unused_ancestors: HashMap(Slot, u64),
    hash: Hash,
    parent_hash: Hash,
    parent_slot: Slot,
    hard_forks: bincode.Vec(struct {
        slot: Slot,
        count: u64,
    }),
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
    fee_rate_governor: struct {
        target_lamports_per_signature: u64,
        target_signatures_per_slot: u64,
        min_lamports_per_signature: u64,
        max_lamports_per_signature: u64,
        burn_percent: u8,
    },
    _unused_collected_rent: u64,
    _unused_rent_collector: struct {
        epoch: Epoch,
        epoch_schedule: EpochSchedule,
        slots_per_year: f64,
        rent: struct {
            lamports_per_byte: u64,
            exemption_threshold: [8]u8, // f64 as raw bytes
            burn_percent: u8,
        },
    },
    epoch_schedule: EpochSchedule,
    inflation: struct {
        initial: f64,
        terminal: f64,
        taper: f64,
        foundation: f64,
        foundation_term: f64,
        __unused: f64,
    },
    stakes: Stakes(Delegation),
    _unused_accounts: struct {
        unused1: HashSet(Pubkey),
        unused2: HashSet(Pubkey),
        unused3: HashMap(Pubkey, u64),
    },
    _unused_epoch_stakes: HashSet(Epoch),
    is_delta: bool,
};

pub const EpochSchedule = struct {
    slots_per_epoch: u64,
    leader_schedule_slot_offset: u64,
    warmup: bool,
    first_normal_epoch: u64,
    first_normal_slot: u64,
};

// DeserializableStakes<T>
pub fn Stakes(comptime StakeDelegation: type) type {
    return struct {
        vote_accounts: VoteAccounts,
        stake_delegations: HashMap(Pubkey, StakeDelegation),
        unused: u64,
        epoch: Epoch,
        stake_history: StakeHistory,
    };
}

pub const StakeHistory = bincode.Vec(struct {
    epoch: Epoch,
    effective: u64,
    activating: u64,
    deactivating: u64,
});

pub const VoteAccounts = HashMap(Pubkey, struct {
    stake: u64,
    account: AccountSharedData,
});

pub const AccountSharedData = struct {
    lamports: u64,
    data: bincode.Vec(u8),
    owner: Pubkey,
    executable: bool,
    rent_epoch: Epoch,
};

pub const Delegation = struct {
    voter_pubkey: Pubkey,
    stake: u64,
    activation_epoch: Epoch,
    deactivation_epoch: Epoch,
    warmup_cooldown_rate: f64,
};

pub const AccountsDbFields = struct {
    account_file_map: AccountFileMap,
    _unused_write_version: u64,
    slot: Slot,
    bank_hash_info: struct { // BankHashInfo
        _unused_accounts_delta_hash: Hash,
        _unused_accounts_hash: Hash,
        stats: struct { // BankHashStats
            num_updated_accounts: u64,
            num_removed_accounts: u64,
            num_lamports_stored: u64,
            total_data_len: u64,
            num_executable_accounts: u64,
        },
    },
    /// All slots that were roots within the last epoch
    rooted_slots: bincode.NullOnEof(bincode.Vec(Slot)),
    /// Slots that were roots within the last epoch for which we care about the hash value
    rooted_slot_hashes: bincode.NullOnEof(bincode.Vec(SlotAndHash)),
};

// HashMap(Slot, struct { // Vec<StorageEntry>
//     entries: bincode.Vec(struct { // SmallVec<[SerializableAccountStorageEntry; 1]>
//         id: u64, // usize
//         length: u64, // usize
//     }),
// })
pub const AccountFileMap = struct {
    entries: []const Entry,
    count: u64,

    const Self = @This();
    pub const Entry = extern struct {
        slot: u32, // slots should be small enough for this to be the case
        length: u32, // a single account file length should not be able to go over 4GB
        id: u64,
    };

    const HASH_MULT = 0x9E3779B97F4A7C15;
    const StorageEntry = struct {
        slot: Slot,
        small_vec_size: u64,
        id: u64,
        length: u64,
    };

    pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !Self {
        const n = try reader.takeInt(u64, .little);
        if (n == 0) return .{ .entries = &.{}, .count = 0 };

        // bump up to load factor (4/5 = 80%)
        const cap = std.math.ceilPowerOfTwo(u64, (n * 5) / 4) catch return error.OutOfMemory;
        const entries: []Entry = try fba.allocator().alloc(Entry, cap);
        @memset(std.mem.sliceAsBytes(entries), 0xff); // make all Entry.slot = maxInt(u32)

        var storage_entry: StorageEntry = undefined;
        for (0..n) |_| {
            try reader.readSliceAll(std.mem.asBytes(&storage_entry));
            if (storage_entry.small_vec_size != 1) return error.InvalidStorageEntry;
            if (storage_entry.slot >= std.math.maxInt(u32)) return error.InvalidSlot;
            if (storage_entry.length > std.math.maxInt(u32)) return error.InvalidAccountFileLength;

            // Find insert to insert at.
            var idx = (storage_entry.slot *% HASH_MULT) >> @intCast(@as(u7, 64) - @ctz(cap));
            while (entries[idx].slot != std.math.maxInt(u32)) {
                idx = (idx +% 1) & (cap - 1);
            }

            entries[idx] = .{
                .slot = @intCast(storage_entry.slot),
                .length = @intCast(storage_entry.length),
                .id = storage_entry.id,
            };
        }

        return .{ .entries = entries, .count = n };
    }

    pub fn getPtr(self: *const Self, slot: Slot) ?*const Entry {
        if (slot >= std.math.maxInt(u32)) return null;

        var idx = (slot *% HASH_MULT) >> @intCast(@as(u7, 64) - @ctz(self.entries.len));
        while (true) {
            const e = &self.entries[idx];
            idx = (idx +% 1) & (self.entries.len - 1);
            if (@as(u64, e.slot) == slot) return e;
            if (e.slot == std.math.maxInt(u32)) return null;
        }
    }

    pub fn bincodeWrite(self: *const Self, writer: *std.Io.Writer) !void {
        try writer.writeInt(u64, self.count, .little);
        for (self.entries) |*e| {
            if (e.slot == std.math.maxInt(u32)) continue;
            try writer.writeAll(std.mem.asBytes(&StorageEntry{
                .slot = e.slot,
                .small_vec_size = 1,
                .id = e.id,
                .length = e.len,
            }));
        }
    }
};

pub const ExtraFields = struct {
    lamports_per_signature: bincode.NullOnEof(u64),
    _unused_incremental_snapshot_persistence: bincode.NullOnEof(?struct {
        full: SlotAndHash,
        full_capitalization: u64,
        incremental_hash: Hash,
        incremental_capitalization: u64,
    }),
    _unused_epoch_accounts_hash: bincode.NullOnEof(?Hash),
    versioned_epoch_stakes: bincode.NullOnEof(bincode.Vec(struct { // EpochStakesPair
        epoch: u64,
        value: union(enum(u32)) { // DeserializableVersionedEpochStakes with one variant
            current: struct {
                epoch_stakes: Stakes(struct { // StakeDelegationWithStake
                    delegation: Delegation,
                    credits_observed: u64,
                }),
                total_stake: u64,
                node_id_to_vote_accounts: HashMap(Pubkey, struct {
                    vote_accounts: bincode.Vec(Pubkey),
                    total_stake: u64,
                }),
                epoch_authorized_voters: HashMap(Pubkey, Pubkey),
            },
        },
    })),
    accounts_lt_hash: bincode.NullOnEof(?LtHash),
    block_id: bincode.NullOnEof(Hash),
};
