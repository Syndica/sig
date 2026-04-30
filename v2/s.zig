const std = @import("std");
const lib = @import("../lib.zig");

pub const bincode = struct {
    pub fn read(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader, comptime T: type) !T {
        switch (@typeInfo(T)) {
            inline .int, .float, .array => |info| {
                if (@typeInfo(T) == .array)
                    comptime std.debug.assert(@typeInfo(info.child) == .int);
                var val: T = undefined;
                try reader.readSliceAll(std.mem.asBytes(&val));
                return val;
            },
            .bool => {
                const b = try read(fba, reader, u8);
                if (b > 1) return error.InvalidBool;
                return b > 0;
            },
            .optional => |info| {
                const is_some = try read(fba, reader, bool);
                return if (is_some) try read(fba, reader, info.child) else null;
            },
            .@"enum" => |info| {
                const tag = try read(fba, reader, info.tag_type);
                return try std.meta.intToEnum(T, tag);
            },
            .@"union" => |info| switch (try read(fba, reader, info.tag_type.?)) {
                inline else => |tag| {
                    const Variant = @FieldType(T, @tagName(tag));
                    return @unionInit(T, @tagName(tag), try read(fba, reader, Variant));
                },
            },
            .@"struct" => |info| {
                if (@hasDecl(T, "bincodeRead")) return @field(T, "bincodeRead")(fba, reader);
                var value: T = undefined;
                inline for (info.fields) |f| @field(value, f.name) = try read(fba, reader, f.type);
                return value;
            },
            .void => return {},
            else => @compileError("unsupported type: " ++ @typeName(T)),
        }
    }

    pub fn VarInt(comptime T: type) type {
        return struct {
            value: T,
            pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !@This() {
                var value: T = 0;
                var i: std.math.Log2Int(T) = 0;
                while (true) {
                    const b = try read(fba, reader, u8);
                    value |= @as(T, b & 0x7f) << i;
                    i += 7;
                    if (b & 0x80 == 0) return .{ .value = value };
                }
            }
        };
    }
    pub fn Vec(comptime T: type) type {
        return struct {
            items: []const T,
            pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !@This() {
                const n = try read(fba, reader, u64);
                const slice = try fba.allocator().alloc(T, n);
                for (slice) |*v| v.* = try read(fba, reader, T);
                return .{ .items = slice };
            }
        };
    }
    pub fn NullOnEof(comptime T: type) type {
        return struct {
            value: ?T,
            pub fn bincodeRead(fba: *std.heap.FixedBufferAllocator, reader: *std.Io.Reader) !@This() {
                return .{ .value = read(fba, reader, T) catch |err| switch (err) {
                    error.EndOfStream => null,
                    else => |e| return e,
                } };
            }
        };
    }
};

const Slot = lib.solana.Slot;
const Hash = lib.solana.Hash;
const SlotAndHash = struct { slot: Slot, hash: Hash };
const Epoch = lib.solana.Epoch;
const Pubkey = lib.solana.Pubkey;
const LtHash = [1024]u16;

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
        const n = try bincode.read(fba, reader, u64);
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

// --- Discard functions: skip over serialized fields without allocating ---

fn readLen(r: *std.Io.Reader) !u64 {
    var buf: [8]u8 = undefined;
    try r.readSliceAll(&buf);
    return std.mem.readInt(u64, &buf, .little);
}

fn readBool(r: *std.Io.Reader) !bool {
    var buf: [1]u8 = undefined;
    try r.readSliceAll(&buf);
    if (buf[0] > 1) return error.InvalidBool;
    return buf[0] > 0;
}

/// Discards VoteAccounts: HashMap(Pubkey, { stake: u64, account: AccountSharedData })
/// AccountSharedData contains a variable-length Vec(u8) data field, so we must loop.
fn discardVoteAccounts(r: *std.Io.Reader) !void {
    const len = try readLen(r);
    for (0..len) |_| {
        try r.discardAll(
            32 + // key: Pubkey
                8 + // value.stake: u64
                8, // value.account.lamports: u64
        );
        // value.account.data: Vec(u8)
        const data_len = try readLen(r);
        try r.discardAll(
            data_len + // account data bytes
                32 + // value.account.owner: Pubkey
                1 + // value.account.executable: bool
                8, // value.account.rent_epoch: Epoch(u64)
        );
    }
}

pub fn discardBankFields(r: *std.Io.Reader) !void {
    // blockhash_queue.last_hash_index: u64
    try r.discardAll(8);
    // blockhash_queue.last_hash: ?Hash
    if (try readBool(r)) try r.discardAll(32);
    // blockhash_queue.hash_infos: HashMap(Hash, { lamports_per_signature: u64, hash_index: u64, timestamp: u64 })
    const hash_infos_len = try readLen(r);
    try r.discardAll(hash_infos_len * (32 + // key: Hash
        8 + // lamports_per_signature: u64
        8 + // hash_index: u64
        8 // timestamp: u64
    ));
    // blockhash_queue.max_age: u64
    try r.discardAll(8);

    // _unused_ancestors: HashMap(Slot, u64)
    const ancestors_len = try readLen(r);
    try r.discardAll(ancestors_len * (8 + // key: Slot
        8 // value: u64
    ));

    // hash(Hash) + parent_hash(Hash) + parent_slot(Slot)
    try r.discardAll(32 + 32 + 8);

    // hard_forks: Vec({ slot: Slot, count: u64 })
    const hard_forks_len = try readLen(r);
    try r.discardAll(hard_forks_len * (8 + // slot: Slot
        8 // count: u64
    ));

    try r.discardAll(
        8 + // transaction_count: u64
            8 + // tick_height: u64
            8 + // signature_count: u64
            8 + // capitalization: u64
            8, // max_tick_height: u64
    );

    // hashes_per_tick: ?u64
    if (try readBool(r)) try r.discardAll(8);

    try r.discardAll(
        8 + // ticks_per_slot: u64
            16 + // ns_per_slot: u128
            8 + // genesis_creation_time: i64
            8 + // slots_per_year: f64
            8 + // accounts_data_len: u64
            8 + // slot: Slot
            8 + // _unused_epoch: Epoch
            8 + // block_height: u64
            32 + // leader_id: Pubkey
            8 + // _unused_collector_fees: u64
            8 + // _unused_fee_calculator: u64
            // fee_rate_governor:
            8 + //   target_lamports_per_signature: u64
            8 + //   target_signatures_per_slot: u64
            8 + //   min_lamports_per_signature: u64
            8 + //   max_lamports_per_signature: u64
            1 + //   burn_percent: u8
            8 + // _unused_collected_rent: u64
            // _unused_rent_collector:
            8 + //   epoch: Epoch
            //   epoch_schedule: EpochSchedule:
            8 + //     slots_per_epoch: u64
            8 + //     leader_schedule_slot_offset: u64
            1 + //     warmup: bool
            8 + //     first_normal_epoch: u64
            8 + //     first_normal_slot: u64
            8 + //   slots_per_year: f64
            //   rent:
            8 + //     lamports_per_byte: u64
            8 + //     exemption_threshold: [8]u8
            1 + //     burn_percent: u8
            // epoch_schedule: EpochSchedule:
            8 + //   slots_per_epoch: u64
            8 + //   leader_schedule_slot_offset: u64
            1 + //   warmup: bool
            8 + //   first_normal_epoch: u64
            8 + //   first_normal_slot: u64
            // inflation:
            8 + //   initial: f64
            8 + //   terminal: f64
            8 + //   taper: f64
            8 + //   foundation: f64
            8 + //   foundation_term: f64
            8, //   __unused: f64
    );

    // stakes: Stakes(Delegation)
    //   vote_accounts: VoteAccounts
    try discardVoteAccounts(r);

    //   stake_delegations: HashMap(Pubkey, Delegation)
    const stake_del_len = try readLen(r);
    try r.discardAll(stake_del_len * (32 + // key: Pubkey
        // Delegation:
        32 + //   voter_pubkey: Pubkey
        8 + //   stake: u64
        8 + //   activation_epoch: Epoch
        8 + //   deactivation_epoch: Epoch
        8 //   warmup_cooldown_rate: f64
    ));

    try r.discardAll(
        8 + // stakes.unused: u64
            8, // stakes.epoch: Epoch
    );

    //   stake_history: Vec({ epoch: Epoch, effective: u64, activating: u64, deactivating: u64 })
    const stake_history_len = try readLen(r);
    try r.discardAll(stake_history_len * (8 + // epoch: Epoch
        8 + // effective: u64
        8 + // activating: u64
        8 // deactivating: u64
    ));

    // _unused_accounts.unused1: HashSet(Pubkey)
    const unused1_len = try readLen(r);
    try r.discardAll(unused1_len * 32);
    // _unused_accounts.unused2: HashSet(Pubkey)
    const unused2_len = try readLen(r);
    try r.discardAll(unused2_len * 32);
    // _unused_accounts.unused3: HashMap(Pubkey, u64)
    const unused3_len = try readLen(r);
    try r.discardAll(unused3_len * (32 + 8));

    // _unused_epoch_stakes: HashSet(Epoch)
    const epoch_stakes_len = try readLen(r);
    try r.discardAll(epoch_stakes_len * 8);

    // is_delta: bool
    try r.discardAll(1);
}

pub fn discardAccountsDbFields(r: *std.Io.Reader) !void {
    // account_file_map: HashMap(Slot, Vec(StorageEntry)) serialized as u64 len + n * { slot: u64, small_vec_size: u64, id: u64, length: u64 }
    const file_map_len = try readLen(r);
    try r.discardAll(file_map_len * (8 + // slot: Slot(u64)
        8 + // small_vec_size: u64
        8 + // id: u64
        8 // length: u64
    ));

    try r.discardAll(
        8 + // _unused_write_version: u64
            8 + // slot: Slot
            // bank_hash_info:
            32 + //   _unused_accounts_delta_hash: Hash
            32 + //   _unused_accounts_hash: Hash
            //   stats: BankHashStats:
            8 + //     num_updated_accounts: u64
            8 + //     num_removed_accounts: u64
            8 + //     num_lamports_stored: u64
            8 + //     total_data_len: u64
            8, //     num_executable_accounts: u64
    );

    // rooted_slots: NullOnEof(Vec(Slot))
    {
        const len = readLen(r) catch |err| switch (err) {
            error.EndOfStream => return,
            else => |e| return e,
        };
        try r.discardAll(len * 8); // Slot: u64
    }

    // rooted_slot_hashes: NullOnEof(Vec(SlotAndHash))
    {
        const len = readLen(r) catch |err| switch (err) {
            error.EndOfStream => return,
            else => |e| return e,
        };
        try r.discardAll(len * (8 + // slot: Slot
            32 // hash: Hash
        ));
    }
}

pub fn discardExtraFields(r: *std.Io.Reader) !void {
    // lamports_per_signature: NullOnEof(u64)
    r.discardAll(8) catch |err| switch (err) {
        error.EndOfStream => return,
        else => |e| return e,
    };

    // _unused_incremental_snapshot_persistence: NullOnEof(?{ full: SlotAndHash, full_capitalization: u64, incremental_hash: Hash, incremental_capitalization: u64 })
    {
        const is_some = readBool(r) catch |err| switch (err) {
            error.EndOfStream => return,
            else => |e| return e,
        };
        if (is_some) try r.discardAll(
            8 + // full.slot: Slot
                32 + // full.hash: Hash
                8 + // full_capitalization: u64
                32 + // incremental_hash: Hash
                8, // incremental_capitalization: u64
        );
    }

    // _unused_epoch_accounts_hash: NullOnEof(?Hash)
    {
        const is_some = readBool(r) catch |err| switch (err) {
            error.EndOfStream => return,
            else => |e| return e,
        };
        if (is_some) try r.discardAll(32);
    }

    // versioned_epoch_stakes: NullOnEof(Vec({ epoch: u64, value: union(enum(u32)) { current: ... } }))
    {
        const outer_len = readLen(r) catch |err| switch (err) {
            error.EndOfStream => return,
            else => |e| return e,
        };
        for (0..outer_len) |_| {
            try r.discardAll(
                8 + // epoch: u64
                    4, // union tag: u32 (enum(u32), always 'current')
            );

            // current.epoch_stakes: Stakes(StakeDelegationWithStake)
            //   vote_accounts: VoteAccounts
            try discardVoteAccounts(r);

            //   stake_delegations: HashMap(Pubkey, { delegation: Delegation, credits_observed: u64 })
            const stake_del_len = try readLen(r);
            try r.discardAll(stake_del_len * (32 + // key: Pubkey
                32 + // delegation.voter_pubkey: Pubkey
                8 + // delegation.stake: u64
                8 + // delegation.activation_epoch: Epoch
                8 + // delegation.deactivation_epoch: Epoch
                8 + // delegation.warmup_cooldown_rate: f64
                8 // credits_observed: u64
            ));

            try r.discardAll(
                8 + // stakes.unused: u64
                    8, // stakes.epoch: Epoch
            );

            //   stake_history: Vec({ epoch: Epoch, effective: u64, activating: u64, deactivating: u64 })
            const sh_len = try readLen(r);
            try r.discardAll(sh_len * (8 + 8 + 8 + 8));

            // current.total_stake: u64
            try r.discardAll(8);

            // current.node_id_to_vote_accounts: HashMap(Pubkey, { vote_accounts: Vec(Pubkey), total_stake: u64 })
            const nv_len = try readLen(r);
            for (0..nv_len) |_| {
                // key: Pubkey
                try r.discardAll(32);
                // value.vote_accounts: Vec(Pubkey)
                const va_len = try readLen(r);
                try r.discardAll(
                    va_len * 32 + // vote_accounts: []Pubkey
                        8, // total_stake: u64
                );
            }

            // current.epoch_authorized_voters: HashMap(Pubkey, Pubkey)
            const eav_len = try readLen(r);
            try r.discardAll(eav_len * (32 + // key: Pubkey
                32 // value: Pubkey
            ));
        }
    }

    // accounts_lt_hash: NullOnEof(?LtHash)
    {
        const is_some = readBool(r) catch |err| switch (err) {
            error.EndOfStream => return,
            else => |e| return e,
        };
        if (is_some) try r.discardAll(2048); // LtHash = [1024]u16
    }

    // block_id: NullOnEof(Hash)
    r.discardAll(32) catch |err| switch (err) {
        error.EndOfStream => return,
        else => |e| return e,
    };
}

fn readTag(r: *std.Io.Reader) !u32 {
    var buf: [4]u8 = undefined;
    try r.readSliceAll(&buf);
    return std.mem.readInt(u32, &buf, .little);
}

/// Discards an InstructionError union. Most variants are void; Custom is u32; BorshIoError is Vec(u8).
fn discardInstructionError(r: *std.Io.Reader) !void {
    const tag = try readTag(r); // enum(u32) tag
    switch (tag) {
        25 => try r.discardAll(4), // Custom: u32
        45 => { // BorshIoError: Vec(u8)
            const len = try readLen(r);
            try r.discardAll(len);
        },
        else => {}, // all other variants are void
    }
}

/// Discards a TransactionError union. Most variants are void; some carry a u8 payload;
/// InstructionError carries { index: u8, err: InstructionError }.
fn discardTransactionError(r: *std.Io.Reader) !void {
    const tag = try readTag(r); // enum(u32) tag
    switch (tag) {
        8 => { // InstructionError: { index: u8, err: InstructionError }
            try r.discardAll(1); // index: u8
            try discardInstructionError(r);
        },
        30, // DuplicateInstruction: u8
        31, // InsufficientFundsForRent: u8
        35, // ProgramExecutionTemporarilyRestricted: u8
        => try r.discardAll(1),
        else => {}, // all other variants are void
    }
}

pub fn discardStatusCache(r: *std.Io.Reader) !void {
    // slot_deltas: Vec({ slot: Slot, is_root: bool, status_map: StatusMap })
    const slot_deltas_len = try readLen(r);
    for (0..slot_deltas_len) |_| {
        // slot(Slot) + is_root(bool)
        try r.discardAll(8 + 1);

        // status_map: HashMap(Hash, { fork_count: u64, entries: Vec({ key_slice: [20]u8, result: union }) })
        const status_map_len = try readLen(r);
        for (0..status_map_len) |_| {
            // key: Hash + value.fork_count: u64
            try r.discardAll(32 + 8);

            // value.entries: Vec({ key_slice: KeySlice, result: union(enum(u32)) { ok, err: TransactionError } })
            const entries_len = try readLen(r);
            for (0..entries_len) |_| {
                // key_slice: [20]u8 + result tag: u32
                try r.discardAll(20);
                const result_tag = try readTag(r); // 0 = ok, 1 = err
                switch (result_tag) {
                    0 => {}, // ok: void
                    1 => try discardTransactionError(r), // err: TransactionError
                    else => return error.InvalidResultTag,
                }
            }
        }
    }
}
