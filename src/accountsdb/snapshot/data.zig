//! fields + data to deserialize snapshot metadata

const std = @import("std");
const zstd = @import("zstd");
const sig = @import("../../sig.zig");
const base58 = @import("base58");
const tracy = @import("tracy");

const bincode = sig.bincode;

const BankFields = sig.core.BankFields;
const Epoch = sig.core.time.Epoch;
const Hash = sig.core.hash.Hash;
const InstructionError = sig.core.instruction.InstructionErrorEnum;
const Pubkey = sig.core.pubkey.Pubkey;
const Slot = sig.core.time.Slot;
const SlotAndHash = sig.core.hash.SlotAndHash;
const SlotHistory = sig.runtime.sysvar.SlotHistory;
const VersionedEpochStakes = sig.core.VersionedEpochStakes;

const FileId = sig.accounts_db.accounts_file.FileId;

const Logger = sig.trace.Logger("snapshots");

pub const MAXIMUM_ACCOUNT_FILE_SIZE: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB
pub const MAX_RECENT_BLOCKHASHES: usize = 300;
pub const MAX_CACHE_ENTRIES: usize = MAX_RECENT_BLOCKHASHES;
const CACHED_KEY_SIZE: usize = 20;

/// Analogous to [ObsoleteIncrementalSnapshotPersistence](https://github.com/anza-xyz/agave/blob/68c1077841eb5a2f0adb2b50f6cfa92a12b8d894/runtime/src/serde_snapshot.rs#L88)
pub const ObsoleteIncrementalSnapshotPersistence = struct {
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

    pub const ZEROES: ObsoleteIncrementalSnapshotPersistence = .{
        .full_slot = 0,
        .full_hash = Hash.ZEROES,
        .full_capitalization = 0,
        .incremental_hash = Hash.ZEROES,
        .incremental_capitalization = 0,
    };

    pub fn initRandom(random: std.Random) ObsoleteIncrementalSnapshotPersistence {
        const full_capitalization = random.int(u64);
        return .{
            .full_slot = random.int(Slot),
            .full_hash = Hash.initRandom(random),
            .full_capitalization = full_capitalization,
            .incremental_hash = Hash.initRandom(random),
            .incremental_capitalization = random.uintAtMost(u64, full_capitalization),
        };
    }
};

// NOTE: Agave has since moved away from having these in "Extra" fields.
/// Analogous to [ExtraFieldsToDeserialize](https://github.com/anza-xyz/agave/blob/8d1ef48c785a5d9ee5c0df71dc520ee1a49d8168/runtime/src/serde_snapshot.rs#L396).
pub const ExtraFields = struct {
    lamports_per_signature: u64,
    snapshot_persistence: ?ObsoleteIncrementalSnapshotPersistence,
    epoch_accounts_hash: ?Hash,
    versioned_epoch_stakes: std.AutoArrayHashMapUnmanaged(Epoch, VersionedEpochStakes),
    accounts_lt_hash: sig.core.hash.LtHash,

    pub const @"!bincode-config": bincode.FieldConfig(ExtraFields) = .{
        .deserializer = bincodeRead,
        .serializer = null, // just use default serialization method
        .free = bincodeFree,
    };

    pub const INIT_EOF: ExtraFields = .{
        .lamports_per_signature = 0,
        .snapshot_persistence = null,
        .epoch_accounts_hash = null,
        .versioned_epoch_stakes = .{},
        .accounts_lt_hash = .IDENTITY,
    };

    pub fn deinit(self: *const ExtraFields, allocator: std.mem.Allocator) void {
        var versioned_epoch_stakes = self.versioned_epoch_stakes;
        for (versioned_epoch_stakes.values()) |ves| ves.deinit(allocator);
        versioned_epoch_stakes.deinit(allocator);
    }

    pub fn clone(
        self: *const ExtraFields,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!ExtraFields {
        return .{
            .lamports_per_signature = self.lamports_per_signature,
            .snapshot_persistence = self.snapshot_persistence,
            .epoch_accounts_hash = self.epoch_accounts_hash,
            .versioned_epoch_stakes = try sig.utils.collections
                .cloneMapAndValues(allocator, self.versioned_epoch_stakes),
            .accounts_lt_hash = self.accounts_lt_hash,
        };
    }

    pub fn initRandom(
        allocator: std.mem.Allocator,
        random: std.Random,
        max_list_entries: usize,
    ) std.mem.Allocator.Error!ExtraFields {
        var extra_fields: ExtraFields = INIT_EOF;
        errdefer extra_fields.deinit(allocator);

        const FieldTag = std.meta.FieldEnum(ExtraFields);
        const field_infos = @typeInfo(ExtraFields).@"struct".fields;

        const NonEofCount = std.math.IntFittingRange(0, field_infos.len);
        const non_eof_count = random.uintLessThan(NonEofCount, field_infos.len);

        inline for (field_infos, 0..) |field, i| runtime_continue: {
            if (i != non_eof_count) break :runtime_continue;
            const field_ptr = &@field(extra_fields, field.name);
            switch (@field(FieldTag, field.name)) {
                .lamports_per_signature,
                => field_ptr.* = random.int(u64),

                .snapshot_persistence,
                => field_ptr.* = ObsoleteIncrementalSnapshotPersistence.initRandom(random),

                .epoch_accounts_hash,
                => field_ptr.* = Hash.initRandom(random),

                .versioned_epoch_stakes,
                => {
                    const entry_count = random.uintAtMost(usize, max_list_entries);
                    try field_ptr.ensureTotalCapacity(allocator, entry_count);
                    for (0..entry_count) |_| {
                        const ves = try VersionedEpochStakes.initRandom(
                            allocator,
                            random,
                            max_list_entries,
                        );
                        field_ptr.putAssumeCapacity(random.int(u64), ves);
                    }
                },

                .accounts_lt_hash,
                => field_ptr.* = hash: {
                    var hash: sig.core.hash.LtHash = undefined;
                    random.bytes(std.mem.asBytes(&hash));
                    break :hash hash;
                },
            }
        }

        return extra_fields;
    }

    fn bincodeRead(
        limit_allocator: *bincode.LimitAllocator,
        reader: anytype,
        params: bincode.Params,
    ) !ExtraFields {
        var extra_fields: ExtraFields = INIT_EOF;
        errdefer extra_fields.deinit(limit_allocator.allocator());

        until_eof: {
            const FieldTag = std.meta.FieldEnum(ExtraFields);
            const assert_allocator = sig.utils.allocators.failing.allocator(.{
                .alloc = .assert,
                .resize = .assert,
                .free = .assert,
            });

            inline for (@typeInfo(ExtraFields).@"struct".fields) |field| {
                const field_ptr = &@field(extra_fields, field.name);
                field_ptr.* = switch (@field(FieldTag, field.name)) {
                    .lamports_per_signature,
                    => bincode.readInt(u64, reader, params),

                    .snapshot_persistence,
                    .epoch_accounts_hash,
                    => bincode.read(assert_allocator, field.type, reader, params),

                    // We need to deserialise this as optional, but really we should always have it
                    .accounts_lt_hash,
                    => if (bincode.read(assert_allocator, ?field.type, reader, params)) |maybe_lt|
                        maybe_lt orelse error.DeltaLtNotPresent
                    else |err|
                        err,

                    .versioned_epoch_stakes,
                    => bincode.readWithLimit(limit_allocator, field.type, reader, params),
                } catch |err| switch (err) {
                    error.EndOfStream => break :until_eof,
                    else => |e| return e,
                };
            }
        }

        return extra_fields;
    }

    fn bincodeFree(allocator: std.mem.Allocator, data: anytype) void {
        comptime if (@TypeOf(data) == ExtraFields) unreachable;
        data.deinit(allocator);
    }
};

/// Analogous to [SerializableAccountStorageEntry](https://github.com/anza-xyz/agave/blob/cadba689cb44db93e9c625770cafd2fc0ae89e33/runtime/src/serde_snapshot/storage.rs#L11)
pub const AccountFileInfo = struct {
    /// note: serialized id is a usize but in code it's FileId (u32)
    id: FileId,
    /// amount of bytes used
    length: usize,

    pub const @"!bincode-config:id" = FileId.BincodeConfig;

    /// Analogous to [AppendVecError](https://github.com/anza-xyz/agave/blob/91a4ecfff78423433cc0001362cea8fed860dcb9/accounts-db/src/append_vec.rs#L74)
    pub const ValidateError = error{
        FileSizeTooSmall,
        FileSizeTooLarge,
        OffsetOutOfBounds,
    };
    /// Analogous to [sanitize_len_and_size](https://github.com/anza-xyz/agave/blob/91a4ecfff78423433cc0001362cea8fed860dcb9/accounts-db/src/append_vec.rs#L376)
    pub fn validate(self: *const AccountFileInfo, file_size: usize) ValidateError!void {
        if (file_size == 0) {
            return error.FileSizeTooSmall;
        } else if (file_size > @as(usize, MAXIMUM_ACCOUNT_FILE_SIZE)) {
            return error.FileSizeTooLarge;
        } else if (self.length > file_size) {
            return error.OffsetOutOfBounds;
        }
    }

    pub fn format(
        account_file_info: AccountFileInfo,
        comptime fmt_str: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = fmt_str;

        try writer.print(".{{ .id = {}, .length = {} }}", .{
            account_file_info.id.toInt(), account_file_info.length,
        });
    }
};

/// Analogous to [BankHashInfo](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L115)
pub const BankHashInfo = struct {
    obsolete_accounts_delta_hash: Hash = Hash.ZEROES,
    obsolete_accounts_hash: Hash = Hash.ZEROES,
    stats: BankHashStats,

    pub fn initRandom(random: std.Random) BankHashInfo {
        return .{
            .obsolete_accounts_delta_hash = Hash.initRandom(random),
            .obsolete_accounts_hash = Hash.initRandom(random),
            .stats = BankHashStats.initRandom(random),
        };
    }
};

/// Analogous to [BankHashStats](https://github.com/anza-xyz/agave/blob/4c921ca276bbd5997f809dec1dd3937fb06463cc/accounts-db/src/accounts_db.rs#L1299)
pub const BankHashStats = struct {
    num_updated_accounts: u64,
    num_removed_accounts: u64,
    num_lamports_stored: u64,
    total_data_len: u64,
    num_executable_accounts: u64,

    pub const zero_init: BankHashStats = .{
        .num_updated_accounts = 0,
        .num_removed_accounts = 0,
        .num_lamports_stored = 0,
        .total_data_len = 0,
        .num_executable_accounts = 0,
    };

    pub fn initRandom(random: std.Random) BankHashStats {
        return .{
            .num_updated_accounts = random.int(u64),
            .num_removed_accounts = random.int(u64),
            .num_lamports_stored = random.int(u64),
            .total_data_len = random.int(u64),
            .num_executable_accounts = random.int(u64),
        };
    }

    pub const AccountData = struct {
        lamports: u64,
        data_len: u64,
        executable: bool,
    };
    pub fn update(stats: *BankHashStats, account: AccountData) void {
        if (account.lamports == 0) {
            stats.num_removed_accounts += 1;
        } else {
            stats.num_updated_accounts += 1;
        }
        stats.total_data_len +%= account.data_len;
        stats.num_executable_accounts += @intFromBool(account.executable);
        stats.num_lamports_stored +%= account.lamports;
    }

    pub fn accumulate(stats: *BankHashStats, other: BankHashStats) void {
        stats.num_updated_accounts += other.num_updated_accounts;
        stats.num_removed_accounts += other.num_removed_accounts;
        stats.total_data_len +%= other.total_data_len;
        stats.num_lamports_stored +%= other.num_lamports_stored;
        stats.num_executable_accounts += other.num_executable_accounts;
    }
};

/// Analogous to [AccountsDbFields](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L77)
pub const AccountsDbFields = struct {
    file_map: FileMap,

    /// NOTE: this is not a meaningful field
    /// NOTE: at the time of writing, a test snapshots we use actually have this field set to 601 on disk,
    /// so be sure to keep that in mind while testing.
    stored_meta_write_version: u64,

    slot: Slot,
    bank_hash_info: BankHashInfo,

    /// NOTE: these are currently always empty?
    /// https://github.com/anza-xyz/agave/blob/9c899a72414993dc005f11afb5df10752b10810b/runtime/src/serde_snapshot.rs#L815-L825
    rooted_slots: []const Slot,
    rooted_slot_hashes: []const SlotAndHash,

    pub const @"!bincode-config": bincode.FieldConfig(AccountsDbFields) = .{
        .deserializer = bincodeRead,
        .serializer = bincodeWrite,
        .free = bincodeFree,
    };

    pub const FileMap = std.AutoArrayHashMapUnmanaged(Slot, AccountFileInfo);

    pub fn deinit(fields: AccountsDbFields, allocator: std.mem.Allocator) void {
        var file_map = fields.file_map;
        file_map.deinit(allocator);

        allocator.free(fields.rooted_slots);
        allocator.free(fields.rooted_slot_hashes);
    }

    pub fn clone(
        fields: AccountsDbFields,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!AccountsDbFields {
        var file_map = try fields.file_map.clone(allocator);
        errdefer file_map.deinit(allocator);

        const rooted_slots = try allocator.dupe(Slot, fields.rooted_slots);
        errdefer allocator.free(rooted_slots);

        const rooted_slot_hashes = try allocator.dupe(SlotAndHash, fields.rooted_slot_hashes);
        errdefer allocator.free(rooted_slot_hashes);

        return .{
            .file_map = file_map,
            .stored_meta_write_version = fields.stored_meta_write_version,
            .slot = fields.slot,
            .bank_hash_info = fields.bank_hash_info,
            .rooted_slots = rooted_slots,
            .rooted_slot_hashes = rooted_slot_hashes,
        };
    }

    fn bincodeRead(
        limit_allocator: *bincode.LimitAllocator,
        reader: anytype,
        params: bincode.Params,
    ) !AccountsDbFields {
        const allocator = limit_allocator.allocator();
        const assert_allocator = sig.utils.allocators.failing.allocator(.{
            .alloc = .assert,
            .resize = .assert,
            .free = .assert,
        });

        var filemap = try bincode.hashmap.readCtx(limit_allocator, FileMap, reader, params, struct {
            pub const readKey = {};
            pub const freeKey = {};
            pub fn readValue(
                _: *bincode.LimitAllocator,
                _reader: anytype,
                _params: bincode.Params,
            ) !AccountFileInfo {
                if (try bincode.readIntAsLength(usize, _reader, _params) != 1) {
                    return error.TooManyAccountFileInfos;
                }
                return bincode.read(assert_allocator, AccountFileInfo, _reader, _params);
            }
            pub const freeValue = {};
        });
        errdefer filemap.deinit(allocator);

        const stored_meta_write_version = try bincode.readInt(u64, reader, params);
        const slot = try bincode.readInt(Slot, reader, params);
        const bank_hash_info = try bincode.read(assert_allocator, BankHashInfo, reader, params);

        const rooted_slots: []const Slot =
            bincode.readWithLimit(limit_allocator, []const Slot, reader, params) catch |err|
                switch (err) {
                    error.EndOfStream => &.{},
                    else => |e| return e,
                };
        errdefer allocator.free(rooted_slots);

        const rooted_slot_hashes: []const SlotAndHash =
            bincode.readWithLimit(limit_allocator, []const SlotAndHash, reader, params) catch |err|
                switch (err) {
                    error.EndOfStream => &.{},
                    else => |e| return e,
                };
        errdefer allocator.free(rooted_slot_hashes);

        return .{
            .file_map = filemap,
            .stored_meta_write_version = stored_meta_write_version,
            .slot = slot,
            .bank_hash_info = bank_hash_info,

            .rooted_slots = rooted_slots,
            .rooted_slot_hashes = rooted_slot_hashes,
        };
    }

    fn bincodeWrite(writer: anytype, data: anytype, params: bincode.Params) !void {
        comptime if (@TypeOf(data) != AccountsDbFields) unreachable;

        {
            try bincode.write(writer, @as(usize, data.file_map.count()), params);
            var iter = data.file_map.iterator();
            while (iter.next()) |entry| {
                try bincode.write(writer, entry.key_ptr.*, params);

                const value_as_slice: []const AccountFileInfo = entry.value_ptr[0..1];
                try bincode.write(writer, value_as_slice, params);
            }
        }

        try bincode.write(writer, data.stored_meta_write_version, params);
        try bincode.write(writer, data.slot, params);
        try bincode.write(writer, data.bank_hash_info, params);

        try bincode.write(writer, data.rooted_slots, params);
        try bincode.write(writer, data.rooted_slot_hashes, params);
    }

    fn bincodeFree(allocator: std.mem.Allocator, data: anytype) void {
        data.deinit(allocator);
    }
};

/// contains all the metadata from a snapshot.
/// this includes fields for accounts-db and the bank of the snapshots slots.
/// this does not include account-specific data.
pub const Manifest = struct {
    bank_fields: BankFields,
    accounts_db_fields: AccountsDbFields,
    /// incremental snapshot fields.
    bank_extra: ExtraFields,

    pub fn deinit(self: Manifest, allocator: std.mem.Allocator) void {
        self.bank_fields.deinit(allocator);
        self.accounts_db_fields.deinit(allocator);
        self.bank_extra.deinit(allocator);
    }

    pub fn clone(
        man: Manifest,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!Manifest {
        const bank_fields = try man.bank_fields.clone(allocator);
        errdefer bank_fields.deinit(allocator);

        const accounts_db_fields = try man.accounts_db_fields.clone(allocator);
        errdefer accounts_db_fields.deinit(allocator);

        const bank_extra = try man.bank_extra.clone(allocator);
        errdefer bank_extra.deinit(allocator);

        return .{
            .bank_fields = bank_fields,
            .accounts_db_fields = accounts_db_fields,
            .bank_extra = bank_extra,
        };
    }

    pub fn readFromFilePath(
        allocator: std.mem.Allocator,
        path: []const u8,
    ) !Manifest {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            switch (err) {
                error.FileNotFound => return error.SnapshotFieldsNotFound,
                else => return err,
            }
        };
        defer file.close();
        return readFromFile(allocator, file);
    }

    pub fn readFromFile(
        allocator: std.mem.Allocator,
        file: std.fs.File,
    ) !Manifest {
        const size = (try file.stat()).size;
        const contents = try file.readToEndAllocOptions(allocator, size, size, .@"1", null);
        defer allocator.free(contents);

        var fbs = std.io.fixedBufferStream(contents);
        return try decodeFromBincode(allocator, fbs.reader());
    }

    pub fn decodeFromBincode(
        allocator: std.mem.Allocator,
        /// `std.io.GenericReader(...)` | `std.io.AnyReader`
        reader: anytype,
    ) !Manifest {
        return try bincode.read(allocator, Manifest, reader, .{ .allocation_limit = 2 << 30 });
    }

    pub fn epochStakes(
        self: *const Manifest,
        epoch: Epoch,
    ) !*const sig.utils.collections.PubkeyMap(u64) {
        if (self.bank_fields.epoch_stakes.getPtr(epoch)) |_| {
            // Agave simply ignores this field. I've added this log message just
            // as a sanity check, but I don't expect to ever see it.
            std.log.warn("ignoring deprecated epoch stakes", .{});
        }
        return if (self.bank_extra.versioned_epoch_stakes.getPtr(epoch)) |es|
            &es.current.stakes.vote_accounts.staked_nodes
        else
            return error.NoEpochStakes;
    }

    pub fn epochVoteAccounts(
        self: *const Manifest,
        epoch: Epoch,
    ) !*const sig.core.stakes.StakeAndVoteAccountsMap {
        if (self.bank_fields.epoch_stakes.getPtr(epoch)) |_| {
            // Agave simply ignores this field. I've added this log message just
            // as a sanity check, but I don't expect to ever see it.
            std.log.warn("ignoring deprecated epoch stakes", .{});
        }
        return if (self.bank_extra.versioned_epoch_stakes.getPtr(epoch)) |es|
            &es.current.stakes.vote_accounts.vote_accounts
        else
            return error.NoEpochStakes;
    }
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

    pub const EMPTY: StatusCache = .{ .bank_slot_deltas = &.{} };

    pub fn initFromPath(allocator: std.mem.Allocator, path: []const u8) !StatusCache {
        const status_cache_file = try std.fs.cwd().openFile(path, .{});
        defer status_cache_file.close();
        return readFromFile(allocator, status_cache_file);
    }

    /// opens the status cache using path {dir}/snapshots/status_cache
    pub fn initFromDir(allocator: std.mem.Allocator, dir: std.fs.Dir) !StatusCache {
        const status_cache_file = try dir.openFile("snapshots/status_cache", .{});
        defer status_cache_file.close();
        return readFromFile(allocator, status_cache_file);
    }

    pub fn readFromFile(allocator: std.mem.Allocator, file: std.fs.File) !StatusCache {
        return decodeFromBincode(allocator, file.deprecatedReader());
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
            if (slot_history.check(slot) != .found) {
                return error.SlotNotFoundInHistory;
            }
        }

        var slots_checked: u32 = 0;
        var slot = slot_history.newest();
        while (slot >= slot_history.oldest() and slots_checked != MAX_CACHE_ENTRIES) {
            if (slot_history.check(slot) == .found) {
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
    slot: Slot,
    hash: Hash,

    pub const SnapshotArchiveNameFmtSpec = sig.utils.fmt.BoundedSpec(
        "snapshot-{[slot]d}-{[hash]s}.tar.zst",
    );

    pub const SnapshotArchiveNameStr = SnapshotArchiveNameFmtSpec.BoundedArrayValue(.{
        .slot = std.math.maxInt(Slot),
        .hash = "1" ** Hash.BASE58_MAX_SIZE,
    });

    pub fn snapshotArchiveName(self: FullSnapshotFileInfo) SnapshotArchiveNameStr {
        const b58_str = self.hash.base58String();
        return SnapshotArchiveNameFmtSpec.fmt(.{
            .slot = self.slot,
            .hash = sig.utils.fmt.boundedString(&b58_str),
        });
    }

    pub const ParseFileNameTarZstError = ParseFileBaseNameError || error{
        MissingExtension,
        InvalidExtension,
    };

    /// Matches with the regex: `^snapshot-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar\.zst)$`.
    pub fn parseFileNameTarZst(
        filename: []const u8,
    ) ParseFileNameTarZstError!FullSnapshotFileInfo {
        const snapshot_file_info, const extension_start = try parseFileBaseName(filename);
        if (extension_start == filename.len) {
            return error.MissingExtension;
        }
        if (!std.mem.eql(u8, filename[extension_start..], ".tar.zst")) {
            return error.InvalidExtension;
        }
        return snapshot_file_info;
    }

    pub const ParseFileBaseNameError = error{
        /// The file name did not start with 'snapshot-'.
        MissingPrefix,
        /// The prefix was not followed by a slot number.
        MissingSlot,
        /// The slot was not followed by a delimiter '-'.
        MissingSlotDelimiter,
        /// The slot number string either did not fit into
        /// a `Slot` integer, or contained invalid digits.
        InvalidSlot,
        /// The slot was not followed by a hash.
        MissingHash,
        /// The hash was invalid.
        InvalidHash,
    };

    /// Matches with the regex: `^snapshot-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)`.
    /// Returns the full snapshot info based on the parsed section, and the index to the
    /// remainder of the unparsed section of `filename`, which the caller can check for
    /// the expected extension.
    pub fn parseFileBaseName(
        filename: []const u8,
    ) ParseFileBaseNameError!struct { FullSnapshotFileInfo, usize } {
        const prefix = "snapshot-";
        if (!std.mem.startsWith(u8, filename, prefix)) {
            return error.MissingPrefix;
        }

        // parse slot until '-'
        const slot, const slot_end = slot: {
            const start = prefix.len;
            if (start == filename.len) {
                return error.MissingSlot;
            }

            const str_max_len = std.fmt.count("{d}", .{std.math.maxInt(Slot)});
            const end_max = @min(filename.len, start + str_max_len + 1);
            const filename_trunc = filename[0..end_max];
            const end = std.mem.indexOfScalarPos(u8, filename_trunc, start + 1, '-') orelse
                return error.MissingSlotDelimiter;

            const str = filename[start..end];
            const slot = std.fmt.parseInt(Slot, str, 10) catch |err| switch (err) {
                error.Overflow, error.InvalidCharacter => return error.InvalidSlot,
            };

            break :slot .{ slot, end };
        };

        // parse until there's no base58 characters left
        const hash, const hash_end = hash: {
            const start = slot_end + 1;
            if (start == filename.len) {
                return error.MissingHash;
            }

            const str_max_len = Hash.BASE58_MAX_SIZE;
            const truncated = filename[0..@min(filename.len, start + str_max_len + 1)];
            const alphabet = std.mem.asBytes(&base58.Table.BITCOIN.alphabet);
            const end = std.mem.indexOfNonePos(u8, truncated, start + 1, alphabet) orelse
                truncated.len;

            const str = filename[start..end];
            const hash = Hash.parseRuntime(str) catch |err| switch (err) {
                error.InvalidHash => return error.InvalidHash,
            };

            break :hash .{ hash, end };
        };

        const snapshot_file_info: FullSnapshotFileInfo = .{
            .slot = slot,
            .hash = hash,
        };

        return .{ snapshot_file_info, hash_end };
    }
};

/// information on an incremental snapshot including the filename, base slot (full snapshot), slot, and hash
///
/// Analogous to [IncrementalSnapshotArchiveInfo](https://github.com/anza-xyz/agave/blob/59bf1809fe5115f0fad51e80cc0a19da1496e2e9/runtime/src/snapshot_archive_info.rs#L103)
pub const IncrementalSnapshotFileInfo = struct {
    base_slot: Slot,
    slot: Slot,
    hash: Hash,

    /// Returns the incremental slot and hash.
    pub fn slotAndHash(self: IncrementalSnapshotFileInfo) SlotAndHash {
        return .{
            .slot = self.slot,
            .hash = self.hash,
        };
    }

    pub const SnapshotArchiveNameFmtSpec = sig.utils.fmt.BoundedSpec(
        "incremental-snapshot-{[base_slot]d}-{[slot]d}-{[hash]s}.tar.zst",
    );

    pub const SnapshotArchiveNameStr = SnapshotArchiveNameFmtSpec.BoundedArrayValue(.{
        .base_slot = std.math.maxInt(Slot),
        .slot = std.math.maxInt(Slot),
        .hash = "1" ** Hash.BASE58_MAX_SIZE,
    });

    pub fn snapshotArchiveName(self: IncrementalSnapshotFileInfo) SnapshotArchiveNameStr {
        const b58_str = self.hash.base58String();

        return SnapshotArchiveNameFmtSpec.fmt(.{
            .base_slot = self.base_slot,
            .slot = self.slot,
            .hash = sig.utils.fmt.boundedString(&b58_str),
        });
    }

    pub const ParseFileNameTarZstError = ParseFileBaseNameError || error{
        MissingExtension,
        InvalidExtension,
    };

    /// Matches against regex: `^incremental-snapshot-(?P<base_slot>[[:digit:]]+)-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)\.(?P<ext>tar\.zst)$`.
    pub fn parseFileNameTarZst(
        filename: []const u8,
    ) ParseFileNameTarZstError!IncrementalSnapshotFileInfo {
        const snapshot_file_info, const extension_start = try parseFileBaseName(filename);
        if (extension_start == filename.len) {
            return error.MissingExtension;
        }
        if (!std.mem.eql(u8, filename[extension_start..], ".tar.zst")) {
            return error.InvalidExtension;
        }
        return snapshot_file_info;
    }

    pub const ParseFileBaseNameError = error{
        /// The file name did not start with 'incremental-snapshot-'.
        MissingPrefix,
        /// The prefix was not followed by a base slot number.
        MissingBaseSlot,
        /// The base slot was not followed by a delimiter '-'.
        MissingBaseSlotDelimiter,
        /// The base slot number string either did not fit into
        /// a `Slot` integer, or contained invalid digits.
        InvalidBaseSlot,
        /// The base slot was not followed by a slot number.
        MissingSlot,
        /// The slot was not followed by a delimiter '-'.
        MissingSlotDelimiter,
        /// The slot number string either did not fit into
        /// a `Slot` integer, or contained invalid digits.
        InvalidSlot,
        /// The slot was not followed by a hash.
        MissingHash,
        /// The hash was invalid.
        InvalidHash,
    };

    /// Matches with the regex: `incremental-snapshot-(?P<base_slot>[[:digit:]]+)-(?P<slot>[[:digit:]]+)-(?P<hash>[[:alnum:]]+)`.
    /// Returns the full snapshot info based on the parsed section, and the index to the
    /// remainder of the unparsed section of `filename`, which the caller can check for
    /// the expected extension.
    pub fn parseFileBaseName(
        filename: []const u8,
    ) ParseFileBaseNameError!struct { IncrementalSnapshotFileInfo, usize } {
        const prefix = "incremental-snapshot-";
        if (!std.mem.startsWith(u8, filename, prefix)) {
            return error.MissingPrefix;
        }

        // parse base slot until '-'
        const base_slot, const base_slot_end = base_slot: {
            const start = prefix.len;
            if (start == filename.len) {
                return error.MissingBaseSlot;
            }

            const str_max_len = std.fmt.count("{d}", .{std.math.maxInt(Slot)});
            const end_max = @min(filename.len, start + str_max_len + 1);
            const filename_trunc = filename[0..end_max];
            const end = std.mem.indexOfScalarPos(u8, filename_trunc, start + 1, '-') orelse
                return error.MissingSlotDelimiter;

            const str = filename[start..end];
            const base_slot = std.fmt.parseInt(Slot, str, 10) catch |err| switch (err) {
                error.Overflow, error.InvalidCharacter => return error.InvalidBaseSlot,
            };

            break :base_slot .{ base_slot, end };
        };

        // parse slot until '-'
        const slot, const slot_end = slot: {
            const start = base_slot_end + 1;
            if (start == filename.len) {
                return error.MissingSlot;
            }

            const str_max_len = std.fmt.count("{d}", .{std.math.maxInt(Slot)});
            const end_max = @min(filename.len, start + str_max_len + 1);
            const filename_trunc = filename[0..end_max];
            const end = std.mem.indexOfScalarPos(u8, filename_trunc, start + 1, '-') orelse
                return error.MissingSlotDelimiter;

            const str = filename[start..end];
            const slot = std.fmt.parseInt(Slot, str, 10) catch |err| switch (err) {
                error.Overflow, error.InvalidCharacter => return error.InvalidSlot,
            };

            break :slot .{ slot, end };
        };

        // parse until there's no base58 characters left
        const hash, const hash_end = hash: {
            const start = slot_end + 1;
            if (start == filename.len) {
                return error.MissingHash;
            }

            const str_max_len = Hash.BASE58_MAX_SIZE;
            const truncated = filename[0..@min(filename.len, start + str_max_len + 1)];
            const alphabet = std.mem.asBytes(&base58.Table.BITCOIN.alphabet);
            const end = std.mem.indexOfNonePos(u8, truncated, start + 1, alphabet) orelse
                truncated.len;

            const str = filename[start..end];
            const hash = Hash.parseRuntime(str) catch |err| switch (err) {
                error.InvalidHash => return error.InvalidHash,
            };

            break :hash .{ hash, end };
        };

        const snapshot_file_info: IncrementalSnapshotFileInfo = .{
            .base_slot = base_slot,
            .slot = slot,
            .hash = hash,
        };

        return .{ snapshot_file_info, hash_end };
    }
};

pub const SnapshotFiles = struct {
    full: FullSnapshotFileInfo,
    incremental_info: ?SlotAndHash,

    pub fn incremental(self: SnapshotFiles) ?IncrementalSnapshotFileInfo {
        const inc_info = self.incremental_info orelse return null;
        return .{
            .base_slot = self.full.slot,
            .slot = inc_info.slot,
            .hash = inc_info.hash,
        };
    }

    /// Asserts that `if (maybe_incremental_info) |inc| inc.base_slot == full_info.slot`.
    pub fn fromFileInfos(
        full_info: FullSnapshotFileInfo,
        maybe_incremental_info: ?IncrementalSnapshotFileInfo,
    ) SnapshotFiles {
        if (maybe_incremental_info) |inc| {
            std.debug.assert(inc.base_slot == full_info.slot);
        }
        return .{
            .full = full_info,
            .incremental_info = if (maybe_incremental_info) |inc| inc.slotAndHash() else null,
        };
    }

    pub const FindError = std.mem.Allocator.Error || std.fs.Dir.Iterator.Error || error{
        NoFullSnapshotFileInfoFound,
    };
    /// finds existing snapshots (full and matching incremental) by looking for .tar.zstd files
    pub fn find(allocator: std.mem.Allocator, search_dir: std.fs.Dir) FindError!SnapshotFiles {
        const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb SnapshotFiles.find" });
        defer zone.deinit();

        var incremental_snapshots: std.ArrayListUnmanaged(IncrementalSnapshotFileInfo) = .{};
        defer incremental_snapshots.deinit(allocator);

        var maybe_latest_full: ?FullSnapshotFileInfo = null;

        var dir_iter = search_dir.iterate();
        while (try dir_iter.next()) |dir_entry| {
            if (dir_entry.kind != .file and dir_entry.kind != .sym_link) continue;
            const filename = dir_entry.name;

            if (IncrementalSnapshotFileInfo.parseFileNameTarZst(filename)) |_incremental| {
                if (maybe_latest_full) |latest_full| {
                    if (_incremental.slot < latest_full.slot) continue;
                    if (_incremental.base_slot < latest_full.slot) continue;
                }
                try incremental_snapshots.append(allocator, _incremental);
                continue;
            } else |_| {}

            const full = FullSnapshotFileInfo.parseFileNameTarZst(filename) catch continue;
            const latest_full = maybe_latest_full orelse {
                maybe_latest_full = full;
                continue;
            };
            if (latest_full.slot < full.slot) {
                maybe_latest_full = full;
                continue;
            }
            if (latest_full.slot == full.slot) {
                // TODO:
                std.debug.panic("TODO: report this error gracefully in some way ({s} vs {s})", .{
                    latest_full.snapshotArchiveName().constSlice(),
                    full.snapshotArchiveName().constSlice(),
                });
            }
        }
        const latest_full = maybe_latest_full orelse return error.NoFullSnapshotFileInfoFound;

        var maybe_latest_incremental: ?IncrementalSnapshotFileInfo = null;
        for (incremental_snapshots.items) |_incremental| {
            if (_incremental.base_slot != latest_full.slot) continue;
            const latest_incremental = maybe_latest_incremental orelse {
                maybe_latest_incremental = _incremental;
                continue;
            };
            if (latest_incremental.slot < _incremental.slot) {
                maybe_latest_incremental = _incremental;
                continue;
            }
            if (latest_incremental.slot == _incremental.slot) {
                // TODO: if they have the same slot, that means they have different hashes, despite it being
                // impossible for a given slot range to possess two different hashes; we have no way at this
                // stage to unambiguously decide which of the two snapshots we want to select, since either
                // could be valid. For now, we panic, but we should gracefully report this in some way.
                std.debug.panic("TODO: report this error gracefully in some way ({s} vs {s})", .{
                    latest_incremental.snapshotArchiveName().constSlice(),
                    _incremental.snapshotArchiveName().constSlice(),
                });
            }
        }

        return fromFileInfos(
            latest_full,
            maybe_latest_incremental,
        );
    }
};

/// Represents the full manifest optionally combined with an incremental manifest.
///
/// Analogous to [SnapshotBankFields](https://github.com/anza-xyz/agave/blob/2de7b565e8b1101824a5e3bac74f3a8cce88ea72/runtime/src/serde_snapshot.rs#L299)
pub const FullAndIncrementalManifest = struct {
    full: Manifest,
    incremental: ?Manifest,

    pub fn fromFiles(
        allocator: std.mem.Allocator,
        logger: Logger,
        snapshot_dir: std.fs.Dir,
        files: SnapshotFiles,
    ) !FullAndIncrementalManifest {
        const full_fields = blk: {
            const rel_path_bounded = sig.utils.fmt.boundedFmt(
                "snapshots/{0}/{0}",
                .{files.full.slot},
            );
            const rel_path = rel_path_bounded.constSlice();

            logger.info().logf(
                "reading *full* snapshot fields from: {s}",
                .{sig.utils.fmt.tryRealPath(snapshot_dir, rel_path)},
            );

            const full_file = try snapshot_dir.openFile(rel_path, .{});
            defer full_file.close();

            break :blk try Manifest.readFromFile(allocator, full_file);
        };
        errdefer full_fields.deinit(allocator);

        const incremental_fields = if (files.incremental_info) |inc_snap| blk: {
            const rel_path_bounded = sig.utils.fmt.boundedFmt(
                "snapshots/{0}/{0}",
                .{inc_snap.slot},
            );
            const rel_path = rel_path_bounded.constSlice();
            logger.info().logf(
                "reading *incremental* snapshot fields from: {s}",
                .{sig.utils.fmt.tryRealPath(snapshot_dir, rel_path)},
            );

            const incremental_file = try snapshot_dir.openFile(rel_path, .{});
            defer incremental_file.close();

            break :blk try Manifest.readFromFile(allocator, incremental_file);
        } else blk: {
            logger.info().log("no incremental snapshot fields found");
            break :blk null;
        };
        errdefer if (incremental_fields) |fields| fields.deinit(allocator);

        return .{
            .full = full_fields,
            .incremental = incremental_fields,
        };
    }

    pub const CollapseError = error{
        /// There are storages for the same slot in both the full and incremental snapshot.
        SnapshotSlotOverlap,
    };

    /// Like `collapseIfNecessary`, but returns a clone of the full snapshot
    /// manifest if there is no incremental update to apply.
    /// The caller is responsible for `.deinit`ing the result with `allocator`.
    pub fn collapse(
        self: FullAndIncrementalManifest,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || CollapseError)!Manifest {
        const maybe_collapsed = try self.collapseIfNecessary(allocator);
        return maybe_collapsed orelse try self.full.clone(allocator);
    }

    /// Returns null if there is no incremental snapshot manifest; otherwise
    /// returns the result of overlaying the updates of the incremental
    /// onto the full snapshot manifest.
    /// The caller is responsible for `.deinit`ing the result with `allocator`
    /// if it is non-null.
    pub fn collapseIfNecessary(
        self: FullAndIncrementalManifest,
        allocator: std.mem.Allocator,
    ) (std.mem.Allocator.Error || CollapseError)!?Manifest {
        const full = self.full;
        const incremental = self.incremental orelse return null;

        // make a heap clone of the incremental manifest's more up-to-date
        // data, except with the file map of the full manifest, which is
        // likely to contain a larger amount of entries; can then overlay
        // the relevant entries from the incremental manifest onto the
        // clone of the full manifest.

        var collapsed = incremental;
        collapsed.accounts_db_fields.file_map = full.accounts_db_fields.file_map;

        collapsed = try collapsed.clone(allocator);
        errdefer collapsed.deinit(allocator);

        const collapsed_file_map = &collapsed.accounts_db_fields.file_map;
        try collapsed_file_map.ensureUnusedCapacity(
            allocator,
            incremental.accounts_db_fields.file_map.count(),
        );

        const inc_file_map = &incremental.accounts_db_fields.file_map;
        for (inc_file_map.keys(), inc_file_map.values()) |slot, account_file_info| {
            if (slot <= full.accounts_db_fields.slot) continue;
            const gop = collapsed_file_map.getOrPutAssumeCapacity(slot);
            if (gop.found_existing) return error.SnapshotSlotOverlap;
            gop.value_ptr.* = account_file_info;
        }

        return collapsed;
    }

    pub fn deinit(self: FullAndIncrementalManifest, allocator: std.mem.Allocator) void {
        self.full.deinit(allocator);
        if (self.incremental) |inc| inc.deinit(allocator);
    }
};

test "checkAllAllocationFailures FullAndIncrementalManifest" {
    const local = struct {
        fn parseFiles(
            allocator: std.mem.Allocator,
            snapdir: std.fs.Dir,
            snapshot_files: SnapshotFiles,
        ) !void {
            const combined_manifest = try FullAndIncrementalManifest.fromFiles(
                allocator,
                .noop,
                snapdir,
                snapshot_files,
            );
            defer combined_manifest.deinit(allocator);

            const collapsed_manifest = try combined_manifest.collapse(allocator);
            defer collapsed_manifest.deinit(allocator);
        }
    };

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapdir = tmp_dir_root.dir;

    const snapshot_files = try sig.accounts_db.db.findAndUnpackTestSnapshots(1, snapdir);

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        local.parseFiles,
        .{ snapdir, snapshot_files },
    );
}

pub const generate = struct {
    /// Writes the version, status cache, and manifest files.
    /// Should call this first to begin generating the snapshot archive.
    pub fn writeMetadataFiles(
        archive_writer: anytype,
        version: sig.version.ClientVersion,
        status_cache: StatusCache,
        manifest: *const Manifest,
    ) !void {
        const slot: Slot = manifest.bank_fields.slot;

        var counting_writer_state = std.io.countingWriter(archive_writer);
        const writer = counting_writer_state.writer();

        // write the version file
        const version_str_bounded = sig.utils.fmt.boundedFmt(
            "{d}.{d}.{d}",
            .{ version.major, version.minor, version.patch },
        );
        const version_str = version_str_bounded.constSlice();
        try sig.utils.tar.writeTarHeader(writer, .regular, "version", version_str.len);
        try writer.writeAll(version_str);
        try writer.writeByteNTimes(0, sig.utils.tar.paddingBytes(
            counting_writer_state.bytes_written,
        ));

        // create the snapshots dir
        try sig.utils.tar.writeTarHeader(writer, .directory, "snapshots/", 0);

        // write the status cache
        try sig.utils.tar.writeTarHeader(
            writer,
            .regular,
            "snapshots/status_cache",
            bincode.sizeOf(status_cache, .{}),
        );
        try bincode.write(writer, status_cache, .{});
        try writer.writeByteNTimes(0, sig.utils.tar.paddingBytes(
            counting_writer_state.bytes_written,
        ));

        // write the manifest
        const dir_name_bounded = sig.utils.fmt.boundedFmt("snapshots/{d}/", .{slot});
        try sig.utils.tar.writeTarHeader(writer, .directory, dir_name_bounded.constSlice(), 0);

        const file_name_bounded = sig.utils.fmt.boundedFmt("snapshots/{0d}/{0d}", .{slot});
        try sig.utils.tar.writeTarHeader(
            writer,
            .regular,
            file_name_bounded.constSlice(),
            bincode.sizeOf(manifest, .{}),
        );
        try bincode.write(writer, manifest, .{});
        try writer.writeByteNTimes(0, sig.utils.tar.paddingBytes(
            counting_writer_state.bytes_written,
        ));

        std.debug.assert(counting_writer_state.bytes_written % 512 == 0);
    }

    /// Writes the accounts dir header. Do this after writing the metadata files.
    pub fn writeAccountsDirHeader(archive_writer: anytype) !void {
        try sig.utils.tar.writeTarHeader(archive_writer, .directory, "accounts/", 0);
    }

    /// Writes the account file header - follow this up by writing the file content to `archive_writer`,
    /// and then follow that up with `writeAccountFilePadding(archive_writer, file_info.length)`.
    /// Do this for each account file included in the snapshot.
    pub fn writeAccountFileHeader(
        archive_writer: anytype,
        file_slot: Slot,
        file_info: AccountFileInfo,
    ) !void {
        const name_bounded = sig.utils.fmt.boundedFmt(
            "accounts/{d}.{d}",
            .{ file_slot, file_info.id.toInt() },
        );
        try sig.utils.tar.writeTarHeader(
            archive_writer,
            .regular,
            name_bounded.constSlice(),
            file_info.length,
        );
    }

    pub fn writeAccountFilePadding(archive_writer: anytype, file_length: usize) !void {
        try archive_writer.writeByteNTimes(0, sig.utils.tar.paddingBytes(file_length));
    }
};

/// unpacks a .tar.zstd file into the given directory
pub fn parallelUnpackZstdTarBall(
    allocator: std.mem.Allocator,
    logger: Logger,
    file: std.fs.File,
    output_dir: std.fs.Dir,
    n_threads: usize,
    /// only used for progress estimation
    full_snapshot: bool,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "accountsdb parallelUnpackZstdTarBall" });
    defer zone.deinit();

    const file_size = (try file.stat()).size;

    // calling posix.mmap on a zero-sized file will cause illegal behaviour
    if (file_size == 0) return error.ZeroSizedTarball;

    // TODO: improve `zstd.Reader` to be capable of sourcing a stream of bytes
    // rather than a fixed slice of bytes, so we don't have to load the entire
    // snapshot file into memory.
    const memory = try std.posix.mmap(
        null,
        file_size,
        std.posix.PROT.READ,
        std.posix.MAP{ .TYPE = .PRIVATE },
        file.handle,
        0,
    );
    defer std.posix.munmap(memory);

    if (@import("builtin").os.tag != .macos) {
        try std.posix.madvise(
            memory.ptr,
            memory.len,
            std.posix.MADV.SEQUENTIAL | std.posix.MADV.WILLNEED,
        );
    }

    var tar_stream = try zstd.Reader.init(memory);
    defer tar_stream.deinit();
    const n_files_estimate: usize = if (full_snapshot) 421_764 else 100_000; // estimate

    try sig.utils.tar.parallelUntarToFileSystem(
        allocator,
        .from(logger),
        output_dir,
        tar_stream.reader(),
        n_threads,
        n_files_estimate,
    );
}

test FullSnapshotFileInfo {
    try testFullSnapshotFileInfo("snapshot-10-11111111111111111111111111111111.tar.zst", .{
        .slot = 10,
        .hash = Hash.ZEROES,
    });

    const snapshot_name = "snapshot-269-EAHHZCVccCdAoCXH8RWxvv9edcwjY2boqni9MJuh3TCn.tar.zst";
    const snapshot_info = try FullSnapshotFileInfo.parseFileNameTarZst(snapshot_name);

    try std.testing.expectEqual(269, snapshot_info.slot);
    try std.testing.expectEqualStrings(
        "EAHHZCVccCdAoCXH8RWxvv9edcwjY2boqni9MJuh3TCn",
        snapshot_info.hash.base58String().constSlice(),
    );

    try std.testing.expectEqualStrings(
        snapshot_name,
        snapshot_info.snapshotArchiveName().constSlice(),
    );
}

fn testFullSnapshotFileInfo(expected: []const u8, info: FullSnapshotFileInfo) !void {
    const name_bounded = info.snapshotArchiveName();
    try std.testing.expectEqualStrings(expected, name_bounded.constSlice());
}

test IncrementalSnapshotFileInfo {
    try testIncrementalSnapshotFileInfo(
        "incremental-snapshot-10-25-11111111111111111111111111111111.tar.zst",
        .{ .base_slot = 10, .slot = 25, .hash = Hash.ZEROES },
    );

    const snapshot_name =
        "incremental-snapshot-269-307-4JLFzdaaqkSrmHs55bBDhZrQjHYZvqU1vCcQ5mP22pdB.tar.zst";
    const snapshot_info = try IncrementalSnapshotFileInfo.parseFileNameTarZst(snapshot_name);

    try std.testing.expectEqual(269, snapshot_info.base_slot);
    try std.testing.expectEqual(307, snapshot_info.slot);
    try std.testing.expectEqualStrings(
        "4JLFzdaaqkSrmHs55bBDhZrQjHYZvqU1vCcQ5mP22pdB",
        snapshot_info.hash.base58String().constSlice(),
    );

    try std.testing.expectEqualStrings(
        snapshot_name,
        snapshot_info.snapshotArchiveName().constSlice(),
    );
}

fn testIncrementalSnapshotFileInfo(expected: []const u8, info: IncrementalSnapshotFileInfo) !void {
    const name_bounded = info.snapshotArchiveName();
    try std.testing.expectEqualStrings(expected, name_bounded.constSlice());
}

test "parse status cache" {
    const allocator = std.testing.allocator;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapdir = tmp_dir_root.dir;

    _ = try sig.accounts_db.db.findAndUnpackTestSnapshots(1, snapdir);

    const status_cache_file = try snapdir.openFile("snapshots/status_cache", .{});
    defer status_cache_file.close();

    const status_cache = try StatusCache.readFromFile(allocator, status_cache_file);
    defer status_cache.deinit(allocator);

    try std.testing.expect(status_cache.bank_slot_deltas.len > 0);
}

test "parse snapshot fields" {
    const allocator = std.testing.allocator;

    var tmp_dir_root = std.testing.tmpDir(.{});
    defer tmp_dir_root.cleanup();
    const snapdir = tmp_dir_root.dir;

    const snapshot_files = try sig.accounts_db.db.findAndUnpackTestSnapshots(1, snapdir);

    const full_slot = snapshot_files.full.slot;
    const full_manifest_path_bounded = sig.utils.fmt.boundedFmt("snapshots/{0}/{0}", .{full_slot});
    const full_manifest_path = full_manifest_path_bounded.constSlice();

    const full_manifest_file = try snapdir.openFile(full_manifest_path, .{});
    defer full_manifest_file.close();

    const full_manifest = try Manifest.readFromFile(allocator, full_manifest_file);
    defer full_manifest.deinit(allocator);

    if (snapshot_files.incremental_info) |inc| {
        const inc_slot = inc.slot;
        const inc_manifest_path_bounded = sig.utils.fmt.boundedFmt(
            "snapshots/{0}/{0}",
            .{inc_slot},
        );
        const inc_manifest_path = inc_manifest_path_bounded.constSlice();

        const inc_manifest_file = try snapdir.openFile(inc_manifest_path, .{});
        defer inc_manifest_file.close();

        const inc_manifest = try Manifest.readFromFile(allocator, inc_manifest_file);
        defer inc_manifest.deinit(allocator);
    }
}
