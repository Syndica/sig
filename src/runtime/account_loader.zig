const std = @import("std");
const sig = @import("../sig.zig");
const runtime = sig.runtime;

const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const RentCollector = sig.core.rent_collector.RentCollector;
const RENT_EXEMPT_RENT_EPOCH = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH;
const CollectedInfo = sig.core.rent_collector.CollectedInfo;

const AccountSharedData = runtime.AccountSharedData;
const ComputeBudgetLimits = runtime.program.compute_budget.ComputeBudgetLimits;
const RuntimeTransaction = runtime.transaction_execution.RuntimeTransaction;
const TransactionResult = runtime.transaction_execution.TransactionResult;

// [firedancer] https://github.com/firedancer-io/firedancer/blob/ddde57c40c4d4334c25bb32de17f833d4d79a889/src/ballet/txn/fd_txn.h#L116
pub const MAX_TX_ACCOUNT_LOCKS = 128;

pub const AccountsDbKind = enum {
    AccountsDb,
    Mocked,

    pub fn T(self: AccountsDbKind) type {
        return switch (self) {
            .AccountsDb => *sig.accounts_db.AccountsDB,
            .Mocked => MockedAccountsDb,
        };
    }
};

pub const MockedAccountsDb = struct {
    allocator: std.mem.Allocator,
    accounts: std.AutoArrayHashMapUnmanaged(Pubkey, sig.core.Account) = .{},

    fn deinit(self: *MockedAccountsDb) void {
        self.accounts.deinit(self.allocator);
    }
};

/// Wraps over real & mocked accountsdb implementations
fn AccountsDb(comptime kind: AccountsDbKind) type {
    return struct {
        inner: kind.T(),
        const Self = @This();

        fn allocator(self: Self) std.mem.Allocator {
            return switch (kind) {
                .AccountsDb => self.inner.accounts_db.allocator,
                .Mocked => self.inner.allocator,
            };
        }

        fn getAccount(
            self: Self,
            pubkey: *const Pubkey,
        ) sig.accounts_db.AccountsDB.GetAccountError!sig.core.Account {
            return switch (kind) {
                .AccountsDb => try self.inner.accounts_db.getAccount(pubkey),
                .Mocked => self.inner.accounts.get(pubkey.*) orelse return error.PubkeyNotInIndex,
            };
        }

        fn getAccountSharedData(
            self: Self,
            data_allocator: std.mem.Allocator,
            pubkey: *const Pubkey,
        ) error{ OutOfMemory, GetAccountFailedUnexpectedly }!?AccountSharedData {
            const account: sig.core.Account = self.getAccount(pubkey) catch |err| switch (err) {
                error.PubkeyNotInIndex => return null,
                error.OutOfMemory => return error.OutOfMemory,
                error.FileIdNotFound,
                error.InvalidOffset,
                error.SlotNotFound,
                => return error.GetAccountFailedUnexpectedly,
            };
            defer account.deinit(self.allocator());

            const shared_account: AccountSharedData = .{
                .data = try account.data.readAllAllocate(data_allocator),
                .executable = account.executable,
                .lamports = account.lamports,
                .owner = account.owner,
                .rent_epoch = account.rent_epoch,
            };

            return shared_account;
        }
    };
}

pub const RentDebit = struct { rent_collected: u64, rent_balance: u64 };

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L417
/// agave's LoadedTransactionAccounts contains a field "program indices". This has been omitted as
/// it's a Vec<Vec<u8>> whose elements are either [program_id] or [] (when program_id is the native
/// loader), which seems pointless.
pub const LoadedTransactionAccounts = struct {
    /// data owned by BatchAccountCache
    accounts: std.BoundedArray(CachedAccount, MAX_TX_ACCOUNT_LOCKS),
    /// equal len to .accounts
    rent_debits: std.BoundedArray(RentDebit, MAX_TX_ACCOUNT_LOCKS),

    rent_collected: u64,
    loaded_accounts_data_size: u32,

    const DEFAULT: LoadedTransactionAccounts = .{
        .accounts = .{},
        .rent_debits = .{},
        .rent_collected = 0,
        .loaded_accounts_data_size = 0,
    };
};

pub const CachedAccount = struct {
    pubkey: Pubkey,
    account: *AccountSharedData,
};

/// Implements much of Agave's AccountLoader functionality. Owns the accounts it loads.
// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L154
pub const BatchAccountCache = struct {
    /// pubkey -> AccountSharedData for all pubkeys *except* SYSVAR_INSTRUCTIONS_ID, which is a
    /// special case (constructed on a per-transaction basis)
    account_cache: AccountMap = .{},

    // holds SYSVAR_INSTRUCTIONS_ID accounts, purely so we can deallocate them later. Index of each
    // one isn't intended to be meaningful.
    // NOTE: we could take this field out, and have the caller deinit it from inside LoadedTransactionAccounts
    sysvar_instruction_account_datas: std.ArrayListUnmanaged(AccountSharedData) = .{},

    // NOTE: we might want to later add another field that keeps a copy of all writable accounts.

    pub const AccountMap = std.AutoArrayHashMapUnmanaged(
        Pubkey,
        AccountSharedData,
    );

    /// Eagerly loads accounts from accounts db. Assumes the best, and will not report errors.
    /// Error reporting is deferred until accounts are loaded from BatchAccountCache.
    /// No rent collection is performed.
    pub fn initFromAccountsDb(
        comptime accountsdb_kind: AccountsDbKind,
        allocator: std.mem.Allocator,
        accountsdb: accountsdb_kind.T(),
        transactions: []const RuntimeTransaction,
    ) !BatchAccountCache {
        const accounts_db = AccountsDb(accountsdb_kind){ .inner = accountsdb };

        // we assume the largest is allowed
        const max_data_len = sig.runtime.program.compute_budget.MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES;

        const max_map_entries = total_account_keys: {
            var n: usize = 0;
            for (transactions) |tx| n += tx.accounts.len;
            for (transactions) |tx| n += tx.instruction_infos.len; // for instr program owner accounts
            break :total_account_keys n;
        };

        // optimisation: we could also keep per-tx indexes to remove reliance on hashmap get
        var map: AccountMap = .{};
        errdefer map.deinit(allocator);
        try map.ensureUnusedCapacity(allocator, max_map_entries);

        const transactions_data_loaded = try allocator.alloc(u32, transactions.len);
        defer allocator.free(transactions_data_loaded);
        @memset(transactions_data_loaded, 0);

        // load txes account_keys
        next_tx: for (transactions, transactions_data_loaded) |*tx, *tx_data_loaded| {
            for (tx.accounts.items(.pubkey)) |account_key| {
                if (account_key.equals(&sig.runtime.ids.SYSVAR_INSTRUCTIONS_ID)) {
                    // this code is special, and requires constructing per-transaction accounts,
                    // which we will not perform in advance.
                    @branchHint(.unlikely);
                    continue;
                }

                var created_new_account: bool = false;
                const account = if (map.get(account_key)) |acc| acc else blk: {
                    if (try accounts_db.getAccountSharedData(
                        allocator,
                        &account_key,
                    )) |acc| {
                        map.putAssumeCapacityNoClobber(account_key, acc);
                        break :blk acc;
                    } else {
                        // account not found, create a new one at this address
                        const account = AccountSharedData.NEW;
                        map.putAssumeCapacityNoClobber(account_key, account);
                        created_new_account = true;
                        break :blk account;
                    }
                };

                if (!created_new_account) std.debug.assert(account.lamports > 0); // this account should be gone?

                accumulateAndCheckLoadedAccountDataSize(
                    tx_data_loaded,
                    account.data.len,
                    max_data_len,
                ) catch continue :next_tx; // tx will fail - loaded too much
            }
        }

        var validated_loaders = std.AutoArrayHashMap(Pubkey, void).init(allocator);
        defer validated_loaders.deinit();

        // load tx instruction's program account + its owner
        next_tx: for (transactions) |tx| {
            try validated_loaders.ensureTotalCapacity(tx.instruction_infos.len);
            defer validated_loaders.clearRetainingCapacity();
            var tx_loaded_account_data_len: u32 = 0;

            for (tx.instruction_infos) |instr| {
                const program_key = tx.accounts.items(
                    .pubkey,
                )[instr.program_meta.index_in_transaction];
                if (program_key.equals(&runtime.ids.NATIVE_LOADER_ID)) continue;
                const program_account = map.get(program_key) orelse
                    unreachable; // safe: we loaded all accounts in the previous loop

                const program_owner_key = &program_account.owner;

                if (validated_loaders.contains(program_owner_key.*))
                    continue; // already loaded + counted program account's owner

                const owner_account = if (map.get(program_owner_key.*)) |owner| owner else blk: {
                    const owner_account = try accounts_db.getAccountSharedData(
                        allocator,
                        program_owner_key,
                    ) orelse {
                        // default account ~= account missing
                        // every account which a load is attempted on should have an entry
                        map.putAssumeCapacityNoClobber(program_owner_key.*, AccountSharedData.NEW);
                        continue :next_tx; // tx will fail - can't get account
                    };

                    map.putAssumeCapacityNoClobber(program_owner_key.*, owner_account);

                    break :blk owner_account;
                };

                accumulateAndCheckLoadedAccountDataSize(
                    &tx_loaded_account_data_len,
                    owner_account.data.len,
                    max_data_len,
                ) catch
                    continue :next_tx; // tx will fail - accounts data too large

                try validated_loaders.put(program_owner_key.*, {});
            }
        }

        return .{ .account_cache = map };
    }

    pub fn deinit(self: *BatchAccountCache, allocator: std.mem.Allocator) void {
        for (self.account_cache.values()) |account|
            allocator.free(account.data);
        self.account_cache.deinit(allocator);
        for (self.sysvar_instruction_account_datas.items) |account|
            allocator.free(account.data);
        self.sysvar_instruction_account_datas.deinit(allocator);
    }

    const LoadedTransactionAccountsError = error{
        OutOfMemory,
        ProgramAccountNotFound,
        InvalidProgramForExecution,
        MaxLoadedAccountsDataSizeExceeded,
    };

    /// Assumes `transaction` was in initFromAccountsDb's `transactions` parameter.
    /// Reports account loading errors.
    /// By the time this is called, we have no dependency on accountsdb.
    pub fn loadTransactionAccounts(
        // note: think we make this a *const by moving sysvar instruction account construction into init
        self: *BatchAccountCache,
        allocator: std.mem.Allocator,
        transaction: *const RuntimeTransaction,
        rent_collector: *const RentCollector,
        feature_set: *const runtime.FeatureSet,
        compute_budget_limits: *const ComputeBudgetLimits,
    ) error{OutOfMemory}!TransactionResult(LoadedTransactionAccounts) {
        const result = loadTransactionAccountsInner(
            self,
            allocator,
            transaction,
            rent_collector,
            feature_set,
            compute_budget_limits,
        ) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.ProgramAccountNotFound => .{ .err = .ProgramAccountNotFound },
            error.InvalidProgramForExecution => .{ .err = .InvalidProgramForExecution },
            error.MaxLoadedAccountsDataSizeExceeded => .{
                .err = .MaxLoadedAccountsDataSizeExceeded,
            },
        };

        return .{ .ok = result };
    }

    fn loadTransactionAccountsInner(
        self: *BatchAccountCache,
        allocator: std.mem.Allocator,
        transaction: *const RuntimeTransaction,
        rent_collector: *const RentCollector,
        feature_set: *const runtime.FeatureSet,
        compute_budget_limits: *const ComputeBudgetLimits,
    ) LoadedTransactionAccountsError!LoadedTransactionAccounts {
        if (compute_budget_limits.loaded_accounts_bytes == 0)
            unreachable; // in agave this is sanitized somewhere prior to this

        var loaded = LoadedTransactionAccounts.DEFAULT;

        const accounts = transaction.accounts.slice();
        for (accounts.items(.pubkey), accounts.items(.is_writable)) |account_key, is_writable| {
            const loaded_account = try self.loadTransactionAccount(
                allocator,
                transaction,
                rent_collector,
                feature_set,
                &account_key,
                is_writable,
            );

            try accumulateAndCheckLoadedAccountDataSize(
                &loaded.loaded_accounts_data_size,
                loaded_account.loaded_size,
                compute_budget_limits.loaded_accounts_bytes,
            );

            loaded.rent_collected += loaded_account.rent_collected;
            loaded.rent_debits.appendAssumeCapacity(.{
                .rent_balance = loaded_account.account.lamports,
                .rent_collected = loaded_account.rent_collected,
            });
            loaded.accounts.appendAssumeCapacity(.{
                .account = loaded_account.account,
                .pubkey = account_key,
            });
        }

        var validated_loaders = std.AutoArrayHashMap(Pubkey, void).init(allocator);
        defer validated_loaders.deinit();

        for (transaction.instruction_infos) |instr| {
            const program_id = &instr.program_meta.pubkey;
            if (program_id.equals(&runtime.ids.NATIVE_LOADER_ID)) continue;
            const program_account = (try loadAccount(
                self,
                allocator,
                transaction,
                program_id,
                false,
            )) orelse return error.ProgramAccountNotFound;

            if (!feature_set.active.contains(
                sig.runtime.features.REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS,
            ) and !program_account.account.executable) return error.InvalidProgramForExecution;

            const owner_id = &program_account.account.owner;

            const owner_account = account: {
                if (owner_id.equals(&runtime.ids.NATIVE_LOADER_ID)) continue;
                if (validated_loaders.contains(owner_id.*)) continue; // only load + count owners once

                break :account (try self.loadAccount(allocator, transaction, owner_id, false)) orelse
                    return error.InvalidProgramForExecution;
            };

            if (!owner_account.account.owner.equals(&runtime.ids.NATIVE_LOADER_ID)) {
                return error.InvalidProgramForExecution;
            }

            try accumulateAndCheckLoadedAccountDataSize(
                &loaded.loaded_accounts_data_size,
                owner_account.loaded_size,
                compute_budget_limits.loaded_accounts_bytes,
            );

            try validated_loaders.put(owner_id.*, {});
        }

        return loaded;
    }

    const LoadedTransactionAccount = struct {
        account: *AccountSharedData,
        loaded_size: usize,
        rent_collected: u64,

        const DEFAULT: LoadedTransactionAccount = .{
            .account = .{
                .lamports = 0,
                .data = &.{},
                .owner = Pubkey.ZEROES,
                .executable = false,
                .rent_epoch = RENT_EXEMPT_RENT_EPOCH,
            },
            .loaded_size = 0,
            .rent_collected = 0,
        };
    };

    fn loadTransactionAccount(
        self: *BatchAccountCache,
        allocator: std.mem.Allocator,
        transaction: *const RuntimeTransaction,
        rent_collector: *const RentCollector,
        feature_set: *const runtime.FeatureSet,
        key: *const Pubkey,
        is_writable: bool,
    ) error{OutOfMemory}!LoadedTransactionAccount {
        if (key.equals(&runtime.ids.SYSVAR_INSTRUCTIONS_ID)) {
            @branchHint(.unlikely);
            const account = try self.sysvar_instruction_account_datas.addOne(allocator);
            account.* = try constructInstructionsAccount(allocator, transaction);
            return .{
                .account = account,
                .loaded_size = 0,
                .rent_collected = 0,
            };
        }

        const account = (try self.loadAccount(allocator, transaction, key, is_writable)) orelse {
            // a previous instruction deallocated this account, we will make a new one in its place.

            var account = AccountSharedData.EMPTY;
            account.rent_epoch = RENT_EXEMPT_RENT_EPOCH;

            const result = self.account_cache.getOrPutAssumeCapacity(key.*);
            std.debug.assert(result.found_existing);

            result.value_ptr.* = account;

            return LoadedTransactionAccount{
                .account = result.value_ptr,
                .loaded_size = 0,
                .rent_collected = 0,
            };
        };

        const rent_collected = collectRentFromAccount(
            account.account,
            key,
            feature_set,
            rent_collector,
        );

        return .{
            .account = account.account,
            .loaded_size = account.account.data.len,
            .rent_collected = rent_collected.rent_amount,
        };
    }

    /// null return => account is now dead
    fn loadAccount(
        self: *BatchAccountCache,
        allocator: std.mem.Allocator,
        transaction: *const RuntimeTransaction,
        key: *const Pubkey,
        is_writable: bool,
    ) error{OutOfMemory}!?LoadedTransactionAccount {
        const maybe_account: ?*AccountSharedData = if (key.equals(
            &runtime.ids.SYSVAR_INSTRUCTIONS_ID,
        )) account: {
            @branchHint(.unlikely);
            const account = try self.sysvar_instruction_account_datas.addOne(allocator);
            account.* = try constructInstructionsAccount(allocator, transaction);
            break :account account;
        } else self.account_cache.getPtr(key.*);

        const account = maybe_account orelse unreachable; // all keys should be already there
        if (account.lamports == 0) {
            // a previous instr deallocated this account
            allocator.free(account.data);
            return null;
        }

        // agave "inspects" the account here, which caches the initial state of writeable accounts
        // TODO: we should probably do this at init time
        _ = is_writable;

        return .{
            .account = account,
            .loaded_size = account.data.len,
            .rent_collected = 0,
        };
    }
};

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L293
fn collectRentFromAccount(
    account: *AccountSharedData,
    account_key: *const Pubkey,
    feature_set: *const runtime.FeatureSet,
    rent_collector: *const RentCollector,
) CollectedInfo {
    if (!feature_set.active.contains(runtime.features.DISABLE_RENT_FEES_COLLECTION)) {
        @branchHint(.unlikely); // this feature should always be enabled?
        return rent_collector.collectFromExistingAccount(account_key, account);
    }

    if (account.rent_epoch != RENT_EXEMPT_RENT_EPOCH and
        rent_collector.getRentDue(
            account.lamports,
            account.data.len,
            account.rent_epoch,
        ) != .Exempt)
    {
        account.rent_epoch = RENT_EXEMPT_RENT_EPOCH;
    }

    return CollectedInfo.NoneCollected;
}

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L618
fn accumulateAndCheckLoadedAccountDataSize(
    accumulated_loaded_accounts_data_size: *u32,
    account_data_size: usize,
    /// non-zero
    requested_loaded_accounts_data_size_limit: u32,
) error{MaxLoadedAccountsDataSizeExceeded}!void {
    const account_data_sz = std.math.cast(u32, account_data_size) orelse
        return error.MaxLoadedAccountsDataSizeExceeded;

    accumulated_loaded_accounts_data_size.* +|= account_data_sz;

    if (accumulated_loaded_accounts_data_size.* > requested_loaded_accounts_data_size_limit) {
        return error.MaxLoadedAccountsDataSizeExceeded;
    }
}

// [agave] https://github.com/anza-xyz/agave/blob/cb32984a9b0d5c2c6f7775bed39b66d3a22e3c46/svm/src/account_loader.rs#L639
fn constructInstructionsAccount(
    allocator: std.mem.Allocator,
    transaction: *const RuntimeTransaction,
) error{OutOfMemory}!AccountSharedData {
    const Instruction = sig.core.Instruction;
    const InstructionAccount = sig.core.instruction.InstructionAccount;

    var decompiled_instructions = try std.ArrayList(Instruction).initCapacity(
        allocator,
        transaction.instruction_infos.len,
    );
    defer {
        for (decompiled_instructions.items) |decompiled| allocator.free(decompiled.accounts);
        decompiled_instructions.deinit();
    }

    const tx_accounts = transaction.accounts.slice();

    for (transaction.instruction_infos) |instruction| {
        const accounts_meta = try allocator.alloc(
            InstructionAccount,
            instruction.account_metas.len,
        );
        errdefer allocator.free(accounts_meta);

        for (instruction.account_metas.slice(), accounts_meta) |account_meta, *new_account_meta| {
            new_account_meta.* = .{
                .pubkey = tx_accounts.items(.pubkey)[account_meta.index_in_transaction],
                .is_signer = tx_accounts.items(.is_signer)[account_meta.index_in_transaction],
                .is_writable = tx_accounts.items(.is_writable)[account_meta.index_in_transaction],
            };
        }

        decompiled_instructions.appendAssumeCapacity(.{
            .accounts = accounts_meta,
            .data = instruction.instruction_data,
            .program_id = tx_accounts.items(.pubkey)[instruction.program_meta.index_in_transaction],
        });
    }

    // [agave] https://github.com/anza-xyz/solana-sdk/blob/0fbfb7d1467c1ab0c35e1a3b905b8ba0ac0bf538/instructions-sysvar/src/lib.rs#L68
    var data = try runtime.sysvar.instruction.serializeInstructions(
        allocator,
        decompiled_instructions.items,
    );
    defer data.deinit();
    try data.appendSlice(&.{ 0, 0 }); // room for current instruction index

    return .{
        .data = try data.toOwnedSlice(),
        .owner = runtime.ids.SYSVAR_INSTRUCTIONS_ID,
        .lamports = 0, // a bit weird, but seems correct
        .executable = false,
        .rent_epoch = 0,
    };
}

const TestingEnv = struct {
    rent_collector: RentCollector,
    feature_set: runtime.FeatureSet,
    compute_budget_limits: ComputeBudgetLimits,
};

fn newTestingEnv() TestingEnv {
    if (!@import("builtin").is_test) @compileError("newTestingEnv for testing only");
    return .{
        .rent_collector = sig.core.rent_collector.defaultCollector(0),
        .feature_set = sig.runtime.FeatureSet.EMPTY,
        .compute_budget_limits = ComputeBudgetLimits{
            .heap_size = 0,
            .compute_unit_limit = 0,
            .compute_unit_price = 0,
            .loaded_accounts_bytes = 1_000,
        },
    };
}

fn emptyTxWithKeys(allocator: std.mem.Allocator, keys: []const Pubkey) !RuntimeTransaction {
    if (!@import("builtin").is_test) @compileError("transactionWithKeys for testing only");

    var accounts = RuntimeTransaction.Accounts{};
    errdefer accounts.deinit(allocator);
    for (keys) |key| {
        try accounts.append(allocator, .{
            .pubkey = key,
            .is_signer = false,
            .is_writable = false,
        });
    }

    return .{
        .signature_count = 0,
        .fee_payer = Pubkey.ZEROES,
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = Hash.ZEROES,
        .instruction_infos = &.{},
        .accounts = accounts,
    };
}

test "loadTransactionAccounts empty transaction" {
    const allocator = std.testing.allocator;
    const accountsdb = MockedAccountsDb{ .allocator = allocator };
    const env = newTestingEnv();

    var batch_account_cache = try BatchAccountCache.initFromAccountsDb(
        .Mocked,
        allocator,
        accountsdb,
        &.{},
    );
    defer batch_account_cache.deinit(allocator);

    const empty_tx = RuntimeTransaction{
        .fee_payer = Pubkey.ZEROES,
        .instruction_infos = &.{},
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = Hash.ZEROES,
        .signature_count = 0,
    };

    const tx_accounts = try batch_account_cache.loadTransactionAccountsInner(
        allocator,
        &empty_tx,
        &env.rent_collector,
        &env.feature_set,
        &env.compute_budget_limits,
    );

    try std.testing.expectEqual(0, tx_accounts.accounts.len);
}

test "loadTransactionAccounts sysvar instruction" {
    const allocator = std.testing.allocator;
    const accountsdb = MockedAccountsDb{ .allocator = allocator };
    const env = newTestingEnv();

    var batch_account_cache = try BatchAccountCache.initFromAccountsDb(
        .Mocked,
        allocator,
        accountsdb,
        &.{},
    );
    defer batch_account_cache.deinit(allocator);

    var accounts = RuntimeTransaction.Accounts{};
    defer accounts.deinit(allocator);
    try accounts.append(allocator, sig.core.instruction.InstructionAccount{
        .pubkey = runtime.ids.SYSVAR_INSTRUCTIONS_ID,
        .is_signer = false,
        .is_writable = false,
    });

    const empty_tx = RuntimeTransaction{
        .fee_payer = Pubkey.ZEROES,
        .instruction_infos = &.{},
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = Hash.ZEROES,
        .signature_count = 0,
        .accounts = accounts,
    };

    const tx_accounts = try batch_account_cache.loadTransactionAccountsInner(
        allocator,
        &empty_tx,
        &env.rent_collector,
        &env.feature_set,
        &env.compute_budget_limits,
    );

    try std.testing.expectEqual(1, tx_accounts.accounts.len);
    const cached_account = tx_accounts.accounts.slice()[0];

    try std.testing.expect(cached_account.account.data.len > 0);
    try std.testing.expectEqual(0, tx_accounts.rent_collected);
    try std.testing.expectEqual(0, tx_accounts.loaded_accounts_data_size);
    try std.testing.expectEqual(1, tx_accounts.rent_debits.len);
    const rent_debit: RentDebit = tx_accounts.rent_debits.slice()[0];

    // maybe interesting? Most program accounts have 1 lamports. But this one is even less "real"
    // than the others
    try std.testing.expectEqual(0, rent_debit.rent_balance);
    try std.testing.expectEqual(0, rent_debit.rent_collected);
}

test "accumulated size" {
    const requested_data_size_limit = 123;

    var accumulated_size: u32 = 0;
    try accumulateAndCheckLoadedAccountDataSize(
        &accumulated_size,
        requested_data_size_limit,
        requested_data_size_limit,
    );

    try std.testing.expectEqual(requested_data_size_limit, accumulated_size);

    // exceed limit
    try std.testing.expectError(
        error.MaxLoadedAccountsDataSizeExceeded,
        accumulateAndCheckLoadedAccountDataSize(
            &accumulated_size,
            1,
            requested_data_size_limit,
        ),
    );
}

test "load accounts rent paid" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    var accountsdb = MockedAccountsDb{ .allocator = allocator };
    defer accountsdb.deinit();
    var env = newTestingEnv();
    env.compute_budget_limits.loaded_accounts_bytes = 2_000;

    const NATIVE_LOADER_ID = runtime.ids.NATIVE_LOADER_ID;

    const fee_payer_address = Pubkey.initRandom(prng.random());
    const instruction_address = Pubkey.initRandom(prng.random());

    const instruction_data = "dummy instruction";

    const fee_payer_balance = 300;
    var fee_payer_account = AccountSharedData.EMPTY;
    fee_payer_account.lamports = fee_payer_balance;

    var data: [1024]u8 = undefined;
    prng.fill(&data);

    try accountsdb.accounts.put(allocator, fee_payer_address, .{
        .data = .{ .unowned_allocation = &data },
        .lamports = fee_payer_balance,
        .executable = false,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });

    try accountsdb.accounts.put(allocator, instruction_address, .{
        .data = .{ .unowned_allocation = instruction_data },
        .lamports = 1,
        .executable = true,
        .owner = NATIVE_LOADER_ID,
        .rent_epoch = 0,
    });
    try accountsdb.accounts.put(allocator, NATIVE_LOADER_ID, .{
        .data = .{ .empty = .{ .len = 0 } },
        .lamports = 1,
        .executable = true,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });
    try accountsdb.accounts.put(allocator, Pubkey.ZEROES, .{
        .data = .{ .empty = .{ .len = 0 } },
        .lamports = 0,
        .executable = true,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });

    var tx = try emptyTxWithKeys(allocator, &.{ fee_payer_address, instruction_address });
    defer tx.accounts.deinit(allocator);

    tx.instruction_infos = &.{
        .{
            .program_meta = .{ .pubkey = instruction_address, .index_in_transaction = 1 },
            .account_metas = try sig.runtime.InstructionInfo.AccountMetas.fromSlice(
                &.{
                    .{
                        .pubkey = fee_payer_address,
                        .index_in_transaction = 0,
                        .index_in_caller = 0,
                        .index_in_callee = 0,
                        .is_signer = true,
                        .is_writable = true,
                    },
                    .{
                        .pubkey = instruction_address,
                        .index_in_transaction = 1,
                        .index_in_caller = 1,
                        .index_in_callee = 1,
                        .is_signer = false,
                        .is_writable = false,
                    },
                },
            ),
            .instruction_data = "",
        },
    };

    var account_cache = try BatchAccountCache.initFromAccountsDb(
        .Mocked,
        allocator,
        accountsdb,
        &.{tx},
    );
    defer account_cache.deinit(allocator);

    const loaded_accounts = try account_cache.loadTransactionAccountsInner(
        allocator,
        &tx,
        &env.rent_collector,
        &env.feature_set,
        &env.compute_budget_limits,
    );

    // slots elapsed   slots per year    lamports per year
    //  |               |                 |      data len
    //  |               |                 |       |     overhead
    //  v               v                 v       v      v
    // ((64) / (7.8892314983999997e7)) * (3480 * (1024 + 128))
    const expected_rent = 3;
    try std.testing.expectEqual(2, loaded_accounts.accounts.len);
    try std.testing.expectEqual(expected_rent, loaded_accounts.rent_collected);
}

test "constructInstructionsAccount" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    var data: [1024]u8 = undefined;
    prng.fill(&data);

    const fee_payer_address = Pubkey.initRandom(prng.random());
    const instruction_address = Pubkey.initRandom(prng.random());

    var accounts = RuntimeTransaction.Accounts{};
    defer accounts.deinit(allocator);
    try accounts.append(allocator, sig.core.instruction.InstructionAccount{
        .pubkey = fee_payer_address,
        .is_signer = true,
        .is_writable = true,
    });
    try accounts.append(allocator, sig.core.instruction.InstructionAccount{
        .pubkey = instruction_address,
        .is_signer = false,
        .is_writable = false,
    });

    const empty_tx = RuntimeTransaction{
        .fee_payer = Pubkey.ZEROES,
        .instruction_infos = &.{
            .{
                .program_meta = .{ .pubkey = instruction_address, .index_in_transaction = 1 },
                .account_metas = .{},
                .instruction_data = "",
                .initial_account_lamports = 0,
            },
        },
        .msg_hash = Hash.ZEROES,
        .recent_blockhash = Hash.ZEROES,
        .signature_count = 1,
        .accounts = accounts,
    };

    const checkFn = struct {
        fn f(alloc: std.mem.Allocator, txn: *const RuntimeTransaction) !void {
            const account = try constructInstructionsAccount(alloc, txn);
            defer allocator.free(account.data);
        }
    }.f;

    try std.testing.checkAllAllocationFailures(allocator, checkFn, .{&empty_tx});

    const account = try constructInstructionsAccount(allocator, &empty_tx);
    defer allocator.free(account.data);
    try std.testing.expectEqual(0, account.lamports);
    try std.testing.expect(account.data.len > 8);
}

test "loadAccount allocations" {
    const allocator = std.testing.allocator;
    const NATIVE_LOADER_ID = runtime.ids.NATIVE_LOADER_ID;

    const checkFn = struct {
        fn f(alloc: std.mem.Allocator) !void {
            var accountsdb = MockedAccountsDb{ .allocator = alloc };
            defer accountsdb.deinit();

            try accountsdb.accounts.put(alloc, NATIVE_LOADER_ID, .{
                .data = .{ .empty = .{ .len = 0 } },
                .lamports = 1,
                .executable = true,
                .owner = Pubkey.ZEROES,
                .rent_epoch = 0,
            });

            var tx = try emptyTxWithKeys(alloc, &.{NATIVE_LOADER_ID});
            defer tx.accounts.deinit(alloc);

            var batch_account_cache = try BatchAccountCache.initFromAccountsDb(
                .Mocked,
                alloc,
                accountsdb,
                &.{tx},
            );
            defer batch_account_cache.deinit(alloc);

            const account = (try batch_account_cache.loadAccount(
                alloc,
                &tx,
                &NATIVE_LOADER_ID,
                false,
            )) orelse @panic("account not found");

            try std.testing.expectEqual(1, account.account.lamports);
            try std.testing.expectEqual(true, account.account.executable);
        }
    }.f;

    try std.testing.checkAllAllocationFailures(allocator, checkFn, .{});
}

test "load tx too large" {
    const allocator = std.testing.allocator;
    var accountsdb = MockedAccountsDb{ .allocator = allocator };
    defer accountsdb.deinit();
    var env = newTestingEnv();
    env.compute_budget_limits.loaded_accounts_bytes = 1000;

    var prng = std.Random.DefaultPrng.init(5083);
    const random = prng.random();

    const address = Pubkey.initRandom(random);

    // large account
    const account_data = try allocator.alloc(u8, 10 * 1024 * 1024);
    defer allocator.free(account_data);

    try accountsdb.accounts.put(allocator, address, .{
        .data = .{ .unowned_allocation = account_data },
        .lamports = 1_000_000,
        .executable = false,
        .owner = sig.runtime.program.system.ID,
        .rent_epoch = RENT_EXEMPT_RENT_EPOCH,
    });

    var tx = try emptyTxWithKeys(allocator, &.{address});
    defer tx.accounts.deinit(allocator);

    var account_cache = try BatchAccountCache.initFromAccountsDb(
        .Mocked,
        allocator,
        accountsdb,
        &.{tx},
    );
    defer account_cache.deinit(allocator);

    const loaded_accounts_result = account_cache.loadTransactionAccountsInner(
        allocator,
        &tx,
        &env.rent_collector,
        &env.feature_set,
        &env.compute_budget_limits,
    );

    try std.testing.expectError(error.MaxLoadedAccountsDataSizeExceeded, loaded_accounts_result);
}

test "dont double count program owner account data size" {
    const allocator = std.testing.allocator;
    var accountsdb = MockedAccountsDb{ .allocator = allocator };
    defer accountsdb.deinit();
    const env = newTestingEnv();
    var prng = std.Random.DefaultPrng.init(5083);
    const random = prng.random();

    const data1 = "data1"; // 5
    const data2 = "data2"; // 5
    const data_owner = "data_owner"; // 10
    const pk1 = Pubkey.initRandom(random);
    const pk2 = Pubkey.initRandom(random);
    const pk_owner = Pubkey.initRandom(random);

    // populate accountsdb
    try accountsdb.accounts.put(allocator, pk1, .{
        .data = .{ .unowned_allocation = data1 },
        .lamports = 1,
        .executable = true,
        .owner = pk_owner,
        .rent_epoch = 0,
    });
    try accountsdb.accounts.put(allocator, pk2, .{
        .data = .{ .unowned_allocation = data2 },
        .lamports = 1,
        .executable = true,
        .owner = pk_owner,
        .rent_epoch = 0,
    });
    try accountsdb.accounts.put(allocator, pk_owner, .{
        .data = .{ .unowned_allocation = data_owner },
        .lamports = 1,
        .executable = true,
        .owner = runtime.ids.NATIVE_LOADER_ID,
        .rent_epoch = 0,
    });

    // a transaction with two programs that share an owner
    // I kinda hate this init, it's very redundant
    var tx: RuntimeTransaction = blk: {
        var tx = try emptyTxWithKeys(allocator, &.{ pk1, pk2 });

        const metas = try sig.runtime.InstructionInfo.AccountMetas.fromSlice(
            &.{
                .{
                    .pubkey = pk1,
                    .index_in_transaction = 0,
                    .index_in_caller = 0,
                    .index_in_callee = 0,
                    .is_signer = false,
                    .is_writable = false,
                },
                .{
                    .pubkey = pk2,
                    .index_in_transaction = 1,
                    .index_in_caller = 1,
                    .index_in_callee = 1,
                    .is_signer = false,
                    .is_writable = false,
                },
            },
        );

        tx.instruction_infos = &.{
            .{
                .program_meta = .{ .pubkey = pk2, .index_in_transaction = 1 },
                .account_metas = metas,
                .instruction_data = "",
            },
            .{
                .program_meta = .{ .pubkey = pk1, .index_in_transaction = 0 },
                .account_metas = metas,
                .instruction_data = "",
            },
        };
        break :blk tx;
    };
    defer tx.accounts.deinit(allocator);

    var account_cache = try BatchAccountCache.initFromAccountsDb(
        .Mocked,
        allocator,
        accountsdb,
        &.{tx},
    );
    defer account_cache.deinit(allocator);

    const loaded_accounts = try account_cache.loadTransactionAccountsInner(
        allocator,
        &tx,
        &env.rent_collector,
        &env.feature_set,
        &env.compute_budget_limits,
    );

    try std.testing.expectEqual(
        data1.len + data2.len + data_owner.len, // owner counted once, not twice
        loaded_accounts.loaded_accounts_data_size,
    );
}

test "load, create new account" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const random = prng.random();
    const new_account_pk = Pubkey.initRandom(random);
    var accountsdb = MockedAccountsDb{ .allocator = allocator };
    defer accountsdb.deinit();
    const env = newTestingEnv();

    var tx = try emptyTxWithKeys(allocator, &.{new_account_pk});
    defer tx.accounts.deinit(allocator);

    var account_cache = try BatchAccountCache.initFromAccountsDb(
        .Mocked,
        allocator,
        accountsdb,
        &.{tx},
    );
    defer account_cache.deinit(allocator);

    const loaded_accounts = try account_cache.loadTransactionAccountsInner(
        allocator,
        &tx,
        &env.rent_collector,
        &env.feature_set,
        &env.compute_budget_limits,
    );

    try std.testing.expectEqual(1, loaded_accounts.accounts.len);
    try std.testing.expectEqual(0, loaded_accounts.rent_collected);
    try std.testing.expectEqual(0, loaded_accounts.accounts.slice()[0].account.lamports);
}

test "invalid program owner owner" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const random = prng.random();
    var accountsdb = MockedAccountsDb{ .allocator = allocator };
    defer accountsdb.deinit();
    const env = newTestingEnv();

    const instruction_address = Pubkey.initRandom(random);
    const instruction_owner = Pubkey.initRandom(random);
    const invalid_owner_owner = Pubkey.initRandom(random);

    try accountsdb.accounts.put(allocator, instruction_address, .{
        .data = .{ .empty = .{ .len = 0 } },
        .lamports = 1,
        .executable = true,
        .owner = instruction_owner,
        .rent_epoch = 0,
    });
    try accountsdb.accounts.put(allocator, instruction_owner, .{
        .data = .{ .empty = .{ .len = 0 } },
        .lamports = 1,
        .executable = true,
        .owner = invalid_owner_owner,
        .rent_epoch = 0,
    });

    var tx = try emptyTxWithKeys(allocator, &.{instruction_address});
    defer tx.accounts.deinit(allocator);
    tx.instruction_infos = &.{
        .{
            .program_meta = .{ .pubkey = instruction_address, .index_in_transaction = 0 },
            .account_metas = .{},
            .instruction_data = "",
            .initial_account_lamports = 0,
        },
    };

    var account_cache = try BatchAccountCache.initFromAccountsDb(
        .Mocked,
        allocator,
        accountsdb,
        &.{tx},
    );
    defer account_cache.deinit(allocator);

    const loaded_accounts_result = account_cache.loadTransactionAccountsInner(
        allocator,
        &tx,
        &env.rent_collector,
        &env.feature_set,
        &env.compute_budget_limits,
    );

    try std.testing.expectError(error.InvalidProgramForExecution, loaded_accounts_result);
}

test "missing program owner account" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const random = prng.random();
    var accountsdb = MockedAccountsDb{ .allocator = allocator };
    defer accountsdb.deinit();
    const env = newTestingEnv();

    const instruction_address = Pubkey.initRandom(random);
    const instruction_owner = Pubkey.initRandom(random);

    try accountsdb.accounts.put(allocator, instruction_address, .{
        .data = .{ .empty = .{ .len = 0 } },
        .lamports = 1,
        .executable = true,
        .owner = instruction_owner,
        .rent_epoch = 0,
    });

    var tx = try emptyTxWithKeys(allocator, &.{instruction_address});
    defer tx.accounts.deinit(allocator);
    tx.instruction_infos = &.{
        .{
            .program_meta = .{ .pubkey = instruction_address, .index_in_transaction = 0 },
            .account_metas = .{},
            .instruction_data = "",
            .initial_account_lamports = 0,
        },
    };

    var account_cache = try BatchAccountCache.initFromAccountsDb(
        .Mocked,
        allocator,
        accountsdb,
        &.{tx},
    );
    defer account_cache.deinit(allocator);

    const loaded_accounts_result = account_cache.loadTransactionAccountsInner(
        allocator,
        &tx,
        &env.rent_collector,
        &env.feature_set,
        &env.compute_budget_limits,
    );

    try std.testing.expectError(error.InvalidProgramForExecution, loaded_accounts_result);
}

test "deallocate account" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(5083);
    const random = prng.random();
    var accountsdb = MockedAccountsDb{ .allocator = allocator };
    defer accountsdb.deinit();
    const env = newTestingEnv();

    const dying_account = Pubkey.initRandom(random);

    try accountsdb.accounts.put(allocator, dying_account, .{
        .data = .{ .unowned_allocation = "this account will soon die, and so will this string" },
        .lamports = 100,
        .executable = false,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });

    var tx = try emptyTxWithKeys(allocator, &.{dying_account});
    defer tx.accounts.deinit(allocator);

    // load with the account being alive
    var account_cache = try BatchAccountCache.initFromAccountsDb(
        .Mocked,
        allocator,
        accountsdb,
        &.{tx},
    );
    defer account_cache.deinit(allocator);

    try std.testing.expect(account_cache.account_cache.get(dying_account).?.data.len > 0);

    // "previous transaction" makes the account dead
    account_cache.account_cache.getPtr(dying_account).?.lamports = 0;

    // load with the account being dead
    const loaded_accounts = try account_cache.loadTransactionAccountsInner(
        allocator,
        &tx,
        &env.rent_collector,
        &env.feature_set,
        &env.compute_budget_limits,
    );

    // newly created account is returned instead
    try std.testing.expectEqual(1, loaded_accounts.accounts.len);
    try std.testing.expectEqual(0, loaded_accounts.accounts.slice()[0].account.data.len);
    try std.testing.expectEqual(0, loaded_accounts.accounts.slice()[0].account.lamports);
}
