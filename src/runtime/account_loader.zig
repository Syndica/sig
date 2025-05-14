const std = @import("std");
const sig = @import("../sig.zig");
const runtime = sig.runtime;

const Pubkey = sig.core.Pubkey;
const AccountSharedData = runtime.AccountSharedData;
const Hash = sig.core.Hash;
const RuntimeTransaction = sig.runtime.transaction_execution.RuntimeTransaction;
const ComputeBudgetLimits = sig.runtime.program.compute_budget.ComputeBudgetLimits;
const Slot = sig.core.Slot;
const TransactionResult = sig.runtime.transaction_execution.TransactionResult;

// [firedancer] https://github.com/firedancer-io/firedancer/blob/ddde57c40c4d4334c25bb32de17f833d4d79a889/src/ballet/txn/fd_txn.h#L116
const MAX_TX_ACCOUNT_LOCKS = 128;

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
            pubkey: *const sig.core.Pubkey,
        ) sig.accounts_db.AccountsDB.GetAccountError!sig.core.Account {
            return switch (kind) {
                .AccountsDb => try self.inner.accounts_db.getAccount(pubkey),
                .Mocked => self.inner.accounts.get(pubkey.*) orelse return error.PubkeyNotInIndex,
            };
        }
        fn getAccountSharedData(
            self: Self,
            data_allocator: std.mem.Allocator,
            pubkey: *const sig.core.Pubkey,
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
    sysvar_instruction_account_datas: std.ArrayListUnmanaged([]const u8) = .{},

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
                    @setCold(true);
                    continue;
                }

                const account = if (map.get(account_key)) |acc| acc else blk: {
                    if (try accounts_db.getAccountSharedData(
                        allocator,
                        &account_key,
                    )) |acc| {
                        map.putAssumeCapacityNoClobber(account_key, acc);
                        break :blk acc;
                    } else {
                        // map not found, create a new one
                        var acc = AccountSharedData.EMPTY;
                        acc.rent_epoch = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH;
                        map.putAssumeCapacityNoClobber(account_key, acc);
                        break :blk acc;
                    }
                };

                std.debug.assert(account.lamports != 0); // this account should be gone?

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
                    const owner = try accounts_db.getAccountSharedData(
                        allocator,
                        program_owner_key,
                    ) orelse
                        continue :next_tx; // tx will fail - can't get account

                    map.putAssumeCapacityNoClobber(program_owner_key.*, owner);

                    break :blk owner;
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
        for (self.account_cache.values()) |account| allocator.free(account.data);
        self.account_cache.deinit(allocator);
        for (self.sysvar_instruction_account_datas.items) |account_data| allocator.free(account_data);
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
        self: *const BatchAccountCache,
        allocator: std.mem.Allocator,
        transaction: *const RuntimeTransaction,
        rent_collector: *const sig.core.rent_collector.RentCollector,
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
            error.MaxLoadedAccountsDataSizeExceeded => .{ .err = .MaxLoadedAccountsDataSizeExceeded },
        };

        return .{ .ok = result };
    }

    fn loadTransactionAccountsInner(
        self: *const BatchAccountCache,
        allocator: std.mem.Allocator,
        transaction: *const RuntimeTransaction,
        rent_collector: *const sig.core.rent_collector.RentCollector,
        feature_set: *const runtime.FeatureSet,
        compute_budget_limits: *const ComputeBudgetLimits,
    ) LoadedTransactionAccountsError!LoadedTransactionAccounts {
        if (compute_budget_limits.loaded_accounts_bytes == 0)
            unreachable; // in agave this is sanitized somewhere prior to this

        var loaded = LoadedTransactionAccounts.DEFAULT;

        const accounts = transaction.accounts.slice();
        for (accounts.items(.pubkey), accounts.items(.is_writable)) |account, is_writable| {
            const loaded_account = try loadTransactionAccount(
                self,
                transaction,
                rent_collector,
                feature_set,
                account,
                is_writable,
            );

            try accumulateAndCheckLoadedAccountDataSize(
                &loaded.loaded_accounts_data_size,
                0,
                compute_budget_limits.loaded_accounts_bytes,
            );

            loaded.rent_collected += loaded_account.rent_collected;
            loaded.rent_debits.appendAssumeCapacity(.{
                .rent_balance = loaded_account.account.lamports,
                .rent_collected = loaded_account.rent_collected,
            });
            loaded.accounts.appendAssumeCapacity(loaded_account.account);
        }

        var validated_loaders = std.AutoArrayHashMap(Pubkey, void).init(allocator);
        defer validated_loaders.deinit();

        for (transaction.instruction_infos) |instr| {
            const program_id = &instr.program_meta.pubkey;
            if (program_id.equals(&runtime.ids.NATIVE_LOADER_ID)) continue;
            const program_account = loadAccount(self, transaction, program_id, false) orelse
                return error.ProgramAccountNotFound;

            if (!feature_set.active.contains(
                sig.runtime.features.REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS,
            ) and !program_account.account.executable) return error.InvalidProgramForExecution;

            const owner_id = &program_account.account.owner;
            const owner_account = account: {
                if (owner_id.equals(&runtime.ids.NATIVE_LOADER_ID)) continue;
                if (validated_loaders.contains(owner_id.*)) continue; // only load + count owners once

                break :account self.loadAccount(owner_id, false) orelse
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
                .rent_epoch = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH,
            },
            .loaded_size = 0,
            .rent_collected = 0,
        };
    };

    fn loadTransactionAccount(
        self: *const BatchAccountCache,
        allocator: std.mem.Allocator,
        transaction: *const RuntimeTransaction,
        rent_collector: *const sig.core.rent_collector.RentCollector,
        feature_set: *const runtime.FeatureSet,
        key: *const Pubkey,
        is_writable: bool,
    ) error{OutOfMemory}!LoadedTransactionAccount {
        if (key.equals(&runtime.ids.SYSVAR_INSTRUCTIONS_ID)) {
            @setCold(true);
            const account = try constructInstructionsAccount(allocator, transaction);
            try self.sysvar_instruction_account_datas.append(allocator, account.data);
            return .{
                .account = account,
                .loaded_size = 0,
                .rent_collected = 0,
            };
        }

        const account = self.loadAccount(allocator, transaction, key, is_writable) orelse {
            // a previous instruction deallocated this account, we will make a new one in its place.

            var account = AccountSharedData.EMPTY;
            account.rent_epoch = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH;

            const result = self.account_cache.getOrPutAssumeCapacity(key);
            std.debug.assert(result.found_existing);

            result.value_ptr.* = account;

            return LoadedTransactionAccount{
                .account = result.value_ptr,
                .loaded_size = 0,
                .rent_collected = 0,
            };
        };

        const rent_collected = collectRentFromAccount(account, key, feature_set, rent_collector);

        return .{
            .account = account.account,
            .loaded_size = account.account.data.len,
            .rent_collected = rent_collected.rent_amount,
        };
    }

    /// null return => account is now dead
    fn loadAccount(
        self: *const BatchAccountCache,
        allocator: std.mem.Allocator,
        transaction: *const RuntimeTransaction,
        key: *const Pubkey,
        is_writable: bool,
    ) ?LoadedTransactionAccount {
        const maybe_account = if (key.equals(&runtime.ids.SYSVAR_INSTRUCTIONS_ID)) account: {
            @setCold(true);
            const account = try constructInstructionsAccount(allocator, transaction);
            try self.sysvar_instruction_account_datas.append(allocator, account.data);
            break :account account;
        } else self.account_cache.getPtr(key);

        const account = maybe_account orelse unreachable; // all keys should be already there
        if (account.lamports == 0) {
            // a previous instr deallocated this account
            allocator.free(account.data);
            account.* = undefined; // fail loudly if we try to use it
            return null;
        }

        // agave "inspects" the account here, which caches the initial state of writeable accounts
        // TODO: we should probably do this at init time
        _ = is_writable;

        return .{
            .account = account,
            .loaded_size = account.account.data.len,
            .rent_collected = 0,
        };
    }
};

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L293
fn collectRentFromAccount(
    account: *AccountSharedData,
    account_key: *const sig.core.Pubkey,
    feature_set: *const runtime.FeatureSet,
    rent_collector: *const sig.core.rent_collector.RentCollector,
) sig.core.rent_collector.CollectedInfo {
    if (!feature_set.active.contains(runtime.features.DISABLE_RENT_FEES_COLLECTION)) {
        @setCold(true); // this feature should always be enabled?
        return rent_collector.collectFromExistingAccount(account_key, account);
    }

    if (account.rent_epoch != sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH and
        rent_collector.getRentDue(
        account.lamports,
        account.data.len,
        account.rent_epoch,
    ) != .Exempt) {
        account.rent_epoch = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH;
    }

    return sig.core.rent_collector.CollectedInfo.NoneCollected;
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
    tx: *const runtime.transaction_execution.RuntimeTransaction,
) error{OutOfMemory}!AccountSharedData {
    const Instruction = sig.core.Instruction;
    const InstructionAccount = sig.core.instruction.InstructionAccount;

    var decompiled_instructions = try std.ArrayList(Instruction).initCapacity(
        allocator,
        tx.instruction_infos.len,
    );
    defer {
        for (decompiled_instructions.items) |decompiled| allocator.free(decompiled.accounts);
        decompiled_instructions.deinit();
    }

    for (tx.instruction_infos) |instruction| {
        const accounts_meta = try allocator.alloc(
            InstructionAccount,
            instruction.account_metas.len,
        );
        errdefer allocator.free(accounts_meta);

        for (instruction.account_metas.slice(), accounts_meta) |account_meta, *new_account_meta| {
            new_account_meta.* = .{
                .pubkey = tx.accounts.items(.pubkey)[account_meta.index_in_transaction],
                .is_signer = tx.accounts.items(.is_signer)[account_meta.index_in_transaction],
                .is_writable = tx.accounts.items(.is_writable)[account_meta.index_in_transaction],
            };
        }

        decompiled_instructions.appendAssumeCapacity(.{
            .accounts = accounts_meta,
            .data = instruction.instruction_data,
            .program_id = tx.accounts.items(.pubkey)[instruction.program_meta.index_in_transaction],
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

// fn newAccountLoader(allocator: std.mem.Allocator) BatchAccountCache(.Mocked) {
//     if (!@import("builtin").is_test) @compileError("newBank for testing only");
//     return .{
//         .cache_allocator = allocator,
//         .account_allocator = allocator,
//         .accountsdb = .{
//             .inner = .{
//                 .allocator = allocator,
//                 .accounts = .{},
//             },
//         },
//     };
// }

comptime {
    // making sure we get compile errors, TODO: remove when tests are enabled
    _ = BatchAccountCache;
    _ = BatchAccountCache.deinit;
    _ = BatchAccountCache.initFromAccountsDb;
    _ = BatchAccountCache.loadAccount;
    _ = BatchAccountCache.loadTransactionAccount;
    _ = BatchAccountCache.loadTransactionAccounts;
    _ = BatchAccountCache.loadTransactionAccountsInner;
    _ = BatchAccountCache.LoadedTransactionAccountsError;
}

test "loadTransactionAccounts empty transaction" {
    const allocator = std.testing.allocator;
    const accountsdb = MockedAccountsDb{ .allocator = allocator };

    var batch_account_cache = try BatchAccountCache.initFromAccountsDb(
        .Mocked,
        allocator,
        accountsdb,
        &.{},
    );
    defer batch_account_cache.deinit(allocator);

    // _ = try loadTransactionAccounts(
    //     .Mocked,
    //     allocator,
    //     &tx,
    //     100_000,
    //     &account_loader,
    //     &runtime.FeatureSet.EMPTY,
    //     &sig.core.rent_collector.defaultCollector(0),
    // );
}

// test "loadTransactionAccounts sysvar instruction" {
//     const allocator = std.testing.allocator;

//     const tx: sig.core.Transaction = .{
//         .signatures = &.{},
//         .version = .legacy,
//         .msg = .{
//             .signature_count = 0,
//             .readonly_signed_count = 0,
//             .readonly_unsigned_count = 0,
//             .account_keys = &.{runtime.ids.SYSVAR_INSTRUCTIONS_ID},
//             .recent_blockhash = .{ .data = [_]u8{0x00} ** Hash.SIZE },
//             .instructions = &.{},
//             .address_lookups = &.{},
//         },
//     };

//     var account_loader = newAccountLoader(allocator);

//     const loaded = try loadTransactionAccounts(
//         .Mocked,
//         allocator,
//         &tx,
//         100_000,
//         &account_loader,
//         &runtime.FeatureSet.EMPTY,
//         &sig.core.rent_collector.defaultCollector(0),
//     );
//     try std.testing.expectEqual(0, loaded.collected_rent);

//     var returned_accounts: usize = 0;
//     for (loaded.accounts.slice()) |account| {
//         try std.testing.expectEqual(runtime.ids.SYSVAR_INSTRUCTIONS_ID, account.owner);
//         try std.testing.expect(account.data.len > 0);
//         allocator.free(account.data);
//         returned_accounts += 1;
//     }
//     try std.testing.expect(returned_accounts == 1);
// }

// test "accumulated size" {
//     const requested_data_size_limit = 123;

//     var accumulated_size: u32 = 0;
//     try accumulateAndCheckLoadedAccountDataSize(
//         &accumulated_size,
//         requested_data_size_limit,
//         requested_data_size_limit,
//     );

//     try std.testing.expectEqual(requested_data_size_limit, accumulated_size);

//     // exceed limit
//     try std.testing.expectError(
//         error.MaxLoadedAccountsDataSizeExceeded,
//         accumulateAndCheckLoadedAccountDataSize(
//             &accumulated_size,
//             1,
//             requested_data_size_limit,
//         ),
//     );
// }

// test "load accounts rent paid" {
//     const allocator = std.testing.allocator;
//     var prng = std.rand.DefaultPrng.init(0);

//     const fee_payer_address = Pubkey.initRandom(prng.random());
//     const instruction_address = Pubkey.initRandom(prng.random());

//     const instruction_data = "dummy instruction";

//     const tx: sig.core.Transaction = .{
//         .signatures = &.{},
//         .version = .legacy,
//         .msg = .{
//             .signature_count = 1, // fee payer is signer + writeable
//             .readonly_signed_count = 0,
//             .readonly_unsigned_count = 0,
//             .account_keys = &.{ fee_payer_address, instruction_address },
//             .recent_blockhash = .{ .data = [_]u8{0x00} ** Hash.SIZE },
//             .instructions = &.{.{
//                 .program_index = 1,
//                 .data = instruction_data,
//                 .account_indexes = &.{},
//             }},
//             .address_lookups = &.{},
//         },
//     };

//     const fee_payer_balance = 300;
//     var fee_payer_account = AccountSharedData.EMPTY;
//     fee_payer_account.lamports = fee_payer_balance;

//     var account_loader = newAccountLoader(allocator);
//     defer {
//         var iter = account_loader.account_cache.iterator();
//         while (iter.next()) |account_entry| allocator.free(account_entry.value_ptr.data);

//         account_loader.accountsdb.inner.deinit();
//         account_loader.deinit();
//     }

//     var data: [1024]u8 = undefined;
//     prng.fill(&data);

//     const NATIVE_LOADER_ID = runtime.ids.NATIVE_LOADER_ID;

//     try account_loader.accountsdb.inner.accounts.put(allocator, fee_payer_address, .{
//         .data = .{ .unowned_allocation = &data },
//         .lamports = fee_payer_balance,
//         .executable = false,
//         .owner = Pubkey.ZEROES,
//         .rent_epoch = 0,
//     });

//     try account_loader.accountsdb.inner.accounts.put(allocator, instruction_address, .{
//         .data = .{ .unowned_allocation = instruction_data },
//         .lamports = 1,
//         .executable = true,
//         .owner = NATIVE_LOADER_ID,
//         .rent_epoch = 0,
//     });
//     try account_loader.accountsdb.inner.accounts.put(allocator, NATIVE_LOADER_ID, .{
//         .data = .{ .empty = .{ .len = 0 } },
//         .lamports = 1,
//         .executable = true,
//         .owner = Pubkey.ZEROES,
//         .rent_epoch = 0,
//     });
//     try account_loader.accountsdb.inner.accounts.put(allocator, Pubkey.ZEROES, .{
//         .data = .{ .empty = .{ .len = 0 } },
//         .lamports = 0,
//         .executable = true,
//         .owner = Pubkey.ZEROES,
//         .rent_epoch = 0,
//     });

//     const loaded = try loadTransactionAccounts(
//         .Mocked,
//         allocator,
//         &tx,
//         64 * 1024 * 1024,
//         &account_loader,
//         &runtime.FeatureSet.EMPTY,
//         &sig.core.rent_collector.defaultCollector(0),
//     );

//     var found: usize = 0;
//     for (loaded.accounts.slice()) |_| found += 1;

//     // slots elapsed   slots per year    lamports per year
//     //  |               |                 |      data len
//     //  |               |                 |       |     overhead
//     //  v               v                 v       v      v
//     // ((64) / (7.8892314983999997e7)) * (3480 * (1024 + 128))
//     const expected_rent = 3;

//     try std.testing.expectEqual(expected_rent, loaded.collected_rent);
//     try std.testing.expectEqual(2, found);
// }

// test "constructInstructionsAccount" {
//     const allocator = std.testing.allocator;
//     var prng = std.rand.DefaultPrng.init(0);

//     var data: [1024]u8 = undefined;
//     prng.fill(&data);

//     const fee_payer_address = Pubkey.initRandom(prng.random());
//     const instruction_address = Pubkey.initRandom(prng.random());

//     const tx: sig.core.Transaction = .{
//         .signatures = &.{},
//         .version = .legacy,
//         .msg = .{
//             .signature_count = 1,
//             .readonly_signed_count = 0,
//             .readonly_unsigned_count = 0,
//             .account_keys = &.{ fee_payer_address, instruction_address },
//             .recent_blockhash = .{ .data = [_]u8{0x00} ** Hash.SIZE },
//             .instructions = &.{.{
//                 .program_index = 1,
//                 .data = &data,
//                 .account_indexes = &.{},
//             }},
//             .address_lookups = &.{},
//         },
//     };

//     const checkFn = struct {
//         fn f(alloc: std.mem.Allocator, txn: *const sig.core.Transaction) !void {
//             const account = try constructInstructionsAccount(alloc, txn);
//             defer allocator.free(account.data);
//         }
//     }.f;

//     try std.testing.checkAllAllocationFailures(allocator, checkFn, .{&tx});

//     const account = try constructInstructionsAccount(allocator, &tx);
//     defer allocator.free(account.data);
//     try std.testing.expectEqual(0, account.lamports);
//     try std.testing.expect(account.data.len > 8);
// }

// test "loadAccount allocations" {
//     const allocator = std.testing.allocator;
//     const NATIVE_LOADER_ID = runtime.ids.NATIVE_LOADER_ID;

//     const checkFn = struct {
//         fn f(alloc: std.mem.Allocator) !void {
//             var account_loader = newAccountLoader(alloc);
//             defer account_loader.deinit();
//             defer account_loader.accountsdb.inner.deinit();

//             try account_loader.accountsdb.inner.accounts.put(alloc, NATIVE_LOADER_ID, .{
//                 .data = .{ .empty = .{ .len = 0 } },
//                 .lamports = 1,
//                 .executable = true,
//                 .owner = Pubkey.ZEROES,
//                 .rent_epoch = 0,
//             });

//             const account = (try account_loader.loadAccount(&NATIVE_LOADER_ID, false)) orelse
//                 @panic("account not found");
//             try std.testing.expectEqual(1, account.account.lamports);
//             try std.testing.expectEqual(true, account.account.executable);
//         }
//     }.f;

//     try std.testing.checkAllAllocationFailures(allocator, checkFn, .{});
// }

// test "load tx too large" {
//     const allocator = std.testing.allocator;
//     var prng = std.rand.DefaultPrng.init(5083);

//     const address = Pubkey.initRandom(prng.random());

//     // large account
//     const account_data = try allocator.alloc(u8, 10 * 1024 * 1024);
//     defer allocator.free(account_data);

//     var account_loader = newAccountLoader(allocator);
//     defer {
//         var iter = account_loader.account_cache.iterator();
//         while (iter.next()) |account_entry| allocator.free(account_entry.value_ptr.data);

//         account_loader.accountsdb.inner.deinit();
//         account_loader.deinit();
//     }

//     try account_loader.accountsdb.inner.accounts.put(allocator, address, .{
//         .data = .{ .unowned_allocation = account_data },
//         .lamports = 1_000_000,
//         .executable = false,
//         .owner = sig.runtime.program.system_program.ID,
//         .rent_epoch = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH,
//     });

//     const tx = sig.core.Transaction{
//         .version = .legacy,
//         .signatures = &.{},
//         .msg = .{
//             .account_keys = &.{address},
//             .instructions = &.{},
//             .readonly_signed_count = 0,
//             .signature_count = 0,
//             .recent_blockhash = sig.core.Hash.ZEROES,
//             .readonly_unsigned_count = 1,
//         },
//     };

//     const loaded_accounts = try loadTransactionAccounts(
//         .Mocked,
//         allocator,
//         &tx,
//         1_000_000, // 1M < 10MiB
//         &account_loader,
//         &sig.runtime.FeatureSet.EMPTY,
//         &sig.core.rent_collector.defaultCollector(0),
//     );

//     const load_err = (loaded_accounts.load_failure orelse
//         return error.TestFailed).err;

//     try std.testing.expectEqual(error.MaxLoadedAccountsDataSizeExceeded, load_err);
// }

// test "dont double count program owner account data size" {
//     const allocator = std.testing.allocator;
//     var prng = std.rand.DefaultPrng.init(5083);
//     const random = prng.random();

//     const data1 = "data1";
//     const data2 = "data2";
//     const data_owner = "data_owner";
//     const pk1 = Pubkey.initRandom(random);
//     const pk2 = Pubkey.initRandom(random);
//     const pk_owner = Pubkey.initRandom(random);

//     const tx = blk: {
//         var tx = sig.core.Transaction.EMPTY;
//         tx.msg.account_keys = &.{ pk1, pk2 };
//         tx.msg.instructions = &.{
//             .{ .program_index = 1, .account_indexes = &.{0}, .data = "instr1" },
//             .{ .program_index = 0, .account_indexes = &.{1}, .data = "instr2" },
//         };
//         break :blk tx;
//     };

//     var account_loader = newAccountLoader(allocator);
//     defer {
//         var iter = account_loader.account_cache.iterator();
//         while (iter.next()) |account_entry| allocator.free(account_entry.value_ptr.data);

//         account_loader.accountsdb.inner.deinit();
//         account_loader.deinit();
//     }

//     try account_loader.accountsdb.inner.accounts.put(allocator, pk1, .{
//         .data = .{ .unowned_allocation = data1 },
//         .lamports = 0,
//         .executable = true,
//         .owner = pk_owner,
//         .rent_epoch = 0,
//     });
//     try account_loader.accountsdb.inner.accounts.put(allocator, pk2, .{
//         .data = .{ .unowned_allocation = data2 },
//         .lamports = 0,
//         .executable = true,
//         .owner = pk_owner,
//         .rent_epoch = 0,
//     });
//     try account_loader.accountsdb.inner.accounts.put(allocator, pk_owner, .{
//         .data = .{ .unowned_allocation = data_owner },
//         .lamports = 0,
//         .executable = true,
//         .owner = runtime.ids.NATIVE_LOADER_ID,
//         .rent_epoch = 0,
//     });

//     const loaded_accounts = try loadTransactionAccounts(
//         .Mocked,
//         allocator,
//         &tx,
//         1_000_000, // 1M < 10MiB
//         &account_loader,
//         &sig.runtime.FeatureSet.EMPTY,
//         &sig.core.rent_collector.defaultCollector(0),
//     );

//     try std.testing.expectEqual(
//         data1.len + data2.len + data_owner.len, // owner counted once, not twice
//         loaded_accounts.loaded_account_data_size,
//     );
// }
