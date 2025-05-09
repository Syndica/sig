const std = @import("std");
const sig = @import("../sig.zig");
const runtime = sig.runtime;

const Pubkey = sig.core.Pubkey;
const AccountSharedData = runtime.AccountSharedData;
const Hash = sig.core.Hash;

// [firedancer] https://github.com/firedancer-io/firedancer/blob/ddde57c40c4d4334c25bb32de17f833d4d79a889/src/ballet/txn/fd_txn.h#L116
const MAX_TX_ACCOUNT_LOCKS = 128;

pub const LoadFailure = struct {
    pub const Location = union(enum) {
        account_idx_load: u8,
        instr_idx_program_check: u16,
    };
    failure_location: Location,
    err: error{
        ProgramAccountNotFound,
        MaxLoadedAccountsDataSizeExceeded,
        InvalidProgramForExecution,
    },

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self.failure_location) {
            .account_idx_load => |idx| try writer.print(
                "Failed to load account[{}] with {}",
                .{ idx, self.err },
            ),
            .instr_idx_program_check => |idx| try writer.print(
                "Failed to check instruction[{}]'s program with {}",
                .{ idx, self.err },
            ),
        }
    }
};

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L417
/// agave's LoadedTransactionAccounts contains a field "program indices". This has been omitted as
/// it's a Vec<Vec<u8>> whose elements are either [program_id] or [] (when program_id is the native
/// loader), which seems pointless.
pub const LoadedAccounts = struct {
    collected_rent: u64 = 0,
    loaded_account_data_size: u32 = 0,

    load_failure: ?LoadFailure = null,

    accounts: std.BoundedArray(AccountSharedData, MAX_TX_ACCOUNT_LOCKS) = .{},
    /// equal in length to accounts
    is_instruction_account: std.BoundedArray(bool, MAX_TX_ACCOUNT_LOCKS) = .{},
    /// equal in length to accounts
    rent_debits: std.BoundedArray(RentDebit, MAX_TX_ACCOUNT_LOCKS) = .{},
};

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

const LoadedTransactionAccount = struct {
    account: AccountSharedData,
    loaded_size: usize,
    rent_collected: u64,

    /// must be deallocated separately
    is_instruction_account: bool = false,

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
        .is_instruction_account = false,
    };
};

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L154
pub fn AccountLoader(comptime accountsdb_kind: AccountsDbKind) type {
    return struct {
        const Self = @This();
        const Cache = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData);

        account_allocator: std.mem.Allocator, // allocates all shared account data
        cache_allocator: std.mem.Allocator, // allocates the account_cache

        account_cache: Cache = .{}, // never evicted from, exists for whole transaction
        accountsdb: AccountsDb(accountsdb_kind),

        // note: no account overrides implemented here
        pub fn newWithCacheCapacity(
            account_allocator: std.mem.Allocator,
            cache_allocator: std.mem.Allocator,
            accountsdb: accountsdb_kind.T(),
            capacity: usize,
        ) !Self {
            var account_cache: Cache = .{};
            try account_cache.ensureUnusedCapacity(account_allocator, capacity);
            return .{
                .account_allocator = account_allocator,
                .cache_allocator = cache_allocator,
                .account_cache = account_cache,
                .accountsdb = .{ .inner = accountsdb },
            };
        }

        fn loadAccount(
            self: *@This(),
            key: *const Pubkey,
            is_writable: bool,
        ) error{ OutOfMemory, GetAccountFailedUnexpectedly }!?LoadedTransactionAccount {
            const account = blk: {
                if (self.account_cache.get(key.*)) |account| {
                    // a previous transaction deallocated this account.
                    break :blk if (account.lamports == 0) null else account;
                }

                if (try self.accountsdb.getAccountSharedData(
                    self.account_allocator,
                    key,
                )) |account| {
                    try self.account_cache.put(self.cache_allocator, key.*, account);
                    break :blk account;
                }

                break :blk null;
            };

            // unimplemented: inspect_account / accounts_lt_hash stuff - not important now
            _ = is_writable;

            return if (account) |found_account| .{
                .account = found_account,
                .rent_collected = 0,
                .loaded_size = found_account.data.len,
            } else null;
        }

        pub fn deinit(self: *Self) void {
            self.account_cache.deinit(self.cache_allocator);
        }
    };
}

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L568
fn loadTransactionAccount(
    comptime accountsdb_kind: AccountsDbKind,
    allocator: std.mem.Allocator,
    account_loader: *AccountLoader(accountsdb_kind),
    tx: *const sig.core.Transaction,
    account_key: *const sig.core.Pubkey,
    account_idx: usize,
    rent_collector: *const sig.core.rent_collector.RentCollector,
    feature_set: *const runtime.FeatureSet,
) error{ OutOfMemory, GetAccountFailedUnexpectedly }!?LoadedTransactionAccount {
    if (account_key.equals(&runtime.ids.SYSVAR_INSTRUCTIONS_ID)) {
        @setCold(true);
        return .{
            .account = try constructInstructionsAccount(allocator, tx),
            .loaded_size = 0,
            .rent_collected = 0,
            .is_instruction_account = true,
        };
    }

    const is_writable = tx.msg.isWritable(account_idx);

    var loaded_account: LoadedTransactionAccount = try account_loader.loadAccount(
        account_key,
        is_writable,
    ) orelse return null;

    if (is_writable) loaded_account.rent_collected = collectRentFromAccount(
        &loaded_account.account,
        account_key,
        feature_set,
        rent_collector,
    ).rent_amount;

    return loaded_account;
}

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

/// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L425
pub fn loadTransactionAccounts(
    comptime accountsdb_kind: AccountsDbKind,
    allocator: std.mem.Allocator,
    tx: *const sig.core.Transaction,
    requested_max_total_data_size: u32,
    /// reusable for a whole batch (i.e. no lock violations)
    account_loader: *AccountLoader(accountsdb_kind),
    features: *const runtime.FeatureSet,
    rent_collector: *const sig.core.rent_collector.RentCollector,
) error{ OutOfMemory, GetAccountFailedUnexpectedly }!LoadedAccounts {
    std.debug.assert(requested_max_total_data_size != 0); // must be non-zero

    var loaded_accounts: LoadedAccounts = .{};
    for (tx.msg.account_keys, 0..) |account_key, account_idx| {
        const loaded_account: LoadedTransactionAccount = try loadTransactionAccount(
            accountsdb_kind,
            allocator,
            account_loader,
            tx,
            &account_key,
            account_idx,
            rent_collector,
            features,
        ) orelse {
            // didn't find tx account, let's stop trying to load accounts from this tx
            loaded_accounts.load_failure = .{
                .failure_location = .{ .account_idx_load = @intCast(account_idx) },
                .err = error.ProgramAccountNotFound,
            };
            return loaded_accounts;
        };

        loaded_accounts.accounts.appendAssumeCapacity(loaded_account.account);
        loaded_accounts.is_instruction_account.appendAssumeCapacity(
            loaded_account.is_instruction_account,
        );
        loaded_accounts.rent_debits.appendAssumeCapacity(.{
            .rent_collected = loaded_account.rent_collected,
            .rent_balance = loaded_account.account.lamports,
        });

        loaded_accounts.collected_rent += loaded_account.rent_collected;

        accumulateAndCheckLoadedAccountDataSize(
            &loaded_accounts.loaded_account_data_size,
            loaded_account.loaded_size,
            requested_max_total_data_size,
        ) catch |err| {
            // total accounts data size too large, let's stop here
            loaded_accounts.load_failure = .{
                .failure_location = .{ .account_idx_load = @intCast(account_idx) },
                .err = err,
            };
            return loaded_accounts;
        };
    }

    var validated_loaders = std.AutoArrayHashMap(Pubkey, void).init(allocator);
    defer validated_loaders.deinit();

    for (tx.msg.instructions, 0..) |instruction, instr_idx| {
        const program_id = &tx.msg.account_keys[instruction.program_index];
        if (program_id.equals(&runtime.ids.NATIVE_LOADER_ID)) continue;
        const program_account = loaded_accounts.accounts.buffer[instruction.program_index];

        if (!program_account.executable and
            !features.active.contains(runtime.features.REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS))
        {
            @setCold(true); // likely dead code (feature should be active)
            loaded_accounts.load_failure = .{
                .err = error.InvalidProgramForExecution,
                .failure_location = .{ .instr_idx_program_check = @intCast(instr_idx) },
            };
            return loaded_accounts;
        }

        const owner_id = &program_account.owner;
        const owner_account = account: {
            if (owner_id.equals(&runtime.ids.NATIVE_LOADER_ID)) continue;
            if (validated_loaders.contains(owner_id.*)) continue; // only load + count owners once

            break :account (try account_loader.loadAccount(owner_id, false)) orelse {
                // failed to load instruction program's owner
                loaded_accounts.load_failure = .{
                    .err = error.InvalidProgramForExecution,
                    .failure_location = .{ .instr_idx_program_check = @intCast(instr_idx) },
                };
                return loaded_accounts;
            };
        };

        if (!owner_account.account.owner.equals(&runtime.ids.NATIVE_LOADER_ID)) {
            // instruction program's owner's owner is not the native loader
            loaded_accounts.load_failure = .{
                .err = error.InvalidProgramForExecution,
                .failure_location = .{ .instr_idx_program_check = @intCast(instr_idx) },
            };
            return loaded_accounts;
        }

        accumulateAndCheckLoadedAccountDataSize(
            &loaded_accounts.loaded_account_data_size,
            owner_account.loaded_size,
            requested_max_total_data_size,
        ) catch |err| {
            loaded_accounts.load_failure = .{
                .err = err,
                .failure_location = .{ .instr_idx_program_check = @intCast(instr_idx) },
            };
            return loaded_accounts;
        };

        try validated_loaders.put(owner_id.*, {});
    }

    return loaded_accounts;
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
    tx: *const sig.core.Transaction,
) error{OutOfMemory}!AccountSharedData {
    const Instruction = sig.core.Instruction;
    const InstructionAccount = sig.core.instruction.InstructionAccount;

    var decompiled_instructions = try std.ArrayList(Instruction).initCapacity(
        allocator,
        tx.msg.instructions.len,
    );
    defer {
        for (decompiled_instructions.items) |decompiled| allocator.free(decompiled.accounts);
        decompiled_instructions.deinit();
    }

    for (tx.msg.instructions) |instruction| {
        const accounts_meta = try allocator.alloc(
            InstructionAccount,
            instruction.account_indexes.len,
        );
        errdefer allocator.free(accounts_meta);

        errdefer comptime unreachable;

        for (instruction.account_indexes, accounts_meta) |account_idx, *account_meta| {
            account_meta.* = .{
                .pubkey = tx.msg.account_keys[account_idx],
                .is_signer = tx.msg.isSigner(account_idx),
                .is_writable = tx.msg.isWritable(account_idx),
            };
        }

        decompiled_instructions.appendAssumeCapacity(.{
            .accounts = accounts_meta,
            .data = instruction.data,
            .program_id = tx.msg.account_keys[instruction.program_index],
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

fn newAccountLoader(allocator: std.mem.Allocator) AccountLoader(.Mocked) {
    if (!@import("builtin").is_test) @compileError("newBank for testing only");
    return .{
        .cache_allocator = allocator,
        .account_allocator = allocator,
        .accountsdb = .{
            .inner = .{
                .allocator = allocator,
                .accounts = .{},
            },
        },
    };
}

test "loadTransactionAccounts empty transaction" {
    const allocator = std.testing.allocator;
    const tx = sig.core.Transaction.EMPTY;

    var account_loader = newAccountLoader(allocator);
    _ = try loadTransactionAccounts(
        .Mocked,
        allocator,
        &tx,
        100_000,
        &account_loader,
        &runtime.FeatureSet.EMPTY,
        &sig.core.rent_collector.defaultCollector(0),
    );
}

test "loadTransactionAccounts sysvar instruction" {
    const allocator = std.testing.allocator;

    const tx: sig.core.Transaction = .{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 0,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 0,
            .account_keys = &.{runtime.ids.SYSVAR_INSTRUCTIONS_ID},
            .recent_blockhash = .{ .data = [_]u8{0x00} ** Hash.SIZE },
            .instructions = &.{},
            .address_lookups = &.{},
        },
    };

    var account_loader = newAccountLoader(allocator);

    const loaded = try loadTransactionAccounts(
        .Mocked,
        allocator,
        &tx,
        100_000,
        &account_loader,
        &runtime.FeatureSet.EMPTY,
        &sig.core.rent_collector.defaultCollector(0),
    );
    try std.testing.expectEqual(0, loaded.collected_rent);

    var returned_accounts: usize = 0;
    for (loaded.accounts.slice()) |account| {
        try std.testing.expectEqual(runtime.ids.SYSVAR_INSTRUCTIONS_ID, account.owner);
        try std.testing.expect(account.data.len > 0);
        allocator.free(account.data);
        returned_accounts += 1;
    }
    try std.testing.expect(returned_accounts == 1);
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
    var prng = std.rand.DefaultPrng.init(0);

    const fee_payer_address = Pubkey.initRandom(prng.random());
    const instruction_address = Pubkey.initRandom(prng.random());

    const instruction_data = "dummy instruction";

    const tx: sig.core.Transaction = .{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 1, // fee payer is signer + writeable
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 0,
            .account_keys = &.{ fee_payer_address, instruction_address },
            .recent_blockhash = .{ .data = [_]u8{0x00} ** Hash.SIZE },
            .instructions = &.{.{
                .program_index = 1,
                .data = instruction_data,
                .account_indexes = &.{},
            }},
            .address_lookups = &.{},
        },
    };

    const fee_payer_balance = 300;
    var fee_payer_account = AccountSharedData.EMPTY;
    fee_payer_account.lamports = fee_payer_balance;

    var account_loader = newAccountLoader(allocator);
    defer {
        var iter = account_loader.account_cache.iterator();
        while (iter.next()) |account_entry| allocator.free(account_entry.value_ptr.data);

        account_loader.accountsdb.inner.deinit();
        account_loader.deinit();
    }

    var data: [1024]u8 = undefined;
    prng.fill(&data);

    const NATIVE_LOADER_ID = runtime.ids.NATIVE_LOADER_ID;

    try account_loader.accountsdb.inner.accounts.put(allocator, fee_payer_address, .{
        .data = .{ .unowned_allocation = &data },
        .lamports = fee_payer_balance,
        .executable = false,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });

    try account_loader.accountsdb.inner.accounts.put(allocator, instruction_address, .{
        .data = .{ .unowned_allocation = instruction_data },
        .lamports = 1,
        .executable = true,
        .owner = NATIVE_LOADER_ID,
        .rent_epoch = 0,
    });
    try account_loader.accountsdb.inner.accounts.put(allocator, NATIVE_LOADER_ID, .{
        .data = .{ .empty = .{ .len = 0 } },
        .lamports = 1,
        .executable = true,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });
    try account_loader.accountsdb.inner.accounts.put(allocator, Pubkey.ZEROES, .{
        .data = .{ .empty = .{ .len = 0 } },
        .lamports = 0,
        .executable = true,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });

    const loaded = try loadTransactionAccounts(
        .Mocked,
        allocator,
        &tx,
        64 * 1024 * 1024,
        &account_loader,
        &runtime.FeatureSet.EMPTY,
        &sig.core.rent_collector.defaultCollector(0),
    );

    var found: usize = 0;
    for (loaded.accounts.slice()) |_| found += 1;

    // slots elapsed   slots per year    lamports per year
    //  |               |                 |      data len
    //  |               |                 |       |     overhead
    //  v               v                 v       v      v
    // ((64) / (7.8892314983999997e7)) * (3480 * (1024 + 128))
    const expected_rent = 3;

    try std.testing.expectEqual(expected_rent, loaded.collected_rent);
    try std.testing.expectEqual(2, found);
}

test "constructInstructionsAccount" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    var data: [1024]u8 = undefined;
    prng.fill(&data);

    const fee_payer_address = Pubkey.initRandom(prng.random());
    const instruction_address = Pubkey.initRandom(prng.random());

    const tx: sig.core.Transaction = .{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 1,
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 0,
            .account_keys = &.{ fee_payer_address, instruction_address },
            .recent_blockhash = .{ .data = [_]u8{0x00} ** Hash.SIZE },
            .instructions = &.{.{
                .program_index = 1,
                .data = &data,
                .account_indexes = &.{},
            }},
            .address_lookups = &.{},
        },
    };

    const checkFn = struct {
        fn f(alloc: std.mem.Allocator, txn: *const sig.core.Transaction) !void {
            const account = try constructInstructionsAccount(alloc, txn);
            defer allocator.free(account.data);
        }
    }.f;

    try std.testing.checkAllAllocationFailures(allocator, checkFn, .{&tx});

    const account = try constructInstructionsAccount(allocator, &tx);
    defer allocator.free(account.data);
    try std.testing.expectEqual(0, account.lamports);
    try std.testing.expect(account.data.len > 8);
}

test "loadAccount allocations" {
    const allocator = std.testing.allocator;
    const NATIVE_LOADER_ID = runtime.ids.NATIVE_LOADER_ID;

    const checkFn = struct {
        fn f(alloc: std.mem.Allocator) !void {
            var account_loader = newAccountLoader(alloc);
            defer account_loader.deinit();
            defer account_loader.accountsdb.inner.deinit();

            try account_loader.accountsdb.inner.accounts.put(alloc, NATIVE_LOADER_ID, .{
                .data = .{ .empty = .{ .len = 0 } },
                .lamports = 1,
                .executable = true,
                .owner = Pubkey.ZEROES,
                .rent_epoch = 0,
            });

            const account = (try account_loader.loadAccount(&NATIVE_LOADER_ID, false)) orelse
                @panic("account not found");
            try std.testing.expectEqual(1, account.account.lamports);
            try std.testing.expectEqual(true, account.account.executable);
        }
    }.f;

    try std.testing.checkAllAllocationFailures(allocator, checkFn, .{});
}

test "load tx too large" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(5083);

    const address = Pubkey.initRandom(prng.random());

    // large account
    const account_data = try allocator.alloc(u8, 10 * 1024 * 1024);
    defer allocator.free(account_data);

    var account_loader = newAccountLoader(allocator);
    defer {
        var iter = account_loader.account_cache.iterator();
        while (iter.next()) |account_entry| allocator.free(account_entry.value_ptr.data);

        account_loader.accountsdb.inner.deinit();
        account_loader.deinit();
    }

    try account_loader.accountsdb.inner.accounts.put(allocator, address, .{
        .data = .{ .unowned_allocation = account_data },
        .lamports = 1_000_000,
        .executable = false,
        .owner = sig.runtime.program.system_program.ID,
        .rent_epoch = sig.core.rent_collector.RENT_EXEMPT_RENT_EPOCH,
    });

    const tx = sig.core.Transaction{
        .version = .legacy,
        .signatures = &.{},
        .msg = .{
            .account_keys = &.{address},
            .instructions = &.{},
            .readonly_signed_count = 0,
            .signature_count = 0,
            .recent_blockhash = sig.core.Hash.ZEROES,
            .readonly_unsigned_count = 1,
        },
    };

    const loaded_accounts = try loadTransactionAccounts(
        .Mocked,
        allocator,
        &tx,
        1_000_000, // 1M < 10MiB
        &account_loader,
        &sig.runtime.FeatureSet.EMPTY,
        &sig.core.rent_collector.defaultCollector(0),
    );

    const load_err = (loaded_accounts.load_failure orelse
        return error.TestFailed).err;

    try std.testing.expectEqual(error.MaxLoadedAccountsDataSizeExceeded, load_err);
}

test "dont double count program owner account data size" {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(5083);
    const random = prng.random();

    const data1 = "data1";
    const data2 = "data2";
    const data_owner = "data_owner";
    const pk1 = Pubkey.initRandom(random);
    const pk2 = Pubkey.initRandom(random);
    const pk_owner = Pubkey.initRandom(random);

    const tx = blk: {
        var tx = sig.core.Transaction.EMPTY;
        tx.msg.account_keys = &.{ pk1, pk2 };
        tx.msg.instructions = &.{
            .{ .program_index = 1, .account_indexes = &.{0}, .data = "instr1" },
            .{ .program_index = 0, .account_indexes = &.{1}, .data = "instr2" },
        };
        break :blk tx;
    };

    var account_loader = newAccountLoader(allocator);
    defer {
        var iter = account_loader.account_cache.iterator();
        while (iter.next()) |account_entry| allocator.free(account_entry.value_ptr.data);

        account_loader.accountsdb.inner.deinit();
        account_loader.deinit();
    }

    try account_loader.accountsdb.inner.accounts.put(allocator, pk1, .{
        .data = .{ .unowned_allocation = data1 },
        .lamports = 0,
        .executable = true,
        .owner = pk_owner,
        .rent_epoch = 0,
    });
    try account_loader.accountsdb.inner.accounts.put(allocator, pk2, .{
        .data = .{ .unowned_allocation = data2 },
        .lamports = 0,
        .executable = true,
        .owner = pk_owner,
        .rent_epoch = 0,
    });
    try account_loader.accountsdb.inner.accounts.put(allocator, pk_owner, .{
        .data = .{ .unowned_allocation = data_owner },
        .lamports = 0,
        .executable = true,
        .owner = runtime.ids.NATIVE_LOADER_ID,
        .rent_epoch = 0,
    });

    const loaded_accounts = try loadTransactionAccounts(
        .Mocked,
        allocator,
        &tx,
        1_000_000, // 1M < 10MiB
        &account_loader,
        &sig.runtime.FeatureSet.EMPTY,
        &sig.core.rent_collector.defaultCollector(0),
    );

    try std.testing.expectEqual(
        data1.len + data2.len + data_owner.len, // owner counted once, not twice
        loaded_accounts.loaded_account_data_size,
    );
}
