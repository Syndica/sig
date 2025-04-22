const std = @import("std");
const sig = @import("../sig.zig");
const runtime = sig.runtime;

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const AccountSharedData = runtime.AccountSharedData;
const Hash = sig.core.Hash;
const RentCollector = sig.core.rent_collector.RentCollector;

// [firedancer] https://github.com/firedancer-io/firedancer/blob/ddde57c40c4d4334c25bb32de17f833d4d79a889/src/ballet/txn/fd_txn.h#L116
const MAX_TX_ACCOUNT_LOCKS = 128;

// [firedancer] https://github.com/firedancer-io/firedancer/blob/49056135a4c7ba024cb75a45925439239904238b/src/flamenco/runtime/fd_executor.c#L377
// firedancer actually already has the accounts data ready at this point, but Agave calls into the
// bank's callbacks into accountsdb (with the exception of [0] - the fee payer). I like the idea of
// loading them up first, but going with the bank for now.
pub fn loadTransactionAccounts(
    allocator: std.mem.Allocator,
    tx: *const sig.core.Transaction,
    requested_max_total_data_size: u32, // should be inside the tx?
    account_loader: *AccountLoader(.AccountsDb),
    features: *const runtime.FeatureSet,
) !LoadedAccounts {
    std.debug.assert(tx.msg.account_keys.len <= 128); // TODO: this should be sanitised earlier
    return try loadTransactionAccountsInner(
        .AccountsDb,
        allocator,
        tx,
        requested_max_total_data_size,
        account_loader,
        features,
    );
}

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L417
/// agave's LoadedTransactionAccounts contains a field "program indices". This has been omitted as
/// it's a Vec<Vec<u8>> whose elements are either [program_id] or [] (when program_id is the native
/// loader), which seems pointless.
pub const LoadedAccounts = struct {
    collected_rent: u64 = 0,
    loaded_account_data_size: u32 = 0,

    /// indexes correspond with tx.msg.account_keys
    accounts_buf: [MAX_TX_ACCOUNT_LOCKS]AccountSharedData,
    rent_debits: [MAX_TX_ACCOUNT_LOCKS]RentDebit,
};

const BankKind = enum {
    AccountsDb,
    Mocked,
    fn T(self: BankKind) type {
        return switch (self) {
            .AccountsDb => sig.accounts_db.Bank,
            .Mocked => MockedBank,
        };
    }
};

const MockedBank = struct {
    allocator: std.mem.Allocator,
    slot: Slot,
    accounts: std.AutoArrayHashMapUnmanaged(Pubkey, sig.core.Account),
    rent_collector: RentCollector,

    fn deinit(self: *MockedBank) void {
        self.accounts.deinit(self.allocator);
    }
};

fn Bank(comptime kind: BankKind) type {
    return struct {
        inner: kind.T(),
        const Self = @This();
        fn allocator(self: Self) std.mem.Allocator {
            return switch (kind) {
                .AccountsDb => self.inner.accounts_db.allocator,
                .Mocked => self.inner.allocator,
            };
        }
        fn slot(self: Self) ?Slot {
            return switch (kind) {
                .AccountsDb => self.inner.bank_fields.slot,
                .Mocked => self.inner.slot,
            };
        }
        fn rentCollector(self: Self) RentCollector {
            return switch (kind) {
                .AccountsDb => self.inner.bank_fields.rent_collector,
                .Mocked => self.inner.rent_collector,
            };
        }
        fn getAccount(self: Self, pubkey: *const sig.core.Pubkey) !sig.core.Account {
            return switch (kind) {
                .AccountsDb => self.inner.accounts_db.getAccount(pubkey),
                .Mocked => self.inner.accounts.get(pubkey.*) orelse return error.PubkeyNotInIndex,
            };
        }
        fn getAccountSharedData(
            self: Self,
            data_allocator: std.mem.Allocator,
            pubkey: *const sig.core.Pubkey,
        ) !?AccountSharedData {
            const account: sig.core.Account = self.getAccount(pubkey) catch |err| switch (err) {
                error.PubkeyNotInIndex => return null,
                else => return err,
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

pub const RentDebit = struct {
    rent_collected: u64,
    rent_balance: u64,
};

const LoadedTransactionAccount = struct {
    account: AccountSharedData,
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

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L154
pub fn AccountLoader(comptime bank_kind: BankKind) type {
    return struct {
        const Self = @This();
        const Cache = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData);

        // reviewer's note: Thinking we should allocate all shared accounts within a transaction
        // with this allocator and use an arena?
        allocator: std.mem.Allocator, // allocates Cache + all shared account data
        account_cache: Cache = .{}, // never evicted from, exists for whole transaction
        bank: Bank(bank_kind),
        features: *const runtime.FeatureSet,

        // note: no account overrides implemented here
        fn newWithCacheCapacity(
            allocator: std.mem.Allocator,
            bank: Bank(bank_kind),
            features: *const runtime.FeatureSet,
            capacity: usize,
        ) !Self {
            var account_cache: Cache = .{};
            account_cache.ensureUnusedCapacity(allocator, capacity);
            return .{
                .allocator = allocator,
                .account_cache = account_cache,
                .bank = bank,
                .features = features,
            };
        }

        fn loadAccount(
            self: *@This(),
            key: *const Pubkey,
            is_writable: bool,
        ) !?LoadedTransactionAccount {
            const account = blk: {
                if (self.account_cache.get(key.*)) |account| {
                    // a previous transaction deallocated this account.
                    break :blk if (account.lamports == 0) null else account;
                }

                if (try self.bank.getAccountSharedData(self.allocator, key)) |account| {
                    try self.account_cache.put(self.allocator, key.*, account);
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
    };
}

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L568
fn loadTransactionAccount(
    comptime bank_kind: BankKind,
    account_loader: *AccountLoader(bank_kind),
    tx: *const sig.core.Transaction,
    account_key: *const sig.core.Pubkey,
    account_idx: usize,
    rent_collector: *const sig.core.rent_collector.RentCollector,
    feature_set: *const runtime.FeatureSet,
) !LoadedTransactionAccount {
    if (account_key.equals(&runtime.ids.SYSVAR_INSTRUCTIONS_ID)) {
        @setCold(true);
        return .{
            .account = try constructInstructionsAccount(account_loader.allocator, tx),
            .loaded_size = 0,
            .rent_collected = 0,
        };
    }

    const is_writable = tx.msg.isWritable(account_idx);

    var maybe_loaded_account: ?LoadedTransactionAccount = try account_loader.loadAccount(
        account_key,
        is_writable,
    );

    return if (maybe_loaded_account) |*loaded_account| blk: {
        if (is_writable) loaded_account.rent_collected = collectRentFromAccount(
            &loaded_account.account,
            account_key,
            feature_set,
            rent_collector,
        ).rent_amount;

        break :blk loaded_account.*;
    } else LoadedTransactionAccount.DEFAULT;
}

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L293
fn collectRentFromAccount(
    account: *AccountSharedData,
    account_key: *const sig.core.Pubkey,
    feature_set: *const runtime.FeatureSet,
    rent_collector: *const sig.core.rent_collector.RentCollector,
) sig.core.rent_collector.CollectedInfo {
    if (!feature_set.active.contains(runtime.features.DISABLE_RENT_FEES_COLLECTION)) {
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

// [agave] https://github.com/anza-xyz/agave/blob/bb5a6e773d5f41388a962c5c4f96f5f2ef2209d0/svm/src/account_loader.rs#L425
fn loadTransactionAccountsInner(
    comptime bank_kind: BankKind,
    allocator: std.mem.Allocator,
    tx: *const sig.core.Transaction,
    requested_max_total_data_size: u32, // should be inside the tx?
    account_loader: *AccountLoader(bank_kind),
    features: *const runtime.FeatureSet,
    rent_collector: *const sig.core.rent_collector.RentCollector,
) !LoadedAccounts {
    var retval: LoadedAccounts = .{
        // safe: upon success, these will be set for every account index
        .accounts_buf = undefined,
        .rent_debits = undefined,
    };
    // attempt to load and collect accounts
    for (tx.msg.account_keys, 0..) |account_key, account_idx| {
        const loaded_account = try loadTransactionAccount(
            bank_kind,
            account_loader,
            tx,
            &account_key,
            account_idx,
            rent_collector,
            features,
        );
        retval.accounts_buf[account_idx] = loaded_account.account;

        retval.collected_rent += loaded_account.rent_collected;
        retval.rent_debits[account_idx] = .{
            .rent_collected = loaded_account.rent_collected,
            .rent_balance = loaded_account.account.lamports,
        };

        try accumulateAndCheckLoadedAccountDataSize(
            &retval.loaded_account_data_size,
            loaded_account.loaded_size,
            requested_max_total_data_size,
        );
    }

    var validated_loaders = std.AutoArrayHashMap(Pubkey, void).init(allocator);
    defer validated_loaders.deinit();

    // load and check the program of each instruction, and the owner of each program

    // I'm not sure why we load the programs as their keys would have been in .account_keys, which
    // means they could have been loaded already in the previous loop. This matches agave.
    for (tx.msg.instructions) |instruction| {
        const program_id = &tx.msg.account_keys[instruction.program_index];

        if (program_id.equals(&runtime.ids.NATIVE_LOADER_ID)) {
            continue;
        }

        const program_account = (try account_loader.loadAccount(program_id, false)) orelse
            return error.ProgramAccountNotFound;

        if (!program_account.account.executable and
            !features.active.contains(runtime.features.REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS))
        {
            return error.InvalidProgramForExecution;
        }

        const owner_id = &program_account.account.owner;
        if (owner_id.equals(&runtime.ids.NATIVE_LOADER_ID)) {
            continue;
        }

        // only load + count owners once
        if (validated_loaders.contains(owner_id.*)) {
            continue;
        }

        const owner_account = (try account_loader.loadAccount(owner_id, false)) orelse
            return error.ProgramAccountNotFound;

        if (!owner_account.account.owner.equals(&runtime.ids.NATIVE_LOADER_ID) or
            (!program_account.account.executable and
            !features.active.contains(runtime.features.REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS)))
        {
            return error.InvalidProgramForExecution;
        }

        try accumulateAndCheckLoadedAccountDataSize(
            &retval.loaded_account_data_size,
            owner_account.loaded_size,
            requested_max_total_data_size,
        );

        try validated_loaders.put(owner_id.*, {});
    }

    return retval;
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
        .allocator = allocator,
        .features = &runtime.FeatureSet.EMPTY,
        .bank = .{
            .inner = .{
                .allocator = allocator,
                .slot = 0,
                .accounts = .{},
                .rent_collector = sig.core.rent_collector.defaultCollector(0),
            },
        },
    };
}

test "loadTransactionAccounts empty transaction" {
    const allocator = std.testing.allocator;
    const tx = sig.core.Transaction.EMPTY;

    var account_loader = newAccountLoader(allocator);
    _ = try loadTransactionAccountsInner(
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

    const loaded = try loadTransactionAccountsInner(
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
    for (loaded.accounts_buf[0..tx.msg.account_keys.len]) |account| {
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
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const allocator = arena.allocator();

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
    defer account_loader.bank.inner.deinit();

    var data: [1024]u8 = undefined;
    prng.fill(&data);

    const NATIVE_LOADER_ID = runtime.ids.NATIVE_LOADER_ID;

    try account_loader.bank.inner.accounts.put(allocator, fee_payer_address, sig.core.Account{
        .data = .{ .unowned_allocation = &data },
        .lamports = fee_payer_balance,
        .executable = false,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });

    try account_loader.bank.inner.accounts.put(allocator, instruction_address, sig.core.Account{
        .data = .{ .unowned_allocation = instruction_data },
        .lamports = 1,
        .executable = true,
        .owner = NATIVE_LOADER_ID,
        .rent_epoch = 0,
    });
    try account_loader.bank.inner.accounts.put(allocator, NATIVE_LOADER_ID, sig.core.Account{
        .data = .{ .empty = .{ .len = 0 } },
        .lamports = 1,
        .executable = true,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });
    try account_loader.bank.inner.accounts.put(allocator, Pubkey.ZEROES, sig.core.Account{
        .data = .{ .empty = .{ .len = 0 } },
        .lamports = 0,
        .executable = true,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });

    const loaded = try loadTransactionAccountsInner(
        .Mocked,
        allocator,
        &tx,
        64 * 1024 * 1024,
        &account_loader,
        &runtime.FeatureSet.EMPTY,
        &sig.core.rent_collector.defaultCollector(0),
    );

    var found: usize = 0;
    for (loaded.accounts_buf[0..tx.msg.account_keys.len]) |account| {
        found += 1;
        allocator.free(account.data);
    }

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
