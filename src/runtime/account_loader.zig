const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const AccountSharedData = sig.runtime.AccountSharedData;
const Hash = sig.core.Hash;
const RentCollector = sig.runtime.rent_collector.RentCollector;

// [firedancer] https://github.com/firedancer-io/firedancer/blob/ddde57c40c4d4334c25bb32de17f833d4d79a889/src/ballet/txn/fd_txn.h#L116
const MAX_TX_ACCOUNT_LOCKS = 128;

pub const LoadedAccounts = struct {
    collected_rent: u64 = 0,
    accounts: [MAX_TX_ACCOUNT_LOCKS]?AccountSharedData = .{null} ** MAX_TX_ACCOUNT_LOCKS,
};

// [firedancer] https://github.com/firedancer-io/firedancer/blob/49056135a4c7ba024cb75a45925439239904238b/src/flamenco/runtime/fd_executor.c#L377
// firedancer actually already has the accounts data ready at this point, but Agave calls into the
// bank's callbacks into accountsdb (with the exception of [0] - the fee payer). I like the idea of
// loading them up first, but going with the bank for now.
pub fn loadTransactionAccounts(
    allocator: std.mem.Allocator,
    tx: *const sig.core.Transaction,
    requested_max_total_data_size: u32, // should be inside the tx?
    bank: sig.accounts_db.Bank,
    features: sig.runtime.FeatureSet,
) !LoadedAccounts {
    return try loadTransactionAccountsInner(
        .AccountsDb,
        allocator,
        tx,
        requested_max_total_data_size,
        Bank(.AccountsDb){ .inner = bank },
        features,
    );
}

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
    };
}

fn loadTransactionAccountsInner(
    comptime bank_kind: BankKind,
    allocator: std.mem.Allocator,
    tx: *const sig.core.Transaction,
    requested_max_total_data_size: u32, // should be inside the tx?
    bank: Bank(bank_kind),
    features: sig.runtime.FeatureSet,
) !LoadedAccounts {
    const account_in_instr = blk: {
        var buf_instr = [_]bool{false} ** MAX_TX_ACCOUNT_LOCKS;
        for (tx.msg.instructions) |instruction| {
            for (instruction.account_indexes) |account_index| {
                buf_instr[account_index] = true;
            }
        }
        break :blk buf_instr;
    };

    var retval: LoadedAccounts = .{};
    errdefer {
        for (retval.accounts) |maybe_account| {
            if (maybe_account) |account| allocator.free(account.data);
        }
    }

    const disable_account_loader_special_case = true;
    // TODO: properly check this once we support false
    // const disable_account_loader_special_case = features.active.contains(
    //     sig.runtime.feature_set.DISABLE_ACCOUNT_LOADER_SPECIAL_CASE,
    // );

    var accumulated_account_size: u32 = 0;

    for (tx.msg.account_keys, 0..) |account_key, account_idx| {
        const is_instruction_account = account_in_instr[account_idx];
        const is_writeable = tx.msg.isWriteable(account_idx);

        var account_data_size: usize = 0;

        // case 1: account is instructions sysvar.
        //         Do not count it towards the total loaded account size.
        if (account_key.equals(&sig.runtime.ids.SYSVAR_INSTRUCTIONS_ID)) {
            @setCold(true);
            retval.accounts[account_idx] = try constructInstructionsAccount(allocator, tx);
            continue;
        }

        // case 2: account is not writeable, not a program account, and may be in loaded program cache.
        //         https://github.com/anza-xyz/agave/pull/3548 > "This "optimization" actually costs us performance"
        if (!is_instruction_account and
            !is_writeable and
            !disable_account_loader_special_case and
            isMaybeInLoadedProgramCache(account_key))
        {
            @setCold(true);
            @panic("TODO: Assuming the feature is enabled");
        }

        // case 3: default case
        const found_account = try bank.getAccount(&account_key);
        defer found_account.deinit(bank.allocator());

        var found_shared_account: AccountSharedData = .{
            .data = try found_account.data.readAllAllocate(allocator),
            .executable = found_account.executable,
            .lamports = found_account.lamports,
            .owner = found_account.owner,
            .rent_epoch = found_account.rent_epoch,
        };

        defer retval.accounts[account_idx] = found_shared_account;
        account_data_size += found_shared_account.data.len;
        if (is_writeable) {
            const collected = bank.rentCollector().collectFromExistingAccount(
                &account_key,
                &found_shared_account,
            );
            retval.collected_rent += collected.rent_amount;
        }

        try accumulateAndCheckLoadedAccountDataSize(
            &accumulated_account_size,
            account_data_size,
            requested_max_total_data_size,
        );
    }

    const remove_accounts_executable_flag_checks = features.active.contains(
        sig.runtime.feature_set.REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS,
    );

    for (tx.msg.instructions) |instr| {
        const program_id = tx.msg.account_keys[instr.program_index];

        if (program_id.equals(&sig.runtime.ids.NATIVE_LOADER_ID)) continue;

        const program_account = retval.accounts[instr.program_index] orelse
            return error.ProgramAccountNotFound;

        if (!remove_accounts_executable_flag_checks and !program_account.executable)
            return error.InvalidProgramForExecution;

        if (program_account.owner.equals(&sig.runtime.ids.NATIVE_LOADER_ID)) continue;

        const found_owner = bank.getAccount(&program_account.owner) catch
            return error.ProgramAccountNotFound;
        defer found_owner.deinit(bank.allocator());

        const owner: AccountSharedData = .{
            .data = try found_owner.data.readAllAllocate(allocator),
            .executable = found_owner.executable,
            .lamports = found_owner.lamports,
            .owner = found_owner.owner,
            .rent_epoch = found_owner.rent_epoch,
        };

        if ((!owner.owner.equals(&sig.runtime.ids.NATIVE_LOADER_ID) or
            !remove_accounts_executable_flag_checks) and
            !owner.executable)
        {
            return error.InvalidProgramForExecution;
        }

        // Seems we're not supposed to double-count owners, but firedancer and agave seem to both
        // currently double count. Reported bug to FD team, fix is merged: https://github.com/firedancer-io/firedancer/pull/4714
        // https://github.com/firedancer-io/firedancer/blob/f8262f71bc3d78ba3a6e0d89a9825434b93b156f/src/flamenco/runtime/fd_executor.c#L516-L523

        try accumulateAndCheckLoadedAccountDataSize(
            &accumulated_account_size,
            owner.data.len,
            requested_max_total_data_size,
        );
    }

    return retval;
}

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

const BorrowedAccountMeta = struct {
    pubkey: Pubkey,
    is_signer: bool,
    is_writeable: bool,
};
const BorrowedInstruction = struct {
    program_id: Pubkey,
    accounts: []const BorrowedAccountMeta,
    data: []const u8,
};

// [agave] https://github.com/anza-xyz/agave/blob/cb32984a9b0d5c2c6f7775bed39b66d3a22e3c46/svm/src/account_loader.rs#L639
fn constructInstructionsAccount(
    allocator: std.mem.Allocator,
    tx: *const sig.core.Transaction,
) !AccountSharedData {
    var decompiled_instructions = try std.ArrayList(BorrowedInstruction).initCapacity(
        allocator,
        tx.msg.instructions.len,
    );
    errdefer {
        for (decompiled_instructions.items) |decompiled| allocator.free(decompiled.data);
        decompiled_instructions.deinit();
    }

    for (tx.msg.instructions) |instruction| {
        const accounts_meta = try allocator.alloc(
            BorrowedAccountMeta,
            instruction.account_indexes.len,
        );
        errdefer comptime unreachable;

        for (instruction.account_indexes, accounts_meta) |account_idx, *account_meta| {
            account_meta.* = .{
                .pubkey = tx.msg.account_keys[account_idx],
                .is_signer = tx.msg.isSigner(account_idx),
                .is_writeable = tx.msg.isWriteable(account_idx),
            };
        }

        decompiled_instructions.appendAssumeCapacity(.{
            .accounts = accounts_meta,
            .data = instruction.data,
            .program_id = tx.msg.account_keys[instruction.program_index],
        });
    }

    // [agave] solana-instructions-sysvar-2.2.1/src/lib.rs:68
    var data = try serializeInstructions(allocator, decompiled_instructions.items);
    errdefer data.deinit();
    try data.appendSlice(&.{ 0, 0 }); // room for current instruction index

    return .{
        .data = try data.toOwnedSlice(),
        .owner = sig.runtime.ids.SYSVAR_INSTRUCTIONS_ID,
        .lamports = 0, // a bit weird, but seems correct
        .executable = false,
        .rent_epoch = 0,
    };
}

// required for DISABLE_ACCOUNT_LOADER_SPECIAL_CASE=false (not yet supported)
fn isMaybeInLoadedProgramCache(account: Pubkey) bool {
    // const keys = .{
    //     sig.runtime.ids.BPF_LOADER_DEPRECATED_ID,
    //     sig.runtime.ids.BPF_LOADER_ID,
    //     sig.runtime.ids.BPF_LOADER_UPGRADEABLE_ID,
    //     sig.runtime.ids.BPF_LOADER_V4_ID,
    // };
    // for (keys) |key| if (key.equals(owner_key)) return true;
    // return false;

    _ = account;
    @panic("TODO: get account's owner");
}

// [agave] solana-instructions-sysvar-2.2.1/src/lib.rs:77
const InstructionsSysvarAccountMeta = packed struct(u8) {
    is_signer: bool,
    is_writeable: bool,
    _: u6 = 0, // padding
};

// TODO: this should live somewhere else
// [agave] solana-instructions-sysvar-2.2.1/src/lib.rs:99
// First encode the number of instructions:
// [0..2 - num_instructions
//
// Then a table of offsets of where to find them in the data
//  3..2 * num_instructions table of instruction offsets
//
// Each instruction is then encoded as:
//   0..2 - num_accounts
//   2 - meta_byte -> (bit 0 signer, bit 1 is_writeable)
//   3..35 - pubkey - 32 bytes
//   35..67 - program_id
//   67..69 - data len - u16
//   69..data_len - data
pub fn serializeInstructions(
    allocator: std.mem.Allocator,
    instructions: []const BorrowedInstruction,
) !std.ArrayList(u8) {
    if (instructions.len > std.math.maxInt(u16)) unreachable;

    const asBytes = std.mem.asBytes;
    const nativeToLittle = std.mem.nativeToLittle;

    // estimated required capacity
    var data = try std.ArrayList(u8).initCapacity(allocator, instructions.len * 64);
    errdefer data.deinit();

    try data.appendSlice(asBytes(&nativeToLittle(u16, @intCast(instructions.len))));
    for (0..instructions.len) |_| try data.appendSlice(&.{ 0, 0 });

    for (instructions, 0..) |instruction, i| {
        const start_instruction_offset: u16 = @intCast(data.items.len);
        const start = 2 + (2 * i);
        @memcpy(
            data.items[start .. start + 2],
            asBytes(&nativeToLittle(u16, start_instruction_offset)),
        );
        try data.appendSlice(asBytes(&nativeToLittle(u16, @intCast(instruction.accounts.len))));

        for (instruction.accounts) |account_meta| {
            const flags: InstructionsSysvarAccountMeta = .{
                .is_signer = account_meta.is_signer,
                .is_writeable = account_meta.is_writeable,
            };
            try data.append(@bitCast(flags));
            try data.appendSlice(&account_meta.pubkey.data);
        }

        try data.appendSlice(&instruction.program_id.data);
        try data.appendSlice(asBytes(&nativeToLittle(u16, @intCast(instruction.data.len))));
        try data.appendSlice(instruction.data);
    }

    return data;
}

fn newBank(allocator: std.mem.Allocator) MockedBank {
    if (!@import("builtin").is_test) @compileError("newBank for testing only");
    return .{
        .allocator = allocator,
        .slot = 0,
        .accounts = .{},
        .rent_collector = sig.runtime.rent_collector.defaultCollector(0),
    };
}

test "loadTransactionAccounts empty transaction" {
    const allocator = std.testing.allocator;
    const tx = sig.core.Transaction.EMPTY;

    const bank = newBank(allocator);
    _ = try loadTransactionAccountsInner(
        .Mocked,
        allocator,
        &tx,
        100_000,
        Bank(.Mocked){ .inner = bank },
        sig.runtime.FeatureSet.EMPTY,
    );
}

// (does not test deserialisation - not implemented yet)
// [agave] https://github.com/anza-xyz/agave/blob/a00f1b5cdea9a7d5a70f8d24b86ea3ae66feff11/sdk/program/src/sysvar/instructions.rs#L520
test serializeInstructions {
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const program_id0 = Pubkey.initRandom(prng.random());
    const program_id1 = Pubkey.initRandom(prng.random());
    const id0 = Pubkey.initRandom(prng.random());
    const id1 = Pubkey.initRandom(prng.random());
    const id2 = Pubkey.initRandom(prng.random());
    const id3 = Pubkey.initRandom(prng.random());

    const instructions = [_]BorrowedInstruction{
        .{
            .program_id = program_id0,
            .accounts = &.{
                .{ .pubkey = id0, .is_signer = false, .is_writeable = false },
            },
            .data = &.{0},
        },
        .{
            .program_id = program_id0,
            .accounts = &.{
                .{ .pubkey = id1, .is_signer = true, .is_writeable = false },
            },
            .data = &.{0},
        },
        .{
            .program_id = program_id1,
            .accounts = &.{
                .{ .pubkey = id2, .is_signer = false, .is_writeable = true },
            },
            .data = &.{0},
        },
        .{
            .program_id = program_id1,
            .accounts = &.{
                .{ .pubkey = id3, .is_signer = true, .is_writeable = true },
            },
            .data = &.{0},
        },
    };

    const serialized = try serializeInstructions(allocator, &instructions);
    defer serialized.deinit();
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
            .account_keys = &.{sig.runtime.ids.SYSVAR_INSTRUCTIONS_ID},
            .recent_blockhash = .{ .data = [_]u8{0x00} ** Hash.SIZE },
            .instructions = &.{},
            .address_lookups = &.{},
        },
    };

    const bank = newBank(allocator);

    const loaded = try loadTransactionAccountsInner(
        .Mocked,
        allocator,
        &tx,
        100_000,
        Bank(.Mocked){ .inner = bank },
        sig.runtime.FeatureSet.EMPTY,
    );
    try std.testing.expectEqual(0, loaded.collected_rent);

    var returned_accounts: usize = 0;
    for (loaded.accounts) |maybe_account| {
        const account = maybe_account orelse continue;
        try std.testing.expectEqual(sig.runtime.ids.SYSVAR_INSTRUCTIONS_ID, account.owner);
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

    const tx: sig.core.Transaction = .{
        .signatures = &.{},
        .version = .legacy,
        .msg = .{
            .signature_count = 1, // fee payer is signer + writeable
            .readonly_signed_count = 0,
            .readonly_unsigned_count = 0,
            .account_keys = &.{fee_payer_address},
            .recent_blockhash = .{ .data = [_]u8{0x00} ** Hash.SIZE },
            .instructions = &.{},
            .address_lookups = &.{},
        },
    };

    const fee_payer_balance = 300;
    var fee_payer_account = AccountSharedData.EMPTY;
    fee_payer_account.lamports = fee_payer_balance;

    var bank = newBank(allocator);
    defer bank.deinit();

    var data: [1024]u8 = undefined;
    prng.fill(&data);

    try bank.accounts.put(allocator, fee_payer_address, sig.core.Account{
        .data = .{ .unowned_allocation = &data },
        .lamports = fee_payer_balance,
        .executable = false,
        .owner = Pubkey.ZEROES,
        .rent_epoch = 0,
    });

    const loaded = try loadTransactionAccountsInner(
        .Mocked,
        allocator,
        &tx,
        64 * 1024 * 1024,
        Bank(.Mocked){ .inner = bank },
        sig.runtime.FeatureSet.EMPTY,
    );

    var found: usize = 0;
    for (loaded.accounts) |maybe_account| {
        if (maybe_account) |account| {
            found += 1;
            allocator.free(account.data);
        }
    }

    // slots elapsed   slots per year      lamports per year
    //  |               |                   |      data len
    //  |               |                   |       |     overhead
    //  v               v                   v       v      v
    // (64) / (7.8892314983999997e7)   * (3480 * (1024 + 128))
    const expected_rent = 3;

    try std.testing.expectEqual(expected_rent, loaded.collected_rent);
    try std.testing.expectEqual(1, found);
}
