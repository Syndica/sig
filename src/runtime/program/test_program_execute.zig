const std = @import("std");
const sig = @import("../../sig.zig");

const bincode = sig.bincode;

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;

const FeatureSet = sig.runtime.FeatureSet;
const InstructionContext = sig.runtime.InstructionContext;
const InstructionAccountInfo = sig.runtime.InstructionAccountInfo;
const LogCollector = sig.runtime.LogCollector;
const SysvarCache = sig.runtime.SysvarCache;
const TransactionContext = sig.runtime.TransactionContext;
const TransactionAccount = sig.runtime.TransactionAccount;

const TransactionAccountParams = struct {
    pubkey: Pubkey,
    lamports: u64 = 0,
    data: []const u8 = &.{},
    owner: Pubkey = Pubkey.ZEROES,
    executable: bool = false,
    rent_epoch: u64 = 0,
};

const TransactionContextParams = struct {
    accounts: []const TransactionAccountParams,
    accounts_resize_delta: i64 = 0,
    compute_meter: u64 = 0,
    custom_error: ?u32 = null,
    log_collector: ?LogCollector = null,
    sysvar_cache: SysvarCache = .{},
    lamports_per_signature: u64 = 0,
    last_blockhash: Hash = Hash.ZEROES,
    feature_set: FeatureSet = FeatureSet.EMPTY,
};

pub fn createTransactionContext(
    allocator: std.mem.Allocator,
    params: TransactionContextParams,
) !TransactionContext {
    var accounts = std.ArrayList(TransactionAccount).init(allocator);
    for (params.accounts) |account_params|
        try accounts.append(TransactionAccount.init(account_params.pubkey, .{
            .lamports = account_params.lamports,
            .data = try allocator.dupe(u8, account_params.data),
            .owner = account_params.owner,
            .executable = account_params.executable,
            .rent_epoch = account_params.rent_epoch,
        }));
    return .{
        .accounts = try accounts.toOwnedSlice(),
        .accounts_resize_delta = params.accounts_resize_delta,
        .compute_meter = params.compute_meter,
        .custom_error = params.custom_error,
        .log_collector = params.log_collector,
        .sysvar_cache = params.sysvar_cache,
        .lamports_per_signature = params.lamports_per_signature,
        .last_blockhash = params.last_blockhash,
        .feature_set = params.feature_set,
    };
}

pub fn createInstructionContext(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
    program: anytype,
    instruction: anytype,
    accounts_params: []const InstructionAccountInfoParams,
) !InstructionContext {
    const program_index = blk: {
        for (tc.accounts, 0..) |account, index|
            if (account.pubkey.equals(&program.ID))
                break :blk index;
        return error.CoulfNotFindProgramAccount;
    };

    var accounts = std.ArrayList(InstructionAccountInfo).init(allocator);
    for (accounts_params) |account_params| {
        if (account_params.index_in_transaction >= tc.accounts.len)
            return error.AccountIndexOutOfBounds;
        try accounts.append(.{
            .pubkey = tc.accounts[account_params.index_in_transaction].pubkey,
            .is_signer = account_params.is_signer,
            .is_writable = account_params.is_writable,
            .index_in_transaction = account_params.index_in_transaction,
        });
    }

    return .{
        .tc = tc,
        .program_id = program.ID,
        .program_index = @intCast(program_index),
        .instruction = try bincode.writeAlloc(allocator, instruction, .{}),
        .accounts = try accounts.toOwnedSlice(),
    };
}

const InstructionAccountInfoParams = struct {
    is_signer: bool = false,
    is_writable: bool = false,
    index_in_transaction: u16 = 0,
};

pub fn expectProgramExecuteResult(
    allocator: std.mem.Allocator,
    program: anytype,
    instruction: anytype,
    instruction_accounts_params: []const InstructionAccountInfoParams,
    transaction_context_params: TransactionContextParams,
    expected_transaction_context_params: TransactionContextParams,
) !void {
    var transaction_context = try createTransactionContext(
        allocator,
        transaction_context_params,
    );
    defer {
        for (transaction_context.accounts) |account|
            allocator.free(account.account.data);
        allocator.free(transaction_context.accounts);
    }

    var instruction_context = try createInstructionContext(
        allocator,
        &transaction_context,
        program,
        instruction,
        instruction_accounts_params,
    );
    defer {
        allocator.free(instruction_context.instruction);
        allocator.free(instruction_context.accounts);
    }

    try program.execute(allocator, &instruction_context);

    const expected_transaction_context = try createTransactionContext(
        allocator,
        expected_transaction_context_params,
    );
    defer {
        for (expected_transaction_context.accounts) |account|
            allocator.free(account.account.data);
        allocator.free(expected_transaction_context.accounts);
    }

    try expectTransactionContextEqual(expected_transaction_context, transaction_context);
}

pub fn expectTransactionAccountEqual(
    expected: TransactionAccount,
    actual: TransactionAccount,
) !void {
    if (!expected.pubkey.equals(&actual.pubkey))
        return error.PubkeyMismatch;
    if (expected.account.lamports != actual.account.lamports)
        return error.LamportsMismatch;
    if (!std.mem.eql(u8, expected.account.data, actual.account.data))
        return error.DataMismatch;
    if (!expected.account.owner.equals(&actual.account.owner))
        return error.OwnerMismatch;
    if (expected.account.executable != actual.account.executable)
        return error.ExecutableMismatch;
    if (expected.account.rent_epoch != actual.account.rent_epoch)
        return error.RentEpochMismatch;
    if (expected.read_refs != actual.read_refs)
        return error.ReadRefsMismatch;
    if (expected.write_ref != actual.write_ref)
        return error.WriteRefMismatch;
}

pub fn expectTransactionContextEqual(
    expected: TransactionContext,
    actual: TransactionContext,
) !void {
    if (expected.accounts.len != actual.accounts.len)
        return error.AccountsLengthMismatch;

    for (expected.accounts, 0..) |expected_account, index| {
        const actual_account = actual.accounts[index];
        expectTransactionAccountEqual(expected_account, actual_account) catch
            return error.AccountMismatch;
    }

    if (expected.accounts_resize_delta != actual.accounts_resize_delta)
        return error.AccountsResizeDeltaMismatch;

    if (expected.compute_meter != actual.compute_meter)
        return error.ComputeMeterMismatch;

    if (expected.custom_error != actual.custom_error)
        return error.MaybeCustomErrorMismatch;

    // TODO: implement eqls for LogCollector
    // if (expected.maybe_log_collector != actual.maybe_log_collector)
    //     return error.MaybeLogCollectorMismatch;

    // TODO: implement eqls for SysvarCache
    // if (expected.sysvar_cache != actual.sysvar_cache)
    //     return error.SysvarCacheMismatch;

    if (expected.lamports_per_signature != actual.lamports_per_signature)
        return error.LamportsPerSignatureMismatch;

    if (!expected.last_blockhash.eql(actual.last_blockhash))
        return error.LastBlockhashMismatch;

    // TODO: implement eqls for FeatureSet
    // if (expected.feature_set != actual.feature_set)
    //     return error.FeatureSetMismatch;
}
