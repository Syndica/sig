const std = @import("std");
const sig = @import("../../sig.zig");

const bincode = sig.bincode;
const executor = sig.runtime.executor;

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;
const Transaction = sig.core.Transaction;

const FeatureSet = sig.runtime.FeatureSet;
const InstructionContext = sig.runtime.InstructionContext;
const InstructionInfo = sig.runtime.InstructionInfo;
const LogCollector = sig.runtime.LogCollector;
const SysvarCache = sig.runtime.SysvarCache;
const TransactionContext = sig.runtime.TransactionContext;
const TransactionContextAccount = sig.runtime.TransactionContextAccount;

const TransactionContextAccountParams = struct {
    pubkey: Pubkey,
    lamports: u64 = 0,
    data: []const u8 = &.{},
    owner: Pubkey = Pubkey.ZEROES,
    executable: bool = false,
    rent_epoch: u64 = 0,
};

const TransactionContextParams = struct {
    accounts: []const TransactionContextAccountParams,
    accounts_resize_delta: i64 = 0,
    compute_meter: u64 = 0,
    custom_error: ?u32 = null,
    log_collector: ?LogCollector = null,
    sysvar_cache: SysvarCache = .{},
    lamports_per_signature: u64 = 0,
    last_blockhash: Hash = Hash.ZEROES,
    feature_set: FeatureSet = FeatureSet.EMPTY,
};

const InstructionContextAccountMetaParams = struct {
    index_in_transaction: u16 = 0,
    index_in_caller: ?u16 = null,
    index_in_callee: ?u16 = null,
    is_signer: bool = false,
    is_writable: bool = false,
};

pub fn createTransactionContext(
    allocator: std.mem.Allocator,
    params: TransactionContextParams,
) !TransactionContext {
    var accounts = std.ArrayList(TransactionContextAccount).init(allocator);
    for (params.accounts) |account_params| {
        try accounts.append(TransactionContextAccount.init(account_params.pubkey, .{
            .lamports = account_params.lamports,
            .data = try allocator.dupe(u8, account_params.data),
            .owner = account_params.owner,
            .executable = account_params.executable,
            .rent_epoch = account_params.rent_epoch,
        }));
    }

    return .{
        .accounts = try accounts.toOwnedSlice(),
        .return_data = .{},
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

pub fn createInstructionInfo(
    tc: *TransactionContext,
    program_pubkey: Pubkey,
    instruction_data: []const u8,
    accounts_params: []const InstructionContextAccountMetaParams,
) !InstructionInfo {
    const program_index = blk: {
        for (tc.accounts, 0..) |account, index| {
            if (account.pubkey.equals(&program_pubkey)) break :blk index;
        }
        return error.CoulfNotFindProgramAccount;
    };

    var account_metas = InstructionInfo.AccountMetas{};
    for (accounts_params, 0..) |account_params, index| {
        if (account_params.index_in_transaction >= tc.accounts.len) {
            return error.AccountIndexOutOfBounds;
        }

        const index_in_callee = blk: {
            for (0..index) |i| {
                if (account_params.index_in_transaction ==
                    accounts_params[i].index_in_transaction)
                {
                    break :blk i;
                }
            }
            break :blk index;
        };

        try account_metas.append(.{
            .pubkey = tc.accounts[account_params.index_in_transaction].pubkey,
            .index_in_transaction = account_params.index_in_transaction,
            .index_in_caller = account_params.index_in_caller orelse account_params.index_in_transaction,
            .index_in_callee = account_params.index_in_callee orelse @intCast(index_in_callee),
            .is_signer = account_params.is_signer,
            .is_writable = account_params.is_writable,
        });
    }

    return .{
        .program_meta = .{
            .pubkey = program_pubkey,
            .index_in_transaction = @intCast(program_index),
        },
        .account_metas = account_metas,
        .instruction_data = instruction_data,
    };
}

pub fn expectProgramExecuteResult(
    allocator: std.mem.Allocator,
    program: anytype,
    instruction: anytype,
    instruction_accounts_params: []const InstructionContextAccountMetaParams,
    transaction_context_params: TransactionContextParams,
    expected_transaction_context_params: TransactionContextParams,
) !void {
    var transaction_context = try createTransactionContext(
        allocator,
        transaction_context_params,
    );
    defer transaction_context.deinit(allocator);

    var instruction_info = blk: {
        const instruction_data = try bincode.writeAlloc(
            allocator,
            instruction,
            .{},
        );
        errdefer allocator.free(instruction_data);

        break :blk try createInstructionInfo(
            &transaction_context,
            program.ID,
            instruction_data,
            instruction_accounts_params,
        );
    };
    defer instruction_info.deinit(allocator);

    try executor.executeInstruction(
        allocator,
        &transaction_context,
        instruction_info,
    );

    const expected_transaction_context = try createTransactionContext(
        allocator,
        expected_transaction_context_params,
    );
    defer expected_transaction_context.deinit(allocator);

    try expectTransactionContextEqual(expected_transaction_context, transaction_context);
}

pub fn expectTransactionAccountEqual(
    expected: TransactionContextAccount,
    actual: TransactionContextAccount,
) !void {
    if (!expected.pubkey.equals(&actual.pubkey))
        return error.PubkeyMismatch;
    if (expected.account.lamports != actual.account.lamports)
        return error.LamportsMismatch;
    if (!std.mem.eql(u8, expected.account.data, actual.account.data)) {
        std.debug.print("\nexpected: {any}", .{expected.account.data});
        std.debug.print("\nactual:   {any}\n", .{actual.account.data});
        return error.DataMismatch;
    }
    if (!expected.account.owner.equals(&actual.account.owner))
        return error.OwnerMismatch;
    if (expected.account.executable != actual.account.executable) {
        std.debug.print("\nexpected: {any}", .{expected.account.executable});
        std.debug.print("\nactual:   {any}\n", .{actual.account.executable});
        return error.ExecutableMismatch;
    }
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
        expectTransactionAccountEqual(expected_account, actual_account) catch {
            std.debug.print("account_index={}\n", .{index});
            return error.AccountMismatch;
        };
    }

    if (expected.accounts_resize_delta != actual.accounts_resize_delta) {
        std.debug.print("\nexpected: {}", .{expected.accounts_resize_delta});
        std.debug.print("\nactual:   {}\n", .{actual.accounts_resize_delta});
        return error.AccountsResizeDeltaMismatch;
    }

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
