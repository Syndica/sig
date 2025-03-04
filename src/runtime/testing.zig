const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const Pubkey = sig.core.Pubkey;
const Hash = sig.core.Hash;

const FeatureSet = sig.runtime.FeatureSet;
const InstructionInfo = sig.runtime.InstructionInfo;
const LogCollector = sig.runtime.LogCollector;
const SysvarCache = sig.runtime.SysvarCache;
const TransactionContext = sig.runtime.TransactionContext;
const TransactionContextAccount = sig.runtime.TransactionContextAccount;

pub const TransactionContextAccountParams = struct {
    pubkey: Pubkey,
    lamports: u64 = 0,
    data: []const u8 = &.{},
    owner: Pubkey = Pubkey.ZEROES,
    executable: bool = false,
    rent_epoch: u64 = 0,
};

pub const TransactionContextParams = struct {
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

pub const InstructionContextAccountMetaParams = struct {
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
    if (!builtin.is_test)
        @compileError("createTransactionContext should only be called in test mode");

    var accounts = std.ArrayList(TransactionContextAccount).init(allocator);
    for (params.accounts) |account_params| {
        try accounts.append(
            TransactionContextAccount.init(account_params.pubkey, .{
                .lamports = account_params.lamports,
                .data = try allocator.dupe(u8, account_params.data),
                .owner = account_params.owner,
                .executable = account_params.executable,
                .rent_epoch = account_params.rent_epoch,
            }),
        );
    }

    return .{
        .accounts = try accounts.toOwnedSlice(),
        .instruction_stack = .{},
        .instruction_trace = .{},
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
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
    program_id: Pubkey,
    instruction: anytype,
    accounts_params: []const InstructionContextAccountMetaParams,
) !InstructionInfo {
    if (!builtin.is_test)
        @compileError("createInstructionContext should only be called in test mode");

    const program_index_in_transaction = blk: {
        for (tc.accounts, 0..) |account, index| {
            if (account.pubkey.equals(&program_id)) break :blk index;
        }
        return error.CoulfNotFindProgramAccount;
    };

    var account_metas = InstructionInfo.AccountMetas{};
    for (accounts_params, 0..) |acc, idx| {
        if (acc.index_in_transaction >= tc.accounts.len) {
            return error.AccountIndexOutOfBounds;
        }

        const index_in_callee = blk: {
            for (0..idx) |i| {
                if (acc.index_in_transaction ==
                    accounts_params[i].index_in_transaction)
                {
                    break :blk i;
                }
            }
            break :blk idx;
        };

        try account_metas.append(.{
            .pubkey = tc.accounts[acc.index_in_transaction].pubkey,
            .index_in_transaction = acc.index_in_transaction,
            .index_in_caller = acc.index_in_caller orelse acc.index_in_transaction,
            .index_in_callee = acc.index_in_callee orelse @intCast(index_in_callee),
            .is_signer = acc.is_signer,
            .is_writable = acc.is_writable,
        });
    }

    return .{
        .program_meta = .{
            .pubkey = program_id,
            .index_in_transaction = @intCast(program_index_in_transaction),
        },
        .account_metas = account_metas,
        .instruction_data = try bincode.writeAlloc(
            allocator,
            instruction,
            .{},
        ),
    };
}

pub fn expectTransactionContextEqual(
    expected: TransactionContext,
    actual: TransactionContext,
) !void {
    if (!builtin.is_test)
        @compileError("expectTransactionContextEqual should only be called in test mode");

    if (expected.accounts.len != actual.accounts.len)
        return error.AccountsLengthMismatch;

    for (expected.accounts, 0..) |expected_account, index|
        try expectTransactionAccountEqual(
            expected_account,
            actual.accounts[index],
        );

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

pub fn expectTransactionAccountEqual(
    expected: TransactionContextAccount,
    actual: TransactionContextAccount,
) !void {
    if (!builtin.is_test)
        @compileError("expectTransactionAccountEqual should only be called in test mode");
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
