const std = @import("std");
const sig = @import("../../sig.zig");

const RwMux = sig.sync.RwMux;
const Epoch = sig.core.Epoch;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Transaction = sig.core.Transaction;
const AccountSharedData = sig.runtime.AccountSharedData;
const ExecuteInstructionAccount = sig.runtime.ExecuteInstructionContext.AccountInfo;
const ExecuteInstructionContext = sig.runtime.ExecuteInstructionContext;
const ExecuteTransactionAccount = sig.runtime.ExecuteTransactionContext.AccountInfo;
const ExecuteTransactionContext = sig.runtime.ExecuteTransactionContext;
const FeatureSet = sig.runtime.FeatureSet;
const SysvarCache = sig.runtime.SysvarCache;

const MAX_INSTRUCTION_ACCOUNTS = sig.runtime.MAX_INSTRUCTION_ACCOUNTS;

const AccountSharedDataParams = struct {
    lamports: u64 = 0,
    data: []const u8 = &.{},
    owner: Pubkey = Pubkey.ZEROES,
    executable: bool = false,
    rent_epoch: u64 = 0,
};

pub fn createAccountSharedData(
    allocator: std.mem.Allocator,
    params: AccountSharedDataParams,
) !AccountSharedData {
    const data = try allocator.create(std.ArrayListUnmanaged(u8));
    data.* = std.ArrayListUnmanaged(u8){
        .capacity = params.data.len,
        .items = try allocator.dupe(u8, params.data),
    };
    return .{
        .lamports = params.lamports,
        .data = data,
        .owner = params.owner,
        .executable = params.executable,
        .rent_epoch = params.rent_epoch,
    };
}

pub fn createAccountSharedDatas(
    allocator: std.mem.Allocator,
    params: []const AccountSharedDataParams,
) ![]AccountSharedData {
    var account_shared_datas = std.ArrayList(AccountSharedData).init(allocator);

    for (params) |param|
        try account_shared_datas.append(try createAccountSharedData(allocator, param));

    return account_shared_datas.toOwnedSlice();
}

const ExecuteTransactionContextParams = struct {
    accounts_resize_delta: i64 = 0,
    compute_meter: u64 = 0,
    maybe_custom_error: ?u32 = null,
    sysvar_cache: SysvarCache = .{},
    lamports_per_signature: u64 = 0,
    last_blockhash: Hash = Hash.ZEROES,
};

pub fn createExecuteTransactionContext(
    accounts: []const AccountSharedData,
    params: ExecuteTransactionContextParams,
) !ExecuteTransactionContext {
    var etc_accounts = std.BoundedArray(
        RwMux(ExecuteTransactionAccount),
        Transaction.MAX_ACCOUNTS,
    ){};

    for (accounts) |account_shared_data|
        try etc_accounts.append(RwMux(ExecuteTransactionAccount).init(.{
            .touched = false,
            .account = account_shared_data,
        }));

    return .{
        .accounts = etc_accounts,
        .accounts_resize_delta = params.accounts_resize_delta,
        .compute_meter = params.compute_meter,
        .maybe_custom_error = params.maybe_custom_error,
        .maybe_log_collector = null,
        .sysvar_cache = params.sysvar_cache,
        .lamports_per_signature = params.lamports_per_signature,
        .last_blockhash = params.last_blockhash,
        .feature_set = FeatureSet.EMPTY,
    };
}

pub fn createExecuteInstructionContext(
    etc: *ExecuteTransactionContext,
    program_id: Pubkey,
    accounts: []const ExecuteInstructionAccount,
    instruction_data: []const u8,
) !ExecuteInstructionContext {
    const eic_accounts = try std.BoundedArray(
        ExecuteInstructionAccount,
        MAX_INSTRUCTION_ACCOUNTS,
    ).fromSlice(accounts);

    return .{
        .etc = etc,
        .program_id = program_id,
        .accounts = eic_accounts,
        .instruction_data = instruction_data,
    };
}

/// TODO: Add Context Pre / Post Checks
pub fn expectInstructionExecutionResult(
    allocator: std.mem.Allocator,
    executor: anytype,
    instruction: anytype,
    instruction_accounts: []const ExecuteInstructionAccount,
    pre_transaction_accounts: []const AccountSharedDataParams,
    post_transaction_accounts: []const AccountSharedDataParams,
    execute_transaction_context: ExecuteTransactionContextParams,
) !void {
    const instruction_data = try sig.bincode.writeAlloc(allocator, instruction, .{});
    defer allocator.free(instruction_data);

    const transaction_accounts = try createAccountSharedDatas(allocator, pre_transaction_accounts);
    defer {
        for (transaction_accounts) |account| {
            account.data.deinit(allocator);
            allocator.destroy(account.data);
        }
        allocator.free(transaction_accounts);
    }

    var etc = try createExecuteTransactionContext(
        transaction_accounts,
        execute_transaction_context,
    );

    var eic = try createExecuteInstructionContext(
        &etc,
        instruction.program_id(),
        instruction_accounts,
        instruction_data,
    );

    try executor(allocator, &eic);

    const expected_transaction_accounts = try createAccountSharedDatas(allocator, post_transaction_accounts);
    defer {
        for (expected_transaction_accounts) |account| {
            account.data.deinit(allocator);
            allocator.destroy(account.data);
        }
        allocator.free(expected_transaction_accounts);
    }

    try std.testing.expectEqual(expected_transaction_accounts.len, etc.accounts.len);
    for (expected_transaction_accounts, 0..) |expected_account, index|
        std.testing.expect(expected_account.equals(etc.getAccountSharedData(index))) catch |err| {
            std.debug.print("Mismatch in account at index {}\n", .{index});
            std.debug.print("\tExpected: {}\n", .{expected_account});
            std.debug.print("\tActual:   {}\n", .{etc.getAccountSharedData(index)});
            return err;
        };
}
