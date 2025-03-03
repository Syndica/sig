const std = @import("std");
const sig = @import("../../sig.zig");

const bincode = sig.bincode;
const executor = sig.runtime.executor;
const runtime_testing = sig.runtime.testing;

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

const InstructionContextAccountMetaParams = runtime_testing.InstructionContextAccountMetaParams;
const TransactionContextParams = runtime_testing.TransactionContextParams;

const createTransactionContext = runtime_testing.createTransactionContext;
const createInstructionInfo = runtime_testing.createInstructionInfo;
const expectTransactionContextEqual = runtime_testing.expectTransactionContextEqual;

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

    const expected_transaction_context = try createTransactionContext(
        allocator,
        expected_transaction_context_params,
    );
    defer expected_transaction_context.deinit(allocator);

    var instruction_info = try createInstructionInfo(
        allocator,
        &transaction_context,
        program.ID,
        instruction,
        instruction_accounts_params,
    );
    defer instruction_info.deinit(allocator);

    try executor.executeInstruction(
        allocator,
        &transaction_context,
        instruction_info,
    );

    try expectTransactionContextEqual(expected_transaction_context, transaction_context);
}
