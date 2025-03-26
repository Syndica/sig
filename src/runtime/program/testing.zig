const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const executor = sig.runtime.executor;
const runtime_testing = sig.runtime.testing;

const Pubkey = sig.core.Pubkey;
const LogCollector = sig.runtime.LogCollector;

pub const InstructionContextAccountMetaParams = runtime_testing.InstructionContextAccountMetaParams;
pub const TransactionContextParams = runtime_testing.TransactionContextParams;
pub const TransactionContextAccountParams = runtime_testing.TransactionContextAccountParams;

pub const createTransactionContext = runtime_testing.createTransactionContext;
pub const createInstructionInfo = runtime_testing.createInstructionInfo;
pub const expectTransactionContextEqual = runtime_testing.expectTransactionContextEqual;

pub const Options = struct {
    print_logs: bool = false,
};

pub fn expectProgramExecuteResult(
    allocator: std.mem.Allocator,
    program_id: Pubkey,
    instruction: anytype,
    instruction_accounts_params: []const InstructionContextAccountMetaParams,
    transaction_context_params: TransactionContextParams,
    expected_transaction_context_params: TransactionContextParams,
    options: Options,
) !void {
    if (!builtin.is_test)
        @compileError("createTransactionContext should only be called in test mode");

    var txn_context_params = transaction_context_params;
    if (options.print_logs and transaction_context_params.log_collector == null) {
        txn_context_params.log_collector = LogCollector.init(allocator, null);
    }

    var prng_0 = std.rand.DefaultPrng.init(0);
    var transaction_context = try createTransactionContext(
        allocator,
        prng_0.random(),
        txn_context_params,
    );
    defer {
        // Log messages before deiniting the transaction context
        if (options.print_logs) {
            if (transaction_context.log_collector) |collector| {
                std.debug.print("Execution Logs:\n", .{});
                for (collector.collect(), 1..) |log, index| {
                    std.debug.print("    {}: {s}\n", .{ index, log });
                }
            }
        }
        transaction_context.deinit(allocator);
    }

    var prng_1 = std.rand.DefaultPrng.init(0);
    var expected_transaction_context = try createTransactionContext(
        allocator,
        prng_1.random(),
        expected_transaction_context_params,
    );
    defer expected_transaction_context.deinit(allocator);

    var instruction_info = try createInstructionInfo(
        allocator,
        &transaction_context,
        program_id,
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
