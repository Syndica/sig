const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const executor = sig.runtime.executor;
const runtime_testing = sig.runtime.testing;

const Pubkey = sig.core.Pubkey;
const LogCollector = sig.runtime.LogCollector;

pub const InstructionContextAccountMetaParams = runtime_testing.InstructionInfoAccountMetaParams;
pub const TransactionContextParams = runtime_testing.ExecuteContextsParams;

const createExecutionContexts = runtime_testing.createExecutionContexts;
const createInstructionInfo = runtime_testing.createInstructionInfo;
const expectTransactionContextEqual = runtime_testing.expectTransactionContextEqual;

pub const Options = struct {
    print_logs: bool = false,
};

pub fn expectProgramExecuteError(
    expected_error: anytype,
    allocator: std.mem.Allocator,
    program_id: Pubkey,
    instruction: anytype,
    instruction_accounts: []const InstructionContextAccountMetaParams,
    initial_context_params: TransactionContextParams,
    options: Options,
) !void {
    try std.testing.expectError(
        expected_error,
        expectProgramExecuteResult(
            allocator,
            program_id,
            instruction,
            instruction_accounts,
            initial_context_params,
            .{},
            options,
        ),
    );
}

pub fn expectProgramExecuteResult(
    allocator: std.mem.Allocator,
    program_id: Pubkey,
    instruction: anytype,
    instruction_accounts: []const InstructionContextAccountMetaParams,
    initial_context_params: TransactionContextParams,
    expected_context_params: TransactionContextParams,
    options: Options,
) !void {
    if (!builtin.is_test)
        @compileError("createTransactionContext should only be called in test mode");

    var initial_context_params_ = initial_context_params;
    if (options.print_logs and initial_context_params.log_collector == null) {
        initial_context_params_.log_collector = LogCollector.init(null);
    }

    // Create the initial transaction context
    var initial_prng = std.rand.DefaultPrng.init(0);

    const initial_ec, const initial_sc, var initial_tc = try createExecutionContexts(
        allocator,
        initial_prng.random(),
        initial_context_params_,
    );
    defer {
        // Log messages before deiniting the transaction context
        if (options.print_logs) {
            std.debug.print("Execution Logs:\n", .{});
            for (initial_tc.log_collector.?.collect(), 1..) |log, index| {
                std.debug.print("    {}: {s}\n", .{ index, log });
            }
        }
        initial_ec.deinit();
        allocator.destroy(initial_ec);
        allocator.destroy(initial_sc);
        initial_tc.deinit();
    }

    // Create the expected transaction context
    var expected_prng = std.rand.DefaultPrng.init(0);

    const expected_ec, const expected_sc, var expected_tc = try createExecutionContexts(
        allocator,
        expected_prng.random(),
        expected_context_params,
    );
    defer {
        expected_ec.deinit();
        allocator.destroy(expected_ec);
        allocator.destroy(expected_sc);
        expected_tc.deinit();
    }

    // Create the instruction info
    var instruction_info = try createInstructionInfo(
        &initial_tc,
        program_id,
        instruction,
        instruction_accounts,
    );
    defer instruction_info.deinit(allocator);

    // Execute the instruction
    try executor.executeInstruction(
        allocator,
        &initial_tc,
        instruction_info,
    );

    // Check the result
    try expectTransactionContextEqual(expected_tc, initial_tc);
}
