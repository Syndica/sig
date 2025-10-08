const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const executor = sig.runtime.executor;
const runtime_testing = sig.runtime.testing;

const Pubkey = sig.core.Pubkey;
const LogCollector = sig.runtime.LogCollector;

pub const InstructionContextAccountMetaParams = runtime_testing.InstructionInfoAccountMetaParams;
pub const ExecuteContextsParams = runtime_testing.ExecuteContextsParams;

const createTransactionContext = runtime_testing.createTransactionContext;
const deinitTransactionContext = runtime_testing.deinitTransactionContext;
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
    initial_context_params: ExecuteContextsParams,
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
    initial_context_params: ExecuteContextsParams,
    expected_context_params: ExecuteContextsParams,
    options: Options,
) !void {
    if (!builtin.is_test)
        @compileError("createTransactionContext should only be called in test mode");

    var context_params = initial_context_params;
    if (options.print_logs and initial_context_params.log_collector == null) {
        context_params.log_collector = LogCollector.init(null);
    }

    // Create the initial transaction context
    var initial_prng = std.Random.DefaultPrng.init(0);

    var initial_cache, var initial_tc = try createTransactionContext(
        allocator,
        initial_prng.random(),
        context_params,
    );
    defer {
        // Log messages before deiniting the transaction context
        if (options.print_logs) {
            std.debug.print("Execution Logs:\n", .{});
            for (initial_tc.log_collector.?.collect(), 1..) |log, index| {
                std.debug.print("    {}: {s}\n", .{ index, log });
            }
        }
        deinitTransactionContext(allocator, initial_tc);
        initial_cache.deinit(allocator);
    }

    // Create the expected transaction context
    var expected_prng = std.Random.DefaultPrng.init(0);

    var expected_cache, const expected_tc = try createTransactionContext(
        allocator,
        expected_prng.random(),
        expected_context_params,
    );
    defer {
        deinitTransactionContext(allocator, expected_tc);
        expected_cache.deinit(allocator);
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
