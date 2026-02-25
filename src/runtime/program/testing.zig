const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const executor = sig.runtime.executor;
const runtime_testing = sig.runtime.testing;

const Pubkey = sig.core.Pubkey;
const LogCollector = sig.runtime.LogCollector;

pub const InstructionContextAccountMetaParams = runtime_testing.InstructionInfoAccountMetaParams;
pub const ExecuteContextsParams = runtime_testing.ExecuteContextsParams;

const createTransactionContextPtr = runtime_testing.createTransactionContextPtr;
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
        context_params.log_collector = try LogCollector.init(allocator, null);
    }

    // Create the initial transaction context
    var initial_prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const initial_cache, var initial_tc = try createTransactionContextPtr(
        allocator,
        initial_prng.random(),
        context_params,
    );
    defer {
        // Log messages before deiniting the transaction context
        if (options.print_logs) {
            std.debug.print("Execution Logs:\n", .{});
            var iter = initial_tc.log_collector.?.iterator();
            var i: usize = 1;
            while (iter.next()) |log| : (i += 1) {
                std.debug.print("    {}: {s}\n", .{ i, log });
            }
        }
        deinitTransactionContext(allocator, initial_tc);
        sig.runtime.testing.deinitAccountMap(initial_cache, allocator);
        allocator.destroy(initial_tc);
    }

    // Create the expected transaction context
    var expected_prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const expected_cache, const expected_tc = try createTransactionContextPtr(
        allocator,
        expected_prng.random(),
        expected_context_params,
    );
    defer {
        deinitTransactionContext(allocator, expected_tc);
        sig.runtime.testing.deinitAccountMap(expected_cache, allocator);
        allocator.destroy(expected_tc);
    }

    // Create the instruction info
    var instruction_info = try createInstructionInfo(
        initial_tc,
        program_id,
        instruction,
        instruction_accounts,
    );
    defer instruction_info.deinit(allocator);

    // Execute the instruction
    try executor.executeInstruction(
        allocator,
        initial_tc,
        instruction_info,
    );

    // Check the result
    try expectTransactionContextEqual(expected_tc, initial_tc);
}

test expectProgramExecuteError {
    const allocator = std.testing.allocator;

    try expectProgramExecuteError(
        error.UnsupportedProgramId,
        allocator,
        Pubkey.ZEROES, // invalid program id
        &.{}, // empty instruction,
        &.{.{ .index_in_transaction = 0 }},
        .{ .accounts = &.{.{ .pubkey = Pubkey.ZEROES }} },
        .{ .print_logs = false },
    );
}

test expectProgramExecuteResult {
    const allocator = std.testing.allocator;
    const system_program = sig.runtime.program.system;

    var prng = std.Random.DefaultPrng.init(0);
    const src_account = Pubkey.initRandom(prng.random());
    const dst_account = Pubkey.initRandom(prng.random());

    var expected_logger = try LogCollector.init(allocator, null);
    try expected_logger.log(allocator, "Program {f} invoke [1]", .{system_program.ID});
    try expected_logger.log(allocator, "Program {f} success", .{system_program.ID});

    // Test log_collector.eql path
    try expectProgramExecuteResult(
        allocator,
        system_program.ID,
        system_program.Instruction{
            .transfer = .{ .lamports = 10 },
        },
        &.{
            .{ .index_in_transaction = 0, .is_writable = true, .is_signer = true },
            .{ .index_in_transaction = 1, .is_writable = true },
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = src_account,
                    .owner = system_program.ID,
                    .lamports = 100,
                },
                .{
                    .pubkey = dst_account,
                    .owner = system_program.ID,
                    .lamports = 50,
                },
                .{
                    .pubkey = system_program.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
            .log_collector = try LogCollector.init(allocator, null),
        },
        .{
            .accounts = &.{
                .{
                    .pubkey = src_account,
                    .owner = system_program.ID,
                    .lamports = 100 - 10,
                },
                .{
                    .pubkey = dst_account,
                    .owner = system_program.ID,
                    .lamports = 50 + 10,
                },
                .{
                    .pubkey = system_program.ID,
                    .owner = sig.runtime.ids.NATIVE_LOADER_ID,
                },
            },
            .log_collector = expected_logger,
        },
        .{},
    );
}
