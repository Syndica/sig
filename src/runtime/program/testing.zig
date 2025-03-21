const builtin = @import("builtin");
const std = @import("std");
const sig = @import("../../sig.zig");

const executor = sig.runtime.executor;
const runtime_testing = sig.runtime.testing;

pub const InstructionContextAccountMetaParams = runtime_testing.InstructionContextAccountMetaParams;
pub const TransactionContextParams = runtime_testing.TransactionContextParams;
pub const TransactionContextAccountParams = runtime_testing.TransactionContextAccountParams;

pub const createTransactionContext = runtime_testing.createTransactionContext;
pub const createInstructionInfo = runtime_testing.createInstructionInfo;
pub const expectTransactionContextEqual = runtime_testing.expectTransactionContextEqual;

pub fn expectProgramExecuteResult(
    allocator: std.mem.Allocator,
    log_writer: anytype,
    program: anytype,
    instruction: anytype,
    instruction_accounts_params: []const InstructionContextAccountMetaParams,
    transaction_context_params: TransactionContextParams,
    expected_transaction_context_params: TransactionContextParams,
) !void {
    if (!builtin.is_test)
        @compileError("createTransactionContext should only be called in test mode");

    var prng_0 = std.rand.DefaultPrng.init(0);
    var transaction_context = try createTransactionContext(
        allocator,
        prng_0.random(),
        transaction_context_params,
    );
    defer transaction_context.deinit(allocator);

    defer {
        if (@TypeOf(log_writer) != void) {
            if (transaction_context.log_collector) |collector| {
                log_writer.writeAll("logs:\n") catch {};
                for (collector.collect()) |log| {
                    log_writer.print("    log: {s}\n", .{log}) catch {};
                }
            }
        }
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
