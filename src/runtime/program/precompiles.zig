// https://github.com/firedancer-io/firedancer/blob/82ecf8392fe076afce5f9cba02a5efa976e664c8/src/flamenco/runtime/program/fd_precompiles.h

const sig = @import("../../sig.zig");

const Transaction = sig.core.Transaction;
const ExecuteTransactionContext = sig.runtime.ExecuteTransactionContext;
const ExecuteInstructionContext = sig.runtime.ExecuteInstructionContext;

pub fn ed25519Verify(ctx: *ExecuteTransactionContext, instruction: Transaction.Instruction) !void {
    _ = ctx;
    _ = instruction;
    @panic("Program not implemented");
}

pub fn secp256k1Verify(ctx: *ExecuteTransactionContext, instruction: Transaction.Instruction) !void {
    _ = ctx;
    _ = instruction;
    @panic("Program not implemented");
}

pub fn secp256r1Verify(ctx: *ExecuteTransactionContext, instruction: Transaction.Instruction) !void {
    _ = ctx;
    _ = instruction;
    @panic("Program not implemented");
}
