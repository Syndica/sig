const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../../sig.zig");

const zksdk = sig.zksdk;
const zk_elgamal = sig.runtime.program.zk_elgamal;
const Pubkey = sig.core.Pubkey;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;

pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const tc = ic.tc;

    const instruction = try ic.ixn_info.deserializeInstruction(
        allocator,
        zk_elgamal.ProofInstruction,
    );

    if (tc.instruction_stack.len != 1 and
        instruction != .close_context_state)
    {
        // Proof verification instructions are not supported as an inner instruction
        return InstructionError.UnsupportedProgramId;
    }

    switch (instruction) {
        .verify_zero_ciphertext => {
            try tc.consumeCompute(zk_elgamal.VERIFY_ZERO_BALANCE_COMPUTE_UNITS);
            try tc.log("VerifyZeroBalance", .{});
            try processVerifyProof(zksdk.ZeroCiphertextProofData, ic);
        },
        else => @panic("TODO"),
    }
}

fn processVerifyProof(
    comptime Proof: type,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const tc = ic.tc;
    const instruction_data = ic.ixn_info.instruction_data;

    // if instruction data is exactly 5 bytes, then read proof from an account
    if (instruction_data.len == 5) {
        @panic("TODO");
    } else {
        const proof_data = Proof.fromBytes(instruction_data[1..]) catch {
            try tc.log("invalid proof data", .{});
            return InstructionError.InvalidInstructionData;
        };
        proof_data.verify() catch {
            // TODO: log error as well
            // [fd] https://github.com/firedancer-io/firedancer/blob/e0de87d2f58547b69ba980b3c88f35094b34561e/src/flamenco/runtime/program/zksdk/fd_zksdk.c#L209-L210
            try tc.log("proof_verification failed", .{});
            return InstructionError.InvalidInstructionData;
        };
    }
}
