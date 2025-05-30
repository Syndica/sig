const std = @import("std");
const sig = @import("../../../sig.zig");

const zksdk = sig.zksdk;
const zk_elgamal = sig.runtime.program.zk_elgamal;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;

const INSTRUCTION_DATA_LENGTH_WITH_PROOF_ACCOUNT = 5;

pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    _ = allocator; // autofix
    const tc = ic.tc;
    const instruction_data = ic.ixn_info.instruction_data;

    if (instruction_data.len < 1) return InstructionError.InvalidInstructionData;
    const instruction = std.meta.intToEnum(
        zk_elgamal.ProofInstruction,
        instruction_data[0],
    ) catch return InstructionError.InvalidInstructionData;

    switch (instruction) {
        .verify_zero_ciphertext => {
            try tc.consumeCompute(zk_elgamal.VERIFY_ZERO_BALANCE_COMPUTE_UNITS);
            try tc.log("VerifyZeroBalance", .{});
            try processVerifyProof(zksdk.ZeroCiphertextProofData, ic);
        },
        .verify_ciphertext_ciphertext_equality => {
            try tc.consumeCompute(zk_elgamal.VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY_COMPUTE_UNITS);
            try tc.log("VerifyCiphertextCiphertextEquality", .{});
            try processVerifyProof(zksdk.CiphertextCiphertextEqualityData, ic);
        },
        .verify_pubkey_validity => {
            try tc.consumeCompute(zk_elgamal.VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS);
            try tc.log("VerifyPubkeyValidity", .{});
            try processVerifyProof(zksdk.PubkeyValidityProofData, ic);
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

    // if instruction data is exactly 5 bytes, then read proof from an account,
    // first byte is the instruction enum, next 4 bytes make up a u32 for the byte offset.
    if (instruction_data.len == INSTRUCTION_DATA_LENGTH_WITH_PROOF_ACCOUNT) {
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
