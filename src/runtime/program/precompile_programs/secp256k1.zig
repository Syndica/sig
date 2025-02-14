const std = @import("std");
const sig = @import("../../../sig.zig");
const precompile_programs = sig.runtime.program.precompile_programs;

const PrecompileProgramError = precompile_programs.PrecompileProgramError;
const getInstructionValue = precompile_programs.getInstructionValue;
const getInstructionData = precompile_programs.getInstructionData;

const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Secp256k1 = std.crypto.ecc.Secp256k1;

pub const SECP256K1_DATA_START = (SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE + SECP256K1_SIGNATURE_OFFSETS_START);
pub const SECP256K1_PUBKEY_SERIALIZED_SIZE = 20;
pub const SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE = 11;
pub const SECP256K1_SIGNATURE_OFFSETS_START = 1;
pub const SECP256K1_SIGNATURE_SERIALIZED_SIZE = 64;

pub const Secp256k1SignatureOffsets = extern struct {
    /// Offset to 64-byte signature plus 1-byte recovery ID.
    signature_offset: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the signature.
    signature_instruction_idx: u8,
    /// Offset to 20-byte Ethereum address.
    eth_address_offset: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the address.
    eth_address_instruction_idx: u8,
    /// Offset to start of message data.
    message_data_offset: u16,
    /// Size of message data in bytes.
    message_data_size: u16,
    /// Within the transaction, the index of the instruction whose instruction data contains the message.
    message_instruction_idx: u8,
};

comptime {
    // std.debug.assert(SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE == @sizeOf(Secp256k1SignatureOffsets));
}

// https://github.com/firedancer-io/firedancer/blob/af74882ffb2c24783a82718dbc5111a94e1b5f6f/src/flamenco/runtime/program/fd_precompiles.c#L227
// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L925
pub fn verify(
    current_instruction_data: []const u8,
    all_instruction_datas: []const []const u8,
) PrecompileProgramError!void {
    _ = all_instruction_datas;

    const data = current_instruction_data;
    const n_signatures = data[0];
    if (data.len < SECP256K1_DATA_START) {
        if (data.len == 1 and n_signatures == 0) return;
        return error.InvalidInstructionDataSize;
    }
    if (n_signatures == 0 and data.len > 1) return error.InvalidInstructionDataSize;

    const expected_data_size = SECP256K1_SIGNATURE_OFFSETS_START +
        n_signatures * SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE;
    if (data.len < expected_data_size) return error.InvalidInstructionDataSize;

    // firedancer seems to assume natural alignment in this loop? Need to prove it to myself.
    for (0..n_signatures) |i| {
        const offset = SECP256K1_SIGNATURE_OFFSETS_START +
            i * SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE;
        const sig_offsets: *const Secp256k1SignatureOffsets = @alignCast(@ptrCast(data.ptr + offset));

        // const signature = try getInstructionValue(
        //     SECP256K1_SIGNATURE_SERIALIZED_SIZE, // + recovery id
        //     data,
        //     all_instruction_datas,
        //     sig_offsets.signature_instruction_idx,
        //     sig_offsets.signature_offset,
        // );
        _ = sig_offsets;
        @panic("TODO");
    }
}
