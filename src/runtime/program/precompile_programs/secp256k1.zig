const std = @import("std");
const sig = @import("../../../sig.zig");
const precompile_programs = sig.runtime.program.precompile_programs;

const PrecompileProgramError = precompile_programs.PrecompileProgramError;

const Keccak256 = std.crypto.hash.sha3.Keccak256;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const Ecdsa = std.crypto.sign.ecdsa.Ecdsa(Secp256k1, Keccak256);

pub const SECP256K1_DATA_START = SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE +
    SECP256K1_SIGNATURE_OFFSETS_START;
pub const SECP256K1_PUBKEY_SERIALIZED_SIZE = 20;
pub const SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE = 11;
pub const SECP256K1_SIGNATURE_OFFSETS_START = 1;
pub const SECP256K1_SIGNATURE_SERIALIZED_SIZE = 64;

comptime {
    std.debug.assert(SECP256K1_SIGNATURE_OFFSETS_SERIALIZED_SIZE ==
        @bitSizeOf(Secp256k1SignatureOffsets) / 8);
}

pub const Secp256k1SignatureOffsets = packed struct {
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

// https://github.com/firedancer-io/firedancer/blob/af74882ffb2c24783a82718dbc5111a94e1b5f6f/src/flamenco/runtime/program/fd_precompiles.c#L227
// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/src/secp256k1_instruction.rs#L925
pub fn verify(
    current_instruction_data: []const u8,
    all_instruction_datas: []const []const u8,
) PrecompileProgramError!void {
    _ = current_instruction_data;
    _ = all_instruction_datas;

    @panic("TODO");
}
