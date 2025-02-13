const std = @import("std");
const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;

/// Re-export instruction execute method in the system_program namespace
pub const execute = @import("precompile_program_execute.zig").precompileProgramExecute;

pub const COMPUTE_UNITS = 1; // TODO: what is the actual value?

pub const ID_ED25519_VERIFY =
    Pubkey.parseBase58String("Ed25519SigVerify111111111111111111111111111") catch unreachable;

pub const ID_SECP256K1 =
    Pubkey.parseBase58String("KeccakSecp256k11111111111111111111111111111") catch unreachable;

pub const ID_SECP256R1_VERIFY =
    Pubkey.parseBase58String("Secp256r1SigVerify1111111111111111111111111") catch unreachable;

// parsed internally
pub const PrecompileProgramInstruction = []const u8;

// https://github.com/anza-xyz/agave/blob/a8aef04122068ec36a7af0721e36ee58efa0bef2/sdk/precompile-error/src/lib.rs#L6
pub const PrecompileProgramError = error{
    InvalidPublicKey,
    InvalidRecoveryId,
    InvalidSignature,
    InvalidDataOffsets,
    InvalidInstructionDataSize,
};
