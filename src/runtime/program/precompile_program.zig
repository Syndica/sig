const std = @import("std");
const sig = @import("../../sig.zig");

const Pubkey = sig.core.Pubkey;

/// Re-export instruction execute method in the system_program namespace
pub const execute = @import("precompile_program_execute.zig").precompileProgramExecute;

pub const COMPUTE_UNITS = 1; // TODO: what is the actual value?

pub const ID =
    Pubkey.parseBase58String("11111111111111111111111111111111") catch unreachable;

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
