const sig = @import("../../../sig.zig");

// https://github.com/solana-program/vote/blob/f6e499f2a29d890896af4f063d8eea762d4d43b7/program/src/lib.rs#L7C30-L7C73
pub const ID =
    sig.core.Pubkey.parseBase58String(
    "Vote111111111111111111111111111111111111111",
) catch unreachable;

pub const COMPUTE_UNITS = 2_100;

pub const Instruction = @import("instruction.zig").Instruction;
pub const execute = @import("execute.zig").execute;
