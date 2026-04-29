const sig = @import("../../../sig.zig");
pub const Instruction = @import("instruction.zig").Instruction;
pub const state = @import("state.zig");

/// [agave] https://github.com/solana-program/vote/blob/f6e499f2a29d890896af4f063d8eea762d4d43b7/program/src/lib.rs#L7C30-L7C73
pub const ID: sig.core.Pubkey = .parse("Vote111111111111111111111111111111111111111");

pub const COMPUTE_UNITS = 2_100;

/// Cost in compute units for BLS proof-of-possession verification (SIMD-0387).
/// [agave] https://github.com/anza-xyz/agave/blob/v4.0.0-rc.0/programs/vote/src/vote_processor.rs#L83
pub const BLS_PROOF_OF_POSSESSION_VERIFICATION_COMPUTE_UNITS: u64 = 34_500;

pub const vote_instruction = @import("instruction.zig");

pub const VoteError = @import("error.zig").VoteError;
pub const VoteAuthorize = state.VoteAuthorize;
pub const execute = @import("execute.zig").execute;
