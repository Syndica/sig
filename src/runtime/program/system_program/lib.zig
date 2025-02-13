const sig = @import("../../../sig.zig");

/// [agave] https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/instruction.rs#L64
pub const NONCE_STATE_SIZE: u64 = 80;

/// [agave] https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/lib.rs#L18
pub const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024;

/// [agave] https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/lib.rs#L26
pub const MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION: i64 = 2 * 10 * 1024 * 1024;

/// [agave] https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/lib.rs#L30
pub const ID =
    sig.core.Pubkey.parseBase58String("11111111111111111111111111111111") catch unreachable;

pub const COMPUTE_UNITS = 150;

pub const Error = @import("error.zig").Error;
pub const Instruction = @import("instruction.zig").Instruction;

pub const execute = @import("execute.zig").execute;
