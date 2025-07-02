const std = @import("std");
const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/instruction.rs#L64
pub const NONCE_STATE_SIZE: u64 = 80;

/// [agave] https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/lib.rs#L18
pub const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024;

/// [agave] https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/lib.rs#L26
pub const MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION: i64 = 2 * 10 * 1024 * 1024;

/// [agave] https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/lib.rs#L30
pub const ID =
    Pubkey.parseBase58String("11111111111111111111111111111111") catch unreachable;

pub const COMPUTE_UNITS = 150;

pub const Error = @import("error.zig").Error;
pub const Instruction = @import("instruction.zig").Instruction;

pub const execute = @import("execute.zig").execute;

// https://github.com/anza-xyz/agave/blob/9e7637a9b6f20201a746007e9dadfddbc43285dc/sdk/program/src/system_instruction.rs#L885
pub fn transfer(
    allocator: std.mem.Allocator,
    from: Pubkey,
    to: Pubkey,
    lamports: u64,
) error{OutOfMemory}!sig.core.Instruction {
    return try sig.core.Instruction.initUsingBincodeAlloc(
        allocator,
        Instruction,
        ID,
        &.{
            .{ .pubkey = from, .is_signer = true, .is_writable = true },
            .{ .pubkey = to, .is_signer = false, .is_writable = true },
        },
        &.{ .transfer = .{ .lamports = lamports } },
    );
}

// https://github.com/anza-xyz/agave/blob/9e7637a9b6f20201a746007e9dadfddbc43285dc/sdk/program/src/system_instruction.rs#L1105
pub fn allocate(
    allocator: std.mem.Allocator,
    pubkey: Pubkey,
    space: u64,
) error{OutOfMemory}!sig.core.Instruction {
    return try sig.core.Instruction.initUsingBincodeAlloc(
        allocator,
        Instruction,
        ID,
        &.{
            .{ .pubkey = pubkey, .is_signer = true, .is_writable = true },
        },
        &.{ .allocate = .{ .space = space } },
    );
}

// https://github.com/anza-xyz/agave/blob/9e7637a9b6f20201a746007e9dadfddbc43285dc/sdk/program/src/system_instruction.rs#L674
pub fn assign(
    allocator: std.mem.Allocator,
    pubkey: Pubkey,
    owner: Pubkey,
) error{OutOfMemory}!sig.core.Instruction {
    return try sig.core.Instruction.initUsingBincodeAlloc(
        allocator,
        Instruction,
        ID,
        &.{
            .{ .pubkey = pubkey, .is_signer = true, .is_writable = true },
        },
        &.{ .assign = .{ .owner = owner } },
    );
}
