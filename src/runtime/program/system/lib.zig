const std = @import("std");
const sig = @import("../../../sig.zig");

const InstructionAccount = sig.core.instruction.InstructionAccount;
const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/instruction.rs#L64
pub const NONCE_STATE_SIZE: u64 = 80;

/// [agave] https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/lib.rs#L18
pub const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024;

/// [agave] https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/lib.rs#L26
pub const MAX_PERMITTED_ACCOUNTS_DATA_ALLOCATIONS_PER_TRANSACTION: i64 = 2 * 10 * 1024 * 1024;

/// [agave] https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/lib.rs#L30
pub const ID: Pubkey = .parse("11111111111111111111111111111111");

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
    const accounts = try allocator.alloc(InstructionAccount, 2);
    errdefer allocator.free(accounts);
    accounts[0] = .{ .pubkey = from, .is_signer = true, .is_writable = true };
    accounts[1] = .{ .pubkey = to, .is_signer = false, .is_writable = true };

    return try sig.core.Instruction.initUsingBincodeAlloc(
        allocator,
        Instruction,
        ID,
        accounts,
        &.{ .transfer = .{ .lamports = lamports } },
    );
}

// https://github.com/anza-xyz/agave/blob/9e7637a9b6f20201a746007e9dadfddbc43285dc/sdk/program/src/system_instruction.rs#L1105
pub fn allocate(
    allocator: std.mem.Allocator,
    pubkey: Pubkey,
    space: u64,
) error{OutOfMemory}!sig.core.Instruction {
    const accounts = try allocator.alloc(InstructionAccount, 1);
    errdefer allocator.free(accounts);
    accounts[0] = .{ .pubkey = pubkey, .is_signer = true, .is_writable = true };

    return try sig.core.Instruction.initUsingBincodeAlloc(
        allocator,
        Instruction,
        ID,
        accounts,
        &.{ .allocate = .{ .space = space } },
    );
}

// https://github.com/anza-xyz/agave/blob/9e7637a9b6f20201a746007e9dadfddbc43285dc/sdk/program/src/system_instruction.rs#L674
pub fn assign(
    allocator: std.mem.Allocator,
    pubkey: Pubkey,
    owner: Pubkey,
) error{OutOfMemory}!sig.core.Instruction {
    const accounts = try allocator.alloc(InstructionAccount, 1);
    errdefer allocator.free(accounts);
    accounts[0] = .{ .pubkey = pubkey, .is_signer = true, .is_writable = true };

    return try sig.core.Instruction.initUsingBincodeAlloc(
        allocator,
        Instruction,
        ID,
        accounts,
        &.{ .assign = .{ .owner = owner } },
    );
}

test "allocate creates instruction with correct program id and accounts" {
    const allocator = std.testing.allocator;
    const pubkey = Pubkey{ .data = [_]u8{0xAA} ** 32 };

    const ix = try allocate(allocator, pubkey, 1024);
    defer ix.deinit(allocator);

    // Program ID should be the system program
    try std.testing.expect(ix.program_id.equals(&ID));

    // Should have exactly 1 account
    try std.testing.expectEqual(@as(usize, 1), ix.accounts.len);
    try std.testing.expect(ix.accounts[0].pubkey.equals(&pubkey));
    try std.testing.expect(ix.accounts[0].is_signer);
    try std.testing.expect(ix.accounts[0].is_writable);

    // Data should deserialize back to the allocate instruction
    const decoded = sig.bincode.readFromSlice(allocator, Instruction, ix.data, .{}) catch
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, 1024), decoded.allocate.space);
}

test "assign creates instruction with correct program id and accounts" {
    const allocator = std.testing.allocator;
    const pubkey = Pubkey{ .data = [_]u8{0xBB} ** 32 };
    const owner = Pubkey{ .data = [_]u8{0xCC} ** 32 };

    const ix = try assign(allocator, pubkey, owner);
    defer ix.deinit(allocator);

    // Program ID should be the system program
    try std.testing.expect(ix.program_id.equals(&ID));

    // Should have exactly 1 account
    try std.testing.expectEqual(@as(usize, 1), ix.accounts.len);
    try std.testing.expect(ix.accounts[0].pubkey.equals(&pubkey));
    try std.testing.expect(ix.accounts[0].is_signer);
    try std.testing.expect(ix.accounts[0].is_writable);

    // Data should deserialize back to the assign instruction
    const decoded = sig.bincode.readFromSlice(allocator, Instruction, ix.data, .{}) catch
        return error.TestUnexpectedResult;
    try std.testing.expect(decoded.assign.owner.equals(&owner));
}
