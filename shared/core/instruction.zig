const std = @import("std");
const sig = @import("../lib.zig");

const Pubkey = sig.core.Pubkey;

pub const InstructionAccount = struct {
    /// An account's public key
    pubkey: Pubkey,
    /// True if account must sign the transaction
    is_signer: bool,
    /// True if the account is mutable
    is_writable: bool,
};

pub const Instruction = struct {
    /// Program address
    program_id: Pubkey,
    /// Accounts that the command references
    accounts: []const InstructionAccount,
    /// Data is the binary encoding of the program instruction and its
    /// arguments. The lifetime of the data must outlive the instruction.
    data: []const u8,
    owned_data: bool,

    pub fn deinit(self: Instruction, allocator: std.mem.Allocator) void {
        if (self.owned_data) allocator.free(self.data);
        allocator.free(self.accounts);
    }

    // https://github.com/anza-xyz/agave/blob/3bbabb38c5800b197841eb79037a82e88e174440/sdk/instruction/src/lib.rs#L221
    pub fn initUsingBincodeAlloc(
        allocator: std.mem.Allocator,
        T: type,
        program_id: Pubkey,
        accounts: []const InstructionAccount,
        data: *const T,
    ) error{OutOfMemory}!Instruction {
        const serialized = sig.bincode.writeAlloc(allocator, data, .{}) catch
            // reviewer's note - can we trim away bincode's use of any error? I don't think we need it,
            // a bit annoying.
            return error.OutOfMemory;
        errdefer allocator.free(serialized);

        return .{
            .program_id = program_id,
            .accounts = accounts,
            .data = serialized,
            .owned_data = true,
        };
    }
};

pub const InstructionError = @import("instruction_error.zig").InstructionError;
pub const InstructionErrorEnum = @import("instruction_error.zig").InstructionErrorEnum;
pub const intFromInstructionError = @import("instruction_error.zig").intFromInstructionError;
