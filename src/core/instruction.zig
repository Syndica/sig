// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/instruction/src/account_meta.rs
// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/instruction/src/error.rs

const std = @import("std");
const sig = @import("../sig.zig");
const shared = @import("shared");

const Pubkey = sig.core.Pubkey;

pub const InstructionAccount = shared.core.InstructionAccount;

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

pub const InstructionError = shared.core.instruction_error.InstructionError;
pub const InstructionErrorEnum = shared.core.instruction_error.InstructionErrorEnum;
pub const intFromInstructionError = shared.core.instruction_error.intFromInstructionError;
