/// Program address
program_id: Pubkey,
/// Accounts that the command references
accounts: []const AccountMeta,
/// Data is the binary encoding of the program instruction and its
/// arguments. The lifetime of the data must outlive the instruction.
data: []const u8,

pub const AccountMeta = struct {
    id: Pubkey,
    is_signer: bool,
    is_writable: bool,
};

const Instruction = @This();

const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
