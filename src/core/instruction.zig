const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const Instruction = struct {
    /// Program address
    program_id: Pubkey,
    /// Accounts that the command references
    accounts: []const AccountMeta,
    /// Data is the binary encoding of the program instruction and its
    /// arguments. The lifetime of the data must outlive the instruction.
    data: []const u8,
};

pub const AccountMeta = struct {
    /// An account's public key
    id: Pubkey,
    /// True if account must sign the transaction
    is_signer: bool,
    /// True if the account is mutable
    is_writable: bool,
};
