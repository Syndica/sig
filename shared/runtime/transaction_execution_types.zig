const std = @import("std");

const core = @import("../core/lib.zig");
const instruction_info = @import("instruction_info.zig");
const compute_budget_program = @import("program/compute_budget/lib.zig");

const InstructionInfo = instruction_info.InstructionInfo;
const AccountMeta = core.InstructionAccount;
const Hash = core.Hash;
const Pubkey = core.Pubkey;
const ComputeBudgetInstructionDetails = compute_budget_program.ComputeBudgetInstructionDetails;

pub const RuntimeTransaction = struct {
    signature_count: u64,
    fee_payer: Pubkey,
    msg_hash: Hash,
    recent_blockhash: Hash,
    instructions: []const InstructionInfo,
    accounts: std.MultiArrayList(AccountMeta) = .{},
    compute_budget_instruction_details: ComputeBudgetInstructionDetails = .{},
    num_lookup_tables: u64,
    /// Count of statically-included account keys (the message's `account_keys`),
    /// excluding any accounts loaded from address-lookup tables. Equal to
    /// `accounts.len - <ALT-loaded count>` and used to enforce SIMD-0242.
    num_static_account_keys: u16,
    is_simple_vote_transaction: bool,
};

pub fn TransactionResult(comptime T: type) type {
    return union(enum(u8)) {
        ok: T,
        err: core.TransactionError,
    };
}
