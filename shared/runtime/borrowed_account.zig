const sig = @import("../lib.zig");

const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/compute-budget/src/compute_budget.rs#L11-L12
pub const MAX_INSTRUCTION_STACK_DEPTH: usize = 5;

/// Borrowed account context exists to provide information about the context under which an account
/// was borrowed. It replaces the reference to an `InstructionContext` used in Agave.
pub const BorrowedAccountContext = struct {
    program_id: Pubkey,
    is_signer: bool = false,
    is_writable: bool = false,
    accounts_lamport_delta: *i128,
};
