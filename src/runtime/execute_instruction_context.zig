// TODO: add comments and permalinks

const std = @import("std");
const sig = @import("../sig.zig");

const Hash = sig.core.Hash;
const BorrowedAccount = sig.runtime.BorrowedAccount;
const ExecuteTransactionContext = sig.runtime.ExecuteTransactionContext;
const InstructionError = sig.core.instruction.InstructionError;
const SystemError = sig.runtime.program.system_program.SystemProgramError;
const Pubkey = sig.core.Pubkey;

const MAX_INSTRUCTION_ACCOUNTS = sig.runtime.MAX_INSTRUCTION_ACCOUNTS;

pub const ExecuteInstructionContext = struct {
    /// The transaction context associated with this instruction execution
    etc: *ExecuteTransactionContext,

    /// The program id of the currently executing instruction
    program_id: Pubkey,

    /// The accounts used by this instruction and their required metadata
    accounts: std.BoundedArray(AccountInfo, MAX_INSTRUCTION_ACCOUNTS),

    /// Instruction data
    instruction_data: []const u8,

    pub const AccountInfo = struct {
        pubkey: Pubkey,
        is_signer: bool,
        is_writable: bool,
        index_in_transaction: u16,
    };

    pub fn checkIsSigner(
        self: *const ExecuteInstructionContext,
        comptime T: type,
        probe: T,
    ) error{MissingRequiredSignature}!void {
        switch (T) {
            Pubkey => {
                for (self.accounts.buffer) |account| {
                    if (account.pubkey.equals(&probe))
                        if (account.is_signer) return else return error.MissingRequiredSignature;
                }
                return error.MissingRequiredSignature;
            },
            u16 => {
                if (!self.accounts.get(probe).is_signer)
                    return error.MissingRequiredSignature;
            },
            else => @compileError("Invalid type for `probe`"),
        }
    }

    pub fn getAccountPubkey(
        self: *const ExecuteInstructionContext,
        index: usize,
    ) error{NotEnoughAccountKeys}!Pubkey {
        if (index >= self.accounts.len) return error.NotEnoughAccountKeys;
        return self.accounts.constSlice()[index].pubkey;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L493
    pub fn checkNumberOfAccounts(
        self: *const ExecuteInstructionContext,
        required: usize,
    ) error{NotEnoughAccountKeys}!void {
        if (self.accounts.len < required) return error.NotEnoughAccountKeys;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L597
    pub fn getBorrowedAccount(
        self: *const ExecuteInstructionContext,
        index: usize,
    ) InstructionError!BorrowedAccount {
        if (index >= self.accounts.len) return error.NotEnoughAccountKeys;
        return self.etc.getBorrowedAccount(self, &self.accounts.constSlice()[index]);
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/sysvar_cache.rs#L229
    pub fn getSysvarWithAccountCheck(self: *const ExecuteInstructionContext, comptime T: type, index: usize) InstructionError!T {
        // try self.checkAccountAtIndex(index, T.id());
        if (index >= self.accounts.len) return error.NotEnoughAccountKeys;
        const actual = try self.getAccountPubkey(index);
        if (!T.id().equals(&actual)) return error.InvalidArgument;
        return self.etc.getSysvar(T);
    }
};
