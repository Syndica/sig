const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;
const Transaction = sig.core.Transaction;

const TransactionContext = sig.runtime.TransactionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;

pub const InstructionContextProgramMeta = struct {
    pubkey: Pubkey,
    index_in_transaction: u16,
};

pub const InstructionContextAccountMeta = struct {
    pubkey: Pubkey,
    index_in_transaction: u16,
    is_signer: bool,
    is_writable: bool,
};

/// `InstructionContext` holds all information required to execute a program instruction; excluding an allocator
/// it is the only argument passed to the program entrypoint function
///
/// Current functionality supports the execution of a single `system_program` instruction
///
/// TODO: add features to support new program execution as required
///
/// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/transaction-context/src/lib.rs#L502
pub const InstructionContext = struct {
    /// The transaction context associated with this instruction execution
    tc: *TransactionContext,

    /// The instruction context which invoked this instruction execution
    parent: ?*const InstructionContext,

    /// The sum of lamports of all accounts associated with this instruction
    total_account_lamports: u128,

    // The meta data of the program associated with this instruction
    program_meta: InstructionContextProgramMeta,

    /// The metadata of accounts associated with this instruction
    account_metas: std.BoundedArray(InstructionContextAccountMeta, Transaction.MAX_ACCOUNTS),

    /// Serialized instruction data
    serialized_instruction: []const u8,

    /// [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/sdk/src/transaction_context.rs#L523
    pub fn getAccountMetaIndex(
        self: *const InstructionContext,
        pubkey: Pubkey,
    ) ?u16 {
        for (self.account_metas.slice(), 0..) |account_meta, index| {
            if (account_meta.pubkey.equals(&pubkey)) return @intCast(index);
        }
        return null;
    }

    // Gets the account meta at a given index returning null if the index is out of bounds
    pub fn getAccountMetaAtIndex(
        self: *const InstructionContext,
        index: u16,
    ) ?*const InstructionContextAccountMeta {
        if (index >= self.account_metas.len) return null;
        return &self.account_metas.buffer[index];
    }

    /// Return if the account at a given index is a signer with bounds checking
    pub fn isIndexSigner(
        self: *const InstructionContext,
        index: u16,
    ) InstructionError!bool {
        const instruction_accout_meta = self.getAccountMetaAtIndex(index) orelse
            return InstructionError.NotEnoughAccountKeys;
        return instruction_accout_meta.is_signer;
    }

    /// Replaces Agave's approach to checking if a pubkey is a signer which is to precompute a
    /// hashmap of signers to parse during instruction execution
    pub fn isPubkeySigner(
        self: *const InstructionContext,
        pubkey: Pubkey,
    ) bool {
        for (self.account_metas.slice()) |account_meta| {
            if (account_meta.pubkey.equals(&pubkey) and account_meta.is_signer) return true;
        }
        return false;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/program_utils.rs#L9
    pub fn deserializeInstruction(
        self: *const InstructionContext,
        allocator: std.mem.Allocator,
        comptime T: type,
    ) InstructionError!T {
        // TODO: Does bincode have limits on the size of the data it can deserialize?
        return bincode.readFromSlice(allocator, T, self.serialized_instruction, .{}) catch {
            return InstructionError.InvalidInstructionData;
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L493
    pub fn checkNumberOfAccounts(
        self: *const InstructionContext,
        minimum_accounts: u16,
    ) InstructionError!void {
        if (self.account_metas.len < minimum_accounts)
            return InstructionError.NotEnoughAccountKeys;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L619
    pub fn borrowProgramAccount(
        self: *const InstructionContext,
        index_in_transaction: u16,
    ) InstructionError!BorrowedAccount {
        const txn_account = self.tc.getAccountAtIndex(index_in_transaction) orelse
            return InstructionError.MissingAccount;

        const account, const account_write_guard = txn_account.writeWithLock() orelse
            return InstructionError.AccountBorrowFailed;

        return .{
            .pubkey = self.program_meta.pubkey,
            .account = account,
            .account_write_guard = account_write_guard,
            .borrow_context = .{
                .program_pubkey = self.program_meta.pubkey,
                .is_signer = false,
                .is_writable = false,
            },
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L647
    pub fn borrowInstructionAccount(
        self: *const InstructionContext,
        index: u16,
    ) InstructionError!BorrowedAccount {
        const instr_account_meta = self.getAccountMetaAtIndex(index) orelse
            return InstructionError.NotEnoughAccountKeys;

        const txn_account = self.tc.getAccountAtIndex(instr_account_meta.index_in_transaction) orelse
            return InstructionError.MissingAccount;

        const account, const account_write_guard = txn_account.writeWithLock() orelse
            return InstructionError.AccountBorrowFailed;

        return .{
            .pubkey = instr_account_meta.pubkey,
            .account = account,
            .account_write_guard = account_write_guard,
            .borrow_context = .{
                .program_pubkey = self.program_meta.pubkey,
                .is_signer = instr_account_meta.is_signer,
                .is_writable = instr_account_meta.is_writable,
            },
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/sysvar_cache.rs#L229
    pub fn getSysvarWithAccountCheck(
        self: *const InstructionContext,
        comptime T: type,
        index: u16,
    ) InstructionError!T {
        const instruction_account_meta = self.getAccountMetaAtIndex(index) orelse
            return InstructionError.NotEnoughAccountKeys;

        if (!T.ID.equals(&instruction_account_meta.pubkey))
            return InstructionError.InvalidArgument;

        return self.tc.sysvar_cache.get(T) orelse
            InstructionError.UnsupportedSysvar;
    }
};
