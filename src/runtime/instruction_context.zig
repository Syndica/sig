const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;

const TransactionContext = sig.runtime.TransactionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;

pub const InstructionAccountInfo = struct {
    pubkey: Pubkey,
    is_signer: bool,
    is_writable: bool,
    index_in_transaction: u16,
};

pub const InstructionContext = struct {
    /// The transaction context associated with this instruction execution
    tc: *TransactionContext,

    /// The program id of the currently executing instruction
    program_id: Pubkey,

    /// The index of the currently executing program in the transaction
    program_index: u16,

    /// Serialized instruction data
    instruction: []const u8,

    /// The accounts associated with this instruction and their metadata
    accounts: []const InstructionAccountInfo,

    /// Return if the account at a given index is a signer with bounds checking
    pub fn isIndexSigner(self: *const InstructionContext, index: anytype) error{NotEnoughAccountKeys}!bool {
        if (index >= self.accounts.len) return InstructionError.NotEnoughAccountKeys;
        return self.accounts[index].is_signer;
    }

    /// Replaces Agave's approach to checking if a pubkey is a signer which is to precompute a
    /// hashmap of signers to parse during instruction execution
    pub fn isPubkeySigner(self: *const InstructionContext, pubkey: anytype) bool {
        for (self.accounts) |account|
            if (account.pubkey.equals(&pubkey) and account.is_signer) return true;
        return false;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/program_utils.rs#L9
    pub fn deserializeInstruction(
        self: *const InstructionContext,
        allocator: std.mem.Allocator,
        comptime T: type,
    ) error{InvalidInstructionData}!T {
        // TODO: Does bincode have limits on the size of the data it can deserialize?
        return bincode.readFromSlice(allocator, T, self.instruction, .{}) catch {
            return InstructionError.InvalidInstructionData;
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L493
    pub fn checkNumberOfAccounts(
        self: *const InstructionContext,
        minimum_accounts: usize,
    ) error{NotEnoughAccountKeys}!void {
        if (self.accounts.len < minimum_accounts) return InstructionError.NotEnoughAccountKeys;
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L619
    pub fn borrowProgramAccount(self: *const InstructionContext) InstructionError!BorrowedAccount {
        if (self.program_index >= self.tc.accounts.len) return InstructionError.MissingAccount;
        const account, const account_write_guard = try self.tc.accounts[self.program_index].writeWithLock();
        return .{
            .pubkey = self.program_id,
            .account = account,
            .account_write_guard = account_write_guard,
            .borrow_context = .{
                .program_id = self.program_id,
                .is_writable = false,
            },
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L647
    pub fn borrowInstructionAccount(
        self: *const InstructionContext,
        index: usize,
    ) InstructionError!BorrowedAccount {
        if (index >= self.accounts.len) return InstructionError.NotEnoughAccountKeys;
        const index_in_transaction = self.accounts[index].index_in_transaction;

        if (index_in_transaction >= self.tc.accounts.len) return InstructionError.MissingAccount;
        const account, const account_write_guard = try self.tc.accounts[index_in_transaction].writeWithLock();

        return .{
            .pubkey = self.accounts[index].pubkey,
            .account = account,
            .account_write_guard = account_write_guard,
            .borrow_context = .{
                .program_id = self.program_id,
                .is_writable = self.accounts[index].is_writable,
            },
        };
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/sysvar_cache.rs#L229
    pub fn getSysvarWithAccountCheck(
        self: *const InstructionContext,
        comptime T: type,
        index: usize,
    ) InstructionError!T {
        if (index >= self.accounts.len) return InstructionError.NotEnoughAccountKeys;
        const actual = self.accounts[index].pubkey;
        if (!T.id().equals(&actual)) return InstructionError.InvalidArgument;
        return if (self.tc.sysvar_cache.get(T)) |value| value else InstructionError.UnsupportedSysvar;
    }
};
