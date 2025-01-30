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

    pub fn checkAccountsResizeDelta(
        self: *const ExecuteInstructionContext,
        delta: i64,
    ) error{MaxAccountsDataAllocationsExceeded}!void {
        try self.etc.checkAccountsResizeDelta(delta);
    }

    pub fn checkAccountAtIndex(
        eic: *ExecuteInstructionContext,
        index: usize,
        expected: Pubkey,
    ) InstructionError!void {
        if (index >= eic.accounts.len) return error.NotEnoughAccountKeys;
        const actual = try eic.getAccountPubkey(index);
        if (!expected.equals(&actual)) return error.InvalidArgument;
    }

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

    pub fn checkNumberOfAccounts(
        self: *const ExecuteInstructionContext,
        required: usize,
    ) error{NotEnoughAccountKeys}!void {
        if (self.accounts.len < required) return error.NotEnoughAccountKeys;
    }

    pub fn consumeCompute(
        self: *const ExecuteInstructionContext,
        units: u64,
    ) error{ComputationalBudgetExceeded}!void {
        try self.etc.consumeCompute(units);
    }

    pub fn getAccountPubkey(
        self: *const ExecuteInstructionContext,
        index: usize,
    ) error{NotEnoughAccountKeys}!Pubkey {
        if (index >= self.accounts.len) return error.NotEnoughAccountKeys;
        return self.accounts.slice()[index].pubkey;
    }

    pub fn getBlockhash(self: *const ExecuteInstructionContext) Hash {
        return self.etc.getBlockhash();
    }

    pub fn getBorrowedAccount(
        self: *const ExecuteInstructionContext,
        index: usize,
    ) InstructionError!BorrowedAccount {
        if (index >= self.accounts.len) return error.NotEnoughAccountKeys;
        return self.etc.getBorrowedAccount(self, &self.accounts.constSlice()[index]);
    }

    pub fn getLamportsPerSignature(self: *const ExecuteInstructionContext) u64 {
        return self.etc.getLamportsPerSignature();
    }

    pub fn getSysvar(self: *const ExecuteInstructionContext, comptime T: type) error{UnsupportedSysvar}!T {
        return try self.etc.getSysvar(T);
    }

    pub fn isOwner(self: *const ExecuteInstructionContext, pubkey: Pubkey) bool {
        return self.program_id.equals(&pubkey);
    }

    pub fn addAccountsResizeDelta(self: *const ExecuteInstructionContext, delta: i64) void {
        self.etc.addAccountsResizeDelta(delta);
    }

    pub fn setCustomError(self: *const ExecuteInstructionContext, custom_error: u32) void {
        self.etc.setCustomError(custom_error);
    }

    pub fn log(
        self: *const ExecuteInstructionContext,
        comptime fmt: []const u8,
        args: anytype,
    ) void {
        self.etc.log(fmt, args);
    }
};
