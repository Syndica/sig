const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;
const executor = sig.runtime.executor;
const system_program = sig.runtime.program.system;
const bpf_loader_program = sig.runtime.program.bpf_loader;

const Pubkey = sig.core.Pubkey;
const Instruction = sig.core.instruction.Instruction;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionAccount = sig.core.instruction.InstructionAccount;

const InstructionInfo = sig.runtime.InstructionInfo;
const TransactionContext = sig.runtime.TransactionContext;
const BorrowedAccount = sig.runtime.BorrowedAccount;

/// `InstructionContext` holds all information required to execute a program instruction; excluding an allocator
/// it is the only argument passed to the program entrypoint function
///
/// Current functionality supports the execution of a single `system_program` instruction
///
/// TODO: add features to support new program execution as required
///
/// [agave] https://github.com/anza-xyz/agave/blob/c5ed1663a1218e9e088e30c81677bc88059cc62b/sdk/transaction-context/src/lib.rs#L502
pub const InstructionContext = struct {
    /// Transaction context
    tc: *TransactionContext,

    /// The instruction information which is constant accross execution
    ixn_info: InstructionInfo,

    /// The depth of the instruction on the stack
    depth: u8,

    pub fn deinit(self: *InstructionContext, allocator: std.mem.Allocator) void {
        self.ixn_info.deinit(allocator);
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L619
    pub fn borrowProgramAccount(
        self: *const InstructionContext,
    ) InstructionError!BorrowedAccount {
        return self.tc.borrowAccountAtIndex(
            self.ixn_info.program_meta.index_in_transaction,
            .{
                .program_id = self.ixn_info.program_meta.pubkey,
                .accounts_lamport_delta = &self.tc.accounts_lamport_delta,
            },
        );
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/src/transaction_context.rs#L647
    pub fn borrowInstructionAccount(
        self: *const InstructionContext,
        index_in_instruction: u16,
    ) InstructionError!BorrowedAccount {
        const account_meta = self.ixn_info.getAccountMetaAtIndex(index_in_instruction) orelse
            return InstructionError.MissingAccount;

        return try self.tc.borrowAccountAtIndex(account_meta.index_in_transaction, .{
            .program_id = self.ixn_info.program_meta.pubkey,
            .is_signer = account_meta.is_signer,
            .is_writable = account_meta.is_writable,
            .accounts_lamport_delta = &self.tc.accounts_lamport_delta,
        });
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/program-runtime/src/sysvar_cache.rs#L229
    pub fn getSysvarWithAccountCheck(
        self: *const InstructionContext,
        comptime T: type,
        index_in_instruction: u16,
    ) InstructionError!T {
        const account_meta = self.ixn_info.getAccountMetaAtIndex(index_in_instruction) orelse
            return InstructionError.MissingAccount;

        if (!T.ID.equals(&account_meta.pubkey))
            return InstructionError.InvalidArgument;

        return self.tc.sysvar_cache.get(T);
    }

    pub fn getAccountKeyByIndexUnchecked(self: *const InstructionContext, index: u16) Pubkey {
        const account_meta = self.ixn_info.getAccountMetaAtIndex(index) orelse unreachable;
        return account_meta.pubkey;
    }

    pub fn nativeInvoke(
        self: *InstructionContext,
        allocator: std.mem.Allocator,
        program_id: Pubkey,
        instruction: anytype,
        account_metas: []const InstructionAccount,
        signers: []const Pubkey,
    ) (error{OutOfMemory} || InstructionError)!void {
        const data = bincode.writeAlloc(allocator, instruction, .{}) catch |e| switch (e) {
            error.NoSpaceLeft, error.OutOfMemory => return error.OutOfMemory,
        };
        defer allocator.free(data);

        try executor.executeNativeCpiInstruction(
            allocator,
            self.tc,
            Instruction{
                .program_id = program_id,
                .accounts = account_metas,
                .data = data,
                .owned_data = false,
            },
            signers,
        );
    }

    /// [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/program-runtime/src/invoke_context.rs#L678
    pub fn getCheckAligned(self: *const InstructionContext) bool {
        const program = self.borrowProgramAccount() catch return true;
        defer program.release();

        return !program.account.owner.equals(&bpf_loader_program.v1.ID);
    }
};
