const std = @import("std");
const sig = @import("../../sig.zig");

const ids = sig.runtime.ids;
const system_program = sig.runtime.program.system_program;
const bpf_loader_program = sig.runtime.program.bpf_loader_program;

const Pubkey = sig.core.Pubkey;
const Transaction = sig.core.Transaction;

const Instruction = sig.core.instruction.Instruction;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionAccount = sig.core.instruction.InstructionAccountMeta;

const InstructionContext = sig.runtime.InstructionContext;
const InstructionContextAccountMeta = sig.runtime.InstructionContextAccountMeta;
const InstructionContextProgramMeta = sig.runtime.InstructionContextProgramMeta;
const TransactionContext = sig.runtime.TransactionContext;

const SystemProgramInstruction = sig.runtime.program.system_program.Instruction;

const sumAccountLamports = @import("./sum_account_lamports.zig").sumAccountLamports;

const NATIVE_PROGRAM_ENTRYPOINTS = std.StaticStringMap(*const fn (std.mem.Allocator, *InstructionContext) InstructionError!void).initComptime(&.{
    .{ system_program.ID.base58String().slice(), system_program.execute },
});

/// [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/program-runtime/src/invoke_context.rs#L308
pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
    instruction: Instruction,
    signers: []const Pubkey,
) InstructionError!void {
    // Prepare intruction
    // [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/program-runtime/src/invoke_context.rs#L328
    // [fd] https://github.com/firedancer-io/firedancer/blob/5e9c865414c12b89f1e0c3a2775cb90e3ca3da60/src/flamenco/vm/syscall/fd_vm_syscall_cpi.c#L62
    const program_meta, const account_metas =
        try prepareInstruction(ic, instruction, signers);

    // Process instruction
    // [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/program-runtime/src/invoke_context.rs#L450
    // [fd] https://github.com/firedancer-io/firedancer/blob/5e9c865414c12b89f1e0c3a2775cb90e3ca3da60/src/flamenco/runtime/fd_executor.c#L1079
    try executeInstruction(
        allocator,
        ic.tc,
        ic,
        program_meta,
        account_metas,
        instruction.serialized,
    );
}

/// [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/program-runtime/src/invoke_context.rs#L328
pub fn prepareInstruction(
    ic: *const InstructionContext,
    instruction: Instruction,
    signers: []const Pubkey,
) InstructionError!struct {
    InstructionContextProgramMeta,
    std.BoundedArray(InstructionContextAccountMeta, Transaction.MAX_ACCOUNTS),
} {
    const PrepareInstructionAccount = struct {
        pubkey: Pubkey,
        is_signer: bool,
        is_writable: bool,
        index_in_caller: u16,
        index_in_callee: u16,
        index_in_transaction: u16,
    };

    var deduped_instruction_accounts = std.BoundedArray(PrepareInstructionAccount, Transaction.MAX_ACCOUNTS){};
    var deduped_indexes = std.BoundedArray(usize, Transaction.MAX_ACCOUNTS){};

    for (instruction.account_metas, 0..) |callee_account, callee_index| {
        // Find the account index in the transaction
        const index_in_transaction = ic.tc.getAccountIndex(callee_account.pubkey) orelse {
            try ic.tc.log("Instruction references unkown account {}", .{callee_account.pubkey});
            return InstructionError.MissingAccount;
        };

        // Check if account is already in deduped list
        for (deduped_instruction_accounts.slice(), 0..) |*deduped_account, deduped_index| {
            if (deduped_account.index_in_transaction == index_in_transaction) {
                deduped_indexes.appendAssumeCapacity(deduped_index);
                deduped_account.is_signer = deduped_account.is_signer or callee_account.is_signer;
                deduped_account.is_writable = deduped_account.is_writable or callee_account.is_writable;
            }
            continue;
        }

        // Account not found in deduped list
        deduped_indexes.appendAssumeCapacity(deduped_instruction_accounts.len);
        const index_in_caller = ic.getAccountMetaIndex(callee_account.pubkey) orelse {
            try ic.tc.log("Instruction references unkown account {}", .{callee_account.pubkey});
            return InstructionError.MissingAccount;
        };
        deduped_instruction_accounts.appendAssumeCapacity(.{
            .pubkey = callee_account.pubkey,
            .is_signer = callee_account.is_signer,
            .is_writable = callee_account.is_writable,
            .index_in_transaction = index_in_transaction,
            .index_in_caller = index_in_caller,
            .index_in_callee = @intCast(callee_index),
        });
    }

    for (deduped_instruction_accounts.slice()) |ic_account| {
        const borrowed_account = try ic.borrowInstructionAccount(ic_account.index_in_transaction);
        defer borrowed_account.release();

        // Readonly in caller cannot become writable in callee
        if (ic_account.is_writable and !borrowed_account.isWritable()) {
            try ic.tc.log("{}'s writable privilege escalated", .{borrowed_account.pubkey});
            return InstructionError.PrivilegeEscalation;
        }

        // To be signed in the callee,
        // it must be either signed in the caller or by the program
        var contains_signer = false;
        for (signers) |signer| if (signer.equals(&borrowed_account.pubkey)) {
            contains_signer = true;
        };
        if (ic_account.is_signer and !(borrowed_account.isSigner() or contains_signer)) {
            try ic.tc.log("{}'s signer privilege escalated", .{borrowed_account.pubkey});
            return InstructionError.PrivilegeEscalation;
        }
    }

    // Collect deduped accounts
    var instruction_accounts = std.BoundedArray(InstructionContextAccountMeta, Transaction.MAX_ACCOUNTS){};
    for (deduped_indexes.slice()) |index| {
        const deduped_account = deduped_instruction_accounts.buffer[index];
        instruction_accounts.appendAssumeCapacity(.{
            .is_duplicate = false,
            .pubkey = deduped_account.pubkey,
            .is_signer = deduped_account.is_signer,
            .is_writable = deduped_account.is_writable,
            .index_in_transaction = deduped_account.index_in_transaction,
        });
    }

    // Check if the program account is executable
    const program_account_index = ic.tc.getAccountIndex(instruction.program_pubkey) orelse {
        try ic.tc.log("Unknown program {}", .{instruction.program_pubkey});
        return InstructionError.MissingAccount;
    };

    const borrowed_program_account = try ic.borrowProgramAccount(program_account_index);
    defer borrowed_program_account.release();

    if (!borrowed_program_account.account.executable) {
        try ic.tc.log("Account {} is not executable", .{instruction.program_pubkey});
        return InstructionError.AccountNotExecutable;
    }

    return .{
        .{
            .pubkey = instruction.program_pubkey,
            .index_in_transaction = program_account_index,
        },
        instruction_accounts,
    };
}

pub fn executeInstruction(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
    maybe_parent: ?*const InstructionContext,
    program_meta: InstructionContextProgramMeta,
    account_metas: std.BoundedArray(InstructionContextAccountMeta, Transaction.MAX_ACCOUNTS),
    serialized: []const u8,
) InstructionError!void {
    // [fd] https://github.com/firedancer-io/firedancer/blob/5e9c865414c12b89f1e0c3a2775cb90e3ca3da60/src/flamenco/runtime/fd_executor.c#L1001-L101
    if (program_meta.pubkey.equals(&ids.NATIVE_LOADER_ID))
        return InstructionError.UnsupportedProgramId;

    // Check for reentrancy
    // [agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/program-runtime/src/invoke_context.rs#L245-L284
    for (tc.instruction_stack.constSlice(), 0..) |ic, level| {
        // If the program is on the stack, it must be the last one
        // otherwise it is a reentrancy violation
        if (ic.program_meta.pubkey.equals(&program_meta.pubkey) and
            level != tc.instruction_stack.len - 1)
            return InstructionError.ReentrancyNotAllowed;
    }

    // [agave] https://github.com/anza-xyz/agave/blob/134be7c14066ea00c9791187d6bbc4795dd92f0e/program-runtime/src/invoke_context.rs#L288
    // TODO: syscall_context.push(None)

    // [agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/program-runtime/src/invoke_context.rs#L245-L284
    // Check that the caller's lamport sum has not changed.
    if (maybe_parent) |parent| {
        if (parent.total_account_lamports != sumAccountLamports(tc, parent.account_metas))
            return InstructionError.UnbalancedInstruction;
    }

    // Check instruction trace length is within bounds
    if (tc.instruction_trace.len >= tc.instruction_trace.capacity())
        return InstructionError.MaxInstructionTraceLengthExceeded;

    // Check instruction stack depth is within bounds
    if (tc.instruction_stack.len >= tc.instruction_stack.capacity())
        return InstructionError.CallDepth;

    // Push instruction onto trace and stack
    var ic = InstructionContext{
        .tc = tc,
        .parent = maybe_parent,
        .total_account_lamports = sumAccountLamports(tc, account_metas),
        .program_meta = program_meta,
        .account_metas = account_metas,
        .serialized_instruction = serialized,
    };
    tc.instruction_trace.appendAssumeCapacity(ic);
    tc.instruction_stack.appendAssumeCapacity(&ic);

    // [agave] https://github.com/anza-xyz/agave/blob/a1ed2b1052bde05e79c31388b399dba9da10f7de/program-runtime/src/invoke_context.rs#L518-L529
    const program_pubkey = blk: {
        const program_account = ic.borrowProgramAccount(ic.program_meta.index_in_transaction) catch
            return InstructionError.UnsupportedProgramId;
        defer program_account.release();
        break :blk if (ids.NATIVE_LOADER_ID.equals(&program_account.account.owner))
            program_account.pubkey
        else
            program_account.account.owner;
    };

    // TODO: replace with comptime func map
    const native_program_entrypoint_fn = NATIVE_PROGRAM_ENTRYPOINTS.get(program_pubkey.base58String().slice()) orelse {
        @panic("Program not supported");
    };

    // TODO: proper execution result handling
    native_program_entrypoint_fn(allocator, &ic) catch |err| {
        try tc.log("Program {} failed: {}", .{ program_pubkey, err });
        return err;
    };

    try tc.log("Program {} success", .{program_pubkey});
}
