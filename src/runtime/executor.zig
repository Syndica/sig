const std = @import("std");
const sig = @import("../sig.zig");

const ids = sig.runtime.ids;
const program = sig.runtime.program;
const stable_log = sig.runtime.stable_log;

const Instruction = sig.core.instruction.Instruction;
const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;

const InstructionContext = sig.runtime.InstructionContext;
const InstructionInfo = sig.runtime.InstructionInfo;
const TransactionContext = sig.runtime.TransactionContext;

/// Execute an instruction described by the instruction info\
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L462-L479
pub fn executeInstruction(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
    instruction_info: InstructionInfo,
) (error{OutOfMemory} || InstructionError)!void {
    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L471-L474
    try pushInstruction(tc, instruction_info);

    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L475
    const maybe_execute_error = processNextInstruction(allocator, tc);

    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L478
    popInstruction(tc) catch |err| if (maybe_execute_error == null) return err;
    if (maybe_execute_error) |err| return err;
}

/// Execute a native CPI instruction\
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L305-L306
pub fn executeNativeCpiInstruction(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
    instruction: Instruction,
    signers: []const Pubkey,
) (error{OutOfMemory} || InstructionError)!void {
    const instruction_info = try prepareCpiInstructionInfo(tc, instruction, signers);
    try executeInstruction(allocator, tc, instruction_info);
}

/// Push an instruction onto the instruction stack and an associated entry onto the instruction trace\
/// Checks for reentrancy violations\
/// Returns a reference to the pushed instruction context\
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L471-L475
/// [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/fd_executor.c#L1034-L1035
fn pushInstruction(
    tc: *TransactionContext,
    instruction_info: InstructionInfo,
) InstructionError!void {
    const program_id = instruction_info.program_meta.pubkey;

    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L250-L253
    // [fd] https://github.com/firedancer-io/firedancer/blob/5e9c865414c12b89f1e0c3a2775cb90e3ca3da60/src/flamenco/runtime/fd_executor.c#L1001-L101
    if (program_id.equals(&ids.NATIVE_LOADER_ID)) {
        return InstructionError.UnsupportedProgramId;
    }

    // [agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/program-runtime/src/invoke_context.rs#L245-L283
    // [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/fd_executor.c#L1048-L1070
    for (tc.instruction_stack.constSlice(), 0..) |ic, level| {
        // If the program is on the stack, it must be the last entry otherwise it is a reentrancy violation
        if (program_id.equals(&ic.info.program_meta.pubkey) and
            level != tc.instruction_stack.len - 1)
        {
            return InstructionError.ReentrancyNotAllowed;
        }
    }

    // TODO: syscall_context.push(None)

    // Push the instruction onto the stack and trace, creating the instruction context
    // [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L366-L403
    // [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/fd_executor.c#L975-L976

    const initial_account_lamports = sumAccountLamports(
        tc,
        instruction_info.account_metas.constSlice(),
    );

    if (tc.instruction_stack.len > 0) {
        const parent = &tc.instruction_stack.buffer[tc.instruction_stack.len - 1];
        const initial_lamports = parent.info.initial_account_lamports;
        const current_lamports = sumAccountLamports(tc, parent.info.account_metas.constSlice());
        if (initial_lamports != current_lamports) return InstructionError.UnbalancedInstruction;
    }

    if (tc.instruction_trace.len >= tc.instruction_trace.capacity()) {
        return InstructionError.MaxInstructionTraceLengthExceeded;
    }

    if (tc.instruction_stack.len >= tc.instruction_stack.capacity()) {
        return InstructionError.CallDepth;
    }

    const info = .{
        .program_meta = instruction_info.program_meta,
        .account_metas = instruction_info.account_metas,
        .instruction_data = instruction_info.instruction_data,
        .initial_account_lamports = initial_account_lamports,
    };

    tc.instruction_stack.appendAssumeCapacity(.{
        .tc = tc,
        .info = info,
        .depth = @intCast(tc.instruction_stack.len),
    });

    tc.instruction_trace.appendAssumeCapacity(.{
        .info = info,
        .depth = @intCast(tc.instruction_stack.len),
    });
}

/// Execute an instruction context after it has been pushed onto the instruction stack\
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L510
fn processNextInstruction(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
) ?(error{OutOfMemory} || InstructionError) {
    // Get next instruction context from the stack
    if (tc.instruction_stack.len == 0) return InstructionError.CallDepth;
    const ic = &tc.instruction_stack.buffer[tc.instruction_stack.len - 1];

    // Lookup the program id
    // [agave] https://github.com/anza-xyz/agave/blob/a1ed2b1052bde05e79c31388b399dba9da10f7de/program-runtime/src/invoke_context.rs#L518-L529
    const program_id = blk: {
        const program_account = ic.borrowProgramAccount() catch
            return InstructionError.UnsupportedProgramId;
        defer program_account.release();

        break :blk if (ids.NATIVE_LOADER_ID.equals(&program_account.account.owner))
            program_account.pubkey
        else
            program_account.account.owner;
    };

    // Lookup native program function
    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/svm/src/message_processor.rs#L72-L75
    // [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/fd_executor.c#L1150-L1159
    // TODO:
    // - precompile feature gate move to svm otherwise noop
    // - precompile entrypoints
    const maybe_precompile_fn =
        program.PRECOMPILE_ENTRYPOINTS.get(program_id.base58String().slice());

    const maybe_native_program_fn = maybe_precompile_fn orelse blk: {
        const native_program_fn = program.PROGRAM_ENTRYPOINTS.get(
            program_id.base58String().slice(),
        );
        ic.tc.return_data.data.clearRetainingCapacity();
        break :blk native_program_fn;
    };

    const native_program_fn = maybe_native_program_fn orelse
        return InstructionError.UnsupportedProgramId;

    // Invoke the program and log the result
    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L551-L571
    // [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/fd_executor.c#L1160-L1167
    try stable_log.program_invoke(&ic.tc.log_collector, program_id, ic.tc.instruction_stack.len);
    if (native_program_fn(allocator, ic)) |execute_error| {
        try stable_log.program_failure(&ic.tc.log_collector, program_id, execute_error);
        return execute_error;
    } else {
        try stable_log.program_success(&ic.tc.log_collector, program_id);
        return null;
    }
}

/// Pop an instruction from the instruction stack\
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L290
fn popInstruction(
    tc: *TransactionContext,
) InstructionError!void {
    // TODO: pop syscall context and record trace log
    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L291-L294

    // [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L407-L409
    if (tc.instruction_stack.len == 0) return InstructionError.CallDepth;

    // [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L411-L426
    const unbalanced_instruction = blk: {
        const ic = &tc.instruction_stack.buffer[tc.instruction_stack.len - 1];

        // Check program account has no outstanding borrows
        const program_account = ic.borrowProgramAccount() catch {
            return InstructionError.AccountBorrowOutstanding;
        };
        program_account.release();

        const initial_lamports = ic.info.initial_account_lamports;
        const current_lamports = sumAccountLamports(tc, ic.info.account_metas.constSlice());

        break :blk (initial_lamports != current_lamports);
    };

    _ = tc.instruction_stack.pop();

    if (unbalanced_instruction) return InstructionError.UnbalancedInstruction;
}

/// Prepare the InstructionInfo for an instruction invoked via CPI\
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L325
fn prepareCpiInstructionInfo(
    tc: *TransactionContext,
    callee: Instruction,
    signers: []const Pubkey,
) (error{OutOfMemory} || InstructionError)!InstructionInfo {
    if (tc.instruction_stack.len == 0) return InstructionError.CallDepth;
    const caller = &tc.instruction_stack.buffer[tc.instruction_stack.len - 1];

    var deduped_account_metas = std.BoundedArray(
        InstructionInfo.AccountMeta,
        InstructionInfo.MAX_ACCOUNT_METAS,
    ){};
    var deduped_indexes = std.BoundedArray(
        usize,
        InstructionInfo.MAX_ACCOUNT_METAS,
    ){};

    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L337-L386
    for (callee.accounts, 0..) |account, index| {
        const index_in_transaction = tc.getAccountIndex(account.pubkey) orelse {
            try tc.log("Instruction references unkown account {}", .{account.pubkey});
            return InstructionError.MissingAccount;
        };

        for (deduped_account_metas.slice(), 0..) |*deduped_meta, deduped_index| {
            if (deduped_meta.index_in_transaction == index_in_transaction) {
                deduped_indexes.appendAssumeCapacity(deduped_index);
                deduped_meta.is_signer = deduped_meta.is_signer or account.is_signer;
                deduped_meta.is_writable = deduped_meta.is_writable or account.is_writable;
            }
            continue;
        }

        const index_in_caller = caller.info.getAccountMetaIndex(account.pubkey) orelse {
            try tc.log("Instruction references unkown account {}", .{account.pubkey});
            return InstructionError.MissingAccount;
        };

        deduped_indexes.appendAssumeCapacity(deduped_account_metas.len);
        deduped_account_metas.appendAssumeCapacity(.{
            .pubkey = account.pubkey,
            .index_in_transaction = index_in_transaction,
            .index_in_caller = index_in_caller,
            .index_in_callee = @intCast(index),
            .is_signer = account.is_signer,
            .is_writable = account.is_writable,
        });
    }

    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L386-L415
    for (deduped_account_metas.slice()) |callee_account| {
        // Borrow the account via the caller context
        const caller_account =
            try caller.borrowInstructionAccount(callee_account.index_in_transaction);
        defer caller_account.release();

        // Readonly in caller cannot become writable in callee
        if (!caller_account.context.is_writable and callee_account.is_writable) {
            try tc.log("{}'s writable privilege escalated", .{caller_account.pubkey});
            return InstructionError.PrivilegeEscalation;
        }

        // To be signed in the callee,
        // it must be either signed in the caller or by the program
        var allow_callee_signer = caller_account.context.is_signer;
        for (signers) |signer| {
            if (!allow_callee_signer) {
                if (signer.equals(&caller_account.pubkey)) allow_callee_signer = true;
            } else break;
        }
        if (!allow_callee_signer and callee_account.is_signer) {
            try tc.log("{}'s signer privilege escalated", .{caller_account.pubkey});
            return InstructionError.PrivilegeEscalation;
        }
    }

    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L415-L425
    var instruction_accounts = std.BoundedArray(
        InstructionInfo.AccountMeta,
        InstructionInfo.MAX_ACCOUNT_METAS,
    ){};
    for (deduped_indexes.slice()) |index| {
        const deduped_account = deduped_account_metas.buffer[index];
        instruction_accounts.appendAssumeCapacity(.{
            .pubkey = deduped_account.pubkey,
            .index_in_transaction = deduped_account.index_in_transaction,
            .index_in_caller = deduped_account.index_in_caller,
            .index_in_callee = deduped_account.index_in_callee,
            .is_signer = deduped_account.is_signer,
            .is_writable = deduped_account.is_writable,
        });
    }

    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L426-L457
    const index_in_caller = caller.info.getAccountMetaIndex(callee.program_id) orelse {
        try tc.log("Unknown program {}", .{callee.program_id});
        return InstructionError.MissingAccount;
    };
    const index_in_transaction =
        caller.info.account_metas.buffer[index_in_caller].index_in_transaction;

    const borrowed_program_account =
        try caller.borrowInstructionAccount(index_in_caller);
    defer borrowed_program_account.release();

    if (!borrowed_program_account.account.executable) {
        try tc.log("Account {} is not executable", .{callee.program_id});
        return InstructionError.AccountNotExecutable;
    }

    return .{
        .program_meta = .{
            .pubkey = callee.program_id,
            .index_in_transaction = index_in_transaction,
        },
        .account_metas = instruction_accounts,
        .instruction_data = callee.data,
        .initial_account_lamports = 0,
    };
}

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L452
fn sumAccountLamports(
    self: *const TransactionContext,
    account_metas: []const InstructionInfo.AccountMeta,
) u128 {
    var lamports: u128 = 0;
    for (account_metas, 0..) |account_meta, index| {
        if (account_meta.index_in_callee != index) continue;

        const transaction_account =
            self.getAccountAtIndex(account_meta.index_in_transaction) orelse return 0;

        const account, const account_read_lock =
            transaction_account.readWithLock() orelse return 0;
        defer account_read_lock.release();

        lamports = std.math.add(u128, lamports, account.lamports) catch {
            return 0;
        };
    }
    return lamports;
}
