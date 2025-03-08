const std = @import("std");
const sig = @import("../sig.zig");

const ids = sig.runtime.ids;
const program = sig.runtime.program;
const stable_log = sig.runtime.stable_log;
const feature_set = sig.runtime.feature_set;

const Instruction = sig.core.instruction.Instruction;
const InstructionError = sig.core.instruction.InstructionError;
const Pubkey = sig.core.Pubkey;

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
    processNextInstruction(allocator, tc) catch |err| {
        popInstruction(tc) catch {};
        return err;
    };

    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L478
    try popInstruction(tc);
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
    instruction_info_: InstructionInfo,
) InstructionError!void {
    var instruction_info = instruction_info_;
    const program_id = instruction_info.program_meta.pubkey;
    std.debug.print("pushInstruction: program id: {s}\n", .{program_id});

    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L250-L253
    // [fd] https://github.com/firedancer-io/firedancer/blob/5e9c865414c12b89f1e0c3a2775cb90e3ca3da60/src/flamenco/runtime/fd_executor.c#L1001-L101
    if (program_id.equals(&ids.NATIVE_LOADER_ID)) {
        std.debug.print("{s}=={s}\n", .{ program_id, ids.NATIVE_LOADER_ID });

        return InstructionError.UnsupportedProgramId;
    }
    std.debug.print("{s}!={s}\n", .{ program_id, ids.NATIVE_LOADER_ID });

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

    // Set initial account lamports before pushing the instruction context
    instruction_info.initial_account_lamports = try sumAccountLamports(
        tc,
        instruction_info.account_metas.constSlice(),
    );

    if (tc.instruction_stack.len > 0) {
        const parent = &tc.instruction_stack.buffer[tc.instruction_stack.len - 1];
        const initial_lamports = parent.info.initial_account_lamports;
        const current_lamports =
            try sumAccountLamports(tc, parent.info.account_metas.constSlice());
        if (initial_lamports != current_lamports) return InstructionError.UnbalancedInstruction;
    }

    if (tc.instruction_trace.len >= tc.instruction_trace.capacity()) {
        return InstructionError.MaxInstructionTraceLengthExceeded;
    }

    if (tc.instruction_stack.len >= tc.instruction_stack.capacity()) {
        return InstructionError.CallDepth;
    }

    tc.instruction_stack.appendAssumeCapacity(.{
        .tc = tc,
        .info = instruction_info,
        .depth = @intCast(tc.instruction_stack.len),
    });

    tc.instruction_trace.appendAssumeCapacity(.{
        .info = instruction_info,
        .depth = @intCast(tc.instruction_stack.len),
    });
}

/// Execute an instruction context after it has been pushed onto the instruction stack\
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L510
fn processNextInstruction(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
) (error{OutOfMemory} || InstructionError)!void {
    // Get next instruction context from the stack
    if (tc.instruction_stack.len == 0) return InstructionError.CallDepth;
    const ic = &tc.instruction_stack.buffer[tc.instruction_stack.len - 1];

    // Lookup the program id
    // [agave] https://github.com/anza-xyz/agave/blob/a1ed2b1052bde05e79c31388b399dba9da10f7de/program-runtime/src/invoke_context.rs#L518-L529
    const program_id = blk: {
        const program_account = ic.borrowProgramAccount() catch
            return InstructionError.UnsupportedProgramId;
        defer program_account.release();

        std.debug.print("borrowed program_account: {any}\n", .{program_account});

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

    std.debug.print("processNextInstruction: {s}\n", .{program_id});

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
    try stable_log.programInvoke(&ic.tc.log_collector, program_id, ic.tc.instruction_stack.len);
    native_program_fn(allocator, ic) catch |execute_error| {
        try stable_log.programFailure(&ic.tc.log_collector, program_id, execute_error);
        return execute_error;
    };
    try stable_log.programSuccess(&ic.tc.log_collector, program_id);
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
        const current_lamports = try sumAccountLamports(tc, ic.info.account_metas.constSlice());

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

        const maybe_duplicate_index: ?usize = blk: {
            for (deduped_account_metas.slice(), 0..) |*deduped_meta, deduped_index| {
                if (deduped_meta.index_in_transaction == index_in_transaction) {
                    break :blk deduped_index;
                }
            }
            break :blk null;
        };

        if (maybe_duplicate_index) |duplicate_index| {
            deduped_indexes.appendAssumeCapacity(duplicate_index);
            const deduped_meta = &deduped_account_metas.buffer[duplicate_index];
            deduped_meta.is_signer = deduped_meta.is_signer or account.is_signer;
            deduped_meta.is_writable = deduped_meta.is_writable or account.is_writable;
        } else {
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
            if (allow_callee_signer) break;
            if (signer.equals(&caller_account.pubkey)) allow_callee_signer = true;
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
    const program_index_in_transaction = if (tc.feature_set.active.contains(
        feature_set.LIFT_CPI_CALLER_RESTRICTION,
    )) blk: {
        break :blk tc.getAccountIndex(callee.program_id) orelse {
            try tc.log("Unknown program {}", .{callee.program_id});
            return InstructionError.MissingAccount;
        };
    } else blk: {
        const index_in_caller = caller.info.getAccountMetaIndex(callee.program_id) orelse {
            try tc.log("Unknown program {}", .{callee.program_id});
            return InstructionError.MissingAccount;
        };
        const program_meta = caller.info.account_metas.buffer[index_in_caller];

        const borrowed_account =
            try caller.borrowInstructionAccount(index_in_caller);
        defer borrowed_account.release();

        if (!tc.feature_set.active.contains(feature_set.REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS) and
            !borrowed_account.account.executable)
        {
            try tc.log("Account {} is not executable", .{callee.program_id});
            return InstructionError.AccountNotExecutable;
        }

        break :blk program_meta.index_in_transaction;
    };

    return .{
        .program_meta = .{
            .pubkey = callee.program_id,
            .index_in_transaction = program_index_in_transaction,
        },
        .account_metas = instruction_accounts,
        .instruction_data = callee.data,
        .initial_account_lamports = 0,
    };
}

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L452
fn sumAccountLamports(
    tc: *const TransactionContext,
    account_metas: []const InstructionInfo.AccountMeta,
) InstructionError!u128 {
    var lamports: u128 = 0;
    for (account_metas, 0..) |account_meta, index| {
        if (account_meta.index_in_callee != index) continue;

        const transaction_account = tc.getAccountAtIndex(
            account_meta.index_in_transaction,
        ) orelse return InstructionError.NotEnoughAccountKeys;

        const account, const read_lock = transaction_account.readWithLock() orelse
            return InstructionError.AccountBorrowOutstanding;
        defer read_lock.release();

        lamports = std.math.add(u128, lamports, account.lamports) catch {
            // Effectively unreachable, would required greater
            // than 1.8e19 accounts with max u64 lamports
            return InstructionError.ArithmeticOverflow;
        };
    }
    return lamports;
}

test "pushInstruction" {
    const testing = sig.runtime.testing;
    const system_program = sig.runtime.program.system_program;
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);
    var tc = try testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{
                .{ .lamports = 2_000 },
                .{ .lamports = 0 },
                .{ .pubkey = system_program.ID },
            },
        },
    );
    defer tc.deinit(allocator);

    var instruction_info = try testing.createInstructionInfo(
        allocator,
        &tc,
        system_program.ID,
        system_program.Instruction{
            .transfer = .{
                .lamports = 1_000,
            },
        },
        &.{
            .{ .index_in_transaction = 0 },
            .{ .index_in_transaction = 1 },
        },
    );
    defer instruction_info.deinit(allocator);

    {
        // Cannot push native loader
        // Modify and defer reset the program id
        const original_program_id = instruction_info.program_meta.pubkey;
        defer instruction_info.program_meta.pubkey = original_program_id;
        instruction_info.program_meta.pubkey = ids.NATIVE_LOADER_ID;

        try std.testing.expectError(
            InstructionError.UnsupportedProgramId,
            pushInstruction(&tc, instruction_info),
        );
    }

    // Success
    try pushInstruction(&tc, instruction_info);
    try std.testing.expectEqual(
        1,
        tc.instruction_stack.len,
    );

    {
        // Failure: UnbalancedInstruction
        // Modify and defer reset the first account's lamports
        const original_lamports = tc.accounts[0].account.lamports;
        defer tc.accounts[0].account.lamports = original_lamports;
        tc.accounts[0].account.lamports = original_lamports + 1;

        try std.testing.expectError(
            InstructionError.UnbalancedInstruction,
            pushInstruction(&tc, instruction_info),
        );
    }

    // Success
    try pushInstruction(&tc, instruction_info);
    try std.testing.expectEqual(
        2,
        tc.instruction_stack.len,
    );

    // Failure: ReentrancyNotAllowed
    // Pushing an instruction to the stack causes a reentrancy violation if there is already
    // an instruction context on the stack with the same program id that is not the last entry
    try std.testing.expectError(
        InstructionError.ReentrancyNotAllowed,
        pushInstruction(&tc, instruction_info),
    );
}

test "processNextInstruction" {
    const testing = sig.runtime.testing;
    const system_program = sig.runtime.program.system_program;
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    var tc = try testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{
                .{ .lamports = 2_000 },
                .{ .lamports = 0 },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
        },
    );
    defer tc.deinit(allocator);

    var instruction_info = try testing.createInstructionInfo(
        allocator,
        &tc,
        system_program.ID,
        system_program.Instruction{
            .transfer = .{
                .lamports = 1_000,
            },
        },
        &.{
            .{ .index_in_transaction = 0, .is_signer = true, .is_writable = true },
            .{ .index_in_transaction = 1, .is_signer = false, .is_writable = true },
        },
    );
    defer instruction_info.deinit(allocator);

    // Failure: CallDepth
    try std.testing.expectError(
        InstructionError.CallDepth,
        processNextInstruction(allocator, &tc),
    );

    {
        // Failure: UnsupportedProgramId
        // Modify and defer reset the system program id
        const original_program_id = tc.accounts[2].pubkey;
        defer tc.accounts[2].pubkey = original_program_id;
        tc.accounts[2].pubkey = Pubkey.initRandom(prng.random());

        try pushInstruction(&tc, instruction_info);

        try std.testing.expectError(
            InstructionError.UnsupportedProgramId,
            processNextInstruction(allocator, &tc),
        );

        _ = tc.instruction_stack.pop();
    }

    // Success
    try pushInstruction(&tc, instruction_info);
    try processNextInstruction(allocator, &tc);
}

test "popInstruction" {
    const testing = sig.runtime.testing;
    const system_program = sig.runtime.program.system_program;
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);
    var tc = try testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{
                .{ .lamports = 2_000 },
                .{ .lamports = 0 },
                .{ .pubkey = system_program.ID },
            },
        },
    );
    defer tc.deinit(allocator);

    var instruction_info = try testing.createInstructionInfo(
        allocator,
        &tc,
        system_program.ID,
        system_program.Instruction{
            .transfer = .{
                .lamports = 1_000,
            },
        },
        &.{
            .{ .index_in_transaction = 0 },
            .{ .index_in_transaction = 1 },
        },
    );
    defer instruction_info.deinit(allocator);

    // Failure: CallDepth
    try std.testing.expectError(
        InstructionError.CallDepth,
        popInstruction(&tc),
    );

    // Push an instruction onto the stack
    try pushInstruction(&tc, instruction_info);

    {
        // Failure: AccountBorrowOutstanding
        const borrowed_account = try tc.borrowAccountAtIndex(0, .{
            .program_id = Pubkey.ZEROES,
            .is_signer = false,
            .is_writable = false,
        });
        defer borrowed_account.release();
        try std.testing.expectError(
            InstructionError.AccountBorrowOutstanding,
            popInstruction(&tc),
        );
    }

    {
        // Failure: UnbalancedInstruction
        const original_lamports = tc.accounts[0].account.lamports;
        defer tc.accounts[0].account.lamports = original_lamports;
        tc.accounts[0].account.lamports = original_lamports + 1;
        try std.testing.expectError(
            InstructionError.UnbalancedInstruction,
            popInstruction(&tc),
        );
    }

    // Unbalanced instruction still pops the instruction so we need to push another
    try pushInstruction(&tc, instruction_info);

    // Success
    try popInstruction(&tc);
    try std.testing.expectEqual(
        0,
        tc.instruction_stack.len,
    );
}

test "prepareCpiInstructionInfo" {
    const testing = sig.runtime.testing;
    const system_program = sig.runtime.program.system_program;
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    var tc = try testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{
                .{ .pubkey = Pubkey.initRandom(prng.random()), .lamports = 2_000 },
                .{ .pubkey = Pubkey.initRandom(prng.random()), .lamports = 0 },
                .{ .pubkey = system_program.ID, .executable = true },
                .{ .pubkey = Pubkey.initRandom(prng.random()) },
            },
        },
    );
    defer tc.deinit(allocator);

    const caller = try testing.createInstructionInfo(
        allocator,
        &tc,
        system_program.ID,
        system_program.Instruction{
            .transfer = .{
                .lamports = 1_000,
            },
        },
        &.{
            .{ .index_in_transaction = 0, .is_signer = true, .is_writable = true },
            .{ .index_in_transaction = 1, .is_signer = false, .is_writable = false },
            .{ .index_in_transaction = 2, .is_signer = false, .is_writable = false },
        },
    );
    defer caller.deinit(allocator);

    var callee: sig.core.Instruction = .{
        .program_id = system_program.ID,
        .accounts = &.{
            .{ .pubkey = tc.accounts[0].pubkey, .is_signer = true, .is_writable = true },
            .{ .pubkey = tc.accounts[1].pubkey, .is_signer = false, .is_writable = false },
        },
        .data = &.{},
    };

    // Failure: CallDepth
    try std.testing.expectError(
        InstructionError.CallDepth,
        prepareCpiInstructionInfo(&tc, callee, &.{}),
    );

    try pushInstruction(&tc, caller);

    // Failure: Missing Account 1 (transaction missing account)
    {
        const original_accounts = callee.accounts;
        callee.accounts = &.{
            .{ .pubkey = Pubkey.initRandom(prng.random()), .is_signer = true, .is_writable = true },
        };
        defer callee.accounts = original_accounts;

        try std.testing.expectError(
            InstructionError.MissingAccount,
            prepareCpiInstructionInfo(&tc, callee, &.{}),
        );
    }

    // Failure: Missing Account 2 (caller missing account)
    {
        const original_accounts = callee.accounts;
        callee.accounts = &.{
            .{ .pubkey = tc.accounts[3].pubkey, .is_signer = false, .is_writable = false },
        };
        defer callee.accounts = original_accounts;

        try std.testing.expectError(
            InstructionError.MissingAccount,
            prepareCpiInstructionInfo(&tc, callee, &.{}),
        );
    }

    // Failure: MissingAccount 3 (caller missing program) lift_cpi_caller_restriction off)
    {
        const original_program_id = callee.program_id;
        callee.program_id = Pubkey.initRandom(prng.random());
        defer callee.program_id = original_program_id;

        try std.testing.expectError(
            InstructionError.MissingAccount,
            prepareCpiInstructionInfo(&tc, callee, &.{}),
        );
    }

    // Failure: PriviledgeEscalation 1 (writable)
    {
        const original_accounts = callee.accounts;
        callee.accounts = &.{
            .{ .pubkey = tc.accounts[1].pubkey, .is_signer = false, .is_writable = true },
        };
        defer callee.accounts = original_accounts;

        try std.testing.expectError(
            InstructionError.PrivilegeEscalation,
            prepareCpiInstructionInfo(&tc, callee, &.{}),
        );
    }

    // Failure: PriviledgeEscalation 2 (signer)
    {
        const original_accounts = callee.accounts;
        callee.accounts = &.{
            .{ .pubkey = tc.accounts[1].pubkey, .is_signer = true, .is_writable = false },
        };
        defer callee.accounts = original_accounts;

        try std.testing.expectError(
            InstructionError.PrivilegeEscalation,
            prepareCpiInstructionInfo(&tc, callee, &.{}),
        );
    }

    // Failure: AccountNotExecutable
    {
        tc.accounts[2].account.executable = false;
        defer tc.accounts[2].account.executable = true;

        try std.testing.expectError(
            InstructionError.AccountNotExecutable,
            prepareCpiInstructionInfo(&tc, callee, &.{}),
        );
    }

    // Success: REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS
    {
        tc.accounts[2].account.executable = false;
        defer tc.accounts[2].account.executable = true;

        try tc.feature_set.active.put(
            allocator,
            feature_set.REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS,
            0,
        );
        defer _ = tc.feature_set.active.swapRemove(
            feature_set.REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS,
        );

        _ = try prepareCpiInstructionInfo(&tc, callee, &.{});
    }
}

test "sumAccountLamports" {
    const testing = sig.runtime.testing;
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);
    var tc = try testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{
                .{ .lamports = 0 },
                .{ .lamports = 1 },
                .{ .lamports = 2 },
                .{ .lamports = 3 },
            },
        },
    );
    defer tc.deinit(allocator);

    {
        // Success: 0 + 1 + 2 + 3 = 6
        const account_metas = try testing.createInstructionContextAccountMetas(&tc, &.{
            .{ .index_in_transaction = 0 },
            .{ .index_in_transaction = 1 },
            .{ .index_in_transaction = 2 },
            .{ .index_in_transaction = 3 },
        });
        try std.testing.expectEqual(
            6,
            try sumAccountLamports(&tc, account_metas.constSlice()),
        );
    }

    {
        // Success: 0 + 1 + 2 + 0 = 3
        // First and last instruction account metas reference the same transaction account
        const account_metas = try testing.createInstructionContextAccountMetas(&tc, &.{
            .{ .index_in_transaction = 0 },
            .{ .index_in_transaction = 1 },
            .{ .index_in_transaction = 2 },
            .{ .index_in_transaction = 0 },
        });

        try std.testing.expectEqual(
            3,
            try sumAccountLamports(&tc, account_metas.constSlice()),
        );
    }

    {
        // Failure: NotEnoughAccountKeys
        var account_metas = try testing.createInstructionContextAccountMetas(&tc, &.{
            .{ .index_in_transaction = 0 },
            .{ .index_in_transaction = 1 },
            .{ .index_in_transaction = 2 },
            .{ .index_in_transaction = 3 },
        });

        account_metas.buffer[0].index_in_transaction = 4;

        try std.testing.expectError(
            InstructionError.NotEnoughAccountKeys,
            sumAccountLamports(&tc, account_metas.constSlice()),
        );
    }

    {
        // Failure: AccountBorrowOutstanding
        const borrowed_account = try tc.borrowAccountAtIndex(0, .{
            .program_id = Pubkey.ZEROES,
            .is_signer = false,
            .is_writable = false,
        });
        defer borrowed_account.release();

        const account_metas = try testing.createInstructionContextAccountMetas(&tc, &.{
            .{ .index_in_transaction = 0 },
            .{ .index_in_transaction = 1 },
            .{ .index_in_transaction = 2 },
            .{ .index_in_transaction = 3 },
        });

        try std.testing.expectError(
            InstructionError.AccountBorrowOutstanding,
            sumAccountLamports(&tc, account_metas.constSlice()),
        );
    }
}
