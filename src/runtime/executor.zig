const std = @import("std");
const sig = @import("../sig.zig");

const ids = sig.runtime.ids;
const program = sig.runtime.program;
const stable_log = sig.runtime.stable_log;
const bpf_loader_program = sig.runtime.program.bpf_loader;

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
pub fn pushInstruction(
    tc: *TransactionContext,
    initial_instruction_info: InstructionInfo,
) InstructionError!void {
    const instruction_info = initial_instruction_info;
    const program_id = instruction_info.program_meta.pubkey;

    // [agave] https://github.com/anza-xyz/agave/blob/92b11cd2eef1d3f5434d6af702f7d7a85ffcfca9/program-runtime/src/invoke_context.rs#L245-L283
    // [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/fd_executor.c#L1048-L1070
    for (tc.instruction_stack.constSlice(), 0..) |ic, level| {
        // If the program is on the stack, it must be the last entry otherwise it is a reentrancy violation
        if (program_id.equals(&ic.ixn_info.program_meta.pubkey) and
            level != tc.instruction_stack.len - 1)
        {
            return InstructionError.ReentrancyNotAllowed;
        }
    }

    // Push to transaction context():
    // [agave] https://github.com/anza-xyz/agave/blob/v3.0/transaction-context/src/lib.rs#L420
    if (tc.instruction_stack.len > 0 and tc.accounts_lamport_delta != 0) {
        return InstructionError.UnbalancedInstruction;
    }
    if (tc.instruction_trace.len >= tc.instruction_trace.capacity()) {
        return InstructionError.MaxInstructionTraceLengthExceeded;
    }
    if (tc.instruction_stack.len >= tc.instruction_stack.capacity()) {
        return InstructionError.CallDepth;
    }

    tc.instruction_stack.appendAssumeCapacity(.{
        .tc = tc,
        .ixn_info = instruction_info,
        .depth = @intCast(tc.instruction_stack.len),
    });

    tc.instruction_trace.appendAssumeCapacity(.{
        .ixn_info = instruction_info,
        .depth = @intCast(tc.instruction_stack.len),
    });

    if (tc.getAccountIndex(sig.runtime.sysvar.instruction.ID)) |index_in_transaction| {
        const account = tc.getAccountAtIndex(index_in_transaction) orelse
            return InstructionError.NotEnoughAccountKeys;
        // Normally this would never be hit since we setup the sysvar accounts and their owners,
        // however if the validator falls into some sort of corrupt state, it is plausible this
        // could trigger. Should only be seen through fuzzing.
        if (!account.account.owner.equals(&sig.runtime.sysvar.OWNER_ID)) {
            return InstructionError.InvalidAccountOwner;
        }

        // store_current_index_checked()
        const data = account.account.data;
        if (data.len < 2) return InstructionError.AccountDataTooSmall;
        const last_index = data.len - 2;
        std.mem.writeInt(u16, data[last_index..][0..2], tc.top_level_instruction_index, .little);
    }
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
    // [agave] https://github.com/anza-xyz/agave/blob/1ceeab0548d5db0bbcf7dab7726c2ffb4180fa76/program-runtime/src/invoke_context.rs#L509-L533
    const native_program_id, const program_id = blk: {
        const program_account = ic.borrowProgramAccount() catch
            return InstructionError.UnsupportedProgramId;
        defer program_account.release();

        const program_key = program_account.pubkey.base58String().constSlice();
        if (ids.NATIVE_LOADER_ID.equals(&program_account.account.owner) or
            program.PRECOMPILE_ENTRYPOINTS.get(program_key) != null)
            break :blk .{ program_account.pubkey, program_account.pubkey };

        const owner_id = program_account.account.owner;
        if (bpf_loader_program.v1.ID.equals(&owner_id) or
            bpf_loader_program.v2.ID.equals(&owner_id) or
            bpf_loader_program.v3.ID.equals(&owner_id) or
            bpf_loader_program.v4.ID.equals(&owner_id))
            break :blk .{ owner_id, program_account.pubkey };

        return InstructionError.UnsupportedProgramId;
    };

    const maybe_precompile_fn =
        program.PRECOMPILE_ENTRYPOINTS.get(native_program_id.base58String().slice());

    const maybe_native_program_fn = maybe_precompile_fn orelse blk: {
        const native_program_fn = program.PROGRAM_ENTRYPOINTS.get(
            native_program_id.base58String().slice(),
        );
        ic.tc.return_data.data.len = 0;
        break :blk native_program_fn;
    };

    const native_program_fn = maybe_native_program_fn orelse
        return InstructionError.UnsupportedProgramId;

    // Invoke the program and log the result
    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L551-L571
    // [fd] https://github.com/firedancer-io/firedancer/blob/dfadb7d33683aa8711dfe837282ad0983d3173a0/src/flamenco/runtime/fd_executor.c#L1160-L1167
    try stable_log.programInvoke(
        ic.tc,
        program_id,
        ic.tc.instruction_stack.len,
    );

    native_program_fn(allocator, ic) catch |err| {
        // This approach to failure logging is used to prevent requiring all native programs to return
        // an ExecutionError. Instead, native programs return an InstructionError, and more granular
        // failure logging for bpf programs is handled in the BPF executor.
        if (err != InstructionError.ProgramFailedToComplete)
            try stable_log.programFailure(
                ic.tc,
                program_id,
                sig.vm.getExecutionErrorMessage(err),
            );
        return err;
    };

    try stable_log.programSuccess(
        ic.tc,
        program_id,
    );
}

/// Pop an instruction from the instruction stack\
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L290
pub fn popInstruction(
    tc: *TransactionContext,
) InstructionError!void {
    // TODO: pop syscall context and record trace log
    // [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L291-L294

    // [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L407-L409
    if (tc.instruction_stack.len == 0) return InstructionError.CallDepth;

    // [agave] https://github.com/anza-xyz/solana-sdk/blob/e1554f4067329a0dcf5035120ec6a06275d3b9ec/transaction-context/src/lib.rs#L411-L426
    const unbalanced_instruction = blk: {
        const ic = try tc.getCurrentInstructionContext();

        // Check program account has no outstanding borrows
        const program_account = ic.borrowProgramAccount() catch |err| switch (err) {
            error.AccountBorrowFailed => return InstructionError.AccountBorrowOutstanding,
            else => |e| return e,
        };
        program_account.release();

        break :blk tc.accounts_lamport_delta != 0;
    };

    _ = tc.instruction_stack.pop();
    if (tc.instruction_stack.len == 0) {
        tc.top_level_instruction_index +|= 1;
    }

    if (unbalanced_instruction) return InstructionError.UnbalancedInstruction;
}

/// Prepare the InstructionInfo for an instruction invoked via CPI\
/// [agave] https://github.com/anza-xyz/agave/blob/a705c76e5a4768cfc5d06284d4f6a77779b24c96/program-runtime/src/invoke_context.rs#L325
pub fn prepareCpiInstructionInfo(
    tc: *TransactionContext,
    callee: Instruction,
    signers: []const Pubkey,
) (error{OutOfMemory} || InstructionError)!InstructionInfo {
    const caller = try tc.getCurrentInstructionContext();

    var dedupe_map: [InstructionInfo.MAX_ACCOUNT_METAS]u8 = @splat(0xff);
    var deduped_account_metas = InstructionInfo.AccountMetas{};

    for (callee.accounts) |account| {
        const index_in_transaction = tc.getAccountIndex(account.pubkey) orelse {
            try tc.log("Instruction references an unknown account {}", .{account.pubkey});
            return InstructionError.MissingAccount;
        };

        const index_in_callee_ptr = &dedupe_map[index_in_transaction];
        if (index_in_callee_ptr.* < deduped_account_metas.len) {
            const prev = &deduped_account_metas.slice()[index_in_callee_ptr.*];
            prev.is_signer = prev.is_signer or account.is_signer;
            prev.is_writable = prev.is_writable or account.is_writable;
            deduped_account_metas.appendAssumeCapacity(prev.*);
        } else {
            index_in_callee_ptr.* = @intCast(deduped_account_metas.len);
            deduped_account_metas.appendAssumeCapacity(.{
                .pubkey = account.pubkey,
                .index_in_transaction = index_in_transaction,
                .is_signer = account.is_signer,
                .is_writable = account.is_writable,
            });
        }
    }

    for (deduped_account_metas.slice(), 0..) |*account_meta, index_in_instruction| {
        const index_in_callee = dedupe_map[account_meta.index_in_transaction];

        if (index_in_callee != index_in_instruction) {
            if (index_in_callee >= deduped_account_metas.len) return error.NotEnoughAccountKeys;
            const prev = deduped_account_metas.get(index_in_callee);
            account_meta.is_signer = account_meta.is_signer or prev.is_signer;
            account_meta.is_writable = account_meta.is_writable or prev.is_writable;
            // This account is repeated, so theres no need to check for perms
            continue;
        }

        const index_in_caller =
            try caller.ixn_info.getAccountInstructionIndex(account_meta.index_in_transaction);

        const callee_account_key = callee.accounts[index_in_instruction].pubkey;
        const caller_account_meta = caller.ixn_info.account_metas.get(index_in_caller);

        // Readonly in caller cannot become writable in callee
        if (account_meta.is_writable and !caller_account_meta.is_writable) {
            try tc.log("{}'s writable privilege escalated", .{callee_account_key});
            return error.PrivilegeEscalation;
        }

        // To be signed in the callee,
        // it must be either signed in the caller or by the program
        const in_signers = for (signers) |signer| {
            if (signer.equals(&callee_account_key)) break true;
        } else false;
        if (account_meta.is_signer and !(caller_account_meta.is_signer or in_signers)) {
            try tc.log("{}'s signer privilege escalated", .{callee_account_key});
            return error.PrivilegeEscalation;
        }
    }

    // Find and validate executables / program accounts
    const program_account_index = for (caller.ixn_info.account_metas.slice(), 0..) |acc_meta, i| {
        const tc_acc = tc.getAccountAtIndex(acc_meta.index_in_transaction) orelse continue;
        if (tc_acc.pubkey.equals(&callee.program_id)) break i;
    } else {
        try tc.log("Unknown program {}", .{callee.program_id});
        return error.MissingAccount;
    };

    const program_index_in_transaction = blk: {
        const program_account_meta = caller.ixn_info.getAccountMetaAtIndex(
            @intCast(program_account_index),
        ) orelse return error.NotEnoughAccountKeys;
        break :blk program_account_meta.index_in_transaction;
    };

    return .{
        .program_meta = .{
            .pubkey = callee.program_id,
            .index_in_transaction = program_index_in_transaction,
        },
        .account_metas = deduped_account_metas,
        .dedupe_map = dedupe_map,
        .instruction_data = callee.data,
        .initial_account_lamports = 0,
    };
}

test pushInstruction {
    const testing = sig.runtime.testing;
    const system_program = sig.runtime.program.system;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    var cache, var tc = try testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{
                .{ .lamports = 2_000, .owner = system_program.ID },
                .{ .lamports = 0 },
                .{ .pubkey = system_program.ID },
            },
        },
    );
    defer {
        testing.deinitTransactionContext(allocator, tc);
        cache.deinit(allocator);
    }

    var instruction_info = try testing.createInstructionInfo(
        &tc,
        system_program.ID,
        system_program.Instruction{
            .transfer = .{
                .lamports = 1_000,
            },
        },
        &.{
            .{ .index_in_transaction = 0, .is_writable = true },
            .{ .index_in_transaction = 1 },
        },
    );
    defer instruction_info.deinit(allocator);

    // Success
    try pushInstruction(&tc, instruction_info);
    try std.testing.expectEqual(
        1,
        tc.instruction_stack.len,
    );

    {
        // Failure: UnbalancedInstruction
        // Modify and defer reset the first account's lamports
        tc.accounts[0].account.lamports += 1;
        tc.accounts_lamport_delta += 1;
        defer {
            tc.accounts[0].account.lamports -= 1;
            tc.accounts_lamport_delta -= 1;
        }

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

test "pushInstruction sysvar account data" {
    const system_program = sig.runtime.program.system;
    const testing = sig.runtime.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    var sysvar_data: [20]u8 = @splat(0);
    var cache, var tc = try testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{
                .{ .lamports = 2_000 },
                .{ .lamports = 0 },
                .{
                    .pubkey = sig.runtime.sysvar.instruction.ID,
                    .owner = sig.runtime.sysvar.OWNER_ID,
                    .data = &sysvar_data,
                },
                .{ .pubkey = system_program.ID },
            },
        },
    );
    defer {
        testing.deinitTransactionContext(allocator, tc);
        cache.deinit(allocator);
    }

    var instruction_info = try testing.createInstructionInfo(
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

    try pushInstruction(&tc, instruction_info);
}

test "pushInstruction sysvar account too small" {
    const system_program = sig.runtime.program.system;
    const testing = sig.runtime.testing;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    var sysvar_data: [1]u8 = @splat(0); // needs to be at least 2 bytes large
    var cache, var tc = try testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{
                .{ .lamports = 2_000 },
                .{ .lamports = 0 },
                .{
                    .pubkey = sig.runtime.sysvar.instruction.ID,
                    .owner = sig.runtime.sysvar.OWNER_ID,
                    .data = &sysvar_data,
                },
                .{ .pubkey = system_program.ID },
            },
        },
    );
    defer {
        testing.deinitTransactionContext(allocator, tc);
        cache.deinit(allocator);
    }

    var instruction_info = try testing.createInstructionInfo(
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

    try std.testing.expectError(
        error.AccountDataTooSmall,
        pushInstruction(&tc, instruction_info),
    );
}

test "processNextInstruction" {
    const testing = sig.runtime.testing;
    const system_program = sig.runtime.program.system;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    var cache, var tc = try testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{
                .{ .lamports = 2_000, .owner = system_program.ID },
                .{ .lamports = 0 },
                .{ .pubkey = system_program.ID, .owner = ids.NATIVE_LOADER_ID },
            },
            .compute_meter = system_program.COMPUTE_UNITS,
        },
    );
    defer {
        testing.deinitTransactionContext(allocator, tc);
        cache.deinit(allocator);
    }

    var instruction_info = try testing.createInstructionInfo(
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

test popInstruction {
    const testing = sig.runtime.testing;
    const system_program = sig.runtime.program.system;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    var cache, var tc = try testing.createTransactionContext(
        allocator,
        prng.random(),
        .{
            .accounts = &.{
                .{ .lamports = 2_000, .owner = system_program.ID },
                .{ .lamports = 0 },
                .{ .pubkey = system_program.ID },
            },
        },
    );
    defer {
        testing.deinitTransactionContext(allocator, tc);
        cache.deinit(allocator);
    }

    var instruction_info = try testing.createInstructionInfo(
        &tc,
        system_program.ID,
        system_program.Instruction{
            .transfer = .{
                .lamports = 1_000,
            },
        },
        &.{
            .{ .index_in_transaction = 0, .is_writable = true },
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
        const borrowed_account = try (try tc.getCurrentInstructionContext()).borrowProgramAccount();
        defer borrowed_account.release();
        try std.testing.expectError(
            InstructionError.AccountBorrowOutstanding,
            popInstruction(&tc),
        );
    }

    {
        // Failure: UnbalancedInstruction
        tc.accounts[0].account.lamports += 1;
        tc.accounts_lamport_delta += 1;
        defer {
            tc.accounts[0].account.lamports -= 1;
            tc.accounts_lamport_delta -= 1;
        }

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

test prepareCpiInstructionInfo {
    const testing = sig.runtime.testing;
    const system_program = sig.runtime.program.system;

    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    var cache, var tc = try testing.createTransactionContext(
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
    defer {
        testing.deinitTransactionContext(allocator, tc);
        cache.deinit(allocator);
    }

    const caller = try testing.createInstructionInfo(
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
}
