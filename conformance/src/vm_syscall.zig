const std = @import("std");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const sig = @import("sig");
const utils = @import("utils.zig");

const executor = sig.runtime.executor;
const serialize = sig.runtime.program.bpf.serialize;
const syscalls = sig.vm.syscalls;
const memory = sig.vm.memory;

const Vm = sig.vm.Vm;
const TransactionContext = sig.runtime.transaction_context.TransactionContext;

const Pubkey = sig.core.Pubkey;

const convertExecutionError = sig.vm.convertExecutionError;

const EMIT_LOGS = false;

const HEAP_MAX = 256 * 1024;
const STACK_SIZE = 4_096 * 64;

export fn sol_compat_vm_cpi_syscall_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    return sol_compat_vm_syscall_execute_v1(out_ptr, out_size, in_ptr, in_size);
}

/// [fd] https://github.com/firedancer-io/firedancer/blob/b5acf851f523ec10a85e1b0c8756b2aea477107e/src/flamenco/runtime/tests/fd_exec_sol_compat.c#L744
/// [solfuzz-agave] https://github.com/firedancer-io/solfuzz-agave/blob/0b8a7971055d822df3f602c287c368400a784c15/src/vm_syscalls.rs#L45
export fn sol_compat_vm_syscall_execute_v1(
    out_ptr: [*]u8,
    out_size: *u64,
    in_ptr: [*]const u8,
    in_size: u64,
) i32 {
    errdefer |err| std.debug.panic("err: {s}", .{@errorName(err)});

    var arena = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const in_slice = in_ptr[0..in_size];
    var ctx = pb.SyscallContext.decode(in_slice, allocator) catch |err| {
        std.debug.print("pb.Syscall.decode: {s}\n", .{@errorName(err)});
        return 0;
    };
    defer ctx.deinit();

    // utils.printPbSyscallContext(ctx) catch |err| {
    //     std.debug.print("printPbSyscallContext: {s}\n", .{@errorName(err)});
    //     return 0;
    // };

    const result = executeSyscall(allocator, ctx, EMIT_LOGS) catch |err| {
        std.debug.print("executeSyscall: {s}\n", .{@errorName(err)});
        return 0;
    };
    defer result.deinit();

    // utils.printPbSyscallEffects(result) catch |err| {
    //     std.debug.print("printPbSyscallEffects: {s}\n", .{@errorName(err)});
    //     return 0;
    // };

    const result_bytes = try result.encode(allocator);
    defer allocator.free(result_bytes);

    const out_slice = out_ptr[0..out_size.*];
    if (result_bytes.len > out_slice.len) {
        std.debug.print("out_slice.len: {d} < result_bytes.len: {d}\n", .{
            out_slice.len,
            result_bytes.len,
        });
        return 0;
    }
    @memcpy(out_slice[0..result_bytes.len], result_bytes);
    out_size.* = result_bytes.len;

    return 1;
}

fn executeSyscall(
    allocator: std.mem.Allocator,
    pb_syscall_ctx: pb.SyscallContext,
    emit_logs: bool,
) !pb.SyscallEffects {
    // Must have instruction context, vm context, and syscall invocation
    const pb_instr = pb_syscall_ctx.instr_ctx orelse return error.NoInstrCtx;
    const pb_vm = pb_syscall_ctx.vm_ctx orelse return error.NoVmCtx;
    const pb_syscall_invocation = pb_syscall_ctx.syscall_invocation orelse
        return error.NoSyscallInvocation;

    // // [solfuzz-agave] https://github.com/firedancer-io/solfuzz-agave/blob/0b8a7971055d822df3f602c287c368400a784c15/src/vm_syscalls.rs#L75-L87
    // for (pb_instr_ctx.accounts.items) |acc| {
    //     if (std.mem.eql(
    //         u8,
    //         acc.address.getSlice(),
    //         pb_instr_ctx.program_id.getSlice(),
    //     )) break;
    // } else {
    //     try pb_instr_ctx.accounts.append(.{
    //         .address = try pb_instr_ctx.program_id.dupe(allocator),
    //         .owner = protobuf.ManagedString.static(comptime &(.{0} ** 32)),
    //     });
    // }

    // Must be heap allocated for utils.deinitTransactionContext;
    const vm_environment = try allocator.create(sig.vm.Environment);

    // Create execution contexts
    var tc: TransactionContext = undefined;
    try utils.createTransactionContext(
        allocator,
        pb_instr,
        .{ .vm_environment = vm_environment },
        &tc,
    );
    defer utils.deinitTransactionContext(allocator, tc);

    // Will be deinit by utils.deinitTransactionContext
    const syscall_registry = &vm_environment.loader;
    syscall_registry.* = sig.vm.Environment.initV1Loader(
        tc.feature_set,
        tc.slot,
        false,
    );

    const reject_broken_elfs = false;
    const debugging_features = false;
    const direct_mapping = tc.feature_set.active(
        .account_data_direct_mapping,
        tc.slot,
    );
    const config = sig.vm.Environment.initV1Config(
        tc.feature_set,
        &tc.compute_budget,
        tc.slot,
        debugging_features,
        reject_broken_elfs,
    );
    vm_environment.config = config;

    // Set return data
    if (pb_vm.return_data) |return_data| {
        if (return_data.program_id.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;
        const program_id = Pubkey{ .data = return_data.program_id.getSlice()[0..Pubkey.SIZE].* };
        tc.return_data = .{ .program_id = program_id, .data = .{} };
        try tc.return_data.data.appendSlice(return_data.data.getSlice());
    }

    // Program Cache Load Builtins
    // https://github.com/firedancer-io/solfuzz-agave/blob/0b8a7971055d822df3f602c287c368400a784c15/src/vm_syscalls.rs#L128-L130
    {
        var accounts: sig.utils.collections.PubkeyMap(sig.runtime.AccountSharedData) = .{};
        defer accounts.deinit(allocator);

        for (tc.accounts) |acc| {
            try accounts.put(allocator, acc.pubkey, acc.account.*);
        }

        const clock = try tc.sysvar_cache.get(sig.runtime.sysvar.Clock);
        tc.program_map.* = try sig.runtime.program_loader.testLoad(
            allocator,
            &accounts,
            tc.vm_environment,
            clock.slot,
        );
    }

    // Create instruction info and push it to the transaction context
    if (pb_instr.program_id.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;
    const instr_info = try utils.createInstructionInfo(
        allocator,
        &tc,
        .{ .data = pb_instr.program_id.getSlice()[0..Pubkey.SIZE].* },
        pb_instr.data.getSlice(),
        pb_instr.instr_accounts.items,
    );
    defer instr_info.deinit(allocator);

    try executor.pushInstruction(&tc, instr_info);
    const ic = try tc.getCurrentInstructionContext();

    const host_align = 16;

    const rodata = try allocator.alignedAlloc(u8, host_align, pb_vm.rodata.getSlice().len);
    defer allocator.free(rodata);
    @memcpy(rodata, pb_vm.rodata.getSlice());

    const executable: sig.vm.Executable = .{
        .instructions = &.{},
        .bytes = rodata,
        .version = .v0,
        .ro_section = .{ .borrowed = .{
            .offset = memory.RODATA_START,
            .start = 0,
            .end = rodata.len,
        } },
        .entry_pc = 0,
        .config = config,
        .text_vaddr = memory.RODATA_START,
        .function_registry = .{},
        .from_asm = false,
    };

    const stricter_abi_and_runtime_constraints = tc.feature_set.active(
        .stricter_abi_and_runtime_constraints,
        tc.slot,
    );
    const mask_out_rent_epoch_in_vm_serialization = tc.feature_set.active(
        .mask_out_rent_epoch_in_vm_serialization,
        tc.slot,
    );
    var serialized = try serialize.serializeParameters(
        allocator,
        ic,
        direct_mapping,
        stricter_abi_and_runtime_constraints,
        mask_out_rent_epoch_in_vm_serialization,
    );
    defer serialized.deinit(allocator);
    tc.serialized_accounts = serialized.account_metas;

    if (pb_vm.heap_max > HEAP_MAX) return error.InvalidHeapSize;

    const heap_max = @min(HEAP_MAX, pb_vm.heap_max);

    const heap = try allocator.alignedAlloc(u8, host_align, heap_max);
    defer allocator.free(heap);
    @memset(heap, 0);

    const stack = try allocator.alignedAlloc(u8, host_align, STACK_SIZE);
    defer allocator.free(stack);
    @memset(stack, 0);

    var input_memory_regions: std.ArrayListUnmanaged(memory.Region) = .{};
    defer input_memory_regions.deinit(allocator);

    try input_memory_regions.appendSlice(allocator, &.{
        memory.Region.init(.constant, rodata, memory.RODATA_START),
        memory.Region.initGapped(
            .mutable,
            stack,
            memory.STACK_START,
            if (config.enable_stack_frame_gaps) config.stack_frame_size else 0,
        ),
        memory.Region.init(.mutable, heap, memory.HEAP_START),
    });
    try input_memory_regions.appendSlice(allocator, serialized.regions.items);

    const memory_map = try memory.MemoryMap.init(
        allocator,
        input_memory_regions.items,
        .v0,
        config,
    );

    var vm = try Vm.init(
        allocator,
        &executable,
        memory_map,
        syscall_registry,
        stack.len,
        0,
        &tc,
    );
    defer vm.deinit();

    vm.registers.set(.r0, pb_vm.r0);
    vm.registers.set(.r1, pb_vm.r1);
    vm.registers.set(.r2, pb_vm.r2);
    vm.registers.set(.r3, pb_vm.r3);
    vm.registers.set(.r4, pb_vm.r4);
    vm.registers.set(.r5, pb_vm.r5);
    vm.registers.set(.r6, pb_vm.r6);
    vm.registers.set(.r7, pb_vm.r7);
    vm.registers.set(.r8, pb_vm.r8);
    vm.registers.set(.r9, pb_vm.r9);
    vm.registers.set(.r10, pb_vm.r10);
    vm.registers.set(.pc, pb_vm.r11);

    utils.copyPrefix(heap, pb_syscall_invocation.heap_prefix.getSlice());
    utils.copyPrefix(stack, pb_syscall_invocation.stack_prefix.getSlice());

    const syscall_name = pb_syscall_ctx.syscall_invocation.?.function_name.getSlice();
    const syscall_tag = std.meta.stringToEnum(syscalls.Syscall, syscall_name) orelse {
        std.debug.print("Syscall not found: {s}\n", .{syscall_name});
        return error.SyscallNotFound;
    };
    const syscall_fn = syscalls.Syscall.map.get(syscall_tag);

    var execution_error: ?sig.vm.ExecutionError = null;
    syscall_fn(&tc, &vm.memory_map, &vm.registers) catch |err| {
        execution_error = err;
    };

    try executor.popInstruction(&tc);

    var @"error": i64, var error_kind: pb.ErrKind = .{ 0, .UNSPECIFIED };
    if (execution_error) |err| {
        @"error", const ek, _ = convertExecutionError(err);
        error_kind = switch (ek) {
            .Instruction => .INSTRUCTION,
            .Syscall => .SYSCALL,
            .Ebpf => .EBPF,
        };
        // Agave doesn't log Poseidon errors
        if (@"error" != -1) try sig.runtime.stable_log.programFailure(
            &tc,
            instr_info.program_meta.pubkey,
            err,
        );
    }

    // Special casing to return only the custom error for transactions which have
    // encountered the loader v4 program or bpf loader v3 migrate instruction.
    if (tc.custom_error == 0x30000000 or tc.custom_error == 0x40000000) {
        return .{
            .@"error" = tc.custom_error.?,
            .input_data_regions = .init(allocator),
        };
    }

    const effects = try utils.createSyscallEffect(allocator, .{
        .tc = &tc,
        .err = @"error",
        .err_kind = error_kind,
        .heap = heap,
        .stack = stack,
        .rodata = rodata,
        .frame_count = vm.depth,
        .memory_map = vm.memory_map,
        .registers = blk: {
            var registers = sig.vm.interpreter.RegisterMap.initFill(0);
            if (execution_error == null) registers.set(.r0, vm.registers.get(.r0));
            break :blk registers;
        },
    });

    if (emit_logs) {
        std.debug.print("Execution Logs:\n", .{});
        var i: usize = 0;
        var msgs = tc.log_collector.?.iterator();
        while (msgs.next()) |msg| : (i += 1) {
            std.debug.print("    {}: {s}\n", .{ i, msg });
        }
    }

    return effects;
}
