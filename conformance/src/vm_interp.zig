const std = @import("std");
const sig = @import("sig");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const utils = @import("utils.zig");

const serialize = sig.runtime.program.bpf.serialize;
const executor = sig.runtime.executor;
const SyscallContext = pb.SyscallContext;
const Pubkey = sig.core.Pubkey;
const svm = sig.vm;
const Executable = svm.Executable;
const Vm = svm.Vm;
const Registry = svm.Registry;
const Instruction = svm.sbpf.Instruction;
const Version = svm.sbpf.Version;
const memory = svm.memory;

const HEAP_MAX = 256 * 1024;
const STACK_SIZE = 4_096 * 64;

export fn sol_compat_vm_interp_v1(
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
    var reader: std.Io.Reader = .fixed(in_slice);
    const syscall_context = SyscallContext.decode(&reader, allocator) catch return 0;
    const result = executeVmTest(syscall_context, allocator) catch return 0;
    var writer: std.Io.Writer.Allocating = .init(allocator);
    defer writer.deinit();
    try result.encode(&writer.writer, allocator);
    const elf_effect_bytes = writer.written();

    const out_slice = out_ptr[0..out_size.*];
    if (elf_effect_bytes.len > out_slice.len) {
        return 0;
    }
    @memcpy(out_slice[0..elf_effect_bytes.len], elf_effect_bytes);
    out_size.* = elf_effect_bytes.len;
    return 1;
}

fn executeVmTest(
    syscall_context: SyscallContext,
    allocator: std.mem.Allocator,
) !pb.SyscallEffects {
    var instr_context = syscall_context.instr_ctx.?;
    const vm_context = syscall_context.vm_ctx.?;

    const slot = if (instr_context.slot_context) |slot_ctx| slot_ctx.slot else 0;

    for (instr_context.accounts.items) |acc| {
        if (std.mem.eql(u8, acc.address, instr_context.program_id)) break;
    } else {
        try instr_context.accounts.append(allocator, .{
            .address = try allocator.dupe(u8, instr_context.program_id),
            .owner = &(.{0} ** 32),
        });
    }

    var feature_set = try utils.loadFeatureSet(instr_context);
    var tc: sig.runtime.TransactionContext = undefined;
    try utils.createTransactionContext(
        allocator,
        instr_context,
        .{ .feature_set = &feature_set },
        &tc,
    );
    defer utils.deinitTransactionContext(allocator, tc);

    const sbpf_version: Version = switch (vm_context.sbpf_version) {
        1 => .v1,
        2 => .v2,
        3 => @panic("there should be no sbpf v3 harnesses"),
        else => .v0,
    };

    var env = sig.vm.Environment.initV1(
        tc.feature_set,
        &tc.compute_budget,
        tc.slot,
        false,
    );
    env.config.maximum_version = sbpf_version;
    env.loader.is_stubbed = true;
    const config = env.config;

    if (instr_context.program_id.len != Pubkey.SIZE) return error.OutOfBounds;
    const instr_info = try utils.createInstructionInfo(
        allocator,
        &tc,
        .{ .data = instr_context.program_id[0..Pubkey.SIZE].* },
        instr_context.data,
        instr_context.instr_accounts.items,
    );
    defer instr_info.deinit(allocator);

    try executor.pushInstruction(&tc, instr_info);

    var ic = tc.instruction_stack.buffer[tc.instruction_stack.len - 1];

    const direct_mapping = tc.feature_set.active(
        .account_data_direct_mapping,
        slot,
    );
    const stricter_abi_and_runtime_constraints = tc.feature_set.active(
        .stricter_abi_and_runtime_constraints,
        slot,
    );
    const mask_out_rent_epoch_in_vm_serialization = tc.feature_set.active(
        .mask_out_rent_epoch_in_vm_serialization,
        slot,
    );
    var serialized = try serialize.serializeParameters(
        allocator,
        &ic,
        direct_mapping,
        stricter_abi_and_runtime_constraints,
        mask_out_rent_epoch_in_vm_serialization,
    );
    defer serialized.deinit(allocator);
    tc.serialized_accounts = serialized.account_metas;

    const rodata = try allocator.dupe(u8, vm_context.rodata);
    defer allocator.free(rodata);

    var function_registry: Registry = .{};

    const max_pc = vm_context.rodata.len / 8;
    const entry_pc = @min(vm_context.entry_pc, max_pc -| 1);
    const hash: u32 = if (sbpf_version.enableStricterElfHeaders())
        @truncate(entry_pc)
    else
        sig.vm.sbpf.hashSymbolName("entrypoint");
    try function_registry.register(allocator, hash, "entrypoint", entry_pc);

    for (vm_context.call_whitelist, 0..) |byte, idx| {
        for (0..8) |bit_idx| {
            if (byte & (@as(u64, 1) << @intCast(bit_idx)) != 0) {
                const pc = idx * 8 + bit_idx;
                if (pc < max_pc) {
                    const whitelist_hash: u32 = if (sbpf_version.enableStricterElfHeaders())
                        @truncate(pc)
                    else
                        sig.vm.sbpf.hashSymbolName(std.mem.asBytes(&pc));
                    try function_registry.register(allocator, whitelist_hash, "fn", pc);
                }
            }
        }
    }

    if (rodata.len % 8 != 0) return .{
        .@"error" = -2,
        .input_data_regions = .{},
    };
    const executable: Executable = .{
        .instructions = std.mem.bytesAsSlice(Instruction, rodata),
        .bytes = rodata,
        .version = sbpf_version,
        .config = env.config,
        .function_registry = function_registry,
        .entry_pc = entry_pc,
        .ro_section = .{ .borrowed = .{
            .offset = memory.RODATA_START,
            .start = 0,
            .end = rodata.len,
        } },
        .from_asm = false,
        .text_vaddr = if (sbpf_version.enableLowerBytecodeVaddr())
            memory.BYTECODE_START
        else
            memory.RODATA_START,
    };

    const verify_result = executable.verify(&env.loader);
    if (std.meta.isError(verify_result)) {
        return .{
            .@"error" = -2,
            .input_data_regions = .{},
        };
    }

    const heap_max = @min(vm_context.heap_max, 256 * 1024);
    const syscall_inv = syscall_context.syscall_invocation.?;

    const stack = try allocator.alloc(u8, STACK_SIZE);
    defer allocator.free(stack);
    @memset(stack, 0);

    const heap = try allocator.alloc(u8, heap_max);
    defer allocator.free(heap);
    @memset(heap, 0);

    var input_memory_regions: std.ArrayListUnmanaged(memory.Region) = .{};
    defer input_memory_regions.deinit(allocator);

    try input_memory_regions.appendSlice(allocator, &.{
        memory.Region.init(.constant, vm_context.rodata, memory.RODATA_START),
        memory.Region.initGapped(
            .mutable,
            stack,
            memory.STACK_START,
            if (!sbpf_version.enableDynamicStackFrames() and config.enable_stack_frame_gaps)
                config.stack_frame_size
            else
                0,
        ),
        memory.Region.init(.mutable, heap, memory.HEAP_START),
    });
    try input_memory_regions.appendSlice(allocator, serialized.regions.items);

    const map = try memory.MemoryMap.init(
        allocator,
        input_memory_regions.items,
        sbpf_version,
        config,
    );
    defer map.deinit(allocator);

    var vm = try Vm.init(
        allocator,
        &executable,
        map,
        &env.loader,
        STACK_SIZE,
        0,
        &tc,
    );
    defer vm.deinit();

    // r1, r2, r10, pc are initialized by Vm.init, modifying them will most like break execution.
    // In vm_syscalls we allow override them (especially r1) because that simulates the fact
    // that a program partially executed before reaching the syscall.
    // Here we want to test what happens when the program starts from the beginning.
    // [agave] https://github.com/firedancer-io/solfuzz-agave/blob/agave-v3.1.0-beta.0/src/vm_interp.rs#L354-L365
    vm.registers.set(.r0, vm_context.r0);
    vm.registers.set(.r1, sig.vm.memory.INPUT_START);
    vm.registers.set(.r2, vm_context.r2);
    vm.registers.set(.r3, vm_context.r3);
    vm.registers.set(.r4, vm_context.r4);
    vm.registers.set(.r5, vm_context.r5);
    vm.registers.set(.r6, vm_context.r6);
    vm.registers.set(.r7, vm_context.r7);
    vm.registers.set(.r8, vm_context.r8);
    vm.registers.set(.r9, vm_context.r9);
    // vm.registers.set(.r10, vm_context.r10);
    // vm.registers.set(.pc, vm_context.r11);

    utils.copyPrefix(heap, syscall_inv.heap_prefix);
    utils.copyPrefix(stack, syscall_inv.stack_prefix);

    const result, _ = vm.run();

    const out_registers = switch (result) {
        .err => r: {
            var out = sig.vm.interpreter.RegisterMap.initFill(0);
            out.set(.pc, vm.registers.get(.pc)); // pc is set no matter if there's an error or not
            break :r out;
        },
        .ok => vm.registers,
    };

    if (result == .err and result.err == error.ExceededMaxInstructions) {
        return .{
            .@"error" = 9,
            .cu_avail = 0,
            .frame_count = vm.depth,
            .input_data_regions = .{},
        };
    }

    const err: i64 = switch (result) {
        .err => |err| sig.vm.convertExecutionError(err)[0],
        .ok => 0,
    };

    // finds the last element that isn't a 0 so that we can compress the stack list
    const last_item = if (std.mem.lastIndexOfNone(u8, stack, &.{0})) |last| last + 1 else 0;
    return utils.createSyscallEffect(allocator, .{
        .tc = &tc,
        .err = err,
        .err_kind = .UNSPECIFIED,
        .heap = heap,
        .stack = stack[0..last_item],
        .rodata = rodata,
        .frame_count = vm.depth,
        .memory_map = vm.memory_map,
        .registers = out_registers,
    });
}
