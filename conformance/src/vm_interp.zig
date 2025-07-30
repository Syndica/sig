const std = @import("std");
const sig = @import("sig");
const pb = @import("proto/org/solana/sealevel/v1.pb.zig");
const protobuf = @import("protobuf");
const utils = @import("utils.zig");

const serialize = sig.runtime.program.bpf.serialize;
const executor = sig.runtime.executor;
const features = sig.core.features;
const SyscallContext = pb.SyscallContext;
const Pubkey = sig.core.Pubkey;
const svm = sig.vm;
const syscalls = svm.syscalls;
const Executable = svm.Executable;
const Config = svm.Config;
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
    const syscall_context = SyscallContext.decode(in_slice, allocator) catch return 0;
    defer syscall_context.deinit();

    const result = executeVmTest(syscall_context, allocator) catch {
        return 0;
    };
    defer result.deinit();

    const elf_effect_bytes = try result.encode(allocator);
    defer allocator.free(elf_effect_bytes);

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

    for (instr_context.accounts.items) |acc| {
        if (std.mem.eql(
            u8,
            acc.address.getSlice(),
            instr_context.program_id.getSlice(),
        )) break;
    } else {
        try instr_context.accounts.append(.{
            .address = try instr_context.program_id.dupe(allocator),
            .owner = protobuf.ManagedString.static(&(.{0} ** 32)),
        });
    }

    var feature_set = try allocator.create(sig.core.FeatureSet);
    feature_set.* = try utils.createFeatureSet(allocator, instr_context);
    var tc: sig.runtime.TransactionContext = undefined;
    try utils.createTransactionContext(
        allocator,
        instr_context,
        .{
            .feature_set = feature_set,
        },
        &tc,
    );
    defer utils.deinitTransactionContext(allocator, tc);

    const sbpf_version: Version = switch (vm_context.sbpf_version) {
        1 => .v1,
        2 => .v2,
        3 => .v3,
        else => .v0,
    };
    if (sbpf_version.gte(.v1)) {
        try feature_set.active.put(allocator, features.BPF_ACCOUNT_DATA_DIRECT_MAPPING, 0);
    }

    const direct_mapping = sbpf_version.gte(.v1) or
        feature_set.active.contains(features.BPF_ACCOUNT_DATA_DIRECT_MAPPING);

    if (instr_context.program_id.getSlice().len != Pubkey.SIZE) return error.OutOfBounds;
    const instr_info = try utils.createInstructionInfo(
        allocator,
        &tc,
        .{ .data = instr_context.program_id.getSlice()[0..Pubkey.SIZE].* },
        instr_context.data.getSlice(),
        instr_context.instr_accounts.items,
    );
    defer instr_info.deinit(allocator);

    try executor.pushInstruction(&tc, instr_info);

    var ic = tc.instruction_stack.buffer[tc.instruction_stack.len - 1];

    const config: Config = .{
        .minimum_version = .v0,
        .maximum_version = sbpf_version,
        .enable_stack_frame_gaps = !direct_mapping,
        .aligned_memory_mapping = !direct_mapping,
        .enable_instruction_tracing = true,
    };

    const mask_out_rent_epoch_in_vm_serialization = tc.feature_set.active.contains(
        features.MASK_OUT_RENT_EPOCH_IN_VM_SERIALIZATION,
    );
    var parameter_bytes, var regions, const accounts_metadata = try serialize.serializeParameters(
        allocator,
        &ic,
        !direct_mapping,
        mask_out_rent_epoch_in_vm_serialization,
    );
    defer {
        parameter_bytes.deinit(allocator);
        regions.deinit(allocator);
    }
    tc.serialized_accounts = accounts_metadata;

    const rodata = try allocator.dupe(u8, vm_context.rodata.getSlice());
    defer allocator.free(rodata);

    var syscall_registry = try createSyscallRegistry(
        allocator,
        feature_set,
        false,
    );
    defer syscall_registry.deinit(allocator);

    var function_registry: Registry(u64) = .{};

    const max_pc = vm_context.rodata.getSlice().len / 8;
    const entry_pc = @min(vm_context.entry_pc, max_pc -| 1);
    const hash: u32 = if (sbpf_version.enableStricterElfHeaders())
        @truncate(entry_pc)
    else
        sig.vm.sbpf.hashSymbolName("entrypoint");
    try function_registry.register(allocator, hash, "entrypoint", entry_pc);

    for (vm_context.call_whitelist.getSlice(), 0..) |byte, idx| {
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
        .input_data_regions = std.ArrayList(pb.InputDataRegion).init(allocator),
    };
    const executable: Executable = .{
        .instructions = std.mem.bytesAsSlice(Instruction, rodata),
        .bytes = rodata,
        .version = sbpf_version,
        .config = config,
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

    const verify_result = executable.verify(&syscall_registry);
    if (std.meta.isError(verify_result)) {
        return .{
            .@"error" = -2,
            .input_data_regions = std.ArrayList(pb.InputDataRegion).init(allocator),
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
        memory.Region.init(.constant, vm_context.rodata.getSlice(), memory.RODATA_START),
        memory.Region.initGapped(
            .mutable,
            stack,
            memory.STACK_START,
            if (config.enable_stack_frame_gaps)
                config.stack_frame_size
            else
                0,
        ),
        memory.Region.init(.mutable, heap, memory.HEAP_START),
    });
    try input_memory_regions.appendSlice(allocator, regions.items);

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
        &syscall_registry,
        STACK_SIZE,
        &tc,
    );
    defer vm.deinit();

    // r1, r10, pc are initialized by Vm.init, modifying them will most like break execution.
    // In vm_syscalls we allow override them (especially r1) because that simulates the fact
    // that a program partially executed before reaching the syscall.
    // Here we want to test what happens when the program starts from the beginning.
    // [agave] https://github.com/firedancer-io/solfuzz-agave/blob/0b8a7971055d822df3f602c287c368400a784c15/src/vm_interp.rs#L357-L362
    vm.registers.set(.r0, vm_context.r0);
    // vm.registers.set(.r1, vm_context.r1);
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

    utils.copyPrefix(heap, syscall_inv.heap_prefix.getSlice());
    utils.copyPrefix(stack, syscall_inv.stack_prefix.getSlice());

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
            .@"error" = 16,
            .cu_avail = 0,
            .frame_count = vm.depth,
            .input_data_regions = std.ArrayList(pb.InputDataRegion).init(allocator),
        };
    }

    const err: i64 = switch (result) {
        .err => |err| convertError(err),
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

/// [agave] https://github.com/firedancer-io/solfuzz-agave/blob/agave-v2.1.14/src/utils/vm/err_map.rs#L7-L31
fn convertError(err: anyerror) i32 {
    return switch (err) {
        // zig fmt: off
        error.NoProgram                  => 6,
        error.UnknownOpCode              => 25,
        error.InvalidSourceRegister      => 26,
        error.InvalidDestinationRegister => 27,
        error.CannotWriteR10             => 27,
        error.InfiniteLoop               => 28, 
        error.JumpOutOfCode              => 29,
        error.JumpToMiddleOfLDDW         => 30,
        error.UnsupportedLEBEArgument    => 31,
        error.LDDWCannotBeLast           => 32,
        error.IncompleteLDDW             => 33,
        error.InvalidRegister            => 35,
        error.ShiftWithOverflow          => 37,
        error.ProgramLengthNotMultiple   => 38,

        error.ComputationalBudgetExceeded => 16,
        error.TooManySlices               => 1,
        error.InvalidLength               => 1,
        error.InvalidAttribute            => 1,
        error.StackAccessViolation        => 13,
        error.AccessViolation             => 13,
        error.InvalidParameters           => 1,
        error.InvalidEndianness           => 1,

        error.CallOutsideTextSegment      => 8,
        error.ExecutionOverrun            => 8,
        error.CallDepthExceeded           => 11,
        error.UnsupportedInstruction      => 12,
        error.InvalidInstruction          => 12,
        // error.AccessViolation             => 13,
        // error.StackAccessViolation        => 13,
        error.ExceededMaxInstructions     => 16,
        error.DivisionByZero              => 18,
        error.DivideOverflow              => 19,

        // zig fmt: on
        else => {
            std.debug.panic("unknown err: {s}", .{@errorName(err)});
        },
    };
}

fn stub(
    _: *sig.runtime.TransactionContext,
    _: *sig.vm.memory.MemoryMap,
    _: *sig.vm.interpreter.RegisterMap,
) sig.vm.syscalls.Error!void {}

// [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/syscalls/mod.rs#L335
pub fn createSyscallRegistry(
    allocator: std.mem.Allocator,
    feature_set: *const sig.core.FeatureSet,
    is_deploy: bool,
) !svm.Registry(svm.Syscall) {
    // Register syscalls
    var registry = svm.Registry(svm.Syscall){};
    errdefer registry.deinit(allocator);

    // Abort
    _ = try registry.registerHashed(
        allocator,
        "abort",
        stub,
    );

    // Panic
    _ = try registry.registerHashed(
        allocator,
        "sol_panic_",
        stub,
    );

    // Alloc Free
    if (!is_deploy) {
        _ = try registry.registerHashed(
            allocator,
            "sol_alloc_free",
            stub,
        );
    }

    // Logging
    _ = try registry.registerHashed(
        allocator,
        "sol_log_",
        stub,
    );

    _ = try registry.registerHashed(
        allocator,
        "sol_log_64_",
        stub,
    );

    _ = try registry.registerHashed(
        allocator,
        "sol_log_pubkey",
        stub,
    );

    _ = try registry.registerHashed(
        allocator,
        "sol_log_compute_units_",
        stub,
    );

    // Log Data
    _ = try registry.registerHashed(
        allocator,
        "sol_log_data",
        stub,
    );

    // Program derived addresses
    _ = try registry.registerHashed(
        allocator,
        "sol_create_program_address",
        stub,
    );
    _ = try registry.registerHashed(
        allocator,
        "sol_try_find_program_address",
        stub,
    );

    // Sha256, Keccak256, Secp256k1Recover
    _ = try registry.registerHashed(
        allocator,
        "sol_sha256",
        stub,
    );
    _ = try registry.registerHashed(
        allocator,
        "sol_keccak256",
        stub,
    );
    _ = try registry.registerHashed(
        allocator,
        "sol_secp256k1_recover",
        stub,
    );
    // Blake3
    if (feature_set.active.contains(features.BLAKE3_SYSCALL_ENABLED)) {
        _ = try registry.registerHashed(
            allocator,
            "sol_blake3",
            stub,
        );
    }

    // Elliptic Curve
    if (feature_set.active.contains(features.CURVE25519_SYSCALL_ENABLED)) {
        _ = try registry.registerHashed(
            allocator,
            "sol_curve_validate_point",
            stub,
        );
        _ = try registry.registerHashed(
            allocator,
            "sol_curve_group_op",
            stub,
        );
        _ = try registry.registerHashed(
            allocator,
            "sol_curve_multiscalar_mul",
            stub,
        );
    }

    // Sysvars
    _ = try registry.registerHashed(
        allocator,
        "sol_get_clock_sysvar",
        stub,
    );
    _ = try registry.registerHashed(
        allocator,
        "sol_get_epoch_schedule_sysvar",
        stub,
    );
    if (!feature_set.active.contains(features.DISABLE_FEES_SYSVAR)) {
        _ = try registry.registerHashed(
            allocator,
            "sol_get_fees_sysvar",
            stub,
        );
    }
    _ = try registry.registerHashed(
        allocator,
        "sol_get_rent_sysvar",
        stub,
    );
    if (feature_set.active.contains(features.LAST_RESTART_SLOT_SYSVAR)) {
        _ = try registry.registerHashed(
            allocator,
            "sol_get_last_restart_slot",
            stub,
        );
    }
    _ = try registry.registerHashed(
        allocator,
        "sol_get_epoch_rewards_sysvar",
        stub,
    );

    // Memory
    _ = try registry.registerHashed(
        allocator,
        "sol_memcpy_",
        stub,
    );

    _ = try registry.registerHashed(
        allocator,
        "sol_memmove_",
        stub,
    );

    _ = try registry.registerHashed(
        allocator,
        "sol_memset_",
        stub,
    );

    _ = try registry.registerHashed(
        allocator,
        "sol_memcmp_",
        stub,
    );

    // Processed Sibling
    _ = try registry.registerHashed(
        allocator,
        "sol_get_processed_sibling_instruction",
        stub,
    );

    // Stack Height
    _ = try registry.registerHashed(
        allocator,
        "sol_get_stack_height",
        stub,
    );

    // Return Data
    _ = try registry.registerHashed(
        allocator,
        "sol_set_return_data",
        stub,
    );
    // _ = try registry.registerHashed(allocator, "sol_get_return_data", getReturnData,);

    // Cross Program Invocation
    _ = try registry.registerHashed(
        allocator,
        "sol_invoke_signed_c",
        stub,
    );
    _ = try registry.registerHashed(
        allocator,
        "sol_invoke_signed_rust",
        stub,
    );

    // Memory Allocator
    if (!feature_set.active.contains(features.DISABLE_DEPLOY_OF_ALLOC_FREE_SYSCALL)) {
        _ = try registry.registerHashed(
            allocator,
            "sol_alloc_free_",
            stub,
        );
    }

    // Alt_bn128
    if (feature_set.active.contains(features.ENABLE_ALT_BN128_SYSCALL)) {
        _ = try registry.registerHashed(
            allocator,
            "sol_alt_bn128_group_op",
            stub,
        );
    }

    // Big_mod_exp
    if (feature_set.active.contains(features.ENABLE_BIG_MOD_EXP_SYSCALL)) {
        _ = try registry.registerHashed(
            allocator,
            "sol_big_mod_exp",
            stub,
        );
    }

    // Poseidon
    if (feature_set.active.contains(features.ENABLE_POSEIDON_SYSCALL)) {
        _ = try registry.registerHashed(
            allocator,
            "sol_poseidon",
            stub,
        );
    }

    // Remaining Compute Units
    if (feature_set.active.contains(features.REMAINING_COMPUTE_UNITS_SYSCALL_ENABLED)) {
        _ = try registry.registerHashed(
            allocator,
            "sol_remaining_compute_units",
            stub,
        );
    }

    // Alt_bn_128_compression
    if (feature_set.active.contains(features.ENABLE_ALT_BN128_COMPRESSION_SYSCALL)) {
        _ = try registry.registerHashed(
            allocator,
            "sol_alt_bn128_compression",
            stub,
        );
    }

    // Sysvar Getter
    if (feature_set.active.contains(features.GET_SYSVAR_SYSCALL_ENABLED)) {
        _ = try registry.registerHashed(
            allocator,
            "sol_get_sysvar",
            stub,
        );
    }

    // Get Epoch Stake
    if (feature_set.active.contains(features.ENABLE_GET_EPOCH_STAKE_SYSCALL)) {
        _ = try registry.registerHashed(
            allocator,
            "sol_get_epoch_stake",
            stub,
        );
    }

    return registry;
}
