const std = @import("std");
const sig = @import("../../../sig.zig");

const vm = sig.vm;
const feature_set = sig.runtime.feature_set;
const serialize = sig.runtime.program.bpf.serialize;
const stable_log = sig.runtime.stable_log;

const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;
const TransactionContext = sig.runtime.TransactionContext;

pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    var executable, var syscalls, const source = blk: {
        const program_account = try ic.borrowProgramAccount();
        defer program_account.release();

        // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L434
        if (!ic.tc.feature_set.active.contains(
            feature_set.REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS,
        ) and
            !program_account.account.executable)
        {
            try ic.tc.log("Program is not executable", .{});
            return InstructionError.IncorrectProgramId;
        }

        // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L124-L131
        var syscalls = registerSyscalls(allocator, ic.tc) catch |err| {
            try ic.tc.log("Failed to register syscalls: {s}", .{@errorName(err)});
            return InstructionError.ProgramEnvironmentSetupFailure;
        };
        errdefer syscalls.deinit(allocator);

        // Clone required to prevent modification of underlying account elf
        const source = try allocator.dupe(u8, program_account.account.data);
        errdefer allocator.free(source);

        // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L133-L143
        const executable = vm.Executable.fromBytes(
            allocator,
            source,
            &syscalls,
            .{},
        ) catch |err| {
            try ic.tc.log("{s}", .{@errorName(err)});
            return InstructionError.InvalidAccountData;
        };
        break :blk .{ executable, syscalls, source };
    };
    defer {
        executable.deinit(allocator);
        syscalls.deinit(allocator);
        allocator.free(source);
    }

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1583-L1584
    // TODO: jit

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1584-L1587
    const direct_mapping = ic.tc.feature_set.active.contains(
        feature_set.BPF_ACCOUNT_DATA_DIRECT_MAPPING,
    );

    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1588
    const parameter_bytes, const regions, const accounts_metadata =
        try serialize.serializeParameters(
        allocator,
        ic,
        !direct_mapping,
    );
    defer {
        allocator.free(parameter_bytes);
        allocator.free(regions);
        allocator.free(accounts_metadata);
    }

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1604-L1617
    // TODO: save account addresses for access violation errors resolution

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1621-L1640
    const compute_available = ic.tc.compute_meter;
    const result, const compute_consumed = blk: {
        var sbpf_vm, const stack, const heap, const mm_regions = initVm(
            allocator,
            ic.tc,
            &executable,
            regions,
            &syscalls,
        ) catch |err| {
            try ic.tc.log("Failed to create SBPF VM: {s}", .{@errorName(err)});
            return InstructionError.ProgramEnvironmentSetupFailure;
        };
        defer {
            sbpf_vm.deinit();
            allocator.free(stack);
            allocator.free(heap);
            allocator.free(mm_regions);
        }
        break :blk sbpf_vm.run();
    };

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1641-L1644
    // TODO: timings

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1646-L1653
    try ic.tc.log("Program {} consumed {} of {} compute units", .{
        ic.info.program_meta.pubkey,
        compute_consumed,
        compute_available,
    });

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1653-L1657
    const return_data = ic.tc.getReturnData();
    if (return_data.data.items.len != 0) {
        try stable_log.programReturn(
            allocator,
            &ic.tc.log_collector,
            ic.info.program_meta.pubkey,
            return_data.data.items,
        );
    }

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1658-L1731
    const execute_error: ?InstructionError = blk: {
        switch (result) {
            .ok => |status| if (status != 0) {
                // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1659-L1663
                std.debug.print(
                    "Program {} failed: {}\n",
                    .{ ic.info.program_meta.pubkey, status },
                );
                @panic("sbpf error handling not implemented!");
            } else {
                break :blk null;
            },
            .err => |sbpf_err| {
                // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1663-L1730
                std.debug.print("Sbpf error: {}\n", .{sbpf_err});
                @panic("sbpf error handling not implemented!");
            },
        }
    };

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1750-L1756
    const execute_or_deserialize_error = if (execute_error == null)
        serialize.deserializeParameters(
            allocator,
            ic,
            !direct_mapping,
            parameter_bytes,
            accounts_metadata,
        )
    else
        execute_error;

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1757-L1761
    // TODO: update timings

    return execute_or_deserialize_error;
}

// [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L299-L300
fn initVm(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
    executable: *const vm.Executable,
    regions: []vm.memory.Region,
    syscalls: *const vm.BuiltinProgram,
) !struct {
    vm.Vm,
    []u8,
    []u8,
    []vm.memory.Region,
} {
    const PAGE_SIZE: u64 = 32 * 1024;

    const stack_size = executable.config.stackSize();
    const heap_size = tc.compute_budget.heap_size;
    const cost = std.mem.alignBackward(u64, heap_size -| 1, PAGE_SIZE) / PAGE_SIZE;
    const heap_cost = cost * tc.compute_budget.heap_cost;
    try tc.consumeCompute(heap_cost);

    const heap = try allocator.alloc(u8, heap_size);
    @memset(heap, 0);
    errdefer allocator.free(heap);

    const stack = try allocator.alloc(u8, stack_size);
    @memset(stack, 0);
    errdefer allocator.free(stack);

    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L256-L280
    var mm_regions_array = std.ArrayList(vm.memory.Region).init(allocator);
    errdefer mm_regions_array.deinit();
    try mm_regions_array.appendSlice(&.{
        executable.getProgramRegion(),
        vm.memory.Region.init(.mutable, stack, vm.memory.STACK_START),
        vm.memory.Region.init(.mutable, heap, vm.memory.HEAP_START),
    });
    try mm_regions_array.appendSlice(regions);
    const mm_regions = try mm_regions_array.toOwnedSlice();
    const memory_map = try vm.memory.MemoryMap.init(
        mm_regions,
        executable.version,
    );

    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L280-L285
    // TODO: Set syscall context

    // Create VM
    const sbpf_vm = try vm.Vm.init(
        allocator,
        executable,
        memory_map,
        syscalls,
        stack.len,
        tc,
    );
    errdefer sbpf_vm.deinit();

    return .{
        sbpf_vm,
        stack,
        heap,
        mm_regions,
    };
}

// [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/syscalls/mod.rs#L335
fn registerSyscalls(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
) !vm.BuiltinProgram {
    // TODO: Feature Activation
    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/syscalls/mod.rs#L341-L374

    // Register syscalls
    var syscalls = vm.BuiltinProgram{};
    errdefer syscalls.deinit(allocator);

    // Abort
    _ = try syscalls.functions.registerHashed(
        allocator,
        "abort",
        vm.syscalls.abort,
    );

    // Panic
    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_panic_",
        vm.syscalls.panic,
    );

    // Logging
    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_log_",
        vm.syscalls.log,
    );
    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_log_64_",
        vm.syscalls.log64,
    );
    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_log_pubkey",
        vm.syscalls.logPubkey,
    );
    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_log_compute_units_",
        vm.syscalls.logComputeUnits,
    );

    // Program derived addresses
    // _ = try syscalls.functions.registerHashed(allocator, "sol_create_program_address", vm.syscalls.createProgramAddress,);
    // _ = try syscalls.functions.registerHashed(allocator, "sol_try_find_program_address", vm.syscalls.createProgramAddress,);

    // Sha256, Keccak256, Secp256k1Recover
    // _ = try syscalls.functions.registerHashed(allocator, "sol_sha256", vm.syscalls.sha256,);
    // _ = try syscalls.functions.registerHashed(allocator, "sol_keccak256", vm.syscalls.keccak256,);
    // _ = try syscalls.functions.registerHashed(allocator, "sol_secp256k1_recover", vm.syscalls.secp256k1Recover,);

    // Blake3
    // if (tc.feature_set.active.contains(feature_set.BLAKE3_SYSCALL_ENABLED)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_blake3", vm.syscalls.blake3,);
    // }

    // Elliptic Curve
    // if (tc.feature_set.active.contains(feature_set.CURVE25519_SYSCALL_ENABLED)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_curve_validate_point", vm.syscalls.curveValidatePoint,);
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_curve_group_op", vm.syscalls.curveGroupOp,);
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_curve_multiscalar_mul", vm.syscalls.curveMultiscalarMul,);
    // }

    // Sysvars
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_clock_sysvar", vm.syscalls.getClockSysvar,);
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_epoch_schedule_sysvar", vm.syscalls.getEpochScheduleSysvar,);
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_fees_sysvar", vm.syscalls.getFeesSysvar,);
    // if (!tc.feature_set.active.contains(feature_set.DISABLE_FEES_SYSVAR)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_get_fees_sysvar", vm.syscalls.getFeesSysvar,);
    // }
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_rent_sysvar", vm.syscalls.getRentSysvar,);
    // if (tc.feature_set.active.contains(feature_set.LAST_RESTART_SLOT_SYSVAR)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_get_last_restart_slot", vm.syscalls.getLastRestartSlotSysvar,);
    // }
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_epoch_rewards_sysvar", vm.syscalls.getEpochRewardsSysvar,);

    // Memory
    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_memcpy_",
        vm.syscalls.memcpy,
    );
    // _ = try syscalls.functions.registerHashed(allocator, "sol_memmove_", vm.syscalls.memmove,);
    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_memset_",
        vm.syscalls.memset,
    );
    _ = try syscalls.functions.registerHashed(
        allocator,
        "sol_memcmp_",
        vm.syscalls.memcmp,
    );

    // Processed Sibling
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_processed_sibling_instruction", vm.syscalls.getProcessedSiblingInstruction,);

    // Stack Height
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_stack_height", vm.syscalls.getStackHeight,);

    // Return Data
    // _ = try syscalls.functions.registerHashed(allocator, "sol_set_return_data", vm.syscalls.setReturnData,);
    // _ = try syscalls.functions.registerHashed(allocator, "sol_get_return_data", vm.syscalls.getReturnData,);

    // Cross Program Invocation
    // _ = try syscalls.functions.registerHashed(allocator, "sol_invoke_signed_c", vm.syscalls.invokeSignedC,);
    // _ = try syscalls.functions.registerHashed(allocator, "sol_invoke_signed_rust", vm.syscalls.invokeSignedRust,);

    // Memory Allocator
    if (!tc.feature_set.active.contains(feature_set.DISABLE_DEPLOY_OF_ALLOC_FREE_SYSCALL)) {
        _ = try syscalls.functions.registerHashed(
            allocator,
            "sol_alloc_free_",
            vm.syscalls.allocFree,
        );
    }

    // Alt_bn128
    // if (tc.feature_set.active.contains(feature_set.ENABLE_ALT_BN128_SYSCALL)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_alt_bn128_group_op", vm.syscalls.altBn128GroupOp,);
    // }

    // Big_mod_exp
    // if (tc.feature_set.active.contains(feature_set.ENABLE_BIG_MOD_EXP_SYSCALL)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_big_mod_exp", vm.syscalls.bigModExp,);
    // }

    // Poseidon
    if (tc.feature_set.active.contains(feature_set.ENABLE_POSEIDON_SYSCALL)) {
        _ = try syscalls.functions.registerHashed(
            allocator,
            "sol_poseidon",
            vm.syscalls.poseidon,
        );
    }

    // Remaining Compute Units
    // if (tc.feature_set.active.contains(feature_set.ENABLE_REMAINING_COMPUTE_UNITS_SYSCALL)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_remaining_compute_units", vm.syscalls.remainingComputeUnits,);
    // }

    // Alt_bn_128_compression
    // if (tc.feature_set.active.contains(feature_set.ENABLE_ALT_BN_128_COMPRESSION_SYSCALL)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_alt_bn_128_compression", vm.syscalls.altBn128Compression,);
    // }

    // Sysvar Getter
    // if (tc.feature_set.active.contains(feature_set.ENABLE_SYSVAR_SYSCALL)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_get_sysvar", vm.syscalls.getSysvar,);
    // }

    // Get Epoch Stake
    // if (tc.feature_set.active.contains(feature_set.ENABLE_GET_EPOCH_STAKE_SYSCALL)) {
    //     _ = try syscalls.functions.registerHashed(allocator, "sol_get_epoch_stake", vm.syscalls.getEpochStake,);
    // }

    // Log Data
    // _ = try syscalls.functions.registerHashed(allocator, "sol_log_data", vm.syscalls.logData,);

    return syscalls;
}
