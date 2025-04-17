const std = @import("std");
const sig = @import("../../../sig.zig");

const vm = sig.vm;
const features = sig.runtime.features;
const serialize = sig.runtime.program.bpf.serialize;
const stable_log = sig.runtime.stable_log;

const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;
const TransactionContext = sig.runtime.TransactionContext;

pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1584-L1587
    const direct_mapping = ic.ec.feature_set.active.contains(
        features.BPF_ACCOUNT_DATA_DIRECT_MAPPING,
    );

    var executable, var syscalls, const source = blk: {
        const program_account = try ic.borrowProgramAccount();
        defer program_account.release();

        // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L434
        if (!ic.ec.feature_set.active.contains(
            features.REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS,
        ) and
            !program_account.account.executable)
        {
            try ic.tc.log("Program is not executable", .{});
            return InstructionError.IncorrectProgramId;
        }

        // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L124-L131
        var syscalls = vm.syscalls.register(
            allocator,
            &ic.tc.sc.ec.feature_set,
            0,
            false,
        ) catch |err| {
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
            .{
                .enable_stack_frame_gaps = !direct_mapping,
                .aligned_memory_mapping = !direct_mapping,
            },
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
        ic.ixn_info.program_meta.pubkey,
        compute_consumed,
        compute_available,
    });

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1653-L1657
    if (ic.tc.return_data.data.len != 0) {
        try stable_log.programReturn(
            ic.tc,
            ic.ixn_info.program_meta.pubkey,
            ic.tc.return_data.data.constSlice(),
        );
    }

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1658-L1731
    const execute_error: ?InstructionError = blk: {
        switch (result) {
            .ok => |status| if (status != 0) {
                // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1642-L1645
                std.debug.print(
                    "Program {} failed: {}\n",
                    .{ ic.ixn_info.program_meta.pubkey, status },
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
pub fn initVm(
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
        allocator,
        mm_regions,
        executable.version,
        executable.config,
    );
    errdefer memory_map.deinit(allocator);

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

    return .{
        sbpf_vm,
        stack,
        heap,
        mm_regions,
    };
}
