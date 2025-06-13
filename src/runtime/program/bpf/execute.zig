const std = @import("std");
const sig = @import("../../../sig.zig");

const vm = sig.vm;
const features = sig.runtime.features;
const serialize = sig.runtime.program.bpf.serialize;
const stable_log = sig.runtime.stable_log;

const ExecutionError = sig.vm.ExecutionError;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;
const TransactionContext = sig.runtime.TransactionContext;

pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) ExecutionError!void {

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1584-L1587
    const direct_mapping = ic.tc.feature_set.active.contains(
        features.BPF_ACCOUNT_DATA_DIRECT_MAPPING,
    );

    var executable, var syscalls, const source = blk: {
        const program_account = try ic.borrowProgramAccount();
        defer program_account.release();

        const feature_set = &ic.tc.feature_set.active;

        // [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/programs/bpf_loader/src/lib.rs#L434
        if (!feature_set.contains(
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
            ic.tc.feature_set,
            false,
        ) catch |err| {
            try ic.tc.log("Failed to register syscalls: {s}", .{@errorName(err)});
            return InstructionError.ProgramEnvironmentSetupFailure;
        };
        errdefer syscalls.deinit(allocator);

        // [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/syscalls/mod.rs#L357-L374
        const min_sbpf_version: vm.sbpf.Version = if (!feature_set.contains(
            features.DISABLE_SBPF_V0_EXECUTION,
        ) or feature_set.contains(
            features.REENABLE_SBPF_V0_EXECUTION,
        )) .v0 else .v3;

        const max_sbpf_version: vm.sbpf.Version = if (feature_set.contains(
            features.ENABLE_SBPF_V3_DEPLOYMENT_AND_EXECUTION,
        )) .v3 else if (feature_set.contains(
            features.ENABLE_SBPF_V2_DEPLOYMENT_AND_EXECUTION,
        )) .v2 else if (feature_set.contains(
            features.ENABLE_SBPF_V1_DEPLOYMENT_AND_EXECUTION,
        )) .v1 else .v0;

        std.debug.assert(max_sbpf_version.gte(min_sbpf_version));

        // Clone required to prevent modification of underlying account elf
        const source = try allocator.dupe(u8, program_account.account.data);
        errdefer allocator.free(source);

        // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L133-L143
        const executable = vm.Executable.fromBytes(
            allocator,
            source,
            &syscalls,
            .{
                .max_call_depth = ic.tc.compute_budget.max_call_depth,
                .stack_frame_size = ic.tc.compute_budget.stack_frame_size,
                .enable_address_translation = true,
                .enable_stack_frame_gaps = !direct_mapping,
                .aligned_memory_mapping = !direct_mapping,
                .minimum_version = min_sbpf_version,
                .maximum_version = max_sbpf_version,
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

    const mask_out_rent_epoch_in_vm_serialization = ic.tc.feature_set.active.contains(
        features.BPF_ACCOUNT_DATA_DIRECT_MAPPING,
    );

    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1588
    var parameter_bytes, //
    var regions, //
    const accounts_metadata = try serialize.serializeParameters(
        allocator,
        ic,
        !direct_mapping,
        mask_out_rent_epoch_in_vm_serialization,
    );
    defer {
        parameter_bytes.deinit(allocator);
        regions.deinit(allocator);
    }

    // [agave] https://github.com/anza-xyz/agave/blob/a11b42a73288ab5985009e21ffd48e79f8ad6c58/programs/bpf_loader/src/lib.rs#L278-L282
    ic.tc.serialized_accounts = accounts_metadata;

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1604-L1617
    // TODO: save account addresses for access violation errors resolution

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1621-L1640
    const compute_available = ic.tc.compute_meter;
    const result, const compute_consumed = blk: {
        var sbpf_vm, const stack, const heap, const mm_regions = initVm(
            allocator,
            ic.tc,
            &executable,
            regions.items,
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
    var maybe_execute_error: ?ExecutionError = null;
    switch (result) {
        // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1642-L1645
        .ok => |status| if (status != 0) {
            maybe_execute_error = sig.vm.executionErrorFromStatusCode(status);
        },
        .err => |err| {
            const err_kind = sig.vm.getExecutionErrorKind(err);
            if (ic.tc.feature_set.active.contains(features.DEPLETE_CU_METER_ON_VM_FAILURE) and
                err_kind != .Syscall)
            {
                ic.tc.compute_meter = 0;
            }

            if (direct_mapping and err == error.AccessViolation) {
                std.debug.print("TODO: Handle AccessViolation: {s}\n", .{@errorName(err)});
            }

            maybe_execute_error = err;
        },
    }

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1750-L1756
    if (maybe_execute_error == null)
        serialize.deserializeParameters(
            allocator,
            ic,
            !direct_mapping,
            parameter_bytes.items,
            accounts_metadata.constSlice(),
        ) catch |err| {
            maybe_execute_error = err;
        };

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1757-L1761
    // TODO: update timings

    if (maybe_execute_error) |err| return err;
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
    const stack_gap: u64 = if (!executable.version.enableDynamicStackFrames() and
        executable.config.enable_stack_frame_gaps)
        executable.config.stack_frame_size
    else
        0;
    try mm_regions_array.appendSlice(&.{
        executable.getProgramRegion(),
        vm.memory.Region.initGapped(.mutable, stack, vm.memory.STACK_START, stack_gap),
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
