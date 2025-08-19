const std = @import("std");
const sig = @import("../../../sig.zig");

const vm = sig.vm;
const serialize = sig.runtime.program.bpf.serialize;
const stable_log = sig.runtime.stable_log;

const ExecutionError = sig.vm.ExecutionError;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;
const TransactionContext = sig.runtime.TransactionContext;
const Registry = sig.vm.Registry;
const Syscall = sig.vm.syscalls.Syscall;

pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) ExecutionError!void {
    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1584-L1587
    const direct_mapping = ic.tc.feature_set.active(
        .bpf_account_data_direct_mapping,
        ic.tc.slot,
    );

    const executable = blk: {
        const program_account = try ic.borrowProgramAccount();
        defer program_account.release();

        const remove_accounts_executable_flag_checks = ic.tc.feature_set.active(
            .remove_accounts_executable_flag_checks,
            ic.tc.slot,
        );

        if (!remove_accounts_executable_flag_checks and
            !program_account.account.executable)
        {
            try ic.tc.log("Program is not executable", .{});
            return InstructionError.IncorrectProgramId;
        }

        const loaded_program = ic.tc.program_map.getPtr(program_account.pubkey) orelse {
            try ic.tc.log("Program is not cached", .{});
            if (remove_accounts_executable_flag_checks)
                return InstructionError.UnsupportedProgramId
            else
                return InstructionError.InvalidAccountData;
        };

        switch (loaded_program.*) {
            .failed => {
                try ic.tc.log("Program is not deployed", .{});
                if (remove_accounts_executable_flag_checks)
                    return InstructionError.UnsupportedProgramId
                else
                    return InstructionError.InvalidAccountData;
            },
            .loaded => |entry| {
                break :blk entry.executable;
            },
        }
    };

    const mask_out_rent_epoch_in_vm_serialization = ic.tc.feature_set.active(
        .bpf_account_data_direct_mapping,
        ic.tc.slot,
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
    const old_accounts = ic.tc.serialized_accounts;
    ic.tc.serialized_accounts = accounts_metadata;
    defer ic.tc.serialized_accounts = old_accounts;

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
            &ic.tc.vm_environment.loader,
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
            var execution_error = sig.vm.executionErrorFromStatusCode(status);
            switch (execution_error) {
                error.Custom => ic.tc.custom_error = @intCast(status),
                error.GenericError => {
                    ic.tc.custom_error = 0;
                    execution_error = error.Custom;
                },
                else => {},
            }
            maybe_execute_error = execution_error;
        },
        .err => |err| {
            const err_kind = sig.vm.getExecutionErrorKind(err);
            if (ic.tc.feature_set.active(
                .deplete_cu_meter_on_vm_failure,
                ic.tc.slot,
            ) and err_kind != .Syscall) {
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
    syscalls: *const Registry(Syscall),
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
