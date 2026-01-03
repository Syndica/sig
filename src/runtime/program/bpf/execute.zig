const std = @import("std");
const sig = @import("../../../sig.zig");

const vm = sig.vm;
const serialize = sig.runtime.program.bpf.serialize;
const stable_log = sig.runtime.stable_log;

const ExecutionError = sig.vm.ExecutionError;
const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;
const TransactionContext = sig.runtime.TransactionContext;
const SyscallMap = sig.vm.SyscallMap;
const Region = sig.vm.memory.Region;

pub fn execute(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) ExecutionError!void {
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

        const loaded_program = ic.tc.program_map.get(program_account.pubkey) orelse {
            try ic.tc.log("Program is not cached", .{});
            if (remove_accounts_executable_flag_checks)
                return InstructionError.UnsupportedProgramId
            else
                return InstructionError.InvalidAccountData;
        };

        switch (loaded_program) {
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

    const account_data_direct_mapping = ic.tc.feature_set.active(
        .account_data_direct_mapping,
        ic.tc.slot,
    );
    const stricter_abi_and_runtime_constraints = ic.tc.feature_set.active(
        .stricter_abi_and_runtime_constraints,
        ic.tc.slot,
    );
    const mask_out_rent_epoch_in_vm_serialization = ic.tc.feature_set.active(
        .mask_out_rent_epoch_in_vm_serialization,
        ic.tc.slot,
    );
    const provide_instruction_data_offset = ic.tc.feature_set.active(
        .provide_instruction_data_offset_in_vm_r2,
        ic.tc.slot,
    );

    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1588
    var serialized = try serialize.serializeParameters(
        allocator,
        ic,
        account_data_direct_mapping,
        stricter_abi_and_runtime_constraints,
        mask_out_rent_epoch_in_vm_serialization,
    );
    defer {
        serialized.memory.deinit(allocator);
        serialized.regions.deinit(allocator);
    }

    // TODO: this is a heavy copy, can we avoid doing it?
    // [agave] https://github.com/anza-xyz/agave/blob/v3.0/programs/bpf_loader/src/lib.rs#L275
    const old_accounts = ic.tc.serialized_accounts;
    ic.tc.serialized_accounts = serialized.account_metas;
    defer ic.tc.serialized_accounts = old_accounts;

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1604-L1617
    // TODO: save account addresses for access violation errors resolution

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1621-L1640
    const compute_available = ic.tc.compute_meter;
    const result, const compute_consumed = blk: {
        var state = initVm(
            allocator,
            ic.tc,
            &executable,
            serialized.regions.items,
            &ic.tc.vm_environment.loader,
            if (provide_instruction_data_offset) serialized.instruction_data_offset else 0,
        ) catch |err| {
            try ic.tc.log("Failed to create SBPF VM: {s}", .{@errorName(err)});
            return InstructionError.ProgramEnvironmentSetupFailure;
        };
        defer state.deinit(allocator);

        // Run our bpf program!
        const result = state.vm.run();

        break :blk result;
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
    var maybe_execute_error: ?ExecutionError = handleExecutionResult(
        result,
        &ic.tc.custom_error,
        &ic.tc.compute_meter,
        stricter_abi_and_runtime_constraints,
        ic.tc.feature_set.active(.deplete_cu_meter_on_vm_failure, ic.tc.slot),
    );

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1750-L1756
    if (maybe_execute_error == null)
        serialize.deserializeParameters(
            allocator,
            ic,
            stricter_abi_and_runtime_constraints,
            account_data_direct_mapping,
            serialized.memory.items,
            serialized.account_metas.constSlice(),
        ) catch |err| {
            maybe_execute_error = err;
        };

    // [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L1757-L1761
    // TODO: update timings

    if (maybe_execute_error) |err| return err;
}

const VmState = struct {
    vm: vm.Vm,
    stack: []u8,
    heap: []u8,
    regions: []Region,

    fn deinit(self: *VmState, allocator: std.mem.Allocator) void {
        self.vm.deinit();
        allocator.free(self.stack);
        allocator.free(self.heap);
        allocator.free(self.regions);
    }
};

// [agave] https://github.com/anza-xyz/agave/blob/a2af4430d278fcf694af7a2ea5ff64e8a1f5b05b/programs/bpf_loader/src/lib.rs#L299-L300
fn initVm(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
    executable: *const vm.Executable,
    trailing_regions: []const Region,
    syscalls: *const SyscallMap,
    instruction_data_offset: u64,
) !VmState {
    const PAGE_SIZE: u64 = 32 * 1024;

    const stack_size = executable.config.stackSize();
    const heap_size = tc.compute_budget.heap_size;
    const cost = std.mem.alignBackward(u64, heap_size -| 1, PAGE_SIZE) / PAGE_SIZE;
    const heap_cost = cost * tc.compute_budget.heap_cost;
    try tc.consumeCompute(heap_cost);

    const stack_gap: u64 = if (!executable.version.enableDynamicStackFrames() and
        executable.config.enable_stack_frame_gaps)
        executable.config.stack_frame_size
    else
        0;

    const heap = try allocator.alloc(u8, heap_size);
    @memset(heap, 0);
    errdefer allocator.free(heap);

    const stack = try allocator.alloc(u8, stack_size);
    @memset(stack, 0);
    errdefer allocator.free(stack);

    // 3 regions for the input, stack, and heap.
    const regions = try allocator.alloc(Region, 3 + trailing_regions.len);
    errdefer allocator.free(regions);

    regions[0..3].* = .{
        executable.getProgramRegion(),
        Region.initGapped(.mutable, stack, vm.memory.STACK_START, stack_gap),
        Region.init(.mutable, heap, vm.memory.HEAP_START),
    };
    @memcpy(regions[3..], trailing_regions);

    const memory_map = try vm.memory.MemoryMap.init(
        allocator,
        regions,
        executable.version,
        executable.config,
    );
    errdefer memory_map.deinit(allocator);

    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L280-L285
    // TODO: Set syscall context

    const sbpf_vm = try vm.Vm.init(
        allocator,
        executable,
        memory_map,
        syscalls,
        stack.len,
        instruction_data_offset,
        tc,
    );

    return .{
        .vm = sbpf_vm,
        .stack = stack,
        .heap = heap,
        .regions = regions,
    };
}

fn handleExecutionResult(
    result: sig.vm.interpreter.Result,
    custom_error: *?u32,
    compute_meter: *u64,
    stricter_abi_and_runtime_constraints: bool,
    deplete_cu_meter: bool,
) ?ExecutionError {
    switch (result) {
        .ok => |status| if (status != 0) {
            switch (sig.vm.executionErrorFromStatusCode(status)) {
                error.Custom => custom_error.* = @intCast(status),
                error.GenericError => custom_error.* = 0,
                else => |err| return err,
            }
            return error.Custom;
        },
        .err => |err| {
            const err_kind = sig.vm.getExecutionErrorKind(err);
            if (deplete_cu_meter and err_kind != .Syscall)
                compute_meter.* = 0;
            if (stricter_abi_and_runtime_constraints and err == error.AccessViolation)
                std.debug.print("TODO: Handle AccessViolation: {s}\n", .{@errorName(err)});
            return err;
        },
    }
    return null;
}

test handleExecutionResult {
    var custom_error: ?u32 = null;
    var compute_meter: u64 = 1000;

    // No Error
    try std.testing.expectEqual(null, handleExecutionResult(
        .{ .ok = 0 },
        &custom_error,
        &compute_meter,
        false,
        false,
    ));
    try std.testing.expectEqual(null, custom_error);
    try std.testing.expectEqual(1000, compute_meter);

    // Generic Error maps to Custom error with code 0
    try std.testing.expectEqual(error.Custom, handleExecutionResult(
        .{ .ok = 0x100000000 },
        &custom_error,
        &compute_meter,
        false,
        false,
    ).?);
    try std.testing.expectEqual(0, custom_error.?);
    try std.testing.expectEqual(1000, compute_meter);

    // Custom error with specific code
    custom_error = null;
    try std.testing.expectEqual(error.Custom, handleExecutionResult(
        .{ .ok = 101 },
        &custom_error,
        &compute_meter,
        false,
        false,
    ).?);
    try std.testing.expectEqual(101, custom_error.?);
    try std.testing.expectEqual(1000, compute_meter);

    // Deplete compute meter on non-syscall error
    custom_error = null;
    try std.testing.expectEqual(error.InvalidArgument, handleExecutionResult(
        .{ .err = error.InvalidArgument },
        &custom_error,
        &compute_meter,
        false,
        true,
    ).?);
    try std.testing.expectEqual(null, custom_error);
    try std.testing.expectEqual(0, compute_meter);

    // TODO: Handle AccessViolation
}
