const std = @import("std");
const sig = @import("../../sig.zig");

const vm = sig.vm;
const serialization = sig.runtime.program.serialization;

const InstructionError = sig.core.instruction.InstructionError;
const InstructionContext = sig.runtime.InstructionContext;
const TransactionContext = sig.runtime.TransactionContext;

fn executeBpfProgram(
    allocator: std.mem.Allocator,
    ic: *InstructionContext,
) (error{OutOfMemory} || InstructionError)!void {
    const program_account = try ic.borrowProgramAccount();
    errdefer program_account.release();
    const copy_account_data = true;

    // Check program is executable
    if (!program_account.account.executable) {
        try ic.tc.log("Program is not executable", .{});
        return InstructionError.IncorrectProgramId;
    }

    // Create Syscalls
    var syscalls = vm.BuiltinProgram{};
    defer syscalls.deinit(allocator);
    _ = syscalls.functions.registerHashed(allocator, "log", vm.syscalls.log) catch {
        return InstructionError.ProgramEnvironmentSetupFailure;
    };

    // Parse ELF and create executable
    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L136-L144
    var executable = vm.Executable.fromBytes(
        allocator,
        program_account.account.data,
        &syscalls,
        .{},
    ) catch |err| {
        try ic.tc.log("{}", .{err});
        return InstructionError.InvalidAccountData;
    };
    defer executable.deinit(allocator);

    program_account.release();

    // Serialize parameters
    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1588
    const parameter_bytes, const regions, const accounts_metadata = try serialization.serializeParameters(
        allocator,
        ic,
        copy_account_data,
    );
    defer {
        allocator.free(parameter_bytes);
        allocator.free(regions);
        allocator.free(accounts_metadata);
    }

    // [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/programs/bpf_loader/src/lib.rs#L1614-L1622
    var sbpf_vm, const stack, const heap = initVm(
        allocator,
        ic.tc,
        executable,
        regions,
        syscalls,
    ) catch |err| {
        try ic.tc.log("Failed to create SBPF VM: {}", .{err});
        return InstructionError.ProgramEnvironmentSetupFailure;
    };
    defer sbpf_vm.deinit();
    defer allocator.free(stack);
    defer allocator.free(heap);

    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1625-L1638
    const result, const compute_consumed = sbpf_vm.run();

    const logs = ic.tc.log_collector.?.collect();

    std.debug.print("result: {}\n", .{result});
    std.debug.print("compute_consumed: {}\n", .{compute_consumed});
    std.debug.print("logs:\n", .{});
    for (logs) |log| {
        std.debug.print("\t{s}\n", .{log});
    }

    // [agave] https://github.com/anza-xyz/agave/blob/01e50dc39bde9a37a9f15d64069459fe7502ec3e/programs/bpf_loader/src/lib.rs#L1744
    try serialization.deserializeParameters(
        allocator,
        ic,
        copy_account_data,
        parameter_bytes,
        accounts_metadata,
    );
}

fn initVm(
    allocator: std.mem.Allocator,
    tc: *TransactionContext,
    executable: vm.Executable,
    regions: []vm.memory.Region,
    syscalls: vm.BuiltinProgram,
) !struct {
    vm.Vm,
    []u8,
    []u8,
} {
    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L1615-L1623
    const PAGE_SIZE: u64 = 32 * 1024;

    const stack_size = executable.config.stackSize();
    const heap_size = 10; // ic.tc.compute_budget.heap_size;
    const cost = std.mem.alignBackward(u64, heap_size -| 1, PAGE_SIZE) / PAGE_SIZE;
    const heap_cost = cost * 10; // ic.tc.compute_budget.heap_cost;
    try tc.consumeCompute(heap_cost);

    const heap = try allocator.alloc(u8, heap_size);
    @memset(heap, 0);
    errdefer allocator.free(heap);

    const stack = try allocator.alloc(u8, stack_size);
    @memset(stack, 0);
    errdefer allocator.free(stack);

    // TODO: Create memory map
    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L256-L280
    std.debug.assert(regions.len == 1);

    const memory_map = try vm.memory.MemoryMap.init(
        &[_]vm.memory.Region{
            executable.getProgramRegion(),
            vm.memory.Region.init(.mutable, stack, vm.memory.STACK_START),
            vm.memory.Region.init(.mutable, heap, vm.memory.HEAP_START),
            regions[0],
        },
        executable.version,
    );

    // TODO: Set syscall context
    // [agave] https://github.com/anza-xyz/agave/blob/32ac530151de63329f9ceb97dd23abfcee28f1d4/programs/bpf_loader/src/lib.rs#L280-L285

    // Create VM
    const sbpf_vm = try vm.Vm.init(
        allocator,
        &executable,
        memory_map,
        &syscalls,
        stack.len,
        tc,
    );
    errdefer sbpf_vm.deinit();

    return .{
        sbpf_vm,
        stack,
        heap,
    };
}

test "testBpfProgramExecution" {
    const sbpf = sig.vm.sbpf;

    const Pubkey = sig.core.Pubkey;
    const LogCollector = sig.runtime.LogCollector;

    const createTransactionContext = sig.runtime.testing.createTransactionContext;
    const createInstructionInfo = sig.runtime.testing.createInstructionInfo;

    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    const program_id = Pubkey.initRandom(prng.random());
    const input_file = try std.fs.cwd().openFile(sig.ELF_DATA_DIR ++ "syscall_static.so", .{});
    const bytes = try input_file.readToEndAlloc(allocator, sbpf.MAX_FILE_SIZE);
    defer allocator.free(bytes);

    var tc = try createTransactionContext(allocator, prng.random(), .{
        .accounts = &.{
            .{
                .pubkey = program_id,
                .lamports = 1_000_000_000,
                .owner = sig.runtime.ids.BPF_LOADER_V3_PROGRAM_ID,
                .executable = true,
                .rent_epoch = 0,
                .data = bytes,
            },
        },
        .log_collector = LogCollector.init(allocator, null),
        .compute_meter = 1_000,
    });
    defer tc.deinit(allocator);

    const instruction_info = try createInstructionInfo(
        allocator,
        &tc,
        program_id,
        [_]u8{},
        &.{.{
            .index_in_transaction = 0,
            .is_signer = false,
            .is_writable = false,
        }},
    );

    var ic = InstructionContext{
        .tc = &tc,
        .info = instruction_info,
        .depth = 0,
    };

    try executeBpfProgram(allocator, &ic);
}
