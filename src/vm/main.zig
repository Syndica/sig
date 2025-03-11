const std = @import("std");
const sig = @import("sig");
const builtin = @import("builtin");

const vm = sig.vm;
const Elf = vm.Elf;
const memory = vm.memory;
const Executable = vm.Executable;
const Vm = vm.Vm;
const sbpf = vm.sbpf;
const syscalls = vm.syscalls;
const Config = vm.Config;

const MemoryMap = memory.MemoryMap;

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 100 }) = .{};
    defer _ = gpa.deinit();
    const allocator = if (builtin.mode == .Debug)
        gpa.allocator()
    else
        std.heap.c_allocator;

    var std_logger = sig.trace.DirectPrintLogger.init(allocator, .debug);
    const logger = std_logger.logger();

    var input_path: ?[]const u8 = null;
    var assemble: bool = false;
    var version: sbpf.Version = .v3;

    var args = try std.process.argsWithAllocator(allocator);
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-a")) {
            assemble = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-v")) {
            const version_string = args.next() orelse fail("provide SBPF version", .{});
            version = std.meta.stringToEnum(sbpf.Version, version_string) orelse
                fail("invalid SBPF version", .{});
            continue;
        }

        if (input_path) |file| {
            fail("input file already given: {s}", .{file});
        } else {
            input_path = arg;
        }
    }
    if (input_path == null) {
        fail("no input file provided", .{});
    }

    const input_file = try std.fs.cwd().openFile(input_path.?, .{});
    defer input_file.close();

    const bytes = try input_file.readToEndAlloc(allocator, sbpf.MAX_FILE_SIZE);
    defer allocator.free(bytes);

    var loader: vm.BuiltinProgram = .{};
    defer loader.deinit(allocator);

    inline for (.{
        .{ "log", syscalls.log },
        .{ "sol_log_64_", syscalls.log64 },
        .{ "sol_log_pubkey", syscalls.logPubkey },
        .{ "sol_log_compute_units_", syscalls.logComputeUnits },
        .{ "sol_memset_", syscalls.memset },
        .{ "sol_memcpy_", syscalls.memcpy },
        .{ "sol_memcmp_", syscalls.memcmp },
        .{ "sol_poseidon", syscalls.poseidon },
        .{ "sol_panic_", syscalls.panic },
        .{ "abort", syscalls.abort },
    }) |entry| {
        const name, const function = entry;
        _ = try loader.functions.registerHashed(
            allocator,
            name,
            function,
        );
    }

    const config: Config = .{
        .maximum_version = version,
        .enable_symbol_and_section_labels = false,
        .optimize_rodata = false,
    };
    var executable = if (assemble)
        try Executable.fromAsm(allocator, bytes, config)
    else exec: {
        const elf = try Elf.parse(allocator, bytes, &loader, config);
        break :exec Executable.fromElf(elf);
    };
    defer executable.deinit(allocator);

    try executable.verify(&loader);

    const heap_mem = try allocator.alloc(u8, 0x40000);
    defer allocator.free(heap_mem);
    @memset(heap_mem, 0x00);

    const stack_memory = try allocator.alloc(u8, config.stackSize());
    defer allocator.free(stack_memory);
    @memset(stack_memory, 0);

    const m = try MemoryMap.init(&.{
        executable.getProgramRegion(),
        memory.Region.init(.mutable, stack_memory, memory.STACK_START),
        memory.Region.init(.mutable, heap_mem, memory.HEAP_START),
        memory.Region.init(.mutable, &.{}, memory.INPUT_START),
    }, executable.version);

    var vm = try Vm.init(
        allocator,
        &executable,
        m,
        &loader,
        logger,
        stack_memory.len,
    );
    defer vm.deinit();
    const result = try vm.run();

    std.debug.print("result: {}, count: {}\n", .{ result, vm.instruction_count });
}

fn fail(comptime fmt: []const u8, args: anytype) noreturn {
    const stderr = std.io.getStdErr().writer();
    stderr.print(fmt ++ "\n", args) catch @panic("failed to print the stderr");
    std.posix.abort();
}
