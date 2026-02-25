const std = @import("std");
const sig = @import("sig");
const builtin = @import("builtin");
const cli = @import("cli");

const vm = sig.vm;

const elf = sig.vm.elf;
const memory = sig.vm.memory;
const Executable = sig.vm.Executable;
const Vm = sig.vm.Vm;
const sbpf = sig.vm.sbpf;
const Config = sig.vm.Config;
const MemoryMap = memory.MemoryMap;
const TransactionContext = sig.runtime.TransactionContext;
const FeatureSet = sig.core.FeatureSet;
const Hash = sig.core.Hash;
const EpochStakes = sig.core.EpochStakes;
const SysvarCache = sig.runtime.SysvarCache;
const ProgramMap = sig.runtime.program_loader.ProgramMap;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = if (builtin.mode == .Debug) gpa_state.allocator() else std.heap.smp_allocator;

    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);

    const parser = cli.Parser(Cmd, Cmd.cmd_info);
    const cmd = try parser.parse(
        gpa,
        "vm",
        std.io.tty.detectConfig(.stdout()),
        std.fs.File.stdout().deprecatedWriter(),
        argv[1..],
    ) orelse return;
    defer parser.free(gpa, cmd);
    if (cmd.input_path == null) @panic("no input file provided");

    const input_file = try std.fs.cwd().openFile(cmd.input_path.?, .{});
    defer input_file.close();

    const bytes = try input_file.readToEndAlloc(gpa, sbpf.MAX_FILE_SIZE);
    defer gpa.free(bytes);

    const epoch_stakes: EpochStakes = .EMPTY_WITH_GENESIS;
    defer epoch_stakes.deinit(gpa);

    var program_map = ProgramMap.empty;
    defer program_map.deinit(gpa);

    var tc: TransactionContext = .{
        .allocator = gpa,
        .programs_allocator = gpa,
        .feature_set = &FeatureSet.ALL_DISABLED,
        .epoch_stakes = &epoch_stakes,
        .sysvar_cache = &SysvarCache{},
        .vm_environment = &.{
            .loader = .ALL_ENABLED,
            .config = .{},
        },
        .program_map = &program_map,
        .next_vm_environment = null,
        .accounts = &.{},
        .serialized_accounts = .{},
        .instruction_stack = .{},
        .instruction_trace = .{},
        .accounts_resize_delta = 0,
        .return_data = .{},
        .custom_error = null,
        .rent = .INIT,
        .log_collector = null,
        .compute_meter = cmd.limit,
        .prev_blockhash = Hash.ZEROES,
        .prev_lamports_per_signature = 0,
        .compute_budget = .DEFAULT,
        .slot = 0,
    };
    defer tc.deinit();

    var loader = sig.vm.Environment.initV1Loader(&.ALL_DISABLED, 0, true);

    const config: Config = .{
        .maximum_version = cmd.version,
        .optimize_rodata = false,
    };
    var executable = if (cmd.assemble)
        try Executable.fromAsm(gpa, bytes, config)
    else
        try elf.load(gpa, bytes, &loader, config);
    defer executable.deinit(gpa);

    try executable.verify(&loader);

    const heap_mem = try gpa.alloc(u8, 0x40000);
    defer gpa.free(heap_mem);
    @memset(heap_mem, 0x00);

    const stack_memory = try gpa.alloc(u8, config.stackSize());
    defer gpa.free(stack_memory);
    @memset(stack_memory, 0);

    const m = try MemoryMap.init(
        gpa,
        &.{
            executable.getProgramRegion(),
            memory.Region.init(.mutable, stack_memory, memory.STACK_START),
            memory.Region.init(.mutable, heap_mem, memory.HEAP_START),
            memory.Region.init(.mutable, &.{}, memory.INPUT_START),
        },
        executable.version,
        config,
    );

    var ebpf_vm = try Vm.init(
        gpa,
        &executable,
        m,
        &loader,
        stack_memory.len,
        0,
        &tc,
    );
    defer ebpf_vm.deinit();
    const result, const instruction_count = ebpf_vm.run();

    std.debug.print("result: {}, count: {}\n", .{ result, instruction_count });
}

const Cmd = struct {
    input_path: ?[]const u8,
    assemble: bool,
    version: sbpf.Version,
    limit: u64,

    const cmd_info: cli.CommandInfo(@This()) = .{
        .help = .{
            .short = "Runs sBPF programs from ELF files or assembly",
            .long = null,
        },
        .sub = .{
            .input_path = .{
                .kind = .positional,
                .name_override = "input",
                .alias = .none,
                .default_value = null,
                .config = .string,
                .help = "input file path",
            },
            .assemble = .{
                .kind = .named,
                .name_override = null,
                .alias = .a,
                .default_value = false,
                .config = {},
                .help = "whether the input file is an assembly file",
            },
            .version = .{
                .kind = .named,
                .name_override = null,
                .alias = .v,
                .default_value = .v2,
                .config = {},
                .help = "sBPF version to execute under",
            },
            .limit = .{
                .kind = .named,
                .name_override = null,
                .alias = .l,
                .default_value = std.math.maxInt(u64),
                .config = {},
                .help = "number of compute units that can be used",
            },
        },
    };
};
