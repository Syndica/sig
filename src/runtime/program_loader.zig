const std = @import("std");
const sig = @import("../sig.zig");

const bpf_loader = sig.runtime.program.bpf_loader;

const Pubkey = sig.core.Pubkey;
const AccountSharedData = sig.runtime.AccountSharedData;

const Executable = sig.vm.Executable;
const VmEnvironment = sig.vm.Environment;

pub const ProgramMap = std.AutoArrayHashMapUnmanaged(Pubkey, LoadedProgram);

pub const LoadedProgram = union(enum(u8)) {
    failed,
    loaded: struct {
        executable: Executable,
        source: []const u8,
    },

    pub fn deinit(self: LoadedProgram, allocator: std.mem.Allocator) void {
        switch (self) {
            .failed => {},
            .loaded => |loaded| {
                var data = loaded;
                allocator.free(data.source);
                data.executable.deinit(allocator);
            },
        }
    }
};

pub fn loadPrograms(
    allocator: std.mem.Allocator,
    accounts: *const std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData),
    enviroment: *const VmEnvironment,
    slot: u64,
) error{OutOfMemory}!ProgramMap {
    var programs = ProgramMap{};
    errdefer programs.deinit(allocator);

    for (accounts.keys(), accounts.values()) |pubkey, account| {
        if (account.executable)
            try programs.put(allocator, pubkey, try loadProgram(
                allocator,
                &account,
                accounts,
                enviroment,
                slot,
            ));
    }

    return programs;
}

pub fn loadProgram(
    allocator: std.mem.Allocator,
    account: *const AccountSharedData,
    accounts: *const std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData),
    environment: *const VmEnvironment,
    slot: u64,
) !LoadedProgram {
    const deployment_slot, const executable_bytes = loadDeploymentSlotAndExecutableBytes(
        allocator,
        account,
        accounts,
    ) orelse return .failed;

    if (deployment_slot >= slot) return .failed;

    const source = try allocator.dupe(u8, executable_bytes);
    const executable = Executable.fromBytes(
        allocator,
        source,
        &environment.loader,
        environment.config,
    ) catch {
        allocator.free(source);
        return .failed;
    };
    errdefer executable.deinit(allocator);

    executable.verify(&environment.loader) catch return .failed;

    return .{
        .loaded = .{
            .executable = executable,
            .source = source,
        },
    };
}

pub fn loadDeploymentSlotAndExecutableBytes(
    allocator: std.mem.Allocator,
    account: *const AccountSharedData,
    accounts: *const std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData),
) ?struct { u64, []const u8 } {
    if (account.owner.equals(&bpf_loader.v1.ID) or account.owner.equals(&bpf_loader.v2.ID)) {
        return .{ 0, account.data };
    } else if (account.owner.equals(&bpf_loader.v3.ID)) {
        const program_state = sig.bincode.readFromSlice(
            allocator,
            bpf_loader.v3.State,
            account.data,
            .{},
        ) catch return null;

        const program_data_key = switch (program_state) {
            .program => |program_data_key| program_data_key.programdata_address,
            else => return null,
        };

        const program_data_account = accounts.getPtr(program_data_key) orelse
            return null;

        const program_metadata_bytes =
            program_data_account.data[0..bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE];
        const program_elf_bytes =
            program_data_account.data[bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE..];

        const program_metadata = sig.bincode.readFromSlice(
            allocator,
            bpf_loader.v3.State,
            program_metadata_bytes,
            .{},
        ) catch return null;

        const slot = switch (program_metadata) {
            .program_data => |data| data.slot,
            else => return null,
        };

        return .{ slot, program_elf_bytes };
    } else if (account.owner.equals(&bpf_loader.v4.ID)) {
        // Loader v4 is not implemented yet.
        return null;
    } else {
        return null;
    }
}

test "loadPrograms: load valid v3 program" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(0);

    const program_key = Pubkey.initRandom(prng.random());
    const program_data_key = Pubkey.initRandom(prng.random());
    const program_deployment_slot = 42;

    const program_elf = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
        std.math.maxInt(usize),
    );
    defer allocator.free(program_elf);

    const program_bytes, const program_data_bytes = try createV3ProgramAccountData(
        allocator,
        program_data_key,
        program_deployment_slot,
        null,
        program_elf,
    );

    var accounts = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData){};
    defer {
        for (accounts.values()) |account| allocator.free(account.data);
        accounts.deinit(allocator);
    }

    try accounts.put(
        allocator,
        program_key,
        .{
            .lamports = 1,
            .owner = bpf_loader.v3.ID,
            .data = program_bytes,
            .executable = true,
            .rent_epoch = std.math.maxInt(u64),
        },
    );

    try accounts.put(
        allocator,
        program_data_key,
        .{
            .lamports = 1,
            .owner = program_key,
            .data = program_data_bytes,
            .executable = false,
            .rent_epoch = std.math.maxInt(u64),
        },
    );

    const environment = VmEnvironment{
        .loader = .{},
        .config = .{},
    };
    const slot = program_deployment_slot + 1;

    var loaded_programs = try loadPrograms(
        allocator,
        &accounts,
        &environment,
        slot,
    );
    defer {
        for (loaded_programs.values()) |loaded_program| loaded_program.deinit(allocator);
        loaded_programs.deinit(allocator);
    }

    switch (loaded_programs.get(program_key).?) {
        .failed => std.debug.panic("Program failed to load!", .{}),
        .loaded => {},
    }
}

pub fn createV3ProgramAccountData(
    allocator: std.mem.Allocator,
    program_data_key: Pubkey,
    program_deployment_slot: u64,
    program_update_authority: ?Pubkey,
    program_elf_bytes: []const u8,
) !struct { []u8, []u8 } {
    if (!@import("builtin").is_test) @compileError("createV3ProgramAccountData is only for tests");
    const program_bytes = try sig.bincode.writeAlloc(
        allocator,
        bpf_loader.v3.State{
            .program = .{
                .programdata_address = program_data_key,
            },
        },
        .{},
    );
    errdefer allocator.free(program_bytes);

    var program_data_bytes = try allocator.alloc(
        u8,
        bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE + program_elf_bytes.len,
    );
    errdefer allocator.free(program_data_bytes);

    const program_data_metadata_bytes = try sig.bincode.writeToSlice(
        program_data_bytes[0..bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE],
        bpf_loader.v3.State{
            .program_data = .{
                .slot = program_deployment_slot,
                .upgrade_authority_address = program_update_authority,
            },
        },
        .{},
    );

    std.debug.assert(
        program_data_metadata_bytes.len <= bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE,
    );

    @memcpy(program_data_bytes[bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE..], program_elf_bytes);

    return .{ program_bytes, program_data_bytes };
}
