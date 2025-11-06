const std = @import("std");
const sig = @import("../sig.zig");

const bpf_loader = sig.runtime.program.bpf_loader;
const vm = sig.vm;

const Pubkey = sig.core.Pubkey;
const AccountSharedData = sig.runtime.AccountSharedData;

const Executable = sig.vm.Executable;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

pub const ProgramMap = std.AutoArrayHashMapUnmanaged(Pubkey, LoadedProgram);

pub const LoadedProgram = union(enum(u8)) {
    failed,
    loaded: struct {
        executable: Executable,
        source: []const u8,
    },

    pub fn deinit(self: *LoadedProgram, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .failed => {},
            .loaded => |*loaded| {
                allocator.free(loaded.source);
                loaded.executable.deinit(allocator);
            },
        }
    }
};

pub fn loadPrograms(
    allocator: std.mem.Allocator,
    accounts: *const std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData),
    enviroment: *const vm.Environment,
    slot: u64,
) error{OutOfMemory}!ProgramMap {
    var programs = ProgramMap{};
    errdefer programs.deinit(allocator);

    for (accounts.keys(), accounts.values()) |pubkey, account| {
        // https://github.com/firedancer-io/solfuzz-agave/blob/agave-v3.0.3/src/lib.rs#L771-L800
        if (!account.owner.equals(&bpf_loader.v1.ID) and
            !account.owner.equals(&bpf_loader.v2.ID) and
            !account.owner.equals(&bpf_loader.v3.ID) and
            !account.owner.equals(&bpf_loader.v4.ID)) continue;

        var loaded_program = try loadProgram(
            allocator,
            &account,
            accounts,
            enviroment,
            slot,
        );
        errdefer loaded_program.deinit(allocator);

        try programs.put(allocator, pubkey, loaded_program);
    }

    return programs;
}

/// Load program requires that the account is executable
pub fn loadProgram(
    allocator: std.mem.Allocator,
    account: *const AccountSharedData,
    accounts: *const std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData),
    environment: *const vm.Environment,
    slot: u64,
) !LoadedProgram {
    // executable bytes are owned by the entry in the accounts map and should not be freed
    const maybe_deployment_slot, const executable_bytes = loadDeploymentSlotAndExecutableBytes(
        account,
        accounts,
    ) orelse return .failed;

    if (maybe_deployment_slot) |ds| if (ds >= slot) return .failed;

    const source = try allocator.dupe(u8, executable_bytes);
    var executable = Executable.fromBytes(
        allocator,
        source,
        &environment.loader,
        environment.config,
    ) catch {
        allocator.free(source);
        return .failed;
    };

    executable.verify(&environment.loader) catch {
        executable.deinit(allocator);
        return .failed;
    };

    return .{
        .loaded = .{
            .executable = executable,
            .source = source,
        },
    };
}

pub fn loadDeploymentSlotAndExecutableBytes(
    account: *const AccountSharedData,
    accounts: *const std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData),
) ?struct { ?u64, []const u8 } {
    if (account.owner.equals(&bpf_loader.v1.ID) or account.owner.equals(&bpf_loader.v2.ID)) {
        return .{ null, account.data };
    } else if (account.owner.equals(&bpf_loader.v3.ID)) {
        const program_state = sig.bincode.readFromSlice(
            failing_allocator,
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

        if (program_data_account.data.len < bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE) {
            return null;
        }

        const program_metadata_bytes =
            program_data_account.data[0..bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE];
        const program_elf_bytes =
            program_data_account.data[bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE..];

        const program_metadata = sig.bincode.readFromSlice(
            failing_allocator,
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
        const program_state = sig.bincode.readFromSlice(
            failing_allocator,
            bpf_loader.v4.State,
            account.data,
            .{},
        ) catch return null;

        if (program_state.status == .retracted) return null;

        return .{
            program_state.slot,
            account.data[bpf_loader.v4.State.PROGRAM_DATA_METADATA_SIZE..],
        };
    } else {
        return null;
    }
}

test "loadPrograms: load v1, v2 program" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const program_elf = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
        std.math.maxInt(usize),
    );
    defer allocator.free(program_elf);

    var accounts = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData){};
    defer accounts.deinit(allocator);

    const program_v1_key = Pubkey.initRandom(prng.random());
    const program_v2_key = Pubkey.initRandom(prng.random());

    try accounts.put(
        allocator,
        program_v1_key,
        .{
            .lamports = 1,
            .owner = bpf_loader.v1.ID,
            .data = program_elf,
            .executable = true,
            .rent_epoch = std.math.maxInt(u64),
        },
    );

    try accounts.put(
        allocator,
        program_v2_key,
        .{
            .lamports = 1,
            .owner = bpf_loader.v2.ID,
            .data = program_elf,
            .executable = true,
            .rent_epoch = std.math.maxInt(u64),
        },
    );

    const environment = vm.Environment{
        .loader = .{},
        .config = .{},
    };
    defer environment.deinit(allocator);

    { // Success
        var loaded_programs = try loadPrograms(
            allocator,
            &accounts,
            &environment,
            0,
        );
        defer {
            for (loaded_programs.values()) |*v| v.deinit(allocator);
            loaded_programs.deinit(allocator);
        }

        switch (loaded_programs.get(program_v1_key).?) {
            .failed => std.debug.panic("Program failed to load!", .{}),
            .loaded => {},
        }

        switch (loaded_programs.get(program_v2_key).?) {
            .failed => std.debug.panic("Program failed to load!", .{}),
            .loaded => {},
        }
    }
}

test "loadPrograms: load v3 program" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

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

    const environment = vm.Environment{
        .loader = .{},
        .config = .{},
    };

    { // Success
        var loaded_programs = try loadPrograms(
            allocator,
            &accounts,
            &environment,
            program_deployment_slot + 1,
        );
        defer {
            for (loaded_programs.values()) |*v| v.deinit(allocator);
            loaded_programs.deinit(allocator);
        }

        switch (loaded_programs.get(program_key).?) {
            .failed => std.debug.panic("Program failed to load!", .{}),
            .loaded => {},
        }
    }

    { // Delay visibility failure
        var loaded_programs = try loadPrograms(
            allocator,
            &accounts,
            &environment,
            program_deployment_slot,
        );
        defer {
            for (loaded_programs.values()) |*v| v.deinit(allocator);
            loaded_programs.deinit(allocator);
        }

        switch (loaded_programs.get(program_key).?) {
            .failed => {},
            .loaded => std.debug.panic("Program should not load!", .{}),
        }
    }

    { // Bad program data meta
        const account = accounts.getPtr(program_data_key).?;
        const tmp_byte = account.data[0];
        account.data[0] = 0xFF; // Corrupt the first byte of the metadata
        defer account.data[0] = tmp_byte;

        var loaded_programs = try loadPrograms(
            allocator,
            &accounts,
            &environment,
            program_deployment_slot + 1,
        );
        defer {
            for (loaded_programs.values()) |*v| v.deinit(allocator);
            loaded_programs.deinit(allocator);
        }

        switch (loaded_programs.get(program_key).?) {
            .failed => {},
            .loaded => std.debug.panic("Program should not load!", .{}),
        }
    }

    { // Bad elf
        const account = accounts.getPtr(program_data_key).?;
        const tmp_byte = account.data[bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE + 1];
        account.data[bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE + 1] = 0xFF; // Corrupt the first byte of the elf
        defer account.data[0] = tmp_byte;

        var loaded_programs = try loadPrograms(
            allocator,
            &accounts,
            &environment,
            program_deployment_slot + 1,
        );
        defer {
            for (loaded_programs.values()) |*loaded_program| loaded_program.deinit(allocator);
            loaded_programs.deinit(allocator);
        }

        switch (loaded_programs.get(program_key).?) {
            .failed => {},
            .loaded => std.debug.panic("Program should not load!", .{}),
        }
    }
}

test "loadPrograms: load v4 program" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const program_deployment_slot = 0;
    const program_key = Pubkey.initRandom(prng.random());
    const program_elf = try std.fs.cwd().readFileAlloc(
        allocator,
        sig.ELF_DATA_DIR ++ "hello_world.so",
        std.math.maxInt(usize),
    );
    defer allocator.free(program_elf);

    const environment = vm.Environment{
        .loader = .{},
        .config = .{},
    };

    var accounts = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData){};
    defer {
        for (accounts.values()) |account| allocator.free(account.data);
        accounts.deinit(allocator);
    }

    const program_state = bpf_loader.v4.State{
        .slot = program_deployment_slot,
        .authority_address_or_next_version = Pubkey.initRandom(prng.random()),
        .status = .deployed,
    };

    const program_data = try allocator.alloc(
        u8,
        bpf_loader.v4.State.PROGRAM_DATA_METADATA_SIZE + program_elf.len,
    );
    errdefer allocator.free(program_data);

    @memcpy(
        program_data[0..bpf_loader.v4.State.PROGRAM_DATA_METADATA_SIZE],
        std.mem.asBytes(&program_state),
    );
    @memcpy(program_data[bpf_loader.v4.State.PROGRAM_DATA_METADATA_SIZE..], program_elf);

    try accounts.put(
        allocator,
        program_key,
        .{
            .lamports = 1,
            .owner = bpf_loader.v4.ID,
            .data = program_data,
            .executable = true,
            .rent_epoch = std.math.maxInt(u64),
        },
    );

    { // Success
        var loaded_programs = try loadPrograms(
            allocator,
            &accounts,
            &environment,
            program_deployment_slot + 1,
        );
        defer {
            for (loaded_programs.values()) |*v| v.deinit(allocator);
            loaded_programs.deinit(allocator);
        }

        switch (loaded_programs.get(program_key).?) {
            .failed => std.debug.panic("Program failed to load!", .{}),
            .loaded => {},
        }
    }

    { // Bad program data meta
        @memset(program_data[0..bpf_loader.v4.State.PROGRAM_DATA_METADATA_SIZE], 0xaa);

        var loaded_programs = try loadPrograms(
            allocator,
            &accounts,
            &environment,
            program_deployment_slot + 1,
        );
        defer {
            for (loaded_programs.values()) |*v| v.deinit(allocator);
            loaded_programs.deinit(allocator);
        }

        switch (loaded_programs.get(program_key).?) {
            .failed => {},
            .loaded => std.debug.panic("Program should not load!", .{}),
        }
    }
}

test "loadPrograms: bad owner" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var accounts = std.AutoArrayHashMapUnmanaged(Pubkey, AccountSharedData){};
    defer {
        for (accounts.values()) |account| allocator.free(account.data);
        accounts.deinit(allocator);
    }

    const program_key = Pubkey.initRandom(prng.random());
    try accounts.put(
        allocator,
        program_key,
        .{
            .lamports = 1,
            .owner = Pubkey.initRandom(prng.random()),
            .data = try allocator.dupe(u8, &.{ 10, 0, 10, 3 }),
            .executable = true,
            .rent_epoch = std.math.maxInt(u64),
        },
    );

    const environment = vm.Environment{
        .loader = .{},
        .config = .{},
    };

    { // Failed to load program with bad owner
        var loaded_programs = try loadPrograms(
            allocator,
            &accounts,
            &environment,
            prng.random().int(u64),
        );
        defer {
            for (loaded_programs.values()) |*v| v.deinit(allocator);
            loaded_programs.deinit(allocator);
        }

        if (loaded_programs.get(program_key) != null)
            std.debug.panic("Program should not load!", .{});
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
