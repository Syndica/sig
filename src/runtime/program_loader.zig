const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../sig.zig");

const bpf_loader = sig.runtime.program.bpf_loader;
const vm = sig.vm;

const Allocator = std.mem.Allocator;

const SlotAccountReader = sig.accounts_db.SlotAccountReader;

const Pubkey = sig.core.Pubkey;
const AccountSharedData = sig.runtime.AccountSharedData;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});
const assert = std.debug.assert;

const AccountLoadError = sig.runtime.account_loader.AccountLoadError;
const wrapDB = sig.runtime.account_loader.wrapDB;

pub const ProgramMap = struct {
    inner: sig.utils.collections.PubkeyMap(LoadedProgram),
    lock: std.Thread.RwLock,

    pub const empty = ProgramMap{
        .inner = .empty,
        .lock = .{},
    };

    pub fn deinit(self: *ProgramMap, allocator: Allocator) void {
        for (self.inner.values()) |*v| v.deinit(allocator);
        self.inner.deinit(allocator);
    }

    pub fn get(self: *ProgramMap, address: Pubkey) ?LoadedProgram {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.inner.get(address);
    }

    pub fn fetchPut(
        self: *ProgramMap,
        allocator: Allocator,
        address: Pubkey,
        program: LoadedProgram,
    ) Allocator.Error!?LoadedProgram {
        self.lock.lock();
        defer self.lock.unlock();
        return if (try self.inner.fetchPut(allocator, address, program)) |x| x.value else null;
    }

    pub fn contains(self: *ProgramMap, address: Pubkey) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.inner.contains(address);
    }
};

pub const LoadedProgram = union(enum(u8)) {
    failed,
    loaded: struct {
        executable: sig.vm.Executable,
        source: []const u8,
    },

    pub fn deinit(self: *const LoadedProgram, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .failed => {},
            .loaded => |*loaded| {
                allocator.free(loaded.source);
                loaded.executable.deinit(allocator);
            },
        }
    }
};

pub fn loadIfProgram(
    programs_allocator: std.mem.Allocator,
    programs: *ProgramMap,
    address: Pubkey,
    account: *const AccountSharedData,
    account_reader: SlotAccountReader,
    enviroment: *const vm.Environment,
    slot: u64,
) AccountLoadError!void {
    // https://github.com/firedancer-io/solfuzz-agave/blob/agave-v3.0.3/src/lib.rs#L771-L800
    if (!account.owner.equals(&bpf_loader.v1.ID) and
        !account.owner.equals(&bpf_loader.v2.ID) and
        !account.owner.equals(&bpf_loader.v3.ID) and
        !account.owner.equals(&bpf_loader.v4.ID) or
        programs.contains(address)) return;

    // TODO(TOCTOU): at this point 2 executions of this function can reach
    // this point for the same program, but addressing this involves completely
    // altering the access pattern for ProgramMap

    var loaded_program = try loadProgram(
        programs_allocator,
        account,
        account_reader,
        enviroment,
        slot,
    );
    errdefer loaded_program.deinit(programs_allocator);

    if (try programs.fetchPut(programs_allocator, address, loaded_program)) |old_value| {
        old_value.deinit(programs_allocator);
    }
}

/// Load program requires that the account is executable
fn loadProgram(
    allocator: std.mem.Allocator,
    account: *const AccountSharedData,
    accounts: SlotAccountReader,
    environment: *const vm.Environment,
    slot: u64,
) AccountLoadError!LoadedProgram {
    const zone = tracy.Zone.init(@src(), .{ .name = "loadProgram" });
    defer zone.deinit();

    const maybe_deployment_slot, var executable_bytes = try loadDeploymentSlotAndExecutableBytes(
        allocator,
        account,
        accounts,
    ) orelse return .failed;
    defer allocator.free(executable_bytes); // freed unless returned

    if (maybe_deployment_slot) |ds| if (ds >= slot) return .failed;

    const executable = sig.vm.elf.load(
        allocator,
        executable_bytes,
        &environment.loader,
        environment.config,
    ) catch return .failed;

    executable.verify(&environment.loader) catch {
        executable.deinit(allocator);
        return .failed;
    };
    defer executable_bytes = &.{}; // to avoid freeing
    return .{ .loaded = .{
        .executable = executable,
        .source = executable_bytes,
    } };
}

/// returned bytes are allocated with the passed allocator and owned by the caller
fn loadDeploymentSlotAndExecutableBytes(
    allocator: Allocator,
    account: *const AccountSharedData,
    accounts: SlotAccountReader,
) AccountLoadError!?struct { ?u64, []u8 } {
    if (account.owner.equals(&bpf_loader.v1.ID) or account.owner.equals(&bpf_loader.v2.ID)) {
        return .{ null, try allocator.dupe(u8, account.data) };
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

        const program_data_account = try wrapDB(accounts.get(allocator, program_data_key)) orelse
            return null;
        defer program_data_account.deinit(allocator);

        const meta_size = bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE;
        const account_len = program_data_account.data.len();
        if (account_len < meta_size) {
            return null;
        }

        var program_metadata_bytes: [meta_size]u8 = undefined;
        assert(meta_size == program_data_account.data.read(0, &program_metadata_bytes));

        const program_elf_bytes = try allocator.alloc(u8, account_len - meta_size);
        errdefer allocator.free(program_elf_bytes);
        assert(account_len - meta_size ==
            program_data_account.data.read(@intCast(meta_size), program_elf_bytes));

        const program_metadata = sig.bincode.readFromSlice(
            failing_allocator,
            bpf_loader.v3.State,
            &program_metadata_bytes,
            .{},
        ) catch {
            allocator.free(program_elf_bytes);
            return null;
        };

        const slot = switch (program_metadata) {
            .program_data => |data| data.slot,
            else => {
                allocator.free(program_elf_bytes);
                return null;
            },
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
            try allocator.dupe(u8, account.data[bpf_loader.v4.State.PROGRAM_DATA_METADATA_SIZE..]),
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

    var accounts = sig.utils.collections.PubkeyMap(AccountSharedData){};
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

    { // Success
        var loaded_programs = try testLoad(allocator, &accounts, &.ALL_ENABLED, 0);
        defer loaded_programs.deinit(allocator);

        switch (loaded_programs.get(program_v1_key).?) {
            .failed => return error.FailedToLoadProgram,
            .loaded => {},
        }

        switch (loaded_programs.get(program_v2_key).?) {
            .failed => return error.FailedToLoadProgram,
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

    var accounts = sig.utils.collections.PubkeyMap(AccountSharedData){};
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

    { // Success
        var loaded_programs = try testLoad(
            allocator,
            &accounts,
            &.ALL_ENABLED,
            program_deployment_slot + 1,
        );
        defer loaded_programs.deinit(allocator);

        switch (loaded_programs.get(program_key).?) {
            .failed => return error.TestFailed,
            .loaded => {},
        }
    }

    { // Delay visibility failure
        var loaded_programs = try testLoad(
            allocator,
            &accounts,
            &.ALL_ENABLED,
            program_deployment_slot,
        );
        defer loaded_programs.deinit(allocator);

        switch (loaded_programs.get(program_key).?) {
            .failed => {},
            .loaded => return error.TestFailed,
        }
    }

    { // Bad program data meta
        const account = accounts.getPtr(program_data_key).?;
        const tmp_byte = account.data[0];
        account.data[0] = 0xFF; // Corrupt the first byte of the metadata
        defer account.data[0] = tmp_byte;

        var loaded_programs = try testLoad(
            allocator,
            &accounts,
            &.ALL_ENABLED,
            program_deployment_slot + 1,
        );
        defer loaded_programs.deinit(allocator);

        switch (loaded_programs.get(program_key).?) {
            .failed => {},
            .loaded => return error.TestFailed,
        }
    }

    { // Bad elf
        const account = accounts.getPtr(program_data_key).?;
        const tmp_byte = account.data[bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE + 1];
        account.data[bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE + 1] = 0xFF; // Corrupt the first byte of the elf
        defer account.data[0] = tmp_byte;

        var loaded_programs = try testLoad(
            allocator,
            &accounts,
            &.ALL_ENABLED,
            program_deployment_slot + 1,
        );
        defer loaded_programs.deinit(allocator);

        switch (loaded_programs.get(program_key).?) {
            .failed => {},
            .loaded => return error.TestFailed,
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

    var accounts = sig.utils.collections.PubkeyMap(AccountSharedData){};
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
        var loaded_programs = try testLoad(
            allocator,
            &accounts,
            &.ALL_ENABLED,
            program_deployment_slot + 1,
        );
        defer loaded_programs.deinit(allocator);

        switch (loaded_programs.get(program_key).?) {
            .failed => return error.TestFailed,
            .loaded => {},
        }
    }

    { // Bad program data meta
        @memset(program_data[0..bpf_loader.v4.State.PROGRAM_DATA_METADATA_SIZE], 0xaa);

        var loaded_programs = try testLoad(
            allocator,
            &accounts,
            &.ALL_ENABLED,
            program_deployment_slot + 1,
        );
        defer loaded_programs.deinit(allocator);

        switch (loaded_programs.get(program_key).?) {
            .failed => {},
            .loaded => return error.TestFailed,
        }
    }
}

test "loadPrograms: bad owner" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    var accounts = sig.utils.collections.PubkeyMap(AccountSharedData){};
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

    { // Failed to load program with bad owner
        var loaded_programs = try testLoad(
            allocator,
            &accounts,
            &.ALL_ENABLED,
            prng.random().int(u64),
        );
        defer loaded_programs.deinit(allocator);

        if (loaded_programs.get(program_key) != null) return error.TestFailed;
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

    assert(program_data_metadata_bytes.len <= bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE);

    @memcpy(program_data_bytes[bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE..], program_elf_bytes);

    return .{ program_bytes, program_data_bytes };
}

/// helper function to load programs for tests
pub fn testLoad(
    allocator: std.mem.Allocator,
    accounts: *const sig.utils.collections.PubkeyMap(AccountSharedData),
    environment: *const vm.Environment,
    slot: u64,
) AccountLoadError!ProgramMap {
    var programs = ProgramMap.empty;
    errdefer programs.deinit(allocator);

    for (accounts.keys(), accounts.values()) |address, account| {
        try loadIfProgram(
            allocator,
            &programs,
            address,
            &account,
            .{ .account_shared_data_map = accounts },
            environment,
            slot,
        );
    }

    return programs;
}
