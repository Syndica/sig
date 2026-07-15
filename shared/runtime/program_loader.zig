const builtin = @import("builtin");
const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../lib.zig");

const bpf_loader = sig.runtime.program.bpf_loader;
const vm = sig.vm;

const Allocator = std.mem.Allocator;

const AccountReader = sig.runtime.execution_interfaces.AccountReader;

const Pubkey = sig.core.Pubkey;
const AccountSharedData = sig.runtime.AccountSharedData;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});
const assert = std.debug.assert;

const AccountLoadError = sig.runtime.execution_interfaces.AccountLoadError;

pub const ProgramMap = struct {
    inner: sig.utils.collections.PubkeyMap(LoadedProgram),
    lock: sig.sync.RwLock,

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

    /// Insert `program` for `address` if absent. If an entry already exists it
    /// is left untouched (it may be in use by a concurrent reader) and the caller
    /// retains ownership of `program` (typically deinit it). Never frees or replaces
    /// a live map entry.
    fn putIfAbsent(
        self: *ProgramMap,
        allocator: Allocator,
        address: Pubkey,
        program: LoadedProgram,
    ) Allocator.Error!bool {
        self.lock.lock();
        defer self.lock.unlock();
        const gop = try self.inner.getOrPut(allocator, address);
        if (gop.found_existing) return false;
        gop.value_ptr.* = program;
        return true;
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
    account_reader: AccountReader,
    enviroment: *const vm.Environment,
    slot: u64,
) AccountLoadError!void {
    // https://github.com/firedancer-io/solfuzz-agave/blob/agave-v3.0.3/src/lib.rs#L771-L800
    if (!account.owner.equals(&bpf_loader.v1.ID) and
        !account.owner.equals(&bpf_loader.v2.ID) and
        !account.owner.equals(&bpf_loader.v3.ID) or
        programs.contains(address)) return;

    var loaded_program = try loadProgram(
        programs_allocator,
        account,
        account_reader,
        enviroment,
        slot,
    );
    errdefer loaded_program.deinit(programs_allocator);

    // NOTE: Two transactions that merely *invoke* the same program are not
    // serialized by the account-lock scheduler, so a concurrent reader may
    // already have cached this program and be running its VM against that
    // entry right now, replacing (and freeing) it would be a use-after-free,
    // which is why we only insert if still absent. On a lost race we drop our
    // redundant copy instead of touching the live entry.
    if (!try programs.putIfAbsent(programs_allocator, address, loaded_program)) {
        loaded_program.deinit(programs_allocator);
    }
}

/// Load program requires that the account is executable
fn loadProgram(
    allocator: std.mem.Allocator,
    account: *const AccountSharedData,
    accounts: AccountReader,
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

    executable.verify() catch {
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
    accounts: AccountReader,
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

        // TODO(accounts_interface): we don't need an owned account data here
        const program_data_account = try accounts.get(allocator, program_data_key) orelse
            return null;
        defer program_data_account.deinit(allocator);

        // [agave] https://github.com/anza-xyz/agave/blob/v4.0.0/svm/src/program_loader.rs#L53
        if (!program_data_account.owner.equals(&bpf_loader.v3.ID)) {
            return null;
        }

        const meta_size = bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE;
        const account_len = program_data_account.data.len;
        if (account_len < meta_size) {
            return null;
        }

        const program_elf_bytes = try allocator.alloc(u8, account_len - meta_size);
        errdefer allocator.free(program_elf_bytes);
        @memcpy(program_elf_bytes, program_data_account.data[meta_size..]);

        const program_metadata = sig.bincode.readFromSlice(
            failing_allocator,
            bpf_loader.v3.State,
            program_data_account.data[0..meta_size],
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
            .owner = bpf_loader.v3.ID,
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

/// Load programs from an in-memory account map (for testing).
pub fn testLoad(
    allocator: std.mem.Allocator,
    accounts: *const sig.utils.collections.PubkeyMap(AccountSharedData),
    environment: *const vm.Environment,
    slot: u64,
) AccountLoadError!ProgramMap {
    var programs = ProgramMap.empty;
    errdefer programs.deinit(allocator);

    const account_reader = AccountReader.fromMap(accounts);

    for (accounts.keys(), accounts.values()) |address, account| {
        try loadIfProgram(
            allocator,
            &programs,
            address,
            &account,
            account_reader,
            environment,
            slot,
        );
    }

    return programs;
}

// Regression test for the program-cache use-after-free data race.
//
// `loadIfProgram` previously populated the per-slot shared `ProgramMap` with a check-then-act
// sequence that was not atomic across its steps (and used `fetchPut` to replace entries):
//
//   if (... or programs.contains(address)) return; // 1. check   (lock released)
//   var loaded_program = try loadProgram(...);      // 2. load    (no lock held)
//   if (try programs.fetchPut(...)) |old|           // 3. insert, replacing and
//       old.deinit(programs_allocator);             //    freeing any prior entry
//
// Two transaction workers that invoke the same not-yet-cached program run in
// parallel (a program account is locked read-only, so the scheduler creates no
// dependency between them). Both pass the `contains` check, both load, and the
// second worker's `fetchPut` frees the first worker's program object while that
// worker is still executing the VM against it (bpf_loader/execute.zig fetches the
// program by value via `program_map.get` and runs the VM with no lock held). The
// result is a use-after-free, corrupted execution, divergent account writes, and
// a non-deterministic bank hash.
//
// Racing real threads would be flaky, so this test drives the interleaving
// deterministically. It makes one real `loadIfProgram` call whose `AccountReader`
// inserts a second, already-loaded copy of the program ("worker A") into the cache
// after `loadIfProgram` passes its `contains` check but before it reaches the
// final insert step (`fetchPut` before this fix, now `putIfAbsent`). The reader's
// `get` runs from inside `loadProgram`, which sits between those two steps.
//
// Afterwards the cache must still hand out worker A's program:
//   * buggy fetchPut-then-free-old: worker A's entry is evicted and freed, and the
//     cache holds worker B's copy, so the cached source pointer differs from worker
//     A's -> FAIL.
//   * fixed put-if-absent: worker B's duplicate is discarded and worker A's program
//     is left in place, so the pointers match -> PASS.

test "loadIfProgram: concurrent first-load must not evict program worker still holds" {
    const allocator = std.testing.allocator;
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);

    const program_key = Pubkey.initRandom(prng.random());
    const program_data_key = Pubkey.initRandom(prng.random());
    const program_deployment_slot = 42;
    const slot = program_deployment_slot + 1;

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
    defer allocator.free(program_bytes);
    defer allocator.free(program_data_bytes);

    const program_account = AccountSharedData{
        .lamports = 1,
        .owner = bpf_loader.v3.ID,
        .data = program_bytes,
        .executable = true,
        .rent_epoch = std.math.maxInt(u64),
    };

    var accounts = sig.utils.collections.PubkeyMap(AccountSharedData){};
    defer accounts.deinit(allocator);
    try accounts.put(allocator, program_key, program_account);
    try accounts.put(allocator, program_data_key, .{
        .lamports = 1,
        .owner = bpf_loader.v3.ID,
        .data = program_data_bytes,
        .executable = false,
        .rent_epoch = std.math.maxInt(u64),
    });

    const environment: vm.Environment = .ALL_ENABLED;

    var programs = ProgramMap.empty;
    defer programs.deinit(allocator);

    // worker A: load the program once. In the real bug this is the copy a
    // worker fetches via `program_map.get` and runs the VM against.
    var decoy = try loadProgram(
        allocator,
        &program_account,
        AccountReader.fromMap(&accounts),
        &environment,
        slot,
    );
    const decoy_source_ptr: [*]const u8 = switch (decoy) {
        .loaded => |l| l.source.ptr,
        .failed => return error.FailedToLoadProgram,
    };

    // A one-shot `AccountReader` that simulates worker A publishing its program to
    // the shared cache mid-load: its `get` runs from inside `loadProgram`, i.e.
    // after `loadIfProgram` passed `contains` but before it reaches `putIfAbsent`. It
    // then delegates to a real map-backed reader so worker B's own load succeeds.
    // Same {ctx, getFn} shape that `AccountReader.fromMap`/`noop` build internally.
    var injector = struct {
        inner: AccountReader,
        programs: *ProgramMap,
        key: Pubkey,
        decoy: LoadedProgram,
        allocator: Allocator,
        injected: bool = false,

        fn get(
            ctx: *const anyopaque,
            account_allocator: Allocator,
            pubkey: Pubkey,
        ) AccountLoadError!?AccountSharedData {
            const self: *@This() = @ptrCast(@alignCast(@constCast(ctx)));
            if (!self.injected) {
                // The map is still empty here (worker B has not inserted yet), so
                // worker A's insert has no prior entry.
                std.debug.assert(
                    (try self.programs.fetchPut(self.allocator, self.key, self.decoy)) == null,
                );
                self.injected = true;
            }
            return self.inner.get(account_allocator, pubkey);
        }
    }{
        .inner = AccountReader.fromMap(&accounts),
        .programs = &programs,
        .key = program_key,
        .decoy = decoy,
        .allocator = allocator,
    };

    // worker B: the real `loadIfProgram` for the same program.
    const load_result = loadIfProgram(
        allocator,
        &programs,
        program_key,
        &program_account,
        .{ .ctx = &injector, .getFn = @TypeOf(injector).get },
        &environment,
        slot,
    );
    // If the load failed before the reader ran, the cache never took ownership of
    // worker A's program, so free it here to avoid a leak.
    if (!injector.injected) decoy.deinit(allocator);
    try load_result;

    // The program the cache hands out must still be worker A's (first-writer-wins).
    // With the buggy fetchPut-then-free-old, worker A's program was evicted and
    // freed while a worker still referenced it, and the cache holds worker B's
    // duplicate; a differing source pointer exposes the use-after-free.
    const cached = programs.get(program_key) orelse return error.ProgramMissingFromCache;
    const cached_source_ptr: [*]const u8 = switch (cached) {
        .loaded => |l| l.source.ptr,
        .failed => return error.ProgramLoadFailed,
    };
    try std.testing.expectEqual(decoy_source_ptr, cached_source_ptr);
}
