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
    lock: sig.sync.RwLock,
    load_stats: ProgramLoadStats = .{},

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

    pub fn putIfAbsent(
        self: *ProgramMap,
        allocator: Allocator,
        address: Pubkey,
        program: LoadedProgram,
    ) Allocator.Error!bool {
        self.lock.lock();
        defer self.lock.unlock();

        if (self.inner.contains(address)) return false;
        try self.inner.put(allocator, address, program);
        return true;
    }

    pub fn contains(self: *ProgramMap, address: Pubkey) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.inner.contains(address);
    }

    /// Returns true only for a successfully compiled program. Failed entries
    /// are same-slot invalidation sentinels and must never suppress account
    /// reads needed to reload the program in a child slot.
    pub fn containsLoaded(self: *ProgramMap, address: Pubkey) bool {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const program = self.inner.getPtr(address) orelse return false;
        return switch (program.*) {
            .loaded => true,
            .failed => false,
        };
    }

    pub fn loadStats(self: *const ProgramMap) ProgramLoadStats.Snapshot {
        return self.load_stats.snapshot();
    }

    pub fn entryCount(self: *ProgramMap) usize {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.inner.count();
    }

    /// Loader instructions replace deployed/retracted/closed programs with a
    /// temporary failed entry so they cannot be executed again in the same
    /// slot. A ProgramMap that survives into a direct child must drop those
    /// sentinels so the child reloads the account's post-commit state.
    pub fn removeFailedEntries(self: *ProgramMap) usize {
        self.lock.lock();
        defer self.lock.unlock();

        var removed: usize = 0;
        var index = self.inner.count();
        while (index > 0) {
            index -= 1;
            switch (self.inner.values()[index]) {
                .failed => {
                    const address = self.inner.keys()[index];
                    std.debug.assert(self.inner.swapRemove(address));
                    removed += 1;
                },
                .loaded => {},
            }
        }
        return removed;
    }
};

pub const ProgramLoadStats = struct {
    cache_hits: std.atomic.Value(u64) = .init(0),
    cache_misses: std.atomic.Value(u64) = .init(0),
    load_attempts: std.atomic.Value(u64) = .init(0),
    load_successes: std.atomic.Value(u64) = .init(0),
    load_failures: std.atomic.Value(u64) = .init(0),
    load_races: std.atomic.Value(u64) = .init(0),
    executable_bytes: std.atomic.Value(u64) = .init(0),
    programdata_reads: std.atomic.Value(u64) = .init(0),
    borrowed_direct_programdata_reads: std.atomic.Value(u64) = .init(0),
    programdata_bytes: std.atomic.Value(u64) = .init(0),
    programdata_read_ns: std.atomic.Value(u64) = .init(0),
    elf_load_ns: std.atomic.Value(u64) = .init(0),
    verify_ns: std.atomic.Value(u64) = .init(0),
    load_total_ns: std.atomic.Value(u64) = .init(0),

    pub const Snapshot = struct {
        cache_hits: u64,
        cache_misses: u64,
        load_attempts: u64,
        load_successes: u64,
        load_failures: u64,
        load_races: u64,
        executable_bytes: u64,
        programdata_reads: u64,
        borrowed_direct_programdata_reads: u64,
        programdata_bytes: u64,
        programdata_read_ns: u64,
        elf_load_ns: u64,
        verify_ns: u64,
        load_total_ns: u64,

        pub fn subtract(self: Snapshot, earlier: Snapshot) Snapshot {
            return .{
                .cache_hits = self.cache_hits -| earlier.cache_hits,
                .cache_misses = self.cache_misses -| earlier.cache_misses,
                .load_attempts = self.load_attempts -| earlier.load_attempts,
                .load_successes = self.load_successes -| earlier.load_successes,
                .load_failures = self.load_failures -| earlier.load_failures,
                .load_races = self.load_races -| earlier.load_races,
                .executable_bytes = self.executable_bytes -| earlier.executable_bytes,
                .programdata_reads = self.programdata_reads -| earlier.programdata_reads,
                .borrowed_direct_programdata_reads = self.borrowed_direct_programdata_reads -|
                    earlier.borrowed_direct_programdata_reads,
                .programdata_bytes = self.programdata_bytes -| earlier.programdata_bytes,
                .programdata_read_ns = self.programdata_read_ns -| earlier.programdata_read_ns,
                .elf_load_ns = self.elf_load_ns -| earlier.elf_load_ns,
                .verify_ns = self.verify_ns -| earlier.verify_ns,
                .load_total_ns = self.load_total_ns -| earlier.load_total_ns,
            };
        }
    };

    fn recordLoad(
        self: *ProgramLoadStats,
        measurement: ProgramLoadMeasurement,
        success: bool,
    ) void {
        _ = self.load_attempts.fetchAdd(1, .monotonic);
        _ = if (success)
            self.load_successes.fetchAdd(1, .monotonic)
        else
            self.load_failures.fetchAdd(1, .monotonic);
        _ = self.executable_bytes.fetchAdd(measurement.executable_bytes, .monotonic);
        _ = self.programdata_reads.fetchAdd(measurement.programdata_reads, .monotonic);
        _ = self.borrowed_direct_programdata_reads.fetchAdd(
            measurement.borrowed_direct_programdata_reads,
            .monotonic,
        );
        _ = self.programdata_bytes.fetchAdd(measurement.programdata_bytes, .monotonic);
        _ = self.programdata_read_ns.fetchAdd(measurement.programdata_read_ns, .monotonic);
        _ = self.elf_load_ns.fetchAdd(measurement.elf_load_ns, .monotonic);
        _ = self.verify_ns.fetchAdd(measurement.verify_ns, .monotonic);
        _ = self.load_total_ns.fetchAdd(measurement.load_total_ns, .monotonic);
    }

    pub fn snapshot(self: *const ProgramLoadStats) Snapshot {
        return .{
            .cache_hits = self.cache_hits.load(.monotonic),
            .cache_misses = self.cache_misses.load(.monotonic),
            .load_attempts = self.load_attempts.load(.monotonic),
            .load_successes = self.load_successes.load(.monotonic),
            .load_failures = self.load_failures.load(.monotonic),
            .load_races = self.load_races.load(.monotonic),
            .executable_bytes = self.executable_bytes.load(.monotonic),
            .programdata_reads = self.programdata_reads.load(.monotonic),
            .borrowed_direct_programdata_reads = self.borrowed_direct_programdata_reads.load(.monotonic),
            .programdata_bytes = self.programdata_bytes.load(.monotonic),
            .programdata_read_ns = self.programdata_read_ns.load(.monotonic),
            .elf_load_ns = self.elf_load_ns.load(.monotonic),
            .verify_ns = self.verify_ns.load(.monotonic),
            .load_total_ns = self.load_total_ns.load(.monotonic),
        };
    }
};

const ProgramLoadMeasurement = struct {
    executable_bytes: u64 = 0,
    programdata_reads: u64 = 0,
    borrowed_direct_programdata_reads: u64 = 0,
    programdata_bytes: u64 = 0,
    programdata_read_ns: u64 = 0,
    elf_load_ns: u64 = 0,
    verify_ns: u64 = 0,
    load_total_ns: u64 = 0,
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
    const is_program = account.owner.equals(&bpf_loader.v1.ID) or
        account.owner.equals(&bpf_loader.v2.ID) or
        account.owner.equals(&bpf_loader.v3.ID) or
        account.owner.equals(&bpf_loader.v4.ID);
    if (!is_program) return;

    if (programs.contains(address)) {
        _ = programs.load_stats.cache_hits.fetchAdd(1, .monotonic);
        return;
    }
    _ = programs.load_stats.cache_misses.fetchAdd(1, .monotonic);

    var load_timer = sig.time.Timer.start();
    var measurement = ProgramLoadMeasurement{};
    var loaded_program = loadProgram(
        programs_allocator,
        account,
        account_reader,
        enviroment,
        slot,
        &measurement,
    ) catch |err| {
        measurement.load_total_ns = load_timer.read().asNanos();
        programs.load_stats.recordLoad(measurement, false);
        return err;
    };
    measurement.load_total_ns = load_timer.read().asNanos();
    programs.load_stats.recordLoad(measurement, switch (loaded_program) {
        .loaded => true,
        .failed => false,
    });

    errdefer loaded_program.deinit(programs_allocator);

    if (!try programs.putIfAbsent(programs_allocator, address, loaded_program)) {
        _ = programs.load_stats.load_races.fetchAdd(1, .monotonic);
        loaded_program.deinit(programs_allocator);
    }
}

/// Load program requires that the account is executable
fn loadProgram(
    allocator: std.mem.Allocator,
    account: *const AccountSharedData,
    accounts: SlotAccountReader,
    environment: *const vm.Environment,
    slot: u64,
    measurement: *ProgramLoadMeasurement,
) AccountLoadError!LoadedProgram {
    const zone = tracy.Zone.init(@src(), .{ .name = "loadProgram" });
    defer zone.deinit();

    const maybe_deployment_slot, var executable_bytes = try loadDeploymentSlotAndExecutableBytes(
        allocator,
        account,
        accounts,
        measurement,
        envBool("SIG_REPLAY_PROGRAMDATA_DIRECT_BORROWED_READ", false),
    ) orelse return .failed;
    defer allocator.free(executable_bytes); // freed unless returned

    measurement.executable_bytes = @intCast(executable_bytes.len);
    if (maybe_deployment_slot) |ds| if (ds >= slot) return .failed;

    const executable = blk: {
        var elf_timer = sig.time.Timer.start();
        defer measurement.elf_load_ns = elf_timer.read().asNanos();
        break :blk sig.vm.elf.load(
            allocator,
            executable_bytes,
            &environment.loader,
            environment.config,
        ) catch return .failed;
    };

    {
        var verify_timer = sig.time.Timer.start();
        defer measurement.verify_ns = verify_timer.read().asNanos();
        executable.verify(&environment.loader) catch {
            executable.deinit(allocator);
            return .failed;
        };
    }
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
    measurement: *ProgramLoadMeasurement,
    direct_borrowed_programdata_read: bool,
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

        measurement.programdata_reads += 1;
        if (direct_borrowed_programdata_read) {
            if (accounts.getStableBorrowedAccountSharedData(program_data_key)) |program_data| {
                var read_timer = sig.time.Timer.start();
                defer measurement.programdata_read_ns += read_timer.read().asNanos();
                measurement.borrowed_direct_programdata_reads += 1;
                const meta_size = bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE;
                measurement.programdata_bytes += @intCast(program_data.data.len);
                if (program_data.data.len < meta_size) return null;

                const program_metadata = sig.bincode.readFromSlice(
                    failing_allocator,
                    bpf_loader.v3.State,
                    program_data.data[0..meta_size],
                    .{},
                ) catch return null;
                const deployment_slot = switch (program_metadata) {
                    .program_data => |data| data.slot,
                    else => return null,
                };
                return .{
                    deployment_slot,
                    try allocator.dupe(u8, program_data.data[meta_size..]),
                };
            }
        }
        const program_data_account = blk: {
            var read_timer = sig.time.Timer.start();
            defer measurement.programdata_read_ns += read_timer.read().asNanos();
            break :blk try wrapDB(accounts.get(allocator, program_data_key)) orelse return null;
        };
        defer program_data_account.deinit(allocator);

        const meta_size = bpf_loader.v3.State.PROGRAM_DATA_METADATA_SIZE;
        const account_len = program_data_account.data.len();
        measurement.programdata_bytes += @intCast(account_len);
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

fn envBool(key: []const u8, default_value: bool) bool {
    const allocator = std.heap.page_allocator;
    const raw = std.process.getEnvVarOwned(allocator, key) catch return default_value;
    defer allocator.free(raw);

    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return default_value;
    if (std.ascii.eqlIgnoreCase(trimmed, "1") or
        std.ascii.eqlIgnoreCase(trimmed, "true") or
        std.ascii.eqlIgnoreCase(trimmed, "yes") or
        std.ascii.eqlIgnoreCase(trimmed, "on"))
    {
        return true;
    }
    if (std.ascii.eqlIgnoreCase(trimmed, "0") or
        std.ascii.eqlIgnoreCase(trimmed, "false") or
        std.ascii.eqlIgnoreCase(trimmed, "no") or
        std.ascii.eqlIgnoreCase(trimmed, "off"))
    {
        return false;
    }
    return default_value;
}

test "ProgramMap.putIfAbsent does not replace existing entry" {
    const allocator = std.testing.allocator;
    var programs = ProgramMap.empty;
    defer programs.deinit(allocator);

    var first_key_data = [_]u8{0} ** Pubkey.SIZE;
    first_key_data[0] = 1;
    const key = Pubkey{ .data = first_key_data };

    try std.testing.expect(try programs.putIfAbsent(allocator, key, .failed));
    try std.testing.expect(!try programs.putIfAbsent(allocator, key, .failed));
    try std.testing.expectEqual(1, programs.inner.count());
    try std.testing.expect(!programs.containsLoaded(key));
}

test "ProgramMap removes failed child-slot sentinels" {
    const allocator = std.testing.allocator;
    var programs = ProgramMap.empty;
    defer programs.deinit(allocator);

    var first_key_data = [_]u8{0} ** Pubkey.SIZE;
    first_key_data[0] = 1;
    var second_key_data = [_]u8{0} ** Pubkey.SIZE;
    second_key_data[0] = 2;
    try programs.inner.put(allocator, .{ .data = first_key_data }, .failed);
    try programs.inner.put(allocator, .{ .data = second_key_data }, .failed);

    try std.testing.expectEqual(2, programs.entryCount());
    try std.testing.expectEqual(2, programs.removeFailedEntries());
    try std.testing.expectEqual(0, programs.entryCount());
}

test "ProgramLoadStats snapshot subtraction reports per-slot delta" {
    var stats = ProgramLoadStats{};
    _ = stats.cache_hits.fetchAdd(9, .monotonic);
    _ = stats.load_attempts.fetchAdd(4, .monotonic);
    const start = stats.snapshot();

    _ = stats.cache_hits.fetchAdd(7, .monotonic);
    _ = stats.cache_misses.fetchAdd(2, .monotonic);
    _ = stats.load_attempts.fetchAdd(2, .monotonic);
    _ = stats.borrowed_direct_programdata_reads.fetchAdd(3, .monotonic);
    _ = stats.load_total_ns.fetchAdd(123, .monotonic);

    const delta = stats.snapshot().subtract(start);
    try std.testing.expectEqual(7, delta.cache_hits);
    try std.testing.expectEqual(2, delta.cache_misses);
    try std.testing.expectEqual(2, delta.load_attempts);
    try std.testing.expectEqual(3, delta.borrowed_direct_programdata_reads);
    try std.testing.expectEqual(123, delta.load_total_ns);
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
        try std.testing.expect(loaded_programs.containsLoaded(program_v1_key));

        switch (loaded_programs.get(program_v2_key).?) {
            .failed => return error.FailedToLoadProgram,
            .loaded => {},
        }

        const first_stats = loaded_programs.loadStats();
        try std.testing.expectEqual(0, first_stats.cache_hits);
        try std.testing.expectEqual(2, first_stats.cache_misses);
        try std.testing.expectEqual(2, first_stats.load_attempts);
        try std.testing.expectEqual(2, first_stats.load_successes);
        try std.testing.expectEqual(0, first_stats.load_failures);
        try std.testing.expectEqual(0, first_stats.load_races);
        try std.testing.expectEqual(@as(u64, @intCast(program_elf.len * 2)), first_stats.executable_bytes);
        try std.testing.expectEqual(0, first_stats.programdata_reads);
        try std.testing.expectEqual(0, first_stats.programdata_bytes);

        const program_v1_account = accounts.get(program_v1_key).?;
        try loadIfProgram(
            allocator,
            &loaded_programs,
            program_v1_key,
            &program_v1_account,
            .{ .account_shared_data_map = &accounts },
            &.ALL_ENABLED,
            0,
        );
        const hit_stats = loaded_programs.loadStats();
        try std.testing.expectEqual(1, hit_stats.cache_hits);
        try std.testing.expectEqual(first_stats.cache_misses, hit_stats.cache_misses);
        try std.testing.expectEqual(first_stats.load_attempts, hit_stats.load_attempts);
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

        const stats = loaded_programs.loadStats();
        try std.testing.expectEqual(1, stats.cache_misses);
        try std.testing.expectEqual(1, stats.load_attempts);
        try std.testing.expectEqual(1, stats.load_successes);
        try std.testing.expectEqual(1, stats.programdata_reads);
        try std.testing.expectEqual(0, stats.borrowed_direct_programdata_reads);
        try std.testing.expectEqual(@as(u64, @intCast(program_data_bytes.len)), stats.programdata_bytes);
        try std.testing.expectEqual(@as(u64, @intCast(program_elf.len)), stats.executable_bytes);
    }

    { // Stable borrowed ProgramData avoids the intermediate account clone.
        const program_account = accounts.get(program_key).?;
        var measurement = ProgramLoadMeasurement{};
        const result = (try loadDeploymentSlotAndExecutableBytes(
            allocator,
            &program_account,
            .{ .account_shared_data_map = &accounts },
            &measurement,
            true,
        )) orelse return error.TestFailed;
        const deployment_slot, const executable_bytes = result;
        defer allocator.free(executable_bytes);

        try std.testing.expectEqual(program_deployment_slot, deployment_slot.?);
        try std.testing.expectEqualSlices(u8, program_elf, executable_bytes);
        try std.testing.expectEqual(1, measurement.programdata_reads);
        try std.testing.expectEqual(1, measurement.borrowed_direct_programdata_reads);
        try std.testing.expectEqual(
            @as(u64, @intCast(program_data_bytes.len)),
            measurement.programdata_bytes,
        );
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

        const stats = loaded_programs.loadStats();
        try std.testing.expectEqual(1, stats.load_attempts);
        try std.testing.expectEqual(0, stats.load_successes);
        try std.testing.expectEqual(1, stats.load_failures);
        try std.testing.expectEqual(1, stats.programdata_reads);
        try std.testing.expectEqual(@as(u64, @intCast(program_data_bytes.len)), stats.programdata_bytes);
        try std.testing.expectEqual(@as(u64, @intCast(program_elf.len)), stats.executable_bytes);
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
