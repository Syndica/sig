const std = @import("std");
const sig = @import("../sig.zig");
const ledger = @import("lib.zig");
const cli = @import("cli");

const ColumnFamily = sig.ledger.database.ColumnFamily;

const Data = struct {
    value: []const u8,

    fn deinit(self: Data, allocator: std.mem.Allocator) void {
        allocator.free(self.value);
    }
};

const cf1 = ColumnFamily{
    .name = "data",
    .Key = u64,
    .Value = Data,
};

pub const LedgerDB = switch (sig.build_options.ledger_db) {
    .rocksdb => ledger.database.RocksDB(&.{cf1}),
    .hashmap => ledger.database.SharedHashMapDB(&.{cf1}),
};

const MIN_ACTION_COUNT = @typeInfo(Action).@"enum".fields.len;

// Note: deleteFilesInRange is not included in the fuzzing as it is not
// implemented in the hashmap implementation, and the RocksDB implementation
// requires manual flushing of the memtable to disk to make the changes visible.
const Action = enum {
    put,
    get,
    get_bytes,
    count,
    contains,
    delete,
    batch,
};

fn getKeys(
    allocator: std.mem.Allocator,
    map: *const std.AutoArrayHashMapUnmanaged(u32, Data),
) ![]const u32 {
    var keys: std.ArrayListUnmanaged(u32) = .empty;
    errdefer keys.deinit(allocator);
    try keys.ensureTotalCapacityPrecise(allocator, map.count());
    for (map.keys()) |key| {
        keys.appendAssumeCapacity(key);
    }
    return try keys.toOwnedSlice(allocator);
}

fn createLedgerDB(allocator: std.mem.Allocator, dst_dir: std.fs.Dir) !LedgerDB {
    const ledger_path = try dst_dir.realpathAlloc(allocator, ".");
    defer allocator.free(ledger_path);
    return try LedgerDB.open(allocator, .noop, ledger_path);
}

pub const RunCmd = struct {
    max_actions: ?u64,

    pub const cmd_info: cli.CommandInfo(RunCmd) = .{
        .help = .{
            .short = "Fuzz the ledger.",
            .long = null,
        },
        .sub = .{
            .max_actions = .{
                .kind = .named,
                .name_override = null,
                .alias = .m,
                .default_value = null,
                .config = {},
                .help = std.fmt.comptimePrint(
                    \\Maximum number of actions to take before exiting the fuzzer;
                    \\floored by the minimum number of actions ({d}).
                , .{MIN_ACTION_COUNT}),
            },
        },
    };
};

const FuzzLogger = sig.trace.Logger("ledger.fuzz");

pub fn run(
    allocator: std.mem.Allocator,
    logger: FuzzLogger,
    initial_seed: u64,
    fuzz_data_dir: std.fs.Dir,
    run_cmd: RunCmd,
) !void {
    try runInner(
        allocator,
        logger,
        initial_seed,
        fuzz_data_dir,
        run_cmd.max_actions,
    );
}

fn runInner(
    allocator: std.mem.Allocator,
    logger: FuzzLogger,
    initial_seed: u64,
    fuzz_data_dir: std.fs.Dir,
    maybe_max_actions: ?usize,
) !void {
    var db = try createLedgerDB(allocator, fuzz_data_dir);
    defer db.deinit();

    var missing_actions: std.EnumSet(Action) = .initFull();
    var seed = initial_seed;
    var count: u64 = 0;
    outer: while (true) {
        var prng_state: std.Random.DefaultPrng = .init(seed);
        const prng = prng_state.random();

        // This is a simpler ledger which is used to make sure
        // the method calls being fuzzed return expected data.
        var data_map: std.AutoArrayHashMapUnmanaged(u32, Data) = .empty;
        defer {
            for (data_map.values()) |data| allocator.free(data.value);
            data_map.deinit(allocator);
        }

        for (0..1_000) |_| {
            if (maybe_max_actions) |max| {
                const actual_max = @max(MIN_ACTION_COUNT, max);
                if (count >= actual_max) {
                    logger.info().logf("reached max actions: {}\n", .{actual_max});
                    break :outer;
                }
            }

            const action = while (true) {
                const action = prng.enumValue(Action);
                if (missing_actions.count() == 0) break action;
                if (missing_actions.contains(action)) break action;
            };
            missing_actions.remove(action);
            switch (action) {
                .put => try dbPut(allocator, &data_map, &db, prng),
                .get => try dbGet(allocator, &data_map, &db, prng),
                .get_bytes => try dbGetBytes(allocator, &data_map, &db, prng),
                .count => try dbCount(&data_map, &db),
                .contains => try dbContains(allocator, &data_map, &db, prng),
                .delete => try dbDelete(allocator, &data_map, &db, prng),
                .batch => try batchAPI(allocator, &data_map, &db, prng),
            }

            count += 1;
        }
        seed += 1;
        logger.debug().logf("using seed: {}\n", .{seed});
    }

    if (missing_actions.count() != 0) {
        std.debug.panic("This shouldn't be possible.", .{});
    }
}

fn dbPut(
    allocator: std.mem.Allocator,
    data_map: *std.AutoArrayHashMapUnmanaged(u32, Data),
    db: *LedgerDB,
    random: std.Random,
) !void {
    const key = random.int(u32);

    // Fill the buffer with random bytes
    var buffer: [61]u8 = undefined;
    random.bytes(&buffer);

    const data: Data = .{ .value = try allocator.dupe(u8, &buffer) };
    errdefer data.deinit(allocator);
    try db.put(cf1, key, data);
    try data_map.put(allocator, key, data);
}

fn dbGet(
    allocator: std.mem.Allocator,
    data_map: *const std.AutoArrayHashMapUnmanaged(u32, Data),
    db: *LedgerDB,
    random: std.Random,
) !void {
    const data_keys = try getKeys(allocator, data_map);
    defer allocator.free(data_keys);

    if (data_keys.len > 0 and random.boolean()) {
        const random_index = random.uintLessThan(usize, data_keys.len);
        const key = data_keys[random_index];
        const expected = data_map.get(key) orelse return error.KeyNotFoundError;

        const actual: Data = try db.get(allocator, cf1, key) orelse return error.KeyNotFoundError;
        defer actual.deinit(allocator);
        try std.testing.expect(std.mem.eql(u8, expected.value, actual.value));
    } else {
        // If there are no keys, we should get a null value.
        var key: u32 = random.int(u32);
        while (data_map.contains(key)) key = random.int(u32);

        const actual: ?Data = try db.get(allocator, cf1, key);
        defer if (actual) |unwrapped| unwrapped.deinit(allocator); // shouldn't happen, but if it does, nice to avoid a leak in the stacktrace
        try std.testing.expectEqual(null, actual);
    }
}

fn dbGetBytes(
    allocator: std.mem.Allocator,
    data_map: *const std.AutoArrayHashMapUnmanaged(u32, Data),
    db: *LedgerDB,
    random: std.Random,
) !void {
    const data_keys = try getKeys(allocator, data_map);
    defer allocator.free(data_keys);

    if (data_keys.len > 0 and random.boolean()) {
        const random_index = random.uintLessThan(usize, data_keys.len);
        const key = data_keys[random_index];
        const expected = data_map.get(key) orelse return error.KeyNotFoundError;

        const actual_bytes = try db.getBytes(cf1, key) orelse return error.KeyNotFoundError;
        defer actual_bytes.deinit();

        const actual: Data = try ledger.database.value_serializer.deserialize(
            cf1.Value,
            allocator,
            actual_bytes.data,
        );
        defer actual.deinit(allocator);

        try std.testing.expectEqualSlices(u8, expected.value, actual.value);
    } else {
        // If there are no keys, we should get a null value.
        var key: u32 = random.int(u32);
        while (data_map.contains(key)) key = random.int(u32);

        const actual = try db.getBytes(cf1, key);
        defer if (actual) |unwrapped| unwrapped.deinit(); // shouldn't happen, but if it does, nice to avoid a leak in the stacktrace
        try std.testing.expectEqual(null, actual);
    }
}

fn dbCount(
    data_map: *const std.AutoArrayHashMapUnmanaged(u32, Data),
    db: *LedgerDB,
) !void {
    // TODO Fix why changes are not reflected in count with rocksdb implementation,
    // but it does with hashmap.
    if (sig.build_options.ledger_db == .rocksdb) {
        return;
    }

    const expected = data_map.count();
    const actual = try db.count(cf1);

    try std.testing.expectEqual(expected, actual);
}

fn dbContains(
    allocator: std.mem.Allocator,
    data_map: *const std.AutoArrayHashMapUnmanaged(u32, Data),
    db: *LedgerDB,
    random: std.Random,
) !void {
    const data_keys = try getKeys(allocator, data_map);
    defer allocator.free(data_keys);

    if (data_keys.len > 0 and random.boolean()) {
        const random_index = random.uintLessThan(usize, data_keys.len);
        const key = data_keys[random_index];

        const actual = try db.contains(cf1, key);
        try std.testing.expect(actual);
    } else {
        // If there are no keys, we should get a null value.
        var key: u32 = random.int(u32);
        while (data_map.contains(key)) key = random.int(u32);

        const actual = try db.contains(cf1, key);
        try std.testing.expect(!actual);
    }
}

fn dbDelete(
    allocator: std.mem.Allocator,
    data_map: *std.AutoArrayHashMapUnmanaged(u32, Data),
    db: *LedgerDB,
    random: std.Random,
) !void {
    const data_keys = try getKeys(allocator, data_map);
    defer allocator.free(data_keys);

    if (data_keys.len > 0 and random.boolean()) {
        const random_index = random.uintLessThan(usize, data_keys.len);
        const key = data_keys[random_index];

        try db.delete(cf1, key);

        const actual = try db.get(allocator, cf1, key) orelse null;
        defer if (actual) |unwrapped| unwrapped.deinit(allocator); // shouldn't happen, but if it does, nice to avoid a leak in the stacktrace
        try std.testing.expectEqual(null, actual);

        // Remove the keys from the map.
        const data = data_map.fetchSwapRemove(key).?.value; // if this panics, something is very wrong
        defer data.deinit(allocator);
    } else {
        var key: u32 = random.int(u32);
        while (data_map.contains(key)) key = random.int(u32);
        try db.delete(cf1, key);
    }
}

// Batch API
fn batchAPI(
    allocator: std.mem.Allocator,
    data_map: *std.AutoArrayHashMapUnmanaged(u32, Data),
    db: *LedgerDB,
    random: std.Random,
) !void {
    // Batch put
    {
        var batch = try db.initWriteBatch();
        defer batch.deinit();

        const start_key = random.int(u32);
        const end_key = start_key +| random.int(u8);
        for (start_key..end_key) |key| {
            // Fill the buffer with random bytes for each key.
            var buffer: [61]u8 = undefined;
            random.bytes(&buffer);

            const data: Data = .{ .value = try allocator.dupe(u8, &buffer) };
            errdefer data.deinit(allocator);

            try batch.put(cf1, key, data);
            try data_map.put(allocator, @as(u32, @intCast(key)), data);
        }

        // Commit batch put.
        // Note: Returns void so no confirmation needed.
        try db.commit(&batch);

        for (data_map.keys(), data_map.values()) |entry_key, expected| {
            const actual: Data = try db.get(
                allocator,
                cf1,
                entry_key,
            ) orelse return error.KeyNotFoundError;
            defer actual.deinit(allocator);
            try std.testing.expectEqualSlices(u8, expected.value, actual.value);
        }
    }

    // Batch delete.
    {
        var batch = try db.initWriteBatch();
        defer batch.deinit();

        const start_key = random.int(u32);
        const end_key = start_key +| random.int(u8);
        for (start_key..end_key) |key| {
            // Fill the buffer with random bytes for each key.
            var buffer: [61]u8 = undefined;
            random.bytes(&buffer);

            const data: Data = .{ .value = &buffer };
            try batch.put(cf1, key, data);
            try batch.delete(cf1, key);
        }

        // Commit batch put and delete.
        // Note: Returns void so no confirmation needed.
        try db.commit(&batch);

        for (start_key..end_key) |key| {
            const actual: ?Data = try db.get(allocator, cf1, @as(u32, @intCast(key)));
            defer if (actual) |unwrapped| unwrapped.deinit(allocator);
            try std.testing.expectEqual(null, actual);
        }
    }

    // Batch delete range.
    {
        const start_key = random.int(u32);
        const end_key = start_key +| random.int(u8);
        var batch = try db.initWriteBatch();
        defer batch.deinit();
        for (start_key..end_key) |key| {
            // Fill the buffer with random bytes for each key.
            var buffer: [61]u8 = undefined;
            random.bytes(&buffer);

            const data: Data = .{ .value = &buffer };
            try batch.put(cf1, key, data);
        }

        try batch.deleteRange(cf1, start_key, end_key);

        // Commit batch put and delete range.
        // Note: Returns void so no confirmation needed.
        try db.commit(&batch);
        for (start_key..end_key) |key| {
            const actual = try db.get(allocator, cf1, @as(u32, @intCast(key)));
            try std.testing.expectEqual(null, actual);
        }
    }
}

test run {
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    try runInner(std.testing.allocator, .noop, 0, tmp_dir.dir, 100);
}
