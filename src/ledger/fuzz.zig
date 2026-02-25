const std = @import("std");
const sig = @import("../sig.zig");
const ledger = @import("lib.zig");

const ColumnFamily = sig.ledger.database.ColumnFamily;

const allocator = std.heap.c_allocator;

const Data = struct {
    value: []const u8,
};

const cf1 = ColumnFamily{
    .name = "data",
    .Key = u64,
    .Value = Data,
};

var executed_actions = std.AutoHashMap(Actions, void).init(allocator);

pub const LedgerDB = switch (sig.build_options.ledger_db) {
    .rocksdb => ledger.database.RocksDB(&.{cf1}),
    .hashmap => ledger.database.SharedHashMapDB(&.{cf1}),
};

// Note: deleteFilesInRange is not included in the fuzzing as it is not
// implemented in the hashmap implementation, and the RocksDB implementation
// requires manual flushing of the memtable to disk to make the changes visible.
const Actions = enum {
    put,
    get,
    get_bytes,
    count,
    contains,
    delete,
    batch,
};

fn getKeys(map: *std.AutoHashMap(u32, Data)) !std.array_list.Managed(u32) {
    var keys = std.array_list.Managed(u32).init(allocator);
    var it = map.iterator();
    while (it.next()) |entry| {
        try keys.append(entry.key_ptr.*);
    }
    return keys;
}

fn createLedgerDB() !LedgerDB {
    const ledger_path =
        try std.fmt.allocPrint(allocator, "{s}/ledger", .{sig.FUZZ_DATA_DIR});

    // ensure we start with a clean slate.
    if (std.fs.cwd().access(ledger_path, .{})) |_| {
        try std.fs.cwd().deleteTree(ledger_path);
    } else |_| {}
    try std.fs.cwd().makePath(ledger_path);

    return try LedgerDB.open(
        allocator,
        .noop,
        ledger_path,
        false,
    );
}

pub fn run(initial_seed: u64, args: []const []const u8, log: bool) !void {
    const maybe_max_actions_string: ?[]const u8 = if (args.len == 0) null else args[0];

    const maybe_max_actions = if (maybe_max_actions_string) |max_actions_str|
        try std.fmt.parseInt(usize, max_actions_str, 10)
    else
        null;

    try runInner(initial_seed, maybe_max_actions, log);
}

fn runInner(initial_seed: u64, maybe_max_actions: ?usize, log: bool) !void {
    var seed = initial_seed;

    const ledger_path =
        try std.fmt.allocPrint(allocator, "{s}/ledger", .{sig.FUZZ_DATA_DIR});

    // ensure we start with a clean slate.
    if (std.fs.cwd().access(ledger_path, .{})) |_| {
        try std.fs.cwd().deleteTree(ledger_path);
    } else |_| {}
    try std.fs.cwd().makePath(ledger_path);

    var db = try createLedgerDB();

    defer db.deinit();

    var count: u64 = 0;

    outer: while (true) {
        var prng = std.Random.DefaultPrng.init(seed);
        const random = prng.random();
        // This is a simpler ledger which is used to make sure
        // the method calls being fuzzed return expected data.
        var data_map = std.AutoHashMap(u32, Data).init(allocator);
        defer data_map.deinit();
        for (0..1_000) |_| {
            if (maybe_max_actions) |max| {
                if (count >= max) {
                    if (log) std.debug.print("reached max actions: {}\n", .{max});
                    break :outer;
                }
            }

            const action = random.enumValue(Actions);

            switch (action) {
                .put => try dbPut(&data_map, &db, random),
                .get => try dbGet(&data_map, &db, random),
                .get_bytes => try dbGetBytes(&data_map, &db, random),
                .count => try dbCount(&data_map, &db),
                .contains => try dbContains(&data_map, &db, random),
                .delete => try dbDelete(&data_map, &db, random),
                .batch => try batchAPI(&data_map, &db, random),
            }

            count += 1;
        }
        seed += 1;
        if (log) std.debug.print("using seed: {}\n", .{seed});
    }

    inline for (@typeInfo(Actions).@"enum".fields) |field| {
        const variant = @field(Actions, field.name);
        if (!executed_actions.contains(variant)) {
            std.debug.print("Action: '{s}' not executed by the fuzzer", .{@tagName(variant)});
            return error.NonExhaustive;
        }
    }
}

fn dbPut(data_map: *std.AutoHashMap(u32, Data), db: *LedgerDB, random: std.Random) !void {
    try executed_actions.put(Actions.put, {});
    const key = random.int(u32);
    var buffer: [61]u8 = undefined;

    // Fill the buffer with random bytes
    for (0..buffer.len) |i| {
        buffer[i] = @intCast(random.int(u8));
    }

    const value: []const u8 = try allocator.dupe(u8, buffer[0..]);
    const data = Data{ .value = value };

    try db.put(cf1, key, data);
    try data_map.put(key, data);
}

fn dbGet(data_map: *std.AutoHashMap(u32, Data), db: *LedgerDB, random: std.Random) !void {
    try executed_actions.put(Actions.get, {});
    const dataKeys = try getKeys(data_map);
    if (dataKeys.items.len > 0 and random.boolean()) {
        const random_index = random.uintLessThan(usize, dataKeys.items.len);
        const key = dataKeys.items[random_index];
        const expected = data_map.get(key) orelse return error.KeyNotFoundError;

        const actual = try db.get(allocator, cf1, key) orelse return error.KeyNotFoundError;

        try std.testing.expect(std.mem.eql(u8, expected.value, actual.value));
    } else {
        // If there are no keys, we should get a null value.
        var key: u32 = random.int(u32);
        while (data_map.contains(key)) key = random.int(u32);
        const actual = try db.get(allocator, cf1, key);
        try std.testing.expectEqual(null, actual);
    }
}

fn dbGetBytes(data_map: *std.AutoHashMap(u32, Data), db: *LedgerDB, random: std.Random) !void {
    try executed_actions.put(Actions.get_bytes, {});
    const dataKeys = try getKeys(data_map);
    if (dataKeys.items.len > 0 and random.boolean()) {
        const random_index = random.uintLessThan(usize, dataKeys.items.len);
        const key = dataKeys.items[random_index];
        const expected = data_map.get(key) orelse return error.KeyNotFoundError;

        const actualBytes = try db.getBytes(cf1, key) orelse return error.KeyNotFoundError;
        const actual = try ledger.database.value_serializer.deserialize(
            cf1.Value,
            allocator,
            actualBytes.data,
        );

        try std.testing.expect(std.mem.eql(u8, expected.value, actual.value));
    } else {
        // If there are no keys, we should get a null value.
        var key: u32 = random.int(u32);
        while (data_map.contains(key)) key = random.int(u32);
        const actual = try db.getBytes(cf1, key);
        try std.testing.expectEqual(null, actual);
    }
}

fn dbCount(
    data_map: *std.AutoHashMap(u32, Data),
    db: *LedgerDB,
) !void {
    try executed_actions.put(Actions.count, {});
    // TODO Fix why changes are not reflected in count with rocksdb implementation,
    // but it does with hashmap.
    if (sig.build_options.ledger_db == .rocksdb) {
        return;
    }

    const expected = data_map.count();
    const actual = try db.count(cf1);

    try std.testing.expectEqual(expected, actual);
}

fn dbContains(data_map: *std.AutoHashMap(u32, Data), db: *LedgerDB, random: std.Random) !void {
    try executed_actions.put(Actions.contains, {});
    const dataKeys = try getKeys(data_map);
    if (dataKeys.items.len > 0 and random.boolean()) {
        const random_index = random.uintLessThan(usize, dataKeys.items.len);
        const key = dataKeys.items[random_index];

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

fn dbDelete(data_map: *std.AutoHashMap(u32, Data), db: *LedgerDB, random: std.Random) !void {
    try executed_actions.put(Actions.delete, {});
    const dataKeys = try getKeys(data_map);
    if (dataKeys.items.len > 0 and random.boolean()) {
        const random_index = random.uintLessThan(usize, dataKeys.items.len);
        const key = dataKeys.items[random_index];

        try db.delete(cf1, key);

        const actual = try db.get(allocator, cf1, key) orelse null;
        try std.testing.expectEqual(null, actual);
        // Remove the keys from the global map.
        _ = data_map.remove(key);
    } else {
        // If there are no keys, we should get a null value.
        var key: u32 = random.int(u32);
        while (data_map.contains(key)) key = random.int(u32);
        try db.delete(cf1, key);
    }
}

// Batch API
fn batchAPI(data_map: *std.AutoHashMap(u32, Data), db: *LedgerDB, random: std.Random) !void {
    try executed_actions.put(Actions.batch, {});
    // Batch put
    {
        const startKey = random.int(u32);
        const endKey = startKey +| random.int(u8);
        var buffer: [61]u8 = undefined;
        var batch = try db.initWriteBatch();
        defer batch.deinit();
        for (startKey..endKey) |key| {
            // Fill the buffer with random bytes for each key.
            for (0..buffer.len) |i| {
                buffer[i] = @intCast(random.int(u8));
            }

            const value: []const u8 = try allocator.dupe(u8, buffer[0..]);
            const data = Data{ .value = value };

            try batch.put(cf1, key, data);
            try data_map.put(@as(u32, @intCast(key)), data);
        }
        // Commit batch put.
        // Note: Returns void so no confirmation needed.
        try db.commit(&batch);
        var it = data_map.iterator();
        while (it.next()) |entry| {
            const entryKey = entry.key_ptr.*;
            const expected = entry.value_ptr.*;
            const actual = try db.get(
                allocator,
                cf1,
                entryKey,
            ) orelse return error.KeyNotFoundError;
            try std.testing.expect(std.mem.eql(u8, expected.value, actual.value));
        }
    }

    // Batch delete.
    {
        const startKey = random.int(u32);
        const endKey = startKey +| random.int(u8);
        var buffer: [61]u8 = undefined;
        var batch = try db.initWriteBatch();
        defer batch.deinit();
        for (startKey..endKey) |key| {
            // Fill the buffer with random bytes for each key.
            for (0..buffer.len) |i| {
                buffer[i] = @intCast(random.int(u8));
            }

            const value: []const u8 = try allocator.dupe(u8, buffer[0..]);
            const data = Data{ .value = value };

            try batch.put(cf1, key, data);
            try batch.delete(cf1, key);
        }
        // Commit batch put and delete.
        // Note: Returns void so no confirmation needed.
        try db.commit(&batch);
        for (startKey..endKey) |key| {
            const actual = try db.get(allocator, cf1, @as(u32, @intCast(key)));
            try std.testing.expectEqual(null, actual);
        }
    }

    // Batch delete range.
    {
        const startKey = random.int(u32);
        const endKey = startKey +| random.int(u8);
        var buffer: [61]u8 = undefined;
        var batch = try db.initWriteBatch();
        defer batch.deinit();
        for (startKey..endKey) |key| {
            // Fill the buffer with random bytes for each key.
            for (0..buffer.len) |i| {
                buffer[i] = @intCast(random.int(u8));
            }

            const value: []const u8 = try allocator.dupe(u8, buffer[0..]);
            const data = Data{ .value = value };

            try batch.put(cf1, key, data);
        }
        try batch.deleteRange(cf1, startKey, endKey);
        // Commit batch put and delete range.
        // Note: Returns void so no confirmation needed.
        try db.commit(&batch);
        for (startKey..endKey) |key| {
            const actual = try db.get(allocator, cf1, @as(u32, @intCast(key)));
            try std.testing.expectEqual(null, actual);
        }
    }
}

test run {
    try run(std.testing.random_seed, &.{"100"}, false);
}
