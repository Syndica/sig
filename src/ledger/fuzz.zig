const std = @import("std");
const sig = @import("../sig.zig");
const build_options = @import("build-options");
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

// Note: This is a simpler blockstore which is used to make sure
// the method calls being fuzzed return expected data.
var data_map = std.AutoHashMap(u32, Data).init(allocator);
var executed_actions = std.AutoHashMap(Actions, void).init(allocator);

pub const BlockstoreDB = switch (build_options.blockstore_db) {
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

fn getKeys(map: *std.AutoHashMap(u32, Data)) !std.ArrayList(u32) {
    var keys = std.ArrayList(u32).init(allocator);
    var it = map.iterator();
    while (it.next()) |entry| {
        try keys.append(entry.key_ptr.*);
    }
    return keys;
}

fn createBlockstoreDB() !BlockstoreDB {
    const ledger_path =
        try std.fmt.allocPrint(allocator, "{s}/ledger", .{sig.FUZZ_DATA_DIR});

    // ensure we start with a clean slate.
    if (std.fs.cwd().access(ledger_path, .{})) |_| {
        try std.fs.cwd().deleteTree(ledger_path);
    } else |_| {}
    try std.fs.cwd().makePath(ledger_path);

    return try BlockstoreDB.open(
        allocator,
        .noop,
        ledger_path,
    );
}

pub fn run(seed: u64, args: *std.process.ArgIterator) !void {
    const maybe_max_actions_string = args.next();

    const maybe_max_actions = if (maybe_max_actions_string) |max_actions_str|
        try std.fmt.parseInt(usize, max_actions_str, 10)
    else
        null;

    var prng = std.rand.DefaultPrng.init(seed);
    const random = prng.random();

    const ledger_path =
        try std.fmt.allocPrint(allocator, "{s}/ledger", .{sig.FUZZ_DATA_DIR});

    // ensure we start with a clean slate.
    if (std.fs.cwd().access(ledger_path, .{})) |_| {
        try std.fs.cwd().deleteTree(ledger_path);
    } else |_| {}
    try std.fs.cwd().makePath(ledger_path);

    var db = try createBlockstoreDB();

    defer db.deinit();

    var count: u64 = 0;

    while (true) {
        if (maybe_max_actions) |max| {
            if (count >= max) {
                std.debug.print("{s} reached max actions: {}\n", .{ "action_name", max });
                break;
            }
        }

        const action = random.enumValue(enum {
            put,
            get,
            get_bytes,
            count,
            contains,
            delete,
            batch,
        });

        switch (action) {
            .put => try dbPut(&db, random),
            .get => try dbGet(&db, random),
            .get_bytes => try dbGetBytes(&db, random),
            .count => try dbCount(&db),
            .contains => try dbContains(&db, random),
            .delete => try dbDelete(&db, random),
            .batch => try batchAPI(&db, random),
        }

        count += 1;
    }

    inline for (@typeInfo(Actions).Enum.fields) |field| {
        const variant = @field(Actions, field.name);
        if (!executed_actions.contains(variant)) {
            std.debug.print("Action: '{s}' not executed by the fuzzer", .{@tagName(variant)});
            return error.NonExhaustive;
        }
    }
}

fn dbPut(
    db: *BlockstoreDB,
    random: std.rand.Random,
) !void {
    try executed_actions.put(Actions.put, void{});
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

fn dbGet(
    db: *BlockstoreDB,
    random: std.rand.Random,
) !void {
    try executed_actions.put(Actions.get, void{});
    const dataKeys = try getKeys(&data_map);
    if (dataKeys.items.len > 0) {
        const random_index = random.uintLessThan(usize, dataKeys.items.len);
        const key = dataKeys.items[random_index];
        const expected = data_map.get(key) orelse return error.KeyNotFoundError;

        const actual = try db.get(allocator, cf1, key) orelse return error.KeyNotFoundError;

        try std.testing.expect(std.mem.eql(u8, expected.value, actual.value));
    } else {
        // If there are no keys, we should get a null value.
        const key = random.int(u32);
        const actual = try db.get(allocator, cf1, key);
        try std.testing.expectEqual(null, actual);
    }
}

fn dbGetBytes(
    db: *BlockstoreDB,
    random: std.rand.Random,
) !void {
    try executed_actions.put(Actions.get_bytes, void{});
    const dataKeys = try getKeys(&data_map);
    if (dataKeys.items.len > 0) {
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
        const key = random.int(u32);
        const actual = try db.getBytes(cf1, key);
        try std.testing.expectEqual(null, actual);
    }
}

fn dbCount(
    db: *BlockstoreDB,
) !void {
    try executed_actions.put(Actions.count, void{});
    // TODO Fix why changes are not reflected in count with rocksdb implementation,
    // but it does with hashmap.
    if (build_options.blockstore_db == .rocksdb) {
        return;
    }

    const expected = data_map.count();
    const actual = try db.count(cf1);

    try std.testing.expectEqual(expected, actual);
}

fn dbContains(
    db: *BlockstoreDB,
    random: std.rand.Random,
) !void {
    try executed_actions.put(Actions.contains, void{});
    const dataKeys = try getKeys(&data_map);
    if (dataKeys.items.len > 0) {
        const random_index = random.uintLessThan(usize, dataKeys.items.len);
        const key = dataKeys.items[random_index];

        const actual = try db.contains(cf1, key);

        try std.testing.expect(actual);
    } else {
        // If there are no keys, we should get a null value.
        const key = random.int(u32);
        const actual = try db.contains(cf1, key);
        try std.testing.expect(!actual);
    }
}

fn dbDelete(
    db: *BlockstoreDB,
    random: std.rand.Random,
) !void {
    try executed_actions.put(Actions.delete, void{});
    const dataKeys = try getKeys(&data_map);
    if (dataKeys.items.len > 0) {
        const random_index = random.uintLessThan(usize, dataKeys.items.len);
        const key = dataKeys.items[random_index];

        try db.delete(cf1, key);

        const actual = try db.get(allocator, cf1, key) orelse null;
        try std.testing.expectEqual(null, actual);
        // Remove the keys from the global map.
        _ = data_map.remove(key);
    } else {
        // If there are no keys, we should get a null value.
        const key = random.int(u32);
        try db.delete(cf1, key);
    }
}

// Batch API
fn batchAPI(
    db: *BlockstoreDB,
    random: std.rand.Random,
) !void {
    try executed_actions.put(Actions.batch, void{});
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
