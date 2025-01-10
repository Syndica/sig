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

var dataMap = std.AutoHashMap(u32, Data).init(allocator);
var dataKeys = std.ArrayList(u32).init(allocator);

pub const BlockstoreDB = switch (build_options.blockstore_db) {
    .rocksdb => ledger.database.RocksDB(&.{cf1}),
    .hashmap => ledger.database.SharedHashMapDB(&.{cf1}),
};

fn createBlockstoreDB() !BlockstoreDB {
    const rocksdb_path =
        try std.fmt.allocPrint(allocator, "{s}/ledger/rocksdb", .{sig.FUZZ_DATA_DIR});

    // ensure we start with a clean slate.
    if (std.fs.cwd().access(rocksdb_path, .{})) |_| {
        try std.fs.cwd().deleteTree(rocksdb_path);
    } else |_| {}
    try std.fs.cwd().makePath(rocksdb_path);

    return try BlockstoreDB.open(
        allocator,
        .noop,
        rocksdb_path,
    );
}

pub fn run(seed: u64, args: *std.process.ArgIterator) !void {
    const maybe_max_actions_string = args.next();
    const maybe_max_actions = blk: {
        if (maybe_max_actions_string) |max_actions_str| {
            break :blk try std.fmt.parseInt(usize, max_actions_str, 10);
        } else {
            break :blk null;
        }
    };

    var prng = std.rand.DefaultPrng.init(seed);
    const random = prng.random();

    const rocksdb_path =
        try std.fmt.allocPrint(allocator, "{s}/ledger/rocksdb", .{sig.FUZZ_DATA_DIR});

    // ensure we start with a clean slate.
    if (std.fs.cwd().access(rocksdb_path, .{})) |_| {
        try std.fs.cwd().deleteTree(rocksdb_path);
    } else |_| {}
    try std.fs.cwd().makePath(rocksdb_path);

    var db = try createBlockstoreDB();

    defer db.deinit();

    const functions = .{
        dbPut,
        dbGet,
        dbGetBytes,
        dbCount,
        dbContains,
        dbDelete,
        dbDeleteFilesInRange,
        // Batch API
        // - batch.put
        // - batch.delete
        // - batch.deleteRange
        batchAPI,
    };

    inline for (functions) |function| {
        const fn_args = .{ &db, random, maybe_max_actions };
        _ = try @call(.auto, function, fn_args);
    }
}

fn dbPut(
    db: *BlockstoreDB,
    random: std.rand.Random,
    max_actions: ?usize,
) !void {
    var count: u64 = 0;
    var last_print_msg_count: u64 = 0;
    const action_name = "put";

    while (true) {
        if (max_actions) |max| {
            if (count >= max) {
                std.debug.print("{s} reached max actions: {}\n", .{ action_name, max });
                break;
            }
        }

        const key = random.int(u32);
        var buffer: [61]u8 = undefined;

        // Fill the buffer with random bytes
        for (0..buffer.len) |i| {
            buffer[i] = @intCast(random.int(u8));
        }

        const value: []const u8 = try allocator.dupe(u8, buffer[0..]);
        const data = Data{ .value = value };

        try db.put(cf1, key, data);
        try dataMap.put(key, data);
        try dataKeys.append(key);

        if ((count - last_print_msg_count) >= 1_000) {
            std.debug.print("{d} {s} actions\n", .{ count, action_name });
            last_print_msg_count = count;
        }

        count += 1;
    }
}

fn dbGet(
    db: *BlockstoreDB,
    random: std.rand.Random,
    max_actions: ?usize,
) !void {
    var count: u64 = 0;
    var last_print_msg_count: u64 = 0;
    const action_name = "get";

    while (true) {
        if (max_actions) |max| {
            if (count >= max) {
                std.debug.print("{s} reached max actions: {}\n", .{ action_name, max });
                break;
            }
        }

        const random_index = random.uintLessThan(usize, dataKeys.items.len);
        const key = dataKeys.items[random_index];
        const expected = dataMap.get(key) orelse return error.KeyNotFoundError;

        const actual = try db.get(allocator, cf1, key) orelse return error.KeyNotFoundError;

        try std.testing.expect(std.mem.eql(u8, expected.value, actual.value));
        if ((count - last_print_msg_count) >= 1_000) {
            std.debug.print("{d} {s} actions\n", .{ count, action_name });
            last_print_msg_count = count;
        }

        count += 1;
    }
}

fn dbGetBytes(
    db: *BlockstoreDB,
    random: std.rand.Random,
    max_actions: ?usize,
) !void {
    var count: u64 = 0;
    var last_print_msg_count: u64 = 0;
    const action_name = "getBytes";

    while (true) {
        if (max_actions) |max| {
            if (count >= max) {
                std.debug.print("{s} reached max actions: {}\n", .{ action_name, max });
                break;
            }
        }

        const random_index = random.uintLessThan(usize, dataKeys.items.len);
        const key = dataKeys.items[random_index];
        const expected = dataMap.get(key) orelse return error.KeyNotFoundError;

        const actualBytes = try db.getBytes(cf1, key) orelse return error.KeyNotFoundError;
        const actual = try ledger.database.value_serializer.deserialize(cf1.Value, allocator, actualBytes.data);

        try std.testing.expect(std.mem.eql(u8, expected.value, actual.value));
        if ((count - last_print_msg_count) >= 1_000) {
            std.debug.print("{d} {s} actions\n", .{ count, action_name });
            last_print_msg_count = count;
        }

        count += 1;
    }
}

fn dbCount(
    db: *BlockstoreDB,
    // Unused. Listed to allow uniform call
    // via @call with the rest of the functions.
    _: std.rand.Random,
    max_actions: ?usize,
) !void {
    // TODO Fix why changes are not reflected in count with rocksdb implementation,
    // but it does with hashmap.
    if (build_options.blockstore_db == .rocksdb) {
        return;
    }

    var count: u64 = 0;
    var last_print_msg_count: u64 = 0;
    const action_name = "count";

    while (true) {
        if (max_actions) |max| {
            if (count >= max) {
                std.debug.print("{s} reached max actions: {}\n", .{ action_name, max });
                break;
            }
        }

        const expected = dataKeys.items.len;
        const actual = try db.count(cf1);

        try std.testing.expectEqual(expected, actual);
        if ((count - last_print_msg_count) >= 1_000) {
            std.debug.print("{d} {s} actions\n", .{ count, action_name });
            last_print_msg_count = count;
        }

        count += 1;
    }
}

fn dbContains(
    db: *BlockstoreDB,
    random: std.rand.Random,
    max_actions: ?usize,
) !void {
    var count: u64 = 0;
    var last_print_msg_count: u64 = 0;
    const action_name = "contains";

    while (true) {
        if (max_actions) |max| {
            if (count >= max) {
                std.debug.print("{s} reached max actions: {}\n", .{ action_name, max });
                break;
            }
        }

        const random_index = random.uintLessThan(usize, dataKeys.items.len);
        const key = dataKeys.items[random_index];

        const actual = try db.contains(cf1, key);

        try std.testing.expect(actual);
        if ((count - last_print_msg_count) >= 1_000) {
            std.debug.print("{d} {s} actions\n", .{ count, action_name });
            last_print_msg_count = count;
        }

        count += 1;
    }
}

fn dbDeleteFilesInRange(
    db: *BlockstoreDB,
    random: std.rand.Random,
    max_actions: ?usize,
) !void {
    // deleteFilesInRange is not implemented in hashmap implementation.
    if (build_options.blockstore_db == .hashmap) {
        return;
    }
    var count: u64 = 0;
    var last_print_msg_count: u64 = 0;
    const action_name = "deleteFilesInRange";

    while (true) {
        if (max_actions) |max| {
            if (count >= max) {
                std.debug.print("{s} reached max actions: {}\n", .{ action_name, max });
                break;
            }
        }

        const random_index = random.uintLessThan(usize, dataKeys.items.len);
        const startKey = dataKeys.items[random_index];
        const endKey = startKey +| @as(u32, random.int(u8));

        try db.deleteFilesInRange(cf1, startKey, endKey);
        // Need to flush memtable to disk to be able to see result of deleteFilesInRange.
        // We do that by deiniting the current db, which triggers the flushing.
        db.deinit();
        db.* = try createBlockstoreDB();

        for (startKey..endKey) |key| {
            const actual = try db.get(allocator, cf1, key) orelse null;
            try std.testing.expectEqual(null, actual);
        }

        if ((count - last_print_msg_count) >= 1_000) {
            std.debug.print("{d} {s} actions\n", .{ count, action_name });
            last_print_msg_count = count;
        }

        count += 1;
    }
}

fn dbDelete(
    db: *BlockstoreDB,
    random: std.rand.Random,
    max_actions: ?usize,
) !void {
    var count: u64 = 0;
    var last_print_msg_count: u64 = 0;
    const action_name = "delete";

    while (true) {
        if (max_actions) |max| {
            if (count >= max) {
                std.debug.print("{s} reached max actions: {}\n", .{ action_name, max });
                break;
            }
        }

        const random_index = random.uintLessThan(usize, dataKeys.items.len);
        const key = dataKeys.items[random_index];

        try db.delete(cf1, key);

        const actual = try db.get(allocator, cf1, key) orelse null;
        try std.testing.expectEqual(null, actual);

        if ((count - last_print_msg_count) >= 1_000) {
            std.debug.print("{d} {s} actions\n", .{ count, action_name });
            last_print_msg_count = count;
        }

        count += 1;
    }
}

// Batch API
fn batchAPI(
    db: *BlockstoreDB,
    random: std.rand.Random,
    max_actions: ?usize,
) !void {
    // Repurpose the gloabl map.
    dataMap.clearAndFree();

    var count: u64 = 0;
    var last_print_msg_count: u64 = 0;
    while (true) {
        if (max_actions) |max| {
            if (count >= max) {
                std.debug.print("Batch actions reached max actions: {}\n", .{max});
                break;
            }
        }

        // Batch put
        {
            const startKey = random.int(u32);
            const endKey = startKey +| @as(u32, random.int(u8));
            var buffer: [61]u8 = undefined;
            var batch = try db.initWriteBatch();
            defer batch.deinit();
            defer dataMap.clearAndFree();
            for (startKey..endKey) |key| {
                // Fill the buffer with random bytes for each key.
                for (0..buffer.len) |i| {
                    buffer[i] = @intCast(random.int(u8));
                }

                const value: []const u8 = try allocator.dupe(u8, buffer[0..]);
                const data = Data{ .value = value };

                try batch.put(cf1, key, data);
                try dataMap.put(@as(u32, @intCast(key)), data);
            }
            // Commit batch put.
            try db.commit(&batch);
            var it = dataMap.iterator();
            while (it.next()) |entry| {
                const entryKey = entry.key_ptr.*;
                const expected = entry.value_ptr.*;
                const actual = try db.get(allocator, cf1, entryKey) orelse return error.KeyNotFoundError;
                try std.testing.expect(std.mem.eql(u8, expected.value, actual.value));
            }
        }

        // Batch delete.
        {
            const startKey = random.int(u32);
            const endKey = startKey +| @as(u32, random.int(u8));
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
            try db.commit(&batch);
            for (startKey..endKey) |key| {
                const actual = try db.get(allocator, cf1, @as(u32, @intCast(key)));
                try std.testing.expectEqual(null, actual);
            }
        }

        // Batch delete range.
        {
            const startKey = random.int(u32);
            const endKey = startKey +| @as(u32, random.int(u8));
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
            try db.commit(&batch);
            for (startKey..endKey) |key| {
                const actual = try db.get(allocator, cf1, @as(u32, @intCast(key)));
                try std.testing.expectEqual(null, actual);
            }
        }

        if ((count - last_print_msg_count) >= 1_000) {
            std.debug.print("{d} Batch actions\n", .{count});
            last_print_msg_count = count;
        }

        count += 1;
    }
}
