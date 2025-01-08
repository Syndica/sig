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
pub const BlockstoreDB = switch (build_options.blockstore_db) {
    .rocksdb => ledger.database.RocksDB(&.{cf1}),
    .hashmap => ledger.database.SharedHashMapDB(&.{cf1}),
};

pub fn run(seed: u64, args: *std.process.ArgIterator) !void {
    const maybe_max_actions_string = args.next();
    const maybe_max_actions = blk: {
        if (maybe_max_actions_string) |max_actions_str| {
            break :blk try std.fmt.parseInt(usize, max_actions_str, 10);
        } else {
            break :blk null;
        }
    };

    // NOTE: change to trace for full logs
    var std_logger = sig.trace.DirectPrintLogger.init(
        allocator,
        .debug,
    );
    const logger = std_logger.logger();

    var prng = std.rand.DefaultPrng.init(seed);
    const random = prng.random();

    const rocksdb_path =
        try std.fmt.allocPrint(allocator, "{s}/ledger/rocksdb", .{sig.FUZZ_DATA_DIR});

    // ensure we start with a clean slate.
    if (std.fs.cwd().access(rocksdb_path, .{})) |_| {
        try std.fs.cwd().deleteTree(rocksdb_path);
    } else |_| {}
    try std.fs.cwd().makePath(rocksdb_path);

    var db = try BlockstoreDB.open(
        allocator,
        logger,
        rocksdb_path,
    );

    defer db.deinit();

    const functions = .{
        dbPut,
        dbDelete,
        dbDeleteFilesInRange,
        dbGetBytes,
        dbGet,
        dbCount,
        dbContains,
        // Batch API
        batchDeleteRange,
    };

    inline for (functions) |function| {
        const fn_args = .{ &db, &random, maybe_max_actions };
        _ = try @call(.auto, function, fn_args);
    }
}

fn performDbAction(
    action_name: []const u8,
    comptime func: anytype,
    args: anytype,
    max_actions: ?usize,
) !void {
    var count: u64 = 0;
    var last_print_msg_count: u64 = 0;

    while (true) {
        if (max_actions) |max| {
            if (count >= max) {
                std.debug.print("{s} reached max actions: {}\n", .{ action_name, max });
                break;
            }
        }

        _ = try @call(.auto, func, args);
        if ((count - last_print_msg_count) >= 1_000) {
            std.debug.print("{d} {s} actions\n", .{ count, action_name });
            last_print_msg_count = count;
        }

        count += 1;
    }
}

fn dbPut(
    db: *BlockstoreDB,
    random: *const std.rand.Random,
    max_actions: ?usize,
) !void {
    const key = random.int(u32);
    var buffer: [61]u8 = undefined;
    // Fill the buffer with random bytes
    for (0..buffer.len) |i| {
        buffer[i] = @intCast(random.int(u8));
    }
    const value: []const u8 = buffer[0..];
    try performDbAction(
        "RocksDb.put",
        BlockstoreDB.put,
        .{ db, cf1, (key + 1), Data{ .value = value } },
        max_actions,
    );
}

fn dbDelete(
    db: *BlockstoreDB,
    random: *const std.rand.Random,
    max_actions: ?usize,
) !void {
    const key = random.int(u32);
    try performDbAction(
        "RocksDb.delete",
        BlockstoreDB.delete,
        .{ db, cf1, key },
        max_actions,
    );
}

fn dbDeleteFilesInRange(
    db: *BlockstoreDB,
    random: *const std.rand.Random,
    max_actions: ?usize,
) !void {
    const start = random.int(u32);
    const end = blk: {
        const end_ = random.int(u32);
        if (end_ < start)
            break :blk (end_ +| start)
        else
            break :blk end_;
    };

    try performDbAction(
        "RocksDb.deleteFilesInRange",
        BlockstoreDB.deleteFilesInRange,
        .{ db, cf1, start, end },
        max_actions,
    );
}

fn dbGetBytes(
    db: *BlockstoreDB,
    random: *const std.rand.Random,
    max_actions: ?usize,
) !void {
    const key = random.int(u32);
    try performDbAction(
        "RocksDb.getBytes",
        BlockstoreDB.getBytes,
        .{ db, cf1, key },
        max_actions,
    );
}

fn dbGet(
    db: *BlockstoreDB,
    random: *const std.rand.Random,
    max_actions: ?usize,
) !void {
    const key = random.int(u32);
    try performDbAction(
        "RocksDb.get",
        BlockstoreDB.get,
        .{ db, allocator, cf1, key },
        max_actions,
    );
}

fn dbCount(
    db: *BlockstoreDB,
    // Unused. Listed to allow uniform call
    // via @call with the rest of the functions.
    _: *const std.rand.Random,
    max_actions: ?usize,
) !void {
    try performDbAction(
        "RocksDb.count",
        BlockstoreDB.count,
        .{ db, cf1 },
        max_actions,
    );
}

fn dbContains(
    db: *BlockstoreDB,
    random: *const std.rand.Random,
    max_actions: ?usize,
) !void {
    const key = random.int(u32);
    try performDbAction(
        "RocksDb.contains",
        BlockstoreDB.contains,
        .{ db, cf1, key },
        max_actions,
    );
}

// Batch API
fn batchDeleteRange(
    db: *BlockstoreDB,
    random: *const std.rand.Random,
    max_actions: ?usize,
) !void {
    var count: u64 = 0;
    var last_print_msg_count: u64 = 0;
    while (true) {
        if (max_actions) |max| {
            if (count >= max) {
                std.debug.print("Batch actions reached max actions: {}\n", .{max});
                break;
            }
        }
        const start = random.int(u32);
        const end = blk: {
            const end_ = random.int(u32);
            if (end_ < start)
                break :blk (end_ +| start)
            else
                break :blk end_;
        };

        const key = random.int(u32);
        var buffer: [61]u8 = undefined;

        // Fill the buffer with random bytes
        for (0..buffer.len) |i| {
            buffer[i] = @intCast(random.int(u8));
        }

        const value: []const u8 = buffer[0..];

        var batch = try db.initWriteBatch();
        defer batch.deinit();

        try batch.put(cf1, key, Data{ .value = value });
        try batch.deleteRange(cf1, start, end);
        try batch.delete(cf1, key);
        try db.commit(&batch);

        if ((count - last_print_msg_count) >= 1_000) {
            std.debug.print("{d} Batch actions\n", .{count});
            last_print_msg_count = count;
        }

        count += 1;
    }
}
