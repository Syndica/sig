const std = @import("std");
const sig = @import("../sig.zig");

const ColumnFamily = sig.ledger.database.ColumnFamily;
const AtomicU64 = std.atomic.Value(u64);

var total_action_count: AtomicU64 = AtomicU64.init(0);

const allocator = std.heap.c_allocator;

const Data = struct {
    value: []const u8,
};

const cf1 = ColumnFamily{
    .name = "data",
    .Key = u64,
    .Value = Data,
};
const RocksDb = sig.ledger.database.RocksDB(&.{cf1});

pub fn run(seed: u64, args: *std.process.ArgIterator) !void {
    const maybe_max_actions_string = args.next();
    const maybe_max_actions = blk: {
        if (maybe_max_actions_string) |max_actions_str| {
            break :blk try std.fmt.parseInt(usize, max_actions_str, 10);
        } else {
            break :blk null;
        }
    };
    defer {
        _ = total_action_count.fetchAdd(1, .monotonic);
    }

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

    var db: RocksDb = try RocksDb.open(
        allocator,
        logger,
        rocksdb_path,
    );

    defer db.deinit();

    {
        var db_put_thread = try std.Thread.spawn(
            .{},
            dbPut,
            .{ &db, &random, &total_action_count, maybe_max_actions },
        );
        defer db_put_thread.join();

        var db_delete_thread = try std.Thread.spawn(
            .{},
            dbDelete,
            .{ &db, &random, &total_action_count, maybe_max_actions },
        );
        defer db_delete_thread.join();

        var db_delete_files_in_range = try std.Thread.spawn(
            .{},
            dbDeleteFilesInRange,
            .{ &db, &random, &total_action_count, maybe_max_actions },
        );
        defer db_delete_files_in_range.join();

        var db_get_bytes_thread = try std.Thread.spawn(
            .{},
            dbGetBytes,
            .{ &db, &random, &total_action_count, maybe_max_actions },
        );
        defer db_get_bytes_thread.join();

        var db_get_thread = try std.Thread.spawn(
            .{},
            dbGet,
            .{ &db, &random, &total_action_count, maybe_max_actions },
        );
        defer db_get_thread.join();

        var db_count_thread = try std.Thread.spawn(
            .{},
            dbCount,
            .{ &db, &total_action_count, maybe_max_actions },
        );
        defer db_count_thread.join();

        var db_contains_thread = try std.Thread.spawn(
            .{},
            dbContains,
            .{ &db, &random, &total_action_count, maybe_max_actions },
        );
        defer db_contains_thread.join();

        // Batch API
        var batch_delete_range_thread = try std.Thread.spawn(
            .{},
            batchDeleteRange,
            .{ &db, &random, &total_action_count, maybe_max_actions },
        );
        defer batch_delete_range_thread.join();
    }
}

fn performDbAction(
    action_name: []const u8,
    comptime func: anytype,
    args: anytype,
    count: *std.atomic.Value(u64),
    max_actions: ?usize,
) !void {
    var last_print_msg_count: u64 = 0;

    while (true) {
        if (max_actions) |max| {
            if (count.load(.monotonic) >= max) {
                std.debug.print("{s} reached max actions: {}\n", .{ action_name, max });
                break;
            }
        }

        _ = try @call(.auto, func, args);
        const current_count = count.load(.monotonic);
        if ((current_count - last_print_msg_count) >= 1_000) {
            std.debug.print("{d} {s} actions\n", .{ current_count, action_name });
            last_print_msg_count = current_count;
        }

        _ = count.fetchAdd(1, .monotonic);
    }
}

fn dbPut(
    db: *RocksDb,
    random: *const std.rand.Random,
    count: *std.atomic.Value(u64),
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
        RocksDb.put,
        .{ db, cf1, (key + 1), Data{ .value = value } },
        count,
        max_actions,
    );
}

fn dbDelete(
    db: *RocksDb,
    random: *const std.rand.Random,
    count: *std.atomic.Value(u64),
    max_actions: ?usize,
) !void {
    const key = random.int(u32);
    try performDbAction(
        "RocksDb.delete",
        RocksDb.delete,
        .{ db, cf1, key },
        count,
        max_actions,
    );
}

fn dbDeleteFilesInRange(
    db: *RocksDb,
    random: *const std.rand.Random,
    count: *std.atomic.Value(u64),
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
        RocksDb.deleteFilesInRange,
        .{ db, cf1, start, end },
        count,
        max_actions,
    );
}

fn dbGetBytes(
    db: *RocksDb,
    random: *const std.rand.Random,
    count: *std.atomic.Value(u64),
    max_actions: ?usize,
) !void {
    const key = random.int(u32);
    try performDbAction(
        "RocksDb.getBytes",
        RocksDb.getBytes,
        .{ db, cf1, key },
        count,
        max_actions,
    );
}

fn dbGet(
    db: *RocksDb,
    random: *const std.rand.Random,
    count: *std.atomic.Value(u64),
    max_actions: ?usize,
) !void {
    const key = random.int(u32);
    try performDbAction(
        "RocksDb.get",
        RocksDb.get,
        .{ db, allocator, cf1, key },
        count,
        max_actions,
    );
}

fn dbCount(
    db: *RocksDb,
    count: *std.atomic.Value(u64),
    max_actions: ?usize,
) !void {
    try performDbAction(
        "RocksDb.count",
        RocksDb.count,
        .{ db, cf1 },
        count,
        max_actions,
    );
}

fn dbContains(
    db: *RocksDb,
    random: *const std.rand.Random,
    count: *std.atomic.Value(u64),
    max_actions: ?usize,
) !void {
    const key = random.int(u32);
    try performDbAction(
        "RocksDb.contains",
        RocksDb.contains,
        .{ db, cf1, key },
        count,
        max_actions,
    );
}

// Batch API
fn batchDeleteRange(
    db: *RocksDb,
    random: *const std.rand.Random,
    count: *std.atomic.Value(u64),
    max_actions: ?usize,
) !void {
    var last_print_msg_count: u64 = 0;
    while (true) {
        if (max_actions) |max| {
            if (count.load(.monotonic) >= max) {
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

        const current_count = count.load(.monotonic);
        if ((current_count - last_print_msg_count) >= 1_000) {
            std.debug.print("{d} Batch actions\n", .{current_count});
            last_print_msg_count = current_count;
        }

        _ = count.fetchAdd(1, .monotonic);
    }
}
