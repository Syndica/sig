const std = @import("std");
const sig = @import("sig");

const ledger = sig.ledger;
const Logger = sig.trace.Logger;
const ChannelPrintLogger = sig.trace.ChannelPrintLogger;
const BlockstoreDB = sig.ledger.BlockstoreDB;
const ColumnFamily = sig.ledger.database.ColumnFamily;
const Database = sig.ledger.database.interface.Database;

const allocator = std.heap.c_allocator;

const cf1 = ColumnFamily{
    .name = "data",
    .Key = u64,
    .Value = []const u8,
};
const DB = Database(sig.ledger.database.RocksDB(&.{cf1}));

pub fn main() !void {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.skip();
    _ = if (args.next()) |arg| blk: {
        break :blk try std.fmt.parseInt(u32, arg, 10);
    } else blk: {
        break :blk @as(u32, 100_000);
    };

    const path = "src/repro/blockstore";

    if (std.fs.cwd().access(path, .{})) |_| {
        try std.fs.cwd().deleteTree(path);
    } else |_| {}
    try std.fs.cwd().makePath(path);

    const logger = try spawnLogger();

    var db: DB = try DB.open(
        allocator,
        logger,
        path,
    );
    defer db.deinit();

    {
        var writer_thread = try std.Thread.spawn(.{}, writer, .{&db});
        defer writer_thread.join();
        var deleter_thread = try std.Thread.spawn(.{}, deleter, .{&db});
        defer deleter_thread.join();
        var reader_thread = try std.Thread.spawn(.{}, reader, .{&db});
        defer reader_thread.join();
    }


}

fn spawnLogger() !Logger {
    var std_logger = try ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_level = sig.trace.Level.info,
        .max_buffer = 1 << 20,
    });
    return std_logger.logger();
}

fn writer(db: *DB) !void {
    var rng = std.rand.DefaultPrng.init(1234);
    while (true) {
        const index = rng.random().int(u32);
        var buffer: [61]u8 = undefined;

        // Fill the buffer with random bytes
        for (0..buffer.len) |i| {
            buffer[i] = @intCast(rng.random().int(u8));
        }

        const slice: []const u8 = buffer[0..];

        //std.debug.print("Writing {}\n", .{index});
        try db.put(cf1, (index + 1), slice);
    }
}

fn deleter(db: *DB) !void {
    var rng = std.rand.DefaultPrng.init(123);
    while (true) {
        const start = rng.random().int(u32);
        const end = blk: {
            const end_ = rng.random().int(u32);
            if (end_ < start)
                break :blk (end_ +| start)
            else
                break :blk end_;
        };
        var batch = try db.initWriteBatch();
        defer batch.deinit();
        std.debug.print("Deleting. Start:{} End: {}\n", .{ start, end });
        try batch.deleteRange(cf1, start, end);
        try db.commit(&batch);
        std.debug.print("Deleted. Start:{} End: {}\n", .{ start, end });
    }
}

fn reader(db: *DB) !void {
    var rng = std.rand.DefaultPrng.init(12345);
    while (true) {
        const index = rng.random().int(u32);
        const read = try db.getBytes(cf1, index);
        if (read) |_| {
            std.debug.print("Read key {}\n", .{index});
        } else {
            std.debug.print("Did not read deleted key {}\n", .{index});
        }
    }
}
