const std = @import("std");
const sig = @import("sig");

const ledger = sig.ledger;
const Logger = sig.trace.Logger;
const ChannelPrintLogger = sig.trace.ChannelPrintLogger;
const BlockstoreDB = sig.ledger.BlockstoreDB;

const allocator = std.heap.c_allocator;

pub fn main() !void {
    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.skip();
    const count: u32 = if (args.next()) |arg| blk: {
        break :blk try std.fmt.parseInt(u32, arg, 10);
    } else blk: {
        break :blk @as(u32, 100_000);
    };

    const path = "validator/blockstore";

    // if (std.fs.cwd().access(path, .{})) |_| {
    //     try std.fs.cwd().deleteTree(path);
    // } else |_| {}
    // try std.fs.cwd().makePath(path);

    const logger = try spawnLogger();

    var db: BlockstoreDB = try sig.ledger.BlockstoreDB.open(
        allocator,
        logger,
        path,
    );
    defer db.deinit();

    var writer_thread = try std.Thread.spawn(.{}, writer, .{ &db, count });
    var deleter_thread = try std.Thread.spawn(.{}, deleter, .{ &db, count });
    var reader_thread = try std.Thread.spawn(.{}, reader, .{ &db, count });

    defer writer_thread.join();
    defer deleter_thread.join();
    defer reader_thread.join();
}

fn spawnLogger() !Logger {
    var std_logger = try ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_level = sig.trace.Level.info,
        .max_buffer = 1 << 20,
    });
    return std_logger.logger();
}

fn writer(db: *BlockstoreDB, count: u32) !void {
    try db.put(ledger.schema.schema.slot_meta, 1, ledger.meta.SlotMeta.init(allocator, 0, null));
    for (1..count) |c| {
        try db.put(ledger.schema.schema.slot_meta, (c + 1), ledger.meta.SlotMeta.init(allocator, c, (c - 1)));
    }
}

fn deleter(db: *BlockstoreDB, count: u32) !void {
    std.time.sleep(15 * std.time.ns_per_s);
    for (0..count) |c| {
        var batch = try db.initWriteBatch();
        defer batch.deinit();
        const start = (c -| @as(u32, 500));
        const end = (c -| @as(u32, 10));
        // std.debug.print("Deleting. Start:{} End: {}\n", .{start, end});
        try batch.deleteRange(ledger.schema.schema.slot_meta, start, end);
        try db.commit(&batch);
    }
}

fn reader(db: *BlockstoreDB, count: u32) !void {
    std.time.sleep(10 * std.time.ns_per_s);
    for (0..count) |c| {
        const read = try db.get(db.allocator, ledger.schema.schema.slot_meta, c);
        if (read) |_| {
            std.debug.print("Read key {}\n", .{c});
        } else {
            std.debug.print("Did not read deleted key {}\n", .{c});
        }
        // std.time.sleep(1 * std.time.ns_per_s);
    }
}
