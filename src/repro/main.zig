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
    _= if (args.next()) |arg| blk: {
        break :blk try std.fmt.parseInt(u32, arg, 10);
    } else blk: {
        break :blk @as(u32, 100_000);
    };

    const path = "src/repro/blockstore";

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

fn writer(db: *BlockstoreDB) !void {
    var rng = std.rand.DefaultPrng.init(1234);
    while (true) {
        const index = rng.random().int(u32);
        const parent = blk: {
            const parent_ = rng.random().int(u32);
            if (parent_ > index)
                break :blk index - 1
            else
                break :blk parent_;
        };
        // std.debug.print("Writing {}\n", .{index});
        try db.put(ledger.schema.schema.slot_meta, (index + 1), ledger.meta.SlotMeta.init(allocator, index,  parent));
    }
}

fn deleter(db: *BlockstoreDB) !void {
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
        std.debug.print("Deleting. Start:{} End: {}\n", .{start, end});
        try batch.deleteRange(ledger.schema.schema.slot_meta, start, end);
        try db.commit(&batch);
        std.debug.print("Deleted. Start:{} End: {}\n", .{start, end});
    }
}

fn reader(db: *BlockstoreDB) !void {
    var rng = std.rand.DefaultPrng.init(12345);
    while (true) {
        const index = rng.random().int(u32);
        const read = try db.get(db.allocator, ledger.schema.schema.slot_meta, index);
        if (read) |_| {
            std.debug.print("Read key {}\n", .{index});
        } else {
            std.debug.print("Did not read deleted key {}\n", .{index});
        }
    }
}
