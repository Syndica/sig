const std = @import("std");

const sig = @import("../lib.zig");

const ArrayList = std.ArrayList;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Blake3 = std.crypto.hash.Blake3;

const AccountsDB = sig.accounts_db.AccountsDB;
const Logger = sig.trace.Logger;

pub fn run(args: *std.process.ArgIterator) !void {
    _ = args;

    const seed = std.crypto.random.int(u64);
    var prng = std.rand.DefaultPrng.init(seed);
    const rand = prng.random();
    std.debug.print("seed: {}\n", .{seed});

    var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa_allocator.allocator();

    const logger = Logger.init(allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    const use_disk = rand.boolean();
    var accounts_db = try AccountsDB.init(allocator, logger, .{
        .use_disk_index = use_disk,
    });
    defer accounts_db.deinit(true);

    const exit = try allocator.create(std.atomic.Value(bool));
    exit.* = std.atomic.Value(bool).init(false);

    var handle = try std.Thread.spawn(.{}, AccountsDB.runManagerLoop, .{
        &accounts_db,
        exit,
    });

    std.time.sleep(std.time.ns_per_s * 5);

    exit.store(true, .seq_cst);
    handle.join();
}
