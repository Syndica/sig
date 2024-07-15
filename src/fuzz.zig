const std = @import("std");
const lib = @import("./lib.zig");

const accountsdb_fuzz = lib.accounts_db.fuzz;
const gossip_fuzz_service = lib.gossip.fuzz_service;
const gossip_fuzz_table = lib.gossip.fuzz_table;
const logger = lib.trace.log;

// where seeds are saved (in case of too many logs)
const SEED_FILE_PATH = "test_data/fuzz_seeds.txt";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    logger.default_logger.* = logger.Logger.init(allocator, .debug);

    var cli_args = try std.process.argsWithAllocator(allocator);
    defer cli_args.deinit();

    _ = cli_args.skip();
    const maybe_filter = cli_args.next();
    const filter = blk: {
        if (maybe_filter) |filter| {
            std.debug.print("filtering fuzz testing with prefix: {s}\n", .{filter});
            break :blk filter;
        } else {
            std.debug.print("fuzz filter required: usage: zig build fuzz -- <filter>\n", .{});
            return error.NoFilterProvided;
        }
    };

    const maybe_seed = cli_args.next();
    const seed = blk: {
        if (maybe_seed) |seed_str| {
            break :blk try std.fmt.parseInt(u64, seed_str, 10);
        } else {
            break :blk std.crypto.random.int(u64);
        }
    };

    std.debug.print("using seed: {d}\n", .{seed});
    try writeSeedToFile(seed);

    // NOTE: changing these hardcoded str values will require a change to the fuzz/kcov in `scripts/`
    if (std.mem.startsWith(u8, filter, "accountsdb")) {
        try accountsdb_fuzz.run(seed, &cli_args);
    } else if (std.mem.startsWith(u8, filter, "gossip_service")) {
        try gossip_fuzz_service.run(seed, &cli_args);
    } else if (std.mem.startsWith(u8, filter, "gossip_table")) {
        try gossip_fuzz_table.run(seed, &cli_args);
    } else {
        std.debug.print("unknown fuzz filter: {s}\n", .{filter});
        return error.UnknownFilter;
    }
}

/// writes the seed to the defined seed file (defined by SEED_FILE_PATH)
pub fn writeSeedToFile(seed: u64) !void {
    std.fs.cwd().access(SEED_FILE_PATH, .{}) catch |err| {
        switch (err) {
            std.fs.Dir.AccessError.FileNotFound => {
                var file = try std.fs.cwd().createFile(SEED_FILE_PATH, .{});
                file.close();
            },
            else => {
                std.debug.print("failed to access seed file: {}\n", .{err});
                return;
            },
        }
    };

    const seed_file = try std.fs.cwd().openFile(SEED_FILE_PATH, .{ .mode = .write_only });
    defer seed_file.close();

    var buf: [1024]u8 = undefined;
    const now: u64 = @intCast(std.time.timestamp());

    const seed_slice = try std.fmt.bufPrint(&buf, "@{d} - seed: {d}\n", .{ now, seed });
    try seed_file.writeAll(seed_slice);
}
