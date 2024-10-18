const std = @import("std");
const sig = @import("sig.zig");
const config = @import("./cmd/config.zig");

const accountsdb_fuzz = sig.accounts_db.fuzz;
const gossip_fuzz_service = sig.gossip.fuzz_service;
const gossip_fuzz_table = sig.gossip.fuzz_table;
const accountsdb_snapshot_fuzz = sig.accounts_db.fuzz_snapshot;
const StandardErrLogger = sig.trace.ChannelPrintLogger;
const Level = sig.trace.Level;

const spawnMetrics = sig.prometheus.spawnMetrics;

// where seeds are saved (in case of too many logs)
const SEED_FILE_PATH = sig.TEST_DATA_DIR ++ "fuzz_seeds.txt";

// Supported fuzz filters.
// NOTE: changing these enum variants will require a change to the fuzz/kcov in `scripts/`
pub const FuzzFilter = enum {
    accountsdb,
    snapshot,
    gossip_service,
    gossip_table,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    var std_logger = try StandardErrLogger.init(.{
        .allocator = std.heap.c_allocator,
        .max_level = Level.debug,
        .max_buffer = 1 << 20,
    });
    defer std_logger.deinit();

    const logger = std_logger.logger();

    var cli_args = try std.process.argsWithAllocator(allocator);
    defer cli_args.deinit();

    logger.info().logf("metrics port: {d}", .{config.current.metrics_port});
    const metrics_thread = try spawnMetrics(
        // TODO: use the GPA here, the server is just leaking because we're losing the handle
        // to it and never deiniting.
        std.heap.c_allocator,
        config.current.metrics_port,
    );
    metrics_thread.detach();

    _ = cli_args.skip();
    const filter = blk: {
        const maybe_filter = cli_args.next();
        if (maybe_filter) |filter| {
            const parsed_filter = std.meta.stringToEnum(FuzzFilter, filter) orelse {
                std.debug.print("Unknown filter. Supported values are: {s} ", .{std.meta.fieldNames(FuzzFilter)});
                return error.UnknownFilter;
            };
            std.debug.print("filtering fuzz testing with prefix: {s}\n", .{filter});
            break :blk parsed_filter;
        } else {
            std.debug.print("fuzz filter required: usage: zig build fuzz -- <filter>\n", .{});
            return error.NoFilterProvided;
        }
    };

    const seed = blk: {
        const maybe_seed = cli_args.next();
        if (maybe_seed) |seed_str| {
            break :blk try std.fmt.parseInt(u64, seed_str, 10);
        } else {
            break :blk std.crypto.random.int(u64);
        }
    };

    std.debug.print("using seed: {d}\n", .{seed});
    try writeSeedToFile(filter, seed);

    switch (filter) {
        .accountsdb => try accountsdb_fuzz.run(seed, &cli_args),
        .snapshot => try accountsdb_snapshot_fuzz.run(&cli_args),
        .gossip_service => try gossip_fuzz_service.run(seed, &cli_args),
        .gossip_table => try gossip_fuzz_table.run(seed, &cli_args),
    }
}

/// writes the seed to the defined seed file (defined by SEED_FILE_PATH)
pub fn writeSeedToFile(filter: FuzzFilter, seed: u64) !void {
    const seed_file = try std.fs.cwd().createFile(SEED_FILE_PATH, .{
        .truncate = false,
    });
    defer seed_file.close();
    try seed_file.seekFromEnd(0);

    const now: u64 = @intCast(std.time.timestamp());
    try seed_file.writer().print("{s}: time: {d}, seed: {d}\n", .{ @tagName(filter), now, seed });
}
