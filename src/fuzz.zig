const std = @import("std");
const sig = @import("sig.zig");

const accountsdb_fuzz = sig.accounts_db.fuzz;
const gossip_fuzz_service = sig.gossip.fuzz_service;
const gossip_fuzz_table = sig.gossip.fuzz_table;
const accountsdb_snapshot_fuzz = sig.accounts_db.snapshot.fuzz;
const ledger_fuzz = sig.ledger.fuzz_ledger;
const ChannelPrintLogger = sig.trace.ChannelPrintLogger;
const Level = sig.trace.Level;

const servePrometheus = sig.prometheus.servePrometheus;
const globalRegistry = sig.prometheus.globalRegistry;

// where seeds are saved (in case of too many logs)
const SEED_FILE_PATH = sig.TEST_DATA_DIR ++ "fuzz_seeds.txt";

// Supported fuzz filters.
// NOTE: changing these enum variants will require a change to the fuzz/kcov in `scripts/`
pub const FuzzFilter = enum {
    accountsdb,
    snapshot,
    gossip_service,
    gossip_table,
    allocators,
    ledger,
};

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const allocator = gpa_state.allocator();

    var std_logger = try ChannelPrintLogger.init(.{
        .allocator = std.heap.c_allocator,
        .max_level = Level.debug,
        .max_buffer = 1 << 20,
    }, null);
    defer std_logger.deinit();

    const logger = std_logger.logger("fuzz");

    var cli_args = try std.process.argsWithAllocator(allocator);
    defer cli_args.deinit();

    const metrics_port: u16 = 12345;

    logger.info().logf("metrics port: {d}", .{metrics_port});
    const metrics_thread = try std.Thread
        // TODO: use the GPA here, the server is just leaking because we're losing the handle
        // to it and never deiniting.
        .spawn(.{}, servePrometheus, .{ std.heap.c_allocator, globalRegistry(), 12355 });
    metrics_thread.detach();

    _ = cli_args.skip();
    const filter = blk: {
        const maybe_filter = cli_args.next();
        if (maybe_filter) |filter| {
            const parsed_filter = std.meta.stringToEnum(FuzzFilter, filter) orelse {
                std.debug.print("Unknown filter. Supported values are: ", .{});
                for (std.meta.fieldNames(FuzzFilter)) |name| std.debug.print("{s} ", .{name});
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
        .ledger => try ledger_fuzz.run(seed, &cli_args),
        .allocators => try sig.utils.allocators.runFuzzer(seed, &cli_args),
    }
}

/// writes the seed to the defined seed file (defined by SEED_FILE_PATH)
pub fn writeSeedToFile(filter: FuzzFilter, seed: u64) !void {
    const seed_file = try std.fs.cwd().createFile(SEED_FILE_PATH, .{ .truncate = false });
    defer seed_file.close();

    var file_writer = seed_file.writer(&.{});
    const writer = &file_writer.interface;

    const now: u64 = @intCast(std.time.timestamp());
    try writer.print("{t}: time: {d}, seed: {d}\n", .{ filter, now, seed });
}
