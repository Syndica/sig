const std = @import("std");
const lib = @import("./lib.zig");

const accountsdb_fuzz = lib.accounts_db.fuzz;
const gossip_fuzz = lib.gossip.fuzz;
const logger = lib.trace.log;

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

    if (std.mem.startsWith(u8, filter, "accountsdb")) {
        try accountsdb_fuzz.run(&cli_args);
    } else if (std.mem.startsWith(u8, filter, "gossip")) {
        try gossip_fuzz.run(&cli_args);
    } else { 
        std.debug.print("unknown fuzz filter: {s}\n", .{filter});
        return error.UnknownFilter;
    }
}
