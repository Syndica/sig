const std = @import("std");
const lib = @import("lib.zig");
const logger = @import("./trace/log.zig");

test {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    logger.default_logger.* = logger.Logger.init(allocator, .debug);

    std.testing.log_level = std.log.Level.err;
    std.testing.refAllDecls(lib.accounts_db);
    std.testing.refAllDecls(lib.bincode);
    std.testing.refAllDecls(lib.bloom);
    std.testing.refAllDecls(lib.cmd);
    std.testing.refAllDecls(lib.common);
    std.testing.refAllDecls(lib.core);
    std.testing.refAllDecls(lib.gossip);
    std.testing.refAllDecls(lib.net);
    std.testing.refAllDecls(lib.prometheus);
    std.testing.refAllDecls(lib.rpc);
    std.testing.refAllDecls(lib.sync);
    std.testing.refAllDecls(lib.trace);
    std.testing.refAllDecls(lib.tvu);
    std.testing.refAllDecls(lib.utils);
    std.testing.refAllDecls(lib.version);
}
