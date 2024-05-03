const std = @import("std");
const lib = @import("lib.zig");
const logger = @import("./trace/log.zig");

test {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    logger.default_logger.* = logger.Logger.init(allocator, .debug);

    std.testing.log_level = std.log.Level.err;
    std.testing.refAllDeclsRecursive(lib);
}
