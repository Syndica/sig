const logger = @import("./trace/log.zig");
const std = @import("std");
const gossip_fuzz = @import("./gossip/fuzz.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    logger.default_logger.* = logger.Logger.init(allocator, .debug);
    try gossip_fuzz.run();
}
