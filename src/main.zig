const cmd = @import("cmd/cmd.zig");
const logger = @import("./trace/log.zig");
const std = @import("std");

// We set this so that std.log knows not to log .debug level messages
// which libraries we import will use
pub const std_options: std.Options = .{
    // Set the log level to info
    .log_level = .info,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    logger.default_logger.* = logger.Logger.init(allocator, .debug);
    try cmd.run();
}
