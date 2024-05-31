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
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var our_logger = logger.Logger.init(allocator, .debug);
    defer our_logger.deinit();

    logger.default_logger.* = our_logger;
    try cmd.run();
}
