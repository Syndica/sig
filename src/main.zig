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
    try cmd.run();
}
