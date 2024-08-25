const std = @import("std");
const time = @import("../time/time.zig");
const Level = @import("level.zig").Level;

pub fn formatter(
    writer: anytype,
    level: Level,
    maybe_scope: ?[]const u8,
    fields: []const u8,
    msg: []const u8,
) !void {
    if (maybe_scope) |scope| {
        std.fmt.format(writer, "[{s}] ", .{scope}) catch unreachable();
    }
    // format time as ISO8601
    const utc_format = "YYYY-MM-DDTHH:mm:ss";
    const now = time.DateTime.now();
    try std.fmt.format(writer, "time=", .{});
    try now.format(utc_format, .{}, writer);
    try std.fmt.format(writer, "Z ", .{});
    try std.fmt.format(writer, "level={s} ", .{level.asText()});
    try std.fmt.format(writer, "{s} ", .{fields});
    try std.fmt.format(writer, "{s}\n", .{msg});
}
