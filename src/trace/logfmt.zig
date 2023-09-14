const std = @import("std");
const Entry = @import("./entry.zig").StandardEntry;

pub fn formatter(e: *const Entry, writer: anytype) !void {
    // format time as ISO8601
    const utc_format = "YYYY-MM-DDTHH:mm:ss";
    try std.fmt.format(writer, "time=", .{});
    try e.time.format(utc_format, .{}, writer);
    try std.fmt.format(writer, "Z ", .{});
    try std.fmt.format(writer, "level={s} ", .{e.level.asText()});

    for (e.fields.items) |f| {
        f.custom_format(writer);
    }
    try std.fmt.format(writer, " {s}\n", .{e.message.items});
}
