const std = @import("std");
const std14 = @import("std14");
const time = @import("../time/time.zig");
const Level = @import("level.zig").Level;

/// Return the format string for the type when used as a value in a field.
fn fieldFmtString(comptime Value: type) []const u8 {
    return switch (@typeInfo(Value)) {
        // Assume arrays of u8 are strings.
        .pointer => |ptr| if (ptr.size == .one)
            fieldFmtString(ptr.child)
        else if (ptr.child == u8)
            "{s}={s} "
        else
            "{s}={any} ",
        .array => |arr| if (arr.child == u8) "{s}={s} " else "{s}={any} ",
        .int, .comptime_int, .float, .comptime_float => "{s}={} ",
        else => "{s}={any} ",
    };
}

/// Formats the entire log message as a string, writing it to the writer.
pub fn writeLog(
    writer: anytype,
    comptime maybe_scope: ?[]const u8,
    level: Level,
    fields: anytype,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    // format time as ISO8601
    const utc_format = "YYYY-MM-DDTHH:mm:ss.SSS";
    try std.fmt.format(writer, "time=", .{});
    const now = time.DateTime.now();
    try now.format(utc_format, .{}, writer);
    try writer.writeByte('Z');

    try writeLogWithoutTime(writer, maybe_scope, level, fields, fmt, args);
}

/// Returns the number of bytes needed to format the log message.
pub fn countLog(
    comptime maybe_scope: ?[]const u8,
    level: Level,
    fields: anytype,
    comptime fmt: []const u8,
    args: anytype,
) usize {
    const time_len: usize = 29;

    var counter = std14.countingWriter(std.io.null_writer);
    try writeLogWithoutTime(counter.writer(), maybe_scope, level, fields, fmt, args);

    return time_len + counter.bytes_written;
}

/// Formats the log message as a string, excluding the time.
fn writeLogWithoutTime(
    writer: anytype,
    comptime maybe_scope: ?[]const u8,
    level: Level,
    fields: anytype,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    try std.fmt.format(writer, " level={s}", .{@tagName(level)});

    if (maybe_scope) |scope| {
        try std.fmt.format(writer, " scope={s}", .{scope});
    }

    try std.fmt.format(writer, " message=\"" ++ fmt ++ "\"", args);

    inline for (@typeInfo(@TypeOf(fields)).@"struct".fields) |field| {
        try writer.writeByte(' ');
        try std.fmt.format(writer, fieldFmtString(field.type), .{
            field.name,
            @field(fields, field.name),
        });
    }
    try std.fmt.format(writer, "\n", .{});
}

test "countLog matches writeLog" {
    const scope = "test-scope";
    const level = .info;
    const fields = .{ .integer = 1, .float = 1.123, .string = "test" };
    const fmt = "here's {} message: {s}";
    const args = .{ 1, "this is a test" };
    const count = countLog(scope, level, fields, fmt, args);
    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try writeLog(stream.writer(), scope, level, fields, fmt, args);
    try std.testing.expectEqual(count, stream.getWritten().len);
}
