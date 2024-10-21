const std = @import("std");
const time = @import("../time/time.zig");
const Level = @import("level.zig").Level;
const sig = @import("../sig.zig");

/// Return the format string for the type when used as a value in a field.
fn fieldFmtString(comptime Value: type) []const u8 {
    return switch (@typeInfo(Value)) {
        // Assume arrays of u8 are strings.
        .Pointer => |ptr| if (ptr.size == .One)
            fieldFmtString(ptr.child)
        else if (ptr.child == u8)
            "{s}={s} "
        else
            "{s}={any} ",
        .Array => |arr| if (arr.child == u8) "{s}={s} " else "{s}={any} ",
        .Int, .ComptimeInt, .Float, .ComptimeFloat => "{s}={} ",
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
    if (maybe_scope) |scope| {
        try std.fmt.format(writer, "[{s}] ", .{scope});
    }

    // format time as ISO8601
    const utc_format = "YYYY-MM-DDTHH:mm:ss.SSS";
    const now = time.DateTime.now();
    try std.fmt.format(writer, "time=", .{});
    try now.format(utc_format, .{}, writer);
    try std.fmt.format(writer, "Z ", .{});

    try std.fmt.format(writer, "level={s} ", .{level.asText()});

    inline for (@typeInfo(@TypeOf(fields)).Struct.fields) |field| {
        try std.fmt.format(writer, fieldFmtString(field.type), .{
            field.name,
            @field(fields, field.name),
        });
    }

    try std.fmt.format(writer, fmt ++ "\n", args);
}

/// Returns the number of bytes needed to format the log message.
pub fn countLog(
    comptime maybe_scope: ?[]const u8,
    level: Level,
    fields: anytype,
    comptime fmt: []const u8,
    args: anytype,
) usize {
    var count: usize = 30; // timestamp is 30 chars

    if (maybe_scope) |scope| count += std.fmt.count("[{s}] ", .{scope});

    count += std.fmt.count("level={s} ", .{level.asText()});

    inline for (@typeInfo(@TypeOf(fields)).Struct.fields) |field| {
        count += std.fmt.count(fieldFmtString(field.type), .{
            field.name,
            @field(fields, field.name),
        });
    }

    count += std.fmt.count(fmt ++ "\n", args);
    return count;
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
