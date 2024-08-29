const std = @import("std");
const time = @import("../time/time.zig");
const Level = @import("level.zig").Level;
const sig = @import("../sig.zig");
const RecycleFBA = sig.utils.allocators.RecycleFBA;

pub const LogMsg = struct {
    level: Level,
    maybe_scope: ?[]const u8 = null,
    maybe_msg: ?[]const u8 = null,
    maybe_kv: ?[]const u8 = null,
    maybe_fmt: ?[]const u8 = null,
};

pub fn formatterLog(
    message: LogMsg,
) !void {
    const writer = std.io.getStdErr().writer();

    if (message.maybe_scope) |scope| {
        std.fmt.format(writer, "[{s}] ", .{scope}) catch unreachable();
    }

    // format time as ISO8601
    const utc_format = "YYYY-MM-DDTHH:mm:ss";
    const now = time.DateTime.now();
    try std.fmt.format(writer, "time=", .{});
    try now.format(utc_format, .{}, writer);
    try std.fmt.format(writer, "Z ", .{});
    try std.fmt.format(writer, "level={s} ", .{message.level.asText()});

    if (message.maybe_kv) |kv| {
        try std.fmt.format(writer, "{s}", .{kv});
    }

    if (message.maybe_msg) |msg| {
        try std.fmt.format(writer, "{s}\n", .{msg});
    }
    if (message.maybe_fmt) |fmt| {
        try std.fmt.format(writer, "{s}\n", .{fmt});
    }
}

pub fn keyValueToString(
    args: anytype,
) ![]const u8 {
    comptime var size: usize = keyValueSize(args);
    var array: [102]u8 = undefined;
    var fbs = std.io.fixedBufferStream(array[0..]);
    const writer = fbs.writer().any();
    switch (@typeInfo(@TypeOf(args))) {
        .Struct => |struc| {
            inline for (struc.fields) |field| {
                size += field.name.len;
                size += @sizeOf(@TypeOf(field.name));
                //For the '=' and ' ' characters
                size += 2;
                try std.fmt.format(writer, "{s}={s} ", .{ field.name, @field(args, field.name) });
            }
        },
        else => {},
    }

    return fbs.getWritten();
}

pub fn keyValueSize(
    args: anytype,
) usize {
    comptime var size: usize = 0;
    switch (@typeInfo(@TypeOf(args))) {
        .Struct => |struc| {
            inline for (struc.fields) |field| {
                size += field.name.len;
                size += @field(args, field.name).len;
                // For "=" and " "
                size += 2;
            }
        },
        else => {},
    }
    return size;
}

pub fn formatter(
    writer: anytype,
    level: Level,
    maybe_scope: ?[]const u8,
    maybe_fields: ?[]const u8,
    maybe_msg: ?[]const u8,
    comptime maybe_fmt: ?[]const u8,
    args: anytype,
    keyvalue: anytype,
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
    if (maybe_fields) |fields| {
        try std.fmt.format(writer, "{s} ", .{fields});
    }
    keyValueToStr(writer, keyvalue) catch unreachable();

    if (maybe_msg) |msg| {
        try std.fmt.format(writer, "{s}\n", .{msg});
    }

    if (maybe_fmt) |fmt| {
        std.fmt.format(writer, fmt, args) catch @panic("could not format");
        std.fmt.format(writer, "{s}", .{"\n"}) catch @panic("could not format");
    }
}

pub fn keyValueToStr(
    writer: anytype,
    args: anytype,
) !void {
    switch (@typeInfo(@TypeOf(args))) {
        .Struct => |struc| {
            inline for (struc.fields) |field| {
                try std.fmt.format(writer, "{s}={s} ", .{ field.name, @field(args, field.name) });
            }
        },
        else => {},
    }
}
