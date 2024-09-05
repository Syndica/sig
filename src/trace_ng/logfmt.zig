const std = @import("std");
const time = @import("../time/time.zig");
const Level = @import("level.zig").Level;
const sig = @import("../sig.zig");
const RecycleFBA = sig.utils.allocators.RecycleFBA;

pub const LogMsg = struct {
    level: Level,
    maybe_scope: ?[]const u8 = null,
    maybe_msg: ?[]const u8 = null,
    maybe_fields: ?[]const u8 = null,
    maybe_fmt: ?[]const u8 = null,
};

pub fn fmtMsg(
    writer: anytype,
    comptime maybe_fmt: ?[]const u8,
    args: anytype,
) void {
    if (maybe_fmt) |fmt| {
        std.fmt.format(writer, fmt, args) catch @panic("could not format");
    }
}

pub fn fmtField(
    writer: anytype,
    args: anytype,
) void {
    if (@typeInfo(@TypeOf(args)) == .Null) {
        return;
    }
    switch (@typeInfo(@TypeOf(args))) {
        .Struct => |struc| {
            inline for (struc.fields) |field| {
                const field_value = @field(args, field.name);
                // Check the field's type and format accordingly
                switch (@typeInfo(@TypeOf(field_value))) {
                    .Pointer, .Array => {
                        // Assume it's a string type
                        std.fmt.format(writer, "{s}={s} ", .{ field.name, field_value }) catch return;
                    },
                    .Int, .ComptimeInt, .Float, .ComptimeFloat => {
                        // Handle numeric types
                        std.fmt.format(writer, "{s}={} ", .{ field.name, field_value }) catch return;
                    },
                    else => {
                        // Fallback for unsupported types
                        std.fmt.format(writer, "{s}=<?> ", .{field.name}) catch return;
                    },
                }
            }
        },
        else => {
            return;
        },
    }
}

pub fn writeLog(
    writer: anytype,
    message: LogMsg,
) !void {
    if (message.maybe_scope) |scope| {
        try std.fmt.format(writer, "[{s}] ", .{scope});
    }

    // format time as ISO8601
    const utc_format = "YYYY-MM-DDTHH:mm:ss";
    const now = time.DateTime.now();
    try std.fmt.format(writer, "time=", .{});
    try now.format(utc_format, .{}, writer);
    try std.fmt.format(writer, "Z ", .{});
    try std.fmt.format(writer, "level={s} ", .{message.level.asText()});

    if (message.maybe_fields) |kv| {
        try std.fmt.format(writer, "{s}", .{kv});
    }

    if (message.maybe_msg) |msg| {
        try std.fmt.format(writer, "{s}\n", .{msg});
    }
    if (message.maybe_fmt) |fmt| {
        try std.fmt.format(writer, "{s}\n", .{fmt});
    }
}
