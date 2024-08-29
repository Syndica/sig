const std = @import("std");
const time = @import("../time/time.zig");
const Level = @import("level.zig").Level;
const sig = @import("../sig.zig");
const RecycleFBA = sig.utils.allocators.RecycleFBA;

pub const LogMsg = struct {
    level: Level,
    maybe_scope: ?[]const u8,
    maybe_msg: ?[]const u8,
};

pub fn formatterLog(
    free_fba: *RecycleFBA,
    total_len: u64,
    message: LogMsg,
) !void {
    // obtain a memory to write to
    free_fba.mux.lock();
    const buf = blk: while (true) {
        const buf = free_fba.allocator().alloc(u8, total_len) catch {
            // no memory available rn - unlock and wait
            free_fba.mux.unlock();
            std.time.sleep(std.time.ns_per_ms);
            free_fba.mux.lock();
            continue;
        };
        break :blk buf;
    };
    free_fba.mux.unlock();
    errdefer {
        free_fba.mux.lock();
        free_fba.allocator().free(buf);
        free_fba.mux.unlock();
    }
    var log_message = std.io.fixedBufferStream(buf);
    const writer = log_message.writer();

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

    if (message.maybe_msg) |msg| {
        try std.fmt.format(writer, "{s}\n", .{msg});
    }

    const stderr_writer = std.io.getStdErr().writer();
    try std.fmt.format(stderr_writer, "{s}", .{log_message.getWritten()});
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
