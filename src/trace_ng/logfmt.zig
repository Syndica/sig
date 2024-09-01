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

pub fn writeLog(
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

pub fn fieldsToStr(
    recycle_fba: *RecycleFBA,
    max_buffer: u64,
    args: anytype,
) ?[]const u8 {
    _ = &max_buffer;

    // obtain a memory to write to
    recycle_fba.mux.lock();
    const buf = blk: while (true) {
        const buf = recycle_fba.allocator().alloc(u8, 256) catch {
            // no memory available rn - unlock and wait
            recycle_fba.mux.unlock();
            std.time.sleep(std.time.ns_per_ms);
            recycle_fba.mux.lock();
            continue;
        };
        break :blk buf;
    };
    recycle_fba.mux.unlock();
    errdefer {
        recycle_fba.mux.lock();
        recycle_fba.allocator().free(buf);
        recycle_fba.mux.unlock();
    }
    var field_message = std.io.fixedBufferStream(buf);
    const writer = field_message.writer();

    switch (@typeInfo(@TypeOf(args))) {
        .Struct => |struc| {
            inline for (struc.fields) |field| {
                const field_value = @field(args, field.name);
                // Check the field's type and format accordingly
                switch (@typeInfo(@TypeOf(field_value))) {
                    .Pointer, .Array => {
                        // Assume it's a string type
                        std.fmt.format(writer, "{s}={s} ", .{ field.name, field_value }) catch return null;
                    },
                    .Int, .ComptimeInt, .Float, .ComptimeFloat => {
                        // Handle numeric types
                        std.fmt.format(writer, "{s}={} ", .{ field.name, field_value }) catch return null;
                    },
                    else => {
                        // Fallback for unsupported types
                        std.fmt.format(writer, "{s}=<?> ", .{field.name}) catch return null;
                    },
                }
            }
        },
        else => {
            return null;
        },
    }

    return field_message.getWritten();
}
