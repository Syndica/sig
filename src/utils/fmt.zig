const std = @import("std");
const sig = @import("../lib.zig");

inline fn maxArg(comptime field: std.builtin.Type.StructField) field.type {
    return switch (@typeInfo(field.type)) {
        .ComptimeInt => sig.utils.types.defaultValue(field) orelse @compileError("comptime_int field without default value has no max value"),
        .Int => std.math.maxInt(field.type),
        else => @compileError("[Argument '" ++ field.name ++ "'] Unsupported type: " ++ @typeName(field.type)),
    };
}

pub inline fn maxArgs(comptime Args: type) Args {
    comptime {
        var max_args: Args = undefined;
        for (@typeInfo(Args).Struct.fields) |field| {
            const ptr = &@field(max_args, field.name);
            ptr.* = maxArg(field);
        }
        return max_args;
    }
}

pub inline fn boundedLen(
    comptime fmt_str: []const u8,
    comptime Args: type,
) usize {
    comptime return std.fmt.count(fmt_str, maxArgs(Args));
}

/// Returns a bounded array string, guaranteed to be able to represent the formatted result.
pub fn boundedFmt(
    comptime fmt_str: []const u8,
    args: anytype,
) std.BoundedArray(u8, boundedLen(fmt_str, @TypeOf(args))) {
    var result: std.BoundedArray(u8, boundedLen(fmt_str, @TypeOf(args))) = .{};
    result.writer().print(fmt_str, args) catch unreachable;
    return result;
}
