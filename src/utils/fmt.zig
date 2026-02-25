const std = @import("std");
const std14 = @import("std14");
const sig = @import("../sig.zig");

/// Wrapper for `BoundedSpec(fmt_str).fmt(args)`.
pub fn boundedFmt(
    comptime fmt_str: []const u8,
    args: anytype,
) BoundedSpec(fmt_str).BoundedArray(@TypeOf(args)) {
    return BoundedSpec(fmt_str).fmt(args);
}

/// Returns a namespace with functions for formatting bounded-length data.
pub fn BoundedSpec(comptime spec: []const u8) type {
    return struct {
        pub const fmt_str = spec;

        /// Returns the maximum length applicable for the format string and `Args` tuple,
        /// such that it would be the equivalent to the length of the bounded array returned
        /// by `fmt`.
        /// ```zig
        /// try expectEqual("255-1".len, BoundedSpec("{d}-{d}").fmtLen(struct { u8, u1 }));
        /// // comptime field values in the struct/tuple are reflected appropriately
        /// try expectEqual("foo-255".len, BoundedSpec("{[a]s}-{[b]d}").fmtLen(struct { comptime a: []const u8 = "foo", b: u8 }));
        /// ```
        pub inline fn fmtLen(comptime Args: type) usize {
            comptime return std.fmt.count(fmt_str, maxArgs(Args));
        }

        /// Same as `fmtLen`, but takes a value instead of a type.
        /// The values should posses the maximum values applicable for each
        /// element type, in order to match the actual bounded length.
        /// For example:
        /// ```zig
        /// try expectEqual("255-255".len, boundedLenValue("{d}-{d}", .{ std.math.maxInt(u8), std.math.maxInt(u8) }));
        /// // comptime field values in the struct/tuple are reflected appropriately
        /// try expectEqual("foo-255".len, boundedLenValue("{[a]s}-{[b]d}", .{ .a = "foo", .b = 255 }));
        /// ```
        pub inline fn fmtLenValue(comptime args_value: anytype) usize {
            comptime return fmtLen(@TypeOf(args_value));
        }

        pub fn BoundedArray(comptime Args: type) type {
            return std14.BoundedArray(u8, fmtLen(Args));
        }

        pub fn BoundedArrayValue(comptime args_value: anytype) type {
            return BoundedArray(@TypeOf(args_value));
        }

        /// Returns a bounded array string, guaranteed to be able to represent the formatted result.
        /// For example:
        /// ```zig
        /// try expectEqualStrings("fizz.buzz", BoundedFmtSpec("{s}.{s}").fmt(.{ "foo", "buzz" }).constSlice());
        /// ```
        pub inline fn fmt(args: anytype) BoundedArray(@TypeOf(args)) {
            var out: std14.BoundedArray(u8, fmtLen(@TypeOf(args))) = .{};
            _ = fmtInto(args, &out);
            return out;
        }

        /// Clears `out`, and writes the equivalent of `fmt` to it, returning the slice (also accessible as `out.slice()`).
        /// For example:
        /// ```zig
        /// const Spec = BoundedFmtSpec("{s}.{s}");
        /// var str: Spec.BoundedArrayValue(.{ "foo", "buzz" }) = .{};
        /// try expectEqualStrings("fizz.buzz", Spec.fmtInto(.{ "foo", "buzz" }, &str));
        /// ```
        pub inline fn fmtInto(args: anytype, out: *BoundedArray(@TypeOf(args))) []u8 {
            out.* = .{};
            std.fmt.format(out.writer(), fmt_str, args) catch unreachable;
            return out.slice();
        }
    };
}

/// Returns a wrapper around the bounded array which will be usable as an argument
/// to `BoundedSpec(spec)` functions.
pub inline fn boundedString(
    /// `*const std14.BoundedArray(u8, capacity)`
    bounded: anytype,
) if (sig.utils.types.boundedArrayInfo(@TypeOf(bounded.*))) |ba_info|
    BoundedString(ba_info.capacity)
else
    noreturn {
    const lazy = struct {
        const compile_err = "Expected `std14.BoundedArray(u8, capacity)`, got " ++
            @typeName(@TypeOf(bounded.*));
    };
    const ba_info = sig.utils.types.boundedArrayInfo(@TypeOf(bounded.*)) orelse
        @compileError(lazy.compile_err);
    if (ba_info.Elem != u8) @compileError(lazy.compile_err);
    return .{ .bounded = bounded };
}

/// A wrapper around a `*const std14.BoundedArray(u8, capacity)` which is
/// usable as an argument type by `BoundedSpec(spec)` functions.
pub fn BoundedString(comptime capacity: usize) type {
    return struct {
        bounded: *const std14.BoundedArray(u8, capacity),
        const Self = @This();

        pub fn format(str: Self, writer: *std.Io.Writer) std.Io.Writer.Error!void {
            try writer.writeAll(str.bounded.constSlice());
        }
    };
}

/// Returns an instance of the tuple of type `Args`, wherein each
/// element of the tuple possesses the maximum value applicable
/// to the type of the element.
inline fn maxArgs(comptime Args: type) Args {
    comptime {
        var max_args: Args = undefined;
        for (@typeInfo(Args).@"struct".fields) |field| {
            if (field.is_comptime) continue;
            const ptr = &@field(max_args, field.name);
            ptr.* = maxArg(field.type);
        }
        return max_args;
    }
}

inline fn maxArg(comptime T: type) T {
    comptime switch (@typeInfo(T)) {
        .comptime_int => @compileError("comptime_int field without default value has no max value"),
        .int => return std.math.maxInt(T),
        .@"struct" => {
            if (boundedStringMaxArg(T)) |max_value| return max_value;
        },
        .array => |array| if (array.child == u8) return .{255} ** array.len,
        .pointer => |pointer| switch (pointer.size) {
            .one => switch (@typeInfo(pointer.child)) {
                .array => |array| if (array.child == u8) {
                    const arr = if (array.sentinel()) |sentinel|
                        [array.len:sentinel]u8
                    else
                        [array.len]u8;
                    const result: arr align(pointer.alignment) = .{255} ** arr.len;
                    return &result;
                },
                else => {},
            },
            .slice => if (pointer.child == u8) {
                // For slices, we can't know the max size at comptime.
                // Return an empty slice - callers should use fmtLenValue with explicit max length
                const empty: []const u8 = "";
                return empty;
            },
            else => {},
        },
        else => {},
    };
    @compileError("Unsupported type: " ++ @typeName(T));
}

inline fn boundedStringMaxArg(comptime T: type) ?T {
    comptime {
        const structure = switch (@typeInfo(T)) {
            else => return null,
            .@"struct" => |info| info,
        };
        if (structure.fields.len != 1) return null;
        if (!@hasField(T, "bounded")) return null;
        const Bounded = switch (@typeInfo(structure.fields[0].type)) {
            else => return null,
            .pointer => |info| switch (info.size) {
                else => return null,
                .one => info.child,
            },
        };
        const ba_info = sig.utils.types.boundedArrayInfo(Bounded) orelse return null;
        if (ba_info.Elem != u8) return null;

        const Actual = BoundedString(ba_info.capacity);
        if (T != Actual) return null;

        const bounded =
            ba_info.Type().fromSlice(&[_]u8{255} ** ba_info.capacity) catch unreachable;
        return boundedString(&bounded);
    }
}

/// Replaces any newlines from the string with spaces. Useful when trying
/// to limit the source code line-length without introducing new lines
/// into strings.
pub fn newlinesToSpaces(comptime str: []const u8) [str.len]u8 {
    var ret: [str.len]u8 = .{' '} ** str.len;
    for (str, 0..) |char, i| if (char != '\n') {
        ret[i] = char;
    };
    return ret;
}

/// Tries to format the real path resolved from `dir` and `pathname`.
/// Should it encounter an error when doing so, `"(error.Name)/pathname"`
/// is printed instead.
pub inline fn tryRealPath(dir: std.fs.Dir, pathname: []const u8) TryRealPathFmt {
    return .{
        .dir = dir,
        .pathname = pathname,
    };
}

pub const TryRealPathFmt = struct {
    dir: std.fs.Dir,
    pathname: []const u8,

    pub fn format(
        fmt: TryRealPathFmt,
        writer: *std.io.Writer,
    ) std.io.Writer.Error!void {
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;

        if (fmt.dir.realpath(".", &path_buf)) |real_path| {
            try writer.writeAll(real_path);
            if (real_path[real_path.len - 1] != '/') {
                try writer.writeByte('/');
            }
            try writer.writeAll(fmt.pathname);
        } else |err| {
            try writer.print("(error.{t})/{s}", .{
                err, fmt.pathname,
            });
        }
    }
};
