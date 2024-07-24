const std = @import("std");
const sig = @import("../lib.zig");

pub inline fn boundedLen(
    comptime fmt_str: []const u8,
    comptime Args: type,
) usize {
    comptime return std.fmt.count(fmt_str, maxArgs(Args));
}

/// Returns a bounded array string, guaranteed to be able to represent the formatted result.
pub inline fn boundedFmt(
    comptime fmt_str: []const u8,
    args: anytype,
) std.BoundedArray(u8, boundedLen(fmt_str, @TypeOf(args))) {
    var result: std.BoundedArray(u8, boundedLen(fmt_str, @TypeOf(args))) = .{};
    result.writer().print(fmt_str, args) catch unreachable;
    return result;
}

pub inline fn maxArgs(comptime Args: type) Args {
    comptime {
        var max_args: Args = undefined;
        for (@typeInfo(Args).Struct.fields) |field| {
            if (field.is_comptime) continue;
            const ptr = &@field(max_args, field.name);
            ptr.* = maxArg(field.type);
        }
        return max_args;
    }
}

pub inline fn boundedString(bounded: anytype) if (sig.utils.types.boundedArrayInfo(@TypeOf(bounded.*))) |ba_info| BoundedString(ba_info.capacity) else noreturn {
    const lazy = struct {
        const compile_err: noreturn = @compileError("Expected `std.BoundedArray(u8, capacity)`, got " ++ @typeName(@TypeOf(bounded.*)));
    };
    const ba_info = sig.utils.types.boundedArrayInfo(@TypeOf(bounded.*)) orelse lazy.compile_err;
    if (ba_info.Elem != u8) lazy.compile_err;
    return .{ .bounded = bounded };
}

pub fn BoundedString(comptime capacity: usize) type {
    return struct {
        bounded: *const std.BoundedArray(u8, capacity),
        const Self = @This();

        pub fn format(
            str: Self,
            comptime fmt_str: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            comptime if (!std.mem.eql(u8, fmt_str, "s")) std.fmt.invalidFmtError(fmt_str, str);
            try writer.writeAll(str.bounded.constSlice());
        }
    };
}

inline fn maxArg(comptime T: type) T {
    comptime switch (@typeInfo(T)) {
        .ComptimeInt => @compileError("comptime_int field without default value has no max value"),
        .Int => return std.math.maxInt(T),
        .Struct => {
            if (boundedStringMaxArg(T)) |max_value| return max_value;
        },
        .Array => |array| if (array.child == u8) return .{255} ** array.len,
        .Pointer => |pointer| switch (pointer.size) {
            .One => switch (@typeInfo(pointer.child)) {
                .Array => |array| if (array.child == u8) {
                    const Array = if (array.sentinel) |s_ptr|
                        [array.len:sig.utils.types.comptimeZeroSizePtrCast(array.child, s_ptr)]u8
                    else
                        [array.len]u8;
                    const result: Array align(pointer.alignment) = .{255} ** array.len;
                    return &result;
                },
                else => {},
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
            .Struct => |info| info,
        };
        if (structure.fields.len != 1) return null;
        if (!@hasField(T, "bounded")) return null;
        const Bounded = switch (@typeInfo(structure.fields[0].type)) {
            else => return null,
            .Pointer => |info| switch (info.size) {
                else => return null,
                .One => info.child,
            },
        };
        const ba_info = sig.utils.types.boundedArrayInfo(Bounded) orelse return null;
        if (ba_info.Elem != u8) return null;

        const Actual = BoundedString(ba_info.capacity);
        if (T != Actual) return null;

        const bounded = ba_info.Type().fromSlice(&[_]u8{255} ** ba_info.capacity) catch unreachable;
        return boundedString(&bounded);
    }
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
        comptime fmt_str: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (comptime !std.mem.eql(u8, fmt_str, "s")) std.fmt.invalidFmtError(fmt_str, fmt);

        var path_buf: [std.fs.max_path_bytes]u8 = undefined;

        if (fmt.dir.realpath(fmt.pathname, &path_buf)) |real_path| {
            try writer.writeAll(real_path);
        } else |err| {
            try writer.print("(error.{s})/{s}", .{
                @errorName(err), fmt.pathname,
            });
        }
    }
};

pub inline fn hashMapFmt(hash_map: anytype, sep: []const u8) if (sig.utils.types.hashMapInfo(@TypeOf(hash_map.*))) |hm_info| HashMapFmt(hm_info) else noreturn {
    const Hm = @TypeOf(hash_map.*);
    if (sig.utils.types.hashMapInfo(Hm) == null) @compileError("Expected pointer to hash map, got " ++ @typeName(Hm));
    return .{
        .map = hash_map,
        .sep = sep,
    };
}

pub fn HashMapFmt(comptime hm_info: sig.utils.types.HashMapInfo) type {
    return struct {
        map: *const hm_info.Type(),
        sep: []const u8,
        const Self = @This();

        pub fn format(
            fmt: Self,
            comptime combo_fmt_str: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            const key_fmt, const val_fmt = comptime blk: {
                var key_fmt: []const u8 = "";

                var i = 0;
                while (std.mem.indexOfScalarPos(u8, combo_fmt_str, i, '|')) |pipe_idx| {
                    const start = i;
                    i = pipe_idx + 1;

                    if (!std.mem.startsWith(u8, combo_fmt_str[start + 1 ..], "|")) {
                        if (i == 0) break;
                        break :blk .{ key_fmt, combo_fmt_str[start + 1 ..] };
                    }

                    key_fmt = key_fmt ++ combo_fmt_str[0..i];
                    i += 1;
                }

                break :blk .{ combo_fmt_str[0..i], combo_fmt_str[i + 1 ..] };
            };

            var i: usize = 0;
            var iter = fmt.map.iterator();
            while (iter.next()) |entry| : (i += 1) {
                if (i != 0) try writer.writeAll(fmt.sep);
                try writer.print(
                    "{{ {" ++ key_fmt ++ "}, {" ++ val_fmt ++ "} }}",
                    .{ entry.key_ptr.*, entry.value_ptr.* },
                );
            }
        }
    };
}
