///! Dumping ground for random useful zig functions.
const std = @import("std");

/// A type that wraps a slice so that it can print the items formatted.
/// `{f}` on a such a slice in `writer.print()` doesn't work for some reason...
pub fn FmtSlice(comptime T: type) type {
    return struct {
        slice: []const T,

        pub fn format(self: @This(), writer: *std.Io.Writer) !void {
            try writer.writeAll("{ ");
            for (self.slice, 0..) |*item, i| {
                try item.format(writer);
                if (i < self.slice.len - 1) try writer.writeAll(", ");
            }
            try writer.writeAll(" }");
        }
    };
}

pub fn fmtSlice(slice: anytype) FmtSlice(@TypeOf(slice[0])) {
    return .{ .slice = slice };
}

pub fn assertInterface(comptime InterfaceType: type, comptime ContractStruct: type) void {
    const Contract = ContractStruct;
    const Interface = switch (@typeInfo(InterfaceType)) {
        .pointer => |info| switch (info.size) {
            .one => info.child,
            else => @compileError("assertInterface does not accept: " ++ @typeName(InterfaceType)),
        },
        else => InterfaceType,
    };

    const info = @typeInfo(Contract).@"struct";
    if (@typeInfo(Interface) != .@"struct") {
        @compileError(std.fmt.comptimePrint("Expected struct, found {s}", .{@typeName(Interface)}));
    }

    // Check interface has matching decls/functions.
    inline for (info.decls) |decl| {
        const Decl = @TypeOf(@field(Contract, decl.name));
        if (!@hasDecl(Interface, decl.name)) {
            @compileError(std.fmt.comptimePrint("{s} missing decl {s}:{s}", .{
                @typeName(Interface),
                decl.name,
                @typeName(Decl),
            }));
        }

        // TODO: support function types with error union returns.
        const IDecl = @TypeOf(@field(Interface, decl.name));
        if (@TypeOf(Decl) != @TypeOf(IDecl)) {
            @compileError(std.fmt.comptimePrint("{s}.{s} expected decl {s}, found {s}", .{
                @typeName(Interface),
                decl.name,
                @typeName(Decl),
                @typeName(IDecl),
            }));
        }
    }

    // Check Interface has contract's fields.
    for (info.fields) |field| {
        if (!@hasField(Interface, field.name)) {
            @compileError(std.fmt.comptimePrint("{s} missing field {s}:{s}", .{
                @typeName(Interface),
                field.name,
                @typeName(field.type),
            }));
        }

        const T = @FieldType(Interface, field.name);
        if (T != field.type) {
            @compileError(std.fmt.comptimePrint("{s}.{s} is {s}, expected {s}", .{
                @typeName(Interface),
                field.name,
                @typeName(T),
                @typeName(field.type),
            }));
        }
    }
}

/// A tightly packed optional value for data that can be represented in memory
/// as an integer.
///
/// This is only safe to use if you can be certain that it will never need to
/// represent the maxInt for the backing integer.
pub fn PackedOptional(T: type) type {
    const Int = @as(?type, switch (@typeInfo(T)) {
        .int => T,
        .@"enum" => |info| info.tag_type,
        .@"struct" => |s| s.backing_integer,
        else => null,
    }) orelse @compileError("Unsupported type for PackedOptional(_): " ++ @typeName(T));

    return enum(Int) {
        null = std.math.maxInt(Int),
        _,

        pub fn init(zig_optional: ?T) PackedOptional(T) {
            if (zig_optional) |x| {
                const int = switch (@typeInfo(T)) {
                    .int => x,
                    .@"enum" => @intFromEnum(x),
                    .@"struct" => @as(Int, @bitCast(x)),
                    else => unreachable,
                };
                std.debug.assert(int != std.math.maxInt(Int));
                return @enumFromInt(int);
            } else return .null;
        }

        pub fn opt(self: PackedOptional(T)) ?T {
            if (self == .null) return null;
            return switch (@typeInfo(T)) {
                .int => @intFromEnum(self),
                .@"enum" => @enumFromInt(@intFromEnum(self)),
                .@"struct" => @as(T, @bitCast(@intFromEnum(self))),
                else => unreachable,
            };
        }

        pub fn format(self: PackedOptional(T), writer: *std.Io.Writer) !void {
            const value = self.opt() orelse return writer.writeAll("null");
            if (comptime std.meta.hasMethod(T, "format")) {
                try writer.print("{f}", .{value});
            } else {
                try writer.print("{any}", .{value});
            }
        }
    };
}

test PackedOptional {
    const T = packed struct { a: u32, b: u32 };
    const o1: PackedOptional(T) = .init(null);
    const o2: PackedOptional(T) = .init(T{ .a = 1234, .b = 5678 });
    try std.testing.expect(o1.opt() == null);
    try std.testing.expect(o2.opt().? == T{ .a = 1234, .b = 5678 });
}

test "PackedOptional format matches ?T" {
    const E = enum(u8) { a, b, c };
    const S = packed struct { a: u16, b: u16 };
    const F = enum(u8) {
        x,
        y,
        pub fn format(self: @This(), writer: *std.Io.Writer) !void {
            try writer.print("F({t})", .{self});
        }
    };

    inline for (.{
        .{ "{?any}", @as(?u32, null) },
        .{ "{?any}", @as(?u32, 12345) },
        .{ "{?any}", @as(?E, null) },
        .{ "{?any}", @as(?E, .b) },
        .{ "{?any}", @as(?S, null) },
        .{ "{?any}", @as(?S, .{ .a = 1, .b = 2 }) },
        .{ "{?f}", @as(?F, null) },
        .{ "{?f}", @as(?F, .x) },
    }) |case| {
        const fmt, const value = case;
        const po: PackedOptional(@typeInfo(@TypeOf(value)).optional.child) = .init(value);
        var expect_buf: [32]u8 = undefined;
        var actual_buf: [32]u8 = undefined;
        const actual = try std.fmt.bufPrint(&actual_buf, "{f}", .{po});
        const expect = try std.fmt.bufPrint(&expect_buf, fmt, .{value});
        try std.testing.expectEqualStrings(expect, actual);
    }
}

/// Convert integer division into multiplication & shift using reciprocals:
/// https://gist.github.com/B-Y-P/5872dbaaf768c204480109007f64a915
pub const FastDiv = extern struct {
    rcp_mul: u64,
    rcp_shr: u8,

    pub fn init(n: u64) FastDiv {
        std.debug.assert(n > 1);
        std.debug.assert(n < (1 << 63));

        const bits = std.math.log2_int_ceil(u63, @intCast(n));
        const shr: u6 = @intCast((@as(u32, bits) + 63) - 64);

        const hi, const lo = .{ @as(u64, 1) << shr, n - 1 };
        const rcp: u64 = @intCast(((@as(u128, hi) << 64) | lo) / n);
        return .{ .rcp_mul = rcp, .rcp_shr = shr };
    }

    pub fn div(self: *const FastDiv, x: u64) u64 {
        const mul_hi: u64 = @truncate((@as(u128, x) * self.rcp_mul) >> 64);
        return mul_hi >> @intCast(self.rcp_shr);
    }
};

test "FastDiv basic division" {
    const d = FastDiv.init(3);
    try std.testing.expectEqual(@as(u64, 0), d.div(0));
    try std.testing.expectEqual(@as(u64, 0), d.div(1));
    try std.testing.expectEqual(@as(u64, 0), d.div(2));
    try std.testing.expectEqual(@as(u64, 1), d.div(3));
    try std.testing.expectEqual(@as(u64, 3), d.div(9));
    try std.testing.expectEqual(@as(u64, 3), d.div(10));
    try std.testing.expectEqual(@as(u64, 3), d.div(11));
    try std.testing.expectEqual(@as(u64, 4), d.div(12));
}

test "FastDiv powers of two" {
    inline for (.{ 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024 }) |n| {
        const d = FastDiv.init(n);
        try std.testing.expectEqual(@as(u64, 0), d.div(0));
        try std.testing.expectEqual(@as(u64, 1), d.div(n));
        try std.testing.expectEqual(@as(u64, 0), d.div(n - 1));
        try std.testing.expectEqual(@as(u64, 10), d.div(n * 10));
        try std.testing.expectEqual(@as(u64, 100), d.div(n * 100));
    }
}

test "FastDiv primes" {
    inline for (.{ 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 97, 127 }) |n| {
        const d = FastDiv.init(n);
        for (0..1000) |x| {
            try std.testing.expectEqual(@as(u64, x / n), d.div(x));
        }
    }
}

test "FastDiv large divisors" {
    const cases = [_]u64{ 1000, 10000, 100000, 1_000_000, 1 << 20, 1 << 30, (1 << 62) - 1 };
    for (cases) |n| {
        const d = FastDiv.init(n);
        try std.testing.expectEqual(@as(u64, 0), d.div(0));
        try std.testing.expectEqual(@as(u64, 1), d.div(n));
        try std.testing.expectEqual(@as(u64, 0), d.div(n - 1));
        try std.testing.expectEqual(@as(u64, 2), d.div(n * 2));
    }
}

test "FastDiv large dividends" {
    const d = FastDiv.init(7);
    const large = @as(u64, 1) << 50;
    try std.testing.expectEqual(large / 7, d.div(large));
    try std.testing.expectEqual((large - 1) / 7, d.div(large - 1));
    try std.testing.expectEqual((large + 1) / 7, d.div(large + 1));
}

test "FastDiv divide by 2" {
    const d = FastDiv.init(2);
    try std.testing.expectEqual(@as(u64, 0), d.div(0));
    try std.testing.expectEqual(@as(u64, 0), d.div(1));
    try std.testing.expectEqual(@as(u64, 1), d.div(2));
    try std.testing.expectEqual(@as(u64, 1), d.div(3));
    try std.testing.expectEqual(@as(u64, 500), d.div(1000));
}

/// A statically-sized enum-keyed map, with preserved insertion order.
/// Lookup and insertion are `O(n)`.
pub fn ArrayEnumMap(comptime E: type, comptime V: type) type {
    const enum_info = @typeInfo(E).@"enum";
    return struct {
        keys_buf: [enum_info.fields.len]E,
        values_buf: [enum_info.fields.len]V,
        len: Count,

        const ArrayEnumMapSelf = @This();

        pub const empty: ArrayEnumMapSelf = .{
            .keys_buf = undefined,
            .values_buf = undefined,
            .len = 0,
        };

        pub const Count = std.math.IntFittingRange(0, enum_info.fields.len);

        pub const Index = std.math.IntFittingRange(0, enum_info.fields.len -| 1);

        fn getIndex(self: *const ArrayEnumMapSelf, key: E) ?Index {
            const index = std.mem.indexOfScalar(E, self.keys_buf[0..self.len], key) orelse
                return null;
            switch (@import("builtin").mode) {
                .Debug, .ReleaseSafe => if (std.mem.indexOfScalarPos(
                    E,
                    self.keys_buf[0..self.len],
                    index + 1,
                    key,
                )) |duplicate| {
                    std.debug.panic(
                        "Multiple instances of `{t}` in map, at indices {} and {}.",
                        .{ key, index, duplicate },
                    );
                },
                .ReleaseFast, .ReleaseSmall => {},
            }
            return @intCast(index);
        }

        pub fn keys(self: *const ArrayEnumMapSelf) []const E {
            return self.keys_buf[0..self.len];
        }

        pub fn values(self: *const ArrayEnumMapSelf) []const V {
            return self.values_buf[0..self.len];
        }

        pub fn contains(self: *const ArrayEnumMapSelf, key: E) bool {
            return self.getIndex(key) != null;
        }

        pub fn get(self: *const ArrayEnumMapSelf, key: E) ?*const V {
            return &self.values_buf[self.getIndex(key) orelse return null];
        }

        pub fn getMut(self: *ArrayEnumMapSelf, key: E) ?*V {
            return &self.values_buf[self.getIndex(key) orelse return null];
        }

        pub fn putNoClobber(self: *ArrayEnumMapSelf, key: E, value: V) void {
            const gop = self.getOrPut(key);
            std.debug.assert(!gop.found_existing);
            gop.value_ptr.* = value;
        }

        pub const GetOrPutResult = struct {
            found_existing: bool,
            value_ptr: *V,
        };

        pub fn getOrPut(self: *ArrayEnumMapSelf, key: E) GetOrPutResult {
            if (self.getIndex(key)) |existing| return .{
                .found_existing = true,
                .value_ptr = &self.values_buf[existing],
            };

            const index: Index = @intCast(self.len);
            self.len += 1;
            std.debug.assert(index < enum_info.fields.len);
            self.keys_buf[index] = key;
            self.values_buf[index] = undefined;

            return .{
                .found_existing = false,
                .value_ptr = &self.values_buf[index],
            };
        }

        pub const IteratorMut = Iterator(.mut);

        pub fn iteratorMut(self: *ArrayEnumMapSelf) IteratorMut {
            return .{ .map = self, .index = 0 };
        }

        pub const IteratorImmut = Iterator(.immut);

        pub fn iteratorImmut(self: *const ArrayEnumMapSelf) IteratorImmut {
            return .{ .map = self, .index = 0 };
        }

        fn Iterator(comptime mutability: enum { mut, immut }) type {
            return struct {
                map: switch (mutability) {
                    .mut => *ArrayEnumMapSelf,
                    .immut => *const ArrayEnumMapSelf,
                },
                index: Count,

                const IteratorSelf = @This();

                const ValuePtr = switch (mutability) {
                    .mut => *V,
                    .immut => *const V,
                };

                pub const Entry = struct {
                    key: E,
                    value: ValuePtr,

                    pub fn destructure(entry: Entry) struct { E, ValuePtr } {
                        return .{ entry.key, entry.value };
                    }
                };

                pub fn next(self: *IteratorSelf) ?Entry {
                    if (self.index == self.map.len) return null;
                    defer self.index += 1;
                    return .{
                        .key = self.map.keys_buf[self.index],
                        .value = &self.map.values_buf[self.index],
                    };
                }

                pub fn nextKey(self: *IteratorSelf) ?E {
                    const entry = self.next() orelse return null;
                    return entry.key;
                }

                pub fn nextValue(self: *IteratorSelf) ?ValuePtr {
                    const entry = self.next() orelse return null;
                    return entry.value;
                }
            };
        }
    };
}
