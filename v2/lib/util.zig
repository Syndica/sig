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

// Initialize an undefined type instance without filling it with 0xAA in safe modes.
pub inline fn initUndefUnchecked(comptime T: type) T {
    @setRuntimeSafety(false);
    var init: T = undefined;
    _ = &init;
    return init;
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
    for (info.decls) |decl| {
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
