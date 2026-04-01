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

pub fn assertInterface(comptime Interface: type, comptime Contract: type) void {
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
