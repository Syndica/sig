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
