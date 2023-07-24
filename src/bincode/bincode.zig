const std = @import("std");
const testing = std.testing;
const bincode = @This();

pub const SerializeFunction = fn (writer: anytype, data: anytype, params: bincode.Params) anyerror!void;
pub const DeserializeFunction = fn (gpa: std.mem.Allocator, comptime T: type, reader: anytype, params: bincode.Params) anyerror!void;

pub const FieldConfig = struct {
    serializer: ?SerializeFunction = null,
    deserializer: ?DeserializeFunction = null,
    skip: bool = false,
};

pub const StructConfig = struct {
    serializer: ?SerializeFunction = null,
    deserializer: ?DeserializeFunction = null,
};

pub fn getStructSerializer(comptime parent_type: type) ?SerializeFunction {
    if (@hasDecl(parent_type, "!bincode-config")) {
        const config = @field(parent_type, "!bincode-config");
        return config.serializer;
    }
    return null;
}

pub fn getStructDeserializer(comptime parent_type: type) ?DeserializeFunction {
    if (@hasDecl(parent_type, "!bincode-config")) {
        const config = @field(parent_type, "!bincode-config");
        return config.deserializer;
    }
    return null;
}

pub fn getFieldSerializer(comptime parent_type: type, comptime struct_field: std.builtin.Type.StructField) ?SerializeFunction {
    if (@hasDecl(parent_type, "!bincode-config:" ++ struct_field.name)) {
        const config = @field(parent_type, "!bincode-config:" ++ struct_field.name);
        return config.serializer;
    }
    return null;
}

pub fn getFieldDeserializer(comptime parent_type: type, comptime struct_field: std.builtin.Type.StructField) ?DeserializeFunction {
    if (@hasDecl(parent_type, "!bincode-config:" ++ struct_field.name)) {
        const config = @field(parent_type, "!bincode-config:" ++ struct_field.name);
        return config.deserializer;
    }
    return null;
}

pub inline fn shouldSkipSerializingField(comptime parent_type: type, comptime struct_field: std.builtin.Type.StructField) bool {
    const parent_type_name = @typeName(parent_type);

    if (@hasDecl(parent_type, "!bincode-config:" ++ struct_field.name)) {
        const config = @field(parent_type, "!bincode-config:" ++ struct_field.name);
        if (config.skip and struct_field.default_value == null) {
            @compileError("┓\n|\n|--> Invalid config: cannot skip field '" ++ parent_type_name ++ "." ++ struct_field.name ++ "' serialization if no default value set\n\n");
        }
        return config.skip;
    }

    return false;
}

pub inline fn shouldUseDefaultValue(comptime parent_type: type, comptime struct_field: std.builtin.Type.StructField) ?*const anyopaque {
    const parent_type_name = @typeName(parent_type);

    if (@hasDecl(parent_type, "!bincode-config:" ++ struct_field.name)) {
        const config = @field(parent_type, "!bincode-config:" ++ struct_field.name);
        if (config.skip and struct_field.default_value == null) {
            @compileError("┓\n|\n|--> Invalid config: cannot skip field '" ++ parent_type_name ++ "." ++ struct_field.name ++ "' deserialization if no default value set\n\n");
        }
        return struct_field.default_value;
    }

    return null;
}

pub const Params = struct {
    pub const legacy: Params = .{
        .endian = .Little,
        .int_encoding = .fixed,
        .include_fixed_array_length = true,
    };

    pub const standard: Params = .{
        .endian = .Little,
        .int_encoding = .fixed,
        .include_fixed_array_length = false,
    };

    endian: std.builtin.Endian = .Little,
    int_encoding: enum { variable, fixed } = .fixed,
    include_fixed_array_length: bool = false,
};

/// An optional type whose enum tag is 32 bits wide.
pub fn Option(comptime T: type) type {
    return union(enum(u32)) {
        none: T,
        some: T,

        pub fn from(inner: ?T) @This() {
            if (inner) |payload| {
                return .{ .some = payload };
            }
            return .{ .none = std.mem.zeroes(T) };
        }

        pub fn into(self: @This()) ?T {
            return switch (self) {
                .some => |payload| payload,
                .none => null,
            };
        }

        pub fn format(self: @This(), comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
            return switch (self) {
                .none => writer.writeAll("null"),
                .some => |payload| writer.print("{any}", .{payload}),
            };
        }
    };
}

pub fn sizeOf(data: anytype, params: bincode.Params) usize {
    var stream = std.io.countingWriter(std.io.null_writer);
    bincode.write(stream.writer(), data, params) catch unreachable;
    return @intCast(stream.bytes_written);
}

pub fn readFromSlice(gpa: std.mem.Allocator, comptime T: type, slice: []const u8, params: bincode.Params) !T {
    var stream = std.io.fixedBufferStream(slice);
    return bincode.read(gpa, T, stream.reader(), params);
}

pub fn writeToSlice(slice: []u8, data: anytype, params: bincode.Params) ![]u8 {
    var stream = std.io.fixedBufferStream(slice);
    try bincode.write(stream.writer(), data, params);
    return stream.getWritten();
}

pub inline fn writeAlloc(gpa: std.mem.Allocator, data: anytype, params: bincode.Params) ![]u8 {
    const buffer = try gpa.alloc(u8, bincode.sizeOf(data, params));
    errdefer gpa.free(buffer);
    return try bincode.writeToSlice(buffer, data, params);
}

pub fn read(gpa: std.mem.Allocator, comptime T: type, reader: anytype, params: bincode.Params) !T {
    const U = switch (T) {
        usize => u64,
        isize => i64,
        else => T,
    };

    switch (@typeInfo(U)) {
        .Void => return {},
        .Bool => return switch (try reader.readByte()) {
            0 => false,
            1 => true,
            else => error.BadBoolean,
        },
        .Enum => |info| {
            const tag = switch (params.int_encoding) {
                .variable => blk: { 
                    break :blk try bincode.read(gpa, if (@typeInfo(info.tag_type).Int.bits < 8) u8 else info.tag_type, reader, params);
                }, 
                .fixed => blk: { 
                    // Enum discriminants are encoded as u32
                    break :blk try bincode.read(gpa, u32, reader, params);
                }
            };
            return std.meta.intToEnum(U, tag);
        },
        .Union => |info| {
            const tag_type = info.tag_type orelse @compileError("Only tagged unions may be read.");
            const raw_tag = try bincode.read(gpa, tag_type, reader, params);

            inline for (info.fields) |field| {
                if (raw_tag == @field(tag_type, field.name)) {
                    // https://github.com/ziglang/zig/issues/7866
                    if (field.type == void) return @unionInit(U, field.name, {});

                    const payload = try bincode.read(gpa, field.type, reader, params);
                    return @unionInit(U, field.name, payload);
                }
            }

            return error.UnknownUnionTag;
        },
        .Struct => |info| {
            var data: U = undefined;
            if (getStructDeserializer(U)) |deserializer| {
                data = try deserializer(gpa, U, reader, params);
                return data;
            }

            inline for (info.fields) |field| {
                if (!field.is_comptime) {
                    if (shouldUseDefaultValue(U, field)) |val| {
                        @field(data, field.name) = @as(*const field.type, @ptrCast(@alignCast(val))).*;
                    } else if (getFieldDeserializer(U, field)) |deserializer| {
                        @field(data, field.name) = try deserializer(gpa, field.type, reader, params);
                    } else {
                        @field(data, field.name) = try bincode.read(gpa, field.type, reader, params);
                    }
                }
            }
            return data;
        },
        .Optional => |info| {
            return switch (try reader.readByte()) {
                0 => null,
                1 => try bincode.read(gpa, info.child, reader, params),
                else => error.BadOptionalBoolean,
            };
        },
        .Array => |info| {
            var data: U = undefined;
            if (params.include_fixed_array_length) {
                const fixed_array_len = try bincode.read(gpa, u64, reader, params);
                if (fixed_array_len != info.len) {
                    return error.UnexpectedFixedArrayLen;
                }
            }
            for (&data) |*element| {
                element.* = try bincode.read(gpa, info.child, reader, params);
            }
            return data;
        },
        .Vector => |info| {
            var data: U = undefined;
            if (params.include_fixed_array_length) {
                const fixed_array_len = try bincode.read(gpa, u64, reader, params);
                if (fixed_array_len != info.len) {
                    return error.UnexpectedFixedArrayVectorLen;
                }
            }
            for (data) |*element| {
                element.* = try bincode.read(gpa, info.child, reader, params);
            }
            return data;
        },
        .Pointer => |info| {
            switch (info.size) {
                // .One => {
                //     const data = try gpa.create(info.child);
                //     errdefer gpa.destroy(data);
                //     data.* = try bincode.read(gpa, info.child, reader, params);
                //     return data;
                // },
                .Slice => {
                    const entries = try gpa.alloc(info.child, try bincode.read(gpa, usize, reader, params));
                    errdefer gpa.free(entries);
                    for (entries) |*entry| {
                        entry.* = try bincode.read(gpa, info.child, reader, params);
                    }
                    return entries;
                },
                else => {},
            }
        },
        .ComptimeFloat => return bincode.read(gpa, f64, reader, params),
        .Float => |info| {
            if (info.bits != 32 and info.bits != 64) {
                @compileError("Only f{32, 64} floating-point integers may be serialized, but attempted to serialize " ++ @typeName(U) ++ ".");
            }
            const bytes = try reader.readBytesNoEof((info.bits + 7) / 8);
            return @as(U, @bitCast(bytes));
        },
        .ComptimeInt => return bincode.read(gpa, u64, reader, params),
        .Int => |info| {
            if ((info.bits & (info.bits - 1)) != 0 or info.bits < 8 or info.bits > 256) {
                @compileError("Only i{8, 16, 32, 64, 128, 256}, u{8, 16, 32, 64, 128, 256} integers may be deserialized, but attempted to deserialize " ++ @typeName(U) ++ ".");
            }

            switch (params.int_encoding) {
                .variable => {
                    const b = try reader.readByte();
                    if (b < 251) {
                        return switch (info.signedness) {
                            .unsigned => b,
                            .signed => zigzag: {
                                if (b % 2 == 0) {
                                    break :zigzag @as(U, @intCast(b / 2));
                                } else {
                                    break :zigzag ~@as(U, @bitCast(@as(std.meta.Int(.unsigned, info.bits), b / 2)));
                                }
                            },
                        };
                    } else if (b == 251) {
                        const z = try switch (params.endian) {
                            .Little => reader.readIntLittle(u16),
                            .Big => reader.readIntBig(u16),
                        };
                        return switch (info.signedness) {
                            .unsigned => std.math.cast(U, z) orelse return error.FailedToCastZZ,
                            .signed => zigzag: {
                                if (z % 2 == 0) {
                                    break :zigzag std.math.cast(U, z / 2) orelse return error.FailedToCastZZ;
                                } else {
                                    break :zigzag ~(std.math.cast(U, z / 2) orelse return error.FailedToCastZZ);
                                }
                            },
                        };
                    } else if (b == 252) {
                        const z = try switch (params.endian) {
                            .Little => reader.readIntLittle(u32),
                            .Big => reader.readIntBig(u32),
                        };
                        return switch (info.signedness) {
                            .unsigned => std.math.cast(U, z) orelse return error.FailedToCastZZ,
                            .signed => zigzag: {
                                if (z % 2 == 0) {
                                    break :zigzag std.math.cast(U, z / 2) orelse return error.FailedToCastZZ;
                                } else {
                                    break :zigzag ~(std.math.cast(U, z / 2) orelse return error.FailedToCastZZ);
                                }
                            },
                        };
                    } else if (b == 253) {
                        const z = try switch (params.endian) {
                            .Little => reader.readIntLittle(u64),
                            .Big => reader.readIntBig(u64),
                        };
                        return switch (info.signedness) {
                            .unsigned => std.math.cast(U, z) orelse return error.FailedToCastZZ,
                            .signed => zigzag: {
                                if (z % 2 == 0) {
                                    break :zigzag std.math.cast(U, z / 2) orelse return error.FailedToCastZZ;
                                } else {
                                    break :zigzag ~(std.math.cast(U, z / 2) orelse return error.FailedToCastZZ);
                                }
                            },
                        };
                    } else if (b == 254) {
                        const z = try switch (params.endian) {
                            .Little => reader.readIntLittle(u128),
                            .Big => reader.readIntBig(u128),
                        };
                        return switch (info.signedness) {
                            .unsigned => std.math.cast(U, z) orelse return error.FailedToCastZZ,
                            .signed => zigzag: {
                                if (z % 2 == 0) {
                                    break :zigzag std.math.cast(U, z / 2) orelse return error.FailedToCastZZ;
                                } else {
                                    break :zigzag ~(std.math.cast(U, z / 2) orelse return error.FailedToCastZZ);
                                }
                            },
                        };
                    } else {
                        const z = try switch (params.endian) {
                            .Little => reader.readIntLittle(u256),
                            .Big => reader.readIntBig(u256),
                        };
                        return switch (info.signedness) {
                            .unsigned => std.math.cast(U, z) orelse return error.FailedToCastZZ,
                            .signed => zigzag: {
                                if (z % 2 == 0) {
                                    break :zigzag std.math.cast(U, z / 2) orelse return error.FailedToCastZZ;
                                } else {
                                    break :zigzag ~(std.math.cast(U, z / 2) orelse return error.FailedToCastZZ);
                                }
                            },
                        };
                    }
                },
                .fixed => return switch (params.endian) {
                    .Little => reader.readIntLittle(U),
                    .Big => reader.readIntBig(U),
                },
            }
        },
        else => {},
    }

    @compileError("Deserializing '" ++ @typeName(U) ++ "' is unsupported.");
}

pub fn readFree(gpa: std.mem.Allocator, value: anytype) void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .Array, .Vector => {
            for (value) |element| {
                bincode.readFree(gpa, element);
            }
        },
        .Struct => |info| {
            inline for (info.fields) |field| {
                if (!field.is_comptime) {
                    bincode.readFree(gpa, @field(value, field.name));
                }
            }
        },
        .Optional => {
            if (value) |v| {
                bincode.readFree(gpa, v);
            }
        },
        .Union => |info| {
            inline for (info.fields) |field| {
                if (value == @field(T, field.name)) {
                    return bincode.readFree(gpa, @field(value, field.name));
                }
            }
        },
        .Pointer => |info| {
            switch (info.size) {
                // .One => gpa.destroy(value),
                .Slice => {
                    for (value) |item| {
                        bincode.readFree(gpa, item);
                    }
                    gpa.free(value);
                },
                else => {},
            }
        },
        else => {},
    }
}

pub fn write(writer: anytype, data: anytype, params: bincode.Params) !void {
    const T = switch (@TypeOf(data)) {
        usize => u64,
        isize => i64,
        else => @TypeOf(data),
    };

    switch (@typeInfo(T)) {
        .Type, .Void, .NoReturn, .Undefined, .Null, .Fn, .Opaque, .Frame, .AnyFrame => return,
        .Bool => return writer.writeByte(@intFromBool(data)),
        .Enum => |info| { 
            // return bincode.write(writer, if (@typeInfo(info.tag_type).Int.bits < 8) @as(u8, @enumToInt(data)) else @enumToInt(data), params);
            switch (params.int_encoding) {
                .variable => { 
                    return bincode.write(writer, if (@typeInfo(info.tag_type).Int.bits < 8) @as(u8, @intFromEnum(data)) else @intFromEnum(data), params);
                }, 
                .fixed => { 
                    // Enum discriminants are encoded as u32
                    return bincode.write(writer, @as(u32, @intFromEnum(data)), params);
                }
            }
        },
        .Union => |info| {
            // try bincode.write(writer, @intFromEnum(data), params);
            switch (params.int_encoding) {
                .variable => { 
                    try bincode.write(writer, @intFromEnum(data), params);
                }, 
                .fixed => { 
                    try bincode.write(writer, @as(u32, @intFromEnum(data)), params);
                }
            }

            inline for (info.fields) |field| {
                if (data == @field(T, field.name)) {
                    return bincode.write(writer, @field(data, field.name), params);
                }
            }
            return;
        },
        .Struct => |info| {
            if (getStructSerializer(T)) |serializer| {
                return serializer(writer, data, params);
            }
            var maybe_err: anyerror!void = {};
            inline for (info.fields) |field| {
                if (!field.is_comptime) {
                    if (@as(?anyerror!void, maybe_err catch null) != null) {
                        if (!shouldSkipSerializingField(T, field)) {
                            if (getFieldSerializer(T, field)) |serializer| {
                                maybe_err = serializer(writer, @field(data, field.name), params);
                            } else {
                                maybe_err = bincode.write(writer, @field(data, field.name), params);
                            }
                        }
                    }
                }
            }
            return maybe_err;
        },
        .Optional => {
            if (data) |value| {
                try writer.writeByte(1);
                try bincode.write(writer, value, params);
            } else {
                try writer.writeByte(0);
            }
            return;
        },
        .Array, .Vector => {
            if (params.include_fixed_array_length) {
                try bincode.write(writer, std.math.cast(u64, data.len) orelse return error.DataTooLarge, params);
            }
            for (data) |element| {
                try bincode.write(writer, element, params);
            }
            return;
        },
        .Pointer => |info| {
            switch (info.size) {
                // .One => return bincode.write(writer, data.*, params),
                .Many => return bincode.write(writer, std.mem.span(data), params),
                .Slice => {
                    try bincode.write(writer, std.math.cast(u64, data.len) orelse return error.DataTooLarge, params);
                    for (data) |element| {
                        try bincode.write(writer, element, params);
                    }
                    return;
                },
                else => {},
            }
        },
        .ComptimeFloat => return bincode.write(writer, @as(f64, data), params),
        .Float => |info| {
            if (info.bits != 32 and info.bits != 64) {
                @compileError("Only f{32, 64} floating-point integers may be serialized, but attempted to serialize " ++ @typeName(T) ++ ".");
            }
            return writer.writeAll(std.mem.asBytes(&data));
        },
        .ComptimeInt => {
            if (data < 0) {
                @compileError("Signed comptime integers can not be serialized.");
            }
            return bincode.write(writer, @as(u64, data), params);
        },
        .Int => |info| {
            if ((info.bits & (info.bits - 1)) != 0 or info.bits < 8 or info.bits > 256) {
                @compileError("Only i{8, 16, 32, 64, 128, 256}, u{8, 16, 32, 64, 128, 256} integers may be serialized, but attempted to serialize " ++ @typeName(T) ++ ".");
            }

            switch (params.int_encoding) {
                .variable => {
                    const z = switch (info.signedness) {
                        .unsigned => data,
                        .signed => zigzag: {
                            if (data < 0) {
                                break :zigzag ~@as(std.meta.Int(.unsigned, info.bits), @bitCast(data)) * 2 + 1;
                            } else {
                                break :zigzag @as(std.meta.Int(.unsigned, info.bits), @intCast(data)) * 2;
                            }
                        },
                    };

                    if (z < 251) {
                        return writer.writeByte(@as(u8, @intCast(z)));
                    } else if (z <= std.math.maxInt(u16)) {
                        try writer.writeByte(251);
                        return switch (params.endian) {
                            .Little => writer.writeIntLittle(u16, @as(u16, @intCast(z))),
                            .Big => writer.writeIntBig(u16, @as(u16, @intCast(z))),
                        };
                    } else if (z <= std.math.maxInt(u32)) {
                        try writer.writeByte(252);
                        return switch (params.endian) {
                            .Little => writer.writeIntLittle(u32, @as(u32, @intCast(z))),
                            .Big => writer.writeIntBig(u32, @as(u32, @intCast(z))),
                        };
                    } else if (z <= std.math.maxInt(u64)) {
                        try writer.writeByte(253);
                        return switch (params.endian) {
                            .Little => writer.writeIntLittle(u64, @as(u64, @intCast(z))),
                            .Big => writer.writeIntBig(u64, @as(u64, @intCast(z))),
                        };
                    } else if (z <= std.math.maxInt(u128)) {
                        try writer.writeByte(254);
                        return switch (params.endian) {
                            .Little => writer.writeIntLittle(u128, @as(u128, @intCast(z))),
                            .Big => writer.writeIntBig(u128, @as(u128, @intCast(z))),
                        };
                    } else {
                        try writer.writeByte(255);
                        return switch (params.endian) {
                            .Little => writer.writeIntLittle(u256, @as(u256, @intCast(z))),
                            .Big => writer.writeIntBig(u256, @as(u256, @intCast(z))),
                        };
                    }
                },
                .fixed => return switch (params.endian) {
                    .Little => writer.writeIntLittle(T, data),
                    .Big => writer.writeIntBig(T, data),
                },
            }
        },
        else => {},
    }

    @compileError("Serializing '" ++ @typeName(T) ++ "' is unsupported.");
}

test "bincode: fixed length enums" { 
    const Foo = union(enum(u8)) {
        A: u32, 
        B: u32
    };

    const expected = [_]u8 { 1, 0, 0, 0, 1, 1, 1, 1};
    const value = Foo {
        .B = 16843009
    };

    var buffer = [_]u8{ 0 } ** 10;
    const buf = try bincode.writeToSlice(&buffer, value, bincode.Params.standard);
    try testing.expectEqualSlices(u8, &expected, buf[0..buf.len]);

    // read it back 
    const value2 = try bincode.readFromSlice(testing.allocator, Foo, &buffer, bincode.Params.standard);
    std.debug.print("{any} {any}\n", .{value, value2});
    try testing.expectEqual(value, value2);
}

test "bincode: decode arbitrary object" {
    const Mint = struct {
        authority: bincode.Option([32]u8),
        supply: u64,
        decimals: u8,
        is_initialized: bool,
        freeze_authority: bincode.Option([32]u8),
    };

    const bytes = [_]u8{
        1,   0,   0,   0,   83,  18,  223, 14,  150, 112, 155, 39,  143, 181,
        58,  12,  16,  228, 56,  110, 253, 193, 149, 16,  253, 81,  214, 206,
        246, 126, 227, 182, 123, 225, 246, 203, 1,   0,   0,   0,   0,   0,
        0,   0,   0,   1,   1,   0,   0,   0,   0,   0,   0,   83,  18,  223,
        14,  150, 112, 155, 39,  143, 181, 58,  12,  16,  228, 56,  110, 253,
        193, 149, 16,  253, 81,  214, 206, 246, 126, 227, 182, 123,
    };
    const mint = try bincode.readFromSlice(testing.allocator, Mint, &bytes, .{});
    defer bincode.readFree(testing.allocator, mint);

    try std.testing.expectEqual(@as(u64, 1), mint.supply);
    try std.testing.expectEqual(@as(u8, 0), mint.decimals);
    try std.testing.expectEqual(true, mint.is_initialized);
    try std.testing.expect(mint.authority == .some);
    try std.testing.expect(mint.freeze_authority == .some);
}

test "bincode: option serialize and deserialize" {
    const Mint = struct {
        authority: bincode.Option([32]u8),
        supply: u64,
        decimals: u8,
        is_initialized: bool,
        freeze_authority: bincode.Option([32]u8),
    };

    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    const expected: Mint = .{
        .authority = bincode.Option([32]u8).from([_]u8{ 1, 2, 3, 4 } ** 8),
        .supply = 1,
        .decimals = 0,
        .is_initialized = true,
        .freeze_authority = bincode.Option([32]u8).from([_]u8{ 5, 6, 7, 8 } ** 8),
    };

    try bincode.write(buffer.writer(), expected, .{});

    try std.testing.expectEqual(@as(usize, 82), buffer.items.len);

    const actual = try bincode.readFromSlice(testing.allocator, Mint, buffer.items, .{});
    defer bincode.readFree(testing.allocator, actual);

    try std.testing.expectEqual(expected, actual);
}

test "bincode: serialize and deserialize" {
    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    inline for (.{ .{}, .{ .int_encoding = .variable }, bincode.Params.legacy, bincode.Params.standard }) |params| {
        inline for (.{
            @as(i8, std.math.minInt(i8)),
            @as(i16, std.math.minInt(i16)),
            @as(i32, std.math.minInt(i32)),
            @as(i64, std.math.minInt(i64)),
            @as(usize, std.math.minInt(usize)),
            @as(isize, std.math.minInt(isize)),
            @as(i8, std.math.maxInt(i8)),
            @as(i16, std.math.maxInt(i16)),
            @as(i32, std.math.maxInt(i32)),
            @as(i64, std.math.maxInt(i64)),
            @as(u8, std.math.maxInt(u8)),
            @as(u16, std.math.maxInt(u16)),
            @as(u32, std.math.maxInt(u32)),
            @as(u64, std.math.maxInt(u64)),
            @as(usize, std.math.maxInt(usize)),
            @as(isize, std.math.maxInt(isize)),

            @as(f32, std.math.floatMin(f32)),
            @as(f64, std.math.floatMin(f64)),
            @as(f32, std.math.floatMax(f32)),
            @as(f64, std.math.floatMax(f64)),

            [_]u8{ 0, 1, 2, 3 },
        }) |expected| {
            try bincode.write(buffer.writer(), expected, params);

            const actual = try bincode.readFromSlice(testing.allocator, @TypeOf(expected), buffer.items, params);
            defer bincode.readFree(testing.allocator, actual);

            try testing.expectEqual(expected, actual);
            buffer.clearRetainingCapacity();
        }
    }

    // inline for (.{ .{}, bincode.Params.legacy, bincode.Params.standard }) |params| {
    //     inline for (.{
    //         "hello world",
    //         @as([]const u8, "hello world"),
    //     }) |expected| {
    //         try bincode.write(buffer.writer(), expected, params);

    //         const actual = try bincode.readFromSlice(testing.allocator, @TypeOf(expected), buffer.items, params);
    //         defer bincode.readFree(testing.allocator, actual);

    //         try testing.expectEqualSlices(std.meta.Elem(@TypeOf(expected)), expected, actual);
    //         buffer.clearRetainingCapacity();
    //     }
    // }
}

test "bincode: (legacy) serialize an array" {
    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    const Foo = struct {
        first: u8,
        second: u8,
    };

    try bincode.write(buffer.writer(), [_]Foo{
        .{ .first = 10, .second = 20 },
        .{ .first = 30, .second = 40 },
    }, bincode.Params.legacy);

    try testing.expectEqualSlices(u8, &[_]u8{
        2, 0, 0, 0, 0, 0, 0, 0, // Length of the array
        10, 20, // First Foo
        30, 40, // Second Foo
    }, buffer.items);
}