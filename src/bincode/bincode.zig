const std = @import("std");

const testing = std.testing;

const bincode = @This();

pub const Params = struct {
    pub const legacy: Params = .{
        .endian = .little,
        .int_encoding = .fixed,
        .include_fixed_array_length = true,
    };

    pub const standard: Params = .{};

    endian: std.builtin.Endian = .little,
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
    return @as(usize, @intCast(stream.bytes_written));
}

pub fn readFromSlice(allocator: std.mem.Allocator, comptime T: type, slice: []const u8, params: bincode.Params) !T {
    var stream = std.io.fixedBufferStream(slice);
    return bincode.read(allocator, T, stream.reader(), params);
}

pub fn writeToSlice(slice: []u8, data: anytype, params: bincode.Params) ![]u8 {
    var stream = std.io.fixedBufferStream(slice);
    try bincode.write(stream.writer(), data, params);
    return stream.getWritten();
}

pub inline fn writeAlloc(allocator: std.mem.Allocator, data: anytype, params: bincode.Params) ![]u8 {
    const buffer = try allocator.alloc(u8, bincode.sizeOf(data, params));
    errdefer allocator.free(buffer);
    return try bincode.writeToSlice(buffer, data, params);
}

pub fn read(allocator: std.mem.Allocator, comptime U: type, reader: anytype, params: bincode.Params) !U {
    const T = switch (U) {
        usize => u64,
        isize => i64,
        else => U,
    };

    switch (@typeInfo(T)) {
        .Void => return {},
        .Bool => return switch (try reader.readByte()) {
            0 => false,
            1 => true,
            else => error.BadBoolean,
        },
        .Enum => |_| {
            comptime var SerializedSize = u32;
            comptime if (@hasDecl(T, "BincodeSize")) {
                SerializedSize = T.BincodeSize;
            };

            const tag = switch (params.endian) {
                .little => reader.readInt(SerializedSize, .little),
                .big => reader.readInt(SerializedSize, .big),
            } catch {
                return error.EOF;
            };
            return std.meta.intToEnum(T, tag);
        },
        .Union => |info| {
            const tag_type = info.tag_type orelse @compileError("Only tagged unions may be read.");
            const raw_tag = try bincode.read(allocator, tag_type, reader, params);

            inline for (info.fields) |field| {
                if (raw_tag == @field(tag_type, field.name)) {
                    // https://github.com/ziglang/zig/issues/7866
                    if (field.type == void) return @unionInit(T, field.name, {});
                    const payload = try bincode.read(allocator, field.type, reader, params);
                    return @unionInit(T, field.name, payload);
                }
            }

            return error.UnknownUnionTag;
        },
        .Struct => |info| {
            var data: T = undefined;

            inline for (info.fields) |field| {
                if (!field.is_comptime) {
                    if (getFieldConfig(T, field)) |config| {
                        if (shouldUseDefaultValue(field, config)) |default_value| {
                            @field(data, field.name) = @as(*const field.type, @ptrCast(@alignCast(default_value))).*;
                            continue;
                        }

                        if (config.deserializer) |deser_fcn| {
                            @field(data, field.name) = try deser_fcn(allocator, reader, params);
                            continue;
                        }

                        if (config.default_on_eof) {
                            const field_type = field.type;

                            @field(data, field.name) = bincode.read(allocator, field_type, reader, params) catch {
                                @field(data, field.name) = @as(*const field_type, @ptrCast(@alignCast(field.default_value))).*;
                            };
                            continue;
                        }
                    }
                    errdefer {
                        std.debug.print("failed to deserialize field {s}\n", .{field.name});
                    }
                    @field(data, field.name) = try bincode.read(allocator, field.type, reader, params);
                }
            }
            return data;
        },
        .Optional => |info| {
            return switch (try reader.readByte()) {
                0 => null,
                1 => try bincode.read(allocator, info.child, reader, params),
                else => error.BadOptionalBoolean,
            };
        },
        .Array => |info| {
            var data: T = undefined;
            if (params.include_fixed_array_length) {
                const fixed_array_len = try bincode.read(allocator, u64, reader, params);
                if (fixed_array_len != info.len) {
                    return error.UnexpectedFixedArrayLen;
                }
            }
            for (&data) |*element| {
                element.* = try bincode.read(allocator, info.child, reader, params);
            }
            return data;
        },
        .Vector => |info| {
            var data: T = undefined;
            if (params.include_fixed_array_length) {
                const fixed_array_len = try bincode.read(allocator, u64, reader, params);
                if (fixed_array_len != info.len) {
                    return error.UnexpectedFixedArrayVectorLen;
                }
            }
            for (&data) |*element| {
                element.* = try bincode.read(allocator, info.child, reader, params);
            }
            return data;
        },
        .Pointer => |info| {
            switch (info.size) {
                .One => {
                    const data = try allocator.create(info.child);
                    errdefer allocator.destroy(data);
                    data.* = try bincode.read(allocator, info.child, reader, params);
                    return data;
                },
                .Slice => {
                    const entries = try allocator.alloc(info.child, try bincode.read(allocator, usize, reader, params));
                    errdefer allocator.free(entries);
                    for (entries) |*entry| {
                        entry.* = try bincode.read(allocator, info.child, reader, params);
                    }
                    return entries;
                },
                else => {},
            }
        },
        .ComptimeFloat => return bincode.read(allocator, f64, reader, params),
        .Float => |info| {
            if (info.bits != 32 and info.bits != 64) {
                @compileError("Only f{32, 64} floating-point integers may be serialized, but attempted to serialize " ++ @typeName(T) ++ ".");
            }
            const bytes = try reader.readBytesNoEof((info.bits + 7) / 8);
            return @as(T, @bitCast(bytes));
        },
        .ComptimeInt => return bincode.read(allocator, u64, reader, params),
        .Int => |info| {
            if ((info.bits & (info.bits - 1)) != 0 or info.bits < 8 or info.bits > 256) {
                @compileError("Only i{8, 16, 32, 64, 128, 256}, u{8, 16, 32, 64, 128, 256} integers may be deserialized, but attempted to deserialize " ++ @typeName(T) ++ ".");
            }

            switch (params.int_encoding) {
                .variable => {
                    const b = try reader.readByte();
                    if (b < 251) {
                        return switch (info.signedness) {
                            .unsigned => b,
                            .signed => zigzag: {
                                if (b % 2 == 0) {
                                    break :zigzag @as(T, @intCast(b / 2));
                                } else {
                                    break :zigzag ~@as(T, @bitCast(@as(std.meta.Int(.unsigned, info.bits), b / 2)));
                                }
                            },
                        };
                    } else if (b == 251) {
                        const z = try switch (params.endian) {
                            .little => reader.readInt(u16, .little),
                            .big => reader.readInt(u16, .big),
                        };
                        return switch (info.signedness) {
                            .unsigned => std.math.cast(T, z) orelse return error.FailedToCastZZ,
                            .signed => zigzag: {
                                if (z % 2 == 0) {
                                    break :zigzag std.math.cast(T, z / 2) orelse return error.FailedToCastZZ;
                                } else {
                                    break :zigzag ~(std.math.cast(T, z / 2) orelse return error.FailedToCastZZ);
                                }
                            },
                        };
                    } else if (b == 252) {
                        const z = try switch (params.endian) {
                            .little => reader.readInt(u32, .little),
                            .big => reader.readInt(u32, .big),
                        };
                        return switch (info.signedness) {
                            .unsigned => std.math.cast(T, z) orelse return error.FailedToCastZZ,
                            .signed => zigzag: {
                                if (z % 2 == 0) {
                                    break :zigzag std.math.cast(T, z / 2) orelse return error.FailedToCastZZ;
                                } else {
                                    break :zigzag ~(std.math.cast(T, z / 2) orelse return error.FailedToCastZZ);
                                }
                            },
                        };
                    } else if (b == 253) {
                        const z = try switch (params.endian) {
                            .little => reader.readInt(u64, .little),
                            .big => reader.readInt(u64, .big),
                        };
                        return switch (info.signedness) {
                            .unsigned => std.math.cast(T, z) orelse return error.FailedToCastZZ,
                            .signed => zigzag: {
                                if (z % 2 == 0) {
                                    break :zigzag std.math.cast(T, z / 2) orelse return error.FailedToCastZZ;
                                } else {
                                    break :zigzag ~(std.math.cast(T, z / 2) orelse return error.FailedToCastZZ);
                                }
                            },
                        };
                    } else if (b == 254) {
                        const z = try switch (params.endian) {
                            .little => reader.readInt(u128, .little),
                            .big => reader.readInt(u128, .big),
                        };
                        return switch (info.signedness) {
                            .unsigned => std.math.cast(T, z) orelse return error.FailedToCastZZ,
                            .signed => zigzag: {
                                if (z % 2 == 0) {
                                    break :zigzag std.math.cast(T, z / 2) orelse return error.FailedToCastZZ;
                                } else {
                                    break :zigzag ~(std.math.cast(T, z / 2) orelse return error.FailedToCastZZ);
                                }
                            },
                        };
                    } else {
                        const z = try switch (params.endian) {
                            .little => reader.readInt(u256, .little),
                            .big => reader.readInt(u256, .big),
                        };
                        return switch (info.signedness) {
                            .unsigned => std.math.cast(T, z) orelse return error.FailedToCastZZ,
                            .signed => zigzag: {
                                if (z % 2 == 0) {
                                    break :zigzag std.math.cast(T, z / 2) orelse return error.FailedToCastZZ;
                                } else {
                                    break :zigzag ~(std.math.cast(T, z / 2) orelse return error.FailedToCastZZ);
                                }
                            },
                        };
                    }
                },
                .fixed => return switch (params.endian) {
                    .little => reader.readInt(T, .little),
                    .big => reader.readInt(T, .big),
                },
            }
        },
        else => {},
    }

    @compileError("Deserializing '" ++ @typeName(T) ++ "' is unsupported.");
}

pub fn free(allocator: std.mem.Allocator, value: anytype) void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .Array, .Vector => {
            for (value) |element| {
                bincode.free(allocator, element);
            }
        },
        .Struct => |info| {
            inline for (info.fields) |field| {
                if (getFieldConfig(T, field)) |config| {
                    if (config.free) |free_fcn| {
                        var field_value = @field(value, field.name);
                        switch (@typeInfo(field.type)) {
                            .Pointer => |*field_info| {
                                // TODO: Why do we do only slice?
                                if (field_info.size == .Slice) {
                                    free_fcn(allocator, field_value);
                                }
                            },
                            else => {
                                free_fcn(allocator, &field_value);
                            },
                        }

                        continue;
                    }
                }

                if (!field.is_comptime) {
                    bincode.free(allocator, @field(value, field.name));
                }
            }
        },
        .Optional => {
            if (value) |v| {
                bincode.free(allocator, v);
            }
        },
        .Union => |info| {
            inline for (info.fields) |field| {
                if (value == @field(T, field.name)) {
                    return bincode.free(allocator, @field(value, field.name));
                }
            }
        },
        .Pointer => |info| {
            if (info.size == .Many) {
                unreachable;
            }
            // TODO: what about .One?
            std.debug.assert(info.size == .Slice);
            for (value) |item| {
                bincode.free(allocator, item);
            }
            allocator.free(value);
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
        .Enum => |_| return bincode.write(writer, @as(u32, @intFromEnum(data)), params),
        .Union => |info| {
            try bincode.write(writer, @as(u32, @intFromEnum(data)), params);
            inline for (info.fields) |field| {
                if (data == @field(T, field.name)) {
                    return bincode.write(writer, @field(data, field.name), params);
                }
            }
            return;
        },
        .Struct => |info| {
            // note: need comptime here for it to compile
            if (comptime std.mem.startsWith(u8, @typeName(T), "array_list")) {
                try bincode.write(writer, @as(u64, data.items.len), params);
                for (data.items) |element| {
                    try bincode.write(writer, element, params);
                }
                return;
            }

            inline for (info.fields) |field| {
                if (!field.is_comptime) {
                    if (getFieldConfig(T, field)) |config| {
                        if (config.skip) {
                            continue;
                        } else if (config.serializer) |ser_fcn| {
                            try ser_fcn(writer, @field(data, field.name), params);
                        } else {
                            try bincode.write(writer, @field(data, field.name), params);
                        }
                    }
                }
            }

            return;

            // TODO: Doesn't above handle this already?
            // var maybe_err: anyerror!void = {};
            // inline for (info.fields) |field| {
            //     if (!field.is_comptime) {
            //         if (@as(?anyerror!void, maybe_err catch null) != null) {
            //             maybe_err = bincode.write(writer, @field(data, field.name), params);
            //         }
            //     }
            // }
            // return maybe_err;
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
                .One => return bincode.write(writer, data.*, params), // TODO: wouldn't this panic if null?
                .Many => return bincode.write(writer, std.mem.span(data), params),
                .Slice => {
                    try bincode.write(writer, @as(u64, data.len), params);
                    for (data) |element| {
                        try bincode.write(writer, element, params);
                    }
                    return;
                },
                else => @compileError("Pointer must be type of One, Many or Slice!"),
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
                            .little => writer.writeInt(u16, @as(u16, @intCast(z)), .little),
                            .big => writer.writeInt(u16, @as(u16, @intCast(z)), .big),
                        };
                    } else if (z <= std.math.maxInt(u32)) {
                        try writer.writeByte(252);
                        return switch (params.endian) {
                            .little => writer.writeInt(u32, @as(u32, @intCast(z)), .little),
                            .big => writer.writeInt(u32, @as(u32, @intCast(z)), .big),
                        };
                    } else if (z <= std.math.maxInt(u64)) {
                        try writer.writeByte(253);
                        return switch (params.endian) {
                            .little => writer.writeInt(u64, @as(u64, @intCast(z)), .little),
                            .big => writer.writeInt(u64, @as(u64, @intCast(z)), .big),
                        };
                    } else if (z <= std.math.maxInt(u128)) {
                        try writer.writeByte(254);
                        return switch (params.endian) {
                            .little => writer.writeInt(u128, @as(u128, @intCast(z)), .little),
                            .big => writer.writeInt(u128, @as(u128, @intCast(z)), .big),
                        };
                    } else {
                        try writer.writeByte(255);
                        return switch (params.endian) {
                            .little => writer.writeInt(u256, @as(u256, @intCast(z)), .little),
                            .big => writer.writeInt(u256, @as(u256, @intCast(z)), .big),
                        };
                    }
                },
                .fixed => return switch (params.endian) {
                    .little => writer.writeInt(T, data, .little),
                    .big => writer.writeInt(T, data, .big),
                },
            }
        },
        else => {},
    }

    @compileError("Serializing '" ++ @typeName(T) ++ "' is unsupported.");
}

// need this fn to define the return type T
pub fn DeserializeFunction(comptime T: type) type {
    return fn (alloc: ?std.mem.Allocator, reader: anytype, params: Params) anyerror!T;
}
pub const SerializeFunction = fn (writer: anytype, data: anytype, params: Params) anyerror!void;
pub const FreeFunction = fn (allocator: std.mem.Allocator, data: anytype) void;

pub fn FieldConfig(comptime T: type) type {
    return struct {
        deserializer: ?DeserializeFunction(T) = null,
        serializer: ?SerializeFunction = null,
        free: ?FreeFunction = null,
        skip: bool = false,
        default_on_eof: bool = false,
        default_fn: ?fn (alloc: std.mem.Allocator) T = null,
    };
}

pub fn getFieldConfig(comptime struct_type: type, comptime field: std.builtin.Type.StructField) ?FieldConfig(field.type) {
    const bincode_field = "!bincode-config:" ++ field.name;
    if (@hasDecl(struct_type, bincode_field)) {
        const config = @field(struct_type, bincode_field);
        return config;
    }
    return null;
}

pub inline fn shouldUseDefaultValue(comptime field: std.builtin.Type.StructField, comptime config: FieldConfig(field.type)) ?*const anyopaque {
    if (config.skip) {
        if (field.default_value == null) {
            const field_type_name = @typeName(field.type);
            @compileError("┓\n|\n|--> Invalid config: cannot skip field '" ++ field_type_name ++ "." ++ field.name ++ "' deserialization if no default value set\n\n");
        }
        return field.default_value;
    } else {
        return null;
    }
}

pub fn getSerializedSizeWithSlice(slice: []u8, data: anytype, params: Params) !usize {
    const ser_slice = try writeToSlice(slice, data, params);
    return ser_slice.len;
}

pub fn writeToArray(alloc: std.mem.Allocator, data: anytype, params: Params) !std.ArrayList(u8) {
    var array_buf = try std.ArrayList(u8).initCapacity(alloc, 2048);
    try bincode.write(array_buf.writer(), data, params);

    return array_buf;
}

pub fn getSerializedSize(alloc: std.mem.Allocator, data: anytype, params: Params) !usize {
    var list = try writeToArray(alloc, data, params);
    defer list.deinit();
    return list.items.len;
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
    defer bincode.free(testing.allocator, mint);

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
    defer bincode.free(testing.allocator, actual);

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
            defer bincode.free(testing.allocator, actual);

            try testing.expectEqual(expected, actual);
            buffer.clearRetainingCapacity();
        }
    }

    inline for (.{ .{}, bincode.Params.legacy, bincode.Params.standard }) |params| {
        inline for (.{
            "hello world",
            @as([]const u8, "hello world"),
        }) |expected| {
            try bincode.write(buffer.writer(), expected, params);

            const actual = try bincode.readFromSlice(testing.allocator, @TypeOf(expected), buffer.items, params);
            defer bincode.free(testing.allocator, actual);

            try testing.expectEqualSlices(std.meta.Elem(@TypeOf(expected)), expected, actual);
            buffer.clearRetainingCapacity();
        }
    }
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
