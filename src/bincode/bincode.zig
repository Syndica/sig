pub const arraylist = @import("arraylist.zig");
pub const hashmap = @import("hashmap.zig");
pub const bounded_array = @import("bounded_array.zig");
pub const int = @import("int.zig");
pub const list = @import("list.zig");
pub const optional = @import("optional.zig");
pub const shortvec = @import("shortvec.zig");

const std = @import("std");
const std14 = @import("std14");
const builtin = @import("builtin");
const sig = @import("../sig.zig");

const testing = std.testing;

const arrayListInfo = sig.utils.types.arrayListInfo;
const hashMapInfo = sig.utils.types.hashMapInfo;
const boundedArrayInfo = sig.utils.types.boundedArrayInfo;

// re-export for ease-of-use on custom deserializers
pub const LimitAllocator = sig.utils.allocators.LimitAllocator;

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
    allocation_limit: usize = 100 * 1024 * 1024, // chosen arbitrarily
};

pub fn sizeOf(data: anytype, params: bincode.Params) usize {
    if (@TypeOf(data) == type) {
        @compileError("sizeOf called with type instead of value");
    }
    var stream = std14.countingWriter(std.io.null_writer);
    bincode.write(stream.writer(), data, params) catch unreachable;
    return @intCast(stream.bytes_written);
}

pub fn readFromSlice(allocator: std.mem.Allocator, comptime T: type, slice: []const u8, params: bincode.Params) !T {
    var stream = std.io.fixedBufferStream(slice);
    return bincode.read(allocator, T, stream.reader(), params);
}

pub fn readFromSliceWithLimit(limit_allocator: *LimitAllocator, comptime T: type, slice: []const u8, params: bincode.Params) !T {
    var stream = std.io.fixedBufferStream(slice);
    return bincode.readWithLimit(limit_allocator, T, stream.reader(), params);
}

pub fn writeToSlice(slice: []u8, data: anytype, params: bincode.Params) ![]u8 {
    var stream = std.io.fixedBufferStream(slice);
    try bincode.write(stream.writer(), data, params);
    return stream.getWritten();
}

pub fn writeAlloc(allocator: std.mem.Allocator, data: anytype, params: bincode.Params) ![]u8 {
    const buffer = try allocator.alloc(u8, bincode.sizeOf(data, params));
    errdefer allocator.free(buffer);
    return try bincode.writeToSlice(buffer, data, params);
}

pub fn read(
    allocator: std.mem.Allocator,
    comptime U: type,
    reader: anytype,
    params: bincode.Params,
) !U {
    return readWithConfig(allocator, U, reader, params, getConfig(U) orelse .{});
}

pub fn readWithLimit(
    limit_allocator: *LimitAllocator,
    comptime U: type,
    reader: anytype,
    params: bincode.Params,
) !U {
    return readWithConfigAndLimit(limit_allocator, U, reader, params, getConfig(U) orelse .{});
}

pub fn readWithConfig(
    base_allocator: std.mem.Allocator,
    comptime U: type,
    reader: anytype,
    params: bincode.Params,
    comptime config: FieldConfig(U),
) !U {
    var limit_allocator = LimitAllocator.init(base_allocator, params.allocation_limit);
    return readWithConfigAndLimit(&limit_allocator, U, reader, params, config);
}

pub fn readWithConfigAndLimit(
    limit_allocator: *LimitAllocator,
    comptime U: type,
    reader: anytype,
    params: bincode.Params,
    comptime config: FieldConfig(U),
) !U {
    const T = switch (U) {
        usize => u64,
        isize => i64,
        else => U,
    };

    if (config.deserializer) |deserialize_fcn| {
        return deserialize_fcn(limit_allocator, reader, params);
    }

    switch (@typeInfo(T)) {
        .void => return {},
        .bool => return switch (try reader.readByte()) {
            0 => false,
            1 => true,
            else => error.BadBoolean,
        },
        .@"enum" => |_| {
            comptime var SerializedSize = u32;
            comptime if (@hasDecl(T, "BincodeSize")) {
                SerializedSize = T.BincodeSize;
            };

            const tag = try switch (params.endian) {
                .little => reader.readInt(SerializedSize, .little),
                .big => reader.readInt(SerializedSize, .big),
            };
            return std.meta.intToEnum(T, tag);
        },
        .@"union" => |info| {
            const tag_type = info.tag_type orelse @compileError("Only tagged unions may be read.");
            const raw_tag = try bincode.readWithLimit(limit_allocator, tag_type, reader, params);

            inline for (info.fields) |field| {
                if (raw_tag == @field(tag_type, field.name)) {
                    // https://github.com/ziglang/zig/issues/7866
                    if (field.type == void) return @unionInit(T, field.name, {});
                    const payload =
                        try bincode.readWithLimit(limit_allocator, field.type, reader, params);
                    return @unionInit(T, field.name, payload);
                }
            }

            return error.UnknownUnionTag;
        },
        .@"struct" => |info| {
            var data: T = undefined;

            inline for (info.fields, 0..) |field, i| {
                errdefer inline for (info.fields[0..i]) |prev| {
                    if (prev.is_comptime) continue;
                    bincode.free(limit_allocator.allocator(), @field(data, prev.name));
                };

                if (field.is_comptime) continue;
                const field_config: FieldConfig(field.type) = getFieldConfig(T, field) orelse {
                    // // if we dont want print statements when our tests run we need to comment this out :(
                    // // specifically, the geyser test fail bincode deser and then recover from it
                    // errdefer {
                    //     // TODO(x19): maybe use a logger instead? (sometimes we can recover from this
                    //     // and so we don't want to print)
                    //     if (builtin.mode == .Debug) {
                    //         std.debug.print("failed to deserialize field {s}\n", .{field.name});
                    //     }
                    // }
                    @field(data, field.name) =
                        try bincode.readWithLimit(limit_allocator, field.type, reader, params);
                    continue;
                };

                @field(data, field.name) =
                    try readFieldWithConfig(limit_allocator, reader, params, field, field_config);
            }

            // TODO: improve implementation of post deserialise method
            const post_deserialize = "!bincode-config:post-deserialize";
            if (@hasDecl(T, post_deserialize)) {
                const field_config = @field(T, post_deserialize);
                if (field_config.post_deserialize_fn) |post_deserialize_fn| {
                    post_deserialize_fn(&data);
                }
            }

            return data;
        },
        .optional => |info| {
            return switch (try reader.readByte()) {
                0 => null,
                1 => try bincode.readWithLimit(limit_allocator, info.child, reader, params),
                else => error.BadOptionalBoolean,
            };
        },
        .array => |info| {
            var data: T = undefined;
            if (params.include_fixed_array_length) {
                const fixed_array_len = try bincode.readWithLimit(limit_allocator, u64, reader, params);
                if (fixed_array_len != info.len) {
                    return error.UnexpectedFixedArrayLen;
                }
            }
            for (&data) |*element| {
                element.* = try bincode.readWithLimit(limit_allocator, info.child, reader, params);
            }
            return data;
        },
        .vector => |info| {
            var data: T = undefined;
            if (params.include_fixed_array_length) {
                const fixed_array_len = try bincode.readWithLimit(limit_allocator, u64, reader, params);
                if (fixed_array_len != info.len) {
                    return error.UnexpectedFixedArrayVectorLen;
                }
            }
            for (&data) |*element| {
                element.* = try bincode.readWithLimit(limit_allocator, info.child, reader, params);
            }
            return data;
        },
        .pointer => |info| {
            const allocator = limit_allocator.allocator();
            switch (info.size) {
                .one => {
                    const data = try allocator.create(info.child);
                    errdefer allocator.destroy(data);
                    data.* = try bincode.readWithLimit(limit_allocator, info.child, reader, params);
                    return data;
                },
                .slice => {
                    const num_entries = try bincode.readWithLimit(limit_allocator, usize, reader, params);
                    const entries = try allocator.alloc(info.child, num_entries);
                    errdefer allocator.free(entries);
                    for (entries) |*entry| {
                        entry.* = try bincode.readWithLimit(limit_allocator, info.child, reader, params);
                    }
                    return entries;
                },
                else => {},
            }
        },
        .comptime_float => return bincode.readWithLimit(limit_allocator, f64, reader, params),
        .float => |info| {
            if (info.bits != 32 and info.bits != 64) {
                @compileError("Only f{32, 64} floating-point integers may be serialized, but attempted to serialize " ++ @typeName(T) ++ ".");
            }
            const bytes = try reader.readBytesNoEof((info.bits + 7) / 8);
            return @as(T, @bitCast(bytes));
        },
        .comptime_int => return bincode.readWithLimit(limit_allocator, u64, reader, params),
        .int => return try bincode.readInt(T, reader, params),
        else => {},
    }

    @compileError("Deserializing '" ++ @typeName(T) ++ "' is unsupported.");
}

pub fn readInt(comptime U: type, reader: anytype, params: bincode.Params) !U {
    const T = switch (U) {
        usize => u64,
        isize => i64,
        else => U,
    };

    const info = @typeInfo(T).int;
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
        .fixed => switch (params.endian) {
            .little => {
                return reader.readInt(T, .little);
            },
            .big => {
                return reader.readInt(T, .big);
            },
        },
    }
}

pub fn readIntAsLength(comptime T: type, reader: anytype, params: bincode.Params) !?T {
    const len_u64 = try bincode.readInt(u64, reader, params);
    if (len_u64 > std.math.maxInt(T)) return null;
    return @intCast(len_u64);
}

pub fn utf8StringCodec(
    /// Should be a slice or array of bytes (ie `[16]u8` `[]const u8`, `[]u8`, etc).
    comptime Str: type,
    comptime max_len: u64,
) FieldConfig(Str) {
    const S = struct {
        fn deserialize(
            limit_allocator: *bincode.LimitAllocator,
            reader: anytype,
            _: bincode.Params,
        ) !Str {
            const len = try bincode.readInt(u64, reader, .{});
            if (len > max_len) return error.DataTooLarge;

            const allocator = limit_allocator.allocator();
            const str = try allocator.alloc(u8, len);
            errdefer allocator.free(str);

            try reader.readNoEof(str);
            if (!std.unicode.utf8ValidateSlice(str[0..])) return error.InvalidUtf8;
            return str;
        }
    };
    return .{ .deserializer = S.deserialize };
}

pub fn readFieldWithConfig(
    limit_allocator: *LimitAllocator,
    reader: anytype,
    params: bincode.Params,
    comptime field: std.builtin.Type.StructField,
    comptime field_config: FieldConfig(field.type),
) !field.type {
    if (shouldUseDefaultValue(field, field_config)) |default_value| {
        return default_value;
    }

    if (field_config.deserializer) |deser_fcn| {
        return try deser_fcn(limit_allocator, reader, params);
    }

    return try bincode.readWithLimit(limit_allocator, field.type, reader, params);
}

pub fn write(writer: anytype, data: anytype, params: bincode.Params) !void {
    return writeWithConfig(writer, data, params, getConfig(@TypeOf(data)) orelse .{});
}

pub fn writeWithConfig(
    writer: anytype,
    data: anytype,
    params: bincode.Params,
    comptime config: FieldConfig(@TypeOf(data)),
) !void {
    const T = switch (@TypeOf(data)) {
        usize => u64,
        isize => i64,
        else => @TypeOf(data),
    };

    if (config.serializer) |serialize_fcn| {
        return serialize_fcn(writer, data, params);
    }

    switch (@typeInfo(T)) {
        .type, .void, .noreturn, .undefined, .null, .@"fn", .@"opaque", .frame, .@"anyframe" => return,
        .bool => return writer.writeByte(@intFromBool(data)),
        .@"enum" => |_| {
            comptime var SerializedSize = u32;
            comptime if (@hasDecl(T, "BincodeSize")) {
                SerializedSize = T.BincodeSize;
            };

            return bincode.write(writer, @as(SerializedSize, @intFromEnum(data)), params);
        },
        .@"union" => |info| {
            try bincode.write(writer, @as(u32, @intFromEnum(data)), params);
            inline for (info.fields) |field| {
                if (data == @field(T, field.name)) {
                    return bincode.write(writer, @field(data, field.name), params);
                }
            }
            return;
        },
        .@"struct" => |info| {
            inline for (info.fields) |field| {
                try writeFieldWithConfig(field, getFieldConfig(T, field), writer, @field(data, field.name), params);
            }
            return;
        },
        .optional => {
            if (data) |value| {
                try writer.writeByte(1);
                try bincode.write(writer, value, params);
            } else {
                try writer.writeByte(0);
            }
            return;
        },
        .array, .vector => {
            if (params.include_fixed_array_length) {
                try bincode.write(writer, std.math.cast(u64, data.len) orelse return error.DataTooLarge, params);
            }
            for (data) |element| {
                try bincode.write(writer, element, params);
            }
            return;
        },
        .pointer => |info| {
            switch (info.size) {
                .one => return bincode.write(writer, data.*, params), // TODO: wouldn't this panic if null?
                .many => return bincode.write(writer, std.mem.span(data), params),
                .slice => {
                    try bincode.write(writer, @as(u64, data.len), params);
                    for (data) |element| {
                        try bincode.write(writer, element, params);
                    }
                    return;
                },
                else => @compileError("pointer must be type of one, many or slice!"),
            }
        },
        .comptime_float => return bincode.write(writer, @as(f64, data), params),
        .float => |info| {
            if (info.bits != 32 and info.bits != 64) {
                @compileError("Only f{32, 64} floating-point integers may be serialized, but attempted to serialize " ++ @typeName(T) ++ ".");
            }
            return writer.writeAll(std.mem.asBytes(&data));
        },
        .comptime_int => {
            if (data < 0) {
                @compileError("Signed comptime integers can not be serialized.");
            }
            return bincode.write(writer, @as(u64, data), params);
        },
        .int => |info| {
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
                .fixed => return writer.writeInt(T, data, params.endian),
            }
        },
        else => {},
    }

    @compileError("Serializing '" ++ @typeName(T) ++ "' is unsupported.");
}

pub fn writeFieldWithConfig(
    comptime field: std.builtin.Type.StructField,
    comptime maybe_field_config: ?FieldConfig(field.type),
    writer: anytype,
    data: field.type,
    params: bincode.Params,
) !void {
    if (field.is_comptime) return;

    if (maybe_field_config) |field_config| {
        if (field_config.skip) return;
        if (field_config.serializer) |ser_fcn| {
            try ser_fcn(writer, data, params);
            return;
        }
    }

    try bincode.write(writer, data, params);
}

pub fn free(allocator: std.mem.Allocator, value: anytype) void {
    return freeWithConfig(allocator, value, getConfig(@TypeOf(value)) orelse .{});
}

pub fn freeWithConfig(
    allocator: std.mem.Allocator,
    value: anytype,
    comptime config: FieldConfig(@TypeOf(value)),
) void {
    const T = @TypeOf(value);

    if (config.free) |freeFn| {
        return freeFn(allocator, value);
    }

    switch (@typeInfo(T)) {
        .array, .vector => for (value) |element| {
            bincode.free(allocator, element);
        },
        .@"struct" => |info| inline for (info.fields) |field| {
            comptime if (field.is_comptime) continue;
            if (getFieldConfig(T, field)) |field_config| {
                if (field_config.free) |freeFn| {
                    freeFn(allocator, @field(value, field.name));
                    continue;
                }
            }
            bincode.free(allocator, @field(value, field.name));
        },
        .optional => if (value) |v| {
            bincode.free(allocator, v);
        },
        .error_union => if (value) |v| {
            bincode.free(allocator, v);
        } else |_| {},
        .@"union" => switch (value) {
            inline else => |payload| bincode.free(allocator, payload),
        },
        .pointer => |info| switch (info.size) {
            .slice => {
                for (value) |item| {
                    bincode.free(allocator, item);
                }
                allocator.free(value);
            },
            .one => {
                bincode.free(allocator, value.*);
                allocator.destroy(value);
            },
            else => unreachable,
        },
        else => {},
    }
}

pub fn VarIntConfig(comptime T: type) bincode.FieldConfig(T) {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            _ = params;
            return std.leb.writeUleb128(writer, data);
        }

        pub fn deserialize(
            limit_allocator: *bincode.LimitAllocator,
            reader: anytype,
            params: bincode.Params,
        ) !T {
            _ = params;
            _ = limit_allocator;
            return std.leb.readUleb128(T, reader);
        }
    };

    return bincode.FieldConfig(T){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
    };
}

pub fn FieldConfig(comptime T: type) type {
    return struct {
        deserializer: ?fn (limit_allocator: *LimitAllocator, reader: anytype, params: Params) anyerror!T = null,
        serializer: ?fn (writer: anytype, data: anytype, params: Params) anyerror!void = null,
        free: ?fn (allocator: std.mem.Allocator, data: anytype) void = null,
        skip: bool = false,
        post_deserialize_fn: ?fn (self: *T) void = null,
        /// NOTE: we use this default parameter to avoid incorrect usage
        /// of structs which should only have defaults on deserialization
        default_value: ?T = null,
    };
}

pub fn getConfig(comptime T: type) ?FieldConfig(T) {
    // Get the config if defined within the type
    const config_field_name = "!bincode-config";
    switch (@typeInfo(T)) {
        .@"struct", .@"enum", .@"union", .@"opaque" => if (@hasDecl(T, config_field_name))
            return @field(T, config_field_name),
        else => {},
    }

    // Provide default configs for some types
    return if (comptime hashMapInfo(T) != null)
        hashmap.hashMapFieldConfig(T, .{})
    else if (comptime arrayListInfo(T) != null)
        arraylist.standardConfig(T)
    else if (comptime boundedArrayInfo(T) != null)
        bounded_array.standardConfig(T)
    else if (T == u8)
        int.U8Config()
    else if (T == []const u8)
        int.U8ConstSliceConfig()
    else if (T == []u8)
        int.U8SliceConfig()
    else if (@typeInfo(T) == .array and @typeInfo(T).array.child == u8)
        if (@typeInfo(T).array.sentinel()) |_|
            int.U8ArraySentinelConfig(@typeInfo(T).array.len)
        else
            int.U8ArrayConfig(@typeInfo(T).array.len)
    else
        null;
}

pub fn getFieldConfig(comptime struct_type: type, comptime field: std.builtin.Type.StructField) ?FieldConfig(field.type) {
    const bincode_field = "!bincode-config:" ++ field.name;
    if (@hasDecl(struct_type, bincode_field)) {
        return @field(struct_type, bincode_field);
    }
    return null;
}

pub inline fn shouldUseDefaultValue(comptime field: std.builtin.Type.StructField, comptime field_config: FieldConfig(field.type)) ?field.type {
    if (field_config.skip) {
        // NOTE: this is **bincode specific** default value
        // eg, a: ?u8 ... @!"bincode-config:a" = { skip = true, default_value = 5 }
        if (field_config.default_value) |v| {
            return v;
        }
        // NOTE: this is the default value of the **field**
        // eg, a: ?u8 = 5
        return field.defaultValue() orelse @compileError(
            "┓\n|\n|--> Invalid config: cannot skip field '" ++ @typeName(field.type) ++
                "." ++
                field.name ++
                "' deserialization if no default value set\n\n",
        );
    } else {
        if (field_config.default_value != null) {
            @compileError("┓\n|\n|--> Invalid config: default value is only allowed when 'skip' is set to true\n\n");
        }
        return null;
    }
}

pub fn getSerializedSizeWithSlice(slice: []u8, data: anytype, params: Params) !usize {
    const ser_slice = try writeToSlice(slice, data, params);
    return ser_slice.len;
}

pub fn writeToArray(allocator: std.mem.Allocator, data: anytype, params: Params) !std.ArrayList(u8) {
    var array_buf = try std.ArrayList(u8).initCapacity(allocator, 2048);
    try bincode.write(array_buf.writer(), data, params);

    return array_buf;
}

// ** Tests **//
fn TestSliceConfig(comptime Child: type) FieldConfig([]Child) {
    const S = struct {
        fn deserializeTestSlice(limit_allocator: *bincode.LimitAllocator, reader: anytype, params: Params) ![]Child {
            const len = try bincode.readWithLimit(limit_allocator, u16, reader, params);

            const allocator = limit_allocator.allocator();
            var elems = try allocator.alloc(Child, len);
            errdefer allocator.free(elems);

            for (0..len) |i| {
                elems[i] = try bincode.readWithLimit(limit_allocator, Child, reader, params);
            }
            return elems;
        }

        pub fn serilaizeTestSlice(writer: anytype, data: anytype, params: bincode.Params) !void {
            const len = std.math.cast(u16, data.len) orelse return error.DataTooLarge;
            try bincode.write(writer, len, params);
            for (data) |item| {
                try bincode.write(writer, item, params);
            }
            return;
        }
    };

    return FieldConfig([]Child){
        .serializer = S.serilaizeTestSlice,
        .deserializer = S.deserializeTestSlice,
    };
}

fn ShredTypeConfig() bincode.FieldConfig(ShredType) {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            try bincode.write(writer, @intFromEnum(data), params);
            return;
        }
    };

    return bincode.FieldConfig(ShredType){
        .serializer = S.serialize,
    };
}

const ShredType = enum(u8) {
    Data = 0b1010_0101,
    Code = 0b0101_1010,

    pub const @"!bincode-config" = ShredTypeConfig();
};

/// Assert that bincode serializes the provided item to the provided bytes,
/// and deserializes the bytes back to the item.
pub fn testRoundTrip(deserialized_item: anytype, bincode_serialized_bytes: []const u8) !void {
    comptime std.debug.assert(builtin.is_test);
    const T = @TypeOf(deserialized_item);
    const allocator = std.testing.allocator;

    const actual_bytes = try sig.bincode.writeAlloc(allocator, deserialized_item, .{});
    defer allocator.free(actual_bytes);
    try std.testing.expectEqualSlices(u8, bincode_serialized_bytes, actual_bytes);

    const actual_struct = try sig.bincode.readFromSlice(allocator, T, actual_bytes, .{});
    defer actual_struct.deinit(allocator);
    try std.testing.expect(sig.utils.types.eql(deserialized_item, actual_struct));
}

test "bincode: custom enum" {
    const x = ShredType.Data;
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try bincode.write(buf.writer(), x, .{});
}

test "bincode: default on eof" {
    const Foo = struct {
        value: u8 = 0,
        accounts: std.ArrayList(u64),
        pub const @"!bincode-config:accounts" = arraylist.defaultOnEofConfig(std.ArrayList(u64));
        pub const @"!bincode-config:value" = int.defaultOnEof(u8, 0);
    };

    var buf: [1]u8 = .{1};
    const r = try readFromSlice(std.testing.allocator, Foo, &buf, .{});
    try std.testing.expect(r.value == 1);

    var buf2: [1024]u8 = undefined;
    const buf3 = try writeToSlice(&buf2, Foo{
        .value = 10,
        .accounts = std.ArrayList(u64).init(std.testing.allocator),
    }, .{});

    const r2 = try readFromSlice(std.testing.allocator, Foo, buf3, .{});
    try std.testing.expect(r2.value == 10);
}

test "bincode: custom field serialization" {
    const Foo = struct {
        accounts: []u8,
        txs: []u32,
        skip_me: u8 = 20,
        skip_me_null: ?u8 = null,

        pub const @"!bincode-config:accounts" = TestSliceConfig(u8);
        pub const @"!bincode-config:txs" = TestSliceConfig(u32);
        pub const @"!bincode-config:skip_me" = FieldConfig(u8){
            .skip = true,
        };
        pub const @"!bincode-config:skip_me_null" = FieldConfig(?u8){
            .skip = true,
        };
    };

    var accounts = [_]u8{ 1, 2, 3 };
    var txs = [_]u32{ 1, 2, 3 };
    const foo = Foo{ .accounts = &accounts, .txs = &txs };

    var buf: [1000]u8 = undefined;
    const out = try writeToSlice(&buf, foo, Params{});
    try std.testing.expect(out[out.len - 1] != 20); // skip worked

    const size = sizeOf(foo, Params{});
    try std.testing.expect(size > 0);

    const r = try readFromSlice(std.testing.allocator, Foo, out, Params{});
    defer free(std.testing.allocator, r);

    try std.testing.expect(r.accounts.len == foo.accounts.len);
    try std.testing.expect(r.txs.len == foo.txs.len);
    try std.testing.expect(r.skip_me == 20);
}

test "bincode: test arraylist" {
    var array = std.ArrayList(u8).init(std.testing.allocator);
    defer array.deinit();

    try array.append(10);
    try array.append(11);

    var buf: [1024]u8 = undefined;
    const bytes = try writeToSlice(&buf, array, .{});

    // var bytes = [_]u8{ 2, 0, 0, 0, 0, 0, 0, 0, 10, 11};
    var array2 = try readFromSlice(std.testing.allocator, std.ArrayList(u8), bytes, .{});
    defer array2.deinit();

    try std.testing.expectEqualSlices(u8, array.items, array2.items);
}

test "bincode: test hashmap/BTree (de)ser" {
    // 20 => 10
    const rust_bytes = [_]u8{ 1, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 10, 0, 0, 0 };

    var map = std.AutoHashMap(u32, u32).init(std.testing.allocator);
    defer map.deinit();

    try map.put(20, 10);

    var buf: [1024]u8 = undefined;
    const bytes = try writeToSlice(&buf, map, .{});

    try std.testing.expectEqualSlices(u8, &rust_bytes, bytes);

    var de_map = try readFromSlice(std.testing.allocator, std.AutoHashMap(u32, u32), bytes, .{});
    defer de_map.deinit();

    const v = de_map.get(20);
    try std.testing.expectEqual(v.?, 10);
}

test "bincode: test float serialization" {
    const f: f64 = 1.234;
    var buf: [1024]u8 = undefined;
    const bytes = try writeToSlice(&buf, f, .{});
    const rust_bytes = [_]u8{ 88, 57, 180, 200, 118, 190, 243, 63 };
    try std.testing.expectEqualSlices(u8, &rust_bytes, bytes);

    const f2 = try readFromSlice(std.testing.allocator, f64, bytes, .{});
    try std.testing.expect(f2 == f);
}

test "bincode: test serialization" {
    var buf: [1]u8 = undefined;

    {
        const out = try writeToSlice(&buf, true, Params.standard);
        try std.testing.expect(out.len == 1);
        try std.testing.expect(out[0] == 1);
    }

    {
        const out = try readFromSlice(std.testing.allocator, bool, &buf, Params{});
        try std.testing.expect(out == true);
    }

    {
        const out = try writeToSlice(&buf, false, Params.standard);
        try std.testing.expect(out.len == 1);
        try std.testing.expect(out[0] == 0);
    }

    var buf2: [8]u8 = undefined; // u64 default
    _ = try writeToSlice(&buf2, 300, Params.standard);

    var buf3: [4]u8 = undefined;
    const v: u32 = 200;
    _ = try writeToSlice(&buf3, v, Params.standard);

    {
        const out = try readFromSlice(std.testing.allocator, u32, &buf3, Params{});
        try std.testing.expect(out == 200);
    }

    const Foo = enum { A, B };
    const out = try writeToSlice(&buf3, Foo.B, Params.standard);
    var e = [_]u8{ 1, 0, 0, 0 };
    try std.testing.expectEqualSlices(u8, &e, out);

    const read_out = try readFromSlice(std.testing.allocator, Foo, &buf3, Params{});
    try std.testing.expectEqual(read_out, Foo.B);

    const Foo2 = union(enum(u8)) { A: u32, B: u32, C: u32 };
    const expected = [_]u8{ 1, 0, 0, 0, 1, 1, 1, 1 };
    const value = Foo2{ .B = 16843009 };
    // Map keys
    // .A = 65 = 1000001 (7 bits)
    // .B = 66 = 1000010
    // .B = 67 = 1000011
    const out2 = try writeToSlice(&buf2, value, Params.standard);
    try std.testing.expectEqualSlices(u8, &expected, out2);

    const read_out2 = try readFromSlice(std.testing.allocator, Foo2, &buf2, Params{});
    try std.testing.expectEqual(read_out2, value);

    const Bar = struct { a: u32, b: u32, c: Foo2 };
    const b = Bar{ .a = 65, .b = 66, .c = Foo2{ .B = 16843009 } };
    var buf4: [100]u8 = undefined;
    const out3 = try writeToSlice(&buf4, b, Params.standard);
    var expected2 = [_]u8{ 65, 0, 0, 0, 66, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1 };
    try std.testing.expectEqualSlices(u8, &expected2, out3);

    const S = struct {
        a: u32,
        b: ?u16,
        c: Bar,
    };
    const s: S = .{
        .a = 65,
        .b = null,
        .c = Bar{ .a = 66, .b = 67, .c = Foo2{ .B = 16843009 } },
    };
    var buf6: [100]u8 = undefined;
    const out4 = try writeToSlice(&buf6, s, Params.standard);
    const result = try readFromSlice(std.testing.allocator, S, out4, Params{});
    try std.testing.expectEqual(result, s);

    // ensure write to array works too
    var array_buf = try writeToArray(std.testing.allocator, s, Params.standard);
    defer array_buf.deinit();
    try std.testing.expectEqualSlices(u8, out4, array_buf.items);
}

test "bincode: tuples" {
    var buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer buffer.deinit();

    const Foo = struct { u16, u16 };
    try bincode.write(buffer.writer(), Foo{ 10, 20 }, bincode.Params.standard);
    try testing.expectEqualSlices(u8, &[_]u8{
        10, 0, 20, 0,
    }, buffer.items);
}

test "bincode: (legacy) serialize an array" {
    var buffer = std.ArrayList(u8).init(std.testing.allocator);
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

test "default value" {
    const FooBar = struct {
        a: []u8,

        pub const @"!bincode-config:a": sig.bincode.FieldConfig([]u8) = .{
            .skip = true,
            .default_value = &.{},
        };
    };

    const fb = try bincode.readFromSlice(std.testing.allocator, FooBar, &.{}, .{});
    std.debug.assert(fb.a.len == 0);
}

test "bincode: serialize and deserialize" {
    var buffer = std.ArrayList(u8).init(testing.allocator);
    defer buffer.deinit();

    inline for (.{
        bincode.Params{},
        bincode.Params{ .int_encoding = .variable },
        bincode.Params.legacy,
        bincode.Params.standard,
    }) |params| {
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

    inline for (.{
        bincode.Params{},
        bincode.Params.legacy,
        bincode.Params.standard,
    }) |params| {
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
