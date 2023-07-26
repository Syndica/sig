const std = @import("std");
const getty = @import("getty");

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

// for ref: https://github.com/getty-zig/json/blob/a5c4d9f996dc3f472267f6210c30f96c39da576b/src/ser/serializer.zig
pub fn serializer(w: anytype, params: Params) blk: {
    break :blk Serializer(@TypeOf(w));
} {
    return Serializer(@TypeOf(w)).init(w, params);
}

pub fn Serializer(
    comptime Writer: type,
) type {
    return struct {
        writer: Writer,
        params: Params,

        const Self = @This();
        const Ok = void;
        const Error = getty.ser.Error || error{IO};

        pub fn init(w: Writer, params: Params) Self {
            std.debug.assert(params.int_encoding == .fixed);
            return .{ .writer = w, .params = params };
        }

        pub usingnamespace getty.Serializer(
            *Self,
            Ok,
            Error,
            custom_ser,
            null,
            null,
            Aggregate,
            null,
            .{
                .serializeBool = serializeBool,
                .serializeInt = serializeInt,
                .serializeEnum = serializeEnum,
                .serializeSome = serializeSome,
                .serializeNull = serializeNull,
                .serializeSeq = serializeSeq,
            },
        );

        fn serializeSeq(self: *Self, len: ?usize) Error!Aggregate {
            if (self.params.include_fixed_array_length) {
                try self.serializeInt(@as(u64, len.?));
            }
            return try self.serializeMap(len);
        }

        fn serializeNull(self: *Self) Error!Ok {
            try (self.writer.writeByte(0) catch Error.IO);
        }

        fn serializeSome(self: *Self, value: anytype) Error!Ok {
            try (self.writer.writeByte(1) catch Error.IO);
            const ss = self.serializer();
            return try getty.serialize(null, value, ss);
        }

        fn serializeMap(self: *Self, len: ?usize) Error!Aggregate {
            _ = len;
            return Aggregate{ .ser = self };
        }

        fn serializeBool(self: *Self, value: bool) Error!Ok {
            try (self.writer.writeByte(@intFromBool(value)) catch Error.IO);
        }

        fn serializeInt(self: *Self, value: anytype) Error!Ok {
            const T = @TypeOf(value);
            switch (@typeInfo(T)) {
                .ComptimeInt => {
                    if (value < 0) {
                        @compileError("Signed comptime integers can not be serialized.");
                    }
                    try self.serializeInt(@as(u64, value));
                },
                .Int => |info| {
                    if ((info.bits & (info.bits - 1)) != 0 or info.bits < 8 or info.bits > 256) {
                        @compileError("Only i{8, 16, 32, 64, 128, 256}, u{8, 16, 32, 64, 128, 256} integers may be serialized, but attempted to serialize " ++ @typeName(T) ++ ".");
                    }

                    switch (self.params.int_encoding) {
                        .fixed => {
                            try (switch (self.params.endian) {
                                .Little => self.writer.writeIntLittle(T, value),
                                .Big => self.writer.writeIntBig(T, value),
                            } catch Error.IO);
                        },
                        else => unreachable,
                    }
                },
                else => {
                    unreachable;
                },
            }
        }

        fn serializeEnum(self: *Self, index: anytype, name: []const u8) Error!Ok {
            _ = name;
            switch (self.params.int_encoding) {
                .fixed => {
                    return try self.serializeInt(@as(u32, index));
                },
                .variable => {
                    unreachable;
                },
            }
        }

        const custom_ser = struct {
            pub fn is(comptime T: type) bool {
                return switch (@typeInfo(T)) {
                    .Union => true,
                    .Struct => true,
                    .Pointer => |*info| {
                        return switch (info.size) {
                            .Slice => true,
                            else => false,
                        };
                    },
                    else => false,
                };
            }

            pub fn serialize(alloc: ?std.mem.Allocator, value: anytype, ss: anytype) Error!Ok {
                const T = @TypeOf(value);
                switch (@typeInfo(T)) {
                    .Union => |*info| {
                        try getty.serialize(alloc, @as(u32, @intFromEnum(value)), ss);
                        inline for (info.fields) |field| {
                            if (value == @field(T, field.name)) {
                                return try getty.serialize(alloc, @field(value, field.name), ss);
                            }
                        }
                    },
                    .Struct => |*info| {
                        var params = ss.context.params;
                        var writer = ss.context.writer;

                        if (getStructSerializer(T)) |ser_fcn| {
                            return ser_fcn(writer, value, params);
                        }

                        inline for (info.fields) |field| {
                            if (!field.is_comptime) {
                                if (!shouldSkipSerializingField(T, field)) {
                                    if (getFieldSerializer(T, field)) |ser_fcn| {
                                        try ser_fcn(writer, @field(value, field.name), params);
                                    } else {
                                        try getty.serialize(alloc, @field(value, field.name), ss);
                                    }
                                }
                            }
                        }
                    },
                    .Pointer => |*info| {
                        std.debug.assert(info.size == .Slice);

                        try getty.serialize(alloc, @as(u64, value.len), ss);
                        for (value) |element| {
                            try getty.serialize(alloc, element, ss);
                        }
                    },
                    else => unreachable,
                }
            }
        };

        const Aggregate = struct {
            ser: *Self,

            const A = @This();

            pub usingnamespace getty.ser.Seq(
                *A,
                Ok,
                Error,
                .{
                    .serializeElement = serializeElement,
                    .end = end,
                },
            );

            fn serializeElement(self: *A, value: anytype) Error!Ok {
                const ss = self.ser.serializer();
                try getty.serialize(null, value, ss);
            }

            fn end(self: *A) Error!Ok {
                _ = self;
            }
        };
    };
}

pub const SerializeFunction = fn (writer: anytype, data: anytype, params: Params) anyerror!void;
pub const DeserializeFunction = fn (gpa: std.mem.Allocator, comptime T: type, reader: anytype, params: Params) anyerror!void;

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

pub fn getFieldSerializer(comptime parent_type: type, comptime struct_field: std.builtin.Type.StructField) ?SerializeFunction {
    if (@hasDecl(parent_type, "!bincode-config:" ++ struct_field.name)) {
        const config = @field(parent_type, "!bincode-config:" ++ struct_field.name);
        return config.serializer;
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

pub fn writeToSlice(slice: []u8, data: anytype, params: Params) ![]u8 {
    var stream = std.io.fixedBufferStream(slice);
    var writer = stream.writer();

    var s = serializer(writer, params);
    const ss = s.serializer();
    try getty.serialize(null, data, ss);

    return stream.getWritten();
}

test "getty: simple buffer writter" {
    var buf: [1]u8 = undefined;

    var out = try writeToSlice(&buf, true, Params.standard);
    try std.testing.expect(out.len == 1);
    try std.testing.expect(out[0] == 1);

    out = try writeToSlice(&buf, false, Params.standard);
    try std.testing.expect(out.len == 1);
    try std.testing.expect(out[0] == 0);

    var buf2: [8]u8 = undefined; // u64 default
    _ = try writeToSlice(&buf2, 300, Params.standard);

    var buf3: [4]u8 = undefined;
    var v: u32 = 200;
    _ = try writeToSlice(&buf3, v, Params.standard);

    const Foo = enum { A, B };
    out = try writeToSlice(&buf3, Foo.B, Params.standard);
    var e = [_]u8{
        1,
        0,
        0,
        0,
    };
    try std.testing.expectEqualSlices(u8, &e, out);

    const Foo2 = union(enum(u8)) { A: u32, B: u32, C: u32 };
    const expected = [_]u8{ 1, 0, 0, 0, 1, 1, 1, 1 };
    const value = Foo2{ .B = 16843009 };
    // Map keys
    // .A = 65 = 1000001 (7 bits)
    // .B = 66 = 1000010
    // .B = 67 = 1000011
    var out2 = try writeToSlice(&buf2, value, Params.standard);
    try std.testing.expectEqualSlices(u8, &expected, out2);

    const Bar = struct { a: u32, b: u32, c: Foo2 };
    const b = Bar{ .a = 65, .b = 66, .c = Foo2{ .B = 16843009 } };
    var buf4: [100]u8 = undefined;
    var out3 = try writeToSlice(&buf4, b, Params.standard);
    var expected2 = [_]u8{ 65, 0, 0, 0, 66, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1 };
    try std.testing.expectEqualSlices(u8, &expected2, out3);
}
