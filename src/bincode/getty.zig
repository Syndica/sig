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
            custom_union,
            null,
            null,
            Aggregate,
            Aggregate,
            .{
                .serializeBool = serializeBool,
                .serializeInt = serializeInt,
                .serializeEnum = serializeEnum,
                .serializeStruct = serializeStruct,
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

        fn serializeStruct(self: *Self, comptime name: []const u8, len: usize) Error!Aggregate {
            _ = name;
            return try self.serializeMap(len);
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

        const custom_union = struct {
            pub fn is(comptime T: type) bool {
                return switch (@typeInfo(T)) {
                    .Union => true,
                    else => false,
                };
            }

            pub fn serialize(alloc: ?std.mem.Allocator, value: anytype, ss: anytype) Error!Ok {
                try getty.serialize(alloc, @as(u32, @intFromEnum(value)), ss);

                const T = @TypeOf(value);
                const info = @typeInfo(T).Union;
                inline for (info.fields) |field| {
                    if (value == @field(T, field.name)) {
                        return try getty.serialize(alloc, @field(value, field.name), ss);
                    }
                }
            }
        };

        const Aggregate = struct {
            ser: *Self,

            const A = @This();

            pub usingnamespace getty.ser.Structure(
                *A,
                Ok,
                Error,
                .{
                    .serializeField = serializeField,
                    .end = end,
                },
            );

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
                return try self.serializeValue(value);
            }

            fn serializeValue(self: *A, value: anytype) Error!Ok {
                const ss = self.ser.serializer();
                try getty.serialize(null, value, ss);
            }

            fn serializeField(self: *A, comptime key: []const u8, value: anytype) Error!Ok {
                _ = key;
                try self.serializeValue(value);
            }

            fn end(self: *A) Error!Ok {
                _ = self;
            }
        };
    };
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
