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
            null,
            null,
            null,
            null,
            null,
            .{
                .serializeBool = serializeBool,
                .serializeInt = serializeInt,
                .serializeEnum = serializeEnum,
            },
        );

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
                    // default = assume u64
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
                        .variable => {
                            unreachable;
                        },
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
                    try self.serializeInt(@as(u32, index));
                },
                .variable => {
                    unreachable;
                },
            }
        }
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
    _ = try writeToSlice(&buf3, Foo.B, Params.standard);
    std.debug.print("{any}\n", .{buf3});

    // const Foo2 = union(enum(u8)) { A: u32, B: u32 };
    // const expected = [_]u8{ 1, 0, 0, 0, 1, 1, 1, 1 };
    // const value = Foo2{ .B = 16843009 };
    // var out2 = try writeToSlice(&buf2, value, Params.standard);
    // try std.testing.expectEqualSlices(u8, &expected, out2);
}
