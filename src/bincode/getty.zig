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
            },
        );

        fn serializeBool(self: *Self, value: bool) Error!Ok {
            try (self.writer.writeByte(@intFromBool(value)) catch Error.IO);
        }
    };
}

test "getty: simple buffer writter" {
    var buf: [1]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    var writer = stream.writer();

    var s = serializer(writer, Params.standard);
    const ss = s.serializer();

    try getty.serialize(null, true, ss);

    var out = stream.getWritten();
    try std.testing.expect(out.len == 1);
    try std.testing.expect(out[0] == 1);

    try stream.seekTo(0); // reset buffer
    try getty.serialize(null, false, ss);
    out = stream.getWritten();

    try std.testing.expect(out.len == 1);
    try std.testing.expect(out[0] == 0);
}
