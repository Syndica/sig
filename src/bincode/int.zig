const std = @import("std");
const sig = @import("../lib.zig");
const bincode = sig.bincode;

pub fn defaultOnEof(comptime T: type, comptime eof_value: T) bincode.FieldConfig(T) {
    const S = struct {
        fn deserializer(
            _: std.mem.Allocator,
            reader: anytype,
            params: bincode.Params,
        ) anyerror!T {
            var fba = comptime std.heap.FixedBufferAllocator.init(&.{});
            return bincode.read(fba.allocator(), T, reader, params) catch |err| switch (err) {
                error.EndOfStream => eof_value,
                else => |e| e,
            };
        }

        fn serializer(
            writer: anytype,
            data: anytype,
            params: bincode.Params,
        ) anyerror!void {
            if (data == eof_value) return;
            try bincode.write(writer, data, params);
        }
    };
    return .{
        .deserializer = S.deserializer,
        .serializer = S.serializer,
    };
}
