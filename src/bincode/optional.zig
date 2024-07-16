const std = @import("std");
const sig = @import("../lib.zig");
const bincode = sig.bincode;
const hashMapInfo = sig.utils.types.hashMapInfo;

pub fn defaultToNullOnEof(
    comptime T: type,
    comptime options: struct {
        /// When this is false, the field will be encoded and decoded as a non-optional value, only reading as null on eof, and not written when it is null.
        /// When this is true, the field will be encoded and decoded as an optional value, defaulting to null on eof while reading.
        encode_optional: bool = false,

        free: ?fn (allocator: std.mem.Allocator, data: anytype) void = null,
        hashmap: if (hashMapInfo(T)) |hm_info| bincode.HashMapConfig(hm_info) else void = if (hashMapInfo(T) != null) .{} else {},
    },
) bincode.FieldConfig(?T) {
    const S = struct {
        fn deserializer(
            allocator: std.mem.Allocator,
            reader: anytype,
            params: bincode.Params,
        ) anyerror!?T {
            const EncodedType = if (options.encode_optional) ?T else T;
            return bincode.read(allocator, EncodedType, reader, params) catch |err| switch (err) {
                error.EndOfStream => null,
                else => |e| e,
            };
        }

        fn serializer(
            writer: anytype,
            maybe_data: anytype,
            params: bincode.Params,
        ) anyerror!void {
            if (options.encode_optional) {
                return try bincode.write(writer, maybe_data, params);
            } else {
                const data = maybe_data orelse return;
                return try bincode.write(writer, data, params);
            }
        }
    };
    return .{
        .deserializer = S.deserializer,
        .serializer = S.serializer,
        .free = options.free,
        .skip = false,
        .hashmap = options.hashmap,
    };
}
