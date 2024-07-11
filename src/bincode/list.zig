const std = @import("std");
const sig = @import("../lib.zig");
const bincode = sig.bincode;

pub const Error = error{SingleElementSliceInvalidLength};
pub fn valueEncodedAsSlice(
    comptime T: type,
    comptime config: bincode.FieldConfig(T),
) bincode.FieldConfig(T) {
    const S = struct {
        fn deserializeImpl(
            allocator: std.mem.Allocator,
            reader: anytype,
            params: bincode.Params,
        ) anyerror!T {
            const len = (try bincode.readIntAsLength(usize, reader, params)) orelse return Error.SingleElementSliceInvalidLength;
            if (len != 1) return Error.SingleElementSliceInvalidLength;
            if (config.deserializer) |deserialize| {
                return try deserialize(allocator, reader, params);
            }
            return try bincode.read(allocator, T, reader, params);
        }

        fn serializeImpl(
            writer: anytype,
            data: anytype,
            params: bincode.Params,
        ) anyerror!void {
            const as_slice: []const T = (&data)[0..1];
            if (config.serializer) |serialize| {
                return try serialize(writer, as_slice, params);
            }
            try bincode.write(writer, as_slice, params);
        }
    };
    return .{
        .deserializer = S.deserializeImpl,
        .serializer = S.serializeImpl,
        .free = config.free,
        .skip = config.skip,
        .hashmap = config.hashmap,
    };
}
