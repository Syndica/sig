const std = @import("std");
const sig = @import("../lib.zig");
const bincode = sig.bincode;

/// faster ser/deser for slices of bytes
pub fn U8SliceConfig() bincode.FieldConfig([]u8) {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, _: bincode.Params) !void {
            try bincode.write(writer, data.len, .{});

            try writer.writeAll(data);
        }

        pub fn deserialize(allocator: std.mem.Allocator, reader: anytype, _: bincode.Params) ![]u8 {
            const len = try bincode.read(allocator, u64, reader, .{});

            const data = try allocator.alloc(u8, len);
            errdefer allocator.free(data);

            _ = try reader.readAll(data);

            return data;
        }

        pub fn free(allocator: std.mem.Allocator, data: anytype) void {
            allocator.free(data);
        }
    };

    return bincode.FieldConfig([]u8){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}
