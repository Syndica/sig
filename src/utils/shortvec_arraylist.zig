const std = @import("std");
const bincode = @import("../bincode/bincode.zig");
const serialize_short_u16 = @import("varint.zig").serialize_short_u16;
const deserialize_short_u16 = @import("varint.zig").deserialize_short_u16;

pub fn ShortVecArrayListConfig(comptime Child: type) bincode.FieldConfig {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            var list: std.ArrayList(Child) = data;
            var len = std.math.cast(u16, list.items.len) orelse return error.DataTooLarge;
            try serialize_short_u16(writer, len, params);
            for (list.items) |item| {
                try bincode.write(null, writer, item, params);
            }
            return;
        }

        pub fn deserialize(allocator: ?std.mem.Allocator, comptime T: type, reader: anytype, params: bincode.Params) !T {
            var ally = allocator.?;
            var len = try deserialize_short_u16(ally, u16, reader, params);
            var list = try std.ArrayList(Child).initCapacity(ally, @as(usize, len));
            for (0..len) |_| {
                var item = try bincode.read(ally, Child, reader, params);
                try list.append(item);
            }
            return list;
        }
    };

    return bincode.FieldConfig{
        .serializer = S.serialize,
        .deserializer = S.deserialize,
    };
}
