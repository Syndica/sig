const std = @import("std");
const bincode = @import("bincode-zig");

pub fn ArrayListConfig(comptime Child: type) bincode.FieldConfig {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            var list: std.ArrayList(Child) = data;
            try bincode.write(writer, @as(u64, list.items.len), params);
            for (list.items) |item| {
                try bincode.write(writer, item, params);
            }
            return;
        }

        pub fn deserialize(allocator: std.mem.Allocator, comptime T: type, reader: anytype, params: bincode.Params) !T {
            var len = try bincode.read(allocator, u64, reader, params);
            var list = try std.ArrayList(Child).initCapacity(allocator, @as(usize, len));
            for (0..len) |_| {
                var item = try bincode.read(allocator, Child, reader, params);
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
