const std = @import("std");
const bincode = @import("../bincode/bincode.zig");

pub fn ArrayListConfig(comptime Child: type) bincode.FieldConfig(std.ArrayList(Child)) {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            const list: std.ArrayList(Child) = data;
            try bincode.write(null, writer, @as(u64, list.items.len), params);
            for (list.items) |item| {
                try bincode.write(null, writer, item, params);
            }
            return;
        }

        pub fn deserialize(allocator: ?std.mem.Allocator, reader: anytype, params: bincode.Params) !std.ArrayList(Child) {
            const ally = allocator.?;
            const len = try bincode.read(ally, u64, reader, params);
            var list = try std.ArrayList(Child).initCapacity(ally, @as(usize, len));
            for (0..len) |_| {
                const item = try bincode.read(ally, Child, reader, params);
                try list.append(item);
            }
            return list;
        }

        pub fn free(allocator: std.mem.Allocator, data: anytype) void {
            _ = allocator;
            data.deinit();
        }
    };

    return bincode.FieldConfig(std.ArrayList(Child)){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}

pub fn defaultArrayListOnEOFConfig(comptime T: type) bincode.FieldConfig(std.ArrayList(T)) {
    const S = struct {
        fn defaultEOF(allocator: std.mem.Allocator) std.ArrayList(T) {
            return std.ArrayList(T).init(allocator);
        }

        fn free(_: std.mem.Allocator, data: anytype) void {
            data.deinit();
        }
    };

    return bincode.FieldConfig(std.ArrayList(T)){
        .default_on_eof = true,
        .free = S.free,
        .default_fn = S.defaultEOF,
    };
}
