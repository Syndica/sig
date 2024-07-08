const std = @import("std");
const sig = @import("../lib.zig");

const bincode = sig.bincode;

pub fn ArrayListConfig(comptime Child: type) bincode.FieldConfig(std.ArrayList(Child)) {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            const list: std.ArrayList(Child) = data;
            try bincode.write(writer, @as(u64, list.items.len), params);
            for (list.items) |item| {
                try bincode.write(writer, item, params);
            }
            return;
        }

        pub fn deserialize(allocator: std.mem.Allocator, reader: anytype, params: bincode.Params) !std.ArrayList(Child) {
            const len = try bincode.read(allocator, u64, reader, params);
            var list = try std.ArrayList(Child).initCapacity(allocator, @as(usize, len));
            for (0..len) |_| {
                const item = try bincode.read(allocator, Child, reader, params);
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

pub fn defaultArrayListUnmanagedOnEOFConfig(comptime T: type) bincode.FieldConfig(std.ArrayListUnmanaged(T)) {
    const S = struct {
        fn defaultEOF(_: std.mem.Allocator) std.ArrayListUnmanaged(T) {
            return .{};
        }

        fn free(allocator: std.mem.Allocator, data: anytype) void {
            data.deinit(allocator);
        }
    };

    return .{
        .default_on_eof = true,
        .free = S.free,
        .default_fn = S.defaultEOF,
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

    return .{
        .default_on_eof = true,
        .free = S.free,
        .default_fn = S.defaultEOF,
    };
}
