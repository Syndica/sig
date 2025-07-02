const std = @import("std");
const sig = @import("../sig.zig");

const bincode = sig.bincode;

pub fn sliceConfig(comptime Slice: type) bincode.FieldConfig(Slice) {
    const Child = std.meta.Elem(Slice);
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            const len: u16 = std.math.cast(u16, data.len) orelse return error.DataTooLarge;
            try std.leb.writeUleb128(writer, len);
            for (data) |item| {
                try bincode.write(writer, item, params);
            }
        }

        pub fn deserialize(allocator: std.mem.Allocator, reader: anytype, params: bincode.Params) !Slice {
            const len = try std.leb.readUleb128(u16, reader);
            const elems = try allocator.alloc(Child, len);
            errdefer allocator.free(elems);
            for (elems, 0..) |*elem, i| {
                errdefer for (elems[0..i]) |prev| bincode.free(allocator, prev);
                elem.* = try bincode.read(allocator, Child, reader, params);
            }
            return elems;
        }

        pub fn free(allocator: std.mem.Allocator, data: anytype) void {
            for (data) |elem| bincode.free(allocator, elem);
            allocator.free(data);
        }
    };

    return .{
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}

pub fn arrayListConfig(comptime Child: type) bincode.FieldConfig(std.ArrayList(Child)) {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            const list: std.ArrayList(Child) = data;
            const len = std.math.cast(u16, list.items.len) orelse return error.DataTooLarge;
            try std.leb.writeUleb128(writer, len);
            for (list.items) |item| {
                try bincode.write(writer, item, params);
            }
        }

        pub fn deserialize(allocator: std.mem.Allocator, reader: anytype, params: bincode.Params) !std.ArrayList(Child) {
            const len = try std.leb.readUleb128(u16, reader);
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

    return .{
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}
