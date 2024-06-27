const std = @import("std");
const sig = @import("../lib.zig");

const bincode = sig.bincode;

const serialize_short_u16 = sig.bincode.varint.serialize_short_u16;
const deserialize_short_u16 = sig.bincode.varint.deserialize_short_u16;

pub fn ShortVecConfig(comptime Child: type) bincode.FieldConfig([]Child) {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            const len: u16 = std.math.cast(u16, data.len) orelse return error.DataTooLarge;
            try serialize_short_u16(writer, len, params);
            for (data) |item| {
                try bincode.write(writer, item, params);
            }
        }

        pub fn deserialize(allocator: ?std.mem.Allocator, reader: anytype, params: bincode.Params) ![]Child {
            var ally = allocator.?;

            const len = try deserialize_short_u16(reader, params);
            var elems = try ally.alloc(Child, len);
            for (0..len) |i| {
                elems[i] = try bincode.read(ally, Child, reader, params);
            }
            return elems;
        }

        pub fn free(allocator: std.mem.Allocator, data: anytype) void {
            allocator.free(data);
        }
    };

    return bincode.FieldConfig([]Child){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}

pub fn ShortVecArrayListConfig(comptime Child: type) bincode.FieldConfig(std.ArrayList(Child)) {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            const list: std.ArrayList(Child) = data;
            const len = std.math.cast(u16, list.items.len) orelse return error.DataTooLarge;
            try serialize_short_u16(writer, len, params);
            for (list.items) |item| {
                try bincode.write(writer, item, params);
            }
        }

        pub fn deserialize(allocator: ?std.mem.Allocator, reader: anytype, params: bincode.Params) !std.ArrayList(Child) {
            const ally = allocator.?;

            const len = try deserialize_short_u16(reader, params);
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
