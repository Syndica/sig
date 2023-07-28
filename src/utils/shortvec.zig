const std = @import("std");
const bincode = @import("../bincode/bincode.zig");
const network = @import("zig-network");
const serialize_short_u16 = @import("varint.zig").serialize_short_u16;
const deserialize_short_u16 = @import("varint.zig").deserialize_short_u16;

pub fn ShortVecConfig(comptime childSerialize: bincode.SerializeFunction, comptime childDeserialize: bincode.DeserializeFunction) bincode.FieldConfig {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            var len: u16 = std.math.cast(u16, data.len) orelse return error.DataTooLarge;
            try serialize_short_u16(writer, len, params);
            for (data) |item| {
                try childSerialize(writer, item, params);
            }
            return;
        }

        pub fn deserialize(allocator: ?std.mem.Allocator, comptime T: type, reader: anytype, params: bincode.Params) !void {
            var ally = allocator.?;

            var len = try deserialize_short_u16(ally, u16, reader, params);
            var elems = try ally.alloc(T.child, len);
            for (0..len) |i| {
                elems[i] = childDeserialize(ally, T.child, reader, params);
            }
            return elems;
        }
    };

    return bincode.FieldConfig{
        .serializer = S.serialize,
        .deserializer = S.deserialize,
    };
}

pub const shortvec_config = bincode.FieldConfig{
    .serializer = serilaize_shortvec,
    .deserializer = deserialize_shortvec,
};

pub fn serilaize_shortvec(writer: anytype, data: anytype, params: bincode.Params) !void {
    var len = std.math.cast(u16, data.len) orelse return error.DataTooLarge;
    try serialize_short_u16(writer, len, params);
    for (data) |item| {
        try bincode.write(null, writer, item, params);
    }
    return;
}

pub fn deserialize_shortvec(allocator: ?std.mem.Allocator, comptime T: type, reader: anytype, params: bincode.Params) !T {
    var ally = allocator.?;

    const Child = @typeInfo(T).Pointer.child;
    var len = try deserialize_short_u16(ally, u16, reader, params);
    var elems = try ally.alloc(Child, len);
    for (0..len) |i| {
        elems[i] = try bincode.read(ally, Child, reader, params);
    }
    return elems;
}
