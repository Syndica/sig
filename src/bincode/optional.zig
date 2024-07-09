const std = @import("std");
const sig = @import("../lib.zig");
const bincode = sig.bincode;
const hashMapInfo = sig.utils.types.hashMapInfo;

pub fn defaultToNullOnEof(comptime T: type, fields: struct {
    free: ?fn (allocator: std.mem.Allocator, data: anytype) void = null,
    hashmap: if (hashMapInfo(T)) |hm_info| bincode.HashMapConfig(hm_info) else void = if (hashMapInfo(T) != null) .{} else {},
}) bincode.FieldConfig(?T) {
    const gen = struct {
        fn deserializer(
            allocator: std.mem.Allocator,
            reader: anytype,
            params: bincode.Params,
        ) anyerror!?T {
            return bincode.read(allocator, T, reader, params) catch |err| switch (err) {
                error.EndOfStream => null,
                else => |e| e,
            };
        }

        fn serializer(
            writer: anytype,
            maybe_data: anytype,
            params: bincode.Params,
        ) anyerror!void {
            const data = maybe_data orelse return;
            try bincode.write(writer, data, params);
        }

        fn default(_: std.mem.Allocator) ?T {
            return null;
        }

        fn skipWrite(maybe_value: anytype) bool {
            return maybe_value == null;
        }
    };
    return .{
        .deserializer = gen.deserializer,
        .serializer = gen.serializer,
        .free = fields.free,
        .skip = false,
        .default_on_eof = true,
        .default_fn = gen.default,
        .skip_write_fn = gen.skipWrite,
        .hashmap = fields.hashmap,
    };
}
