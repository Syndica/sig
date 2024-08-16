const std = @import("std");
const sig = @import("../sig.zig");
const bincode = sig.bincode;

pub fn defaultOnEof(comptime T: type, comptime eof_value: T) bincode.FieldConfig(T) {
    const S = struct {
        fn deserializer(
            _: std.mem.Allocator,
            reader: anytype,
            params: bincode.Params,
        ) anyerror!T {
            var fba = comptime std.heap.FixedBufferAllocator.init(&.{});
            return bincode.read(fba.allocator(), T, reader, params) catch |err| switch (err) {
                error.EndOfStream => eof_value,
                else => |e| e,
            };
        }

        fn serializer(
            writer: anytype,
            data: anytype,
            params: bincode.Params,
        ) anyerror!void {
            if (data == eof_value) return;
            try bincode.write(writer, data, params);
        }
    };
    return .{
        .deserializer = S.deserializer,
        .serializer = S.serializer,
    };
}

// TODO: make this the default behaviour for bincode []u8 slices
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

// TODO: make this the default behaviour for bincode [size]u8 arrays
pub fn U8ArrayConfig(comptime size: u64) bincode.FieldConfig([size]u8) {
    const S = struct {
        pub fn serialize(writer: anytype, data: anytype, params: bincode.Params) !void {
            if (params.include_fixed_array_length) {
                try bincode.write(writer, @as(u64, data.len), .{});
            }

            try writer.writeAll(&data);
        }

        pub fn deserialize(allocator: std.mem.Allocator, reader: anytype, params: bincode.Params) ![size]u8 {
            if (params.include_fixed_array_length) {
                _ = try bincode.read(allocator, u64, reader, .{});
            }
            const data = try reader.readBytesNoEof(size);
            return data;
        }

        pub fn free(allocator: std.mem.Allocator, data: anytype) void {
            _ = allocator;
            _ = data;
        }
    };

    return bincode.FieldConfig([size]u8){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}
