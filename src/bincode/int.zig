const std = @import("std");
const sig = @import("../sig.zig");
const bincode = sig.bincode;

pub fn defaultOnEof(comptime T: type, comptime eof_value: T) bincode.FieldConfig(T) {
    const S = struct {
        fn deserializer(
            _: *bincode.LimitAllocator,
            reader: anytype,
            params: bincode.Params,
        ) anyerror!T {
            var fba = comptime std.heap.FixedBufferAllocator.init(&.{});
            return bincode.read(fba.allocator(), T, reader, params) catch |err|
                if (err == error.EndOfStream) eof_value else err;
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

pub fn U8SliceConfig(comptime T: type) bincode.FieldConfig(T) {
    const S = struct {
        pub fn serialize(writer: *std.Io.Writer, data: T, _: bincode.Params) !void {
            try bincode.write(writer, data.len, .{});

            try writer.writeAll(data);
        }

        pub fn deserialize(
            limit_allocator: *bincode.LimitAllocator,
            reader: *std.Io.Reader,
            _: bincode.Params,
        ) !T {
            const len = try bincode.readWithLimit(limit_allocator, u64, reader, .{});
            const allocator = limit_allocator.allocator();

            const data = try reader.readAlloc(allocator, len);
            return data;
        }

        pub fn free(allocator: std.mem.Allocator, data: T) void {
            allocator.free(data);
        }
    };

    return .{
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}

pub fn U8Config() bincode.FieldConfig(u8) {
    const S = struct {
        pub fn serialize(writer: *std.Io.Writer, data: u8, _: bincode.Params) !void {
            try writer.writeByte(data);
        }

        pub fn deserialize(_: *bincode.LimitAllocator, reader: *std.Io.Reader, _: bincode.Params) !u8 {
            return try reader.takeByte();
        }
    };

    return bincode.FieldConfig(u8){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = null,
    };
}

pub fn U8ArrayConfig(comptime size: u64) bincode.FieldConfig([size]u8) {
    const S = struct {
        pub fn serialize(
            writer: *std.Io.Writer,
            data: [size]u8,
            params: bincode.Params,
        ) !void {
            if (params.include_fixed_array_length) {
                try bincode.write(writer, @as(u64, data.len), .{});
            }

            try writer.writeAll(&data);
        }

        pub fn deserialize(
            limit_allocator: *bincode.LimitAllocator,
            reader: *std.Io.Reader,
            params: bincode.Params,
        ) ![size]u8 {
            if (params.include_fixed_array_length) {
                _ = try bincode.readWithLimit(limit_allocator, u64, reader, .{});
            }
            const data = try reader.takeArray(size);
            return data.*;
        }

        pub fn free(allocator: std.mem.Allocator, data: [size]u8) void {
            _ = allocator;
            _ = data;
        }
    };

    return bincode.FieldConfig([size]u8){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = null,
    };
}

pub fn U8ArraySentinelConfig(comptime size: u64) bincode.FieldConfig([size:0]u8) {
    const S = struct {
        pub fn deserialize(
            limit_allocator: *bincode.LimitAllocator,
            reader: *std.Io.Reader,
            params: bincode.Params,
        ) ![size:0]u8 {
            if (params.include_fixed_array_length) {
                _ = try bincode.readWithLimit(limit_allocator, u64, reader, .{});
            }
            var buf: [size:0]u8 = undefined;
            @memcpy(&buf, try reader.takeArray(size));
            return buf;
        }
    };

    return bincode.FieldConfig([size:0]u8){
        .serializer = U8ArrayConfig(size).serializer,
        .deserializer = S.deserialize,
        .free = U8ArrayConfig(size).free,
    };
}
