const std = @import("std");
const sig = @import("../sig.zig");
const bincode = sig.bincode;

pub fn defaultOnEof(comptime T: type, comptime eof_value: T) bincode.FieldConfig(T) {
    const S = struct {
        fn deserializer(
            _: std.mem.Allocator,
            reader: anytype,
            params: bincode.Params,
        ) !T {
            var fba = comptime std.heap.FixedBufferAllocator.init(&.{});
            return bincode.read(fba.allocator(), T, reader, params) catch |err|
                if (err == error.EndOfStream) eof_value else err;
        }

        fn serializer(
            writer: anytype,
            data: T,
            params: bincode.Params,
        ) !void {
            if (data == eof_value) return;
            try bincode.write(writer, data, params);
        }
    };
    return .{
        .deserializer = S.deserializer,
        .serializer = S.serializer,
    };
}

pub fn U8SliceConfig() bincode.FieldConfig([]u8) {
    const S = struct {
        pub fn serialize(writer: anytype, data: []u8, _: bincode.Params) !void {
            try bincode.write(writer, data.len, .{});
            try writer.writeAll(data);
        }

        pub fn deserialize(allocator: std.mem.Allocator, reader: anytype, _: bincode.Params) ![]u8 {
            const len = try bincode.read(allocator, u64, reader, .{});

            const data = try allocator.alloc(u8, len);
            errdefer allocator.free(data);

            if (try reader.readAll(data) != len) return error.EndOfStream;

            return data;
        }

        pub fn free(allocator: std.mem.Allocator, data: []u8) void {
            allocator.free(data);
        }
    };

    return bincode.FieldConfig([]u8){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}

pub fn U8Config() bincode.FieldConfig(u8) {
    const S = struct {
        pub fn serialize(writer: anytype, data: u8, _: bincode.Params) !void {
            try writer.writeByte(data);
        }

        pub fn deserialize(_: std.mem.Allocator, reader: anytype, _: bincode.Params) !u8 {
            return try reader.readByte();
        }

        pub fn free(_: std.mem.Allocator, _: u8) void {}
    };

    return bincode.FieldConfig(u8){
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}

pub fn U8ConstSliceConfig() bincode.FieldConfig([]const u8) {
    const S = struct {
        pub fn serialize(writer: anytype, data: []const u8, _: bincode.Params) !void {
            try bincode.write(writer, data.len, .{});
            try writer.writeAll(data);
        }

        pub fn deserialize(
            allocator: std.mem.Allocator,
            reader: anytype,
            params: bincode.Params,
        ) ![]const u8 {
            return U8SliceConfig().deserializer.?(allocator, reader, params);
        }

        pub fn free(allocator: std.mem.Allocator, data: []const u8) void {
            allocator.free(data);
        }
    };

    return .{
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}

pub fn U8ArrayConfig(comptime size: u64) bincode.FieldConfig([size]u8) {
    const S = struct {
        pub fn serialize(writer: anytype, data: [size]u8, params: bincode.Params) !void {
            if (params.include_fixed_array_length) {
                try bincode.write(writer, @as(u64, data.len), .{});
            }
            try writer.writeAll(&data);
        }

        pub fn deserialize(
            allocator: std.mem.Allocator,
            reader: anytype,
            params: bincode.Params,
        ) ![size]u8 {
            if (params.include_fixed_array_length) {
                _ = try bincode.read(allocator, u64, reader, .{});
            }
            return try reader.readBytesNoEof(size);
        }

        pub fn free(allocator: std.mem.Allocator, data: [size]u8) void {
            _ = allocator;
            _ = data;
        }
    };

    return .{
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}

pub fn U8ArraySentinelConfig(comptime size: u64) bincode.FieldConfig([size:0]u8) {
    const S = struct {
        pub fn serialize(writer: anytype, data: [size:0]u8, params: bincode.Params) !void {
            if (params.include_fixed_array_length) {
                try bincode.write(writer, @as(u64, data.len), .{});
            }
            try writer.writeAll(&data);
        }

        pub fn deserialize(
            allocator: std.mem.Allocator,
            reader: anytype,
            params: bincode.Params,
        ) ![size:0]u8 {
            if (params.include_fixed_array_length) {
                const encoded_len = try bincode.read(allocator, u64, reader, .{});
                if (encoded_len != size) return error.LengthMismatch;
            }
            var data: [size:0]u8 = .{undefined} ** size;
            const bytes_read = try reader.readAll(&data);
            std.debug.assert(bytes_read <= size);
            if (bytes_read != size) return error.EndOfStream;
            return data;
        }

        pub fn free(allocator: std.mem.Allocator, data: [size:0]u8) void {
            _ = allocator;
            _ = data;
        }
    };

    return .{
        .serializer = S.serialize,
        .deserializer = S.deserialize,
        .free = S.free,
    };
}
