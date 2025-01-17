const std = @import("std");
const base58 = @import("base58-zig");

const Allocator = std.mem.Allocator;

pub fn Base58Sized(decoded_size: usize) type {
    const encoder = base58.Encoder.init(.{});
    const decoder = base58.Decoder.init(.{});

    const decoded_size_float = @as(f64, @floatFromInt(decoded_size));
    const max_encoded_size_float = decoded_size_float * (8.0 / std.math.log2(58.0));

    return struct {
        pub const max_encoded_size: usize = @ceil(max_encoded_size_float);
        pub const String = std.BoundedArray(u8, max_encoded_size);

        pub fn decode(str: []const u8) ![decoded_size]u8 {
            var result_data: [decoded_size]u8 = undefined;
            @setEvalBranchQuota(decoded_size * 145);
            const decoded_len = try decoder.decode(str, &result_data);
            if (decoded_len != decoded_size) return error.InvalidDecodedSize;
            return result_data;
        }

        pub fn encode(data: [decoded_size]u8) String {
            var result: std.BoundedArray(u8, max_encoded_size) = .{};
            // unreachable because `max_encoded_size` is the
            // maximum encoded size for `decoded_size` bytes
            const encoded_len = encoder.encode(&data, &result.buffer) catch unreachable;
            result.len = @intCast(encoded_len);
            return result;
        }

        pub fn encodeAlloc(
            data: [decoded_size]u8,
            allocator: Allocator,
        ) Allocator.Error![]const u8 {
            const buf = try allocator.alloc(u8, max_encoded_size);
            const actual_size = encodeToSlice(data, buf[0..max_encoded_size]);
            return try allocator.realloc(buf, actual_size);
        }

        pub fn encodeToSlice(data: [decoded_size]u8, buf: *[max_encoded_size]u8) usize {
            // unreachable because `max_encoded_size` is the
            // maximum encoded size for `decoded_size` bytes
            const actual_size = encoder.encode(&data, buf[0..]) catch unreachable;
            std.debug.assert(actual_size <= max_encoded_size);
            return actual_size;
        }

        pub fn format(data: [decoded_size]u8, writer: anytype) !void {
            const b58_str_bounded = encode(data);
            return writer.writeAll(b58_str_bounded.constSlice());
        }
    };
}
