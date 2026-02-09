const std = @import("std");

/// Whether the current backend supports SIMD vector operations.
const backend_supports_vectors = switch (@import("builtin").zig_backend) {
    .stage2_llvm, .stage2_c => true,
    else => false,
};

/// Applies XOR masking/unmasking to payload in-place using the 4-byte mask key.
/// The same function works for both masking and unmasking (XOR is its own inverse).
/// Uses SIMD acceleration when available, with scalar fallback.
pub fn mask(m: []const u8, payload: []u8) void {
    std.debug.assert(m.len == 4);
    var data = payload;

    if (!comptime backend_supports_vectors) return scalarMask(m, data);

    const vector_size = comptime std.simd.suggestVectorLength(u8) orelse @sizeOf(usize);
    if (data.len >= vector_size) {
        const mask_vector: @Vector(vector_size, u8) = std.simd.repeat(vector_size, m[0..4].*);
        while (data.len >= vector_size) {
            const slice = data[0..vector_size];
            const masked: @Vector(vector_size, u8) = slice.*;
            slice.* = masked ^ mask_vector;
            data = data[vector_size..];
        }
    }
    scalarMask(m, data);
}

/// Scalar byte-by-byte XOR mask fallback for remaining bytes or unsupported backends.
fn scalarMask(m: []const u8, payload: []u8) void {
    @setRuntimeSafety(false);
    for (payload, 0..) |b, i| {
        payload[i] = b ^ m[i & 3];
    }
}

const testing = std.testing;

test "mask: empty payload is no-op" {
    var buf = [_]u8{};
    mask(&.{ 0xAA, 0xBB, 0xCC, 0xDD }, &buf);
}

test "mask: single byte" {
    var buf = [_]u8{0x42};
    mask(&.{ 0xFF, 0x00, 0x00, 0x00 }, &buf);
    try testing.expectEqual(@as(u8, 0x42 ^ 0xFF), buf[0]);
}

test "mask: round-trip produces original" {
    const original = "Hello, WebSocket!";
    var buf: [original.len]u8 = undefined;
    @memcpy(&buf, original);

    const key = [_]u8{ 0x37, 0xFA, 0x21, 0x3D };

    // Mask
    mask(&key, &buf);
    // Should differ from original
    try testing.expect(!std.mem.eql(u8, &buf, original));
    // Unmask (same operation)
    mask(&key, &buf);
    try testing.expectEqualSlices(u8, original, &buf);
}

test "mask: exact 4-byte alignment" {
    var buf = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const key = [_]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
    mask(&key, &buf);
    const expected = [_]u8{ 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7 };
    try testing.expectEqualSlices(u8, &expected, &buf);
}

test "mask: SIMD boundary sizes" {
    const key = [_]u8{ 0x12, 0x34, 0x56, 0x78 };
    // Test various sizes including around typical SIMD widths (16, 32, 64)
    const sizes = [_]usize{
        1,  2,  3,  4,  5,  7,   8,   15,  16,  17,  31,
        32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257,
    };

    for (sizes) |size| {
        const buf = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(buf);
        const expected = try testing.allocator.alloc(u8, size);
        defer testing.allocator.free(expected);

        // Fill with known pattern
        for (buf, 0..) |*b, i| {
            b.* = @truncate(i);
        }
        @memcpy(expected, buf);

        // Mask then unmask should round-trip
        mask(&key, buf);
        mask(&key, buf);
        try testing.expectEqualSlices(u8, expected, buf);
    }
}

test "mask: all-zero mask is identity" {
    const original = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };
    var buf = original;
    mask(&.{ 0x00, 0x00, 0x00, 0x00 }, &buf);
    try testing.expectEqualSlices(u8, &original, &buf);
}

test "mask: all-ones mask inverts all bits" {
    var buf = [_]u8{ 0x00, 0xFF, 0xAA, 0x55 };
    mask(&.{ 0xFF, 0xFF, 0xFF, 0xFF }, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0x00, 0x55, 0xAA }, &buf);
}

test "mask: RFC 6455 example verification" {
    // RFC 6455 Section 5.7 examples use masking; verify XOR properties
    // "Hello" = { 0x48, 0x65, 0x6c, 0x6c, 0x6f }
    // With mask key { 0x37, 0xfa, 0x21, 0x3d }:
    // masked = { 0x48^0x37, 0x65^0xfa, 0x6c^0x21, 0x6c^0x3d, 0x6f^0x37 }
    //        = { 0x7f, 0x9f, 0x4d, 0x51, 0x58 }
    var buf = [_]u8{ 0x48, 0x65, 0x6c, 0x6c, 0x6f };
    mask(&.{ 0x37, 0xfa, 0x21, 0x3d }, &buf);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x7f, 0x9f, 0x4d, 0x51, 0x58 }, &buf);
}

test "mask: fuzz round-trip" {
    const Context = struct {
        fn testOne(_: @This(), input: []const u8) anyerror!void {
            if (input.len < 4) return;
            const key = input[0..4];
            const buf = try testing.allocator.alloc(u8, input.len - 4);
            defer testing.allocator.free(buf);
            @memcpy(buf, input[4..]);
            const original = try testing.allocator.alloc(u8, buf.len);
            defer testing.allocator.free(original);
            @memcpy(original, buf);

            mask(key, buf);
            mask(key, buf);
            try testing.expectEqualSlices(u8, original, buf);
        }
    };
    try testing.fuzz(Context{}, Context.testOne, .{});
}
