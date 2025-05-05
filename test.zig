const std = @import("std");
const BigInt = std.math.big.int.Managed;

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    const bytes: []const u8 = "Hello world!";
    std.debug.print("original len: {}\n", .{bytes.len});

    const buffer = try allocator.alloc(u64, try std.math.divCeil(u64, bytes.len, 8));
    @memset(buffer, 0);

    std.debug.print("buffer: {}\n", .{buffer.len});

    @memcpy(std.mem.sliceAsBytes(buffer)[0..bytes.len], bytes);

    const big_int: std.math.big.int.Const = .{
        .limbs = buffer,
        .positive = true,
    };

    std.debug.print("int: {}\n", .{big_int});
}
