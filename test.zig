const std = @import("std");

export fn byteSwap(a: *const [32]u8, out: *[32]u8) void {
    const limbs: [4]u64 = @bitCast(a.*);
    const array: [4]u64 = .{
        @byteSwap(limbs[3]),
        @byteSwap(limbs[2]),
        @byteSwap(limbs[1]),
        @byteSwap(limbs[0]),
    };
    out.* = @bitCast(array);
}

export fn foo(a: *const [32]u8, out: *[32]u8) void {
    const x: u256 = @bitCast(a.*);
    out.* = @bitCast(@byteSwap(x));
}

pub fn main() !void {
    var buffer: [32]u8 = @splat(0);
    buffer[0] = 0x1;
}
