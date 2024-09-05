const std = @import("std");

pub fn indexOf(comptime T: type, slice: []const T, value: T) ?usize {
    for (slice, 0..) |element, index| {
        if (std.meta.eql(value, element)) return index;
    } else return null;
}

pub fn shuffleFirstN(rng: std.rand.Random, comptime T: type, buf: []T, n: usize) void {
    for (0..n) |i| {
        const j = rng.intRangeLessThan(usize, 0, buf.len);
        std.mem.swap(T, &buf[i], &buf[j]);
    }
}
