const std = @import("std");

pub fn indexOf(comptime T: type, slice: []const T, value: T) ?usize {
    for (slice, 0..) |element, index| {
        if (std.meta.eql(value, element)) return index;
    } else return null;
}

pub fn shuffleFirstN(random: std.rand.Random, comptime T: type, buf: []T, n: usize) void {
    for (0..n) |i| {
        const j = random.intRangeLessThan(usize, 0, buf.len);
        std.mem.swap(T, &buf[i], &buf[j]);
    }
}
