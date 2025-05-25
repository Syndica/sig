const std = @import("std");

var x: f32 = 10.4;

pub fn main() !void {
    const y: f64 = x;
    std.debug.print("y: {}\n", .{y});
}
