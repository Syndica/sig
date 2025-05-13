const std = @import("std");

pub fn main() !void {
    const x: []const (struct { c: u8 align(4096) }) = &.{ undefined, undefined };
    std.debug.print("addr: {*}\n", .{&x[1]});
}
