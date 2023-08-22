const cmd = @import("cmd/cmd.zig");
const std = @import("std");

pub fn main() !void {
    try cmd.run();
}
