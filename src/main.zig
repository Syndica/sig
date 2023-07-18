const cmd = @import("cmd/cmd.zig");

pub fn main() !void {
    try cmd.run();
}
