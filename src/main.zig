const gossip_cmd = @import("cmd/gossip.zig");

pub fn main() !void {
    try gossip_cmd.run();
}
