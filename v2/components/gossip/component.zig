comptime {
    if (@import("builtin").is_test) {
        _ = @import("Metrics.zig");
        _ = @import("node.zig");
        _ = @import("tests.zig");
    }
}

pub const api = @import("gossip_api");

pub const GossipNode = @import("node.zig").GossipNode;
pub const Metrics = @import("Metrics.zig");
