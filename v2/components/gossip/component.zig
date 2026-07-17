//! The `gossip` component wraps the `GossipNode` runtime + `Metrics` around
//! the public gossip protocol types in `api`.

comptime {
    if (@import("builtin").is_test) {
        _ = @import("Metrics.zig");
        _ = @import("bincode.zig");
        _ = @import("node.zig");
    }
}

pub const api = @import("api");

pub const GossipNode = @import("node.zig").GossipNode;
pub const Metrics = @import("Metrics.zig");
