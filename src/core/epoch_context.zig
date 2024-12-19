const std = @import("std");
const core = @import("lib.zig");

/// constant data about a particular epoch.
/// this can be computed before the epoch begins, and does not change during the epoch
pub const EpochContext = struct {
    /// the staked nodes for this particular cluster to use for the leader schedule and turbine tree
    staked_nodes: std.AutoArrayHashMapUnmanaged(core.Pubkey, u64),
    /// the leader schedule for this epoch
    leader_schedule: []const core.Pubkey,

    pub fn deinit(self: *EpochContext, allocator: std.mem.Allocator) void {
        self.staked_nodes.deinit(allocator);
        allocator.free(self.leader_schedule);
    }
};
