const std = @import("std");
const sig = @import("../../sig.zig");
const methods = @import("../methods.zig");

const CommitmentTracker = sig.replay.trackers.CommitmentTracker;

// Maximum allowed slot distance before node is considered unhealthy.
// See: https://github.com/anza-xyz/agave/blob/v3.1.8/rpc-client-types/src/request.rs#L158
const DELINQUENT_VALIDATOR_SLOT_DISTANCE: u64 = 128;

const HealthChecker = @This();

commitments: *sig.replay.trackers.CommitmentTracker,

/// Check the health of the node.
///
/// A node is considered healthy if the node's latest optimistically confirmed
/// slot is within `DELINQUENT_VALIDATOR_SLOT_DISTANCE` of the cluster's latest
/// optimistically confirmed slot.
///
/// Returns `RpcHealthStatus` which is then formatted by the server layer:
/// - JSON-RPC: "ok" result on success, error with code -32005 on failure
/// - HTTP GET /health: always 200 OK with "ok", "behind", or "unknown"
///
/// [agave] https://github.com/anza-xyz/agave/blob/v3.1.8/rpc/src/rpc.rs#L2806-L2818
pub fn getHealth(
    self: HealthChecker,
    _: std.mem.Allocator,
    _: methods.GetHealth,
) !methods.GetHealth.Response {
    // Get the node's processed slot (replay tip according to vote tracking)
    const latest_processed_slot = self.commitments.get(.processed);
    if (latest_processed_slot == 0) {
        return .unknown;
    }

    // Get the cluster's latest optimistically confirmed slot
    // NOTE: this commitment confirmed value is from both replay and vote tracker gossip votes,
    // gossip has latest from the network which is what we need for comparison
    const latest_confirmed_slot = self.commitments.get(.confirmed);
    if (latest_confirmed_slot == 0) {
        return .unknown;
    }

    if (latest_processed_slot >= latest_confirmed_slot -| DELINQUENT_VALIDATOR_SLOT_DISTANCE) {
        return .ok;
    } else {
        const num_slots_behind = latest_confirmed_slot -| latest_processed_slot;
        return .{ .behind = num_slots_behind };
    }
}

test "getHealth returns unknown when processed slot is unknown" {
    var commitments = CommitmentTracker.init(std.testing.allocator, 0);
    defer commitments.deinit(std.testing.allocator);
    commitments.confirmed.store(10, .monotonic);
    const result = try getHealth(.{ .commitments = &commitments }, std.testing.allocator, .{});
    try std.testing.expect(result.eql(.unknown));
}

test "getHealth returns unknown when confirmed slot is unknown" {
    var commitments = CommitmentTracker.init(std.testing.allocator, 0);
    defer commitments.deinit(std.testing.allocator);
    commitments.processed.store(10, .monotonic);
    const result = try getHealth(.{ .commitments = &commitments }, std.testing.allocator, .{});
    try std.testing.expect(result.eql(.unknown));
}

test "getHealth returns ok when processed slot is within delinquent distance" {
    var commitments = CommitmentTracker.init(std.testing.allocator, 0);
    defer commitments.deinit(std.testing.allocator);
    commitments.processed.store(72, .monotonic);
    commitments.confirmed.store(200, .monotonic);
    const result = try getHealth(.{ .commitments = &commitments }, std.testing.allocator, .{});
    try std.testing.expect(result.eql(.ok));
}

test "getHealth returns behind when processed slot is outside delinquent distance" {
    var commitments = CommitmentTracker.init(std.testing.allocator, 0);
    defer commitments.deinit(std.testing.allocator);
    commitments.processed.store(71, .monotonic);
    commitments.confirmed.store(200, .monotonic);
    const result = try getHealth(.{ .commitments = &commitments }, std.testing.allocator, .{});
    try std.testing.expect(result.eql(.{ .behind = 129 }));
}
