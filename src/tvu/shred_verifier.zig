const std = @import("std");
const sig = @import("../lib.zig");
const network = @import("zig-network");

const shred_layout = sig.tvu.shred_layout;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const Atomic = std.atomic.Atomic;

const Channel = sig.sync.Channel;
const Packet = sig.net.Packet;

pub fn runShredSigVerify(
    exit: *Atomic(bool),
    incoming: *Channel(ArrayList(Packet)),
    verified: *Channel(ArrayList(Packet)),
    leader_schedule: LeaderScheduleCalculator,
) void {
    // TODO: unreachable
    var verified_count: usize = 0;
    var buf: ArrayList(ArrayList(Packet)) = ArrayList(ArrayList(Packet)).init(incoming.allocator);
    while (true) {
        incoming.tryDrainRecycle(&buf) catch unreachable;
        if (buf.items.len == 0) {
            std.time.sleep(10 * std.time.ns_per_ms);
            continue;
        }
        for (buf.items) |packet_batch| {
            // TODO parallelize this once it's actually verifying signatures
            for (packet_batch.items) |*packet| {
                if (!verifyShred(packet, &leader_schedule)) {
                    packet.set(.discard);
                } else {
                    verified_count += 1;
                }
            }
            verified.send(packet_batch) catch unreachable; // TODO
            if (exit.load(.Monotonic)) return;
        }
    }
}

/// verify_shred_cpu
fn verifyShred(packet: *const Packet, leader_schedule: *const LeaderScheduleCalculator) bool {
    if (packet.isSet(.discard)) return false;
    const shred = shred_layout.getShred(packet) orelse return false;
    const slot = shred_layout.getSlot(shred) orelse return false;
    const signature = shred_layout.getSignature(shred) orelse return false;
    const signed_data = shred_layout.getSignedData(shred) orelse return false;

    // TODO: once implemented, this should no longer be optional
    if (leader_schedule.getLeader(slot)) |leader| {
        return signature.verify(leader, &signed_data.data);
    }

    return true;
}

// TODO
pub const LeaderScheduleCalculator = struct {
    fn getLeader(_: *const @This(), _: sig.core.Slot) ?sig.core.Pubkey {
        return null;
    }
};
