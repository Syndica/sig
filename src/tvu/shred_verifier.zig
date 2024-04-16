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
) void {
    while (incoming.receive()) |packet_batch| {
        // TODO parallelize this once it's actually verifying signatures
        for (packet_batch.items) |*packet| {
            if (!verifyShred(packet, {})) {
                packet.set(.discard);
            }
        }
        verified.send(packet_batch) catch unreachable; // TODO
        if (exit.load(.Monotonic)) return;
    }
}

/// verify_shred_cpu
/// TODO slot leaders
fn verifyShred(packet: *const Packet, slot_leaders: void) bool {
    if (packet.isSet(.discard)) return false;
    const shred = shred_layout.getShred(packet) orelse return false;
    const slot = shred_layout.getSlot(shred) orelse return false;
    const signature = shred_layout.getSignature(shred) orelse return false;
    const signed_data = shred_layout.getSignedData(shred) orelse return false;

    // TODO get slot leader pubkey and actually verify signature
    _ = slot_leaders;
    _ = slot;
    if (false) return signature.verify(unreachable, signed_data.data);

    return true;
}

// pub const EpochLeaderSchedule = struct {
//     data: []const sig.core.Pubkey,
//     first_slot: sig.core.Slot,

//     fn getLeader(self: *@This(), slot: sig.core.Slot) sig.core.Pubkey {
//         const index = @as(usize, @intCast(slot)) - @as(usize, @intCast(self.first_slot));
//         return self.data[index];
//     }
// };
