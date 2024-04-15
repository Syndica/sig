const std = @import("std");
const sig = @import("../lib.zig");

const layout = sig.tvu.shred_layout;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const BasicShredTracker = sig.tvu.BasicShredTracker;
const Channel = sig.sync.Channel;
const Logger = sig.trace.Logger;
const Packet = sig.net.Packet;
const Shred = sig.tvu.Shred;

/// analogous to `WindowService`
pub fn processShreds(
    allocator: Allocator,
    logger: Logger,
    verified_shreds: *Channel(ArrayList(Packet)),
    tracker: *BasicShredTracker,
) !void {
    _ = logger;
    // TODO unreachables
    while (verified_shreds.receive()) |packet_batch| {
        for (packet_batch.items) |*packet| if (!packet.isSet(.discard)) {
            const shred_payload = layout.getShred(packet) orelse unreachable;
            const slot = layout.getSlot(shred_payload) orelse unreachable;
            const index = layout.getIndex(shred_payload) orelse unreachable;
            tracker.registerShred(slot, index) catch |e| {
                if (e != error.SlotUnderflow) return e;
                continue;
            };
            const shred = try Shred.fromPayload(allocator, shred_payload);
            if (shred.isLastInSlot()) {
                try tracker.setLastShred(slot, index);
            }
        };
    }
}
