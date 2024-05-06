const std = @import("std");
const sig = @import("../lib.zig");

const layout = sig.shred_collector.shred_layout;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const BasicShredTracker = sig.shred_collector.BasicShredTracker;
const Channel = sig.sync.Channel;
const Packet = sig.net.Packet;
const Shred = sig.shred_collector.Shred;

/// analogous to `WindowService` TODO permalink
pub fn processShreds(
    allocator: Allocator,
    verified_shreds: *Channel(ArrayList(Packet)),
    tracker: *BasicShredTracker,
) !void {
    var processed_count: usize = 0;
    var buf = ArrayList(ArrayList(Packet)).init(allocator);
    while (true) {
        try verified_shreds.tryDrainRecycle(&buf);
        if (buf.items.len == 0) {
            std.time.sleep(10 * std.time.ns_per_ms);
            continue;
        }
        for (buf.items) |packet_batch| {
            for (packet_batch.items) |*packet| if (!packet.isSet(.discard)) {
                const shred_payload = layout.getShred(packet) orelse continue;
                const slot = layout.getSlot(shred_payload) orelse continue;
                const index = layout.getIndex(shred_payload) orelse continue;
                tracker.registerShred(slot, index) catch |err| switch (err) {
                    error.SlotUnderflow, error.SlotOverflow => continue,
                    else => return err,
                };
                var shred = try Shred.fromPayload(allocator, shred_payload);
                defer shred.deinit();
                if (shred.isLastInSlot()) {
                    tracker.setLastShred(slot, index) catch |err| switch (err) {
                        error.SlotUnderflow, error.SlotOverflow => continue,
                        else => return err,
                    };
                }
                processed_count += 1;
            };
        }
    }
}
