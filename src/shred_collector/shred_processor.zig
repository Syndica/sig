const std = @import("std");
const sig = @import("../lib.zig");
const shred_collector = @import("lib.zig")._private;

const layout = shred_collector.shred.layout;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const BasicShredTracker = shred_collector.shred_tracker.BasicShredTracker;
const Channel = sig.sync.Channel;
const Packet = sig.net.Packet;
const Shred = shred_collector.shred.Shred;

/// Analogous to [WindowService](https://github.com/anza-xyz/agave/blob/aa2f078836434965e1a5a03af7f95c6640fe6e1e/core/src/window_service.rs#L395)
pub fn runShredProcessor(
    allocator: Allocator,
    // shred verifier --> me
    verified_shred_channel: *Channel(ArrayList(Packet)),
    tracker: *BasicShredTracker,
) !void {
    var processed_count: usize = 0;
    var buf = ArrayList(ArrayList(Packet)).init(allocator);
    while (true) {
        try verified_shred_channel.tryDrainRecycle(&buf);
        if (buf.items.len == 0) {
            std.time.sleep(10 * std.time.ns_per_ms);
            continue;
        }
        for (buf.items) |packet_batch| {
            for (packet_batch.items) |*packet| if (!packet.flags.isSet(.discard)) {
                const shred_payload = layout.getShred(packet) orelse continue;
                const slot = layout.getSlot(shred_payload) orelse continue;
                const index = layout.getIndex(shred_payload) orelse continue;
                tracker.registerShred(slot, index) catch |err| switch (err) {
                    error.SlotUnderflow, error.SlotOverflow => continue,
                    else => return err,
                };
                var shred = try Shred.fromPayload(allocator, shred_payload);
                if (shred == Shred.Data) {
                    const parent = try shred.Data.parent();
                    if (parent + 1 != slot) {
                        try tracker.skipSlots(parent, slot);
                    }
                }
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
