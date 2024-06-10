const std = @import("std");
const sig = @import("../lib.zig");
const shred_collector = @import("lib.zig");

const layout = shred_collector.shred.layout;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

const BasicShredTracker = shred_collector.shred_tracker.BasicShredTracker;
const Channel = sig.sync.Channel;
const Logger = sig.trace.Logger;
const Packet = sig.net.Packet;
const Shred = shred_collector.shred.Shred;

/// Analogous to [WindowService](https://github.com/anza-xyz/agave/blob/aa2f078836434965e1a5a03af7f95c6640fe6e1e/core/src/window_service.rs#L395)
pub fn runShredProcessor(
    allocator: Allocator,
    logger: Logger,
    // shred verifier --> me
    verified_shred_receiver: *Channel(ArrayList(Packet)),
    tracker: *BasicShredTracker,
) !void {
    var buf = ArrayList(ArrayList(Packet)).init(allocator);
    var error_context = ErrorContext{};
    while (true) {
        try verified_shred_receiver.tryDrainRecycle(&buf);
        if (buf.items.len == 0) {
            std.time.sleep(10 * std.time.ns_per_ms);
            continue;
        }
        for (buf.items) |packet_batch| {
            for (packet_batch.items) |*packet| if (!packet.flags.isSet(.discard)) {
                processShred(allocator, tracker, packet, &error_context) catch |e| {
                    logger.errf(
                        "failed to process verified shred {?}.{?}: {}",
                        .{ error_context.slot, error_context.index, e },
                    );
                    error_context = .{};
                };
            };
        }
    }
}

const ErrorContext = struct { slot: ?u64 = null, index: ?u32 = null };

fn processShred(
    allocator: Allocator,
    tracker: *BasicShredTracker,
    packet: *const Packet,
    error_context: *ErrorContext,
) !void {
    const shred_payload = layout.getShred(packet) orelse return error.InvalidPayload;
    const slot = layout.getSlot(shred_payload) orelse return error.InvalidSlot;
    errdefer error_context.slot = slot;
    const index = layout.getIndex(shred_payload) orelse return error.InvalidIndex;
    errdefer error_context.index = index;

    tracker.registerShred(slot, index) catch |err| switch (err) {
        error.SlotUnderflow, error.SlotOverflow => return,
    };
    var shred = try Shred.fromPayload(allocator, shred_payload);
    defer shred.deinit();
    if (shred == Shred.Data) {
        const parent = try shred.Data.parent();
        if (parent + 1 != slot) {
            tracker.skipSlots(parent, slot) catch |err| switch (err) {
                error.SlotUnderflow, error.SlotOverflow => {},
            };
        }
    }
    if (shred.isLastInSlot()) {
        tracker.setLastShred(slot, index) catch |err| switch (err) {
            error.SlotUnderflow, error.SlotOverflow => return,
        };
    }
}
