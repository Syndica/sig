const std = @import("std");
const sig = @import("../sig.zig");
const shred_collector = @import("lib.zig");

const layout = sig.ledger.shred.layout;

const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Atomic = std.atomic.Value;

const BasicShredTracker = shred_collector.shred_tracker.BasicShredTracker;
const Channel = sig.sync.Channel;
const Logger = sig.trace.Logger;
const Packet = sig.net.Packet;
const Shred = sig.ledger.shred.Shred;
const ShredInserter = sig.ledger.ShredInserter;

// TODO: add metrics (e.g. total count of shreds processed)

/// Analogous to [WindowService](https://github.com/anza-xyz/agave/blob/aa2f078836434965e1a5a03af7f95c6640fe6e1e/core/src/window_service.rs#L395)
pub fn runShredProcessor(
    allocator: Allocator,
    exit: *Atomic(bool),
    logger: Logger,
    // shred verifier --> me
    verified_shred_receiver: *Channel(Packet),
    tracker: *BasicShredTracker,
    shred_inserter_: ShredInserter,
    leader_schedule: sig.core.leader_schedule.SlotLeaderProvider,
) !void {
    var shred_inserter = shred_inserter_;
    var shreds: ArrayListUnmanaged(Shred) = .{};
    var is_repaired: ArrayListUnmanaged(bool) = .{};
    var error_context: ErrorContext = .{};

    while (!exit.load(.acquire) or
        verified_shred_receiver.len() != 0)
    {
        shreds.clearRetainingCapacity();
        is_repaired.clearRetainingCapacity();
        while (verified_shred_receiver.receive()) |packet| {
            processShred(
                allocator,
                tracker,
                &packet,
                &shreds,
                &is_repaired,
                &error_context,
            ) catch |e| {
                logger.err().logf(
                    "failed to process verified shred {?}.{?}: {}",
                    .{ error_context.slot, error_context.index, e },
                );
                error_context = .{};
            };
        }
        _ = try shred_inserter.insertShreds(
            shreds.items,
            is_repaired.items,
            leader_schedule,
            false,
            null,
        );
    }
}

const ErrorContext = struct { slot: ?u64 = null, index: ?u32 = null };

fn processShred(
    allocator: Allocator,
    tracker: *BasicShredTracker,
    packet: *const Packet,
    shreds: *ArrayListUnmanaged(Shred),
    is_repaired: *ArrayListUnmanaged(bool),
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

    var shred = try shreds.addOne(allocator);
    errdefer _ = shreds.pop();
    try is_repaired.append(allocator, packet.flags.isSet(.repair));
    errdefer _ = is_repaired.pop();

    shred.* = try Shred.fromPayload(allocator, shred_payload);

    if (shred.* == .data) {
        const parent = try shred.data.parent();
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
