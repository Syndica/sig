const std = @import("std");
const sig = @import("../sig.zig");
const shred_collector = @import("lib.zig");

const layout = sig.ledger.shred.layout;

const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Atomic = std.atomic.Value;

const BasicShredTracker = shred_collector.shred_tracker.BasicShredTracker;
const Channel = sig.sync.Channel;
const Counter = sig.prometheus.Counter;
const Histogram = sig.prometheus.Histogram;
const Logger = sig.trace.Logger;
const Packet = sig.net.Packet;
const Registry = sig.prometheus.Registry;
const Shred = sig.ledger.shred.Shred;
const ShredInserter = sig.ledger.ShredInserter;
const SlotOutOfBounds = shred_collector.shred_tracker.SlotOutOfBounds;
const VariantCounter = sig.prometheus.VariantCounter;

/// Analogous to [WindowService](https://github.com/anza-xyz/agave/blob/aa2f078836434965e1a5a03af7f95c6640fe6e1e/core/src/window_service.rs#L395)
pub fn runShredProcessor(
    allocator: Allocator,
    exit: *Atomic(bool),
    logger: Logger,
    registry: *Registry(.{}),
    // shred verifier --> me
    verified_shred_receiver: *Channel(Packet),
    tracker: *BasicShredTracker,
    shred_inserter_: ShredInserter,
    leader_schedule: sig.core.leader_schedule.SlotLeaderProvider,
) !void {
    // var shred_inserter = shred_inserter_;
    var shreds: ArrayListUnmanaged(Shred) = .{};
    var is_repaired: ArrayListUnmanaged(bool) = .{};
    var error_context: ErrorContext = .{};
    const metrics = try registry.initStruct(Metrics);

    while (!exit.load(.acquire) or
        verified_shred_receiver.len() != 0)
    {
        std.time.sleep(1_000_00_0);
        shreds.clearRetainingCapacity();
        is_repaired.clearRetainingCapacity();
        while (verified_shred_receiver.receive()) |packet| {
            processShred(
                allocator,
                tracker,
                metrics,
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
        metrics.insertion_batch_size.observe(shreds.items.len);
        metrics.passed_to_inserter_count.add(shreds.items.len);
        _ = shred_inserter_;
        _ = leader_schedule;
        // _ = try shred_inserter.insertShreds(
        //     shreds.items,
        //     is_repaired.items,
        //     leader_schedule,
        //     false,
        //     null,
        // );
    }
}

const ErrorContext = struct { slot: ?u64 = null, index: ?u32 = null };

fn processShred(
    allocator: Allocator,
    tracker: *BasicShredTracker,
    metrics: Metrics,
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
        error.SlotUnderflow, error.SlotOverflow => {
            metrics.register_shred_error.observe(err);
            return;
        },
    };

    var shred = try shreds.addOne(allocator);
    errdefer _ = shreds.pop();
    try is_repaired.append(allocator, packet.flags.isSet(.repair));
    errdefer _ = is_repaired.pop();

    shred.* = try Shred.fromPayload(allocator, shred_payload);

    if (shred.* == .data) {
        const parent = try shred.data.parent();
        if (parent + 1 != slot) {
            metrics.skipped_slot_count.add(slot - parent);
            tracker.skipSlots(parent, slot) catch |err| switch (err) {
                error.SlotUnderflow, error.SlotOverflow => {
                    metrics.skip_slots_error.observe(err);
                },
            };
        }
    }
    if (shred.isLastInSlot()) {
        tracker.setLastShred(slot, index) catch |err| switch (err) {
            error.SlotUnderflow, error.SlotOverflow => {
                metrics.set_last_shred_error.observe(err);
                return;
            },
        };
    }
}

const Metrics = struct {
    passed_to_inserter_count: *Counter,
    skipped_slot_count: *Counter,
    insertion_batch_size: *Histogram,
    register_shred_error: *VariantCounter(SlotOutOfBounds),
    skip_slots_error: *VariantCounter(SlotOutOfBounds),
    set_last_shred_error: *VariantCounter(SlotOutOfBounds),

    pub const prefix = "shred_processor";
    pub const histogram_buckets = sig.prometheus.histogram.exponentialBuckets(2, -1, 8);
};
