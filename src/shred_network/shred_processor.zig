const std = @import("std");
const sig = @import("../sig.zig");
const shred_network = @import("lib.zig");

const layout = sig.ledger.shred.layout;

const Allocator = std.mem.Allocator;
const ArrayListUnmanaged = std.ArrayListUnmanaged;
const Atomic = std.atomic.Value;

const BasicShredTracker = shred_network.shred_tracker.BasicShredTracker;
const Channel = sig.sync.Channel;
const Counter = sig.prometheus.Counter;
const Histogram = sig.prometheus.Histogram;
const Logger = sig.trace.Logger;
const Packet = sig.net.Packet;
const Registry = sig.prometheus.Registry;
const Shred = sig.ledger.shred.Shred;
const ShredInserter = sig.ledger.ShredInserter;
const SlotOutOfBounds = shred_network.shred_tracker.SlotOutOfBounds;
const VariantCounter = sig.prometheus.VariantCounter;

// The identifier for the scoped logger used in this file.
const LOG_SCOPE = "shred_processor";

/// Analogous to [WindowService](https://github.com/anza-xyz/agave/blob/aa2f078836434965e1a5a03af7f95c6640fe6e1e/core/src/window_service.rs#L395)
pub fn runShredProcessor(
    allocator: Allocator,
    exit: *Atomic(bool),
    logger_: Logger,
    registry: *Registry(.{}),
    // shred verifier --> me
    verified_shred_receiver: *Channel(Packet),
    tracker: *BasicShredTracker,
    shred_inserter_: ShredInserter,
    leader_schedule: sig.core.leader_schedule.SlotLeaders,
) !void {
    const logger = logger_.withScope(LOG_SCOPE);
    var shred_inserter = shred_inserter_;
    var shreds: ArrayListUnmanaged(Shred) = .{};
    var is_repaired: ArrayListUnmanaged(bool) = .{};
    const metrics = try registry.initStruct(Metrics);

    while (!exit.load(.acquire) or
        verified_shred_receiver.len() != 0)
    {
        shreds.clearRetainingCapacity();
        is_repaired.clearRetainingCapacity();
        while (verified_shred_receiver.tryReceive()) |packet| {
            const shred_payload = layout.getShred(&packet) orelse return error.InvalidVerifiedShred;
            const shred = try shreds.addOne(allocator);
            errdefer _ = shreds.pop();
            shred.* = Shred.fromPayload(allocator, shred_payload) catch |e| {
                logger.err().logf(
                    "failed to process verified shred {?}.{?}: {}",
                    .{ layout.getSlot(shred_payload), layout.getIndex(shred_payload), e },
                );
                continue;
            };

            try is_repaired.append(allocator, packet.flags.isSet(.repair));
        }
        metrics.insertion_batch_size.observe(shreds.items.len);
        metrics.passed_to_inserter_count.add(shreds.items.len);
        _ = try shred_inserter.insertShreds(
            shreds.items,
            is_repaired.items,
            .{
                .slot_leaders = leader_schedule,
                .shred_tracker = tracker,
            },
        );
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
