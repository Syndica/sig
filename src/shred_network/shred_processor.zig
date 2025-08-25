const std = @import("std");
const sig = @import("../sig.zig");
const shred_network = @import("lib.zig");

const layout = sig.ledger.shred.layout;

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const BasicShredTracker = shred_network.shred_tracker.BasicShredTracker;
const Channel = sig.sync.Channel;
const Counter = sig.prometheus.Counter;
const Histogram = sig.prometheus.Histogram;
const Packet = sig.net.Packet;
const Registry = sig.prometheus.Registry;
const Shred = sig.ledger.shred.Shred;
const ShredInserter = sig.ledger.ShredInserter;
const SlotOutOfBounds = shred_network.shred_tracker.SlotOutOfBounds;
const VariantCounter = sig.prometheus.VariantCounter;

// The identifier for the scoped logger used in this file.
pub const Logger = sig.trace.Logger("shred_processor");

/// Analogous to [WindowService](https://github.com/anza-xyz/agave/blob/aa2f078836434965e1a5a03af7f95c6640fe6e1e/core/src/window_service.rs#L395)
pub fn runShredProcessor(
    allocator: Allocator,
    exit: *Atomic(bool),
    logger: Logger,
    registry: *Registry(.{}),
    // shred verifier --> me
    verified_shred_receiver: *Channel(Packet),
    tracker: *BasicShredTracker,
    shred_inserter: *ShredInserter,
    leader_schedule: sig.core.leader_schedule.SlotLeaders,
) !void {
    const metrics = try registry.initStruct(Metrics);

    var shreds_buffer: std.MultiArrayList(struct {
        shred: Shred,
        is_required: bool,
    }) = .empty;
    defer shreds_buffer.deinit(allocator);
    defer for (shreds_buffer.items(.shred)) |shred| shred.deinit();

    const MAX_SHREDS_PER_ITER = 1024;
    try shreds_buffer.ensureTotalCapacity(allocator, MAX_SHREDS_PER_ITER);

    while (true) {
        verified_shred_receiver.waitToReceive(.{ .unordered = exit }) catch break;

        for (shreds_buffer.items(.shred)) |shred| shred.deinit();
        shreds_buffer.clearRetainingCapacity();

        while (verified_shred_receiver.tryReceive()) |packet| {
            const shred_payload = layout.getShred(&packet) orelse return error.InvalidVerifiedShred;
            const shred = Shred.fromPayload(allocator, shred_payload) catch |e| {
                logger.err().logf(
                    "failed to process verified shred {?}.{?}: {}",
                    .{ layout.getSlot(shred_payload), layout.getIndex(shred_payload), e },
                );
                continue;
            };
            shreds_buffer.appendAssumeCapacity(.{
                .shred = shred,
                .is_required = packet.flags.isSet(.repair),
            });
            if (shreds_buffer.len == MAX_SHREDS_PER_ITER) break;
        }
        metrics.insertion_batch_size.observe(shreds_buffer.len);
        metrics.passed_to_inserter_count.add(shreds_buffer.len);
        const result = try shred_inserter.insertShreds(
            shreds_buffer.items(.shred),
            shreds_buffer.items(.is_required),
            .{
                .slot_leaders = leader_schedule,
                .shred_tracker = tracker,
            },
        );
        result.deinit();
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
