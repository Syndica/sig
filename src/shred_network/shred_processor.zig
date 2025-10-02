const std = @import("std");
const tracy = @import("tracy");
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

pub const Params = struct {
    /// shred verifier --> me
    verified_shred_receiver: *Channel(Packet),
    tracker: *BasicShredTracker,
    inserter: *ShredInserter,
    leader_schedule: sig.core.leader_schedule.SlotLeaders,
};

/// Analogous to [WindowService](https://github.com/anza-xyz/agave/blob/aa2f078836434965e1a5a03af7f95c6640fe6e1e/core/src/window_service.rs#L395)
pub fn runShredProcessor(
    allocator: Allocator,
    logger: Logger,
    registry: *Registry(.{}),
    exit: *Atomic(bool),
    params: Params,
) !void {
    const metrics = try registry.initStruct(Metrics);

    var shreds_buffer: ShredsBuffer = .empty;
    defer shreds_buffer.deinit(allocator);
    defer for (shreds_buffer.items(.shred)) |shred| shred.deinit();
    try shreds_buffer.ensureTotalCapacity(allocator, MAX_SHREDS_PER_ITER);

    while (true) {
        params.verified_shred_receiver.waitToReceive(.{ .unordered = exit }) catch break;
        try runShredProcessorOnceOver(
            allocator,
            logger,
            &shreds_buffer,
            metrics,
            params,
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

const ShredsBuffer = std.MultiArrayList(struct {
    shred: Shred,
    is_required: bool,
});

const MAX_SHREDS_PER_ITER = 1024;

fn runShredProcessorOnceOver(
    allocator: Allocator,
    logger: Logger,
    shreds_buffer: *ShredsBuffer,
    metrics: Metrics,
    params: Params,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "runShredProcessorOnceOver" });
    defer zone.deinit();

    for (shreds_buffer.items(.shred)) |shred| shred.deinit();
    shreds_buffer.clearRetainingCapacity();
    std.debug.assert(shreds_buffer.capacity >= MAX_SHREDS_PER_ITER);

    while (params.verified_shred_receiver.tryReceive()) |packet| {
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
    const result = try params.inserter.insertShreds(
        shreds_buffer.items(.shred),
        shreds_buffer.items(.is_required),
        .{
            .slot_leaders = params.leader_schedule,
            .shred_tracker = params.tracker,
        },
    );
    result.deinit();
}

test runShredProcessorOnceOver {
    const allocator = std.testing.allocator;

    var ledger_db = try sig.ledger.tests.TestDB.init(@src());
    defer ledger_db.deinit();

    var registry: Registry(.{}) = .init(allocator);
    defer registry.deinit();

    const verified_shred_channel: *Channel(Packet) = try .create(allocator);
    defer verified_shred_channel.destroy();

    var shred_tracker: BasicShredTracker = try .init(allocator, 0, .noop, &registry);
    defer shred_tracker.deinit();

    var shred_inserter: ShredInserter = try .init(allocator, .noop, &registry, ledger_db);
    defer shred_inserter.deinit();

    const dummy_leader_schedule: sig.core.leader_schedule.SlotLeaders = .{
        .state = undefined,
        .getFn = struct {
            fn getSlotLeader(_: *anyopaque, _: sig.core.Slot) ?sig.core.Pubkey {
                return null;
            }
        }.getSlotLeader,
    };
    std.debug.assert(dummy_leader_schedule.get(0) == null);

    const params: Params = .{
        .verified_shred_receiver = verified_shred_channel,
        .tracker = &shred_tracker,
        .inserter = &shred_inserter,
        .leader_schedule = dummy_leader_schedule,
    };

    var shreds_buffer: ShredsBuffer = .empty;
    defer shreds_buffer.deinit(allocator);
    defer for (shreds_buffer.items(.shred)) |shred| shred.deinit();
    try shreds_buffer.ensureTotalCapacity(allocator, MAX_SHREDS_PER_ITER);

    const metrics = try registry.initStruct(Metrics);

    try std.testing.expectEqual(
        {},
        runShredProcessorOnceOver(allocator, .noop, &shreds_buffer, metrics, params),
    );

    try verified_shred_channel.send(.ANY_EMPTY);
    try std.testing.expectEqual(
        {},
        runShredProcessorOnceOver(allocator, .noop, &shreds_buffer, metrics, params),
    );

    for (0..MAX_SHREDS_PER_ITER * 3) |_| {
        try verified_shred_channel.send(.ANY_EMPTY);
    }
    try std.testing.expectEqual(
        {},
        runShredProcessorOnceOver(allocator, .noop, &shreds_buffer, metrics, params),
    );

    try std.testing.expectEqual(
        {},
        runShredProcessorOnceOver(allocator, .noop, &shreds_buffer, metrics, params),
    );
}
