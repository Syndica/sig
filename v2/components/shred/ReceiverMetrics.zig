const std = @import("std");
const builtin = @import("builtin");

comptime {
    _ = std.testing.refAllDecls(@This());
}

const lib = @import("lib");
const tel = lib.telemetry;

const LatencyHistogram = tel.LatencyHistogram;
const Receiver = @import("receiver.zig").Receiver;

const ReceiverMetrics = @This();

reset_elapsed_ns: LatencyHistogram,
update_slot_range_elapsed_ns: LatencyHistogram,
process_packet_elapsed_ns: ProcessPacketElapsedHistogram,

/// One latency series per `processPacket` outcome: each `NonErrorStatus` variant plus each error,
/// flattened into `variant="<label>"` labels. `observe` takes the raw `ProcessPacketError!...`.
const ProcessPacketElapsedHistogram = tel.ResultLatencyHistogram(
    Receiver.ProcessPacketError!Receiver.NonErrorStatus,
    .{ .payload_prefix = .initComptime(.{
        .{ "fec_set_finished", "full_" },
        .{ "fec_set_already_finished", "early_" },
        .{ "shred_already_seen", "early_" },
        .{ "unfinished_fec_set", "early_" },
    }) },
);

/// Backs every series on the heap instead of in a metric region, so a test can build a `Receiver`
/// without standing up an `Appender`. The layout is irrelevant to what these tests assert; it only
/// has to be valid.
pub fn initForTest(gpa: std.mem.Allocator) std.mem.Allocator.Error!ReceiverMetrics {
    if (!builtin.is_test) @compileError("initForTest is only valid in test builds");
    const layout: LatencyHistogram.Layout = .{
        .min_upper_bound_ns = 512,
        .max_upper_bound_ns = 512 << 20,
        .bounds_per_doubling = 4,
    };
    const reset: LatencyHistogram = try .initForTest(gpa, layout);
    errdefer reset.deinitForTest(gpa);

    const update_slot_range: LatencyHistogram = try .initForTest(gpa, layout);
    errdefer update_slot_range.deinitForTest(gpa);

    return .{
        .reset_elapsed_ns = reset,
        .update_slot_range_elapsed_ns = update_slot_range,
        .process_packet_elapsed_ns = try .initForTest(gpa, layout),
    };
}

/// Only valid if `self` was initialized using `initForTest`.
pub fn deinitForTest(self: ReceiverMetrics, gpa: std.mem.Allocator) void {
    if (!builtin.is_test) @compileError("deinitForTest is only valid in test builds");
    self.reset_elapsed_ns.deinitForTest(gpa);
    self.update_slot_range_elapsed_ns.deinitForTest(gpa);
    self.process_packet_elapsed_ns.deinitForTest(gpa);
}

fn initNoopLatencyHistogram() LatencyHistogram {
    const layout: LatencyHistogram.Layout = .{
        .min_upper_bound_ns = 1,
        .max_upper_bound_ns = 2,
        .bounds_per_doubling = 1,
    };
    const storage = struct {
        var elements: [1 + 2 * (2 + 3)]u64 = @splat(0);
    };
    comptime std.debug.assert(storage.elements.len == layout.elementsFromBucketCount());
    return .fromRaw(layout, .{ .elements = &storage.elements });
}

pub fn initNoop() ReceiverMetrics {
    return .{
        .reset_elapsed_ns = initNoopLatencyHistogram(),
        .update_slot_range_elapsed_ns = initNoopLatencyHistogram(),
        .process_packet_elapsed_ns = .{
            .inner = .{ .histograms = @splat(initNoopLatencyHistogram()) },
        },
    };
}
