const std = @import("std");
const tel = @import("../telemetry.zig");

/// Formatter defined such that:
/// * An integer is rendered in base 10 as-is.
/// * A float is rendered in base 10 after a round-trip conversion to `Int` and back.
///   - Rendered without a decimal point (i.e. as an integer) if the round-trip retains
///     equality with the original value.
///   - Rendered as a 6-digit decimal precision float if the round-trip loses equality.
pub fn numberFmt(value: anytype) NumberFmt(@TypeOf(value)) {
    return .init(value);
}

/// See `numberFmt`.
pub fn NumberFmt(comptime T: type) type {
    return struct {
        value: T,
        const PrometheusNumberFmtSelf = @This();

        pub fn init(value: T) PrometheusNumberFmtSelf {
            return .{ .value = value };
        }

        pub fn format(
            self: PrometheusNumberFmtSelf,
            w: *std.Io.Writer,
        ) std.Io.Writer.Error!void {
            switch (@typeInfo(T)) {
                .int => try w.printInt(self.value, 10, .lower, .{}),
                .float => try w.printFloat(self.value, .{
                    .mode = .decimal,
                    .precision = 6,
                }),
                inline else => |_, tag| @compileError(
                    "expected int or float, got " ++ @tagName(tag),
                ),
            }
        }
    };
}

pub fn writeBody(
    w: *std.Io.Writer,
    metrics: *const tel.metric.Map,
) std.Io.Writer.Error!void {
    for (metrics.keys(), metrics.values()) |metric_id, metric_ptrs| {
        std.debug.assert((metric_id.label_count == 0) == (metric_id.labels.len == 0));

        switch (metric_ptrs) {
            inline .gauge_int, .gauge_float => |gauge| try w.print(
                "{f} {f}\n",
                .{ metric_id.fmtText(), numberFmt(gauge.load(.monotonic)) },
            ),
            .histogram => |*histogram| {
                try writeHistogramBody(histogram, metric_id, w);
            },
        }

        const buffered = w.buffered();
        std.debug.assert(buffered[buffered.len - 1] == '\n');
    }
}

/// This does mutate pointers to write a snapshot of the histogram atomically.
/// Writes a snapshot of the histogram as entries for the HTTP response to the prometheus client.
/// If `histogram.upper_bounds.len == 0`, does nothing.
pub fn writeHistogramBody(
    histogram: *const tel.Histogram,
    metric_id: tel.metric.Id,
    w: *std.Io.Writer,
) std.Io.Writer.Error!void {
    if (histogram.upper_bounds.len == 0) return;

    var snapshot_reader = histogram.swapOutSnapshot();
    defer snapshot_reader.release();

    while (snapshot_reader.nextBucket()) |bucket| { // write the buckets
        try w.print("{s}_bucket", .{metric_id.name});

        try w.writeByte('{');
        if (metric_id.label_count != 0) {
            try w.writeAll(metric_id.labels);
            try w.writeByte(',');
        }
        try w.print("le={f}", .{numberFmt(bucket.upper_bound)});
        try w.writeByte('}');

        try w.writeByte(' ');

        try w.print("{d}\n", .{bucket.cumulative_count});
    }

    // write the sum
    try w.print("{s}_sum", .{metric_id.name});
    if (metric_id.label_count != 0) {
        try w.writeByte('{');
        try w.writeAll(metric_id.labels);
        try w.writeByte('}');
    }
    try w.writeByte(' ');
    try w.print("{f}\n", .{numberFmt(snapshot_reader.sum)});

    // write the count
    try w.print("{s}_count", .{metric_id.name});
    if (metric_id.label_count != 0) {
        try w.writeByte('{');
        try w.writeAll(metric_id.labels);
        try w.writeByte('}');
    }
    try w.writeByte(' ');
    try w.print("{d}\n", .{snapshot_reader.count});
}
