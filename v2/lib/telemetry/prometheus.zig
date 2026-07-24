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
            .latency_histogram => |*latency_histogram| {
                try writeLatencyHistogramBody(latency_histogram, metric_id, w);
            },
        }

        const buffered = w.buffered();
        std.debug.assert(buffered[buffered.len - 1] == '\n');
    }
}

/// Emits a prometheus histogram for a float-bounds `Histogram`. Bounds and `_sum` are rendered
/// as-is (no unit conversion, no name suffix). No-op when `upper_bounds` is empty. Mutates shard
/// pointers to swap out a consistent snapshot. See `writeHistogramSnapshot`.
pub fn writeHistogramBody(
    histogram: *const tel.Histogram,
    metric_id: tel.metric.Id,
    w: *std.Io.Writer,
) std.Io.Writer.Error!void {
    if (histogram.upper_bounds.len == 0) return;

    var snapshot_reader = histogram.swapOutSnapshot();
    defer snapshot_reader.release();

    try writeHistogramSnapshot(&snapshot_reader, metric_id, w);
}

/// Writes a snapshot of a `LatencyHistogram` as prometheus histogram entries. Like
/// `writeHistogramBody`, this mutates shard pointers to swap out a consistent snapshot.
///
/// The bounds and `_sum` are raw nanoseconds, which is NOT prometheus' duration convention
/// (durations are conventionally exposed in fractional seconds). To keep consumers from
/// mistaking these for seconds, every `LatencyHistogram` name already ends in `_ns` (enforced
/// at comptime by `metric.Appender.appendLatencyHistogram`), so the emitted names come out as
/// `{name}_bucket` / `{name}_sum` / `{name}_count` with the unit already in `{name}`, and the
/// values are rendered as-is via `numberFmt`. If we later convert to fractional seconds, drop
/// the naming rule and swap in a seconds-aware formatter.
pub fn writeLatencyHistogramBody(
    histogram: *const tel.LatencyHistogram,
    metric_id: tel.metric.Id,
    w: *std.Io.Writer,
) std.Io.Writer.Error!void {
    var snapshot_reader = histogram.swapOutSnapshot();
    defer snapshot_reader.release();

    try writeHistogramSnapshot(&snapshot_reader, metric_id, w);
}

/// Shared body of `writeHistogramBody` and `writeLatencyHistogramBody`: drains an already-swapped
/// `snapshot_reader` and renders it as prometheus `_bucket` / `_sum` / `_count` lines.
/// `snapshot_reader` is a mutable pointer to either histogram kind's `SnapshotReader` — both
/// expose `nextBucket()`, `count`, and `sum`. `metric_id.name` is emitted verbatim — a
/// `LatencyHistogram` carries its `_ns` unit suffix in the name itself. The unit-carrying values —
/// the bucket `le` bounds and `_sum` — render via `numberFmt`, which handles both kinds as-is
/// (`Histogram`'s floats, `LatencyHistogram`'s raw-nanosecond integers); the dimensionless integer
/// counts (`cumulative_count`, `_count`) always render as `{d}`.
fn writeHistogramSnapshot(
    snapshot_reader: anytype,
    metric_id: tel.metric.Id,
    w: *std.Io.Writer,
) std.Io.Writer.Error!void {
    while (snapshot_reader.nextBucket()) |bucket| { // write the buckets
        try w.print("{s}_bucket", .{metric_id.name});

        try w.writeByte('{');
        if (metric_id.label_count != 0) {
            try w.writeAll(metric_id.labels);
            try w.writeByte(',');
        }
        try w.print("le=\"{f}\"", .{numberFmt(bucket.upper_bound)});
        try w.writeByte('}');

        try w.writeByte(' ');

        // Cumulative: each bucket reports observations `<= le`, including the buckets below it.
        try w.print("{d}\n", .{bucket.cumulative_count});
    }

    try writeInfBucket(metric_id, snapshot_reader.count, w);

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

/// Writes the mandatory `{name}_bucket{...,le="+Inf"} <count>` line shared by both histogram
/// renderers. `count` is the cumulative total (equal to `_count`).
fn writeInfBucket(
    metric_id: tel.metric.Id,
    count: u64,
    w: *std.Io.Writer,
) std.Io.Writer.Error!void {
    try w.print("{s}_bucket", .{metric_id.name});
    try w.writeByte('{');
    if (metric_id.label_count != 0) {
        try w.writeAll(metric_id.labels);
        try w.writeByte(',');
    }
    try w.writeAll("le=\"+Inf\"");
    try w.writeByte('}');
    try w.writeByte(' ');
    try w.print("{d}\n", .{count});
}

test "prometheus: histogram labels are valid" {
    const gpa = std.testing.allocator;
    const histogram = try tel.Histogram.initForTest(gpa, &.{ 1.0, 2.5 });
    defer histogram.deinitForTest(gpa);

    histogram.observe(0.5);
    histogram.observe(2.0);
    histogram.observe(3.0);

    var output: std.Io.Writer.Allocating = .init(gpa);
    defer output.deinit();

    try writeHistogramBody(&histogram, .initNameOnly("test_histogram"), &output.writer);

    try std.testing.expectEqualStrings(
        \\test_histogram_bucket{le="1.000000"} 1
        \\test_histogram_bucket{le="2.500000"} 2
        \\test_histogram_bucket{le="+Inf"} 3
        \\test_histogram_sum 5.500000
        \\test_histogram_count 3
        \\
    , output.written());
}

test "prometheus: latency histogram emits ns-suffixed raw nanoseconds" {
    const gpa = std.testing.allocator;
    const Layout = tel.LatencyHistogram.Layout;

    // schema 2, window at 512ns: rounded geometric le-bounds 512, 609, 724, 861, 1024, ...; +Inf.
    const histogram: tel.LatencyHistogram = try .initForTest(gpa, Layout{
        .schema = 2,
        .min_ns = 512,
        .octaves = 2,
    });
    defer histogram.deinitForTest(gpa);

    histogram.observe(512); // bucket 0
    histogram.observe(513); // bucket 1
    histogram.observe(700); // bucket 2
    histogram.observe(1024); // bucket 4
    histogram.observe(2000); // +Inf

    var output: std.Io.Writer.Allocating = .init(gpa);
    defer output.deinit();

    try writeLatencyHistogramBody(&histogram, .initNameOnly("test_latency_ns"), &output.writer);

    // Bounds and `_sum` are raw nanoseconds; the `_ns` suffix flagging the unit comes from the
    // metric name itself, which the renderer emits verbatim.
    try std.testing.expectEqualStrings(
        \\test_latency_ns_bucket{le="512"} 1
        \\test_latency_ns_bucket{le="609"} 2
        \\test_latency_ns_bucket{le="724"} 3
        \\test_latency_ns_bucket{le="861"} 3
        \\test_latency_ns_bucket{le="1024"} 4
        \\test_latency_ns_bucket{le="1218"} 4
        \\test_latency_ns_bucket{le="1448"} 4
        \\test_latency_ns_bucket{le="1722"} 4
        \\test_latency_ns_bucket{le="+Inf"} 5
        \\test_latency_ns_sum 4749
        \\test_latency_ns_count 5
        \\
    , output.written());
}
