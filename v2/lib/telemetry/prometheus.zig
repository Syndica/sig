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

    try writeHistogramSnapshot(&snapshot_reader, metric_id, w, "", numberFmt);
}

/// Writes a snapshot of a `LatencyHistogram` as prometheus histogram entries. Like
/// `writeHistogramBody`, this mutates shard pointers to swap out a consistent snapshot.
///
/// The bounds and `_sum` are raw nanoseconds, which is NOT prometheus' duration convention
/// (durations are conventionally exposed in fractional seconds). To keep consumers from
/// mistaking these for seconds, the emitted metric names carry an explicit `_ns` suffix
/// (`{name}_ns_bucket` / `{name}_ns_sum` / `{name}_ns_count`) and the values are rendered
/// as-is via `numberFmt`. If we later convert to fractional seconds, drop the suffix and swap
/// in a seconds-aware formatter.
pub fn writeLatencyHistogramBody(
    histogram: *const tel.LatencyHistogram,
    metric_id: tel.metric.Id,
    w: *std.Io.Writer,
) std.Io.Writer.Error!void {
    var snapshot_reader = histogram.swapOutSnapshot();
    defer snapshot_reader.release();

    try writeHistogramSnapshot(&snapshot_reader, metric_id, w, "_ns", numberFmt);
}

/// Shared body of `writeHistogramBody` and `writeLatencyHistogramBody`: drains an already-swapped
/// `snapshot_reader` and renders it as prometheus `_bucket` / `_sum` / `_count` lines.
/// `snapshot_reader` is a mutable pointer to either histogram kind's `SnapshotReader` — both
/// expose `nextBucket()`, `count`, and `sum`. `name_suffix` is appended to `metric_id.name` for
/// every emitted metric name (`""` for `Histogram`, `"_ns"` for `LatencyHistogram` to flag its
/// nanosecond unit). `fmtValue` is applied wherever the two histogram kinds carry a physical unit
/// — the bucket `le` bounds and `_sum` — while the dimensionless integer counts (`cumulative_count`,
/// `_count`) always render as `{d}`. `Histogram` passes `numberFmt` (float/int as-is);
/// `LatencyHistogram` also passes `numberFmt`, emitting raw nanoseconds.
fn writeHistogramSnapshot(
    snapshot_reader: anytype,
    metric_id: tel.metric.Id,
    w: *std.Io.Writer,
    comptime name_suffix: []const u8,
    comptime fmtValue: anytype,
) std.Io.Writer.Error!void {
    while (snapshot_reader.nextBucket()) |bucket| { // write the buckets
        try w.print("{s}" ++ name_suffix ++ "_bucket", .{metric_id.name});

        try w.writeByte('{');
        if (metric_id.label_count != 0) {
            try w.writeAll(metric_id.labels);
            try w.writeByte(',');
        }
        try w.print("le=\"{f}\"", .{fmtValue(bucket.upper_bound)});
        try w.writeByte('}');

        try w.writeByte(' ');

        // Cumulative: each bucket reports observations `<= le`, including the buckets below it.
        try w.print("{d}\n", .{bucket.cumulative_count});
    }

    try writeInfBucket(metric_id, name_suffix, snapshot_reader.count, w);

    // write the sum
    try w.print("{s}" ++ name_suffix ++ "_sum", .{metric_id.name});
    if (metric_id.label_count != 0) {
        try w.writeByte('{');
        try w.writeAll(metric_id.labels);
        try w.writeByte('}');
    }
    try w.writeByte(' ');
    try w.print("{f}\n", .{fmtValue(snapshot_reader.sum)});

    // write the count
    try w.print("{s}" ++ name_suffix ++ "_count", .{metric_id.name});
    if (metric_id.label_count != 0) {
        try w.writeByte('{');
        try w.writeAll(metric_id.labels);
        try w.writeByte('}');
    }
    try w.writeByte(' ');
    try w.print("{d}\n", .{snapshot_reader.count});
}

/// Writes the mandatory `{name}{name_suffix}_bucket{...,le="+Inf"} <count>` line shared by both
/// histogram renderers. `count` is the cumulative total (equal to `_count`).
fn writeInfBucket(
    metric_id: tel.metric.Id,
    comptime name_suffix: []const u8,
    count: u64,
    w: *std.Io.Writer,
) std.Io.Writer.Error!void {
    try w.print("{s}" ++ name_suffix ++ "_bucket", .{metric_id.name});
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

    // linear: inclusive-upper le-bounds 10, 20, 30, 40, 50; then implicit `+Inf`.
    const histogram: tel.LatencyHistogram = try .initForTest(gpa, Layout{ .linear = .{
        .base_ns = 0,
        .step_ns = 10,
        .octaves = 5,
    } });
    defer histogram.deinitForTest(gpa);

    histogram.observe(5); // bucket 0
    histogram.observe(15); // bucket 1
    histogram.observe(15); // bucket 1
    histogram.observe(25); // bucket 2
    histogram.observe(999); // +Inf

    var output: std.Io.Writer.Allocating = .init(gpa);
    defer output.deinit();

    try writeLatencyHistogramBody(&histogram, .initNameOnly("test_latency"), &output.writer);

    // Bounds and `_sum` are raw nanoseconds; names carry the `_ns` suffix flagging the unit.
    try std.testing.expectEqualStrings(
        \\test_latency_ns_bucket{le="10"} 1
        \\test_latency_ns_bucket{le="20"} 3
        \\test_latency_ns_bucket{le="30"} 4
        \\test_latency_ns_bucket{le="40"} 4
        \\test_latency_ns_bucket{le="50"} 4
        \\test_latency_ns_bucket{le="+Inf"} 5
        \\test_latency_ns_sum 1059
        \\test_latency_ns_count 5
        \\
    , output.written());
}
