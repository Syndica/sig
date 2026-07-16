//! Prometheus protobuf exposition (`io.prometheus.client`), the alternative to the text format in
//! `prometheus.zig`. It is what a Prometheus server negotiates when `scrape_native_histograms` is
//! enabled (`Accept: application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily;
//! encoding=delimited`), and is the only format that can carry native histograms.
//!
//! This is a hand-rolled encoder for the fixed set of messages we emit (no protobuf dependency):
//! * gauges/counters -> `UNTYPED` (matching the text format, which carries no `# TYPE`);
//! * the float-bounds `Histogram` and any non-`exponential` `LatencyHistogram` -> a classic
//!   protobuf `Histogram` (explicit `bucket` list);
//! * an `exponential` `LatencyHistogram` -> a standard exponential native histogram (`schema`,
//!   `positive_span`, delta-encoded `positive_delta`).
//!
//! The body is a stream of length-delimited `MetricFamily` messages (`encoding=delimited`): each is
//! prefixed with its byte length as a varint. Metrics are grouped into families by `Id.name`, which
//! is sound because `metric.collect` sorts the map by name then labels, so equal-name entries are
//! adjacent (see `metric.zig`).

const std = @import("std");
const tel = @import("../telemetry.zig");

const Map = tel.metric.Map;
const Id = tel.metric.Id;
const Any = tel.metric.Any;

pub const Error = std.mem.Allocator.Error || std.Io.Writer.Error;

// Protobuf wire types.
const wire_varint: u3 = 0;
const wire_i64: u3 = 1;
const wire_len: u3 = 2;

// Field numbers from io/prometheus/client/metrics.proto.
const MetricFamily = struct {
    const name = 1;
    const kind = 3;
    const metric = 4;
};
const MetricType = struct {
    const untyped = 3;
    const histogram = 4;
};
const Metric = struct {
    const label = 1;
    const untyped = 5;
    const histogram = 7;
};
const LabelPair = struct {
    const name = 1;
    const value = 2;
};
const Untyped = struct {
    const value = 1;
};
const Histogram = struct {
    const sample_count = 1;
    const sample_sum = 2;
    const bucket = 3;
    const schema = 5;
    const zero_threshold = 6;
    const zero_count = 7;
    const positive_span = 12;
    const positive_delta = 13;
};
const Bucket = struct {
    const cumulative_count = 1;
    const upper_bound = 2;
};
const BucketSpan = struct {
    const offset = 1;
    const length = 2;
};

// ---- wire primitives ----

fn writeVarint(w: *std.Io.Writer, value: u64) std.Io.Writer.Error!void {
    var v = value;
    while (v >= 0x80) {
        try w.writeByte(@as(u8, @truncate(v)) | 0x80);
        v >>= 7;
    }
    try w.writeByte(@truncate(v));
}

fn writeTag(w: *std.Io.Writer, field: u32, wire: u3) std.Io.Writer.Error!void {
    try writeVarint(w, (@as(u64, field) << 3) | wire);
}

/// ZigZag encoding for `sint32`: maps small-magnitude signed values to small unsigned varints.
fn zigzag32(v: i32) u64 {
    const u: u32 = @bitCast(v);
    return (u *% 2) ^ @as(u32, @bitCast(v >> 31));
}

/// ZigZag encoding for `sint64`.
fn zigzag64(v: i64) u64 {
    const u: u64 = @bitCast(v);
    return (u *% 2) ^ @as(u64, @bitCast(v >> 63));
}

fn writeVarintField(w: *std.Io.Writer, field: u32, value: u64) std.Io.Writer.Error!void {
    try writeTag(w, field, wire_varint);
    try writeVarint(w, value);
}

fn writeSint32Field(w: *std.Io.Writer, field: u32, value: i32) std.Io.Writer.Error!void {
    try writeTag(w, field, wire_varint);
    try writeVarint(w, zigzag32(value));
}

fn writeSint64Field(w: *std.Io.Writer, field: u32, value: i64) std.Io.Writer.Error!void {
    try writeTag(w, field, wire_varint);
    try writeVarint(w, zigzag64(value));
}

fn writeDoubleField(w: *std.Io.Writer, field: u32, value: f64) std.Io.Writer.Error!void {
    try writeTag(w, field, wire_i64);
    try w.writeInt(u64, @bitCast(value), .little);
}

/// A length-delimited field: `string`, `bytes`, or an embedded message's already-encoded bytes.
fn writeBytesField(w: *std.Io.Writer, field: u32, bytes: []const u8) std.Io.Writer.Error!void {
    try writeTag(w, field, wire_len);
    try writeVarint(w, bytes.len);
    try w.writeAll(bytes);
}

fn toF64(v: anytype) f64 {
    return switch (@typeInfo(@TypeOf(v))) {
        .int, .comptime_int => @floatFromInt(v),
        .float, .comptime_float => v,
        else => @compileError("toF64: unsupported type " ++ @typeName(@TypeOf(v))),
    };
}

// ---- body ----

/// Writes the full protobuf exposition body: a stream of length-delimited `MetricFamily` messages.
pub fn writeBody(gpa: std.mem.Allocator, w: *std.Io.Writer, metrics: *const Map) Error!void {
    const ids = metrics.keys();
    const anys = metrics.values();

    var i: usize = 0;
    while (i < ids.len) {
        // Extend the family over the run of entries that share `Id.name` (adjacent after sorting).
        var j = i + 1;
        while (j < ids.len and std.mem.eql(u8, ids[j].name, ids[i].name)) j += 1;
        try writeFamily(gpa, w, ids[i..j], anys[i..j]);
        i = j;
    }
}

fn writeFamily(
    gpa: std.mem.Allocator,
    w: *std.Io.Writer,
    ids: []const Id,
    anys: []const Any,
) Error!void {
    var fam: std.Io.Writer.Allocating = .init(gpa);
    defer fam.deinit();
    const fw = &fam.writer;

    switch (anys[0]) {
        .gauge_int, .gauge_float => {
            try writeBytesField(fw, MetricFamily.name, ids[0].name);
            try writeVarintField(fw, MetricFamily.kind, MetricType.untyped);
            for (ids, anys) |id, any| try writeGaugeMetric(gpa, fw, id, any);
        },
        .histogram => |histogram| {
            try writeBytesField(fw, MetricFamily.name, ids[0].name);
            try writeVarintField(fw, MetricFamily.kind, MetricType.histogram);
            var snap = histogram.swapOutSnapshot();
            defer snap.release();
            try writeHistogramMetric(gpa, fw, ids[0], classicHistogramWriter(gpa, &snap));
        },
        .latency_histogram => |latency_histogram| {
            // Native histograms drop the classic `_bucket`/`_sum`/`_count` split into one series; we
            // keep the `_ns` suffix to flag the nanosecond unit (see `prometheus.zig`).
            const fam_name = try std.fmt.allocPrint(gpa, "{s}_ns", .{ids[0].name});
            defer gpa.free(fam_name);
            try writeBytesField(fw, MetricFamily.name, fam_name);
            try writeVarintField(fw, MetricFamily.kind, MetricType.histogram);
            try writeLatencyHistogramMetric(gpa, fw, ids[0], latency_histogram);
        },
    }

    const bytes = fam.written();
    try writeVarint(w, bytes.len);
    try w.writeAll(bytes);
}

fn writeGaugeMetric(
    gpa: std.mem.Allocator,
    fw: *std.Io.Writer,
    id: Id,
    any: Any,
) Error!void {
    const value: f64 = switch (any) {
        .gauge_int => |g| @floatFromInt(g.load(.monotonic)),
        .gauge_float => |g| g.load(.monotonic),
        else => return, // malformed: same name mixing gauges and histograms; skip.
    };

    var m: std.Io.Writer.Allocating = .init(gpa);
    defer m.deinit();
    try writeLabels(gpa, &m.writer, id);

    var untyped: std.Io.Writer.Allocating = .init(gpa);
    defer untyped.deinit();
    try writeDoubleField(&untyped.writer, Untyped.value, value);
    try writeBytesField(&m.writer, Metric.untyped, untyped.written());

    try writeBytesField(fw, MetricFamily.metric, m.written());
}

fn writeLatencyHistogramMetric(
    gpa: std.mem.Allocator,
    fw: *std.Io.Writer,
    id: Id,
    lh: tel.LatencyHistogram,
) Error!void {
    // A `LatencyHistogram`'s layout is always native-schema-aligned, so it always renders native.
    var snap = lh.swapOutSnapshot();
    defer snap.release();
    try writeHistogramMetric(gpa, fw, id, nativeHistogramWriter(gpa, &snap, lh.layout));
}

/// Wraps `id`'s labels and a `Histogram` submessage (produced by `hist_writer.write`) into a
/// `Metric`, then appends it to the enclosing `MetricFamily` writer `fw`.
fn writeHistogramMetric(
    gpa: std.mem.Allocator,
    fw: *std.Io.Writer,
    id: Id,
    hist_writer: anytype,
) Error!void {
    var m: std.Io.Writer.Allocating = .init(gpa);
    defer m.deinit();
    try writeLabels(gpa, &m.writer, id);

    var h: std.Io.Writer.Allocating = .init(gpa);
    defer h.deinit();
    try hist_writer.write(&h.writer);
    try writeBytesField(&m.writer, Metric.histogram, h.written());

    try writeBytesField(fw, MetricFamily.metric, m.written());
}

/// Emits each `LabelPair` of `id` as a `Metric.label` field. Assumes `id.labels` is the codebase's
/// simple `key="value"[,key="value"]...` form (values are enum tag names — no commas or escapes).
fn writeLabels(gpa: std.mem.Allocator, mw: *std.Io.Writer, id: Id) Error!void {
    if (id.label_count == 0) return;
    var it = std.mem.splitScalar(u8, id.labels, ',');
    while (it.next()) |segment| {
        const eq = std.mem.indexOfScalar(u8, segment, '=') orelse continue;
        const key = segment[0..eq];
        var value = segment[eq + 1 ..];
        if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') {
            value = value[1 .. value.len - 1];
        }

        var lp: std.Io.Writer.Allocating = .init(gpa);
        defer lp.deinit();
        try writeBytesField(&lp.writer, LabelPair.name, key);
        try writeBytesField(&lp.writer, LabelPair.value, value);
        try writeBytesField(mw, Metric.label, lp.written());
    }
}

// ---- histogram submessage writers ----
//
// Each exposes `write(*std.Io.Writer) Error!void`, filling in a `Histogram` submessage. They own a
// pointer to an already-swapped `SnapshotReader` and drain it (folding counts back into the hot
// shard) exactly once.

fn classicHistogramWriter(
    gpa: std.mem.Allocator,
    snap: anytype,
) ClassicHistogramWriter(@TypeOf(snap)) {
    return .{ .gpa = gpa, .snap = snap };
}

/// Renders a float `Histogram` snapshot as a classic protobuf `Histogram`: explicit finite `bucket`
/// list plus `sample_sum`/`sample_count`. There is no explicit `+Inf` bucket — Prometheus derives it
/// from `sample_count`. (`LatencyHistogram`s always render native; see `NativeHistogramWriter`.)
fn ClassicHistogramWriter(comptime SnapPtr: type) type {
    return struct {
        gpa: std.mem.Allocator,
        snap: SnapPtr,
        fn write(self: @This(), hw: *std.Io.Writer) Error!void {
            try writeVarintField(hw, Histogram.sample_count, self.snap.count);
            try writeDoubleField(hw, Histogram.sample_sum, toF64(self.snap.sum));
            while (self.snap.nextBucket()) |b| {
                var bucket: std.Io.Writer.Allocating = .init(self.gpa);
                defer bucket.deinit();
                try writeVarintField(&bucket.writer, Bucket.cumulative_count, b.cumulative_count);
                try writeDoubleField(&bucket.writer, Bucket.upper_bound, toF64(b.upper_bound));
                try writeBytesField(hw, Histogram.bucket, bucket.written());
            }
        }
    };
}

fn nativeHistogramWriter(
    gpa: std.mem.Allocator,
    snap: *tel.LatencyHistogram.SnapshotReader,
    layout: tel.LatencyHistogram.Layout,
) NativeHistogramWriter {
    return .{ .gpa = gpa, .snap = snap, .layout = layout };
}

/// Renders a `LatencyHistogram` snapshot as a standard exponential native histogram: `schema`, one
/// `positive_span`, and delta-encoded `positive_delta` (or a single no-op span when empty, so the
/// message is still recognized as native rather than an empty classic histogram).
const NativeHistogramWriter = struct {
    gpa: std.mem.Allocator,
    snap: *tel.LatencyHistogram.SnapshotReader,
    layout: tel.LatencyHistogram.Layout,

    fn write(self: NativeHistogramWriter, hw: *std.Io.Writer) Error!void {
        const bucket_count: usize = @intCast(self.layout.bucketCount());
        const counts = try self.gpa.alloc(u64, bucket_count);
        defer self.gpa.free(counts);

        const total_count = self.snap.count;
        const sum_ns = self.snap.sum;

        // The reader yields cumulative counts; recover each bucket's own population.
        var prev_cumulative: u64 = 0;
        var idx: usize = 0;
        while (self.snap.nextBucket()) |b| : (idx += 1) {
            counts[idx] = b.cumulative_count - prev_cumulative;
            prev_cumulative = b.cumulative_count;
        }

        try writeSint32Field(hw, Histogram.schema, @intCast(self.layout.schema));
        try writeDoubleField(hw, Histogram.zero_threshold, 0.0);
        try writeVarintField(hw, Histogram.zero_count, 0);
        try writeVarintField(hw, Histogram.sample_count, total_count);
        try writeDoubleField(hw, Histogram.sample_sum, @floatFromInt(sum_ns));

        // Populated range [first, last]; native buckets are sparse, so a single span with interior
        // zero-deltas is the simplest faithful encoding.
        var first: ?usize = null;
        var last: usize = 0;
        for (counts, 0..) |c, k| {
            if (c != 0) {
                if (first == null) first = k;
                last = k;
            }
        }

        var span: std.Io.Writer.Allocating = .init(self.gpa);
        defer span.deinit();
        if (first) |f| {
            const offset: i32 = @intCast(self.layout.baseIndex() + @as(i64, @intCast(f)));
            try writeSint32Field(&span.writer, BucketSpan.offset, offset);
            try writeVarintField(&span.writer, BucketSpan.length, last - f + 1);
            try writeBytesField(hw, Histogram.positive_span, span.written());

            var prev: i64 = 0;
            var k = f;
            while (k <= last) : (k += 1) {
                const cur: i64 = @intCast(counts[k]);
                try writeSint64Field(hw, Histogram.positive_delta, cur - prev);
                prev = cur;
            }
        } else {
            // Mandatory no-op span (offset=0, length=0) marking an empty native histogram.
            try writeSint32Field(&span.writer, BucketSpan.offset, 0);
            try writeVarintField(&span.writer, BucketSpan.length, 0);
            try writeBytesField(hw, Histogram.positive_span, span.written());
        }
    }
};

// ---- tests ----

const testing = std.testing;

test "prometheus_proto: varint encoding" {
    const cases = [_]struct { v: u64, want: []const u8 }{
        .{ .v = 0, .want = &.{0x00} },
        .{ .v = 1, .want = &.{0x01} },
        .{ .v = 127, .want = &.{0x7f} },
        .{ .v = 128, .want = &.{ 0x80, 0x01 } },
        .{ .v = 300, .want = &.{ 0xac, 0x02 } },
        .{ .v = 16384, .want = &.{ 0x80, 0x80, 0x01 } },
    };
    for (cases) |c| {
        var out: std.Io.Writer.Allocating = .init(testing.allocator);
        defer out.deinit();
        try writeVarint(&out.writer, c.v);
        try testing.expectEqualSlices(u8, c.want, out.written());
    }
}

test "prometheus_proto: zigzag encoding" {
    try testing.expectEqual(@as(u64, 0), zigzag32(0));
    try testing.expectEqual(@as(u64, 1), zigzag32(-1));
    try testing.expectEqual(@as(u64, 2), zigzag32(1));
    try testing.expectEqual(@as(u64, 3), zigzag32(-2));
    try testing.expectEqual(@as(u64, 0xFFFFFFFF), zigzag32(std.math.minInt(i32)));
    try testing.expectEqual(@as(u64, 0), zigzag64(0));
    try testing.expectEqual(@as(u64, 1), zigzag64(-1));
    try testing.expectEqual(@as(u64, 2), zigzag64(1));
}

/// Minimal single-pass protobuf reader used to validate the encoder without a protobuf dependency.
const TestReader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn varint(self: *TestReader) u64 {
        var result: u64 = 0;
        var shift: u6 = 0;
        while (true) {
            const byte = self.buf[self.pos];
            self.pos += 1;
            result |= @as(u64, byte & 0x7f) << shift;
            if (byte & 0x80 == 0) break;
            shift += 7;
        }
        return result;
    }

    fn tag(self: *TestReader) struct { field: u32, wire: u3 } {
        const t = self.varint();
        return .{ .field = @intCast(t >> 3), .wire = @intCast(t & 0x7) };
    }

    fn bytes(self: *TestReader) []const u8 {
        const len: usize = @intCast(self.varint());
        const out = self.buf[self.pos..][0..len];
        self.pos += len;
        return out;
    }

    fn fixed64(self: *TestReader) u64 {
        const out = std.mem.readInt(u64, self.buf[self.pos..][0..8], .little);
        self.pos += 8;
        return out;
    }

    fn atEnd(self: *TestReader) bool {
        return self.pos >= self.buf.len;
    }
};

fn unzigzag64(u: u64) i64 {
    return @bitCast((u >> 1) ^ (~(u & 1) +% 1));
}

test "prometheus_proto: native histogram round-trips through the wire" {
    const gpa = testing.allocator;
    const Layout = tel.LatencyHistogram.Layout;

    const layout: Layout = .{ .schema = 2, .min_ns = 512, .octaves = 2 };
    const hist: tel.LatencyHistogram = try .initForTest(gpa, layout);
    defer hist.deinitForTest(gpa);

    hist.observe(512); // bucket 0 (global native index 36)
    hist.observe(513); // bucket 1 (global native index 37)
    hist.observe(700); // bucket 2 (global native index 38)
    hist.observe(2000); // +Inf (unstored, still counted)

    var metrics: Map = .empty;
    defer metrics.deinit(gpa);
    try metrics.put(gpa, .initNameOnly("net_recv_packet_latency"), .{ .latency_histogram = hist });

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try writeBody(gpa, &out.writer, &metrics);

    // Decode: one length-delimited MetricFamily.
    var r: TestReader = .{ .buf = out.written() };
    const family = r.bytes();
    try testing.expect(r.atEnd());

    var fr: TestReader = .{ .buf = family };
    var fam_name: []const u8 = "";
    var histogram_bytes: []const u8 = "";
    while (!fr.atEnd()) {
        const t = fr.tag();
        switch (t.field) {
            MetricFamily.name => fam_name = fr.bytes(),
            MetricFamily.kind => {
                try testing.expectEqual(@as(u64, MetricType.histogram), fr.varint());
            },
            MetricFamily.metric => {
                var mr: TestReader = .{ .buf = fr.bytes() };
                while (!mr.atEnd()) {
                    const mt = mr.tag();
                    switch (mt.field) {
                        Metric.histogram => histogram_bytes = mr.bytes(),
                        else => _ = mr.bytes(),
                    }
                }
            },
            else => _ = fr.bytes(),
        }
    }
    try testing.expectEqualStrings("net_recv_packet_latency_ns", fam_name);

    // Decode the native Histogram submessage.
    var hr: TestReader = .{ .buf = histogram_bytes };
    var schema: i64 = 0;
    var sample_count: u64 = 0;
    var sample_sum: f64 = 0;
    var span_offset: i64 = 0;
    var span_length: u64 = 0;
    var deltas: std.ArrayList(i64) = .empty;
    defer deltas.deinit(gpa);
    while (!hr.atEnd()) {
        const t = hr.tag();
        switch (t.field) {
            Histogram.schema => schema = unzigzag64(hr.varint()),
            Histogram.sample_count => sample_count = hr.varint(),
            Histogram.sample_sum => sample_sum = @bitCast(hr.fixed64()),
            Histogram.zero_threshold => _ = hr.fixed64(),
            Histogram.zero_count => _ = hr.varint(),
            Histogram.positive_span => {
                var sr: TestReader = .{ .buf = hr.bytes() };
                while (!sr.atEnd()) {
                    const st = sr.tag();
                    switch (st.field) {
                        BucketSpan.offset => span_offset = unzigzag64(sr.varint()),
                        BucketSpan.length => span_length = sr.varint(),
                        else => _ = sr.varint(),
                    }
                }
            },
            Histogram.positive_delta => try deltas.append(gpa, unzigzag64(hr.varint())),
            else => _ = hr.bytes(),
        }
    }

    try testing.expectEqual(@as(i64, 2), schema); // schema 2
    try testing.expectEqual(@as(u64, 4), sample_count); // 4 observations total (incl. +Inf)
    try testing.expectEqual(@as(f64, 512 + 513 + 700 + 2000), sample_sum);
    try testing.expectEqual(@as(i64, 36), span_offset); // base_index 36, first populated bucket 0
    try testing.expectEqual(@as(u64, 3), span_length); // buckets 0,1,2 populated
    // Per-bucket populations 1,1,1 -> deltas 1,0,0.
    try testing.expectEqualSlices(i64, &.{ 1, 0, 0 }, deltas.items);
}

test "prometheus_proto: gauge renders as an untyped metric" {
    const gpa = testing.allocator;

    var value: std.atomic.Value(u64) = .init(42);
    var metrics: Map = .empty;
    defer metrics.deinit(gpa);
    try metrics.put(gpa, .initNameOnly("some_gauge"), .{ .gauge_int = &value });

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try writeBody(gpa, &out.writer, &metrics);

    var r: TestReader = .{ .buf = out.written() };
    var fr: TestReader = .{ .buf = r.bytes() };
    var fam_name: []const u8 = "";
    var untyped_value: f64 = 0;
    while (!fr.atEnd()) {
        const t = fr.tag();
        switch (t.field) {
            MetricFamily.name => fam_name = fr.bytes(),
            MetricFamily.kind => try testing.expectEqual(@as(u64, MetricType.untyped), fr.varint()),
            MetricFamily.metric => {
                var mr: TestReader = .{ .buf = fr.bytes() };
                while (!mr.atEnd()) {
                    const mt = mr.tag();
                    switch (mt.field) {
                        Metric.untyped => {
                            var ur: TestReader = .{ .buf = mr.bytes() };
                            _ = ur.tag();
                            untyped_value = @bitCast(ur.fixed64());
                        },
                        else => _ = mr.bytes(),
                    }
                }
            },
            else => _ = fr.bytes(),
        }
    }
    try testing.expectEqualStrings("some_gauge", fam_name);
    try testing.expectEqual(@as(f64, 42), untyped_value);
}

test "prometheus_proto: labeled gauge encodes a LabelPair" {
    const gpa = testing.allocator;

    // A `variant`-style label, in the same `key="value"` form `metric.Id` stores (see metric.zig).
    const raw: [14]u8 = "variant=\"blue\"".*;
    const label_data = raw ++ [_:'}']u8{};
    const id: Id = .{ .name = "colors", .label_count = 1, .labels = &label_data };

    var value: std.atomic.Value(u64) = .init(7);
    var metrics: Map = .empty;
    defer metrics.deinit(gpa);
    try metrics.put(gpa, id, .{ .gauge_int = &value });

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try writeBody(gpa, &out.writer, &metrics);

    var r: TestReader = .{ .buf = out.written() };
    var fr: TestReader = .{ .buf = r.bytes() };
    var label_name: []const u8 = "";
    var label_value: []const u8 = "";
    while (!fr.atEnd()) {
        const t = fr.tag();
        switch (t.field) {
            MetricFamily.kind => _ = fr.varint(),
            MetricFamily.metric => {
                var mr: TestReader = .{ .buf = fr.bytes() };
                while (!mr.atEnd()) {
                    const mt = mr.tag();
                    switch (mt.field) {
                        Metric.label => {
                            var lr: TestReader = .{ .buf = mr.bytes() };
                            while (!lr.atEnd()) {
                                const lt = lr.tag();
                                switch (lt.field) {
                                    LabelPair.name => label_name = lr.bytes(),
                                    LabelPair.value => label_value = lr.bytes(),
                                    else => _ = lr.bytes(),
                                }
                            }
                        },
                        else => _ = mr.bytes(),
                    }
                }
            },
            else => _ = fr.bytes(),
        }
    }
    try testing.expectEqualStrings("variant", label_name);
    try testing.expectEqualStrings("blue", label_value);
}
