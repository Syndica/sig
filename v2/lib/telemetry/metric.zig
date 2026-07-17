const std = @import("std");
const tel = @import("../telemetry.zig");

pub const Kind = enum(u8) {
    gauge_int,
    gauge_float,
    histogram,
    latency_histogram,
};

/// This represents the metric detail that appears before the metric value in memory.
pub const Detail = struct {
    id: Id,
    kind: Kind,
    /// The index representing the location of the metric, with its meaning depending on `kind`:
    /// * `gauge_int` & `gauge_float`: index of element in the `gauges` region.
    /// * `histogram`: index of a `bucket_count` element in `histogram_data`, which will be
    /// followed by a number of elements corresponding to a `Histogram` with that bucket_count.
    index: u32,

    /// Returns the number of bytes that would be written by `self.binaryWrite(w)`.
    pub fn binaryLength(self: Detail) usize {
        var trash_buffer: [128]u8 = undefined;
        var dw: std.Io.Writer.Discarding = .init(&trash_buffer);
        self.binaryWrite(&dw.writer) catch |err| switch (err) {
            error.WriteFailed => unreachable,
        };
        return dw.fullCount();
    }

    /// Write metric detail in binary format.
    pub fn binaryWrite(
        self: Detail,
        w: *std.Io.Writer,
    ) std.Io.Writer.Error!void {
        try self.id.writeBinary(w);
        try w.writeInt(u8, @intFromEnum(self.kind), tel.endian);
        try w.writeInt(u32, self.index, tel.endian);
    }

    pub const FromFixedReaderError = std.Io.Reader.Error || std.Io.Reader.TakeEnumError;

    /// Expects `r` to be a reader that contains the full serialized metric detail,
    /// such that calls to '`r.take`*' never invalidate previous calls to '`r.take`*'.
    /// This is most easily achieved when `r.* = .fixed(buffer)`.
    pub fn fromFixedReader(
        r: *std.Io.Reader,
    ) FromFixedReaderError!Detail {
        return .{
            .id = try .fromFixedReader(r),
            .kind = try r.takeEnum(Kind, tel.endian),
            .index = try r.takeInt(u32, tel.endian),
        };
    }
};

pub const Id = struct {
    name: []const u8,
    label_count: usize,
    /// Should be a list of comma-separated strings.
    /// It is asserted that:
    /// * `count(u8, labels, ',') + 1 == label_count`.
    labels: [:'}']const u8,

    pub fn initNameOnly(name: []const u8) Id {
        return .{
            .name = name,
            .label_count = 0,
            .labels = &.{},
        };
    }

    pub fn eql(a: Id, b: Id) bool {
        if (a.label_count != b.label_count) return false;
        if (!std.mem.eql(u8, a.name, b.name)) return false;
        if (!std.mem.eql(u8, a.labels, b.labels)) return false;
        return true;
    }

    /// Returns a formatter for the metric id using `writeText`.
    pub fn fmtText(self: Id) std.fmt.Alt(Id, writeText) {
        return .{ .data = self };
    }

    pub fn writeText(self: Id, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeAll(self.name);
        try w.writeByte('{');
        try w.writeAll(self.labels);
        try w.writeByte('}');
    }

    pub fn writeBinary(self: Id, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeInt(usize, self.name.len, tel.endian);
        try w.writeAll(self.name);

        try w.writeInt(usize, self.label_count, tel.endian);
        try w.writeAll(self.labels);
        try w.writeByte('}');
    }

    /// Expects `r` to be a reader that contains the full serialized metric id,
    /// such that consecutive calls to '`r.take`*' never invalidate previous calls
    /// to '`r.take`*'.
    /// This is most easily achieved when `r.* = .fixed(buffer)`.
    ///
    /// This is bijective with `writeBinary`.
    pub fn fromFixedReader(
        r: *std.Io.Reader,
    ) std.Io.Reader.Error!Id {
        const name_len = try r.takeInt(usize, tel.endian);
        const name = try r.take(name_len);

        const label_count = try r.takeInt(usize, tel.endian);

        var index: usize = 0;
        for (0..label_count) |label_index| while (true) : (index += 1) {
            try r.fill(index + 1);
            switch (r.buffered()[index]) {
                ',' => {
                    std.debug.assert(label_index < label_count - 1);
                    break;
                },
                '}' => {
                    std.debug.assert(label_index == label_count - 1);
                    break;
                },
                else => {},
            }
        };
        const labels = try r.take(index + 1);

        return .{
            .name = name,
            .label_count = label_count,
            .labels = labels[0 .. labels.len - 1 :'}'],
        };
    }

    pub fn hash(self: Id) u64 {
        var hashing_ws_buf: [4096]u8 = undefined;
        var hashing_ws: std.Io.Writer.Hashing(std.hash.Wyhash) =
            .initHasher(.init(0), &hashing_ws_buf);
        const hashing_w = &hashing_ws.writer;
        self.writeBinary(hashing_w) catch unreachable;
        return hashing_ws.hasher.final();
    }

    pub const ArrayHashCtx = struct {
        pub fn eql(ctx: ArrayHashCtx, a: Id, b: Id, b_index: usize) bool {
            _ = ctx;
            _ = b_index;
            return a.eql(b);
        }

        pub fn hash(ctx: ArrayHashCtx, key: Id) u32 {
            _ = ctx;
            return @truncate(key.hash());
        }
    };
};

pub const Appender = struct {
    id_mem: []u8,
    id_mem_end: *std.atomic.Value(u32),

    gauges: []std.atomic.Value(u64),
    gauges_end: *std.atomic.Value(u32),

    histogram_data: []u64,
    histogram_data_end: *std.atomic.Value(u32),

    pub const GaugeKind = enum {
        int,
        float,

        pub fn Type(comptime kind: GaugeKind) type {
            return switch (kind) {
                .int => u64,
                .float => f64,
            };
        }
    };

    pub fn appendCounter(self: Appender, id: Id) tel.Counter {
        return .{ .value = self.appendGaugeRaw(id, .int, 0) };
    }

    pub fn appendGauge(self: Appender, id: Id) tel.Gauge {
        return .{ .value = self.appendGaugeRaw(id, .int, 0) };
    }

    pub fn appendVariantCounter(
        self: Appender,
        name: []const u8,
        comptime V: type,
    ) tel.Variant(V) {
        const Vc = tel.Variant(V);
        var vc: Vc = .{
            .counts = @splat(undefined),
        };

        const gauges_count = @typeInfo(Vc.Enum).@"enum".fields.len;
        const gauges_start = self.gauges_end.fetchAdd(gauges_count, .monotonic);
        const gauges = self.gauges[gauges_start..][0..gauges_count];

        for (
            &vc.counts,
            gauges,
            gauges_start..,
            0..,
        ) |*gauge_ptr, *gauge, gauge_index, tag_index| {
            gauge_ptr.* = gauge;
            const tag = Vc.Indexer.keyForIndex(tag_index);
            const id: Id = .{
                .name = name,
                .label_count = 1,
                .labels = switch (tag) {
                    inline else => |itag| comptime labels: {
                        const str = "variant=\"" ++ @tagName(itag) ++ "\"";
                        const no_sentinel: [str.len]u8 = str.*;
                        break :labels &no_sentinel ++ [_:'}']u8{};
                    },
                },
            };
            const detail: Detail = .{
                .id = id,
                .kind = .gauge_int,
                .index = @intCast(gauge_index),
            };
            self.appendId(detail);
        }

        return vc;
    }

    pub fn appendHistogram(
        self: Appender,
        id: Id,
        upper_bounds: []const f64,
    ) tel.Histogram {
        const raw = self.appendHistogramRaw(id, @intCast(upper_bounds.len));
        raw.init(upper_bounds);
        return .fromRaw(raw);
    }

    pub fn appendLatencyHistogram(
        self: Appender,
        id: Id,
        comptime layout: tel.LatencyHistogram.Layout,
    ) tel.LatencyHistogram {
        const raw = self.appendLatencyHistogramRaw(id, layout);
        raw.init();
        return .fromRaw(layout, raw);
    }

    pub fn appendVariantHistogram(
        self: Appender,
        name: []const u8,
        comptime V: type,
        comptime Hist: type,
        comptime config: if (Hist == tel.LatencyHistogram)
            tel.LatencyHistogram.Layout
        else
            []const f64,
    ) tel.VariantHistogram(V, Hist) {
        const Vh = tel.VariantHistogram(V, Hist);
        var vh: Vh = .{ .histograms = @splat(undefined) };

        for (&vh.histograms, 0..) |*hist_ptr, tag_index| {
            const tag = Vh.Indexer.keyForIndex(tag_index);
            const id: Id = .{
                .name = name,
                .label_count = 1,
                .labels = switch (tag) {
                    inline else => |itag| comptime labels: {
                        const str = "variant=\"" ++ @tagName(itag) ++ "\"";
                        const no_sentinel: [str.len]u8 = str.*;
                        break :labels &no_sentinel ++ [_:'}']u8{};
                    },
                },
            };
            hist_ptr.* = if (Hist == tel.LatencyHistogram)
                self.appendLatencyHistogram(id, config)
            else
                self.appendHistogram(id, config);
        }

        return vh;
    }

    pub fn appendFields(
        self: Appender,
        comptime S: type,
        comptime fields_config: FieldsConfig(S),
    ) S {
        var result: S = undefined;
        inline for (@typeInfo(S).@"struct".fields) |s_field| {
            const field_ptr = &@field(result, s_field.name);
            const field_config = @field(fields_config.fields, s_field.name);

            const id_name: []const u8 = fields_config.prefix ++ "_" ++
                (field_config.id_override orelse s_field.name);

            field_ptr.* = switch (s_field.type) {
                tel.Counter => self.appendCounter(.initNameOnly(id_name)),
                tel.Gauge => self.appendGauge(.initNameOnly(id_name)),
                tel.Histogram => self.appendHistogram(
                    .initNameOnly(id_name),
                    field_config.upper_bounds orelse
                        &tel.Histogram.DEFAULT_UPPER_BOUNDS,
                ),
                tel.LatencyHistogram => self.appendLatencyHistogram(
                    .initNameOnly(id_name),
                    field_config.layout orelse @compileError(
                        std.fmt.comptimePrint(
                            "LatencyHistogram metric '{s}' requires a `.layout`.\n",
                            .{s_field.name},
                        ),
                    ),
                ),
                else => blk: {
                    if (isVariantCounter(s_field.type)) {
                        break :blk self.appendVariantCounter(id_name, s_field.type.Value);
                    } else if (maybeVariantHistogram(s_field.type)) |Hist| {
                        break :blk self.appendVariantHistogram(
                            id_name,
                            s_field.type.Value,
                            Hist,
                            if (Hist == tel.LatencyHistogram)
                                field_config.layout orelse @compileError(std.fmt.comptimePrint(
                                    "VariantHistogram metric '{s}' requires a `.layout`.\n",
                                    .{s_field.name},
                                ))
                            else
                                field_config.upper_bounds orelse
                                    &tel.Histogram.DEFAULT_UPPER_BOUNDS,
                        );
                    } else comptime unreachable;
                },
            };
        }
        return result;
    }

    pub fn appendGaugeRaw(
        self: Appender,
        id: Id,
        comptime kind: GaugeKind,
        init_value: kind.Type(),
    ) *std.atomic.Value(kind.Type()) {
        const gauge_index = self.gauges_end.fetchAdd(1, .monotonic);
        self.appendId(.{
            .id = id,
            .kind = switch (kind) {
                .int => .gauge_int,
                .float => .gauge_float,
            },
            .index = gauge_index,
        });
        const gauge = &self.gauges[gauge_index];
        gauge.* = .init(init_value);
        return @ptrCast(gauge);
    }

    pub fn appendHistogramRaw(
        self: Appender,
        id: Id,
        bucket_count: u32,
    ) tel.Histogram.Raw {
        const elem_count = tel.Histogram.elementsFromBucketCount(bucket_count);
        const elem_offs = self.histogram_data_end.fetchAdd(elem_count + 1, .acq_rel);
        self.appendId(.{
            .id = id,
            .kind = .histogram,
            .index = elem_offs,
        });
        self.histogram_data[elem_offs] = bucket_count;
        return .{ .elements = self.histogram_data[elem_offs + 1 ..][0..elem_count] };
    }

    pub fn appendLatencyHistogramRaw(
        self: Appender,
        id: Id,
        comptime layout: tel.LatencyHistogram.Layout,
    ) tel.LatencyHistogram.Raw {
        const header_words = tel.LatencyHistogram.Layout.header_words;
        const element_count = layout.elementsFromBucketCount();
        const elem_offs = self.histogram_data_end.fetchAdd(header_words + element_count, .acq_rel);
        self.appendId(.{
            .id = id,
            .kind = .latency_histogram,
            .index = elem_offs,
        });
        layout.writeHeader(self.histogram_data[elem_offs..][0..header_words]);
        return .{
            .elements = self.histogram_data[elem_offs + header_words ..][0..element_count],
        };
    }

    fn appendId(self: Appender, detail: Detail) void {
        const id_mem_len = detail.binaryLength();
        const id_mem_offset = self.id_mem_end.fetchAdd(@intCast(id_mem_len), .acq_rel);

        var id_mem_w: std.Io.Writer = .fixed(self.id_mem[id_mem_offset..][0..id_mem_len]);
        detail.binaryWrite(&id_mem_w) catch |err| switch (err) {
            error.WriteFailed => unreachable,
        };
    }
};

pub const FieldConfigBasic = struct {
    id_override: ?[]const u8,

    const default: FieldConfigBasic = .{
        .id_override = null,
    };
};

pub const FieldConfigHistogram = struct {
    id_override: ?[]const u8,
    upper_bounds: ?[]const f64,

    const default: FieldConfigHistogram = .{
        .id_override = null,
        .upper_bounds = null,
    };
};

pub const FieldConfigLatencyHistogram = struct {
    id_override: ?[]const u8 = null,
    /// Required: selects the bucket layout & count.
    layout: ?tel.LatencyHistogram.Layout = null,

    const default: FieldConfigLatencyHistogram = .{};
};

pub fn FieldsConfig(comptime S: type) type {
    return struct {
        prefix: []const u8,
        fields: FieldConfigs(S) = .{},
    };
}

pub fn FieldConfigs(comptime S: type) type {
    const s_info = @typeInfo(S).@"struct";
    var new_fields: [s_info.fields.len]std.builtin.Type.StructField = undefined;
    @setEvalBranchQuota(s_info.fields.len);
    for (s_info.fields, &new_fields) |s_field, *new_field| {
        const Field = switch (s_field.type) {
            tel.Counter => FieldConfigBasic,
            tel.Gauge => FieldConfigBasic,
            tel.Histogram => FieldConfigHistogram,
            tel.LatencyHistogram => FieldConfigLatencyHistogram,
            else => blk: {
                if (isVariantCounter(s_field.type)) break :blk FieldConfigBasic;
                if (maybeVariantHistogram(s_field.type)) |Hist| {
                    break :blk if (Hist == tel.LatencyHistogram)
                        FieldConfigLatencyHistogram
                    else
                        FieldConfigHistogram;
                }
                @compileError("Unsupported: " ++ @typeName(s_field.type));
            },
        };
        new_field.* = .{
            .name = s_field.name,
            .type = Field,
            .default_value_ptr = &@as(Field, .default),
            .is_comptime = false,
            .alignment = @alignOf(Field),
        };
    }
    return @Type(.{ .@"struct" = .{
        .layout = .auto,
        .backing_integer = null,
        .fields = &new_fields,
        .decls = &.{},
        .is_tuple = false,
    } });
}

inline fn isVariantCounter(comptime S: type) bool {
    comptime {
        if (!@hasDecl(S, "Value")) return false;
        if (@TypeOf(S.Value) != type) return false;
        const is_variant = switch (@typeInfo(S.Value)) {
            .@"enum", .error_set => true,
            .@"union" => |u_info| u_info.tag_type != null,
            else => false,
        };
        if (!is_variant) return false;
        if (tel.Variant(S.Value) != S) return false;
        return true;
    }
}

inline fn maybeVariantHistogram(comptime S: type) ?type {
    comptime {
        if (!@hasDecl(S, "Value")) return null;
        if (@TypeOf(S.Value) != type) return null;
        switch (@typeInfo(S.Value)) {
            .@"enum", .error_set => {},
            .@"union" => |u| if (u.tag_type == null) return null,
            else => return null,
        }
        if (!@hasField(S, "histograms")) return null;
        const info = @typeInfo(@FieldType(S, "histograms"));
        if (info != .array) return null;
        const Hist = info.array.child;
        if (tel.VariantHistogram(S.Value, Hist) != S) return null;
        return Hist;
    }
}

pub const Any = union(Kind) {
    gauge_int: *const std.atomic.Value(u64),
    gauge_float: *const std.atomic.Value(f64),
    histogram: tel.Histogram,
    latency_histogram: tel.LatencyHistogram,
};

pub const Map = std.ArrayHashMapUnmanaged(Id, Any, Id.ArrayHashCtx, true);

pub fn collect(
    gpa: std.mem.Allocator,
    metrics: *Map,
    params: struct {
        id_mem: []const u8,
        gauges: []const std.atomic.Value(u64),
        histogram_data: []u64,
    },
) (std.mem.Allocator.Error || Detail.FromFixedReaderError || error{DuplicateGauge})!void {
    try metrics.ensureUnusedCapacity(gpa, params.gauges.len + params.histogram_data.len);

    var metric_id_r: std.Io.Reader = .fixed(params.id_mem);
    while (metric_id_r.bufferedLen() != 0) {
        const detail: Detail = try .fromFixedReader(&metric_id_r);
        const gop = metrics.getOrPutAssumeCapacity(detail.id);
        if (gop.found_existing) {
            std.log.err(
                "Multiple metrics with id '{f}' specified.",
                .{detail.id.fmtText()},
            );
            return error.DuplicateGauge;
        }

        gop.value_ptr.* = switch (detail.kind) {
            inline //
            .gauge_int,
            .gauge_float,
            => |tag| @unionInit(Any, @tagName(tag), gauge: {
                break :gauge @ptrCast(&params.gauges[detail.index]);
            }),
            .histogram => .{ .histogram = histogram: {
                const bucket_count = params.histogram_data[detail.index];
                const element_count = tel.Histogram.elementsFromBucketCount(@intCast(bucket_count));
                const raw: tel.Histogram.Raw = .{
                    .elements = params.histogram_data[detail.index + 1 ..][0..element_count],
                };
                break :histogram .fromRaw(raw);
            } },
            .latency_histogram => .{ .latency_histogram = lat: {
                const header_words = tel.LatencyHistogram.Layout.header_words;
                const layout: tel.LatencyHistogram.Layout = .initFromHeader(
                    params.histogram_data[detail.index..][0..header_words],
                );
                const element_count = layout.elementsFromBucketCount();
                const offset = detail.index + header_words;
                const raw: tel.LatencyHistogram.Raw = .{
                    .elements = params.histogram_data[offset..][0..element_count],
                };
                break :lat .fromRaw(layout, raw);
            } },
        };
    }

    const SortCtx = struct {
        ids: []const Id,

        pub fn lessThan(ctx: *const @This(), a_index: usize, b_index: usize) bool {
            return switch (std.mem.order(u8, ctx.ids[a_index].name, ctx.ids[b_index].name)) {
                .lt => true,
                .gt => false,
                .eq => switch (std.mem.order(
                    u8,
                    ctx.ids[a_index].labels,
                    ctx.ids[b_index].labels,
                )) {
                    .lt => true,
                    .gt, .eq => false,
                },
            };
        }
    };
    const sort_ctx: SortCtx = .{ .ids = metrics.keys() };
    metrics.sort(sort_ctx);
}

/// Allocates a fresh telemetry `Region` backed by a heap buffer, for exercising the appender and
/// `collect` paths in tests. Caller owns the returned buffer and must free it.
fn testRegion(gpa: std.mem.Allocator) !struct { *tel.Region, []align(@alignOf(tel.Region)) u8 } {
    const params: tel.Region.InitParams = .{
        .port = 0,
        .log_filters_encoded = &.{},
        .service_count = 1,
        .id_mem_len = 4096,
        .gauges_len = 16,
        .histogram_data_len = 4096,
    };
    const buf = try gpa.alignedAlloc(u8, .of(tel.Region), params.info().regionSize());
    const region: *tel.Region = @ptrCast(buf.ptr);
    region.init(params);
    return .{ region, buf };
}

/// Collects `region`'s currently-registered metrics into a fresh, caller-owned `Map`.
fn testCollect(gpa: std.mem.Allocator, region: *tel.Region) !Map {
    const slices = region.getSlices();
    var metrics: Map = .empty;
    errdefer metrics.deinit(gpa);
    try collect(gpa, &metrics, .{
        .id_mem = slices.id_mem[0..region.id_mem_end.load(.monotonic)],
        .gauges = slices.gauges,
        .histogram_data = slices.histogram_data,
    });
    return metrics;
}

test "variant histogram: appendVariantHistogram registers one latency series per variant" {
    const gpa = std.testing.allocator;
    const Method = enum { get, put, delete };

    const region, const buf = try testRegion(gpa);
    defer gpa.free(buf);

    const vh = region.metricAppender().appendVariantHistogram(
        "req_latency_seconds",
        Method,
        tel.LatencyHistogram,
        .{ .schema = 2, .min_ns = 512, .octaves = 4 },
    );

    // Observations land in the histogram for their own tag and nowhere else.
    vh.observe(.get, 700);
    vh.observe(.get, 800);
    vh.observe(.put, 1024);
    inline for (.{ .{ Method.get, 2 }, .{ Method.put, 1 }, .{ Method.delete, 0 } }) |case| {
        var snap = vh.get(case[0]).swapOutSnapshot();
        defer snap.release();
        try std.testing.expectEqual(@as(u63, case[1]), snap.count);
    }

    var metrics = try testCollect(gpa, region);
    defer metrics.deinit(gpa);

    var seen: usize = 0;
    for (metrics.keys(), metrics.values()) |id, any| {
        if (!std.mem.eql(u8, id.name, "req_latency_seconds")) continue;
        seen += 1;
        try std.testing.expectEqual(@as(usize, 1), id.label_count);
        try std.testing.expectEqual(Kind.latency_histogram, std.meta.activeTag(any));
        try std.testing.expect(
            std.mem.eql(u8, id.labels, "variant=\"get\"") or
                std.mem.eql(u8, id.labels, "variant=\"put\"") or
                std.mem.eql(u8, id.labels, "variant=\"delete\""),
        );
    }
    try std.testing.expectEqual(@as(usize, 3), seen);
}

test "variant histogram: appendVariantHistogram registers one bounds series per variant" {
    const gpa = std.testing.allocator;
    const Outcome = enum { ok, err, timeout };

    const region, const buf = try testRegion(gpa);
    defer gpa.free(buf);

    const vh = region.metricAppender().appendVariantHistogram(
        "request_size_bytes",
        Outcome,
        tel.Histogram,
        &.{ 1, 10, 100, 1000 },
    );

    // Observations land in the histogram for their own tag and nowhere else; the `.err` sample of
    // 5000 sits above the top bound, landing in the implicit `+Inf` bucket but still counted.
    vh.observe(.ok, 5);
    vh.observe(.ok, 50);
    vh.observe(.err, 5000);
    inline for (.{ .{ Outcome.ok, 2 }, .{ Outcome.err, 1 }, .{ Outcome.timeout, 0 } }) |case| {
        var snap = vh.get(case[0]).swapOutSnapshot();
        defer snap.release();
        try std.testing.expectEqual(@as(u63, case[1]), snap.count);
    }

    var metrics = try testCollect(gpa, region);
    defer metrics.deinit(gpa);

    var seen: usize = 0;
    for (metrics.keys(), metrics.values()) |id, any| {
        if (!std.mem.eql(u8, id.name, "request_size_bytes")) continue;
        seen += 1;
        try std.testing.expectEqual(@as(usize, 1), id.label_count);
        try std.testing.expectEqual(Kind.histogram, std.meta.activeTag(any));
        try std.testing.expect(
            std.mem.eql(u8, id.labels, "variant=\"ok\"") or
                std.mem.eql(u8, id.labels, "variant=\"err\"") or
                std.mem.eql(u8, id.labels, "variant=\"timeout\""),
        );
    }
    try std.testing.expectEqual(@as(usize, 3), seen);
}

test "variant histogram: appendFields registers latency and bounds variants" {
    const gpa = std.testing.allocator;
    const Method = enum { get, put };
    const Outcome = enum { ok, err };
    const Metrics = struct {
        latency: tel.VariantHistogram(Method, tel.LatencyHistogram),
        sizes: tel.VariantHistogram(Outcome, tel.Histogram),
    };

    const region, const buf = try testRegion(gpa);
    defer gpa.free(buf);

    const metrics_struct = region.metricAppender().appendFields(Metrics, .{
        .prefix = "svc",
        .fields = .{
            .latency = .{ .layout = .{ .schema = 2, .min_ns = 512, .octaves = 4 } },
            .sizes = .{ .id_override = null, .upper_bounds = &.{ 1, 10, 100 } },
        },
    });
    metrics_struct.latency.observe(.get, 700);
    metrics_struct.sizes.observe(.ok, 50);

    var metrics = try testCollect(gpa, region);
    defer metrics.deinit(gpa);

    var latency_series: usize = 0;
    var sizes_series: usize = 0;
    for (metrics.keys(), metrics.values()) |id, any| {
        if (std.mem.eql(u8, id.name, "svc_latency")) {
            latency_series += 1;
            try std.testing.expectEqual(Kind.latency_histogram, std.meta.activeTag(any));
        } else if (std.mem.eql(u8, id.name, "svc_sizes")) {
            sizes_series += 1;
            try std.testing.expectEqual(Kind.histogram, std.meta.activeTag(any));
        }
    }
    try std.testing.expectEqual(@as(usize, 2), latency_series); // get, put
    try std.testing.expectEqual(@as(usize, 2), sizes_series); // ok, err
}
