/// This service consumes information from other services,
/// and sends them to an aggregator (prometheus).
const tel = @This();

const std = @import("std");
const start = @import("start");
const lib = @import("lib");
const api = lib.telemetry;

comptime {
    _ = start;
}

pub const name = .telemetry;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {
    startup: *const api.Startup,
    id_mem: []const u8,
    /// NOTE: Some of these are actually `f64`s.
    gauges: []const std.atomic.Value(u64),
};

pub const ReadWrite = struct {
    /// NOTE: some of these actually represent floats, and `std.atomic.Value(T)`s.
    histogram_data: []u64,
    log_streams: []api.log.MessageStream,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    var fba_state: std.heap.FixedBufferAllocator = .init(&struct {
        var buffer: [4096 * 4096 * 16]u8 = @splat(0);
    }.buffer);
    const gpa = fba_state.allocator();

    var metrics: MetricsMap = .empty;
    defer metrics.deinit(gpa);

    { // wait until all pending services have registered their metrics
        const pending_services = &ro.startup.pending_services;
        var previous = pending_services.load(.acquire);
        while (previous != 0) {
            const current = pending_services.load(.acquire);
            defer previous = current;
            if (previous >= current) continue;

            std.log.err(
                "Number of pending services went from {d} to {d}," ++
                    " which is not allowed (decrement-only).",
                .{ previous, current },
            );
            return error.PendingServicesIncremented;
        }
    }
    const log_streams = rw.log_streams[0..ro.startup.log_streams.load(.acquire)];

    try collectMetrics(gpa, &metrics, .{
        .id_mem = ro.id_mem[0..ro.startup.id_mem_end.load(.acquire)],
        .gauges = ro.gauges,
        .histogram_data = rw.histogram_data,
    });

    const listen_addr: std.net.Address = .initIp4(.{ 0, 0, 0, 0 }, ro.startup.port);
    var server = try listen_addr.listen(.{ .force_nonblocking = true });
    defer server.deinit();

    while (true) {
        {
            var stderr_buf: [4096]u8 = undefined;
            var stderr_fw: std.fs.File.Writer = .init(
                .{ .handle = start.panic_state.stderr },
                &stderr_buf,
            );
            const stderr = &stderr_fw.interface;
            defer stderr.flush() catch {};
            for (log_streams) |*log_stream| {
                try api.log.streamLogs(.{
                    .output = stderr,
                    .service_name = log_stream.name.slice(),
                    .log_messages_buffer = log_stream.swap_buffer.swap(),
                });
            }
            try stderr.flush();
        }

        const conn = server.accept() catch |err| switch (err) {
            error.WouldBlock => continue,
            else => |e| return e,
        };
        defer conn.stream.close();

        var conn_reader_state_buf: [4096 * 16]u8 = undefined;
        var conn_reader_state = conn.stream.reader(&conn_reader_state_buf);

        var conn_writer_state_buf: [4096 * 16]u8 = undefined;
        var conn_writer_state = conn.stream.writer(&conn_writer_state_buf);

        var http_server: std.http.Server = .init(
            conn_reader_state.interface(),
            &conn_writer_state.interface,
        );
        var http_request = try http_server.receiveHead();

        if (!std.mem.eql(u8, http_request.head.target, "/metrics")) {
            try http_request.respond(
                (
                    \\<!doctype html>
                    \\<head>
                    \\<title>404 Not Found</title>
                    \\</head>
                    \\
                ),
                .{
                    .status = .not_found,
                    .keep_alive = false,
                },
            );
            continue;
        }

        var response_body_writer_buf: [4096 * 16]u8 = undefined;
        var response_body_writer_state =
            try http_request.respondStreaming(&response_body_writer_buf, .{
                // NOTE: we can't technically pre-calculate the content length without writing
                // the response to memory first, since multiple reads cannot be guaranteed to be
                // the same, so we have to just stream it using chunked encoding.
                .content_length = null,
                .respond_options = .{
                    .status = .ok,
                    .transfer_encoding = .chunked,
                    .extra_headers = &.{
                        .{ .name = "Content-Type", .value = "text/plain; charset=UTF-8" },
                    },
                },
            });
        const response_body_writer = &response_body_writer_state.writer;
        try writePrometheusBody(response_body_writer, &metrics);
        try response_body_writer_state.end();
    }
}

const MetricPtrs = union(api.MetricKind) {
    gauge_int: *const std.atomic.Value(u64),
    gauge_float: *const std.atomic.Value(f64),
    histogram: api.Histogram,
};

const MetricsMap = std.ArrayHashMapUnmanaged(
    api.MetricId,
    MetricPtrs,
    MetricIdHashCtx,
    true,
);

const MetricIdHashCtx = struct {
    pub fn eql(
        ctx: MetricIdHashCtx,
        a: api.MetricId,
        b: api.MetricId,
        b_index: usize,
    ) bool {
        _ = ctx;
        _ = b_index;
        return a.eql(b);
    }

    pub fn hash(
        ctx: MetricIdHashCtx,
        key: api.MetricId,
    ) u32 {
        _ = ctx;
        return @truncate(key.hash());
    }
};

fn collectMetrics(
    gpa: std.mem.Allocator,
    metrics: *MetricsMap,
    params: struct {
        id_mem: []const u8,
        gauges: []const std.atomic.Value(u64),
        histogram_data: []u64,
    },
) !void {
    // rough estimate for pre-allocation, with the conservative estimate of 16 bytes per id.
    try metrics.ensureUnusedCapacity(gpa, params.id_mem.len / 16);

    var metric_id_r: std.Io.Reader = .fixed(params.id_mem);
    while (metric_id_r.bufferedLen() != 0) {
        const detail: api.MetricDetail = try .fromFixedReader(&metric_id_r);
        const gop = try metrics.getOrPut(gpa, detail.id);
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
            => |tag| @unionInit(MetricPtrs, @tagName(tag), gauge: {
                break :gauge @ptrCast(&params.gauges[detail.index]);
            }),
            .histogram => .{ .histogram = histogram: {
                const bucket_count = params.histogram_data[detail.index];
                const element_count = api.Histogram.elementsFromBucketCount(@intCast(bucket_count));
                const raw: api.Histogram.Raw = .{
                    .elements = params.histogram_data[detail.index + 1 ..][0..element_count],
                };
                break :histogram .fromRaw(raw);
            } },
        };
    }

    const SortCtx = struct {
        ids: []const api.MetricId,

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

fn writePrometheusBody(
    w: *std.Io.Writer,
    metrics: *const MetricsMap,
) std.Io.Writer.Error!void {
    for (metrics.keys(), metrics.values()) |metric_id, metric_ptrs| {
        std.debug.assert((metric_id.label_count == 0) == (metric_id.labels.len == 0));

        switch (metric_ptrs) {
            inline .gauge_int, .gauge_float => |gauge| try w.print(
                "{f} {f}\n",
                .{ metric_id.fmtText(), prometheusNumberFmt(gauge.load(.monotonic)) },
            ),
            .histogram => |*histogram| {
                try writeHistogramPrometheusBody(histogram, metric_id, w);
            },
        }

        const buffered = w.buffered();
        std.debug.assert(buffered[buffered.len - 1] == '\n');
    }
}

/// This does mutate pointers to write a snapshot of the histogram atomically.
fn writeHistogramPrometheusBody(
    histogram: *const api.Histogram,
    metric_id: api.MetricId,
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
        try w.print("le={f}", .{prometheusNumberFmt(bucket.upper_bound)});
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
    try w.print("{f}\n", .{prometheusNumberFmt(snapshot_reader.sum)});

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

/// Formatter defined such that:
/// * An integer is rendered in base 10 as-is.
/// * A float is rendered in base 10 after a round-trip conversion to `Int` and back.
///   - Rendered without a decimal point (i.e. as an integer) if the round-trip retains
///     equality with the original value.
///   - Rendered as a 6-digit decimal precision float if the round-trip loses equality.
fn prometheusNumberFmt(value: anytype) PrometheusNumberFmt(@TypeOf(value)) {
    return .init(value);
}

fn PrometheusNumberFmt(comptime T: type) type {
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
