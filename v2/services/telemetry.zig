//! This service consumes information from other services,
//! and sends them to an aggregator (prometheus).

const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const services = @import("services");
const api = lib.telemetry;

comptime {
    _ = start;
}

pub const name = .telemetry;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = services.telemetry.ReadOnly;
pub const ReadWrite = services.telemetry.ReadWrite;

/// `Content-Type` for the Prometheus protobuf exposition (the format that carries native histograms).
const proto_content_type =
    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited";

pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
    _ = ro;

    const region = rw.region;

    { // wait until all pending services have registered their metrics
        const pending_services: *const std.atomic.Value(u32) = &region.pending_services;
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
    const log_streams = region.getSlices().log_streams[0..region.log_streams.load(.acquire)];

    var metrics: api.metric.Map = .empty;
    {
        var fba_state: std.heap.FixedBufferAllocator = .init(&struct {
            var buffer: [4096 * 4096 * 16]u8 = undefined;
        }.buffer);
        const slices = region.getSlices();
        try api.metric.collect(fba_state.allocator(), &metrics, .{
            .id_mem = slices.id_mem[0..region.id_mem_end.load(.acquire)],
            .gauges = slices.gauges[0..region.gauges_end.load(.acquire)],
            .histogram_data = slices.histogram_data[0..region.histogram_data_end.load(.acquire)],
        });
    }

    var filters_buffer: [4096]api.log.Filter = undefined;
    const filters: []const api.log.Filter = filters: {
        var filters: std.ArrayList(api.log.Filter) = .initBuffer(&filters_buffer);
        var fbr: std.Io.Reader = .fixed(region.getSlices().log_filters_encoded);
        while (fbr.bufferedLen() != 0) {
            const header = try fbr.takeStruct(api.log.Filter.Header, api.endian);
            const filter = header.getFilterFromFixedReader(&fbr) orelse {
                return error.InvalidFilterHeader;
            };
            try filters.appendBounded(filter);
        }
        std.sort.block(api.log.Filter, filters.items, {}, api.log.Filter.sortLessThanInverted);
        if (filters.items.len == 0 or !filters.getLast().isLevelOnly()) {
            std.log.err(
                "Missing default log level; there must be at least one level-only log level.",
                .{},
            );
            return error.MissingDefaultLogLevel;
        }
        break :filters filters.items;
    };

    const listen_addr: std.net.Address = .initIp4(.{ 0, 0, 0, 0 }, region.info.port);
    var server = try listen_addr.listen(.{
        .force_nonblocking = true,
        .reuse_address = true,
    });
    defer server.deinit();

    try setRecvTimeOut(server.stream.handle, .{ .sec = 1, .usec = 0 });
    try setSendTimeOut(server.stream.handle, .{ .sec = 1, .usec = 0 });

    // telemetry will always signal as idle, so that it will never cause other tests to block.
    // this is necessary because so long as other tests are running, even if they are idle,
    // they may continue to log messages, causing telemetry to appear active, even if it
    // should soon be shut down along with all the other services.
    try runner.activity.signalIdleImmediate();

    // Scratch for encoding a protobuf response; reset after each request. Backed by a fixed
    // buffer rather than `page_allocator`: the latter grows allocations with `mremap`, which the
    // service seccomp sandbox forbids (see `lib.linux.SeccompProg.seccompFilters`), and a fixed
    // buffer keeps encoding syscall-free besides.
    var proto_fba: std.heap.FixedBufferAllocator = .init(&struct {
        var buffer: [4096 * 4096]u8 = undefined; // 16 MiB
    }.buffer);

    while (true) : (try runner.activity.checkCanceled()) {
        {
            var stderr_buf: [4096]u8 = undefined;
            var stderr_fw: std.fs.File.Writer = .init(
                .{ .handle = start.panic_state.stderr },
                &stderr_buf,
            );
            const stderr = &stderr_fw.interface;
            defer stderr.flush() catch {};
            for (log_streams) |*log_stream| {
                const log_messages_buffer = log_stream.swap_buffer.swap();
                try api.log.streamLogs(.{
                    .output = stderr,
                    .service_name = log_stream.name.slice(),
                    .log_messages_buffer = log_messages_buffer,
                    .filters = filters,
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
        var http_request = http_server.receiveHead() catch |err| switch (err) {
            error.HttpHeadersOversize,
            error.HttpRequestTruncated,
            error.HttpConnectionClosing,
            error.HttpHeadersInvalid,
            => |e| {
                std.log.warn("{}", .{e});
                continue;
            },
            error.ReadFailed => switch (conn_reader_state.getError().?) {
                error.WouldBlock,
                error.Canceled,
                error.MessageTooBig,
                error.ConnectionTimedOut,
                error.ConnectionResetByPeer,
                => |e| {
                    std.log.debug("{}", .{e});
                    continue;
                },
                else => |e| return e,
            },
        };

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

        // Serve protobuf when the client negotiates it (a Prometheus server does when
        // `scrape_native_histograms` is enabled); otherwise the text format, so `curl` still works.
        // Native histograms can only be carried by the protobuf format.
        const want_proto = acceptsProtobuf(&http_request);
        const content_type = if (want_proto) proto_content_type else "text/plain; charset=UTF-8";

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
                        .{ .name = "Content-Type", .value = content_type },
                    },
                },
            });
        const response_body_writer = &response_body_writer_state.writer;
        if (want_proto) {
            defer proto_fba.reset();
            try api.prometheus_proto.writeBody(
                proto_fba.allocator(),
                response_body_writer,
                &metrics,
            );
        } else {
            try api.prometheus.writeBody(response_body_writer, &metrics);
        }
        try response_body_writer_state.end();
    }
}

/// Whether the request's `Accept` header negotiates the Prometheus protobuf exposition format.
/// A Prometheus server sends `application/vnd.google.protobuf;proto=io.prometheus.client.MetricFamily;
/// encoding=delimited` when `scrape_native_histograms` (or a protobuf `scrape_protocols`) is enabled.
fn acceptsProtobuf(request: *std.http.Server.Request) bool {
    var it = request.iterateHeaders();
    while (it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "accept")) continue;
        if (std.mem.indexOf(u8, header.value, "application/vnd.google.protobuf") != null and
            std.mem.indexOf(u8, header.value, "encoding=delimited") != null)
        {
            return true;
        }
    }
    return false;
}

fn setRecvTimeOut(
    handle: std.os.linux.socket_t,
    timeout: std.os.linux.timeval,
) !void {
    try std.posix.setsockopt(
        handle,
        std.os.linux.SOL.SOCKET,
        std.os.linux.SO.RCVTIMEO,
        @ptrCast(&timeout),
    );
}

fn setSendTimeOut(
    handle: std.os.linux.socket_t,
    timeout: std.os.linux.timeval,
) !void {
    try std.posix.setsockopt(
        handle,
        std.os.linux.SOL.SOCKET,
        std.os.linux.SO.SNDTIMEO,
        @ptrCast(&timeout),
    );
}
