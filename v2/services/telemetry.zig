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

pub const ReadOnly = struct {};

pub const ReadWrite = struct {
    region: *api.Region,
};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
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

    const listen_addr: std.net.Address = .initIp4(.{ 0, 0, 0, 0 }, region.info.port);
    var server = try listen_addr.listen(.{ .force_nonblocking = true });
    defer server.deinit();

    try setRecvTimeOut(server.stream.handle, .{ .sec = 1, .usec = 0 });
    try setSendTimeOut(server.stream.handle, .{ .sec = 1, .usec = 0 });

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
        std.log.err("Handling prometheus", .{});

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
        try api.prometheus.writeBody(response_body_writer, &metrics);
        try response_body_writer_state.end();
    }
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
