const std = @import("std");
const testing = std.testing;
const ws = @import("webzockets_lib");

const servers = @import("../support/test_servers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/fd_leak.zig").FdLeakDetector;

test "e2e client close: server-initiated close disconnects cleanly" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    // Server closes immediately on open (server-initiated close).
    // Client echoes and disconnects.
    const ts = try servers.startCloseOnOpenServer(testing.allocator);
    defer ts.stop();

    var handler: clients.ServerCloseHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestServerCloseClient.Conn = undefined;
    var client = env.initClient(clients.TestServerCloseClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expect(handler.close_called);
    conn.deinit();
}

test "e2e client close: close frame still sent when ping write is in flight" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    var capture: CaptureContext = .{};

    var handler: PingThenCloseHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    {
        var fake = try FrameCaptureServer.start(&capture);
        defer fake.stop();

        const PingThenCloseClient = ws.Client(PingThenCloseHandler, 4096);

        var conn: PingThenCloseClient.Conn = undefined;
        var client = env.initClient(PingThenCloseClient, &handler, &conn, .{
            .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, fake.port),
        });

        try client.connect();
        try env.loop.run(.until_done);

        try testing.expect(handler.open_called);
        try testing.expect(handler.close_called);

        conn.deinit();
    }

    try testing.expect(capture.saw_ping);
    try testing.expect(capture.saw_close);
}

const PingThenCloseHandler = struct {
    open_called: bool = false,
    close_called: bool = false,

    pub fn onOpen(self: *PingThenCloseHandler, conn: anytype) void {
        self.open_called = true;
        conn.sendPing("hello") catch return;
        conn.close(.normal, "done");
    }

    pub fn onMessage(_: *PingThenCloseHandler, _: anytype, _: ws.Message) void {}
    pub fn onWriteComplete(_: *PingThenCloseHandler, _: anytype) void {}

    pub fn onClose(self: *PingThenCloseHandler, _: anytype) void {
        self.close_called = true;
    }
};

/// Minimal single-connection WebSocket server used by this close test.
///
/// It performs a basic handshake and records whether it observed ping and
/// close frames from the client.
const CaptureContext = struct {
    saw_ping: bool = false,
    saw_close: bool = false,
};

const FrameCaptureServer = struct {
    listener: std.posix.socket_t,
    port: u16,
    thread: std.Thread,

    fn start(ctx: *CaptureContext) !FrameCaptureServer {
        const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
        const listener = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
        errdefer std.posix.close(listener);

        try std.posix.bind(listener, @ptrCast(&addr.any), addr.getOsSockLen());
        try std.posix.listen(listener, 1);

        var bound_addr: std.posix.sockaddr.storage = undefined;
        var addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(bound_addr));
        try std.posix.getsockname(listener, @ptrCast(&bound_addr), &addr_len);
        const sa4: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&bound_addr));
        const port = std.mem.bigToNative(u16, sa4.port);

        const thread = try std.Thread.spawn(.{}, acceptAndCaptureFrames, .{ listener, ctx });
        return .{ .listener = listener, .port = port, .thread = thread };
    }

    fn stop(self: *FrameCaptureServer) void {
        std.posix.close(self.listener);
        self.thread.join();
    }
};

fn acceptAndCaptureFrames(listener: std.posix.socket_t, ctx: *CaptureContext) !void {
    var client_addr: std.posix.sockaddr.storage = undefined;
    var client_addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(client_addr));
    const conn_fd = try std.posix.accept(
        listener,
        @ptrCast(&client_addr),
        &client_addr_len,
        0,
    );
    defer std.posix.close(conn_fd);

    const stream = std.net.Stream{ .handle = conn_fd };

    // Keep reads bounded so test failures do not block indefinitely.
    const timeout = std.posix.timeval{ .sec = 2, .usec = 0 };
    try std.posix.setsockopt(
        conn_fd,
        std.posix.SOL.SOCKET,
        std.posix.SO.RCVTIMEO,
        std.mem.asBytes(&timeout),
    );

    var req_buf: [4096]u8 = undefined;
    var req_total: usize = 0;
    while (req_total < req_buf.len) {
        const n = try stream.read(req_buf[req_total..]);
        if (n == 0) {
            return;
        }
        req_total += n;
        if (std.mem.indexOf(u8, req_buf[0..req_total], "\r\n\r\n") != null) {
            break;
        }
    }

    const key = extractWebSocketKey(req_buf[0..req_total]) orelse return;

    var accept_buf: [28]u8 = undefined;
    const accept_key = ws.http.computeAcceptKey(&accept_buf, key);

    var response_buf: [256]u8 = undefined;
    const response = try std.fmt.bufPrint(
        &response_buf,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n\r\n",
        .{accept_key},
    );
    try stream.writeAll(response);

    var frame_buf: [1024]u8 = undefined;
    var frame_start: usize = 0;
    var frame_end: usize = 0;

    while (!ctx.saw_close) {
        if (frame_start > 0) {
            const remaining = frame_end - frame_start;
            if (remaining > 0) {
                std.mem.copyForwards(u8, frame_buf[0..remaining], frame_buf[frame_start..frame_end]);
            }
            frame_start = 0;
            frame_end = remaining;
        }

        const n = try stream.read(frame_buf[frame_end..]);
        if (n == 0) {
            return;
        }
        frame_end += n;

        while (frame_start < frame_end) {
            const available = frame_buf[frame_start..frame_end];
            const header = ws.frame.parseHeader(available) catch |err| switch (err) {
                error.InsufficientData => break,
                else => return err,
            };

            try header.validate();
            try header.validateServerBound();

            const total_len: usize = @intCast(header.totalLen());
            if (available.len < total_len) {
                break;
            }

            const payload_start = frame_start + header.header_len;
            const payload_end = payload_start + @as(usize, @intCast(header.payload_len));
            const payload = frame_buf[payload_start..payload_end];
            header.unmaskPayload(payload);

            switch (header.opcode) {
                .ping => ctx.saw_ping = true,
                .close => {
                    ctx.saw_close = true;
                    return;
                },
                else => {},
            }

            frame_start += total_len;
        }
    }
}

fn extractWebSocketKey(request: []const u8) ?[]const u8 {
    const needle = "Sec-WebSocket-Key: ";
    const start = std.mem.indexOf(u8, request, needle) orelse return null;
    const value_start = start + needle.len;
    const rest = request[value_start..];
    const end = std.mem.indexOf(u8, rest, "\r\n") orelse return null;
    return rest[0..end];
}
