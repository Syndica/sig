const std = @import("std");
const testing = std.testing;
const ws = @import("webzockets_lib");

const servers = @import("../support/test_servers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/fd_leak.zig").FdLeakDetector;

test "e2e client timeout: close timeout force-disconnects unresponsive peer" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    var srv = try UnresponsiveServer.start();
    defer srv.stop();

    var handler: clients.CloseOnOpenHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestCloseClient.Conn = undefined;
    var client = env.initClient(clients.TestCloseClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, srv.port),
        .close_timeout_ms = 200,
    });
    try client.connect();
    try env.loop.run(.until_done);

    // Server never responded to close → close timer fired → force disconnect
    try testing.expect(handler.open_called);
    try testing.expect(handler.close_called);
    conn.deinit();
}

test "e2e client timeout: normal close completes before timeout" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var handler: clients.EchoTestHandler = .{
        .allocator = testing.allocator,
        .send_kind = .text,
        .send_data = "hello",
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestEchoClient.Conn = undefined;
    var client = env.initClient(clients.TestEchoClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
        // Close timeout configured but server responds promptly, so it
        // should never fire.
        .close_timeout_ms = 500,
    });
    try client.connect();
    try env.loop.run(.until_done);

    // Normal echo + close should work fine with close timer enabled
    try testing.expect(handler.open_called);
    try testing.expectEqualSlices(u8, "hello", handler.received_data.?);
    conn.deinit();
}

test "e2e client timeout: close in onOpen arms close timer" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    // Echo server will respond to close, so timer gets cancelled cleanly
    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var handler: clients.CloseOnOpenHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestCloseClient.Conn = undefined;
    var client = env.initClient(clients.TestCloseClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
        .close_timeout_ms = 200,
    });
    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    conn.deinit();
}

test "e2e client timeout: server-initiated close does not arm close timer" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    // Server closes immediately on open (server-initiated close).
    // Client echoes and disconnects — no close timer needed.
    const ts = try servers.startCloseOnOpenServer(testing.allocator);
    defer ts.stop();

    var handler: clients.ServerCloseHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestServerCloseClient.Conn = undefined;
    var client = env.initClient(clients.TestServerCloseClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
        .close_timeout_ms = 200,
    });
    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expect(handler.close_called);
    conn.deinit();
}

/// Minimal raw TCP "server" that completes the WebSocket handshake but then
/// ignores all further data (never responds to close frames). Used to test
/// client-side close-handshake timeout behavior.
const UnresponsiveServer = struct {
    listener: std.posix.socket_t,
    port: u16,
    thread: std.Thread,

    fn start() !UnresponsiveServer {
        // Low-level posix to test exactly the handshake and timeout behavior we want
        const address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
        const listener = try std.posix.socket(
            address.any.family,
            std.posix.SOCK.STREAM,
            std.posix.IPPROTO.TCP,
        );
        errdefer std.posix.close(listener);

        try std.posix.setsockopt(
            listener,
            std.posix.SOL.SOCKET,
            std.posix.SO.REUSEADDR,
            &std.mem.toBytes(@as(c_int, 1)),
        );
        try std.posix.bind(listener, &address.any, address.getOsSockLen());
        try std.posix.listen(listener, 1);

        var bound_addr: std.posix.sockaddr.storage = undefined;
        var addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(bound_addr));
        try std.posix.getsockname(listener, @ptrCast(&bound_addr), &addr_len);
        const sa4: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&bound_addr));
        const port = std.mem.bigToNative(u16, sa4.port);

        const thread = try std.Thread.spawn(.{}, acceptAndHandshake, .{listener});
        return .{
            .listener = listener,
            .port = port,
            .thread = thread,
        };
    }

    fn acceptAndHandshake(listener: std.posix.socket_t) void {
        var addr: std.posix.sockaddr.storage = undefined;
        var addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(addr));
        const conn_fd = std.posix.accept(listener, @ptrCast(&addr), &addr_len, 0) catch return;
        const stream = std.net.Stream{ .handle = conn_fd };
        defer stream.close();

        // Safety net: if the client never disconnects (test bug), don't block forever.
        const timeout: std.posix.timeval = .{ .sec = 5, .usec = 0 };
        std.posix.setsockopt(
            conn_fd,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeout),
        ) catch {};

        // Read the HTTP upgrade request
        var buf: [4096]u8 = undefined;
        var total: usize = 0;
        while (total < buf.len) {
            const n = stream.read(buf[total..]) catch return;
            if (n == 0) return;
            total += n;
            if (std.mem.indexOf(u8, buf[0..total], "\r\n\r\n")) |_| break;
        }

        // Extract the Sec-WebSocket-Key
        const request = buf[0..total];
        const key_header = "Sec-WebSocket-Key: ";
        const key_start = (std.mem.indexOf(u8, request, key_header) orelse return) + key_header.len;
        const key_end = std.mem.indexOf(u8, request[key_start..], "\r\n") orelse return;
        const client_key = request[key_start..][0..key_end];

        // Compute accept key using the library's utility
        var accept_key_buf: [28]u8 = undefined;
        const accept_key = ws.http.computeAcceptKey(&accept_key_buf, client_key);

        // Send 101 Switching Protocols
        var resp_buf: [256]u8 = undefined;
        const resp = std.fmt.bufPrint(&resp_buf, "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n\r\n", .{accept_key}) catch return;
        stream.writeAll(resp) catch return;

        // Block until client force-disconnects; never respond to close frames.
        // NOTE: timeout set on socket so this wont block forever if there is a bug
        _ = stream.read(&buf) catch {};
    }

    fn stop(self: *UnresponsiveServer) void {
        std.posix.close(self.listener);
        self.thread.join();
    }
};
