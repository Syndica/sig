const std = @import("std");
const testing = std.testing;

const http = @import("webzockets_lib").http;
const servers = @import("../support/test_servers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/fd_leak.zig").FdLeakDetector;

test "connection to non-existent server" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    // Use an ephemeral port that nothing is listening on.
    // Bind a socket to get an OS-assigned port, then close it immediately.
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    try std.posix.bind(sock, @ptrCast(&addr.any), addr.getOsSockLen());
    var bound_addr: std.posix.sockaddr.storage = undefined;
    var addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(bound_addr));
    try std.posix.getsockname(sock, @ptrCast(&bound_addr), &addr_len);
    const sa4: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&bound_addr));
    const unused_port = std.mem.bigToNative(u16, sa4.port);
    std.posix.close(sock);

    var handler: clients.ConnectFailHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestConnectFailClient.Conn = undefined;
    var client = env.initClient(clients.TestConnectFailClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, unused_port),
    });

    try client.connect();
    try env.loop.run(.until_done);

    // Connection should have failed — onOpen should NOT have been called
    try testing.expect(!handler.open_called);
    // onSocketClose should have been called
    try testing.expect(handler.socket_close_called);
}

test "connection refused by server (handler rejects)" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startRejectServer(testing.allocator);
    defer ts.stop();

    var handler: clients.ConnectFailHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestConnectFailClient.Conn = undefined;
    var client = env.initClient(clients.TestConnectFailClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });

    try client.connect();
    try env.loop.run(.until_done);

    // Server rejected the upgrade — onOpen should NOT have been called
    try testing.expect(!handler.open_called);
    // onSocketClose should have been called (handshake failure)
    try testing.expect(handler.socket_close_called);
}

test "10 concurrent clients to same server" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const num_clients = 10;

    var handlers: [num_clients]clients.EchoTestHandler = undefined;
    var conns: [num_clients]clients.TestEchoClient.Conn = undefined;
    var client_instances: [num_clients]clients.TestEchoClient = undefined;

    // Initialize all handlers with unique messages
    var msg_bufs: [num_clients][16]u8 = undefined;
    for (0..num_clients) |i| {
        const msg = std.fmt.bufPrint(&msg_bufs[i], "client_{d}", .{i}) catch unreachable;
        handlers[i] = .{
            .send_kind = .text,
            .send_data = msg,
            .allocator = testing.allocator,
        };
    }
    defer for (&handlers) |*h| h.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    // Create and connect all clients
    for (0..num_clients) |i| {
        client_instances[i] = env.initClient(clients.TestEchoClient, &handlers[i], &conns[i], .{
            .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
        });
        try client_instances[i].connect();
    }

    try env.loop.run(.until_done);

    // Verify all clients connected and received their echoed messages
    for (0..num_clients) |i| {
        defer if (handlers[i].open_called) conns[i].deinit();
        try testing.expect(handlers[i].open_called);
        const expected = std.fmt.bufPrint(&msg_bufs[i], "client_{d}", .{i}) catch unreachable;
        const received_data = handlers[i].received_data orelse return error.NoData;
        try testing.expectEqualSlices(u8, expected, received_data);
    }
}

test "bare LF response doesn't crash client" {
    // A malicious/broken server sends a 101 response where the status line
    // uses \r\n but headers use bare \n, terminated by \n\n. The client must
    // reject gracefully without crashing.
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const fake = try startWithResponseFn(buildBareLfResponse);
    defer fake.stop();

    var handler: clients.ConnectFailHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestConnectFailClient.Conn = undefined;
    var client = env.initClient(clients.TestConnectFailClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, fake.port),
    });

    try client.connect();
    try env.loop.run(.until_done);

    // The handshake should have failed — onOpen must NOT have been called.
    try testing.expect(!handler.open_called);
    // onSocketClose should have been called (handshake failure path).
    try testing.expect(handler.socket_close_called);
}

test "fully bare LF response (no \\r\\n at all) doesn't crash client" {
    // Same as above but the entire response uses bare \n — no \r\n anywhere.
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const fake = try startWithResponseFn(buildFullyBareLfResponse);
    defer fake.stop();

    var handler: clients.ConnectFailHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestConnectFailClient.Conn = undefined;
    var client = env.initClient(clients.TestConnectFailClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, fake.port),
    });

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(!handler.open_called);
    try testing.expect(handler.socket_close_called);
}

/// Build a 101 response with \r\n on the status line but bare \n on headers.
fn buildBareLfResponse(buf: []u8, accept_key: []const u8) []const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    w.writeAll("HTTP/1.1 101 Switching Protocols\r\n") catch unreachable;
    w.writeAll("Upgrade: websocket\n") catch unreachable;
    w.writeAll("Connection: Upgrade\n") catch unreachable;
    w.print("Sec-WebSocket-Accept: {s}\n", .{accept_key}) catch unreachable;
    w.writeAll("\n") catch unreachable;
    return buf[0..fbs.pos];
}

/// Build a 101 response where the entire response uses bare \n (no \r\n at all).
fn buildFullyBareLfResponse(buf: []u8, accept_key: []const u8) []const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    w.writeAll("HTTP/1.1 101 Switching Protocols\n") catch unreachable;
    w.writeAll("Upgrade: websocket\n") catch unreachable;
    w.writeAll("Connection: Upgrade\n") catch unreachable;
    w.print("Sec-WebSocket-Accept: {s}\n", .{accept_key}) catch unreachable;
    w.writeAll("\n") catch unreachable;
    return buf[0..fbs.pos];
}

const FakeServer = struct {
    listener: std.posix.socket_t,
    port: u16,
    thread: std.Thread,

    fn stop(self: *const FakeServer) void {
        std.posix.close(self.listener);
        self.thread.join();
    }
};

/// Shared implementation: start a TCP listener on an ephemeral port and spawn
/// a background thread that accepts one connection, reads the client's upgrade
/// request to extract Sec-WebSocket-Key, then responds using `responseFn`.
fn startWithResponseFn(comptime responseFn: fn ([]u8, []const u8) []const u8) !FakeServer {
    const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    const listener = std.posix.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0) catch
        @panic("failed to create socket");
    std.posix.bind(listener, @ptrCast(&addr.any), addr.getOsSockLen()) catch
        @panic("failed to bind");
    std.posix.listen(listener, 1) catch @panic("failed to listen");

    // Get the assigned port.
    var bound_addr: std.posix.sockaddr.storage = undefined;
    var addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(bound_addr));
    std.posix.getsockname(listener, @ptrCast(&bound_addr), &addr_len) catch
        @panic("failed to getsockname");
    const sa4: *const std.posix.sockaddr.in = @ptrCast(@alignCast(&bound_addr));
    const port = std.mem.bigToNative(u16, sa4.port);

    const thread = std.Thread.spawn(.{}, acceptAndRespond, .{ listener, responseFn }) catch
        @panic("failed to spawn thread");

    return FakeServer{ .listener = listener, .port = port, .thread = thread };
}

/// Thread function: accept one connection, read the upgrade request, extract
/// the Sec-WebSocket-Key, compute the accept key, send the response, then close.
fn acceptAndRespond(
    listener: std.posix.socket_t,
    comptime responseFn: fn ([]u8, []const u8) []const u8,
) void {
    var client_addr: std.posix.sockaddr.storage = undefined;
    var client_addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(client_addr));
    const conn_fd = std.posix.accept(
        listener,
        @ptrCast(&client_addr),
        &client_addr_len,
        0,
    ) catch return;
    defer std.posix.close(conn_fd);
    const stream = std.net.Stream{ .handle = conn_fd };

    // Read the client's upgrade request.
    var req_buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < req_buf.len) {
        const n = stream.read(req_buf[total..]) catch return;
        if (n == 0) return;
        total += n;
        if (std.mem.indexOf(u8, req_buf[0..total], "\r\n\r\n") != null) break;
    }

    // Extract Sec-WebSocket-Key from the request.
    const key = extractWebSocketKey(req_buf[0..total]) orelse return;

    // Compute the accept key.
    var accept_buf: [28]u8 = undefined;
    const accept_key = http.computeAcceptKey(&accept_buf, key);

    // Build and send the bare-LF response.
    var resp_buf: [512]u8 = undefined;
    const response = responseFn(&resp_buf, accept_key);
    stream.writeAll(response) catch return;
}

/// Extract the Sec-WebSocket-Key header value from a raw HTTP request.
fn extractWebSocketKey(request: []const u8) ?[]const u8 {
    const needle = "Sec-WebSocket-Key: ";
    const start = std.mem.indexOf(u8, request, needle) orelse return null;
    const value_start = start + needle.len;
    const remaining = request[value_start..];
    const end = std.mem.indexOf(u8, remaining, "\r\n") orelse return null;
    return remaining[0..end];
}
