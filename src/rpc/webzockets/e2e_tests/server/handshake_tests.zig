const std = @import("std");
const testing = std.testing;
const ws = @import("webzockets_lib");

const servers = @import("../support/test_servers.zig");
const RawClient = @import("../support/raw_client.zig").RawClient;
const FdLeakDetector = @import("../support/fd_leak_detector.zig");
const verifyServerFunctional = @import("../support/test_helpers.zig").verifyServerFunctional;

const wait_ms: u64 = 2_000;

test "malformed HTTP request (garbage bytes)" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const stream = try rawConnect(ts.port);
    defer stream.close();

    // Send garbage bytes terminated with \r\n\r\n so the server sees a
    // "complete" header block and attempts to parse it as HTTP.
    try stream.writeAll("\x00\x01\x02\x03GARBAGE\xff\xfe\r\n\r\n");

    try expectClosed(stream);
}

test "missing Upgrade header" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const stream = try rawConnect(ts.port);
    defer stream.close();

    var buf: [512]u8 = undefined;
    const request = buildRequest(&buf, .{ .include_upgrade = false });
    try stream.writeAll(request);

    try expectClosed(stream);
}

test "missing Sec-WebSocket-Key" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const stream = try rawConnect(ts.port);
    defer stream.close();

    var buf: [512]u8 = undefined;
    const request = buildRequest(&buf, .{ .include_key = false });
    try stream.writeAll(request);

    try expectClosed(stream);
}

test "wrong HTTP method (POST)" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const stream = try rawConnect(ts.port);
    defer stream.close();

    var buf: [512]u8 = undefined;
    const request = buildRequest(&buf, .{ .method = "POST" });
    try stream.writeAll(request);

    try expectClosed(stream);
}

test "unsupported WebSocket version" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const stream = try rawConnect(ts.port);
    defer stream.close();

    var buf: [512]u8 = undefined;
    const request = buildRequest(&buf, .{ .ws_version = "12" });
    try stream.writeAll(request);

    try expectClosed(stream);
}

test "incremental request (chunked with delays)" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const stream = try rawConnect(ts.port);
    defer stream.close();

    // Build a valid upgrade request, then send it in small chunks with delays
    // to exercise the incremental HeadParser path (multiple reads needed).
    var buf: [512]u8 = undefined;
    const request = buildRequest(&buf, .{});

    // Send in 3 chunks: first line, middle headers, final headers + \r\n\r\n
    const chunk1_end = std.mem.indexOf(u8, request, "\r\n").? + 2;
    const chunk2_end = chunk1_end + ((request.len - chunk1_end) / 2);

    try stream.writeAll(request[0..chunk1_end]);
    std.time.sleep(10 * std.time.ns_per_ms);

    try stream.writeAll(request[chunk1_end..chunk2_end]);
    std.time.sleep(10 * std.time.ns_per_ms);

    try stream.writeAll(request[chunk2_end..]);

    // If the server successfully parsed the incremental request, it will send
    // back a 101 Switching Protocols response.
    var response_buf: [512]u8 = undefined;
    var total_read: usize = 0;
    while (total_read < response_buf.len) {
        const n = stream.read(response_buf[total_read..]) catch break;
        if (n == 0) break;
        total_read += n;
        if (std.mem.indexOf(u8, response_buf[0..total_read], "\r\n\r\n") != null) break;
    }

    const response = response_buf[0..total_read];
    try testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 101 Switching Protocols\r\n"));
}

test "byte-by-byte request" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const stream = try rawConnect(ts.port);
    defer stream.close();

    // Send a valid upgrade request one byte at a time to stress-test
    // the incremental HeadParser with minimal feed sizes.
    var buf: [512]u8 = undefined;
    const request = buildRequest(&buf, .{});

    for (request) |byte| {
        try stream.writeAll(&.{byte});
        std.time.sleep(1 * std.time.ns_per_ms);
    }

    // Read the 101 response.
    var response_buf: [512]u8 = undefined;
    var total_read: usize = 0;
    while (total_read < response_buf.len) {
        const n = stream.read(response_buf[total_read..]) catch break;
        if (n == 0) break;
        total_read += n;
        if (std.mem.indexOf(u8, response_buf[0..total_read], "\r\n\r\n") != null) break;
    }

    const response = response_buf[0..total_read];
    try testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 101 Switching Protocols\r\n"));
}

test "bare LF headers (no \\r\\n) doesn't crash server" {
    // HeadParser accepts \n\n as end-of-headers. Send a request with \r\n on
    // the request line but bare \n on headers, terminated by \n\n. The server
    // must reject it gracefully (close the connection) without crashing.
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const stream = try rawConnect(ts.port);
    defer stream.close();

    // Request line ends with \r\n (so parseRequest finds the request line),
    // but all headers use bare \n. The \n\n terminates the head for HeadParser.
    try stream.writeAll(
        "GET / HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\n" ++
            "Upgrade: websocket\n" ++
            "Connection: Upgrade\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\n" ++
            "Sec-WebSocket-Version: 13\n" ++
            "\n",
    );

    try expectClosed(stream);

    // Verify the server is still functional after handling the malformed request.
    std.time.sleep(50 * std.time.ns_per_ms);
    try verifyServerFunctional(ts.port);
}

test "fully bare LF request (no \\r\\n at all) doesn't crash server" {
    // Everything uses bare \n — no \r\n anywhere. HeadParser sees \n\n and
    // reports finished, but the headers won't be found without \r\n line endings.
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const stream = try rawConnect(ts.port);
    defer stream.close();

    try stream.writeAll(
        "GET / HTTP/1.1\n" ++
            "Host: 127.0.0.1\n" ++
            "Upgrade: websocket\n" ++
            "Connection: Upgrade\n" ++
            "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\n" ++
            "Sec-WebSocket-Version: 13\n" ++
            "\n",
    );

    try expectClosed(stream);

    // Verify the server is still functional after handling the malformed request.
    std.time.sleep(50 * std.time.ns_per_ms);
    try verifyServerFunctional(ts.port);
}

test "partial request then disconnect" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    // Send a partial HTTP request and immediately close the connection
    {
        const stream = try rawConnect(ts.port);
        try stream.writeAll("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n");
        stream.close();
    }

    // Give the server time to clean up the aborted handshake
    std.time.sleep(50 * std.time.ns_per_ms);

    // Verify the server is still functional after the aborted handshake
    try verifyServerFunctional(ts.port);
}

test "headers exceeding read buffer size" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const stream = try rawConnect(ts.port);
    defer stream.close();

    // Build a request whose headers exceed the server's read buffer (4096 bytes).
    // The \r\n\r\n terminator won't appear within the first 4096 bytes, so the
    // server fills its buffer without finding a complete header block and
    // transitions to the failed state.
    var big_buf: [8192]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&big_buf);
    const w = fbs.writer();
    w.writeAll("GET / HTTP/1.1\r\n") catch unreachable;
    w.writeAll("Host: 127.0.0.1\r\n") catch unreachable;
    w.writeAll("X-Padding: ") catch unreachable;
    // Fill with padding until we've written well past the server buffer size
    const target = servers.default_read_buf_size + 500;
    while (fbs.pos < target) {
        w.writeByte('A') catch unreachable;
    }
    w.writeAll("\r\n") catch unreachable;
    w.writeAll("Upgrade: websocket\r\n") catch unreachable;
    w.writeAll("Connection: Upgrade\r\n") catch unreachable;
    w.writeAll("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n") catch unreachable;
    w.writeAll("Sec-WebSocket-Version: 13\r\n") catch unreachable;
    w.writeAll("\r\n") catch unreachable;

    try stream.writeAll(big_buf[0..fbs.pos]);

    try expectClosed(stream);
}

/// Connect raw TCP to the test server with a 2s read timeout.
fn rawConnect(port: u16) !std.net.Stream {
    const address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port);
    const stream = try std.net.tcpConnectToAddress(address);
    errdefer stream.close();
    const timeout = std.posix.timeval{ .sec = 2, .usec = 0 };
    try std.posix.setsockopt(
        stream.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.RCVTIMEO,
        std.mem.asBytes(&timeout),
    );
    return stream;
}

/// Read from `stream` until the server closes the connection. Returns success
/// if the connection is closed (read returns 0 or a connection error). Returns
/// `error.ConnectionNotClosed` if a 2s read timeout fires first.
fn expectClosed(stream: std.net.Stream) !void {
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = stream.read(&buf) catch |err| switch (err) {
            error.WouldBlock => return error.ConnectionNotClosed,
            else => return, // Connection broken = closed
        };
        if (n == 0) return; // Clean FIN
    }
}

test "onHandshakeFailed fires on connection pool exhaustion" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    var ctx = HandshakeFailContext{};

    const ts = try HandshakeFailTrackingTestServer.start(testing.allocator, .{
        .address = servers.localhost,
        .max_connections = 1,
        .handler_context = &ctx,
    });
    defer ts.stop();

    // First connection: fills the single connection slot.
    var client1 = try RawClient.connect(testing.allocator, ts.port);
    defer client1.deinit();

    // Second connection: handler.init() succeeds but transitionToConnection
    // fails (pool exhausted), so onHandshakeFailed should fire.
    const stream2 = try rawConnect(ts.port);
    defer stream2.close();

    // Send a valid upgrade request on the second connection.
    var buf: [512]u8 = undefined;
    const request = buildRequest(&buf, .{});
    try stream2.writeAll(request);

    // The server should close this connection since the pool is exhausted.
    try expectClosed(stream2);

    // Wait (bounded) for the server thread to run the callback.
    try ctx.called.timedWait(2 * std.time.ns_per_s);

    // Verify the first connection is still functional (server didn't crash).
    try verifyEchoOnClient(&client1);
}

test "handler without onHandshakeFailed still works" {
    // The default EchoHandler does NOT declare onHandshakeFailed.
    // Verify that pool exhaustion doesn't crash — the handler is silently
    // dropped (pre-existing behavior for handlers without the callback).
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try LimitedEchoTestServer.start(testing.allocator, .{
        .address = servers.localhost,
        .handler_context = {},
        .max_connections = 1,
    });
    defer ts.stop();

    // First connection fills the pool.
    var client1 = try RawClient.connect(testing.allocator, ts.port);
    defer client1.deinit();

    // Second connection: init succeeds, pool exhausted, no onHandshakeFailed
    // declared — should just close without crashing.
    const stream2 = try rawConnect(ts.port);
    defer stream2.close();

    var buf: [512]u8 = undefined;
    const request = buildRequest(&buf, .{});
    try stream2.writeAll(request);

    try expectClosed(stream2);

    // Verify the first connection is still functional (server didn't crash).
    try verifyEchoOnClient(&client1);
}

const HandshakeFailContext = struct {
    called: std.Thread.ResetEvent = .{},
};

/// Echo handler that tracks `onHandshakeFailed` calls via a caller-provided
/// `HandshakeFailContext` passed through `Config.handler_context`.
const HandshakeFailTrackingHandler = struct {
    pub const Context = HandshakeFailContext;

    ctx: *Context,

    pub fn init(_: ws.http.Request, context: *Context) !HandshakeFailTrackingHandler {
        return .{ .ctx = context };
    }

    pub fn onHandshakeFailed(self: *HandshakeFailTrackingHandler) void {
        // This should only ever be called once per handshake.
        if (self.ctx.called.isSet()) @panic("onHandshakeFailed called more than once");
        self.ctx.called.set();
    }

    pub fn onMessage(_: *HandshakeFailTrackingHandler, conn: anytype, message: ws.Message) void {
        switch (message.type) {
            .text => conn.sendText(@constCast(message.data)) catch return,
            .binary => conn.sendBinary(@constCast(message.data)) catch return,
            else => {},
        }
    }

    pub fn onWriteComplete(_: *HandshakeFailTrackingHandler, _: anytype) void {}
    pub fn onClose(_: *HandshakeFailTrackingHandler, _: anytype) void {}
};

const HandshakeFailTrackingServer = ws.Server(
    HandshakeFailTrackingHandler,
    servers.default_read_buf_size,
);
const HandshakeFailTrackingTestServer = servers.ServerRunner(HandshakeFailTrackingServer);

const LimitedEchoServer = ws.Server(
    servers.EchoHandler,
    servers.default_read_buf_size,
);
const LimitedEchoTestServer = servers.ServerRunner(LimitedEchoServer);

/// Send a text message through an existing RawClient and verify the echo.
/// Used to confirm the server is still functional after error scenarios
/// where the client's connection slot is already occupied.
fn verifyEchoOnClient(client: *RawClient) !void {
    var msg = "echo check".*;
    try client.write(&msg);

    const response = try client.waitForMessageType(.text, wait_ms);
    defer client.done(response);
    try testing.expectEqualSlices(u8, "echo check", response.data);
}

/// Options for building a crafted HTTP upgrade request.
const RequestOpts = struct {
    method: []const u8 = "GET",
    path: []const u8 = "/",
    http_version: []const u8 = "HTTP/1.1",
    include_host: bool = true,
    include_upgrade: bool = true,
    include_connection: bool = true,
    include_key: bool = true,
    ws_version: []const u8 = "13",
    include_ws_version: bool = true,
};

/// Build an HTTP upgrade request into `buf` with selective header omission.
fn buildRequest(buf: []u8, opts: RequestOpts) []const u8 {
    var fbs = std.io.fixedBufferStream(buf);
    const w = fbs.writer();
    w.print("{s} {s} {s}\r\n", .{ opts.method, opts.path, opts.http_version }) catch unreachable;
    if (opts.include_host) w.writeAll("Host: 127.0.0.1\r\n") catch unreachable;
    if (opts.include_upgrade) w.writeAll("Upgrade: websocket\r\n") catch unreachable;
    if (opts.include_connection) w.writeAll("Connection: Upgrade\r\n") catch unreachable;
    if (opts.include_key) {
        w.writeAll("Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n") catch unreachable;
    }
    if (opts.include_ws_version) {
        w.print("Sec-WebSocket-Version: {s}\r\n", .{opts.ws_version}) catch unreachable;
    }
    w.writeAll("\r\n") catch unreachable;
    return buf[0..fbs.pos];
}
