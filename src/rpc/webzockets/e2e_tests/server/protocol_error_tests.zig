const std = @import("std");
const ws = @import("webzockets_lib");

const testing = std.testing;
const servers = @import("../support/test_servers.zig");
const RawClient = @import("../support/raw_client.zig").RawClient;
const FdLeakDetector = @import("../support/fd_leak.zig").FdLeakDetector;
const expectCloseWithCode = @import("../support/test_helpers.zig").expectCloseWithCode;

test "e2e protocol error: unmasked client frame → 1002" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Send a text frame without the mask bit set — violates RFC 6455 §5.1
    var payload = "hello".*;
    try client.writeFrameEx(@intFromEnum(ws.Opcode.text), &payload, .{ .mask = false });

    try expectCloseWithCode(&client, 1002);
}

test "e2e protocol error: reserved opcode 0x3 → 1002" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Opcode 0x3 is reserved for future non-control frames — RFC 6455 §5.2
    var payload = "test".*;
    try client.writeFrameEx(0x3, &payload, .{});

    try expectCloseWithCode(&client, 1002);
}

test "e2e protocol error: RSV1 set without extension → 1002" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // RSV1 must be 0 unless an extension is negotiated — RFC 6455 §5.2
    var payload = "test".*;
    try client.writeFrameEx(@intFromEnum(ws.Opcode.text), &payload, .{ .rsv1 = true });

    try expectCloseWithCode(&client, 1002);
}

test "e2e protocol error: fragmented ping (FIN=0) → 1002" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Control frames must not be fragmented — RFC 6455 §5.5
    var payload = "ping".*;
    try client.writeFrameEx(@intFromEnum(ws.Opcode.ping), &payload, .{ .fin = false });

    try expectCloseWithCode(&client, 1002);
}

test "e2e protocol error: ping with 126-byte payload → 1002" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Control frame payloads must be <= 125 bytes — RFC 6455 §5.5
    var payload: [126]u8 = undefined;
    @memset(&payload, 'X');
    try client.writeFrameEx(@intFromEnum(ws.Opcode.ping), &payload, .{});

    try expectCloseWithCode(&client, 1002);
}

test "e2e protocol error: unexpected continuation frame → 1002" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Continuation without a preceding non-FIN data frame — RFC 6455 §5.4
    var payload = "data".*;
    try client.writeFrameEx(@intFromEnum(ws.Opcode.continuation), &payload, .{});

    try expectCloseWithCode(&client, 1002);
}

test "e2e protocol error: new data frame during fragmentation → 1002" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Start a fragmented message (text, FIN=0)
    var frag1 = "hello".*;
    try client.writeFrameEx(@intFromEnum(ws.Opcode.text), &frag1, .{ .fin = false });

    // Send another text frame instead of continuation — RFC 6455 §5.4
    var frag2 = "world".*;
    try client.writeFrameEx(@intFromEnum(ws.Opcode.text), &frag2, .{});

    try expectCloseWithCode(&client, 1002);
}

test "e2e protocol error: message exceeding max_message_size → 1009" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try startSmallMaxTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Send a message larger than max_message_size (128 bytes)
    var payload: [256]u8 = undefined;
    @memset(&payload, 'A');
    try client.writeFrameEx(@intFromEnum(ws.Opcode.text), &payload, .{});

    try expectCloseWithCode(&client, 1009);
}

/// Server type with small max_message_size for testing oversized messages.
const SmallMaxServer = ws.Server(
    servers.EchoHandler,
    servers.default_read_buf_size,
);
const SmallMaxTestServer = servers.ServerRunner(SmallMaxServer);

fn startSmallMaxTestServer(allocator: std.mem.Allocator) !*SmallMaxTestServer {
    const address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    return try SmallMaxTestServer.start(allocator, .{
        .address = address,
        .handler_context = {},
        .max_message_size = 128,
    });
}
