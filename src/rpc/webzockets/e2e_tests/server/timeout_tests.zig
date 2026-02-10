const std = @import("std");
const testing = std.testing;

const servers = @import("../support/test_servers.zig");
const RawClient = @import("../support/raw_client.zig").RawClient;
const FdLeakDetector = @import("../support/fd_leak.zig").FdLeakDetector;

test "close timeout: server disconnects when peer ignores close response" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    // Server echoes first message then closes; close timeout is 200ms
    const ts = try servers.startCloseAfterFirstMessageServer(testing.allocator, 200);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Send a message to trigger echo + server close
    var msg = "hello".*;
    try client.write(&msg);

    // Read the echo
    const echo = (try client.read()) orelse return error.NoResponse;
    try testing.expectEqualSlices(u8, "hello", echo.data);
    client.done(echo);

    // Read the close frame from the server
    const close_msg = (try client.read()) orelse return error.NoResponse;
    try testing.expectEqual(.close, close_msg.type);
    client.done(close_msg);

    // Do NOT echo the close frame — just wait for the server to force disconnect
    // The close timeout is 200ms, and the raw client has a 500ms read timeout,
    // so the server should disconnect well before the read times out.
    switch (try client.readResult()) {
        .closed => {},
        .timeout => return error.ExpectedDisconnect,
        .message => |msg2| {
            client.done(msg2);
            return error.UnexpectedData;
        },
    }
}

test "idle timeout: server closes idle connection" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startEchoServerWithTimeouts(testing.allocator, 200, 200);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Do nothing after handshake — wait for the server to send a close frame
    const close_msg = (try client.read()) orelse return error.NoResponse;
    defer client.done(close_msg);
    try testing.expectEqual(.close, close_msg.type);

    // Verify the close code is 1001 (going_away)
    try testing.expect(close_msg.data.len >= 2);
    const code = std.mem.readInt(u16, close_msg.data[0..2], .big);
    try testing.expectEqual(@as(u16, 1001), code);

    // Echo the close frame to complete the handshake cleanly
    try client.close(.{ .code = 1001 });

    // Verify TCP connection is closed (distinguish close from read timeout)
    switch (try client.readResult()) {
        .closed => {},
        .timeout => return error.ExpectedDisconnect,
        .message => |msg2| {
            client.done(msg2);
            return error.UnexpectedData;
        },
    }
}

test "idle timeout: activity resets timer" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    // Worst-case close arrives 2 × idle_timeout after last message,
    // so keep 2 × 200ms = 400ms under the 500ms read timeout.
    const ts = try servers.startEchoServerWithTimeouts(testing.allocator, 200, 5000);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Send messages at 50ms intervals for ~500ms, well past idle timeout
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        std.time.sleep(50 * std.time.ns_per_ms);
        var msg = "ping".*;
        try client.write(&msg);

        const echo = (try client.read()) orelse return error.NoResponse;
        try testing.expectEqualSlices(u8, "ping", echo.data);
        client.done(echo);
    }

    // Wait for idle timeout close
    const close_msg = (try client.read()) orelse return error.NoResponse;
    defer client.done(close_msg);
    try testing.expectEqual(.close, close_msg.type);

    // Verify the close code is 1001 (going_away)
    try testing.expect(close_msg.data.len >= 2);
    const code = std.mem.readInt(u16, close_msg.data[0..2], .big);
    try testing.expectEqual(@as(u16, 1001), code);

    // Echo close to complete handshake
    try client.close(.{ .code = 1001 });
}

test "idle timeout into close timeout" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startEchoServerWithTimeouts(testing.allocator, 200, 200);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Do nothing — wait for idle timeout close frame
    const close_msg = (try client.read()) orelse return error.NoResponse;
    defer client.done(close_msg);
    try testing.expectEqual(.close, close_msg.type);

    // Do NOT echo the close frame — let the close timeout fire
    // The close timeout is 200ms, and the raw client has a 500ms read timeout
    switch (try client.readResult()) {
        .closed => {},
        .timeout => return error.ExpectedDisconnect,
        .message => |msg2| {
            client.done(msg2);
            return error.UnexpectedData;
        },
    }
}

test "close in onOpen with idle timeout configured" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    // Server calls close() in onOpen. idle_timeout_ms is configured, which
    // previously would overwrite the close timer started by close(). The
    // close timeout (200ms) should apply, not the idle timeout (5000ms).
    const ts = try servers.startCloseOnOpenServerWithTimeouts(testing.allocator, 5000, 200);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Server closes immediately on open — read the close frame
    const close_msg = (try client.read()) orelse return error.NoResponse;
    defer client.done(close_msg);
    try testing.expectEqual(.close, close_msg.type);
    try testing.expect(close_msg.data.len >= 2);
    const code = std.mem.readInt(u16, close_msg.data[0..2], .big);
    try testing.expectEqual(@as(u16, 1000), code);

    // Do NOT echo the close frame — let the close timeout fire.
    // The close timeout is 200ms and raw client read timeout is 500ms,
    // so if the idle timeout (5000ms) were used instead, this would hang.
    switch (try client.readResult()) {
        .closed => {},
        .timeout => return error.ExpectedDisconnect,
        .message => |msg| {
            client.done(msg);
            return error.UnexpectedData;
        },
    }
}

test "normal close still works with timeouts enabled" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startEchoServerWithTimeouts(testing.allocator, 500, 500);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Send a message to verify connection works
    var msg = "test".*;
    try client.write(&msg);

    const echo = (try client.read()) orelse return error.NoResponse;
    try testing.expectEqualSlices(u8, "test", echo.data);
    client.done(echo);

    // Initiate a normal close handshake (peer-initiated)
    try client.close(.{ .code = 1000, .reason = "goodbye" });

    // Read the server's close echo
    const close_msg = (try client.read()) orelse return error.NoResponse;
    defer client.done(close_msg);
    try testing.expectEqual(.close, close_msg.type);
    try testing.expect(close_msg.data.len >= 2);
    const code = std.mem.readInt(u16, close_msg.data[0..2], .big);
    try testing.expectEqual(@as(u16, 1000), code);
}
