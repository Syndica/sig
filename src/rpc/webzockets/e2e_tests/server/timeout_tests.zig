const std = @import("std");
const testing = std.testing;

const servers = @import("../support/test_servers.zig");
const RawClient = @import("../support/raw_client.zig").RawClient;
const FdLeakDetector = @import("../support/fd_leak.zig").FdLeakDetector;

const poll_read_timeout_ms: u32 = 100;
const close_deadline_ms: u64 = 2_000;

test "idle timeout: server closes idle connection" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startEchoServerWithTimeouts(testing.allocator, 200, 200);
    defer ts.stop();

    var client = try RawClient.connectEx(testing.allocator, ts.port, .{
        .read_timeout_ms = poll_read_timeout_ms,
    });
    defer client.deinit();

    // Do nothing after handshake — wait for the server to send a close frame
    const close_msg = try client.waitForCloseFrame(close_deadline_ms);
    defer client.done(close_msg);
    try testing.expectEqual(.close, close_msg.type);

    // Verify the close code is 1001 (going_away)
    try testing.expect(close_msg.data.len >= 2);
    const code = std.mem.readInt(u16, close_msg.data[0..2], .big);
    try testing.expectEqual(@as(u16, 1001), code);

    // Server disconnects after writing close.
    try client.waitForClosedNoData(close_deadline_ms);
}

test "idle timeout: activity resets timer" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    // Worst-case close arrives 2 × idle_timeout after last message.
    const ts = try servers.startEchoServerWithTimeouts(testing.allocator, 200, 200);
    defer ts.stop();

    var client = try RawClient.connectEx(testing.allocator, ts.port, .{
        .read_timeout_ms = poll_read_timeout_ms,
    });
    defer client.deinit();

    // Send messages at 50ms intervals for ~500ms, well past idle timeout
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        std.time.sleep(50 * std.time.ns_per_ms);
        var msg = "ping".*;
        try client.write(&msg);

        const echo = try client.waitForMessageType(.text, close_deadline_ms);
        try testing.expectEqualSlices(u8, "ping", echo.data);
        client.done(echo);
    }

    // Wait for idle timeout close
    const close_msg = try client.waitForCloseFrame(close_deadline_ms);
    defer client.done(close_msg);
    try testing.expectEqual(.close, close_msg.type);

    // Verify the close code is 1001 (going_away)
    try testing.expect(close_msg.data.len >= 2);
    const code = std.mem.readInt(u16, close_msg.data[0..2], .big);
    try testing.expectEqual(@as(u16, 1001), code);

    // Server disconnects after writing close.
    try client.waitForClosedNoData(close_deadline_ms);
}

test "idle timeout: peer ignoring close still disconnects" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startEchoServerWithTimeouts(testing.allocator, 200, 200);
    defer ts.stop();

    var client = try RawClient.connectEx(testing.allocator, ts.port, .{
        .read_timeout_ms = poll_read_timeout_ms,
    });
    defer client.deinit();

    // Do nothing — wait for idle timeout close frame
    const close_msg = try client.waitForCloseFrame(close_deadline_ms);
    defer client.done(close_msg);
    try testing.expectEqual(.close, close_msg.type);

    // Do NOT echo the close frame — server should still disconnect promptly.
    try client.waitForClosedNoData(close_deadline_ms);
}

test "close in onOpen with idle timeout configured" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    // Server calls close() in onOpen. idle_timeout_ms is configured, but
    // close in onOpen should still disconnect promptly.
    const ts = try servers.startCloseOnOpenServerWithTimeouts(testing.allocator, 5000, 200);
    defer ts.stop();

    var client = try RawClient.connectEx(testing.allocator, ts.port, .{
        .read_timeout_ms = poll_read_timeout_ms,
    });
    defer client.deinit();

    // Server closes immediately on open — read the close frame
    const close_msg = try client.waitForCloseFrame(close_deadline_ms);
    defer client.done(close_msg);
    try testing.expectEqual(.close, close_msg.type);
    try testing.expect(close_msg.data.len >= 2);
    const code = std.mem.readInt(u16, close_msg.data[0..2], .big);
    try testing.expectEqual(@as(u16, 1000), code);

    // Do NOT echo the close frame — server should still disconnect promptly.
    try client.waitForClosedNoData(close_deadline_ms);
}

test "normal close still works with idle timeout enabled" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startEchoServerWithTimeouts(testing.allocator, 500, 500);
    defer ts.stop();

    var client = try RawClient.connectEx(testing.allocator, ts.port, .{
        .read_timeout_ms = poll_read_timeout_ms,
    });
    defer client.deinit();

    // Send a message to verify connection works
    var msg = "test".*;
    try client.write(&msg);

    const echo = try client.waitForMessageType(.text, close_deadline_ms);
    try testing.expectEqualSlices(u8, "test", echo.data);
    client.done(echo);

    // Initiate a normal close handshake (peer-initiated)
    try client.close(.{ .code = 1000, .reason = "goodbye" });

    // Read the server's close echo
    const close_msg = try client.waitForCloseFrame(close_deadline_ms);
    defer client.done(close_msg);
    try testing.expectEqual(.close, close_msg.type);
    try testing.expect(close_msg.data.len >= 2);
    const code = std.mem.readInt(u16, close_msg.data[0..2], .big);
    try testing.expectEqual(@as(u16, 1000), code);
}
