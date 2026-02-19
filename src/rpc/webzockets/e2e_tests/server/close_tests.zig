const std = @import("std");
const testing = std.testing;

const servers = @import("../support/test_servers.zig");
const RawClient = @import("../support/raw_client.zig").RawClient;
const FdLeakDetector = @import("../support/fd_leak.zig").FdLeakDetector;
const helpers = @import("../support/test_helpers.zig");

const wait_ms: u64 = 2_000;
const poll_read_timeout_ms: u32 = 100;

test "e2e close: normal code 1000" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    var msg = "test".*;
    try client.write(&msg);

    const response = try client.waitForMessageType(.text, wait_ms);
    defer client.done(response);
    try testing.expectEqualSlices(u8, "test", response.data);

    try client.close(.{ .code = 1000 });
    try helpers.expectCloseWithCode(&client, 1000);
}

test "e2e close: custom code in registered range (3000-3999)" {
    try testCloseEcho(3500, "custom close");
}

test "e2e close: custom code in private range (4000-4999)" {
    try testCloseEcho(4999, "private close");
}

test "e2e close: server echoes close frame" {
    try testCloseEcho(1000, "bye");
}

test "e2e close: server disconnects when peer ignores close response" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    // Server echoes first message then closes.
    const ts = try servers.startCloseAfterFirstMessageServer(testing.allocator, 200);
    defer ts.stop();

    var client = try RawClient.connectEx(testing.allocator, ts.port, .{
        .read_timeout_ms = poll_read_timeout_ms,
    });
    defer client.deinit();

    // Send a message to trigger echo + server close.
    var msg = "hello".*;
    try client.write(&msg);

    // Read the echo.
    const echo = try client.waitForMessageType(.text, wait_ms);
    try testing.expectEqualSlices(u8, "hello", echo.data);
    client.done(echo);

    // Read the close frame from the server.
    const close_msg = try client.waitForCloseFrame(wait_ms);
    try testing.expectEqual(.close, close_msg.type);
    client.done(close_msg);

    // Do NOT echo the close frame — server should still disconnect promptly.
    try client.waitForClosedNoData(wait_ms);
}

test "e2e close: server sends close even when ping write is in flight" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startPingThenCloseOnOpenServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connectEx(testing.allocator, ts.port, .{
        .read_timeout_ms = poll_read_timeout_ms,
    });
    defer client.deinit();

    const ping_msg = try client.waitForMessageType(.ping, wait_ms);
    defer client.done(ping_msg);
    try testing.expectEqualSlices(u8, "hello", ping_msg.data);

    const close_msg = try client.waitForCloseFrame(wait_ms);
    defer client.done(close_msg);
    try testing.expectEqual(.close, close_msg.type);

    try testing.expect(close_msg.data.len >= 2);
    const code = std.mem.readInt(u16, close_msg.data[0..2], .big);
    try testing.expectEqual(@as(u16, 1000), code);

    try client.waitForClosedNoData(wait_ms);
}

test "e2e close: server rejects invalid close code 0 with 1002" {
    var payload = [_]u8{ 0x00, 0x00 };
    try testCloseRejection(&payload, 1002);
}

test "e2e close: server rejects reserved close code 1004 with 1002" {
    var payload = [_]u8{ 0x03, 0xEC };
    try testCloseRejection(&payload, 1002);
}

test "e2e close: server rejects API-only close code 1005 with 1002" {
    var payload = [_]u8{ 0x03, 0xED };
    try testCloseRejection(&payload, 1002);
}

test "e2e close: server rejects out-of-range close code 5000 with 1002" {
    var payload = [_]u8{ 0x13, 0x88 };
    try testCloseRejection(&payload, 1002);
}

test "e2e close: server rejects invalid UTF-8 in close reason with 1007" {
    // 0xFE is never valid in UTF-8
    var payload = [_]u8{ 0x03, 0xE8, 0xFE, 0xFF };
    try testCloseRejection(&payload, 1007);
}

test "e2e close: server rejects 1-byte close payload with 1002" {
    var payload = [_]u8{0x42};
    try testCloseRejection(&payload, 1002);
}

test "e2e close: server rejects API-only close code 1006 with 1002" {
    var payload = [_]u8{ 0x03, 0xEE };
    try testCloseRejection(&payload, 1002);
}

test "e2e close: server rejects close code 999 (below valid range) with 1002" {
    var payload = [_]u8{ 0x03, 0xE7 };
    try testCloseRejection(&payload, 1002);
}

test "e2e close: server rejects close code 2000 (gap range 1012-2999) with 1002" {
    var payload = [_]u8{ 0x07, 0xD0 };
    try testCloseRejection(&payload, 1002);
}

test "e2e close: server echoes max-length close reason (123 bytes)" {
    // Control frame max payload is 125 bytes; 2 for code leaves 123 for reason
    var reason: [123]u8 = undefined;
    @memset(&reason, 'R');
    try testCloseEcho(1000, &reason);
}

test "e2e close: server accepts close with no payload" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    var empty = [0]u8{};
    try client.writeFrame(.close, &empty);

    const response = try client.waitForCloseFrame(wait_ms);
    defer client.done(response);
}

/// Send a close frame with the given raw payload and assert the server
/// responds with the expected close code.
fn testCloseRejection(close_payload: []u8, expected_code: u16) !void {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    try client.writeFrame(.close, close_payload);
    try helpers.expectCloseWithCode(&client, expected_code);
}

/// Send a close frame with the given code and reason, and assert the server
/// echoes them back.
fn testCloseEcho(code: u16, reason: []const u8) !void {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    try client.close(.{ .code = code, .reason = reason });
    try helpers.expectCloseWithCodeAndReason(&client, code, reason);
}
