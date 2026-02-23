const std = @import("std");
const ws = @import("webzockets_lib");
const testing = std.testing;

const servers = @import("../support/test_servers.zig");
const RawClient = @import("../support/raw_client.zig").RawClient;
const FdLeakDetector = @import("../support/FdLeakDetector.zig");

const wait_ms: u64 = 2_000;

test "text message in 2 fragments" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Fragment 1: text FIN=0 "Hel"
    var frag1 = "Hel".*;
    try client.writeFrameEx(TEXT, &frag1, .{ .fin = false });

    // Fragment 2: continuation FIN=1 "lo"
    var frag2 = "lo".*;
    try client.writeFrameEx(CONTINUATION, &frag2, .{});

    const response = try client.waitForMessageType(.text, wait_ms);
    defer client.done(response);
    try testing.expectEqualSlices(u8, "Hello", response.data);
}

test "text message in 6 fragments" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    const parts = [_][]const u8{ "This ", "is ", "a ", "frag", "mented ", "message" };
    const expected = "This is a fragmented message";

    // First fragment: text FIN=0
    var buf0: [5]u8 = undefined;
    @memcpy(&buf0, parts[0]);
    try client.writeFrameEx(TEXT, &buf0, .{ .fin = false });

    // Middle fragments: continuation FIN=0
    inline for (1..5) |i| {
        var buf: [parts[i].len]u8 = undefined;
        @memcpy(&buf, parts[i]);
        try client.writeFrameEx(CONTINUATION, &buf, .{ .fin = false });
    }

    // Final fragment: continuation FIN=1
    var buf_last: [7]u8 = undefined;
    @memcpy(&buf_last, parts[5]);
    try client.writeFrameEx(CONTINUATION, &buf_last, .{});

    const response = try client.waitForMessageType(.text, wait_ms);
    defer client.done(response);
    try testing.expectEqualSlices(u8, expected, response.data);
}

test "binary message in 2 fragments" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Fragment 1: binary FIN=0
    var frag1 = [_]u8{ 0x01, 0x02, 0x03 };
    try client.writeFrameEx(BINARY, &frag1, .{ .fin = false });

    // Fragment 2: continuation FIN=1
    var frag2 = [_]u8{ 0x04, 0x05 };
    try client.writeFrameEx(CONTINUATION, &frag2, .{});

    const response = try client.waitForMessageType(.binary, wait_ms);
    defer client.done(response);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 }, response.data);
}

test "ping interleaved during fragmentation" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Fragment 1: text FIN=0 "Hel"
    var frag1 = "Hel".*;
    try client.writeFrameEx(TEXT, &frag1, .{ .fin = false });

    // Interleaved ping
    var ping_payload = "ping".*;
    try client.writeFrameEx(PING, &ping_payload, .{});

    // Fragment 2: continuation FIN=1 "lo"
    var frag2 = "lo".*;
    try client.writeFrameEx(CONTINUATION, &frag2, .{});

    // Should get the pong first (server dispatches control frames immediately)
    const pong = try client.waitForMessageType(.pong, wait_ms);
    defer client.done(pong);
    try testing.expectEqualSlices(u8, "ping", pong.data);

    // Then the reassembled text message
    const response = try client.waitForMessageType(.text, wait_ms);
    defer client.done(response);
    try testing.expectEqualSlices(u8, "Hello", response.data);
}

test "non-empty first, empty final continuation" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Fragment 1: text FIN=0 "data"
    var frag1 = "data".*;
    try client.writeFrameEx(TEXT, &frag1, .{ .fin = false });

    // Fragment 2: continuation FIN=1, empty payload
    var frag2 = [0]u8{};
    try client.writeFrameEx(CONTINUATION, &frag2, .{});

    const response = try client.waitForMessageType(.text, wait_ms);
    defer client.done(response);
    try testing.expectEqualSlices(u8, "data", response.data);
}

test "empty first, non-empty final continuation" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Fragment 1: text FIN=0, empty payload
    var frag1 = [0]u8{};
    try client.writeFrameEx(TEXT, &frag1, .{ .fin = false });

    // Fragment 2: continuation FIN=1 "data"
    var frag2 = "data".*;
    try client.writeFrameEx(CONTINUATION, &frag2, .{});

    const response = try client.waitForMessageType(.text, wait_ms);
    defer client.done(response);
    try testing.expectEqualSlices(u8, "data", response.data);
}

test "all-empty fragments produce empty message" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    // Fragment 1: text FIN=0, empty
    var frag1 = [0]u8{};
    try client.writeFrameEx(TEXT, &frag1, .{ .fin = false });

    // Fragment 2: continuation FIN=1, empty
    var frag2 = [0]u8{};
    try client.writeFrameEx(CONTINUATION, &frag2, .{});

    const response = try client.waitForMessageType(.text, wait_ms);
    defer client.done(response);
    try testing.expectEqual(@as(usize, 0), response.data.len);
}

test "8KB message across 4 fragments" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    // 8KB response needs a larger read buffer than the default 4096
    var client = try RawClient.connectEx(
        testing.allocator,
        ts.port,
        .{ .read_buf_size = 16 * 1024 },
    );
    defer client.deinit();

    // 8192 bytes total, split into 4 × 2048-byte fragments
    const fragment_size = 2048;
    const num_fragments = 4;
    const total_size = fragment_size * num_fragments;

    // Build expected payload: each fragment filled with its index byte
    var expected: [total_size]u8 = undefined;
    for (0..num_fragments) |i| {
        @memset(expected[i * fragment_size ..][0..fragment_size], @as(u8, @truncate(i + 'A')));
    }

    // Send fragments
    for (0..num_fragments) |i| {
        var buf: [fragment_size]u8 = undefined;
        @memcpy(&buf, expected[i * fragment_size ..][0..fragment_size]);

        const opcode: u4 = if (i == 0) TEXT else CONTINUATION;
        const is_last = (i == num_fragments - 1);
        try client.writeFrameEx(opcode, &buf, .{ .fin = is_last });
    }

    // Note: assumes the echo server responds with a single unfragmented frame.
    // Fragmented responses would need multiple waits.
    const response = try client.waitForMessageType(.text, wait_ms);
    defer client.done(response);
    try testing.expectEqual(@as(usize, total_size), response.data.len);
    try testing.expectEqualSlices(u8, &expected, response.data);
}

test "256KB message across 64 fragments" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    // 256KB response needs a much larger read buffer
    var client = try RawClient.connectEx(
        testing.allocator,
        ts.port,
        .{ .read_buf_size = 512 * 1024 },
    );
    defer client.deinit();

    // 262144 bytes total, split into 64 × 4096-byte fragments
    const fragment_size = 4096;
    const num_fragments = 64;
    const total_size = fragment_size * num_fragments;

    // Build expected payload: repeating pattern (heap-allocated to avoid 256KB on the stack)
    const expected = try testing.allocator.alloc(u8, total_size);
    defer testing.allocator.free(expected);
    for (0..total_size) |i| {
        expected[i] = @as(u8, @truncate(i));
    }

    // Send fragments
    for (0..num_fragments) |i| {
        var buf: [fragment_size]u8 = undefined;
        @memcpy(&buf, expected[i * fragment_size ..][0..fragment_size]);

        const opcode: u4 = if (i == 0) BINARY else CONTINUATION;
        const is_last = (i == num_fragments - 1);
        try client.writeFrameEx(opcode, &buf, .{ .fin = is_last });
    }

    // Note: assumes the echo server responds with a single unfragmented frame.
    // Fragmented responses would need multiple waits.
    const response = try client.waitForMessageType(.binary, wait_ms);
    defer client.done(response);
    try testing.expectEqual(@as(usize, total_size), response.data.len);
    try testing.expectEqualSlices(u8, expected, response.data);
}

const Opcode = ws.Opcode;
const TEXT: u4 = @intFromEnum(Opcode.text);
const BINARY: u4 = @intFromEnum(Opcode.binary);
const CONTINUATION: u4 = @intFromEnum(Opcode.continuation);
const PING: u4 = @intFromEnum(Opcode.ping);
