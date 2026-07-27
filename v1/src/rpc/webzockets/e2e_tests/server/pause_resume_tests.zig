const std = @import("std");
const testing = std.testing;

const servers = @import("../support/test_servers.zig");
const server_handlers = @import("../support/server_handlers.zig");
const RawClient = @import("../support/raw_client.zig").RawClient;
const FdLeakDetector = @import("../support/FdLeakDetector.zig");
const helpers = @import("../support/test_helpers.zig");

const wait_ms: u64 = 4_000;

fn expectText(client: *RawClient, expected: []const u8) !void {
    const response = try client.waitForMessageType(.text, wait_ms);
    defer client.done(response);
    try testing.expectEqualSlices(u8, expected, response.data);
}

test "sequential processing of buffered burst" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    // Each masked text frame: 6-byte header (2 + 4 mask) + payload.
    // "a","b","c","d" = 4 × (6 + 1) = 28 bytes.
    var ctx: server_handlers.PauseUntilBufferedEchoHandler.Context = .{
        .resume_threshold = 28,
        .expected_messages = 4,
    };
    const ts = try servers.startPauseUntilBufferedEchoServer(testing.allocator, &ctx);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    var m1 = "a".*;
    var m2 = "b".*;
    var m3 = "c".*;
    var m4 = "d".*;

    try client.writeFrame(.text, &m1);
    try client.writeFrame(.text, &m2);
    try client.writeFrame(.text, &m3);
    try client.writeFrame(.text, &m4);

    try expectText(&client, "a");
    try expectText(&client, "b");
    try expectText(&client, "c");
    try expectText(&client, "d");

    try helpers.expectCloseWithCode(&client, 1000);
}

test "pause mid-stream stops dispatch then delivers on resume" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    // 4 × (6 + 1) = 28 bytes threshold.
    var mid_ctx: server_handlers.PauseMidStreamEchoHandler.Context = .{
        .resume_threshold = 28,
        .expected_messages = 4,
    };
    const ts = try servers.startPauseMidStreamEchoServer(testing.allocator, &mid_ctx);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    var m1 = "a".*;
    var m2 = "b".*;
    var m3 = "c".*;
    var m4 = "d".*;

    try client.writeFrame(.text, &m1);
    try client.writeFrame(.text, &m2);
    try client.writeFrame(.text, &m3);
    try client.writeFrame(.text, &m4);

    // Each echo arrives only after the handler resumes from onWriteComplete.
    try expectText(&client, "a");
    try expectText(&client, "b");
    try expectText(&client, "c");
    try expectText(&client, "d");

    try helpers.expectCloseWithCode(&client, 1000);
}

test "close frame while server is paused" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    // "hello" text frame: 6 + 5 = 11 bytes.
    // Close frame (code 1000, no reason): 6 + 2 = 8 bytes.
    // Total threshold: 19 bytes.
    var ctx: server_handlers.PauseUntilBufferedEchoHandler.Context = .{
        .resume_threshold = 19,
        .expected_messages = 0,
    };
    const ts = try servers.startPauseUntilBufferedEchoServer(testing.allocator, &ctx);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    var msg = "hello".*;
    try client.writeFrame(.text, &msg);
    try client.close(.{ .code = 1000 });

    // Echo should still be delivered before close handshake completes.
    try expectText(&client, "hello");
    try helpers.expectCloseWithCode(&client, 1000);
}

test "no re-entrant onMessage dispatch" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    // "a"(7) + "b"(7) + "c"(7) + "done"(10) = 31 bytes.
    var ctx: server_handlers.ReentrancyDetectHandler.Context = .{
        .resume_threshold = 31,
    };
    const ts = try servers.startReentrancyDetectServer(testing.allocator, &ctx);
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    var m1 = "a".*;
    var m2 = "b".*;
    var m3 = "c".*;
    var done = "done".*;

    try client.writeFrame(.text, &m1);
    try client.writeFrame(.text, &m2);
    try client.writeFrame(.text, &m3);
    try client.writeFrame(.text, &done);

    // Without the re-entrancy guard, pauseReads() + resumeReads() inside
    // onMessage would recursively dispatch into onMessage, triggering a
    // close with policy_violation (1008). With the guard, messages dispatch
    // sequentially and "done" triggers a normal close (1000).
    try helpers.expectCloseWithCode(&client, 1000);
}

test "buffer fills while paused (small read buffer)" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    // 256-byte read buffer. Each masked frame with 20-byte payload = 26 bytes.
    // 12 messages × 26 = 312 bytes total — exceeds the 256-byte buffer.
    // Threshold of 256 ensures we only resume once the buffer is completely
    // full and reads have been stopped (freeSpace() == 0).
    const msg_len = 20;
    const msg_count = 12;
    var ctx: server_handlers.PauseUntilBufferedEchoHandler.Context = .{
        .resume_threshold = 256,
        .expected_messages = msg_count,
    };
    const ts = try servers.startPauseUntilBufferedEchoSmallBufServer(
        testing.allocator,
        &ctx,
    );
    defer ts.stop();

    var client = try RawClient.connect(testing.allocator, ts.port);
    defer client.deinit();

    var expected: [msg_count][msg_len]u8 = undefined;
    for (0..msg_count) |i| {
        const byte = @as(u8, @truncate('A' + i));
        @memset(&expected[i], byte);

        var payload = expected[i];
        try client.writeFrame(.text, &payload);
    }

    for (0..msg_count) |i| {
        const response = try client.waitForMessageType(.text, wait_ms);
        defer client.done(response);
        try testing.expectEqual(@as(usize, msg_len), response.data.len);
        try testing.expectEqualSlices(u8, &expected[i], response.data);
    }

    try helpers.expectCloseWithCode(&client, 1000);
}
