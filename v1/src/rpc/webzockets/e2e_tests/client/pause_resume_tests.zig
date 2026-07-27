const std = @import("std");
const testing = std.testing;

const servers = @import("../support/test_servers.zig");
const server_handlers = @import("../support/server_handlers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/FdLeakDetector.zig");

test "sequential processing of server burst" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    const messages = [_][]const u8{ "msg-1", "msg-2", "msg-3" };
    var send_ctx: server_handlers.SendMessagesOnOpenHandler.Context = .{ .messages = &messages };
    const ts = try servers.startSendMessagesOnOpenServer(testing.allocator, &send_ctx);
    defer ts.stop();

    // Each server-to-client text frame for "msg-N" (5 bytes payload) is 7 bytes
    // on the wire: 2-byte header (FIN+opcode, length) + 5-byte payload.
    // 3 messages × 7 bytes = 21 bytes minimum before we resume.
    var handler: clients.PauseUntilBufferedClientHandler = .{
        .allocator = testing.allocator,
        .expected_messages = messages.len,
        .resume_threshold = 21,
        .results = .empty,
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestPauseUntilBufferedClient.Conn = undefined;
    var client = env.initClient(clients.TestPauseUntilBufferedClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expect(handler.close_called);
    try testing.expectEqual(messages.len, handler.results.items.len);
    for (messages, handler.results.items) |expected, result| {
        try testing.expectEqualSlices(u8, expected, result.data);
    }

    conn.deinit();
}

test "pause mid-stream stops dispatch then delivers on resume" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    const messages = [_][]const u8{ "msg-1", "msg-2", "msg-3", "msg-4" };
    var send_ctx: server_handlers.SendMessagesOnOpenHandler.Context = .{
        .messages = &messages,
        .close_reason = null,
    };
    const ts = try servers.startSendMessagesOnOpenServer(testing.allocator, &send_ctx);
    defer ts.stop();

    // Server sends 4 unmasked text frames: "msg-1".."msg-4" (5 bytes each).
    // Each frame = 2 + 5 = 7 bytes → 4 × 7 = 28 bytes threshold.
    var handler: clients.PauseMidStreamClientHandler = .{
        .allocator = testing.allocator,
        .expected_messages = messages.len,
        .resume_threshold = 28,
        .results = .empty,
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestPauseMidStreamClient.Conn = undefined;
    var client = env.initClient(clients.TestPauseMidStreamClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expect(handler.close_called);
    try testing.expectEqual(messages.len, handler.results.items.len);
    for (messages, handler.results.items) |expected, result| {
        try testing.expectEqualSlices(u8, expected, result.data);
    }

    conn.deinit();
}

test "close while client is paused" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    const messages = [_][]const u8{"msg-1"};
    var send_ctx: server_handlers.SendMessagesOnOpenHandler.Context = .{ .messages = &messages };
    const ts = try servers.startSendMessagesOnOpenServer(testing.allocator, &send_ctx);
    defer ts.stop();

    // Server sends "msg-1" (2 + 5 = 7 bytes) then close frame with code 1000
    // + reason "done" (2 + 6 = 8 bytes). Total threshold: 15 bytes.
    var handler: clients.PauseUntilBufferedClientHandler = .{
        .allocator = testing.allocator,
        .expected_messages = 0,
        .resume_threshold = 15,
        .results = .empty,
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestPauseUntilBufferedClient.Conn = undefined;
    var client = env.initClient(clients.TestPauseUntilBufferedClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expect(handler.close_called);
    try testing.expectEqual(@as(usize, 1), handler.results.items.len);
    try testing.expectEqualSlices(u8, "msg-1", handler.results.items[0].data);

    conn.deinit();
}

test "no re-entrant onMessage dispatch" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    const messages = [_][]const u8{ "a", "b", "c", "done" };
    var send_ctx: server_handlers.SendMessagesOnOpenHandler.Context = .{ .messages = &messages };
    const ts = try servers.startSendMessagesOnOpenServer(testing.allocator, &send_ctx);
    defer ts.stop();

    // Server sends 4 unmasked text frames: "a" (3B), "b" (3B), "c" (3B), "done" (6B) = 15 bytes.
    var handler: clients.ReentrancyDetectClientHandler = .{
        .allocator = testing.allocator,
        .resume_threshold = 15,
        .results = .empty,
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestReentrancyDetectClient.Conn = undefined;
    var client = env.initClient(clients.TestReentrancyDetectClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expect(handler.close_called);
    try testing.expect(!handler.reentrant_detected);
    try testing.expectEqual(messages.len, handler.results.items.len);
    for (messages, handler.results.items) |expected, result| {
        try testing.expectEqualSlices(u8, expected, result.data);
    }

    conn.deinit();
}

test "buffer fills while paused (small read buffer)" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    var send_ctx: server_handlers.SendMessagesOnOpenHandler.Context = .{
        .messages = &servers.small_buf_slices,
    };
    const ts = try servers.startSendMessagesOnOpenServer(testing.allocator, &send_ctx);
    defer ts.stop();

    const msg_len = servers.small_buf_msg_len;
    const msg_count = servers.small_buf_msg_count;

    // 256-byte client read buffer. Server sends 12 unmasked text frames,
    // each with 20-byte payload = 22 bytes per frame. 12 × 22 = 264 bytes
    // total — exceeds the 256-byte buffer.
    // Threshold of 256 ensures we only resume once the buffer is completely
    // full and reads have been stopped (freeSpace() == 0).
    var handler: clients.PauseUntilBufferedClientHandler = .{
        .allocator = testing.allocator,
        .expected_messages = msg_count,
        .resume_threshold = 256,
        .results = .empty,
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestPauseUntilBufferedSmallBufClient.Conn = undefined;
    var client = env.initClient(clients.TestPauseUntilBufferedSmallBufClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expect(handler.close_called);
    try testing.expectEqual(@as(usize, msg_count), handler.results.items.len);

    for (0..msg_count) |i| {
        var expected: [msg_len]u8 = undefined;
        const byte = @as(u8, @truncate('A' + i));
        @memset(&expected, byte);
        try testing.expectEqualSlices(u8, &expected, handler.results.items[i].data);
    }

    conn.deinit();
}
