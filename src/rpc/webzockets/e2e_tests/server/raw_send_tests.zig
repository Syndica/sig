const std = @import("std");

const testing = std.testing;
const servers = @import("../support/test_servers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/fd_leak_detector.zig");
const server_handlers = @import("../support/server_handlers.zig");

test "raw send text" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const frames = [_]server_handlers.RawSendOnOpenHandler.FrameSpec{
        .{ .opcode = .text, .data = "hello raw" },
    };
    var ctx: server_handlers.RawSendOnOpenHandler.Context = .{ .frames = &frames };
    const ts = try servers.startRawSendServer(testing.allocator, &ctx);
    defer ts.stop();

    var handler: clients.EchoTestHandler = .{
        .allocator = testing.allocator,
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestEchoClient.Conn = undefined;
    var client = env.initClient(clients.TestEchoClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    defer if (handler.open_called) conn.deinit();

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    const received_type = handler.received_type orelse return error.NoData;
    const received_data = handler.received_data orelse return error.NoData;
    try testing.expectEqual(.text, received_type);
    try testing.expectEqualSlices(u8, "hello raw", received_data);
}

test "raw send binary" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const payload = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    const frames = [_]server_handlers.RawSendOnOpenHandler.FrameSpec{
        .{ .opcode = .binary, .data = &payload },
    };
    var ctx: server_handlers.RawSendOnOpenHandler.Context = .{ .frames = &frames };
    const ts = try servers.startRawSendServer(testing.allocator, &ctx);
    defer ts.stop();

    var handler: clients.EchoTestHandler = .{
        .allocator = testing.allocator,
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestEchoClient.Conn = undefined;
    var client = env.initClient(clients.TestEchoClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    defer if (handler.open_called) conn.deinit();

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    const received_type = handler.received_type orelse return error.NoData;
    const received_data = handler.received_data orelse return error.NoData;
    try testing.expectEqual(.binary, received_type);
    try testing.expectEqualSlices(u8, &payload, received_data);
}

test "raw send 16-bit length" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const large_payload = try testing.allocator.alloc(u8, 300);
    defer testing.allocator.free(large_payload);
    @memset(large_payload, 'B');

    const frames = [_]server_handlers.RawSendOnOpenHandler.FrameSpec{
        .{ .opcode = .binary, .data = large_payload },
    };
    var ctx: server_handlers.RawSendOnOpenHandler.Context = .{ .frames = &frames };
    const ts = try servers.startRawSendServer(testing.allocator, &ctx);
    defer ts.stop();

    var handler: clients.EchoTestHandler = .{
        .allocator = testing.allocator,
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestEchoClient.Conn = undefined;
    var client = env.initClient(clients.TestEchoClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    defer if (handler.open_called) conn.deinit();

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    const received_type = handler.received_type orelse return error.NoData;
    const received_data = handler.received_data orelse return error.NoData;
    try testing.expectEqual(.binary, received_type);
    try testing.expectEqual(@as(usize, 300), received_data.len);
    for (received_data) |byte| {
        try testing.expectEqual(@as(u8, 'B'), byte);
    }
}

test "raw send batched messages" {
    const fd_check = FdLeakDetector.baseline();
    defer std.testing.expect(fd_check.check() == .ok) catch @panic("FD leak");

    const frames = [_]server_handlers.RawSendOnOpenHandler.FrameSpec{
        .{ .opcode = .text, .data = "first" },
        .{ .opcode = .text, .data = "second" },
        .{ .opcode = .binary, .data = &[_]u8{ 0x01, 0x02, 0x03 } },
    };
    var ctx: server_handlers.RawSendOnOpenHandler.Context = .{ .frames = &frames };
    const ts = try servers.startRawSendServer(testing.allocator, &ctx);
    defer ts.stop();

    // Use PauseUntilBufferedClientHandler to collect all messages
    var handler: clients.PauseUntilBufferedClientHandler = .{
        .allocator = testing.allocator,
        .expected_messages = 3,
        .resume_threshold = 1, // resume immediately — server sends everything at once
        .results = std.ArrayList(
            clients.PauseUntilBufferedClientHandler.RecvResult,
        ).init(testing.allocator),
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestPauseUntilBufferedClient.Conn = undefined;
    var client = env.initClient(clients.TestPauseUntilBufferedClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    defer if (handler.open_called) conn.deinit();

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expectEqual(@as(usize, 3), handler.results.items.len);
    try testing.expectEqualSlices(u8, "first", handler.results.items[0].data);
    try testing.expectEqualSlices(u8, "second", handler.results.items[1].data);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03 }, handler.results.items[2].data);
}
