const std = @import("std");

const testing = std.testing;
const servers = @import("../support/test_servers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/FdLeakDetector.zig");

test "raw send text (client)" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    const frames = [_]clients.RawSendOnOpenHandler.FrameSpec{
        .{ .opcode = .text, .data = "hello raw client" },
    };
    var handler: clients.RawSendOnOpenHandler = .{
        .frames = &frames,
        .results = std.ArrayList(clients.RawSendOnOpenHandler.RecvResult).init(testing.allocator),
        .allocator = testing.allocator,
        .csprng = &env.csprng,
    };
    defer handler.deinit();

    var conn: clients.TestRawSendClient.Conn = undefined;
    var client = env.initClient(clients.TestRawSendClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    defer if (handler.open_called) conn.deinit();

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expectEqual(@as(usize, 1), handler.results.items.len);
    try testing.expectEqual(.text, handler.results.items[0].msg_type);
    try testing.expectEqualSlices(u8, "hello raw client", handler.results.items[0].data);
}

test "raw send binary (client)" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    const payload = [_]u8{ 0xCA, 0xFE, 0xBA, 0xBE };
    const frames = [_]clients.RawSendOnOpenHandler.FrameSpec{
        .{ .opcode = .binary, .data = &payload },
    };
    var handler: clients.RawSendOnOpenHandler = .{
        .frames = &frames,
        .results = std.ArrayList(clients.RawSendOnOpenHandler.RecvResult).init(testing.allocator),
        .allocator = testing.allocator,
        .csprng = &env.csprng,
    };
    defer handler.deinit();

    var conn: clients.TestRawSendClient.Conn = undefined;
    var client = env.initClient(clients.TestRawSendClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    defer if (handler.open_called) conn.deinit();

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expectEqual(@as(usize, 1), handler.results.items.len);
    try testing.expectEqual(.binary, handler.results.items[0].msg_type);
    try testing.expectEqualSlices(u8, &payload, handler.results.items[0].data);
}

test "raw send batched messages (client)" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    const frames = [_]clients.RawSendOnOpenHandler.FrameSpec{
        .{ .opcode = .text, .data = "alpha" },
        .{ .opcode = .text, .data = "beta" },
        .{ .opcode = .binary, .data = &[_]u8{ 0xFF, 0x00 } },
    };
    var handler: clients.RawSendOnOpenHandler = .{
        .frames = &frames,
        .results = std.ArrayList(clients.RawSendOnOpenHandler.RecvResult).init(testing.allocator),
        .allocator = testing.allocator,
        .csprng = &env.csprng,
    };
    defer handler.deinit();

    var conn: clients.TestRawSendClient.Conn = undefined;
    var client = env.initClient(clients.TestRawSendClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    defer if (handler.open_called) conn.deinit();

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expectEqual(@as(usize, 3), handler.results.items.len);
    try testing.expectEqual(.text, handler.results.items[0].msg_type);
    try testing.expectEqualSlices(u8, "alpha", handler.results.items[0].data);
    try testing.expectEqual(.text, handler.results.items[1].msg_type);
    try testing.expectEqualSlices(u8, "beta", handler.results.items[1].data);
    try testing.expectEqual(.binary, handler.results.items[2].msg_type);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0x00 }, handler.results.items[2].data);
}
