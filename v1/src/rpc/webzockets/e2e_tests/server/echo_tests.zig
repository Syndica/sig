const std = @import("std");

const testing = std.testing;
const servers = @import("../support/test_servers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/FdLeakDetector.zig");

test "text echo" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var handler: clients.EchoTestHandler = .{
        .send_kind = .text,
        .send_data = "hello",
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
    try testing.expectEqualSlices(u8, "hello", received_data);
}

test "binary echo" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var handler: clients.EchoTestHandler = .{
        .send_kind = .binary,
        .send_data = &[_]u8{ 0x01, 0x02, 0x03, 0xFF },
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
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03, 0xFF }, received_data);
}

test "ping/pong" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var handler: clients.EchoTestHandler = .{
        .send_kind = .ping,
        .send_data = "ping",
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
    try testing.expectEqual(.pong, received_type);
    try testing.expectEqualSlices(u8, "ping", received_data);
}

test "close handshake" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var handler: clients.CloseOnOpenHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestCloseClient.Conn = undefined;
    var client = env.initClient(clients.TestCloseClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    defer if (handler.open_called) conn.deinit();

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
}

test "multiple messages in sequence" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const messages = [_]clients.SequenceHandler.MsgSpec{
        .{ .data = "one" },
        .{ .data = "two" },
        .{ .data = "three" },
    };
    var handler: clients.SequenceHandler = .{
        .messages = &messages,
        .results = .empty,
        .allocator = testing.allocator,
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestSequenceClient.Conn = undefined;
    var client = env.initClient(clients.TestSequenceClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    defer if (handler.open_called) conn.deinit();

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expectEqual(@as(usize, 3), handler.results.items.len);
    try testing.expectEqualSlices(u8, "one", handler.results.items[0].data);
    try testing.expectEqualSlices(u8, "two", handler.results.items[1].data);
    try testing.expectEqualSlices(u8, "three", handler.results.items[2].data);
}

test "large message (>125 bytes)" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const large_msg = try testing.allocator.alloc(u8, 1000);
    defer testing.allocator.free(large_msg);
    @memset(large_msg, 'A');

    var handler: clients.EchoTestHandler = .{
        .send_kind = .binary,
        .send_data = large_msg,
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
    const received = handler.received_data orelse return error.NoData;
    try testing.expectEqual(.binary, received_type);
    try testing.expectEqual(@as(usize, 1000), received.len);
    for (received) |byte| {
        try testing.expectEqual(@as(u8, 'A'), byte);
    }
}

test "multiple concurrent connections" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    var handler1: clients.EchoTestHandler = .{
        .send_kind = .text,
        .send_data = "from_client_1",
        .allocator = testing.allocator,
    };
    defer handler1.deinit();

    var handler2: clients.EchoTestHandler = .{
        .send_kind = .text,
        .send_data = "from_client_2",
        .allocator = testing.allocator,
    };
    defer handler2.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn1: clients.TestEchoClient.Conn = undefined;
    var client1 = env.initClient(clients.TestEchoClient, &handler1, &conn1, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    defer if (handler1.open_called) conn1.deinit();

    var conn2: clients.TestEchoClient.Conn = undefined;
    var client2 = env.initClient(clients.TestEchoClient, &handler2, &conn2, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    defer if (handler2.open_called) conn2.deinit();

    try client1.connect();
    try client2.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler1.open_called);
    const received1 = handler1.received_data orelse return error.NoData;
    try testing.expectEqualSlices(u8, "from_client_1", received1);

    try testing.expect(handler2.open_called);
    const received2 = handler2.received_data orelse return error.NoData;
    try testing.expectEqualSlices(u8, "from_client_2", received2);
}
