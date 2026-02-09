const std = @import("std");

const testing = std.testing;
const servers = @import("../support/test_servers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/fd_leak.zig").FdLeakDetector;

test "e2e: text echo" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

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
    try testing.expectEqual(.text, handler.received_type.?);
    try testing.expectEqualSlices(u8, "hello", handler.received_data.?);
}

test "e2e: binary echo" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

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
    try testing.expectEqual(.binary, handler.received_type.?);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x02, 0x03, 0xFF }, handler.received_data.?);
}

test "e2e: ping/pong" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

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
    try testing.expectEqual(.pong, handler.received_type.?);
    try testing.expectEqualSlices(u8, "ping", handler.received_data.?);
}

test "e2e: close handshake" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

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

test "e2e: multiple messages in sequence" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try servers.startTestServer(testing.allocator);
    defer ts.stop();

    const messages = [_]clients.SequenceHandler.MsgSpec{
        .{ .data = "one" },
        .{ .data = "two" },
        .{ .data = "three" },
    };
    var handler: clients.SequenceHandler = .{
        .messages = &messages,
        .results = std.ArrayList(clients.SequenceHandler.RecvResult).init(testing.allocator),
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

test "e2e: large message (>125 bytes)" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

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
    try testing.expectEqual(.binary, handler.received_type.?);
    try testing.expectEqual(@as(usize, 1000), handler.received_data.?.len);
    for (handler.received_data.?) |byte| {
        try testing.expectEqual(@as(u8, 'A'), byte);
    }
}

test "e2e: multiple concurrent connections" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

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
    try testing.expectEqualSlices(u8, "from_client_1", handler1.received_data.?);

    try testing.expect(handler2.open_called);
    try testing.expectEqualSlices(u8, "from_client_2", handler2.received_data.?);
}
