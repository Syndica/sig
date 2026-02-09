const std = @import("std");
const ws = @import("webzockets_lib");

const testing = std.testing;
const servers = @import("../support/test_servers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/fd_leak.zig").FdLeakDetector;

test "e2e: connection pool exhaustion" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try startLimitedTestServer(testing.allocator);
    defer ts.stop();

    var handler1: clients.EchoTestHandler = .{
        .send_kind = .text,
        .send_data = "still works",
        .allocator = testing.allocator,
    };
    defer handler1.deinit();

    var handler2: clients.CloseOnOpenHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn1: clients.TestEchoClient.Conn = undefined;
    var client1 = env.initClient(clients.TestEchoClient, &handler1, &conn1, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    defer if (handler1.open_called) conn1.deinit();

    var conn2: clients.TestCloseClient.Conn = undefined;
    var client2 = env.initClient(clients.TestCloseClient, &handler2, &conn2, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });
    defer if (handler2.open_called) conn2.deinit();

    try client1.connect();
    try client2.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler1.open_called);
    try testing.expectEqualSlices(u8, "still works", handler1.received_data.?);
}

/// WebSocket server type used for connection-pool exhaustion tests.
const LimitedServer = ws.Server(
    servers.EchoHandler,
    servers.default_read_buf_size,
    servers.default_pool_buf_size,
);
const LimitedTestServer = servers.ServerRunner(LimitedServer);

fn startLimitedTestServer(allocator: std.mem.Allocator) !*LimitedTestServer {
    const address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    return try LimitedTestServer.start(allocator, .{
        .address = address,
        .handler_context = {},
        .max_connections = 1,
    });
}
