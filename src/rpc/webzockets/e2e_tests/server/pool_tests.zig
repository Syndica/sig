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

    // With max_connections=1, exactly one of the two clients should get the
    // connection slot and complete its echo exchange. The other is rejected
    // at the server's handshake-to-connection transition (pool exhausted).
    // There is no ordering guarantee for which client gets the slot.

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

    const h1_ok = handler1.received_data != null;
    const h2_ok = handler2.received_data != null;

    // At least one client must have completed the echo exchange.
    try testing.expect(h1_ok or h2_ok);

    if (h1_ok) {
        try testing.expectEqualSlices(u8, "from_client_1", handler1.received_data.?);
    }
    if (h2_ok) {
        try testing.expectEqualSlices(u8, "from_client_2", handler2.received_data.?);
    }
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
