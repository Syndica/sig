const std = @import("std");
const testing = std.testing;

const servers = @import("../support/test_servers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/fd_leak.zig").FdLeakDetector;

test "auto-pong response to server ping" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    // PingOnOpenServer sends ping("hello") on open. The client's handler
    // (ServerCloseHandler) does not declare onPing, so the library auto-pongs.
    // The server receives the pong and closes the connection. If auto-pong
    // were broken the connection would not complete cleanly.
    const ts = try servers.startPingOnOpenServer(testing.allocator);
    defer ts.stop();

    var handler: clients.ServerCloseHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestServerCloseClient.Conn = undefined;
    var client = env.initClient(clients.TestServerCloseClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expect(handler.close_called);
    conn.deinit();
}

test "onPong callback fires on unsolicited pong" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    // PongOnOpenServer sends an unsolicited pong("hello") on open.
    // The client's PongTrackingHandler captures the pong data via onPong
    // and closes the connection.
    const ts = try servers.startPongOnOpenServer(testing.allocator);
    defer ts.stop();

    var handler: clients.PongTrackingHandler = .{
        .allocator = testing.allocator,
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestPongTrackingClient.Conn = undefined;
    var client = env.initClient(clients.TestPongTrackingClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expect(handler.pong_received);
    const pong_data = handler.pong_data orelse return error.NoData;
    try testing.expectEqualSlices(u8, "hello", pong_data);
    conn.deinit();
}

test "explicit onPing handler sends pong" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    // PingOnOpenServer sends ping("hello") on open. The client's
    // ExplicitPongHandler declares onPing, so the library does NOT auto-pong.
    // The handler manually calls sendPong in onPing. The server receives the
    // pong and closes. This verifies that declaring onPing disables auto-pong
    // and the handler can manage pong responses itself.
    const ts = try servers.startPingOnOpenServer(testing.allocator);
    defer ts.stop();

    var handler: clients.ExplicitPongHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestExplicitPongClient.Conn = undefined;
    var client = env.initClient(clients.TestExplicitPongClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
    });

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    try testing.expect(handler.ping_received);
    try testing.expect(handler.close_called);
    conn.deinit();
}
