const std = @import("std");
const testing = std.testing;

const servers = @import("../support/test_servers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/fd_leak.zig").FdLeakDetector;

test "e2e client: server-initiated close" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    // Start a server that sends close immediately on open
    const ts = try servers.startCloseOnOpenServer(testing.allocator);
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

    // Client should have connected successfully
    try testing.expect(handler.open_called);
    // Client should have received the server's close and cleaned up
    try testing.expect(handler.close_called);
    conn.deinit();
}
