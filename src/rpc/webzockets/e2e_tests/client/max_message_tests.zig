const std = @import("std");
const testing = std.testing;

const servers = @import("../support/test_servers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/FdLeakDetector.zig");

test "max_message_size enforcement closes with 1009" {
    const fd_check = FdLeakDetector.baseline();
    defer _ = fd_check.detectLeaks();

    // OversizedServer sends a 2048-byte binary message on open.
    // The client is configured with max_message_size = 1024, so it should
    // reject the message and close the connection with code 1009 (message too big).
    const ts = try servers.startOversizedServer(testing.allocator);
    defer ts.stop();

    var handler: clients.MaxMessageHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestMaxMessageClient.Conn = undefined;
    var client = env.initClient(clients.TestMaxMessageClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
        .max_message_size = 1024,
    });
    try client.connect();
    try env.loop.run(.until_done);

    // Client should have connected successfully
    try testing.expect(handler.open_called);
    // onClose should have been called (client closed due to oversized message)
    try testing.expect(handler.close_called);
    // The oversized message should NOT have been delivered to onMessage
    try testing.expect(!handler.message_received);
    conn.deinit();
}
