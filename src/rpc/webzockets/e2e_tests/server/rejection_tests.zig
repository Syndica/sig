const std = @import("std");
const ws = @import("webzockets_lib");

const testing = std.testing;
const servers = @import("../support/test_servers.zig");
const clients = @import("../support/test_clients.zig");
const FdLeakDetector = @import("../support/fd_leak.zig").FdLeakDetector;

test "e2e: handler rejects connection" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try startRejectingTestServer(testing.allocator);
    defer ts.stop();

    var handler: clients.NoOpHandler = .{};

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestNoOpClient.Conn = undefined;
    var client = env.initClient(clients.TestNoOpClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
        .path = "/reject-me",
    });

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(!handler.open_called);
}

test "e2e: handler accepts valid path" {
    const fd_check = FdLeakDetector.baseline();
    defer fd_check.assertNoLeaks();

    const ts = try startRejectingTestServer(testing.allocator);
    defer ts.stop();

    var handler: clients.EchoTestHandler = .{
        .send_kind = .text,
        .send_data = "test",
        .allocator = testing.allocator,
    };
    defer handler.deinit();

    var env: clients.TestEnv = undefined;
    try env.start();
    defer env.deinit();

    var conn: clients.TestEchoClient.Conn = undefined;
    var client = env.initClient(clients.TestEchoClient, &handler, &conn, .{
        .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, ts.port),
        .path = "/valid-path",
    });
    defer if (handler.open_called) conn.deinit();

    try client.connect();
    try env.loop.run(.until_done);

    try testing.expect(handler.open_called);
    const received_data = handler.received_data orelse return error.NoData;
    try testing.expectEqualSlices(u8, "test", received_data);
}

/// Server-side handler that rejects connections to paths starting with "/reject".
const RejectingHandler = struct {
    pub const Context = void;

    inner: servers.EchoHandler,

    pub fn init(request: ws.http.Request, _: void) !RejectingHandler {
        if (std.mem.startsWith(u8, request.path, "/reject")) {
            return error.ConnectionRejected;
        }
        return .{ .inner = try servers.EchoHandler.init(request, {}) };
    }

    pub fn onMessage(self: *RejectingHandler, conn: anytype, message: ws.Message) void {
        self.inner.onMessage(conn, message);
    }

    pub fn onWriteComplete(self: *RejectingHandler, conn: anytype) void {
        self.inner.onWriteComplete(conn);
    }

    pub fn onClose(self: *RejectingHandler, conn: anytype) void {
        self.inner.onClose(conn);
    }
};

const RejectingServer = ws.Server(
    RejectingHandler,
    servers.default_read_buf_size,
    servers.default_pool_buf_size,
);
const RejectingTestServer = servers.ServerRunner(RejectingServer);

fn startRejectingTestServer(allocator: std.mem.Allocator) !*RejectingTestServer {
    const address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);
    return try RejectingTestServer.start(allocator, .{
        .address = address,
        .handler_context = {},
    });
}
