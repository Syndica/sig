const std = @import("std");
const ws = @import("webzockets_lib");

const server_runner = @import("server_runner.zig");
const server_handlers = @import("server_handlers.zig");

/// Localhost ephemeral-port address used by all test servers.
pub const localhost = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);

/// Default read buffer size used by the test servers.
pub const default_read_buf_size: usize = 4096;

/// Default pool buffer size used by the test servers.
pub const default_pool_buf_size: usize = 64 * 1024;

/// Server-side handler that echoes any text/binary message back to the client.
pub const EchoHandler = server_handlers.EchoHandler;

/// Generic server runner for creating custom test servers.
pub const ServerRunner = server_runner.ServerRunner;

/// WebSocket server type used by most e2e tests (echo server).
pub const EchoServer = ws.Server(EchoHandler, default_read_buf_size, default_pool_buf_size);

/// In-process echo server runner used by most e2e tests.
pub const TestServer = server_runner.ServerRunner(EchoServer);

pub fn startTestServer(allocator: std.mem.Allocator) !*TestServer {
    return try TestServer.start(allocator, .{ .address = localhost, .handler_context = {} });
}

/// Server that closes every connection immediately on open.
pub const CloseOnOpenServer = ws.Server(
    server_handlers.CloseOnOpenHandler,
    default_read_buf_size,
    default_pool_buf_size,
);
pub const CloseOnOpenTestServer = server_runner.ServerRunner(CloseOnOpenServer);

pub fn startCloseOnOpenServer(allocator: std.mem.Allocator) !*CloseOnOpenTestServer {
    return try CloseOnOpenTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = {},
    });
}

/// Server that sends a ping to every connection immediately on open.
pub const PingOnOpenServer = ws.Server(
    server_handlers.PingOnOpenHandler,
    default_read_buf_size,
    default_pool_buf_size,
);
pub const PingOnOpenTestServer = server_runner.ServerRunner(PingOnOpenServer);

pub fn startPingOnOpenServer(allocator: std.mem.Allocator) !*PingOnOpenTestServer {
    return try PingOnOpenTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = {},
    });
}

/// Server that sends an unsolicited pong to every connection immediately on open.
pub const PongOnOpenServer = ws.Server(
    server_handlers.PongOnOpenHandler,
    default_read_buf_size,
    default_pool_buf_size,
);
pub const PongOnOpenTestServer = server_runner.ServerRunner(PongOnOpenServer);

pub fn startPongOnOpenServer(allocator: std.mem.Allocator) !*PongOnOpenTestServer {
    return try PongOnOpenTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = {},
    });
}

/// Server that sends a 2048-byte message to every connection on open.
pub const OversizedServer = ws.Server(
    server_handlers.SendOversizedOnOpenHandler,
    default_read_buf_size,
    default_pool_buf_size,
);
pub const OversizedTestServer = server_runner.ServerRunner(OversizedServer);

pub fn startOversizedServer(allocator: std.mem.Allocator) !*OversizedTestServer {
    return try OversizedTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = {},
    });
}

/// Server that rejects every connection at init time (HTTP 403).
pub const RejectServer = ws.Server(
    server_handlers.RejectOnInitHandler,
    default_read_buf_size,
    default_pool_buf_size,
);
pub const RejectTestServer = server_runner.ServerRunner(RejectServer);

pub fn startRejectServer(allocator: std.mem.Allocator) !*RejectTestServer {
    return try RejectTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = {},
    });
}

/// CloseOnOpen server with custom timeout configuration for timeout tests.
pub fn startCloseOnOpenServerWithTimeouts(
    allocator: std.mem.Allocator,
    idle_timeout_ms: ?u32,
    close_timeout_ms: u32,
) !*CloseOnOpenTestServer {
    return try CloseOnOpenTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = {},
        .idle_timeout_ms = idle_timeout_ms,
        .close_timeout_ms = close_timeout_ms,
    });
}

/// Echo server with custom timeout configuration for timeout tests.
pub fn startEchoServerWithTimeouts(
    allocator: std.mem.Allocator,
    idle_timeout_ms: ?u32,
    close_timeout_ms: u32,
) !*TestServer {
    return try TestServer.start(allocator, .{
        .address = localhost,
        .handler_context = {},
        .idle_timeout_ms = idle_timeout_ms,
        .close_timeout_ms = close_timeout_ms,
    });
}

/// Server that echoes the first message then closes the connection.
pub const CloseAfterFirstMessageServer = ws.Server(
    server_handlers.CloseAfterFirstMessageHandler,
    default_read_buf_size,
    default_pool_buf_size,
);
pub const CloseAfterFirstMessageTestServer = server_runner.ServerRunner(
    CloseAfterFirstMessageServer,
);

pub fn startCloseAfterFirstMessageServer(
    allocator: std.mem.Allocator,
    close_timeout_ms: u32,
) !*CloseAfterFirstMessageTestServer {
    return try CloseAfterFirstMessageTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = {},
        .close_timeout_ms = close_timeout_ms,
    });
}
