const std = @import("std");
const ws = @import("webzockets_lib");

const server_runner = @import("server_runner.zig");
const server_handlers = @import("server_handlers.zig");

/// Localhost ephemeral-port address used by all test servers.
pub const localhost = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 0);

/// Default read buffer size used by the test servers.
pub const default_read_buf_size: usize = 4096;

/// Server-side handler that echoes any text/binary message back to the client.
pub const EchoHandler = server_handlers.EchoHandler;

/// Generic server runner for creating custom test servers.
pub const ServerRunner = server_runner.ServerRunner;

/// WebSocket server type used by most e2e tests (echo server).
pub const EchoServer = ws.Server(EchoHandler, default_read_buf_size);

/// In-process echo server runner used by most e2e tests.
pub const TestServer = server_runner.ServerRunner(EchoServer);

pub fn startTestServer(allocator: std.mem.Allocator) !*TestServer {
    return try TestServer.start(allocator, .{ .address = localhost, .handler_context = {} });
}

/// Server that closes every connection immediately on open.
pub const CloseOnOpenServer = ws.Server(server_handlers.CloseOnOpenHandler, default_read_buf_size);
pub const CloseOnOpenTestServer = server_runner.ServerRunner(CloseOnOpenServer);

pub fn startCloseOnOpenServer(allocator: std.mem.Allocator) !*CloseOnOpenTestServer {
    return try CloseOnOpenTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = {},
    });
}

/// Server that sends a ping to every connection immediately on open.
pub const PingOnOpenServer = ws.Server(server_handlers.PingOnOpenHandler, default_read_buf_size);
pub const PingOnOpenTestServer = server_runner.ServerRunner(PingOnOpenServer);

pub fn startPingOnOpenServer(allocator: std.mem.Allocator) !*PingOnOpenTestServer {
    return try PingOnOpenTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = {},
    });
}

/// Server that sends ping then closes immediately on open.
pub const PingThenCloseOnOpenServer = ws.Server(
    server_handlers.PingThenCloseOnOpenHandler,
    default_read_buf_size,
);
pub const PingThenCloseOnOpenTestServer = server_runner.ServerRunner(PingThenCloseOnOpenServer);

pub fn startPingThenCloseOnOpenServer(allocator: std.mem.Allocator) !*PingThenCloseOnOpenTestServer {
    return try PingThenCloseOnOpenTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = {},
    });
}

/// Server that sends an unsolicited pong to every connection immediately on open.
pub const PongOnOpenServer = ws.Server(server_handlers.PongOnOpenHandler, default_read_buf_size);
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
);
pub const OversizedTestServer = server_runner.ServerRunner(OversizedServer);

pub fn startOversizedServer(allocator: std.mem.Allocator) !*OversizedTestServer {
    return try OversizedTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = {},
    });
}

/// Server that rejects every connection at init time (HTTP 403).
pub const RejectServer = ws.Server(server_handlers.RejectOnInitHandler, default_read_buf_size);
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

/// Server that pauses on open, waits for byte threshold, resumes, echoes messages.
pub const PauseUntilBufferedEchoServer = ws.Server(
    server_handlers.PauseUntilBufferedEchoHandler,
    default_read_buf_size,
);
pub const PauseUntilBufferedEchoTestServer =
    server_runner.ServerRunner(PauseUntilBufferedEchoServer);

/// PauseUntilBufferedEcho variant with a small 256-byte read buffer.
pub const PauseUntilBufferedEchoSmallBufServer = ws.Server(
    server_handlers.PauseUntilBufferedEchoHandler,
    256,
);
pub const PauseUntilBufferedEchoSmallBufTestServer =
    server_runner.ServerRunner(PauseUntilBufferedEchoSmallBufServer);

pub fn startPauseUntilBufferedEchoServer(
    allocator: std.mem.Allocator,
    ctx: *server_handlers.PauseUntilBufferedEchoHandler.Context,
) !*PauseUntilBufferedEchoTestServer {
    return try PauseUntilBufferedEchoTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = ctx,
    });
}

pub fn startPauseUntilBufferedEchoSmallBufServer(
    allocator: std.mem.Allocator,
    ctx: *server_handlers.PauseUntilBufferedEchoHandler.Context,
) !*PauseUntilBufferedEchoSmallBufTestServer {
    return try PauseUntilBufferedEchoSmallBufTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = ctx,
    });
}

/// Server that pauses on open, threshold resumes, then pauses per-message
/// with echo and resume in onWriteComplete.
pub const PauseMidStreamEchoServer = ws.Server(
    server_handlers.PauseMidStreamEchoHandler,
    default_read_buf_size,
);
pub const PauseMidStreamEchoTestServer = server_runner.ServerRunner(PauseMidStreamEchoServer);

pub fn startPauseMidStreamEchoServer(
    allocator: std.mem.Allocator,
    ctx: *server_handlers.PauseMidStreamEchoHandler.Context,
) !*PauseMidStreamEchoTestServer {
    return try PauseMidStreamEchoTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = ctx,
    });
}

/// Server that sends configured messages on open, then closes.
pub const SendMessagesOnOpenServer = ws.Server(
    server_handlers.SendMessagesOnOpenHandler,
    default_read_buf_size,
);
pub const SendMessagesOnOpenTestServer = server_runner.ServerRunner(SendMessagesOnOpenServer);

pub fn startSendMessagesOnOpenServer(
    allocator: std.mem.Allocator,
    ctx: *server_handlers.SendMessagesOnOpenHandler.Context,
) !*SendMessagesOnOpenTestServer {
    return try SendMessagesOnOpenTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = ctx,
    });
}

// 12 messages of 20 bytes each for small-buffer tests.
pub const small_buf_msg_len = 20;
pub const small_buf_msg_count = 12;

fn makeSmallBufBufs() [small_buf_msg_count][small_buf_msg_len]u8 {
    var bufs: [small_buf_msg_count][small_buf_msg_len]u8 = undefined;
    for (0..small_buf_msg_count) |i| {
        @memset(&bufs[i], @as(u8, @truncate('A' + i)));
    }
    return bufs;
}

const small_buf_bufs = makeSmallBufBufs();
pub const small_buf_slices = makeSmallBufSlices();

fn makeSmallBufSlices() [small_buf_msg_count][]const u8 {
    var slices: [small_buf_msg_count][]const u8 = undefined;
    for (0..small_buf_msg_count) |i| {
        slices[i] = &small_buf_bufs[i];
    }
    return slices;
}

/// Server that sends raw pre-built frames on open.
pub const RawSendServer = ws.Server(server_handlers.RawSendOnOpenHandler, default_read_buf_size);
pub const RawSendTestServer = server_runner.ServerRunner(RawSendServer);

pub fn startRawSendServer(
    allocator: std.mem.Allocator,
    ctx: *server_handlers.RawSendOnOpenHandler.Context,
) !*RawSendTestServer {
    return try RawSendTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = ctx,
    });
}

/// Server that detects re-entrant onMessage dispatch via pauseReads/resumeReads.
pub const ReentrancyDetectServer = ws.Server(
    server_handlers.ReentrancyDetectHandler,
    default_read_buf_size,
);
pub const ReentrancyDetectTestServer = server_runner.ServerRunner(ReentrancyDetectServer);

pub fn startReentrancyDetectServer(
    allocator: std.mem.Allocator,
    ctx: *server_handlers.ReentrancyDetectHandler.Context,
) !*ReentrancyDetectTestServer {
    return try ReentrancyDetectTestServer.start(allocator, .{
        .address = localhost,
        .handler_context = ctx,
    });
}
