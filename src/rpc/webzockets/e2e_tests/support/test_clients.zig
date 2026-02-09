const std = @import("std");
const xev = @import("xev");
const ws = @import("webzockets_lib");

const client_handlers = @import("client_handlers.zig");

/// Client-side handler used by basic e2e tests.
///
/// See `support/handlers.zig`.
pub const EchoTestHandler = client_handlers.SendOnceHandler;
pub const EchoSendKind = client_handlers.SendOnceHandler.SendKind;

/// Client-side handler that closes immediately on open.
pub const CloseOnOpenHandler = client_handlers.CloseOnOpenHandler;

/// Client-side handler that tracks open_called but takes no action.
pub const NoOpHandler = client_handlers.NoOpHandler;

/// Sequence handler for multi-message tests.
pub const SequenceHandler = client_handlers.SequenceHandler;

/// Client-side handler that waits for server-initiated close.
pub const ServerCloseHandler = client_handlers.ServerCloseHandler;

/// Client-side handler that tracks pong reception.
pub const PongTrackingHandler = client_handlers.PongTrackingHandler;

/// Client-side handler for max_message_size tests.
pub const MaxMessageHandler = client_handlers.MaxMessageHandler;

/// Client-side handler that detects connection/handshake failures.
pub const ConnectFailHandler = client_handlers.ConnectFailHandler;

/// Client-side handler that explicitly manages pong responses via onPing.
pub const ExplicitPongHandler = client_handlers.ExplicitPongHandler;

/// WebSocket client type paired with `EchoTestHandler`.
pub const TestEchoClient = ws.Client(EchoTestHandler, 4096);

/// WebSocket client type for close-on-open tests.
pub const TestCloseClient = ws.Client(CloseOnOpenHandler, 4096);

/// WebSocket client type for rejection tests.
pub const TestNoOpClient = ws.Client(NoOpHandler, 4096);

/// WebSocket client type for sequence tests.
pub const TestSequenceClient = ws.Client(SequenceHandler, 4096);

/// WebSocket client type for server-initiated close tests.
pub const TestServerCloseClient = ws.Client(ServerCloseHandler, 4096);

/// WebSocket client type for pong tracking tests.
pub const TestPongTrackingClient = ws.Client(PongTrackingHandler, 4096);

/// WebSocket client type for max_message_size tests (small read buffer).
pub const TestMaxMessageClient = ws.Client(MaxMessageHandler, 4096);

/// WebSocket client type for connection failure tests.
pub const TestConnectFailClient = ws.Client(ConnectFailHandler, 4096);

/// WebSocket client type for explicit pong handler tests.
pub const TestExplicitPongClient = ws.Client(ExplicitPongHandler, 4096);

/// Default buffer pool config used across all e2e tests.
const default_pool_buf_size: usize = 64 * 1024;
const default_pool_preheat: usize = 2;

/// Bundles the thread pool, event loop, buffer pool, and CSPRNG needed by
/// client-side e2e tests. Uses pointer-stable init via `start()` on an
/// existing instance. Must not be moved or copied after `start()`.
///
/// ```zig
/// var env: clients.TestEnv = undefined;
/// try env.start();
/// defer env.deinit();
///
/// var client = env.initClient(clients.TestEchoClient, &handler, &conn, .{
///     .address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, port),
/// });
/// ```
pub const TestEnv = struct {
    tp: xev.ThreadPool,
    loop: xev.Loop,
    buf_pool: ws.buffer.BufferPool,
    csprng: ws.ClientMaskPRNG,

    /// Initialize in place. The loop stores a pointer to `self.tp`, so the
    /// struct must not be moved or copied after `start()` returns.
    pub fn start(self: *TestEnv) !void {
        self.tp = xev.ThreadPool.init(.{});
        errdefer {
            self.tp.shutdown();
            self.tp.deinit();
        }

        self.loop = try xev.Loop.init(.{ .thread_pool = &self.tp });
        errdefer self.loop.deinit();

        self.buf_pool = ws.buffer.BufferPool.init(std.testing.allocator, default_pool_buf_size);
        errdefer self.buf_pool.deinit();
        try self.buf_pool.preheat(default_pool_preheat);

        var seed: [ws.ClientMaskPRNG.secret_seed_length]u8 = undefined;
        std.crypto.random.bytes(&seed);
        self.csprng = ws.ClientMaskPRNG.init(seed);
    }

    /// Create a client wired to this env's loop, buffer pool, and CSPRNG.
    pub fn initClient(
        self: *TestEnv,
        comptime ClientType: type,
        handler: anytype,
        conn: anytype,
        config: ClientType.Config,
    ) ClientType {
        return ClientType.init(
            std.testing.allocator,
            &self.loop,
            handler,
            conn,
            &self.buf_pool,
            &self.csprng,
            config,
        );
    }

    pub fn deinit(self: *TestEnv) void {
        self.buf_pool.deinit();
        self.loop.deinit();
        self.tp.shutdown();
        self.tp.deinit();
    }
};
