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

/// Client-side handler that pauses reads on open and waits for enough data
/// to buffer before resuming. Used for deterministic burst-processing tests.
pub const PauseUntilBufferedClientHandler = client_handlers.PauseUntilBufferedClientHandler;

/// Client-side handler that pauses on open, threshold-resumes, then pauses
/// per-message with resume in onWriteComplete.
pub const PauseMidStreamClientHandler = client_handlers.PauseMidStreamClientHandler;

/// Client-side handler that detects re-entrant onMessage dispatch via
/// pauseReads/resumeReads while messages are buffered.
pub const ReentrancyDetectClientHandler = client_handlers.ReentrancyDetectClientHandler;

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

/// WebSocket client type for deterministic pause-until-buffered tests.
pub const TestPauseUntilBufferedClient = ws.Client(PauseUntilBufferedClientHandler, 4096);

/// WebSocket client type for deterministic pause-until-buffered tests with small read buffer.
pub const TestPauseUntilBufferedSmallBufClient = ws.Client(PauseUntilBufferedClientHandler, 256);

/// WebSocket client type for pause-mid-stream tests.
pub const TestPauseMidStreamClient = ws.Client(PauseMidStreamClientHandler, 4096);

/// WebSocket client type for re-entrancy detection tests.
pub const TestReentrancyDetectClient = ws.Client(ReentrancyDetectClientHandler, 4096);

/// Bundles the thread pool, event loop, and CSPRNG needed by
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
            &self.csprng,
            config,
        );
    }

    pub fn deinit(self: *TestEnv) void {
        self.loop.deinit();
        self.tp.shutdown();
        self.tp.deinit();
    }
};
