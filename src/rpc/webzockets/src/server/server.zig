const std = @import("std");
const xev = @import("xev");

const slot_pool = @import("slot_pool.zig");
const server_hs = @import("handshake.zig");
const server_conn = @import("connection.zig");

/// TCP listener wrapping a libxev accept loop with memory-pooled connections.
///
/// Manages the full lifecycle of WebSocket connections: accepting TCP
/// connections, performing the HTTP upgrade handshake, and running the
/// WebSocket protocol. Pre-allocates memory pools for handshakes,
/// connections, and large-message buffers.
///
/// Comptime parameters:
///   - `Handler`: User handler type for protocol events (see below).
///   - `read_buf_size`: Size of per-connection embedded read buffer
///     (fast path for small messages).
///
/// **Required handler declarations** (comptime-enforced):
///   - `pub const Context = T` — the handler's context *pointee* type (`void` for none).
///     When `Context != void`, the caller provides `Config.handler_context: *T`, which is
///     passed to `init` as the second parameter. The pointer must outlive any handshake/
///     connection that might call `init` or `onHandshakeFailed`.
///
/// **Required handler methods** (comptime-enforced):
///   - `init(http.Request, if (Context == void) void else *Context) !Handler` —
///     factory method called during the HTTP upgrade, before the 101 response is sent.
///     Return an error to reject the connection. The handler pointer is stable for the
///     lifetime of the connection.
///   - `onMessage(*Handler, *Conn, types.Message)` — complete message
///     received (text or binary, after reassembly of fragments).
///   - `onWriteComplete(*Handler, *Conn)` — data send finished; the
///     caller's buffer may now be freed or reused. Also called on
///     disconnect if a data write was in-flight or pending. Required
///     because sends are zero-copy — the caller must not free or reuse
///     the buffer until this fires. Not called for `sendPing`/`sendPong`
///     (those copy into an internal queue; the caller can free immediately).
///   - `onClose(*Handler, *Conn)` — connection torn down (called exactly
///     once). The connection is released back to the pool after this
///     returns.
///
/// **Optional handler methods** (detected via `@hasDecl`):
///   - `onHandshakeFailed(*Handler)` — called if the handshake fails after
///     `init` succeeds (e.g., write error, connection pool exhausted,
///     server shutdown). Use to clean up resources allocated in `init`.
///     Neither `onOpen` nor `onClose` will fire when this is called.
///     There is no connection parameter — only `*Handler` is available.
///   - `onOpen(*Handler, *Conn)` — protocol phase started, connection is
///     ready to send. Called after successful `init`, before reading
///     messages.
///   - `onPing(*Handler, *Conn, []const u8)` — ping received. When
///     declared, the handler is responsible for sending pong via
///     `conn.sendPong()`, which enqueues each pong individually into the
///     control queue. When absent, the library auto-pongs using "latest
///     wins" semantics: if multiple pings arrive before a pong can be
///     sent, only the most recent ping's payload is used (permitted by
///     RFC 6455 §5.5.3). Implement `onPing` if you need to respond to
///     every ping.
///   - `onPong(*Handler, *Conn, []const u8)` — unsolicited or solicited
///     pong received. Useful for latency measurement with application-
///     level ping/pong.
///
/// Connection tracking is delegated to the user via handler callbacks.
pub fn Server(
    comptime Handler: type,
    comptime read_buf_size: usize,
) type {
    comptime {
        if (!@hasDecl(Handler, "Context"))
            @compileError("Handler must declare `pub const Context = T`");
        if (!@hasDecl(Handler, "init"))
            @compileError("Handler must declare init(request, context) !Handler");
        if (!@hasDecl(Handler, "onMessage"))
            @compileError("Handler must declare an onMessage method");
        if (!@hasDecl(Handler, "onWriteComplete"))
            @compileError("Handler must declare an onWriteComplete method (sends are zero-copy)");
        if (!@hasDecl(Handler, "onClose"))
            @compileError("Handler must declare an onClose method");
    }

    return struct {
        allocator: std.mem.Allocator,
        loop: *xev.Loop,
        config: Config,
        listen_socket: xev.TCP,
        accept_completion: xev.Completion,
        handshake_pool: HandshakePool,
        connection_pool: ConnectionPool,
        shutting_down: bool,
        listen_socket_closed: bool,
        /// Connections in WebSocket phase; walked during shutdown to issue close frames.
        active_connections: ConnectionList,
        /// Timer for periodic shutdown drain check.
        shutdown_timer: xev.Timer,
        shutdown_timer_completion: xev.Completion,
        /// For closing listen socket.
        listen_close_completion: xev.Completion,
        /// Absolute nanoTimestamp after which shutdown times out.
        shutdown_deadline: i128,
        shutdown_userdata: ?*anyopaque,

        const ServerSelf = @This();

        const log = std.log.scoped(.server);

        const HandlerContext = if (Handler.Context != void) *Handler.Context else void;

        const HsImpl = server_hs.Handshake(ServerSelf, Handler, read_buf_size);
        const ConnImpl = server_conn.Connection(ServerSelf, Handler, read_buf_size);
        const ConnectionList = ConnImpl.List;
        const HandshakePool = slot_pool.SlotPool(HsImpl);
        const ConnectionPool = slot_pool.SlotPool(ConnImpl);

        pub const ShutdownResult = enum { clean, timed_out };

        /// The per-connection WebSocket type exposed to handler callbacks.
        /// Provides `sendText`, `sendBinary`, `sendPing`, `sendPong`, and `close` methods.
        pub const Conn = ConnImpl;

        pub const Config = struct {
            /// Address to bind and listen on.
            address: std.net.Address,
            /// Typed context passed to `Handler.init`. `*T` when
            /// `Handler.Context` is non-void; `void` (`{}`) otherwise.
            handler_context: HandlerContext,
            /// TCP listen backlog.
            tcp_accept_backlog: u31 = 128,
            /// Maximum total size of a reassembled fragmented message.
            max_message_size: usize = 16 * 1024 * 1024,
            /// Number of handshake slots to pre-allocate in the pool.
            initial_handshake_pool_size: usize = 16,
            /// Number of connection slots to pre-allocate in the pool.
            initial_connection_pool_size: usize = 64,
            /// Maximum number of concurrent handshakes. Null means unlimited.
            max_handshakes: ?usize = null,
            /// Maximum number of concurrent connections. Null means unlimited.
            max_connections: ?usize = null,
            /// Idle timeout in ms. Server sends close (going_away) if no data
            /// received for this long. null = disabled (default).
            idle_timeout_ms: ?u32 = null,
            /// Maximum time in ms a connection may remain in `.closing`
            /// before force-disconnecting. Default: 5000.
            close_timeout_ms: u32 = 5_000,
        };

        /// Create a server: opens, binds, and listens on the configured address.
        /// Pre-heats the memory pools with the configured initial sizes.
        /// The event loop is not started — call `accept()` then run the loop.
        pub fn init(allocator: std.mem.Allocator, loop: *xev.Loop, config: Config) !ServerSelf {
            // The kqueue and epoll backends require a thread pool to be set on
            // the loop, otherwise they cannot perform socket close operations.
            if (comptime @hasField(xev.Loop, "thread_pool")) {
                std.debug.assert(loop.thread_pool != null);
            }

            const listen_socket = try xev.TCP.init(config.address);
            errdefer std.posix.close(listen_socket.fd);

            try listen_socket.bind(config.address);
            try listen_socket.listen(config.tcp_accept_backlog);

            // Create pools with preheating (handshake pool has no limit, connection pool may be limited)
            var hs_pool = HandshakePool.init(allocator, config.max_handshakes);
            errdefer hs_pool.deinit();
            try hs_pool.preheat(config.initial_handshake_pool_size);

            var conn_pool = ConnectionPool.init(allocator, config.max_connections);
            errdefer conn_pool.deinit();
            try conn_pool.preheat(config.initial_connection_pool_size);

            return .{
                .allocator = allocator,
                .loop = loop,
                .config = config,
                .listen_socket = listen_socket,
                .accept_completion = .{},
                .handshake_pool = hs_pool,
                .connection_pool = conn_pool,
                .shutting_down = false,
                .listen_socket_closed = false,
                .active_connections = .{},
                .shutdown_timer = undefined,
                .shutdown_timer_completion = .{},
                .listen_close_completion = .{},
                .shutdown_deadline = 0,
                .shutdown_userdata = null,
            };
        }

        /// Close the listen socket and clean up memory pools.
        /// Does not affect active connections (they continue until closed).
        pub fn deinit(self: *ServerSelf) void {
            if (!self.listen_socket_closed) {
                std.posix.close(self.listen_socket.fd);
            }
            self.handshake_pool.deinit();
            self.connection_pool.deinit();
        }

        /// Start the asynchronous accept loop. Each accepted connection goes through
        /// the HTTP upgrade handshake, then transitions to the WebSocket protocol phase.
        /// The accept loop re-arms automatically after each connection.
        pub fn accept(self: *ServerSelf) void {
            self.listen_socket.accept(
                self.loop,
                &self.accept_completion,
                ServerSelf,
                self,
                acceptCallback,
            );
        }

        fn acceptCallback(
            self_opt: ?*ServerSelf,
            _: *xev.Loop,
            completion: *xev.Completion,
            result: xev.AcceptError!xev.TCP,
        ) xev.CallbackAction {
            // NOTE: in this callback we always return .disarm, even if just calling self.accept() again,
            // because of bug with libxev kqueue backend when returning .rearm
            const self = self_opt orelse return .disarm;

            if (self.shutting_down) {
                const client_socket = result catch return .disarm;
                log.debug("accept rejected: shutting down", .{});
                client_socket.close(self.loop, completion, ServerSelf, self, onRejectCloseComplete);
                return .disarm;
            }

            const client_socket = result catch |err| {
                log.debug("accept failed: {}", .{err});
                // Accept failed — re-register to keep listening.
                self.accept();
                return .disarm;
            };

            if (!self.setupConnection(client_socket)) {
                // Pool exhausted, close socket asynchronously, then resume accepting
                client_socket.close(
                    self.loop,
                    completion,
                    ServerSelf,
                    self,
                    onRejectCloseComplete,
                );
                return .disarm;
            }

            // Re-register to accept the next connection.
            self.accept();
            return .disarm;
        }

        fn setupConnection(self: *ServerSelf, client_socket: xev.TCP) bool {
            // Acquire handshake slot from pool
            const hs = self.handshake_pool.create() catch {
                log.debug("setupConnection: handshake pool exhausted", .{});
                return false;
            };

            // Initialize and start the handshake
            hs.init(client_socket, self);
            hs.start();
            return true;
        }

        fn onRejectCloseComplete(
            self_opt: ?*ServerSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.TCP,
            result: xev.CloseError!void,
        ) xev.CallbackAction {
            result catch |err| log.debug("rejected connection close failed: {}", .{err});
            if (self_opt) |self| {
                if (!self.shutting_down) self.accept();
            }
            return .disarm;
        }

        fn onListenSocketCloseComplete(
            self_opt: ?*ServerSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.TCP,
            result: xev.CloseError!void,
        ) xev.CallbackAction {
            result catch |err| log.debug("listen socket close failed: {}", .{err});
            if (self_opt) |self| {
                log.debug("listen socket closed", .{});
                self.listen_socket_closed = true;
            }
            return .disarm;
        }

        fn isFullyDrained(self: *const ServerSelf) bool {
            return self.connection_pool.active_count == 0 and
                self.handshake_pool.active_count == 0 and
                self.listen_socket_closed;
        }

        /// Initiate graceful shutdown: stop accepting connections, close all active
        /// WebSocket connections with a going_away close frame, and invoke the callback
        /// when fully drained or after the timeout expires.
        pub fn shutdown(
            self: *ServerSelf,
            max_wait_ms: u64,
            comptime Context: type,
            context: ?*Context,
            comptime onComplete: fn (?*Context, ShutdownResult) void,
        ) void {
            log.debug("shutdown: max_wait_ms={d}, active_connections={d}, active_handshakes={d}", .{
                max_wait_ms,
                self.connection_pool.active_count,
                self.handshake_pool.active_count,
            });
            self.shutting_down = true;
            self.shutdown_userdata = @ptrCast(context);
            self.shutdown_deadline = std.time.nanoTimestamp() +
                @as(i128, max_wait_ms) * std.time.ns_per_ms;

            // Close the listen socket to stop accepting new connections
            self.listen_socket.close(
                self.loop,
                &self.listen_close_completion,
                ServerSelf,
                self,
                onListenSocketCloseComplete,
            );

            // Close all active WebSocket connections
            var it = self.active_connections.first;
            while (it) |node| {
                it = node.next;
                node.data.close(.going_away, "");
            }

            // Check if already drained (no connections, listen close may fire synchronously)
            if (self.isFullyDrained()) {
                onComplete(@ptrCast(@alignCast(self.shutdown_userdata)), .clean);
                return;
            }

            // Start periodic timer to check for drain completion
            const S = struct {
                fn onTimer(
                    s_opt: ?*ServerSelf,
                    _: *xev.Loop,
                    _: *xev.Completion,
                    result: xev.Timer.RunError!void,
                ) xev.CallbackAction {
                    result catch |err| log.err("shutdown timer failed: {}", .{err});
                    const s = s_opt orelse return .disarm;
                    if (s.isFullyDrained()) {
                        log.debug("shutdown: fully drained", .{});
                        onComplete(@ptrCast(@alignCast(s.shutdown_userdata)), .clean);
                        return .disarm;
                    }
                    if (std.time.nanoTimestamp() >= s.shutdown_deadline) {
                        log.debug("shutdown: timed out, connections={d}, handshakes={d}", .{
                            s.connection_pool.active_count,
                            s.handshake_pool.active_count,
                        });
                        onComplete(@ptrCast(@alignCast(s.shutdown_userdata)), .timed_out);
                        return .disarm;
                    }
                    s.shutdown_timer.run(
                        s.loop,
                        &s.shutdown_timer_completion,
                        10,
                        ServerSelf,
                        s,
                        onTimer,
                    );
                    return .disarm;
                }
            };

            self.shutdown_timer = xev.Timer.init() catch |err| {
                log.err("shutdown: failed to create drain timer (should never happen): {}", .{err});
                return;
            };
            self.shutdown_timer.run(
                self.loop,
                &self.shutdown_timer_completion,
                10,
                ServerSelf,
                self,
                S.onTimer,
            );
        }
    };
}
