const std = @import("std");
const xev = @import("xev");

const types = @import("../types.zig");
const buffer = @import("../buffer.zig");
const client_connection = @import("connection.zig");
const client_handshake = @import("handshake.zig");

/// Transient WebSocket client that connects TCP, performs the handshake, and
/// initializes a caller-provided `ClientConnection` (allowing external
/// pooling/management). After the handshake completes, the client struct can
/// be discarded — the connection is self-contained.
///
/// NOTE: this type does not allocate, the allocator and buffer pool
/// is just passed through to the connection for its later use.
///
/// Comptime parameters:
///   - `Handler`: User handler for protocol events.
///   - `read_buf_size`: Size of the embedded per-connection read buffer. Also
///     defines the maximum size for the handshake response.
///
/// See `ClientConnection` for the `Handler` interface and callback semantics.
///
/// ## Connection sequence
///
/// ```
///  Caller                Client                  xev Loop              Server
///    │                     │                        │                     │
///    │  connect()          │                        │                     │
///    ├────────────────────>│  TCP.init()            │                     │
///    │                     │  TCP.connect()         │                     │
///    │                     ├───────────────────────>│──── SYN ───────────>│
///    │                     │                        │<──── SYN-ACK ───────│
///    │                     │   onConnectComplete    │──── ACK ───────────>│
///    │                     │<───────────────────────│                     │
///    │                     │                        │                     │
///    │                     │  Handshake.init()      │                     │
///    │                     │  Handshake.start()     │                     │
///    │                     │   ┌─────────────────┐  │                     │
///    │                     │   │ generate ws key │  │                     │
///    │                     │   │ build HTTP req  │  │                     │
///    │                     │   └─────────────────┘  │                     │
///    │                     │  TCP.write(upgrade req)│                     │
///    │                     ├───────────────────────>│──── HTTP Upgrade ──>│
///    │                     │   onWriteComplete      │                     │
///    │                     │<───────────────────────│                     │
///    │                     │  (loop if partial write)                     │
///    │                     │                        │                     │
///    │                     │  TCP.read()            │                     │
///    │                     ├───────────────────────>│<──── HTTP 101 ──────│
///    │                     │   onReadCallback       │                     │
///    │                     │<───────────────────────│                     │
///    │                     │  (loop if headers incomplete)                │
///    │                     │                        │                     │
///    │                     │  processResponse()     │                     │
///    │                     │   ┌─────────────────┐  │                     │
///    │                     │   │ validate 101    │  │                     │
///    │                     │   │ check accept key│  │                     │
///    │                     │   └─────────────────┘  │                     │
///    │                     │                        │                     │
///    │                     │  ┌── onSuccess ──────────────────────────┐   │
///    │                     │  │ conn.init()  — init ClientConnection  │   │
///    │                     │  │ conn.start() — begin WebSocket I/O    │   │
///    │                     │  └───────────────────────────────────────┘   │
///    │                     │                        │                     │
///    │  ┌──────────────────────────────────────┐    │                     │
///    │  │ Client struct can now be discarded.  │    │                     │
///    │  │ ClientConnection is self-contained.  │    │                     │
///    │  └──────────────────────────────────────┘    │                     │
///    │                     │                        │                     │
///    │  conn.send()        │                        │                     │
///    ├────────────────────>│  TCP.write()           │                     │
///    │                     ├───────────────────────>│──── WS frame ──────>│
///    │                     │                        │                     │
///    │                     │                        │<──── WS frame ──────│
///    │                     │   onReadCallback       │                     │
///    │  handler.onMessage()│<───────────────────────│                     │
///    │<────────────────────│                        │                     │
/// ```
///
/// On failure at any stage, the socket is closed and `Handler.onSocketClose`
/// is called (if declared).
pub fn Client(comptime Handler: type, comptime read_buf_size: usize) type {
    return struct {
        // -- Caller-provided state --
        conn: *Conn,
        handler: *Handler,
        allocator: std.mem.Allocator,
        config: Config,
        buffer_pool: *buffer.BufferPool,
        loop: *xev.Loop,

        /// Randomness source used for the client handshake (`Sec-WebSocket-Key`)
        /// and for per-frame mask key generation (via `ClientConnection`).
        ///
        /// Must be pointer-stable and outlive the `ClientConnection`. The PRNG
        /// is mutated and is not thread-safe; only use it from the `loop.run()`
        /// thread and do not share it across loops/threads.
        csprng: *types.ClientMaskPRNG,

        // -- Transient handshake state --
        hs: Handshake,
        connect_completion: xev.Completion,
        socket: xev.TCP,

        const ClientSelf = @This();

        const log = std.log.scoped(.client);

        const Handshake = client_handshake.ClientHandshake(ClientSelf);

        /// The per-connection WebSocket type exposed to handler callbacks.
        pub const Conn = client_connection.ClientConnection(Handler, read_buf_size);

        /// Configuration for a WebSocket client connection.
        pub const Config = struct {
            /// Server address to connect to (IPv4 or IPv6). Also used
            /// (formatted as IP:port) for the HTTP `Host` header during
            /// the WebSocket handshake. DNS resolution is not performed.
            address: std.net.Address,
            /// HTTP request path for the WebSocket upgrade (e.g. "/ws").
            path: []const u8 = "/",
            /// Maximum total size in bytes of a reassembled message
            /// (across all fragments). Messages exceeding this limit
            /// cause the connection to be closed with a message too big error.
            max_message_size: usize = 16 * 1024 * 1024,
            /// Close handshake timeout in ms. Force disconnect if peer doesn't
            /// respond to our close frame within this duration. Default: 5000.
            close_timeout_ms: u32 = 5_000,
        };

        pub fn init(
            allocator: std.mem.Allocator,
            loop: *xev.Loop,
            handler: *Handler,
            conn: *Conn,
            pool: *buffer.BufferPool,
            csprng: *types.ClientMaskPRNG,
            config: Config,
        ) ClientSelf {
            // The kqueue and epoll backends require a thread pool to be set on
            // the loop, otherwise they cannot perform socket close operations.
            if (comptime @hasField(xev.Loop, "thread_pool")) {
                std.debug.assert(loop.thread_pool != null);
            }

            return ClientSelf{
                .allocator = allocator,
                .loop = loop,
                .handler = handler,
                .conn = conn,
                .config = config,
                .buffer_pool = pool,
                .csprng = csprng,
                .hs = undefined,
                .connect_completion = .{},
                .socket = undefined,
            };
        }

        /// Start connecting to the WebSocket server.
        pub fn connect(self: *ClientSelf) !void {
            log.debug("connect: address={}, path={s}", .{ self.config.address, self.config.path });

            self.socket = try xev.TCP.init(self.config.address);

            self.socket.connect(
                self.loop,
                &self.connect_completion,
                self.config.address,
                ClientSelf,
                self,
                onConnectComplete,
            );
            log.debug("connect: connect submitted to loop", .{});
        }

        fn onConnectComplete(
            self_opt: ?*ClientSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.TCP,
            result: xev.ConnectError!void,
        ) xev.CallbackAction {
            const self = self_opt orelse {
                log.debug("onConnectComplete: self is null", .{});
                return .disarm;
            };

            result catch |err| {
                log.debug("onConnectComplete: TCP connect failed: {s}", .{@errorName(err)});
                // TCP connect failed — close and notify handler
                self.socket.close(
                    self.loop,
                    &self.connect_completion,
                    ClientSelf,
                    self,
                    onFailClose,
                );
                return .disarm;
            };

            log.debug("onConnectComplete: TCP connected, starting handshake", .{});
            // TCP connected — start WebSocket handshake using connection's read buffer
            // Safe: connection isn't started yet, so read_buf is unused
            self.hs = Handshake.init(
                self.socket,
                self.loop,
                &self.conn.read_buf,
                self,
                self.csprng,
            );
            self.hs.start(self.config.address, self.config.path);

            return .disarm;
        }

        fn onFailClose(
            self_opt: ?*ClientSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.TCP,
            result: xev.CloseError!void,
        ) xev.CallbackAction {
            result catch |err| log.debug("onFailClose: close failed: {}", .{err});
            const self = self_opt orelse return .disarm;
            log.debug("onFailClose: notifying handler", .{});
            if (comptime @hasDecl(Handler, "onSocketClose")) {
                self.handler.onSocketClose();
            }
            return .disarm;
        }

        // -- Handshake context callbacks --

        pub fn onSuccess(self: *ClientSelf, hs: *Handshake) void {
            const leftover = hs.read_pos - hs.header_len;
            log.debug("onSuccess: handshake completed, leftover={d} bytes", .{leftover});

            // Initialize the caller's connection in-place.
            // Critical: init() does NOT touch read_buf — the handshake read its
            // HTTP response into conn.read_buf (borrowed). The leftover bytes are
            // still there at an offset. Point the reader at them in-place.
            self.conn.init(
                hs.socket,
                self.loop,
                self.buffer_pool,
                self.handler,
                self.allocator,
                .{
                    .max_message_size = self.config.max_message_size,
                    .close_timeout_ms = self.config.close_timeout_ms,
                },
                self.csprng,
            );
            self.conn.start(hs.header_len, hs.read_pos);
        }

        pub fn onError(self: *ClientSelf, hs: *Handshake) void {
            log.debug("onError: handshake failed, state={s}, write_pos={d}, " ++
                "request_len={d}, read_pos={d}", .{
                @tagName(hs.state),
                hs.write_pos,
                hs.request_len,
                hs.read_pos,
            });
            if (hs.read_pos > 0) {
                const preview_len = @min(hs.read_pos, 256);
                log.debug("onError: server response ({d} bytes): {s}", .{
                    hs.read_pos,
                    hs.read_buf[0..preview_len],
                });
            } else if (hs.request_len == 0) {
                log.debug("onError: writeRequest failed (request never built)", .{});
            } else if (hs.write_pos < hs.request_len) {
                log.debug("onError: write failed at {d}/{d} bytes", .{
                    hs.write_pos,
                    hs.request_len,
                });
            } else {
                log.debug("onError: write succeeded but read got error/EOF", .{});
            }
            // Close the socket, then notify handler via onSocketClose
            hs.closeSocketWithCallback(ClientSelf, self, onFailClose);
        }
    };
}
