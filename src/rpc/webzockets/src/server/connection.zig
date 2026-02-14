const std = @import("std");
const xev = @import("xev");

const types = @import("../types.zig");
const frame = @import("../frame.zig");
const buffer = @import("../buffer.zig");
const Reader = @import("../reader.zig").Reader(.server);
const ControlQueue = @import("../control_queue.zig").ControlQueue;

/// Poolable server connection that handles the WebSocket protocol phase
/// (after HTTP upgrade). Owns its read buffer, manages write scheduling,
/// and handles lifecycle (pool release, list removal) internally.
///
/// Comptime parameters:
///   - `ServerType`: The server struct (provides pools, loop, active list).
///   - `Handler`: User handler for protocol events (see below).
///   - `read_buf_size`: Size of the embedded per-connection read buffer.
///
/// **Required handler methods** (comptime-enforced):
///   - `onMessage(*Handler, *Conn, types.Message)` — complete message received.
///   - `onWriteComplete(*Handler, *Conn)` — send finished; caller buffer may be
///     freed. Also called on disconnect if a data write was in-flight/pending.
///   - `onClose(*Handler, *Conn)` — connection torn down (exactly once). The
///     connection is released back to the pool after this returns.
///
/// **Optional handler methods** (detected via `@hasDecl`):
///   - `onOpen(*Handler, *Conn)` — protocol phase started, ready to send.
///   - `onPing(*Handler, *Conn, []const u8)` — ping received. When declared,
///     the handler is responsible for sending pong via `sendPong()`, which
///     enqueues each pong individually into the control queue. When absent,
///     the library auto-pongs using "latest wins" semantics: if multiple
///     pings arrive before a pong can be sent, only the most recent ping's
///     payload is used (permitted by RFC 6455 §5.5.3). Implement `onPing`
///     if you need to respond to every ping.
///   - `onPong(*Handler, *Conn, []const u8)` — pong received.
///   - `onBytesRead(*Handler, *Conn, usize)` — raw TCP data received.
///     Fires on every read completion regardless of whether reads are paused.
///     `usize` parameter is the number of bytes received. Combine with
///     `peekBufferedBytes()` to inspect raw data as it arrives.
///
/// All data slices passed to read callbacks point into internal buffers and are
/// only valid for the duration of that callback.
pub fn Connection(
    comptime ServerType: type,
    comptime Handler: type,
    comptime read_buf_size: usize,
) type {
    comptime {
        if (!@hasDecl(Handler, "onMessage"))
            @compileError("Handler must declare an onMessage method");
        if (!@hasDecl(Handler, "onWriteComplete"))
            @compileError("Handler must declare an onWriteComplete method (sends are zero-copy)");
        if (!@hasDecl(Handler, "onClose"))
            @compileError("Handler must declare an onClose method");
    }

    return struct {
        // -- Owned read buffer --
        read_buf: [read_buf_size]u8,

        // -- Core state --
        state: types.ConnectionState,
        socket: xev.TCP,
        allocator: std.mem.Allocator,
        config: Config,
        /// When true all message bytes received are buffered (up to current reader capacity)
        /// but onMessage/onPing/onPong/close-frame handling is deferred until reads
        /// are resumed.
        read_paused: bool,
        /// Re-entrancy guard: true while processMessages is on the call stack.
        in_process_messages: bool,

        // -- Tiered read buffer management --
        reader: Reader,

        // -- Completions --
        read_completion: xev.Completion,
        close_completion: xev.Completion,
        write_completion: xev.Completion,
        cancel_completion: xev.Completion,

        // -- Write state --
        write: WriteState,

        // -- Timer state --
        timer: xev.Timer,
        idle_timer_completion: xev.Completion,
        idle_timer_cancel_completion: xev.Completion,
        close_timer_completion: xev.Completion,
        close_timer_cancel_completion: xev.Completion,
        received_data: bool,

        // -- Server back-pointer --
        server: *ServerType,

        // -- User handler, called directly --
        user_handler: Handler,

        // -- Intrusive list node for server's active_connections list --
        node: List.Node,

        const ConnectionSelf = @This();

        const log = std.log.scoped(.server_connection);

        /// Comptime flags for optional handler capabilities.
        const has = struct {
            const on_open = @hasDecl(Handler, "onOpen");
            const on_ping = @hasDecl(Handler, "onPing");
            const on_pong = @hasDecl(Handler, "onPong");
            const on_bytes_read = @hasDecl(Handler, "onBytesRead");
        };

        pub const List = std.DoublyLinkedList(*ConnectionSelf);

        pub const Config = struct {
            /// Maximum total size of a reassembled fragmented message.
            max_message_size: usize = 16 * 1024 * 1024,
            /// Idle timeout in ms. Server sends close (going_away) if no data
            /// received for this long. null = disabled (default).
            idle_timeout_ms: ?u32 = null,
            /// Close handshake timeout in ms. Force disconnect if peer doesn't
            /// respond to our close frame within this duration. Default: 5000.
            close_timeout_ms: u32 = 5_000,
        };

        /// Holds pending auto-pong payload when the handler does not declare
        /// `onPing` (the library auto-responds). When `onPing` is declared this
        /// is a zero-sized struct, adding no bytes to WriteState.
        const AutoPongState = if (has.on_ping)
            // Handler manages pong responses; no auto-pong state needed.
            struct {}
        else
            struct {
                /// Whether an auto-pong is pending (latest ping payload wins).
                pending: bool = false,
                /// Payload for the pending auto-pong.
                data: [125]u8 = undefined,
                /// Length of the pending auto-pong payload.
                len: u8 = 0,
            };

        /// All write-path state, grouped for clarity.
        const WriteState = struct {
            /// What is currently being written to the socket.
            const InFlight = union(enum) {
                idle,
                /// Two-phase data write: header bytes first, then caller's payload.
                data: struct {
                    phase: enum { header, payload },
                    offset: usize,
                },
                /// Single-phase control frame write from control_buf.
                control: struct {
                    offset: usize,
                },
            };

            /// Current in-flight write operation state.
            in_flight: InFlight = .idle,

            // Data write buffers — populated in startDataWrite, used by both
            // in-flight (.data) and deferred data writes.
            /// Header buffer for current or pending data write.
            header_buf: [10]u8 = undefined,
            /// Length of actual header in header_buf.
            header_len: usize = 0,
            /// Payload for current or pending data write.
            payload: []const u8 = &.{},

            // Control frame buffers — control_buf holds the in-flight frame,
            // control_queue holds deferred control frames.
            /// Control frame buffer for in-flight control writes.
            control_buf: [127]u8 = undefined,
            /// Length of actual control frame in control_buf.
            control_len: usize = 0,
            /// Queue for pending control frames (close, ping, pong).
            control_queue: ControlQueue = ControlQueue.init(),
            /// Auto-pong state (only present when Handler lacks onPing).
            auto_pong: AutoPongState = .{},
            /// True when we should disconnect after sending the current close frame.
            /// Set when the peer initiates a close (we echo and disconnect) or when
            /// we detect a protocol error (we send 1002 and disconnect).
            peer_caused_close: bool = false,
        };

        // ====================================================================
        // Lifecycle
        // ====================================================================

        /// Initialize the connection in-place. Sets all runtime fields except
        /// `read_buf` (the pool provides the struct and the buffer is embedded).
        /// Reader is initialized with `&self.read_buf`.
        pub fn init(
            self: *ConnectionSelf,
            socket: xev.TCP,
            server: *ServerType,
            user_handler: Handler,
            allocator: std.mem.Allocator,
            pool: *buffer.BufferPool,
            config: Config,
        ) void {
            self.socket = socket;
            self.server = server;
            self.user_handler = user_handler;
            self.allocator = allocator;
            self.config = config;
            self.reader = Reader.init(
                &self.read_buf,
                pool,
                allocator,
                config.max_message_size,
            );
            self.timer = xev.Timer.init() catch unreachable;
            self.resetOpenRuntimeState();
        }

        /// Release any resources allocated by the connection (reader buffers).
        /// Note: not used in pool-managed server connections — `SlotPool.release`
        /// calls `reset()` which performs the same cleanup. Provided for manual
        /// lifecycle management outside of a pool.
        pub fn deinit(self: *ConnectionSelf) void {
            self.reader.deinit();
            self.timer.deinit();
        }

        /// Reset the connection state for reuse from a pool.
        /// Cleans up any fragment buffers and resets all state.
        pub fn reset(self: *ConnectionSelf) void {
            self.reader.reset();
            self.resetOpenRuntimeState();
        }

        fn resetOpenRuntimeState(self: *ConnectionSelf) void {
            self.state = .open;
            self.read_completion = .{};
            self.close_completion = .{};
            self.write_completion = .{};
            self.cancel_completion = .{};
            self.write = .{};
            self.idle_timer_completion = .{};
            self.idle_timer_cancel_completion = .{};
            self.close_timer_completion = .{};
            self.close_timer_cancel_completion = .{};
            self.received_data = false;
            self.read_paused = false;
            self.in_process_messages = false;
        }

        /// Begin the WebSocket protocol phase. Sets the reader position to
        /// account for leftover handshake bytes already in the read buffer,
        /// calls `onOpen` (if defined), then processes any leftover data and
        /// starts reading new data.
        pub fn start(self: *ConnectionSelf, data_start: usize, data_end: usize) void {
            std.debug.assert(data_start <= data_end);
            std.debug.assert(data_end <= self.reader.buf.len);
            self.reader.start = data_start;
            self.reader.pos = data_end;

            if (comptime has.on_open) {
                self.user_handler.onOpen(self);
            }

            // NOTE: we check state is still open here to avoid arming the idle
            // timer if the handler.onOpen() called close().
            if (self.state == .open) {
                // Start idle timer if configured
                if (self.config.idle_timeout_ms) |timeout_ms| {
                    self.timer.run(
                        self.server.loop,
                        &self.idle_timer_completion,
                        timeout_ms,
                        ConnectionSelf,
                        self,
                        onIdleTimerCallback,
                    );
                }
            }

            // Process any leftover handshake data, and start reading
            self.processMessages();
        }

        // ====================================================================
        // Public send API
        // ====================================================================

        /// Send a text message. The payload is written zero-copy; keep the buffer
        /// alive and unmodified until `onWriteComplete` fires. Only one data
        /// write can be in flight; returns `error.WriteBusy` if another send is
        /// pending. Queue additional sends and retry from `onWriteComplete`.
        pub fn sendText(self: *ConnectionSelf, data: []const u8) !void {
            if (self.state != .open) return error.InvalidState;
            try self.startDataWrite(.text, data);
        }

        /// Send a binary message. The payload is written zero-copy; keep the buffer
        /// alive and unmodified until `onWriteComplete` fires. Only one data
        /// write can be in flight; returns `error.WriteBusy` if another send is
        /// pending. Queue additional sends and retry from `onWriteComplete`.
        pub fn sendBinary(self: *ConnectionSelf, data: []const u8) !void {
            if (self.state != .open) return error.InvalidState;
            try self.startDataWrite(.binary, data);
        }

        /// Send a ping frame. The payload is copied into an internal control queue,
        /// so the caller can free the buffer immediately after this returns.
        /// No `onWriteComplete` callback fires for ping sends.
        /// Returns `error.ControlFrameTooBig` if payload exceeds 125 bytes,
        /// or `error.QueueFull` if the control queue has insufficient space.
        pub fn sendPing(self: *ConnectionSelf, data: []const u8) !void {
            if (self.state != .open) return error.InvalidState;
            if (data.len > 125) return error.ControlFrameTooBig;
            try self.enqueueAndFlush(.ping, data);
        }

        /// Send a pong frame. The payload is copied into an internal control queue,
        /// so the caller can free the buffer immediately after this returns.
        /// No `onWriteComplete` callback fires for pong sends.
        /// Returns `error.ControlFrameTooBig` if payload exceeds 125 bytes,
        /// or `error.QueueFull` if the control queue has insufficient space.
        pub fn sendPong(self: *ConnectionSelf, data: []const u8) !void {
            if (self.state != .open) return error.InvalidState;
            if (data.len > 125) return error.ControlFrameTooBig;
            try self.enqueueAndFlush(.pong, data);
        }

        /// Initiate a close handshake with the given status code and optional reason.
        /// The connection transitions to `.closing` and waits for the peer's close response.
        /// The reason is silently truncated to 123 bytes (the maximum allowed by RFC 6455
        /// after the 2-byte close code in a 125-byte control frame payload).
        pub fn close(self: *ConnectionSelf, code: types.CloseCode, reason: []const u8) void {
            if (self.state != .open) return;
            self.initiateClose(code, reason);

            // Cancel idle timer to avoid repeated wakeups during the close handshake.
            self.cancelTimer(&self.idle_timer_completion, &self.idle_timer_cancel_completion);
        }

        /// Pause frame dispatch. While paused, onMessage/onPing/onPong/close-frame
        /// handling stops until `resumeReads()` is called. TCP reads continue until
        /// read buffer is full, but will not grow the buffer while paused.
        pub fn pauseReads(self: *ConnectionSelf) void {
            self.read_paused = true;
        }

        /// Resume frame dispatch and drain any already-buffered frames, this will
        /// cause onMessage/onPing/onPong/close-frame handling to resume.
        pub fn resumeReads(self: *ConnectionSelf) void {
            if (self.state == .closed or !self.read_paused) return;
            self.read_paused = false;
            self.processMessages();
        }

        /// Peek at the raw bytes currently buffered in the reader (received
        /// from TCP but not yet consumed as websocket frames). The returned
        /// slice points into an internal buffer and may be invalidated as soon
        /// as the xev loop ticks again.
        pub fn peekBufferedBytes(self: *ConnectionSelf) []const u8 {
            return self.reader.buf[self.reader.start..self.reader.pos];
        }

        /// Perform the state transition and close frame enqueue.
        /// Ensures the close-handshake timer is running.
        fn initiateClose(self: *ConnectionSelf, code: types.CloseCode, reason: []const u8) void {
            self.state = .closing;

            // Build close payload: 2-byte big-endian status code + reason text
            var payload: [125]u8 = undefined;
            payload[0..2].* = code.payloadBytes();
            const reason_len = @min(reason.len, 123); // control frame payload max 125
            @memcpy(payload[2..][0..reason_len], reason[0..reason_len]);
            const total_len: u8 = @intCast(2 + reason_len);

            self.write.peer_caused_close = false;
            self.enqueueClose(payload[0..total_len]);

            // Start close-handshake deadline timer.
            // Uses a dedicated completion so it can't be clobbered by the idle
            // timer's guaranteed `error.Canceled` callback.
            if (self.close_timer_completion.state() != .active) {
                self.timer.run(
                    self.server.loop,
                    &self.close_timer_completion,
                    self.config.close_timeout_ms,
                    ConnectionSelf,
                    self,
                    onCloseTimerCallback,
                );
            }
        }

        // ====================================================================
        // Read path
        // ====================================================================

        /// Arm another socket read when legal; while paused this continues
        /// filling the read buffer until it has no free space.
        fn maybeReadMore(self: *ConnectionSelf) void {
            if (self.state == .closed or self.write.peer_caused_close) return;
            if (self.read_completion.state() == .active) return;
            if (self.read_paused) {
                // Reclaim consumed bytes if buffer is full so we can buffer as much as
                // possible without growing the read buffer.
                self.reader.compactIfFull();
                // If still full then just return to avoid growing the buffer
                if (self.reader.availableSpace() == 0) return;
            }
            self.startRead();
        }

        fn startRead(self: *ConnectionSelf) void {
            const slice = self.reader.readSlice() catch |err| {
                log.debug("readSlice failed: {}", .{err});
                self.handleDisconnect();
                return;
            };
            self.socket.read(
                self.server.loop,
                &self.read_completion,
                .{ .slice = slice },
                ConnectionSelf,
                self,
                onReadCallback,
            );
        }

        fn onReadCallback(
            self_opt: ?*ConnectionSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.TCP,
            _: xev.ReadBuffer,
            result: xev.ReadError!usize,
        ) xev.CallbackAction {
            const self = self_opt orelse return .disarm;
            if (self.state == .closed) {
                self.checkAllDone();
                return .disarm;
            }

            const bytes_read = result catch |err| {
                log.debug("read failed: {}", .{err});
                self.handleDisconnect();
                return .disarm;
            };

            if (bytes_read == 0) {
                log.debug("peer closed TCP connection", .{});
                self.handleDisconnect();
                return .disarm;
            }

            self.received_data = true;
            self.reader.advancePos(bytes_read);

            if (comptime has.on_bytes_read) {
                self.user_handler.onBytesRead(self, bytes_read);
            }

            if (self.read_paused) {
                self.maybeReadMore();
                return .disarm;
            }

            switch (self.state) {
                .open, .closing => self.processMessages(),
                .closed => {},
            }

            return .disarm;
        }

        // ====================================================================
        // Frame processing
        // ====================================================================

        fn processMessages(self: *ConnectionSelf) void {
            // Re-entrancy guard: prevents recursion into processMessages() when a handler
            // calls resumeReads()
            if (self.in_process_messages) return;

            if (self.read_paused) {
                self.maybeReadMore();
                return;
            }

            self.in_process_messages = true;
            defer self.in_process_messages = false;

            while (true) {
                const maybe_msg = self.reader.nextMessage() catch |err| {
                    log.debug("nextMessage failed: {}", .{err});
                    switch (err) {
                        error.ProtocolError => self.failWithClose(.protocol_error),
                        error.MessageTooBig => self.failWithClose(.message_too_big),
                        error.OutOfMemory => self.handleDisconnect(),
                    }
                    return;
                };
                const msg = maybe_msg orelse break;

                switch (msg.type) {
                    .text, .binary => self.user_handler.onMessage(self, msg),
                    .ping => {
                        if (comptime has.on_ping) {
                            self.user_handler.onPing(self, msg.data);
                        } else {
                            // Auto-pong: store in dedicated field (latest wins)
                            const len: u8 = @intCast(msg.data.len);
                            @memcpy(self.write.auto_pong.data[0..len], msg.data[0..len]);
                            self.write.auto_pong.len = len;
                            self.write.auto_pong.pending = true;
                            self.trySubmitNextControl();
                        }
                    },
                    .pong => {
                        if (comptime has.on_pong) {
                            self.user_handler.onPong(self, msg.data);
                        }
                    },
                    .close => {
                        self.handleCloseFrame(msg.data);
                        if (self.state == .closed) return;
                    },
                }
                if (self.state == .closed or self.read_paused) break;
            }
            // Only start a new read if we're still active.
            // When peer_caused_close is set, we're echoing the peer's close frame
            // and will disconnect as soon as the write completes — no need to read more.
            self.maybeReadMore();
        }

        /// Send a close frame with the given code and disconnect.
        /// Used for server-initiated error closes (protocol error, message too big).
        fn failWithClose(self: *ConnectionSelf, code: types.CloseCode) void {
            if (self.state == .closed) return;
            self.state = .closing;
            self.write.peer_caused_close = true;
            const close_payload = code.payloadBytes();
            self.enqueueClose(&close_payload);
        }

        fn handleCloseFrame(self: *ConnectionSelf, payload: []const u8) void {
            if (self.state == .closing) {
                // Already in closing state. If we're waiting to send our close response
                // (peer_caused_close), ignore this duplicate. Otherwise, we initiated
                // the close and this is the peer's response — complete the handshake.
                if (!self.write.peer_caused_close) {
                    self.handleDisconnect();
                }
                // else: peer sent multiple close frames — ignore per RFC 6455
            } else {
                // Peer initiated — validate and echo the close frame, then disconnect
                self.state = .closing;
                self.write.peer_caused_close = true;

                const validation = types.validateClosePayload(payload);
                switch (validation) {
                    .valid_payload => |vp| self.enqueueClose(vp),
                    .close_code => |code| {
                        const close_payload = code.payloadBytes();
                        self.enqueueClose(&close_payload);
                    },
                }
            }
        }

        // ====================================================================
        // Write path
        // ====================================================================

        /// True when a user data write is in-flight or deferred.
        fn outstandingUserWrite(self: *ConnectionSelf) bool {
            return self.write.header_len != 0;
        }

        /// Start a two-phase data write: header first, then payload.
        /// If a control frame is in flight, the data write is deferred and will
        /// start automatically when the control frame completes.
        /// Returns error.WriteBusy if another data write is already in flight or pending.
        fn startDataWrite(self: *ConnectionSelf, opcode: types.Opcode, payload: []const u8) !void {
            // Only one data write can be pending/in-flight at a time
            if (self.outstandingUserWrite()) {
                return error.WriteBusy;
            }

            // Build header into inline buffer (safe — header_buf is not used by control writes)
            // Compression integration point: pass compressed=true when permessage-deflate is active
            const header = frame.writeFrameHeader(
                &self.write.header_buf,
                opcode,
                payload.len,
                false,
            );
            self.write.header_len = header.len;
            self.write.payload = payload;

            if (self.write.in_flight == .control) {
                // Control frame in flight — defer data write until it completes
                return;
            }

            // Idle — start immediately
            self.write.in_flight = .{ .data = .{ .phase = .header, .offset = 0 } };
            self.submitWrite(self.write.header_buf[0..self.write.header_len]);
        }

        /// Build a control frame into control_buf and issue the socket write.
        fn writeControlFrame(self: *ConnectionSelf, opcode: types.Opcode, payload: []const u8) void {
            const header = frame.writeFrameHeader(
                self.write.control_buf[0..10],
                opcode,
                payload.len,
                false,
            );
            const header_len = header.len;
            if (payload.len > 0) {
                @memcpy(self.write.control_buf[header_len..][0..payload.len], payload);
            }
            self.write.control_len = header_len + payload.len;
            self.write.in_flight = .{ .control = .{ .offset = 0 } };

            self.submitWrite(self.write.control_buf[0..self.write.control_len]);
        }

        /// Issue a socket write for the given slice.
        fn submitWrite(self: *ConnectionSelf, slice: []const u8) void {
            self.socket.write(
                self.server.loop,
                &self.write_completion,
                .{ .slice = slice },
                ConnectionSelf,
                self,
                onWriteCallback,
            );
        }

        /// Advance a write offset by bytes_written. If the full slice has been
        /// written, returns true. Otherwise reissues a write for the remainder.
        fn advanceWrite(
            self: *ConnectionSelf,
            offset: *usize,
            bytes_written: usize,
            full_slice: []const u8,
        ) bool {
            offset.* += bytes_written;
            if (offset.* < full_slice.len) {
                self.submitWrite(full_slice[offset.*..]);
                return false;
            }
            return true;
        }

        fn onWriteCallback(
            self_opt: ?*ConnectionSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.TCP,
            _: xev.WriteBuffer,
            result: xev.WriteError!usize,
        ) xev.CallbackAction {
            const self = self_opt orelse return .disarm;

            if (self.state == .closed) {
                self.checkAllDone();
                return .disarm;
            }

            const bytes_written = result catch |err| {
                log.debug("write failed: {}", .{err});
                self.handleDisconnect();
                return .disarm;
            };

            switch (self.write.in_flight) {
                .data => |*d| switch (d.phase) {
                    .header => {
                        const header_data = self.write.header_buf[0..self.write.header_len];
                        if (self.advanceWrite(&d.offset, bytes_written, header_data)) {
                            if (self.write.payload.len == 0) {
                                self.finishWrite();
                            } else {
                                d.phase = .payload;
                                d.offset = 0;
                                self.submitWrite(self.write.payload);
                            }
                        }
                    },
                    .payload => {
                        if (self.advanceWrite(&d.offset, bytes_written, self.write.payload)) {
                            self.finishWrite();
                        }
                    },
                },
                .control => |*ctrl| {
                    const control_data = self.write.control_buf[0..self.write.control_len];
                    if (self.advanceWrite(&ctrl.offset, bytes_written, control_data)) {
                        self.finishControlWrite();
                    }
                },
                .idle => {},
            }

            return .disarm;
        }

        fn finishWrite(self: *ConnectionSelf) void {
            self.write.in_flight = .idle;
            self.write.payload = &.{};
            self.write.header_len = 0;
            // Flush pending controls first (priority over data) before invoking user callback
            self.trySubmitNextControl();
            self.user_handler.onWriteComplete(self);
        }

        fn finishControlWrite(self: *ConnectionSelf) void {
            self.write.in_flight = .idle;

            if (self.write.peer_caused_close) {
                // Close frame sent (peer-initiated echo or protocol error) — tear down
                self.write.peer_caused_close = false;
                self.handleDisconnect();
                return;
            }

            // Pending controls have priority over pending data writes
            self.trySubmitNextControl();
            if (self.write.in_flight == .idle and self.outstandingUserWrite()) {
                // Start deferred data write (header already built in header_buf)
                self.write.in_flight = .{ .data = .{ .phase = .header, .offset = 0 } };
                self.submitWrite(self.write.header_buf[0..self.write.header_len]);
            }
        }

        /// Enqueue a control frame and flush if the write path is idle.
        fn enqueueAndFlush(self: *ConnectionSelf, opcode: types.Opcode, data: []const u8) !void {
            try self.write.control_queue.enqueue(opcode, data);
            self.trySubmitNextControl();
        }

        /// Enqueue a close frame, clearing any pending controls (close takes priority).
        fn enqueueClose(self: *ConnectionSelf, payload: []const u8) void {
            self.write.control_queue.clear();
            if (comptime !has.on_ping) {
                self.write.auto_pong.pending = false;
            }
            self.write.control_queue.enqueue(.close, payload) catch unreachable;
            self.trySubmitNextControl();
        }

        /// Flush the next pending control frame, if any. No-op when a write is
        /// already in flight. Implements the priority chain:
        /// 1. Close frame in the queue (always wins)
        /// 2. Pending auto-pong (latest ping payload)
        /// 3. Other queued control frames (FIFO)
        fn trySubmitNextControl(self: *ConnectionSelf) void {
            if (self.write.in_flight != .idle) return;

            var payload_buf: [125]u8 = undefined;
            // Priority 1: Close frame in queue
            if (self.write.control_queue.isNextClose()) {
                const entry = self.write.control_queue.dequeue(&payload_buf).?;
                self.writeControlFrame(entry.opcode, payload_buf[0..entry.len]);
                return;
            }
            // Priority 2: Pending auto-pong
            if (comptime !has.on_ping) {
                if (self.write.auto_pong.pending) {
                    self.write.auto_pong.pending = false;
                    const pong_data = self.write.auto_pong.data[0..self.write.auto_pong.len];
                    self.writeControlFrame(.pong, pong_data);
                    return;
                }
            }
            // Priority 3: Other queued control frames
            if (self.write.control_queue.dequeue(&payload_buf)) |entry| {
                self.writeControlFrame(entry.opcode, payload_buf[0..entry.len]);
            }
        }

        // ====================================================================
        // Timer callbacks
        // ====================================================================

        fn onIdleTimerCallback(
            self_opt: ?*ConnectionSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            result: xev.Timer.RunError!void,
        ) xev.CallbackAction {
            const self = self_opt orelse return .disarm;

            result catch |err| switch (err) {
                error.Canceled => {
                    if (self.state == .closed) self.checkAllDone();
                    return .disarm;
                },
                error.Unexpected => |e| {
                    // should never happen
                    log.err("idle timer error: {}", .{e});
                    // just disconnect to avoid leaking resources
                    self.handleDisconnect();
                    return .disarm;
                },
            };

            switch (self.state) {
                .open => {
                    if (self.received_data) {
                        // Activity detected — clear flag, re-run idle timer
                        self.received_data = false;
                        self.timer.run(
                            self.server.loop,
                            &self.idle_timer_completion,
                            self.config.idle_timeout_ms.?,
                            ConnectionSelf,
                            self,
                            onIdleTimerCallback,
                        );
                    } else {
                        // Idle timeout
                        self.initiateClose(.going_away, "");
                    }
                },
                .closing => {
                    // We may be in the middle of a server-initiated close while the
                    // idle timer is being canceled; never treat an idle timer fire
                    // as a close timeout.
                },
                .closed => self.checkAllDone(),
            }

            return .disarm;
        }

        fn onCloseTimerCallback(
            self_opt: ?*ConnectionSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            result: xev.Timer.RunError!void,
        ) xev.CallbackAction {
            const self = self_opt orelse return .disarm;

            result catch |err| switch (err) {
                error.Canceled => {
                    if (self.state == .closed) self.checkAllDone();
                    return .disarm;
                },
                error.Unexpected => |e| {
                    // should never happen
                    log.err("close timer error: {}", .{e});
                    // fallthrough to enforce close/cleanup
                },
            };

            switch (self.state) {
                .closing => {
                    if (!self.write.peer_caused_close) {
                        // Close timeout expired (server-initiated) — force disconnect
                        self.handleDisconnect();
                    }
                    // else: peer-initiated close — write path handles disconnect
                },
                .open => {
                    // Shouldn't happen: close timer is only armed for server-initiated closes.
                },
                .closed => self.checkAllDone(),
            }

            return .disarm;
        }

        fn onTimerCancelled(
            self_opt: ?*ConnectionSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            result: xev.Timer.CancelError!void,
        ) xev.CallbackAction {
            // Cancel completion exists so we can wait for a backend-specific
            // timer removal operation to complete (io_uring uses timer_remove).
            result catch |err| log.debug("timer cancel error: {}", .{err});

            // Only relevant for teardown if the connection closed while the
            // cancellation was in-flight.
            if (self_opt) |self| {
                if (self.state == .closed) self.checkAllDone();
            }
            return .disarm;
        }

        // ====================================================================
        // Cleanup
        // ====================================================================

        fn handleDisconnect(self: *ConnectionSelf) void {
            if (self.state == .closed) return;
            self.state = .closed;

            // Notify handler if a data write was in flight or pending so buffer
            // can be cleaned up. Not fired for internal control frame writes.
            if (self.outstandingUserWrite()) {
                self.user_handler.onWriteComplete(self);
            }

            self.write = .{};
            self.user_handler.onClose(self);

            self.cancelTimer(&self.idle_timer_completion, &self.idle_timer_cancel_completion);
            self.cancelTimer(&self.close_timer_completion, &self.close_timer_cancel_completion);
            self.cancelActive(&self.read_completion, &self.cancel_completion);
            self.cancelActive(&self.write_completion, &self.close_completion);

            self.checkAllDone();
        }

        /// Raw xev callback for cancel completions.
        fn cancelCallback(
            ud: ?*anyopaque,
            _: *xev.Loop,
            _: *xev.Completion,
            result: xev.Result,
        ) xev.CallbackAction {
            result.cancel catch |err| log.debug("cancel failed: {}", .{err});
            if (ud) |ptr| {
                const self: *ConnectionSelf = @ptrCast(@alignCast(ptr));
                self.checkAllDone();
            }
            return .disarm;
        }

        /// Cancel an active timer using its cancel completion slot.
        fn cancelTimer(
            self: *ConnectionSelf,
            timer_completion: *xev.Completion,
            cancel_slot: *xev.Completion,
        ) void {
            const is_active = timer_completion.state() == .active;
            if (is_active and cancel_slot.state() != .active) {
                // Cancel via xev.Timer.cancel() (not a raw `.cancel` op) since some
                // backends (e.g. io_uring) require a timer-specific remove.
                self.timer.cancel(
                    self.server.loop,
                    timer_completion,
                    cancel_slot,
                    ConnectionSelf,
                    self,
                    onTimerCancelled,
                );
            }
        }

        /// Cancel an active completion using a cancel slot.
        fn cancelActive(
            self: *ConnectionSelf,
            target: *xev.Completion,
            cancel_slot: *xev.Completion,
        ) void {
            if (target.state() == .active) {
                cancel_slot.* = .{
                    .op = .{ .cancel = .{ .c = target } },
                    .userdata = @ptrCast(self),
                    .callback = cancelCallback,
                };
                self.server.loop.add(cancel_slot);
            }
        }

        /// Check if all completions (read, write, cancel, close) are inactive.
        /// If so, initiate async shutdown then close.
        fn checkAllDone(self: *ConnectionSelf) void {
            const completions = [_]*xev.Completion{
                &self.read_completion,
                &self.write_completion,
                &self.cancel_completion,
                &self.close_completion,
                &self.idle_timer_completion,
                &self.idle_timer_cancel_completion,
                &self.close_timer_completion,
                &self.close_timer_cancel_completion,
            };
            for (completions) |c| {
                if (c.state() == .active) return;
            }

            // Shutdown write side to send FIN, this is required by RFC 6455.
            // Reuses close_completion since all cancellations are done. The
            // shutdown callback then reuses it again for the final socket close.
            self.socket.shutdown(
                self.server.loop,
                &self.close_completion,
                ConnectionSelf,
                self,
                onShutdownComplete,
            );
        }

        fn onShutdownComplete(
            self_opt: ?*ConnectionSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.TCP,
            result: xev.ShutdownError!void,
        ) xev.CallbackAction {
            // Shutdown errors are expected — socket may already be closed by client (ENOTCONN).
            result catch |err| log.debug("shutdown failed: {}", .{err});
            if (self_opt) |self| {
                self.closeSocket();
            }
            return .disarm;
        }

        fn closeSocket(self: *ConnectionSelf) void {
            self.socket.close(
                self.server.loop,
                &self.close_completion,
                ConnectionSelf,
                self,
                onCloseComplete,
            );
        }

        fn onCloseComplete(
            self_opt: ?*ConnectionSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.TCP,
            result: xev.CloseError!void,
        ) xev.CallbackAction {
            result catch |err| log.debug("close failed: {}", .{err});
            if (self_opt) |self| {
                // Remove from server's active connections list and release to pool.
                self.server.active_connections.remove(&self.node);
                self.server.connection_pool.release(self);
            }
            return .disarm;
        }
    };
}
