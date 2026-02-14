const std = @import("std");
const xev = @import("xev");
const types = @import("../types.zig");
const http = @import("../http.zig");

/// Poolable server handshake — reads the HTTP upgrade request, validates it,
/// writes the 101 response, creates the user handler, and transitions to
/// the connection phase. Owns its read buffer and holds a server back-pointer.
///
/// Comptime parameters:
///   - `ServerType`: Server struct providing pools, loop, allocator, config,
///     active_connections, and shutting_down flag.
///   - `Handler`: User handler type. See `Server` doc comment for the full
///     handler contract including `init`, `onHandshakeFailed`, and Context.
///   - `read_buf_size`: Size of the embedded HTTP read buffer.
pub fn Handshake(
    comptime ServerType: type,
    comptime Handler: type,
    comptime read_buf_size: usize,
) type {
    return struct {
        read_buf: [read_buf_size]u8,
        response_buf: [response_buf_len]u8,
        state: types.HandshakeState,
        socket: xev.TCP,
        read_pos: usize,
        response_len: usize,
        write_pos: usize,
        head_parser: http.HeadParser,
        read_completion: xev.Completion,
        write_completion: xev.Completion,
        close_completion: xev.Completion,
        header_len: usize,
        server: *ServerType,
        user_handler: ?Handler,

        const HandshakeSelf = @This();

        const log = std.log.scoped(.server_handshake);
        const has_on_handshake_failed = @hasDecl(Handler, "onHandshakeFailed");

        /// Fixed-size buffer length for the HTTP 101 Switching Protocols response.
        /// 129 bytes: status line + headers + base64-encoded accept key + \r\n\r\n.
        const response_buf_len = 129;

        /// Initialize the handshake in-place. Sets all runtime fields except
        /// `read_buf` (the pool provides the struct and the buffer is embedded).
        pub fn init(self: *HandshakeSelf, socket: xev.TCP, server: *ServerType) void {
            self.reset();
            self.socket = socket;
            self.server = server;
            self.response_buf = undefined;
        }

        /// Begin reading the HTTP upgrade request from the socket.
        pub fn start(self: *HandshakeSelf) void {
            self.startRead();
        }

        /// Reset all state for pool reuse. Does not touch `read_buf`.
        pub fn reset(self: *HandshakeSelf) void {
            self.state = .reading;
            self.read_pos = 0;
            self.response_len = 0;
            self.write_pos = 0;
            self.head_parser = .{};
            self.read_completion = .{};
            self.write_completion = .{};
            self.close_completion = .{};
            self.header_len = 0;
            self.user_handler = null;
        }

        fn startRead(self: *HandshakeSelf) void {
            if (self.read_pos >= self.read_buf.len) {
                log.debug("handshake failed: read buffer full", .{});
                self.fail();
                return;
            }

            self.socket.read(
                self.server.loop,
                &self.read_completion,
                .{ .slice = self.read_buf[self.read_pos..] },
                HandshakeSelf,
                self,
                onReadCallback,
            );
        }

        fn onReadCallback(
            self_opt: ?*HandshakeSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.TCP,
            _: xev.ReadBuffer,
            result: xev.ReadError!usize,
        ) xev.CallbackAction {
            const self = self_opt orelse return .disarm;
            if (self.state != .reading) return .disarm;

            const bytes_read = result catch |err| {
                log.debug("handshake read failed: {}", .{err});
                self.fail();
                return .disarm;
            };

            if (bytes_read == 0) {
                log.debug("handshake failed: peer closed connection", .{});
                self.fail();
                return .disarm;
            }

            const old_pos = self.read_pos;
            self.read_pos += bytes_read;

            // Feed only the new bytes to the incremental head parser.
            const consumed = self.head_parser.feed(self.read_buf[old_pos..self.read_pos]);
            if (self.head_parser.state != .finished) {
                self.startRead();
                return .disarm;
            }

            self.header_len = old_pos + consumed;
            self.processHandshake();
            return .disarm;
        }

        fn processHandshake(self: *HandshakeSelf) void {
            const req = http.parseRequest(self.read_buf[0..self.header_len]) catch |err| {
                log.debug("handshake failed: invalid HTTP request: {}", .{err});
                self.fail();
                return;
            };

            self.user_handler = Handler.init(req, self.server.config.handler_context) catch |err| {
                log.debug("handshake failed: handler rejected connection: {}", .{err});
                self.fail();
                return;
            };

            const response = http.writeResponse(&self.response_buf, req.websocket_key) catch |err| {
                log.debug("handshake failed: response write error: {}", .{err});
                self.fail();
                return;
            };

            self.response_len = response.len;
            self.write_pos = 0;
            self.state = .writing;
            self.startWrite();
        }

        fn startWrite(self: *HandshakeSelf) void {
            self.socket.write(
                self.server.loop,
                &self.write_completion,
                .{ .slice = self.response_buf[self.write_pos..self.response_len] },
                HandshakeSelf,
                self,
                onWriteComplete,
            );
        }

        fn onWriteComplete(
            self_opt: ?*HandshakeSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.TCP,
            _: xev.WriteBuffer,
            result: xev.WriteError!usize,
        ) xev.CallbackAction {
            const self = self_opt orelse return .disarm;
            if (self.state != .writing) return .disarm;

            const bytes_written = result catch |err| {
                log.debug("handshake write failed: {}", .{err});
                self.fail();
                return .disarm;
            };

            self.write_pos += bytes_written;

            if (self.write_pos < self.response_len) {
                self.startWrite();
                return .disarm;
            }

            self.state = .completed;
            self.transitionToConnection();
            return .disarm;
        }

        fn transitionToConnection(self: *HandshakeSelf) void {
            if (self.server.shutting_down) {
                log.debug("handshake rejected: shutting down", .{});
                self.fail();
                return;
            }

            const conn = self.server.connection_pool.create() catch {
                log.debug("handshake rejected: connection pool exhausted", .{});
                self.fail();
                return;
            };

            defer self.server.handshake_pool.release(self);

            const leftover = self.read_buf[self.header_len..self.read_pos];

            if (leftover.len > 0) {
                @memcpy(conn.read_buf[0..leftover.len], leftover);
            }

            conn.init(
                self.socket,
                self.server,
                self.user_handler.?,
                self.server.allocator,
                .{
                    .max_message_size = self.server.config.max_message_size,
                    .idle_timeout_ms = self.server.config.idle_timeout_ms,
                    .close_timeout_ms = self.server.config.close_timeout_ms,
                },
            );

            conn.node = .{ .data = conn };
            self.server.active_connections.append(&conn.node);
            conn.start(0, leftover.len);
        }

        /// Mark state as failed and close the socket.
        /// RFC 6455 §4.2.2 says the server should return an appropriate HTTP error
        /// code for failed WebSocket validation, but we close without a response
        /// for simplicity.
        fn fail(self: *HandshakeSelf) void {
            self.state = .failed;
            if (self.user_handler) |*handler| {
                if (comptime has_on_handshake_failed) {
                    handler.onHandshakeFailed();
                }
                self.user_handler = null;
            }
            self.closeAndRelease();
        }

        fn closeAndRelease(self: *HandshakeSelf) void {
            self.socket.close(
                self.server.loop,
                &self.close_completion,
                HandshakeSelf,
                self,
                onCloseComplete,
            );
        }

        fn onCloseComplete(
            self_opt: ?*HandshakeSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.TCP,
            result: xev.CloseError!void,
        ) xev.CallbackAction {
            result catch |err| log.debug("handshake close failed: {}", .{err});
            if (self_opt) |self| {
                self.server.handshake_pool.release(self);
            }
            return .disarm;
        }
    };
}
