const std = @import("std");
const xev = @import("xev");
const types = @import("../types.zig");
const http = @import("../http.zig");

/// Async HTTP upgrade client handshake wrapping libxev I/O.
///
/// Writes the HTTP upgrade request to the socket, reads the 101 response,
/// validates it, and calls the context's `onSuccess` or `onError` callback.
/// On error, the caller is responsible for closing the socket via
/// `closeSocketWithCallback`.
///
/// Comptime-parameterized by `Context`, which must declare:
///   - `onSuccess(ctx: *Context, hs: *ClientHandshake(Context)) void`
///   - `onError(ctx: *Context, hs: *ClientHandshake(Context)) void`
pub fn ClientHandshake(comptime Context: type) type {
    comptime {
        if (!@hasDecl(Context, "onSuccess"))
            @compileError("Context must declare an onSuccess method");
        if (!@hasDecl(Context, "onError"))
            @compileError("Context must declare an onError method");
    }

    return struct {
        state: types.HandshakeState,
        socket: xev.TCP,
        loop: *xev.Loop,
        context: *Context,

        read_buf: []u8,
        read_pos: usize,
        request_buf: [512]u8,
        request_len: usize,
        write_pos: usize,
        head_parser: http.HeadParser,

        key_buf: [24]u8,
        key_len: usize,

        /// Caller-provided PRNG used to generate the WebSocket key.
        /// Must only be used from the loop thread (not thread-safe).
        csprng: *types.ClientMaskPRNG,

        read_completion: xev.Completion,
        write_completion: xev.Completion,
        close_completion: xev.Completion,

        header_len: usize,

        const ClientHandshakeSelf = @This();

        const log = std.log.scoped(.client_handshake);

        pub fn init(
            socket: xev.TCP,
            loop: *xev.Loop,
            read_buf: []u8,
            context: *Context,
            csprng: *types.ClientMaskPRNG,
        ) ClientHandshakeSelf {
            return .{
                .state = .writing,
                .socket = socket,
                .loop = loop,
                .context = context,
                .read_buf = read_buf,
                .read_pos = 0,
                .request_buf = undefined,
                .request_len = 0,
                .write_pos = 0,
                .head_parser = .{},
                .key_buf = undefined,
                .key_len = 0,
                .csprng = csprng,
                .read_completion = .{},
                .write_completion = .{},
                .close_completion = .{},
                .header_len = 0,
            };
        }

        /// Begin the handshake: generate key, build request, write to socket.
        pub fn start(self: *ClientHandshakeSelf, address: std.net.Address, path: []const u8) void {
            log.debug("start: address={}, path={s}", .{ address, path });

            var raw_key: [16]u8 = undefined;
            self.csprng.fill(&raw_key);
            self.key_len = http.encodeKey(&self.key_buf, &raw_key).len;

            const key = self.key_buf[0..self.key_len];
            const request = http.writeRequest(&self.request_buf, address, path, key) catch {
                log.debug("start: writeRequest failed (buffer too small)", .{});
                self.fail();
                return;
            };
            self.request_len = request.len;
            self.write_pos = 0;
            self.state = .writing;
            log.debug("start: sending {d} byte request", .{self.request_len});

            // TODO: missing timer for write timeout
            self.socket.write(
                self.loop,
                &self.write_completion,
                .{ .slice = self.request_buf[0..self.request_len] },
                ClientHandshakeSelf,
                self,
                onWriteComplete,
            );
        }

        /// Close the socket with a caller-provided callback (so the caller
        /// can be notified when the close completes).
        pub fn closeSocketWithCallback(
            self: *ClientHandshakeSelf,
            comptime Ctx: type,
            ctx: *Ctx,
            comptime cb: fn (
                ?*Ctx,
                *xev.Loop,
                *xev.Completion,
                xev.TCP,
                xev.CloseError!void,
            ) xev.CallbackAction,
        ) void {
            self.socket.close(self.loop, &self.close_completion, Ctx, ctx, cb);
        }

        // ====================================================================
        // Internal
        // ====================================================================

        fn fail(self: *ClientHandshakeSelf) void {
            self.state = .failed;
            self.context.onError(self);
        }

        fn onWriteComplete(
            self_opt: ?*ClientHandshakeSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.TCP,
            _: xev.WriteBuffer,
            result: xev.WriteError!usize,
        ) xev.CallbackAction {
            const self = self_opt orelse return .disarm;
            if (self.state != .writing) return .disarm;

            const bytes_written = result catch |err| {
                log.debug("onWriteComplete: write error: {s}", .{@errorName(err)});
                self.fail();
                return .disarm;
            };

            self.write_pos += bytes_written;
            log.debug("onWriteComplete: wrote {d}/{d} bytes", .{ self.write_pos, self.request_len });

            if (self.write_pos < self.request_len) {
                self.socket.write(
                    self.loop,
                    &self.write_completion,
                    .{ .slice = self.request_buf[self.write_pos..self.request_len] },
                    ClientHandshakeSelf,
                    self,
                    onWriteComplete,
                );
                return .disarm;
            }

            // Request fully sent — start reading response
            log.debug("onWriteComplete: request fully sent, reading response", .{});
            self.state = .reading;
            self.startRead();
            return .disarm;
        }

        fn startRead(self: *ClientHandshakeSelf) void {
            if (self.read_pos >= self.read_buf.len) {
                log.debug("startRead: buffer full ({d} bytes), failing", .{self.read_pos});
                self.fail();
                return;
            }

            log.debug("startRead: reading at offset {d}, buf remaining {d}", .{
                self.read_pos,
                self.read_buf.len - self.read_pos,
            });
            // TODO: missing timer for read timeout
            self.socket.read(
                self.loop,
                &self.read_completion,
                .{ .slice = self.read_buf[self.read_pos..] },
                ClientHandshakeSelf,
                self,
                onReadCallback,
            );
        }

        fn onReadCallback(
            self_opt: ?*ClientHandshakeSelf,
            _: *xev.Loop,
            _: *xev.Completion,
            _: xev.TCP,
            _: xev.ReadBuffer,
            result: xev.ReadError!usize,
        ) xev.CallbackAction {
            const self = self_opt orelse return .disarm;
            if (self.state != .reading) return .disarm;

            const bytes_read = result catch |err| {
                log.debug("onReadCallback: read error: {s}", .{@errorName(err)});
                self.fail();
                return .disarm;
            };

            if (bytes_read == 0) {
                log.debug("onReadCallback: EOF (0 bytes read), total read so far: {d}", .{
                    self.read_pos,
                });
                self.fail();
                return .disarm;
            }

            log.debug("onReadCallback: read {d} bytes, total {d}", .{
                bytes_read,
                self.read_pos + bytes_read,
            });
            const old_pos = self.read_pos;
            self.read_pos += bytes_read;

            // Feed only the new bytes to the incremental head parser.
            const new_data = self.read_buf[old_pos..self.read_pos];
            const consumed = self.head_parser.feed(new_data);
            if (self.head_parser.state != .finished) {
                // Headers not yet complete — keep reading.
                self.startRead();
                return .disarm;
            }

            self.header_len = old_pos + consumed;
            self.processResponse();
            return .disarm;
        }

        fn processResponse(self: *ClientHandshakeSelf) void {
            const key = self.key_buf[0..self.key_len];
            http.validateResponse(self.read_buf[0..self.header_len], key) catch |err| {
                log.debug("processResponse: parse error: {s}", .{@errorName(err)});
                self.fail();
                return;
            };

            self.state = .completed;
            log.debug("processResponse: success, header_len={d}, leftover={d}", .{
                self.header_len,
                self.read_pos - self.header_len,
            });
            self.context.onSuccess(self);
        }
    };
}
