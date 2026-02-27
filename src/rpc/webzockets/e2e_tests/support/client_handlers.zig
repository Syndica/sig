const std = @import("std");
const ws = @import("webzockets_lib");

/// Client-side handler that closes immediately on open.
/// Useful for testing close handshake and connection pool exhaustion.
pub const CloseOnOpenHandler = struct {
    open_called: bool = false,
    close_called: bool = false,

    pub fn onOpen(self: *CloseOnOpenHandler, conn: anytype) void {
        self.open_called = true;
        conn.close(.normal, "");
    }

    pub fn onMessage(_: *CloseOnOpenHandler, _: anytype, _: ws.Message) void {}
    pub fn onWriteComplete(_: *CloseOnOpenHandler, _: anytype) void {}

    pub fn onClose(self: *CloseOnOpenHandler, _: anytype) void {
        self.close_called = true;
    }
};

/// Client-side handler that tracks open_called but takes no action.
/// Useful for testing rejection scenarios where onOpen should not be called.
pub const NoOpHandler = struct {
    open_called: bool = false,

    pub fn onOpen(self: *NoOpHandler, _: anytype) void {
        self.open_called = true;
    }

    pub fn onMessage(_: *NoOpHandler, _: anytype, _: ws.Message) void {}
    pub fn onWriteComplete(_: *NoOpHandler, _: anytype) void {}
    pub fn onClose(_: *NoOpHandler, _: anytype) void {}
};

/// Client-side handler that waits for the server to close.
/// Tracks that onClose was called and that the client never initiated the close.
/// Used by client close_tests.zig for server-initiated close tests.
pub const ServerCloseHandler = struct {
    close_called: bool = false,
    open_called: bool = false,

    pub fn onOpen(self: *ServerCloseHandler, _: anytype) void {
        self.open_called = true;
    }

    pub fn onMessage(_: *ServerCloseHandler, _: anytype, _: ws.Message) void {}
    pub fn onWriteComplete(_: *ServerCloseHandler, _: anytype) void {}

    pub fn onClose(self: *ServerCloseHandler, _: anytype) void {
        self.close_called = true;
    }
};

/// Client-side handler that tracks pong reception and then closes.
/// Used by client ping_pong_tests.zig to verify the onPong callback fires.
pub const PongTrackingHandler = struct {
    pong_received: bool = false,
    pong_data: ?[]const u8 = null,
    open_called: bool = false,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *PongTrackingHandler) void {
        if (self.pong_data) |data| {
            self.allocator.free(data);
            self.pong_data = null;
        }
    }

    pub fn onOpen(self: *PongTrackingHandler, _: anytype) void {
        self.open_called = true;
    }

    pub fn onMessage(_: *PongTrackingHandler, _: anytype, _: ws.Message) void {}
    pub fn onWriteComplete(_: *PongTrackingHandler, _: anytype) void {}

    pub fn onPong(self: *PongTrackingHandler, conn: anytype, data: []const u8) void {
        self.pong_received = true;
        self.pong_data = self.allocator.dupe(u8, data) catch null;
        conn.close(.normal, "");
    }

    pub fn onClose(_: *PongTrackingHandler, _: anytype) void {}
};

/// Client-side handler that tracks whether onClose was called.
/// Does not send or receive data. Used for max_message_size tests where the
/// server sends an oversized message and the client is expected to close with 1009.
pub const MaxMessageHandler = struct {
    open_called: bool = false,
    close_called: bool = false,
    message_received: bool = false,

    pub fn onOpen(self: *MaxMessageHandler, _: anytype) void {
        self.open_called = true;
    }

    pub fn onMessage(self: *MaxMessageHandler, _: anytype, _: ws.Message) void {
        self.message_received = true;
    }

    pub fn onWriteComplete(_: *MaxMessageHandler, _: anytype) void {}

    pub fn onClose(self: *MaxMessageHandler, _: anytype) void {
        self.close_called = true;
    }
};

/// Client-side handler that tracks socket-level close for connection failure tests.
/// Implements onSocketClose to detect TCP/handshake failures.
pub const ConnectFailHandler = struct {
    open_called: bool = false,
    socket_close_called: bool = false,

    pub fn onOpen(self: *ConnectFailHandler, _: anytype) void {
        self.open_called = true;
    }

    pub fn onMessage(_: *ConnectFailHandler, _: anytype, _: ws.Message) void {}
    pub fn onWriteComplete(_: *ConnectFailHandler, _: anytype) void {}
    pub fn onClose(_: *ConnectFailHandler, _: anytype) void {}

    pub fn onSocketClose(self: *ConnectFailHandler) void {
        self.socket_close_called = true;
    }
};

/// Client-side handler that explicitly responds to pings via onPing.
/// Used to test that declaring onPing disables auto-pong and the handler
/// can manually send pong.
pub const ExplicitPongHandler = struct {
    open_called: bool = false,
    close_called: bool = false,
    ping_received: bool = false,

    pub fn onOpen(self: *ExplicitPongHandler, _: anytype) void {
        self.open_called = true;
    }

    pub fn onPing(self: *ExplicitPongHandler, conn: anytype, data: []const u8) void {
        self.ping_received = true;
        conn.sendPong(data) catch |err| std.debug.panic("sendPong failed: {}", .{err});
    }

    pub fn onMessage(_: *ExplicitPongHandler, _: anytype, _: ws.Message) void {}
    pub fn onWriteComplete(_: *ExplicitPongHandler, _: anytype) void {}

    pub fn onClose(self: *ExplicitPongHandler, _: anytype) void {
        self.close_called = true;
    }
};

/// Common client-side handler for e2e tests.
///
/// Behavior:
/// - Optionally sends one message/ping on open.
/// - Captures the first message/pong.
/// - Initiates a normal close.
///
/// Owns any allocations made for sending/capturing and provides `deinit()`
/// so tests can clean up consistently.
pub const SendOnceHandler = struct {
    pub const SendKind = enum {
        none,
        text,
        binary,
        ping,
    };

    /// What to send on open.
    send_kind: SendKind = .none,

    /// Payload to send (required unless `send_kind == .none`).
    send_data: ?[]const u8 = null,

    /// Captured data from the first received message/pong.
    received_data: ?[]const u8 = null,
    received_type: ?ws.Message.Type = null,

    open_called: bool = false,

    allocator: std.mem.Allocator,

    /// Owned copy used for text/binary sends.
    sent_data: ?[]const u8 = null,

    pub fn deinit(self: *SendOnceHandler) void {
        if (self.received_data) |data| {
            self.allocator.free(data);
            self.received_data = null;
        }
        if (self.sent_data) |data| {
            self.allocator.free(data);
            self.sent_data = null;
        }
    }

    pub fn onOpen(self: *SendOnceHandler, conn: anytype) void {
        self.open_called = true;

        const kind = self.send_kind;
        if (kind == .none) return;
        const data = self.send_data orelse return;

        switch (kind) {
            .ping => {
                // sendPing copies the payload into an internal queue (no onWriteComplete),
                // so no allocation or lifetime management is needed.
                conn.sendPing(data) catch return;
            },
            .text => {
                const copy = self.allocator.dupe(u8, data) catch return;
                conn.sendText(copy) catch {
                    self.allocator.free(copy);
                    return;
                };
                self.sent_data = copy;
            },
            .binary => {
                const copy = self.allocator.dupe(u8, data) catch return;
                conn.sendBinary(copy) catch {
                    self.allocator.free(copy);
                    return;
                };
                self.sent_data = copy;
            },
            .none => {},
        }
    }

    pub fn onMessage(self: *SendOnceHandler, conn: anytype, message: ws.Message) void {
        self.received_data = self.allocator.dupe(u8, message.data) catch null;
        self.received_type = message.type;
        conn.close(.normal, "");
    }

    pub fn onPong(self: *SendOnceHandler, conn: anytype, data: []const u8) void {
        self.received_data = self.allocator.dupe(u8, data) catch null;
        self.received_type = .pong;
        conn.close(.normal, "");
    }

    pub fn onWriteComplete(self: *SendOnceHandler, _: anytype) void {
        if (self.sent_data) |data| {
            self.allocator.free(data);
            self.sent_data = null;
        }
    }

    pub fn onClose(self: *SendOnceHandler, _: anytype) void {
        if (self.sent_data) |data| {
            self.allocator.free(data);
            self.sent_data = null;
        }
    }
};

/// Client-side handler that sends multiple messages sequentially.
/// Sends the next message only after the previous write completes and echo is received.
/// Supports mixed text/binary messages via MsgSpec.
pub const SequenceHandler = struct {
    /// Message specification for sending.
    pub const MsgSpec = struct {
        data: []const u8,
        is_binary: bool = false,
    };

    /// Captured result for a received message.
    pub const RecvResult = struct {
        data: []const u8,
        len: usize,
    };

    messages: []const MsgSpec,
    send_index: usize = 0,
    recv_index: usize = 0,
    results: std.ArrayList(RecvResult),
    allocator: std.mem.Allocator,
    sent_data: ?[]const u8 = null,
    open_called: bool = false,

    pub fn deinit(self: *SequenceHandler) void {
        for (self.results.items) |item| {
            self.allocator.free(item.data);
        }
        self.results.deinit(self.allocator);
        if (self.sent_data) |data| {
            self.allocator.free(data);
            self.sent_data = null;
        }
    }

    pub fn onOpen(self: *SequenceHandler, conn: anytype) void {
        self.open_called = true;
        self.maybeSendNext(conn);
    }

    fn maybeSendNext(self: *SequenceHandler, conn: anytype) void {
        if (self.sent_data != null) return;
        if (self.recv_index < self.send_index) return;
        if (self.send_index >= self.messages.len) return;

        const spec = self.messages[self.send_index];
        const copy = self.allocator.dupe(u8, spec.data) catch return;
        if (spec.is_binary) {
            conn.sendBinary(copy) catch {
                self.allocator.free(copy);
                return;
            };
        } else {
            conn.sendText(copy) catch {
                self.allocator.free(copy);
                return;
            };
        }
        self.sent_data = copy;
        self.send_index += 1;
    }

    pub fn onMessage(self: *SequenceHandler, conn: anytype, message: ws.Message) void {
        const copy = self.allocator.dupe(u8, message.data) catch return;
        self.results.append(self.allocator, .{ .data = copy, .len = message.data.len }) catch {
            self.allocator.free(copy);
            return;
        };
        self.recv_index += 1;
        if (self.recv_index >= self.messages.len) {
            conn.close(.normal, "");
        } else {
            self.maybeSendNext(conn);
        }
    }

    pub fn onWriteComplete(self: *SequenceHandler, conn: anytype) void {
        if (self.sent_data) |data| {
            self.allocator.free(data);
            self.sent_data = null;
        }
        self.maybeSendNext(conn);
    }

    pub fn onClose(self: *SequenceHandler, _: anytype) void {
        if (self.sent_data) |data| {
            self.allocator.free(data);
            self.sent_data = null;
        }
    }
};

/// Client-side handler that sends raw pre-built masked frames on open.
/// Captures echo responses and closes after receiving the expected number.
pub const RawSendOnOpenHandler = struct {
    pub const FrameSpec = struct {
        opcode: ws.Opcode,
        data: []const u8,
    };

    pub const RecvResult = struct {
        data: []const u8,
        msg_type: ws.Message.Type,
    };

    frames: []const FrameSpec,
    results: std.ArrayList(RecvResult),
    allocator: std.mem.Allocator,
    csprng: *ws.ClientMaskPRNG,
    sent_buf: ?[]const u8 = null,
    open_called: bool = false,

    pub fn deinit(self: *RawSendOnOpenHandler) void {
        for (self.results.items) |item| {
            self.allocator.free(item.data);
        }
        self.results.deinit(self.allocator);
        if (self.sent_buf) |buf| {
            self.allocator.free(buf);
            self.sent_buf = null;
        }
    }

    pub fn onOpen(self: *RawSendOnOpenHandler, conn: anytype) void {
        self.open_called = true;

        // Upper-bound allocation: client header is 6/8/14 bytes depending
        // on payload size; use 14 (worst case) so the buffer is always big enough.
        var total_size: usize = 0;
        for (self.frames) |f| {
            total_size += 14 + f.data.len;
        }

        const buf = self.allocator.alloc(u8, total_size) catch return;
        var pos: usize = 0;

        for (self.frames) |f| {
            var mask_key: [4]u8 = undefined;
            self.csprng.fill(&mask_key);

            var header_buf: [14]u8 = undefined;
            const header = ws.frame.writeClientFrameHeader(
                &header_buf,
                f.opcode,
                f.data.len,
                mask_key,
                false,
            );
            @memcpy(buf[pos..][0..header.len], header);
            pos += header.len;
            @memcpy(buf[pos..][0..f.data.len], f.data);
            ws.mask.mask(mask_key, buf[pos..][0..f.data.len]);
            pos += f.data.len;
        }

        const raw_data = buf[0..pos];
        conn.sendRaw(raw_data) catch {
            self.allocator.free(buf);
            return;
        };
        self.sent_buf = buf;
    }

    pub fn onMessage(self: *RawSendOnOpenHandler, conn: anytype, message: ws.Message) void {
        const copy = self.allocator.dupe(u8, message.data) catch return;
        self.results.append(self.allocator, .{ .data = copy, .msg_type = message.type }) catch {
            self.allocator.free(copy);
            return;
        };
        if (self.results.items.len >= self.frames.len) {
            conn.close(.normal, "");
        }
    }

    pub fn onWriteComplete(self: *RawSendOnOpenHandler, _: anytype) void {
        if (self.sent_buf) |buf| {
            self.allocator.free(buf);
            self.sent_buf = null;
        }
    }

    pub fn onClose(self: *RawSendOnOpenHandler, _: anytype) void {
        if (self.sent_buf) |buf| {
            self.allocator.free(buf);
            self.sent_buf = null;
        }
    }
};

/// Client-side handler that pauses reads on open and waits for enough data
/// to accumulate in the read buffer before resuming. Uses `onBytesRead` to
/// observe raw TCP data arrival while paused. This makes burst-processing
/// tests deterministic by ensuring all expected messages are buffered before
/// dispatch begins.
pub const PauseUntilBufferedClientHandler = struct {
    pub const RecvResult = struct {
        data: []const u8,
    };

    allocator: std.mem.Allocator,
    /// Number of messages expected before closing. 0 = don't auto-close.
    expected_messages: usize = 0,
    /// Minimum bytes that must be buffered before reads are resumed.
    resume_threshold: usize = 0,
    results: std.ArrayList(RecvResult),
    open_called: bool = false,
    close_called: bool = false,

    pub fn deinit(self: *PauseUntilBufferedClientHandler) void {
        for (self.results.items) |item| {
            self.allocator.free(item.data);
        }
        self.results.deinit(self.allocator);
    }

    pub fn onOpen(self: *PauseUntilBufferedClientHandler, conn: anytype) void {
        self.open_called = true;
        conn.pauseReads();
    }

    pub fn onBytesRead(self: *PauseUntilBufferedClientHandler, conn: anytype, _: usize) void {
        if (conn.peekBufferedBytes().len >= self.resume_threshold) {
            conn.resumeReads();
        }
    }

    pub fn onMessage(
        self: *PauseUntilBufferedClientHandler,
        conn: anytype,
        message: ws.Message,
    ) void {
        switch (message.type) {
            .text, .binary => {},
            else => return,
        }

        const copy = self.allocator.dupe(u8, message.data) catch return;
        self.results.append(self.allocator, .{ .data = copy }) catch {
            self.allocator.free(copy);
            return;
        };

        if (self.expected_messages != 0 and self.results.items.len >= self.expected_messages) {
            conn.close(.normal, "done");
        }
    }

    pub fn onWriteComplete(_: *PauseUntilBufferedClientHandler, _: anytype) void {}

    pub fn onClose(self: *PauseUntilBufferedClientHandler, _: anytype) void {
        self.close_called = true;
    }
};

/// Client-side handler that pauses on open, waits for a byte threshold, then
/// resumes. After the initial resume, each onMessage pauses reads, records the
/// message, sends an echo/ack, and resumes in onWriteComplete. This tests the
/// processMessages loop breaking when read_paused is set mid-loop, and
/// re-entering from onWriteComplete via resumeReads.
pub const PauseMidStreamClientHandler = struct {
    pub const RecvResult = struct {
        data: []const u8,
    };

    allocator: std.mem.Allocator,
    expected_messages: usize = 0,
    resume_threshold: usize = 0,
    results: std.ArrayList(RecvResult),
    sent_data: ?[]u8 = null,
    initial_resumed: bool = false,
    open_called: bool = false,
    close_called: bool = false,

    pub fn deinit(self: *PauseMidStreamClientHandler) void {
        for (self.results.items) |item| {
            self.allocator.free(item.data);
        }
        self.results.deinit(self.allocator);

        if (self.sent_data) |data| {
            self.allocator.free(data);
            self.sent_data = null;
        }
    }

    pub fn onOpen(self: *PauseMidStreamClientHandler, conn: anytype) void {
        self.open_called = true;
        conn.pauseReads();
    }

    pub fn onBytesRead(self: *PauseMidStreamClientHandler, conn: anytype, _: usize) void {
        if (!self.initial_resumed and conn.peekBufferedBytes().len >= self.resume_threshold) {
            self.initial_resumed = true;
            conn.resumeReads();
        }
    }

    pub fn onMessage(self: *PauseMidStreamClientHandler, conn: anytype, message: ws.Message) void {
        switch (message.type) {
            .text, .binary => {},
            else => return,
        }

        conn.pauseReads();

        const copy = self.allocator.dupe(u8, message.data) catch {
            conn.resumeReads();
            return;
        };
        self.results.append(self.allocator, .{ .data = copy }) catch {
            self.allocator.free(copy);
            conn.resumeReads();
            return;
        };

        // Send an ack to trigger onWriteComplete where we resume reads.
        const ack = self.allocator.dupe(u8, message.data) catch {
            conn.resumeReads();
            return;
        };

        conn.sendText(ack) catch {
            self.allocator.free(ack);
            conn.resumeReads();
            return;
        };

        self.sent_data = ack;
    }

    pub fn onWriteComplete(self: *PauseMidStreamClientHandler, conn: anytype) void {
        if (self.sent_data) |data| {
            self.allocator.free(data);
            self.sent_data = null;
        }

        if (self.expected_messages != 0 and self.results.items.len >= self.expected_messages) {
            conn.close(.normal, "done");
            return;
        }

        conn.resumeReads();
    }

    pub fn onClose(self: *PauseMidStreamClientHandler, _: anytype) void {
        self.close_called = true;
        if (self.sent_data) |data| {
            self.allocator.free(data);
            self.sent_data = null;
        }
    }
};

/// Client-side handler that detects re-entrant onMessage dispatch.
///
/// Pauses reads in onOpen and waits (via onBytesRead + peekBufferedBytes)
/// until all expected messages are buffered. Once resumed, all messages
/// dispatch synchronously. In each onMessage the handler calls
/// pauseReads() then resumeReads() — without the re-entrancy guard this
/// would recursively dispatch the next buffered message while still inside
/// onMessage. Closes with policy_violation if re-entrancy is detected.
pub const ReentrancyDetectClientHandler = struct {
    pub const RecvResult = struct {
        data: []const u8,
    };

    allocator: std.mem.Allocator,
    /// Minimum bytes that must be buffered before reads are resumed.
    resume_threshold: usize = 0,
    results: std.ArrayList(RecvResult),
    in_on_message: bool = false,
    reentrant_detected: bool = false,
    open_called: bool = false,
    close_called: bool = false,

    pub fn deinit(self: *ReentrancyDetectClientHandler) void {
        for (self.results.items) |item| {
            self.allocator.free(item.data);
        }
        self.results.deinit(self.allocator);
    }

    pub fn onOpen(self: *ReentrancyDetectClientHandler, conn: anytype) void {
        self.open_called = true;
        conn.pauseReads();
    }

    pub fn onBytesRead(self: *ReentrancyDetectClientHandler, conn: anytype, _: usize) void {
        if (conn.peekBufferedBytes().len >= self.resume_threshold) {
            conn.resumeReads();
        }
    }

    pub fn onMessage(self: *ReentrancyDetectClientHandler, conn: anytype, message: ws.Message) void {
        switch (message.type) {
            .text, .binary => {},
            else => return,
        }

        if (self.in_on_message) {
            self.reentrant_detected = true;
            conn.close(.policy_violation, "reentrant");
            return;
        }
        self.in_on_message = true;
        defer self.in_on_message = false;

        const copy = self.allocator.dupe(u8, message.data) catch return;
        self.results.append(self.allocator, .{ .data = copy }) catch {
            self.allocator.free(copy);
            return;
        };

        // Exercise the re-entrancy guard: without it, resumeReads() would
        // recursively call processMessages() and dispatch the next buffered
        // message before we return.
        conn.pauseReads();
        conn.resumeReads();
    }

    pub fn onWriteComplete(_: *ReentrancyDetectClientHandler, _: anytype) void {}

    pub fn onClose(self: *ReentrancyDetectClientHandler, _: anytype) void {
        self.close_called = true;
    }
};
