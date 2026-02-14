const std = @import("std");
const ws = @import("webzockets_lib");

/// Server-side handler that closes the connection immediately on open.
/// Used by client close_tests.zig to test server-initiated close.
pub const CloseOnOpenHandler = struct {
    pub const Context = void;

    pub fn init(_: ws.http.Request, _: void) !CloseOnOpenHandler {
        return .{};
    }

    pub fn onOpen(_: *CloseOnOpenHandler, conn: anytype) void {
        conn.close(.normal, "server closing");
    }

    pub fn onMessage(_: *CloseOnOpenHandler, _: anytype, _: ws.Message) void {}
    pub fn onWriteComplete(_: *CloseOnOpenHandler, _: anytype) void {}
    pub fn onClose(_: *CloseOnOpenHandler, _: anytype) void {}
};

/// Server-side handler that sends a ping immediately on open, then closes
/// after receiving the client's pong response.
/// Used by client ping_pong_tests.zig to verify automatic pong response.
pub const PingOnOpenHandler = struct {
    pub const Context = void;

    pub fn init(_: ws.http.Request, _: void) !PingOnOpenHandler {
        return .{};
    }

    pub fn onOpen(_: *PingOnOpenHandler, conn: anytype) void {
        conn.sendPing("hello") catch return;
    }

    pub fn onMessage(_: *PingOnOpenHandler, _: anytype, _: ws.Message) void {}
    pub fn onWriteComplete(_: *PingOnOpenHandler, _: anytype) void {}

    pub fn onPong(_: *PingOnOpenHandler, conn: anytype, _: []const u8) void {
        conn.close(.normal, "");
    }

    pub fn onClose(_: *PingOnOpenHandler, _: anytype) void {}
};

/// Server-side handler that sends an unsolicited pong immediately on open.
/// Used by client ping_pong_tests.zig to verify client onPong callback.
/// Does not initiate close — the test client is expected to close after
/// receiving the pong (see PongTrackingHandler).
pub const PongOnOpenHandler = struct {
    pub const Context = void;

    pub fn init(_: ws.http.Request, _: void) !PongOnOpenHandler {
        return .{};
    }

    pub fn onOpen(_: *PongOnOpenHandler, conn: anytype) void {
        conn.sendPong("hello") catch return;
    }

    pub fn onMessage(_: *PongOnOpenHandler, _: anytype, _: ws.Message) void {}
    pub fn onWriteComplete(_: *PongOnOpenHandler, _: anytype) void {}
    pub fn onClose(_: *PongOnOpenHandler, _: anytype) void {}
};

/// Server-side handler that sends a message larger than the client's expected
/// max_message_size on open. Used by client max_message_tests.zig.
pub const SendOversizedOnOpenHandler = struct {
    pub const Context = void;

    sent_data: ?[]const u8 = null,

    pub fn init(_: ws.http.Request, _: void) !SendOversizedOnOpenHandler {
        return .{};
    }

    pub fn onOpen(self: *SendOversizedOnOpenHandler, conn: anytype) void {
        // Send a 2048-byte message (client will be configured with max_message_size = 1024)
        const payload = conn.allocator.alloc(u8, 2048) catch return;
        @memset(payload, 'X');
        conn.sendBinary(payload) catch {
            conn.allocator.free(payload);
            return;
        };
        self.sent_data = payload;
    }

    pub fn onMessage(_: *SendOversizedOnOpenHandler, _: anytype, _: ws.Message) void {}

    pub fn onWriteComplete(self: *SendOversizedOnOpenHandler, conn: anytype) void {
        if (self.sent_data) |data| {
            conn.allocator.free(data);
            self.sent_data = null;
        }
    }

    pub fn onClose(self: *SendOversizedOnOpenHandler, conn: anytype) void {
        if (self.sent_data) |data| {
            conn.allocator.free(data);
            self.sent_data = null;
        }
    }
};

/// Server-side handler that echoes the first message, then closes the connection.
/// Used by server timeout_tests.zig to test close timeout behavior.
pub const CloseAfterFirstMessageHandler = struct {
    pub const Context = void;

    got_first: bool = false,
    sent_data: ?[]const u8 = null,

    pub fn init(_: ws.http.Request, _: void) !CloseAfterFirstMessageHandler {
        return .{};
    }

    pub fn onMessage(self: *CloseAfterFirstMessageHandler, conn: anytype, message: ws.Message) void {
        if (self.got_first) return;
        self.got_first = true;

        switch (message.type) {
            .text, .binary => {
                const copy = conn.allocator.dupe(u8, message.data) catch return;
                if (message.type == .text) {
                    conn.sendText(copy) catch {
                        conn.allocator.free(copy);
                        return;
                    };
                } else {
                    conn.sendBinary(copy) catch {
                        conn.allocator.free(copy);
                        return;
                    };
                }
                self.sent_data = copy;
            },
            else => {},
        }
    }

    pub fn onWriteComplete(self: *CloseAfterFirstMessageHandler, conn: anytype) void {
        if (self.sent_data) |data| {
            conn.allocator.free(data);
            self.sent_data = null;
        }
        // Close after the echo completes
        conn.close(.normal, "closing after first message");
    }

    pub fn onClose(self: *CloseAfterFirstMessageHandler, conn: anytype) void {
        if (self.sent_data) |data| {
            conn.allocator.free(data);
            self.sent_data = null;
        }
    }
};

/// Server-side handler that always rejects connections by returning an error
/// from init. Used by client connection_tests.zig.
pub const RejectOnInitHandler = struct {
    pub const Context = void;

    pub fn init(_: ws.http.Request, _: void) !RejectOnInitHandler {
        return error.ConnectionRejected;
    }

    pub fn onMessage(_: *RejectOnInitHandler, _: anytype, _: ws.Message) void {}
    pub fn onWriteComplete(_: *RejectOnInitHandler, _: anytype) void {}
    pub fn onClose(_: *RejectOnInitHandler, _: anytype) void {}
};

/// Server-side handler that echoes any text/binary message back to the client.
///
/// Copies inbound data into owned allocations and queues writes so only one
/// write is in flight at a time.
pub const EchoHandler = struct {
    pub const Context = void;

    const PendingMessage = struct {
        data: []const u8,
        is_text: bool,
        next: ?*PendingMessage = null,
    };

    sent_data: ?[]const u8 = null,
    queue_head: ?*PendingMessage = null,
    queue_tail: ?*PendingMessage = null,

    pub fn init(_: ws.http.Request, _: void) !EchoHandler {
        return .{};
    }

    pub fn onMessage(self: *EchoHandler, conn: anytype, message: ws.Message) void {
        switch (message.type) {
            .text, .binary => {
                const copy = conn.allocator.dupe(u8, message.data) catch return;
                const msg = conn.allocator.create(PendingMessage) catch {
                    conn.allocator.free(copy);
                    return;
                };
                msg.* = .{
                    .data = copy,
                    .is_text = message.type == .text,
                };
                if (self.queue_tail) |tail| {
                    tail.next = msg;
                } else {
                    self.queue_head = msg;
                }
                self.queue_tail = msg;
                self.drainQueue(conn);
            },
            else => {},
        }
    }

    fn drainQueue(self: *EchoHandler, conn: anytype) void {
        while (self.queue_head) |msg| {
            if (self.sent_data != null) return;
            self.queue_head = msg.next;
            if (self.queue_head == null) self.queue_tail = null;

            if (msg.is_text) {
                conn.sendText(msg.data) catch {
                    conn.allocator.free(msg.data);
                    conn.allocator.destroy(msg);
                    continue;
                };
            } else {
                conn.sendBinary(msg.data) catch {
                    conn.allocator.free(msg.data);
                    conn.allocator.destroy(msg);
                    continue;
                };
            }

            self.sent_data = msg.data;
            conn.allocator.destroy(msg);
            return;
        }
    }

    pub fn onWriteComplete(self: *EchoHandler, conn: anytype) void {
        if (self.sent_data) |data| {
            conn.allocator.free(data);
            self.sent_data = null;
        }
        self.drainQueue(conn);
    }

    pub fn onClose(self: *EchoHandler, conn: anytype) void {
        if (self.sent_data) |data| {
            conn.allocator.free(data);
        }
        while (self.queue_head) |msg| {
            self.queue_head = msg.next;
            conn.allocator.free(msg.data);
            conn.allocator.destroy(msg);
        }
        self.queue_tail = null;
    }
};

/// Server-side handler that pauses reads on open and waits (via onBytesRead +
/// peekBufferedBytes) until a configurable byte threshold is reached before
/// resuming. Echoes each text/binary message back to the client (one write
/// at a time). Optionally closes after a configured number of messages.
pub const PauseUntilBufferedEchoHandler = struct {
    pub const Context = struct {
        resume_threshold: usize,
        expected_messages: usize = 0,
    };

    const PendingMessage = struct {
        data: []const u8,
        is_text: bool,
        next: ?*PendingMessage = null,
    };

    resume_threshold: usize,
    expected_messages: usize,
    send_count: usize = 0,
    sent_data: ?[]const u8 = null,
    queue_head: ?*PendingMessage = null,
    queue_tail: ?*PendingMessage = null,

    pub fn init(_: ws.http.Request, ctx: *Context) !PauseUntilBufferedEchoHandler {
        return .{
            .resume_threshold = ctx.resume_threshold,
            .expected_messages = ctx.expected_messages,
        };
    }

    pub fn onOpen(_: *PauseUntilBufferedEchoHandler, conn: anytype) void {
        conn.pauseReads();
    }

    pub fn onBytesRead(self: *PauseUntilBufferedEchoHandler, conn: anytype, _: usize) void {
        if (conn.peekBufferedBytes().len >= self.resume_threshold) {
            conn.resumeReads();
        }
    }

    pub fn onMessage(self: *PauseUntilBufferedEchoHandler, conn: anytype, message: ws.Message) void {
        switch (message.type) {
            .text, .binary => {},
            else => return,
        }

        const copy = conn.allocator.dupe(u8, message.data) catch return;
        const msg = conn.allocator.create(PendingMessage) catch {
            conn.allocator.free(copy);
            return;
        };
        msg.* = .{ .data = copy, .is_text = message.type == .text };
        if (self.queue_tail) |tail| {
            tail.next = msg;
        } else {
            self.queue_head = msg;
        }
        self.queue_tail = msg;
        self.drainQueue(conn);
    }

    fn drainQueue(self: *PauseUntilBufferedEchoHandler, conn: anytype) void {
        while (self.queue_head) |msg| {
            if (self.sent_data != null) return;
            self.queue_head = msg.next;
            if (self.queue_head == null) self.queue_tail = null;

            if (msg.is_text) {
                conn.sendText(msg.data) catch {
                    conn.allocator.free(msg.data);
                    conn.allocator.destroy(msg);
                    continue;
                };
            } else {
                conn.sendBinary(msg.data) catch {
                    conn.allocator.free(msg.data);
                    conn.allocator.destroy(msg);
                    continue;
                };
            }

            self.sent_data = msg.data;
            conn.allocator.destroy(msg);
            return;
        }
    }

    pub fn onWriteComplete(self: *PauseUntilBufferedEchoHandler, conn: anytype) void {
        if (self.sent_data) |data| {
            conn.allocator.free(data);
            self.sent_data = null;
        }
        self.send_count += 1;
        if (self.expected_messages != 0 and self.send_count >= self.expected_messages) {
            conn.close(.normal, "done");
            return;
        }
        self.drainQueue(conn);
    }

    pub fn onClose(self: *PauseUntilBufferedEchoHandler, conn: anytype) void {
        if (self.sent_data) |data| {
            conn.allocator.free(data);
        }
        while (self.queue_head) |msg| {
            self.queue_head = msg.next;
            conn.allocator.free(msg.data);
            conn.allocator.destroy(msg);
        }
        self.queue_tail = null;
    }
};

/// Server-side handler that pauses on open, waits for a byte threshold, then
/// resumes. After the initial resume, each onMessage pauses reads, echoes the
/// message, and resumes in onWriteComplete. This tests the processMessages
/// loop breaking when read_paused is set mid-loop, and re-entering from
/// onWriteComplete via resumeReads.
pub const PauseMidStreamEchoHandler = struct {
    pub const Context = struct {
        resume_threshold: usize,
        expected_messages: usize,
    };

    resume_threshold: usize,
    expected_messages: usize,
    initial_resumed: bool = false,
    recv_count: usize = 0,
    sent_data: ?[]const u8 = null,

    pub fn init(_: ws.http.Request, ctx: *Context) !PauseMidStreamEchoHandler {
        return .{
            .resume_threshold = ctx.resume_threshold,
            .expected_messages = ctx.expected_messages,
        };
    }

    pub fn onOpen(_: *PauseMidStreamEchoHandler, conn: anytype) void {
        conn.pauseReads();
    }

    pub fn onBytesRead(self: *PauseMidStreamEchoHandler, conn: anytype, _: usize) void {
        if (!self.initial_resumed and conn.peekBufferedBytes().len >= self.resume_threshold) {
            self.initial_resumed = true;
            conn.resumeReads();
        }
    }

    pub fn onMessage(self: *PauseMidStreamEchoHandler, conn: anytype, message: ws.Message) void {
        switch (message.type) {
            .text, .binary => {},
            else => return,
        }

        self.recv_count += 1;
        conn.pauseReads();

        const copy = conn.allocator.dupe(u8, message.data) catch {
            conn.resumeReads();
            return;
        };

        if (message.type == .text) {
            conn.sendText(copy) catch {
                conn.allocator.free(copy);
                conn.resumeReads();
                return;
            };
        } else {
            conn.sendBinary(copy) catch {
                conn.allocator.free(copy);
                conn.resumeReads();
                return;
            };
        }

        self.sent_data = copy;
    }

    pub fn onWriteComplete(self: *PauseMidStreamEchoHandler, conn: anytype) void {
        if (self.sent_data) |data| {
            conn.allocator.free(data);
            self.sent_data = null;
        }
        if (self.expected_messages != 0 and self.recv_count >= self.expected_messages) {
            conn.close(.normal, "done");
            return;
        }
        conn.resumeReads();
    }

    pub fn onClose(self: *PauseMidStreamEchoHandler, conn: anytype) void {
        if (self.sent_data) |data| {
            conn.allocator.free(data);
            self.sent_data = null;
        }
    }
};

/// Server-side handler that sends configured messages on open (one per write
/// completion) and then closes.
pub const SendMessagesOnOpenHandler = struct {
    pub const Context = struct {
        messages: []const []const u8,
        close_reason: []const u8 = "done",
    };

    messages: []const []const u8,
    close_reason: []const u8,
    next_index: usize = 0,
    sent_data: ?[]const u8 = null,

    pub fn init(_: ws.http.Request, ctx: *Context) !SendMessagesOnOpenHandler {
        return .{
            .messages = ctx.messages,
            .close_reason = ctx.close_reason,
        };
    }

    pub fn onOpen(self: *SendMessagesOnOpenHandler, conn: anytype) void {
        self.sendNext(conn);
    }

    fn sendNext(self: *SendMessagesOnOpenHandler, conn: anytype) void {
        if (self.sent_data != null) return;

        if (self.next_index >= self.messages.len) {
            conn.close(.normal, self.close_reason);
            return;
        }

        const copy = conn.allocator.dupe(u8, self.messages[self.next_index]) catch return;
        conn.sendText(copy) catch {
            conn.allocator.free(copy);
            return;
        };
        self.sent_data = copy;
        self.next_index += 1;
    }

    pub fn onMessage(_: *SendMessagesOnOpenHandler, _: anytype, _: ws.Message) void {}

    pub fn onWriteComplete(self: *SendMessagesOnOpenHandler, conn: anytype) void {
        if (self.sent_data) |data| {
            conn.allocator.free(data);
            self.sent_data = null;
        }
        self.sendNext(conn);
    }

    pub fn onClose(self: *SendMessagesOnOpenHandler, conn: anytype) void {
        if (self.sent_data) |data| {
            conn.allocator.free(data);
            self.sent_data = null;
        }
    }
};

/// Server-side handler that detects re-entrant onMessage dispatch.
///
/// Pauses reads on open, waits for a byte threshold via onBytesRead +
/// peekBufferedBytes, then resumes. All buffered messages dispatch
/// synchronously. In each onMessage the handler calls pauseReads() then
/// resumeReads() — without the re-entrancy guard in processMessages this
/// would recursively dispatch the next buffered message while still inside
/// onMessage. Closes with policy_violation if re-entrancy is detected, or
/// normal when it receives a "done" sentinel.
pub const ReentrancyDetectHandler = struct {
    pub const Context = struct {
        resume_threshold: usize,
    };

    resume_threshold: usize,
    in_on_message: bool = false,

    pub fn init(_: ws.http.Request, ctx: *Context) !ReentrancyDetectHandler {
        return .{
            .resume_threshold = ctx.resume_threshold,
        };
    }

    pub fn onOpen(_: *ReentrancyDetectHandler, conn: anytype) void {
        conn.pauseReads();
    }

    pub fn onBytesRead(self: *ReentrancyDetectHandler, conn: anytype, _: usize) void {
        if (conn.peekBufferedBytes().len >= self.resume_threshold) {
            conn.resumeReads();
        }
    }

    pub fn onMessage(self: *ReentrancyDetectHandler, conn: anytype, message: ws.Message) void {
        if (message.type != .text and message.type != .binary) return;

        if (self.in_on_message) {
            conn.close(.policy_violation, "reentrant");
            return;
        }
        self.in_on_message = true;
        defer self.in_on_message = false;

        conn.pauseReads();
        conn.resumeReads();

        if (std.mem.eql(u8, message.data, "done")) {
            conn.close(.normal, "ok");
        }
    }

    pub fn onWriteComplete(_: *ReentrancyDetectHandler, _: anytype) void {}

    pub fn onClose(_: *ReentrancyDetectHandler, _: anytype) void {}
};
