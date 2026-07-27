const std = @import("std");
const xev = @import("xev");
const ws = @import("webzockets_lib");

/// Default read buffer size for the echo server.
const default_read_buf_size: usize = 4096;

/// Echo handler: sends back every text/binary message it receives.
/// Messages are copied into owned allocations and queued so that
/// back-to-back arrivals are echoed in order (only one write can
/// be in flight at a time).
///
/// Note: We allocate a copy for every message for simplicity. Both received
/// message data (internal read buffers) and sent data (zero-copy writes) have
/// transient lifetimes, so copies are needed to safely hold onto the data.
///
/// Uses an intrusive singly-linked list for O(1) queue operations.
const EchoHandler = struct {
    pub const Context = void;

    const PendingMessage = struct {
        data: []const u8,
        is_text: bool,
        next: ?*PendingMessage = null,
    };

    /// Data currently being written (freed in onWriteComplete).
    sent_data: ?[]const u8 = null,
    /// Head of pending message queue.
    queue_head: ?*PendingMessage = null,
    /// Tail of pending message queue (for O(1) append).
    queue_tail: ?*PendingMessage = null,

    pub fn init(_: ws.http.Request, _: void) !EchoHandler {
        return .{};
    }

    pub fn onMessage(self: *EchoHandler, conn: *EchoServer.Conn, message: ws.Message) void {
        switch (message.type) {
            .text, .binary => {
                std.debug.print("Received {s} ({d} bytes): {s}\n", .{
                    @tagName(message.type),
                    message.data.len,
                    message.data,
                });
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

    fn drainQueue(self: *EchoHandler, conn: *EchoServer.Conn) void {
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

    pub fn onWriteComplete(self: *EchoHandler, conn: *EchoServer.Conn) void {
        if (self.sent_data) |data| {
            std.debug.print("Sent ({d} bytes): {s}\n", .{ data.len, data });
            conn.allocator.free(data);
            self.sent_data = null;
        }
        self.drainQueue(conn);
    }

    pub fn onClose(self: *EchoHandler, conn: *EchoServer.Conn) void {
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

const EchoServer = ws.Server(EchoHandler, default_read_buf_size);

pub fn main() !void {
    const address = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 8080);

    var thread_pool = xev.ThreadPool.init(.{});
    defer thread_pool.deinit();
    defer thread_pool.shutdown();

    var loop = try xev.Loop.init(.{ .thread_pool = &thread_pool });
    defer loop.deinit();

    var server = try EchoServer.init(
        std.heap.page_allocator,
        &loop,
        .{
            .address = address,
            .handler_context = {},
            .tcp_accept_backlog = 128,
            .max_message_size = 16 * 1024 * 1024,
            .initial_handshake_pool_size = 16,
            .initial_connection_pool_size = 64,
            .max_handshakes = null,
            .max_connections = null,
            .idle_timeout_ms = null,
        },
    );
    defer server.deinit();

    server.accept();
    std.debug.print("WebSocket echo server listening on ws://127.0.0.1:8080\n", .{});
    try loop.run(.until_done);
}
