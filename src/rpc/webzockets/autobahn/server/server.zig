const std = @import("std");
const xev = @import("xev");
const ws = @import("webzockets_lib");

pub const std_options: std.Options = .{
    .log_level = .info,
};

const log = std.log.scoped(.autobahn_server);

/// Embedded read buffer size per connection.
const read_buf_size: usize = 4096;

/// Pool buffer size for medium/large messages.
const pool_buf_size: usize = 65536;

/// Maximum reassembled message size — Autobahn sends up to ~16MB.
const max_message_size: usize = 20 * 1024 * 1024;

const AutobahnServer = ws.Server(AutobahnHandler, read_buf_size, pool_buf_size);

/// Echo handler for the Autobahn testsuite.
///
/// Echoes text and binary messages back verbatim. Validates UTF-8 on text
/// messages and closes with code 1007 (Invalid Payload Data) on failure,
/// which is required to pass Autobahn section 6.x tests. We do it here rather
/// than in the library as it's not something you necessarily want in all servers.
///
/// Uses an intrusive singly-linked list for O(1) queue operations.
const AutobahnHandler = struct {
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

    pub fn init(_: ws.http.Request, _: void) !AutobahnHandler {
        return .{};
    }

    /// Explicitly handle pings so every ping gets its own pong response.
    /// Without this, the library's auto-pong uses "latest wins" semantics,
    /// which is spec-compliant but fails Autobahn test 2.10 (expects a
    /// pong for each of 10 rapidly sent pings).
    pub fn onPing(_: *AutobahnHandler, conn: *AutobahnServer.Conn, data: []const u8) void {
        conn.sendPong(data) catch |err| {
            log.err("sendPong failed: {}", .{err});
        };
    }

    pub fn onMessage(self: *AutobahnHandler, conn: *AutobahnServer.Conn, message: ws.Message) void {
        switch (message.type) {
            .text => {
                if (!std.unicode.utf8ValidateSlice(message.data)) {
                    conn.close(.invalid_payload, "Invalid UTF-8");
                    return;
                }
                self.enqueue(conn, message.data, true);
            },
            .binary => self.enqueue(conn, message.data, false),
            else => {},
        }
    }

    fn enqueue(
        self: *AutobahnHandler,
        conn: *AutobahnServer.Conn,
        data: []const u8,
        is_text: bool,
    ) void {
        const copy = conn.allocator.dupe(u8, data) catch return;
        const msg = conn.allocator.create(PendingMessage) catch {
            conn.allocator.free(copy);
            return;
        };
        msg.* = .{
            .data = copy,
            .is_text = is_text,
        };
        // Append to tail
        if (self.queue_tail) |tail| {
            tail.next = msg;
        } else {
            self.queue_head = msg;
        }
        self.queue_tail = msg;
        self.drainQueue(conn);
    }

    fn drainQueue(self: *AutobahnHandler, conn: *AutobahnServer.Conn) void {
        while (self.queue_head) |msg| {
            if (self.sent_data != null) return; // write in flight
            // Pop from head
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

    pub fn onWriteComplete(self: *AutobahnHandler, conn: *AutobahnServer.Conn) void {
        if (self.sent_data) |data| {
            conn.allocator.free(data);
            self.sent_data = null;
        }
        self.drainQueue(conn);
    }

    pub fn onClose(self: *AutobahnHandler, conn: *AutobahnServer.Conn) void {
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

pub fn main() !void {
    const address = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 9001);

    var thread_pool = xev.ThreadPool.init(.{});
    defer thread_pool.deinit();
    defer thread_pool.shutdown();

    var loop = try xev.Loop.init(.{ .thread_pool = &thread_pool });
    defer loop.deinit();

    var server = try AutobahnServer.init(
        std.heap.c_allocator,
        &loop,
        .{
            .address = address,
            .handler_context = {},
            .max_message_size = max_message_size,
        },
    );
    defer server.deinit();

    server.accept();

    log.info("Autobahn echo server listening on ws://0.0.0.0:9001", .{});

    try loop.run(.until_done);
}
