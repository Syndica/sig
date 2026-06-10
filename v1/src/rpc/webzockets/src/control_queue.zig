const std = @import("std");
const testing = std.testing;
const Opcode = @import("types.zig").Opcode;

/// A fixed-capacity inline circular buffer queue for WebSocket control frames.
///
/// Stores variable-length entries of the form `[opcode: u8][length: u8][payload: 0-125 bytes]`
/// in a 256-byte ring buffer with no heap allocation. Used by both client and server
/// connections to queue outbound control frames (close, ping, pong) independently of
/// the data write path.
///
/// ```
///  buf (256 bytes, wraps around)
///  ┌──────────────────────────────────────────────────────────────────┐
///  │  free  │◄── entry 1 ──►│◄──── entry 2 ────►│◄─ entry 3 ─►│free   │
///  └──────────────────────────────────────────────────────────────────┘
///           ▲                                                 ▲
///           head                                              tail
///
///  Each entry is variable-length:
///  ┌────────┬────────┬─────────────────────────┐
///  │ opcode │ length │ payload (0-125 bytes)   │
///  │  (u8)  │  (u8)  │                         │
///  └────────┴────────┴─────────────────────────┘
///  ◄─ header_size=2 ─►
///  ◄──────── 2 to 127 bytes total ─────────────►
///
///  head/tail are u8 and wrap naturally at 256 (the buffer capacity).
///  count (u16) tracks total bytes used, enabling availableSpace = 256 - count.
///
///  enqueue  → writes [opcode][len][payload...] at tail, advances tail
///  dequeue  → reads  [opcode][len][payload...] at head, advances head
///
///  Wraparound example (entry spans the buffer boundary):
///  ┌──────────────────────────────────────────────────────────────────┐
///  │ yload...]│               free                │[op][len][pa...    │
///  └──────────────────────────────────────────────────────────────────┘
///             ▲                                   ▲
///             head                                tail
/// ```
pub const ControlQueue = struct {
    buf: [capacity]u8 = undefined,
    head: u8 = 0,
    tail: u8 = 0,
    count: u16 = 0,

    const capacity = 256;
    comptime {
        // IMPORTANT: capacity must be 256 for head/tail wraparound logic with u8.
        std.debug.assert(capacity == 256);
    }
    /// Overhead per entry: 1 byte opcode + 1 byte length.
    const header_size = 2;

    pub const Entry = struct {
        opcode: Opcode,
        len: u8,
    };

    pub const Error = error{QueueFull};

    /// Returns a new empty ControlQueue.
    pub fn init() ControlQueue {
        return .{};
    }

    /// Appends a control frame entry to the back of the queue.
    /// Returns `error.QueueFull` if there is insufficient space for the entry.
    /// Payload must be at most 125 bytes (per RFC 6455 control frame limit).
    pub fn enqueue(self: *ControlQueue, opcode: Opcode, payload: []const u8) Error!void {
        std.debug.assert(payload.len <= 125);
        std.debug.assert(opcode.isControl());
        const entry_size: u8 = @intCast(header_size + payload.len);
        if (self.availableSpace() < entry_size) return error.QueueFull;

        self.writeByte(@intFromEnum(opcode));
        self.writeByte(@intCast(payload.len));
        for (payload) |b| {
            self.writeByte(b);
        }
        self.count += entry_size;
    }

    /// Pops the front entry from the queue, copying its payload into `out_buf`.
    /// Returns the entry metadata, or `null` if the queue is empty.
    /// `out_buf` must be at least 125 bytes to accommodate any control frame payload.
    pub fn dequeue(self: *ControlQueue, out_buf: []u8) ?Entry {
        std.debug.assert(out_buf.len >= 125);
        if (self.count == 0) return null;

        const opcode_byte = self.readByte();
        const len = self.readByte();
        const entry_size: u8 = header_size + len;

        for (0..len) |i| {
            out_buf[i] = self.readByte();
        }

        self.count -= entry_size;
        return .{
            .opcode = @enumFromInt(opcode_byte),
            .len = len,
        };
    }

    /// Inspects the front entry without removing it.
    /// Returns the entry metadata, or `null` if the queue is empty.
    pub fn peek(self: *const ControlQueue) ?Entry {
        if (self.count == 0) return null;

        const opcode_byte = self.buf[self.head];
        const len = self.buf[self.head +% 1];
        return .{
            .opcode = @enumFromInt(opcode_byte),
            .len = len,
        };
    }

    /// Resets the queue to empty.
    pub fn clear(self: *ControlQueue) void {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }

    /// Returns `true` if the queue contains no entries.
    pub fn isEmpty(self: *const ControlQueue) bool {
        return self.count == 0;
    }

    /// Returns `true` if the front entry is a close frame.
    pub fn isNextClose(self: *const ControlQueue) bool {
        const entry = self.peek() orelse return false;
        return entry.opcode == .close;
    }

    /// Returns the number of free bytes in the buffer.
    pub fn availableSpace(self: *const ControlQueue) usize {
        return capacity - @as(usize, self.count);
    }

    // -- internal helpers --

    fn writeByte(self: *ControlQueue, byte: u8) void {
        self.buf[self.tail] = byte;
        self.tail +%= 1;
    }

    fn readByte(self: *ControlQueue) u8 {
        const byte = self.buf[self.head];
        self.head +%= 1;
        return byte;
    }
};

test "enqueue and dequeue single entry — FIFO order" {
    var q = ControlQueue.init();
    const payload = "hello";
    try q.enqueue(.ping, payload);

    var out: [125]u8 = undefined;
    const entry = q.dequeue(&out).?;
    try testing.expectEqual(Opcode.ping, entry.opcode);
    try testing.expectEqual(@as(u8, 5), entry.len);
    try testing.expectEqualSlices(u8, payload, out[0..entry.len]);
    try testing.expect(q.isEmpty());
}

test "enqueue and dequeue multiple entries — FIFO order" {
    var q = ControlQueue.init();
    try q.enqueue(.ping, "aaa");
    try q.enqueue(.pong, "bb");
    try q.enqueue(.close, "c");

    var out: [125]u8 = undefined;

    const e1 = q.dequeue(&out).?;
    try testing.expectEqual(Opcode.ping, e1.opcode);
    try testing.expectEqualSlices(u8, "aaa", out[0..e1.len]);

    const e2 = q.dequeue(&out).?;
    try testing.expectEqual(Opcode.pong, e2.opcode);
    try testing.expectEqualSlices(u8, "bb", out[0..e2.len]);

    const e3 = q.dequeue(&out).?;
    try testing.expectEqual(Opcode.close, e3.opcode);
    try testing.expectEqualSlices(u8, "c", out[0..e3.len]);

    try testing.expect(q.isEmpty());
}

test "wraparound — dequeue some, enqueue more that wraps around buffer" {
    var q = ControlQueue.init();
    var out: [125]u8 = undefined;

    // Fill most of the buffer with a large payload (header_size + 120 = 122 bytes).
    const large: [120]u8 = @splat('x');
    try q.enqueue(.ping, &large);
    try q.enqueue(.pong, &large); // 244 bytes used

    // Dequeue first to free space at the front.
    const e1 = q.dequeue(&out).?;
    try testing.expectEqual(Opcode.ping, e1.opcode);
    try testing.expectEqualSlices(u8, &large, out[0..e1.len]);
    // 122 bytes free at front, tail is at 244.

    // Enqueue an entry that wraps around the end of the buffer.
    const wrap_payload = "wrap-around!";
    try q.enqueue(.ping, wrap_payload);

    // Dequeue the pong, then the wrapped entry.
    const e2 = q.dequeue(&out).?;
    try testing.expectEqual(Opcode.pong, e2.opcode);

    const e3 = q.dequeue(&out).?;
    try testing.expectEqual(Opcode.ping, e3.opcode);
    try testing.expectEqualSlices(u8, wrap_payload, out[0..e3.len]);
    try testing.expect(q.isEmpty());
}

test "full queue returns error.QueueFull" {
    var q = ControlQueue.init();

    // Each entry with 125-byte payload takes 127 bytes. Two fit in 256 (254 bytes).
    const max_payload: [125]u8 = @splat('M');
    try q.enqueue(.ping, &max_payload); // 127 bytes
    try q.enqueue(.pong, &max_payload); // 127 bytes → 254 used, 2 free

    // Even an empty-payload entry needs 2 bytes — exactly fits.
    try q.enqueue(.ping, "");

    // Now 0 bytes free — any enqueue should fail.
    try testing.expectError(error.QueueFull, q.enqueue(.ping, ""));
}

test "empty dequeue returns null" {
    var q = ControlQueue.init();
    var out: [125]u8 = undefined;
    try testing.expect(q.dequeue(&out) == null);
}

test "variable-length entries — empty, small, max 125-byte payload" {
    var q = ControlQueue.init();
    var out: [125]u8 = undefined;

    try q.enqueue(.pong, "");
    try q.enqueue(.ping, "hi");

    const e1 = q.dequeue(&out).?;
    try testing.expectEqual(@as(u8, 0), e1.len);

    const e2 = q.dequeue(&out).?;
    try testing.expectEqual(@as(u8, 2), e2.len);
    try testing.expectEqualSlices(u8, "hi", out[0..e2.len]);

    // Max payload in isolation.
    const max_payload: [125]u8 = @splat('Z');
    try q.enqueue(.close, &max_payload);
    const e3 = q.dequeue(&out).?;
    try testing.expectEqual(Opcode.close, e3.opcode);
    try testing.expectEqual(@as(u8, 125), e3.len);
    try testing.expectEqualSlices(u8, &max_payload, out[0..e3.len]);
}

test "clear resets to empty" {
    var q = ControlQueue.init();
    try q.enqueue(.ping, "data");
    try q.enqueue(.pong, "more");
    try testing.expect(!q.isEmpty());

    q.clear();
    try testing.expect(q.isEmpty());
    try testing.expectEqual(@as(usize, 256), q.availableSpace());

    var out: [125]u8 = undefined;
    try testing.expect(q.dequeue(&out) == null);
}

test "isNextClose detection" {
    var q = ControlQueue.init();
    try testing.expect(!q.isNextClose());

    try q.enqueue(.ping, "");
    try testing.expect(!q.isNextClose());

    // Dequeue the ping, then enqueue a close.
    var out: [125]u8 = undefined;
    const e1 = q.dequeue(&out).?;
    try testing.expectEqual(Opcode.ping, e1.opcode);
    try testing.expectEqual(@as(u8, 0), e1.len);

    try q.enqueue(.close, &[_]u8{ 0x03, 0xE8 });
    try testing.expect(q.isNextClose());
}

test "peek returns null on empty queue" {
    var q = ControlQueue.init();
    try testing.expect(q.peek() == null);
}

test "peek does not consume the entry" {
    var q = ControlQueue.init();
    try q.enqueue(.pong, "peek-test");

    // Peek twice — should return the same entry each time.
    const p1 = q.peek().?;
    const p2 = q.peek().?;
    try testing.expectEqual(p1.opcode, p2.opcode);
    try testing.expectEqual(p1.len, p2.len);

    // Queue should still have exactly one entry.
    try testing.expect(!q.isEmpty());

    var out: [125]u8 = undefined;
    const entry = q.dequeue(&out).?;
    try testing.expectEqual(Opcode.pong, entry.opcode);
    try testing.expectEqualSlices(u8, "peek-test", out[0..entry.len]);
    try testing.expect(q.isEmpty());
}

test "availableSpace tracks usage correctly" {
    var q = ControlQueue.init();
    try testing.expectEqual(@as(usize, 256), q.availableSpace());

    try q.enqueue(.ping, "abc"); // 2 + 3 = 5 bytes
    try testing.expectEqual(@as(usize, 251), q.availableSpace());

    try q.enqueue(.pong, ""); // 2 bytes
    try testing.expectEqual(@as(usize, 249), q.availableSpace());

    var out: [125]u8 = undefined;
    const e1 = q.dequeue(&out).?; // free 5 bytes
    try testing.expectEqual(Opcode.ping, e1.opcode);
    try testing.expectEqualSlices(u8, "abc", out[0..e1.len]);
    try testing.expectEqual(@as(usize, 254), q.availableSpace());
}
