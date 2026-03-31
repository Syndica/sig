const std = @import("std");

comptime {
    _ = std.testing.refAllDecls(@This());
}

const Atomic = std.atomic.Value;

/// The ring that holds the packet buffers.
pub fn Ring(N: comptime_int, T: type) type {
    return extern struct {
        head: Pos align(std.atomic.cache_line),
        tail: Pos align(std.atomic.cache_line),
        array: [N]T,

        const RingSelf = @This();
        const Pos = extern struct {
            value: Atomic(u32) = .init(0),
            cached_other: u32 = 0,
        };

        pub fn init(self: *RingSelf) void {
            self.head = .{};
            self.tail = .{};
        }

        pub const Side = enum { reader, writer };

        /// Get a reference to one side of the Ring buffer to start using items.
        pub fn get(self: *RingSelf, comptime side: Side) Iterator(side) {
            const pos = if (side == .reader) &self.head else &self.tail;
            return .{ .ring = self, .pos = pos.value.raw, .other = pos.cached_other };
        }

        pub fn Iterator(comptime side: Side) type {
            return struct {
                ring: *RingSelf,
                pos: u32,
                other: u32,

                const Self = @This();
                const Ptr = if (side == .reader) *const T else *T;

                /// Returns a pointer to the next item to consume on this side of the ring buffer.
                pub fn peek(self: *Self) ?Ptr {
                    return switch (side) {
                        .reader => {
                            if (self.pos == self.other) { // head == cached_tail
                                self.other = self.ring.tail.value.load(.acquire); // cached_tail = load(tail)
                                if (self.pos == self.other) return null;
                                self.ring.head.cached_other = self.other;
                            }
                            return &self.ring.array[self.pos % N];
                        },
                        .writer => {
                            if (self.pos -% self.other == N) { // tail -% cached_head == N
                                self.other = self.ring.head.value.load(.acquire); // cached_head = load(head)
                                if (self.pos -% self.other == N) return null;
                                self.ring.tail.cached_other = self.other;
                            }
                            std.debug.assert((self.pos -% self.other) < N);
                            return &self.ring.array[self.pos % N];
                        },
                    };
                }

                /// If theres an element to use, returns the element and advance's this view of the
                /// ring buffer. NOTE: Does NOT update the ring buffer for the other side.
                pub fn next(self: *Self) ?Ptr {
                    const ptr = self.peek() orelse return null;
                    self.pos +%= 1;
                    return ptr;
                }

                // Using the increments done via `next()` since either 1) the .get() creating this Iterator or
                // 2) the last markUsed() call, update the position of this side on the ring buffer, making any
                // changes to the memory visible to the other side.
                pub fn markUsed(self: *const Self) void {
                    const pos = if (side == .reader) &self.ring.head else &self.ring.tail;
                    pos.value.store(self.pos, .release);
                }
            };
        }
    };
}

const TestRing = Ring(4, u64);

// -- Basic empty / single-element tests -------------------------------------

test "reader gets null on empty ring" {
    var r: TestRing = undefined;
    r.init();
    var reader = r.get(.reader);
    try std.testing.expectEqual(@as(?*const u64, null), reader.peek());
    try std.testing.expectEqual(@as(?*const u64, null), reader.next());
}

test "write one, read one" {
    var r: TestRing = undefined;
    r.init();

    var writer = r.get(.writer);
    const slot = writer.next().?;
    slot.* = 42;
    writer.markUsed();

    var reader = r.get(.reader);
    const val = reader.next().?;
    try std.testing.expectEqual(@as(u64, 42), val.*);
    reader.markUsed();

    // Ring is empty again
    try std.testing.expectEqual(@as(?*const u64, null), reader.peek());
}

// -- peek vs next semantics -------------------------------------------------

test "peek does not advance position" {
    var r: TestRing = undefined;
    r.init();

    var writer = r.get(.writer);
    writer.next().?.* = 10;
    writer.next().?.* = 20;
    writer.markUsed();

    var reader = r.get(.reader);
    // Peeking twice should return the same element.
    const a = reader.peek().?;
    const b = reader.peek().?;
    try std.testing.expectEqual(a, b);
    try std.testing.expectEqual(@as(u64, 10), a.*);

    // next() returns same element then advances
    const c = reader.next().?;
    try std.testing.expectEqual(@as(u64, 10), c.*);
    // Now peek should show the second element
    const d = reader.peek().?;
    try std.testing.expectEqual(@as(u64, 20), d.*);
}

// -- Capacity / full ring ---------------------------------------------------

test "writer returns null when ring is full" {
    var r: TestRing = undefined;
    r.init();

    var writer = r.get(.writer);
    // Fill all 4 slots
    for (0..4) |i| {
        writer.next().?.* = @intCast(i);
    }
    writer.markUsed();

    // 5th write should fail
    try std.testing.expectEqual(@as(?*u64, null), writer.peek());
    try std.testing.expectEqual(@as(?*u64, null), writer.next());
}

test "draining ring frees space for writer" {
    var r: TestRing = undefined;
    r.init();

    var writer = r.get(.writer);
    var reader = r.get(.reader);

    // Fill
    for (0..4) |i| {
        writer.next().?.* = @intCast(i);
    }
    writer.markUsed();

    // Drain 2
    _ = reader.next();
    _ = reader.next();
    reader.markUsed();

    // Same writer iterator sees freed space via peek()'s atomic reload
    try std.testing.expect(writer.next() != null);
    try std.testing.expect(writer.next() != null);
    writer.markUsed();

    try std.testing.expectEqual(@as(?*u64, null), writer.peek());
}

// -- markUsed visibility ----------------------------------------------------

test "reader cannot see items until writer calls markUsed" {
    var r: TestRing = undefined;
    r.init();

    var writer = r.get(.writer);
    var reader = r.get(.reader);

    writer.next().?.* = 99;
    // Do NOT call markUsed

    try std.testing.expectEqual(@as(?*const u64, null), reader.peek());

    // Now publish
    writer.markUsed();

    // Same reader iterator picks up the store via peek()'s atomic reload
    try std.testing.expectEqual(@as(u64, 99), reader.peek().?.*);
}

test "writer cannot reclaim slots until reader calls markUsed" {
    var r: TestRing = undefined;
    r.init();

    var writer = r.get(.writer);
    var reader = r.get(.reader);

    // Fill
    for (0..4) |_| _ = writer.next();
    writer.markUsed();

    // Read all but do NOT markUsed
    for (0..4) |_| _ = reader.next();

    // Writer still sees the ring as full
    try std.testing.expectEqual(@as(?*u64, null), writer.peek());

    // Now publish the reader's progress
    reader.markUsed();

    // Same writer iterator sees freed space via peek()'s atomic reload
    try std.testing.expect(writer.next() != null);
}

// -- Wrap-around ------------------------------------------------------------

test "wrap-around preserves data integrity" {
    var r: TestRing = undefined;
    r.init();

    var writer = r.get(.writer);
    var reader = r.get(.reader);

    // Write and read more than N elements to force wrap-around
    const total: u64 = 13;
    var written: u64 = 0;
    var read: u64 = 0;

    while (read < total) {
        // Write as many as we can
        var did_write = false;
        while (written < total) {
            const ptr = writer.next() orelse break;
            ptr.* = written;
            written += 1;
            did_write = true;
        }
        if (did_write) writer.markUsed();

        // Read as many as we can
        var did_read = false;
        while (true) {
            const ptr = reader.next() orelse break;
            try std.testing.expectEqual(read, ptr.*);
            read += 1;
            did_read = true;
        }
        if (did_read) reader.markUsed();
    }

    try std.testing.expectEqual(total, read);
    try std.testing.expectEqual(total, written);
}

// -- Batch write / batch read -----------------------------------------------

test "batch write then batch read" {
    var r: TestRing = undefined;
    r.init();

    var writer = r.get(.writer);
    writer.next().?.* = 100;
    writer.next().?.* = 200;
    writer.next().?.* = 300;
    writer.markUsed();

    var reader = r.get(.reader);
    try std.testing.expectEqual(@as(u64, 100), reader.next().?.*);
    try std.testing.expectEqual(@as(u64, 200), reader.next().?.*);
    try std.testing.expectEqual(@as(u64, 300), reader.next().?.*);
    try std.testing.expectEqual(@as(?*const u64, null), reader.next());
    reader.markUsed();
}

// -- Multiple produce-consume cycles ----------------------------------------

test "multiple produce-consume cycles" {
    var r: TestRing = undefined;
    r.init();

    var writer = r.get(.writer);
    var reader = r.get(.reader);

    for (0..8) |cycle| {
        // Write 2 items per cycle
        writer.next().?.* = cycle * 2;
        writer.next().?.* = cycle * 2 + 1;
        writer.markUsed();

        try std.testing.expectEqual(@as(u64, cycle * 2), reader.next().?.*);
        try std.testing.expectEqual(@as(u64, cycle * 2 + 1), reader.next().?.*);
        reader.markUsed();
    }
}

// -- Different element types ------------------------------------------------

test "ring with struct element type" {
    const Packet = extern struct {
        id: u32,
        len: u32,
    };

    var r: Ring(2, Packet) = undefined;
    r.init();

    var writer = r.get(.writer);
    const slot = writer.next().?;
    slot.* = .{ .id = 7, .len = 128 };
    writer.markUsed();

    var reader = r.get(.reader);
    const pkt = reader.next().?;
    try std.testing.expectEqual(@as(u32, 7), pkt.id);
    try std.testing.expectEqual(@as(u32, 128), pkt.len);
    reader.markUsed();
}

// -- Concurrent reader/writer via threads -----------------------------------

test "threaded producer-consumer" {
    const count = 100_000;

    var r: Ring(64, u64) = undefined;
    r.init();

    const producer = struct {
        fn run(ring: *Ring(64, u64)) void {
            var writer = ring.get(.writer);
            var i: u64 = 0;
            while (i < count) {
                while (i < count) {
                    const ptr = writer.next() orelse break;
                    ptr.* = i;
                    i += 1;
                }
                writer.markUsed();
            }
        }
    }.run;

    const consumer = struct {
        fn run(ring: *Ring(64, u64)) !void {
            var reader = ring.get(.reader);
            var i: u64 = 0;
            while (i < count) {
                while (i < count) {
                    const ptr = reader.next() orelse break;
                    try std.testing.expectEqual(i, ptr.*);
                    i += 1;
                }
                reader.markUsed();
            }
        }
    }.run;

    const t = try std.Thread.spawn(.{}, producer, .{&r});
    try consumer(&r);
    t.join();
}

// -- Edge: power-of-two and non-power-of-two N ------------------------------

test "ring with non-power-of-two capacity" {
    var r: Ring(3, u32) = undefined;
    r.init();

    var writer = r.get(.writer);
    writer.next().?.* = 1;
    writer.next().?.* = 2;
    writer.next().?.* = 3;
    writer.markUsed();

    try std.testing.expectEqual(@as(?*u32, null), writer.peek());

    var reader = r.get(.reader);
    try std.testing.expectEqual(@as(u32, 1), reader.next().?.*);
    try std.testing.expectEqual(@as(u32, 2), reader.next().?.*);
    try std.testing.expectEqual(@as(u32, 3), reader.next().?.*);
    try std.testing.expectEqual(@as(?*const u32, null), reader.next());
    reader.markUsed();
}

// -- Edge: capacity of 1 ---------------------------------------------------

test "ring with capacity 1" {
    var r: Ring(1, u8) = undefined;
    r.init();

    std.debug.print("hi\n", .{});

    var writer = r.get(.writer);
    var reader = r.get(.reader);

    for (0..10) |i| {
        writer.next().?.* = @intCast(i);
        writer.markUsed();

        // Second write should fail - ring is full
        try std.testing.expectEqual(@as(?*u8, null), writer.peek());

        try std.testing.expectEqual(@as(u8, @intCast(i)), reader.next().?.*);
        reader.markUsed();
    }
}
