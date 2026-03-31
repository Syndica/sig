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
