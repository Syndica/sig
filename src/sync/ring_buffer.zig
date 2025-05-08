const std = @import("std");

const Allocator = std.mem.Allocator;

/// Lock-free thread-safe ring buffer using atomic CAS loop for synchronization.
pub fn RingBuffer(T: type) type {
    return struct {
        slots: []Slot,
        head: std.atomic.Value(usize),
        tail: std.atomic.Value(usize),

        const Slot = struct { item: T, next_action: std.atomic.Value(Action) };

        const Action = enum(usize) {
            _,

            fn write(tail: usize) Action {
                return @enumFromInt(tail);
            }

            fn read(head: usize) Action {
                return @enumFromInt((1 << 63) | head);
            }
        };

        pub fn init(allocator: Allocator, len: usize) Allocator.Error!RingBuffer(T) {
            const slots = try allocator.alloc(Slot, len);
            for (slots, 0..) |*slot, i|
                slot.next_action = std.atomic.Value(Action).init(Action.write(i));
            return .{
                .slots = slots,
                .head = std.atomic.Value(usize).init(0),
                .tail = std.atomic.Value(usize).init(0),
            };
        }

        pub fn deinit(self: RingBuffer(T), allocator: Allocator) void {
            allocator.free(self.slots);
        }

        pub fn push(self: *RingBuffer(T), item: T) error{Full}!void {
            const index, const slot = self.acquireSlot(&self.tail, Action.write) orelse
                return error.Full;
            slot.item = item;
            slot.next_action.store(Action.read(index), .release);
        }

        pub fn pop(self: *RingBuffer(T)) ?T {
            const index, const slot = self.acquireSlot(&self.head, Action.read) orelse
                return null;
            defer slot.next_action.store(Action.write(index + self.slots.len), .release);
            return slot.item;
        }

        fn acquireSlot(
            self: *RingBuffer(T),
            head_or_tail: *std.atomic.Value(usize),
            init_action: fn (index: usize) Action,
        ) ?struct { usize, *Slot } {
            var index = head_or_tail.load(.monotonic);
            while (true) {
                const slot = &self.slots[index % self.slots.len];
                if (init_action(index) != slot.next_action.load(.acquire)) {
                    return null;
                }
                if (head_or_tail.cmpxchgWeak(index, index + 1, .acquire, .monotonic)) |head| {
                    index = @intCast(head);
                } else {
                    return .{ index, slot };
                }
                std.atomic.spinLoopHint();
            }
        }
    };
}

test "RingBuffer - single threaded" {
    var ring = try RingBuffer(u64).init(std.testing.allocator, 100);
    defer ring.deinit(std.testing.allocator);

    try std.testing.expectEqual(null, ring.pop());
    for (0..100) |i| {
        try ring.push(i);
    }
    try std.testing.expectError(error.Full, ring.push(123));
    for (0..100) |i| {
        try std.testing.expectEqual(i, ring.pop());
    }
    try std.testing.expectEqual(null, ring.pop());
}

test "RingBuffer - multi threaded" {
    const BIG: usize = 32;
    const SMALL: usize = 8;
    std.debug.assert(BIG > SMALL);
    var source = try RingBuffer(u64).init(std.testing.allocator, BIG);
    var target = try RingBuffer(u64).init(std.testing.allocator, SMALL);
    defer source.deinit(std.testing.allocator);
    defer target.deinit(std.testing.allocator);
    for (0..BIG) |i| try source.push(i);
    var threads: [32]std.Thread = undefined;
    for (0..32) |thread_id| {
        threads[thread_id] = try std.Thread.spawn(.{}, struct {
            fn run(seed: u64, src: *RingBuffer(u64), tgt: *RingBuffer(u64)) void {
                var rand = std.rand.Xoshiro256.init(seed);
                const random = rand.random();
                var maybe_item: ?u64 = null;
                for (0..10_000) |_| {
                    const buf = if (random.boolean()) tgt else src;
                    if (maybe_item) |item| {
                        buf.push(item) catch continue;
                        maybe_item = null;
                    } else {
                        maybe_item = buf.pop();
                    }
                }
                while (maybe_item) |item| {
                    if (src.push(item)) |_| {
                        break;
                    } else |_| if (tgt.push(item)) |_| {
                        break;
                    } else |_| {
                        std.atomic.spinLoopHint();
                    }
                }
            }
        }.run, .{ thread_id, &source, &target });
    }
    for (threads) |thread| thread.join();
    var sum: u128 = 0;
    var count: u128 = 0;
    while (source.pop()) |item| {
        try std.testing.expect(item <= BIG);
        count += 1;
        sum += item;
    }
    while (target.pop()) |item| {
        try std.testing.expect(item <= BIG);
        count += 1;
        sum += item;
    }
    try std.testing.expectEqual(32, count);
    try std.testing.expectEqual(496, sum);
}
