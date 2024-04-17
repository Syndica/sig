const std = @import("std");
const Atomic = std.atomic.Atomic;
const State = @import("chanx.zig").State;
const Channel = @import("chanx.zig").ChannelX;
const Backoff = @import("backoff.zig").Backoff;
const Waker = @import("waker.zig").Waker;
const OperationId = @import("waker.zig").OperationId;
const thread_context = @import("thread_context.zig");
const ThreadLocalContext = thread_context.ThreadLocalContext;
const ThreadState = thread_context.ThreadState;

/// TempSlot is a temporary struct that holds a reference to Slot(T) within the
/// channel's buffer along with a stamp (slot identifier) that will be writen to slot
/// upon successful read/write.
pub fn TempSlot(comptime T: type) type {
    return struct {
        slot: *Slot(T),
        stamp: usize,

        const Self = @This();

        pub fn uninitialized() Self {
            return .{
                .slot = undefined,
                .stamp = 0,
            };
        }

        pub fn toOperationId(self: *const Self) OperationId {
            return @intFromPtr(self);
        }

        pub fn fromOperationId(op: OperationId) *Self {
            return @ptrFromInt(op);
        }
    };
}
pub fn Slot(comptime T: type) type {
    return struct {
        stamp: Atomic(usize),
        val: T,
    };
}

pub fn Bounded(comptime T: type) type {
    return struct {
        allocator: std.mem.Allocator,
        buffer: []Slot(T),
        head: Atomic(usize),
        tail: Atomic(usize),
        disconnect_bit: usize, // if this bit is set on the tail, the channel is disconnected
        one_lap: usize,
        receivers: Waker,
        senders: Waker,
        n_receivers: Atomic(usize),
        n_senders: Atomic(usize),

        const Self = @This();

        pub fn init(config: struct { allocator: std.mem.Allocator, init_capacity: usize }) error{OutOfMemory}!*Self {
            if (config.init_capacity < 1) {
                @panic("bounded init_capacity must be greater than 0");
            }

            var allocator = config.allocator;
            var disconnect_bit = std.math.ceilPowerOfTwo(usize, config.init_capacity + 1) catch unreachable;
            var one_lap = disconnect_bit * 2;

            var self = try allocator.create(Self);
            var buff = try allocator.alloc(Slot(T), config.init_capacity);

            // initialize all slots with proper stamps
            for (0..config.init_capacity) |i| {
                buff[i] = .{
                    .stamp = Atomic(usize).init(i),
                    .val = undefined,
                };
            }

            self.* = .{
                .allocator = allocator,
                .buffer = buff,
                .head = Atomic(usize).init(0),
                .tail = Atomic(usize).init(0),
                .disconnect_bit = disconnect_bit,
                .one_lap = one_lap,
                .receivers = Waker.init(allocator),
                .senders = Waker.init(allocator),
                .n_receivers = Atomic(usize).init(0),
                .n_senders = Atomic(usize).init(0),
            };

            return self;
        }

        pub fn deinit(self: *Self) void {
            self.disconnect();
            self.senders.deinit();
            self.receivers.deinit();
            self.allocator.free(self.buffer);
            self.allocator.destroy(self);
        }

        pub fn capacity(self: *Self) usize {
            return self.buffer.len;
        }

        /// Attempts to acquire a slot to send a message in
        inline fn acquireSendSlot(self: *Self, token: *TempSlot(T)) error{ full, disconnected }!void {
            var backoff = Backoff.init();
            var tail = self.tail.load(.Unordered);

            while (true) {
                // Check if the channel is disconnected.
                if (tail & self.disconnect_bit != 0) {
                    token.slot = undefined;
                    token.stamp = 0;
                    return error.disconnected;
                }

                // Deconstruct the tail.
                var index = tail & (self.disconnect_bit - 1);
                var lap = tail & ~(self.one_lap - 1);

                // Inspect the corresponding slot.
                std.debug.assert(index < self.buffer.len);
                var slot = &self.buffer[index];
                var stamp = slot.stamp.load(.Acquire);

                if (tail == stamp) {
                    var new_tail = if (index + 1 < self.buffer.len) tail + 1 else lap +| self.one_lap;
                    if (self.tail.tryCompareAndSwap(tail, new_tail, .SeqCst, .Monotonic)) |current_tail| {
                        // failed
                        tail = current_tail;
                        backoff.spin();
                    } else {
                        // succeeded
                        token.slot = slot;
                        token.stamp = tail + 1;
                        return;
                    }
                } else if (tail + 1 == (stamp +| self.one_lap)) {
                    std.atomic.fence(.SeqCst);
                    var head = self.head.load(.Unordered);

                    if (head +| self.one_lap == tail) {
                        // channel full
                        return error.full;
                    }

                    backoff.spin();
                    tail = self.tail.load(.Unordered);
                } else {
                    // Snooze because we need to wait for the stamp to get updated.
                    backoff.snooze();
                    tail = self.tail.load(.Unordered);
                }
            }
        }

        /// writes a value to given `Token`'s slot
        inline fn write(self: *Self, token: *TempSlot(T), val: T) void {
            token.slot.val = val;
            token.slot.stamp.store(token.stamp, .Release);
            self.receivers.notify();
        }

        pub fn trySend(self: *Self, val: T) error{ full, disconnected }!void {
            var temp_slot = TempSlot(T).uninitialized();
            try self.acquireSendSlot(&temp_slot);
            self.write(&temp_slot, val);
        }

        pub fn send(self: *Self, val: T, timeout_ns: ?u64) error{ timeout, disconnected }!void {
            var temp_slot = TempSlot(T).uninitialized();
            var timeout: ?std.time.Instant = null;

            if (timeout_ns) |ns| {
                var instant = std.time.Instant.now() catch unreachable;
                addToInstant(&instant, ns);
                timeout = instant;
            }

            while (true) {
                var backoff = Backoff.init();

                while (true) {
                    if (self.acquireSendSlot(&temp_slot)) {
                        return self.write(&temp_slot, val);
                    } else |err| switch (err) {
                        // if channel disconnected, we return as nothing else can be done
                        error.disconnected => return error.disconnected,
                        // if channel full, we backoff before putting thread to sleep
                        error.full => {
                            if (backoff.isCompleted()) {
                                break;
                            } else {
                                backoff.snooze();
                            }
                        },
                    }
                }

                if (timeout != null and (std.time.Instant.now() catch unreachable).order(timeout.?) == .gt)
                    return error.timeout;

                var thread_ctx = thread_context.getThreadLocalContext();
                thread_ctx.reset();
                var opId = temp_slot.toOperationId();
                self.senders.registerOperation(opId, thread_ctx);

                // We do this because if channel is not full or if channel is not disconnected,
                // (in either case) we don't want to wait. Let's break out of the sleep.
                //
                // If some other operation was able to update this context's state, we are ok
                // with this. This is why we don't check the return value as a call to `waitUntil`
                // will allow us to perform the checks below.
                if (!self.isFull() or self.isDisconnected())
                    _ = thread_ctx.tryUpdateFromWaitingStateTo(.aborted);

                switch (thread_ctx.waitUntil(timeout)) {
                    .waiting => unreachable,
                    .aborted, .disconnected => {
                        // there must be an entry with this operation id, if not panic!
                        _ = self.senders.unregisterOperation(opId) orelse unreachable;
                    },
                    .operation => |operationId| {
                        std.debug.assert(opId == operationId);
                    },
                }
            }
        }

        inline fn acquireReceiveSlot(self: *Self, token: *TempSlot(T)) error{ empty, disconnected }!void {
            var backoff = Backoff.init();
            var head = self.head.load(.Unordered);

            while (true) {
                var index = head & (self.disconnect_bit - 1);
                var lap = head & ~(self.one_lap - 1);

                std.debug.assert(index < self.buffer.len);
                var slot = &self.buffer[index];
                var stamp = slot.stamp.load(.Acquire);

                if (head + 1 == stamp) {
                    var new = if (index + 1 < self.buffer.len) head + 1 else lap +| self.one_lap;

                    // Try moving the head.
                    if (self.head.tryCompareAndSwap(
                        head,
                        new,
                        .SeqCst,
                        .Monotonic,
                    )) |current_head| {
                        // failed
                        head = current_head;
                        backoff.spin();
                    } else {
                        // succeeded
                        token.slot = slot;
                        token.stamp = head +| self.one_lap;
                        return;
                    }
                } else if (stamp == head) {
                    std.atomic.fence(.SeqCst);
                    var tail = self.tail.load(.Unordered);

                    // If the tail equals the head, that means the channel is empty.
                    if ((tail & ~self.disconnect_bit) == head) {
                        // channel is disconnected if mark_bit set otherwise the receive operation is not ready (empty)
                        return if (tail & self.disconnect_bit != 0) error.disconnected else error.empty;
                    }

                    backoff.spin();
                    head = self.head.load(.Unordered);
                } else {
                    // Snooze because we need to wait for the stamp to get updated.
                    backoff.snooze();
                    head = self.head.load(.Unordered);
                }
            }
        }

        inline fn read(self: *Self, token: *TempSlot(T)) T {
            var slot = token.slot;
            slot.stamp.store(token.stamp, .Release);
            self.senders.notify();
            return slot.val;
        }

        pub fn tryReceive(self: *Self) error{ empty, disconnected }!T {
            var temp_slot = TempSlot(T).uninitialized();
            try self.acquireReceiveSlot(&temp_slot);
            return self.read(&temp_slot);
        }

        pub fn receive(self: *Self, timeout_ns: ?u64) error{ timeout, disconnected }!T {
            var temp_slot = TempSlot(T).uninitialized();
            var timeout: ?std.time.Instant = null;

            if (timeout_ns) |ns| {
                var instant = std.time.Instant.now() catch unreachable;
                addToInstant(&instant, ns);
                timeout = instant;
            }

            while (true) {
                var backoff = Backoff.init();

                while (true) {
                    if (self.acquireReceiveSlot(&temp_slot)) {
                        return self.read(&temp_slot);
                    } else |err| switch (err) {
                        // if channel disconnected, we return as nothing else can be done
                        error.disconnected => return error.disconnected,
                        // if channel empty, we backoff before putting thread to sleep
                        error.empty => {
                            if (backoff.isCompleted()) {
                                break;
                            } else {
                                backoff.snooze();
                            }
                        },
                    }
                }

                if (timeout != null and (std.time.Instant.now() catch unreachable).order(timeout.?) == .gt)
                    return error.timeout;

                var thread_ctx = thread_context.getThreadLocalContext();
                thread_ctx.reset();
                var opId = temp_slot.toOperationId();
                self.receivers.registerOperation(opId, thread_ctx);

                // We do this because if channel is not full or if channel is not disconnected,
                // (in either case) we don't want to wait. Let's break out of the sleep.
                //
                // If some other operation was able to update this context's state, we are ok
                // with this. This is why we don't check the return value as a call to `waitUntil`
                // will allow us to perform the checks below.
                if (!self.isEmpty() or self.isDisconnected())
                    _ = thread_ctx.tryUpdateFromWaitingStateTo(.aborted);

                switch (thread_ctx.waitUntil(timeout)) {
                    .waiting => unreachable,
                    .aborted, .disconnected => {
                        // there must be an entry with this operation id, if not panic!
                        _ = self.receivers.unregisterOperation(opId) orelse unreachable;
                    },
                    .operation => |operationId| {
                        std.debug.assert(opId == operationId);
                    },
                }
            }
        }

        pub inline fn acquireReceiver(self: *Self) void {
            _ = self.n_receivers.fetchAdd(1, .SeqCst);
        }

        pub inline fn releaseReceiver(self: *Self) bool {
            if (self.n_receivers.load(.SeqCst) == 0)
                return false;
            if (self.n_receivers.fetchSub(1, .SeqCst) == 1) {
                self.disconnect();
            }
            return true;
        }

        /// attempts to acquire a sender, returns true if successful, returns
        /// false if channel is disconnected.
        pub inline fn acquireSender(self: *Self) void {
            _ = self.n_senders.fetchAdd(1, .SeqCst);
        }

        /// attempts to release a sender, returns true if successful, returns
        /// false if channel is disconnected.
        pub inline fn releaseSender(self: *Self) bool {
            if (self.n_senders.load(.SeqCst) == 0)
                return false;
            if (self.n_senders.fetchSub(1, .SeqCst) == 1) {
                self.disconnect();
            }
            return true;
        }

        pub inline fn isFull(self: *const Self) bool {
            var tail = self.tail.load(.SeqCst);
            var head = self.head.load(.SeqCst);

            // Is the head lagging one lap behind tail?
            //
            // Note: If the tail changes just before we load the head, that means there was a moment
            // when the channel was not full, so it is safe to just return `false`.
            return head +| self.one_lap == tail & ~self.disconnect_bit;
        }

        pub inline fn isEmpty(self: *Self) bool {
            var head = self.head.load(.SeqCst);
            var tail = self.tail.load(.SeqCst);

            // Is the tail equal to the head?
            //
            // Note: If the head changes just before we load the tail, that means there was a moment
            // when the channel was not empty, so it is safe to just return `false`.
            return (tail & ~self.disconnect_bit) == head;
        }

        pub inline fn isDisconnected(self: *const Self) bool {
            return self.tail.load(.SeqCst) & self.disconnect_bit != 0;
        }

        pub inline fn disconnect(self: *Self) void {
            var tail = self.tail.fetchOr(self.disconnect_bit, .SeqCst);

            // if tail & disconnect_bit == 0 it means this is the first time
            // this was called so we should disconnect all sleepers
            if (tail & self.disconnect_bit == 0) {
                self.senders.disconnectAll();
                self.receivers.disconnectAll();
            }
        }
    };
}

fn addToInstant(instant: *std.time.Instant, duration_ns: u64) void {
    var secs: u64 = duration_ns / std.time.ns_per_s;
    var nsecs: u64 = duration_ns % std.time.ns_per_s;
    instant.timestamp.tv_sec +|= @intCast(secs);
    instant.timestamp.tv_nsec +|= @intCast(nsecs);
}

fn testChannelSender(chan: *Bounded(usize), count: usize, timeout_ns: ?u64) void {
    chan.acquireSender();
    defer std.debug.assert(chan.releaseSender());

    var i: usize = 0;
    while (i < count) : (i += 1) {
        chan.send(i, timeout_ns) catch break;
    }
}

fn testChannelReceiver(chan: *Bounded(usize), received_counter: ?*Atomic(usize), timeout_ns: ?u64) void {
    chan.acquireReceiver();
    defer std.debug.assert(chan.releaseReceiver());

    while (true) {
        _ = chan.receive(timeout_ns) catch break;
        if (received_counter) |counter| {
            _ = counter.fetchAdd(1, .SeqCst);
        }
    }
}

test "sync.bounded: bounded channel works" {
    const items_to_send = 1000;
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    var received_counter = Atomic(usize).init(0);

    var sender_handle = try std.Thread.spawn(.{}, testChannelSender, .{ chan, items_to_send, null });
    var receiver_handle = try std.Thread.spawn(.{}, testChannelReceiver, .{ chan, &received_counter, null });

    sender_handle.join();
    receiver_handle.join();

    try std.testing.expectEqual(received_counter.load(.SeqCst), 1000);
    try std.testing.expectEqual(chan.n_receivers.load(.SeqCst), 0);
    try std.testing.expectEqual(chan.n_senders.load(.SeqCst), 0);
    try std.testing.expectEqual(chan.isDisconnected(), true);
    try std.testing.expectEqual(chan.isEmpty(), true);
    try std.testing.expectEqual(chan.isFull(), false);
}

test "sync.bounded: buffer len is correct" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    try std.testing.expectEqual(chan.capacity(), 10);
}

test "sync.bounded: disconnect bit is correct" {
    var capacity: usize = 0b01100100;
    var disconnect_bit: usize = 0b10000000;
    var fake_tail: usize = 0b01000100;
    var disconnected_fake_tail: usize = fake_tail | disconnect_bit; // 0b11000100;
    var disconnected: usize = disconnected_fake_tail & disconnect_bit;

    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = capacity,
    });
    defer chan.deinit();

    try std.testing.expectEqual(chan.disconnect_bit, disconnect_bit);
    try std.testing.expect(!chan.isDisconnected());
    chan.disconnect();

    try std.testing.expect(chan.isDisconnected());
    try std.testing.expectError(error.disconnected, chan.send(1, null));
    try std.testing.expectError(error.disconnected, chan.trySend(1));
    try std.testing.expectError(error.disconnected, chan.receive(null));
    try std.testing.expectError(error.disconnected, chan.tryReceive());

    try std.testing.expectEqual(capacity, 100);
    try std.testing.expectEqual(disconnect_bit, try std.math.ceilPowerOfTwo(usize, capacity + 1));
    try std.testing.expectEqual(disconnected_fake_tail, 0b11000100);
    try std.testing.expect(disconnected != 0);
}

test "sync.bounded: one_lap is correct" {
    var capacity: usize = 0b01100100;
    var disconnect_bit: usize = 0b10000000;
    var one_lap: usize = disconnect_bit * 2; // 0b100000000

    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = capacity,
    });
    defer chan.deinit();

    try std.testing.expectEqual(one_lap, chan.one_lap);
}

test "sync.bounded: mpsc" {
    var capacity: usize = 100;
    var n_items: usize = 1000;
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = capacity,
    });
    defer chan.deinit();
    var received_count = Atomic(usize).init(0);

    var sender_1_handle = try std.Thread.spawn(.{}, testChannelSender, .{ chan, n_items / 2, null });
    var sender_2_handle = try std.Thread.spawn(.{}, testChannelSender, .{ chan, n_items / 2, null });
    var receiver_handle = try std.Thread.spawn(.{}, testChannelReceiver, .{ chan, &received_count, null });

    sender_1_handle.join();
    sender_2_handle.join();
    receiver_handle.join();

    try std.testing.expectEqual(n_items, received_count.load(.SeqCst));
}

test "sync.bounded: mpmc" {
    var capacity: usize = 100;
    var n_items: usize = 1000;
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = capacity,
    });
    defer chan.deinit();
    var received_count = Atomic(usize).init(0);

    var sender_1_handle = try std.Thread.spawn(.{}, testChannelSender, .{ chan, n_items / 2, null });
    var sender_2_handle = try std.Thread.spawn(.{}, testChannelSender, .{ chan, n_items / 2, null });
    var receiver_1_handle = try std.Thread.spawn(.{}, testChannelReceiver, .{ chan, &received_count, null });
    var receiver_2_handle = try std.Thread.spawn(.{}, testChannelReceiver, .{ chan, &received_count, null });

    sender_1_handle.join();
    sender_2_handle.join();
    receiver_1_handle.join();
    receiver_2_handle.join();

    try std.testing.expectEqual(n_items, received_count.load(.SeqCst));
}

test "sync.bounded: spsc" {
    var capacity: usize = 100;
    var n_items: usize = 1000;
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = capacity,
    });
    defer chan.deinit();
    var received_count = Atomic(usize).init(0);

    var sender_handle = try std.Thread.spawn(.{}, testChannelSender, .{ chan, n_items, null });
    var receiver_handle = try std.Thread.spawn(.{}, testChannelReceiver, .{ chan, &received_count, null });

    sender_handle.join();
    receiver_handle.join();

    try std.testing.expectEqual(n_items, received_count.load(.SeqCst));
}

test "sync.bounded: spmc" {
    var capacity: usize = 100;
    var n_items: usize = 1000;
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = capacity,
    });
    defer chan.deinit();
    var received_count = Atomic(usize).init(0);

    var sender_handle = try std.Thread.spawn(.{}, testChannelSender, .{ chan, n_items, null });
    var receiver_1_handle = try std.Thread.spawn(.{}, testChannelReceiver, .{ chan, &received_count, null });
    var receiver_2_handle = try std.Thread.spawn(.{}, testChannelReceiver, .{ chan, &received_count, null });

    sender_handle.join();
    receiver_1_handle.join();
    receiver_2_handle.join();

    try std.testing.expectEqual(n_items, received_count.load(.SeqCst));
}

test "sync.bounded: disconnect after all senders released" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    // acquire a few senders and a single receiver
    chan.acquireReceiver();
    defer std.debug.assert(chan.releaseReceiver());
    chan.acquireSender();
    chan.acquireSender();
    chan.acquireSender();

    // channel should not be disconnected
    try std.testing.expect(!chan.isDisconnected());

    // release only 2
    try std.testing.expect(chan.releaseSender());
    try std.testing.expect(chan.releaseSender());

    // should still be connected
    try std.testing.expect(!chan.isDisconnected());

    // release last sender
    try std.testing.expect(chan.releaseSender());

    // channel should now be disconnected
    try std.testing.expect(chan.isDisconnected());
    try std.testing.expectError(error.disconnected, chan.receive(null));
}

test "sync.bounded: disconnect after all receivers deinit" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    // acquire a few receivers and a single sender
    chan.acquireSender();
    defer std.debug.assert(chan.releaseSender());
    chan.acquireReceiver();
    chan.acquireReceiver();
    chan.acquireReceiver();

    // channel should not be disconnected
    try std.testing.expect(!chan.isDisconnected());

    // release only 2
    try std.testing.expect(chan.releaseReceiver());
    try std.testing.expect(chan.releaseReceiver());

    // should still be connected
    try std.testing.expect(!chan.isDisconnected());

    // release last sender
    try std.testing.expect(chan.releaseReceiver());

    // channel should now be disconnected
    try std.testing.expect(chan.isDisconnected());
    try std.testing.expectError(error.disconnected, chan.send(1, null));
}

test "sync.bounded: acquire sender correctly" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    // acquire a few receivers and a single sender
    chan.acquireSender();
    try std.testing.expect(chan.n_senders.load(.SeqCst) == 1);
    try std.testing.expect(chan.releaseSender());
    try std.testing.expect(chan.n_senders.load(.SeqCst) == 0);
    try std.testing.expect(chan.isDisconnected());
}

test "sync.bounded: acquire sender fails after disconnect" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    chan.acquireSender();
    try std.testing.expect(chan.n_senders.load(.SeqCst) == 1);
    try std.testing.expect(chan.releaseSender());
    try std.testing.expect(chan.n_senders.load(.SeqCst) == 0);
    try std.testing.expect(chan.isDisconnected());
    chan.acquireSender();
}

test "sync.bounded: acquire receiver" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    chan.acquireReceiver();
    try std.testing.expect(chan.n_receivers.load(.SeqCst) == 1);
    try std.testing.expect(chan.releaseReceiver());
    try std.testing.expect(chan.n_receivers.load(.SeqCst) == 0);
    try std.testing.expect(chan.isDisconnected());
}

test "sync.bounded: acquire receiver fails after disconnect" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    chan.acquireReceiver();
    try std.testing.expect(chan.n_receivers.load(.SeqCst) == 1);
    try std.testing.expect(chan.releaseReceiver());
    try std.testing.expect(chan.n_receivers.load(.SeqCst) == 0);
    try std.testing.expect(chan.isDisconnected());
    chan.acquireReceiver();
}

test "sync.bounded: release sender correctly" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    chan.acquireSender();
    try std.testing.expect(chan.n_senders.load(.SeqCst) == 1);
    try std.testing.expect(chan.releaseSender());
    try std.testing.expect(chan.n_senders.load(.SeqCst) == 0);
    try std.testing.expect(!chan.releaseSender());
}

test "sync.bounded: release receiver correctly" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    chan.acquireReceiver();
    try std.testing.expect(chan.n_receivers.load(.SeqCst) == 1);
    try std.testing.expect(chan.releaseReceiver());
    try std.testing.expect(chan.n_receivers.load(.SeqCst) == 0);
    try std.testing.expect(!chan.releaseReceiver());
}

test "sync.bounded: channel full/empty works correctly" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 2,
    });
    defer chan.deinit();

    try std.testing.expect(chan.isEmpty());
    try std.testing.expect(!chan.isFull());
    try chan.send(1, null);
    try chan.send(2, null);
    try std.testing.expectError(error.full, chan.trySend(3));
    try std.testing.expect(chan.isFull());
    try std.testing.expect(!chan.isEmpty());
}

test "sync.bounded: channel send works correctly" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    try chan.send(1, null);
    try std.testing.expectEqual(try chan.receive(null), 1);
}

test "sync.bounded: send while disconnected fails" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    chan.disconnect();
    try std.testing.expectError(error.disconnected, chan.send(1, null));
}

test "sync.bounded: send timeout works" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 1,
    });
    defer chan.deinit();

    var timeout: u64 = std.time.ns_per_ms * 100;

    chan.acquireSender();
    defer std.debug.assert(chan.releaseSender());
    try chan.send(1, null);
    var timer = try std.time.Timer.start();
    try std.testing.expectError(error.timeout, chan.send(2, timeout));
    var time = timer.read();
    try std.testing.expect(time >= timeout);
}

test "sync.bounded: acquireSenderSlot works correctly" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 3,
    });
    defer chan.deinit();

    try chan.send(1, null);
    try chan.send(2, null);
    try chan.send(3, null);

    var temp_slot = TempSlot(usize).uninitialized();
    try std.testing.expectError(error.full, chan.acquireSendSlot(&temp_slot));

    chan.disconnect();
    try std.testing.expectError(error.disconnected, chan.acquireSendSlot(&temp_slot));
}

test "sync.bounded: trySend works properly" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 3,
    });
    defer chan.deinit();

    try chan.trySend(1);
    try chan.trySend(2);
    try chan.trySend(3);
    try std.testing.expectError(error.full, chan.trySend(4));
    chan.disconnect();
    try std.testing.expectError(error.disconnected, chan.trySend(4));
}

test "sync.bounded: receive order is correct" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 3,
    });
    defer chan.deinit();

    try chan.send(1, null);
    try chan.send(2, null);
    try chan.send(3, null);
    try std.testing.expectEqual(try chan.receive(null), 1);
    try std.testing.expectEqual(try chan.receive(null), 2);
    try std.testing.expectEqual(try chan.receive(null), 3);
}

test "sync.bounded: receive while disconnected should still drain all elements" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    try chan.send(1, null);
    try chan.send(2, null);
    try chan.send(3, null);
    chan.disconnect();
    try std.testing.expect(try chan.receive(null) == 1);
    try std.testing.expect(try chan.receive(null) == 2);
    try std.testing.expect(try chan.receive(null) == 3);
    try std.testing.expectError(error.disconnected, chan.receive(null));
}

test "sync.bounded: receive while empty with timeout" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    var timeout: u64 = std.time.ns_per_ms * 100;

    try std.testing.expectError(error.timeout, chan.receive(timeout));
}

test "sync.bounded: acquireReceiveSlot works correctly" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    try chan.send(1, null);
    try chan.send(2, null);
    try chan.send(3, null);
    try std.testing.expect(try chan.receive(null) == 1);
    try std.testing.expect(try chan.receive(null) == 2);
    try std.testing.expect(try chan.receive(null) == 3);

    var temp_slot = TempSlot(usize).uninitialized();
    try std.testing.expectError(error.empty, chan.acquireReceiveSlot(&temp_slot));

    chan.disconnect();
    try std.testing.expectError(error.disconnected, chan.acquireReceiveSlot(&temp_slot));
}

test "sync.bounded: tryReceive works correctly" {
    var chan = try Bounded(usize).init(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    try std.testing.expectError(error.empty, chan.tryReceive());
    try chan.send(1, null);
    try std.testing.expectEqual(@as(usize, 1), try chan.tryReceive());
    try std.testing.expectError(error.empty, chan.tryReceive());
    chan.disconnect();
    try std.testing.expectError(error.disconnected, chan.tryReceive());
}
