const std = @import("std");
const Atomic = std.atomic.Atomic;
const State = @import("chanx.zig").State;
const Channel = @import("chanx.zig").Channel;
const Backoff = @import("backoff.zig").Backoff;
const Waker = @import("waker.zig").Waker;
const OperationId = @import("waker.zig").OperationId;
const thread_context = @import("thread_context.zig");
const ThreadLocalContext = thread_context.ThreadLocalContext;
const ThreadState = thread_context.ThreadState;

/// Token is a temporary struct that holds a reference to Slot(T) within the
/// channel's buffer along with a stamp (slot identifier)
pub fn Token(comptime T: type) type {
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

        /// Attempts to acquire a slot to send a message in
        inline fn acquireSendSlot(self: *Self, token: *Token(T)) error{ full, disconnected }!void {
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
                } else if (stamp +| self.one_lap == tail + 1) {
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
        inline fn write(self: *Self, token: *Token(T), val: T) void {
            token.slot.val = val;
            token.slot.stamp.store(token.stamp, .Release);
            self.receivers.notify();
        }

        pub fn trySend(self: *Self, val: T) error{ full, disconnected }!void {
            var token = Token(T).default();
            try self.acquireSendSlot(&token);
            self.write(&token, val);
        }

        pub fn send(self: *Self, val: T, timeout_ns: ?u64) error{ timeout, disconnected }!void {
            var token = Token(T).uninitialized();
            var timeout: ?std.time.Instant = null;

            if (timeout_ns) |ns| {
                var instant = std.time.Instant.now() catch unreachable;
                addToInstant(&instant, ns);
                timeout = instant;
            }

            while (true) {
                var backoff = Backoff.init();

                while (true) {
                    if (self.acquireSendSlot(&token)) {
                        return self.write(&token, val);
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

                var context = thread_context.getThreadLocalContext();
                context.reset();
                var opId = token.toOperationId();
                self.senders.registerOperation(opId, context);

                // We do this because if channel is not full or if channel is not disconnected,
                // (in either case) we don't want to wait. Let's break out of the sleep.
                //
                // If some other operation was able to update this context's state, we are ok
                // with this. This is why we don't check the return value as a call to `waitUntil`
                // will allow us to perform the checks below.
                if (!self.isFull() or self.isDisconnected())
                    _ = context.tryUpdateState(.aborted);

                switch (context.waitUntil(timeout)) {
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

        inline fn acquireReceiveSlot(self: *Self, token: *Token(T)) error{ empty, disconnected }!void {
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

        inline fn read(self: *Self, token: *Token(T)) T {
            var slot = token.slot;
            slot.stamp.store(token.stamp, .Release);
            self.senders.notify();
            return slot.val;
        }

        pub fn tryReceive(self: *Self) error{ empty, disconnected }!T {
            var token = Token(T).uninitialized();
            try self.acquireReceiveSlot(&token);
            return self.read(&token);
        }

        pub fn receive(self: *Self, timeout_ns: ?u64) error{ timeout, disconnected }!T {
            var token = Token(T).uninitialized();
            var timeout: ?std.time.Instant = null;

            if (timeout_ns) |ns| {
                var instant = std.time.Instant.now() catch unreachable;
                addToInstant(&instant, ns);
                timeout = instant;
            }

            while (true) {
                var backoff = Backoff.init();

                while (true) {
                    if (self.acquireReceiveSlot(&token)) {
                        return self.read(&token);
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

                var context = thread_context.getThreadLocalContext();
                context.reset();
                var opId = token.toOperationId();
                self.receivers.registerOperation(opId, context);

                // We do this because if channel is not full or if channel is not disconnected,
                // (in either case) we don't want to wait. Let's break out of the sleep.
                //
                // If some other operation was able to update this context's state, we are ok
                // with this. This is why we don't check the return value as a call to `waitUntil`
                // will allow us to perform the checks below.
                if (!self.isEmpty() or self.isDisconnected())
                    _ = context.tryUpdateState(.aborted);

                switch (context.waitUntil(timeout)) {
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

        pub inline fn releaseReceiver(self: *Self) void {
            if (self.n_receivers.fetchSub(1, .SeqCst) == 1) {
                self.disconnect();
            }
        }

        pub inline fn acquireSender(self: *Self) void {
            _ = self.n_senders.fetchAdd(1, .SeqCst);
        }

        pub inline fn releaseSender(self: *Self) void {
            if (self.n_senders.fetchSub(1, .SeqCst) == 1) {
                self.disconnect();
            }
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

test "bounded channel" {
    var chan = try Bounded(u64).init(.{ .allocator = std.testing.allocator, .init_capacity = 10 });
    defer chan.deinit();

    try chan.send(100, null);
    var received = try chan.receive(null);

    try std.testing.expectEqual(received, 100);
}
