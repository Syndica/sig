const std = @import("std");
const Bounded = @import("bounded.zig").Bounded;
const Atomic = std.atomic.Atomic;
const page_allocator = std.heap.page_allocator;

/// `ChannelX` is an enum that unifies channel API across different kinds of backing
/// channels such as `bounded`, `unbounded`, etc.
pub fn ChannelX(comptime T: type) type {
    return union(enum(u8)) {
        bounded: *Bounded(T),

        const Self = @This();

        /// Initializes a `bounded` channel.
        pub fn initBounded(config: Bounded(T).Config) error{OutOfMemory}!Self {
            return try Self.init(.bounded, config);
        }

        /// Initializes a channel based on `kind` and `config`
        pub fn init(kind: enum { bounded }, config: anytype) error{OutOfMemory}!Self {
            return switch (kind) {
                .bounded => .{
                    .bounded = try Bounded(T).init(config),
                },
            };
        }

        /// Deinitializes self and underlying channel.
        pub fn deinit(self: Self) void {
            switch (self) {
                .bounded => |b| {
                    b.deinit();
                },
            }
        }

        /// Initializes a new `Sender` to allow for sending values to the underlying channel. It's
        /// the caller's responsibility to `deinit()` returned sender.
        pub fn initSender(self: Self) error{disconnected}!Sender(T) {
            switch (self) {
                .bounded => |ch| if (ch.isDisconnected()) return error.disconnected,
            }
            return Sender(T).init(self);
        }

        /// Initializes a new `Receiver` to allow for receiving values from the underlying channel.
        /// It's the caller's responsibility to `deinit()` returned receiver.
        pub fn initReceiver(self: Self) error{disconnected}!Receiver(T) {
            switch (self) {
                .bounded => |ch| if (ch.isDisconnected()) return error.disconnected,
            }
            return Receiver(T).init(self);
        }

        /// Acquires a sender from the underlying channel
        fn acquireSender(self: Self) void {
            switch (self) {
                .bounded => |c| c.acquireSender(),
            }
        }

        /// Releases a sender from the underlying channel
        fn releaseSender(self: Self) void {
            switch (self) {
                .bounded => |c| std.debug.assert(c.releaseSender()),
            }
        }

        /// Acquires a receiver from the underlying channel
        fn acquireReceiver(self: Self) void {
            switch (self) {
                .bounded => |c| c.acquireReceiver(),
            }
        }

        /// Releases a receiver from the underlying channel
        fn releaseReceiver(self: Self) void {
            switch (self) {
                .bounded => |c| std.debug.assert(c.releaseReceiver()),
            }
        }

        /// Sends a value to underlying channel, blocking until channel
        /// has space.
        fn send(self: Self, val: T) error{disconnected}!void {
            switch (self) {
                .bounded => |chan| {
                    chan.send(val, null) catch |err| switch (err) {
                        error.disconnected => return error.disconnected,
                        error.timeout => unreachable,
                    };
                },
            }
        }

        /// Tries to send a value immediately or returns `error.full` if underlying
        /// channel is full.
        fn trySend(self: Self, val: T) error{ full, disconnected }!void {
            switch (self) {
                .bounded => |chan| {
                    return chan.trySend(val);
                },
            }
        }

        /// Sends a value to underlying channel blocking until `timeout_ns` has elpased or until
        /// channel successfully sends value.
        fn sendTimeout(self: Self, val: T, timeout_ns: u64) error{ timeout, disconnected }!void {
            switch (self) {
                .bounded => |chan| {
                    return chan.send(val, timeout_ns);
                },
            }
        }

        /// Receives a value from the underlying channel, blocking until a value is ready to be read.
        fn receive(self: Self) ?T {
            switch (self) {
                .bounded => |chan| {
                    if (chan.receive(null)) |val| {
                        return val;
                    } else |err| switch (err) {
                        error.disconnected => return null,
                        error.timeout => unreachable,
                    }
                },
            }
        }

        /// Tries to receive a value from the underlying channel immediately or returns
        /// `error.empty` if no value is available to be read.
        fn tryReceive(self: Self) error{ empty, disconnected }!T {
            switch (self) {
                .bounded => |chan| {
                    return chan.tryReceive();
                },
            }
        }

        /// Receives a value from underlying channel, blocking until `timeout_ns` has elapsed
        /// or until value is ready to be read.
        fn receiveTimeout(self: Self, timeout_ns: u64) error{ timeout, disconnected }!T {
            switch (self) {
                .bounded => |chan| {
                    return chan.receive(timeout_ns);
                },
            }
        }

        /// Returns the underlying channel's capacity
        pub fn capacity(self: Self) usize {
            return switch (self) {
                .bounded => |chan| chan.capacity(),
            };
        }
    };
}

/// Sender is a **non**-thread-safe structure which can be used to send
/// values to the underlying channel.
///
/// `Sender` provides blocking and non-blocking methods to send items to
/// underlying channel:
/// - `send(value)`: blocking
/// - `sendTimeout(value, timeout_ns)`: blocking until timeout or item sent
/// - `trySend(value)`: non-blocking
///
/// NOTE: In order to ensure consistent channel state, you must acquire the sender in the
/// thread you will be `send`ing from.
///
/// **Don't do this:**
/// ```
/// fn incorrect_cross_thread_usage(sender: *Sender(usize)) void {
///     // this will cause potential inconsistent channel state:
///     defer sender.deinit();
///     try sender.send(1);
/// }
/// try std.Thread.spawn(.{}, incorrect_cross_thread_usage, &sender);
/// ```
///
///
/// **Do this instead:**
/// ```
/// fn correct_cross_thread_usage(chan: ChannelX(usize)) void {
///     var sender = chan.sender();
///     defer sender.deinit();
///     // now safe to send
///     try sender.send(1);
/// }
/// try std.Thread.spawn(.{}, correct_cross_thread_usage, chan);
/// ```
///
pub fn Sender(comptime T: type) type {
    return struct {
        private: Internal,

        const Internal = struct {
            thread_id: std.Thread.Id,
            released: bool,
            ch: ChannelX(T),
        };

        const Self = @This();

        /// Initializes a new `Sender` by acquiring a sender from the underlying channel
        fn init(chan: ChannelX(T)) Self {
            chan.acquireSender();
            return Self{
                .private = .{
                    .thread_id = std.Thread.getCurrentId(),
                    .released = false,
                    .ch = chan,
                },
            };
        }

        /// Sends a value to underlying channel, blocking if the channel is full.
        pub fn send(self: *Self, val: T) error{disconnected}!void {
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            std.debug.assert(!self.private.released);
            return self.private.ch.send(val);
        }

        /// Tries to send a value to underlying channel (non-blockingly). It returns an `error.full`
        /// if the channel is currently full.
        pub fn trySend(self: *Self, val: T) error{ full, disconnected }!void {
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            std.debug.assert(!self.private.released);
            return self.private.ch.trySend(val);
        }

        /// Sends a value to the underlying channel blocking if the channel is full up to `timeout_ns`
        /// has elapsed at which point returns `error.timeout`.
        pub fn sendTimeout(self: *Self, val: T, timeout_ns: u64) error{ timeout, disconnected }!void {
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            std.debug.assert(!self.private.released);
            return self.private.ch.sendTimeout(val, timeout_ns);
        }

        /// Deinitializes self and releases the sender from the underlying channel.
        pub fn deinit(self: *Self) void {
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            std.debug.assert(!self.private.released);
            self.private.released = true;
            self.private.ch.releaseSender();
        }
    };
}

/// Receiver is a **non**-thread-safe structure which can be used to receive
/// values from the underlying channel.
///
/// Receiver provides blocking and non-blocking methods to receive items from
/// underlying channel:
/// - `receive()`: blocking
/// - `receiveTimeout(timeout_ns)`: blocking until timeout or value received
/// - `tryReceive()`: non-blocking
///
/// NOTE: In order to ensure consistent channel state, you must acquire the `Receiver` in the
/// thread you will be `receive`ing.
///
///
/// **Don't do this:**
/// ```
/// fn incorrect_cross_thread_usage(receiver: *Receiver(usize)) void {
///     // this will cause potential inconsistent channel state:
///     defer receiver.deinit();
///     var val = receiver.receive() orelse return;
/// }
/// try std.Thread.spawn(.{}, incorrect_cross_thread_usage, &receiver);
/// ```
///
///
/// **Do this instead:**
/// ```
/// fn correct_cross_thread_usage(chan: ChannelX(usize)) void {
///     var receiver = chan.receiver();
///     defer receiver.deinit();
///     // now safe to send
///     var val = receiver.receive() orelse return;
/// }
/// try std.Thread.spawn(.{}, correct_cross_thread_usage, chan);
/// ```
///
pub fn Receiver(comptime T: type) type {
    return struct {
        private: Internal,

        const Internal = struct {
            thread_id: std.Thread.Id,
            released: bool,
            ch: ChannelX(T),
        };

        const Self = @This();

        /// Initializes Self while acquiring a receiver from the underlying channel.
        fn init(chan: ChannelX(T)) Self {
            chan.acquireReceiver();
            return Self{
                .private = .{
                    .thread_id = std.Thread.getCurrentId(),
                    .released = false,
                    .ch = chan,
                },
            };
        }

        /// Receives a value from the channel, blocking until a value is ready to be
        /// read if underlying channel is empty.
        pub fn receive(self: *Self) ?T {
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            std.debug.assert(!self.private.released);
            return self.private.ch.receive();
        }

        /// Tries to receive a value from the channel. It returns an `error.empty`
        /// if underlying channel has no values to read.
        pub fn tryReceive(self: *Self) error{ empty, disconnected }!T {
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            std.debug.assert(!self.private.released);
            return self.private.ch.tryReceive();
        }

        /// Receives a value from channel blocking until either `timeout_ns` has elpased at
        /// which point `error.timeout` is returned or if value is read from underlying channel.
        pub fn receiveTimeout(self: *Self, timeout_ns: u64) error{ timeout, disconnected }!T {
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            std.debug.assert(!self.private.released);
            return self.private.ch.receiveTimeout(timeout_ns);
        }

        /// Deinitializes Self while releasing receiver from underlying channel.
        pub fn deinit(self: *Self) void {
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            std.debug.assert(!self.private.released);
            self.private.released = true;
            self.private.ch.releaseReceiver();
        }
    };
}

const Packet = @import("../net/packet.zig").Packet;

fn benchPacketSender(
    chan: ChannelX(Packet),
    total_send: usize,
) void {
    var sender = chan.initSender() catch unreachable;
    defer sender.deinit();
    var i: usize = 0;

    while (i < total_send) : (i += 1) {
        var packet = Packet.default();
        sender.send(packet) catch unreachable;
    }
}

fn benchPacketReceiver(
    chan: ChannelX(Packet),
    _: usize,
) void {
    var receiver = chan.initReceiver() catch unreachable;
    defer receiver.deinit();

    while (receiver.receive()) |v| {
        _ = v;
    }
}

fn benchUsizeSender(
    chan: ChannelX(usize),
    total_send: usize,
) void {
    var sender = chan.initSender() catch unreachable;
    defer sender.deinit();

    var i: usize = 0;
    while (i < total_send) : (i += 1) {
        sender.send(i) catch unreachable;
    }
}

fn benchUsizeReceiver(
    chan: ChannelX(usize),
    _: usize,
) void {
    var receiver = chan.initReceiver() catch unreachable;
    defer receiver.deinit();

    while (receiver.receive()) |v| {
        _ = v;
    }
}

pub const BenchmarkChannel = struct {
    pub const min_iterations = 10;
    pub const max_iterations = 25;

    pub const BenchmarkArgs = struct {
        name: []const u8 = "",
        n_items: usize,
        n_senders: usize,
        n_receivers: usize,
    };

    pub const args = [_]BenchmarkArgs{
        .{
            .name = "  10k_items,   1_senders,   1_receivers ",
            .n_items = 10_000,
            .n_senders = 1,
            .n_receivers = 1,
        },
        .{
            .name = " 100k_items,   4_senders,   4_receivers ",
            .n_items = 100_000,
            .n_senders = 4,
            .n_receivers = 4,
        },
        .{
            .name = " 500k_items,   8_senders,   8_receivers ",
            .n_items = 500_000,
            .n_senders = 8,
            .n_receivers = 8,
        },
        .{
            .name = "   1m_items,  16_senders,  16_receivers ",
            .n_items = 1_000_000,
            .n_senders = 16,
            .n_receivers = 16,
        },
        .{
            .name = "   5m_items,   4_senders,   4_receivers ",
            .n_items = 5_000_000,
            .n_senders = 4,
            .n_receivers = 4,
        },
        .{
            .name = "   5m_items,  16_senders,  16_receivers ",
            .n_items = 5_000_000,
            .n_senders = 16,
            .n_receivers = 16,
        },
    };

    pub fn benchmarkBoundedUsizeChannel(argss: BenchmarkArgs) !usize {
        var thread_handles: [64]?std.Thread = [_]?std.Thread{null} ** 64;
        var n_items = argss.n_items;
        var senders_count = argss.n_senders;
        var receivers_count = argss.n_receivers;
        var timer = try std.time.Timer.start();

        var channel = try ChannelX(usize).init(.bounded, .{
            .allocator = page_allocator,
            .init_capacity = 4096,
        });
        defer channel.deinit();

        var sends_per_sender: usize = n_items / senders_count;
        var received_per_sender: usize = n_items / receivers_count;

        var thread_index: usize = 0;
        while (thread_index < senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, benchUsizeSender, .{ channel, sends_per_sender });
        }

        while (thread_index < receivers_count + senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, benchUsizeReceiver, .{ channel, received_per_sender });
        }

        for (0..thread_handles.len) |i| {
            if (thread_handles[i]) |handle| {
                handle.join();
            } else {
                break;
            }
        }

        const elapsed = timer.read();
        return elapsed;
    }

    pub fn benchmarkBoundedPacketChannel(argss: BenchmarkArgs) !usize {
        var thread_handles: [64]?std.Thread = [_]?std.Thread{null} ** 64;
        var n_items = argss.n_items;
        var senders_count = argss.n_senders;
        var receivers_count = argss.n_receivers;
        var timer = try std.time.Timer.start();

        var channel = try ChannelX(Packet).init(.bounded, .{
            .allocator = page_allocator,
            .init_capacity = 4096,
        });
        defer channel.deinit();

        var sends_per_sender: usize = n_items / senders_count;
        var received_per_sender: usize = n_items / receivers_count;

        var thread_index: usize = 0;
        while (thread_index < senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, benchPacketSender, .{ channel, sends_per_sender });
        }

        while (thread_index < receivers_count + senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, benchPacketReceiver, .{ channel, received_per_sender });
        }

        for (0..thread_handles.len) |i| {
            if (thread_handles[i]) |handle| {
                handle.join();
            } else {
                break;
            }
        }

        const elapsed = timer.read();
        return elapsed;
    }
};

fn testUsizeSender(
    chan: ChannelX(usize),
    total_send: usize,
) void {
    var sender = chan.initSender() catch unreachable;
    defer sender.deinit();

    var i: usize = 0;
    while (i < total_send) : (i += 1) {
        sender.send(i) catch unreachable;
    }
}

fn testUsizeReceiver(
    chan: ChannelX(usize),
    received_count: *Atomic(usize),
) void {
    var receiver = chan.initReceiver() catch unreachable;
    defer receiver.deinit();

    while (receiver.receive()) |v| {
        _ = v;
        _ = received_count.fetchAdd(1, .SeqCst);
    }
}

test "sync.chanx.bounded works" {
    var chan = try ChannelX(usize).initBounded(.{ .allocator = std.testing.allocator, .init_capacity = 100 });
    defer chan.deinit();

    // we deinit sender after sending (not defer'ing it) so it can trigger disconnect
    // and receiving while can break
    var sender = try chan.initSender();

    var receiver = try chan.initReceiver();
    defer receiver.deinit();

    try sender.send(1);
    try sender.send(2);
    try sender.send(3);
    sender.deinit();

    var i: usize = 1;
    while (receiver.receive()) |v| {
        try std.testing.expectEqual(v, i);
        i += 1;
    }
}

test "sync.chanx.bounded channel sends/received in different threads" {
    const items_to_send = 1000;
    var chan = try ChannelX(usize).initBounded(.{ .allocator = std.testing.allocator, .init_capacity = 100 });
    defer chan.deinit();

    var received_count = Atomic(usize).init(0);

    var sender_handle = try std.Thread.spawn(.{}, testUsizeSender, .{ chan, items_to_send });
    var receiver_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ chan, &received_count });

    sender_handle.join();
    receiver_handle.join();

    try std.testing.expect(received_count.load(.SeqCst) == items_to_send);
}

test "sync.chanx.bounded buffer len is correct" {
    var chan = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    try std.testing.expectEqual(chan.capacity(), 10);
}

test "sync.chanx.bounded mpmc" {
    var capacity: usize = 100;
    var n_items: usize = 1000;
    var chan = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = capacity,
    });
    defer chan.deinit();
    var received_count = Atomic(usize).init(0);

    var sender_1_handle = try std.Thread.spawn(.{}, testUsizeSender, .{ chan, n_items / 2 });
    var sender_2_handle = try std.Thread.spawn(.{}, testUsizeSender, .{ chan, n_items / 2 });
    var receiver_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ chan, &received_count });

    sender_1_handle.join();
    sender_2_handle.join();
    receiver_handle.join();

    try std.testing.expectEqual(n_items, received_count.load(.SeqCst));
}

test "sync.chanx.bounded: mpmc" {
    var capacity: usize = 100;
    var n_items: usize = 1000;
    var chan = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = capacity,
    });
    defer chan.deinit();
    var received_count = Atomic(usize).init(0);

    var sender_1_handle = try std.Thread.spawn(.{}, testUsizeSender, .{ chan, n_items / 2 });
    var sender_2_handle = try std.Thread.spawn(.{}, testUsizeSender, .{ chan, n_items / 2 });
    var receiver_1_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ chan, &received_count });
    var receiver_2_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ chan, &received_count });

    sender_1_handle.join();
    sender_2_handle.join();
    receiver_1_handle.join();
    receiver_2_handle.join();

    try std.testing.expectEqual(n_items, received_count.load(.SeqCst));
}

test "sync.chanx.bounded: spsc" {
    var capacity: usize = 100;
    var n_items: usize = 1000;
    var chan = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = capacity,
    });
    defer chan.deinit();
    var received_count = Atomic(usize).init(0);

    var sender_1_handle = try std.Thread.spawn(.{}, testUsizeSender, .{ chan, n_items });
    var receiver_1_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ chan, &received_count });
    var receiver_2_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ chan, &received_count });

    sender_1_handle.join();
    receiver_1_handle.join();
    receiver_2_handle.join();

    try std.testing.expectEqual(n_items, received_count.load(.SeqCst));
}

test "sync.chanx.bounded: spmc" {
    var capacity: usize = 100;
    var n_items: usize = 1000;
    var chan = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = capacity,
    });
    defer chan.deinit();
    var received_count = Atomic(usize).init(0);

    var sender_handle = try std.Thread.spawn(.{}, testUsizeSender, .{ chan, n_items });
    var receiver_1_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ chan, &received_count });
    var receiver_2_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ chan, &received_count });

    sender_handle.join();
    receiver_1_handle.join();
    receiver_2_handle.join();

    try std.testing.expectEqual(n_items, received_count.load(.SeqCst));
}

test "sync.chanx.bounded: disconnect after all senders released" {
    var chan = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    var sender = try chan.initSender();
    var receiver = try chan.initReceiver();
    defer receiver.deinit();

    try sender.send(1);
    try std.testing.expectEqual(receiver.receive(), 1);
    sender.deinit();
    try std.testing.expectEqual(receiver.receive(), null);
}

test "sync.chanx.bounded: disconnect after all receivers deinit" {
    var chan = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    var sender = try chan.initSender();
    defer sender.deinit();
    var receiver = try chan.initReceiver();

    try sender.send(1);
    try std.testing.expectEqual(receiver.receive(), 1);
    receiver.deinit();
    try std.testing.expectError(error.disconnected, sender.send(2));
}

test "sync.chanx.bounded: initSender or initReceiver fails after disconnect" {
    var chan = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    var sender_1 = try chan.initSender();
    defer sender_1.deinit();
    var receiver_1 = try chan.initReceiver();
    receiver_1.deinit();
    try std.testing.expectError(error.disconnected, chan.initSender());
    try std.testing.expectError(error.disconnected, chan.initReceiver());
}

test "sync.chanx.bounded: channel full/empty works correctly" {
    var chan = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 1,
    });
    defer chan.deinit();

    var sender = try chan.initSender();
    var receiver = try chan.initReceiver();

    try std.testing.expectError(error.empty, receiver.tryReceive());
    try sender.send(1);
    try std.testing.expectEqual(receiver.tryReceive(), 1);
    try sender.send(2);
    try std.testing.expectError(error.full, sender.trySend(3));
}

test "sync.chanx.bounded: send timeout works" {
    var chan = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 1,
    });
    defer chan.deinit();

    var timeout: u64 = std.time.ns_per_ms * 100;

    var sender = try chan.initSender();
    defer sender.deinit();

    try sender.send(1);
    var timer = try std.time.Timer.start();
    try std.testing.expectError(error.timeout, sender.sendTimeout(2, timeout));
    var time = timer.read();

    try std.testing.expect(time >= std.time.ns_per_ms * 99);
}

test "sync.chanx.bounded: trySend works properly" {
    var chan = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 3,
    });
    defer chan.deinit();

    var sender = try chan.initSender();
    var receiver = try chan.initReceiver();

    try sender.trySend(1);
    try sender.trySend(2);
    try sender.trySend(3);
    try std.testing.expectError(error.full, sender.trySend(4));
    receiver.deinit();
    try std.testing.expectError(error.disconnected, sender.trySend(4));
}

test "sync.chanx.bounded: receive order is correct" {
    var chan = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 3,
    });
    defer chan.deinit();

    var sender = try chan.initSender();
    var receiver = try chan.initReceiver();

    try sender.send(1);
    try sender.send(2);
    try sender.send(3);
    try std.testing.expectEqual(receiver.receive(), 1);
    try std.testing.expectEqual(receiver.receive(), 2);
    try std.testing.expectEqual(receiver.receive(), 3);
}

test "sync.chanx.bounded: receive while disconnected should still drain all elements" {
    var chan = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    var sender = try chan.initSender();
    var receiver = try chan.initReceiver();
    defer receiver.deinit();

    try sender.send(1);
    try sender.send(2);
    try sender.send(3);
    sender.deinit();
    try std.testing.expect(receiver.receive() == 1);
    try std.testing.expect(receiver.receive() == 2);
    try std.testing.expect(receiver.receive() == 3);
    try std.testing.expect(receiver.receive() == null);
}

test "sync.chanx.bounded: receive while empty with timeout" {
    var chan = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    var sender = try chan.initSender();
    defer sender.deinit();
    var receiver = try chan.initReceiver();
    defer receiver.deinit();
    var timeout: u64 = std.time.ns_per_ms * 100;

    var timer = try std.time.Timer.start();
    try std.testing.expectError(error.timeout, receiver.receiveTimeout(timeout));
    var time = timer.read();
    try std.testing.expect(time >= std.time.ns_per_ms * 99);
}
