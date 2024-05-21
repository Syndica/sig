const std = @import("std");
const builtin = @import("builtin");
const Bounded = @import("bounded.zig").Bounded;
const Atomic = std.atomic.Value;
const page_allocator = std.heap.page_allocator;

/// `ChannelX` is an enum that unifies channel API across different kinds of backing
/// channels such as `bounded`, `unbounded`, etc.
pub fn ChannelX(comptime T: type) type {
    return union(enum(u8)) {
        none,
        bounded: *Bounded(T),

        const Self = @This();

        /// Initializes a `bounded` channel.
        pub fn initBounded(config: Bounded(T).Config) error{OutOfMemory}!struct { Self, Sender(T), Receiver(T) } {
            const self = try Self.init(.bounded, config);
            return .{ self, self.initSender(), self.initReceiver() };
        }

        /// Initializes a channel based on `kind` and `config`
        pub fn init(kind: enum { bounded, none }, config: anytype) error{OutOfMemory}!Self {
            return switch (kind) {
                .bounded => .{
                    .bounded = try Bounded(T).init(config),
                },
                .none => return .none,
            };
        }

        /// Deinitializes self and underlying channel.
        pub fn deinit(self: Self) void {
            switch (self) {
                .bounded => |b| {
                    b.deinit();
                },
                .none => {},
            }
        }

        fn allocator(self: Self) std.mem.Allocator {
            return switch (self) {
                .bounded => |ch| ch.allocator,
                .none => unreachable,
            };
        }

        /// Initializes a new `Sender` to allow for sending values to the underlying channel. It's
        /// the caller's responsibility to `deinit()` returned sender.
        pub fn initSender(self: Self) Sender(T) {
            return Sender(T).init(self);
        }

        /// Initializes a new `Receiver` to allow for receiving values from the underlying channel.
        /// It's the caller's responsibility to `deinit()` returned receiver.
        pub fn initReceiver(self: Self) Receiver(T) {
            return Receiver(T).init(self);
        }

        /// Acquires a sender from the underlying channel
        fn acquireSender(self: Self) void {
            switch (self) {
                .bounded => |c| c.acquireSender(),
                .none => {},
            }
        }

        /// Releases a sender from the underlying channel
        fn releaseSender(self: Self) void {
            switch (self) {
                .bounded => |c| std.debug.assert(c.releaseSender()),
                .none => {},
            }
        }

        /// Acquires a receiver from the underlying channel
        fn acquireReceiver(self: Self) void {
            switch (self) {
                .bounded => |c| c.acquireReceiver(),
                .none => {},
            }
        }

        /// Releases a receiver from the underlying channel
        fn releaseReceiver(self: Self) void {
            switch (self) {
                .bounded => |c| std.debug.assert(c.releaseReceiver()),
                .none => {},
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
                .none => return error.disconnected,
            }
        }

        /// Tries to send a value immediately or returns `error.full` if underlying
        /// channel is full.
        fn trySend(self: Self, val: T) error{ full, disconnected }!void {
            switch (self) {
                .bounded => |chan| {
                    return chan.trySend(val);
                },
                .none => return error.disconnected,
            }
        }

        /// Sends a value to underlying channel blocking until `timeout_ns` has elpased or until
        /// channel successfully sends value.
        fn sendTimeout(self: Self, val: T, timeout_ns: u64) error{ timeout, disconnected }!void {
            switch (self) {
                .bounded => |chan| {
                    return chan.send(val, timeout_ns);
                },
                .none => return error.disconnected,
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
                .none => return null,
            }
        }

        /// Tries to receive a value from the underlying channel immediately or returns
        /// `error.empty` if no value is available to be read.
        fn tryReceive(self: Self) error{ empty, disconnected }!T {
            switch (self) {
                .bounded => |chan| {
                    return chan.tryReceive();
                },
                .none => return error.disconnected,
            }
        }

        /// Receives a value from underlying channel, blocking until `timeout_ns` has elapsed
        /// or until value is ready to be read.
        fn receiveTimeout(self: Self, timeout_ns: u64) error{ timeout, disconnected }!T {
            switch (self) {
                .bounded => |chan| {
                    return chan.receive(timeout_ns);
                },
                .none => return error.disconnected,
            }
        }

        /// Returns the underlying channel's capacity
        pub fn capacity(self: Self) usize {
            return switch (self) {
                .bounded => |chan| chan.capacity(),
                .none => return 0,
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
/// NOTE: In order to ensure consistent channel state, you should exercise caution when using
/// across threads. See examples below:
///
/// **Don't do this:**
/// ```
/// fn incorrect_cross_thread_usage(sender: *Sender(usize)) void {
///     // this will cause potential inconsistent channel state and will lead to a panic:
///     defer sender.deinit();
///     try sender.send(1);
/// }
/// try std.Thread.spawn(.{}, incorrect_cross_thread_usage, &sender);
/// ```
/// ---
/// **Do this instead:**
/// ```
/// fn correct_cross_thread_usage(chan: ChannelX(usize)) void {
///     var sender = chan.initSender();
///     defer sender.deinit();
///     // now safe to send
///     try sender.send(1);
/// }
/// try std.Thread.spawn(.{}, correct_cross_thread_usage, chan);
/// ```
/// ---
/// **Or if you only have a `Sender`, you can always `move` a Sender to another thread like so:**
/// ```
/// fn correct_cross_thread_usage(sndr: Sender(usize)) void {
///     var sender = sndr.move();
///     defer sender.deinit();
///     // now safe to send
///     try sender.send(1);
/// }
/// try std.Thread.spawn(.{}, correct_cross_thread_usage, original_sender.clone());
/// original_sender.deinit();
/// ```
///
/// NOTE: channel state is dependent on how you manage `Sender`(s) so use caution when using. General
/// set of rules to follow:
/// 1. Use `Sender` where you `init`ed it when possible.
/// 2. If need to use across threads, use `move()` and/or `clone()`.
/// 3. If you `clone()`, don't forget to `deinit()` original `Sender` in original thread.
/// 4. If you `move()`, don't prematurely `deinit()` a `Sender` in original thread.
///
pub fn Sender(comptime T: type) type {
    return struct {
        private: *Internal,

        const Internal = struct {
            thread_id: std.Thread.Id,
            ch: ChannelX(T),
            mux: std.Thread.Mutex,

            fn init(chan: ChannelX(T)) *Internal {
                const internal = chan.allocator().create(Internal) catch unreachable;
                internal.* = .{
                    .thread_id = std.Thread.getCurrentId(),
                    .ch = chan,
                    .mux = std.Thread.Mutex{},
                };
                return internal;
            }

            fn deinit(self: *Internal) void {
                self.ch.allocator().destroy(self);
            }
        };

        const Self = @This();

        /// Initializes a new `Sender` by acquiring a sender from the underlying channel
        fn init(chan: ChannelX(T)) Self {
            chan.acquireSender();
            return Self{ .private = Internal.init(chan) };
        }

        /// Sends a value to underlying channel, blocking if the channel is full.
        pub fn send(self: *Self, val: T) error{disconnected}!void {
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            return self.private.ch.send(val);
        }

        /// Tries to send a value to underlying channel (non-blockingly). It returns an `error.full`
        /// if the channel is currently full.
        pub fn trySend(self: *Self, val: T) error{ full, disconnected }!void {
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            return self.private.ch.trySend(val);
        }

        /// Sends a value to the underlying channel blocking if the channel is full up to `timeout_ns`
        /// has elapsed at which point returns `error.timeout`.
        pub fn sendTimeout(self: *Self, val: T, timeout_ns: u64) error{ timeout, disconnected }!void {
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            return self.private.ch.sendTimeout(val, timeout_ns);
        }

        /// Deinitializes self and releases the sender from the underlying channel.
        pub fn deinit(self: *Self) void {
            self.private.mux.lock();
            // we purposefully don't unlock since it's being deinit'ed

            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            self.private.ch.releaseSender();
            self.private.deinit();
        }

        /// Moves the `Sender` to the caller's thread
        pub fn move(self: *const Self) Self {
            const me: *Self = @constCast(self);
            me.private.mux.lock();
            defer me.private.mux.unlock();

            std.debug.assert(std.Thread.getCurrentId() != me.private.thread_id);
            me.private.thread_id = std.Thread.getCurrentId();
            return me.*;
        }

        /// Takes the `Sender` (must be in same thread), this locks so should not be called often.
        ///
        /// An example of when you'd use this:
        /// ```
        /// fn sendValues(values: []usize, sndr: Sender(usize)) void {
        ///     // argument sndr is going to be *const Sender so we take() it
        ///     var sender = sndr.take();
        ///     for (values) |val| {
        ///         sender.send(val);
        ///     }
        /// }
        ///
        /// ```
        pub fn take(self: *const Self) Self {
            const me: *Self = @constCast(self);
            me.private.mux.lock();
            defer me.private.mux.unlock();
            std.debug.assert(std.Thread.getCurrentId() == me.private.thread_id);
            return me.*;
        }

        /// Clones `Sender`, must be called in thread it was initialized in.
        pub fn clone(self: *Self) Self {
            self.private.mux.lock();
            defer self.private.mux.unlock();
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            return Self.init(self.private.ch);
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
///     // this will cause potential inconsistent channel state and will lead to panic:
///     defer receiver.deinit();
///     var val = receiver.receive() orelse return;
/// }
///
/// try std.Thread.spawn(.{}, incorrect_cross_thread_usage, &receiver);
/// ```
/// ---
/// **Do this instead:**
/// ```
/// fn correct_cross_thread_usage(chan: ChannelX(usize)) void {
///     var receiver = chan.receiver();
///     defer receiver.deinit();
///     // now safe to send
///     var val = receiver.receive() orelse return;
/// }
///
/// try std.Thread.spawn(.{}, correct_cross_thread_usage, chan);
/// ```
/// ---
/// **Or if you only have a `Receiver`, you can always `move` a `Receiver` to another thread like so:**
/// ```
/// fn correct_cross_thread_usage(recv: Receiver(usize)) void {
///     var receiver = recv.move();
///     defer receiver.deinit();
///     // now safe to receive
///     const val = try receiver.receive();
/// }
///
/// try std.Thread.spawn(.{}, correct_cross_thread_usage, receiver.clone());
/// receiver.deinit();
/// ```
///
/// NOTE: channel state is dependent on how you manage `Receiver`(s) so use caution when using. General
/// set of rules to follow:
/// 1. Use `Receiver` where you `init`ed it when possible.
/// 2. If need to use across threads, use `move()` and/or `clone()`.
/// 3. If you `clone()`, don't forget to `deinit()` original `Receiver` in original thread.
/// 4. If you `move()`, don't prematurely `deinit()` a `Receiver` in original thread.
///
pub fn Receiver(comptime T: type) type {
    return struct {
        private: *Internal,

        const Internal = struct {
            thread_id: std.Thread.Id,
            ch: ChannelX(T),
            mux: std.Thread.Mutex,

            fn init(chan: ChannelX(T)) *Internal {
                const internal = chan.allocator().create(Internal) catch unreachable;
                internal.* = .{
                    .thread_id = std.Thread.getCurrentId(),
                    .ch = chan,
                    .mux = std.Thread.Mutex{},
                };
                return internal;
            }

            fn deinit(self: *Internal) void {
                self.ch.allocator().destroy(self);
            }
        };

        const Self = @This();

        /// Initializes Self while acquiring a receiver from the underlying channel.
        fn init(chan: ChannelX(T)) Self {
            chan.acquireReceiver();
            return Self{ .private = Internal.init(chan) };
        }

        /// Receives a value from the channel, blocking until a value is ready to be
        /// read if underlying channel is empty.
        pub fn receive(self: *Self) ?T {
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            return self.private.ch.receive();
        }

        /// Tries to receive a value from the channel. It returns an `error.empty`
        /// if underlying channel has no values to read.
        pub fn tryReceive(self: *Self) error{ empty, disconnected }!T {
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            return self.private.ch.tryReceive();
        }

        /// Receives a value from channel blocking until either `timeout_ns` has elpased at
        /// which point `error.timeout` is returned or if value is read from underlying channel.
        pub fn receiveTimeout(self: *Self, timeout_ns: u64) error{ timeout, disconnected }!T {
            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            return self.private.ch.receiveTimeout(timeout_ns);
        }

        /// Deinitializes `Receiver` while releasing a receiver from underlying channel.
        pub fn deinit(self: *Self) void {
            self.private.mux.lock();

            std.debug.assert(std.Thread.getCurrentId() == self.private.thread_id);
            self.private.ch.releaseReceiver();
            self.private.deinit();
        }

        /// Moves the `Receiver` to the caller's thread
        pub fn move(self: *const Self) Self {
            const me: *Self = @constCast(self);
            me.private.mux.lock();
            defer me.private.mux.unlock();

            std.debug.assert(std.Thread.getCurrentId() != me.private.thread_id);
            me.private.thread_id = std.Thread.getCurrentId();
            return me.*;
        }

        /// Takes the `Receiver` (must be in same thread), this locks so should not be called often.
        ///
        /// An example of when you'd use this:
        /// ```
        /// fn receiveValues(rcvr: Receiver(usize)) void {
        ///     // argument rcvr is going to be *const Receiver(usize) so we take() it
        ///     var receiver = rcvr.take();
        ///     for (receiver.receive()) |val| {
        ///         _ = val
        ///     }
        /// }
        ///
        /// ```
        pub fn take(self: *const Self) Self {
            const me: *Self = @constCast(self);
            me.private.mux.lock();
            defer me.private.mux.unlock();
            std.debug.assert(std.Thread.getCurrentId() == me.private.thread_id);
            return me.*;
        }

        /// Clones `Sender`
        pub fn clone(self: *const Self) Self {
            var me: *Self = @constCast(self);
            me.private.mux.lock();
            defer me.private.mux.unlock();

            std.debug.assert(std.Thread.getCurrentId() == me.private.thread_id);
            return Self.init(self.private.ch);
        }
    };
}

const Packet = @import("../net/packet.zig").Packet;

fn benchPacketSender(
    chan: ChannelX(Packet),
    total_send: usize,
) void {
    var sender = chan.initSender();
    defer sender.deinit();
    var i: usize = 0;

    while (i < total_send) : (i += 1) {
        const packet = Packet.default();
        sender.send(packet) catch unreachable;
    }
}

fn benchPacketReceiver(
    chan: ChannelX(Packet),
    _: usize,
) void {
    var receiver = chan.initReceiver();
    defer receiver.deinit();

    while (receiver.receive()) |v| {
        _ = v;
    }
}

fn benchUsizeSender(
    chan: ChannelX(usize),
    total_send: usize,
) void {
    var sender = chan.initSender();
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
    var receiver = chan.initReceiver();
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
        const n_items = argss.n_items;
        const senders_count = argss.n_senders;
        const receivers_count = argss.n_receivers;
        var timer = try std.time.Timer.start();

        var channel = try ChannelX(usize).init(.bounded, .{
            .allocator = page_allocator,
            .init_capacity = 4096,
        });
        defer channel.deinit();

        const sends_per_sender: usize = n_items / senders_count;
        const received_per_sender: usize = n_items / receivers_count;

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
        const n_items = argss.n_items;
        const senders_count = argss.n_senders;
        const receivers_count = argss.n_receivers;
        var timer = try std.time.Timer.start();

        var channel = try ChannelX(Packet).init(.bounded, .{
            .allocator = page_allocator,
            .init_capacity = 4096,
        });
        defer channel.deinit();

        const sends_per_sender: usize = n_items / senders_count;
        const received_per_sender: usize = n_items / receivers_count;

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
    sndr: Sender(usize),
    total_send: usize,
) void {
    var sender = sndr.move();
    defer sender.deinit();

    var i: usize = 0;
    while (i < total_send) : (i += 1) {
        sender.send(i) catch unreachable;
    }
}

fn testUsizeReceiver(
    recv: Receiver(usize),
    received_count: *Atomic(usize),
) void {
    var receiver = recv.move();
    defer receiver.deinit();

    while (receiver.receive()) |v| {
        _ = v;
        _ = received_count.fetchAdd(1, .seq_cst);
    }
}

test "sync.chanx: bounded works" {
    var chan, var sender, var receiver = try ChannelX(usize).initBounded(.{ .allocator = std.testing.allocator, .init_capacity = 100 });
    defer chan.deinit();
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

test "sync.chanx: bounded channel sends/received in different threads" {
    const items_to_send = 1000;
    var chan, const sender, const receiver = try ChannelX(usize).initBounded(.{ .allocator = std.testing.allocator, .init_capacity = 100 });
    defer chan.deinit();

    var received_count = Atomic(usize).init(0);

    var sender_handle = try std.Thread.spawn(.{}, testUsizeSender, .{ sender, items_to_send });
    var receiver_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ receiver, &received_count });

    sender_handle.join();
    receiver_handle.join();

    try std.testing.expect(received_count.load(.seq_cst) == items_to_send);
}

test "sync.chanx: bounded buffer len is correct" {
    const chan, var sender, var receiver = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();
    defer sender.deinit();
    defer receiver.deinit();

    try std.testing.expectEqual(chan.capacity(), 10);
}

test "sync.chanx: bounded mpsc" {
    const capacity: usize = 100;
    const n_items: usize = 1000;
    var chan, var sender, const receiver = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = capacity,
    });
    defer chan.deinit();
    var received_count = Atomic(usize).init(0);

    var sender_1_handle = try std.Thread.spawn(.{}, testUsizeSender, .{ sender.clone(), n_items / 2 });
    var sender_2_handle = try std.Thread.spawn(.{}, testUsizeSender, .{ sender, n_items / 2 });
    var receiver_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ receiver, &received_count });

    sender_1_handle.join();
    sender_2_handle.join();
    receiver_handle.join();

    try std.testing.expectEqual(n_items, received_count.load(.seq_cst));
}

test "sync.chanx: bounded mpmc" {
    const capacity: usize = 100;
    const n_items: usize = 1000;
    var chan, var sender, var receiver = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = capacity,
    });
    defer chan.deinit();

    var received_count = Atomic(usize).init(0);

    var sender_1_handle = try std.Thread.spawn(.{}, testUsizeSender, .{ sender.clone(), n_items / 2 });
    var sender_2_handle = try std.Thread.spawn(.{}, testUsizeSender, .{ sender, n_items / 2 });
    var receiver_1_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ receiver.clone(), &received_count });
    var receiver_2_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ receiver, &received_count });

    sender_1_handle.join();
    sender_2_handle.join();
    receiver_1_handle.join();
    receiver_2_handle.join();

    try std.testing.expectEqual(n_items, received_count.load(.seq_cst));
}

test "sync.chanx: bounded spmc" {
    const capacity: usize = 100;
    const n_items: usize = 1000;
    var chan, const sender, var receiver = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = capacity,
    });
    defer chan.deinit();

    var received_count = Atomic(usize).init(0);

    var sender_1_handle = try std.Thread.spawn(.{}, testUsizeSender, .{ sender, n_items });
    var receiver_1_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ receiver.clone(), &received_count });
    var receiver_2_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ receiver, &received_count });

    sender_1_handle.join();
    receiver_1_handle.join();
    receiver_2_handle.join();

    try std.testing.expectEqual(n_items, received_count.load(.seq_cst));
}

test "sync.chanx: bounded spsc" {
    const capacity: usize = 100;
    const n_items: usize = 1000;
    var chan, const sender, const receiver = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = capacity,
    });
    defer chan.deinit();

    var received_count = Atomic(usize).init(0);

    var sender_handle = try std.Thread.spawn(.{}, testUsizeSender, .{ sender, n_items });
    var receiver_handle = try std.Thread.spawn(.{}, testUsizeReceiver, .{ receiver, &received_count });

    sender_handle.join();
    receiver_handle.join();

    try std.testing.expectEqual(n_items, received_count.load(.seq_cst));
}

test "sync.chanx: bounded disconnect after all senders released" {
    var chan, var sender, var receiver = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();
    defer receiver.deinit();

    try sender.send(1);
    try std.testing.expectEqual(receiver.receive(), 1);
    sender.deinit();
    try std.testing.expectEqual(receiver.receive(), null);
}

test "sync.chanx: bounded disconnect after all receivers deinit" {
    var chan, var sender, var receiver = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    defer sender.deinit();

    try sender.send(1);
    try std.testing.expectEqual(receiver.receive(), 1);
    receiver.deinit();
    try std.testing.expectError(error.disconnected, sender.send(2));
}

test "sync.chanx: bounded channel full/empty works correctly" {
    var chan, var sender, var receiver = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 1,
    });
    defer chan.deinit();
    defer sender.deinit();
    defer receiver.deinit();

    try std.testing.expectError(error.empty, receiver.tryReceive());
    try sender.send(1);
    try std.testing.expectEqual(receiver.tryReceive(), 1);
    try sender.send(2);
    try std.testing.expectError(error.full, sender.trySend(3));
}

test "sync.chanx: bounded send timeout works" {
    const chan, var sender, var receiver = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 1,
    });
    defer chan.deinit();
    defer sender.deinit();
    defer receiver.deinit();

    const timeout: u64 = std.time.ns_per_ms * 100;

    try sender.send(1);
    var timer = try std.time.Timer.start();
    try std.testing.expectError(error.timeout, sender.sendTimeout(2, timeout));
    const time = timer.read();

    try std.testing.expect(time >= std.time.ns_per_ms * 80);
}

test "sync.chanx: bounded trySend works properly" {
    var chan, var sender, var receiver = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 3,
    });
    defer chan.deinit();
    defer sender.deinit();

    try sender.trySend(1);
    try sender.trySend(2);
    try sender.trySend(3);
    try std.testing.expectError(error.full, sender.trySend(4));
    receiver.deinit();
    try std.testing.expectError(error.disconnected, sender.trySend(4));
}

test "sync.chanx: bounded receive order is correct" {
    var chan, var sender, var receiver = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 3,
    });
    defer chan.deinit();
    defer sender.deinit();
    defer receiver.deinit();

    try sender.send(1);
    try sender.send(2);
    try sender.send(3);
    try std.testing.expectEqual(receiver.receive(), 1);
    try std.testing.expectEqual(receiver.receive(), 2);
    try std.testing.expectEqual(receiver.receive(), 3);
}

test "sync.chanx: bounded receive while disconnected should still drain all elements" {
    var chan, var sender, var receiver = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

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

test "sync.chanx: bounded receive while empty with timeout" {
    var chan, var sender, var receiver = try ChannelX(usize).initBounded(.{
        .allocator = std.testing.allocator,
        .init_capacity = 10,
    });
    defer chan.deinit();

    defer sender.deinit();
    defer receiver.deinit();
    const timeout: u64 = std.time.ns_per_ms * 100;

    var timer = try std.time.Timer.start();
    try std.testing.expectError(error.timeout, receiver.receiveTimeout(timeout));
    const time = timer.read();
    try std.testing.expect(time >= std.time.ns_per_ms * 80);
}
