const std = @import("std");
const Bounded = @import("bounded.zig").Bounded;
const Atomic = std.atomic.Atomic;
const page_allocator = std.heap.page_allocator;

/// ChannelX is an abstraction on top of different channels which provide different
/// performance/functionality. The idea is to allow for a generic API that each channel kind
/// implements allowing for ease of swapping to a different kin if needed.
pub fn ChannelX(comptime T: type) type {
    return union(enum(u8)) {
        bounded: *Bounded(T),

        const Self = @This();

        pub fn init(kind: enum { bounded }, config: anytype) error{OutOfMemory}!Self {
            return switch (kind) {
                .bounded => .{
                    .bounded = try Bounded(T).init(config),
                },
            };
        }

        pub fn deinit(self: Self) void {
            switch (self) {
                .bounded => |b| {
                    b.deinit();
                },
            }
        }

        pub fn sender(self: Self) Sender(T) {
            return Sender(T).init(self);
        }

        pub fn receiver(self: Self) Receiver(T) {
            return Receiver(T).init(self);
        }

        fn acquireSender(self: Self) void {
            switch (self) {
                .bounded => |c| c.acquireSender(),
            }
        }

        fn releaseSender(self: Self) void {
            switch (self) {
                .bounded => |c| c.releaseSender(),
            }
        }

        fn acquireReceiver(self: Self) void {
            switch (self) {
                .bounded => |c| c.acquireReceiver(),
            }
        }

        fn releaseReceiver(self: Self) void {
            switch (self) {
                .bounded => |c| c.releaseReceiver(),
            }
        }

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

        fn trySend(self: Self, val: T) error{ full, disconnected }!void {
            switch (self) {
                .bounded => |chan| {
                    return chan.trySend(val, null);
                },
            }
        }

        fn sendTimeout(self: Self, val: T, timeout_ns: u64) error{ timeout, disconnected }!void {
            switch (self) {
                .bounded => |chan| {
                    return chan.send(val, timeout_ns);
                },
            }
        }

        fn receive(self: Self) error{disconnected}!T {
            switch (self) {
                .bounded => |chan| {
                    if (chan.receive(null)) |val| {
                        return val;
                    } else |err| switch (err) {
                        error.disconnected => return error.disconnected,
                        error.timeout => unreachable,
                    }
                },
            }
        }

        fn tryReceive(self: Self) error{ emtpy, disconnected }!T {
            switch (self) {
                .bounded => |chan| {
                    return chan.tryReceive();
                },
            }
        }

        fn receiveTimeout(self: Self, timeout_ns: u64) error{ timeout, disconnected }!T {
            switch (self) {
                .bounded => |chan| {
                    return chan.receive(timeout_ns);
                },
            }
        }
    };
}

/// Sender is a **non**-thread-safe structure which can be used to send
/// values to the underlying channel.
///
/// In order to clone sender and use in another thread, you must first
/// `clone()` and then call `move()` in the other thread. This is so that
/// the underlying channel has consistent reference counts of `Sender`(s) and
/// doesn't prematurally deinit/disconnect channel.
///
/// Example to clone and then move cloned `Sender` to another thread
/// ```
///
/// var new_sender = existing_sender.clone();
/// _ = try std.Thread.spawn(.{}, newThread, .{new_sender});
///
/// fn newThread(sender: *Sender) void {
///     sender.move();
///     // now it's safe to send
///     sender.send(10333);
/// }
/// ```
pub fn Sender(comptime T: type) type {
    return struct {
        private: Internal,

        const Internal = struct {
            tid: std.Thread.Id,
            released: bool,
            ch: ChannelX(T),
        };

        const Self = @This();

        fn init(chan: ChannelX(T)) Self {
            chan.acquireSender();
            return Self{
                .private = .{
                    .tid = std.Thread.getCurrentId(),
                    .released = false,
                    .ch = chan,
                },
            };
        }

        pub fn send(self: *Self, val: T) error{disconnected}!void {
            std.debug.assert(std.Thread.getCurrentId() == self.private.tid);
            std.debug.assert(!self.private.released);
            return self.private.ch.send(val);
        }

        /// `trySend` allows you to non-blockingly send a value to the channel. It returns
        /// an `error.full` or `error.disconnected` if either of those cases are encountered.
        pub fn trySend(self: *Self, val: T) error{ full, disconnected }!void {
            std.debug.assert(std.Thread.getCurrentId() == self.private.tid);
            std.debug.assert(!self.private.released);
            return self.private.ch.trySend(val);
        }

        pub fn sendTimeout(self: *Self, val: T, timeout_ns: u64) error{ timeout, disconnected }!void {
            std.debug.assert(std.Thread.getCurrentId() == self.private.tid);
            std.debug.assert(!self.private.released);
            return self.private.ch.sendTimeout(val, timeout_ns);
        }

        pub fn deinit(self: *Self) void {
            std.debug.assert(std.Thread.getCurrentId() == self.private.tid);
            std.debug.assert(!self.private.released);
            self.private.released = true;
            self.private.ch.releaseSender();
        }
    };
}

pub fn Receiver(comptime T: type) type {
    return struct {
        private: Internal,

        const Internal = struct {
            tid: std.Thread.Id,
            released: bool,
            ch: ChannelX(T),
        };

        const Self = @This();

        fn init(chan: ChannelX(T)) Self {
            return Self{
                .private = .{
                    .tid = std.Thread.getCurrentId(),
                    .released = false,
                    .ch = chan,
                },
            };
        }

        pub fn receive(self: *Self) error{disconnected}!T {
            std.debug.assert(std.Thread.getCurrentId() == self.private.tid);
            std.debug.assert(!self.private.released);
            return self.private.ch.receive();
        }

        /// `tryreceive` allows you to non-blockingly receive a value to the channel. It returns
        /// an `error.empty` or `error.disconnected` if either of those cases are encountered.
        pub fn tryReceive(self: *Self) error{ empty, disconnected }!T {
            std.debug.assert(std.Thread.getCurrentId() == self.private.tid);
            std.debug.assert(!self.private.released);
            return self.private.ch.tryReceive();
        }

        pub fn receiveTimeout(self: *Self, timeout_ns: u64) error{ timeout, disconnected }!T {
            std.debug.assert(std.Thread.getCurrentId() == self.private.tid);
            std.debug.assert(!self.private.released);
            return self.private.ch.receiveTimeout(timeout_ns);
        }

        pub fn deinit(self: *Self) void {
            std.debug.assert(std.Thread.getCurrentId() == self.private.tid);
            std.debug.assert(!self.private.released);
            self.private.released = true;
            self.private.ch.releaseReceiver();
        }
    };
}

const Packet = @import("../net/packet.zig").Packet;

fn testPacketSender(
    chan: ChannelX(Packet),
    total_send: usize,
) void {
    var sender = chan.sender();
    defer sender.deinit();
    var i: usize = 0;

    while (i < total_send) : (i += 1) {
        var packet = Packet.default();
        sender.send(packet) catch unreachable;
    }
}

fn testPacketReceiver(
    chan: ChannelX(Packet),
    _: usize,
) void {
    var receiver = chan.receiver();
    defer receiver.deinit();

    while (true) {
        const v = receiver.receive() catch break;
        _ = v;
    }
}

fn testUsizeSender(
    chan: ChannelX(usize),
    total_send: usize,
) void {
    var sender = chan.sender();
    defer sender.deinit();

    var i: usize = 0;
    while (i < total_send) : (i += 1) {
        sender.send(i) catch unreachable;
    }
}

fn testUsizeReceiver(
    chan: ChannelX(usize),
    _: usize,
) void {
    var receiver = chan.receiver();
    defer receiver.deinit();

    while (true) {
        const v = receiver.receive() catch break;
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
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testUsizeSender, .{ channel, sends_per_sender });
        }

        while (thread_index < receivers_count + senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testUsizeReceiver, .{ channel, received_per_sender });
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
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testPacketSender, .{ channel, sends_per_sender });
        }

        while (thread_index < receivers_count + senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testPacketReceiver, .{ channel, received_per_sender });
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
