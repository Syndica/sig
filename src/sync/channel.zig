const std = @import("std");
const Atomic = std.atomic.Atomic;
const Mutex = std.Thread.Mutex;
const Condition = std.Thread.Condition;
const testing = std.testing;
const assert = std.debug.assert;
const Mux = @import("mux.zig").Mux;
const Ordering = std.atomic.Ordering;

/// A very basic mpmc channel implementation - TODO: replace with a legit channel impl
pub fn Channel(comptime T: type) type {
    return struct {
        buffer: Mux(std.ArrayList(T)),
        has_value: Condition = .{},
        closed: Atomic(bool) = Atomic(bool).init(false),
        allocator: std.mem.Allocator,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, init_capacity: usize) *Self {
            const self = allocator.create(Self) catch unreachable;
            self.* = .{
                .buffer = Mux(std.ArrayList(T)).init(std.ArrayList(T).initCapacity(allocator, init_capacity) catch unreachable),
                .allocator = allocator,
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            var buff_lock = self.buffer.lock();
            var buff: *std.ArrayList(T) = buff_lock.mut();
            buff.deinit();
            buff_lock.unlock();

            self.allocator.destroy(self);
        }

        pub fn send(self: *Self, value: T) error{ OutOfMemory, ChannelClosed }!void {
            if (self.closed.load(.Monotonic)) {
                return error.ChannelClosed;
            }
            var buffer_lock = self.buffer.lock();
            defer buffer_lock.unlock();

            var buffer: *std.ArrayList(T) = buffer_lock.mut();
            try buffer.append(value);

            self.has_value.signal();
        }

        pub fn sendBatch(self: *Self, value: std.ArrayList(T)) error{ OutOfMemory, ChannelClosed }!void {
            if (self.closed.load(.Monotonic)) {
                return error.ChannelClosed;
            }
            var buffer_lock = self.buffer.lock();
            defer buffer_lock.unlock();

            var buffer: *std.ArrayList(T) = buffer_lock.mut();
            try buffer.appendSlice(value.items);

            self.has_value.signal();
        }

        pub fn receive(self: *Self) ?T {
            var buffer = self.buffer.lock();
            defer buffer.unlock();

            while (buffer.get().items.len == 0 and !self.closed.load(.seq_cst)) {
                buffer.condition(&self.has_value);
            }

            // channel closed so return null to signal no more items
            if (buffer.get().items.len == 0) {
                return null;
            }

            return buffer.mut().pop();
        }

        /// `drain` func will remove all pending items from queue.
        ///
        /// NOTE: Caller is responsible for calling `allocator.free` on the returned slice.
        pub fn drain(self: *Self) ?[]T {
            var buffer = self.buffer.lock();
            defer buffer.unlock();

            while (buffer.get().items.len == 0 and !self.closed.load(.seq_cst)) {
                buffer.condition(&self.has_value);
            }

            // channel closed so return null to signal no more items
            if (buffer.get().items.len == 0) {
                return null;
            }

            const num_items_to_drain = buffer.get().items.len;

            const out = self.allocator.alloc(T, num_items_to_drain) catch @panic("could not alloc");
            @memcpy(out, buffer.get().items);

            buffer.mut().shrinkRetainingCapacity(0);
            assert(buffer.get().items.len == 0);
            assert(num_items_to_drain == out.len);

            return out;
        }

        pub fn try_drain(self: *Self) error{ ChannelClosed, OutOfMemory }!?[]T {
            var buffer = self.buffer.lock();
            defer buffer.unlock();

            if (self.closed.load(.seq_cst)) {
                return error.ChannelClosed;
            }

            const num_items_to_drain = buffer.get().items.len;
            if (num_items_to_drain == 0) {
                return null;
            }

            const out = try self.allocator.alloc(T, num_items_to_drain);
            @memcpy(out, buffer.get().items);
            buffer.mut().clearRetainingCapacity();

            return out;
        }

        pub fn close(self: *Self) void {
            self.closed.store(true, .seq_cst);
            self.has_value.broadcast();
        }

        pub fn isClosed(self: *Self) bool {
            return self.closed.load(.seq_cst);
        }
    };
}

const Packet = @import("../net/packet.zig").Packet;

fn testPacketSender(chan: *Channel(Packet), total_send: usize) void {
    var i: usize = 0;
    while (i < total_send) : (i += 1) {
        const packet = Packet.default();
        chan.send(packet) catch unreachable;
    }
}

fn testPacketReceiver(chan: *Channel(Packet), total_recv: usize) void {
    var count: usize = 0;
    while (count < total_recv) : (count += 1) {
        const v = chan.receive() orelse unreachable;
        _ = v;
    }
}

fn testUsizeReceiver(chan: *Channel(usize), recv_count: usize) void {
    var count: usize = 0;
    while (count < recv_count) : (count += 1) {
        if (chan.try_drain()) |v| {
            _ = v;
        } else |_| {
            // break;
            @panic("channel closed while trying to receive!");
        }
    }
}

fn testUsizeSender(chan: *Channel(usize), send_count: usize) void {
    var i: usize = 0;
    while (i < send_count) : (i += 1) {
        chan.send(i) catch |err| {
            std.debug.print("could not send on chan: {any}", .{err});
            @panic("could not send on channel!");
        };
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

    pub fn benchmarkSimpleUsizeChannel(argss: BenchmarkArgs) !usize {
        var thread_handles: [64]?std.Thread = [_]?std.Thread{null} ** 64;
        const n_items = argss.n_items;
        const senders_count = argss.n_senders;
        const receivers_count = argss.n_receivers;
        var timer = try std.time.Timer.start();

        const allocator = std.heap.page_allocator;
        var channel = Channel(usize).init(allocator, n_items / 2);
        defer channel.deinit();

        const sends_per_sender: usize = n_items / senders_count;
        const receives_per_receiver: usize = n_items / receivers_count;

        var thread_index: usize = 0;
        while (thread_index < senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testUsizeSender, .{ channel, sends_per_sender });
        }

        while (thread_index < receivers_count + senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testUsizeReceiver, .{ channel, receives_per_receiver });
        }

        for (0..thread_handles.len) |i| {
            if (thread_handles[i]) |handle| {
                handle.join();
            } else {
                break;
            }
        }

        channel.close();
        const elapsed = timer.read();
        return elapsed;
    }

    pub fn benchmarkSimplePacketChannel(argss: BenchmarkArgs) !usize {
        var thread_handles: [64]?std.Thread = [_]?std.Thread{null} ** 64;
        const n_items = argss.n_items;
        const senders_count = argss.n_senders;
        const receivers_count = argss.n_receivers;
        var timer = try std.time.Timer.start();

        const allocator = std.heap.page_allocator;
        var channel = Channel(Packet).init(allocator, n_items / 2);
        defer channel.deinit();

        const sends_per_sender: usize = n_items / senders_count;
        const receives_per_receiver: usize = n_items / receivers_count;

        var thread_index: usize = 0;
        while (thread_index < senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testPacketSender, .{ channel, sends_per_sender });
        }

        while (thread_index < receivers_count + senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testPacketReceiver, .{ channel, receives_per_receiver });
        }

        for (0..thread_handles.len) |i| {
            if (thread_handles[i]) |handle| {
                handle.join();
            } else {
                break;
            }
        }

        channel.close();
        const elapsed = timer.read();
        return elapsed;
    }
};
