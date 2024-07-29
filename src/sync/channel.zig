const std = @import("std");
const Atomic = std.atomic.Value;
const Condition = std.Thread.Condition;
const testing = std.testing;
const assert = std.debug.assert;
const Mux = @import("mux.zig").Mux;

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
            if (self.closed.load(.monotonic)) {
                return error.ChannelClosed;
            }
            var buffer_lock = self.buffer.lock();
            defer buffer_lock.unlock();

            var buffer: *std.ArrayList(T) = buffer_lock.mut();
            try buffer.append(value);

            self.has_value.signal();
        }

        pub fn sendBatch(self: *Self, value: std.ArrayList(T)) error{ OutOfMemory, ChannelClosed }!void {
            if (self.closed.load(.monotonic)) {
                return error.ChannelClosed;
            }
            var buffer_lock = self.buffer.lock();
            defer buffer_lock.unlock();

            var buffer: *std.ArrayList(T) = buffer_lock.mut();
            try buffer.appendSlice(value.items);

            self.has_value.signal();
        }

        pub fn len(self: *Self) error{ChannelClosed}!u64 {
            if (self.closed.load(.monotonic)) {
                return error.ChannelClosed;
            }
            var buffer = self.buffer.lock();
            defer buffer.unlock();

            return buffer.get().items.len;
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

            const values: *const std.ArrayList(T) = buffer.get();
            const num_items_to_drain = values.items.len;
            if (num_items_to_drain == 0) {
                return null;
            }

            const out = try self.allocator.alloc(T, num_items_to_drain);
            @memcpy(out, values.items);
            buffer.mut().clearRetainingCapacity();

            return out;
        }

        pub fn tryDrainRecycle(
            self: *Self,
            buf: *std.ArrayList(T),
        ) error{ ChannelClosed, OutOfMemory }!void {
            var buffer = self.buffer.lock();
            defer buffer.unlock();
            buf.clearRetainingCapacity();

            if (self.closed.load(.seq_cst)) {
                return error.ChannelClosed;
            }

            const num_items_to_drain = buffer.get().items.len;
            if (num_items_to_drain == 0) {
                return;
            }

            try buf.appendSlice(buffer.get().items);
            buffer.mut().clearRetainingCapacity();
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

const Block = struct {
    num: u32 = 333,
    valid: bool = true,
    data: [1024]u8 = undefined,
};

const BlockChannel = Channel(Block);
const BlockPointerChannel = Channel(*Block);

const logger = std.log.scoped(.sync_channel_tests);

fn testReceiver(chan: *BlockChannel, recv_count: *Atomic(usize), id: u8) void {
    _ = id;
    while (chan.receive()) |v| {
        _ = v;
        _ = recv_count.fetchAdd(1, .seq_cst);
    }
}

fn testSender(chan: *BlockChannel, total_send: usize) void {
    var i: usize = 0;
    while (i < total_send) : (i += 1) {
        chan.send(Block{ .num = @intCast(i) }) catch unreachable;
    }
    chan.close();
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
        const v = chan.receive();
        _ = v;
    }
}

test "sync.channel: channel works properly" {
    var ch = BlockChannel.init(testing.allocator, 100);
    defer ch.deinit();

    var recv_count: Atomic(usize) = Atomic(usize).init(0);
    const send_count: usize = 1_000_000;

    var join1 = try std.Thread.spawn(.{}, testSender, .{ ch, send_count });
    var join2 = try std.Thread.spawn(.{}, testReceiver, .{ ch, &recv_count, 1 });
    var join3 = try std.Thread.spawn(.{}, testReceiver, .{ ch, &recv_count, 1 });
    var join4 = try std.Thread.spawn(.{}, testReceiver, .{ ch, &recv_count, 1 });

    join1.join();
    join2.join();
    join3.join();
    join4.join();

    try testing.expectEqual(send_count, recv_count.load(.seq_cst));
}

pub const BenchmarkChannel = struct {
    pub const min_iterations = 5;
    pub const max_iterations = 5;

    const send_count: usize = 500_000;

    pub fn benchmarkChannel() !u64 {
        const allocator = std.heap.page_allocator;
        var channel = BlockChannel.init(allocator, send_count / 2);
        defer channel.deinit();

        var recv_count: Atomic(usize) = Atomic(usize).init(0);

        var timer = try std.time.Timer.start();
        var join2 = try std.Thread.spawn(.{}, testSender, .{ channel, send_count });
        var join1 = try std.Thread.spawn(.{}, testReceiver, .{ channel, &recv_count, 1 });

        join2.join();
        join1.join();

        return timer.read();
    }

    pub fn benchmarkPacketChannel() !u64 {
        const allocator = std.heap.page_allocator;
        var channel = Channel(Packet).init(allocator, send_count / 2);
        defer channel.deinit();

        var timer = try std.time.Timer.start();
        var join1 = try std.Thread.spawn(.{}, testPacketReceiver, .{ channel, send_count });
        var join2 = try std.Thread.spawn(.{}, testPacketSender, .{ channel, send_count });

        join1.join();
        join2.join();

        return timer.read();
    }
};
