const std = @import("std");
const Atomic = std.atomic.Atomic;
const Mutex = std.Thread.Mutex;
const Condition = std.Thread.Condition;
const testing = std.testing;
const assert = std.debug.assert;
const Mux = @import("mux.zig").Mux;

/// A very basic mpmc channel implementation - TODO: replace with a legit channel impl
pub fn Channel(comptime T: type) type {
    return struct {
        buffer: Mux(std.ArrayList(T)),
        hasValue: Condition = .{},
        closed: Atomic(bool) = Atomic(bool).init(false),
        allocator: std.mem.Allocator,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, init_capacity: usize) *Self {
            var self = allocator.create(Self) catch unreachable;
            self.* = .{
                .buffer = Mux(std.ArrayList(T)).init(std.ArrayList(T).initCapacity(allocator, init_capacity) catch unreachable),
                .allocator = allocator,
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            var buff = self.buffer.lock();
            buff.mut().deinit();
            buff.unlock();

            self.allocator.destroy(self);
        }

        pub fn send(self: *Self, value: T) error{ OutOfMemory, ChannelClosed }!void {
            if (self.closed.load(.Monotonic)) {
                return error.ChannelClosed;
            }
            var buffer = self.buffer.lock();
            defer buffer.unlock();
            try buffer.mut().append(value);
            self.hasValue.signal();
        }

        pub fn receive(self: *Self) ?T {
            var buffer = self.buffer.lock();
            defer buffer.unlock();

            while (buffer.get().items.len == 0 and !self.closed.load(.SeqCst)) {
                buffer.condition(&self.hasValue);
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

            while (buffer.get().items.len == 0 and !self.closed.load(.SeqCst)) {
                buffer.condition(&self.hasValue);
            }

            // channel closed so return null to signal no more items
            if (buffer.get().items.len == 0) {
                return null;
            }

            var num_items_to_drain = buffer.get().items.len;

            var out = self.allocator.alloc(T, num_items_to_drain) catch @panic("could not alloc");
            @memcpy(out, buffer.get().items);

            buffer.mut().shrinkRetainingCapacity(0);
            assert(buffer.get().items.len == 0);
            assert(num_items_to_drain == out.len);

            return out;
        }

        pub fn try_drain(self: *Self) error{ ChannelClosed, OutOfMemory }!?[]T {
            var buffer = self.buffer.lock();
            defer buffer.unlock();

            if (self.closed.load(.SeqCst)) {
                return error.ChannelClosed;
            }

            var num_items_to_drain = buffer.get().items.len;
            if (num_items_to_drain == 0) {
                return null;
            }

            var out = try self.allocator.alloc(T, num_items_to_drain);
            @memcpy(out, buffer.get().items);
            buffer.mut().clearRetainingCapacity();

            return out;
        }

        pub fn close(self: *Self) void {
            self.closed.store(true, .SeqCst);
            self.hasValue.broadcast();
        }
    };
}

const Block = struct {
    num: u32 = 333,
    valid: bool = true,
};

const BlockChannel = Channel(Block);

const logger = std.log.scoped(.sync_channel_tests);

fn testReceiver(chan: *BlockChannel, recv_count: *Atomic(usize), id: u8) void {
    _ = id;
    while (chan.receive()) |v| {
        _ = v;
        _ = recv_count.fetchAdd(1, .SeqCst);
    }
}

fn testSender(chan: *BlockChannel, total_send: usize) void {
    var i: usize = 0;
    while (i < total_send) : (i += 1) {
        chan.send(Block{ .num = @intCast(i) }) catch unreachable;
    }
    chan.close();
}

test "sync.channel: channel works properly" {
    var ch = BlockChannel.init(testing.allocator, 100);
    defer ch.deinit();

    var recv_count: Atomic(usize) = Atomic(usize).init(0);
    var send_count: usize = 100_000;

    var join1 = try std.Thread.spawn(.{}, testReceiver, .{ ch, &recv_count, 1 });
    var join2 = try std.Thread.spawn(.{}, testSender, .{ ch, send_count });
    var join3 = try std.Thread.spawn(.{}, testReceiver, .{ ch, &recv_count, 2 });
    var join4 = try std.Thread.spawn(.{}, testReceiver, .{ ch, &recv_count, 3 });

    join1.join();
    join2.join();
    join3.join();
    join4.join();

    try testing.expectEqual(send_count, recv_count.value);
}

pub const BenchmarkChannel = struct {
    pub const min_iterations = 10;
    pub const max_iterations = 20;

    pub fn benchmarkChannel() !void {
        const T: type = Block;

        const allocator = std.heap.page_allocator;
        var channel = Channel(T).init(allocator, 100);
        defer channel.deinit();

        var recv_count: Atomic(usize) = Atomic(usize).init(0);
        var send_count: usize = 100_000;

        var join1 = try std.Thread.spawn(.{}, testReceiver, .{ channel, &recv_count, 1 });
        var join2 = try std.Thread.spawn(.{}, testSender, .{ channel, send_count });
        var join3 = try std.Thread.spawn(.{}, testReceiver, .{ channel, &recv_count, 2 });
        var join4 = try std.Thread.spawn(.{}, testReceiver, .{ channel, &recv_count, 3 });

        join1.join();
        join2.join();
        join3.join();
        join4.join();
    }
};
