const std = @import("std");
const Atomic = std.atomic.Atomic;
const Mutex = std.Thread.Mutex;
const Condition = std.Thread.Condition;
const testing = std.testing;
const assert = std.debug.assert;

/// A very basic mpmc channel implementation - TODO: replace with a legit channel impl
pub fn Channel(comptime T: type) type {
    return struct {
        buffer: std.ArrayList(T),
        lock: Mutex = .{},
        hasValue: Condition = .{},
        closed: Atomic(bool) = Atomic(bool).init(false),
        allocator: std.mem.Allocator,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, init_capacity: usize) *Self {
            var self = allocator.create(Self) catch unreachable;
            self.* = .{
                .buffer = std.ArrayList(T).initCapacity(allocator, init_capacity) catch unreachable,
                .allocator = allocator,
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.buffer.deinit();
            self.allocator.destroy(self);
        }

        pub fn send(self: *Self, value: T) void {
            self.lock.lock();
            self.buffer.append(value) catch unreachable;
            self.lock.unlock();
            self.hasValue.signal();
        }

        pub fn receive(self: *Self) ?T {
            self.lock.lock();
            defer self.lock.unlock();

            while (self.buffer.items.len == 0 and !self.closed.load(.SeqCst)) {
                self.hasValue.wait(&self.lock);
            }

            // channel closed so return null to signal no more items
            if (self.buffer.items.len == 0) {
                return null;
            }

            return self.buffer.pop();
        }

        /// `drain` func will remove all pending items from queue.
        ///
        /// NOTE: Caller is responsible for calling `allocator.free` on the returned slice.
        pub fn drain(self: *Self) ?[]T {
            self.lock.lock();
            defer self.lock.unlock();

            while (self.buffer.items.len == 0 and !self.closed.load(.SeqCst)) {
                self.hasValue.wait(&self.lock);
            }

            // channel closed so return null to signal no more items
            if (self.buffer.items.len == 0) {
                return null;
            }

            var num_items_to_drain = self.buffer.items.len;

            var out = self.allocator.alloc(T, num_items_to_drain) catch @panic("could not alloc");
            @memcpy(out, self.buffer.items);

            self.buffer.shrinkRetainingCapacity(0);
            assert(self.buffer.items.len == 0);
            assert(num_items_to_drain == out.len);

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
        chan.send(Block{ .num = @intCast(i) });
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
