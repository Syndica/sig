const std = @import("std");
const Atomic = std.atomic.Atomic;
const Mutex = std.Thread.Mutex;
const Condition = std.Thread.Condition;
const testing = std.testing;
const assert = std.debug.assert;
const Mux = @import("mux.zig").Mux;
const Ordering = std.atomic.Ordering;

pub fn RingBufferV2(comptime T: type) type { 
    return struct { 
        buffer: []T,
        index: usize, 
        count: Atomic(usize),
        allocator: std.mem.Allocator, // just used for deinit

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, capacity: usize) *Self {
            std.debug.assert(capacity > 0);
            var self = allocator.create(Self) catch unreachable;
            const buffer = allocator.alloc(T, capacity) catch unreachable;
            self.* = RingBufferV2(T){
                .buffer = buffer,
                .index = 0,
                .count = Atomic(usize).init(0),
                .allocator = allocator,
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buffer); 
        }

        pub inline fn isFull(self: *const Self) bool {
            return self.count.load(Ordering.Acquire) == self.buffer.len;
        }

        pub inline fn isEmpty(self: *const Self) bool { 
            return self.count.load(Ordering.Acquire) == 0;
        }

        // get next free pointer => fill it up => increment count
        pub inline fn getNextFreePtr(self: *Self) ?*T {
            if (self.isFull()) return null;
            const count = self.count.load(Ordering.Acquire);
            return &self.buffer[(self.index + count) % self.buffer.len];
        }

        pub inline fn incrementCount(self: *Self) void {
            const count = self.count.fetchAdd(1, Ordering.Release);
            _ = count;
        }

        // get head pointer => process it => increment head
        pub inline fn getHeadPtr(self: *Self) ?*T {
            if (self.isEmpty()) return null;
            return &self.buffer[self.index % self.buffer.len];
        }

        // higher level functions 
        pub inline fn push(self: *Self, value: T) bool {
            if (self.getNextFreePtr()) |ptr| {
                ptr.* = value;
                _ = self.count.fetchAdd(1, Ordering.Release);
                return true;
            } else { 
                return false;
            }
        }

        pub inline fn try_drain(self: *Self) !?std.ArrayList(T) { 
            if (self.isEmpty()) return null;

            const count = self.count.load(Ordering.Acquire);
            var items = try std.ArrayList(T).initCapacity(self.allocator, count);
            for (0..count) |i| {
                var ptr = &self.buffer[(self.index + i) % self.buffer.len];
                items.appendAssumeCapacity(ptr.*);
            }

            _ = self.count.fetchSub(count, Ordering.Release);
            self.index += count;

            return items;
        }
    };
}

pub fn RingBuffer(comptime T: type) type { 
    return struct { 
        buffer: []T,
        index: usize, 
        count: Atomic(usize),
        allocator: std.mem.Allocator, // just used for deinit

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, capacity: usize) *Self {
            std.debug.assert(capacity > 0);
            var self = allocator.create(Self) catch unreachable;
            const buffer = allocator.alloc(T, capacity) catch unreachable;
            self.* = RingBuffer(T){
                .buffer = buffer,
                .index = 0,
                .count = Atomic(usize).init(0),
                .allocator = allocator,
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.buffer); 
        }

        pub fn isFull(self: *const Self) bool {
            return self.count.load(Ordering.Acquire) == self.buffer.len;
        }

        pub fn isEmpty(self: *const Self) bool { 
            return self.count.load(Ordering.Acquire) == 0;
        }

        // get next free pointer => fill it up => increment count
        pub inline fn getNextFreePtr(self: *Self) ?*T {
            if (self.isFull()) return null;
            const count = self.count.load(Ordering.Acquire);
            return &self.buffer[(self.index + count) % self.buffer.len];
        }

        pub inline fn incrementCount(self: *Self) void {
            const count = self.count.fetchAdd(1, Ordering.Release);
            _ = count;
            // std.debug.print("count incremented from {} -> {}\n", .{count, count+1});
        }

        // get head pointer => process it => increment head
        pub inline fn getHeadPtr(self: *Self) ?*T {
            if (self.isEmpty()) return null;
            return &self.buffer[self.index % self.buffer.len];
        }

        pub inline fn consumeAmount(self: *Self, amount: usize) void {
            const count = self.count.fetchSub(amount, Ordering.Release);
            // std.debug.print("consuming {}:  count: {}->{} new index: {}->{}\n", .{amount, count, count - amount, self.index, self.index+amount});
            _ = count;
            self.index += amount;
        }

        // higher level functions 
        pub fn push(self: *Self, value: T) bool {
            if (self.getNextFreePtr()) |ptr| {
                ptr.* = value;
                self.incrementCount();
                return true;
            } else { 
                return false;
            }
        }

        pub fn try_drain(self: *const Self) !?std.ArrayList(*T) { 
            if (self.isEmpty()) return null;

            const count = self.count.load(Ordering.Acquire);
            // std.debug.print("reading: {} -> {} (count = {})\n", .{self.index, self.index + count, count});
            var items = try std.ArrayList(*T).initCapacity(self.allocator, count);
            for (0..count) |i| {
                var ptr = &self.buffer[(self.index + i) % self.buffer.len];
                items.appendAssumeCapacity(ptr);
            }
            return items;
        }
    };
}

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

        pub fn isClosed(self: *Self) bool {
            return self.closed.load(.SeqCst);
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

const Packet = @import("../gossip/packet.zig").Packet;
fn testPacketSender(chan: *Channel(Packet), total_send: usize) void {
    var i: usize = 0;
    while (i < total_send) : (i += 1) {
        var packet = Packet.default(); 
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

fn testPacketSenderBuffer(ring_buffer: *RingBuffer(Packet), total_send: usize) void {
    var i: usize = 0;
    while (i < total_send) {
        var packet = Packet.default(); 
        packet.data[2] = @as(u8, @truncate(i));
        if (ring_buffer.push(packet)) { 
            i += 1;
        }
    }
}

fn testPacketRecvBuffer(ring_buffer: *RingBuffer(Packet), total_recv: usize) void {
    var count: usize = 0;
    while (count < total_recv) {
        if (ring_buffer.getHeadPtr()) |head| { 
            defer ring_buffer.consumeAmount(1);
            _ = head; 
            count += 1; 
            // std.debug.print("recv count: {}/{} \n", .{count, total_recv});
        }
    }
}

fn testPacketRecvBufferDrain(ring_buffer: *RingBuffer(Packet), total_recv: usize) void {
    var count: usize = 0;
    while (count < total_recv) {
        if (ring_buffer.try_drain() catch unreachable) |ptrs| { 
            for (ptrs.items) |ptr| {
                // std.debug.print("{any}", .{ptr.*.data[2]});
                _ = ptr;
                count += 1; 
            }
            defer { 
                ptrs.deinit();
                ring_buffer.consumeAmount(ptrs.items.len);
            }
        }
    }
}

fn testPacketSenderBufferV2(ring_buffer: *RingBufferV2(Packet), total_send: usize) void {
    var i: usize = 0;
    while (i < total_send) {
        var packet = Packet.default(); 
        packet.data[2] = @as(u8, @truncate(i));
        if (ring_buffer.push(packet)) { 
            i += 1;
        }
    }
}

fn testPacketRecvBufferDrainV2(ring_buffer: *RingBufferV2(Packet), total_recv: usize) void {
    var count: usize = 0;
    while (count < total_recv) {
        if (ring_buffer.try_drain() catch unreachable) |v| { 
            for (v.items) |val| {
                // std.debug.print("{any}", .{val.data[2]});
                _ = val;
                count += 1; 
            }
            v.deinit();
        }
    }
}

fn testPointerSender(chan: *BlockPointerChannel, total_send: usize) void {
    var allocator = chan.allocator;
    var i: usize = 0;
    while (i < total_send) : (i += 1) {
        var block_ptr = allocator.create(Block) catch unreachable;
        block_ptr.* = Block{ .num = @intCast(i) };
        chan.send(block_ptr) catch unreachable;
    }
    chan.close();
}

fn testPointerReceiver(chan: *BlockPointerChannel, recv_count: *Atomic(usize), id: u8) void {
    var allocator = chan.allocator;
    _ = id;
    while (chan.receive()) |v| {
        _ = recv_count.fetchAdd(1, .SeqCst);
        allocator.destroy(v);
    }
}

test "sync.channel: channel works properly" {
    var ch = BlockChannel.init(testing.allocator, 100);
    defer ch.deinit();

    var recv_count: Atomic(usize) = Atomic(usize).init(0);
    var send_count: usize = 100_000;

    var join2 = try std.Thread.spawn(.{}, testSender, .{ ch, send_count });
    var join1 = try std.Thread.spawn(.{}, testReceiver, .{ ch, &recv_count, 1 });

    join1.join();
    join2.join();

    try testing.expectEqual(send_count, recv_count.value);
}

pub const BenchmarkChannel = struct {
    pub const min_iterations = 5;
    pub const max_iterations = 5;
    const send_count: usize = 500_000;

    pub fn benchmarkChannel() !void {
        const allocator = std.heap.page_allocator;
        var channel = BlockChannel.init(allocator, send_count / 2);
        defer channel.deinit();

        var recv_count: Atomic(usize) = Atomic(usize).init(0);

        var join2 = try std.Thread.spawn(.{}, testSender, .{ channel, send_count });
        var join1 = try std.Thread.spawn(.{}, testReceiver, .{ channel, &recv_count, 1 });
        join1.join();
        join2.join();
    }

    pub fn benchmarkPacketChannel() !void {
        const allocator = std.heap.page_allocator;
        var channel = Channel(Packet).init(allocator, send_count / 2);
        defer channel.deinit();

        var join1 = try std.Thread.spawn(.{}, testPacketReceiver, .{ channel, send_count });
        var join2 = try std.Thread.spawn(.{}, testPacketSender, .{ channel, send_count });

        join1.join();
        join2.join();
    }

    pub fn benchmarkPacketChannelBuffer() !void {
        const allocator = std.heap.page_allocator;
        var buffer = RingBuffer(Packet).init(allocator, send_count / 2);
        defer buffer.deinit();

        var join1 = try std.Thread.spawn(.{}, testPacketRecvBuffer, .{ buffer, send_count });
        var join2 = try std.Thread.spawn(.{}, testPacketSenderBuffer, .{ buffer, send_count });

        join1.join();
        join2.join();
    }

    pub fn benchmarkPacketChannelBufferDrain() !void {
        const allocator = std.heap.page_allocator;
        var buffer = RingBuffer(Packet).init(allocator, send_count / 2);
        defer buffer.deinit();

        var join1 = try std.Thread.spawn(.{}, testPacketRecvBufferDrain, .{ buffer, send_count });
        var join2 = try std.Thread.spawn(.{}, testPacketSenderBuffer, .{ buffer, send_count });

        join1.join();
        join2.join();
    }

    pub fn benchmarkPacketChannelBufferDrainV2() !void {
        const allocator = std.heap.page_allocator;
        var buffer = RingBufferV2(Packet).init(allocator, send_count / 2);
        defer buffer.deinit();

        var join1 = try std.Thread.spawn(.{}, testPacketRecvBufferDrainV2, .{ buffer, send_count });
        var join2 = try std.Thread.spawn(.{}, testPacketSenderBufferV2, .{ buffer, send_count });

        join1.join();
        join2.join();
    }
};
