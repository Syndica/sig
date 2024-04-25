// NOTE: WIP
const std = @import("std");
const assert = std.debug.assert;
const Atomic = std.atomic.Value;
const ref = @import("ref.zig");

/// An UnboundedChannel with the following characteristics:
/// - non-blocking sender
/// - blocking receiver
/// - no mutex/rwlock
/// - data ordering is not guaranteed
/// - atomically reference counted data
/// - thread safe
pub fn UnboundedChannel(comptime T: type) type {
    return struct {
        arena: std.heap.ArenaAllocator,
        stack: Atomic(usize),
        cache: ?*Node,
        closed: Atomic(bool),

        const Self = @This();

        pub const Error = error{
            Closed,
        };

        /// Node which holds data. Ideally, these should be recycled.
        pub const Node = struct {
            next: ?*Node,
            data: ref.Arc(T),

            pub fn init(allocator: std.mem.Allocator, data: T) !*Node {
                const node = try allocator.create(Node);
                node.* = .{
                    .next = null,
                    .data = try ref.arc(allocator, data),
                };
                return node;
            }

            pub fn deinit(self: *Node, allocator: std.mem.Allocator) void {
                self.data.release();
                allocator.destroy(self);
            }
        };

        /// A batch of linked list nodes
        pub const Batch = struct {
            first: *Node,
            last: *Node,

            pub fn init(first: *Node, last: *Node) Batch {
                return .{
                    .first = first,
                    .last = last,
                };
            }
        };

        pub const Sender = struct {
            allocator: std.mem.Allocator,
            stack: *Atomic(usize),
            closed: *Atomic(bool),

            fn init(allocator: std.mem.Allocator, stack: *Atomic(usize), closed: *Atomic(bool)) Sender {
                return Sender{
                    .allocator = allocator,
                    .stack = stack,
                    .closed = closed,
                };
            }

            pub fn deinit(_: *Sender) void {
                return;
            }

            fn flush(self: *Sender, list: Batch) void {
                var stack = self.stack.load(.seq_cst);
                while (true) {
                    // Attach the list to the stack (pt. 1)
                    list.last.next = @as(?*Node, @ptrFromInt(stack & PTR_MASK));

                    // Update the stack with the list (pt. 2).
                    // Don't change the HAS_CACHE and IS_CONSUMING bits of the consumer.
                    var new_stack = @intFromPtr(list.first);
                    assert(new_stack & ~PTR_MASK == 0);
                    new_stack |= (stack & ~PTR_MASK);

                    // Push to the stack with a release barrier for the consumer to see the proper list links.
                    stack = self.stack.tryCompareAndSwap(
                        stack,
                        new_stack,
                        .release,
                        .monotonic,
                    ) orelse break;
                }
            }

            pub fn send(self: *Sender, data: T) error{Closed}!void {
                if (self.closed.load(.monotonic)) {
                    return error.Closed;
                }
                const node = Node.init(self.allocator, data) catch unreachable;
                self.flush(Batch.init(node, node));
            }
        };

        pub const Receiver = struct {
            allocator: std.mem.Allocator,
            stack: *Atomic(usize),
            ref: ?*Node,
            cache: *?*Node,
            acquired: bool,
            closed: *Atomic(bool),

            fn init(allocator: std.mem.Allocator, stack: *Atomic(usize), closed: *Atomic(bool), cache: *?*Node) Receiver {
                return Receiver{ .allocator = allocator, .stack = stack, .ref = null, .cache = cache, .acquired = false, .closed = closed };
            }

            pub fn deinit(noalias self: *Receiver) void {
                // Stop consuming and remove the HAS_CACHE bit as well if the consumer's cache is empty.
                // When HAS_CACHE bit is zeroed, the next consumer will acquire the pushed stack nodes.
                var remove = IS_CONSUMING;
                if (self.ref == null)
                    remove |= HAS_CACHE;

                // Release the consumer with a release barrier to ensure cache/node accesses
                // happen before the consumer was released and before the next consumer starts using the cache.
                self.cache.* = self.ref;
                const stack = self.stack.fetchSub(remove, .seq_cst);
                assert(stack & remove != 0);
            }

            fn tryAcquireConsumer(noalias self: *Receiver) error{ Empty, Contended }!?*Node {
                var stack = self.stack.load(.monotonic);
                while (true) {
                    if (stack & IS_CONSUMING != 0)
                        return error.Contended; // The queue already has a consumer.
                    if (stack & (HAS_CACHE | PTR_MASK) == 0)
                        return error.Empty; // The queue is empty when there's nothing cached and nothing in the stack.

                    // When we acquire the consumer, also consume the pushed stack if the cache is empty.
                    var new_stack = stack | HAS_CACHE | IS_CONSUMING;
                    if (stack & HAS_CACHE == 0) {
                        assert(stack & PTR_MASK != 0);
                        new_stack &= ~PTR_MASK;
                    }

                    // Acquire barrier on getting the consumer to see cache/Node updates done by previous consumers
                    // and to ensure our cache/Node updates in pop() happen after that of previous consumers.
                    stack = self.stack.tryCompareAndSwap(
                        stack,
                        new_stack,
                        .acquire,
                        .monotonic,
                    ) orelse return self.cache.* orelse @as(*Node, @ptrFromInt(stack & PTR_MASK));
                }
            }

            pub fn recv(noalias self: *Receiver) ?ref.Arc(T) {
                while (!self.closed.load(.monotonic)) {
                    while (!self.acquired) {
                        if (self.closed.load(.monotonic)) {
                            return null;
                        }
                        self.ref = self.tryAcquireConsumer() catch continue;
                        self.acquired = true;
                    }

                    // Check the consumer cache (fast path)
                    if (self.ref) |node| {
                        self.ref = node.next;
                        // grab the data and retain arc
                        const data = node.data.retain();
                        // deinit the node
                        node.deinit(self.allocator);
                        // return the data
                        return data;
                    }

                    // Load the stack to see if there was anything pushed that we could grab.
                    var stack = self.stack.load(.monotonic);
                    assert(stack & IS_CONSUMING != 0);
                    if (stack & PTR_MASK == 0) {
                        continue;
                    }

                    // Nodes have been pushed to the stack, grab then with an Acquire barrier to see the Node links.
                    stack = self.stack.swap(HAS_CACHE | IS_CONSUMING, .acquire);
                    assert(stack & IS_CONSUMING != 0);
                    assert(stack & PTR_MASK != 0);

                    const node = @as(*Node, @ptrFromInt(stack & PTR_MASK));
                    self.ref = node.next;
                    const data = node.data.retain();
                    node.deinit(self.allocator);
                    return data;
                }
                return null;
            }
        };

        const HAS_CACHE: usize = 0b01;
        const IS_CONSUMING: usize = 0b10;
        const PTR_MASK: usize = ~(HAS_CACHE | IS_CONSUMING);

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .stack = Atomic(usize).init(0),
                .cache = null,
                .arena = std.heap.ArenaAllocator.init(allocator),
                .closed = Atomic(bool).init(false),
            };
        }

        pub fn deinit(self: *Self) void {
            self.arena.deinit();
        }

        comptime {
            assert(@alignOf(Node) >= ((IS_CONSUMING | HAS_CACHE) + 1));
        }

        pub fn close(self: *Self) void {
            self.closed.store(true, .monotonic);
        }

        pub fn sender(self: *Self) error{Closed}!Sender {
            if (self.closed.load(.seq_cst)) {
                return error.Closed;
            }
            return Sender.init(self.arena.allocator(), &self.stack, &self.closed);
        }

        pub fn receiver(self: *Self) error{Closed}!Receiver {
            if (self.closed.load(.seq_cst)) {
                return error.Closed;
            }
            return Receiver.init(self.arena.allocator(), &self.stack, &self.closed, &self.cache);
        }
    };
}

fn startSender(chan: *UnboundedChannel(u32), count: usize) !void {
    var sender = try chan.sender();
    defer sender.deinit();

    for (0..count) |i| {
        try sender.send(@intCast(i));
        if ((i % 4) == 0) {
            std.time.sleep(2);
        }
    }
    std.time.sleep(std.time.ns_per_s * 1);
    chan.close();
}

fn startReceiver(chan: *UnboundedChannel(u32), observed: *usize, id: u8) !void {
    var receiver = chan.receiver() catch return;
    defer receiver.deinit();

    var i: usize = 0;
    while (receiver.recv()) |data| {
        i += 1;
        defer data.release();
        std.log.info("[{any}] got data: {any}", .{ id, data.value.* });
        observed.* += 1;
        if ((i % 10) == 0) {
            std.time.sleep(3);
        }
    }
}

const testing = std.testing;

test "sync.mpmc: UnboundedChannel works" {
    return error.SkipZigTest;

    // var chan = UnboundedChannel(u32).init(testing.allocator);
    // defer chan.deinit();

    // var items_to_produce: usize = 1000;
    // var observed: usize = 0;

    // var send_handle = try std.Thread.spawn(.{}, startSender, .{ &chan, items_to_produce });
    // var recv_handle_1 = try std.Thread.spawn(.{}, startReceiver, .{ &chan, &observed, 1 });
    // // std.time.sleep(1);
    // var recv_handle_2 = try std.Thread.spawn(.{}, startReceiver, .{ &chan, &observed, 2 });
    // // std.time.sleep(1);
    // var recv_handle_3 = try std.Thread.spawn(.{}, startReceiver, .{ &chan, &observed, 3 });

    // send_handle.join();
    // recv_handle_1.join();
    // recv_handle_2.join();
    // recv_handle_3.join();
    // try testing.expectEqual(items_to_produce, observed);
}
