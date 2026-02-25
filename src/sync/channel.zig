const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");
const tracy = @import("tracy");

const Atomic = std.atomic.Value;
const Allocator = std.mem.Allocator;

const ExitCondition = sig.sync.ExitCondition;

pub fn Channel(T: type) type {
    return struct {
        head: Position,
        tail: Position,
        closed: Atomic(bool) = Atomic(bool).init(false),
        allocator: Allocator,
        event: std.Thread.ResetEvent = .{},
        send_hook: ?*SendHook = null,
        name: [:0]const u8 = std.fmt.comptimePrint("channel ({s})", .{@typeName(T)}),

        pub const SendHook = struct {
            /// Called after the channel has pushed the value.
            after_send: *const fn (*SendHook, *Self) void = defaultAfterSend,

            fn defaultAfterSend(_: *SendHook, _: *Self) void {}
        };

        const Self = @This();
        const BLOCK_CAP = 31;
        const SHIFT = 1;
        const LAP = 32;

        const WRITTEN_TO: usize = 0b01;
        const READ_FROM: usize = 0b10;
        const DESTROYED: usize = 0b100;

        const HAS_NEXT: usize = 0b01;

        const Position = struct {
            index: Atomic(usize),
            block: Atomic(?*Buffer),

            fn deinit(pos: *Position, allocator: Allocator) void {
                if (pos.block.load(.monotonic)) |block| {
                    block.deinit(allocator);
                    allocator.destroy(block);
                }
            }
        };

        const Buffer = struct {
            next: Atomic(?*Buffer),
            slots: [BLOCK_CAP]Slot,

            fn create(allocator: Allocator) !*Buffer {
                const new = try allocator.create(Buffer);
                @memset(&new.slots, Slot.uninit);
                new.next = Atomic(?*Buffer).init(null);
                return new;
            }

            fn destroy(block: *Buffer, start: usize, allocator: Allocator) void {
                for (start..BLOCK_CAP - 1) |i| {
                    const slot = &block.slots[i];

                    if (slot.state.load(.acquire) & READ_FROM == 0 and
                        slot.state.fetchOr(DESTROYED, .acq_rel) & READ_FROM == 0)
                    {
                        return;
                    }
                }

                allocator.destroy(block);
            }

            fn deinit(block: *Buffer, allocator: Allocator) void {
                if (block.next.load(.monotonic)) |n| {
                    n.deinit(allocator);
                    allocator.destroy(n);
                }
            }
        };

        const Slot = struct {
            value: T,
            state: Atomic(usize),

            const uninit: Slot = .{
                .value = undefined,
                .state = Atomic(usize).init(0),
            };
        };

        // NOTE: if we start seeing performance problems with the channel implementation in the future
        // note that it's possible to pre-allocate an initial capacity of blocks in order to speed it up.
        pub fn init(allocator: Allocator) !Self {
            const first_block = try Buffer.create(allocator);
            const first_position: Position = .{
                .index = Atomic(usize).init(0),
                .block = Atomic(?*Buffer).init(first_block),
            };
            return .{
                .head = first_position,
                .tail = first_position,
                .allocator = allocator,
            };
        }

        pub fn deinit(channel: *Self) void {
            var head = channel.head.index.raw;
            var tail = channel.tail.index.raw;
            var block = channel.head.block.raw;

            head &= ~((@as(usize, 1) << SHIFT) - 1);
            tail &= ~((@as(usize, 1) << SHIFT) - 1);

            while (head != tail) {
                const offset = (head >> SHIFT) % LAP;

                if (offset >= BLOCK_CAP) {
                    const next = block.?.next.raw;
                    channel.allocator.destroy(block.?);
                    block = next;
                }

                head +%= (1 << SHIFT);
            }

            if (block) |b| {
                channel.allocator.destroy(b);
            }
        }

        pub fn create(allocator: Allocator) !*Self {
            const channel = try allocator.create(Self);
            errdefer allocator.destroy(channel);
            channel.* = try Self.init(allocator);
            return channel;
        }

        /// to deinit channels created with `create`
        pub fn destroy(channel: *Self) void {
            channel.deinit();
            channel.allocator.destroy(channel);
        }

        pub fn close(channel: *Self) void {
            channel.closed.store(true, .monotonic);
        }

        pub fn send(channel: *Self, value: T) !void {
            const zone = tracy.Zone.init(@src(), .{ .name = "Channel.send" });
            defer zone.deinit();

            defer tracy.plot(u32, channel.name, @intCast(channel.len()));

            if (channel.closed.load(.monotonic)) {
                return error.ChannelClosed;
            }

            const send_hook = channel.send_hook;

            var backoff: Backoff = .{};
            var tail = channel.tail.index.load(.acquire);
            var block = channel.tail.block.load(.acquire);
            var next_block: ?*Buffer = null;

            while (true) {
                const offset = (tail >> SHIFT) % LAP;
                if (offset == BLOCK_CAP) {
                    // Another block has incremented the tail index before us,
                    // we need to wait for the next block to be installed.
                    backoff.snooze();
                    tail = channel.tail.index.load(.acquire);
                    block = channel.tail.block.load(.acquire);
                    continue;
                }

                if (offset + 1 == BLOCK_CAP and next_block == null) {
                    next_block = try Buffer.create(channel.allocator);
                }

                const new_tail = tail + (1 << SHIFT);

                // Try to increment the tail index by one to block all future producers
                // until we install the next_block and next_index.
                if (channel.tail.index.cmpxchgWeak(tail, new_tail, .seq_cst, .acquire)) |t| {
                    // We failed the CAS, another thread has installed a new tail index.
                    tail = t;
                    block = channel.tail.block.load(.acquire);
                    backoff.spin();
                } else {
                    // We won the race, now we install the next_block and next_index for other threads
                    // to see and unblock.
                    if (offset + 1 == BLOCK_CAP) {
                        // We're now one over the block cap and the next slot we write to
                        // will be inside of the next block. Wrap the offset around the block,
                        // and shift to get the next index.
                        const next_index = new_tail +% (1 << SHIFT);
                        channel.tail.block.store(next_block, .release);
                        channel.tail.index.store(next_index, .release);
                        block.?.next.store(next_block, .release);
                    } else if (next_block) |b| {
                        // When you win the CAS the time other threads snooze is from the CAS to the tail.index store above.
                        // Moving allocation after the CAS increases the amount of time other threads must snooze.
                        // Moving the allocation before the CAS lowers it, but you need to handle the install
                        // failures by de-allocating the next_block.
                        channel.allocator.destroy(b);
                    }

                    const slot = &block.?.slots[offset];
                    slot.value = value;
                    // Release the exclusive lock on the slot's value, which allows a consumer
                    // to read the data we've just assigned.
                    _ = slot.state.fetchOr(WRITTEN_TO, .release);

                    channel.event.set();

                    if (send_hook) |hook| {
                        hook.after_send(hook, channel);
                    }

                    return;
                }
            }
        }

        // Blocks until an item is received or the exit condition has been set.
        pub fn receive(self: *Self, exit: ExitCondition) error{Exit}!T {
            while (true) {
                try self.waitToReceive(exit);
                if (self.tryReceive()) |item| {
                    return item;
                }
            }
        }

        /// Waits untli the channel potentially has items, periodically checking for the ExitCondition.
        /// Must be called by only one receiver thread at a time.
        pub fn waitToReceive(channel: *Self, exit: ExitCondition) error{Exit}!void {
            while (channel.isEmpty()) {
                channel.event.timedWait(10 * std.time.ns_per_ms) catch {};
                if (exit.shouldExit()) return error.Exit;
                if (channel.event.isSet()) return channel.event.reset();
            }
        }

        /// Attempt to receive an item, returning immediately.
        /// Returns null if the channel is empty.
        pub fn tryReceive(channel: *Self) ?T {
            var backoff: Backoff = .{};
            var head = channel.head.index.load(.acquire);
            var block = channel.head.block.load(.acquire);

            while (true) {
                // Shift away the meta-data bits and get the index into whichever block we're in.
                const offset = (head >> SHIFT) % LAP;

                // This means another thread has begun the process of installing a new head block and index,
                // we just need to wait until that's done.
                if (offset == BLOCK_CAP) {
                    backoff.snooze();
                    head = channel.head.index.load(.acquire);
                    block = channel.head.block.load(.acquire);
                    continue;
                }

                // After we consume this, this will be our next head.
                var new_head = head + (1 << SHIFT);

                // A bit confusing, but this checks if the current head *doesn't* have a next block linked.
                // It's encoded as a bit in order to be able to tell without dereferencing it.
                if (new_head & HAS_NEXT == 0) {
                    // NOTE: could also be tail.index.load(.acquire), but to be safe, seq_cst RMW load
                    const tail = channel.tail.index.fetchAdd(0, .seq_cst);

                    // If the indicies are the same, the channel is empty and there's nothing to receive.
                    if (head >> SHIFT == tail >> SHIFT) {
                        return null;
                    }

                    // The head index must always be less than or equal to the tail index.
                    // Using this invariance, we can prove that if the head is in a different block than
                    // the tail, it *must* be ahead of it and in a "next" block. Hence we set the "HAS_NEXT"
                    // bit in the index.
                    if ((head >> SHIFT) / LAP != (tail >> SHIFT) / LAP) {
                        new_head |= HAS_NEXT;
                    }
                }

                // Try to install a new head index.
                if (channel.head.index.cmpxchgWeak(head, new_head, .seq_cst, .acquire)) |h| {
                    // We lost the install race against something, the new head index is acquired,
                    // and we update the block as it could have changed due to a new block being installed.
                    head = h;
                    block = channel.head.block.load(.acquire);
                    backoff.spin();
                } else {
                    // There is a consumer on the other end that should be installing the next block right now.
                    if (offset + 1 == BLOCK_CAP) {
                        // Wait until it installs the next block and update the references.
                        const next = while (true) {
                            backoff.snooze();
                            const next = block.?.next.load(.acquire);
                            if (next != null) break next.?;
                        };
                        var next_index = (new_head & ~HAS_NEXT) +% (1 << SHIFT);

                        if (next.next.load(.monotonic) != null) {
                            next_index |= HAS_NEXT;
                        }

                        channel.head.block.store(next, .release);
                        channel.head.index.store(next_index, .release);
                    }

                    // Now we should have a stable reference to a slot. Loop if there's a producer
                    // currently writing to this slot.
                    const slot = &block.?.slots[offset];
                    while (slot.state.load(.acquire) & WRITTEN_TO == 0) {
                        backoff.snooze();
                    }
                    const value = slot.value;

                    // If this is the last block, we can just destroy it.
                    if (offset + 1 == BLOCK_CAP) {
                        block.?.destroy(0, channel.allocator);
                    } else
                    // Set the slot as READ_FROM, and if DESTROYED was set, destroy the block.
                    if (slot.state.fetchOr(READ_FROM, .acq_rel) & DESTROYED != 0) {
                        block.?.destroy(offset + 1, channel.allocator);
                    }

                    return value;
                }
            }
        }

        pub fn len(channel: *Self) usize {
            while (true) {
                var tail = channel.tail.index.load(.seq_cst);
                var head = channel.head.index.load(.seq_cst);

                // Make sure `tail` wasn't modified while we were loading `head`.
                if (channel.tail.index.load(.seq_cst) == tail) {
                    // Shift out the bottom bit, which is used to indicate whether
                    // there is a next link in the block.
                    tail &= ~((@as(usize, 1) << SHIFT) - 1);
                    head &= ~((@as(usize, 1) << SHIFT) - 1);

                    // We're waiting for another thread to install the next_block
                    // and next_index, so we "mock" increment our tail as if it was installed.
                    if ((tail >> SHIFT) % LAP == (LAP - 1)) {
                        tail +%= (1 << SHIFT);
                    }
                    if ((head >> SHIFT) % LAP == (LAP - 1)) {
                        head +%= (1 << SHIFT);
                    }

                    // Calculate on which block link we're on. Between 0-31 is block 1, 32-63 is block 2, etc.
                    const lap = (head >> SHIFT) / LAP;
                    // Rotates the indices to fall into the first slot.
                    // (lap * LAP) is the first index of the block we're in.
                    tail -%= (lap * LAP) << SHIFT;
                    head -%= (lap * LAP) << SHIFT;

                    // Remove the lower bits.
                    tail >>= SHIFT;
                    head >>= SHIFT;

                    // Return the difference minus the number of blocks between tail and head.
                    return tail - head - tail / LAP;
                }
            }
        }

        pub fn isEmpty(channel: *Self) bool {
            const head = channel.head.index.load(.seq_cst);
            const tail = channel.tail.index.load(.seq_cst);
            // The channel is empty if the indices are pointing at the same slot.
            return (head >> SHIFT) == (tail >> SHIFT);
        }
    };
}

pub const Backoff = struct {
    step: u32 = 0,

    const SPIN_LIMIT = 6;

    pub fn snooze(_: *Backoff) void {
        switch (builtin.cpu.arch) {
            .aarch64 => asm volatile ("wfe" ::: .{ .memory = true }),
            else => std.atomic.spinLoopHint(),
        }
    }

    pub fn spin(b: *Backoff) void {
        for (0..(@as(u32, 1) << @intCast(b.step))) |_| {
            std.atomic.spinLoopHint();
        }

        if (b.step <= SPIN_LIMIT) {
            b.step += 1;
        }
    }
};

const expect = std.testing.expect;

test "Channel clean init and deinit" {
    const ns = struct {
        pub fn run(allocator: Allocator) !void {
            var channel = try Channel(u8).create(allocator);
            defer channel.destroy();
        }
    };

    try ns.run(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, ns.run, .{});
}

test "smoke" {
    var ch = try Channel(u32).init(std.testing.allocator);
    defer ch.deinit();

    try ch.send(7);
    try expect(ch.tryReceive() == 7);

    try ch.send(8);
    try expect(ch.tryReceive() == 8);
    try expect(ch.tryReceive() == null);
}

test "len_empty_full" {
    var ch = try Channel(u32).init(std.testing.allocator);
    defer ch.deinit();

    try expect(ch.len() == 0);
    try expect(ch.isEmpty());

    try ch.send(0);

    try expect(ch.len() == 1);
    try expect(!ch.isEmpty());

    _ = ch.tryReceive().?;

    try expect(ch.len() == 0);
    try expect(ch.isEmpty());
}

test "len" {
    var ch = try Channel(u64).init(std.testing.allocator);
    defer ch.deinit();

    try expect(ch.len() == 0);

    for (0..50) |i| {
        try ch.send(i);
        try expect(ch.len() == i + 1);
    }

    for (0..50) |i| {
        _ = ch.tryReceive().?;
        try expect(ch.len() == 50 - i - 1);
    }

    try expect(ch.len() == 0);
}

test "spsc" {
    const COUNT = 100;

    const S = struct {
        fn producer(ch: *Channel(u64)) !void {
            for (0..COUNT) |i| {
                try ch.send(i);
            }
        }

        fn consumer(ch: *Channel(u64)) void {
            for (0..COUNT) |i| {
                while (true) {
                    if (ch.tryReceive()) |x| {
                        std.debug.assert(x == i);
                        break;
                    }
                }
            }
        }
    };

    var ch = try Channel(u64).init(std.testing.allocator);
    defer ch.deinit();

    const consumer = try std.Thread.spawn(.{}, S.consumer, .{&ch});
    const producer = try std.Thread.spawn(.{}, S.producer, .{&ch});

    consumer.join();
    producer.join();
}

test "send-hook" {
    const Counter = struct {
        count: usize = 0,
        hook: Channel(u64).SendHook = .{ .after_send = afterSend },

        fn afterSend(hook: *Channel(u64).SendHook, channel: *Channel(u64)) void {
            const self: *@This() = @alignCast(@fieldParentPtr("hook", hook));
            self.count += 1;
            std.debug.assert(channel.len() == self.count);
        }
    };

    const Consumer = struct {
        collected: std.array_list.Managed(u64),
        hook: Channel(u64).SendHook = .{ .after_send = afterSend },

        fn afterSend(hook: *Channel(u64).SendHook, channel: *Channel(u64)) void {
            const self: *@This() = @alignCast(@fieldParentPtr("hook", hook));
            const value = channel.tryReceive() orelse @panic("empty channel after send");
            self.collected.append(value) catch @panic("oom");
        }
    };

    const to_send = 100;
    const allocator = std.testing.allocator;

    var ch = try Channel(u64).init(allocator);
    defer ch.deinit();

    // Check that afterSend counts sent channel items.
    var counter = Counter{};
    ch.send_hook = &counter.hook;

    for (0..to_send) |i| try ch.send(i);
    try expect(ch.len() == to_send);
    try expect(counter.count == to_send);

    // Check that afterSend consumes any sent values.
    var consumer = Consumer{ .collected = std.array_list.Managed(u64).init(allocator) };
    ch.send_hook = &consumer.hook;
    defer consumer.collected.deinit();

    while (ch.tryReceive()) |_| {} // drain before starting.
    for (0..to_send) |i| try ch.send(i);
    try expect(ch.isEmpty());
    try expect(consumer.collected.items.len == to_send);
}

test "mpmc" {
    const COUNT = 100;
    const THREADS = 4;

    const S = struct {
        fn producer(ch: *Channel(u64)) !void {
            for (0..COUNT) |i| {
                try ch.send(i);
            }
        }

        fn consumer(ch: *Channel(u64), v: *[COUNT]Atomic(usize)) void {
            for (0..COUNT) |_| {
                const n = while (true) {
                    if (ch.tryReceive()) |x| break x;
                };
                _ = v[n].fetchAdd(1, .seq_cst);
            }
        }
    };

    var v: [COUNT]Atomic(usize) = .{Atomic(usize).init(0)} ** COUNT;

    var ch = try Channel(u64).init(std.testing.allocator);
    defer ch.deinit();

    var c_threads: [THREADS]std.Thread = undefined;
    var p_threads: [THREADS]std.Thread = undefined;

    for (&c_threads) |*c_thread| {
        c_thread.* = try std.Thread.spawn(.{}, S.consumer, .{ &ch, &v });
    }

    for (&p_threads) |*p_thread| {
        p_thread.* = try std.Thread.spawn(.{}, S.producer, .{&ch});
    }

    for (c_threads, p_threads) |c_thread, p_thread| {
        c_thread.join();
        p_thread.join();
    }

    for (v) |c| try expect(c.load(.seq_cst) == THREADS);
}

const Block = struct {
    num: u32 = 333,
    valid: bool = true,
    data: [1024]u8 = undefined,
};

const logger = std.log.scoped(.sync_channel_tests);

fn testUsizeReceiver(chan: anytype, recv_count: usize) void {
    var count: usize = 0;
    while (count < recv_count) {
        if (chan.tryReceive()) |_| count += 1;
    }
}

fn testUsizeSender(chan: anytype, send_count: usize) void {
    var i: usize = 0;
    while (i < send_count) : (i += 1) {
        chan.send(i) catch |err| {
            std.debug.print("could not send on chan: {any}", .{err});
            @panic("could not send on channel!");
        };
    }
}

const Packet = @import("../net/packet.zig").Packet;

fn testPacketSender(chan: anytype, total_send: usize) void {
    var i: usize = 0;
    while (i < total_send) : (i += 1) {
        const packet = Packet.ANY_EMPTY;
        chan.send(packet) catch |err| {
            std.debug.print("could not send on chan: {any}", .{err});
            @panic("could not send on channel!");
        };
    }
}

fn testPacketReceiver(chan: anytype, total_recv: usize) void {
    var count: usize = 0;
    while (count < total_recv) {
        if (chan.tryReceive()) |_| count += 1;
    }
}

pub const BenchmarkChannel = struct {
    pub const min_iterations = 10;
    pub const max_iterations = 500;
    pub const name = "channel";

    pub const BenchmarkInput = struct {
        name: []const u8 = "",
        n_senders: ?usize,
        receives: bool,
        is_unit_test: bool = false,
    };

    pub const inputs = [_]BenchmarkInput{
        .{
            .name = "1_senders-   1_receivers ",
            .n_senders = 1,
            .receives = true,
        },
        .{
            .name = "N_senders-   0_receivers ",
            .n_senders = null, // null = num_cpus
            .receives = false,
        },
        .{
            .name = "N_senders-   1_receivers ",
            .n_senders = null, // null = num_cpus
            .receives = true,
        },
    };

    const Context = struct {
        channel: Channel(Packet),
        start: std.Thread.ResetEvent = .{},
        stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        popped: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    };

    fn runSender(ctx: *Context) !void {
        ctx.start.wait();
        while (!ctx.stop.load(.monotonic)) {
            try ctx.channel.send(Packet.ANY_EMPTY);
        }
    }

    fn runReceiver(ctx: *Context) !void {
        ctx.start.wait();
        while (!ctx.stop.load(.monotonic)) {
            std.mem.doNotOptimizeAway(ctx.channel.tryReceive() orelse continue);
            // NOTE: should happen-after len() update from tryReceive().
            _ = ctx.popped.fetchAdd(1, .release);
        }
    }

    pub fn benchmarkSimplePacketChannel(input: BenchmarkInput) !sig.time.Duration {
        const num_cpus = @max(1, try std.Thread.getCpuCount());
        const allocator = if (@import("builtin").is_test)
            std.testing.allocator
        else
            std.heap.c_allocator;

        var ctx: Context = .{ .channel = try Channel(Packet).init(allocator) };
        defer ctx.channel.deinit();

        var threads: std.ArrayListUnmanaged(std.Thread) = .empty;
        defer {
            ctx.stop.store(true, .monotonic);
            for (threads.items) |t| t.join();
            threads.deinit(allocator);
        }

        const num_senders = input.n_senders orelse num_cpus;
        for (0..num_senders) |_| {
            try threads.append(allocator, try std.Thread.spawn(
                .{},
                runSender,
                .{&ctx},
            ));
        }

        if (input.receives) {
            try threads.append(allocator, try std.Thread.spawn(
                .{},
                runReceiver,
                .{&ctx},
            ));
        }

        ctx.start.set();

        const time = 10 * std.time.ns_per_ms;

        // run benchmark for 10 milliseconds
        std.Thread.sleep(time);

        // NOTE: should happen-before len() read.
        const popped = ctx.popped.load(.acquire);
        const total = popped + ctx.channel.len();

        return .fromNanos(time / @max(1, total));
    }
};

test "BenchmarkChannel.benchmarkSimplePacketChannel" {
    _ = try BenchmarkChannel.benchmarkSimplePacketChannel(.{
        .n_senders = 4,
        .receives = true,
        .is_unit_test = true,
    });
}
