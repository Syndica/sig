const std = @import("std");
const Atomic = std.atomic.Value;
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

const sig = @import("../sig.zig");
const Backoff = @import("backoff.zig").Backoff;

pub fn Channel(T: type) type {
    return struct {
        head: Position,
        tail: Position,
        closed: Atomic(bool) = Atomic(bool).init(false),
        allocator: Allocator,

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

        pub fn create(allocator: Allocator) !*Self {
            const channel = try allocator.create(Self);
            channel.* = try Self.init(allocator);
            return channel;
        }

        pub fn send(channel: *Self, value: T) !void {
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
                    return;
                }
            }
        }

        pub fn receive(channel: *Self) ?T {
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
                    // A rare usecase for fence :P, we need to create a barrier before anything else modifying
                    // the index. This is just easier than creating an acquire-release pair.
                    channel.tail.index.fence(.seq_cst);
                    const tail = channel.tail.index.load(.monotonic);

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
                    if ((tail >> SHIFT) % (LAP - 1) == (LAP - 1)) {
                        tail +%= (1 << SHIFT);
                    }
                    if ((head >> SHIFT) % (LAP - 1) == (LAP - 1)) {
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
    };
}

const expect = std.testing.expect;

test "smoke" {
    var ch = try Channel(u32).init(std.testing.allocator);
    defer ch.deinit();

    try ch.send(7);
    try expect(ch.receive() == 7);

    try ch.send(8);
    try expect(ch.receive() == 8);
    try expect(ch.receive() == null);
}

test "len_empty_full" {
    var ch = try Channel(u32).init(std.testing.allocator);
    defer ch.deinit();

    try expect(ch.len() == 0);
    try expect(ch.isEmpty());

    try ch.send(0);

    try expect(ch.len() == 1);
    try expect(!ch.isEmpty());

    _ = ch.receive().?;

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
        _ = ch.receive().?;
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
                    if (ch.receive()) |x| {
                        assert(x == i);
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
                    if (ch.receive()) |x| break x;
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
        if (chan.receive()) |_| count += 1;
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
        const packet = Packet.default();
        chan.send(packet) catch |err| {
            std.debug.print("could not send on chan: {any}", .{err});
            @panic("could not send on channel!");
        };
    }
}

fn testPacketReceiver(chan: anytype, total_recv: usize) void {
    var count: usize = 0;
    while (count < total_recv) {
        if (chan.receive()) |_| count += 1;
    }
}

pub const BenchmarkChannel = struct {
    pub const min_iterations = 10;
    pub const max_iterations = 20;

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
    };

    pub fn benchmarkSimpleUsizeBetterChannel(argss: BenchmarkArgs) !sig.time.Duration {
        var thread_handles: [64]?std.Thread = [_]?std.Thread{null} ** 64;
        const n_items = argss.n_items;
        const senders_count = argss.n_senders;
        const receivers_count = argss.n_receivers;
        var timer = try sig.time.Timer.start();

        const allocator = if (@import("builtin").is_test) std.testing.allocator else std.heap.c_allocator;
        var channel = try Channel(usize).init(allocator);
        defer channel.deinit();

        const sends_per_sender: usize = n_items / senders_count;
        const receives_per_receiver: usize = n_items / receivers_count;

        var thread_index: usize = 0;
        while (thread_index < senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testUsizeSender, .{ &channel, sends_per_sender });
        }

        while (thread_index < receivers_count + senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testUsizeReceiver, .{ &channel, receives_per_receiver });
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

    pub fn benchmarkSimplePacketBetterChannel(argss: BenchmarkArgs) !sig.time.Duration {
        var thread_handles: [64]?std.Thread = [_]?std.Thread{null} ** 64;
        const n_items = argss.n_items;
        const senders_count = argss.n_senders;
        const receivers_count = argss.n_receivers;
        var timer = try sig.time.Timer.start();

        const allocator = std.heap.c_allocator;
        var channel = try Channel(Packet).init(allocator);
        defer channel.deinit();

        const sends_per_sender: usize = n_items / senders_count;
        const receives_per_receiver: usize = n_items / receivers_count;

        var thread_index: usize = 0;
        while (thread_index < senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testPacketSender, .{ &channel, sends_per_sender });
        }

        while (thread_index < receivers_count + senders_count) : (thread_index += 1) {
            thread_handles[thread_index] = try std.Thread.spawn(.{}, testPacketReceiver, .{ &channel, receives_per_receiver });
        }

        for (0..thread_handles.len) |i| {
            if (thread_handles[i]) |handle| {
                handle.join();
            } else {
                break;
            }
        }

        return timer.read();
    }
};

test "BenchmarkChannel.benchmarkSimplePacketBetterChannel" {
    _ = try BenchmarkChannel.benchmarkSimplePacketBetterChannel(.{
        .name = " 100k_items,   4_senders,   4_receivers ",
        .n_items = 100_000,
        .n_senders = 4,
        .n_receivers = 4,
    });
}
