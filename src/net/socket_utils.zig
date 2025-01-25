const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");
const network = @import("zig-network");

const Allocator = std.mem.Allocator;
const UdpSocket = network.Socket;

const Packet = sig.net.Packet;
const PACKET_DATA_SIZE = sig.net.PACKET_DATA_SIZE;
const Channel = sig.sync.Channel;
const Logger = sig.trace.Logger;
const ExitCondition = sig.sync.ExitCondition;

pub const SOCKET_TIMEOUT_US: usize = 1 * std.time.us_per_s;
pub const PACKETS_PER_BATCH: usize = 64;

// The identifier for the scoped logger used in this file.
const LOG_SCOPE: []const u8 = "socket_utils";

pub const SocketThread = struct {
    allocator: std.mem.Allocator,
    closed: std.Thread.ResetEvent = .{},
    send_hook: Channel(Packet).SendHook = .{ .after_send = afterSend },

    fn afterSend(_: *Channel(Packet).SendHook, _: *Channel(Packet)) void {
        IoThread.notify();
    }

    const Loop = struct {
        var ring: std.os.linux.IoUring = undefined;
        var retry_submit = SubmitQueue{};

        const SubmitQueue = std.DoublyLinkedList(void);
        const Completion = struct {
            sq: SubmitQueue.Node,
            addr: std.net.Address,
            buf: union {
                recv: struct {
                    msg: std.posix.msghdr,
                    iov: std.posix.iovec,
                },
                send: struct {
                    msg: std.posix.msghdr_const,
                    iov: std.posix.iovec_const,
                },
            },
        };

        pub fn run(notify_fd: std.posix.fd_t) !void {
            ring = try std.os.linux.IoUring.init(256, 0);
            defer ring.deinit();

            var notify_buf = [_]u8{0};
            var notify_sq: SubmitQueue.Node = undefined;
            enqueue(&notify_sq, "read", .{ notify_fd, .{ .buffer = &notify_buf }, 0});

            var ts = std.os.linux.kernel_timespec{ .tv_sec = 1, .tv_nsec = 0 };
            var timer_sq: SubmitQueue.Node = undefined;
            enqueue(&timer_sq, "timeout", .{ &ts, 0, 0 });

            while (IoThread.tick()) {
                _ = try ring.submit_and_wait(@intFromBool(retry_submit.len == 0));

                while (ring.sq_ready() < ring.sq.sqes.len) {
                    const sq = retry_submit.popFirst() orelse break;
                    if (sq == &notify_sq) {
                        enqueue(&notify_sq, "read", .{ notify_fd, .{ .buffer = &notify_buf }, 0});
                    } else if (sq == &timer_sq) {
                        enqueue(&timer_sq, "timeout", .{ &ts, 0, 0 });
                    } else {
                        const c: *Completion = @alignCast(@fieldParentPtr("sq", sq));
                        const data: *@TypeOf(@as(List.Node, undefined).data) = 
                            @alignCast(@fieldParentPtr("completion", c));

                        switch (data.direction) {
                            .sender => enqueue(&c.sq, "sendmsg", .{
                                data.socket.internal,
                                &data.completion.buf.send.msg,
                                0,
                            }),
                            .receiver => enqueue(&c.sq, "recvmsg", .{
                                data.socket.internal,
                                &data.completion.buf.recv.msg,
                                0,
                            }),
                        } 
                    }
                }

                var cqes: [256]std.os.linux.io_uring_cqe = undefined;
                const n = try ring.copy_cqes(&cqes, 0);

                for (cqes[0..n]) |cqe| {
                    const sq: *SubmitQueue.Node = @ptrFromInt(cqe.user_data);
                    if (sq == &notify_sq) {
                        std.debug.assert(IoThread.notified.swap(false, .acquire));
                        enqueue(&notify_sq, "read", .{ notify_fd, .{ .buffer = &notify_buf }, 0});
                    } else if (sq == &timer_sq) {
                        enqueue(&timer_sq, "timeout", .{ &ts, 0, 0 });
                    } else {
                        const c: *Completion = @alignCast(@fieldParentPtr("sq", sq));
                        const data: *@TypeOf(@as(List.Node, undefined).data) = 
                            @alignCast(@fieldParentPtr("completion", c));
                        const node: *List.Node = @alignCast(@fieldParentPtr("data", data));

                        var maybe_err: ?anyerror = null;
                        handle(node, &cqe) catch |e| {
                            maybe_err = e;
                        };

                        IoThread.completed(node, maybe_err);
                    }
                }
            }
        }

        fn handle(node: *List.Node, cqe: *const std.os.linux.io_uring_cqe) !void {
            if (cqe.res < 0) return std.posix.unexpectedErrno(cqe.err());
            const bytes: usize = @intCast(cqe.res);

            switch (node.data.direction) {
                .sender => {
                    std.debug.assert(node.data.packet.size == bytes);
                },
                .receiver => {
                    if (bytes == 0) return error.Eof;
                    node.data.packet.size = bytes;
                    node.data.packet.addr = try network.EndPoint.fromSocketAddress(
                        &node.data.completion.addr.any,
                        node.data.completion.addr.getOsSockLen(),
                    );
                    try node.data.channel.send(node.data.packet);
                },
            }
        }

        pub fn submit(node: *List.Node) !void {
            const c = &node.data.completion;
            switch (node.data.direction) {
                .sender => {
                    var buf = std.BoundedArray(u8, 256){};
                    try buf.writer().print("{}", .{node.data.packet.addr.address});
                    c.addr = try std.net.Address.parseIp(buf.slice(), node.data.packet.addr.port);
                    c.buf = .{
                        .send = .{
                            .msg = undefined,
                            .iov = .{
                                .base = &node.data.packet.data,
                                .len = @intCast(node.data.packet.size),
                            },
                        },
                    };
                    c.buf.send.msg = .{
                        .name = &c.addr.any,
                        .namelen = c.addr.getOsSockLen(),
                        .iov = @ptrCast(&c.buf.send.iov),
                        .iovlen = 1,
                        .control = null,
                        .controllen = 0,
                        .flags = 0,
                    };
                    enqueue(&c.sq, "sendmsg", .{
                        node.data.socket.internal,
                        &c.buf.send.msg,
                        0,
                    });
                },
                .receiver => {
                    c.addr = std.net.Address.initIp4([_]u8{0, 0, 0, 0}, 0);
                    c.buf = .{
                        .recv = .{
                            .msg = undefined,
                            .iov = .{
                                .base = &node.data.packet.data,
                                .len = node.data.packet.data.len,
                            },
                        },
                    };
                    c.buf.recv.msg = .{
                        .name = &c.addr.any,
                        .namelen = c.addr.getOsSockLen(),
                        .iov = @ptrCast(&c.buf.recv.iov),
                        .iovlen = 1,
                        .control = null,
                        .controllen = 0,
                        .flags = 0,
                    };
                    enqueue(&c.sq, "recvmsg", .{
                        node.data.socket.internal,
                        &c.buf.recv.msg,
                        0,
                    });
                },
            }
        }

        fn enqueue(sq: *SubmitQueue.Node, comptime fn_name: []const u8, args: anytype) void {
            const func = @field(@TypeOf(ring), fn_name);
            _ = @call(
                .auto,
                func,
                .{&ring, @intFromPtr(sq)} ++ args,
            ) catch return retry_submit.append(sq);
        }
    };

    const Direction = enum { sender, receiver };
    const List = std.DoublyLinkedList(struct {
        socket: UdpSocket,
        logger: Logger,
        channel: *Channel(Packet),
        direction: Direction,
        exit: ExitCondition,
        allocator: std.mem.Allocator,
        closed: *std.Thread.ResetEvent,
        packet: Packet = undefined,
        completion: Loop.Completion = undefined,
        io_state: enum{ idle, pending, cancelled } = .idle,
    });

    const IoThread = struct {
        var notified = std.atomic.Value(bool).init(false); // amortize notify_fd wakeups
        var notify_fds: [2]std.posix.fd_t = undefined; // wake up the Loop thread
        var ref_count = std.atomic.Value(usize).init(0); // synchronize io_thread spawn/join
        var register = std.atomic.Value(?*List.Node).init(null); // move nodes to the io_thread
        var handle: std.Thread = undefined; // the io_thread handle
        var active: List = .{}; // list of registered nodes to poll on

        fn push(node: *List.Node) !void {
            if (ref_count.fetchAdd(2, .acquire) == 0) {
                notify_fds = try std.posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
                handle = try std.Thread.spawn(.{}, Loop.run, .{notify_fds[0]});
            }

            node.next = register.load(.monotonic);
            while (true) {
                node.next = register.cmpxchgWeak(node.next, node, .release, .monotonic) orelse {
                    break notify();
                };
            }
        }

        fn pop() void {
            if (ref_count.fetchSub(2, .release) == 2) {
                std.debug.assert(ref_count.swap(1, .acquire) == 0);
                defer std.debug.assert(ref_count.swap(0, .release) == 1);

                notify();
                handle.join();
                notified.store(false, .monotonic);
            }
        }

        fn notify() void {
            const already_notified = notified.swap(true, .release);
            if (!already_notified) {
                const n = std.posix.write(notify_fds[1], &[_]u8{'a'}) catch |e| {
                    std.debug.panic("io thread notify signal failed: {}", .{e});
                };
                std.debug.assert(n == 1);
            }
        }

        fn tick() bool {
            const shutdown = ref_count.load(.monotonic) == 1;

            var added = register.swap(null, .acquire);
            while (added) |node| {
                added = node.next;
                active.append(node);
            }

            var iter = active.first;
            while (iter) |node| {
                iter = node.next;
                if (shutdown) {
                    close(node, error.Shutdown);
                } else {
                    poll(node) catch |err| close(node, err);
                }
            }

            return !shutdown;
        }

        fn poll(node: *List.Node) !void {
            if (node.data.exit.shouldExit()) return error.Exit;
            switch (node.data.io_state) {
                .idle => {},
                .pending => return,
                .cancelled => unreachable,
            }

            switch (node.data.direction) {
                .sender => {
                    node.data.packet = node.data.channel.tryReceive() orelse return;
                    node.data.io_state = .pending;
                    try Loop.submit(node);
                },
                .receiver => {
                    node.data.packet = Packet.default();
                    node.data.io_state = .pending;
                    try Loop.submit(node);
                },
            }
        }

        fn completed(node: *List.Node, maybe_err: ?anyerror) void {
            switch (node.data.io_state) {
                .idle => unreachable,
                .pending => node.data.io_state = .idle,
                .cancelled => return node.data.allocator.destroy(node),
            }

            if (maybe_err) |err| {
                const logger = node.data.logger.withScope(LOG_SCOPE);
                switch (node.data.direction) {
                    .sender => {
                        logger.err().logf("send socket error: {s}", .{@errorName(err)});
                        // on error, continue processing the next packet in the channel.
                    },
                    .receiver => {
                        logger.err().logf("recv socket error: {s}", .{@errorName(err)});
                        return close(node, err);
                    }
                }
            }

            poll(node) catch |err| close(node, err);
        } 

        fn close(node: *List.Node, err: anyerror) void {
            // Sender drains channel on exit.
            if (node.data.direction == .sender) {
                while (node.data.channel.tryReceive()) |_| {}
            }

            const logger = node.data.logger.withScope(LOG_SCOPE);
            node.data.exit.afterExit();
            logger.debug().logf("{s} loop closed: {any}", .{@tagName(node.data.direction), err});

            active.remove(node);
            node.data.closed.set();

            switch (node.data.io_state) {
                .idle => node.data.allocator.destroy(node),
                .pending => node.data.io_state = .cancelled,
                .cancelled => unreachable,
            }
        }
    };

    pub fn spawnSender(
        allocator: Allocator,
        logger: Logger,
        socket: UdpSocket,
        outgoing_channel: *Channel(Packet),
        exit: ExitCondition,
    ) !*SocketThread {
        return spawn(allocator, logger, socket, outgoing_channel, exit, .sender);
    }

    pub fn spawnReceiver(
        allocator: Allocator,
        logger: Logger,
        socket: UdpSocket,
        incoming_channel: *Channel(Packet),
        exit: ExitCondition,
    ) !*SocketThread {
        return spawn(allocator, logger, socket, incoming_channel, exit, .receiver);
    }

    fn spawn(
        allocator: Allocator,
        logger: Logger,
        socket: UdpSocket,
        channel: *Channel(Packet),
        exit: ExitCondition,
        direction: Direction,
    ) !*SocketThread {
        // Make socket non-blocking.
        var flags = try std.posix.fcntl(socket.internal, std.posix.F.GETFL, 0);
        flags |= @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }));
        _ = try std.posix.fcntl(socket.internal, std.posix.F.SETFL, flags);

        const self = try allocator.create(SocketThread);
        errdefer allocator.destroy(self);
        self.* = .{
            .allocator = allocator,
        };

        const node = try allocator.create(List.Node);
        errdefer allocator.destroy(self);
        node.* = .{
            .data = .{
                .allocator = allocator,
                .logger = logger,
                .socket = socket,
                .channel = channel,
                .exit = exit,
                .direction = direction,
                .closed = &self.closed,
            },
        };

        if (direction == .sender) {
            channel.send_hook = &self.send_hook;
        }

        try IoThread.push(node);
        return self;
    }

    pub fn join(self: *SocketThread) void {
        IoThread.pop();
        self.closed.wait();
        self.allocator.destroy(self);
    }
};

pub const BenchmarkPacketProcessing = struct {
    pub const min_iterations = 1;
    pub const max_iterations = 20;

    pub const BenchmarkArgs = struct {
        n_packets: usize,
        name: []const u8 = "",
    };

    pub const args = [_]BenchmarkArgs{
        BenchmarkArgs{
            .n_packets = 100_000,
            .name = "100k_msgs",
        },
    };

    pub fn benchmarkReadSocket(bench_args: BenchmarkArgs) !sig.time.Duration {
        const n_packets = bench_args.n_packets;
        const allocator = if (builtin.is_test) std.testing.allocator else std.heap.c_allocator;

        var socket = try UdpSocket.create(.ipv4, .udp);
        try socket.bindToPort(0);
        try socket.setReadTimeout(std.time.us_per_s); // 1 second

        const to_endpoint = try socket.getLocalEndPoint();

        var exit_flag = std.atomic.Value(bool).init(false);
        const exit_condition = ExitCondition{ .unordered = &exit_flag };

        // Setup incoming

        var incoming_channel = try Channel(Packet).init(allocator);
        defer incoming_channel.deinit();

        const incoming_pipe = try SocketThread.spawnReceiver(
            allocator,
            .noop,
            socket,
            &incoming_channel,
            exit_condition,
        );
        defer incoming_pipe.join();

        // Start outgoing

        const S = struct {
            fn sender(channel: *Channel(Packet), addr: network.EndPoint, e: ExitCondition) !void {
                var i: usize = 0;
                var packet: Packet = undefined;
                var prng = std.rand.DefaultPrng.init(0);
                var timer = try std.time.Timer.start();

                while (e.shouldRun()) {
                    prng.fill(&packet.data);
                    packet.addr = addr;
                    packet.size = PACKET_DATA_SIZE;
                    try channel.send(packet);

                    // 10Kb per second, until one second
                    // each packet is 1k bytes
                    // = 10 packets per second
                    i += 1;
                    if (i % 10 == 0) {
                        const elapsed = timer.read();
                        if (elapsed < std.time.ns_per_s) {
                            std.time.sleep(std.time.ns_per_s);
                        }
                    }
                }
            }
        };

        var outgoing_channel = try Channel(Packet).init(allocator);
        defer outgoing_channel.deinit();

        const outgoing_pipe = try SocketThread.spawnSender(
            allocator,
            .noop,
            socket,
            &outgoing_channel,
            exit_condition,
        );
        defer outgoing_pipe.join();

        const outgoing_handle = try std.Thread.spawn(
            .{},
            S.sender,
            .{ &outgoing_channel, to_endpoint, exit_condition },
        );
        defer outgoing_handle.join();

        // run incoming until received n_packets

        var packets_to_recv = n_packets;
        var timer = try sig.time.Timer.start();
        while (packets_to_recv > 0) {
            incoming_channel.waitToReceive(exit_condition) catch break;
            while (incoming_channel.tryReceive()) |_| {
                packets_to_recv -|= 1;
            }
        }

        exit_condition.setExit(); // kill benchSender and join it on defer.
        return timer.read();
    }
};

test "benchmark packet processing" {
    _ = try BenchmarkPacketProcessing.benchmarkReadSocket(.{
        .n_packets = 100_000,
    });
}
