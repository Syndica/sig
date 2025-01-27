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
    node: List.Node,

    const Direction = enum { sender, receiver };
    const List = std.DoublyLinkedList(Data);
    const Data = struct {
        allocator: Allocator,
        logger: Logger,
        socket: UdpSocket,
        channel: *Channel(Packet),
        exit: ExitCondition,
        direction: Direction,
        packet: ?Packet = null,
        io_pending: bool = false,
        closed: std.Thread.ResetEvent = .{},
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
            .node = .{
                .data = .{
                    .allocator = allocator,
                    .logger = logger,
                    .socket = socket,
                    .channel = channel,
                    .exit = exit,
                    .direction = direction,
                },
            },
        };

        if (direction == .sender) {
            channel.send_hook = &IoThread.send_hook;
        }

        try IoThread.push(&self.node);
        return self;
    }

    pub fn join(self: *SocketThread) void {
        IoThread.pop();
        self.node.data.closed.wait();
        self.node.data.allocator.destroy(self);
    }

    const IoThread = struct {
        var ref_count = std.atomic.Value(usize).init(0);
        var handle: std.Thread = undefined;
        var register = std.atomic.Value(?*List.Node).init(null);
        var notified = std.atomic.Value(bool).init(false);
        var notify_fds: [2]std.posix.fd_t = undefined;
        var send_hook: Channel(Packet).SendHook = .{ .after_send = afterSend };

        fn afterSend(_: *Channel(Packet).SendHook, _: *Channel(Packet)) void {
            IoThread.notify();
        }

        fn push(node: *List.Node) !void {
            if (ref_count.fetchAdd(2, .acquire) == 0) {
                notify_fds = try std.posix.pipe2(.{ .NONBLOCK = true, .CLOEXEC = true });
                handle = try std.Thread.spawn(.{}, run, .{});
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

        fn run() !void {
            var active = List{};
            defer while (active.pop()) |node| close(&node.data, error.Shutdown);

            var pfd = std.BoundedArray(std.posix.pollfd, 256){};
            var data = std.BoundedArray(?*Data, 256){};

            var skipped_io_poll: usize = 0;
            while (ref_count.load(.monotonic) != 1) { // run until shutdown.
                pfd.len = 0;
                data.len = 0;

                // Always listen for IoThread notifications.
                try data.append(null);
                try pfd.append(.{
                    .fd = notify_fds[0],
                    .events = std.posix.POLL.IN,
                    .revents = 0,
                });

                // Take in new SocketThread nodes that were created/registered.
                var pushed = register.swap(null, .acquire);
                while (pushed) |node| {
                    pushed = node.next;
                    active.append(node);
                }

                // Poll all SocketThread nodes (ensures data.exit is checked frequently).
                var ready: usize = 0;
                var iter = active.first;
                while (iter) |node| {
                    iter = node.next;
                    poll(&node.data) catch |e| switch (e) {
                        error.WouldBlock => {
                            node.data.io_pending = true;
                            try data.append(&node.data);
                            try pfd.append(.{
                                .fd = node.data.socket.internal,
                                .events = switch (node.data.direction) {
                                    .sender => std.posix.POLL.OUT,
                                    .receiver => std.posix.POLL.IN,
                                },
                                .revents = 0,
                            });
                        },
                        error.RePoll => {
                            ready += 1;
                        },
                        else => |err| {
                            active.remove(node);
                            close(&node.data, err);
                        },
                    };
                }

                // Skip polling for IO if there's nodes that are still ready to poll again.
                // But make sure not to skip IO polling for too long to avoid starvation.
                if (ready > 0 and skipped_io_poll < 128) {
                    skipped_io_poll += 1;
                    continue;
                }

                const timeout_ms: i32 = if (ready > 0) 0 else 1_000; // if ready, non-blocking poll.
                const io_ready = try std.posix.poll(pfd.slice(), timeout_ms);
                skipped_io_poll = 0;

                if (io_ready > 0) {
                    for (pfd.slice(), data.slice()) |p, maybe_data| {
                        if (p.revents > 0) { // pollfd is ready
                            if (maybe_data) |d| {
                                std.debug.assert(d.io_pending);
                                d.io_pending = false;
                            } else { // IoThread was notified, consume it.
                                var buf = [_]u8{0};
                                const n = try std.posix.read(p.fd, &buf);
                                std.debug.assert(n == 1);
                                std.debug.assert(notified.swap(false, .acquire));
                            }
                        }
                    }
                }
            }
        }

        fn poll(data: *Data) !void {
            if (data.exit.shouldExit()) return error.Exit;
            if (data.io_pending) return error.WouldBlock;

            const logger = data.logger.withScope(LOG_SCOPE);
            switch (data.direction) {
                .sender => {
                    const p = data.packet orelse data.channel.tryReceive() orelse return;
                    data.packet = p;
                    const b = data.socket.sendTo(p.addr, p.data[0..p.size]) catch |e| switch (e) {
                        error.WouldBlock => return error.WouldBlock,
                        else => {
                            logger.err().logf("send socket error: {}", .{e});
                            data.packet = null;
                            return error.RePoll; // on send failure, process another packet.
                        },
                    };
                    std.debug.assert(b == p.size);
                    data.packet = null;
                    return error.RePoll; // send success, process another packet.
                },
                .receiver => {
                    data.packet = data.packet orelse Packet.default();
                    const r = data.socket.receiveFrom(&data.packet.?.data) catch |e| switch (e) {
                        error.WouldBlock => return error.WouldBlock,
                        else => {
                            logger.err().logf("recv socket error: {}\n", .{e});
                            return e;
                        },
                    };
                    if (r.numberOfBytes == 0) return error.SocketClosed;
                    data.packet.?.addr = r.sender;
                    data.packet.?.size = r.numberOfBytes;
                    try data.channel.send(data.packet.?);
                    return error.RePoll; // recv'd packet sent, receive another.
                },
            }
        }

        fn close(data: *Data, err: anyerror) void {
            // Sender drains channel on exit.
            if (data.direction == .sender) {
                while (data.channel.tryReceive()) |_| {}
            }

            const logger = data.logger.withScope(LOG_SCOPE);
            logger.debug().logf("{s} socket loop closed: {}", .{ @tagName(data.direction), err });
            data.exit.afterExit();
            data.closed.set();
        }
    };
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
