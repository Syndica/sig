const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const sig = @import("../sig.zig");
const Packet = sig.net.Packet;
const PACKET_DATA_SIZE = sig.net.PACKET_DATA_SIZE;
const Channel = sig.sync.Channel;
const Logger = sig.trace.Logger;
const ExitCondition = sig.sync.ExitCondition;

const xev = @import("xev");

const network = @import("zig-network");
const UdpSocket = network.Socket;

pub const SOCKET_TIMEOUT_US: usize = 1 * std.time.us_per_s;
pub const PACKETS_PER_BATCH: usize = 64;

// The identifier for the scoped logger used in this file.
const LOG_SCOPE: []const u8 = "socket_utils";

const XevLoop = struct {
    const Udp = struct {
        socket: xev.UDP,
        state: xev.UDP.State = undefined,
        completion: xev.Completion = undefined,

        fn init(socket: UdpSocket) Udp {
            return .{ .socket = xev.UDP.initFd(socket.internal) };
        }
    };

    var event: xev.Async = undefined;
    var loop: xev.Loop = undefined;

    fn spawn() !std.Thread {
        event = try xev.Async.init();
        return std.Thread.spawn(.{}, run, .{});
    }

    fn run() !void {
        loop = try xev.Loop.init(.{});
        defer loop.deinit();

        var completion: xev.Completion = undefined;
        event.wait(&loop, &completion, void, null, onEventNotified);

        try loop.run(.until_done);
    }

    fn notify() void {
        event.notify() catch |e| std.debug.panic("Loop notification failed: {}", .{e});
    }

    fn onEventNotified(
        _: ?*void,
        _: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        result catch |e| std.debug.panic("Loop notification event wait failed: {}", .{e});
        if (SocketPipe.tick()) {
            event.wait(&loop, completion, void, null, onEventNotified);
        } else {
            loop.stop();
        }
        return .disarm;
    }

    fn poll(pipe: *SocketPipe) !void {
        return pollWith(pipe, null);
    }

    const RecvResult = struct {
        bytes: usize,
        addr: std.net.Address,
    };

    fn pollWith(pipe: *SocketPipe, maybe_result_ptr: ?*const anyopaque) !void {
        const logger = pipe.logger.withScope(LOG_SCOPE);
        errdefer |err| {
            // Sender drains the channel when closing.
            if (pipe.direction == .sender) {
                while (pipe.channel.tryReceive()) |_| {}
            }

            pipe.exit.afterExit();
            logger.debug().logf("{s} loop closed: {}", .{ @tagName(pipe.direction), err });
            SocketPipe.close(pipe);
        }

        if (pipe.exit.shouldExit()) {
            return error.Exit;
        }

        switch (pipe.direction) {
            .sender => {
                if (maybe_result_ptr) |ptr| {
                    const bytes = try @as(*const anyerror!usize, @alignCast(@ptrCast(ptr))).*;
                    std.debug.assert(bytes == pipe.active.?.size);
                    pipe.active = null;
                } else if (pipe.active != null) {
                    return;
                }

                pipe.active = pipe.channel.tryReceive() orelse return;
                pipe.udp.socket.write(
                    &loop,
                    &pipe.udp.completion,
                    &pipe.udp.state,
                    b: {
                        var buf = std.BoundedArray(u8, 256){};
                        try buf.writer().print("{}", .{pipe.active.?.addr.address});
                        break :b try std.net.Address.parseIp(buf.slice(), pipe.active.?.addr.port);
                    },
                    .{ .slice = pipe.active.?.data[0..pipe.active.?.size] },
                    SocketPipe,
                    pipe,
                    onSend,
                );
            },
            .receiver => {
                if (maybe_result_ptr) |ptr| {
                    const result = try @as(*const anyerror!RecvResult, @alignCast(@ptrCast(ptr))).*;
                    pipe.active.?.size = result.bytes;
                    pipe.active.?.addr = blk: {
                        var buf = std.BoundedArray(u8, 256){};
                        try buf.writer().print("{}", .{result.addr});
                        break :blk try network.EndPoint.parse(buf.slice());
                    };
                    try pipe.channel.send(pipe.active.?);
                } else if (pipe.active != null) {
                    return;
                }

                pipe.active = Packet.default();
                pipe.udp.socket.read(
                    &loop,
                    &pipe.udp.completion,
                    &pipe.udp.state,
                    .{ .slice = &pipe.active.?.data },
                    SocketPipe,
                    pipe,
                    onRecv,
                );
            },
        }
    }

    fn onSend(
        maybe_pipe: ?*SocketPipe,
        _: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        _: xev.UDP,
        _: xev.WriteBuffer,
        xev_result: xev.UDP.WriteError!usize,
    ) xev.CallbackAction {
        const pipe = maybe_pipe.?;
        const result: anyerror!usize = xev_result;
        pollWith(pipe, &result) catch {};
        return .disarm;
    }

    fn onRecv(
        maybe_pipe: ?*SocketPipe,
        _: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        peer_addr: std.net.Address,
        _: xev.UDP,
        _: xev.ReadBuffer,
        xev_result: xev.UDP.ReadError!usize,
    ) xev.CallbackAction {
        const pipe = maybe_pipe.?;
        const result: anyerror!RecvResult = blk: {
            const bytes = xev_result catch |err| break :blk err;
            break :blk RecvResult{ .bytes = bytes, .addr = peer_addr };
        };
        pollWith(pipe, &result) catch {};
        return .disarm;
    }
};

const SyscallLoop = struct {
    // TODO: on error.WouldBlock, register to std.posix.poll(). Write to pipe on notify() to wake.
    const Udp = struct {
        fn init(_: UdpSocket) Udp {
            return .{};
        }
    };

    fn spawn() !std.Thread {
        return std.Thread.spawn(.{}, run, .{});
    }

    fn run() !void {
        while (SocketPipe.tick()) {}
    }

    fn notify() void {
        // Empty. See todo above.
    }

    fn poll(pipe: *SocketPipe) !void {
        const logger = pipe.logger.withScope(LOG_SCOPE);
        errdefer |err| {
            // Sender drains the channel when closing.
            if (pipe.direction == .sender) {
                while (pipe.channel.tryReceive()) |_| {}
            }
            pipe.exit.afterExit();
            logger.debug().logf("{s} loop closed: {}", .{ @tagName(pipe.direction), err });
            SocketPipe.close(pipe);
        }

        if (pipe.exit.shouldExit()) {
            return error.Exit;
        }

        switch (pipe.direction) {
            .sender => while (true) {
                const p = pipe.active orelse pipe.channel.tryReceive() orelse return;
                pipe.active = p;

                const sent = pipe.socket.sendTo(p.addr, p.data[0..p.size]) catch |e| switch (e) {
                    error.WouldBlock => return,
                    else => |err| {
                        logger.err().logf("send socket error: {s}", .{@errorName(err)});
                        continue;
                    },
                };
                std.debug.assert(sent == p.size);
                pipe.active = null;
                return;
            },
            .receiver => {
                var p = Packet.default();
                const recv = pipe.socket.receiveFrom(&p.data) catch |e| switch (e) {
                    error.WouldBlock => return,
                    else => |err| {
                        logger.err().logf("recv socket error: {s}", .{@errorName(err)});
                        return err;
                    },
                };
                p.size = recv.numberOfBytes;
                p.addr = recv.sender;
                try pipe.channel.send(p);
            },
        }
    }
};

const Loop = switch (builtin.os.tag) {
    .linux => XevLoop,
    else => SyscallLoop,
};

pub const SocketPipe = struct {
    direction: Direction,
    logger: Logger,
    socket: UdpSocket,
    channel: *Channel(Packet),
    exit: ExitCondition,
    udp: Loop.Udp,
    active: ?Packet = null,
    closed: std.Thread.ResetEvent = .{},

    const List = std.DoublyLinkedList(SocketPipe);

    var send_hook: Channel(Packet).SendHook = .{ .after_send = afterSend };
    var register = std.atomic.Value(?*List.Node).init(null);
    var ref_count = std.atomic.Value(usize).init(0);
    var notified = std.atomic.Value(bool).init(false);
    var handle: std.Thread = undefined;
    var active = List{};

    pub const Direction = enum {
        sender,
        receiver,
    };

    pub fn init(
        allocator: Allocator,
        direction: Direction,
        logger: Logger,
        socket: UdpSocket,
        channel: *Channel(Packet),
        exit: ExitCondition,
    ) !*SocketPipe {
        // Make the socket non-blocking.
        var flags = try std.posix.fcntl(socket.internal, std.posix.F.GETFL, 0);
        flags |= @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }));
        _ = try std.posix.fcntl(socket.internal, std.posix.F.SETFL, flags);

        const node = try allocator.create(List.Node);
        errdefer allocator.destroy(node);

        node.* = .{
            .data = .{
                .direction = direction,
                .logger = logger,
                .socket = socket,
                .channel = channel,
                .exit = exit,
                .udp = Loop.Udp.init(socket),
            },
        };

        // Reference the global event loop and start it if we're the first one.
        if (ref_count.fetchAdd(2, .acquire) == 0) {
            handle = try Loop.spawn();
        }

        // Push the node to the register stack & notify the loop to start using it.
        node.next = register.load(.monotonic);
        while (true) {
            node.next = register.cmpxchgWeak(node.next, node, .release, .monotonic) orelse {
                if (!notified.swap(true, .release)) Loop.notify();
                break;
            };
        }

        if (direction == .sender) {
            channel.send_hook = &send_hook;
        }

        return &node.data;
    }

    fn afterSend(_: *Channel(Packet).SendHook, _: *Channel(Packet)) void {
        if (!notified.swap(true, .release)) Loop.notify();
    }

    fn tick() bool {
        // Reset notified state & move all registered SocketPipes into active.
        if (notified.load(.acquire)) {
            notified.store(false, .monotonic);
            var added = register.swap(null, .acquire);
            while (added) |node| {
                added = node.next;
                active.append(node);
            }
        }

        // Iterate active SocketPipes, polling them or cancelling them.
        const shutdown = ref_count.load(.monotonic) == 1;
        var iter = active.first;
        while (iter) |node| {
            iter = node.next;
            if (shutdown) {
                close(&node.data);
            } else {
                Loop.poll(&node.data) catch {};
            }
        }

        return !shutdown;
    }

    fn close(self: *SocketPipe) void {
        const node: *List.Node = @alignCast(@fieldParentPtr("data", self));
        active.remove(node);
        self.closed.set();
    }

    pub fn deinit(self: *SocketPipe, allocator: Allocator) void {
        if (ref_count.fetchSub(2, .release) == 2) {
            std.debug.assert(ref_count.swap(1, .acquire) == 0);
            if (!notified.swap(true, .release)) Loop.notify();
            handle.join();
            std.debug.assert(ref_count.swap(0, .release) == 1);
        }

        const node: *List.Node = @alignCast(@fieldParentPtr("data", self));
        self.closed.wait();
        allocator.destroy(node);
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

        const incoming_pipe = try SocketPipe
            .init(allocator, .receiver, .noop, socket, &incoming_channel, exit_condition);
        defer incoming_pipe.deinit(allocator);

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

        const outgoing_pipe = try SocketPipe
            .init(allocator, .sender, .noop, socket, &outgoing_channel, exit_condition);
        defer outgoing_pipe.deinit(allocator);

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
            incoming_channel.wait(exit_condition) catch break;
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
