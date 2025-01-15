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

pub const SocketPipe = struct {
    direction: Direction,
    logger: Logger,
    channel: *Channel(Packet),
    exit: ExitCondition,
    udp: xev.UDP,
    state: xev.UDP.State = undefined,
    completion: xev.Completion = undefined,
    active: ?Packet = null,
    closed: std.Thread.ResetEvent = .{},

    const List = std.DoublyLinkedList(SocketPipe);

    var send_hook: Channel(Packet).SendHook = .{ .after_send = afterSend };
    var register = std.atomic.Value(?*List.Node).init(null);
    var ref_count = std.atomic.Value(usize).init(0);
    var notified = std.atomic.Value(bool).init(false);
    var handle: std.Thread = undefined;
    var event: xev.Async = undefined;
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
                .channel = channel,
                .exit = exit,
                .udp = xev.UDP.initFd(socket.internal),
            },
        };

        // Reference the global event loop and start it if we're the first one.
        if (ref_count.fetchAdd(2, .acquire) == 0) {
            event = try xev.Async.init();
            handle = try std.Thread.spawn(.{}, runEventLoop, .{});
        }

        // Push the node to the register stack & notify the loop to start using it.
        node.next = register.load(.monotonic);
        while (true) {
            node.next = register.cmpxchgWeak(node.next, node, .release, .monotonic) orelse {
                notifyEventLoop();
                break;
            };
        }

        // When a sender channel receives a message, tell the event loop to wake up to send it.
        if (direction == .sender) {
            channel.send_hook = &send_hook;
        }

        return &node.data;
    }

    fn afterSend(_: *Channel(Packet).SendHook, _: *Channel(Packet)) void {
        notifyEventLoop();
    }

    fn notifyEventLoop() void {
        if (!notified.swap(true, .release)) {
            event.notify() catch @panic("failed to notify global event loop");
        }
    }

    fn runEventLoop() !void {
        var loop = try xev.Loop.init(.{});
        defer loop.deinit();

        // on channel sends or shutdown, trigger pollEventLoop.
        var event_completion: xev.Completion = undefined;
        event.wait(&loop, &event_completion, void, null, onEventLoopNotify);

        // Every once in a while, trigger pollEventLoop to check SocketPipe.exit flags.
        var timer = try xev.Timer.init();
        defer timer.deinit();
        var timer_completion: xev.Completion = undefined;
        timer.run(&loop, &timer_completion, SOCKET_TIMEOUT_US, void, null, onEventLoopTick);

        try loop.run(.until_done);
    }

    fn onEventLoopTick(
        _: ?*void,
        loop: *xev.Loop,
        _: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        result catch |e| std.debug.panic("event loop timer failed: {}", .{e});
        return if (pollEventLoop(loop)) .rearm else .disarm;
    }

    fn onEventLoopNotify(
        _: ?*void,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        result catch |e| std.debug.panic("event loop wait failed: {}", .{e});
        if (pollEventLoop(loop)) {
            event.wait(loop, completion, void, null, onEventLoopNotify);
        }
        return .disarm;
    }

    fn pollEventLoop(loop: *xev.Loop) bool {
        // Reset notified state & move all registered SocketPipes into active.
        const shutdown = ref_count.load(.monotonic) == 1;
        if (notified.load(.acquire)) {
            notified.store(false, .monotonic);
            var added = register.swap(null, .acquire);
            while (added) |node| {
                added = node.next;
                active.append(node);
            }
        }

        // Iterate active SocketPipes, polling or closing them.
        var iter = active.first;
        while (iter) |node| {
            iter = node.next;
            if (shutdown) {
                node.data.close(error.LoopShutdown);
            } else {
                node.data.poll(loop) catch |err| node.data.close(err);
            }
        }

        if (shutdown) loop.stop();
        return !shutdown;
    }

    fn poll(self: *SocketPipe, loop: *xev.Loop) !void {
        if (self.exit.shouldExit()) return error.Exit;
        if (self.active != null) return;
        switch (self.direction) {
            .sender => {
                self.active = self.channel.tryReceive() orelse return;
                self.udp.write(
                    loop,
                    &self.completion,
                    &self.state,
                    b: {
                        var buf = std.BoundedArray(u8, 256){};
                        try buf.writer().print("{}", .{self.active.?.addr.address});
                        break :b try std.net.Address.parseIp(buf.slice(), self.active.?.addr.port);
                    },
                    .{ .slice = self.active.?.data[0..self.active.?.size] },
                    SocketPipe,
                    self,
                    onSend,
                );
            },
            .receiver => {
                self.active = Packet.default();
                self.udp.read(
                    loop,
                    &self.completion,
                    &self.state,
                    .{ .slice = &self.active.?.data },
                    SocketPipe,
                    self,
                    onRecv,
                );
            },
        }
    }

    fn onSend(
        maybe_self: ?*SocketPipe,
        loop: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        _: xev.UDP,
        _: xev.WriteBuffer,
        xev_result: xev.UDP.WriteError!usize,
    ) xev.CallbackAction {
        const self = maybe_self.?;
        self.handleSend(loop, xev_result) catch |err| self.close(err);
        return .disarm;
    }

    fn handleSend(self: *SocketPipe, loop: *xev.Loop, result: xev.UDP.WriteError!usize) !void {
        if (result) |bytes| {
            std.debug.assert(bytes == self.active.?.size);
        } else |err| {
            const logger = self.logger.withScope(LOG_SCOPE);
            logger.err().logf("send socket error: {}", .{err});
        }

        self.active = null;
        try self.poll(loop);
    }

    fn onRecv(
        maybe_self: ?*SocketPipe,
        loop: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        peer_addr: std.net.Address,
        _: xev.UDP,
        _: xev.ReadBuffer,
        xev_result: xev.UDP.ReadError!usize,
    ) xev.CallbackAction {
        const self = maybe_self.?;
        self.handleReceive(loop, peer_addr, xev_result) catch |err| self.close(err);
        return .disarm;
    }

    fn handleReceive(
        self: *SocketPipe,
        loop: *xev.Loop,
        address: std.net.Address,
        result: xev.UDP.ReadError!usize,
    ) !void {
        const bytes = try result;
        self.active.?.size = bytes;
        self.active.?.addr = b: {
            var buf = std.BoundedArray(u8, 256){};
            try buf.writer().print("{}", .{address});
            break :b try network.EndPoint.parse(buf.slice());
        };

        try self.channel.send(self.active.?);
        self.active = null;
        try self.poll(loop);
    }

    fn close(self: *SocketPipe, err: anyerror) void {
        // Sender drains the channel when closing.
        // if (self.direction == .sender) {
        //     while (self.channel.tryReceive()) |_| {}
        // }

        const logger = self.logger.withScope(LOG_SCOPE);
        self.exit.afterExit();
        logger.debug().logf("{s} loop closed: {}", .{ @tagName(self.direction), err });

        const node: *List.Node = @alignCast(@fieldParentPtr("data", self));
        active.remove(node);
        self.closed.set();
    }

    pub fn deinit(self: *SocketPipe, allocator: Allocator) void {
        if (ref_count.fetchSub(2, .release) == 2) {
            std.debug.assert(ref_count.swap(1, .acquire) == 0);
            notifyEventLoop();
            handle.join();
            event.deinit();
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
