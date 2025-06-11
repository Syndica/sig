const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../sig.zig");
const network = @import("zig-network");
const xev = @import("xev");

const Allocator = std.mem.Allocator;
const UdpSocket = network.Socket;

const Packet = sig.net.Packet;
const PACKET_DATA_SIZE = Packet.DATA_SIZE;
const Channel = sig.sync.Channel;
const Logger = sig.trace.Logger;
const ExitCondition = sig.sync.ExitCondition;

pub const SOCKET_TIMEOUT_US: usize = 1 * std.time.us_per_s;
pub const PACKETS_PER_BATCH: usize = 64;

// The identifier for the scoped logger used in this file.
const LOG_SCOPE: []const u8 = "socket_utils";

const XevThread = struct {
    pub const Handle = std.Thread.ResetEvent;

    const List = std.DoublyLinkedList(struct {
        allocator: Allocator,
        st: ?*SocketThread,
        packet: Packet = undefined,
        udp: xev.UDP,
        udp_state: xev.UDP.State = undefined,
        udp_completion: xev.Completion = undefined,
        io: enum { idle, pending, cancelled } = .idle,
    });

    const RefCount = packed struct(u32) {
        shutdown: bool = false,
        active: u31 = 0,
    };

    var ref_count = std.atomic.Value(u32).init(0); // Ref
    var register = std.atomic.Value(?*List.Node).init(null);
    var io_notified = std.atomic.Value(bool).init(false);
    var io_thread: std.Thread = undefined;
    var io_event: xev.Async = undefined;
    var active = List{};

    pub fn spawn(st: *SocketThread) !void {
        // Make the socket non-blocking (required by xev).
        var flags = try std.posix.fcntl(st.socket.internal, std.posix.F.GETFL, 0);
        flags |= @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }));
        _ = try std.posix.fcntl(st.socket.internal, std.posix.F.SETFL, flags);

        const rc: RefCount = @bitCast(ref_count.fetchAdd(
            @bitCast(RefCount{ .active = 1 }),
            .acquire,
        ));
        std.debug.assert(!rc.shutdown);
        std.debug.assert(rc.active < std.math.maxInt(@TypeOf(rc.active)));

        // Start xev thread if not running.
        if (rc.active == 0) {
            io_notified.store(false, .monotonic);
            io_event = try xev.Async.init();
            io_thread = try std.Thread.spawn(.{}, runIoThread, .{});
        }

        // When a sender SocketThread receives a message, it needs to wake up xev to udp send it.
        if (st.direction == .sender) {
            st.channel.send_hook = &(struct {
                var send_hook: Channel(Packet).SendHook = .{ .after_send = afterSend };
                fn afterSend(_: *Channel(Packet).SendHook, _: *Channel(Packet)) void {
                    notifyIoThread();
                }
            }).send_hook;
        }

        // When the node exits, it will trigger this event.
        st.handle = std.Thread.ResetEvent{};

        // Create a node for the SocketThread
        const node = try st.allocator.create(List.Node);
        node.* = .{
            .data = .{
                .allocator = st.allocator,
                .st = st,
                .udp = xev.UDP.initFd(st.socket.internal),
            },
        };

        // Push the node to the register stack & wake the xev thread to start handling it.
        node.next = register.load(.monotonic);
        while (true) {
            node.next = register.cmpxchgWeak(node.next, node, .release, .monotonic) orelse {
                break notifyIoThread();
            };
        }
    }

    pub fn join(st: *SocketThread) void {
        var rc: RefCount = @bitCast(ref_count.fetchSub(
            @bitCast(RefCount{ .active = 1 }),
            .release,
        ));
        std.debug.assert(!rc.shutdown);
        std.debug.assert(rc.active >= 1);

        // The last SocketThread to join will stop the xev thread.
        if (rc.active == 1) {
            // Lock the ref_count to detect if theres races (i.e. another spawn()) during shutdown.
            rc = @bitCast(ref_count.swap(@bitCast(RefCount{ .shutdown = true }), .acquire));
            std.debug.assert(rc == .{});

            defer {
                rc = @bitCast(ref_count.swap(@bitCast(RefCount{}), .release));
                std.debug.assert(rc == .{ .shutdown = true });
            }

            notifyIoThread(); // wake up xev thread to see ref_count.shutdown to stop/shutdown
            io_thread.join();
            io_event.deinit();
        }

        st.handle.wait();
    }

    fn notifyIoThread() void {
        const already_notified = io_notified.swap(true, .release);
        if (!already_notified) {
            io_event.notify() catch std.debug.panic("failed to notify xev event loop", .{});
        }
    }

    fn runIoThread() !void {
        var loop = try xev.Loop.init(.{});
        defer loop.deinit();

        // Trigger pollIo() when the xev thread is notified from outside (channel send, shutdown).
        var io_event_completion: xev.Completion = undefined;
        io_event.wait(&loop, &io_event_completion, void, null, onNotify);

        // Every once in a while, trigger pollIo() to check SocketThread.exit flags.
        var timer = try xev.Timer.init();
        defer timer.deinit();
        var timer_completion: xev.Completion = undefined;
        timer.run(&loop, &timer_completion, SOCKET_TIMEOUT_US, xev.Timer, &timer, onTick);

        try loop.run(.until_done);
    }

    fn onNotify(
        _: ?*void,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Async.WaitError!void,
    ) xev.CallbackAction {
        result catch |e| std.debug.panic("xev notify event failed: {}", .{e});
        std.debug.assert(io_notified.swap(false, .acquire));

        pollIo(loop);
        io_event.wait(loop, completion, void, null, onNotify);
        return .disarm;
    }

    fn onTick(
        timer: ?*xev.Timer,
        loop: *xev.Loop,
        completion: *xev.Completion,
        result: xev.Timer.RunError!void,
    ) xev.CallbackAction {
        result catch |e| std.debug.panic("xev notify event failed: {}", .{e});

        pollIo(loop);
        timer.?.run(loop, completion, SOCKET_TIMEOUT_US, xev.Timer, timer, onTick);
        return .disarm;
    }

    fn pollIo(loop: *xev.Loop) void {
        const shutdown = @as(RefCount, @bitCast(ref_count.load(.acquire))).shutdown;
        defer if (shutdown) loop.stop();

        // Move registered nodes into the active list.
        var pushed = register.swap(null, .acquire);
        while (pushed) |node| {
            pushed = node.next;
            active.append(node);
        }

        // Iterate active nodes and poll them. If shutting down, close them instead.
        var iter = active.first;
        while (iter) |node| {
            iter = node.next;
            if (shutdown) {
                closeNode(node, error.Shutdown);
            } else {
                pollNode(node, loop) catch |e| closeNode(node, e);
            }
        }
    }

    fn pollNode(node: *List.Node, loop: *xev.Loop) !void {
        const st = node.data.st.?;
        if (st.exit.shouldExit()) return error.Exit;

        switch (node.data.io) {
            .idle => {}, // start new IO operation below.
            .pending => return, // IO operation already running.
            .cancelled => unreachable, // only observable in onSend/onRecv callback.
        }

        const addr = node.data.packet.addr;
        switch (st.direction) {
            .sender => {
                node.data.packet = st.channel.tryReceive() orelse return;
                node.data.io = .pending;
                node.data.udp.write(
                    loop,
                    &node.data.udp_completion,
                    &node.data.udp_state,
                    switch (addr.address) {
                        .ipv4 => |ipv4| std.net.Address.initIp4(ipv4.value, addr.port),
                        .ipv6 => @panic("TODO: ipv6 support"),
                    },
                    .{ .slice = node.data.packet.data() },
                    List.Node,
                    node,
                    onSend,
                );
            },
            .receiver => {
                node.data.packet = Packet.ANY_EMPTY;
                node.data.io = .pending;
                node.data.udp.read(
                    loop,
                    &node.data.udp_completion,
                    &node.data.udp_state,
                    .{ .slice = &node.data.packet.buffer },
                    List.Node,
                    node,
                    onRecv,
                );
            },
        }
    }

    fn closeNode(node: *List.Node, err: anyerror) void {
        const st = node.data.st.?;
        node.data.st = null;

        // Sender drains the channel when closing.
        if (st.direction == .sender) {
            while (st.channel.tryReceive()) |_| {}
        }

        const logger = st.logger.withScope(LOG_SCOPE);
        logger.debug().logf("{s} loop closed: {}", .{ @tagName(st.direction), err });
        st.exit.afterExit();

        // Unregister node and signal SocketThread to deinit/dealloc itself (node may live on).
        active.remove(node);
        st.handle.set();

        switch (node.data.io) {
            .idle => node.data.allocator.destroy(node),
            .pending => node.data.io = .cancelled, // tell onSend/onRecv callback to free itself.
            .cancelled => unreachable, // only observable in onSend/onRecv callback.
        }
    }

    fn getNodeOnCallback(node: *List.Node) ?*List.Node {
        switch (node.data.io) {
            .idle => unreachable, // IO just finished, it must have been started.
            .pending => { // IO finished as normal.
                node.data.io = .idle;
                return node;
            },
            .cancelled => { // The node was closed during IO. Deallocate it now.
                node.data.allocator.destroy(node);
                return null;
            },
        }
    }

    fn onSend(
        maybe_node: ?*List.Node,
        loop: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        _: xev.UDP,
        _: xev.WriteBuffer,
        result: xev.UDP.WriteError!usize,
    ) xev.CallbackAction {
        if (getNodeOnCallback(maybe_node.?)) |node| {
            handleSend(node, loop, result) catch |e| closeNode(node, e);
        }
        return .disarm;
    }

    fn handleSend(
        node: *List.Node,
        loop: *xev.Loop,
        result: xev.UDP.WriteError!usize,
    ) !void {
        const st = node.data.st.?;
        const logger = st.logger.withScope(LOG_SCOPE);

        if (result) |bytes_sent| {
            std.debug.assert(node.data.packet.size == bytes_sent);
        } else |err| { // On send error, skip packet and proces next in pollNode
            logger.err().logf("send socket error: {}", .{err});
        }

        try pollNode(node, loop);
    }

    fn onRecv(
        maybe_node: ?*List.Node,
        loop: *xev.Loop,
        _: *xev.Completion,
        _: *xev.UDP.State,
        peer_addr: std.net.Address,
        _: xev.UDP,
        _: xev.ReadBuffer,
        result: xev.UDP.ReadError!usize,
    ) xev.CallbackAction {
        if (getNodeOnCallback(maybe_node.?)) |node| {
            handleRecv(node, loop, peer_addr, result) catch |e| closeNode(node, e);
        }
        return .disarm;
    }

    fn handleRecv(
        node: *List.Node,
        loop: *xev.Loop,
        peer_addr: std.net.Address,
        result: xev.UDP.ReadError!usize,
    ) !void {
        const st = node.data.st.?;
        const logger = st.logger.withScope(LOG_SCOPE);

        node.data.packet.size = result catch |err| {
            logger.err().logf("recv socket error: {}", .{err});
            return err;
        };

        node.data.packet.addr = blk: {
            var buf = std.BoundedArray(u8, 256){};
            try buf.writer().print("{}", .{peer_addr});
            break :blk try network.EndPoint.parse(buf.slice());
        };

        try st.channel.send(node.data.packet);
        try pollNode(node, loop);
    }
};

const PerThread = struct {
    pub const Handle = std.Thread;

    pub fn spawn(st: *SocketThread) !void {
        st.handle = switch (st.direction) {
            .sender => try std.Thread.spawn(.{}, runSender, .{st}),
            .receiver => try std.Thread.spawn(.{}, runReceiver, .{st}),
        };
    }

    pub fn join(st: *SocketThread) void {
        st.handle.join();
    }

    fn runReceiver(st: *SocketThread) !void {
        const logger = st.logger.withScope(LOG_SCOPE);
        defer {
            st.exit.afterExit();
            logger.info().log("readSocket loop closed");
        }

        // NOTE: we set a timeout to periodically check if we should exit
        try st.socket.setReadTimeout(SOCKET_TIMEOUT_US);

        while (st.exit.shouldRun()) {
            var packet: Packet = Packet.ANY_EMPTY;
            const recv_meta = st.socket.receiveFrom(&packet.buffer) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| {
                    logger.err().logf("readSocket error: {s}", .{@errorName(e)});
                    return e;
                },
            };
            const bytes_read = recv_meta.numberOfBytes;
            if (bytes_read == 0) return error.SocketClosed;
            packet.addr = recv_meta.sender;
            packet.size = bytes_read;
            try st.channel.send(packet);
        }
    }

    fn runSender(st: *SocketThread) !void {
        const logger = st.logger.withScope(LOG_SCOPE);
        defer {
            // empty the channel
            while (st.channel.tryReceive()) |_| {}
            st.exit.afterExit();
            logger.debug().log("sendSocket loop closed");
        }

        while (true) {
            st.channel.waitToReceive(st.exit) catch break;

            next_packet: while (st.channel.tryReceive()) |p| {
                const bytes_sent = while (true) { // loop on error.SystemResources below.
                    if (st.exit.shouldExit()) return; // drop packets if exit prematurely.
                    break st.socket.sendTo(p.addr, p.data()) catch |e| switch (e) {
                        // on macOS, sendto() returns ENOBUFS on full buffer instead of blocking.
                        // Wait for the socket to be writable (buffer has room) and retry.
                        error.SystemResources => {
                            var fds = [_]std.posix.pollfd{.{
                                .fd = st.socket.internal,
                                .events = std.posix.POLL.OUT,
                                .revents = 0,
                            }};
                            _ = try std.posix.poll(&fds, 1000); // poll at most 1s to check exit.
                            continue;
                        },
                        else => {
                            logger.err().logf("sendSocket error: {s}", .{@errorName(e)});
                            continue :next_packet; // on error, skip this packet and send another.
                        },
                    };
                };
                std.debug.assert(bytes_sent == p.size);
            }
        }
    }
};

// TODO: Evaluate when XevThread socket backend is beneficial.
const SocketBackend = PerThread;

pub const SocketThread = struct {
    allocator: Allocator,
    logger: Logger,
    socket: UdpSocket,
    channel: *Channel(Packet),
    exit: ExitCondition,
    direction: Direction,
    handle: SocketBackend.Handle,

    const Direction = enum { sender, receiver };

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
        const self = try allocator.create(SocketThread);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .logger = logger,
            .socket = socket,
            .channel = channel,
            .exit = exit,
            .direction = direction,
            .handle = undefined,
        };

        try SocketBackend.spawn(self);
        return self;
    }

    pub fn join(self: *SocketThread) void {
        SocketBackend.join(self);
        self.allocator.destroy(self);
    }
};

test "SocketThread: overload sendto" {
    const allocator = std.testing.allocator;

    var send_channel = try Channel(Packet).init(allocator);
    defer send_channel.deinit();

    var socket = try UdpSocket.create(.ipv4, .udp);
    try socket.bindToPort(0);

    var exit = std.atomic.Value(bool).init(false);
    var st = try SocketThread.spawnSender(
        allocator,
        .noop,
        socket,
        &send_channel,
        .{ .unordered = &exit },
    );
    defer st.join();
    defer exit.store(true, .release);

    // send a bunch of packets to overload the SocketThread's internal sendto().
    const addr = try network.EndPoint.parse("127.0.0.1:12345");
    for (0..10_000) |_| {
        try send_channel.send(Packet.init(addr, undefined, PACKET_DATA_SIZE));
    }

    // Wait for all sends to have started/happened.
    while (!send_channel.isEmpty()) std.Thread.sleep(10 * std.time.ns_per_ms);
}

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
                var prng = std.Random.DefaultPrng.init(0);
                var timer = try std.time.Timer.start();

                while (e.shouldRun()) {
                    prng.fill(&packet.buffer);
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
                            std.Thread.sleep(std.time.ns_per_s);
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
