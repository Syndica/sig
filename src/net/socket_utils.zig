const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

const sig = @import("../sig.zig");
const Packet = sig.net.Packet;
const PACKET_DATA_SIZE = sig.net.PACKET_DATA_SIZE;
const Channel = sig.sync.Channel;
const Logger = sig.trace.Logger;
const ExitCondition = sig.sync.ExitCondition;

const UdpSocket = @import("zig-network").Socket;

pub const SOCKET_TIMEOUT_US: usize = 1 * std.time.us_per_s;
pub const PACKETS_PER_BATCH: usize = 64;

// The identifier for the scoped logger used in this file.
const LOG_SCOPE: []const u8 = "socket_utils";

pub const SocketPipe = struct {
    const Self = @This();

    handle: std.Thread,

    pub fn initSender(
        allocator: Allocator,
        logger: Logger,
        socket: UdpSocket,
        channel: *Channel(Packet),
        exit: ExitCondition,
    ) !Self {
        _ = allocator;
        return .{ .handle = try std.Thread.spawn(.{}, sendSocket, .{ logger, socket, channel, exit }) };
    }

    fn sendSocket(
        logger_: Logger,
        socket: UdpSocket,
        outgoing_channel: *Channel(Packet),
        exit: ExitCondition,
    ) !void {
        const logger = logger_.withScope(LOG_SCOPE);
        defer {
            exit.afterExit();
            logger.info().log("sender socket loop closed");
        }

        while (exit.shouldRun()) {
            while (outgoing_channel.tryReceive()) |p| {
                const bytes_sent = socket.sendTo(p.addr, p.data[0..p.size]) catch |e| {
                    logger.debug().logf("send_socket error: {s}", .{@errorName(e)});
                    std.debug.print("sendTo: {any}", .{e});
                    continue;
                };
                std.debug.assert(bytes_sent == p.size);
            }
        }
    }

    pub fn initReceiver(
        allocator: Allocator,
        logger: Logger,
        socket: UdpSocket,
        channel: *Channel(Packet),
        exit: ExitCondition,
    ) !Self {
        _ = allocator;
        return .{ .handle = try std.Thread.spawn(.{}, readSocket, .{ logger, socket, channel, exit }) };
    }

    fn readSocket(
        logger_: Logger,
        socket_: UdpSocket,
        incoming_channel: *Channel(Packet),
        exit: ExitCondition,
    ) !void {
        const logger = logger_.withScope(LOG_SCOPE);
        defer {
            exit.afterExit();
            logger.info().log("receiver socket loop closed");
        }

        // Allow periodic checking of exit.
        var socket = socket_;
        try socket.setReadTimeout(SOCKET_TIMEOUT_US);

        while (exit.shouldRun()) {
            var packet: Packet = Packet.default();
            const recv_meta = socket.receiveFrom(&packet.data) catch |err| switch (err) {
                error.WouldBlock => continue,
                else => |e| {
                    std.debug.print("recvFrom: {any}", .{e});
                    return e;
                },
            };
            const bytes_read = recv_meta.numberOfBytes;
            if (bytes_read == 0) {
                std.debug.print("recvfrom: SocketClosed", .{});
                return error.SocketClosed;
            }
            packet.addr = recv_meta.sender;
            packet.size = bytes_read;
            try incoming_channel.send(packet);
        }
    }

    pub fn deinit(self: Self, allocator: Allocator) void {
        _ = allocator;
        self.handle.join();
    }
};

pub const SocketChannel = struct {
    const Self = @This();

    pipe: SocketPipe,
    channel: union(enum) {
        sender: *Channel(Packet),
        receiver: *Channel(Packet),
    },

    pub fn initSender(
        allocator: Allocator,
        logger: Logger,
        socket: UdpSocket,
        exit: ExitCondition,
    ) !Self {
        const channel = try Channel(Packet).create(allocator);
        errdefer {
            channel.deinit();
            allocator.destroy(channel);
        }

        return .{
            .pipe = try SocketPipe.initSender(allocator, logger, socket, channel, exit),
            .channel = .{ .sender = channel },
        };
    }

    pub fn initReceiver(
        allocator: Allocator,
        logger: Logger,
        socket: UdpSocket,
        exit: ExitCondition,
    ) !Self {
        const channel = try Channel(Packet).create(allocator);
        errdefer {
            channel.deinit();
            allocator.destroy(channel);
        }

        return .{
            .pipe = try SocketPipe.initReceiver(allocator, logger, socket, channel, exit),
            .channel = .{ .receiver = channel },
        };
    }

    pub fn send(self: Self, packet: Packet) !void {
        return self.channel.sender.send(packet);
    }

    pub fn tryReceive(self: Self) ?Packet {
        return self.channel.receiver.tryReceive();
    }

    pub fn deinit(self: Self, allocator: Allocator) void {
        self.pipe.deinit(allocator);
        switch (self.channel) {
            inline else => |channel| {
                channel.deinit();
                allocator.destroy(channel);
            },
        }
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

        var exit_flag = std.atomic.Value(bool).init(false);
        const exit: ExitCondition = .{ .unordered = &exit_flag };
        const to_endpoint = try socket.getLocalEndPoint();

        const sender = try SocketChannel.initSender(allocator, .noop, socket, exit);
        defer sender.deinit(allocator);

        const receiver = try SocketChannel.initReceiver(allocator, .noop, socket, exit);
        defer receiver.deinit(allocator);

        var packets_received: usize = 0;
        var prng = std.rand.DefaultPrng.init(0);
        var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
        var timer = try sig.time.Timer.start();

        // NOTE: send more packets than we need because UDP drops some
        for (1..(n_packets * 2 + 1)) |i| {
            prng.fill(&packet_buf);
            try sender.send(Packet.init(to_endpoint, packet_buf, packet_buf.len));

            // Receive concurrently while sending.
            while (receiver.tryReceive()) |p| {
                //std.debug.print("received inner {}\n", .{packets_received});
                std.mem.doNotOptimizeAway(p);
                packets_received += 1;
            }

            // 10Kb per second
            // each packet is 1k bytes
            // = 10 packets per second
            if (i % 10 == 0) {
                const elapsed = timer.read();
                if (elapsed.asNanos() < std.time.ns_per_s) {
                    std.time.sleep(std.time.ns_per_s - elapsed.asNanos());
                }
            }
        }

        // Receive any remaining packets.
        while (packets_received < n_packets) {
            while (receiver.tryReceive()) |p| {
                //std.debug.print("received outer {}\n", .{packets_received});
                std.mem.doNotOptimizeAway(p);
                packets_received += 1;
            }
        }

        exit.setExit();
        return timer.read();
    }
};

test "benchmark packet processing" {
    _ = try BenchmarkPacketProcessing.benchmarkReadSocket(.{
        .n_packets = 100_000,
    });
}
