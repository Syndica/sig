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

const network = @import("zig-network");
const UdpSocket = network.Socket;

pub const SOCKET_TIMEOUT_US: usize = 1 * std.time.us_per_s;
pub const PACKETS_PER_BATCH: usize = 64;

// The identifier for the scoped logger used in this file.
const LOG_SCOPE: []const u8 = "socket_utils";

pub const SocketPipe = struct {
    handle: std.Thread,
    outgoing_signal: Channel(Packet).SendSignal,

    const Self = @This();

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
    ) !*Self {
        // TODO(king): store event-lop data in SocketPipe (hence, heap-alloc)..
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        switch (direction) {
            .sender => {
                self.outgoing_signal = .{};
                channel.send_hook = &self.outgoing_signal.hook;
                self.handle = try std.Thread.spawn(.{}, runSender, .{self, logger, socket, channel, exit});
            },
            .receiver => {
                self.handle = try std.Thread.spawn(.{}, runReceiver, .{logger, socket, channel, exit});
            },
        }

        return self;
    }

    fn runReceiver(
        logger_: Logger,
        socket_: UdpSocket,
        incoming_channel: *Channel(Packet),
        exit: ExitCondition,
    ) !void {
        const logger = logger_.withScope(LOG_SCOPE);
        defer {
            exit.afterExit();
            logger.info().log("readSocket loop closed");
        }

        // NOTE: we set to non-blocking to periodically check if we should exit
        var socket = socket_;
        try socket.setReadTimeout(SOCKET_TIMEOUT_US);

        while (exit.shouldRun()) {
            var packet: Packet = Packet.default();
            const recv_meta = socket.receiveFrom(&packet.data) catch |err| switch (err) {
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
            try incoming_channel.send(packet);
        }
    }

    fn runSender(
        self: *Self,
        logger_: Logger,
        socket: UdpSocket,
        outgoing_channel: *Channel(Packet),
        exit: ExitCondition,
    ) !void {
        const logger = logger_.withScope(LOG_SCOPE);
        defer {
            // empty the channel
            while (outgoing_channel.tryReceive()) |_| {}
            exit.afterExit();
            logger.debug().log("sendSocket loop closed");
        }

        while (true) {
            self.outgoing_signal.wait(exit) catch break;
            while (outgoing_channel.tryReceive()) |p| {
                const bytes_sent = socket.sendTo(p.addr, p.data[0..p.size]) catch |e| {
                    logger.err().logf("sendSocket error: {s}", .{@errorName(e)});
                    continue;
                };
                std.debug.assert(bytes_sent == p.size);
            }
        }
    }

    pub fn deinit(self: *Self, allocator: Allocator) void {
        self.handle.join();
        allocator.destroy(self);
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

        var incoming_signal: Channel(Packet).SendSignal = .{};
        incoming_channel.send_hook = &incoming_signal.hook;

        const incoming_pipe = try SocketPipe.init(allocator, .receiver, .noop, socket, &incoming_channel, exit_condition);
        defer incoming_pipe.deinit(allocator);

        // Start outgoing

        const S = struct {
            fn runSender(channel: *Channel(Packet), addr: network.EndPoint, e: ExitCondition) !void {
                var i: usize = 0;
                var packet: Packet = undefined;
                var prng = std.rand.DefaultPrng.init(0);
                var timer = try std.time.Timer.start();

                while (e.shouldRun()) {
                    prng.fill(&packet.data);
                    packet.addr = addr;
                    packet.size = packet.data.len;
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

        const outgoing_pipe = try SocketPipe.init(allocator, .sender, .noop, socket, &outgoing_channel, exit_condition);
        defer outgoing_pipe.deinit(allocator);

        const outgoing_handle = try std.Thread.spawn(.{}, S.runSender, .{&outgoing_channel, to_endpoint, exit_condition});
        defer outgoing_handle.join();

        // run incoming until received n_packets
        
        var packets_to_recv = n_packets;
        var timer = try sig.time.Timer.start();
        while (packets_to_recv > 0) {
            incoming_signal.wait(exit_condition) catch break;
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
