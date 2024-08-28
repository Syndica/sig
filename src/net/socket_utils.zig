const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const UdpSocket = @import("zig-network").Socket;
const Packet = @import("packet.zig").Packet;
const PACKET_DATA_SIZE = @import("packet.zig").PACKET_DATA_SIZE;
const Channel = @import("../sync/channel.zig").Channel;
const std = @import("std");
const Logger = @import("../trace/log.zig").Logger;

pub const SOCKET_TIMEOUT_US: usize = 1 * std.time.us_per_s;
pub const PACKETS_PER_BATCH: usize = 64;

pub fn readSocket(
    allocator: std.mem.Allocator,
    socket_: UdpSocket,
    incoming_channel: *Channel(std.ArrayList(Packet)),
    exit: *const std.atomic.Value(bool),
    logger: Logger,
) !void {
    // NOTE: we set to non-blocking to periodically check if we should exit
    var socket = socket_;
    try socket.setReadTimeout(SOCKET_TIMEOUT_US);

    inf_loop: while (!exit.load(.acquire)) {
        // init a new batch
        var packet_batch = try std.ArrayList(Packet).initCapacity(
            allocator,
            PACKETS_PER_BATCH,
        );
        errdefer packet_batch.deinit();

        // recv packets into batch
        while (packet_batch.items.len != packet_batch.capacity) {
            var packet: Packet = Packet.default();
            const recv_meta = socket.receiveFrom(&packet.data) catch |err| switch (err) {
                error.WouldBlock => {
                    if (packet_batch.items.len > 0) break;
                    if (exit.load(.acquire)) {
                        packet_batch.deinit();
                        break :inf_loop;
                    }
                    continue;
                },
                else => |e| return e,
            };
            const bytes_read = recv_meta.numberOfBytes;
            if (bytes_read == 0) return error.SocketClosed;
            packet.addr = recv_meta.sender;
            packet.size = bytes_read;
            packet_batch.appendAssumeCapacity(packet);
        }

        packet_batch.shrinkAndFree(packet_batch.items.len);
        try incoming_channel.send(packet_batch);
    }

    logger.debugf("readSocket loop closed", .{});
}

pub fn sendSocket(
    socket: UdpSocket,
    outgoing_channel: *Channel(std.ArrayList(Packet)),
    exit: *const std.atomic.Value(bool),
    logger: Logger,
) error{ SocketSendError, OutOfMemory, ChannelClosed }!void {
    var packets_sent: u64 = 0;

    while (!exit.load(.acquire)) {
        while (outgoing_channel.receive()) |*packet_batch| {
            for (packet_batch.items) |*p| {
                const bytes_sent = socket.sendTo(p.addr, p.data[0..p.size]) catch |e| {
                    logger.debugf("send_socket error: {s}", .{@errorName(e)});
                    continue;
                };
                packets_sent +|= 1;
                std.debug.assert(bytes_sent == p.size);
            }
            packet_batch.deinit();
        }
    }
    logger.debugf("sendSocket loop closed", .{});
}

/// A thread that is dedicated to either sending or receiving data over a socket.
/// The included channel can be used communicate with that thread.
///
/// The channel only supports one: either sending or receiving, depending how it
/// was initialized. While you *could* send data to the channel for a "receiver"
/// socket, the underlying thread won't actually read the data from the channel.
pub const SocketThread = struct {
    channel: *Channel(std.ArrayList(Packet)),
    exit: *std.atomic.Value(bool),
    handle: std.Thread,

    const Self = @This();

    pub fn initSender(allocator: Allocator, logger: Logger, socket: UdpSocket, exit: *Atomic(bool)) !Self {
        const channel = try Channel(std.ArrayList(Packet)).create(allocator, 0);
        return .{
            .channel = channel,
            .exit = exit,
            .handle = try std.Thread.spawn(.{}, sendSocket, .{ socket, channel, exit, logger }),
        };
    }

    pub fn initReceiver(allocator: Allocator, logger: Logger, socket: UdpSocket, exit: *Atomic(bool)) !Self {
        const channel = try Channel(std.ArrayList(Packet)).create(allocator, 0);
        return .{
            .channel = channel,
            .exit = exit,
            .handle = try std.Thread.spawn(.{}, readSocket, .{ allocator, socket, channel, exit, logger }),
        };
    }

    pub fn deinit(self: Self, allocator: Allocator) void {
        self.exit.store(true, .release);
        self.handle.join();
        // close the channel first, so that we can drain without waiting for new items
        self.channel.close();
        while (self.channel.receive()) |list| {
            list.deinit();
        }
        self.channel.deinit();
        allocator.destroy(self.channel);
    }
};

pub const BenchmarkPacketProcessing = struct {
    pub const min_iterations = 3;
    pub const max_iterations = 5;

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

    pub fn benchmarkReadSocket(bench_args: BenchmarkArgs) !u64 {
        const n_packets = bench_args.n_packets;
        const allocator = std.heap.page_allocator;

        var channel = Channel(std.ArrayList(Packet)).init(allocator, n_packets);
        defer channel.deinit();

        var socket = try UdpSocket.create(.ipv4, .udp);
        try socket.bindToPort(0);
        try socket.setReadTimeout(1000000); // 1 second

        const to_endpoint = try socket.getLocalEndPoint();

        var exit = std.atomic.Value(bool).init(false);

        var handle = try std.Thread.spawn(.{}, readSocket, .{ allocator, socket, &channel, &exit, .noop });
        var recv_handle = try std.Thread.spawn(.{}, benchmarkChannelRecv, .{ &channel, n_packets });

        var rand = std.rand.DefaultPrng.init(0);
        var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
        var timer = try std.time.Timer.start();

        // NOTE: send more packets than we need because UDP drops some
        for (1..(n_packets * 2 + 1)) |i| {
            rand.fill(&packet_buf);
            _ = try socket.sendTo(to_endpoint, &packet_buf);

            // 10Kb per second
            // each packet is 1k bytes
            // = 10 packets per second
            if (i % 10 == 0) {
                const elapsed = timer.read();
                if (elapsed < std.time.ns_per_s) {
                    std.time.sleep(std.time.ns_per_s - elapsed);
                }
            }
        }
        // std.debug.print("sent all packets.. waiting on receiver\r", .{});

        recv_handle.join();
        const elapsed = timer.read();

        exit.store(true, .release);
        handle.join();

        return elapsed;
    }
};

pub fn benchmarkChannelRecv(
    channel: *Channel(std.ArrayList(Packet)),
    n_values_to_receive: usize,
) !void {
    var count: usize = 0;
    while (true) {
        if (channel.receive()) |value| {
            count += value.items.len;
        }
        if (count >= n_values_to_receive) {
            break;
        }
    }
}
