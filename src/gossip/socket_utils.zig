const UdpSocket = @import("zig-network").Socket;
const Packet = @import("../gossip/packet.zig").Packet;
const PACKET_DATA_SIZE = @import("../gossip/packet.zig").PACKET_DATA_SIZE;
const Channel = @import("../sync/channel.zig").Channel;
const std = @import("std");
const Logger = @import("../trace/log.zig").Logger;

pub fn readSocket(
    socket: *UdpSocket,
    incoming_channel: *Channel(Packet),
    exit: *const std.atomic.Atomic(bool),
    logger: Logger,
) error{ SocketClosed, SocketRecvError, OutOfMemory, ChannelClosed }!void {
    var read_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var packets_read: u64 = 0;

    while (!exit.load(std.atomic.Ordering.Unordered)) {
        const recv_meta = socket.receiveFrom(&read_buf) catch |err| {
            if (err == error.WouldBlock) {
                std.time.sleep(std.time.ns_per_ms * 1);
                continue;
            } else {
                logger.debugf("read_socket error: {s}\n", .{@errorName(err)});
                continue;
            }
        };

        const bytes_read = recv_meta.numberOfBytes;
        if (bytes_read == 0) {
            logger.debugf("read_socket closed\n", .{});
            return error.SocketClosed;
        }
        packets_read +|= 1;

        // send packet through channel
        const packet = Packet.init(recv_meta.sender, read_buf, bytes_read);
        try incoming_channel.send(packet);
    }
    logger.debugf("read_socket loop closed\n", .{});
}

pub fn sendSocket(
    socket: *UdpSocket,
    outgoing_channel: *Channel(Packet),
    exit: *const std.atomic.Atomic(bool),
    logger: Logger,
) error{ SocketSendError, OutOfMemory, ChannelClosed }!void {
    var packets_sent: u64 = 0;

    while (!exit.load(std.atomic.Ordering.Unordered)) {
        const maybe_packets = try outgoing_channel.try_drain();
        if (maybe_packets == null) {
            // sleep for 1ms
            std.time.sleep(std.time.ns_per_ms * 1);
            continue;
        }
        const packets = maybe_packets.?;
        defer outgoing_channel.allocator.free(packets);

        for (packets) |p| {
            const bytes_sent = socket.sendTo(p.addr, p.data[0..p.size]) catch |e| {
                logger.debugf("send_socket error: {s}\n", .{@errorName(e)});
                continue;
            };
            packets_sent +|= 1;
            std.debug.assert(bytes_sent == p.size);
        }
    }
    logger.debugf("send_socket loop closed\n", .{});
}

pub const BenchmarkPacketProcessing = struct {
    pub const min_iterations = 3;
    pub const max_iterations = 5;

    pub fn benchmarkReadSocket() !void {
        const N_ITERS = 10;
        const allocator = std.heap.page_allocator;

        var channel = Channel(Packet).init(allocator, N_ITERS);
        defer channel.deinit();

        var socket = try UdpSocket.create(.ipv4, .udp);
        try socket.bindToPort(0);
        try socket.setReadTimeout(1000000); // 1 second

        const to_endpoint = try socket.getLocalEndPoint();

        var exit = std.atomic.Atomic(bool).init(false);

        var handle = try std.Thread.spawn(.{}, readSocket, .{ &socket, channel, &exit, .noop });

        var rand = std.rand.DefaultPrng.init(0);
        var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
        for (0..N_ITERS) |_| {
            rand.fill(&packet_buf);
            _ = try socket.sendTo(to_endpoint, &packet_buf);
        }

        var count: usize = 0;
        while (true) {
            const values = channel.drain() orelse {
                continue;
            };
            count += values.len;
            if (count == N_ITERS) {
                break;
            }
        }

        exit.store(true, std.atomic.Ordering.Unordered);
        handle.join();
    }

    pub fn benchmarkSendSocket() !void {
        const N_ITERS = 10;
        const allocator = std.heap.page_allocator;

        var channel = Channel(Packet).init(allocator, N_ITERS);
        defer channel.deinit();

        var socket = try UdpSocket.create(.ipv4, .udp);
        try socket.bindToPort(0);
        try socket.setReadTimeout(1000000); // 1 second
        const to_endpoint = try socket.getLocalEndPoint();

        var exit = std.atomic.Atomic(bool).init(false);

        var logger = Logger.init(allocator, .debug);
        defer logger.deinit();
        logger.spawn();

        var handle = try std.Thread.spawn(.{}, sendSocket, .{ &socket, channel, &exit, logger });

        var rand = std.rand.DefaultPrng.init(0);
        var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
        for (0..N_ITERS) |_| {
            rand.fill(&packet_buf);
            try channel.send(Packet.init(
                to_endpoint,
                packet_buf,
                packet_buf.len,
            ));
        }

        var count: usize = 0;
        while (true) {
            const recv_meta = socket.receiveFrom(&packet_buf) catch |err| {
                if (err == error.WouldBlock) {
                    continue;
                } else {
                    return error.SocketRecvError;
                }
            };

            const bytes_read = recv_meta.numberOfBytes;
            if (bytes_read == 0) {
                return error.SocketClosed;
            }

            count += 1;
            if (count == N_ITERS) {
                break;
            }
        }

        exit.store(true, std.atomic.Ordering.Unordered);
        handle.join();
    }
};
