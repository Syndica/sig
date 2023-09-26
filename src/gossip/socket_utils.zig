const UdpSocket = @import("zig-network").Socket;
const Packet = @import("../gossip/packet.zig").Packet;
const PACKET_DATA_SIZE = @import("../gossip/packet.zig").PACKET_DATA_SIZE;
const Channel = @import("../sync/channel.zig").Channel;
const std = @import("std");
const Logger = @import("../trace/log.zig").Logger;

pub const SOCKET_TIMEOUT: usize = 1000000;
pub const PACKETS_PER_BATCH: usize = 64;

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
                // std.time.sleep(std.time.ns_per_ms * 1);
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

pub fn readSocketV2(
    allocator: std.mem.Allocator,
    socket: *UdpSocket,
    incoming_channel: *Channel(std.ArrayList(Packet)),
    exit: *const std.atomic.Atomic(bool),
    // logger: Logger,
) !void {
    //Performance out of the IO without poll
    //  * block on the socket until it's readable
    //  * set the socket to non blocking
    //  * read until it fails
    //  * set it back to blocking before returning

    const MAX_WAIT_NS = std.time.ns_per_ms; // 1ms

    while (!exit.load(std.atomic.Ordering.Unordered)) {
        // init a new batch
        var count: usize = 0;
        const capacity = PACKETS_PER_BATCH;
        var packet_batch = try std.ArrayList(Packet).initCapacity(
            allocator,
            capacity,
        );
        for (0..capacity) |_| { 
            packet_batch.appendAssumeCapacity(Packet.default());
        }

        // set socket to block
        try socket.setReadTimeout(null);
        var timer = std.time.Timer.start() catch unreachable;

        // recv packets into batch
        while (true) { 
            var n_packets_read = recvMmsg(socket, packet_batch.items[count..capacity]) catch |err| { 
                if (count > 0 and err == error.WouldBlock) { 
                    if (timer.read() > MAX_WAIT_NS) { 
                        break;
                    }
                    continue;
                } else { 
                    return err;
                }
            };

            if (count == 0) { 
                // set to nonblocking mode
                try socket.setReadTimeout(SOCKET_TIMEOUT);
            }
            count += n_packets_read;
            if (timer.read() > MAX_WAIT_NS or count >= capacity) { 
                break;
            }
        }

        if (count < capacity) { 
            packet_batch.shrinkAndFree(count);
        }
        try incoming_channel.send(packet_batch);
    }
}

pub fn recvMmsg(
    socket: *UdpSocket,
    /// pre-allocated array of packets to fill up
    packet_batch: []Packet,
) !usize {
    const max_size = packet_batch.len;
    var count: usize = 0;

    while (count < max_size) {
        var packet = &packet_batch[count];
        const recv_meta = socket.receiveFrom(&packet.data) catch |err| {
            // would block then return
            if (count > 0 and err == error.WouldBlock) {
                break;
            } else {
                return err;
            }
        };

        const bytes_read = recv_meta.numberOfBytes;
        if (bytes_read == 0) {
            return error.SocketClosed;
        }
        packet.addr = recv_meta.sender;
        packet.size = bytes_read;

        if (count == 0) {
            // nonblocking mode
            try socket.setReadTimeout(SOCKET_TIMEOUT);
        }
        count += 1;
    }

    return count;
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
            // std.time.sleep(std.time.ns_per_ms * 1);
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

    const N_ITERS = 100_000;

    pub fn benchmarkReadSocket() !void {
        const allocator = std.heap.page_allocator;

        var channel = Channel(Packet).init(allocator, N_ITERS);
        defer channel.deinit();

        var socket = try UdpSocket.create(.ipv4, .udp);
        try socket.bindToPort(0);
        try socket.setReadTimeout(1000000); // 1 second

        const to_endpoint = try socket.getLocalEndPoint();

        var exit = std.atomic.Atomic(bool).init(false);

        var handle = try std.Thread.spawn(.{}, readSocket, .{ &socket, channel, &exit, .noop });
        var recv_handle = try std.Thread.spawn(.{}, benchmarkChannelRecv, .{ channel, N_ITERS });

        var rand = std.rand.DefaultPrng.init(0);
        var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
        var timer = std.time.Timer.start() catch unreachable;
        for (1..(N_ITERS * 2 + 1)) |i| {
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

        recv_handle.join();
        exit.store(true, std.atomic.Ordering.Unordered);
        handle.join();
    }

    pub fn benchmarkReadSocketV2() !void {
        const allocator = std.heap.page_allocator;

        var channel = Channel(std.ArrayList(Packet)).init(allocator, N_ITERS);
        defer channel.deinit();

        var socket = try UdpSocket.create(.ipv4, .udp);
        try socket.bindToPort(0);
        try socket.setReadTimeout(1000000); // 1 second

        const to_endpoint = try socket.getLocalEndPoint();

        var exit = std.atomic.Atomic(bool).init(false);

        var handle = try std.Thread.spawn(.{}, readSocketV2, .{ allocator, &socket, channel, &exit });
        var recv_handle = try std.Thread.spawn(.{}, benchmarkChannelRecvV2, .{ channel, N_ITERS });

        var rand = std.rand.DefaultPrng.init(0);
        var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
        var timer = std.time.Timer.start() catch unreachable;

        for (1..(N_ITERS * 2 + 1)) |i| {
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

        recv_handle.join();
        exit.store(true, std.atomic.Ordering.Unordered);
        handle.join();
    }

    pub fn benchmarkSendSocket() !void {
        const allocator = std.heap.page_allocator;

        var channel = Channel(Packet).init(allocator, N_ITERS);
        defer channel.deinit();

        var socket = try UdpSocket.create(.ipv4, .udp);
        try socket.bindToPort(0);
        try socket.setReadTimeout(1000000); // 1 second
        const to_endpoint = try socket.getLocalEndPoint();

        var exit = std.atomic.Atomic(bool).init(false);

        var recv_handle = try std.Thread.spawn(.{}, benchmarkSocketRecv, .{ &socket, N_ITERS });

        var handle = try std.Thread.spawn(.{}, sendSocket, .{ &socket, channel, &exit, .noop });
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

        recv_handle.join();
        exit.store(true, std.atomic.Ordering.Unordered);
        handle.join();
    }
};

pub fn benchmarkChannelRecvV2(
    channel: *Channel(std.ArrayList(Packet)),
    n_values_to_receive: usize,
) !void {
    var count: usize = 0;
    while (true) {
        const values = (try channel.try_drain()) orelse {
            continue;
        };
        for (values) |packet_batch| { 
            count += packet_batch.items.len;
        }
        if (count >= n_values_to_receive) {
            break;
        }
    }
}

pub fn benchmarkChannelRecv(
    channel: *Channel(Packet),
    N_ITERS: usize,
) !void {
    var count: usize = 0;
    while (true) {
        const values = (try channel.try_drain()) orelse {
            continue;
        };
        count += values.len;
        if (count >= N_ITERS) {
            break;
        }
    }
}

pub fn benchmarkSocketRecv(
    socket: *UdpSocket,
    total: usize,
) !void {
    var count: usize = 0;
    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;

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
        if (count == total) {
            break;
        }
    }
}
