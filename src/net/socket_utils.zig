const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const UdpSocket = @import("zig-network").Socket;
const Packet = @import("packet.zig").Packet;
const PACKET_DATA_SIZE = @import("packet.zig").PACKET_DATA_SIZE;
const Channel = @import("../sync/channel.zig").Channel;
const std = @import("std");
const Logger = @import("../trace/log.zig").Logger;

pub const SOCKET_TIMEOUT: usize = 1000000;
pub const PACKETS_PER_BATCH: usize = 64;

pub fn readSocket(
    allocator: std.mem.Allocator,
    socket_: UdpSocket,
    incoming_channel: *Channel(std.ArrayList(Packet)),
    exit: *const std.atomic.Value(bool),
    logger: Logger,
) !void {
    //Performance out of the IO without poll
    //  * block on the socket until it's readable
    //  * set the socket to non blocking
    //  * read until it fails
    //  * set it back to blocking before returning

    var socket = socket_;
    const MAX_WAIT_NS = std.time.ns_per_ms; // 1ms

    while (!exit.load(.unordered)) {
        // init a new batch
        var count: usize = 0;
        const capacity = PACKETS_PER_BATCH;
        var packet_batch = try std.ArrayList(Packet).initCapacity(
            allocator,
            capacity,
        );
        packet_batch.appendNTimesAssumeCapacity(Packet.default(), capacity);

        // NOTE: usually this would be null (ie, blocking)
        // but in order to exit cleanly in tests - we set to 1 second
        try socket.setReadTimeout(std.time.ms_per_s);
        var timer = std.time.Timer.start() catch unreachable;

        // recv packets into batch
        while (true) {
            const n_packets_read = recvMmsg(&socket, packet_batch.items[count..capacity], exit) catch |err| {
                if (count > 0 and err == error.WouldBlock) {
                    if (timer.read() > MAX_WAIT_NS) {
                        break;
                    }
                }
                continue;
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
    logger.debugf("readSocket loop closed", .{});
}

pub fn recvMmsg(
    socket: *UdpSocket,
    /// pre-allocated array of packets to fill up
    packet_batch: []Packet,
    exit: *const std.atomic.Value(bool),
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
                if (exit.load(.unordered)) return 0;
                continue;
            }
        };

        const bytes_read = recv_meta.numberOfBytes;
        if (bytes_read == 0) {
            return error.SocketClosed;
        }
        packet.addr = recv_meta.sender;
        packet.size = bytes_read;
        packet.flags = .{};

        if (count == 0) {
            // nonblocking mode
            try socket.setReadTimeout(SOCKET_TIMEOUT);
        }
        count += 1;
    }

    return count;
}

pub fn sendSocket(
    socket: UdpSocket,
    outgoing_channel: *Channel(std.ArrayList(Packet)),
    exit: *const std.atomic.Value(bool),
    logger: Logger,
) error{ SocketSendError, OutOfMemory, ChannelClosed }!void {
    var packets_sent: u64 = 0;

    while (!exit.load(.unordered)) {
        const maybe_packet_batches = try outgoing_channel.try_drain();
        if (maybe_packet_batches == null) {
            // sleep for 1ms
            // std.time.sleep(std.time.ns_per_ms * 1);
            continue;
        }
        const packet_batches = maybe_packet_batches.?;
        defer {
            for (packet_batches) |*packet_batch| {
                packet_batch.deinit();
            }
            outgoing_channel.allocator.free(packet_batches);
        }

        for (packet_batches) |*packet_batch| {
            for (packet_batch.items) |*p| {
                const bytes_sent = socket.sendTo(p.addr, p.data[0..p.size]) catch |e| {
                    logger.debugf("send_socket error: {s}", .{@errorName(e)});
                    continue;
                };
                packets_sent +|= 1;
                std.debug.assert(bytes_sent == p.size);
            }
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
        const channel = Channel(std.ArrayList(Packet)).init(allocator, 0);
        return .{
            .channel = channel,
            .exit = exit,
            .handle = try std.Thread.spawn(.{}, sendSocket, .{ socket, channel, exit, logger }),
        };
    }

    pub fn initReceiver(allocator: Allocator, logger: Logger, socket: UdpSocket, exit: *Atomic(bool)) !Self {
        const channel = Channel(std.ArrayList(Packet)).init(allocator, 0);
        return .{
            .channel = channel,
            .exit = exit,
            .handle = try std.Thread.spawn(.{}, readSocket, .{ allocator, socket, channel, exit, logger }),
        };
    }

    pub fn deinit(self: Self) void {
        self.exit.store(true, .unordered);
        self.handle.join();
        self.channel.deinit();
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

        var handle = try std.Thread.spawn(.{}, readSocket, .{ allocator, socket, channel, &exit, .noop });
        var recv_handle = try std.Thread.spawn(.{}, benchmarkChannelRecv, .{ channel, n_packets });

        var rand = std.rand.DefaultPrng.init(0);
        var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
        var timer = try std.time.Timer.start();

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

        recv_handle.join();
        const elapsed = timer.read();

        exit.store(true, .unordered);
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
