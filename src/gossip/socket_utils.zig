const UdpSocket = @import("zig-network").Socket;
const Packet = @import("../gossip/packet.zig").Packet;
const PACKET_DATA_SIZE = @import("../gossip/packet.zig").PACKET_DATA_SIZE;
const Channel = @import("../sync/channel.zig").Channel;
const std = @import("std");

pub fn read_socket(
    socket: *UdpSocket,
    send_channel: *Channel(Packet),
    exit: *const std.atomic.Atomic(bool),
) error{ SocketClosed, SocketRecvError, OutOfMemory, ChannelClosed }!void {
    var read_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var packets_read: u64 = 0;

    while (!exit.load(std.atomic.Ordering.Unordered)) {
        const recv_meta = socket.receiveFrom(&read_buf) catch |err| {
            if (err == error.WouldBlock) {
                std.time.sleep(std.time.ns_per_ms * 1);
                continue;
            } else {
                return error.SocketRecvError;
            }
        };

        const bytes_read = recv_meta.numberOfBytes;
        if (bytes_read == 0) {
            return error.SocketClosed;
        }
        packets_read +|= 1;

        // send packet through channel
        const packet = Packet.init(recv_meta.sender, read_buf, bytes_read);
        try send_channel.send(packet);
    }
    std.debug.print("read_socket loop closed\n", .{});
}

pub fn send_socket(
    socket: *UdpSocket,
    recv_channel: *Channel(Packet),
    exit: *const std.atomic.Atomic(bool),
) error{ SocketSendError, OutOfMemory, ChannelClosed }!void {
    var packets_sent: u64 = 0;

    while (!exit.load(std.atomic.Ordering.Unordered)) {
        const maybe_packets = try recv_channel.try_drain();
        if (maybe_packets == null) {
            // sleep for 1ms
            std.time.sleep(std.time.ns_per_ms * 1);
            continue;
        }
        const packets = maybe_packets.?;
        defer recv_channel.allocator.free(packets);

        for (packets) |p| {
            const bytes_sent = socket.sendTo(p.addr, p.data[0..p.size]) catch |e| {
                std.debug.print("send_socket error: {s}\n", .{@errorName(e)});
                continue;
            };
            packets_sent +|= 1;
            std.debug.assert(bytes_sent == p.size);
        }
    }
    std.debug.print("send_socket loop closed\n", .{});
}

pub const benchmark_packet_processing = struct {
    pub const min_iterations = 1000;
    pub const max_iterations = 1000;

    pub fn run() void {
        std.time.sleep(200);
    }
};
