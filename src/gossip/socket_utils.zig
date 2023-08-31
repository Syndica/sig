const UdpSocket = @import("zig-network").Socket;
const Packet = @import("../gossip/packet.zig").Packet;
const PACKET_DATA_SIZE = @import("../gossip/packet.zig").PACKET_DATA_SIZE;
const NonBlockingChannel = @import("../sync/channel.zig").NonBlockingChannel;
const SocketAddr = @import("net.zig").SocketAddr;
const std = @import("std");

pub fn read_socket(
    socket: *UdpSocket,
    send_channel: *NonBlockingChannel(Packet),
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
    recv_channel: *NonBlockingChannel(Packet),
    exit: *const std.atomic.Atomic(bool),
) error{ SocketSendError, ChannelClosed }!void {
    var packets_sent: u64 = 0;

    while (!exit.load(std.atomic.Ordering.Unordered)) {
        const maybe_packets = try recv_channel.drain();
        if (maybe_packets == null) {
            // sleep for 1ms
            std.time.sleep(std.time.ns_per_ms * 1);
            continue;
        }
        const packets = maybe_packets.?;
        defer recv_channel.allocator.free(packets);

        for (packets) |p| {
            // NOTE: sometimes this hard fails (with 195.156.175.48:38647 => UnexpectedError: errno: 49)
            //  MAC: 49 EADDRNOTAVAIL Cannot assign requested address.  Normally results from
            //          an attempt to create a socket with an address not on this
            //          machine.
            // on linux = send_socket error: UnreachableAddress

            std.debug.print("socket endpoint: {any}\n", .{socket.getLocalEndPoint()});
            std.debug.print("sending to {s}: {any}\n", .{ p.addr, p.size });
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

// TODO: fix
test "gossip.socket_utils: sending a packet" {
    var allocator = std.testing.allocator;
    var addr = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 9999);

    var gossip_socket = UdpSocket.create(.ipv4, .udp) catch return error.SocketCreateFailed;
    gossip_socket.bind(addr.toEndpoint()) catch return error.SocketBindFailed;
    gossip_socket.setReadTimeout(1000000) catch return error.SocketSetTimeoutFailed; // 1 second

    var send_channel = NonBlockingChannel(Packet).init(allocator, 10);
    defer send_channel.deinit();

    var exit = std.atomic.Atomic(bool).init(false);
    var responder_handle = try std.Thread.spawn(.{}, send_socket, .{
        &gossip_socket,
        send_channel,
        &exit,
    });
    defer responder_handle.join();

    var packet_buf: [PACKET_DATA_SIZE]u8 = undefined;
    var random_addr = SocketAddr.init_ipv4(.{ 103, 50, 32, 83 }, 8899);

    var packet = Packet.init(random_addr.toEndpoint(), packet_buf, 10);
    try send_channel.send(packet);

    std.time.sleep(std.time.ns_per_s * 4);

    exit.store(true, std.atomic.Ordering.Unordered);
}
