const std = @import("std");
const ClusterInfo = @import("cluster_info.zig").ClusterInfo;
const network = @import("zig-network");
const Packet = @import("packet.zig").Packet;
const PACKET_DATA_SIZE = @import("packet.zig").PACKET_DATA_SIZE;
const Channel = @import("../sync/channel.zig").Channel;
const Thread = std.Thread;
const AtomicBool = std.atomic.Atomic(bool);
const UdpSocket = network.Socket;
const Tuple = std.meta.Tuple;
const SocketAddr = @import("net.zig").SocketAddr;
const Protocol = @import("protocol.zig").Protocol;
const Ping = @import("protocol.zig").Ping;
const bincode = @import("bincode-zig");

var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
var gpa = gpa_allocator.allocator();

const PacketChannel = Channel(Packet);
const logger = std.log.scoped(.gossip_service);

pub const GossipService = struct {
    cluster_info: *ClusterInfo,
    gossip_socket: UdpSocket,
    exit_sig: AtomicBool,
    packet_chan: PacketChannel,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        cluster_info: *ClusterInfo,
        gossip_socket: UdpSocket,
        exit: AtomicBool,
    ) Self {
        var channel = PacketChannel.init(allocator, 10000);

        return Self{
            .cluster_info = cluster_info,
            .gossip_socket = gossip_socket,
            .exit_sig = exit,
            .packet_chan = channel,
        };
    }

    pub fn deinit(self: *Self) void {
        self.packet_chan.deinit();
    }

    pub fn run(self: *Self) !void {
        logger.info("running gossip service on at {any}", .{self.gossip_socket.getLocalEndPoint()});

        defer self.deinit();

        // spawn gossip udp receiver thread
        var gossip_handle = try Thread.spawn(.{}, Self.read_gossip_socket, .{self});
        var packet_handle = try Thread.spawn(.{}, ClusterInfo.processPackets, .{
            self.cluster_info,
            gpa,
            &self.packet_chan,
        });
        var random_packet_handle = try Thread.spawn(.{}, Self.generate_random_ping_protocols, .{self});

        gossip_handle.join();
        packet_handle.join();
        random_packet_handle.join();
    }

    fn generate_random_ping_protocols(self: *Self) !void {
        while (true) {
            std.time.sleep(std.time.ns_per_s * 1);
            var protocol = Protocol{ .PingMessage = Ping.random(self.cluster_info.our_keypair) };
            var out = [_]u8{0} ** PACKET_DATA_SIZE;
            var bytes = try bincode.writeToSlice(out[0..], protocol, bincode.Params.standard);
            self.packet_chan.send(
                Packet.init(SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 1000).toEndpoint(), out, bytes.len),
            );
        }
    }

    fn read_gossip_socket(self: *Self) !void {
        // we close the chan if no more packet's can ever be produced
        defer self.packet_chan.close();

        // handle packet reads
        var read_buf: [PACKET_DATA_SIZE]u8 = undefined;
        @memset(&read_buf, 0);

        var bytes_read: usize = undefined;
        var first_run = true;
        while (first_run or bytes_read != 0) {
            if (first_run) {
                first_run = false;
                continue;
            }

            var recv_meta = try self.gossip_socket.receiveFrom(&read_buf);
            bytes_read = recv_meta.numberOfBytes;

            // send packet through channel
            self.packet_chan.send(Packet.init(recv_meta.sender, read_buf, recv_meta.numberOfBytes));

            // reset buffer
            @memset(&read_buf, 0);
        }
    }
};
