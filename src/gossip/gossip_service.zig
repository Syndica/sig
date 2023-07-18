const std = @import("std");
const ClusterInfo = @import("cluster_info.zig").ClusterInfo;
const network = @import("zig-network");
const EndPoint = network.EndPoint;
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
const crds = @import("../gossip/crds.zig");

var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
var gpa = gpa_allocator.allocator();

const PacketChannel = Channel(Packet);
// const ProtocolChannel = Channel(Protocol);

const logger = std.log.scoped(.gossip_service);

pub const GossipService = struct {
    cluster_info: *ClusterInfo,
    gossip_socket: UdpSocket,
    exit_sig: AtomicBool,
    packet_channel: PacketChannel,
    responder_channel: PacketChannel,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        cluster_info: *ClusterInfo,
        gossip_socket: UdpSocket,
        exit: AtomicBool,
    ) Self {
        var packet_channel = PacketChannel.init(allocator, 10000);
        var responder_channel = PacketChannel.init(allocator, 10000);

        return Self{
            .cluster_info = cluster_info,
            .gossip_socket = gossip_socket,
            .exit_sig = exit,
            .packet_channel = packet_channel,
            .responder_channel = responder_channel,
        };
    }

    pub fn deinit(self: *Self) void {
        self.packet_channel.deinit();
        self.responder_channel.deinit();
    }

    pub fn run(self: *Self) !void {
        logger.info("running gossip service at {any}", .{self.gossip_socket.getLocalEndPoint()});

        defer self.deinit();

        // spawn gossip udp receiver thread
        var receiver_handle = try Thread.spawn(.{}, Self.read_gossip_socket, .{self});
        var packet_handle = try Thread.spawn(.{}, Self.process_packets, .{
            self,
            gpa,
        });
        var responder_handle = try Thread.spawn(.{}, Self.responder, .{self});
        var gossip_loop_handle = try Thread.spawn(.{}, Self.gossip_loop, .{self});

        responder_handle.join();
        receiver_handle.join();
        packet_handle.join();
        gossip_loop_handle.join();
    }


    fn responder(self: *Self) !void { 
        while (self.responder_channel.receive()) |p| { 
            _ = try self.gossip_socket.sendTo(p.from, p.data[0..p.size]);
        }
    }

    fn gossip_loop(self: *Self) !void {
        // solana-gossip spy -- local node for testing
        const peer = SocketAddr.init_ipv4(.{ 0, 0, 0, 0 }, 8000).toEndpoint();

        while (true) {
            try self.send_ping(&peer);
            try self.push_contact_info(&peer);

            std.time.sleep(std.time.ns_per_s * 1);
        }
    }

    fn send_ping(self: *Self, peer: *const EndPoint) !void { 
        var protocol = Protocol{ .PingMessage = Ping.random(self.cluster_info.our_keypair) };
        var out = [_]u8{0} ** PACKET_DATA_SIZE;
        var bytes = try bincode.writeToSlice(out[0..], protocol, bincode.Params.standard);
        self.responder_channel.send(
            Packet.init(peer.*, out, bytes.len),
        );
    }

    fn push_contact_info(self: *Self, peer: *const EndPoint) !void { 
        const id = self.cluster_info.our_contact_info.pubkey;
        const gossip_endpoint = try self.gossip_socket.getLocalEndPoint();
        const gossip_addr = SocketAddr.init_ipv4(gossip_endpoint.address.ipv4.value, gossip_endpoint.port);
        const unspecified_addr = SocketAddr.init_ipv4(.{0, 0, 0, 0}, 0);
        const wallclock = @as(u64, @intCast(std.time.milliTimestamp()));

        var legacy_contact_info = crds.LegacyContactInfo {
            .id = id,
            .gossip = gossip_addr,
            .tvu = unspecified_addr,
            .tvu_forwards = unspecified_addr,
            .repair = unspecified_addr,
            .tpu = unspecified_addr,
            .tpu_forwards = unspecified_addr,
            .tpu_vote = unspecified_addr,
            .rpc = unspecified_addr,
            .rpc_pubsub = unspecified_addr,
            .serve_repair = unspecified_addr,
            .wallclock = wallclock,
            .shred_version = 0,
        };
        var crds_data = crds.CrdsData {
            .LegacyContactInfo = legacy_contact_info,
        };
        var crds_value = try crds.CrdsValue.initSigned(crds_data, self.cluster_info.our_keypair);
        var values = [_]crds.CrdsValue{ crds_value };

        const msg = Protocol {
            .PushMessage = .{
                id, 
                &values 
            },
        };

        var buf = [_]u8{0} ** PACKET_DATA_SIZE;
        var bytes = try bincode.writeToSlice(buf[0..], msg, bincode.Params.standard);
        const packet = Packet.init(peer.*, buf, bytes.len);
        self.responder_channel.send(packet);
    }

    fn read_gossip_socket(self: *Self) !void {
        // we close the chan if no more packet's can ever be produced
        defer self.packet_channel.close();

        // handle packet reads
        var read_buf: [PACKET_DATA_SIZE]u8 = undefined;
        @memset(&read_buf, 0);

        var bytes_read: usize = undefined;
        while (bytes_read != 0) {
            var recv_meta = try self.gossip_socket.receiveFrom(&read_buf);
            bytes_read = recv_meta.numberOfBytes;

            // send packet through channel
            self.packet_channel.send(Packet.init(recv_meta.sender, read_buf, bytes_read));

            // reset buffer
            @memset(&read_buf, 0);
        }

        logger.debug("reading gossip exiting...", .{});
    }

    pub fn process_packets(self: *Self, allocator: std.mem.Allocator) !void {
        while (self.packet_channel.receive()) |p| {
            // note: to recieve PONG messages (from a local spy node) from a PING
            // you need to modify: streamer/src/socket.rs
            // pub fn check(&self, addr: &SocketAddr) -> bool {
            //     return true;
            // }

            var protocol_message = try bincode.readFromSlice(allocator, Protocol, p.data[0..p.size], bincode.Params.standard);
            logger.debug("got a protocol message: {any}", .{protocol_message});
        }
    }
};
