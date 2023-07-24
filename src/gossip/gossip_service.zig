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

const _crds_table = @import("../gossip/crds_table.zig");
const CrdsTable = _crds_table.CrdsTable;
const CrdsError = _crds_table.CrdsError;
const Logger = @import("../trace/log.zig").Logger;

var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
var gpa = gpa_allocator.allocator();

const PacketChannel = Channel(Packet);
// const ProtocolChannel = Channel(Protocol);

const CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS: u64 = 30000;

pub fn get_wallclock() u64 {
    return @intCast(std.time.milliTimestamp());
}

pub const GossipService = struct {
    cluster_info: *ClusterInfo,
    gossip_socket: UdpSocket,
    exit_sig: AtomicBool,
    packet_channel: PacketChannel,
    responder_channel: PacketChannel,
    crds_table: CrdsTable,

    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        cluster_info: *ClusterInfo,
        gossip_socket: UdpSocket,
        exit: AtomicBool,
    ) Self {
        var packet_channel = PacketChannel.init(allocator, 10000);
        var responder_channel = PacketChannel.init(allocator, 10000);
        var crds_table = CrdsTable.init(allocator);

        return Self{
            .cluster_info = cluster_info,
            .gossip_socket = gossip_socket,
            .exit_sig = exit,
            .packet_channel = packet_channel,
            .responder_channel = responder_channel,
            .crds_table = crds_table,
        };
    }

    pub fn deinit(self: *Self) void {
        self.packet_channel.deinit();
        self.responder_channel.deinit();
        self.crds_table.deinit();
    }

    pub fn run(self: *Self, logger: *Logger) !void {
        const id = self.cluster_info.our_contact_info.pubkey;
        logger.infof("running gossip service at {any} with pubkey {s}", .{ self.gossip_socket.getLocalEndPoint(), id.cached_str.? });
        defer self.deinit();

        // spawn gossip udp receiver thread
        var receiver_handle = try Thread.spawn(.{}, Self.read_gossip_socket, .{ self, logger });
        var packet_handle = try Thread.spawn(.{}, Self.process_packets, .{ self, gpa, logger });
        var responder_handle = try Thread.spawn(.{}, Self.responder, .{self});
        var gossip_loop_handle = try Thread.spawn(.{}, Self.gossip_loop, .{ self, logger });

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

    fn gossip_loop(self: *Self, logger: *Logger) !void {
        // solana-gossip spy -- local node for testing
        const peer = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, 8000).toEndpoint();

        while (true) {
            try self.send_ping(&peer, logger);
            try self.push_contact_info(&peer);

            std.time.sleep(std.time.ns_per_s * 1);
        }
    }

    fn send_ping(self: *Self, peer: *const EndPoint, logger: *Logger) !void {
        var protocol = Protocol{ .PingMessage = Ping.random(self.cluster_info.our_keypair) };
        var out = [_]u8{0} ** PACKET_DATA_SIZE;
        var bytes = try bincode.writeToSlice(out[0..], protocol, bincode.Params.standard);

        logger.debugf("sending a ping message to: {any}", .{peer});
        self.responder_channel.send(
            Packet.init(peer.*, out, bytes.len),
        );
    }

    fn push_contact_info(self: *Self, peer: *const EndPoint) !void {
        const id = self.cluster_info.our_contact_info.pubkey;
        const gossip_endpoint = try self.gossip_socket.getLocalEndPoint();
        const gossip_addr = SocketAddr.init_ipv4(gossip_endpoint.address.ipv4.value, gossip_endpoint.port);
        const unspecified_addr = SocketAddr.init_ipv4(.{ 0, 0, 0, 0 }, 0);
        const wallclock = get_wallclock();

        var legacy_contact_info = crds.LegacyContactInfo{
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
        var crds_data = crds.CrdsData{
            .LegacyContactInfo = legacy_contact_info,
        };
        var crds_value = try crds.CrdsValue.initSigned(crds_data, self.cluster_info.our_keypair);
        var values = [_]crds.CrdsValue{crds_value};

        const msg = Protocol{
            .PushMessage = .{ id, &values },
        };

        var buf = [_]u8{0} ** PACKET_DATA_SIZE;
        var bytes = try bincode.writeToSlice(buf[0..], msg, bincode.Params.standard);
        const packet = Packet.init(peer.*, buf, bytes.len);
        self.responder_channel.send(packet);
    }

    fn read_gossip_socket(self: *Self, logger: *Logger) !void {
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

        logger.debugf("reading gossip exiting...", .{});
    }

    pub fn process_packets(self: *Self, allocator: std.mem.Allocator, logger: *Logger) !void {
        var failed_protocol_msgs: usize = 0;

        while (self.packet_channel.receive()) |p| {
            // note: to recieve PONG messages (from a local spy node) from a PING
            // you need to modify: streamer/src/socket.rs
            // pub fn check(&self, addr: &SocketAddr) -> bool {
            //     return true;
            // }

            var protocol_message = bincode.readFromSlice(allocator, Protocol, p.data[0..p.size], bincode.Params.standard) catch {
                failed_protocol_msgs += 1;
                logger.debugf("failed to read protocol message from: {any} -- total failed: {d}", .{ p.from, failed_protocol_msgs });
                continue;
            };

            switch (protocol_message) {
                .PongMessage => |*pong| {
                    if (pong.signature.verify(pong.from, &pong.hash.data)) {
                        logger.debugf("got a pong message", .{});
                    } else {
                        logger.debugf("pong message verification failed...", .{});
                    }
                },
                .PingMessage => |*ping| {
                    if (ping.signature.verify(ping.from, &ping.token)) {
                        logger.debugf("got a ping message", .{});
                    } else {
                        logger.debugf("ping message verification failed...", .{});
                    }
                },
                .PushMessage => |*push| {
                    logger.debugf("got a push message: {any}", .{protocol_message});
                    const values = push[1];
                    handle_push_message(&self.crds_table, values, logger);
                },
                else => {
                    logger.debugf("got a protocol message: {any}", .{protocol_message});
                },
            }
        }
    }

    pub fn handle_push_message(crds_table: *CrdsTable, values: []crds.CrdsValue, logger: *Logger) void {
        var now = get_wallclock();

        for (values) |value| {
            const value_time = value.wallclock();
            const is_too_new = value_time > now +| CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS;
            const is_too_old = value_time < now -| CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS;
            if (is_too_new or is_too_old) {
                continue;
            }

            crds_table.insert(value, now) catch |err| switch (err) {
                CrdsError.OldValue => {
                    logger.debugf("failed to insert into crds: {any}", .{value});
                },
                else => {
                    logger.debugf("failed to insert into crds with unkown error: {any}", .{err});
                },
            };
        }
    }
};
