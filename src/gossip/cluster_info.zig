const std = @import("std");
const ContactInfo = @import("node.zig").ContactInfo;
const UdpSocket = @import("zig-network").Socket;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const SocketAddr = @import("net.zig").SocketAddr;
const cmd = @import("cmd.zig");
const LegacyContactInfo = @import("crds.zig").LegacyContactInfo;
const NodeInstance = @import("crds.zig").NodeInstance;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const ArrayList = std.ArrayList;
const Channel = @import("../sync/channel.zig").Channel;
const Packet = @import("packet.zig").Packet;
const Protocol = @import("protocol.zig").Protocol;
const bincode = @import("../bincode/bincode.zig");
const CrdsValue = @import("crds.zig").CrdsValue;
const CrdsData = @import("crds.zig").CrdsData;
const Version = @import("crds.zig").Version;
const Logger = @import("../trace/log.zig").Logger;
const RwLock = std.Thread.RwLock;

const GOSSIP_SLEEP_MILLIS: i64 = 100;

const GossipController = struct {};

pub const ClusterInfo = struct {
    gossip_controller: GossipController = .{},
    our_keypair: KeyPair,
    our_contact_info: ContactInfo,
    our_node_instance: NodeInstance,
    entrypoints: ArrayList(LegacyContactInfo),
    outbound_socket: UdpSocket,
    push_messages: ArrayList(CrdsValue),
    push_messages_rwlock: RwLock = .{},

    pub fn discover() void {}

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, keypair: KeyPair, entrypoints: ArrayList(LegacyContactInfo), contact_info: ContactInfo) !Self {
        var outbound = try UdpSocket.create(.ipv4, .udp);
        try outbound.bindToPort(0);
        var node_instance = NodeInstance.init(Pubkey.fromPublicKey(&keypair.public_key, false), @intCast(std.time.microTimestamp()));
        return Self{
            .our_keypair = keypair,
            .our_contact_info = contact_info,
            .our_node_instance = node_instance,
            .entrypoints = entrypoints,
            .outbound_socket = outbound,
            .push_messages = ArrayList(CrdsValue).init(allocator),
        };
    }

    const ClusterInfoPlus = struct {
        cluster_info: ClusterInfo,
        our_contact_info: ContactInfo,
        gossip_socket: UdpSocket,
        keypair: KeyPair,
    };

    pub fn initSpy(allocator: std.mem.Allocator, gossip_socket_addr: SocketAddr, entrypoints: ArrayList(LegacyContactInfo), logger: *Logger) !ClusterInfoPlus {
        // bind to gosssip socket port
        var gossip_socket = try UdpSocket.create(.ipv4, .udp);
        try gossip_socket.bind(gossip_socket_addr.toEndpoint());

        // get or init our keypair
        var keypair = try cmd.getOrInitIdentity(allocator, logger);

        // build our spy contact info
        var our_contact_info = try ContactInfo.initSpy(
            allocator,
            Pubkey.fromPublicKey(&keypair.public_key, false),
            gossip_socket_addr,
            0,
        );

        // init cluster info
        var cluster_info = try Self.init(allocator, keypair, entrypoints, our_contact_info);

        return ClusterInfoPlus{
            .cluster_info = cluster_info,
            .our_contact_info = our_contact_info,
            .gossip_socket = gossip_socket,
            .keypair = keypair,
        };
    }

    pub fn gossip(self: *Self) !void {
        var crds_data_version: CrdsData = .{ .Version = Version.default(self.our_contact_info.pubkey) };
        var crds_data_instance: CrdsData = .{ .NodeInstance = self.our_node_instance.withWallclock(@as(u64, @intCast(std.time.milliTimestamp()))) };
        self.push_messages_rwlock.lock();
        defer self.push_messages_rwlock.unlock();
        try self.push_messages.append(try CrdsValue.initSigned(crds_data_version, self.our_keypair));
        try self.push_messages.append(try CrdsValue.initSigned(crds_data_instance, self.our_keypair));

        while (true) {

            // sleep
            var start = std.time.milliTimestamp();
            var elapsed = std.time.milliTimestamp() - start;
            std.time.sleep(std.time.ns_per_ms(GOSSIP_SLEEP_MILLIS - elapsed));
        }
    }
};
