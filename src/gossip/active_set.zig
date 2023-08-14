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
const Ping = @import("ping_pong.zig").Ping;
const bincode = @import("../bincode/bincode.zig");
const crds = @import("../gossip/crds.zig");
const CrdsValue = crds.CrdsValue;

const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const get_wallclock = @import("../gossip/crds.zig").get_wallclock;

const _crds_table = @import("../gossip/crds_table.zig");
const CrdsTable = _crds_table.CrdsTable;
const CrdsError = _crds_table.CrdsError;
const Logger = @import("../trace/log.zig").Logger;
const GossipRoute = _crds_table.GossipRoute;

const pull_request = @import("../gossip/pull_request.zig");
const CrdsFilter = pull_request.CrdsFilter;
const MAX_NUM_PULL_REQUESTS = pull_request.MAX_NUM_PULL_REQUESTS;

const pull_response = @import("../gossip/pull_response.zig");
const GossipService = @import("../gossip/gossip_service.zig").GossipService;

var gpa_allocator = std.heap.GeneralPurposeAllocator(.{}){};
var gpa = gpa_allocator.allocator();

const PacketChannel = Channel(Packet);
const ProtocolMessage = struct { from_addr: EndPoint, message: Protocol };
const ProtocolChannel = Channel(ProtocolMessage);

const CRDS_GOSSIP_PULL_CRDS_TIMEOUT_MS: u64 = 15000;
const CRDS_GOSSIP_PUSH_MSG_TIMEOUT_MS: u64 = 30000;
const FAILED_INSERTS_RETENTION_MS: u64 = 20_000;
const MAX_BYTES_PER_PUSH: u64 = PACKET_DATA_SIZE * 64;
const PUSH_MESSAGE_MAX_PAYLOAD_SIZE: usize = PACKET_DATA_SIZE - 44;

const GOSSIP_SLEEP_MILLIS: u64 = 100;

const NUM_ACTIVE_SET_ENTRIES: usize = 25;
const CRDS_GOSSIP_PUSH_FANOUT: usize = 6;

pub const ActiveSet = struct {
    // store pubkeys as keys in crds table bc the data can change
    peers: [NUM_ACTIVE_SET_ENTRIES]Pubkey,
    len: u8,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .peers = undefined,
            .len = 0,
        };
    }

    pub fn get_fanout_peers(self: *const Self) []const Pubkey {
        const size = @min(CRDS_GOSSIP_PUSH_FANOUT, self.len);
        return self.peers[0..size];
    }

    pub fn reset(self: *Self, crds_table: *CrdsTable, my_pubkey: Pubkey, my_shred_version: u16) !void {
        const now = get_wallclock();
        var buf: [NUM_ACTIVE_SET_ENTRIES]crds.LegacyContactInfo = undefined;
        var crds_peers = try GossipService.get_gossip_nodes(
            crds_table,
            &my_pubkey,
            my_shred_version,
            &buf,
            NUM_ACTIVE_SET_ENTRIES,
            now,
        );

        const size = @min(crds_peers.len, NUM_ACTIVE_SET_ENTRIES);
        var rng = std.rand.DefaultPrng.init(get_wallclock());
        pull_request.shuffle_first_n(rng.random(), crds.LegacyContactInfo, crds_peers, size);

        for (0..size) |i| {
            self.peers[i] = crds_peers[i].id;
        }
        self.len = size;
    }
};
