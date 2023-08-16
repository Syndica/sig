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

const Bloom = @import("../bloom/bloom.zig").Bloom;

const NUM_ACTIVE_SET_ENTRIES: usize = 25;
pub const CRDS_GOSSIP_PUSH_FANOUT: usize = 6;

const MIN_NUM_BLOOM_ITEMS: usize = 512;
const BLOOM_FALSE_RATE: f64 = 0.1;
const BLOOM_MAX_BITS: usize = 1024 * 8 * 4;

pub const ActiveSet = struct {
    // store pubkeys as keys in crds table bc the data can change
    peers: [NUM_ACTIVE_SET_ENTRIES]Pubkey,
    pruned_nodes: std.AutoHashMap(Pubkey, Bloom),
    len: u8 = 0,

    const Self = @This();

    pub fn rotate(
        alloc: std.mem.Allocator,
        crds_table: *CrdsTable,
        my_pubkey: Pubkey,
        my_shred_version: u16,
    ) !Self {
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

        var peers: [NUM_ACTIVE_SET_ENTRIES]Pubkey = undefined;
        var pruned_peers = std.AutoHashMap(Pubkey, Bloom).init(alloc);

        if (crds_peers.len == 0) {
            return Self{ .peers = peers, .len = 0, .pruned_nodes = pruned_peers };
        }

        const size = @min(crds_peers.len, NUM_ACTIVE_SET_ENTRIES);
        var rng = std.rand.DefaultPrng.init(get_wallclock());
        pull_request.shuffle_first_n(rng.random(), crds.LegacyContactInfo, crds_peers, size);

        const bloom_num_items = @max(crds_peers.len, MIN_NUM_BLOOM_ITEMS);
        for (0..size) |i| {
            peers[i] = crds_peers[i].id;

            // *full* hard restart on blooms -- labs doesnt do this - bug?
            var bloom = try Bloom.random(
                alloc,
                bloom_num_items,
                BLOOM_FALSE_RATE,
                BLOOM_MAX_BITS,
            );
            try pruned_peers.put(peers[i], bloom);
        }

        return Self{
            .peers = peers,
            .len = size,
            .pruned_nodes = pruned_peers,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.peers[0..self.len]) |peer| {
            var entry = self.pruned_nodes.getEntry(peer).?;
            entry.value_ptr.deinit();
        }
        self.pruned_nodes.deinit();
    }

    pub fn prune(self: *Self, from: Pubkey, origin: Pubkey) void {
        if (self.pruned_nodes.getEntry(from)) |entry| {
            const origin_bytes = origin.data;
            entry.value_ptr.add(&origin_bytes);
        }
    }

    pub fn get_fanout_peers(
        self: *const Self,
        allocator: std.mem.Allocator,
        origin: Pubkey,
        crds_table: *CrdsTable,
    ) !std.ArrayList(EndPoint) {
        var active_set_endpoints = std.ArrayList(EndPoint).init(allocator);
        errdefer active_set_endpoints.deinit();

        // change to while loop
        for (self.peers[0..self.len]) |peer_pubkey| {
            const peer_info = crds_table.get(crds.CrdsValueLabel{
                .LegacyContactInfo = peer_pubkey,
            }).?;
            const peer_gossip_addr = peer_info.value.data.LegacyContactInfo.gossip;

            crds.sanitize_socket(&peer_gossip_addr) catch continue;

            const entry = self.pruned_nodes.getEntry(peer_pubkey).?;
            const origin_bytes = origin.data;
            if (entry.value_ptr.contains(&origin_bytes)) {
                continue;
            }

            try active_set_endpoints.append(peer_gossip_addr.toEndpoint());
            if (active_set_endpoints.items.len == CRDS_GOSSIP_PUSH_FANOUT) {
                break;
            }
        }

        return active_set_endpoints;
    }
};

test "gossip.active_set: init/deinit" {
    var alloc = std.testing.allocator;

    var crds_table = try CrdsTable.init(alloc);
    defer crds_table.deinit();

    // insert some contacts
    var rng = std.rand.DefaultPrng.init(100);
    for (0..CRDS_GOSSIP_PUSH_FANOUT) |_| {
        var keypair = try KeyPair.create(null);
        var value = try CrdsValue.random_with_index(rng.random(), keypair, 0);
        try crds_table.insert(value, get_wallclock(), null);
    }

    var kp = try KeyPair.create(null);
    var pk = Pubkey.fromPublicKey(&kp.public_key, true);
    var active_set = try ActiveSet.rotate(
        alloc,
        &crds_table,
        pk,
        0,
    );
    defer active_set.deinit();

    try std.testing.expect(active_set.len == CRDS_GOSSIP_PUSH_FANOUT);

    const origin = Pubkey.random(rng.random(), .{});

    var fanout = try active_set.get_fanout_peers(alloc, origin, &crds_table);
    defer fanout.deinit();
    const no_prune_fanout_len = fanout.items.len;
    try std.testing.expect(no_prune_fanout_len > 0);

    const peer_pubkey = active_set.peers[0];
    active_set.prune(peer_pubkey, origin);

    var fanout_with_prune = try active_set.get_fanout_peers(alloc, origin, &crds_table);
    defer fanout_with_prune.deinit();
    try std.testing.expectEqual(no_prune_fanout_len, fanout_with_prune.items.len + 1);
}
