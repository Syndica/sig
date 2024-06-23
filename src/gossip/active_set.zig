const std = @import("std");
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const network = @import("zig-network");
const EndPoint = network.EndPoint;
const _gossip_data = @import("../gossip/data.zig");
const SignedGossipData = _gossip_data.SignedGossipData;
const getWallclockMs = _gossip_data.getWallclockMs;
const ContactInfo = _gossip_data.ContactInfo;
const LegacyContactInfo = _gossip_data.LegacyContactInfo;

const Pubkey = @import("../core/pubkey.zig").Pubkey;
const GossipTable = @import("../gossip/table.zig").GossipTable;
const shuffleFirstN = @import("../gossip/pull_request.zig").shuffleFirstN;
const Bloom = @import("../bloom/bloom.zig").Bloom;

const NUM_ACTIVE_SET_ENTRIES: usize = 25;
pub const GOSSIP_PUSH_FANOUT: usize = 6;

const MIN_NUM_BLOOM_ITEMS: usize = 512;
const BLOOM_FALSE_RATE: f64 = 0.1;
const BLOOM_MAX_BITS: usize = 1024 * 8 * 4;

pub const ActiveSet = struct {
    // store pubkeys as keys in gossip table bc the data can change
    pruned_peers: std.AutoHashMap(Pubkey, Bloom),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .pruned_peers = std.AutoHashMap(Pubkey, Bloom).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.pruned_peers.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.pruned_peers.deinit();
    }

    pub fn len(self: *const Self) u32 {
        return self.pruned_peers.count();
    }

    pub fn rotate(
        self: *Self,
        peers: []ContactInfo,
    ) error{OutOfMemory}!void {
        // clear the existing
        var iter = self.pruned_peers.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.pruned_peers.clearRetainingCapacity();

        if (peers.len == 0) {
            return;
        }
        const size = @min(peers.len, NUM_ACTIVE_SET_ENTRIES);
        var rng = std.rand.DefaultPrng.init(getWallclockMs());
        shuffleFirstN(rng.random(), ContactInfo, peers, size);

        const bloom_num_items = @max(peers.len, MIN_NUM_BLOOM_ITEMS);
        for (0..size) |i| {
            const entry = try self.pruned_peers.getOrPut(peers[i].pubkey);
            if (entry.found_existing == false) {
                // *full* hard restart on blooms -- labs doesnt do this - bug?
                const prng_seed: u64 = @intCast(std.time.milliTimestamp());
                var prng = std.Random.Xoshiro256.init(prng_seed);
                const bloom = try Bloom.random(
                    self.allocator,
                    prng.random(),
                    bloom_num_items,
                    BLOOM_FALSE_RATE,
                    BLOOM_MAX_BITS,
                );
                entry.value_ptr.* = bloom;
            }
        }
    }

    pub fn prune(self: *Self, from: Pubkey, origin: Pubkey) void {
        // we only prune peers which we are sending push messages to
        if (self.pruned_peers.getEntry(from)) |entry| {
            const origin_bytes = origin.data;
            entry.value_ptr.add(&origin_bytes);
        }
    }

    /// get a set of GOSSIP_PUSH_FANOUT peers to send push messages to
    /// while accounting for peers that have been pruned from
    /// the given origin Pubkey
    pub fn getFanoutPeers(
        self: *const Self,
        allocator: std.mem.Allocator,
        origin: Pubkey,
        table: *const GossipTable,
    ) error{OutOfMemory}!std.ArrayList(EndPoint) {
        var active_set_endpoints = try std.ArrayList(EndPoint).initCapacity(allocator, GOSSIP_PUSH_FANOUT);
        errdefer active_set_endpoints.deinit();

        // change to while loop
        var iter = self.pruned_peers.iterator();
        while (iter.next()) |entry| {
            // lookup peer contact info
            const peer_info = table.getContactInfo(entry.key_ptr.*) orelse continue;
            const peer_gossip_addr = peer_info.getSocket(.gossip) orelse continue;

            peer_gossip_addr.sanitize() catch continue;

            // check if peer has been pruned
            const origin_bytes = origin.data;
            if (entry.value_ptr.contains(&origin_bytes)) {
                continue;
            }

            active_set_endpoints.appendAssumeCapacity(peer_gossip_addr.toEndpoint());
            if (active_set_endpoints.items.len == GOSSIP_PUSH_FANOUT) {
                break;
            }
        }

        return active_set_endpoints;
    }
};

test "gossip.active_set: init/deinit" {
    const alloc = std.testing.allocator;

    const ThreadPool = @import("../sync/thread_pool.zig").ThreadPool;
    var tp = ThreadPool.init(.{});
    var table = try GossipTable.init(alloc, &tp);
    defer table.deinit();

    // insert some contacts
    var rng = std.rand.DefaultPrng.init(100);
    var gossip_peers = try std.ArrayList(ContactInfo).initCapacity(alloc, 10);
    defer {
        for (gossip_peers.items) |p| p.deinit();
        gossip_peers.deinit();
    }

    for (0..GOSSIP_PUSH_FANOUT) |_| {
        var data = LegacyContactInfo.random(rng.random());
        try gossip_peers.append(try data.toContactInfo(alloc));

        var keypair = try KeyPair.create(null);
        const value = try SignedGossipData.initSigned(.{
            .LegacyContactInfo = data,
        }, &keypair);
        try table.insert(value, getWallclockMs());
    }

    var active_set = ActiveSet.init(alloc);
    defer active_set.deinit();
    try active_set.rotate(gossip_peers.items);

    try std.testing.expect(active_set.len() == GOSSIP_PUSH_FANOUT);

    const origin = Pubkey.random(rng.random());

    var fanout = try active_set.getFanoutPeers(alloc, origin, &table);
    defer fanout.deinit();
    const no_prune_fanout_len = fanout.items.len;
    try std.testing.expect(no_prune_fanout_len > 0);

    var iter = active_set.pruned_peers.keyIterator();
    const peer_pubkey = iter.next().?.*;
    active_set.prune(peer_pubkey, origin);

    var fanout_with_prune = try active_set.getFanoutPeers(alloc, origin, &table);
    defer fanout_with_prune.deinit();
    try std.testing.expectEqual(no_prune_fanout_len, fanout_with_prune.items.len + 1);
}

test "gossip.active_set: gracefully rotates with duplicate contact ids" {
    const alloc = std.testing.allocator;

    var rng = std.rand.DefaultPrng.init(100);
    var gossip_peers = try std.ArrayList(ContactInfo).initCapacity(alloc, 10);
    defer gossip_peers.deinit();

    var data = try LegacyContactInfo.random(rng.random()).toContactInfo(alloc);
    var dupe = try LegacyContactInfo.random(rng.random()).toContactInfo(alloc);
    defer data.deinit();
    defer dupe.deinit();
    dupe.pubkey = data.pubkey;
    try gossip_peers.append(data);
    try gossip_peers.append(dupe);

    var active_set = ActiveSet.init(alloc);
    defer active_set.deinit();
    try active_set.rotate(gossip_peers.items);
}
