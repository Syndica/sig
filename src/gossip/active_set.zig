const std = @import("std");
const network = @import("zig-network");
const sig = @import("../lib.zig");

const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const EndPoint = network.EndPoint;

const Pubkey = sig.core.Pubkey;
const Bloom = sig.bloom.Bloom;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const LegacyContactInfo = sig.gossip.data.LegacyContactInfo;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const GossipTable = sig.gossip.table.GossipTable;

const getWallclockMs = sig.gossip.getWallclockMs;
const shuffleFirstN = sig.gossip.pull_request.shuffleFirstN;

const NUM_ACTIVE_SET_ENTRIES: usize = 25;
pub const GOSSIP_PUSH_FANOUT: usize = 6;

const MIN_NUM_BLOOM_ITEMS: usize = 512;
const BLOOM_FALSE_RATE: f64 = 0.1;
const BLOOM_MAX_BITS: usize = 1024 * 8 * 4;

pub const ActiveSet = struct {
    // store pubkeys as keys in gossip table bc the data can change
    // For each peer, a bloom filter is used to store pruned origins
    peers: std.AutoHashMap(Pubkey, Bloom),
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .peers = std.AutoHashMap(Pubkey, Bloom).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.peers.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.peers.deinit();
    }

    pub fn len(self: *const Self) u32 {
        return self.peers.count();
    }

    pub fn rotate(
        self: *Self,
        rand: std.Random,
        peers: []ThreadSafeContactInfo,
    ) error{OutOfMemory}!void {
        // clear the existing
        var iter = self.peers.iterator();
        while (iter.next()) |entry| {
            entry.value_ptr.deinit();
        }
        self.peers.clearRetainingCapacity();

        if (peers.len == 0) {
            return;
        }
        const size = @min(peers.len, NUM_ACTIVE_SET_ENTRIES);
        shuffleFirstN(rand, ThreadSafeContactInfo, peers, size);

        const bloom_num_items = @max(peers.len, MIN_NUM_BLOOM_ITEMS);
        for (0..size) |i| {
            const entry = try self.peers.getOrPut(peers[i].pubkey);
            if (entry.found_existing == false) {
                // *full* hard restart on blooms -- labs doesnt do this - bug?
                const bloom = try Bloom.random(
                    self.allocator,
                    rand,
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
        if (self.peers.getEntry(from)) |entry| {
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

        var iter = self.peers.iterator();
        while (iter.next()) |entry| {
            // lookup peer contact info
            const peer_info = table.getThreadSafeContactInfo(entry.key_ptr.*) orelse continue;
            const peer_gossip_addr = peer_info.gossip_addr orelse continue;

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
    var gossip_peers = try std.ArrayList(ThreadSafeContactInfo).initCapacity(alloc, 10);
    defer gossip_peers.deinit();

    for (0..GOSSIP_PUSH_FANOUT) |_| {
        const data = LegacyContactInfo.random(rng.random());
        try gossip_peers.append(ThreadSafeContactInfo.fromLegacyContactInfo(data));

        var keypair = try KeyPair.create(null);
        const value = try SignedGossipData.initSigned(.{
            .LegacyContactInfo = data,
        }, &keypair);
        try table.insert(value, getWallclockMs());
    }

    var active_set = ActiveSet.init(alloc);
    defer active_set.deinit();
    var prng = std.Random.Xoshiro256.init(@intCast(std.time.milliTimestamp()));
    try active_set.rotate(prng.random(), gossip_peers.items);

    try std.testing.expect(active_set.len() == GOSSIP_PUSH_FANOUT);

    const origin = Pubkey.random(rng.random());

    var fanout = try active_set.getFanoutPeers(alloc, origin, &table);
    defer fanout.deinit();
    const no_prune_fanout_len = fanout.items.len;
    try std.testing.expect(no_prune_fanout_len > 0);

    var iter = active_set.peers.keyIterator();
    const peer_pubkey = iter.next().?.*;
    active_set.prune(peer_pubkey, origin);

    var fanout_with_prune = try active_set.getFanoutPeers(alloc, origin, &table);
    defer fanout_with_prune.deinit();
    try std.testing.expectEqual(no_prune_fanout_len, fanout_with_prune.items.len + 1);
}

test "gossip.active_set: gracefully rotates with duplicate contact ids" {
    const alloc = std.testing.allocator;

    var rng = std.rand.DefaultPrng.init(100);
    var gossip_peers = try std.ArrayList(ThreadSafeContactInfo).initCapacity(alloc, 10);
    defer gossip_peers.deinit();

    var data = try LegacyContactInfo.random(rng.random()).toContactInfo(alloc);
    var dupe = try LegacyContactInfo.random(rng.random()).toContactInfo(alloc);
    defer data.deinit();
    defer dupe.deinit();
    dupe.pubkey = data.pubkey;
    try gossip_peers.append(ThreadSafeContactInfo.fromContactInfo(data));
    try gossip_peers.append(ThreadSafeContactInfo.fromContactInfo(dupe));

    var active_set = ActiveSet.init(alloc);
    defer active_set.deinit();
    var prng = std.Random.Xoshiro256.init(@intCast(std.time.milliTimestamp()));
    try active_set.rotate(prng.random(), gossip_peers.items);
}
