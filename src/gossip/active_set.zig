const std = @import("std");
const network = @import("zig-network");
const sig = @import("../sig.zig");

const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const EndPoint = network.EndPoint;

const Pubkey = sig.core.Pubkey;
const Bloom = sig.bloom.Bloom;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const LegacyContactInfo = sig.gossip.data.LegacyContactInfo;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const GossipTable = sig.gossip.table.GossipTable;

const getWallclockMs = sig.time.getWallclockMs;

const NUM_ACTIVE_SET_ENTRIES: usize = 25;
pub const GOSSIP_PUSH_FANOUT: usize = 6;

const MIN_NUM_BLOOM_ITEMS: usize = 512;
const BLOOM_FALSE_RATE: f64 = 0.1;
const BLOOM_MAX_BITS: usize = 1024 * 8 * 4;

/// Store pubkeys as keys in the gossip table because the data can change
/// for each peer. A bloom filter is used to store pruned origins.
pub const ActiveSet = struct {
    peers: std.AutoHashMapUnmanaged(Pubkey, Bloom),

    pub const EMPTY: ActiveSet = .{ .peers = .{} };

    pub fn deinit(self: *ActiveSet, allocator: std.mem.Allocator) void {
        var iter = self.peers.iterator();
        while (iter.next()) |entry| entry.value_ptr.deinit(allocator);
        self.peers.deinit(allocator);
    }

    pub fn len(self: *const ActiveSet) u32 {
        return self.peers.count();
    }

    pub fn initRotate(
        self: *ActiveSet,
        allocator: std.mem.Allocator,
        random: std.Random,
        peers: []ThreadSafeContactInfo,
    ) error{OutOfMemory}!void {
        // clear the existing
        {
            var iter = self.peers.iterator();
            while (iter.next()) |entry| entry.value_ptr.deinit(allocator);
            self.peers.clearRetainingCapacity();
        }

        if (peers.len == 0) return;
        const size = @min(peers.len, NUM_ACTIVE_SET_ENTRIES);
        sig.rand.shuffleFocusedRange(random, ThreadSafeContactInfo, peers, 0, size);

        const bloom_num_items = @max(peers.len, MIN_NUM_BLOOM_ITEMS);
        for (0..size) |i| {
            const entry = try self.peers.getOrPut(allocator, peers[i].pubkey);
            if (entry.found_existing == false) {
                // TODO: *full* hard restart on blooms -- labs doesnt do this - bug?
                const bloom = try Bloom.initRandom(
                    allocator,
                    random,
                    bloom_num_items,
                    BLOOM_FALSE_RATE,
                    BLOOM_MAX_BITS,
                );
                entry.value_ptr.* = bloom;
            }
        }
    }

    pub fn prune(self: *ActiveSet, from: Pubkey, origin: Pubkey) void {
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
        self: *const ActiveSet,
        allocator: std.mem.Allocator,
        origin: Pubkey,
        table: *const GossipTable,
    ) error{OutOfMemory}!std.ArrayList(EndPoint) {
        var active_set_endpoints = try std.ArrayList(EndPoint).initCapacity(
            allocator,
            GOSSIP_PUSH_FANOUT,
        );
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

test "init/denit" {
    const allocator = std.testing.allocator;

    var table = try GossipTable.init(allocator, allocator);
    defer table.deinit();

    // insert some contacts
    var prng = std.Random.DefaultPrng.init(100);
    var gossip_peers = try std.ArrayList(ThreadSafeContactInfo).initCapacity(allocator, 10);
    defer gossip_peers.deinit();

    for (0..GOSSIP_PUSH_FANOUT) |_| {
        const data = LegacyContactInfo.initRandom(prng.random());
        try gossip_peers.append(ThreadSafeContactInfo.fromLegacyContactInfo(data));

        const keypair = KeyPair.generate();
        const value = SignedGossipData.initSigned(&keypair, .{
            .LegacyContactInfo = data,
        });
        _ = try table.insert(value, getWallclockMs());
    }

    var active_set: ActiveSet = .EMPTY;
    defer active_set.deinit(allocator);
    try active_set.initRotate(
        allocator,
        prng.random(),
        gossip_peers.items,
    );

    try std.testing.expect(active_set.len() == GOSSIP_PUSH_FANOUT);

    const origin = Pubkey.initRandom(prng.random());

    var fanout = try active_set.getFanoutPeers(allocator, origin, &table);
    defer fanout.deinit();
    const no_prune_fanout_len = fanout.items.len;
    try std.testing.expect(no_prune_fanout_len > 0);

    var iter = active_set.peers.keyIterator();
    const peer_pubkey = iter.next().?.*;
    active_set.prune(peer_pubkey, origin);

    var fanout_with_prune = try active_set.getFanoutPeers(allocator, origin, &table);
    defer fanout_with_prune.deinit();
    try std.testing.expectEqual(no_prune_fanout_len, fanout_with_prune.items.len + 1);
}

test "gracefully rotates with duplicate contact ids" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(100);
    var gossip_peers = try std.ArrayList(ThreadSafeContactInfo).initCapacity(allocator, 10);
    defer gossip_peers.deinit();

    var data = try LegacyContactInfo.initRandom(prng.random()).toContactInfo(allocator);
    var dupe = try LegacyContactInfo.initRandom(prng.random()).toContactInfo(allocator);
    defer data.deinit();
    defer dupe.deinit();
    dupe.pubkey = data.pubkey;
    try gossip_peers.append(ThreadSafeContactInfo.fromContactInfo(data));
    try gossip_peers.append(ThreadSafeContactInfo.fromContactInfo(dupe));

    var active_set: ActiveSet = .EMPTY;
    defer active_set.deinit(allocator);
    try active_set.initRotate(
        allocator,
        prng.random(),
        gossip_peers.items,
    );
}
