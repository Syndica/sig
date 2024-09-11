const std = @import("std");
const sig = @import("../sig.zig");

const IpAddr = sig.net.IpAddr;
const SocketAddr = sig.net.SocketAddr;
const ShredId = sig.ledger.shred.ShredId;
const RwMux = sig.sync.RwMux;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const BankFields = sig.accounts_db.snapshots.BankFields;
const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const Slot = sig.core.Slot;
const Duration = sig.time.Duration;
const Instant = sig.time.Instant;
const WeightedShuffle = sig.rand.WeightedShuffle(u64);
const ChaChaRng = sig.rand.ChaChaRng(20);

pub const TurbineTreeCache = struct {
    allocator: std.mem.Allocator,
    cache: std.AutoArrayHashMap(Epoch, CacheEntry),
    ttl: Duration,

    pub const CacheEntry = struct {
        created: Instant,
        turbine_tree: TurbineTree,

        pub fn alive(self: *const CacheEntry, ttl: Duration) bool {
            return self.created.elapsed().asNanos() < ttl.asNanos();
        }
    };

    pub fn init(allocator: std.mem.Allocator, ttl: Duration) TurbineTreeCache {
        return .{
            .allocator = allocator,
            .cache = std.AutoArrayHashMap(Epoch, CacheEntry).init(allocator),
            .ttl = ttl,
        };
    }

    pub fn getTurbineTree(self: TurbineTreeCache, bank_fields: *const BankFields) *const TurbineTree {
        const entry = try self.cache.getOrPut(bank_fields.epoch);
        if (entry.found_existing and self.cacheEntryAlive(entry.value_ptr)) {
            return &entry.value_ptr[1];
        }

        const epoch_staked_nodes = try bank_fields.getStakedNodes();
        // const turbine_tree = TurbineTree.initForRetransmit(
        //     self.allocator,
        //     my_contact_info,
        //     tvu_peers,
        //     epoch_staked_nodes,
        // );
        _ = epoch_staked_nodes;
    }

    pub fn cacheEntryAlive(self: TurbineTreeCache, cache_entry: *CacheEntry) bool {
        return cache_entry[0].elapsed().asNanos() < self.ttl.asNanos();
    }
};

/// Analogous to [ClusterNodes](https://github.com/anza-xyz/agave/blob/efd47046c1bb9bb027757ddabe408315bc7865cc/turbine/src/cluster_nodes.rs#L65)
pub const TurbineTree = struct {
    allocator: std.mem.Allocator,
    my_pubkey: Pubkey,
    nodes: []const Node,
    index: std.AutoArrayHashMap(Pubkey, usize),
    weighted_shuffle: WeightedShuffle,

    const DATA_PLANE_FANOUT = 200;
    const MAX_NODES_PER_IP = 2;

    const NodeId = union(enum) {
        contact_info: ThreadSafeContactInfo,
        pubkey: Pubkey,
    };

    const Node = struct {
        id: NodeId,
        stake: u64,

        pub fn pubkey(self: Node) Pubkey {
            return switch (self.id) {
                .contact_info => |ci| ci.pubkey,
                .pubkey => |pk| pk,
            };
        }

        pub fn contactInfo(self: Node) ?ThreadSafeContactInfo {
            return switch (self.id) {
                .contact_info => |ci| ci,
                .pubkey => null,
            };
        }

        pub fn fromContactInfo(ci: ThreadSafeContactInfo) Node {
            return .{ .id = .contact_info(ci), .stake = ci.stake };
        }

        pub fn random(rng: std.rand.Random) Node {
            // TODO: use float for selecting probability of contact info vs pubkey
            return .{ .id = .{ .pubkey = Pubkey.random(rng) }, .stake = rng.intRangeLessThan(u64, 0, 1_000) };
        }
    };

    pub fn initForBroadcast(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        tvu_peers: []const ThreadSafeContactInfo,
        stakes: *std.AutoArrayHashMap(Pubkey, u64),
    ) !TurbineTree {
        var tree = try initForRetransmit(
            allocator,
            my_contact_info,
            tvu_peers,
            stakes,
        );
        tree.weighted_shuffle.removeIndex(tree.index.get(my_contact_info.pubkey).?);
        return tree;
    }

    pub fn initForRetransmit(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        tvu_peers: []const ThreadSafeContactInfo,
        stakes: *const std.AutoArrayHashMap(Pubkey, u64),
    ) !TurbineTree {
        const nodes = try getNodes(allocator, my_contact_info, tvu_peers, stakes);
        errdefer allocator.free(nodes);

        var index = std.AutoArrayHashMap(Pubkey, usize).init(allocator);
        errdefer index.deinit();
        for (nodes, 0..) |node, i| try index.put(node.pubkey(), i);

        var node_stakes = try std.ArrayList(u64).initCapacity(allocator, nodes.len);
        defer node_stakes.deinit();
        for (nodes) |node| try node_stakes.append(node.stake);

        const weighted_shuffle = try WeightedShuffle.init(allocator, node_stakes.items);

        return .{
            .allocator = allocator,
            .my_pubkey = my_contact_info.pubkey,
            .nodes = nodes,
            .index = index,
            .weighted_shuffle = weighted_shuffle,
        };
    }

    pub fn deinit(self: *TurbineTree) void {
        self.allocator.free(self.nodes);
        self.index.deinit();
        self.weighted_shuffle.deinit();
    }

    pub fn getBroadcastPeer(
        self: *const TurbineTree,
        shred: *ShredId,
    ) ?*ThreadSafeContactInfo {
        const rng = getSeededRng(self.my_pubkey, shred);
        const index = self.weighted_shuffle.first(rng).?;
        return self.nodes[index].contactInfo();
    }

    pub fn getRetransmitAddresses(
        self: *const TurbineTree,
        allocator: std.mem.Allocator,
        slot_leader: Pubkey,
        shred: *ShredId,
        fanout: usize,
    ) struct {
        usize,
        []SocketAddr,
    } {
        const root_distance, const children, const addresses = try self.getRetransmitChildren(slot_leader, shred, fanout);
        var peers = std.ArrayList(SocketAddr).init(allocator);
        for (children) |child| {
            if (child.contactInfo()) |ci| {
                if (addresses.get(ci.tvu_addr) == ci.pubkey()) peers.append(ci.tvu_addr);
            }
        }
        return .{ root_distance, peers.toOwnedSlice() };
    }

    pub fn getRetransmitChildren(
        self: *const TurbineTree,
        allocator: std.mem.Allocator,
        slot_leader: *Pubkey,
        shred: *ShredId,
        fanout: usize,
    ) !struct {
        root_distance: usize,
        children: []const Node,
        addresses: std.AutoArrayHashMap(SocketAddr, Pubkey),
    } {
        if (slot_leader == self.my_pubkey) return error{LoopBack};

        var weighted_shuffle = self.weighted_shuffle.clone();
        if (self.index.get(slot_leader)) |index| weighted_shuffle.removeIndex(index);

        var nodes = std.ArrayList(*Node).init(allocator);
        var addresses = std.AutoArrayHashMap(SocketAddr, Pubkey).init(allocator);
        var shuffled = weighted_shuffle.shuffle(getSeededRng(slot_leader, shred));
        while (shuffled.next()) |index| {
            const node = self.nodes[index];
            if (node.contactInfo()) |ci| {
                if (ci.tvu_addr) |addr| addresses.put(addr, node.pubkey());
            }
            try nodes.append(&node);
        }

        // TODO: Use proper search
        const my_index: usize = undefined;
        for (nodes.items, 0..) |node, index| {
            if (node.pubkey() == self.my_pubkey) {
                my_index = index;
            }
        }
        const root_distance: usize = if (my_index == 0)
            0
        else if (my_index <= fanout)
            1
        else if (my_index <= fanout +| 1 *| fanout)
            2
        else
            3;

        const peers = try computeRetransmitChildren(
            allocator,
            fanout,
            my_index,
            nodes,
        );

        return .{ root_distance, peers, addresses };
    }

    fn computeRetransmitChildren(
        allocator: std.mem.Allocator,
        fanout: usize,
        index: usize,
        nodes: []const Node,
    ) ![]Node {
        var peers = std.ArrayList(Node).init(allocator);
        errdefer peers.deinit();

        const offset = (index -| 1) % fanout;
        const anchor = index - offset;
        const step = if (index == 0) 1 else fanout;
        var curr = anchor * fanout + offset + 1;
        var steps: usize = 0;
        while (curr < nodes.len and steps < fanout) {
            try peers.append(nodes[curr]);
            curr += step;
            steps += 1;
        }

        return peers.toOwnedSlice();
    }

    pub fn getRetransmitParent(
        self: *const TurbineTree,
        allocator: std.mem.Allocator,
        slot_leader: *Pubkey,
        shred: *ShredId,
        fanout: usize,
    ) !?Pubkey {
        if (slot_leader == self.my_pubkey) return error{LoopBack};
        if (self.nodes.items[self.index.get(self.my_pubkey).?].stake == 0) return null;

        var weighted_shuffle = self.weighted_shuffle.clone();
        if (self.index.get(slot_leader)) |index| weighted_shuffle.removeIndex(index);

        var nodes = std.ArrayList(*Node).init(allocator);
        var shuffled = weighted_shuffle.shuffle(getSeededRng(slot_leader, shred));
        while (shuffled.next()) |index| {
            if (self.nodes[index].pubkey() == self.my_pubkey) break;
            try nodes.append(&self.nodes[index]);
        }

        return computeRetransmitParent(fanout, nodes.items.len, nodes);
    }

    fn computeRetransmitParent(
        fanout: usize,
        index_: usize,
        nodes: []const Node,
    ) ?Pubkey {
        var index = index_;
        const offset = (index -| 1) % fanout;
        index = if (index == 0) return null else (index - 1) / fanout;
        index = index - (index -| 1) % fanout;
        index = if (index == 0) index else index + offset;
        return nodes[index].pubkey();
    }

    /// Agave uses slot and root bank to check for feature activation for
    /// running fanout experiments. Fine to just use a constant until we
    /// want to run experiments.
    pub fn getDataPlaneFanout(
        // slot: Slot,
        // root_bank: *Bank,
    ) usize {
        return DATA_PLANE_FANOUT;
    }

    fn getSeededRng(leader: *Pubkey, shred: *ShredId) std.rand.Random {
        const seed = shred.seed(leader);
        return ChaChaRng.fromSeed(seed);
    }

    fn getNodes(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        tvu_peers: []const ThreadSafeContactInfo,
        stakes: *const std.AutoArrayHashMap(Pubkey, u64),
    ) ![]Node {
        var nodes = std.ArrayList(Node).init(allocator);
        defer nodes.deinit();

        var has_contact_info = std.AutoArrayHashMap(Pubkey, void).init(allocator);
        defer has_contact_info.deinit();

        try nodes.append(.{
            .id = .{ .contact_info = my_contact_info },
            .stake = if (stakes.get(my_contact_info.pubkey)) |stake| stake else 0,
        });
        try has_contact_info.put(my_contact_info.pubkey, void{});

        for (tvu_peers) |peer| {
            try nodes.append(.{
                .id = .{ .contact_info = peer },
                .stake = if (stakes.get(peer.pubkey)) |stake| stake else 0,
            });
            try has_contact_info.put(peer.pubkey, void{});
        }

        for (stakes.keys(), stakes.values()) |pubkey, stake| {
            if (stake > 0 and !has_contact_info.contains(pubkey)) {
                try nodes.append(.{
                    .id = .{ .pubkey = pubkey },
                    .stake = stake,
                });
            }
        }

        std.mem.sortUnstable(Node, nodes.items, {}, struct {
            pub fn lt(_: void, lhs: Node, rhs: Node) bool {
                if (lhs.stake > rhs.stake) return true;
                if (lhs.stake < rhs.stake) return false;
                return std.mem.lessThan(u8, &lhs.pubkey().data, &rhs.pubkey().data);
            }
        }.lt);

        var counts = std.AutoArrayHashMap(IpAddr, usize).init(allocator);
        defer counts.deinit();

        var result = std.ArrayList(Node).init(allocator);
        errdefer result.deinit();

        for (nodes.items) |node| {
            if (node.contactInfo()) |ci| {
                if (ci.tvu_addr) |addr| {
                    const current = counts.get(addr.ip()) orelse 0;
                    if (current < MAX_NODES_PER_IP) try result.append(node);
                    try counts.put(
                        addr.ip(),
                        current + 1,
                    );
                    continue;
                }
            }
            if (node.stake > 0) try result.append(node);
        }

        return result.toOwnedSlice();
    }
};

const TestEnvironment = struct {
    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    nodes: []const ThreadSafeContactInfo,
    tvu_peers: []const ThreadSafeContactInfo,
    node_stakes: std.AutoArrayHashMap(Pubkey, u64),

    fn init(allocator: std.mem.Allocator, rand: std.rand.Random, num_nodes: usize) !TestEnvironment {
        const nodes = try allocator.alloc(ThreadSafeContactInfo, num_nodes);
        errdefer allocator.free(nodes);
        for (0..num_nodes) |i| nodes[i] = try ThreadSafeContactInfo.random(
            allocator,
            rand,
            Pubkey.random(rand),
            0,
            0,
            0,
        );

        const my_contact_info = nodes[0];
        const tvu_peers = try allocator.dupe(ThreadSafeContactInfo, nodes[1..]);
        errdefer allocator.free(tvu_peers);

        var node_stakes = std.AutoArrayHashMap(Pubkey, u64).init(allocator);
        errdefer node_stakes.deinit();
        for (nodes) |node| {
            if (rand.intRangeAtMost(u8, 1, 7) != 1) {
                try node_stakes.put(node.pubkey, rand.intRangeLessThan(u64, 0, 20));
            }
        }
        for (0..100) |_| {
            try node_stakes.put(Pubkey.random(rand), rand.intRangeLessThan(u64, 0, 20));
        }

        return .{
            .allocator = allocator,
            .my_contact_info = my_contact_info,
            .nodes = nodes,
            .tvu_peers = tvu_peers,
            .node_stakes = node_stakes,
        };
    }

    fn deinit(self: *TestEnvironment) void {
        self.allocator.free(self.nodes);
        self.allocator.free(self.tvu_peers);
        self.node_stakes.deinit();
    }
};

test "initForBroadcast" {
    // TODO: Check that tree initialisation is correct for broadcasting

}

test "initForRetransmit" {
    // TODO: Check that tree initialisation is correct for retransmitting
    const allocator = std.testing.allocator;
    var prng = std.rand.DefaultPrng.init(0);

    // Setup Environment
    var env = try TestEnvironment.init(allocator, prng.random(), 1000);
    defer env.deinit();

    // Create Turbine Tree
    var turbine_tree = try TurbineTree.initForRetransmit(
        allocator,
        env.my_contact_info,
        env.tvu_peers,
        &env.node_stakes,
    );
    defer turbine_tree.deinit();

    // All nodes with contact-info or stakes should be in the index.
    try std.testing.expect(turbine_tree.nodes.len > env.nodes.len);

    // Assert that all nodes keep their contact-info.
    // and, all staked nodes are also included.
    var node_map = std.AutoArrayHashMap(Pubkey, TurbineTree.Node).init(allocator);
    defer node_map.deinit();
    for (turbine_tree.nodes) |node| try node_map.put(node.pubkey(), node);
    for (env.nodes) |node| {
        try std.testing.expectEqual(node.pubkey, node_map.get(node.pubkey).?.pubkey());
    }
    for (env.node_stakes.keys(), env.node_stakes.values()) |pubkey, stake| {
        if (stake > 0) {
            try std.testing.expectEqual(stake, node_map.get(pubkey).?.stake);
        }
    }
}

fn checkRetransmitNodes(allocator: std.mem.Allocator, fanout: usize, nodes: []const TurbineTree.Node, node_expected_children: []const []const TurbineTree.Node) !void {
    // Create an index of the nodes
    var index = std.AutoArrayHashMap(Pubkey, usize).init(allocator);
    for (nodes, 0..) |node, i| try index.put(node.pubkey(), i);

    // Root nodes parent is null
    try std.testing.expectEqual(TurbineTree.computeRetransmitParent(fanout, 0, nodes), null);

    // Check that the retransmit and parent nodes are correct
    for (node_expected_children, 0..) |expected_children, i| {
        // Check that the retransmit children for the ith node are correct
        const actual_peers = try TurbineTree.computeRetransmitChildren(allocator, fanout, i, nodes);
        for (expected_children, actual_peers) |expected, actual| {
            try std.testing.expectEqual(expected.pubkey(), actual.pubkey());
        }

        // Check that the ith node is the parent of its retransmit children
        const expected_parent_pubkey = nodes[i].pubkey();
        for (expected_children) |peer| {
            const actual_parent_pubkey = TurbineTree.computeRetransmitParent(fanout, index.get(peer.pubkey()).?, nodes).?;
            try std.testing.expectEqual(expected_parent_pubkey, actual_parent_pubkey);
        }
    }

    // Check that the remaining nodes have no children
    for (node_expected_children.len..nodes.len) |i| {
        const actual_peers = try TurbineTree.computeRetransmitChildren(allocator, fanout, i, nodes);
        try std.testing.expectEqual(0, actual_peers.len);
    }
}

test "retransmit nodes computation: 20 nodes, 2 fanout" {
    const Node = TurbineTree.Node;
    var prng = std.rand.DefaultPrng.init(0);
    const nds = [_]Node{
        Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()),
        Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()),
        Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()),
        Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()),
        Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()),
    };
    const nodes: []const Node = &.{
        nds[7], // root
        nds[6], nds[10], // 1st layer
        // 2nd layer
        nds[5], nds[19], // 1st neighborhood
        nds[0], nds[14], // 2nd
        // 3rd layer
        nds[3], nds[1], // 1st neighborhood
        nds[12], nds[2], // 2nd
        nds[11], nds[4], // 3rd
        nds[15], nds[18], // 4th
        // 4th layer
        nds[13], nds[16], // 1st neighborhood
        nds[17], nds[9], // 2nd
        nds[8], // 3rd
    };
    const peers: []const []const Node = &.{
        &.{ nds[6], nds[10] },
        &.{ nds[5], nds[0] },
        &.{ nds[19], nds[14] },
        &.{ nds[3], nds[12] },
        &.{ nds[1], nds[2] },
        &.{ nds[11], nds[15] },
        &.{ nds[4], nds[18] },
        &.{ nds[13], nds[17] },
        &.{ nds[16], nds[9] },
        &.{nds[8]},
    };
    try checkRetransmitNodes(std.heap.page_allocator, 2, nodes, peers);
}

test "retransmit nodes computation: 36 nodes, 3 fanout" {
    const Node = TurbineTree.Node;
    var prng = std.rand.DefaultPrng.init(0);
    const nds = [_]Node{
        Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()),
        Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()),
        Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()),
        Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()),
        Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()),
        Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()),
        Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()),
        Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()),
        Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()), Node.random(prng.random()),
    };
    const nodes: []const Node = &.{
        nds[19], // root
        nds[14], nds[15], nds[28], // 1st layer
        // 2nd layer
        nds[29], nds[4], nds[5], // 1st neighborhood
        nds[9], nds[16], nds[7], // 2nd
        nds[26], nds[23], nds[2], // 3rd
        // 3rd layer
        nds[31], nds[3], nds[17], // 1st neighborhood
        nds[20], nds[25], nds[0], // 2nd
        nds[13], nds[30], nds[18], // 3rd
        nds[35], nds[21], nds[22], // 4th
        nds[6], nds[8], nds[11], // 5th
        nds[27], nds[1], nds[10], // 6th
        nds[12], nds[24], nds[34], // 7th
        nds[33], nds[32], // 8th
    };
    const peers: []const []const Node = &.{
        &.{ nds[14], nds[15], nds[28] },
        &.{ nds[29], nds[9], nds[26] },
        &.{ nds[4], nds[16], nds[23] },
        &.{ nds[5], nds[7], nds[2] },
        &.{ nds[31], nds[20], nds[13] },
        &.{ nds[3], nds[25], nds[30] },
        &.{ nds[17], nds[0], nds[18] },
        &.{ nds[35], nds[6], nds[27] },
        &.{ nds[21], nds[8], nds[1] },
        &.{ nds[22], nds[11], nds[10] },
        &.{ nds[12], nds[33] },
        &.{ nds[24], nds[32] },
        &.{nds[34]},
    };
    try checkRetransmitNodes(std.heap.page_allocator, 3, nodes, peers);
}

fn checkRetransmitNodesRoundTrip(allocator: std.mem.Allocator, fanout: usize, size: usize) !void {
    var prng = std.rand.DefaultPrng.init(0);
    const rand = prng.random();

    const nodes = try allocator.alloc(TurbineTree.Node, size);
    defer allocator.free(nodes);
    for (0..size) |i| nodes[i] = TurbineTree.Node.random(rand);

    var index = std.AutoArrayHashMap(Pubkey, usize).init(allocator);
    defer index.deinit();
    for (nodes, 0..) |node, i| try index.put(node.pubkey(), i);

    // Root nodes parent is null
    try std.testing.expectEqual(null, TurbineTree.computeRetransmitParent(fanout, 0, nodes));

    // Check that each node is contained in its parents computed children
    for (1..size) |i| {
        const parent = TurbineTree.computeRetransmitParent(fanout, i, nodes).?;
        const children = try TurbineTree.computeRetransmitChildren(allocator, fanout, index.get(parent).?, nodes);
        defer allocator.free(children);
        var node_i_in_children = false;
        for (children) |child| {
            if (child.pubkey().equals(&nodes[i].pubkey())) {
                node_i_in_children = true;
                break;
            }
        }
        try std.testing.expect(node_i_in_children);
    }

    // Check that the computed parent of each nodes child the parent
    for (0..size) |i| {
        const expected_parent_pubkey = nodes[i].pubkey();
        const children = try TurbineTree.computeRetransmitChildren(allocator, fanout, i, nodes);
        defer allocator.free(children);
        for (children) |child| {
            const actual_parent_pubkey = TurbineTree.computeRetransmitParent(fanout, index.get(child.pubkey()).?, nodes).?;
            try std.testing.expectEqual(expected_parent_pubkey, actual_parent_pubkey);
        }
    }
}

test "retransmit nodes round trip" {
    try checkRetransmitNodesRoundTrip(std.testing.allocator, 2, 1_347);
    try checkRetransmitNodesRoundTrip(std.testing.allocator, 3, 1_359);
    try checkRetransmitNodesRoundTrip(std.testing.allocator, 4, 4_296);
    try checkRetransmitNodesRoundTrip(std.testing.allocator, 5, 3_925);
    try checkRetransmitNodesRoundTrip(std.testing.allocator, 6, 8_778);
    try checkRetransmitNodesRoundTrip(std.testing.allocator, 7, 9_879);
}
