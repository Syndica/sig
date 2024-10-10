const std = @import("std");
const sig = @import("../../sig.zig");

const KeyPair = std.crypto.sign.Ed25519.KeyPair;

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
const GossipTable = sig.gossip.GossipTable;
const WeightedShuffle = sig.rand.WeightedShuffle(u64);
const ChaChaRng = sig.rand.ChaChaRng(20);
const AtomicUsize = std.atomic.Value(usize);
const TurbineTree = sig.turbine.TurbineTree;
const TurbineTreeProvider = sig.turbine.TurbineTreeProvider;
const NodeId = TurbineTree.NodeId;
const Node = TurbineTree.Node;

const TestEnvironment = struct {
    gossip_table_rw: RwMux(GossipTable),
    staked_nodes: std.AutoArrayHashMapUnmanaged(Pubkey, u64),

    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    nodes: std.ArrayList(ThreadSafeContactInfo),
    tvu_peers: std.ArrayList(ThreadSafeContactInfo),
    node_stakes: std.AutoArrayHashMap(Pubkey, u64),

    fn init(allocator: std.mem.Allocator, rand: std.rand.Random, num_nodes: usize) !TestEnvironment {
        const my_keypair = try KeyPair.create([_]u8{0} ** KeyPair.seed_length);
        const my_contact_info = try ThreadSafeContactInfo.random(
            rand,
            Pubkey.fromPublicKey(&my_keypair.public_key),
            0,
        );

        var nodes = try std.ArrayList(ThreadSafeContactInfo).initCapacity(allocator, num_nodes);
        errdefer nodes.deinit();

        nodes.append(my_contact_info);
        for (1..num_nodes) |_| nodes.append(try ThreadSafeContactInfo.random(
            rand,
            Pubkey.random(rand),
            0,
        ));

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
        self.nodes.deinit();
        self.tvu_peers.deinit();
        self.node_stakes.deinit();
    }
};

test "initForRetransmit" {
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
        &env.node_stakes.unmanaged,
    );
    defer turbine_tree.deinit();

    // All nodes with contact-info or stakes should be in the index.
    std.debug.print("tree_nodes: {}\n", .{turbine_tree.nodes.items.len});
    std.debug.print("env_index: {}\n", .{env.nodes.len});
    try std.testing.expect(turbine_tree.nodes.items.len > env.nodes.len);

    // Assert that all nodes keep their contact-info.
    // and, all staked nodes are also included.
    var node_map = std.AutoArrayHashMap(Pubkey, Node).init(allocator);
    defer node_map.deinit();
    for (turbine_tree.nodes.items) |node| try node_map.put(node.pubkey(), node);
    for (env.nodes) |node| {
        try std.testing.expectEqual(node.pubkey, node_map.get(node.pubkey).?.pubkey());
    }
    for (env.node_stakes.keys(), env.node_stakes.values()) |pubkey, stake| {
        if (stake > 0) {
            try std.testing.expectEqual(stake, node_map.get(pubkey).?.stake);
        }
    }
}

fn checkRetransmitNodes(allocator: std.mem.Allocator, fanout: usize, nodes: []const Node, node_expected_children: []const []const Node) !void {
    // Create an index of the nodes
    var index = std.AutoArrayHashMap(Pubkey, usize).init(allocator);
    defer index.deinit();
    for (nodes, 0..) |node, i| try index.put(node.pubkey(), i);

    // Root nodes parent is null
    try std.testing.expectEqual(TurbineTree.computeRetransmitParent(fanout, 0, nodes), null);

    // Check that the retransmit and parent nodes are correct
    for (node_expected_children, 0..) |expected_children, i| {
        // Check that the retransmit children for the ith node are correct
        const actual_peers = try TurbineTree.computeRetransmitChildren(allocator, fanout, i, nodes);
        defer actual_peers.deinit();
        for (expected_children, actual_peers.items) |expected, actual| {
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
        defer actual_peers.deinit();
        try std.testing.expectEqual(0, actual_peers.items.len);
    }
}

test "retransmit nodes computation: 20 nodes, 2 fanout" {
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
    try checkRetransmitNodes(std.testing.allocator, 2, nodes, peers);
}

test "retransmit nodes computation: 36 nodes, 3 fanout" {
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
    try checkRetransmitNodes(std.testing.allocator, 3, nodes, peers);
}

fn checkRetransmitNodesRoundTrip(allocator: std.mem.Allocator, fanout: usize, size: usize) !void {
    var prng = std.rand.DefaultPrng.init(0);
    const rand = prng.random();

    var nodes = try std.ArrayList(Node).initCapacity(allocator, size);
    defer nodes.deinit();
    for (0..size) |_| nodes.appendAssumeCapacity(Node.random(rand));

    var index = std.AutoArrayHashMap(Pubkey, usize).init(allocator);
    defer index.deinit();
    for (nodes.items, 0..) |node, i| try index.put(node.pubkey(), i);

    // Root nodes parent is null
    try std.testing.expectEqual(null, TurbineTree.computeRetransmitParent(fanout, 0, nodes.items));

    // Check that each node is contained in its parents computed children
    for (1..size) |i| {
        const parent = TurbineTree.computeRetransmitParent(fanout, i, nodes.items).?;
        const children = try TurbineTree.computeRetransmitChildren(allocator, fanout, index.get(parent).?, nodes.items);
        defer children.deinit();
        var node_i_in_children = false;
        for (children.items) |child| {
            if (child.pubkey().equals(&nodes.items[i].pubkey())) {
                node_i_in_children = true;
                break;
            }
        }
        try std.testing.expect(node_i_in_children);
    }

    // Check that the computed parent of each nodes child the parent
    for (0..size) |i| {
        const expected_parent_pubkey = nodes.items[i].pubkey();
        const children = try TurbineTree.computeRetransmitChildren(allocator, fanout, i, nodes.items);
        defer children.deinit();
        for (children.items) |child| {
            const actual_parent_pubkey = TurbineTree.computeRetransmitParent(fanout, index.get(child.pubkey()).?, nodes.items).?;
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
