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
const GossipTable = sig.gossip.GossipTable;
const WeightedShuffle = sig.rand.WeightedShuffle(u64);
const ChaChaRng = sig.rand.ChaChaRng(20);
const AtomicUsize = std.atomic.Value(usize);

/// A TurbineTreeProvider is responsible for creating and caching TurbineTrees.
/// It is used by the retransmit service to load TurbineTree's by reference.
pub const TurbineTreeProvider = struct {
    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    gossip_table_rw: *RwMux(GossipTable),
    cache: std.AutoArrayHashMap(Epoch, CacheEntry),
    cache_entry_ttl: Duration,

    /// A cached TurbineTree for a given epoch
    /// The cache entry is valid for a certain amount of time
    /// before it is considered stale and evicted. This is required
    /// to keep in sync with changes to gossip data.
    pub const CacheEntry = struct {
        created: Instant,
        turbine_tree: *TurbineTree,

        pub fn alive(self: *const CacheEntry, ttl: Duration) bool {
            return self.created.elapsed().asNanos() < ttl.asNanos();
        }
    };

    pub fn init(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        gossip_table_rw: *RwMux(GossipTable),
    ) TurbineTreeProvider {
        return .{
            .allocator = allocator,
            .my_contact_info = my_contact_info,
            .gossip_table_rw = gossip_table_rw,
            .cache = std.AutoArrayHashMap(Epoch, CacheEntry).init(allocator),
            .cache_entry_ttl = Duration.fromSecs(5), // value from agave
        };
    }

    pub fn deinit(self: *TurbineTreeProvider) void {
        for (self.cache.values()) |_entry| {
            var entry = _entry;
            entry.turbine_tree.deinit();
        }
        self.cache.deinit();
    }

    /// Get the turbine tree for the given epoch. If the tree is not cached, create a new one
    /// and cache it. The returned pointer is reference counted, however, is is NOT thread safe
    /// in a general sense. See [TurbineTree.acquire] and [TurbineTree.release] for more details.
    pub fn getTurbineTree(
        self: *TurbineTreeProvider,
        epoch: Epoch,
        bank_fields: *const BankFields,
    ) !*TurbineTree {
        const gopr = try self.cache.getOrPut(epoch);

        if (gopr.found_existing) {
            if (gopr.value_ptr.alive(self.cache_entry_ttl)) {
                return gopr.value_ptr.turbine_tree;
            } else {
                gopr.value_ptr.turbine_tree.release();
            }
        }

        gopr.value_ptr.* = .{
            .created = Instant.now(),
            .turbine_tree = try self.createTurbineTree(
                epoch,
                bank_fields,
            ),
        };

        return gopr.value_ptr.turbine_tree;
    }

    /// Create a new TurbineTree for retransmit
    fn createTurbineTree(self: *const TurbineTreeProvider, epoch: Epoch, bank_fields: *const BankFields) !*TurbineTree {
        const tvu_peers = try self.getTvuPeers();
        defer tvu_peers.deinit();

        const turbine_tree = try self.allocator.create(TurbineTree);
        turbine_tree.* = try TurbineTree.initForRetransmit(
            self.allocator,
            self.my_contact_info,
            tvu_peers.items,
            try bank_fields.getStakedNodes(
                self.allocator,
                epoch,
            ),
        );

        return turbine_tree;
    }

    /// Get the contact info of all gossip peers which have a matching shred version
    fn getTvuPeers(self: *const TurbineTreeProvider) !std.ArrayList(ThreadSafeContactInfo) {
        const gossip_table, var gossip_table_lg = self.gossip_table_rw.readWithLock();
        defer gossip_table_lg.unlock();

        var contact_info_iter = gossip_table.contactInfoIterator(0);
        var tvu_peers = std.ArrayList(ThreadSafeContactInfo).init(self.allocator);

        while (contact_info_iter.nextThreadSafe()) |contact_info| {
            if (!contact_info.pubkey.equals(&self.my_contact_info.pubkey) and contact_info.shred_version == self.my_contact_info.shred_version) {
                try tvu_peers.append(contact_info);
            }
        }

        return tvu_peers;
    }
};

/// Nodes in the TurbineTree may be identified by solely their
/// pubkey if they are not in the gossip table or their contact info
/// is not known.
pub const NodeId = union(enum) {
    contact_info: ThreadSafeContactInfo,
    pubkey: Pubkey,
};

/// A node in the TurbineTree
pub const Node = struct {
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

    pub fn tvuAddress(self: Node) ?SocketAddr {
        return switch (self.id) {
            .contact_info => |ci| ci.tvu_addr,
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

/// A TurbineTree is a data structure used to determine the set of nodes to retransmit
pub const TurbineTree = struct {
    allocator: std.mem.Allocator,
    my_pubkey: Pubkey,
    /// All staked nodes + other known tvu-peers + the node itself;
    /// sorted by (stake, pubkey) in descending order.
    nodes: std.ArrayList(Node),
    /// Pubkey -> index in nodes
    index: std.AutoArrayHashMap(Pubkey, usize),
    /// Weighted shuffle of node stakes
    weighted_shuffle: WeightedShuffle,
    reference_count: AtomicUsize,

    pub const DATA_PLANE_FANOUT: usize = 200;
    pub const MAX_TURBINE_TREE_DEPTH: usize = 4;
    pub const MAX_NODES_PER_IP_ADDRESS: usize = 10;

    /// Initialise the TurbineTree for retransmit service
    /// The tvu_peers and stakes are used to construct the nodes in the tree
    pub fn initForRetransmit(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        tvu_peers: []const ThreadSafeContactInfo,
        stakes: *const std.AutoArrayHashMapUnmanaged(Pubkey, u64),
    ) !TurbineTree {
        const nodes = try getNodes(allocator, my_contact_info, tvu_peers, stakes);
        errdefer nodes.deinit();

        var index = std.AutoArrayHashMap(Pubkey, usize).init(allocator);
        errdefer index.deinit();
        for (nodes.items, 0..) |node, i| try index.put(node.pubkey(), i);

        var node_stakes = try std.ArrayList(u64).initCapacity(allocator, nodes.items.len);
        defer node_stakes.deinit();
        for (nodes.items) |node| node_stakes.appendAssumeCapacity(node.stake);

        const weighted_shuffle = try WeightedShuffle.init(allocator, node_stakes.items);

        return .{
            .allocator = allocator,
            .my_pubkey = my_contact_info.pubkey,
            .nodes = nodes,
            .index = index,
            .weighted_shuffle = weighted_shuffle,
            .reference_count = AtomicUsize.init(1),
        };
    }

    pub fn deinit(self: *TurbineTree) void {
        self.nodes.deinit();
        self.index.deinit();
        self.weighted_shuffle.deinit();
    }

    /// CAUTION: use this method IFF you are CERTAIN that the TurbineTree has not been deinitialized.
    /// - invalid usage will panic in debug and release safe mode
    /// - invalid usage will result in use after free in release fast mode
    pub fn acquireUnsafe(self: *TurbineTree) *TurbineTree {
        const previous_references = self.reference_count.fetchAdd(1, .monotonic);
        std.debug.assert(previous_references > 0);
        return self;
    }

    pub fn release(self: *TurbineTree) void {
        if (self.reference_count.fetchSub(1, .monotonic) == 1) self.deinit();
    }

    /// Get the root distance and retransmit children for the given slot leader and shred id.
    /// The retransmit children are calculated from the weighted shuffle of nodes using the
    /// slot leader and shred id as the seed for the shuffle.
    pub fn getRetransmitChildren(
        self: *const TurbineTree,
        allocator: std.mem.Allocator,
        slot_leader: Pubkey,
        shred_id: ShredId,
        fanout: usize,
    ) !struct {
        usize, // root distance
        std.ArrayList(Node), // children
    } {
        if (slot_leader.equals(&self.my_pubkey)) {
            return error.LoopBack;
        }

        // Clone the weighted shuffle, and remove the slot leader as
        // it should not be included in the retransmit set
        var weighted_shuffle = try self.weighted_shuffle.clone();
        defer weighted_shuffle.deinit();
        if (self.index.get(slot_leader)) |index| {
            weighted_shuffle.removeIndex(index);
        }

        // Shuffle the nodes and find my index
        var shuffled_nodes = try std.ArrayList(Node).initCapacity(
            allocator,
            self.nodes.items.len,
        );
        defer shuffled_nodes.deinit();

        var my_index: usize = undefined;
        var found_my_index = false;
        var chacha = getSeededRng(slot_leader, shred_id);
        var shuffled_indexes = weighted_shuffle.shuffle(chacha.random());

        while (shuffled_indexes.next()) |index| {
            shuffled_nodes.appendAssumeCapacity(self.nodes.items[index]);
            if (!found_my_index) {
                if (self.nodes.items[index].pubkey().equals(&self.my_pubkey)) {
                    my_index = shuffled_nodes.items.len - 1;
                    found_my_index = true;
                }
            }
        }

        // Compute the retransmit children from the shuffled nodes
        const children = try computeRetransmitChildren(
            allocator,
            fanout,
            my_index,
            shuffled_nodes.items,
        );

        // Compute the root distance
        const root_distance: usize = if (my_index == 0)
            0
        else if (my_index <= fanout)
            1
        else if (my_index <= (fanout +| 1) *| fanout) // Does this make sense?
            2
        else
            3;

        return .{ root_distance, children };
    }

    // root     : [0]
    // 1st layer: [1, 2, ..., fanout]
    // 2nd layer: [[fanout + 1, ..., fanout * 2],
    //             [fanout * 2 + 1, ..., fanout * 3],
    //             ...
    //             [fanout * fanout + 1, ..., fanout * (fanout + 1)]]
    // 3rd layer: ...
    // ...
    // The leader node broadcasts shreds to the root node.
    // The root node retransmits the shreds to all nodes in the 1st layer.
    // Each other node retransmits shreds to fanout many nodes in the next layer.
    // For example the node k in the 1st layer will retransmit to nodes:
    // fanout + k, 2*fanout + k, ..., fanout*fanout + k
    fn computeRetransmitChildren(
        allocator: std.mem.Allocator,
        fanout: usize,
        index: usize,
        nodes: []const Node,
    ) !std.ArrayList(Node) {
        var children = try std.ArrayList(Node).initCapacity(allocator, fanout);

        const offset = (index -| 1) % fanout;
        const anchor = index - offset;
        const step = if (index == 0) 1 else fanout;
        var curr = anchor * fanout + offset + 1;
        var steps: usize = 0;

        while (curr < nodes.len and steps < fanout) {
            children.appendAssumeCapacity(nodes[curr]);
            curr += step;
            steps += 1;
        }

        return children;
    }

    // Returns the parent node in the turbine broadcast tree.
    // Returns None if the node is the root of the tree.
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

    /// TODO: Equivalence with agave
    fn getSeededRng(leader: Pubkey, shred: ShredId) ChaChaRng {
        const seed = shred.seed(leader);
        return ChaChaRng.fromSeed(seed);
    }

    /// All staked nodes + other known tvu-peers + the node itself;
    /// sorted by (stake, pubkey) in descending order.
    fn getNodes(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        tvu_peers: []const ThreadSafeContactInfo,
        stakes: *const std.AutoArrayHashMapUnmanaged(Pubkey, u64),
    ) !std.ArrayList(Node) {
        var nodes = try std.ArrayList(Node).initCapacity(allocator, tvu_peers.len + stakes.count());
        defer nodes.deinit();

        var pubkeys = std.AutoArrayHashMap(Pubkey, void).init(allocator);
        defer pubkeys.deinit();

        // HACK TO SET OUR STAKE
        var max_stake: u64 = 0;
        for (stakes.values()) |stake| {
            if (stake > max_stake) max_stake = stake;
        }
        nodes.appendAssumeCapacity(.{
            .id = .{ .contact_info = my_contact_info },
            .stake = @divFloor(max_stake, 2),
        });
        // REPLACES
        // // Add ourself to the list of nodes
        // try nodes.append(.{
        //     .id = .{ .contact_info = my_contact_info },
        //     .stake = if (stakes.get(my_contact_info.pubkey)) |stake| stake else 0,
        // });
        // END
        try pubkeys.put(my_contact_info.pubkey, void{});

        // Add all TVU peers directly to the list of nodes
        // The TVU peers are all nodes in gossip table with the same shred version
        for (tvu_peers) |peer| {
            nodes.appendAssumeCapacity(.{
                .id = .{ .contact_info = peer },
                .stake = if (stakes.get(peer.pubkey)) |stake| stake else 0,
            });
            try pubkeys.put(peer.pubkey, void{});
        }

        // Add all staked nodes to the list of nodes
        // Skip nodes that are already in the list, i.e. nodes with contact info
        for (stakes.keys(), stakes.values()) |pubkey, stake| {
            if (stake > 0 and !pubkeys.contains(pubkey)) {
                nodes.appendAssumeCapacity(.{
                    .id = .{ .pubkey = pubkey },
                    .stake = stake,
                });
            }
        }

        // Sort the nodes by stake, then pubkey
        std.mem.sortUnstable(Node, nodes.items, {}, struct {
            pub fn lt(_: void, lhs: Node, rhs: Node) bool {
                if (lhs.stake > rhs.stake) return true;
                if (lhs.stake < rhs.stake) return false;
                return std.mem.lessThan(u8, &lhs.pubkey().data, &rhs.pubkey().data);
            }
        }.lt);

        // Filter out nodes which exceed the maximum number of nodes per IP and
        // nodes with a stake of 0
        var result = try std.ArrayList(Node).initCapacity(allocator, nodes.items.len);
        errdefer result.deinit();
        var ip_counts = std.AutoArrayHashMap(IpAddr, usize).init(allocator);
        defer ip_counts.deinit();
        for (nodes.items) |node| {
            // Add the node to the result if it does not exceed the
            // maximum number of nodes per IP
            var exceeds_ip_limit = false;
            if (node.tvuAddress()) |tvu_addr| {
                const ip_count = ip_counts.get(tvu_addr.ip()) orelse 0;
                if (ip_count < MAX_NODES_PER_IP_ADDRESS) {
                    result.appendAssumeCapacity(node);
                } else {
                    exceeds_ip_limit = true;
                }
                try ip_counts.put(tvu_addr.ip(), ip_count + 1);
            }

            // Keep the node for deterministic shuffle but remove
            // contact info so that it is not used for retransmit
            if (exceeds_ip_limit and node.stake > 0) {
                result.appendAssumeCapacity(.{
                    .id = .{ .pubkey = node.pubkey() },
                    .stake = node.stake,
                });
            }
        }

        return result;
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
