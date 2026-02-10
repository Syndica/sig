const std = @import("std");
const sig = @import("../../sig.zig");

const IpAddr = sig.net.IpAddr;
const SocketAddr = sig.net.SocketAddr;
const ShredId = sig.ledger.shred.ShredId;
const RwMux = sig.sync.RwMux;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const ContactInfo = sig.gossip.data.ContactInfo;
const SignedGossipData = sig.gossip.data.SignedGossipData;
const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const Slot = sig.core.Slot;
const Duration = sig.time.Duration;
const Instant = sig.time.Instant;
const GossipTable = sig.gossip.GossipTable;
const WeightedShuffle = sig.rand.WeightedShuffle(u64);
const ChaChaRng = sig.rand.ChaChaRng(20);
const AtomicUsize = std.atomic.Value(usize);
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const SecretKey = std.crypto.sign.Ed25519.SecretKey;

const intRangeLessThanRust = sig.rand.weighted_shuffle.intRangeLessThanRust;

/// TurbineTreeCache
/// Cache turbine trees and clear them once they are too old.
/// The time to live ensures updates to gossip data are reflected
/// in the turbine trees.
pub const TurbineTreeCache = struct {
    cache: std.AutoArrayHashMap(Epoch, Entry),
    cache_entry_ttl: Duration,

    pub const Entry = struct {
        created: Instant,
        turbine_tree: *TurbineTree,

        pub fn alive(self: *const Entry, ttl: Duration) bool {
            return self.created.elapsed().asNanos() < ttl.asNanos();
        }
    };

    pub fn init(allocator: std.mem.Allocator) TurbineTreeCache {
        return .{
            .cache = std.AutoArrayHashMap(Epoch, Entry).init(allocator),
            .cache_entry_ttl = Duration.fromSecs(5),
        };
    }

    pub fn deinit(self: *TurbineTreeCache) void {
        for (self.cache.values()) |entry| entry.turbine_tree.releaseUnsafe();
        self.cache.deinit();
    }

    pub fn get(self: *TurbineTreeCache, epoch: Epoch) !?*TurbineTree {
        const gopr = try self.cache.getOrPut(epoch);

        if (gopr.found_existing) {
            if (gopr.value_ptr.alive(self.cache_entry_ttl)) {
                return gopr.value_ptr.turbine_tree.acquireUnsafe();
            } else {
                gopr.value_ptr.turbine_tree.releaseUnsafe();
                std.debug.assert(self.cache.swapRemove(epoch));
            }
        }

        return null;
    }

    pub fn put(self: *TurbineTreeCache, epoch: Epoch, turbine_tree: *TurbineTree) !void {
        try self.cache.put(epoch, .{
            .created = Instant.now(),
            .turbine_tree = turbine_tree.acquireUnsafe(),
        });

        for (self.cache.keys(), self.cache.values()) |key, entry| {
            if (!entry.alive(self.cache_entry_ttl)) {
                entry.turbine_tree.releaseUnsafe();
                _ = self.cache.swapRemove(key);
            }
        }
    }
};

/// A TurbineTree is a data structure used to determine the set of nodes to
/// broadcast or retransmit shreds to in the network.
pub const TurbineTree = struct {
    allocator: std.mem.Allocator,
    my_pubkey: Pubkey,
    /// All staked nodes + other known tvu-peers + the node itself;
    /// sorted by (stake, pubkey) in descending order.
    nodes: std.array_list.Managed(Node),
    /// Pubkey -> index in nodes
    index: sig.utils.collections.PubkeyMapManaged(usize),
    /// Weighted shuffle of node stakes
    weighted_shuffle: WeightedShuffle,
    /// The reference count is used to facilitate deallocation, it does not
    /// provide thread safety in a general sense.
    reference_count: AtomicUsize,

    /// The maximum number of nodes each node should retransmit to
    pub const DATA_PLANE_FANOUT: usize = 200;
    /// The maximum depth of the TurbineTree (0->1->2->3)
    /// Fanout of 200 and max depth of 4 allows for ~200^3 (8 million) nodes
    pub const MAX_TURBINE_TREE_DEPTH: usize = 4;
    /// The maximum number of nodes per IP address
    /// When this limit is reached, the nodes contact info is removed so that
    /// the shuffle is deterministic but the node is not used for retransmit
    pub const MAX_NODES_PER_IP_ADDRESS: usize = 10;

    /// A node in the TurbineTree
    /// Nodes in the TurbineTree may be identified by solely their
    /// pubkey if they are not in the gossip table or their contact info
    /// is not known
    pub const Node = struct {
        id: union(enum) {
            contact_info: ThreadSafeContactInfo,
            pubkey: Pubkey,
        },
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
    };

    pub fn initForRetransmit(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        gossip_table_rw: *RwMux(GossipTable),
        staked_nodes: *const sig.utils.collections.PubkeyMap(u64),
        use_stake_hack_for_testing: bool,
    ) !TurbineTree {
        const gossip_peers = blk: {
            const gossip_table, var gossip_table_lg = gossip_table_rw.readWithLock();
            defer gossip_table_lg.unlock();

            break :blk try gossip_table.getThreadSafeContactInfosMatchingShredVersion(
                allocator,
                &my_contact_info.pubkey,
                my_contact_info.shred_version,
                0,
            );
        };
        defer gossip_peers.deinit();

        const nodes = try collectTvuAndStakedNodes(
            allocator,
            my_contact_info,
            gossip_peers.items,
            staked_nodes,
            use_stake_hack_for_testing,
        );
        errdefer nodes.deinit();

        var index = sig.utils.collections.PubkeyMapManaged(usize).init(allocator);
        errdefer index.deinit();

        var node_stakes = try std.array_list.Managed(u64).initCapacity(allocator, nodes.items.len);
        defer node_stakes.deinit();

        for (nodes.items, 0..) |node, i| {
            try index.put(node.pubkey(), i);
            node_stakes.appendAssumeCapacity(node.stake);
        }

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

    /// CAUTION: use this method iff you are certain that the TurbineTree has not been
    /// deinitialized. Invalid usage will panic in debug and release safe mode and result
    /// in a use after free in release fast mode.
    pub fn acquireUnsafe(self: *TurbineTree) *TurbineTree {
        const previous_references = self.reference_count.fetchAdd(1, .monotonic);
        std.debug.assert(previous_references > 0);
        return self;
    }

    /// CAUTION: use this method iff you are certain that the TurbineTree has not been
    /// deinitialized. Invalid usage will result in a use after free.
    pub fn releaseUnsafe(self: *TurbineTree) void {
        if (self.reference_count.fetchSub(1, .monotonic) == 1) self.deinit();
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

    /// Get the root distance and retransmit children for the given slot leader and shred id.
    /// The retransmit children are calculated from the weighted shuffle of nodes using the
    /// slot leader and shred id as the seed for the shuffle.
    pub fn getRetransmitChildren(
        self: *const TurbineTree,
        children: *std.array_list.Managed(Node),
        shuffled_nodes: *std.array_list.Managed(Node),
        slot_leader: Pubkey,
        shred_id: ShredId,
        fanout: usize,
    ) !usize // root distance
    {
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
        var my_index: usize = undefined;
        var found_my_index = false;
        var chacha = getSeededRng(slot_leader, shred_id);
        var shuffled_indexes = weighted_shuffle.shuffle(chacha.random());
        try shuffled_nodes.ensureTotalCapacity(self.nodes.items.len);
        while (shuffled_indexes.next()) |index| {
            // std.debug.print("index={} shuffled_nodes.len={} self.nodes.len={}\n", .{ index, shuffled_nodes.items.len, self.nodes.items.len });
            shuffled_nodes.appendAssumeCapacity(self.nodes.items[index]);
            if (!found_my_index) {
                if (self.nodes.items[index].pubkey().equals(&self.my_pubkey)) {
                    my_index = shuffled_nodes.items.len - 1;
                    found_my_index = true;
                }
            }
        }

        // Compute the retransmit children from the shuffled nodes
        computeRetransmitChildren(
            children,
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

        return root_distance;
    }

    /// Create a seeded RNG for the given leader and shred id.
    /// The resulting RNG must be identical to the agave implementation
    /// to ensure that the weighted shuffle is deterministic.
    fn getSeededRng(leader: Pubkey, shred_id: ShredId) ChaChaRng {
        var slot_bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &slot_bytes, shred_id.slot, .little);
        var index_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &index_bytes, shred_id.index, .little);
        var shred_bytes: [1]u8 = undefined;
        std.mem.writeInt(u8, &shred_bytes, @intFromEnum(shred_id.shred_type), .little);
        const values: []const []const u8 = &.{
            &slot_bytes,
            &shred_bytes,
            &index_bytes,
            &leader.data,
        };
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        for (values) |val| hasher.update(val);
        return ChaChaRng.fromSeed(hasher.finalResult());
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
        children: *std.array_list.Managed(Node),
        fanout: usize,
        index: usize,
        nodes: []const Node,
    ) void {
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

    /// All staked nodes + other known tvu-peers + the node itself;
    /// sorted by (stake, pubkey) in descending order.
    fn collectTvuAndStakedNodes(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        gossip_peers: []const ThreadSafeContactInfo,
        staked_nodes: *const sig.utils.collections.PubkeyMap(u64),
        use_stake_hack_for_testing: bool,
    ) !std.array_list.Managed(Node) {
        var nodes = try std.array_list.Managed(Node).initCapacity(
            allocator,
            gossip_peers.len + staked_nodes.count() + 1, // 1 for self
        );
        defer nodes.deinit();

        var pubkeys = sig.utils.collections.PubkeyMapManaged(void).init(allocator);
        defer pubkeys.deinit();

        const my_stake = if (use_stake_hack_for_testing) blk: {
            var max_stake: u64 = 0;
            for (staked_nodes.values()) |stake| if (stake > max_stake) {
                max_stake = stake;
            };
            break :blk @divFloor(max_stake, 2);
        } else if (staked_nodes.get(my_contact_info.pubkey)) |stake|
            stake
        else
            0;

        // Add ourself to the list of nodes
        nodes.appendAssumeCapacity(.{
            .id = .{ .contact_info = my_contact_info },
            .stake = my_stake,
        });
        try pubkeys.put(my_contact_info.pubkey, void{});

        // Add all TVU peers directly to the list of nodes
        // The TVU peers are all nodes in gossip table with the same shred version
        for (gossip_peers) |peer| {
            nodes.appendAssumeCapacity(.{
                .id = .{ .contact_info = peer },
                .stake = if (staked_nodes.get(peer.pubkey)) |stake| stake else 0,
            });
            try pubkeys.put(peer.pubkey, void{});
        }

        // Add all staked nodes to the list of nodes
        // Skip nodes that are already in the list, i.e. nodes with contact info
        for (staked_nodes.keys(), staked_nodes.values()) |pubkey, stake| {
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
                return !std.mem.lessThan(u8, &lhs.pubkey().data, &rhs.pubkey().data);
            }
        }.lt);

        // Filter out nodes which exceed the maximum number of nodes per IP and
        // nodes with a stake of 0
        var result_nodes = try std.array_list.Managed(Node).initCapacity(allocator, nodes.items.len);
        errdefer result_nodes.deinit();
        var ip_counts = std.AutoArrayHashMap(IpAddr, usize).init(allocator);
        defer ip_counts.deinit();
        for (nodes.items) |node| {
            // Add the node to the result if it does not exceed the
            // maximum number of nodes per IP
            var node_appended = false;
            if (node.tvuAddress()) |tvu_addr| {
                const ip_count = ip_counts.get(tvu_addr.ip()) orelse 0;
                if (ip_count < MAX_NODES_PER_IP_ADDRESS) {
                    node_appended = true;
                    result_nodes.appendAssumeCapacity(node);
                    try ip_counts.put(tvu_addr.ip(), ip_count + 1);
                }
            }

            // Keep the node for deterministic shuffle but remove
            // contact info so that it is not used for retransmit
            if (!node_appended and node.stake > 0) {
                result_nodes.appendAssumeCapacity(.{
                    .id = .{ .pubkey = node.pubkey() },
                    .stake = node.stake,
                });
            }
        }

        return result_nodes;
    }
};

/// TestEnvironment sets up the dependencies for testing the TurbineTree.
/// Testing could be made more thorough by constructing the gossip table and
/// bank fields, and using the TurbineTreeProvider but this is sufficient for now.
const TestEnvironment = struct {
    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    gossip_table_rw: RwMux(GossipTable),
    staked_nodes: sig.utils.collections.PubkeyMapManaged(u64),

    pub fn init(params: struct {
        allocator: std.mem.Allocator,
        random: std.Random,
        num_known_nodes: usize,
        num_unknown_staked_nodes: usize,
        known_nodes_unstaked_ratio: struct { u64, u64 },
    }) !TestEnvironment {
        var staked_nodes = sig.utils.collections.PubkeyMapManaged(u64).init(params.allocator);
        errdefer staked_nodes.deinit();

        var gossip_table = try GossipTable.init(params.allocator, params.allocator);
        errdefer gossip_table.deinit();

        // Add known nodes to the gossip table
        var my_contact_info: ThreadSafeContactInfo = undefined;
        for (0..params.num_known_nodes) |i| {
            var contact_info: ContactInfo = try .initRandom(
                params.allocator,
                params.random,
                .initRandom(params.random),
                0,
                0,
                0,
            );
            errdefer contact_info.deinit();
            try contact_info.setSocket(
                .turbine_recv,
                .initRandom(params.random),
            );
            _ = try gossip_table.insert(
                .{
                    .signature = .ZEROES,
                    .data = .{ .ContactInfo = contact_info },
                },
                0,
            );
            if (i == 0) my_contact_info = .fromContactInfo(contact_info);
        }

        // Add stakes for the known nodes
        const unstaked_numerator, const unstaked_denominator = params.known_nodes_unstaked_ratio;
        var contact_info_iterator = gossip_table.contactInfoIterator(0);
        while (contact_info_iterator.next()) |contact_info| {
            try staked_nodes.put(
                contact_info.pubkey,
                if (params.random.intRangeAtMost(
                    u64,
                    1,
                    unstaked_denominator,
                ) > unstaked_numerator)
                    params.random.intRangeLessThan(u64, 0, 20)
                else
                    0,
            );
        }

        // Add unknown nodes with non-zero stakes
        for (0..params.num_unknown_staked_nodes) |_| {
            try staked_nodes.put(
                Pubkey.initRandom(params.random),
                params.random.intRangeLessThan(u64, 0, 20),
            );
        }

        return .{
            .allocator = params.allocator,
            .my_contact_info = my_contact_info,
            .gossip_table_rw = RwMux(GossipTable).init(gossip_table),
            .staked_nodes = staked_nodes,
        };
    }

    pub fn deinit(self: *TestEnvironment) void {
        const gossip_table: *GossipTable, _ = self.gossip_table_rw.writeWithLock();
        gossip_table.deinit();
        self.staked_nodes.deinit();
    }

    pub fn getKnownNodes(self: *TestEnvironment) !std.array_list.Managed(ThreadSafeContactInfo) {
        const gossip_table, var gossip_table_lg = self.gossip_table_rw.readWithLock();
        defer gossip_table_lg.unlock();

        var known_nodes = try std.array_list.Managed(ThreadSafeContactInfo).initCapacity(
            self.allocator,
            gossip_table.contact_infos.count(),
        );

        var contact_info_iter = gossip_table.contactInfoIterator(0);
        while (contact_info_iter.nextThreadSafe()) |contact_info| {
            known_nodes.appendAssumeCapacity(contact_info);
        }

        return known_nodes;
    }
};

fn testGetRandomNodes(n: comptime_int, rng: std.Random) [n]TurbineTree.Node {
    var nodes: [n]TurbineTree.Node = undefined;
    for (0..n) |i| nodes[i] = .{
        .id = .{ .pubkey = Pubkey.initRandom(rng) },
        .stake = 0,
    };
    return nodes;
}

fn testCheckRetransmitNodes(
    allocator: std.mem.Allocator,
    fanout: usize,
    nodes: []const TurbineTree.Node,
    node_expected_children: []const []const TurbineTree.Node,
) !void {
    // Create an index of the nodes
    var index = sig.utils.collections.PubkeyMapManaged(usize).init(allocator);
    defer index.deinit();
    for (nodes, 0..) |node, i| try index.put(node.pubkey(), i);

    // Root nodes parent is null
    try std.testing.expectEqual(TurbineTree.computeRetransmitParent(fanout, 0, nodes), null);

    // Check that the retransmit and parent nodes are correct
    var actual_peers = try std.array_list.Managed(TurbineTree.Node).initCapacity(
        allocator,
        TurbineTree.DATA_PLANE_FANOUT,
    );
    defer actual_peers.deinit();
    for (node_expected_children, 0..) |expected_children, i| {
        // Check that the retransmit children for the ith node are correct
        actual_peers.clearRetainingCapacity();
        TurbineTree.computeRetransmitChildren(&actual_peers, fanout, i, nodes);
        for (expected_children, actual_peers.items) |expected, actual| {
            try std.testing.expectEqual(expected.pubkey(), actual.pubkey());
        }

        // Check that the ith node is the parent of its retransmit children
        const expected_parent_pubkey = nodes[i].pubkey();
        for (expected_children) |peer| {
            const actual_parent_pubkey = TurbineTree.computeRetransmitParent(
                fanout,
                index.get(peer.pubkey()).?,
                nodes,
            ).?;
            try std.testing.expectEqual(expected_parent_pubkey, actual_parent_pubkey);
        }
    }

    // Check that the remaining nodes have no children
    for (node_expected_children.len..nodes.len) |i| {
        actual_peers.clearRetainingCapacity();
        TurbineTree.computeRetransmitChildren(&actual_peers, fanout, i, nodes);
        try std.testing.expectEqual(0, actual_peers.items.len);
    }
}

fn testCheckRetransmitNodesRoundTrip(
    allocator: std.mem.Allocator,
    fanout: usize,
    size: comptime_int,
) !void {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const rand = prng.random();

    var nodes = testGetRandomNodes(size, rand);

    var index = sig.utils.collections.PubkeyMapManaged(usize).init(allocator);
    defer index.deinit();
    for (nodes, 0..) |node, i| try index.put(node.pubkey(), i);

    // Root nodes parent is null
    try std.testing.expectEqual(
        null,
        TurbineTree.computeRetransmitParent(fanout, 0, &nodes),
    );

    // Check that each node is contained in its parents computed children
    var children = try std.array_list.Managed(TurbineTree.Node).initCapacity(
        allocator,
        TurbineTree.DATA_PLANE_FANOUT,
    );
    defer children.deinit();
    for (1..size) |i| {
        const parent = TurbineTree.computeRetransmitParent(fanout, i, &nodes).?;
        children.clearRetainingCapacity();
        TurbineTree.computeRetransmitChildren(
            &children,
            fanout,
            index.get(parent).?,
            &nodes,
        );
        var node_i_in_children = false;
        for (children.items) |child| {
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
        children.clearRetainingCapacity();
        TurbineTree.computeRetransmitChildren(&children, fanout, i, &nodes);
        for (children.items) |child| {
            const actual_parent_pubkey = TurbineTree.computeRetransmitParent(
                fanout,
                index.get(child.pubkey()).?,
                &nodes,
            ).?;
            try std.testing.expectEqual(expected_parent_pubkey, actual_parent_pubkey);
        }
    }
}

test "agave: cluster nodes retransmit" {
    const allocator = std.testing.allocator;
    var xrng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const rng = xrng.random();

    // Setup Environment
    var env = try TestEnvironment.init(.{
        .allocator = allocator,
        .random = rng,
        .num_known_nodes = 1_000,
        .num_unknown_staked_nodes = 100,
        .known_nodes_unstaked_ratio = .{ 1, 7 },
    });
    defer env.deinit();

    // Get Turbine Tree
    var turbine_tree = try TurbineTree.initForRetransmit(
        std.testing.allocator,
        env.my_contact_info,
        &env.gossip_table_rw,
        &env.staked_nodes.unmanaged,
        false,
    );
    defer turbine_tree.deinit();

    // All nodes with contact-info or stakes should be in the index.
    try std.testing.expect(turbine_tree.nodes.items.len > 1_000);

    // Assert that all nodes keep their contact-info.
    // and, all staked nodes are also included.
    var node_map = sig.utils.collections.PubkeyMapManaged(TurbineTree.Node).init(allocator);
    defer node_map.deinit();

    const known_nodes = try env.getKnownNodes();
    defer known_nodes.deinit();

    for (turbine_tree.nodes.items) |node| try node_map.put(node.pubkey(), node);
    for (known_nodes.items) |known_node| {
        const node = node_map.get(known_node.pubkey).?;
        try std.testing.expectEqual(known_node.pubkey, node.pubkey());
    }
    for (env.staked_nodes.keys(), env.staked_nodes.values()) |pubkey, stake| {
        if (stake > 0) {
            try std.testing.expectEqual(stake, node_map.get(pubkey).?.stake);
        }
    }
}

// test "agave: cluster nodes broadcast"

test "agave: get retransmit nodes" {
    { // 20 nodes, 2 fanout
        var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
        const nds = testGetRandomNodes(20, prng.random());
        const nodes: []const TurbineTree.Node = &.{
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
        const peers: []const []const TurbineTree.Node = &.{
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
        try testCheckRetransmitNodes(std.testing.allocator, 2, nodes, peers);
    }
    { // 36 nodes, 3 fanout
        var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
        const nds = testGetRandomNodes(36, prng.random());
        const nodes: []const TurbineTree.Node = &.{
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
        const peers: []const []const TurbineTree.Node = &.{
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
        try testCheckRetransmitNodes(std.testing.allocator, 3, nodes, peers);
    }
}

test "agave: get retransmit nodes round trip" {
    try testCheckRetransmitNodesRoundTrip(std.testing.allocator, 2, 1_347);
    try testCheckRetransmitNodesRoundTrip(std.testing.allocator, 3, 1_359);
    try testCheckRetransmitNodesRoundTrip(std.testing.allocator, 4, 4_296);
    try testCheckRetransmitNodesRoundTrip(std.testing.allocator, 5, 3_925);
    try testCheckRetransmitNodesRoundTrip(std.testing.allocator, 6, 8_778);
    try testCheckRetransmitNodesRoundTrip(std.testing.allocator, 7, 9_879);
}

test "agave-equivalence: get seeeded rng" {
    {
        const pubkey: Pubkey = .parse("57fFnkGGWzfnhmQEqbCBtZoYnNh26QxFa3FXZJhLmA19");
        const shred_id = ShredId{ .slot = 1_013, .index = 10, .shred_type = .data };
        var chacha = TurbineTree.getSeededRng(pubkey, shred_id);
        const rng = chacha.random();
        try std.testing.expectEqual(6377385843710208803, rng.int(u64));
        try std.testing.expectEqual(16700903141058506452, rng.int(u64));
        try std.testing.expectEqual(3913197096749217054, rng.int(u64));
    }
    {
        const pubkey: Pubkey = .parse("3qChSzvc79TAKbd7jM8uAGHzeNh6PTjvQR8WPFiftNUq");
        const shred_id = ShredId{ .slot = 200_378, .index = 0, .shred_type = .data };
        var chacha = TurbineTree.getSeededRng(pubkey, shred_id);
        const rng = chacha.random();
        try std.testing.expectEqual(4906107860997587194, rng.int(u64));
        try std.testing.expectEqual(11492004887003779529, rng.int(u64));
        try std.testing.expectEqual(8278812339973083991, rng.int(u64));
    }
}

pub fn makeTestCluster(params: struct {
    allocator: std.mem.Allocator,
    random: std.Random,
    my_pubkey: Pubkey,
    my_stake: u64,
    min_stake: u64,
    max_stake: u64,
    num_staked_nodes: usize,
    n_staked_nodes_in_gossip_table: usize,
    n_unstaked_nodes_in_gossip_table: usize,
}) !struct {
    sig.utils.collections.PubkeyMapManaged(u64),
    RwMux(GossipTable),
} {
    var stakes = sig.utils.collections.PubkeyMapManaged(u64).init(params.allocator);
    errdefer stakes.deinit();

    var gossip_table = try GossipTable.init(
        params.allocator,
        params.allocator,
    );
    errdefer gossip_table.deinit();

    for (0..params.num_staked_nodes - @intFromBool(params.my_stake > 0)) |_| {
        try stakes.put(
            Pubkey.initRandom(params.random),
            intRangeLessThanRust(u64, params.random, params.min_stake, params.max_stake),
        );
    }

    var stakes_iter = stakes.iterator();
    for (0..params.n_staked_nodes_in_gossip_table + params.n_unstaked_nodes_in_gossip_table) |i| {
        const pubkey = if (i < params.n_staked_nodes_in_gossip_table)
            stakes_iter.next().?.key_ptr.*
        else
            Pubkey.initRandom(params.random);
        var contact_info = ContactInfo.init(params.allocator, pubkey, 0, 0);
        try contact_info.setSocket(.turbine_recv, .init(
            .initIpv4(.{
                intRangeLessThanRust(u8, params.random, 128, 200),
                params.random.int(u8),
                params.random.int(u8),
                params.random.int(u8),
            }),
            params.random.int(u16),
        ));
        _ = try gossip_table.insert(
            SignedGossipData.init(.{ .ContactInfo = contact_info }),
            0,
        );
    }

    if (params.my_stake > 0) {
        try stakes.put(params.my_pubkey, params.my_stake);
    }

    std.debug.assert(params.num_staked_nodes == stakes.count());

    return .{ stakes, RwMux(GossipTable).init(gossip_table) };
}

pub fn writeStakes(
    allocator: std.mem.Allocator,
    writer: std.fs.File.Writer,
    staked_nodes: sig.utils.collections.PubkeyMapManaged(u64),
) !void {
    const SNode = struct { Pubkey, u64 };
    var entries = std.array_list.Managed(SNode).init(allocator);
    defer entries.deinit();

    for (staked_nodes.keys(), staked_nodes.values()) |pubkey, stake| {
        try entries.append(.{ pubkey, stake });
    }

    std.mem.sortUnstable(SNode, entries.items, {}, struct {
        pub fn lt(_: void, lhs: SNode, rhs: SNode) bool {
            if (lhs[1] > rhs[1]) return true;
            if (lhs[1] < rhs[1]) return false;
            return !std.mem.lessThan(u8, &lhs[0].data, &rhs[0].data);
        }
    }.lt);

    try std.fmt.format(writer, "STAKED_NODES: ", .{});
    for (entries.items) |entry| {
        try std.fmt.format(
            writer,
            "({s}, {}), ",
            .{ entry[0].string().slice(), entry[1] },
        );
    }
    try std.fmt.format(writer, "\n", .{});
}

fn writeShuffledIndices(writer: std.fs.File.Writer, shuffled_indices: std.array_list.Managed(usize)) !void {
    try std.fmt.format(writer, "SHUFFLED_INDICES: ", .{});
    for (shuffled_indices.items) |index| {
        try std.fmt.format(writer, "{}, ", .{index});
    }
    try std.fmt.format(writer, "\n", .{});
}

fn writeRetransmitPeers(
    writer: std.fs.File.Writer,
    i: usize,
    root_distance: usize,
    children: std.array_list.Managed(TurbineTree.Node),
) !void {
    try std.fmt.format(writer, "ITER: {}, ROOT_DISTANCE: {}, CHILDREN: ", .{ i, root_distance });
    for (children.items) |child| {
        try std.fmt.format(
            writer,
            "({s}, {}), ",
            .{ child.pubkey().string().slice(), child.stake },
        );
    }
    try std.fmt.format(writer, "\n", .{});
}

pub fn runTurbineTreeBlackBoxTest() !void {
    const my_keypair = try KeyPair.fromSecretKey(try SecretKey.fromBytes([_]u8{
        233, 236, 240, 63,  159, 199, 2,   210,
        8,   217, 34,  214, 242, 104, 123, 94,
        233, 1,   168, 142, 186, 47,  171, 97,
        172, 81,  163, 22,  75,  105, 195, 199,
        105, 158, 161, 231, 207, 32,  51,  255,
        135, 190, 20,  23,  194, 223, 232, 180,
        163, 129, 226, 85,  141, 255, 100, 225,
        191, 82,  231, 195, 46,  182, 188, 220,
    }));

    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    const my_contact_info = ContactInfo.init(std.heap.c_allocator, my_pubkey, 0, 0);
    const my_threadsafe_contact_info = ThreadSafeContactInfo.fromContactInfo(my_contact_info);

    { // TEST 0
        const file = try std.fs.cwd().createFile(
            "demo/turbine-tree-black-box-test-0-sig.txt",
            .{ .read = true },
        );
        defer file.close();

        // Create a seeded RNG
        var chacha = ChaChaRng.fromSeed([_]u8{0} ** 32);
        const random = chacha.random();

        // Create a test cluster and save the staked nodes.
        var stakes, var gossip_table_rw = try makeTestCluster(.{
            .allocator = std.testing.allocator,
            .random = random,
            .my_pubkey = my_pubkey,
            .my_stake = 20,
            .min_stake = 1,
            .max_stake = 20,
            .num_staked_nodes = 201,
            .num_staked_nodes_in_gossip_table = 100,
            .num_unstaked_nodes_in_gossip_table = 200,
        });
        defer {
            stakes.deinit();
            const gossip_table: *GossipTable, _ = gossip_table_rw.writeWithLock();
            gossip_table.deinit();
        }
        try writeStakes(std.heap.c_allocator, file.writer(), stakes);

        // Create a TurbineTree instance
        var turbine_tree = try TurbineTree.initForRetransmit(
            std.heap.c_allocator,
            my_threadsafe_contact_info,
            &gossip_table_rw,
            &stakes.unmanaged,
            false,
        );
        defer turbine_tree.deinit();

        // Shuffle the nodes and save the shuffled indices.
        var weighted_shuffle = try turbine_tree.weighted_shuffle.clone();
        defer weighted_shuffle.deinit();
        var shuffled_iterator = weighted_shuffle.shuffle(chacha.random());
        const shuffled_indices = try shuffled_iterator.intoArrayList(std.heap.c_allocator);
        defer shuffled_indices.deinit();
        try writeShuffledIndices(file.writer(), shuffled_indices);

        // Generate retransmit children
        var children = try std.array_list.Managed(TurbineTree.Node).initCapacity(
            std.heap.c_allocator,
            TurbineTree.DATA_PLANE_FANOUT,
        );
        defer children.deinit();
        var shuffled_nodes = std.array_list.Managed(TurbineTree.Node).init(std.heap.c_allocator);
        defer shuffled_nodes.deinit();
        for (0..1_000) |i| {
            const slot_leader = Pubkey.initRandom(random);
            const shred_id = ShredId{
                .slot = random.int(u64),
                .index = random.int(u32),
                .shred_type = .data,
            };
            children.clearRetainingCapacity();
            shuffled_nodes.clearRetainingCapacity();
            const root_distance = try turbine_tree.getRetransmitChildren(
                &children,
                &shuffled_nodes,
                slot_leader,
                shred_id,
                TurbineTree.DATA_PLANE_FANOUT,
                null,
            );
            try writeRetransmitPeers(file.writer(), i, root_distance, children);
        }
    }

    { // TEST 1
        const file = try std.fs.cwd().createFile(
            "demo/turbine-tree-black-box-test-1-sig.txt",
            .{ .read = true },
        );
        defer file.close();

        // Create a seeded RNG
        var chacha = ChaChaRng.fromSeed([_]u8{0} ** 32);
        const random = chacha.random();

        // Create a test cluster and save the staked nodes.
        var stakes, var gossip_table_rw = try makeTestCluster(.{
            .allocator = std.heap.c_allocator,
            .random = random,
            .my_pubkey = my_pubkey,
            .my_stake = 20,
            .min_stake = 1,
            .max_stake = 20,
            .num_staked_nodes = 2201,
            .num_staked_nodes_in_gossip_table = 2001,
            .num_unstaked_nodes_in_gossip_table = 2799,
        });
        defer {
            stakes.deinit();
            const gossip_table: *GossipTable, _ = gossip_table_rw.writeWithLock();
            gossip_table.deinit();
        }
        try writeStakes(std.heap.c_allocator, file.writer(), stakes);

        // Create a TurbineTree instance
        var turbine_tree = try TurbineTree.initForRetransmit(
            std.heap.c_allocator,
            my_threadsafe_contact_info,
            &gossip_table_rw,
            &stakes.unmanaged,
            false,
        );
        defer turbine_tree.deinit();

        // Shuffle the nodes and save the shuffled indices.
        var weighted_shuffle = try turbine_tree.weighted_shuffle.clone();
        defer weighted_shuffle.deinit();
        var shuffled_iterator = weighted_shuffle.shuffle(chacha.random());
        const shuffled_indices = try shuffled_iterator.intoArrayList(std.heap.c_allocator);
        defer shuffled_indices.deinit();
        try writeShuffledIndices(file.writer(), shuffled_indices);

        // Generate retransmit children
        var children = try std.array_list.Managed(TurbineTree.Node).initCapacity(
            std.heap.c_allocator,
            TurbineTree.DATA_PLANE_FANOUT,
        );
        defer children.deinit();
        var shuffled_nodes = std.array_list.Managed(TurbineTree.Node).init(std.heap.c_allocator);
        defer shuffled_nodes.deinit();
        for (0..1_000) |i| {
            const slot_leader = Pubkey.initRandom(random);
            const shred_id = ShredId{
                .slot = random.int(u64),
                .index = random.int(u32),
                .shred_type = .data,
            };
            children.clearRetainingCapacity();
            shuffled_nodes.clearRetainingCapacity();
            const root_distance = try turbine_tree.getRetransmitChildren(
                &children,
                &shuffled_nodes,
                slot_leader,
                shred_id,
                TurbineTree.DATA_PLANE_FANOUT,
                null,
            );
            try writeRetransmitPeers(file.writer(), i, root_distance, children);
        }
    }
}
