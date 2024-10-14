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

    use_stake_hack_for_testing: bool,

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
        use_stake_hack_for_testing: bool,
    ) TurbineTreeProvider {
        return .{
            .allocator = allocator,
            .my_contact_info = my_contact_info,
            .gossip_table_rw = gossip_table_rw,
            .cache = std.AutoArrayHashMap(Epoch, CacheEntry).init(allocator),
            .cache_entry_ttl = Duration.fromSecs(5), // value from agave
            .use_stake_hack_for_testing = use_stake_hack_for_testing,
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
    pub fn getForRetransmit(
        self: *TurbineTreeProvider,
        epoch: Epoch,
        bank: *const BankFields,
    ) !*TurbineTree {
        const gopr = try self.cache.getOrPut(epoch);

        if (gopr.found_existing) {
            if (gopr.value_ptr.alive(self.cache_entry_ttl)) {
                return gopr.value_ptr.turbine_tree;
            } else {
                gopr.value_ptr.turbine_tree.releaseUnsafe();
            }
        }

        const staked_nodes = try bank.getStakedNodes(self.allocator, epoch);
        defer staked_nodes.deinit();

        gopr.value_ptr.* = .{
            .created = Instant.now(),
            .turbine_tree = try createForRetransmit(
                self.allocator,
                self.my_contact_info,
                self.gossip_table_rw,
                staked_nodes,
                self.use_stake_hack_for_testing,
            ),
        };

        return gopr.value_ptr.turbine_tree;
    }

    pub fn createForRetransmit(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        gossip_table_rw: *RwMux(GossipTable),
        staked_nodes: *const std.AutoArrayHashMapUnmanaged(Pubkey, u64),
        use_stake_hack_for_testing: bool,
    ) !*TurbineTree {
        const tvu_peers = try getTvuPeers(
            allocator,
            my_contact_info,
            gossip_table_rw,
        );
        defer tvu_peers.deinit();

        const turbine_tree = try allocator.create(TurbineTree);
        turbine_tree.* = try TurbineTree.initForRetransmit(
            allocator,
            my_contact_info,
            tvu_peers.items,
            staked_nodes,
            use_stake_hack_for_testing,
        );

        return turbine_tree;
    }

    pub fn getTvuPeers(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        gossip_table_rw: *RwMux(GossipTable),
    ) !std.ArrayList(ThreadSafeContactInfo) {
        const gossip_table, var gossip_table_lg = gossip_table_rw.readWithLock();
        defer gossip_table_lg.unlock();

        var contact_info_iter = gossip_table.contactInfoIterator(0);
        var tvu_peers = try std.ArrayList(ThreadSafeContactInfo).initCapacity(allocator, gossip_table.contact_infos.count());

        while (contact_info_iter.nextThreadSafe()) |contact_info| {
            if (!contact_info.pubkey.equals(&my_contact_info.pubkey) and contact_info.shred_version == my_contact_info.shred_version) {
                tvu_peers.appendAssumeCapacity(contact_info);
            }
        }

        return tvu_peers;
    }
};

/// A TurbineTree is a data structure used to determine the set of nodes to
/// broadcast or retransmit shreds to in the network.
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

    /// Nodes in the TurbineTree may be identified by solely their
    /// pubkey if they are not in the gossip table or their contact info
    /// is not known
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
    };

    pub fn initForRetransmit(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        tvu_peers: []const ThreadSafeContactInfo,
        staked_nodes: *const std.AutoArrayHashMapUnmanaged(Pubkey, u64),
        use_stake_hack_for_testing: bool,
    ) !TurbineTree {
        const nodes = try getNodes(
            allocator,
            my_contact_info,
            tvu_peers,
            staked_nodes,
            use_stake_hack_for_testing,
        );
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

    /// Create a seeded RNG for the given leader and shred id.
    /// The resulting RNG must be identical to the agave implementation
    /// to ensure that the weighted shuffle is deterministic.
    fn getSeededRng(leader: Pubkey, shred: ShredId) ChaChaRng {
        const seed = shred.seed(leader);
        return ChaChaRng.fromSeed(seed);
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

    /// All staked nodes + other known tvu-peers + the node itself;
    /// sorted by (stake, pubkey) in descending order.
    fn getNodes(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        tvu_peers: []const ThreadSafeContactInfo,
        staked_nodes: *const std.AutoArrayHashMapUnmanaged(Pubkey, u64),
        use_stake_hack_for_testing: bool,
    ) !std.ArrayList(Node) {
        var nodes = try std.ArrayList(Node).initCapacity(allocator, tvu_peers.len + staked_nodes.count());
        defer nodes.deinit();

        var pubkeys = std.AutoArrayHashMap(Pubkey, void).init(allocator);
        defer pubkeys.deinit();

        // Add ourself to the list of nodes
        if (use_stake_hack_for_testing) {
            var max_stake: u64 = 0;
            for (staked_nodes.values()) |stake| if (stake > max_stake) {
                max_stake = stake;
            };
            nodes.appendAssumeCapacity(.{ .id = .{ .contact_info = my_contact_info }, .stake = @divFloor(max_stake, 2) });
        } else {
            try nodes.append(.{
                .id = .{ .contact_info = my_contact_info },
                .stake = if (staked_nodes.get(my_contact_info.pubkey)) |stake| stake else 0,
            });
        }
        try pubkeys.put(my_contact_info.pubkey, void{});

        // Add all TVU peers directly to the list of nodes
        // The TVU peers are all nodes in gossip table with the same shred version
        for (tvu_peers) |peer| {
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
