const std = @import("std");
const sig = @import("../lib.zig");

const Instant = std.time.Instant;

const IpAddr = sig.net.IpAddr;
const SocketAddr = sig.net.SocketAddr;
const ShredId = sig.ledger.shred.ShredId;
const RwMux = sig.sync.RwMux;
const ThreadSafeContactInfo = sig.gossip.data.ThreadSafeContactInfo;
const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;
const Duration = sig.time.Duration;
const WeightedShuffle = sig.rand.WeightedShuffle(u64);
const ChaChaRng = sig.rand.ChaChaRng(20);
const AutoArrayHashSet = sig.gossip.table.AutoArrayHashSet;

const MAX_NODES_PER_IP = 2;

const NodeId = union(enum) {
    contact_info: ThreadSafeContactInfo,
    pubkey: Pubkey,
};

const Node = struct {
    id: NodeId,
    stake: u64,

    pub fn pubkey(self: Node) Pubkey {
        switch (self.id) {
            .contact_info => |ci| ci.pubkey,
            .pubkey => |pk| pk,
        }
    }

    pub fn contactInfo(self: Node) ?ThreadSafeContactInfo {
        switch (self.id) {
            .contact_info => |ci| ci,
            .pubkey => null,
        }
    }

    pub fn fromContactInfo(ci: ThreadSafeContactInfo) Node {
        return .{ .id = .contact_info(ci), .stake = ci.stake };
    }
};

const Tree = struct {
    my_pubkey: Pubkey,
    nodes: []const Node,
    index: std.AutoArrayHashMap(Pubkey, usize),
    weighted_shuffle: WeightedShuffle,

    pub fn initForBroadcast(
        allocator: std.mem.Allocator,
        my_contact_info: ThreadSafeContactInfo,
        tvu_peers: []const ThreadSafeContactInfo,
        stakes: *std.AutoArrayHashMap(Pubkey, u64),
    ) !Tree {
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
        stakes: *std.AutoArrayHashMap(Pubkey, u64),
    ) !Tree {
        const nodes = try getNodes(allocator, my_contact_info, tvu_peers, stakes);
        var index = std.AutoArrayHashMap(Pubkey, usize).init(allocator);
        for (nodes.items, 0..) |node, i| index.put(node.pubkey(), i);
        var node_stakes = try std.ArrayList(u64).initCapacity(allocator, nodes.len);
        defer node_stakes.deinit();
        for (nodes.items) |node| node_stakes.append(node.stake);
        const weighted_shuffle = try WeightedShuffle.init(allocator, node_stakes.items);
        return .{
            .my_pubkey = my_contact_info.pubkey,
            .nodes = nodes,
            .index = index,
            .weighted_shuffle = weighted_shuffle,
        };
    }

    pub fn getBroadcastPeer(
        self: *const Tree,
        shred: *ShredId,
    ) ?*ThreadSafeContactInfo {
        const rng = getSeededRng(self.my_pubkey, shred);
        const index = self.weighted_shuffle.first(rng).?;
        return self.nodes[index].contactInfo();
    }

    pub fn getRetransmitAddresses(
        self: *const Tree,
        allocator: std.mem.Allocator,
        slot_leader: Pubkey,
        shred: *ShredId,
        fanout: usize,
    ) struct {
        usize,
        []ThreadSafeContactInfo,
    } {
        const root_distance, const children, const addresses = try self.getRetransmitPeers(slot_leader, shred, fanout);
        var peers = std.ArrayList(SocketAddr).init(allocator);
        for (children) |child| {
            if (child.contactInfo()) |ci| {
                if (addresses.get(ci.tvu_addr) == ci.pubkey()) peers.append(ci.tvu_addr);
            }
        }
        return .{ root_distance, peers.toOwnedSlice() };
    }

    pub fn getRetransmitPeers(
        self: *const Tree,
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

        var peers = std.ArrayList(*Node).init(allocator);
        const offset = (my_index -| 1) % fanout;
        const anchor = my_index - offset;
        const step = if (my_index == 0) 1 else fanout;
        const curr = anchor * fanout + offset + 1;
        var steps = 0;
        while (curr < nodes.len and steps < fanout) {
            try peers.append(&nodes[curr]);
            curr += step;
            steps += 1;
        }

        return .{ root_distance, peers, addresses };
    }

    pub fn getRetransmitParent(
        self: *const Tree,
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

        const my_index: usize = nodes.items.len;
        const offset = (my_index -| 1) % fanout;
        const index_a = if (my_index == 0) return null else (my_index - 1) / fanout;
        const index_b = index_a - (index_a -| 1) % fanout;
        const index = if (index_b == 0) index_b else index_b + offset;
        return nodes.items[index].pubkey();
    }
};

fn getSeededRng(leader: *Pubkey, shred: *ShredId) std.rand.Random {
    const seed = shred.seed(leader);
    return ChaChaRng.fromSeed(seed);
}

fn getNodes(
    allocator: std.mem.Allocator,
    my_contact_info: ThreadSafeContactInfo,
    tvu_peers: []const ThreadSafeContactInfo,
    stakes: *std.AutoArrayHashMap(Pubkey, u64),
) ![]Node {
    var nodes = try std.ArrayList(Node).initCapacity(allocator, stakes.count());
    defer nodes.deinit();
    var has_contact_info = AutoArrayHashSet(Pubkey).init(allocator);

    try nodes.append(.{
        .id = .{ .contact_info = my_contact_info },
        .stake = if (stakes.get(my_contact_info.pubkey())) |stake| stake else 0,
    });
    has_contact_info.put(my_contact_info.pubkey());

    for (tvu_peers) |peer_contact_info| {
        try nodes.append(.{
            .id = .{ .contact_info = peer_contact_info },
            .stake = if (stakes.get(peer_contact_info.pubkey())) |stake| stake else 0,
        });
        has_contact_info.put(peer_contact_info.pubkey());
    }

    for (stakes.keys(), stakes.values()) |pubkey, stake| {
        if (stake > 0 and !has_contact_info.contains(pubkey)) {
            nodes.append(.{
                .id = .{ .pubkey = pubkey },
                .stake = stake,
            });
        }
    }

    std.mem.sortUnstable(Node, nodes.items, void, struct {
        pub fn lt(_: void, lhs: Node, rhs: Node) bool {
            if (lhs.stake > rhs.stake) return true;
            if (lhs.stake < rhs.stake) return false;
            return lhs.pubkey() >= rhs.pubkey();
        }
    }.lt);

    var counts = std.AutoArrayHashMap(IpAddr, usize).init(allocator);
    var result = std.ArrayList(Node).init(allocator);
    for (nodes.items) |node| {
        if (node.contactInfo()) |ci| {
            if (ci.tvu_addr) |addr| {
                const current = counts.get(addr.ip()) orelse 0;
                if (current < MAX_NODES_PER_IP) try result.append(node);
                counts.put(
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

// TODO: Implement Testing
// fn testEnvironment() struct {
//     std.ArrayList(ThreadSafeContactInfo), // Nodes
//     ThreadSafeContactInfo, // My contact info
//     []const ThreadSafeContactInfo, // TVU peers
//     std.AutoArrayHashMap(Pubkey, u64), // Stakes
// } {}
