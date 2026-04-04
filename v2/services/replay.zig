const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tracy = @import("tracy");
const bk = @import("binkode");

const Packet = lib.net.Packet;

const Pubkey = lib.solana.Pubkey;
const Signature = lib.solana.Signature;
const Hash = lib.solana.Hash;
const Slot = lib.solana.Slot;

const Shred = lib.shred.Shred;
const FecSetId = lib.shred.FecSetId;

const Tree = lib.collections.LCRSTree;
const Pool = lib.collections.Pool;

comptime {
    _ = start;
}

pub const name = .replay;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = struct {
    deshredded_in: *lib.shred.DeshredRing,
};

var scratch_memory: [256 * 1024 * 1024]u8 = undefined;

pub fn serviceMain(rw: ReadWrite) !noreturn {
    const zone = tracy.Zone.init(@src(), .{ .name = @tagName(name) });
    defer zone.deinit();

    var fba = std.heap.FixedBufferAllocator.init(&scratch_memory);
    const allocator = fba.allocator();

    var map_tree: MerkleForest = try .init(allocator);

    var deshredded_iter = rw.deshredded_in.get(.reader);

    while (true) {
        const deshredded_fec_set: *const lib.shred.DeshreddedFecSet = deshredded_iter.next() orelse continue;
        defer deshredded_iter.markUsed();

        const received_zone = tracy.Zone.init(@src(), .{ .name = "received fec set" });
        defer received_zone.deinit();

        const result = try map_tree.put(deshredded_fec_set);
        std.log.info("{}: {f}, last? {}", .{ deshredded_fec_set.id, result, deshredded_fec_set.slot_complete });
    }
}

const BlockId = BlockTree.NodePool.ItemId;

const BlockTree = struct {
    node_pool: NodePool,
    node_tree: NodeTree,

    /// The latest block that has been rooted by consensus
    /// This node may have parents if other subsystems are still holding references to previous
    /// slots.
    /// For example, accountsdb may want to hold onto data for blocks for a while longer before it
    /// flushes to disk.
    /// Such subsystems may want to hold onto their own root?
    consensus_rooted_block: BlockId,

    // // NOTE: It would probably better to traverse the tree from a given root instead of using a map,
    // // as it would be easier to make lock-free. Currently if made multithreaded, value mutations
    // // could race with map inclusion.
    // last_merkle_map: LastMerkleMap,

    const capacity = 1024;

    const NodePool = Pool(Node, u32);
    const NodeTree = Tree(Node, u32);

    // TODO: large values (e.g. Hashes) should probably live elsewhere in memory to keep tree
    // traversal fast
    // This could maybe be 24 bytes (u32 idx * 3, slot u64, last merkle root hash u32)
    const Node = extern struct {
        parent: BlockId = .null,
        child: BlockId = .null,
        sibling: BlockId = .null,

        slot: Slot,

        // true when inside last_merkle_map
        last_fecset_received: bool,

        first_fecset_chained_merkle_root: Hash,

        // only valid when last_fecset_received is true
        // this is the safe way to identify a block
        last_fecset_merkle_root: Hash,
    };

    // You must get the root slot's last fec set's merkle root as this is used to identify blocks.
    // Currently, this is (very annoyingly) not part of the snapshot. This means we must repair the
    // snapshot slot in order to properly identify it.
    // SIMD-0333 `Serialize Block ID in Bank into Snapshot` fixes this problem.
    fn init(
        allocator: std.mem.Allocator,
        root_slot: Slot,
        root_slot_last_fec_set_merkle_root: *const Hash,
    ) !BlockTree {
        const pool_buf = try allocator.alloc(Node, capacity);
        errdefer allocator.free(pool_buf);

        var pool: NodePool = .init(@ptrCast(pool_buf));
        const root_node = try pool.create();

        root_node.* = .{
            .slot = root_slot,
            .last_fecset_received = true,
            .first_fecset_chained_merkle_root = undefined, // we don't need this
            .last_fecset_merkle_root = root_slot_last_fec_set_merkle_root.*,
        };

        return .{
            .node_pool = pool,
            .node_tree = .{ .buf = @ptrCast(pool_buf.ptr), .len = @intCast(pool_buf.len) },
            .consensus_rooted_block = pool.ptrToIndex(root_node),
        };
    }

    fn deinit(self: *BlockTree, allocator: std.mem.Allocator) void {
        allocator.free(self.node_pool.buf[0..self.node_pool.len]);
    }

    fn findUnrootedParent(
        self: *const BlockTree,
        parent_slot: Slot,
        parent_last_fecset_merkle_root: *const Hash,
    ) ?*Node {
        std.debug.assert(self.consensus_rooted_block != .null);

        const root_node: *Node = &self.node_pool.buf[@intFromEnum(self.consensus_rooted_block)].item;

        return self.findUnrootedParentRecursive(
            root_node,
            parent_slot,
            parent_last_fecset_merkle_root,
        );
    }

    fn findUnrootedParentRecursive(
        self: *const BlockTree,
        node: *Node,
        parent_slot: Slot,
        parent_last_fecset_merkle_root: *const Hash,
    ) ?*Node {
        // assuming for now we don't want to assign blockids until we have at least *received*
        // all of the parent
        if (node.slot == parent_slot and
            node.last_fecset_received and
            node.last_fecset_merkle_root.eql(parent_last_fecset_merkle_root))
            return node;

        // if the node's slot is >= the parent's slot, we can skip the child traversal, as children
        // always have increasing slots
        if (parent_slot > node.slot and node.child != .null) {
            const child_node: *Node = @ptrCast(&self.node_pool.buf[@intFromEnum(node.child)]);
            if (findUnrootedParentRecursive(
                self,
                child_node,
                parent_slot,
                parent_last_fecset_merkle_root,
            )) |found| return found;
        }

        // NOTE: siblings can have greater, equal, or lesser slot numbers than the current node, as
        // siblings are nodes which have chained off the same parent node, which does not imply
        // ordering.
        if (node.sibling != .null) {
            const sibling_node: *Node = @ptrCast(&self.node_pool.buf[@intFromEnum(node.child)]);
            if (findUnrootedParentRecursive(
                self,
                sibling_node,
                parent_slot,
                parent_last_fecset_merkle_root,
            )) |found| return found;
        }

        return null;
    }

    /// Should be called when
    ///  a) A new chain of fec sets "reaches" back to its parent slot. In the most basic case, this
    ///     should happen with all (valid) first fec sets.
    ///  b) A conflicting fec set is found.
    ///
    /// Attempts to find parent
    /// Tries to allocate new block ID
    /// Links parent and child
    ///
    fn tryAllocNewBlockId(
        self: *BlockTree,
        parent_slot: Slot,
        new_slot: Slot,
        // i.e. the last merke root of its parent
        first_fecset_chained_merkle_root: *const Hash,
    ) !?BlockId {
        std.debug.assert(new_slot > parent_slot);

        const parent: *Node = self.findUnrootedParent(parent_slot, first_fecset_chained_merkle_root) orelse {
            std.log.warn(
                \\ Failed to find parent block {}:{f}, is this block missing?
                \\ NOTE: parent blocks cannot be found unless they have received all their fecsets.
            ,
                .{ parent_slot, first_fecset_chained_merkle_root },
            );
            return null;
        };

        const new_child = try self.node_pool.create();
        errdefer self.node_pool.destroy(new_child);

        new_child.* = .{
            .slot = new_slot,
            .last_fecset_received = false,
            .first_fecset_chained_merkle_root = first_fecset_chained_merkle_root.*,
            .last_fecset_merkle_root = undefined, // only set once the last fecset is received
        };

        self.node_tree.linkOrphaned(parent, new_child);

        return self.node_pool.ptrToIndex(new_child);
    }

    /// Asserts node is already linked to parent
    /// Assumes node is that of a block which has received all fec sets
    fn markBlockFullyReceived(
        self: *const BlockTree,
        block: BlockId,
        last_fecset_merkle_root: *const Hash,
    ) void {
        std.debug.assert(block != .null);

        const node: *Node = @ptrCast(&self.node_pool.buf[@intFromEnum(block)]);

        std.debug.assert(node.parent != .null);
        node.last_fecset_received = true;
        node.last_fecset_merkle_root = last_fecset_merkle_root.*;
    }
};

test "Basic blocktree" {
    const allocator = std.testing.allocator;

    const root_hash: Hash = .parse("ByzshhkRgXWnTkHjapkkqaKgEFnsg8ceY3bw4MWBzFE");

    var blocks: BlockTree = try .init(allocator, 0, &root_hash);
    defer blocks.deinit(allocator);

    const slot_1_block = (try blocks.tryAllocNewBlockId(0, 1, &root_hash)).?;
    const slot_1_hash: Hash = .parse("2GyMeUytf6fcsfNP2QQ6F5e5qwAUoMtKUbnH6QU6bTNm");
    blocks.markBlockFullyReceived(slot_1_block, &slot_1_hash);

    const slot_2_block = (try blocks.tryAllocNewBlockId(1, 2, &slot_1_hash)).?;
    const slot_2_hash: Hash = .parse("BMHr4knWhDp8JhqCYhA2K5DUYQsYUVXdy2zWahzt5jLd");
    blocks.markBlockFullyReceived(slot_2_block, &slot_2_hash);
}

/// A hashmap value, and a tree node.
/// This node is also used for the keys of hashmaps. When doing so, be careful of which adapted
/// context you use.
///
/// NOTE: When used inside the Pool, these may be items in a free list. However such nodes should
/// not be in either map or the tree.
const MerkleNode = extern struct {
    parent: MerkleForest.NodePool.ItemId = .null,
    child: MerkleForest.NodePool.ItemId = .null,
    sibling: MerkleForest.NodePool.ItemId = .null,

    merkle_root: Hash,
    chained_merkle_root: Hash,
    id: FecSetId,
    data_complete: bool,
    slot_complete: bool,
    payload_len: u16,

    // TODO: this shouldn't be copied, and should instead come in via a pool
    // NOTE: it is an advantage for MerkleNode to be small! (cache locality for map lookup and tree
    // traversal).
    payload_buf: [32 * Shred.data_payload_max]u8,

    pub fn format(node: *const MerkleNode, writer: *std.io.Writer) !void {
        try writer.print(
            \\ {{
            \\     id: {}, slot_complete: {}
            \\     parent: {}, child: {}, sibling: {}
            \\     root: {f}, chained_root: {f}
            \\     data_complete: {}, slot_complete: {}
            \\ }}
            \\
        , .{
            node.id,
            node.parent,
            node.child,
            node.sibling,
            node.merkle_root,
            node.chained_merkle_root,
            node.data_complete,
            node.slot_complete,
        });
    }
};

// TODO: handle eviction
/// A tree of FEC sets, which are also keyed by their merkle (and chained) merkle roots.
const MerkleForest = struct {
    // owns all of the memory of nodes used in the tree
    pool: NodePool,
    tree: NodeTree,

    // Nodes are inserted, keyed by their merkle root.
    // New nodes can look for their parent using this map.
    //
    // merkle-hash -> node
    map: MerkleMap,

    // Nodes are inserted, keyed by their *chained* merkle root.
    // New nodes can look for their child using this map.
    //
    // chained-merkle-hash -> node
    orphan_map: OrphanMap,

    const capacity = 2048;

    // keyed by merkle root
    const OrphanMap = std.ArrayHashMapUnmanaged(void, *MerkleNode, OrphanContext, true);

    // keyed by chained merkle root
    const MerkleMap = std.ArrayHashMapUnmanaged(void, *MerkleNode, MerkleContext, true);

    const NodePool = Pool(MerkleNode, u32);
    const NodeTree = Tree(MerkleNode, u32);

    const MerkleContext = struct {
        map: *const MerkleMap,

        pub fn hash(ctx: MerkleContext, key: *const Hash) u32 {
            _ = ctx;
            return @bitCast(key.data[0..4].*);
        }
        pub fn eql(ctx: MerkleContext, a: *const Hash, _: void, key_idx: usize) bool {
            const b: *const Hash = &ctx.map.values()[key_idx].merkle_root;
            return a.eql(b);
        }
    };

    const OrphanContext = struct {
        map: *const OrphanMap,

        pub fn hash(ctx: OrphanContext, key: *const Hash) u32 {
            _ = ctx;
            return @bitCast(key.data[0..4].*);
        }
        pub fn eql(ctx: OrphanContext, a: *const Hash, _: void, key_idx: usize) bool {
            const b: *const Hash = &ctx.map.values()[key_idx].chained_merkle_root;
            return a.eql(b);
        }
    };

    fn init(allocator: std.mem.Allocator) !MerkleForest {
        const pool_buf = try allocator.alloc(MerkleNode, capacity);
        errdefer allocator.free(pool_buf);

        var map: MerkleMap = .empty;
        errdefer map.deinit(allocator);
        try map.ensureTotalCapacity(allocator, capacity);

        var orphan_map: OrphanMap = .empty;
        errdefer orphan_map.deinit(allocator);
        try orphan_map.ensureTotalCapacity(allocator, capacity);

        return .{
            // NOTE: the pool and the tree share the exact same buffer - this is intentional
            .pool = .init(pool_buf[0..capacity]),
            .tree = .{ .buf = @ptrCast(pool_buf.ptr), .len = @intCast(pool_buf.len) },

            .map = map,
            .orphan_map = orphan_map,
        };
    }

    fn deinit(self: *MerkleForest, allocator: std.mem.Allocator) void {
        allocator.free(self.pool.buf[0..self.pool.len]);
        self.map.deinit(allocator);
        self.orphan_map.deinit(allocator);
    }

    const InsertResult = union(enum) {
        node_already_known, // merkle root in map early return

        waiting_for_child,
        waiting_for_parent,
        waiting_for_parent_and_child,

        // The new node's parent and child nodes are both found (or not needed), but we still don't
        // have a complete slot.
        chain_incomplete,
        chain_complete,

        pub fn format(self: InsertResult, writer: *std.io.Writer) !void {
            switch (self) {
                inline else => try writer.print("{s}", .{@tagName(self)}),
            }
        }
    };

    // TODO: eviction
    // TODO: remove orphans from orphan_map once parented
    fn put(self: *MerkleForest, new_fec_set: *const lib.shred.DeshreddedFecSet) !InsertResult {
        const map_ctx: MerkleContext = .{ .map = &self.map };
        const orphan_map_ctx: OrphanContext = .{ .map = &self.orphan_map };

        self.assertCounts();
        defer self.assertCounts();

        const map_result = self.map.getOrPutAssumeCapacityAdapted(&new_fec_set.merkle_root, map_ctx);
        if (map_result.found_existing) return .node_already_known;

        const node = try self.pool.create();
        map_result.value_ptr.* = node;

        node.* = .{
            .merkle_root = new_fec_set.merkle_root,
            .chained_merkle_root = new_fec_set.chained_merkle_root,
            .id = new_fec_set.id,
            .data_complete = new_fec_set.data_complete,
            .slot_complete = new_fec_set.slot_complete,
            .payload_len = new_fec_set.payload_len,
            .payload_buf = new_fec_set.payload_buf,
        };

        var must_wait_for_parent: bool = false;

        // TODO: stop checking cross-slot?
        if (self.map.getAdapted(&new_fec_set.chained_merkle_root, map_ctx)) |parent| {
            self.tree.linkOrphaned(parent, node);
            // return .{ .inserted_known_chain = parent };
        } else if (new_fec_set.id.fec_set_idx != 0) {
            // We don't have this fec set's parent yet, and it should have one.
            //
            // The chained merkle root of a node is the node's parent; nodes encode enough
            // information to find their parent, but not their child.
            //
            // We insert this parent-less node into this map, such that if the parent comes later,
            // it can find its child, only knowing the merkle root of itself.
            //

            const orphan_map_result = self.orphan_map.getOrPutAssumeCapacityAdapted(
                &new_fec_set.chained_merkle_root,
                orphan_map_ctx,
            );
            std.debug.assert(!orphan_map_result.found_existing);
            orphan_map_result.value_ptr.* = node;

            must_wait_for_parent = true;
        }

        var must_wait_for_child: bool = false;

        if (self.orphan_map.getAdapted(&new_fec_set.merkle_root, orphan_map_ctx)) |child| {
            self.tree.linkOrphaned(node, child);
        } else if (!new_fec_set.slot_complete) {
            // We don't have this fec set's child yet, and it should have one
            //
            // There is nothing to do here, the child can find its parent through the child's
            // chained merkle root in self.map.

            must_wait_for_child = true;
        }

        if (!must_wait_for_child and !must_wait_for_parent) {
            // This slot might be finished? Let's traverse our node's parents and children to find
            // out.
            const start_finished: bool = node.id.fec_set_idx == 0 or found_idx_0: {
                var maybe_backwards_idx: ?u32 = node.parent.index();

                break :found_idx_0 while (maybe_backwards_idx) |backwards_idx| {
                    const parent_node: *const MerkleNode = @ptrCast(&self.pool.buf[backwards_idx]);

                    if (parent_node.id.fec_set_idx == 0) break true;

                    maybe_backwards_idx = parent_node.parent.index();
                } else false;
            };

            const end_finished: bool = node.slot_complete or found_slot_complete: {
                var maybe_forwards_idx: ?u32 = node.child.index();

                break :found_slot_complete while (maybe_forwards_idx) |forwards_idx| {
                    const child_node: *const MerkleNode = @ptrCast(&self.pool.buf[forwards_idx]);

                    if (child_node.slot_complete) break true;

                    maybe_forwards_idx = child_node.child.index();
                } else false;
            };

            return if (start_finished and end_finished) return .chain_complete else .chain_incomplete;
        }

        if (must_wait_for_child and must_wait_for_parent) return .waiting_for_parent_and_child;
        if (must_wait_for_child) return .waiting_for_child;
        if (must_wait_for_parent) return .waiting_for_parent;
        unreachable;
    }

    fn assertCounts(self: *const MerkleForest) void {
        std.debug.assert(self.orphan_map.count() <= self.map.count());
        tracy.plot(u32, "Merkle forest fec sets", @intCast(self.map.count()));
        tracy.plot(u32, "Merkle forest fec sets (orphaned)", @intCast(self.orphan_map.count()));
    }
};

test "MerkleForest tree put" {
    var tree: MerkleForest = try .init(std.testing.allocator);
    defer tree.deinit(std.testing.allocator);

    const a_hash: Hash = .parse("ByzshhkRgXWnTkHjapkkqaKgEFnsg8ceY3bw4MWBzFE");
    const b_hash: Hash = .parse("BMHr4knWhDp8JhqCYhA2K5DUYQsYUVXdy2zWahzt5jLd");
    const c_hash: Hash = .parse("2GyMeUytf6fcsfNP2QQ6F5e5qwAUoMtKUbnH6QU6bTNm");

    const a: lib.shred.DeshreddedFecSet = .{
        .chained_merkle_root = .parse("DWCWjQciWoWDzJKwqUZ1ntKqTyXtLVt4C8aL7biBJZ4z"), // prev slot
        .merkle_root = a_hash,

        .id = .{ .slot = 409284941, .fec_set_idx = 0 },

        .data_complete = true,
        .slot_complete = false,

        .payload_len = 0,
        .payload_buf = undefined,
    };

    const b: lib.shred.DeshreddedFecSet = .{
        .chained_merkle_root = a_hash,
        .merkle_root = b_hash,

        .id = .{ .slot = 409284941, .fec_set_idx = 32 },

        .data_complete = true,
        .slot_complete = false,

        .payload_len = 0,
        .payload_buf = undefined,
    };

    const c: lib.shred.DeshreddedFecSet = .{
        .chained_merkle_root = b_hash,
        .merkle_root = c_hash,

        .id = .{ .slot = 409284941, .fec_set_idx = 64 },

        .data_complete = true,
        .slot_complete = true,

        .payload_len = 0,
        .payload_buf = undefined,
    };

    try std.testing.expectEqual(.waiting_for_child, try tree.put(&a));
    try std.testing.expectEqual(.waiting_for_child, try tree.put(&b));
    try std.testing.expectEqual(.chain_complete, try tree.put(&c));
}

test "MerkleForest fec set completion out of order" {
    const allocator = std.testing.allocator;

    var forest = try MerkleForest.init(allocator);
    defer forest.deinit(allocator);

    // a <- b <- c <- d, inserted in order: a, c, b, d
    const a_hash: Hash = .parse("ByzshhkRgXWnTkHjapkkqaKgEFnsg8ceY3bw4MWBzFE");
    const b_hash: Hash = .parse("BMHr4knWhDp8JhqCYhA2K5DUYQsYUVXdy2zWahzt5jLd");
    const c_hash: Hash = .parse("2GyMeUytf6fcsfNP2QQ6F5e5qwAUoMtKUbnH6QU6bTNm");
    const d_hash: Hash = .parse("Cg37799xhTFEGyqXSEekbVbiCZKQAjzc6CQC75Hk91S9");

    const a_result = try forest.put(&.{
        .merkle_root = a_hash,
        .chained_merkle_root = .parse("DWCWjQciWoWDzJKwqUZ1ntKqTyXtLVt4C8aL7biBJZ4z"), // prev slot
        .id = .{ .slot = 409284941, .fec_set_idx = 0 },
        .slot_complete = false,

        .data_complete = true,
        .payload_len = undefined,
        .payload_buf = undefined,
    });

    const c_result = try forest.put(&.{
        .merkle_root = c_hash,
        .chained_merkle_root = b_hash,
        .id = .{ .slot = 409284941, .fec_set_idx = 64 },
        .slot_complete = false,

        .data_complete = true,
        .payload_len = undefined,
        .payload_buf = undefined,
    });

    const b_result = try forest.put(&.{
        .merkle_root = b_hash,
        .chained_merkle_root = a_hash,
        .id = .{ .slot = 409284941, .fec_set_idx = 32 },
        .slot_complete = false,

        .data_complete = true,
        .payload_len = undefined,
        .payload_buf = undefined,
    });

    const d_result = try forest.put(&.{
        .merkle_root = d_hash,
        .chained_merkle_root = c_hash,
        .id = .{ .slot = 409284941, .fec_set_idx = 96 },
        .slot_complete = true,

        .data_complete = true,
        .payload_len = undefined,
        .payload_buf = undefined,
    });

    try std.testing.expectEqual(.waiting_for_child, a_result);
    try std.testing.expectEqual(.waiting_for_parent_and_child, c_result);
    try std.testing.expectEqual(.chain_incomplete, b_result);
    try std.testing.expectEqual(.chain_complete, d_result);
}

const bincode = struct {
    // This isn't quite a bincode fixed int, nor a varint. It's some custom Solana thing used in
    // Agave's `short_vec`. I think it's supposed to be smaller than a fixed or varint for a u16.
    const compact_u16: bk.Codec(u16) = .implement(void, void, struct {
        pub fn encode(
            writer: *std.Io.Writer,
            _: bk.Config,
            values: []const u16,
            _: ?*[encode_stack_size]u64,
            limit: std.Io.Limit,
            _: void,
        ) bk.EncodeToWriterError!bk.EncodedCounts {
            const max_count = limit.max(values.len);
            var byte_count: usize = 0;
            for (values[0..max_count]) |val| {
                var rem: u16 = val;
                while (true) {
                    var elem: u8 = @truncate(rem & 0x7f);
                    rem >>= 7;
                    if (rem == 0) {
                        writer.writeByte(elem) catch return error.EncodeFailed;
                        byte_count += 1;
                        break;
                    } else {
                        elem |= 0x80;
                        writer.writeByte(elem) catch return error.EncodeFailed;
                        byte_count += 1;
                    }
                }
            }
            return .{ .value_count = max_count, .byte_count = byte_count };
        }

        pub const encode_min_size: usize = 1;
        pub const encode_stack_size: usize = 0;
        pub const decodeInit = null;

        pub fn decode(
            reader: *std.Io.Reader,
            _: bk.Config,
            _: ?std.mem.Allocator,
            values: []u16,
            decoded_count: *usize,
            _: void,
        ) bk.DecodeFromReaderError!void {
            for (values, 0..) |*value, i| {
                errdefer decoded_count.* = i;

                var result: u16 = 0;
                var shift: u4 = 0;
                for (0..3) |_| {
                    const byte = try reader.takeByte();
                    result |= @as(u16, byte & 0x7f) << shift;
                    if (byte & 0x80 == 0) break;
                    shift += 7;
                } else {
                    // Fourth byte would be needed → overflow for u16
                    return error.DecodeFailed;
                }
                value.* = result;
            }
            decoded_count.* = values.len;
        }

        pub fn decodeSkip(
            reader: *std.Io.Reader,
            _: bk.Config,
            value_count: usize,
            decoded_count: *usize,
            _: void,
        ) bk.DecodeSkipError!void {
            for (0..value_count) |i| {
                errdefer decoded_count.* = i;
                for (0..3) |_| {
                    const byte = try reader.takeByte();
                    if (byte & 0x80 == 0) break;
                } else {
                    return error.DecodeFailed;
                }
            }
            decoded_count.* = value_count;
        }

        pub const free = null;
    });

    // For slices that have a compact_u16 length rather than a u64
    fn shortVec(comptime Element: type, comptime element: bk.Codec(Element)) bk.Codec([]Element) {
        return comptime .implement(element.EncodeCtx, element.DecodeCtx, struct {
            pub fn encode(
                writer: *std.Io.Writer,
                config: bk.Config,
                values: []const []Element,
                _: ?*[encode_stack_size]u64,
                limit: std.Io.Limit,
                ctx: element.EncodeCtx,
            ) bk.EncodeToWriterError!bk.EncodedCounts {
                const max_count = limit.max(values.len);
                var byte_count: usize = 0;
                for (values[0..max_count]) |slice_val| {
                    // Write compact-u16 length
                    const len: u16 = std.math.cast(u16, slice_val.len) orelse return error.EncodeFailed;
                    const len_counts = try compact_u16.encodeOnePartialRaw(writer, config, &len, null, .unlimited, {});
                    byte_count += len_counts.byte_count;

                    // Write elements
                    const elem_counts = try element.encodeManyPartialRaw(writer, config, slice_val, null, .unlimited, ctx);
                    byte_count += elem_counts.byte_count;
                }
                return .{ .value_count = max_count, .byte_count = byte_count };
            }

            pub const encode_min_size: usize = 1;
            pub const encode_stack_size: usize = 0;

            pub fn decodeInit(
                gpa_opt: ?std.mem.Allocator,
                values: [][]Element,
                _: element.DecodeCtx,
            ) std.mem.Allocator.Error!void {
                _ = gpa_opt.?;
                @memset(values, &.{});
            }

            pub fn decode(
                reader: *std.Io.Reader,
                config: bk.Config,
                gpa_opt: ?std.mem.Allocator,
                values: [][]Element,
                decoded_count: *usize,
                ctx: element.DecodeCtx,
            ) bk.DecodeFromReaderError!void {
                const gpa = gpa_opt.?;
                for (values, 0..) |*value, i| {
                    errdefer decoded_count.* = i;

                    const len = try compact_u16.decode(reader, null, .default, {});

                    const elems = try gpa.alloc(Element, len);
                    errdefer gpa.free(elems);

                    // decode into elems
                    try element.decodeInitMany(gpa, elems, ctx);
                    errdefer element.freeMany(gpa, elems, ctx);

                    try element.decodeIntoMany(reader, gpa, config, elems, ctx);

                    value.* = elems;
                }
                decoded_count.* = values.len;
            }

            pub fn decodeSkip(
                reader: *std.Io.Reader,
                config: bk.Config,
                value_count: usize,
                decoded_count: *usize,
                ctx: element.DecodeCtx,
            ) bk.DecodeSkipError!void {
                for (0..value_count) |i| {
                    errdefer decoded_count.* = i;
                    const len = try compact_u16.decode(reader, null, .default, null);
                    try element.decodeSkip(reader, config, len, ctx);
                }
                decoded_count.* = value_count;
            }

            pub fn free(
                gpa_opt: ?std.mem.Allocator,
                slice_list: []const []Element,
                ctx: element.DecodeCtx,
            ) void {
                const gpa = gpa_opt.?;
                for (slice_list) |slice_value| {
                    element.freeMany(gpa, slice_value, ctx);
                    gpa.free(slice_value);
                }
            }
        });
    }

    const hash_codec: bk.Codec(Hash) = .standard(.tuple(.{
        .data = .array(.fixint),
    }));

    const pubkey_codec: bk.Codec(Pubkey) = .standard(.tuple(.{
        .data = .array(.fixint),
    }));

    const MessageHeader = struct {
        num_required_signatures: u8,
        num_readonly_signed_accounts: u8,
        num_readonly_unsigned_accounts: u8,

        const bk_config: bk.Codec(MessageHeader) = .standard(.tuple(.{
            .num_required_signatures = .fixint,
            .num_readonly_signed_accounts = .fixint,
            .num_readonly_unsigned_accounts = .fixint,
        }));
    };

    const CompiledInstruction = struct {
        program_id_index: u8,
        accounts: []u8,
        data: []u8,

        const bk_config: bk.Codec(CompiledInstruction) = .standard(.tuple(.{
            .program_id_index = .fixint,
            .accounts = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
            .data = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
        }));
    };

    const AddressLookup = struct {
        account_key: Pubkey,
        writable_indexes: []u8,
        readonly_indexes: []u8,

        const bk_config: bk.Codec(AddressLookup) = .standard(.tuple(.{
            .account_key = .from(pubkey_codec),
            .writable_indexes = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
            .readonly_indexes = .from(shortVec(u8, bk.StdCodec(u8).fixint.codec)),
        }));
    };

    const LegacyMessage = struct {
        header: MessageHeader,
        account_keys: []Pubkey,
        recent_blockhash: Hash,
        instructions: []CompiledInstruction,

        const bk_config: bk.Codec(LegacyMessage) = .standard(.tuple(.{
            .header = .from(MessageHeader.bk_config),
            .account_keys = .from(shortVec(Pubkey, pubkey_codec)),
            .recent_blockhash = .from(hash_codec),
            .instructions = .from(shortVec(CompiledInstruction, CompiledInstruction.bk_config)),
        }));
    };

    const V0Message = struct {
        header: MessageHeader,
        account_keys: []Pubkey,
        recent_blockhash: Hash,
        instructions: []CompiledInstruction,
        address_table_lookups: []AddressLookup,

        const bk_config: bk.Codec(V0Message) = .standard(.tuple(.{
            .header = .from(MessageHeader.bk_config),
            .account_keys = .from(shortVec(Pubkey, pubkey_codec)),
            .recent_blockhash = .from(hash_codec),
            .instructions = .from(shortVec(CompiledInstruction, CompiledInstruction.bk_config)),
            .address_table_lookups = .from(shortVec(AddressLookup, AddressLookup.bk_config)),
        }));
    };

    const VersionedMessage = union(enum) {
        // first byte & 0x80 == 0
        legacy: LegacyMessage,
        // first byte & 0x80 != 0
        v0: V0Message,

        const bk_config: bk.Codec(VersionedMessage) = .implement(void, void, struct {
            pub fn encode(
                writer: *std.Io.Writer,
                config: bk.Config,
                values: []const VersionedMessage,
                _: ?*[encode_stack_size]u64,
                limit: std.Io.Limit,
                _: void,
            ) bk.EncodeToWriterError!bk.EncodedCounts {
                const max_count = limit.max(values.len);
                var byte_count: usize = 0;
                for (values[0..max_count]) |value| {
                    switch (value) {
                        .legacy => |msg| {
                            // Legacy: no version prefix byte; MessageHeader.num_required_signatures
                            // is the first byte on the wire (written by LegacyMessage codec).
                            const counts = LegacyMessage.bk_config.encodeOnePartialRaw(
                                writer,
                                config,
                                &msg,
                                null,
                                .unlimited,
                                {},
                            ) catch return error.EncodeFailed;
                            byte_count += counts.byte_count;
                        },
                        .v0 => |msg| {
                            // V0: write version prefix byte (0x80 | 0x00 = 0x80), then V0Message.
                            writer.writeByte(0x80) catch return error.EncodeFailed;
                            byte_count += 1;
                            const counts = V0Message.bk_config.encodeOnePartialRaw(
                                writer,
                                config,
                                &msg,
                                null,
                                .unlimited,
                                {},
                            ) catch return error.EncodeFailed;
                            byte_count += counts.byte_count;
                        },
                    }
                }
                return .{ .value_count = max_count, .byte_count = byte_count };
            }

            pub const encode_min_size: usize = 1;
            pub const encode_stack_size: usize = 0;
            pub const decodeInit = null;

            pub fn decode(
                reader: *std.Io.Reader,
                config: bk.Config,
                gpa_opt: ?std.mem.Allocator,
                values: []VersionedMessage,
                decoded_count: *usize,
                _: void,
            ) bk.DecodeFromReaderError!void {
                for (values, 0..) |*value, i| {
                    errdefer decoded_count.* = i;

                    // Peek the first byte to determine version.
                    const first_byte = try reader.takeByte();

                    if (first_byte & 0x80 == 0) {
                        // Legacy message. The byte we just read is num_required_signatures.
                        // We need to "put it back" — reconstruct by reading the remaining
                        // MessageHeader fields (2 more bytes), then the rest of the message.
                        const num_readonly_signed = try reader.takeByte();
                        const num_readonly_unsigned = try reader.takeByte();
                        const header: MessageHeader = .{
                            .num_required_signatures = first_byte,
                            .num_readonly_signed_accounts = num_readonly_signed,
                            .num_readonly_unsigned_accounts = num_readonly_unsigned,
                        };

                        // Decode the remaining fields of LegacyMessage (account_keys, recent_blockhash, instructions)
                        const account_keys_codec = shortVec(Pubkey, pubkey_codec);
                        const account_keys = try account_keys_codec.decode(reader, gpa_opt, config, null);

                        var recent_blockhash: Hash = undefined;
                        try hash_codec.decodeIntoOne(reader, null, config, &recent_blockhash, null);

                        const instructions_codec = shortVec(CompiledInstruction, CompiledInstruction.bk_config);
                        const instructions = try instructions_codec.decode(reader, gpa_opt, config, null);

                        value.* = .{ .legacy = .{
                            .header = header,
                            .account_keys = account_keys,
                            .recent_blockhash = recent_blockhash,
                            .instructions = instructions,
                        } };
                    } else {
                        // Versioned message. The byte was consumed. Check version.
                        const version = first_byte & 0x7F;
                        if (version != 0) {
                            return error.DecodeFailed; // unsupported version
                        }

                        // Decode V0Message
                        const msg = try V0Message.bk_config.decode(reader, gpa_opt, config, null);
                        value.* = .{ .v0 = msg };
                    }
                }
                decoded_count.* = values.len;
            }

            pub fn decodeSkip(
                reader: *std.Io.Reader,
                config: bk.Config,
                value_count: usize,
                decoded_count: *usize,
                _: void,
            ) bk.DecodeSkipError!void {
                for (0..value_count) |i| {
                    errdefer decoded_count.* = i;
                    const first_byte = try reader.takeByte();

                    if (first_byte & 0x80 == 0) {
                        // Legacy: skip remaining 2 header bytes + fields
                        try reader.discardAll(2);
                        // Skip account_keys (shortVec of 32-byte pubkeys)
                        const ak_len = try compact_u16.decode(reader, null, .default, null);
                        try reader.discardAll(ak_len * Pubkey.SIZE);
                        // Skip recent_blockhash
                        try reader.discardAll(Hash.SIZE);
                        // Skip instructions
                        const ix_len = try compact_u16.decode(reader, null, .default, null);
                        try CompiledInstruction.bk_config.decodeSkip(reader, config, ix_len, {});
                    } else {
                        // V0: version byte already consumed. Skip V0Message.
                        try V0Message.bk_config.decodeSkip(reader, config, 1, {});
                    }
                }
                decoded_count.* = value_count;
            }

            pub fn free(
                gpa_opt: ?std.mem.Allocator,
                values: []const VersionedMessage,
                _: void,
            ) void {
                for (values) |value| {
                    switch (value) {
                        .legacy => |msg| LegacyMessage.bk_config.free(gpa_opt, &msg, null),
                        .v0 => |msg| V0Message.bk_config.free(gpa_opt, &msg, null),
                    }
                }
            }
        });
    };

    const VersionedTransaction = struct {
        signatures: []Signature,
        message: VersionedMessage,

        const bk_config: bk.Codec(VersionedTransaction) = .standard(.tuple(.{
            .signatures = .from(shortVec(Signature, Signature.bk_config)),
            .message = .from(VersionedMessage.bk_config),
        }));
    };

    const Entry = struct {
        num_hashes: u64,
        hash: Hash,
        transactions: []VersionedTransaction,

        const bk_config: bk.Codec(Entry) = .standard(.tuple(.{
            .num_hashes = .fixint,
            .hash = .from(hash_codec),
            .transactions = .sliceNonStd(VersionedTransaction.bk_config),
        }));

        // slice of entries
        const slice_config: bk.Codec([]Entry) = .standard(.sliceNonStd(Entry.bk_config));
    };
};
