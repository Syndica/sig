const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tracy = @import("tracy");

const replay = lib.replay;

const bincode = lib.solana.bincode;

const Hash = lib.solana.Hash;
const Slot = lib.solana.Slot;
const Entry = lib.solana.transaction.Entry;

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

pub const ReadOnly = struct {};
pub const ReadWrite = struct {
    deshredded_in: *lib.shred.DeshredRing,
    replay_transaction_pool: *lib.replay.TransactionPool,
    block_pool: *lib.replay.BlockPool,
    exec_req_response: *lib.replay.ExecReqResponse,
};

var scratch_memory: [256 * 1024 * 1024]u8 = undefined;

const TransactionsIterator = struct {
    current_node: *const MerkleNode,
    current_node_read_transaction_count: u16,
    current_entry_batch_transaction_count: u16,

    fn init(current_node: *const MerkleNode) TransactionsIterator {
        return .{
            .current_node = current_node,
            .current_node_read_transaction_count = 0,
            .current_entry_batch_transaction_count = 0,
        };
    }

    // returns the n
    // hash.* == null <=> num_hashes.* == null
    fn next(
        iter: *TransactionsIterator,
        transaction_buf: *[1232]u8,
        hash: *?Hash,
        num_hashes: *?u64,
    ) ?[]const u8 {
        _ = iter;
        _ = transaction_buf;
        _ = hash;
        _ = num_hashes;
        // if (current_node_read_transaction_count == 0)
    }
};

pub fn serviceMain(_: ReadOnly, rw: ReadWrite) !noreturn {
    var fba: std.heap.FixedBufferAllocator = .init(&scratch_memory);
    const allocator = fba.allocator();

    var map_tree: MerkleForest = try .init(allocator);

    var deshredded_iter = rw.deshredded_in.get(.reader);

    while (true) {
        const deshredded_fec_set: *const lib.shred.DeshreddedFecSet = blk: {
            const loop_zone = tracy.Zone.init(@src(), .{ .name = "spinning" });
            defer loop_zone.deinit();

            while (true) {
                break :blk deshredded_iter.next() orelse continue;
            }
        };
        defer deshredded_iter.markUsed();

        const received_zone = tracy.Zone.init(@src(), .{ .name = "received fec set" });
        defer received_zone.deinit();

        const inserted_node = try map_tree.put(rw.block_pool, deshredded_fec_set) orelse
            continue; // null => node already known, nothing to do here

        // _ = inserted_node;

        var exec_request_sender = rw.exec_req_response.request_ring.get(.writer);
        var exec_response_receiver = rw.exec_req_response.response_ring.get(.reader);

        if (inserted_node.block_ref == .null) {
            // blockrefs are assigned from the 0th fecset, and carried forward. If the newly
            // inserted node isn't attached to a 0th fecset, we won't be able to execute it until it
            // is.

            // NOTE: we *could* do some PoH and sig verify tasks early here, but it seems like there
            // isn't actually an advantage, as a validator executing transactions will have plenty
            // of "gaps" in exec thread pool usage, and these tasks only have to be finished before
            // we finish the block as a whole.

            // TODO: with that being said, we could probably benefit from prefetching accounts here.
            continue;
        }

        // assert that we've got a chain of fec sets back to the 0th fec set
        {
            var maybe_node: ?*MerkleNode = inserted_node;
            while (maybe_node) |node| : (maybe_node = map_tree.pool.indexToOptPtr(node.parent)) {
                std.debug.assert(node.parent != .null or node.id.fec_set_idx == 0);
            }
        }

        if (inserted_node.dataStart(map_tree.pool) == true and inserted_node.data_complete) {
            // we can deserialise all at once

            var reader = std.io.Reader.fixed(inserted_node.payload());

            // 64 should be fine, extra is for allocations made by bincode
            var deserialised_buf: [128 * 1024]u8 = undefined;
            var deserial_fba: std.heap.FixedBufferAllocator = .init(&deserialised_buf);

            const n_entries = try bincode.read(&deserial_fba, &reader, u64);
            for (0..n_entries) |_| {
                const num_hashes: u64 = try bincode.read(&deserial_fba, &reader, u64);
                const hash: Hash = try bincode.read(&deserial_fba, &reader, Hash);

                _ = num_hashes;
                _ = hash;

                const n_transactions = try bincode.read(&deserial_fba, &reader, u64);
                for (0..n_transactions) |_| {
                    var pre = reader; // capture before position

                    const transaction = try bincode.read(&deserial_fba, &reader, lib.solana.transaction.VersionedTransaction);

                    // NOTE: we store bincode-encoded transactions as-is, as:
                    //       1) we know the upper bound size
                    //       2) deserialising is cheap, and I think we only have to do it twice
                    _ = transaction;

                    const transaction_id = try rw.replay_transaction_pool.createId();
                    defer rw.replay_transaction_pool.destroyId(transaction_id);

                    const transaction_buf: *[1232]u8 = rw.replay_transaction_pool.indexToPtr(transaction_id);
                    const transaction_bytes: []u8 = transaction_buf[0 .. reader.seek - pre.seek];
                    pre.readSliceAll(transaction_bytes) catch return error.badbadbad;

                    tracy.plot(u16, "transaction size", @intCast(transaction_bytes.len));

                    const request: *lib.replay.ExecRequest = exec_request_sender.next() orelse @panic("no space");
                    request.* = .{
                        .task_id = 0,

                        .request_kind = .transaction_execution,
                        .data = .{
                            .transaction_execution = .{
                                .block_idx = .null,
                                .tx_idx = transaction_id,
                            },
                        },
                    };
                    exec_request_sender.markUsed();

                    const polling_zone = tracy.Zone.init(@src(), .{ .name = "polling" });
                    while (exec_response_receiver.peek() == null) {}
                    polling_zone.deinit();

                    const response: *const lib.replay.ExecResponse = exec_response_receiver.next().?;
                    defer exec_response_receiver.markUsed();

                    std.debug.assert(response.task_id == request.task_id);
                    std.debug.assert(response.request_kind == request.request_kind);
                    std.debug.assert(response.data.transaction_execution.success);
                }
            }

            // const entries = try bincode.read(&deserial_fba, &reader, bincode.Vec(Entry));

            // for (entries.items) |entry| {
            //     for (entry.transactions.items) |transaction| {
            //         std.log.info("transaction: ", .{});

            //         switch (transaction.message) {
            //             inline else => |msg| {
            //                 for (msg.account_keys.items) |account_key| {
            //                     std.log.info("account_key: {f}", .{account_key});
            //                 }
            //             },
            //         }
            //     }
            // }
        }

        // std.log.info(
        //     "{}: {f}, last? {}",
        //     .{ deshredded_fec_set.id, result, deshredded_fec_set.slot_complete },
        // );

        // if

        // // if (deshredded_fec_set.id.)

        // if (result == .chain_complete) {
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        //     std.log.info("woo!!!!", .{});
        // }
    }
}

const BlockTree = struct {
    block_pool: *BlockPool,

    /// The latest block that has been rooted by consensus
    /// This node may have parents if other subsystems are still holding references to previous
    /// slots.
    /// For example, accountsdb may want to hold onto data for blocks for a while longer before it
    /// flushes to disk.
    /// Such subsystems may want to hold onto their own root?
    consensus_rooted_block: BlockRef,

    const BlockPool = replay.BlockPool;
    const Node = replay.Node;

    /// NOTE: this is what we use for referencing blocks. This is equivalent to the block's index
    /// our block mem pool. If you want what Agave calls the "Block ID", this is the merkle root of
    ///  the last fec set.
    const BlockRef = replay.BlockRef;
    const NodeTree = Tree(Node, struct {
        pool: *BlockPool,

        const Ctx = @This();

        fn buf(ctx: Ctx) []Node {
            return @ptrCast(ctx.pool.buf()[0..BlockPool.capacity]);
        }

        pub fn parentOf(ctx: Ctx, node: *Node) ?*Node {
            return &ctx.buf()[node.parent.index() orelse return null];
        }
        pub fn childOf(ctx: Ctx, node: *Node) ?*Node {
            return &ctx.buf()[node.child.index() orelse return null];
        }
        pub fn siblingOf(ctx: Ctx, node: *Node) ?*Node {
            return &ctx.buf()[node.sibling.index() orelse return null];
        }

        pub fn setParent(ctx: Ctx, node: *Node, parent: ?*Node) void {
            node.parent = if (parent) |p| ctx.pool.ptrToIndex(p) else .null;
        }
        pub fn setChild(ctx: Ctx, node: *Node, child: ?*Node) void {
            node.child = if (child) |c| ctx.pool.ptrToIndex(c) else .null;
        }
        pub fn setSibling(ctx: Ctx, node: *Node, sibling: ?*Node) void {
            node.sibling = if (sibling) |s| ctx.pool.ptrToIndex(s) else .null;
        }
    });

    // // TODO: large values (e.g. Hashes) should probably live elsewhere in memory to keep tree
    // // traversal fast
    // // This could maybe be 24 bytes (u32 idx * 3, slot u64, last merkle root hash u32)
    // const Node = extern struct {
    //     parent: BlockRef = .null,
    //     child: BlockRef = .null,
    //     sibling: BlockRef = .null,

    //     slot: Slot,

    //     // true when inside last_merkle_map
    //     last_fecset_received: bool,

    //     first_fecset_chained_merkle_root: Hash,

    //     // only valid when last_fecset_received is true
    //     // this is the safe way to identify a block
    //     last_fecset_merkle_root: Hash,
    // };

    // You must get the root slot's last fec set's merkle root as this is used to identify blocks.
    // Currently, this is (very annoyingly) not part of the snapshot. This means we must repair the
    // snapshot slot in order to properly identify it.
    // SIMD-0333 `Serialize Block ID in Bank into Snapshot` fixes this problem.
    fn init(
        block_pool: *BlockPool,
        root_slot: Slot,
        root_slot_last_fec_set_merkle_root: *const Hash,
    ) !BlockTree {
        const root_node = try block_pool.create();

        root_node.* = .{
            .slot = root_slot,
            .last_fecset_received = true,
            .first_fecset_chained_merkle_root = undefined, // we don't need this
            .last_fecset_merkle_root = root_slot_last_fec_set_merkle_root.*,
        };

        return .{
            .block_pool = block_pool,
            .consensus_rooted_block = block_pool.ptrToIndex(root_node),
        };
    }

    fn findUnrootedParent(
        self: *const BlockTree,
        parent_slot: Slot,
        parent_last_fecset_merkle_root: *const Hash,
    ) ?*Node {
        const root_node: *Node = self.block_pool.indexToPtr(self.consensus_rooted_block);

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
            const child_node: *Node = self.block_pool.indexToPtr(node.child);
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
            const sibling_node: *Node = self.block_pool.indexToPtr(node.sibling);
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
    ) !?BlockRef {
        std.debug.assert(new_slot > parent_slot);

        const parent: *Node = self.findUnrootedParent(
            parent_slot,
            first_fecset_chained_merkle_root,
        ) orelse {
            std.log.warn(
                \\ Failed to find parent block {}:{f}, is this block missing?
                \\ NOTE: parent blocks cannot be found unless they have received all their fecsets.
            ,
                .{ parent_slot, first_fecset_chained_merkle_root },
            );
            return null;
        };

        const new_child = try self.block_pool.create();
        errdefer self.block_pool.destroy(new_child);

        new_child.* = .{
            .slot = new_slot,
            .last_fecset_received = false,
            .first_fecset_chained_merkle_root = first_fecset_chained_merkle_root.*,
            .last_fecset_merkle_root = undefined, // only set once the last fecset is received
        };

        NodeTree.linkOrphaned(.{ .pool = self.block_pool }, .tail, parent, new_child);

        return self.block_pool.ptrToIndex(new_child);
    }

    /// Asserts node is already linked to parent
    /// Assumes node is that of a block which has received all fec sets
    fn markBlockFullyReceived(
        self: *const BlockTree,
        block: BlockRef,
        last_fecset_merkle_root: *const Hash,
    ) void {
        const node: *Node = self.block_pool.indexToPtr(block);

        std.debug.assert(node.parent != .null);
        node.last_fecset_received = true;
        node.last_fecset_merkle_root = last_fecset_merkle_root.*;
    }
};

test "Basic blocktree" {
    const root_hash: Hash = .parse("ByzshhkRgXWnTkHjapkkqaKgEFnsg8ceY3bw4MWBzFE");

    var block_pool_buf: [replay.BlockPool.size()]u8 align(@alignOf(replay.BlockPool)) = undefined;
    var block_pool: *replay.BlockPool = @ptrCast(&block_pool_buf);
    block_pool.init();

    var blocks: BlockTree = try .init(block_pool, 0, &root_hash);

    const slot_1_block = (try blocks.tryAllocNewBlockId(0, 1, &root_hash)).?;
    const slot_1_hash: Hash = .parse("2GyMeUytf6fcsfNP2QQ6F5e5qwAUoMtKUbnH6QU6bTNm");
    blocks.markBlockFullyReceived(slot_1_block, &slot_1_hash);

    const slot_2_block = (try blocks.tryAllocNewBlockId(1, 2, &slot_1_hash)).?;
    const slot_2_hash: Hash = .parse("BMHr4knWhDp8JhqCYhA2K5DUYQsYUVXdy2zWahzt5jLd");
    blocks.markBlockFullyReceived(slot_2_block, &slot_2_hash);
}
/// Represents a deshredded FEC set.
///
/// Used as a hashmap value, and a tree node (these are the same memory)
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

    // allocated upon insertion of 1st fec set, copied down through children
    // TODO: allocate additional blockref under equivocation
    // TODO: eviction
    block_ref: lib.replay.BlockRef,

    deserialise_finish_pos: extern struct {
        byte_offset: u16,
        remaining: enum(u8) { all, transactions, entries, none },
        n_remaining: u16,
    } = .{ .byte_offset = 0, .remaining = .all, .n_remaining = 0 },

    payload_len: u16,

    // TODO: this shouldn't be copied, and should instead come in via a pool
    // NOTE: it is an advantage for MerkleNode to be small! (cache locality for map lookup and tree
    // traversal).
    payload_buf: [32 * Shred.data_payload_max]u8,

    fn payload(node: *const MerkleNode) []const u8 {
        return node.payload_buf[0..node.payload_len];
    }

    /// Returns null if we can't yet know
    fn dataStart(node: *MerkleNode, pool: MerkleForest.NodePool) ?bool {
        if (node.id.fec_set_idx == 0) return true;

        const parent: *MerkleNode = MerkleForest.NodeTree.parentOf(.{ .pool = pool }, node) orelse
            return null;

        // the parent's data is completed => the current node's data is starting
        return parent.data_complete;
    }

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
            node.slot_complete,
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

const BlockData = struct {};

const TransactionPool = Pool(EncodedTransaction);

const Pubkey = lib.solana.Pubkey;

const EncodedTransaction = extern struct {
    bincode_data: [1232]u8,
};

const Microblock = struct {
    entries: [128]Entry,
    entries_len: u8,
};

// TODO: handle eviction
/// A tree of FEC sets, which are also keyed by their merkle (and chained) merkle roots.
const MerkleForest = struct {
    // owns all of the memory of nodes used in the map/tree nodes
    pool: NodePool,

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

    const NodeTree = Tree(MerkleNode, struct {
        pool: NodePool,

        const Ctx = @This();

        fn buf(ctx: Ctx) []MerkleNode {
            return @ptrCast(ctx.pool.buf[0..ctx.pool.len]);
        }

        pub fn parentOf(ctx: Ctx, node: *MerkleNode) ?*MerkleNode {
            return &ctx.buf()[node.parent.index() orelse return null];
        }
        pub fn childOf(ctx: Ctx, node: *MerkleNode) ?*MerkleNode {
            return &ctx.buf()[node.child.index() orelse return null];
        }
        pub fn siblingOf(ctx: Ctx, node: *MerkleNode) ?*MerkleNode {
            return &ctx.buf()[node.sibling.index() orelse return null];
        }

        pub fn setParent(ctx: Ctx, node: *MerkleNode, parent: ?*MerkleNode) void {
            node.parent = if (parent) |p| ctx.pool.ptrToIndex(p) else .null;
        }
        pub fn setChild(ctx: Ctx, node: *MerkleNode, child: ?*MerkleNode) void {
            node.child = if (child) |c| ctx.pool.ptrToIndex(c) else .null;
        }
        pub fn setSibling(ctx: Ctx, node: *MerkleNode, sibling: ?*MerkleNode) void {
            node.sibling = if (sibling) |s| ctx.pool.ptrToIndex(s) else .null;
        }
    });

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
            .map = map,
            .orphan_map = orphan_map,
        };
    }

    fn deinit(self: *MerkleForest, allocator: std.mem.Allocator) void {
        allocator.free(self.pool.buf[0..self.pool.len]);
        self.map.deinit(allocator);
        self.orphan_map.deinit(allocator);
    }

    // TODO: eviction
    // TODO: remove orphans from orphan_map once parented
    /// Returns the newly inserted node, null => node already known (this is not an error).
    fn put(
        self: *MerkleForest,
        block_pool: *replay.BlockPool,
        new_fec_set: *const lib.shred.DeshreddedFecSet,
    ) !?*MerkleNode {
        const zone = tracy.Zone.init(@src(), .{ .name = "MerkleForest.put" });
        defer zone.deinit();

        const map_ctx: MerkleContext = .{ .map = &self.map };
        const orphan_map_ctx: OrphanContext = .{ .map = &self.orphan_map };

        self.assertCounts();
        defer self.assertCounts();

        const map_result = self.map.getOrPutAssumeCapacityAdapted(&new_fec_set.merkle_root, map_ctx);
        if (map_result.found_existing) return null; // node already known

        const new_node = try self.pool.create();
        map_result.value_ptr.* = new_node;

        new_node.* = .{
            .merkle_root = new_fec_set.merkle_root,
            .chained_merkle_root = new_fec_set.chained_merkle_root,
            .id = new_fec_set.id,
            .data_complete = new_fec_set.data_complete,
            .slot_complete = new_fec_set.slot_complete,

            .block_ref = if (new_fec_set.id.fec_set_idx == 0) try block_pool.createId() else .null,

            .payload_len = new_fec_set.payload_len,
            .payload_buf = new_fec_set.payload_buf,
        };

        var must_wait_for_parent: bool = false;

        // TODO: stop checking cross-slot?
        if (self.map.getAdapted(&new_fec_set.chained_merkle_root, map_ctx)) |parent| {
            // we found the parent of our new node

            var did_insert_equivocated: bool = false;

            if (parent.child == .null) {
                @branchHint(.likely);
                new_node.block_ref = parent.block_ref;
            } else {
                // This node's parent already has a child. This means the leader produced multiple
                // conflicting fec sets.
                // TODO: report this and special case the handling in the caller
                std.log.warn("Equivocation detected! Fec set {f} has multiple children\n", .{@as(*const MerkleNode, parent)});
                new_node.block_ref = try block_pool.createId();
                std.debug.assert(new_node.block_ref != .null);
                std.debug.assert(new_node.block_ref != parent.block_ref);
                did_insert_equivocated = true;
            }

            NodeTree.linkOrphaned(.{ .pool = self.pool }, .tail, parent, new_node);

            if (did_insert_equivocated) {
                // If we insert equivocated, we should allocate a new blockref. In the case of
                // equivocation we will "choose" the one that came first by convention - the chosen
                // fec set will be at the head of the sibling list, i.e. the direct child of the
                // parent.
                std.debug.assert(self.pool.indexToPtr(parent.child).block_ref != new_node.block_ref);
            }

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

            if (orphan_map_result.found_existing) {
                std.log.warn(
                    "Equivocation detected! Orphaned Nodes {f} and {f} want the same parent {f}",
                    .{ orphan_map_result.value_ptr.*, new_node, &new_fec_set.chained_merkle_root },
                );
                NodeTree.linkNewOrphanedSibling(.{ .pool = self.pool }, orphan_map_result.value_ptr.*, new_node);

                // Block IDs are allocated by the 0th fec set, and propogated to their children.
                // Orphans don't have parents, and aren't the 0th fec set.
                std.debug.assert(orphan_map_result.value_ptr.*.block_ref == .null);
                std.debug.assert(new_node.block_ref == .null);
            } else {
                orphan_map_result.value_ptr.* = new_node;
            }

            must_wait_for_parent = true;
        }

        var must_wait_for_child: bool = false;

        if (self.orphan_map.getAdapted(&new_fec_set.merkle_root, orphan_map_ctx)) |child| {
            NodeTree.linkOrphaned(.{ .pool = self.pool }, .tail, new_node, child);

            // propogate our block_ref to the children
            if (new_node.block_ref != .null) {
                var child_node: ?*MerkleNode = child;

                while (child_node) |c_n| : (child_node = NodeTree.childOf(.{ .pool = self.pool }, c_n)) {
                    c_n.block_ref = new_node.block_ref;
                }
            }
        } else if (!new_fec_set.slot_complete) {
            // We don't have this fec set's child yet, and it should have one
            //
            // There is nothing to do here, the child can find its parent through the child's
            // chained merkle root in self.map.

            must_wait_for_child = true;
        }

        // if (!must_wait_for_child and !must_wait_for_parent) {
        //     // This slot might be finished? Let's traverse our node's parents and children to find
        //     // out.
        //     const start_finished: bool = node.id.fec_set_idx == 0 or found_idx_0: {
        //         var maybe_backwards_idx: ?u32 = node.parent.index();

        //         break :found_idx_0 while (maybe_backwards_idx) |backwards_idx| {
        //             const parent_node: *const MerkleNode = @ptrCast(&self.pool.buf[backwards_idx]);

        //             if (parent_node.id.fec_set_idx == 0) break true;

        //             maybe_backwards_idx = parent_node.parent.index();
        //         } else false;
        //     };

        //     const end_finished: bool = node.slot_complete or found_slot_complete: {
        //         var maybe_forwards_idx: ?u32 = node.child.index();

        //         break :found_slot_complete while (maybe_forwards_idx) |forwards_idx| {
        //             const child_node: *const MerkleNode = @ptrCast(&self.pool.buf[forwards_idx]);

        //             if (child_node.slot_complete) break true;

        //             maybe_forwards_idx = child_node.child.index();
        //         } else false;
        //     };

        //     return if (start_finished and end_finished) .chain_complete else .chain_incomplete;
        // }

        return new_node;

        // if (must_wait_for_child and must_wait_for_parent) return .waiting_for_parent_and_child;
        // if (must_wait_for_child) return .waiting_for_child;
        // if (must_wait_for_parent) return .waiting_for_parent;
        // unreachable;
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

    _ = .{ a, b, c };
    // try std.testing.expectEqual(.waiting_for_child, try tree.put(&a));
    // try std.testing.expectEqual(.waiting_for_child, try tree.put(&b));
    // try std.testing.expectEqual(.chain_complete, try tree.put(&c));
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

    _ = .{ a_result, c_result, b_result, d_result };
    // try std.testing.expectEqual(.waiting_for_child, a_result);
    // try std.testing.expectEqual(.waiting_for_parent_and_child, c_result);
    // try std.testing.expectEqual(.chain_incomplete, b_result);
    // try std.testing.expectEqual(.chain_complete, d_result);
}
