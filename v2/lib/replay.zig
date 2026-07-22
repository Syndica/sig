const std = @import("std");
const tracy = @import("tracy");
const solana = @import("solana.zig");
const collections = @import("collections.zig");
const ipc = @import("ipc.zig");
const util = @import("util.zig");
const accounts_db = @import("accounts_db.zig");
const shred = @import("shred.zig");
const telemetry = @import("telemetry.zig");

const Hash = solana.Hash;
const Slot = solana.Slot;
const Shred = shred.Shred;
const FecSetId = shred.FecSetId;
const Pool = collections.Pool;

// This is a bit large currently because of the unrooted store
pub const scratch_buffer_size = 3 * 1024 * 1024 * 1024;

pub const TransactionPool = collections.SharedPool([1232]u8, 10_000);

pub const BlockPool = collections.SharedPool(Node, 1024);

/// NOTE: this is what we use for referencing blocks. This is equivalent to the block's index
/// our block mem pool. If you want what Agave calls the "Block ID", this is the merkle root of
/// the last fec set.
pub const BlockRef = BlockPool.ItemId;

// TODO: large values (e.g. Hashes) should probably live elsewhere in memory to keep tree
// traversal fast
// This could maybe be 24 bytes (u32 idx * 3, slot u64, last merkle root hash u32)
pub const Node = extern struct {
    parent: BlockRef.Optional = .null,
    child: BlockRef.Optional = .null,
    sibling: BlockRef.Optional = .null,
    /// this is null for blocks older than the bootstrap root. do not unwrap
    /// unless you are certain the block is not older than the bootstrap root
    slot: util.PackedOptional(solana.Slot, std.math.maxInt(solana.Slot)),
};

pub const ExecReqResponse = extern struct {
    // submission queue
    request_ring: RequestRing,

    // completion queue
    response_ring: ResponseRing,

    pub const RequestRing = ipc.Ring(256, ExecRequest);
    pub const ResponseRing = ipc.Ring(256, ExecResponse);

    pub fn init(self: *ExecReqResponse) void {
        self.request_ring.init();
        self.response_ring.init();
    }
};

pub const RequestKind = enum(u8) {
    txn_exec,
    txn_sig_verify,
};

pub const ExecRequest = extern struct {
    task_id: u64, // user-provided, arbitrary, for the caller's tracking

    request_kind: RequestKind,
    data: extern union {
        txn_exec: extern struct {
            block_idx: BlockRef,
            tx_idx: TransactionPool.ItemId,
            n_account_refs: u8,
            account_ref_buf: [128]accounts_db.AccountPool.AccountRef,
        },
        txn_sig_verify: extern struct {
            tx_idx: TransactionPool.ItemId,
        },
    },
};

pub const ExecResponse = extern struct {
    task_id: u64, // user-provided, arbitrary, for the caller's tracking

    request_kind: RequestKind,
    data: extern union {
        txn_exec: extern struct {
            block_idx: BlockRef,
            tx_idx: TransactionPool.ItemId,
            n_account_refs: u8,
            account_ref_buf: [128]accounts_db.AccountPool.AccountRef,
            result: TxExecResult,
        },
        txn_sig_verify: extern struct { success: bool },
    },
};

pub const TxExecResult = extern struct {
    success: bool,
};

/// Represents a deshredded FEC set.
///
/// Used as a hashmap value, and a tree node (these are the same memory)
/// This node is also used for the keys of hashmaps. When doing so, be careful of which adapted
/// context you use.
///
/// NOTE: When used inside the Pool, these may be items in a free list. However such nodes should
/// not be in either map or the tree.
pub const MerkleNode = extern struct {
    parent: MerkleForest.NodePool.ItemId.Optional = .null,
    child: MerkleForest.NodePool.ItemId.Optional = .null,
    sibling: MerkleForest.NodePool.ItemId.Optional = .null,

    merkle_root: Hash,
    chained_merkle_root: Hash,
    id: FecSetId,
    data_complete: bool,
    slot_complete: bool,

    // allocated upon insertion of 1st fec set, copied down through children
    // TODO: eviction
    block_ref: BlockRef.Optional,

    payload_len: u16,

    // TODO: pool the payload buffer out-of-line; MerkleNode-in-map benefits
    // from cache locality.
    payload_buf: [32 * Shred.data_payload_max]u8,

    pub fn payload(node: *const MerkleNode) []const u8 {
        return node.payload_buf[0..node.payload_len];
    }

    pub fn format(node: *const MerkleNode, writer: *std.io.Writer) !void {
        try writer.print(
            \\ {{
            \\     id: {}, slot_complete: {}
            \\     parent: {}, child: {}, sibling: {}
            \\     root: {f}, chained_root: {f}
            \\     data_complete: {}, slot_complete: {}
            \\     block_ref: {}
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
            node.block_ref,
        });
    }
};

// TODO: handle eviction
/// A tree of FEC sets, which are also keyed by their merkle (and chained) merkle roots.
pub const MerkleForest = struct {
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

    pub const capacity = 4096;

    // keyed by merkle root
    pub const OrphanMap = std.ArrayHashMapUnmanaged(void, *MerkleNode, OrphanContext, true);

    // keyed by chained merkle root
    pub const MerkleMap = std.ArrayHashMapUnmanaged(void, *MerkleNode, MerkleContext, true);

    pub const NodePool = Pool(MerkleNode, u32);

    pub const MerkleContext = struct {
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

    pub const OrphanContext = struct {
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

    pub fn init(allocator: std.mem.Allocator) !MerkleForest {
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

    pub fn deinit(self: *MerkleForest, allocator: std.mem.Allocator) void {
        allocator.free(self.pool.buf[0..self.pool.len]);
        self.map.deinit(allocator);
        self.orphan_map.deinit(allocator);
    }

    pub fn reset(self: *MerkleForest) void {
        self.pool.reset();
        self.map.clearRetainingCapacity();
        self.orphan_map.clearRetainingCapacity();
    }

    fn assertCounts(self: *const MerkleForest) void {
        std.debug.assert(self.orphan_map.count() <= self.map.count());
        tracy.plot(u32, "Merkle forest fec sets", @intCast(self.map.count()));
        tracy.plot(u32, "Merkle forest fec sets (orphaned)", @intCast(self.orphan_map.count()));
    }
};

/// Finds a node's parent, and attaches the new node to it.
///
/// In the case of a missing parent, also adds the current node (keyed by the parent's merkle root)
/// into the orphan map.
///
/// NOTE: when removing nodes from the orphan map, make sure to handle all sibling nodes.
fn attachParent(
    logger: telemetry.Logger("main"),
    node: *MerkleNode,
    forest: *MerkleForest,
) ?*MerkleNode {
    const zone = tracy.Zone.init(@src(), .{ .name = "attachParent" });
    defer zone.deinit();

    std.debug.assert(node.parent == .null);
    const map_ctx: MerkleForest.MerkleContext = .{ .map = &forest.map };
    const orphan_map_ctx: MerkleForest.OrphanContext = .{ .map = &forest.orphan_map };

    const parent = forest.map.getAdapted(&node.chained_merkle_root, map_ctx) orelse {
        zone.text("parent not found");

        // No parent found, insert current node into orphan map (keyed by its parent's merkle-root)
        // NOTE: it's probably a good idea to preemptively send repair requests for the parent here.

        const orphan_map_result = forest.orphan_map.getOrPutAssumeCapacityAdapted(
            &node.chained_merkle_root,
            orphan_map_ctx,
        );

        logger.info().logf(
            "inserting ({}:{}) into orphans, already other orphans with same parent?: {}",
            .{ node.id.slot, node.id.fec_set_idx, orphan_map_result.found_existing },
        );

        if (orphan_map_result.found_existing) {
            @branchHint(.unlikely);
            // this could happen under equivocation or forking, should be unlikely to hit this.
            // i.e. there's multiple fec sets currently missing the same parent

            // NOTE: the code that finds this orphan entry later *must* attach all of the orphan's
            // siblings

            // insert at tail of the existing node's siblings
            var orphan_sibling_tail: ?*MerkleNode = orphan_map_result.value_ptr.*;
            while (orphan_sibling_tail) |tail_node| {
                const next_sibling = (tail_node.sibling.opt() orelse break).ptr(&forest.pool);
                // Adjacent orphans may share a FecSetId under leader
                // equivocation; they'll have distinct merkle_roots and thus
                // distinct entries in `forest.map`.
                orphan_sibling_tail = next_sibling;
            }
            std.debug.assert(orphan_sibling_tail.?.sibling == .null);
            orphan_sibling_tail.?.sibling = .init(forest.pool.ptrToIndex(node));
        } else {
            orphan_map_result.value_ptr.* = node; // TODO: double check this
        }

        return null; // no parent found
    };

    if (!parent.id.mayFollowWith(&node.id)) {
        @branchHint(.cold); // this would be malicious behaviour, chaining in an invalid order
        zone.text("mayFollowWith check failed");

        return null; // parent found, but fec set ids don't align
    }

    // insert node into tree of parent
    {
        std.debug.assert(node.parent == .null);
        node.parent = .init(forest.pool.ptrToIndex(parent));

        if (parent.child == .null) {
            @branchHint(.likely); // no equivocation or forking

            parent.child = .init(forest.pool.ptrToIndex(node));
            return parent;
        }

        std.debug.assert(parent.child != .null);
        var last_child_of_parent: *MerkleNode = parent.child.opt().?.ptr(&forest.pool);
        while (true) {
            // Children may share a FecSetId under leader equivocation;
            // distinct merkle_roots keep them as distinct forest entries.
            const next = (last_child_of_parent.sibling.opt() orelse break).ptr(&forest.pool);
            last_child_of_parent = next;
        }

        last_child_of_parent.sibling = .init(forest.pool.ptrToIndex(node));
        return parent;
    }
}

fn attachChildren(node: *MerkleNode, forest: *MerkleForest) void {
    std.debug.assert(node.child == .null);

    const zone = tracy.Zone.init(@src(), .{ .name = "attachChildren" });
    defer zone.deinit();

    const orphan_map_ctx: MerkleForest.OrphanContext = .{ .map = &forest.orphan_map };
    const map_ctx: MerkleForest.MerkleContext = .{ .map = &forest.map };

    var children_head: ?*MerkleNode = forest.orphan_map.getAdapted(
        &node.merkle_root,
        orphan_map_ctx,
    ) orelse return;

    // Iterate over all child nodes, setting their parent node, and deleting any bad child nodes
    {
        var maybe_child_node: ?*MerkleNode = children_head;
        while (maybe_child_node) |child_node| {
            std.debug.assert(child_node.parent == .null);
            maybe_child_node = if (child_node.sibling.opt()) |s| s.ptr(&forest.pool) else null;

            if (node.id.mayFollowWith(&child_node.id)) {
                @branchHint(.likely);
                child_node.parent = .init(forest.pool.ptrToIndex(node));

                continue;
            }

            // Invalid child chaining implies leader malice; unlink the
            // orphan sibling and drop it.
            const next_node = if (child_node.sibling.opt()) |s| s.ptr(&forest.pool) else null;
            const prev_node: ?*MerkleNode = node: {
                if (child_node == children_head) break :node null;

                var prev_node: ?*MerkleNode = children_head;
                break :node while (prev_node) |n| {
                    const next = if (n.sibling.opt()) |s| s.ptr(&forest.pool) else null;
                    if (next == child_node) break n;
                    prev_node = next.?;
                } else unreachable; // either we're the head node, or we have a prev
            };

            if (prev_node) |prev| {
                prev.sibling = if (next_node) |next|
                    .init(forest.pool.ptrToIndex(next))
                else
                    .null;
            } else {
                // head of list is invalid, let's move it forward
                children_head = next_node;
            }

            if (child_node.child != .null)
                // Remove the node from the map + delete it
                // if this orphan has invalid chaining, this means *all* of its children are also invalid
                @panic("TODO: handle recursive removal from invalid orphan chaining");
            const removed = forest.map.swapRemoveAdapted(&child_node.merkle_root, map_ctx);
            std.debug.assert(removed);
            forest.pool.destroy(child_node);
        }
    }

    if (children_head) |c_h| node.child = .init(forest.pool.ptrToIndex(c_h));

    // NOTE: this 2nd map lookup could be removed (we looked up this entry earlier)
    const removed = forest.orphan_map.swapRemoveAdapted(&node.merkle_root, orphan_map_ctx);
    std.debug.assert(removed);
}

// Either:
//  a) does nothing (parent has no BlockRef)
//  b) allocates a new BlockRef due to reaching the slot boundary
//  c) allocates a new BlockRef due to the parent already having a child (forking/equivocation)
//  d) carries the parent's BlockRef forward (same slot + no forking/equivocation)
fn setChildBlockRef(
    parent: *const MerkleNode,
    child: *MerkleNode,
    forest_pool: *MerkleForest.NodePool,
    block_pool: *BlockPool,
) !void {
    std.debug.assert(child.block_ref == .null);
    const parent_block_ref = parent.block_ref.opt() orelse return; // a)

    // optionally allocate a new BlockRef
    child.block_ref = if (parent.id.slot != child.id.slot) ref: {
        // new slot, let's create a new BlockRef
        const new_block = try block_pool.create();
        new_block.* = .{
            .parent = .init(parent_block_ref),
            .slot = .init(child.id.slot),
        };

        break :ref .init(block_pool.ptrToIndex(new_block)); // b)
    } else ref: {
        // treat the first child as the canonical path
        if (parent.child.opt()) |child_id| if (child_id == forest_pool.ptrToIndex(child)) {
            break :ref .init(parent_block_ref); // d)
        };

        // forking/equivocation
        const new_block = try block_pool.create();
        new_block.* = .{
            .parent = .init(parent_block_ref),
            .slot = .init(child.id.slot),
        };

        break :ref .init(block_pool.ptrToIndex(new_block)); // c)

    };
}

fn setChildTreeBlockRefs(
    parent: *MerkleNode,
    child: *MerkleNode,
    forest_pool: *MerkleForest.NodePool,
    block_pool: *BlockPool,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "setChildTreeBlockRefs" });
    defer zone.deinit();

    // If we have a BlockRef we must have a parent (except in the case of an evicted parent, which
    // doesn't apply here)
    std.debug.assert(child.parent != .null);

    try setChildBlockRef(parent, child, forest_pool, block_pool);

    // recursively apply BlockRefs to reachable merkle nodes
    // NOTE: it is possible to do this without recursion *or* a stack, as a non-null block_ref can
    //       be used to mark a node as visited.
    var maybe_child = if (child.child.opt()) |id| id.ptr(forest_pool) else null;
    while (maybe_child) |child_node| {
        try setChildTreeBlockRefs(child, child_node, forest_pool, block_pool);
        maybe_child = if (child_node.sibling.opt()) |id| id.ptr(forest_pool) else null;
    }
}

pub fn insertFecSet(
    logger: telemetry.Logger("main"),
    // to be transformed and inserted into the forest
    deshredded_node: *const shred.DeshreddedFecSet,
    forest: *MerkleForest,
    // block associated parameters
    // additional blocks may be allocated when inserting a fec set
    block_pool: *BlockPool,
) error{OutOfSpace}!?*MerkleNode {
    const zone = tracy.Zone.init(@src(), .{ .name = "insertFecSet" });
    defer zone.deinit();

    forest.assertCounts();
    defer forest.assertCounts();

    const map_ctx: MerkleForest.MerkleContext = .{ .map = &forest.map };

    const node: *MerkleNode = newly_inserted: {
        const map_result = forest.map.getOrPutAssumeCapacityAdapted(
            &deshredded_node.merkle_root,
            map_ctx,
        );
        if (map_result.found_existing) return null; // node already known

        const node = try forest.pool.create();
        map_result.value_ptr.* = node;

        node.* = .{
            .merkle_root = deshredded_node.merkle_root,
            .chained_merkle_root = deshredded_node.chained_merkle_root,
            .id = deshredded_node.id,
            .data_complete = deshredded_node.data_complete,
            .slot_complete = deshredded_node.slot_complete,

            .block_ref = .null,

            .payload_len = deshredded_node.payload_len,
            .payload_buf = deshredded_node.payload_buf,
        };

        break :newly_inserted node;
    };

    const maybe_parent = attachParent(logger, node, forest);
    attachChildren(node, forest);

    // "propagate" BlockRefs (see `setChildBlockRef` for details)
    if (maybe_parent) |parent| {
        try setChildTreeBlockRefs(parent, node, &forest.pool, block_pool);
    }

    return node;
}

test "MerkleForest tree put" {
    var tree: MerkleForest = try .init(std.testing.allocator);
    defer tree.deinit(std.testing.allocator);

    const a_hash: Hash = .parse("ByzshhkRgXWnTkHjapkkqaKgEFnsg8ceY3bw4MWBzFE");
    const b_hash: Hash = .parse("BMHr4knWhDp8JhqCYhA2K5DUYQsYUVXdy2zWahzt5jLd");
    const c_hash: Hash = .parse("2GyMeUytf6fcsfNP2QQ6F5e5qwAUoMtKUbnH6QU6bTNm");
    const d_hash: Hash = .parse("4UahX8LzYC7xnubvP9QzRHmPPYovtcNYo7rBXKpp3ADM");
    const e_hash: Hash = .parse("An7mDXKMpRninZw6rvqc4wnQ6ukqd3ARko6QmPitjx8B");

    const a: shred.DeshreddedFecSet = .{
        .chained_merkle_root = .parse("DWCWjQciWoWDzJKwqUZ1ntKqTyXtLVt4C8aL7biBJZ4z"), // prev slot
        .merkle_root = a_hash,

        .id = .{ .slot = 409284941, .fec_set_idx = 0 },

        .data_complete = true,
        .slot_complete = false,

        .payload_len = 0,
        .payload_buf = undefined,
    };

    const b: shred.DeshreddedFecSet = .{
        .chained_merkle_root = a_hash,
        .merkle_root = b_hash,

        .id = .{ .slot = 409284941, .fec_set_idx = 32 },

        .data_complete = true,
        .slot_complete = false,

        .payload_len = 0,
        .payload_buf = undefined,
    };

    const c: shred.DeshreddedFecSet = .{
        .chained_merkle_root = b_hash,
        .merkle_root = c_hash,

        .id = .{ .slot = 409284941, .fec_set_idx = 64 },

        .data_complete = true,
        .slot_complete = false,

        .payload_len = 0,
        .payload_buf = undefined,
    };

    const d: shred.DeshreddedFecSet = .{
        .chained_merkle_root = c_hash,
        .merkle_root = d_hash,

        .id = .{ .slot = 409284941, .fec_set_idx = 96 },

        .data_complete = true,
        .slot_complete = true,

        .payload_len = 0,
        .payload_buf = undefined,
    };

    // new slot
    const e: shred.DeshreddedFecSet = .{
        .chained_merkle_root = d_hash,
        .merkle_root = e_hash,

        .id = .{ .slot = 409284942, .fec_set_idx = 0 },

        .data_complete = true,
        .slot_complete = true,

        .payload_len = 0,
        .payload_buf = undefined,
    };

    var pool_buf: [BlockPool.size()]u8 align(@alignOf(BlockPool)) = undefined;
    const pool: *BlockPool = @ptrCast(&pool_buf);
    pool.init();

    const logger = telemetry.Logger("main").noop;

    const a_inserted = (try insertFecSet(logger, &a, &tree, pool)).?;
    try std.testing.expect(a_inserted.parent == .null);
    try std.testing.expect(a_inserted.child == .null);
    try std.testing.expect(a_inserted.block_ref == .null);
    // give the ancestor block a BlockRef, so that it may propagate
    // NOTE: it is expected that the root-most fec set to be inserted first this way as a special
    //       case. In a real environment this would be the last fec set in the rooted slot.
    a_inserted.block_ref = .init(BlockRef.fromInt(8053));

    const expected_block_ref: BlockRef.Optional = .init(BlockRef.fromInt(8053));

    const d_inserted = (try insertFecSet(logger, &d, &tree, pool)).?;
    try std.testing.expect(d_inserted.parent == .null);
    try std.testing.expect(d_inserted.child == .null);
    try std.testing.expect(d_inserted.block_ref == .null); // no path to a => null

    const b_inserted = (try insertFecSet(logger, &b, &tree, pool)).?;
    try std.testing.expect(b_inserted.parent != .null);
    try std.testing.expect(b_inserted.child == .null);
    try std.testing.expect(b_inserted.block_ref == expected_block_ref);

    const c_inserted = (try insertFecSet(logger, &c, &tree, pool)).?;
    try std.testing.expect(c_inserted.parent != .null);
    try std.testing.expect(c_inserted.child != .null);
    try std.testing.expect(c_inserted.block_ref == expected_block_ref);
    try std.testing.expect(d_inserted.block_ref == expected_block_ref);

    const e_inserted = (try insertFecSet(logger, &e, &tree, pool)).?;
    try std.testing.expect(e_inserted.parent != .null);
    try std.testing.expect(e_inserted.child == .null);
    // new slot => new BlockRef
    try std.testing.expect(e_inserted.block_ref != .null);
    try std.testing.expect(e_inserted.block_ref != expected_block_ref);

    // We cannot insert duplicates
    try std.testing.expectEqual(null, try insertFecSet(logger, &a, &tree, pool));
    try std.testing.expectEqual(null, try insertFecSet(logger, &b, &tree, pool));
    try std.testing.expectEqual(null, try insertFecSet(logger, &c, &tree, pool));
    try std.testing.expectEqual(null, try insertFecSet(logger, &d, &tree, pool));
    try std.testing.expectEqual(null, try insertFecSet(logger, &e, &tree, pool));
}
