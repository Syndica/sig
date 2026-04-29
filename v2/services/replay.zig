const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tracy = @import("tracy");

const replay = lib.replay;

const bincode_2 = lib.solana.bincode_2;

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

const DeserialStates = [lib.replay.BlockPool.capacity]?BlockDeserialState;
const BlockExecStates = [lib.replay.BlockPool.capacity]BlockExecState;

pub fn serviceMain(_: ReadOnly, rw: ReadWrite) !noreturn {
    var fba: std.heap.FixedBufferAllocator = .init(&scratch_memory);
    const allocator = fba.allocator();

    var map_tree: MerkleForest = try .init(allocator);

    const deserial_states: *DeserialStates = try allocator.create(DeserialStates);
    @memset(deserial_states, null);

    const exec_states: *BlockExecStates = try allocator.create(BlockExecStates);
    @memset(exec_states, .default);

    // TODO: remove this, it's just a copy for nothing
    var deserialised_buf: [128 * 1024]u8 = undefined;
    var deserial_fba: std.heap.FixedBufferAllocator = .init(&deserialised_buf);

    var deshredded_iter = rw.deshredded_in.get(.reader);
    var exec_request_sender = rw.exec_req_response.request_ring.get(.writer);
    var exec_response_receiver = rw.exec_req_response.response_ring.get(.reader);

    task: switch (@as(enum { exec_response, fec_set, idle }, .idle)) {
        .idle => {
            if (exec_response_receiver.peek() != null) continue :task .exec_response;
            if (deshredded_iter.peek() != null) continue :task .fec_set;

            const zone = tracy.Zone.init(@src(), .{ .name = "idle" });
            defer zone.deinit();

            while (true) {
                if (exec_response_receiver.peek() != null) continue :task .exec_response;
                if (deshredded_iter.peek() != null) continue :task .fec_set;
            }
        },
        .exec_response => {
            const zone = tracy.Zone.init(@src(), .{ .name = "exec_response" });
            defer zone.deinit();

            const response: *const lib.replay.ExecResponse = exec_response_receiver.next() orelse unreachable;
            defer exec_response_receiver.markUsed();

            zone.value(response.task_id);

            std.debug.assert(response.request_kind == .transaction_execution); // others unimplemented
            const response_data = response.data.transaction_execution;

            defer rw.replay_transaction_pool.destroyId(response_data.tx_idx);

            const block_ref = response_data.block_idx;
            const exec_state: *BlockExecState = &exec_states[block_ref.index().?];

            // We previously used the transaction number within the block as our "task_id".
            // Asserting that we're receiving them back in order (we have single threaded exec).
            std.debug.assert(response.task_id == exec_state.n_transactions_completed);

            exec_state.n_transactions_completed += 1;

            if (exec_state.all_transactions_requested and
                exec_state.n_transactions_completed == exec_state.n_transactions_requested)
            {
                std.log.info(
                    "Slot {} ({}) complete! ({}/{})",
                    .{
                        rw.block_pool.indexToPtr(block_ref).slot,
                        block_ref,
                        exec_state.n_transactions_requested,
                        exec_state.n_transactions_completed,
                    },
                );
            }

            continue :task .idle;
        },
        .fec_set => {
            const zone = tracy.Zone.init(@src(), .{ .name = "received fec set" });
            defer zone.deinit();

            const deshredded_fec_set: *const lib.shred.DeshreddedFecSet =
                deshredded_iter.next() orelse unreachable;
            defer deshredded_iter.markUsed();

            const inserted_node = try map_tree.put(rw.block_pool, deshredded_fec_set) orelse
                continue :task .idle; // null => node already known, nothing to do here

            if (inserted_node.block_ref == .null) {
                const null_zone = tracy.Zone.init(@src(), .{ .name = "received fec set (block_id=null)" });
                defer null_zone.deinit();
                // blockrefs are assigned from the 0th fecset, and carried forward. If the newly
                // inserted node isn't attached to a 0th fecset, we won't be able to execute it until it
                // is.

                // NOTE: we *could* do some PoH and sig verify tasks early here, but it seems like there
                // isn't actually an advantage, as a validator executing transactions will have plenty
                // of "gaps" in exec thread pool usage, and these tasks only have to be finished before
                // we finish the block as a whole.

                // TODO: with that being said, we could probably benefit from prefetching accounts here.
                continue :task .idle;
            }

            // assert that we've got a chain of fec sets back to the 0th fec set
            const fec_0: *const MerkleNode = node: {
                var maybe_node: ?*MerkleNode = inserted_node;
                while (maybe_node) |node| : (maybe_node = map_tree.pool.indexToOptPtr(node.parent)) {
                    std.debug.assert(node.parent != .null or node.id.fec_set_idx == 0);
                    if (node.id.fec_set_idx == 0) break :node node;
                }
                unreachable;
            };

            const block_deserial_state: *BlockDeserialState = blk: {
                const state: *?BlockDeserialState = &deserial_states[inserted_node.block_ref.index().?];
                if (state.* == null) state.* = .init(fec_0);
                break :blk &state.*.?;
            };

            zone.value(inserted_node.block_ref.index().?);
            zone.value(rw.block_pool.indexToConstPtr(inserted_node.block_ref).slot);

            // Read transactions until we can't anymore, sending to exec as we go
            while (true) {
                defer deserial_fba.reset();

                const tx_ref = try rw.replay_transaction_pool.createId();
                // TODO: this is a major leak risk, should use comptime errdefer unreachable

                const tx_buf: *[1232]u8 = rw.replay_transaction_pool.indexToPtr(tx_ref);

                const tx = try block_deserial_state.nextTransaction(&deserial_fba, &map_tree.pool, tx_buf) orelse break;
                tracy.plot(u16, "transaction size", @intCast(tx.len));

                const exec_state: *BlockExecState = &exec_states[inserted_node.block_ref.index().?];

                // index within the block
                const tx_index: u32 = exec_state.n_transactions_requested;
                exec_state.n_transactions_requested += 1;

                zone.value(tx_index);

                // send task to exec
                {
                    const request: *lib.replay.ExecRequest = exec_request_sender.next() orelse @panic("no space");
                    defer exec_request_sender.markUsed();
                    request.* = .{
                        .task_id = tx_index,
                        .request_kind = .transaction_execution,
                        .data = .{
                            .transaction_execution = .{
                                .block_idx = inserted_node.block_ref,
                                .tx_idx = tx_ref,
                            },
                        },
                    };
                }
            }
            if (inserted_node.slot_complete) {
                const exec_state: *BlockExecState = &exec_states[inserted_node.block_ref.index().?];
                exec_state.all_transactions_requested = true;
            }

            continue :task .idle;
        },
    }
}

const BlockDeserialState = struct {
    pos_node: *const MerkleNode,
    pos_offset: usize,

    n_transactions_left: ?u64,
    n_entries_left: ?u64,

    next_read: NextRead,

    const NextRead = enum { n_entries, num_hashes, hash, n_transactions, transaction };

    const Reader = struct {
        deserial_state: *BlockDeserialState,
        merkle_pool: *const MerkleForest.NodePool,
        interface: std.Io.Reader,

        fn advance(self: *Reader) error{EndOfStream}!void {
            const child: *const MerkleNode = MerkleForest.NodeTree.childOf(
                .{ .pool = self.merkle_pool.* },
                self.deserial_state.pos_node,
            ) orelse return error.EndOfStream;

            std.debug.assert(child.block_ref != .null);
            std.debug.assert(child.parent != .null);

            self.deserial_state.pos_node = child;
            self.deserial_state.pos_offset = 0;
        }

        fn maybeAdvance(self: *Reader) error{EndOfStream}!void {
            if (self.deserial_state.pos_offset < self.deserial_state.pos_node.payload_len) return;
            std.debug.assert(self.deserial_state.pos_offset == self.deserial_state.pos_node.payload_len);

            try self.advance();
        }

        fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) !usize {
            const self: *Reader = @alignCast(@fieldParentPtr("interface", r));
            try self.maybeAdvance();

            const read_slice = limit.sliceConst(self.deserial_state.pos_node.payload()[self.deserial_state.pos_offset..]);
            try w.writeAll(read_slice);
            self.deserial_state.pos_offset += read_slice.len;
            return read_slice.len;
        }

        fn rebase(r: *std.Io.Reader, capacity: usize) !void {
            _ = .{ r, capacity };
            @panic("rebase is illegal");
        }

        fn readVec(r: *std.Io.Reader, data: [][]u8) !usize {
            const self: *Reader = @alignCast(@fieldParentPtr("interface", r));
            try self.maybeAdvance();

            const first = data[0];
            var writer: std.Io.Writer = .{
                .buffer = first,
                .end = 0,
                .vtable = &.{ .drain = std.Io.Writer.fixedDrain },
            };
            const limit: std.Io.Limit = .limited(writer.buffer.len - writer.end);
            return r.vtable.stream(r, &writer, limit) catch |err| switch (err) {
                error.WriteFailed => unreachable,
                else => |e| return e,
            };
        }
    };

    fn init(root_node: *const MerkleNode) BlockDeserialState {
        std.debug.assert(root_node.block_ref != .null);
        std.debug.assert(root_node.id.fec_set_idx == 0);

        return .{
            .pos_node = root_node,
            .pos_offset = 0,

            .n_transactions_left = null,
            .n_entries_left = null,

            .next_read = .n_entries,
        };
    }

    fn getReader(self: *BlockDeserialState, merkle_pool: *const MerkleForest.NodePool) Reader {
        return .{
            .deserial_state = self,
            .merkle_pool = merkle_pool,
            .interface = .{
                .vtable = &.{
                    .stream = Reader.stream,
                    .rebase = Reader.rebase,
                    .readVec = Reader.readVec,
                },
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn diff(
        before: BlockDeserialState,
        after: BlockDeserialState,
        merkle_pool: *const MerkleForest.NodePool,
    ) usize {
        if (before.pos_node == after.pos_node) return after.pos_offset - before.pos_offset;

        const after_parent: *const MerkleNode = MerkleForest.NodeTree.parentOf(
            .{ .pool = merkle_pool.* },
            after.pos_node,
        ) orelse unreachable;
        std.debug.assert(after_parent == before.pos_node);

        const before_bytes_read = before.pos_node.payload_len - before.pos_offset;
        const after_bytes_read = after.pos_offset;

        return before_bytes_read + after_bytes_read;
    }

    fn nextTransaction(
        self: *BlockDeserialState,
        fba: *std.heap.FixedBufferAllocator,
        merkle_pool: *const MerkleForest.NodePool,
        tx_buf: *[1232]u8,
    ) !?[]const u8 {
        const zone = tracy.Zone.init(@src(), .{ .name = "nextTransaction" });
        defer zone.deinit();

        const backup = self.*;

        return nextTransactionInner(self, fba, merkle_pool, tx_buf) catch |err| switch (err) {
            error.EndOfStream => {
                zone.text("EndOfStream");
                self.* = backup;
                return null;
            },
            else => |e| return e,
        };
    }

    fn nextTransactionInner(
        self: *BlockDeserialState,
        fba: *std.heap.FixedBufferAllocator,
        merkle_pool: *const MerkleForest.NodePool,
        tx_buf: *[1232]u8,
    ) !?[]const u8 {
        var reader = self.getReader(merkle_pool);

        loopback: switch (self.next_read) {
            .n_entries => {
                self.n_entries_left = try bincode_2.read(fba, &reader.interface, u64);
                if (self.n_entries_left.? == 0) {
                    self.next_read = .n_entries;
                    return null; // advance to next?

                }

                self.next_read = .num_hashes;
                continue :loopback .num_hashes;
            },
            // start of entry
            .num_hashes => {
                _ = try bincode_2.read(fba, &reader.interface, u64);

                self.next_read = .hash;
                continue :loopback .hash;
            },
            .hash => {
                _ = try bincode_2.read(fba, &reader.interface, Hash);

                self.next_read = .n_transactions;
                continue :loopback .n_transactions;
            },
            .n_transactions => {
                self.n_transactions_left = try bincode_2.read(fba, &reader.interface, u64);
                if (self.n_transactions_left == 0) {
                    self.n_entries_left.? -= 1;
                    if (self.n_entries_left.? == 0) {
                        self.next_read = .n_entries;
                        return null; // advance to next?

                    }

                    self.next_read = .num_hashes;
                    continue :loopback .num_hashes;
                }
                self.next_read = .transaction;
                continue :loopback .transaction;
            },
            .transaction => {
                if (self.n_transactions_left == 0) {
                    self.n_entries_left.? -= 1;
                    if (self.n_entries_left.? == 0) {
                        self.next_read = .n_entries;
                        return null; // advance to next?

                    }

                    self.next_read = .num_hashes;
                    continue :loopback .num_hashes;
                }

                var pre_state = self.*;

                _ = try bincode_2.read(fba, &reader.interface, lib.solana.transaction.VersionedTransaction);
                self.n_transactions_left.? -= 1;

                const post_state = self.*;

                const tx_bytes_read = diff(pre_state, post_state, merkle_pool);

                var tx_reader = pre_state.getReader(merkle_pool);
                try tx_reader.interface.readSliceAll(tx_buf[0..tx_bytes_read]);

                self.next_read = .transaction;
                return tx_buf[0..tx_bytes_read];
            },
        }
    }
};

const BlockExecState = struct {
    n_transactions_requested: u32,
    n_transactions_completed: u32,
    all_transactions_requested: bool,

    const default: BlockExecState = .{
        .n_transactions_requested = 0,
        .n_transactions_completed = 0,
        .all_transactions_requested = false,
    };
};

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

const TransactionPool = Pool(EncodedTransaction);

const Pubkey = lib.solana.Pubkey;

const EncodedTransaction = extern struct {
    bincode_data: [1232]u8,
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

        pub fn parentOf(ctx: Ctx, node: *const MerkleNode) ?*MerkleNode {
            return &ctx.buf()[node.parent.index() orelse return null];
        }
        pub fn childOf(ctx: Ctx, node: *const MerkleNode) ?*MerkleNode {
            return &ctx.buf()[node.child.index() orelse return null];
        }
        pub fn siblingOf(ctx: Ctx, node: *const MerkleNode) ?*MerkleNode {
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

            .block_ref = if (new_fec_set.id.fec_set_idx == 0) ref: {
                const block_ref = try block_pool.createId();
                block_pool.indexToPtr(block_ref).* = .{
                    // TODO: these are probably useless fields
                    .first_fecset_chained_merkle_root = undefined,
                    .last_fecset_merkle_root = undefined,
                    .last_fecset_received = undefined,

                    // TODO: chain if possible
                    .slot = new_fec_set.id.slot,
                };
                break :ref block_ref;
            } else .null,

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
                if (new_node.block_ref == .null)
                    new_node.block_ref = parent.block_ref
                else
                    std.debug.assert(new_node.id.fec_set_idx == 0);
            } else {
                // This node's parent already has a child. This means the leader produced multiple
                // conflicting fec sets.
                // TODO: report this and special case the handling in the caller
                std.log.warn("Equivocation detected! Fec set {f} has multiple children\n", .{@as(*const MerkleNode, parent)});
                new_node.block_ref = ref: {
                    const block_ref = try block_pool.createId();
                    block_pool.indexToPtr(block_ref).* = .{
                        // TODO: these are probably useless fields
                        .first_fecset_chained_merkle_root = undefined,
                        .last_fecset_merkle_root = undefined,
                        .last_fecset_received = undefined,

                        // TODO: chain if possible
                        .slot = new_fec_set.id.slot,
                    };
                    break :ref block_ref;
                };
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

        return new_node;
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
