//! Completed FEC (Forward Error Correction) sets flow into this service from the shred receiver.
//!
//! Each FEC set contains its own Merkle Root, and its Chained Merkle Root, with the Chained Merkle
//! Root referring to the FEC set of its parent, i.e. the previous FEC set.
//!
//! These FEC sets are linked together to form a Merkle Forest (a tree of merkle trees), from the
//! chained roots forming parental relationships.
//!
//! As FEC sets come in, we incrementally form this tree.
//!
//! Nodes reachable from the root of this tree may be allocated BlockRefs, which can be used to
//! store block-specific data for e.g. execution.
//!
//! Each FEC set contains part of a (or a whole) bincode-encoded list of transactions. It is also
//! replay's job to deserialise these incrementally as they come in, such that each transaction may
//! be dispatched to the execution service(s).
//!
//!
//!
//! Key data structures:
//!
//! - The Block Tree
//!
//!         Built on a shared pool, this forms the relationships between blocks. Each node allocated
//!         corresponds to its own BlockRef which is intended as the primary way to key
//!         block-specific data.
//!
//!         Each node contains a Slot (u64) and { parent, child, sibling } BlockRefs - This forms an
//!         LCRS (left-child right-sibling) tree.
//!
//!         Replay is responsible for allocating these BlockRefs, and may do so when there is a path
//!         from the root's FEC set to the newly inserted one.
//!
//!
//! - The Merkle Forest
//!
//!         Built on a pool, each node contains the data required for a FEC set for the purpose of
//!         replay. This includes fields such as the Merkle Root and Chained Merkle Root.
//!
//!         We also have two maps: a primary map, and an orphan map. Each map has exactly the same
//!         capacity as the forest's pool. These use the adapted hashmap pattern, effectively only
//!         storing some metadata merkle node pointers.
//!
//!         The primary map is keyed by the Merkle Root of the FEC set, and the orphan map is keyed
//!         by the Chained Merkle Root (i.e. the Merkle Root of its parent).
//!
//!         The primary map is used to lookup the parent of a newly inserted FEC set, whereas the
//!         orphan map is used to lookup the child(ren) of the newly inserted FEC set.
//!
//!         The keying is effectively "inverted" for the orphan map, as a parent FEC set does not
//!         store the Merkle Root(s) of its child(ren). Instead it finds children with its *own*
//!         Merkle Root.
//!
//!         FEC sets only end up in the orphan map if their parent wasn't in the primary map at the
//!         time of its insertion. Typically, the parent will arrive some time soon afterwards and
//!         will be able to find its orphaned children via the orphan map.
//!
//!         We link these nodes together with an LCRS tree. In the case of multiple children, the
//!         newly inserted child is inserted at the tail of the sibling list, i.e. the first
//!         received node will be at the head.
//!
//! - Other block-specific state
//!
//!         This is all keyed by BlockRef. Currently we have:
//!
//!         1) BlockDeserialStates to track the state of our incremental deserialiser
//!
//!         2) BlockExecStates to track the progress of execution
//!
//!
//!
//! NOTE: While this code currently implements async execution (i.e. dispatching tasks to another
//!       thread and continuing work on the current thread), it does not yet implement parallel
//!       execution. This requires supporting multiple exec services and implementing a transaction
//!       scheduler. However, the service and its data structures are designed to support parallel
//!       execution.
//!
//! NOTE: This code does not currently implement eviction, meaning that it will eventually run out
//!       of space and exit (error.OutOfSpace).

const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tracy = @import("tracy");
const services = @import("services");
const tel = lib.telemetry;

const replay = lib.replay;

const Hash = lib.solana.Hash;
const Slot = lib.solana.Slot;

const Shred = lib.shred.Shred;
const FecSetId = lib.shred.FecSetId;

const Pool = lib.collections.Pool;

comptime {
    _ = start;
}

pub const name = .replay;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = services.replay.ReadOnly;
pub const ReadWrite = services.replay.ReadWrite;

const DeserialStates = [replay.BlockPool.capacity]?BlockDeserialState;
const BlockExecStates = [replay.BlockPool.capacity]?BlockExecState;
const BlockHashStates = [lib.replay.BlockPool.capacity]?Hash;

const AccountRef = lib.accounts_db.AccountPool.AccountRef;
const Pubkey = lib.solana.Pubkey;
const BlockRef = replay.BlockRef;

/// A hacky consensus-less approach for following the longest fork.
///
/// If progress is possible, returns the child of the root that goes "towards" the longest fork,
/// otherwise returning the passed-in root.
///
/// We will traverse the blocktree downwards, starting at the root, stopping when we find a node that
/// 1) is at least 32 nodes away from the root
/// 2) has no other nodes at the same level in the tree
///
/// Once we find this node, we will advance the root by one node "towards" the node we have found.
///
/// In the basic case that the root only has one child, we will progress the root to its child iff
/// the tree of the child has a depth of at least 32.
fn progressRoot(old_root: BlockRef, block_pool: *replay.BlockPool) BlockRef {
    const min_depth = 32;

    const QueueItem = struct { node: BlockRef, root_child: BlockRef.Optional };
    var queue_buf: [replay.BlockPool.capacity]QueueItem = undefined;

    var head: u16 = 0;
    var tail: u16 = 1;
    var level_end: u16 = tail;
    var depth: u16 = 0;

    queue_buf[0] = .{ .node = old_root, .root_child = .null };

    while (head < tail) : (depth += 1) {
        const next_level_start = tail;

        while (head < level_end) : (head += 1) {
            const item = queue_buf[head];
            const node = item.node.ptr(block_pool);

            // visit all children
            var maybe_child = node.child.ptr(block_pool);
            while (maybe_child) |child| : (maybe_child = child.sibling.ptr(block_pool)) {
                std.debug.assert(tail < queue_buf.len);

                const child_ref = block_pool.ptrToIndex(child);
                queue_buf[tail] = .{
                    .node = child_ref,
                    .root_child = if (item.root_child == .null)
                        .init(child_ref)
                    else
                        item.root_child,
                };
                tail += 1;
            }
        }

        const next_depth = depth + 1;
        const next_level_len = tail - next_level_start;

        if (next_depth >= min_depth and next_level_len == 1) {
            return queue_buf[next_level_start].root_child.opt().?;
        }

        if (next_level_len == 0) break;
        level_end = tail;
    }

    return old_root;
}

pub fn serviceMain(runner: lib.runner.Connection, _: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    var fba: std.heap.FixedBufferAllocator = .init(rw.scratch_memory);
    const allocator = fba.allocator();

    var forest: MerkleForest = try .init(allocator);

    const unrooted: *Unrooted = try allocator.create(Unrooted);
    unrooted.init();

    const deserial_states: *DeserialStates = try allocator.create(DeserialStates);
    @memset(deserial_states, null);

    const exec_states: *BlockExecStates = try allocator.create(BlockExecStates);
    @memset(exec_states, null);

    const blockhash_states: *BlockHashStates = try allocator.create(BlockHashStates);
    @memset(blockhash_states, null);

    var deshredded_iter = rw.deshredded_in.get(.reader);
    var exec_request_sender = rw.exec_req_response.request_ring.get(.writer);
    var exec_response_receiver = rw.exec_req_response.response_ring.get(.reader);

    { // wait for snapshot metadata from accounts_db
        var blockhashes_in = rw.snapshot_metadata_in.blockhash_queue.hashes.getView(.reader);
        defer blockhashes_in.close();

        var latest_block: ?lib.replay.BlockPool.ItemId = null;
        while (true) {
            const hashes = try blockhashes_in.getBufferBlocking(runner);
            if (hashes.len == 0) break; // blockhashes_out closed their end

            for (hashes) |*hash| {
                // TODO: initialize the block tree nodes and descend new blocks off these
                latest_block = try rw.block_pool.createId();
                blockhash_states[latest_block.?.index()] = hash.*;
            }
            blockhashes_in.advance(hashes.len);
        }
    }

    // TODO: get this from snapshot metadata
    var first_slot: ?Slot = null; // this is a hack, remove it!

    var maybe_rooted_block: ?BlockRef = null;

    // After the slot is supposedly populated, start shred recv (eventually Repair service) on it.

    task: switch (@as(enum { exec_response, fec_set, idle }, .idle)) {
        .idle => {
            if (exec_response_receiver.peek() != null) continue :task .exec_response;
            if (deshredded_iter.peek() != null) continue :task .fec_set;

            const zone = tracy.Zone.init(@src(), .{ .name = "idle" });
            defer zone.deinit();

            while (true) : (std.atomic.spinLoopHint()) {
                if (exec_response_receiver.peek() != null) continue :task .exec_response;
                if (deshredded_iter.peek() != null) continue :task .fec_set;
                try runner.activity.signalIdleSpinning();
            }
        },
        .exec_response => {
            const zone = tracy.Zone.init(@src(), .{ .name = "exec_response" });
            defer zone.deinit();
            try runner.activity.signalActive();

            const response: *const replay.ExecResponse = exec_response_receiver.next() orelse
                unreachable;
            defer exec_response_receiver.markUsed();

            zone.value(response.task_id);

            std.debug.assert(response.request_kind == .txn_exec); // others unimplemented
            const response_data = response.data.txn_exec;

            for (response_data.account_ref_buf[0..response_data.n_account_refs]) |account_ref| {
                if (account_ref == .invalid) continue;

                const account = rw.account_pool.getAccount(account_ref);
                if (account.unref()) rw.account_pool.free(account_ref);
            }

            defer rw.replay_transaction_pool.destroyId(response_data.tx_idx);

            const block_ref = response_data.block_idx;
            const exec_state: *BlockExecState = &(exec_states[block_ref.index()].?);

            // We previously used the transaction number within the block as our "task_id".
            // Asserting that we're receiving them back in order (we have single threaded exec).
            std.debug.assert(response.task_id == exec_state.n_transactions_completed);

            exec_state.n_transactions_completed += 1;

            if (exec_state.finished()) {
                logger.info().logf(
                    "Slot {} ({}) complete! ({}/{})",
                    .{
                        rw.block_pool.indexToPtr(block_ref).slot,
                        block_ref,
                        exec_state.n_transactions_requested,
                        exec_state.n_transactions_completed,
                    },
                );
            }

            if (maybe_rooted_block) |*rooted_block| {
                @branchHint(.likely);

                // progresses root until it is no longer possible
                while (true) {
                    const progress_zone = tracy.Zone.init(@src(), .{ .name = "progress?" });
                    defer progress_zone.deinit();

                    const new_root = progressRoot(rooted_block.*, rw.block_pool);
                    if (new_root == rooted_block.*) {
                        progress_zone.text("same blockref as parent");
                        break;
                    }
                    const new_root_exec_state = exec_states[new_root.index()] orelse {
                        progress_zone.text("no exec state for new blockref");
                        break;
                    };

                    if (!new_root_exec_state.finished()) {
                        progress_zone.text("new root exec unfinished");
                        break;
                    }

                    const old_slot = rw.block_pool.indexToPtr(rooted_block.*).slot;
                    const new_slot = rw.block_pool.indexToPtr(new_root).slot;
                    std.debug.assert(old_slot != new_slot);

                    logger.info().logf("root progressed from {} to {}", .{ old_slot, new_slot });

                    tracy.plot(u63, "rooted slot", @intCast(new_slot));

                    progress_zone.text("Root progressed!");
                    rooted_block.* = new_root;

                    forest.evictBelow(new_slot);
                }
            }

            continue :task .idle;
        },
        .fec_set => {
            const zone = tracy.Zone.init(@src(), .{ .name = "received fec set" });
            defer zone.deinit();
            try runner.activity.signalActive();

            const deshredded_fec_set: *const lib.shred.DeshreddedFecSet =
                deshredded_iter.next() orelse unreachable;
            defer deshredded_iter.markUsed();

            zone.value(deshredded_fec_set.id.slot);
            zone.value(deshredded_fec_set.id.fec_set_idx);

            const inserted = (try insertFecSet(
                logger,
                deshredded_fec_set,
                &forest,
                rw.block_pool,
            )) orelse {
                zone.text("already found");
                continue :task .idle;
            };

            // This is an awful hack, we are treating the first received fec set as our root.
            // We should instead insert the last fec set of the rooted slot, similarly allocate it
            // a BlockRef, and call setChildTreeBlockRefs directly after.
            if (first_slot == null) {
                logger.info().logf("inserting first {f}", .{inserted});
                std.debug.assert(first_slot == null);
                first_slot = inserted.id.slot;

                const rooted_slot = first_slot.? - 1;

                std.debug.assert(inserted.block_ref == .null);

                const rooted_block_ref = try rw.block_pool.createId();
                const first_block_ref = try rw.block_pool.createId();

                rooted_block_ref.ptr(rw.block_pool).* = .{
                    .slot = rooted_slot,
                    .child = .init(first_block_ref),
                };
                first_block_ref.ptr(rw.block_pool).* = .{
                    .slot = first_slot.?,
                    .parent = .init(rooted_block_ref),
                };

                exec_states[rooted_block_ref.index()] = .{
                    .n_transactions_requested = 0,
                    .n_transactions_completed = 0,
                    .all_transactions_requested = true,
                };
                std.debug.assert(exec_states[rooted_block_ref.index()].?.finished());

                inserted.block_ref = .init(first_block_ref);

                logger.info().logf("inserted first {f}", .{inserted});

                maybe_rooted_block = rooted_block_ref;
            }

            if (inserted.id.fec_set_idx == 0) {
                logger.info().logf(
                    "received 0th fec set of slot {}",
                    .{inserted.id.slot},
                );
            }
            if (inserted.slot_complete) {
                logger.info().logf(
                    "received last fec set of slot {} (idx={})",
                    .{ inserted.id.slot, inserted.id.fec_set_idx },
                );
            }

            // NOTE: Currently we're doing nothing if we can't find a path from the inserted node to
            //       the root. We could deserialise early for prefetching.
            const inserted_block_ref = inserted.block_ref.opt() orelse {
                zone.text("null blockref");
                continue :task .idle;
            };

            try maybeContinueBlockExec(
                logger,
                inserted,
                inserted_block_ref,
                &forest.pool,
                rw.block_pool,
                rw.replay_transaction_pool,
                exec_states,
                deserial_states,
                &exec_request_sender,

                unrooted,
                rw.account_pool,
                rw.account_lookups,
            );

            continue :task .idle;
        },
    }
}

/// Holds the accounts mutated for each tracked Block.
const Unrooted = extern struct {
    maps: [max_blocks]Map, // we could initialise with `= @splat(.{})`, but lld disagrees

    // [firedancer] https://github.com/firedancer-io/firedancer/blob/c2050b9c7fb8787b1eaaf9e50cac421a7281f70f/src/flamenco/runtime/fd_cost_tracker.h#L78
    // TODO: calculate this constant ourselves / keep it up to date
    const max_mutations_per_block = 367_535;

    const max_blocks = replay.BlockPool.capacity;

    const Map = extern struct {
        seed: u64,
        len: u32 = 0, // only used to assert `max_mutations_per_block` holds true
        data: [N]AccountRef = @splat(.invalid), // ~1.4MiB

        // NOTE: might be a good idea to oversize this for performance reasons
        const N = max_mutations_per_block;

        fn EntryPtr(comptime SelfPtr: type) type {
            return switch (SelfPtr) {
                *Map => *AccountRef,
                *const Map => *const AccountRef,
                else => unreachable,
            };
        }

        fn entry(
            self: anytype,
            account_pool: *lib.accounts_db.AccountPool,
            pubkey: *const Pubkey,
        ) EntryPtr(@TypeOf(self)) {
            var i: usize = @intCast(pubkey.hash(self.seed) % N);

            while (true) : (i = (i + 1) % N) {
                if (self.data[i] == .invalid)
                    return &self.data[i];
                if (pubkey.equals(&account_pool.getAccount(self.data[i]).pubkey))
                    return &self.data[i];
            }
        }

        fn get(
            self: *const Map,
            account_pool: *lib.accounts_db.AccountPool,
            pubkey: *const Pubkey,
        ) AccountRef {
            return self.entry(account_pool, pubkey).*;
        }

        // The map takes a ref to the new account.
        // Returns the replaced entry, which the caller is expected to unref/free.
        // Entries are replaced when an account of the inserted pubkey already exists in the map.
        // lint: allow_unused
        fn put(
            self: *Map,
            account_pool: *lib.accounts_db.AccountPool,
            new_account_ref: AccountRef,
        ) AccountRef {
            const zone = tracy.Zone.init(@src(), .{ .name = "Map.put" });
            defer zone.deinit();

            std.debug.assert(new_account_ref != .invalid);
            const new_account = account_pool.getAccount(new_account_ref);
            const pubkey: *const Pubkey = &new_account.pubkey;

            const found_entry: *AccountRef = self.entry(account_pool, pubkey);

            // don't "replace" an accountref with itself!
            std.debug.assert(found_entry.* != new_account_ref);

            const old_account_ref = found_entry.*;
            if (old_account_ref != .invalid) {
                zone.text("replace");

                std.debug.assert(pubkey.equals(&account_pool.getAccount(old_account_ref).pubkey));
            } else {
                zone.text("insert");

                self.len += 1;
                if (self.len > max_mutations_per_block) @panic("max_mutations_per_block exceeded");
            }

            found_entry.* = new_account_ref;
            new_account.ref();

            return old_account_ref;
        }
    };

    fn init(self: *Unrooted) void {
        for (&self.maps) |*map| map.* = .{
            // TODO:
            // 1) create randomly + secretly at startup, to avoid performance degradation from attackers
            //    using pre-made keys to cause bad clustering
            // 2) change the seed used per block to avoid possibility of worst-case clustering
            .seed = 123,
        };
    }

    /// Get an account purely from the unrooted store.
    /// For internal/testing usage only.
    /// NOTE: caller is responsible for freeing the account
    fn fetch(
        self: *Unrooted,
        key: *const lib.solana.Pubkey,

        // current block + pool for ancestor lookups
        block: BlockRef,
        block_pool: *replay.BlockPool,

        // account storage
        account_pool: *lib.accounts_db.AccountPool,
    ) AccountRef {
        const zone = tracy.Zone.init(@src(), .{ .name = "Unrooted.fetch" });
        defer zone.deinit();

        var current: ?*replay.Node = block.ptr(block_pool);
        while (current) |ancestor_block| : (current = ancestor_block.parent.ptr(block_pool)) {
            const current_map: *const Map =
                &self.maps[block_pool.ptrToIndex(ancestor_block).index()];

            const account_ref = current_map.get(account_pool, key);
            if (account_ref != .invalid) {
                const account = account_pool.getAccount(account_ref);
                account.ref();

                zone.text("found");

                return account_ref;
            }
        }

        return .invalid;
    }
};

// TODO:
// 1) *never* block the replay thread (remove this function)
// 2) introduce a basic transaction scheduler
// 3) add a prefetcher
/// Gets an account, trying the unrooted store before asking rooted.
/// NOTE: caller is responsible for freeing the account
fn fetchBlocking(
    unrooted: *Unrooted,
    key: *const lib.solana.Pubkey,

    // current block + pool for ancestor lookups
    block: BlockRef,
    block_pool: *replay.BlockPool,

    // account storage
    account_pool: *lib.accounts_db.AccountPool,

    // ring buffer pair for rooted lookups
    rooted_lookups: *lib.accounts_db.AccountLookups,
) AccountRef {
    const zone = tracy.Zone.init(@src(), .{ .name = "fetchBlocking" });
    defer zone.deinit();

    const unrooted_account = unrooted.fetch(key, block, block_pool, account_pool);
    if (unrooted_account != .invalid) {
        zone.text("unrooted");
        return unrooted_account;
    }

    var requester = rooted_lookups.in.get(.writer);
    var response_queue = rooted_lookups.out.get(.reader);

    const request_buf = requester.next() orelse @panic("out of space");
    request_buf.* = key.*;
    requester.markUsed();

    // blocking the thread - do not do this
    while (response_queue.peek() == null) : (std.atomic.spinLoopHint()) {}

    const response = response_queue.next().?;
    defer response_queue.markUsed();

    std.debug.assert(response.pubkey.equals(key));

    if (response.account_index == .invalid) {
        zone.text("account not found");
        return response.account_index;
    }

    const account = account_pool.getAccount(response.account_index);

    std.debug.assert(account.ref_count.load(.monotonic) > 0);
    std.debug.assert(account.pubkey.equals(key));

    zone.text("rooted");
    return response.account_index;
}

/// Finds a node's parent, and attaches the new node to it.
///
/// In the case of a missing parent, also adds the current node (keyed by the parent's merkle root)
/// into the orphan map.
///
/// NOTE: when removing nodes from the orphan map, make sure to handle all sibling nodes.
fn attachParent(
    logger: tel.Logger("main"),
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

                if (next_sibling.id.eql(&tail_node.id)) @panic("equivocation");

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
            // NOTE: We should get rid of this panic once we're confident that we're handling it
            //       correctly downstream.
            if (last_child_of_parent.id.eql(&node.id)) @panic("equivocation");
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

            // Invalid chaining should only happen if the leader is being malicious.
            // I'm not sure if this branch will ever be hit, but we must still handle this case.
            // This node is illegal, let's remove it now.

            // Remove this node from the linked list of siblings
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
//  c) carries the parent's BlockRef forward (same slot)
//
// NOTE: this function detects equivocation, currently panicking.
fn setChildBlockRef(
    parent: *const MerkleNode,
    child: *MerkleNode,
    forest_pool: *const MerkleForest.NodePool,
    block_pool: *replay.BlockPool,
) !void {
    std.debug.assert(child.block_ref == .null);
    std.debug.assert(child.id.slot >= parent.id.slot);
    std.debug.assert(parent.id.mayFollowWith(&child.id));

    const parent_block_ref = parent.block_ref.opt() orelse return; // a)

    // a merkle node with a slot different to that of its block is surely invalid
    std.debug.assert(parent_block_ref.ptr(block_pool).slot == parent.id.slot);

    // detect equivocation: check if the parent already has a child with the same fecset ID.
    // TODO: remove this panic once we're confident that we're handling equivocation correctly.
    {
        var maybe_sibling: ?*const MerkleNode = parent.child.constPtr(forest_pool);
        while (maybe_sibling) |sibling| : (maybe_sibling = sibling.sibling.constPtr(forest_pool)) {
            if (sibling != child and sibling.id.eql(&child.id)) @panic("equivocation detected");
        }
    }

    std.debug.assert(parent.id.slot <= child.id.slot);

    if (parent.id.slot < child.id.slot) {
        std.debug.assert(child.id.fec_set_idx == 0); // we checked mayFollowWith earlier

        // new slot, let's create a new BlockRef
        const new_block = try block_pool.create();
        new_block.* = .{
            .parent = .init(parent_block_ref),
            .slot = child.id.slot,
        };
        const new_block_id = block_pool.ptrToIndex(new_block);

        child.block_ref = .init(new_block_id);

        setBlockTreeRelation(parent_block_ref, new_block_id, block_pool); // b)
    }

    if (parent.id.slot == child.id.slot) {
        // detect equivocation: within a given slot, a parent should only have one child
        // TODO: remove this panic once we're confident that we're handling equivocation correctly.
        if (parent.child.constPtr(forest_pool) != child) @panic("equivocation");
        if (child.sibling != .null) @panic("equivocation");

        child.block_ref = .init(parent_block_ref); // c)

    }
}

// creates parent-child relationships in the block tree
fn setBlockTreeRelation(parent: BlockRef, child: BlockRef, block_pool: *replay.BlockPool) void {
    std.debug.assert(parent != child);

    child.ptr(block_pool).parent = .init(parent);

    const parent_block: *replay.Node = parent.ptr(block_pool);
    if (parent_block.child == .null)
        parent_block.child = .init(child)
    else {
        var tail_child = parent_block.child.ptr(block_pool);
        while (tail_child) |node| : (tail_child = node.sibling.ptr(block_pool)) {
            if (node.sibling == .null) {
                node.sibling = .init(child);
                break;
            }
        }
    }
}

fn setChildTreeBlockRefs(
    parent: *MerkleNode,
    child: *MerkleNode,
    forest_pool: *MerkleForest.NodePool,
    block_pool: *replay.BlockPool,
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

fn insertFecSet(
    logger: tel.Logger("main"),
    // to be transformed and inserted into the forest
    deshredded_node: *const lib.shred.DeshreddedFecSet,
    forest: *MerkleForest,
    // block associated parameters
    // additional blocks may be allocated when inserting a fec set
    block_pool: *replay.BlockPool,
) error{OutOfSpace}!?*MerkleNode {
    const zone = tracy.Zone.init(@src(), .{ .name = "insertFecSet" });
    defer zone.deinit();

    forest.assertCounts();
    defer forest.assertCounts();

    const map_ctx: MerkleForest.MerkleContext = .{ .map = &forest.map };

    if (deshredded_node.id.slot < forest.min_slot) return null; // reject old fec sets

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

fn maybeContinueBlockExec(
    logger: tel.Logger("main"),
    // newly inserted node (or, rarely, when called recursively, the idx=0 ancestor of the block)
    node: *MerkleNode,
    // the block_ref of the newly inserted node
    block_ref: BlockRef,

    // pools
    forest_pool: *MerkleForest.NodePool,
    block_pool: *replay.BlockPool,
    transaction_pool: *replay.TransactionPool,

    // per-block states
    block_exec_states: *BlockExecStates,
    block_deserial_states: *DeserialStates,

    // for sending exec requests
    // NOTE: we should instead be sending to the transaction scheduler (when it is implemented)
    exec_request_sender: *replay.ExecReqResponse.RequestRing.Iterator(.writer),

    // for fetching accounts
    unrooted: *Unrooted,
    account_pool: *lib.accounts_db.AccountPool,
    rooted_lookups: *lib.accounts_db.AccountLookups,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "maybeContinueBlockExec" });
    defer zone.deinit();

    {
        const block: *const replay.Node = block_ref.ptr(block_pool);

        // parentless blocks shouldn't ever reach this stage
        const block_parent = block.parent.opt().?;

        // parent state not initialised => parent not finished
        // parent not finished => can't start exec for child
        const parent_exec_state: *BlockExecState =
            &(block_exec_states[block_parent.index()] orelse return);
        if (!parent_exec_state.all_transactions_requested) return;
    }

    const exec_state: *BlockExecState = blk: {
        const current: *?BlockExecState = &block_exec_states[block_ref.index()];
        if (current.* == null) {
            if (node.id.fec_set_idx != 0) {
                // This branch happens when the idx=0 node of a block wasn't allocated a BlockRef
                // when it was inserted, but now it has one.
                // (If its ancestor has a BlockRef, so must it)

                // Find the fec_set_idx=0 node by walking up the parent chain
                var root = node;
                while (root.id.fec_set_idx != 0) {
                    // The current node has a BlockRef, therefore it must be possible to reach
                    // an ancestor with idx=0
                    root = root.parent.opt().?.ptr(forest_pool);
                }

                // return after calling, as this call semantically "replaces" the current call
                return maybeContinueBlockExec(
                    logger,
                    root,
                    // Importantly using the block_ref of the inserted node, not the block_ref of
                    // the idx=0 ancestor.
                    // They may be different if equivocation has occurred within the slot
                    block_ref,
                    forest_pool,
                    block_pool,
                    transaction_pool,
                    block_exec_states,
                    block_deserial_states,
                    exec_request_sender,

                    unrooted,
                    account_pool,
                    rooted_lookups,
                );
            }
            current.* = .default;
        }
        break :blk &current.*.?;
    };

    const block_deserial_state: *BlockDeserialState = blk: {
        const current: *?BlockDeserialState = &block_deserial_states[block_ref.index()];
        if (current.* == null) {
            std.debug.assert(node.id.fec_set_idx == 0);
            current.* = .init(node);
        }
        break :blk &current.*.?;
    };

    // Read transactions until we can't anymore, sending to exec as we go
    while (true) {
        const tx_ref = try transaction_pool.createId();
        // TODO: this is a major leak risk, should use comptime errdefer unreachable

        const tx_buf: *[1232]u8 = transaction_pool.indexToPtr(tx_ref);

        const tx = try block_deserial_state.nextTransaction(
            forest_pool,
            tx_buf,
        ) orelse {
            transaction_pool.destroyId(tx_ref);
            break;
        };
        tracy.plot(u16, "transaction size", @intCast(tx.len));

        // index within the block
        const tx_index: u32 = exec_state.n_transactions_requested;
        exec_state.n_transactions_requested += 1;

        // prepare transaction's accounts and send the task to exec
        // NOTE: in the future this should be "sent" to the transaction scheduler, not to exec
        // directly
        {
            // TODO: replace this with something custom, this is slow - we only need to extract the
            // accounts (including ALT accounts) here.
            var deserialised_buf: [16 * 1024]u8 = undefined;
            var deserial_fba: std.heap.FixedBufferAllocator = .init(&deserialised_buf);
            var reader = std.io.Reader.fixed(tx);
            const transaction: lib.solana.transaction.VersionedTransaction =
                try lib.solana.bincode.read(
                    &deserial_fba,
                    &reader,
                    lib.solana.transaction.VersionedTransaction,
                );

            var held_accounts_buf: [128]AccountRef = undefined;
            var held_accounts: u8 = 0;

            const account_keys: []const Pubkey = switch (transaction.message) {
                inline else => |txn| txn.account_keys.items,
            };

            for (account_keys) |*k| {
                held_accounts_buf[held_accounts] = fetchBlocking(
                    unrooted,
                    k,
                    block_ref,
                    block_pool,
                    account_pool,
                    rooted_lookups,
                );
                held_accounts += 1;
            }

            const address_lookups: []const lib.solana.transaction.AddressLookup =
                switch (transaction.message) {
                    .legacy => &.{},
                    .v0 => |v0| v0.address_table_lookups.items,
                };

            const Pass = enum { write, read };

            // looked up accounts are writable first, then readable
            for (@as([]const Pass, &.{ .write, .read })) |pass| {
                for (address_lookups) |lookup| {
                    const account_ref = fetchBlocking(
                        unrooted,
                        &lookup.account_key,
                        block_ref,
                        block_pool,
                        account_pool,
                        rooted_lookups,
                    );

                    if (account_ref == .invalid)
                        @panic("missing address lookup table / TODO: handle bad blocks");

                    const ALT_account: *lib.accounts_db.AccountPool.Account =
                        account_pool.getAccount(account_ref);

                    defer if (ALT_account.unref()) account_pool.free(account_ref);

                    // NOTE: this is *not* a conformant implementation of an Address Lookup Table
                    // lookup; we need to respect the fields in the ALT account's header.
                    // Here we are just skipping over the header (56 bytes), which means we could be
                    // fetching accounts which are not yet active in the ALT.
                    const ALT_data = ALT_account.getData();
                    const header_len = 56;
                    if (ALT_data.len < header_len or (ALT_data.len - header_len) % 32 != 0)
                        @panic("invalid ALT / TODO: handle bad blocks");
                    const ALT_pubkeys: []const Pubkey = @ptrCast(ALT_data[header_len..]);

                    const indexes = switch (pass) {
                        .write => lookup.writable_indexes.items,
                        .read => lookup.readonly_indexes.items,
                    };

                    for (indexes) |account_idx| {
                        if (account_idx >= ALT_pubkeys.len)
                            @panic("bad ALT lookup / TODO: handle bad blocks");
                        const account_pk: *const Pubkey = &ALT_pubkeys[account_idx];

                        if (held_accounts >= held_accounts_buf.len)
                            @panic("too many accounts for transaction / TODO: handle bad blocks");

                        held_accounts_buf[held_accounts] = fetchBlocking(
                            unrooted,
                            account_pk,
                            block_ref,
                            block_pool,
                            account_pool,
                            rooted_lookups,
                        );
                        held_accounts += 1;
                    }
                }
            }

            const request: *replay.ExecRequest = exec_request_sender.next() orelse
                @panic("no space");
            request.* = .{
                .task_id = tx_index,
                .request_kind = .txn_exec,
                .data = .{
                    .txn_exec = .{
                        .block_idx = block_ref,
                        .tx_idx = tx_ref,
                        .n_account_refs = held_accounts,
                        .account_ref_buf = undefined,
                    },
                },
            };
            @memcpy(
                request.data.txn_exec.account_ref_buf[0..held_accounts],
                held_accounts_buf[0..held_accounts],
            );

            exec_request_sender.markUsed();
        }
    }

    // If we've just finished a batch, we should progress to the next one, skipping any junk data
    if (!block_deserial_state.start_of_batch) {
        var reader = block_deserial_state.getReader(forest_pool);
        while (true) {
            const was_data_complete = block_deserial_state.pos_node.data_complete;
            block_deserial_state.pos_offset = block_deserial_state.pos_node.payload_len;
            reader.nextNode() catch break;
            if (was_data_complete) break;
        }
        block_deserial_state.start_of_batch = true;
    }

    // If the deserialiser has reached the last node in the block, we have requested all of the
    // transactions inside.
    if (!block_deserial_state.pos_node.slot_complete) return;

    // // start_of_batch should be false if we have finished deserialising.
    // std.debug.assert(!block_deserial_state.start_of_batch);
    exec_state.all_transactions_requested = true;

    logger.info().logf(
        "requested all transactions for slot {} ({})",
        .{ block_ref.ptr(block_pool).slot, block_ref },
    );

    if (exec_state.finished()) {
        logger.info().logf(
            "Slot {} ({}) (already) complete! ({}/{})",
            .{
                block_ref.ptr(block_pool).slot,
                block_ref,
                exec_state.n_transactions_requested,
                exec_state.n_transactions_completed,
            },
        );
    }

    // try to exec children
    var maybe_child = if (block_deserial_state.pos_node.child.opt()) |id|
        id.ptr(forest_pool)
    else
        null;
    while (maybe_child) |child| {
        try maybeContinueBlockExec(
            logger,
            child,
            child.block_ref.opt().?,
            forest_pool,
            block_pool,
            transaction_pool,
            block_exec_states,
            block_deserial_states,
            exec_request_sender,

            unrooted,
            account_pool,
            rooted_lookups,
        );

        maybe_child = if (child.sibling.opt()) |id| id.ptr(forest_pool) else null;
    }
}

const BlockDeserialState = struct {
    pos_node: *const MerkleNode,
    pos_offset: usize,

    n_transactions_left: ?u64,
    n_entries_left: ?u64,

    next_read: NextRead,

    // set to false when there's no entries left
    start_of_batch: bool,

    const NextRead = enum { n_entries, num_hashes, hash, n_transactions, transaction };

    const Reader = struct {
        deserial_state: *BlockDeserialState,
        merkle_pool: *const MerkleForest.NodePool,
        bytes_consumed: usize = 0,

        fn currentReadableSlice(self: *Reader) []const u8 {
            return self.deserial_state.pos_node.payload()[self.deserial_state.pos_offset..];
        }

        fn advanceBytes(
            self: *Reader,
            comptime mode: enum { copy, no_copy },
            out: if (mode == .copy) []u8 else void,
            len: if (mode == .no_copy) usize else void,
        ) !void {
            const n_bytes = switch (mode) {
                .copy => out.len,
                .no_copy => len,
            };

            const current_readable_slice = self.currentReadableSlice();

            if (current_readable_slice.len >= n_bytes) {
                @branchHint(.likely);

                if (mode == .copy) {
                    @memcpy(out, current_readable_slice[0..n_bytes]);
                }
                self.deserial_state.pos_offset += n_bytes;
                self.bytes_consumed += n_bytes;
                return;
            }

            var next_copy: []const u8 = current_readable_slice;
            var offset: usize = 0;

            while (offset < n_bytes) {
                const chunk_len = @min(next_copy.len, n_bytes - offset);
                if (mode == .copy) {
                    @memcpy(out[offset..][0..chunk_len], next_copy[0..chunk_len]);
                }

                self.deserial_state.pos_offset += chunk_len;
                offset += chunk_len;

                if (offset == n_bytes) break;
                try self.nextNode();
                next_copy = self.currentReadableSlice();
            }

            std.debug.assert(offset == n_bytes); // no overshooting
            self.bytes_consumed += n_bytes;
        }

        fn copyValue(self: *Reader, T: type) !T {
            var tmp: T = undefined;
            try self.advanceBytes(.copy, std.mem.asBytes(&tmp), {});
            return tmp;
        }

        fn nextNode(self: *Reader) error{EndOfStream}!void {
            const child_id = self.deserial_state.pos_node.child.opt() orelse
                return error.EndOfStream;
            const child = child_id.constPtr(self.merkle_pool);

            std.debug.assert(child.block_ref != .null);
            std.debug.assert(child.parent != .null);

            // do not advance to other blockrefs!
            if (child.block_ref != self.deserial_state.pos_node.block_ref) return error.EndOfStream;

            self.deserial_state.pos_node = child;
            self.deserial_state.pos_offset = 0;
        }

        /// `parseTransaction` reader contract.
        pub fn readByte(self: *Reader) error{EndOfStream}!u8 {
            return self.copyValue(u8);
        }

        /// `parseTransaction` reader contract.
        pub fn readSlice(self: *Reader, out: []u8) error{EndOfStream}!void {
            try self.advanceBytes(.copy, out, {});
        }

        /// `parseTransaction` reader contract.
        pub fn bytesConsumed(self: *const Reader) usize {
            return self.bytes_consumed;
        }

        /// `parseTransaction` reader contract.
        pub fn skipBytes(self: *Reader, n_bytes: usize) error{EndOfStream}!void {
            try self.advanceBytes(.no_copy, {}, n_bytes);
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

            .start_of_batch = true,
        };
    }

    fn getReader(self: *BlockDeserialState, merkle_pool: *const MerkleForest.NodePool) Reader {
        return .{ .deserial_state = self, .merkle_pool = merkle_pool };
    }

    fn nextTransaction(
        self: *BlockDeserialState,
        merkle_pool: *const MerkleForest.NodePool,
        tx_buf: *[1232]u8,
    ) !?[]const u8 {
        const zone = tracy.Zone.init(@src(), .{ .name = "nextTransaction" });
        defer zone.deinit();

        const backup = self.*;

        return nextTransactionInner(self, merkle_pool, tx_buf) catch |err| switch (err) {
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
        merkle_pool: *const MerkleForest.NodePool,
        tx_buf: *[1232]u8,
    ) !?[]const u8 {
        var reader = self.getReader(merkle_pool);

        // microblock deserialisation state machine
        loopback: switch (self.next_read) {
            // start of microblock
            .n_entries => {
                std.debug.assert(self.start_of_batch);

                self.n_entries_left = try reader.copyValue(u64);
                if (self.n_entries_left.? == 0) {
                    self.next_read = .n_entries;
                    return null; // advance to next?
                }

                self.next_read = .num_hashes;
                continue :loopback .num_hashes;
            },
            // start of entry
            .num_hashes => {
                try reader.skipBytes(8); // num_hashes: u64

                self.next_read = .hash;
                continue :loopback .hash;
            },
            .hash => {
                // ignoring PoH
                try reader.skipBytes(32); // Hash

                self.next_read = .n_transactions;
                continue :loopback .n_transactions;
            },
            .n_transactions => {
                self.n_transactions_left = try reader.copyValue(u64);
                if (self.n_transactions_left == 0) {
                    self.n_entries_left.? -= 1;
                    if (self.n_entries_left.? == 0) {
                        self.next_read = .n_entries;
                        self.start_of_batch = false;
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
                        self.start_of_batch = false;
                        return null; // advance to next?
                    }

                    self.next_read = .num_hashes;
                    continue :loopback .num_hashes;
                }

                var pre_state = self.*;

                const tx_bytes_read = try lib.solana.transaction
                    .VersionedTransaction.parse(&reader);

                self.n_transactions_left.? -= 1;

                var tx_reader = pre_state.getReader(merkle_pool);
                try tx_reader.advanceBytes(.copy, tx_buf[0..tx_bytes_read], {});
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

    fn finished(self: BlockExecState) bool {
        return self.all_transactions_requested and
            self.n_transactions_completed == self.n_transactions_requested;
    }
};

/// Represents a deshredded FEC set.
///
/// Used as a hashmap value, and a tree node (these are the same memory)
/// This node is also used for the keys of hashmaps. When doing so, be careful of which adapted
/// context you use.
///
/// NOTE: When used inside the Pool, these may be items in a free list. However such nodes should
/// not be in either map or the tree.
const MerkleNode = extern struct {
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
    block_ref: lib.replay.BlockRef.Optional,

    payload_len: u16,

    // TODO: this shouldn't be copied, and should instead come in via a pool
    // NOTE: it is an advantage for MerkleNode to be small! (cache locality for map lookup and tree
    // traversal).
    payload_buf: [32 * Shred.data_payload_max]u8,

    fn payload(node: *const MerkleNode) []const u8 {
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

    // The lowest slot that we'll accept
    min_slot: Slot,

    const capacity = 4096;

    // keyed by merkle root
    const OrphanMap = std.ArrayHashMapUnmanaged(void, *MerkleNode, OrphanContext, true);

    // keyed by chained merkle root
    const MerkleMap = std.ArrayHashMapUnmanaged(void, *MerkleNode, MerkleContext, true);

    const NodePool = Pool(MerkleNode, u32);

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
            .min_slot = 0, // initially accepting everything
        };
    }

    fn deinit(self: *MerkleForest, allocator: std.mem.Allocator) void {
        allocator.free(self.pool.buf[0..self.pool.len]);
        self.map.deinit(allocator);
        self.orphan_map.deinit(allocator);
    }

    fn assertCounts(self: *const MerkleForest) void {
        std.debug.assert(self.orphan_map.count() <= self.map.count());
        tracy.plot(u32, "Merkle forest fec sets", @intCast(self.map.count()));
        tracy.plot(u32, "Merkle forest fec sets (orphaned)", @intCast(self.orphan_map.count()));
    }

    /// Iterates over all merkle nodes, evicting any that are older than `slot`. Handles associated
    /// data structures appropriately.
    ///
    // TODO: We should try a smarter strategy, this is ~15us in testing.
    fn evictBelow(self: *MerkleForest, slot: Slot) void {
        const zone = tracy.Zone.init(@src(), .{ .name = "MerkleForest.evictBelow" });
        defer zone.deinit();

        // TODO: we should probably send this value up to shred-receiver
        self.min_slot = @max(self.min_slot, slot);

        self.assertCounts();
        defer self.assertCounts();

        var evict_buf: [capacity]NodePool.ItemId = undefined;
        var evict_len: usize = 0;

        for (self.map.values()) |node| {
            // if the node is old, mark entry for removal
            if (node.id.slot < slot) {
                evict_buf[evict_len] = self.pool.ptrToIndex(node);
                evict_len += 1;
                continue;
            }

            // if the node's *parent* is old, detach it from the parent
            if (node.parent.opt()) |parent_id| {
                const parent = parent_id.ptr(&self.pool);
                if (parent.id.slot < slot) {
                    node.parent = .null;
                    node.sibling = .null;
                }
            }
        }

        // remove old entries
        const map_ctx: MerkleContext = .{ .map = &self.map };
        for (evict_buf[0..evict_len]) |node_id| {
            const node = node_id.ptr(&self.pool);

            std.debug.assert(node.id.slot < self.min_slot);
            const removed = self.map.swapRemoveAdapted(&node.merkle_root, map_ctx);
            std.debug.assert(removed);

            self.pool.destroy(node);
        }

        // rebuild orphan_map
        {
            self.orphan_map.clearRetainingCapacity();

            for (self.map.values()) |node| {
                if (node.parent == .null) node.sibling = .null;
            }

            for (self.map.values()) |node| {
                if (node.parent == .null) self.replaceEvictedOrphan(node);
            }
        }
    }

    fn replaceEvictedOrphan(self: *MerkleForest, node: *MerkleNode) void {
        std.debug.assert(node.parent == .null);
        std.debug.assert(node.sibling == .null);

        const orphan_ctx: OrphanContext = .{ .map = &self.orphan_map };
        const result = self.orphan_map.getOrPutAssumeCapacityAdapted(
            &node.chained_merkle_root,
            orphan_ctx,
        );

        if (!result.found_existing) {
            result.value_ptr.* = node;
            return;
        }

        var tail = result.value_ptr.*;
        while (tail.sibling.opt()) |next_id| {
            tail = next_id.ptr(&self.pool);
        }
        tail.sibling = .init(self.pool.ptrToIndex(node));
    }
};

test "MerkleForest tree put" {
    var tree: MerkleForest = try .init(std.testing.allocator);
    defer tree.deinit(std.testing.allocator);

    const a_hash: Hash = .parse("ByzshhkRgXWnTkHjapkkqaKgEFnsg8ceY3bw4MWBzFE");
    const b_hash: Hash = .parse("BMHr4knWhDp8JhqCYhA2K5DUYQsYUVXdy2zWahzt5jLd");
    const c_hash: Hash = .parse("2GyMeUytf6fcsfNP2QQ6F5e5qwAUoMtKUbnH6QU6bTNm");
    const d_hash: Hash = .parse("4UahX8LzYC7xnubvP9QzRHmPPYovtcNYo7rBXKpp3ADM");
    const e_hash: Hash = .parse("An7mDXKMpRninZw6rvqc4wnQ6ukqd3ARko6QmPitjx8B");

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
        .slot_complete = false,

        .payload_len = 0,
        .payload_buf = undefined,
    };

    const d: lib.shred.DeshreddedFecSet = .{
        .chained_merkle_root = c_hash,
        .merkle_root = d_hash,

        .id = .{ .slot = 409284941, .fec_set_idx = 96 },

        .data_complete = true,
        .slot_complete = true,

        .payload_len = 0,
        .payload_buf = undefined,
    };

    // new slot
    const e: lib.shred.DeshreddedFecSet = .{
        .chained_merkle_root = d_hash,
        .merkle_root = e_hash,

        .id = .{ .slot = 409284942, .fec_set_idx = 0 },

        .data_complete = true,
        .slot_complete = true,

        .payload_len = 0,
        .payload_buf = undefined,
    };

    var pool_buf: [replay.BlockPool.size()]u8 align(@alignOf(replay.BlockPool)) = undefined;
    const pool: *replay.BlockPool = @ptrCast(&pool_buf);
    pool.init();

    const logger = tel.Logger("main").noop;

    const a_inserted = (try insertFecSet(logger, &a, &tree, pool)).?;
    try std.testing.expect(a_inserted.parent == .null);
    try std.testing.expect(a_inserted.child == .null);
    try std.testing.expect(a_inserted.block_ref == .null);
    // give the ancestor block a BlockRef, so that it may propagate
    // NOTE: it is expected that the root-most fec set to be inserted first this way as a special
    //       case. In a real environment this would be the last fec set in the rooted slot.

    const expected_block_ref: replay.BlockRef.Optional = .init(try pool.createId());
    expected_block_ref.opt().?.ptr(pool).* = .{ .slot = 409284941 };

    a_inserted.block_ref = expected_block_ref;

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
