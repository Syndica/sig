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

comptime {
    _ = start;
}

pub const name = .replay;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = services.replay.ReadOnly;
pub const ReadWrite = services.replay.ReadWrite;

var scratch_memory: [256 * 1024 * 1024]u8 = undefined;

const DeserialStates = [lib.replay.BlockPool.capacity]?BlockDeserialState;
const BlockExecStates = [lib.replay.BlockPool.capacity]?BlockExecState;
const BlockHashStates = [lib.replay.BlockPool.capacity]?Hash;

const AccountRef = lib.accounts_db.AccountPool.AccountRef;
const Pubkey = lib.solana.Pubkey;

pub fn serviceMain(runner: lib.runner.Connection, _: ReadOnly, rw: ReadWrite) !noreturn {
    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    var fba: std.heap.FixedBufferAllocator = .init(rw.scratch_memory);
    const allocator = fba.allocator();

    var forest: replay.MerkleForest = try .init(allocator);

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

    try bootstrap(
        logger,
        runner,
        rw.snapshot_metadata_in,
        &forest,
        rw.block_pool,
        exec_states,
        blockhash_states,
    );

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

            const response: *const lib.replay.ExecResponse = exec_response_receiver.next() orelse
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
                    "Slot {f} ({}) complete! ({}/{})",
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
            try runner.activity.signalActive();

            const deshredded_fec_set: *const lib.shred.DeshreddedFecSet =
                deshredded_iter.next() orelse unreachable;
            defer deshredded_iter.markUsed();

            zone.value(deshredded_fec_set.id.slot);
            zone.value(deshredded_fec_set.id.fec_set_idx);

            const inserted = (try replay.insertFecSet(
                logger,
                deshredded_fec_set,
                &forest,
                rw.block_pool,
            )) orelse {
                zone.text("already found");
                continue :task .idle;
            };

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

/// Reads all the RuntimeMetadata provided by accountsdb from the snapshot or
/// its internal state. This bootstraps replay with information about its
/// starting root slot, and some older info like the history of blockhashes.
/// This data populates the block tree, some other structures indexed by
/// BlockRef, and seeds the merkle forest with some minimal info about the last
/// fec set in the rooted slot.
///
/// Currently some placeholder data is used, which is not accurate because it is
/// impossible to derive from the snapshot. We must be very careful about how we
/// use this:
/// - slot number in the block tree for slots older than the starting root
/// - fields in the final fec set of the starting root:
///     - chained_merkle_root
///     - fec_set_idx
///     - payload_len
fn bootstrap(
    logger: tel.Logger("main"),
    runner: lib.runner.Connection,
    snapshot_metadata: *lib.accounts_db.RuntimeMetadata,
    forest: *replay.MerkleForest,
    block_pool: *lib.replay.BlockPool,
    exec_states: *BlockExecStates,
    blockhash_states: *BlockHashStates,
) !void {
    var num_hashes: usize = 0;
    // Drain the blockhash queue into the block tree. accountsdb writes into
    // this ring blocks waiting for the reader (us).
    var root_block = bhq: {
        var blockhashes_in = snapshot_metadata.blockhash_queue.hashes.getView(.reader);
        defer blockhashes_in.close();
        var last_block: ?lib.replay.BlockRef = null;
        while (true) {
            const hashes = try blockhashes_in.getBufferBlocking(runner);
            if (hashes.len == 0) break; // blockhashes_out closed their end
            for (hashes) |*hash| {
                const block = try block_pool.createId();
                block.ptr(block_pool).* = .{
                    .slot = .null, // cannot be determined from the snapshot
                    .child = .null,
                    .parent = .init(last_block),
                };
                if (last_block) |p| p.ptr(block_pool).child = .init(block);
                blockhash_states[block.index()] = hash.*;
                last_block = block;
                num_hashes += 1;
            }
            blockhashes_in.advance(hashes.len);
        }

        const root_block = last_block orelse return error.NoBlockhashesInSnapshot;

        break :bhq root_block;
    };
    logger.info().logf("loaded {} blockhashes from accountsdb snapshot data", .{num_hashes});

    const root_slot = try snapshot_metadata.getSlotBlocking(runner);
    root_block.ptr(block_pool).slot = .init(root_slot);
    logger.info().logf("got the root slot from the snapshot: {}", .{root_slot});

    // create a synthetic fec-set node that doesn't have all information about
    // the fec set, but it is enough to get started processing the first block
    // after the root
    const root_node = try replay.insertFecSet(logger, &.{
        .merkle_root = snapshot_metadata.block_id,
        .chained_merkle_root = .ZEROES, // cannot be determined from the snapshot
        .id = .{
            .slot = root_slot,
            .fec_set_idx = 0, // cannot be determined from the snapshot
        },
        .data_complete = true,
        .slot_complete = true,
        .payload_len = 0, // cannot be determined from the snapshot
        .payload_buf = undefined,
    }, forest, block_pool) orelse unreachable;

    root_node.block_ref = .init(root_block);

    // Prevent the synthetic node from being interpreted as an orphan child of some future node
    // whose `merkle_root` happens to equal `Hash.ZEROES`.
    std.debug.assert(forest.orphan_map.swapRemoveAdapted(
        &root_node.chained_merkle_root,
        replay.MerkleForest.OrphanContext{ .map = &forest.orphan_map },
    ));

    // Mark the root block as fully executed so `maybeContinueBlockExec` will immediately
    // dispatch transactions for its first child.
    exec_states[root_block.index()] = .{
        .n_transactions_requested = 0,
        .n_transactions_completed = 0,
        .all_transactions_requested = true,
    };
    std.debug.assert(exec_states[root_block.index()].?.finished());

    logger.info().logf(
        "finished bootstrapping replay at slot {} (block_id={f})",
        .{ root_slot, snapshot_metadata.block_id },
    );
}

/// Holds the accounts mutated for each tracked Block.
const Unrooted = extern struct {
    seed: u64,
    maps: [max_blocks]Map, // we could initialise with `= @splat(.{})`, but lld disagrees

    // [firedancer] https://github.com/firedancer-io/firedancer/blob/c2050b9c7fb8787b1eaaf9e50cac421a7281f70f/src/flamenco/runtime/fd_cost_tracker.h#L78
    // TODO: calculate this constant ourselves / keep it up to date
    const max_mutations_per_block = 367_535;

    const max_blocks = lib.replay.BlockPool.capacity;

    const Map = extern struct {
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
            seed: u64,
            account_pool: *lib.accounts_db.AccountPool,
            pubkey: *const Pubkey,
        ) EntryPtr(@TypeOf(self)) {
            var i: usize = @intCast(pubkey.hash(seed) % N);

            while (true) : (i = (i + 1) % N) {
                if (self.data[i] == .invalid)
                    return &self.data[i];
                if (pubkey.equals(&account_pool.getAccount(self.data[i]).pubkey))
                    return &self.data[i];
            }
        }

        fn get(
            self: *const Map,
            seed: u64,
            account_pool: *lib.accounts_db.AccountPool,
            pubkey: *const Pubkey,
        ) AccountRef {
            return self.entry(seed, account_pool, pubkey).*;
        }

        // The map takes a ref to the new account.
        // Returns the replaced entry, which the caller is expected to unref/free.
        // Entries are replaced when an account of the inserted pubkey already exists in the map.
        // lint: allow_unused
        fn put(
            self: *Map,
            seed: u64,
            account_pool: *lib.accounts_db.AccountPool,
            new_account_ref: AccountRef,
        ) AccountRef {
            const zone = tracy.Zone.init(@src(), .{ .name = "Map.put" });
            defer zone.deinit();

            std.debug.assert(new_account_ref != .invalid);
            const new_account = account_pool.getAccount(new_account_ref);
            const pubkey: *const Pubkey = &new_account.pubkey;

            const found_entry: *AccountRef = self.entry(seed, account_pool, pubkey);

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
        // TODO: create randomly + secretly at startup, to avoid performance degradation from
        //       attackers using pre-made keys to cause bad clustering
        self.seed = 123;
        for (&self.maps) |*map| map.* = .{};
    }

    /// Get an account purely from the unrooted store.
    /// For internal/testing usage only.
    /// NOTE: caller is responsible for freeing the account
    fn fetch(
        self: *Unrooted,
        key: *const lib.solana.Pubkey,

        // current block + pool for ancestor lookups
        block: lib.replay.BlockRef,
        block_pool: *lib.replay.BlockPool,

        // account storage
        account_pool: *lib.accounts_db.AccountPool,
    ) AccountRef {
        const zone = tracy.Zone.init(@src(), .{ .name = "Unrooted.fetch" });
        defer zone.deinit();

        var current: ?*replay.Node = block.ptr(block_pool);
        while (current) |ancestor_block| {
            const current_map: *const Map =
                &self.maps[block_pool.ptrToIndex(ancestor_block).index()];

            const account_ref = current_map.get(self.seed, account_pool, key);
            if (account_ref != .invalid) {
                const account = account_pool.getAccount(account_ref);
                account.ref();

                zone.text("found");

                return account_ref;
            }
            current = if (ancestor_block.parent.opt()) |p| p.ptr(block_pool) else null;
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
    block: lib.replay.BlockRef,
    block_pool: *lib.replay.BlockPool,

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

fn maybeContinueBlockExec(
    logger: tel.Logger("main"),
    // newly inserted node (or, rarely, when called recursively, the idx=0 ancestor of the block)
    node: *replay.MerkleNode,
    // the block_ref of the newly inserted node
    block_ref: replay.BlockRef,

    // pools
    forest_pool: *replay.MerkleForest.NodePool,
    block_pool: *replay.BlockPool,
    transaction_pool: *lib.replay.TransactionPool,

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

            const request: *lib.replay.ExecRequest = exec_request_sender.next() orelse
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
        "requested all transactions for slot {f} ({})",
        .{ block_ref.ptr(block_pool).slot, block_ref },
    );

    if (exec_state.finished()) {
        logger.info().logf(
            "Slot {f} ({}) (already) complete! ({}/{})",
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
    pos_node: *const replay.MerkleNode,
    pos_offset: usize,

    n_transactions_left: ?u64,
    n_entries_left: ?u64,

    next_read: NextRead,

    // set to false when there's no entries left
    start_of_batch: bool,

    const NextRead = enum { n_entries, num_hashes, hash, n_transactions, transaction };

    const Reader = struct {
        deserial_state: *BlockDeserialState,
        merkle_pool: *const replay.MerkleForest.NodePool,
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

    fn init(root_node: *const replay.MerkleNode) BlockDeserialState {
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

    fn getReader(
        self: *BlockDeserialState,
        merkle_pool: *const replay.MerkleForest.NodePool,
    ) Reader {
        return .{ .deserial_state = self, .merkle_pool = merkle_pool };
    }

    fn nextTransaction(
        self: *BlockDeserialState,
        merkle_pool: *const replay.MerkleForest.NodePool,
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
        merkle_pool: *const replay.MerkleForest.NodePool,
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
