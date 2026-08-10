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

comptime {
    if (@import("builtin").is_test) {
        _ = @import("merkle.zig");
    }
}

const std = @import("std");
const lib = @import("lib");
const tracy = @import("tracy");
const merkle = @import("merkle.zig");

pub const api = @import("replay_api");

const tel = lib.telemetry;
const Hash = lib.solana.Hash;
const AccountRef = lib.AccountPool.AccountRef;
const Pubkey = lib.solana.Pubkey;

const DeserialStates = [api.BlockPool.capacity]?BlockDeserialState;
const BlockExecStates = [api.BlockPool.capacity]?BlockExecState;
const BlockHashStates = [api.BlockPool.capacity]?Hash;

const MerkleNode = merkle.MerkleNode;
const MerkleForest = merkle.MerkleForest;
const insertFecSet = merkle.insertFecSet;

pub const Input = union(enum) {
    exec_response: *const api.ExecResponse,
    fec_set: *const api.DeshreddedFecSet,
    idle,
};

pub fn Replay(comptime Effects: type) type {
    return struct {
        const Self = @This();

        effects: Effects,
        forest: MerkleForest,
        unrooted: *Unrooted,
        deserial_states: *DeserialStates,
        exec_states: *BlockExecStates,
        blockhash_states: *BlockHashStates,

        const PollResult = enum { active, idle };

        pub fn init(
            allocator: std.mem.Allocator,
            config: struct {
                effects: Effects,
                logger: tel.Logger("main"),
                runner: lib.runner.Connection,
            },
        ) !Self {
            const unrooted = try allocator.create(Unrooted);
            unrooted.init();

            const deserial_states = try allocator.create(DeserialStates);
            @memset(deserial_states, null);

            const exec_states = try allocator.create(BlockExecStates);
            @memset(exec_states, null);

            const blockhash_states = try allocator.create(BlockHashStates);
            @memset(blockhash_states, null);

            var self: Self = .{
                .effects = config.effects,
                .forest = try .init(allocator),
                .unrooted = unrooted,
                .deserial_states = deserial_states,
                .exec_states = exec_states,
                .blockhash_states = blockhash_states,
            };

            try bootstrap(
                config.logger,
                config.runner,
                &self.forest,
                self.exec_states,
                self.blockhash_states,
                config.effects,
            );

            return self;
        }

        pub fn poll(self: *Self, logger: tel.Logger("main")) !PollResult {
            const input = self.effects.nextInput();
            defer self.effects.releaseInput(input);

            switch (input) {
                .exec_response => |response| {
                    try self.processExecResponse(logger, response);
                    return .active;
                },
                .fec_set => |fec_set| {
                    try self.processFecSet(logger, fec_set);
                    return .active;
                },
                .idle => return .idle,
            }
        }

        fn processExecResponse(
            self: *Self,
            logger: tel.Logger("main"),
            response: *const api.ExecResponse,
        ) !void {
            const zone = tracy.Zone.init(@src(), .{ .name = "exec_response" });
            defer zone.deinit();

            zone.value(response.task_id);

            std.debug.assert(response.request_kind == .txn_exec); // others unimplemented
            const response_data = response.data.txn_exec;

            const account_pool = self.effects.accountPool();
            for (response_data.account_ref_buf[0..response_data.n_account_refs]) |account_ref| {
                if (account_ref == .invalid) continue;

                const account = account_pool.getAccount(account_ref);
                if (account.unref()) account_pool.free(account_ref);
            }

            defer self.effects.transactionPool().destroyId(response_data.tx_idx);

            const block_ref = response_data.block_idx;
            const exec_state: *BlockExecState = &(self.exec_states[block_ref.index()].?);

            // We previously used the transaction number within the block as our task_id.
            // Assert that responses come back in order while exec is single threaded.
            std.debug.assert(response.task_id == exec_state.n_transactions_completed);

            exec_state.n_transactions_completed += 1;

            if (exec_state.finished()) {
                logger.info().logf(
                    "Slot {f} ({}) complete! ({}/{})",
                    .{
                        self.effects.blockPool().indexToPtr(block_ref).slot,
                        block_ref,
                        exec_state.n_transactions_requested,
                        exec_state.n_transactions_completed,
                    },
                );
            }
        }

        fn processFecSet(
            self: *Self,
            logger: tel.Logger("main"),
            deshredded_fec_set: *const api.DeshreddedFecSet,
        ) !void {
            const zone = tracy.Zone.init(@src(), .{ .name = "received fec set" });
            defer zone.deinit();

            zone.value(deshredded_fec_set.id.slot);
            zone.value(deshredded_fec_set.id.fec_set_idx);

            const inserted = (try insertFecSet(
                logger,
                deshredded_fec_set,
                &self.forest,
                self.effects.blockPool(),
            )) orelse {
                zone.text("already found");
                return;
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

            // NOTE: Currently we do nothing if there is no path from this node to the root.
            //       We could deserialise early for prefetching.
            const inserted_block_ref = inserted.block_ref.opt() orelse {
                zone.text("null blockref");
                return;
            };

            try maybeContinueBlockExec(
                logger,
                inserted,
                inserted_block_ref,
                &self.forest.pool,
                self.exec_states,
                self.deserial_states,
                self.unrooted,
                self.effects,
            );
        }
    };
}

fn maybeContinueBlockExec(
    logger: tel.Logger("main"),
    // newly inserted node (or, rarely, when called recursively, the idx=0 ancestor of the block)
    node: *MerkleNode,
    // the block_ref of the newly inserted node
    block_ref: api.BlockRef,

    // pools
    forest_pool: *MerkleForest.NodePool,

    // per-block states
    block_exec_states: *BlockExecStates,
    block_deserial_states: *DeserialStates,

    // for fetching accounts
    unrooted: *Unrooted,
    effects: anytype,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "maybeContinueBlockExec" });
    defer zone.deinit();

    const block_pool = effects.blockPool();
    const transaction_pool = effects.transactionPool();
    const exec_request_sender = effects.execRequestSender();
    const account_pool = effects.accountPool();

    {
        const block: *const api.Node = block_ref.ptr(block_pool);

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
                    block_exec_states,
                    block_deserial_states,
                    unrooted,
                    effects,
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
                    effects,
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
                        effects,
                    );

                    if (account_ref == .invalid)
                        @panic("missing address lookup table / TODO: handle bad blocks");

                    const ALT_account: *lib.AccountPool.Account =
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
                            effects,
                        );
                        held_accounts += 1;
                    }
                }
            }

            const request: *api.ExecRequest = exec_request_sender.next() orelse
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
            block_exec_states,
            block_deserial_states,
            unrooted,
            effects,
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
    forest: *MerkleForest,
    exec_states: *BlockExecStates,
    blockhash_states: *BlockHashStates,
    effects: anytype,
) !void {
    const block_pool = effects.blockPool();
    const snapshot_metadata = effects.snapshotMetadata();

    var num_hashes: usize = 0;
    // Drain the blockhash queue into the block tree. accountsdb writes into
    // this ring blocks waiting for the reader (us).
    var root_block = bhq: {
        var blockhashes_in = snapshot_metadata.blockhash_queue.hashes.getView(.reader);
        defer blockhashes_in.close();
        var last_block: ?api.BlockRef = null;
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
    const root_node = try insertFecSet(logger, &.{
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
        MerkleForest.OrphanContext{ .map = &forest.orphan_map },
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

    const max_blocks = api.BlockPool.capacity;

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
            account_pool: *lib.AccountPool,
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
            account_pool: *lib.AccountPool,
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
            account_pool: *lib.AccountPool,
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
        block: api.BlockRef,
        block_pool: *api.BlockPool,

        // account storage
        account_pool: *lib.AccountPool,
    ) AccountRef {
        const zone = tracy.Zone.init(@src(), .{ .name = "Unrooted.fetch" });
        defer zone.deinit();

        var current: ?*api.Node = block.ptr(block_pool);
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

    // current block for ancestor lookups
    block: api.BlockRef,
    effects: anytype,
) AccountRef {
    const zone = tracy.Zone.init(@src(), .{ .name = "fetchBlocking" });
    defer zone.deinit();

    const block_pool = effects.blockPool();
    const account_pool = effects.accountPool();
    const unrooted_account = unrooted.fetch(key, block, block_pool, account_pool);
    if (unrooted_account != .invalid) {
        zone.text("unrooted");
        return unrooted_account;
    }

    const rooted_account = effects.fetchRootedAccountBlocking(key);
    if (rooted_account == .invalid) {
        zone.text("account not found");
        return rooted_account;
    }

    const account = account_pool.getAccount(rooted_account);

    std.debug.assert(account.ref_count.load(.monotonic) > 0);
    std.debug.assert(account.pubkey.equals(key));

    zone.text("rooted");
    return rooted_account;
}

const TestRuntimeMetadata = struct {
    slot: lib.solana.Slot = 0,
    block_id: Hash,
    blockhash_queue: struct {
        hashes: lib.ipc.Ring(256, Hash),
    },

    fn init(self: *TestRuntimeMetadata) void {
        self.blockhash_queue.hashes.init();
    }

    fn populateSlot(self: *TestRuntimeMetadata, slot: lib.solana.Slot) void {
        self.slot = slot;
    }

    fn getSlotBlocking(
        self: *TestRuntimeMetadata,
        runner: lib.runner.Connection,
    ) !lib.solana.Slot {
        _ = runner;
        return self.slot;
    }
};

test "bootstrap creates root block and chains blockhashes" {
    const allocator = std.testing.allocator;

    var activity: lib.runner.Activity = .{};
    var service_view = activity.serviceView();
    const runner: lib.runner.Connection = .{ .activity = &service_view };

    var metadata: TestRuntimeMetadata = undefined;
    metadata.init();
    metadata.block_id = .parse("ByzshhkRgXWnTkHjapkkqaKgEFnsg8ceY3bw4MWBzFE");

    // Prefill the blockhash ring with N > 1 hashes as a single writer batch,
    // then close the writer end so bootstrap's drain loop terminates.
    const test_hashes = [_]Hash{
        .parse("BMHr4knWhDp8JhqCYhA2K5DUYQsYUVXdy2zWahzt5jLd"),
        .parse("2GyMeUytf6fcsfNP2QQ6F5e5qwAUoMtKUbnH6QU6bTNm"),
        .parse("4UahX8LzYC7xnubvP9QzRHmPPYovtcNYo7rBXKpp3ADM"),
        .parse("Hh8DjJdpQRGeZ6bUxYyt1PBktnFtNAwZoQuwZqGWLPfB"),
    };
    {
        var writer = metadata.blockhash_queue.hashes.getView(.writer);
        const buf = writer.getBuffer().?;
        try std.testing.expect(buf.len >= test_hashes.len);
        @memcpy(buf[0..test_hashes.len], &test_hashes);
        writer.advance(test_hashes.len);
        writer.close();
    }

    const root_slot: lib.solana.Slot = 100;
    metadata.populateSlot(root_slot);

    var pool_buf: [api.BlockPool.size()]u8 align(@alignOf(api.BlockPool)) = undefined;
    const pool: *api.BlockPool = @ptrCast(&pool_buf);
    pool.init();

    var forest: MerkleForest = try .init(allocator);
    defer forest.deinit(allocator);

    const exec_states = try allocator.create(BlockExecStates);
    defer allocator.destroy(exec_states);
    @memset(exec_states, null);

    const blockhash_states = try allocator.create(BlockHashStates);
    defer allocator.destroy(blockhash_states);
    @memset(blockhash_states, null);

    const logger = tel.Logger("main").noop;

    const TestEffects = struct {
        metadata: *TestRuntimeMetadata,
        pool: *api.BlockPool,

        const Self = @This();

        fn snapshotMetadata(self: *const Self) *TestRuntimeMetadata {
            return self.metadata;
        }

        fn blockPool(self: *const Self) *api.BlockPool {
            return self.pool;
        }
    };
    const effects: TestEffects = .{ .metadata = &metadata, .pool = pool };

    try bootstrap(logger, runner, &forest, exec_states, blockhash_states, effects);

    // find root in pool
    var root_opt: ?api.BlockRef = null;
    for (pool.buf(), 0..) |block, i| {
        if (block.item.slot.opt()) |slot| if (slot == root_slot) {
            try std.testing.expectEqual(null, root_opt);
            root_opt = api.BlockRef.fromInt(@intCast(i));
        };
    }
    const root = root_opt orelse return error.NoRoot;

    try std.testing.expectEqual(root_slot, root.ptr(pool).slot.opt().?);
    try std.testing.expect(exec_states[root.index()].?.finished());

    // walk backwards from root, checking each block's hash, slot, and that the
    // parent and child link properly.
    var current: ?api.BlockRef = root;
    var expected_child: ?api.BlockRef = null;
    for (0..test_hashes.len) |i| {
        const block_ref = current orelse return error.ParentNotSpecified;
        const block = block_ref.ptr(pool);
        try std.testing.expectEqual(
            test_hashes[test_hashes.len - 1 - i],
            blockhash_states[block_ref.index()].?,
        );
        try std.testing.expectEqual(
            if (i == 0) root_slot else null,
            block.slot.opt(),
        );
        try std.testing.expectEqual(expected_child, block.child.opt());
        expected_child = block_ref;
        current = block.parent.opt();
    }
    try std.testing.expectEqual(null, current);
}
