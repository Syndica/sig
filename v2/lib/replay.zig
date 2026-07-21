const std = @import("std");
const solana = @import("solana.zig");
const collections = @import("collections.zig");
const ipc = @import("ipc.zig");
const util = @import("util.zig");
const accounts_db = @import("accounts_db.zig");

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
    tx_hash: solana.Hash,
};

/// Stores hashes of transactions that have been recently executed.
///
/// Represents a minimal subset of what is known as `StatusCache` in agave.
///
/// Transactions are organized according to the block they specify as their
/// recent blockhash. Transactions can appear in multiple blocks when there are forks.
/// When a block is evicted, all the associated transaction hashes are as well.
pub const ExecutionRegistry = extern struct {
    blocks: [BlockPool.capacity]Entry,
    tx_segment_pool: TxSegmentPool,

    pub fn init(self: *ExecutionRegistry) void {
        @memset(&self.blocks, .{ .transactions = .null });
        self.tx_segment_pool.init();
    }

    /// The number of bytes of the transaction hash to use as a key.
    pub const CACHED_KEY_SIZE = 20;
    /// The first `CACHED_KEY_SIZE` bytes of a transaction hash, used as the key.
    pub const KeySlice = [CACHED_KEY_SIZE]u8;

    pub const Entry = extern struct {
        transactions: TxSegmentNode.Id.Optional,
    };

    /// Uses a capacity such that there is roughly a 1:1000 ratio of blocks:transactions.
    pub const TxSegmentPool = collections.SharedPool(
        TxSegmentNode,
        BlockPool.capacity * 1000 / TxSegmentNode.tx_per_segment,
    );

    pub const TxSegmentNode = extern struct {
        buf: [tx_per_segment]KeySlice,
        next: Id.Optional,

        pub const Id = TxSegmentPool.ItemId;

        pub const tx_per_segment = std.atomic.cache_line / @sizeOf(KeySlice);
        const tx_hash_id_sentinel: KeySlice = @splat(0);

        pub fn init(self: *TxSegmentNode) void {
            @memset(&self.buf, tx_hash_id_sentinel);
            self.next = .null;
        }

        const LookupResult = union(enum) {
            /// There was a match in the segment.
            match: usize,
            /// There was no match in the segment, but there is a vacancy.
            vacant: usize,
            /// There are no vacancies in the segment, and no matches.
            full_no_match,
        };

        fn getOrFindPlace(segment: *const TxSegmentNode, lookup_key: *const KeySlice) LookupResult {
            for (&segment.buf, 0..) |*tx_hash_slice, i| {
                if (std.mem.eql(u8, tx_hash_slice, &tx_hash_id_sentinel)) {
                    std.debug.assert(segment.next == .null);
                    return .{ .vacant = i };
                }
                if (std.mem.eql(u8, tx_hash_slice, lookup_key)) return .{ .match = i };
            }
            return .full_no_match;
        }
    };

    pub fn containsTransaction(
        exec_registry: *const ExecutionRegistry,
        /// Block that's associated with the `recent_blockhash` of interest, with the implied ancestors.
        recent_block_ref: BlockRef,
        /// The transaction key.
        tx_key: *const solana.Hash,
    ) bool {
        const entry = &exec_registry.blocks[recent_block_ref.index()];
        const lookup_key = tx_key.data[0..CACHED_KEY_SIZE];
        var current = entry.transactions;
        while (current.opt()) |segment_id| {
            const segment = segment_id.constPtr(&exec_registry.tx_segment_pool);
            defer current = segment.next;
            switch (segment.getOrFindPlace(lookup_key)) {
                .match => return true,
                .vacant => std.debug.assert(segment.next == .null),
                .full_no_match => {},
            }
        }
        return false;
    }

    pub fn insert(
        exec_registry: *ExecutionRegistry,
        /// Block that's associated with the `recent_blockhash` of interest, with the implied ancestors.
        recent_block_ref: BlockRef,
        tx_key: *const KeySlice,
    ) error{OutOfSpace}!void {
        const entry = &exec_registry.blocks[recent_block_ref.index()];
        if (std.mem.allEqual(u8, tx_key, 0)) {
            std.debug.panic("Invalid tx_key (all zeroes).", .{});
        }
        const first_segment_id = entry.transactions.opt() orelse {
            entry.transactions = .init(try exec_registry.makeNewSegment(tx_key));
            return;
        };
        const first_segment = first_segment_id.ptr(&exec_registry.tx_segment_pool);
        switch (first_segment.getOrFindPlace(tx_key)) {
            .match => return,
            .vacant => |vacancy| {
                first_segment.buf[vacancy] = tx_key.*;
                return;
            },
            .full_no_match => {},
        }

        var current_parent_id = first_segment_id;
        while (true) {
            const current_parent = current_parent_id.ptr(&exec_registry.tx_segment_pool);
            const current_child_id = current_parent.next.opt() orelse {
                current_parent.next = .init(try exec_registry.makeNewSegment(tx_key));
                return;
            };
            defer current_parent_id = current_child_id;
            const current_child = current_child_id.ptr(&exec_registry.tx_segment_pool);
            switch (current_child.getOrFindPlace(tx_key)) {
                .match => return,
                .vacant => |vacancy| {
                    current_child.buf[vacancy] = tx_key.*;
                    return;
                },
                .full_no_match => {},
            }
        }
    }

    fn makeNewSegment(
        exec_registry: *ExecutionRegistry,
        lookup_key: *const KeySlice,
    ) !TxSegmentNode.Id {
        const tx_entry_id = try exec_registry.tx_segment_pool.createId();
        const tx_entry = tx_entry_id.ptr(&exec_registry.tx_segment_pool);
        tx_entry.init();
        tx_entry.buf[0] = lookup_key.*;
        return tx_entry_id;
    }

    /// Evicts all of the resources associated with `block_ref`.
    pub fn evictBlock(
        exec_registry: *ExecutionRegistry,
        block_ref: BlockRef,
    ) void {
        const entry = &exec_registry.blocks[block_ref.index()];
        var current_id_opt = entry.transactions;
        while (current_id_opt.opt()) |current_id| {
            const current = current_id.ptr(&exec_registry.tx_segment_pool);
            current_id_opt = current.next;
            exec_registry.tx_segment_pool.destroyId(current_id);
        }
        entry.* = .{ .transactions = .null };
    }

    /// Evicts all blocks whose slot is `<= min_root`.
    /// Must eventually be called after any slot `> min_root` is rooted.
    pub fn evictRooted(
        exec_registry: *ExecutionRegistry,
        block_pool: *const BlockPool,
        min_root: solana.Slot,
    ) void {
        for (0..exec_registry.blocks.len) |block_ref_int| {
            const block_ref: BlockRef = .fromInt(@intCast(block_ref_int));
            const block = block_ref.constPtr(block_pool);
            if (block.slot <= min_root) exec_registry.evictBlock(block_ref);
        }
    }
};
