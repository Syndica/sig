const std = @import("std");
const solana = @import("solana.zig");
const collections = @import("collections.zig");
const ipc = @import("ipc.zig");
const util = @import("util.zig");
const accounts_db = @import("accounts_db.zig");

const unrooted = @import("replay/unrooted.zig");
const account_fetcher = @import("replay/account_fetcher.zig");

const VersionedTransaction = solana.transaction.VersionedTransaction;

// This is a bit large currently because of the unrooted store
pub const scratch_buffer_size = 3 * 1024 * 1024 * 1024;

pub const TransactionPool = collections.SharedPool(TransactionRecord, 10_000);

pub const BlockPool = collections.SharedPool(Node, 1024);

pub const Unrooted = unrooted.Unrooted;

pub const AccountFetcher = account_fetcher.AccountFetcher;

/// Transaction bytes plus their validated wire layout.
///
/// This struct itself is safe to share between processes. Consumers can construct transient
/// `VersionedTransaction.View`s locally, avoiding a re-parse of the transaction bytes.
///
/// The `Layout` struct is a collection of offsets and lengths into the `payload` array.
/// The `payload` array is a copy of the transaction bytes in wire format.
pub const TransactionRecord = extern struct {
    layout: VersionedTransaction.Layout,
    payload: [VersionedTransaction.MAX_BYTES]u8,

    pub fn bytes(self: *const TransactionRecord) []const u8 {
        const payload_len: usize = self.layout.payload_len;
        std.debug.assert(payload_len <= self.payload.len);
        return self.payload[0..payload_len];
    }

    pub fn view(self: *const TransactionRecord) VersionedTransaction.View {
        return .{
            .layout = &self.layout,
            .payload = self.bytes(),
        };
    }
};

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
