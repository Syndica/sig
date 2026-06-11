const solana = @import("solana.zig");
const collections = @import("collections.zig");
const ipc = @import("ipc.zig");

pub const TransactionPool = collections.SharedPool([1232]u8, 10_000);

pub const BlockPool = collections.SharedPool(Node, 1024);

/// NOTE: this is what we use for referencing blocks. This is equivalent to the block's index
/// our block mem pool. If you want what Agave calls the "Block ID", this is the merkle root of
///  the last fec set.
pub const BlockRef = BlockPool.ItemId;

// TODO: large values (e.g. Hashes) should probably live elsewhere in memory to keep tree
// traversal fast
// This could maybe be 24 bytes (u32 idx * 3, slot u64, last merkle root hash u32)
pub const Node = extern struct {
    parent: BlockRef = .null,
    child: BlockRef = .null,
    sibling: BlockRef = .null,
    slot: solana.Slot,
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
            result: TxExecResult,
        },
        txn_sig_verify: extern struct { success: bool },
    },
};

pub const TxExecResult = extern struct {
    success: bool,
};
