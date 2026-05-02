const std = @import("std");
const solana = @import("solana.zig");
const collections = @import("collections.zig");
const ipc = @import("ipc.zig");

comptime {
    _ = std.testing.refAllDecls(@This());
}

pub const TransactionPool = collections.SharedPool([1232]u8, 1_000_000);

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
    request_ring: ipc.Ring(256, ExecRequest),

    // completion queue
    response_ring: ipc.Ring(256, ExecResponse),
};

pub const RequestKind = enum(u8) {
    transaction_execution,
    transaction_signature_verify,
};

pub const ExecRequest = extern struct {
    task_id: u64, // user-provided, arbitrary, for the caller's tracking

    request_kind: RequestKind,
    data: extern union {
        transaction_execution: extern struct {
            block_idx: BlockRef,
            tx_idx: TransactionPool.ItemId,
        },
        transaction_signature_verify: extern struct {
            tx_idx: TransactionPool.ItemId,
        },
    },
};

pub const ExecResponse = extern struct {
    task_id: u64, // user-provided, arbitrary, for the caller's tracking

    request_kind: RequestKind,
    data: extern union {
        transaction_execution: extern struct {
            block_idx: BlockRef,
            tx_idx: TransactionPool.ItemId,
            success: bool,
        },
        transaction_signature_verify: extern struct { success: bool },
    },
};

// pub const ExecRequest = extern struct {
//     block_idx: BlockRef,
//     tx_idx: TransactionPool.ItemId,
// };
