const std = @import("std");
const sig = @import("../sig.zig");
const ledger = @import("lib.zig");

const meta = ledger.meta;

const ColumnFamily = ledger.database.ColumnFamily;
const ErasureSetId = ledger.shred.ErasureSetId;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;

pub const schema = struct {
    /// Information about the slot, including how many shreds we have received for the slot, and
    /// whether we've processed data from any of the adjacent slots
    pub const slot_meta: ColumnFamily = .{
        .name = "meta",
        .Key = Slot,
        .Value = meta.SlotMeta,
    };
    /// Indicates whether a slot is "dead." A dead slot is a slot that has been downgraded by the
    /// leader to have fewer shreds than they initially planned. This means it may not be possible
    /// to derive a complete block from this slot.
    pub const dead_slots: ColumnFamily = .{
        .name = "dead_slots",
        .Key = Slot,
        .Value = bool,
    };
    /// Indicates whether the leader has produced duplicate blocks for the slot. If the leader
    /// commits this offense, it means some of the data from the slot cannot be included properly in
    /// the ledger.
    pub const duplicate_slots: ColumnFamily = .{
        .name = "duplicate_slots",
        .Key = Slot,
        .Value = meta.DuplicateSlotProof,
    };
    /// Indicates which slots are rooted. A slot is "rooted" when consensus is finalized for that
    /// slot. It means the block from that slot is permanently included on-chain.
    pub const rooted_slots: ColumnFamily = .{
        .name = "roots",
        .Key = Slot,
        .Value = bool,
    };
    /// Metadata about each Reed-Solomon erasure set, such as how many shreds are in the set.
    pub const erasure_meta: ColumnFamily = .{
        .name = "erasure_meta",
        .Key = ErasureSetId,
        .Value = meta.ErasureMeta,
    };
    /// Tracks slots that we've received shreds for, but we haven't received any shreds for the
    /// parent slot. A slot's parent is the slot that was supposed to come immediately before it.
    pub const orphan_slots: ColumnFamily = .{
        .name = "orphans",
        .Key = Slot,
        .Value = bool,
    };
    /// Index is a single data structure for every slot that indicates which shreds have been
    /// received for that slot.
    pub const index: ColumnFamily = .{
        .name = "index",
        .Key = Slot,
        .Value = meta.Index,
    };
    /// Every data shred received or recovered by the validator.
    pub const data_shred: ColumnFamily = .{
        .name = "data_shred",
        .Key = struct { Slot, u64 },
        .Value = []const u8,
    };
    /// Every code shred received or recovered by the validator.
    pub const code_shred: ColumnFamily = .{
        .name = "code_shred",
        .Key = struct { Slot, u64 },
        .Value = []const u8,
    };
    /// Metadata about executed transactions, such as whether they succeeded or failed, what data
    /// was returned, and other side effects of the transaction.
    pub const transaction_status: ColumnFamily = .{
        .name = "transaction_status",
        .Key = struct { Signature, Slot },
        .Value = meta.TransactionStatusMeta,
    };
    /// Associates each address with all of the transactions that touched the account at this
    /// address.
    pub const address_signatures: ColumnFamily = .{
        .name = "address_signatures",
        .Key = struct {
            address: Pubkey,
            slot: Slot,
            transaction_index: u32,
            signature: Signature,
        },
        .Value = meta.AddressSignatureMeta,
    };
    /// Messages describing the transaction
    pub const transaction_memos: ColumnFamily = .{
        .name = "transaction_memos",
        .Key = struct { Signature, Slot },
        .Value = []const u8,
    };
    /// Populated during blockstore cleanup, but not used for anything consequential. This is
    /// retained for compatibility, but can likely be removed.
    pub const transaction_status_index: ColumnFamily = .{
        .name = "transaction_status_index",
        .Key = Slot,
        .Value = meta.TransactionStatusIndexMeta,
    };
    /// Block rewards to the leader for the block.
    pub const rewards: ColumnFamily = .{
        .name = "rewards",
        .Key = Slot,
        .Value = struct {
            rewards: []const meta.Reward,
            num_partitions: ?u64,
        },
    };
    /// Time a block was produced.
    pub const blocktime: ColumnFamily = .{
        .name = "blocktime",
        .Key = Slot,
        .Value = meta.UnixTimestamp,
    };
    /// Tracks the rate that the ledger is progressing, in terms of slots and transactions.
    pub const perf_samples: ColumnFamily = .{
        .name = "perf_samples",
        .Key = Slot,
        .Value = meta.PerfSample,
    };
    /// Total number of blocks that have been produced throughout history for each slot.
    pub const block_height: ColumnFamily = .{
        .name = "block_height",
        .Key = Slot,
        .Value = Slot,
    };
    /// Not actually used for anything. This is retained for compatibility, but can likely be
    /// removed.
    pub const program_costs: ColumnFamily = .{
        .name = "program_costs",
        .Key = Pubkey,
        .Value = meta.ProgramCost,
    };
    /// For every slot, this has the combined hash of all accounts which were changed during the
    /// slot.
    pub const bank_hash: ColumnFamily = .{
        .name = "bank_hash",
        .Key = Slot,
        .Value = meta.FrozenHashVersioned,
    };
    /// Tracks which slots have been optimistically confirmed by consensus, along with the hash, and
    /// the time that it was recognized as confirmed by this validator.
    pub const optimistic_slots: ColumnFamily = .{
        .name = "optimistic_slots",
        .Key = Slot,
        .Value = meta.OptimisticSlotMetaVersioned,
    };
    /// The Merkle root for each Reed-Solomon erasure set, and which shred it came from.
    pub const merkle_root_meta: ColumnFamily = .{
        .name = "merkle_root_meta",
        .Key = ErasureSetId,
        .Value = meta.MerkleRootMeta,
    };
};

const decls = @typeInfo(schema).Struct.decls;

pub const list: [decls.len]ColumnFamily = l: {
    var ret: [decls.len]ColumnFamily = undefined;
    for (decls, 0..) |decl, i| {
        ret[i] = @field(schema, decl.name);
    }
    break :l ret;
};
