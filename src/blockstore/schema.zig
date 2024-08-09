const std = @import("std");
const sig = @import("../lib.zig");

const meta = sig.blockstore.meta;

const ColumnFamily = sig.blockstore.database.ColumnFamily;
const ErasureSetId = sig.shred_collector.shred.ErasureSetId;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;

pub const schema = struct {
    pub const slot_meta: ColumnFamily = .{
        .name = "meta",
        .Key = Slot,
        .Value = meta.SlotMeta,
    };
    pub const dead_slots: ColumnFamily = .{
        .name = "dead_slots",
        .Key = Slot,
        .Value = bool,
    };
    pub const duplicate_slots: ColumnFamily = .{
        .name = "duplicate_slots",
        .Key = Slot,
        .Value = meta.DuplicateSlotProof,
    };
    pub const roots: ColumnFamily = .{
        .name = "roots",
        .Key = Slot,
        .Value = bool,
    };
    pub const erasure_meta: ColumnFamily = .{
        .name = "erasure_meta",
        .Key = ErasureSetId,
        .Value = meta.ErasureMeta,
    };
    pub const orphans: ColumnFamily = .{
        .name = "orphans",
        .Key = Slot,
        .Value = bool,
    };
    pub const index: ColumnFamily = .{
        .name = "index",
        .Key = Slot,
        .Value = meta.Index,
    };
    pub const data_shred: ColumnFamily = .{
        .name = "data_shred",
        .Key = struct { Slot, u64 },
        .Value = []const u8,
    };
    pub const code_shred: ColumnFamily = .{
        .name = "code_shred",
        .Key = struct { Slot, u64 },
        .Value = []const u8,
    };
    pub const transaction_status: ColumnFamily = .{
        .name = "transaction_status",
        .Key = struct { Signature, Slot },
        .Value = meta.TransactionStatusMeta,
    };
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
    pub const transaction_memos: ColumnFamily = .{
        .name = "transaction_memos",
        .Key = Signature,
        .Value = []const u8,
    };
    pub const transaction_status_index: ColumnFamily = .{
        .name = "transaction_status_index",
        .Key = Slot,
        .Value = meta.TransactionStatusIndexMeta,
    };
    pub const rewards: ColumnFamily = .{
        .name = "rewards",
        .Key = Slot,
        .Value = []const meta.Reward,
    };
    pub const blocktime: ColumnFamily = .{
        .name = "blocktime",
        .Key = Slot,
        .Value = meta.UnixTimestamp,
    };
    pub const perf_samples: ColumnFamily = .{
        .name = "perf_samples",
        .Key = Slot,
        .Value = meta.PerfSample,
    };
    pub const block_height: ColumnFamily = .{
        .name = "block_height",
        .Key = Slot,
        .Value = Slot,
    };
    pub const program_costs: ColumnFamily = .{
        .name = "program_costs",
        .Key = Pubkey,
        .Value = meta.ProgramCost,
    };
    pub const bank_hash: ColumnFamily = .{
        .name = "bank_hash",
        .Key = Slot,
        .Value = meta.FrozenHashVersioned,
    };
    pub const optimistic_slots: ColumnFamily = .{
        .name = "optimistic_slots",
        .Key = Slot,
        .Value = meta.OptimisticSlotMetaVersioned,
    };
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
