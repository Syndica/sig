const std = @import("std");
const sig = @import("../lib.zig");

const meta = sig.blockstore.meta;

const Allocator = std.mem.Allocator;

const ColumnFamily = sig.blockstore.database.ColumnFamily;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const SlotMeta = sig.blockstore.meta.SlotMeta;

pub const schema: Schema = Schema{};

pub const Schema = struct {
    meta: ColumnFamily = .{
        .name = "meta",
        .Key = Slot,
        .Value = meta.SlotMeta,
    },
    dead_slots: ColumnFamily = .{
        .name = "dead_slots",
        .Key = Slot,
        .Value = bool,
    },
    duplicate_slots: ColumnFamily = .{
        .name = "duplicate_slots",
        .Key = Slot,
        .Value = meta.DuplicateSlotProof,
    },
    roots: ColumnFamily = .{
        .name = "roots",
        .Key = Slot,
        .Value = bool,
    },
    erasure_meta: ColumnFamily = .{
        .name = "erasure_meta",
        .Key = meta.ErasureSetId,
        .Value = meta.ErasureMeta,
    },
    orphans: ColumnFamily = .{
        .name = "orphans",
        .Key = Slot,
        .Value = bool,
    },
    index: ColumnFamily = .{
        .name = "index",
        .Key = Slot,
        .Value = meta.Index,
    },
    data_shred: ColumnFamily = .{
        .name = "data_shred",
        .Key = struct { slot: Slot, index: u64 },
        .Value = []const u8,
        .KeySerializer = sig.blockstore.database.BytesSerializer,
    },
    code_shred: ColumnFamily = .{
        .name = "code_shred",
        .Key = struct { slot: Slot, index: u64 },
        .Value = []const u8,
        .KeySerializer = sig.blockstore.database.BytesSerializer,
    },
    transaction_status: ColumnFamily = .{
        .name = "transaction_status",
        .Key = struct { Signature, Slot },
        .Value = meta.TransactionStatusMeta,
    },
    address_signatures: ColumnFamily = .{
        .name = "address_signatures",
        .Key = struct {
            address: Pubkey,
            slot: Slot,
            transaction_index: u32,
            signature: Signature,
        },
        .Value = meta.AddressSignatureMeta,
    },
    transaction_memos: ColumnFamily = .{
        .name = "transaction_memos",
        .Key = Signature,
        .Value = []const u8,
    },
    transaction_status_index: ColumnFamily = .{
        .name = "transaction_status_index",
        .Key = Slot,
        .Value = meta.TransactionStatusIndexMeta,
    },
    rewards: ColumnFamily = .{
        .name = "rewards",
        .Key = Slot,
        .Value = []const meta.Reward,
    },
    blocktime: ColumnFamily = .{
        .name = "blocktime",
        .Key = Slot,
        .Value = meta.UnixTimestamp,
    },
    perf_samples: ColumnFamily = .{
        .name = "perf_samples",
        .Key = Slot,
        .Value = meta.PerfSample,
    },
    block_height: ColumnFamily = .{
        .name = "block_height",
        .Key = Slot,
        .Value = Slot,
    },
    program_costs: ColumnFamily = .{
        .name = "program_costs",
        .Key = Pubkey,
        .Value = meta.ProgramCost,
    },
    bank_hash: ColumnFamily = .{
        .name = "bank_hash",
        .Key = Slot,
        .Value = meta.FrozenHashVersioned,
    },
    optimistic_slots: ColumnFamily = .{
        .name = "optimistic_slots",
        .Key = Slot,
        .Value = meta.OptimisticSlotMetaVersioned,
    },
    merkle_root_meta: ColumnFamily = .{
        .name = "merkle_root_meta",
        .Key = meta.ErasureSetId,
        .Value = void,
    },

    const Self = @This();

    const fields = @typeInfo(Self).Struct.fields;

    pub fn list(self: Self) [fields.len]ColumnFamily {
        var ret: [fields.len]ColumnFamily = undefined;
        for (fields, 0..) |field, i| {
            ret[i] = @field(self, field.name);
        }
        return ret;
    }
};

pub const list: [decls.len]ColumnFamily = l: {
    var ret: [decls.len]ColumnFamily = undefined;
    for (decls, 0..) |decl, i| {
        ret[i] = @field(Schema, decl.name);
    }
    break :l ret;
};
const decls = @typeInfo(Schema).Struct.decls;
