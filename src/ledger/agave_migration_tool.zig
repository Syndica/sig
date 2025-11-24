const std = @import("std");
const sig = @import("../sig.zig");

const ledger = sig.ledger;

const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;

const meta = ledger.meta;
const ColumnFamily = ledger.database.ColumnFamily;
const ErasureSetId = ledger.shred.ErasureSetId;
const SigSchema = ledger.schema.schema;

const Logger = sig.trace.Logger("agave-migrate");

const agave_meta = struct {
    const null_sentinel = std.math.maxInt(u64);

    const SlotMeta = struct {
        slot: Slot,
        consecutive_received_from_0: u64,
        received: u64,
        first_shred_timestamp_milli: u64,
        last_index: u64 = null_sentinel,
        parent_slot: Slot = null_sentinel,
        child_slots: []Slot,
        connected_flags: meta.ConnectedFlags,
        completed_data_indexes: []const u32,

        fn fromOurs(ours: meta.SlotMeta) SlotMeta {
            return .{
                .slot = ours.slot,
                .consecutive_received_from_0 = ours.consecutive_received_from_0,
                .received = ours.received,
                .first_shred_timestamp_milli = ours.first_shred_timestamp_milli,
                .last_index = ours.last_index orelse null_sentinel,
                .parent_slot = ours.parent_slot orelse null_sentinel,
                .child_slots = ours.child_slots.items,
                .connected_flags = ours.connected_flags,
                .completed_data_indexes = ours.completed_data_indexes.map.unmanaged.inner.keys(),
            };
        }
    };
};

const decls = @typeInfo(AgaveSchema).@"struct".decls;

pub const list: [decls.len]ColumnFamily = l: {
    var ret: [decls.len]ColumnFamily = undefined;
    for (decls, 0..) |decl, i| {
        ret[i] = @field(AgaveSchema, decl.name);
    }
    break :l ret;
};

/// This format may not be stable! You may want to check that this schema matches the one in the
/// version of Agave that you're using.
/// [agave] https://github.com/anza-xyz/agave/blob/93df4052e311fc1417cb90575836c5030c5e37d6/ledger/src/blockstore_db.rs#L176
const AgaveSchema = struct {
    /// Information about the slot, including how many shreds we have received for the slot, and
    /// whether we've processed data from any of the adjacent slots
    pub const slot_meta: ColumnFamily = .{
        .name = "meta",
        .Key = Slot,
        .Value = agave_meta.SlotMeta,
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
    /// Populated during ledger cleanup, but not used for anything consequential. This is
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
        .Value = sig.core.UnixTimestamp,
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

/// This tool is for when you find a live issue in Sig, and need another validator to compare
/// behaviour against.
/// This is tool that you will hopefully never need.
pub fn migrateLedgerToAgave(
    allocator: std.mem.Allocator,
    logger: Logger,
    in_db_path: []const u8,
    out_db_path: []const u8,
) !void {
    const OurDb = sig.ledger.database.rocksdb.RocksDB(&ledger.schema.list);
    const TheirDb = sig.ledger.database.rocksdb.RocksDB(&list);

    var in_db = try OurDb.open(allocator, .from(logger), in_db_path);
    defer in_db.deinit();

    var out_db = try TheirDb.open(allocator, .from(logger), out_db_path);
    defer out_db.deinit();
    {
        var iter = try in_db.iterator(SigSchema.slot_meta, .forward, null);
        defer iter.deinit();

        while (try iter.next()) |n| {
            const key: Slot, const value: ledger.meta.SlotMeta = n;
            const read_meta = agave_meta.SlotMeta.fromOurs(value);
            try out_db.put(AgaveSchema.slot_meta, key, read_meta);
            std.debug.print("put key: {}\n", .{key});
        }
    }
    {
        var iter = try in_db.iterator(AgaveSchema.data_shred, .forward, null);
        defer iter.deinit();

        while (try iter.nextBytes()) |n| {
            defer n[0].deinit();
            defer n[1].deinit();

            const key = try sig.ledger.database.key_serializer.deserialize(
                AgaveSchema.data_shred.Key,
                allocator,
                n[0].data,
            );
            const value: []const u8 = n[1].data;
            try out_db.put(AgaveSchema.data_shred, key, value);
            std.debug.print("put key: {}\n", .{key});
        }
    }

    // TODO: put in test
    const our_slot_meta: []const u8 = &.{
        137, 135, 247, 21, 0, 0, 0, 0, // slot
        0, 0, 0, 0, 0, 0, 0, 0, // .consecutive_received_from_0
        0, 0, 0, 0, 0, 0, 0, 0, // .received
        0, 0, 0, 0, 0, 0, 0, 0, // .first_shred_timestamp_milli
        0, // .last_index
        0, // .parent_slot
        1, 0, 0, 0, 0, 0, 0, 0, // child slots len
        138, 135, 247, 21, 0, 0, 0, 0, // child slots items
        0, // connected flags
        0, 0, 0, 0, 0, 0, 0, 0, // inner (len)
        0, // max
        1, // is_sorted
    };

    const their_slot_meta: []const u8 = &.{
        137, 135, 247, 21, 0, 0, 0, 0, // slot
        0, 0, 0, 0, 0, 0, 0, 0, // .consecutive_received_from_0
        0, 0, 0, 0, 0, 0, 0, 0, // .received
        0, 0, 0, 0, 0, 0, 0, 0, // .first_shred_timestamp_milli
        255, 255, 255, 255, 255, 255, 255, 255, // .last_index
        255, 255, 255, 255, 255, 255, 255, 255, // .parent_slot
        1, 0, 0, 0, 0, 0, 0, 0, // child slots len
        138, 135, 247, 21, 0, 0, 0, 0, // child slots items
        0, // connected flags
        0, 0, 0, 0, 0, 0, 0, 0, // completed_data_indexes (BTreeSet<u32>)
    };

    const slot_meta = try sig.bincode.readFromSlice(allocator, meta.SlotMeta, our_slot_meta, .{});

    const bytes = try sig.bincode.writeAlloc(allocator, slot_meta.completed_data_indexes, .{});

    std.debug.print("slot_meta: {}\n", .{slot_meta});
    std.debug.print("completed_data_indexes bytes: {any}\n", .{bytes});

    const bytes_2 = try sig.bincode.readFromSlice(allocator, agave_meta.SlotMeta, their_slot_meta, .{});
    std.debug.print("bytes: {any}\n", .{bytes_2});

    const new_agave_meta = agave_meta.SlotMeta.fromOurs(slot_meta);
    const bytes_3 = try sig.bincode.writeAlloc(allocator, new_agave_meta, .{});
    std.debug.print("bytes3: {any}\n", .{bytes_3});
}
