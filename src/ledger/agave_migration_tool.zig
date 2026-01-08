const std = @import("std");
const sig = @import("../sig.zig");

const ledger = sig.ledger;

const Slot = sig.core.Slot;

const sig_meta = ledger.meta;
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
        connected_flags: sig_meta.ConnectedFlags,
        completed_data_indexes: []const u32,

        fn fromOurs(ours: sig_meta.SlotMeta) agave_meta.SlotMeta {
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

        fn intoOurs(
            self: *const agave_meta.SlotMeta,
            allocator: std.mem.Allocator,
        ) !sig_meta.SlotMeta {
            const child_slots: std.ArrayList(Slot) = .{
                .items = self.child_slots,
                .capacity = self.child_slots.len,
                .allocator = std.testing.failing_allocator,
            };

            var completed_data_indexes: sig.utils.collections.SortedSet(u32) = .init(allocator);
            errdefer completed_data_indexes.deinit();
            for (self.completed_data_indexes) |data_idx| try completed_data_indexes.put(data_idx);

            return .{
                .slot = self.slot,
                .consecutive_received_from_0 = self.consecutive_received_from_0,
                .received = self.received,
                .first_shred_timestamp_milli = self.first_shred_timestamp_milli,
                .last_index = if (self.last_index == null_sentinel) null else self.last_index,
                .parent_slot = if (self.parent_slot == null_sentinel) null else self.parent_slot,
                .child_slots = child_slots,
                .connected_flags = self.connected_flags,
                .completed_data_indexes = completed_data_indexes,
            };
        }
    };
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
    /// Every data shred received or recovered by the validator.
    pub const data_shred: ColumnFamily = .{
        .name = "data_shred",
        .Key = struct { Slot, u64 },
        .Value = []const u8,
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
        .Value = sig_meta.DuplicateSlotProof,
    };
    // /// Indicates which slots are rooted. A slot is "rooted" when consensus is finalized for that
    // /// slot. It means the block from that slot is permanently included on-chain.
    // pub const rooted_slots: ColumnFamily = .{
    //     .name = "roots",
    //     .Key = Slot,
    //     .Value = bool,
    // };
    /// Metadata about each Reed-Solomon erasure set, such as how many shreds are in the set.
    pub const erasure_meta: ColumnFamily = .{
        .name = "erasure_meta",
        .Key = ErasureSetId,
        .Value = sig_meta.ErasureMeta,
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
        .Value = sig_meta.Index,
    };
};

comptime {
    std.debug.assert(std.meta.eql(AgaveSchema.data_shred, SigSchema.data_shred));
}

const list = l: {
    const decls = @typeInfo(AgaveSchema).@"struct".decls;

    var ret: [decls.len]ColumnFamily = undefined;
    for (decls, 0..) |decl, i| {
        ret[i] = @field(AgaveSchema, decl.name);
    }
    break :l ret;
};

const OurDb = sig.ledger.database.rocksdb.RocksDB(&ledger.schema.list);
const TheirDb = sig.ledger.database.rocksdb.RocksDB(&list);

/// This tool is for when you find a live issue in Sig, and need another validator to compare
/// behaviour against.
/// This is tool that you will hopefully never need.
pub fn migrateLedgerToAgave(
    allocator: std.mem.Allocator,
    logger: Logger,
    in_db_path: []const u8,
    out_db_path: []const u8,
) !void {
    var in_db = try OurDb.open(allocator, .from(logger), in_db_path, true);
    defer in_db.deinit();

    var out_db = try TheirDb.open(allocator, .from(logger), out_db_path, false);
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
                std.testing.failing_allocator,
                n[0].data,
            );
            const value: []const u8 = n[1].data;
            try out_db.put(AgaveSchema.data_shred, key, value);
            std.debug.print("put key: {}\n", .{key});
        }
    }
}

pub fn migrateLedgerFromAgave(
    allocator: std.mem.Allocator,
    logger: Logger,
    in_db_path: []const u8,
    out_db_path: []const u8,
) !void {
    std.debug.print("opening in_db\n", .{});
    var in_db = try TheirDb.open(allocator, .from(logger), in_db_path, true);
    defer in_db.deinit();

    std.debug.print("opening out_db\n", .{});
    var out_db = try OurDb.open(allocator, .from(logger), out_db_path, false);
    defer out_db.deinit();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    {
        var iter = try in_db.iterator(AgaveSchema.slot_meta, .forward, null);
        defer iter.deinit();

        std.debug.print("hi\n", .{});

        while (try iter.next()) |n| {
            std.debug.print("value\n", .{});

            defer _ = arena.reset(.retain_capacity);
            const key: Slot, const value: agave_meta.SlotMeta = n;

            const read_meta: sig_meta.SlotMeta = try value.intoOurs(arena.allocator());
            defer read_meta.completed_data_indexes.deinit();

            try out_db.put(SigSchema.slot_meta, key, read_meta);
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
                std.testing.failing_allocator,
                n[0].data,
            );
            const value: []const u8 = n[1].data;
            try out_db.put(AgaveSchema.data_shred, key, value);
            std.debug.print("put key: {}\n", .{key});
        }
    }
}

test "slotmeta encode/decode" {
    const allocator = std.testing.allocator;

    const our_meta: []const u8 = &.{
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

    const their_meta: []const u8 = &.{
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

    const our_meta_deserialized: sig_meta.SlotMeta = try sig.bincode.readFromSlice(
        allocator,
        sig_meta.SlotMeta,
        our_meta,
        .{},
    );
    defer sig.bincode.free(allocator, our_meta_deserialized);

    const their_meta_from_ours: agave_meta.SlotMeta = .fromOurs(our_meta_deserialized);

    const round_tripped_bytes = try sig.bincode.writeAlloc(allocator, their_meta_from_ours, .{});
    defer allocator.free(round_tripped_bytes);

    const their_meta_deserialized: agave_meta.SlotMeta = try sig.bincode.readFromSlice(
        allocator,
        agave_meta.SlotMeta,
        their_meta,
        .{},
    );
    defer sig.bincode.free(allocator, their_meta_deserialized);

    const our_meta_from_their_meta_from_ours: sig_meta.SlotMeta =
        try their_meta_from_ours.intoOurs(allocator);
    defer our_meta_from_their_meta_from_ours.completed_data_indexes.deinit();

    try std.testing.expectEqualSlices(u8, their_meta, round_tripped_bytes);
    try std.testing.expectEqualDeep(their_meta_deserialized, their_meta_from_ours);
    try std.testing.expect(sig.utils.types.eqlCustom(
        our_meta_from_their_meta_from_ours,
        our_meta_deserialized,
        .{},
    ));
}
