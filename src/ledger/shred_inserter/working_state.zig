const std = @import("std");
const tracy = @import("tracy");
const sig = @import("../../sig.zig");
const ledger = @import("../lib.zig");

const meta = ledger.meta;
const schema = ledger.schema.schema;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const AutoHashMap = std.AutoHashMap;

const Slot = sig.core.Slot;
const SortedMap = sig.utils.collections.SortedMap;
const Timer = sig.time.Timer;

const LedgerDB = ledger.db.LedgerDB;
const BytesRef = ledger.database.BytesRef;
const CodeShred = ledger.shred.CodeShred;
const ColumnFamily = ledger.database.ColumnFamily;
const ErasureSetId = ledger.shred.ErasureSetId;
const Shred = ledger.shred.Shred;
const ShredId = ledger.shred.ShredId;
const WriteBatch = LedgerDB.WriteBatch;

const ErasureMeta = meta.ErasureMeta;
const Index = meta.Index;
const MerkleRootMeta = meta.MerkleRootMeta;
const ShredIndex = meta.ShredIndex;
const SlotMeta = meta.SlotMeta;

const newlinesToSpaces = sig.utils.fmt.newlinesToSpaces;

const Logger = sig.trace.Logger("ledger.shred_inserter.working_state");

/// Acts as a proxy to the database during a single call to
/// ShredInserter.insertShreds. Contains pending items that need to be written to
/// and read from the database.
///
/// Only intended for use within a single thread. The lifetime is not expected to
/// exceed a single call to insertShreds.
///
/// This struct is not a catchall bucket for whatever kind of state may exist
/// during insertShreds. It is only supposed to contain the following:
///
/// 1. Data that insertShreds needs to insert into the database. Those insertions
///    won't take place until the write batch is committed at the end of
///    insertShreds. This struct manages those items and the write batch, and
///    processes the commit of the write batch.
///
/// 2. Data of the same type as the items being inserted, but it may have simply
///    been read from the database, instead of being inserted by insertShreds.
///
/// The insertShreds implementation is simplest if it can just behave as if it's
/// instantly modifying the database, instead of using a write batch. But the
/// write batch is needed for atomicity. So, during the course of insert shreds
/// being executed, the database itself becomes stale. If insertShreds tries to
/// read from the database, while assuming that its previous mutations to the
/// database were applied immediately, the state that it reads directly from the
/// database won't be consistent with its assumption.
///
/// This struct's goal is to be usable by insertShreds as if it *is* the database
/// itself, as if all modifications are applied instantly. It acts as a local
/// view into the future state of the database. This will be the actual state,
/// once the write batch is committed. This struct handles the negotiation
/// between atomicity and staleness, so the shred inserter doesn't need to.
///
/// Since this is treated as the authoritative view of the database, it needs to
/// support reading arbitrary items out of the database, regardless of whether
/// they were actually modified by the shred inserter. Unmodified items that were
/// simply loaded from the database are classified internally as "clean" working
/// entries, and they will not be inserted into the database on commit, since
/// they were already present.
///
/// This struct should not have any business logic about how to validate shreds,
/// or anything like that. It is only used for negotiating state between the
/// database and working sets.
pub const PendingInsertShredsState = struct {
    allocator: Allocator,
    logger: sig.trace.Logger(@typeName(Self)),
    db: *LedgerDB,
    write_batch: WriteBatch,
    just_inserted_shreds: AutoHashMap(ShredId, Shred),
    erasure_metas: SortedMap(ErasureSetId, WorkingEntry(ErasureMeta), .{}),
    merkle_root_metas: AutoHashMap(ErasureSetId, WorkingEntry(MerkleRootMeta)),
    slot_meta_working_set: AutoHashMap(u64, SlotMetaWorkingSetEntry),
    index_working_set: AutoHashMap(u64, IndexMetaWorkingSetEntry),
    duplicate_shreds: ArrayList(PossibleDuplicateShred),
    metrics: ?ledger.ShredInserter.Metrics,

    // TODO unmanaged

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        db: *LedgerDB,
        metrics: ?ledger.ShredInserter.Metrics,
    ) !Self {
        return .{
            .allocator = allocator,
            .db = db,
            .logger = logger.withScope(@typeName(Self)),
            .write_batch = try db.initWriteBatch(),
            .just_inserted_shreds = .init(allocator), // TODO capacity = shreds.len
            .erasure_metas = .empty,
            .merkle_root_metas = .init(allocator),
            .slot_meta_working_set = .init(allocator),
            .index_working_set = .init(allocator),
            .duplicate_shreds = .init(allocator),
            .metrics = metrics,
        };
    }

    /// duplicate_shreds is not deinitialized. ownership is transfered to caller
    pub fn deinit(self: *Self) void {
        self.just_inserted_shreds.deinit();
        self.erasure_metas.deinit(self.allocator);
        self.merkle_root_metas.deinit();

        {
            var iter = self.slot_meta_working_set.iterator();
            while (iter.next()) |entry| entry.value_ptr.deinit(self.allocator);
            self.slot_meta_working_set.deinit();
        }
        {
            var iter = self.index_working_set.iterator();
            while (iter.next()) |entry| entry.value_ptr.deinit(self.allocator);
            self.index_working_set.deinit();
        }
        self.write_batch.deinit();
    }

    /// agave: get_index_meta_entry
    pub fn getIndexMetaEntry(self: *Self, slot: Slot) !*IndexMetaWorkingSetEntry {
        var timer = Timer.start();
        const entry = try self.index_working_set.getOrPut(slot);
        if (!entry.found_existing) {
            if (try self.db.get(self.allocator, schema.index, slot)) |item| {
                entry.value_ptr.* = .{ .index = item };
            } else {
                entry.value_ptr.* = IndexMetaWorkingSetEntry.init(slot);
            }
        }
        if (self.metrics) |m| m.index_meta_time_us.add(timer.read().asMicros());
        return entry.value_ptr;
    }

    /// agave: get_slot_meta_entry
    pub fn getSlotMetaEntry(
        self: *Self,
        slot: Slot,
        parent_slot: Slot,
    ) !*SlotMetaWorkingSetEntry {
        const entry = try self.slot_meta_working_set.getOrPut(slot);
        if (!entry.found_existing) {
            if (try self.db.get(self.allocator, schema.slot_meta, slot)) |backup| {
                var slot_meta: SlotMeta = try backup.clone(self.allocator);
                // If parent_slot == None, then this is one of the orphans inserted
                // during the chaining process, see the function find_slot_meta_in_cached_state()
                // for details. Slots that are orphans are missing a parent_slot, so we should
                // fill in the parent now that we know it.
                if (slot_meta.isOrphan()) {
                    slot_meta.parent_slot = parent_slot;
                }
                entry.value_ptr.* = .{
                    .new_slot_meta = slot_meta,
                    .old_slot_meta = backup,
                };
            } else {
                entry.value_ptr.* = .{
                    .new_slot_meta = SlotMeta.init(slot, parent_slot),
                };
            }
        }
        return entry.value_ptr;
    }

    pub fn shreds(self: *Self) ShredWorkingStore {
        return .{
            .logger = self.logger.withScope(@typeName(ShredWorkingStore)),
            .db = self.db,
            .just_inserted_shreds = &self.just_inserted_shreds,
        };
    }

    pub fn erasureMetas(self: *Self) ErasureMetaWorkingStore {
        return .{
            .allocator = self.allocator,
            .db = self.db,
            .working_entries = &self.erasure_metas,
        };
    }

    pub fn merkleRootMetas(self: *Self) MerkleRootMetaWorkingStore {
        return .{
            .allocator = self.allocator,
            .db = self.db,
            .working_entries = &self.merkle_root_metas,
        };
    }

    pub fn duplicateShreds(self: *Self) DuplicateShredsWorkingStore {
        return .{ .db = self.db, .duplicate_shreds = &self.duplicate_shreds };
    }

    pub fn commit(self: *Self) !void {
        const zone = tracy.Zone.init(@src(), .{ .name = "commit" });
        defer zone.deinit();

        var commit_working_sets_timer = Timer.start();

        // TODO: inputs and outputs of this function may need to be fleshed out
        // as the ledger is used more throughout the codebase.
        _, const newly_completed_slots = try self.commitSlotMetaWorkingSet(self.allocator, &.{});
        newly_completed_slots.deinit();

        try persistWorkingEntries(&self.write_batch, schema.erasure_meta, &self.erasure_metas);
        try persistWorkingEntries(&self.write_batch, schema.merkle_root_meta, &self.merkle_root_metas);

        var index_working_set_iterator = self.index_working_set.iterator();
        while (index_working_set_iterator.next()) |entry| {
            const working_entry = entry.value_ptr;
            if (working_entry.did_insert_occur) {
                try self.write_batch.put(schema.index, entry.key_ptr.*, working_entry.index);
            }
        }

        if (self.metrics) |m|
            m.insert_working_sets_elapsed_us.add(commit_working_sets_timer.read().asMicros());

        var commit_timer = Timer.start();
        try self.db.commit(&self.write_batch);
        if (self.metrics) |m| m.write_batch_elapsed_us.add(commit_timer.read().asMicros());
    }

    /// For each slot in the slot_meta_working_set which has any change, include
    /// corresponding updates to schema.slot_meta via the specified `write_batch`.
    /// The `write_batch` will later be atomically committed to the ledger.
    ///
    /// Arguments:
    /// - `slot_meta_working_set`: a map that maintains slot-id to its `SlotMeta`
    ///   mapping.
    /// - `completed_slot_senders`: the units which are responsible for sending
    ///   signals for completed slots.
    /// - `write_batch`: the write batch which includes all the updates of the
    ///   the current write and ensures their atomicity.
    ///
    /// On success, the function returns an Ok result with <should_signal,
    /// newly_completed_slots> pair where:
    ///  - `should_signal`: a boolean flag indicating whether to send signal.
    ///  - `newly_completed_slots`: a subset of slot_meta_working_set which are
    ///    newly completed.
    ///
    /// agave: commit_slot_meta_working_set
    fn commitSlotMetaWorkingSet(
        self: *Self,
        allocator: Allocator,
        completed_slots_senders: []const void, // TODO
    ) !struct { bool, ArrayList(u64) } {
        var should_signal = false;
        var newly_completed_slots = ArrayList(u64).init(allocator);

        // Check if any metadata was changed, if so, insert the new version of the
        // metadata into the write batch
        var iter = self.slot_meta_working_set.iterator();
        while (iter.next()) |entry| {
            // Any slot that wasn't written to should have been filtered out by now.
            std.debug.assert(entry.value_ptr.did_insert_occur);
            const slot_meta = &entry.value_ptr.new_slot_meta;
            const backup = &entry.value_ptr.old_slot_meta;
            if (completed_slots_senders.len > 0 and isNewlyCompletedSlot(slot_meta, backup)) {
                try newly_completed_slots.append(entry.key_ptr.*);
            }
            // Check if the working copy of the metadata has changed
            if (backup.* == null or !(&backup.*.?).eql(slot_meta)) {
                should_signal = should_signal or slotHasUpdates(slot_meta, backup);
                try self.write_batch.put(schema.slot_meta, entry.key_ptr.*, slot_meta.*);
            }
        }

        return .{ should_signal, newly_completed_slots };
    }

    fn persistWorkingEntries(
        write_batch: *WriteBatch,
        cf: ColumnFamily,
        /// Map(cf.Key, WorkingEntry(cf.Value))
        working_entries_map: anytype,
    ) !void {
        var iterator = working_entries_map.iterator();
        while (iterator.next()) |entry| {
            const key = entry.key_ptr.*;
            const value = entry.value_ptr;
            if (value.* == .dirty) {
                try write_batch.put(cf, key, value.asRef().*);
            }
        }
    }
};

pub const MerkleRootMetaWorkingStore = struct {
    allocator: Allocator,
    db: *LedgerDB,
    working_entries: *AutoHashMap(ErasureSetId, WorkingEntry(MerkleRootMeta)),

    const Self = @This();

    pub fn get(self: Self, id: ErasureSetId) !?MerkleRootMeta {
        return if (self.working_entries.get(id)) |nes|
            nes.asRef().*
        else
            try self.db.get(self.allocator, schema.merkle_root_meta, id);
    }

    // TODO: should this actually be called externally?
    // consider moving this logic into a getOrPut-style method
    pub fn load(self: Self, erasure_set_id: ErasureSetId) !void {
        if (!self.working_entries.contains(erasure_set_id)) {
            if (try self.db.get(self.allocator, schema.merkle_root_meta, erasure_set_id)) |meta_| {
                try self.working_entries.put(erasure_set_id, .{ .clean = meta_ });
            }
        }
    }

    // TODO: should this actually be called externally?
    pub fn initIfMissing(self: Self, erasure_set_id: ErasureSetId, shred: anytype) !void {
        const entry = try self.working_entries.getOrPut(erasure_set_id);
        if (!entry.found_existing) {
            entry.value_ptr.* = .{ .dirty = MerkleRootMeta.fromFirstReceivedShred(shred) };
        }
    }
};

pub const ErasureMetaWorkingStore = struct {
    allocator: Allocator,
    db: *LedgerDB,
    working_entries: *SortedMap(ErasureSetId, WorkingEntry(ErasureMeta), .{}),

    const Self = @This();

    pub fn get(self: Self, id: ErasureSetId) !?MerkleRootMeta {
        return if (self.working_entries.get(id)) |nes|
            nes.asRef().*
        else if (try self.db.get(self.allocator, schema.erasure_meta, id)) |nes|
            nes;
    }

    pub fn getOrPut(
        self: Self,
        erasure_set_id: ErasureSetId,
        code_shred: CodeShred,
    ) !*const ErasureMeta {
        const erasure_meta_entry = try self.working_entries.getOrPut(self.allocator, erasure_set_id);
        if (!erasure_meta_entry.found_existing) {
            if (try self.db.get(self.allocator, schema.erasure_meta, erasure_set_id)) |meta_| {
                erasure_meta_entry.value_ptr.* = .{ .clean = meta_ };
            } else {
                erasure_meta_entry.value_ptr.* = .{
                    .dirty = ErasureMeta.fromCodeShred(code_shred) orelse return error.Unwrap,
                };
            }
        }
        return erasure_meta_entry.value_ptr.asRef();
    }

    // TODO: should this actually be called externally?
    // consider moving this logic into a getOrPut-style method
    pub fn load(self: Self, erasure_set_id: ErasureSetId) !void {
        if (!self.working_entries.contains(erasure_set_id)) {
            if (try self.db.get(self.allocator, schema.erasure_meta, erasure_set_id)) |meta_| {
                try self.working_entries.put(self.allocator, erasure_set_id, .{ .clean = meta_ });
            }
        }
    }

    /// agave: previous_erasure_set
    pub fn previousSet(
        self: Self,
        erasure_set: ErasureSetId,
    ) !?struct { ErasureSetId, ErasureMeta } { // TODO: agave uses CoW here
        const slot = erasure_set.slot;
        const erasure_set_index = erasure_set.erasure_set_index;

        // Check the previous entry from the in memory map to see if it is the consecutive
        // set to `erasure set`

        {
            var iter = self.working_entries.iteratorRanged(
                .{ .slot = slot, .erasure_set_index = 0 },
                erasure_set,
                .end,
            );

            if (iter.prev()) |entry| {
                const last_meta = entry.value_ptr.asRef();
                if (@as(u32, @intCast(erasure_set_index)) == last_meta.nextErasureSetIndex()) {
                    return .{ entry.key_ptr.*, last_meta.* };
                }
            }
        }

        // Consecutive set was not found in memory, scan ledger for a potential candidate
        const key_serializer = ledger.database.key_serializer;
        const value_serializer = ledger.database.value_serializer;
        var iter = try self.db.iterator(schema.erasure_meta, .reverse, erasure_set);
        defer iter.deinit();
        const candidate_set: ErasureSetId, //
        const candidate: ErasureMeta //
        = while (try iter.nextBytes()) |entry| {
            defer for (entry) |e| e.deinit();
            const key = try key_serializer.deserialize(ErasureSetId, self.allocator, entry[0].data);
            if (key.slot != slot) return null;
            if (key.erasure_set_index != erasure_set_index) break .{
                key,
                try value_serializer.deserialize(ErasureMeta, self.allocator, entry[1].data),
            };
        } else return null;

        // Check if this is actually the consecutive erasure set
        const next = if (candidate.nextErasureSetIndex()) |n| n else return error.InvalidErasureConfig;
        return if (next == erasure_set_index)
            .{ candidate_set, candidate }
        else
            return null;
    }
};

pub const DuplicateShredsWorkingStore = struct {
    db: *LedgerDB,
    duplicate_shreds: *std.ArrayList(PossibleDuplicateShred),

    const Self = DuplicateShredsWorkingStore;

    pub fn contains(self: Self, slot: Slot) !bool {
        return try self.db.contains(schema.duplicate_slots, slot);
    }

    pub fn append(self: Self, dupe: PossibleDuplicateShred) !void {
        try self.duplicate_shreds.append(dupe);
    }
};

pub fn WorkingEntry(comptime T: type) type {
    return union(enum) {
        // Value has been modified with respect to the ledger column
        dirty: T,
        // Value matches what is currently in the ledger column
        clean: T,

        pub fn asRef(self: *const @This()) *const T {
            return switch (self.*) {
                .dirty => &self.dirty,
                .clean => &self.clean,
            };
        }
    };
}

pub const IndexMetaWorkingSetEntry = struct {
    index: meta.Index,
    // true only if at least one shred for this Index was inserted since the time this
    // struct was created
    did_insert_occur: bool = false,

    pub fn init(slot: Slot) IndexMetaWorkingSetEntry {
        return .{ .index = meta.Index.init(slot) };
    }

    pub fn deinit(self: *IndexMetaWorkingSetEntry, allocator: std.mem.Allocator) void {
        self.index.deinit(allocator);
    }
};

/// The in-memory data structure for updating entries in the column family
/// [`SlotMeta`].
pub const SlotMetaWorkingSetEntry = struct {
    /// The dirty version of the `SlotMeta` which might not be persisted
    /// to the ledger yet.
    new_slot_meta: SlotMeta,
    /// The latest version of the `SlotMeta` that was persisted in the
    /// ledger.  If None, it means the current slot is new to the
    /// ledger.
    old_slot_meta: ?SlotMeta = null,
    /// True only if at least one shred for this SlotMeta was inserted since
    /// this struct was created.
    did_insert_occur: bool = false,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        self.new_slot_meta.deinit(allocator);
        if (self.old_slot_meta) |*old| old.deinit(allocator);
    }
};

pub const PossibleDuplicateShred = union(enum) {
    /// Ledger has another shred in its spot
    Exists: Shred,
    /// The index of this shred conflicts with `slot_meta.last_index`
    LastIndexConflict: ShredConflict,
    /// The code shred has a conflict in the erasure_meta
    ErasureConflict: ShredConflict,
    /// Merkle root conflict in the same fec set
    MerkleRootConflict: ShredConflict,
    /// Merkle root chaining conflict with previous fec set
    ChainedMerkleRootConflict: ShredConflict,

    pub fn deinit(self: PossibleDuplicateShred) void {
        switch (self) {
            inline else => |conflict| conflict.deinit(),
        }
    }
};

const ShredConflict = struct {
    original: Shred,
    conflict: BytesRef,

    pub fn deinit(self: ShredConflict) void {
        self.original.deinit();
        self.conflict.deinit();
    }
};

pub const ShredWorkingStore = struct {
    logger: sig.trace.Logger(@typeName(Self)),
    db: *LedgerDB,
    just_inserted_shreds: *const AutoHashMap(ShredId, Shred),

    const Self = @This();

    /// returned shred lifetime does not exceed this struct
    /// you should call deinit on the returned data
    pub fn get(self: Self, id: ShredId) !?BytesRef {
        if (self.just_inserted_shreds.get(id)) |shred| {
            return .{ .data = shred.payload(), .deinitializer = null };
        }
        return switch (id.shred_type) {
            .data => self.getFromDb(schema.data_shred, id),
            .code => self.getFromDb(schema.code_shred, id),
        };
    }

    /// Returned shred is owned by the caller (you must deinit it)
    /// This does almost the same thing as `get` and may not actually be necessary.
    /// This just adds a check on the index and evaluates the cf at comptime instead of runtime.
    pub fn getWithIndex(
        self: Self,
        allocator: Allocator,
        index: *const ShredIndex,
        comptime shred_type: sig.ledger.shred.ShredType,
        slot: Slot,
        shred_index: u64,
    ) !?Shred {
        const cf = switch (shred_type) {
            .data => schema.data_shred,
            .code => schema.code_shred,
        };
        const id = ShredId{ .slot = slot, .index = @intCast(shred_index), .shred_type = shred_type };
        return if (self.just_inserted_shreds.get(id)) |shred|
            try shred.clone() // TODO perf - avoid clone without causing memory issues
        else if (index.contains(shred_index)) blk: {
            const shred = try self.db.getBytes(cf, .{ slot, @intCast(id.index) }) orelse {
                self.logger.err().logf(&newlinesToSpaces(
                    \\Unable to read the {s} with slot {}, index {} for shred
                    \\recovery. The shred is marked present in the slot's index,
                    \\but the shred could not be found in the column.
                ), .{ cf.name, slot, shred_index });
                return null;
            };
            defer shred.deinit();
            break :blk try Shred.fromPayload(allocator, shred.data);
        } else null;
    }

    fn getFromDb(self: Self, comptime cf: ColumnFamily, id: ShredId) !?BytesRef {
        return try self.db.getBytes(cf, .{ id.slot, @intCast(id.index) });
    }
};

/// agave: is_newly_completed_slot
pub fn isNewlyCompletedSlot(slot_meta: *const SlotMeta, backup_slot_meta: *const ?SlotMeta) bool {
    return slot_meta.isFull() and ( //
        backup_slot_meta.* == null or
            slot_meta.consecutive_received_from_0 !=
                (backup_slot_meta.*.?).consecutive_received_from_0);
    // TODO unreachable: explain or fix
}

/// Returns a boolean indicating whether a slot has received additional shreds
/// that can be replayed since the previous update to the slot's SlotMeta.
/// agave: slot_has_updates
fn slotHasUpdates(slot_meta: *const SlotMeta, slot_meta_backup: *const ?SlotMeta) bool {
    // First, this slot's parent must be connected in order to even consider
    // starting replay; otherwise, the replayed results may not be valid.
    return slot_meta.isParentConnected() and
        // Then,
        // If the slot didn't exist in the db before, any consecutive shreds
        // at the start of the slot are ready to be replayed.
        ((slot_meta_backup.* == null and slot_meta.consecutive_received_from_0 != 0) or
            // Or,
            // If the slot has more consecutive shreds than it last did from the
            // last update, those shreds are new and also ready to be replayed.
            (slot_meta_backup.* != null and
                slot_meta_backup.*.?.consecutive_received_from_0 !=
                    slot_meta.consecutive_received_from_0));
}
