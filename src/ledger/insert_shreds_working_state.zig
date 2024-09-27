const std = @import("std");
const sig = @import("../sig.zig");

const ledger = sig.ledger;
const meta = ledger.meta;
const schema = ledger.schema.schema;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const AutoHashMap = std.AutoHashMap;

const Slot = sig.core.Slot;
const SortedMap = sig.utils.collections.SortedMap;
const Timer = sig.time.Timer;

const BlockstoreDB = ledger.blockstore.BlockstoreDB;
const BlockstoreInsertionMetrics = ledger.insert_shred.BlockstoreInsertionMetrics;
const CodeShred = ledger.shred.CodeShred;
const ColumnFamily = ledger.database.ColumnFamily;
const ErasureSetId = ledger.shred.ErasureSetId;
const Shred = ledger.shred.Shred;
const ShredId = ledger.shred.ShredId;
const WriteBatch = BlockstoreDB.WriteBatch;

const ErasureMeta = meta.ErasureMeta;
const Index = meta.Index;
const MerkleRootMeta = meta.MerkleRootMeta;
const ShredIndex = meta.ShredIndex;
const SlotMeta = meta.SlotMeta;

const newlinesToSpaces = sig.utils.fmt.newlinesToSpaces;

/// Working state that lives for a single call to ShredInserter.insertShreds.
///
/// This struct is responsible for tracking working entries for items that need to be loaded
/// from the database if they are present there, otherwise initialized to some default value.
/// Then, they need to be used throughout the lifetime of the insertShreds call (when they may
/// or may not be mutated). And at the end, they need to be persisted into the database.
///
/// This struct should not have any business logic about how to verify shreds or anything like
/// that. It is only used for negotiating state between the database and working sets.
///
/// Only intended for use within a single thread
pub const InsertShredsWorkingState = struct {
    allocator: Allocator,
    logger: sig.trace.Logger,
    db: *BlockstoreDB,
    write_batch: WriteBatch,
    just_inserted_shreds: AutoHashMap(ShredId, Shred),
    erasure_metas: SortedMap(ErasureSetId, WorkingEntry(ErasureMeta)),
    merkle_root_metas: AutoHashMap(ErasureSetId, WorkingEntry(MerkleRootMeta)),
    slot_meta_working_set: AutoHashMap(u64, SlotMetaWorkingSetEntry),
    index_working_set: AutoHashMap(u64, IndexMetaWorkingSetEntry),
    duplicate_shreds: ArrayList(PossibleDuplicateShred),
    metrics: BlockstoreInsertionMetrics,

    // TODO unmanaged

    const Self = @This();

    // TODO add param for metrics
    pub fn init(allocator: Allocator, logger: sig.trace.Logger, db: *BlockstoreDB) !Self {
        return .{
            .allocator = allocator,
            .db = db,
            .logger = logger,
            .write_batch = try db.initWriteBatch(),
            .just_inserted_shreds = AutoHashMap(ShredId, Shred).init(allocator), // TODO capacity = shreds.len
            .erasure_metas = SortedMap(ErasureSetId, WorkingEntry(ErasureMeta)).init(allocator),
            .merkle_root_metas = AutoHashMap(ErasureSetId, WorkingEntry(MerkleRootMeta)).init(allocator),
            .slot_meta_working_set = AutoHashMap(u64, SlotMetaWorkingSetEntry).init(allocator),
            .index_working_set = AutoHashMap(u64, IndexMetaWorkingSetEntry).init(allocator),
            .duplicate_shreds = ArrayList(PossibleDuplicateShred).init(allocator),
            .metrics = try BlockstoreInsertionMetrics.init(sig.prometheus.globalRegistry()),
        };
    }

    pub fn deinit(self: *Self) void {
        self.just_inserted_shreds.deinit();
        self.erasure_metas.deinit();
        self.merkle_root_metas.deinit();
        deinitMapRecursive(&self.slot_meta_working_set);
        deinitMapRecursive(&self.index_working_set);
        self.duplicate_shreds.deinit();
        self.write_batch.deinit();
    }

    pub fn getOrPutErasureMeta(
        self: *Self,
        erasure_set_id: ErasureSetId,
        code_shred: CodeShred,
    ) !*const ErasureMeta {
        const erasure_meta_entry = try self.erasure_metas.getOrPut(erasure_set_id);
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

    /// agave: get_index_meta_entry
    pub fn getIndexMetaEntry(self: *Self, slot: Slot) !*IndexMetaWorkingSetEntry {
        var timer = try Timer.start();
        const entry = try self.index_working_set.getOrPut(slot);
        if (!entry.found_existing) {
            // TODO lifetimes (conflicting?)
            if (try self.db.get(self.allocator, schema.index, slot)) |item| {
                entry.value_ptr.* = .{ .index = item };
            } else {
                entry.value_ptr.* = IndexMetaWorkingSetEntry.init(self.allocator, slot);
            }
        }
        self.metrics.index_meta_time_us.add(timer.read().asMicros());
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
                    .new_slot_meta = SlotMeta.init(self.allocator, slot, parent_slot),
                };
            }
        }
        return entry.value_ptr;
    }

    pub fn shredStore(self: *Self) WorkingShredStore {
        return .{
            .logger = self.logger,
            .db = self.db,
            .just_inserted_shreds = &self.just_inserted_shreds,
        };
    }

    // TODO: should this actually be called externally?
    // consider moving this logic into a getOrPut-style method
    pub fn loadErasureMeta(self: *Self, erasure_set_id: ErasureSetId) !void {
        if (!self.erasure_metas.contains(erasure_set_id)) {
            if (try self.db.get(self.allocator, schema.erasure_meta, erasure_set_id)) |meta_| {
                try self.erasure_metas.put(erasure_set_id, .{ .clean = meta_ });
            }
        }
    }

    // TODO: should this actually be called externally?
    // consider moving this logic into a getOrPut-style method
    pub fn loadMerkleRootMeta(self: *Self, erasure_set_id: ErasureSetId) !void {
        if (!self.merkle_root_metas.contains(erasure_set_id)) {
            if (try self.db.get(self.allocator, schema.merkle_root_meta, erasure_set_id)) |meta_| {
                try self.merkle_root_metas.put(erasure_set_id, .{ .clean = meta_ });
            }
        }
    }

    // TODO: should this actually be called externally?
    pub fn initMerkleRootMetaIfMissing(
        self: *Self,
        erasure_set_id: ErasureSetId,
        shred: anytype,
    ) !void {
        const entry = try self.merkle_root_metas.getOrPut(erasure_set_id);
        if (!entry.found_existing) {
            entry.value_ptr.* = .{ .dirty = MerkleRootMeta.fromFirstReceivedShred(shred) };
        }
    }

    pub fn commit(self: *Self) !void {
        var commit_working_sets_timer = try Timer.start();

        // TODO: inputs and outputs of this function may need to be fleshed out
        // as the blockstore is used more throughout the codebase.
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

        self.metrics.insert_working_sets_elapsed_us.add(commit_working_sets_timer.read().asMicros());

        var commit_timer = try Timer.start();
        try self.db.commit(self.write_batch);
        self.metrics.write_batch_elapsed_us.add(commit_timer.read().asMicros());
    }

    /// For each slot in the slot_meta_working_set which has any change, include
    /// corresponding updates to schema.slot_meta via the specified `write_batch`.
    /// The `write_batch` will later be atomically committed to the blockstore.
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

pub fn WorkingEntry(comptime T: type) type {
    return union(enum) {
        // Value has been modified with respect to the blockstore column
        dirty: T,
        // Value matches what is currently in the blockstore column
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

    pub fn init(allocator: std.mem.Allocator, slot: Slot) IndexMetaWorkingSetEntry {
        return .{ .index = meta.Index.init(allocator, slot) };
    }

    pub fn deinit(self: *IndexMetaWorkingSetEntry) void {
        self.index.deinit();
    }
};

/// The in-memory data structure for updating entries in the column family
/// [`SlotMeta`].
pub const SlotMetaWorkingSetEntry = struct {
    /// The dirty version of the `SlotMeta` which might not be persisted
    /// to the blockstore yet.
    new_slot_meta: SlotMeta,
    /// The latest version of the `SlotMeta` that was persisted in the
    /// blockstore.  If None, it means the current slot is new to the
    /// blockstore.
    old_slot_meta: ?SlotMeta = null,
    /// True only if at least one shred for this SlotMeta was inserted since
    /// this struct was created.
    did_insert_occur: bool = false,

    pub fn deinit(self: *@This()) void {
        self.new_slot_meta.deinit();
        if (self.old_slot_meta) |*old| old.deinit();
    }
};

pub const PossibleDuplicateShred = union(enum) {
    Exists: Shred, // Blockstore has another shred in its spot
    LastIndexConflict: ShredConflict, // The index of this shred conflicts with `slot_meta.last_index`
    ErasureConflict: ShredConflict, // The code shred has a conflict in the erasure_meta
    MerkleRootConflict: ShredConflict, // Merkle root conflict in the same fec set
    ChainedMerkleRootConflict: ShredConflict, // Merkle root chaining conflict with previous fec set
};

const ShredConflict = struct {
    original: Shred,
    conflict: []const u8,
};

pub const WorkingShredStore = struct {
    logger: sig.trace.Logger,
    db: *BlockstoreDB,
    just_inserted_shreds: *const AutoHashMap(ShredId, Shred),

    const Self = @This();

    // TODO consider lifetime -> return must inform a conditional deinit
    pub fn get(self: Self, id: ShredId) !?[]const u8 {
        if (self.just_inserted_shreds.get(id)) |shred| {
            return shred.payload(); // owned by map
        }
        return switch (id.shred_type) {
            // owned by database
            .data => self.getFromDb(schema.data_shred, id),
            .code => self.getFromDb(schema.code_shred, id),
        };
    }

    // TODO consider lifetime -> return may be owned by different contexts
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
            shred
        else if (index.contains(shred_index)) blk: {
            const shred = try self.db.getBytes(cf, .{ slot, @intCast(id.index) }) orelse {
                self.logger.errf(&newlinesToSpaces(
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

    fn getFromDb(self: Self, comptime cf: ColumnFamily, id: ShredId) !?[]const u8 {
        return if (try self.db.getBytes(cf, .{ id.slot, @intCast(id.index) })) |s|
            s.data
        else
            null;
    }
};

pub fn deinitMapRecursive(map: anytype) void {
    var iter = map.iterator();
    while (iter.next()) |entry| {
        entry.value_ptr.deinit();
    }
    map.deinit();
}

/// agave: is_newly_completed_slot
pub fn isNewlyCompletedSlot(slot_meta: *const SlotMeta, backup_slot_meta: *const ?SlotMeta) bool {
    return slot_meta.isFull() and ( //
        backup_slot_meta.* == null or
        slot_meta.consecutive_received_from_0 !=
        (backup_slot_meta.* orelse unreachable).consecutive_received_from_0);
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
