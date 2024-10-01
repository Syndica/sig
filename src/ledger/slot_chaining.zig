const std = @import("std");
const sig = @import("../sig.zig");

const ledger = sig.ledger;
const schema = ledger.schema.schema;

const Allocator = std.mem.Allocator;
const AutoHashMap = std.AutoHashMap;

const Slot = sig.core.Slot;

const BlockstoreDB = ledger.blockstore.BlockstoreDB;
const SlotMeta = ledger.meta.SlotMeta;
const SlotMetaWorkingSetEntry = ledger.insert_shred.SlotMetaWorkingSetEntry;
const WriteBatch = BlockstoreDB.WriteBatch;

const deinitMapRecursive = ledger.insert_shred.deinitMapRecursive;
const isNewlyCompletedSlot = ledger.insert_shred.isNewlyCompletedSlot;

/// agave: handle_chaining
pub fn handleChaining(
    allocator: Allocator,
    db: *BlockstoreDB,
    write_batch: *WriteBatch,
    working_set: *AutoHashMap(u64, SlotMetaWorkingSetEntry),
) !void {
    const count = working_set.count();
    if (count == 0) return; // TODO is this correct?

    // filter out slots that were not inserted
    var keys = try allocator.alloc(u64, count);
    defer allocator.free(keys);
    var keep_i: usize = 0;
    var delete_i = count;
    var iter = working_set.iterator();
    while (iter.next()) |entry| {
        if (entry.value_ptr.did_insert_occur) {
            keys[keep_i] = entry.key_ptr.*;
            keep_i += 1;
        } else {
            delete_i -= 1;
            keys[delete_i] = entry.key_ptr.*;
        }
    }
    std.debug.assert(keep_i == delete_i);
    for (keys[delete_i..count]) |k| {
        if (working_set.fetchRemove(k)) |entry| {
            var slot_meta_working_set_entry = entry.value;
            slot_meta_working_set_entry.deinit();
        }
    }

    // handle chaining
    var new_chained_slots = AutoHashMap(u64, SlotMeta).init(allocator);
    defer deinitMapRecursive(&new_chained_slots);
    for (keys[0..keep_i]) |slot| {
        try handleChainingForSlot(allocator, db, write_batch, working_set, &new_chained_slots, slot);
    }

    // Write all the newly changed slots in new_chained_slots to the write_batch
    var new_iter = new_chained_slots.iterator();
    while (new_iter.next()) |entry| {
        try write_batch.put(schema.slot_meta, entry.key_ptr.*, entry.value_ptr.*);
    }
}

/// agave: handle_chaining_for_slot
fn handleChainingForSlot(
    allocator: Allocator,
    db: *BlockstoreDB,
    write_batch: *WriteBatch,
    working_set: *AutoHashMap(u64, SlotMetaWorkingSetEntry),
    new_chained_slots: *AutoHashMap(u64, SlotMeta),
    slot: Slot,
) !void {
    const slot_meta_entry = working_set.getPtr(slot) orelse return error.Unwrap;
    const slot_meta = &slot_meta_entry.new_slot_meta;
    const meta_backup = slot_meta_entry.old_slot_meta;

    const was_orphan_slot = meta_backup != null and meta_backup.?.isOrphan();

    // If:
    // 1) This is a new slot
    // 2) slot != 0
    // then try to chain this slot to a previous slot
    if (slot != 0) if (slot_meta.parent_slot) |prev_slot| {
        // Check if the slot represented by meta_mut is either a new slot or a orphan.
        // In both cases we need to run the chaining logic b/c the parent on the slot was
        // previously unknown.

        if (meta_backup == null or was_orphan_slot) {
            const prev_slot_meta = try findSlotMetaElseCreate(
                allocator,
                db,
                working_set,
                new_chained_slots,
                prev_slot,
            );

            // This is a newly inserted slot/orphan so run the chaining logic to link it to a
            // newly discovered parent
            try chainNewSlotToPrevSlot(prev_slot_meta, slot, slot_meta);

            // If the parent of `slot` is a newly inserted orphan, insert it into the orphans
            // column family
            if (prev_slot_meta.isOrphan()) {
                try write_batch.put(schema.orphans, prev_slot, true);
            }
        }
    };

    // At this point this slot has received a parent, so it's no longer an orphan
    if (was_orphan_slot) {
        try write_batch.delete(schema.orphans, slot);
    }

    // If this is a newly completed slot and the parent is connected, then the
    // slot is now connected. Mark the slot as connected, and then traverse the
    // children to update their parent_connected and connected status.
    if (isNewlyCompletedSlot(slot_meta, &meta_backup) and slot_meta.isParentConnected()) {
        slot_meta.setConnected();
        try traverseChildrenMut(
            allocator,
            db,
            slot_meta.next_slots.items,
            working_set,
            new_chained_slots,
        );
    }
}

/// Returns the `SlotMeta` with the specified `slot_index`.  The resulting
/// `SlotMeta` could be either from the cache or from the DB.  Specifically,
/// the function:
///
/// 1) Finds the slot metadata in the cache of dirty slot metadata we've
///    previously touched, otherwise:
/// 2) Searches the database for that slot metadata. If still no luck, then:
/// 3) Create a dummy orphan slot in the database.
///
/// Also see [`find_slot_meta_in_cached_state`] and [`find_slot_meta_in_db_else_create`].
///
/// agave: find_slot_meta_else_create
fn findSlotMetaElseCreate(
    allocator: Allocator,
    db: *BlockstoreDB,
    working_set: *const AutoHashMap(u64, SlotMetaWorkingSetEntry),
    chained_slots: *AutoHashMap(u64, SlotMeta),
    slot: Slot,
) !*SlotMeta {
    if (working_set.getPtr(slot)) |m| {
        return &m.new_slot_meta;
    }
    const entry = try chained_slots.getOrPut(slot);
    if (entry.found_existing) {
        return entry.value_ptr;
    }
    entry.value_ptr.* = if (try db.get(allocator, schema.slot_meta, slot)) |m|
        m
    else
        SlotMeta.init(allocator, slot, null);
    return entry.value_ptr;
}

/// Traverse all slots and their children (direct and indirect), and apply
/// `setParentConnected` to each.
///
/// Arguments:
/// `db`: the blockstore db that stores shreds and their metadata.
/// `slot_meta`: the SlotMeta of the above `slot`.
/// `working_set`: a slot-id to SlotMetaWorkingSetEntry map which is used
///   to traverse the graph.
/// `passed_visited_slots`: all the traversed slots which have passed the
///   slot_function.  This may also include the input `slot`.
/// `slot_function`: a function which updates the SlotMeta of the visisted
///   slots and determine whether to further traverse the children slots of
///   a given slot.
///
/// agave: traverse_children_mut
fn traverseChildrenMut(
    allocator: Allocator,
    db: *BlockstoreDB,
    slots: []const u64,
    working_set: *AutoHashMap(u64, SlotMetaWorkingSetEntry),
    passed_visited_slots: *AutoHashMap(u64, SlotMeta),
) !void {
    var slot_lists = std.ArrayList([]const u64).init(allocator);
    defer slot_lists.deinit();
    try slot_lists.append(slots);
    var i: usize = 0;
    while (i < slot_lists.items.len) {
        const slot_list = slot_lists.items[i];
        for (slot_list) |slot| {
            const slot_meta = try findSlotMetaElseCreate(
                allocator,
                db,
                working_set,
                passed_visited_slots,
                slot,
            );
            if (slot_meta.setParentConnected()) {
                try slot_lists.append(slot_meta.next_slots.items);
            }
        }
        i += 1;
    }
}

/// agave: chain_new_slot_to_prev_slot
fn chainNewSlotToPrevSlot(
    prev_slot_meta: *SlotMeta,
    current_slot: Slot,
    current_slot_meta: *SlotMeta,
) !void {
    try prev_slot_meta.next_slots.append(current_slot);
    if (prev_slot_meta.isConnected()) {
        _ = current_slot_meta.setParentConnected();
    }
}
