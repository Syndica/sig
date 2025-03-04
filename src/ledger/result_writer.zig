pub const std = @import("std");
pub const sig = @import("../sig.zig");
pub const ledger = @import("lib.zig");

// std
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;

// sig common
const Hash = sig.core.Hash;
const Histogram = sig.prometheus.Histogram;
const Logger = sig.trace.Logger;
const ScopedLogger = sig.trace.ScopedLogger;
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.RwMux;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const Timer = sig.time.Timer;

// ledger
const AncestorIterator = ledger.reader.AncestorIterator;
const BlockstoreDB = ledger.blockstore.BlockstoreDB;
const FrozenHashVersioned = ledger.meta.FrozenHashVersioned;
const FrozenHashStatus = ledger.meta.FrozenHashStatus;
const SlotMeta = ledger.meta.SlotMeta;
const TransactionStatusMeta = ledger.transaction_status.TransactionStatusMeta;

const schema = ledger.schema.schema;

/// Persist the results of executing a transaction, executing a block,
/// or reaching consensus on a block.
pub const LedgerResultWriter = struct {
    allocator: Allocator,
    logger: ScopedLogger(@typeName(Self)),
    db: BlockstoreDB,
    // TODO: change naming to 'highest_slot_cleaned'
    lowest_cleanup_slot: *RwMux(Slot),
    max_root: *std.atomic.Value(Slot),
    scan_and_fix_roots_metrics: ScanAndFixRootsMetrics,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        db: BlockstoreDB,
        registry: *sig.prometheus.Registry(.{}),
        lowest_cleanup_slot: *RwMux(Slot),
        max_root: *std.atomic.Value(Slot),
    ) !LedgerResultWriter {
        return .{
            .allocator = allocator,
            .logger = logger.withScope(@typeName(Self)),
            .db = db,
            .lowest_cleanup_slot = lowest_cleanup_slot,
            .max_root = max_root,
            .scan_and_fix_roots_metrics = try registry.initStruct(ScanAndFixRootsMetrics),
        };
    }

    /// agave: write_transaction_status
    pub fn writeTransactionStatus(
        self: *Self,
        slot: Slot,
        signature: Signature,
        writeable_keys: ArrayList(Pubkey),
        readonly_keys: ArrayList(Pubkey),
        status: TransactionStatusMeta,
        transaction_index: usize,
    ) !void {
        try self.db.put(schema.transaction_status, .{ signature, slot }, status);
        inline for (.{ writeable_keys, readonly_keys }, .{ true, false }) |keys, writeable| {
            for (keys.items) |address| {
                try self.db.put(
                    schema.address_signatures,
                    .{
                        .address = address,
                        .slot = slot,
                        .transaction_index = @intCast(transaction_index),
                        .signature = signature,
                    },
                    .{ .writeable = writeable },
                );
            }
        }
    }

    /// agave: insert_bank_hash
    pub fn insertBankHash(
        self: *Self,
        slot: Slot,
        frozen_hash: Hash,
        is_duplicate_confirmed: bool,
    ) !void {
        if (try self.db.get(self.allocator, schema.bank_hash, slot)) |prev_value| {
            if (frozen_hash.eql(prev_value.frozenHash()) and prev_value.isDuplicateConfirmed()) {
                // Don't overwrite is_duplicate_confirmed == true with is_duplicate_confirmed == false,
                // which may happen on startup when procesing from blockstore processor because the
                // blocks may not reflect earlier observed gossip votes from before the restart.
                return;
            }
        }
        const data = FrozenHashVersioned{ .current = FrozenHashStatus{
            .frozen_hash = frozen_hash,
            .is_duplicate_confirmed = is_duplicate_confirmed,
        } };
        try self.db.put(schema.bank_hash, slot, data);
    }

    /// agave: set_duplicate_confirmed_slots_and_hashes
    pub fn setDuplicateConfirmedSlotsAndHashes(
        self: *Self,
        duplicate_confirmed_slot_hashes: []struct { Slot, Hash },
    ) !void {
        var write_batch = try self.db.initWriteBatch();
        for (duplicate_confirmed_slot_hashes) |slot_hash| {
            const slot, const frozen_hash = slot_hash;
            const data = FrozenHashVersioned{ .current = FrozenHashStatus{
                .frozen_hash = frozen_hash,
                .is_duplicate_confirmed = true,
            } };
            try write_batch.put(schema.bank_hash, slot, data);
        }
        try self.db.commit(&write_batch);
    }

    /// agave: set_roots
    pub fn setRoots(self: *Self, rooted_slots: []const Slot) !void {
        var write_batch = try self.db.initWriteBatch();
        defer write_batch.deinit();
        var max_new_rooted_slot: Slot = 0;
        for (rooted_slots) |slot| {
            max_new_rooted_slot = @max(max_new_rooted_slot, slot);
            try write_batch.put(schema.rooted_slots, slot, true);
        }

        try self.db.commit(&write_batch);
        _ = self.max_root.fetchMax(max_new_rooted_slot, .monotonic);
    }

    /// agave: mark_slots_as_if_rooted_normally_at_startup
    pub fn markSlotsAsIfRootedNormallyAtStartup(
        self: *Self,
        slot_maybe_hashes: []struct { Slot, ?Hash },
        with_hash: bool,
    ) !void {
        var slots = try ArrayList(Slot).initCapacity(self.allocator, slot_maybe_hashes.len);
        defer slots.deinit();
        for (slot_maybe_hashes) |slot_hash| {
            slots.appendAssumeCapacity(slot_hash[0]);
        }
        try self.setRoots(slots.items);
        if (with_hash) {
            var slot_hashes = try ArrayList(struct { Slot, Hash })
                .initCapacity(self.allocator, slot_maybe_hashes.len);
            defer slot_hashes.deinit();
            for (slot_maybe_hashes) |slot_hash| {
                const slot, const maybe_hash = slot_hash;
                slot_hashes.appendAssumeCapacity(.{
                    slot,
                    maybe_hash orelse return error.MissingHash,
                });
            }
            try self.setDuplicateConfirmedSlotsAndHashes(slot_hashes.items);
        }
    }

    /// Scan for any ancestors of the supplied `start_root` that are not
    /// marked as roots themselves. Mark any found slots as roots since
    /// the ancestor of a root is also inherently a root. Returns the
    /// number of slots that were actually updated.
    ///
    /// NOTE: with correct usage, start_root should be greater than end_slot. since
    /// we iterate from start_root to end_slot using the `parent_slot` field.
    ///
    /// Arguments:
    ///  - `start_root`: The root to start scan from, or the highest root in
    ///    the blockstore if this value is `None`. This slot must be a root.
    ///  - `end_slot``: The slot to stop the scan at; the scan will continue to
    ///    the earliest slot in the Blockstore if this value is `None`.
    ///  - `exit`: Exit early if this flag is set to `true`.
    /// agave: scan_and_fix_roots
    pub fn scanAndFixRoots(
        self: *Self,
        maybe_start_root: ?Slot,
        maybe_end_slot: ?Slot,
        exit: std.atomic.Value(bool),
    ) !usize {
        // Hold the lowest_cleanup_slot read lock to prevent any cleaning of
        // the blockstore from another thread. Doing so will prevent a
        // possible inconsistency across column families where a slot is:
        //  - Identified as needing root repair by this thread
        //  - Cleaned from the blockstore by another thread (LedgerCleanupSerivce)
        //  - Marked as root via Self::set_root() by this this thread
        var lowest_cleanup_slot = self.lowest_cleanup_slot.read();
        defer lowest_cleanup_slot.unlock();

        const start_root = if (maybe_start_root) |slot| blk: {
            if (!try self.isRoot(slot)) {
                return error.SlotNotRooted;
            }
            break :blk slot;
        } else self.max_root.load(.monotonic);
        const end_slot = maybe_end_slot orelse lowest_cleanup_slot.get().*;

        var ancestor_iterator = try AncestorIterator
            .initExclusive(self.allocator, &self.db, start_root);

        var find_missing_roots_timer = try Timer.start();
        var roots_to_fix = ArrayList(Slot).init(self.allocator);
        defer roots_to_fix.deinit();

        while (try ancestor_iterator.next()) |slot| {
            if (slot < end_slot) break;
            if (!try self.isRoot(slot)) {
                try roots_to_fix.append(slot);
            }
            if (exit.load(.acquire)) {
                return 0;
            }
        }
        const find_missing_roots_us = find_missing_roots_timer.read().asMicros();
        var fix_roots_timer = try Timer.start();
        if (roots_to_fix.items.len != 0) {
            self.logger.info().logf("{} slots to be rooted", .{roots_to_fix.items.len});
            const chunk_size = 100;
            const num_chunks = (roots_to_fix.items.len - 1) / chunk_size + 1;
            for (0..num_chunks) |chunk_index| {
                if (exit.load(.acquire)) {
                    return chunk_index * chunk_size;
                }
                const start_index = chunk_index * chunk_size;
                const end_index = @min(roots_to_fix.items.len, (chunk_index + 1) * chunk_size);
                const chunk = roots_to_fix.items[start_index..end_index];
                // self.logger.tracef("{any}", .{chunk});
                try self.setRoots(chunk);
            }
        } else {
            self.logger.debug().logf("No missing roots found in range {} to {}", .{ start_root, end_slot });
        }
        const fix_roots_us = fix_roots_timer.read().asMicros();
        const num_roots_fixed = roots_to_fix.items.len;

        self.scan_and_fix_roots_metrics.fix_roots_us.observe(fix_roots_us);
        self.scan_and_fix_roots_metrics.find_missing_roots_us.observe(find_missing_roots_us);
        self.scan_and_fix_roots_metrics.num_roots_to_fix.observe(roots_to_fix.items.len);

        return num_roots_fixed;
    }

    /// Mark a root `slot` as connected, traverse `slot`'s children and update
    /// the children's connected status if appropriate.
    ///
    /// A ledger with a full path of blocks from genesis to the latest root will
    /// have all of the rooted blocks marked as connected such that new blocks
    /// could also be connected. However, starting from some root (such as from
    /// a snapshot) is a valid way to join a cluster. For this case, mark this
    /// root as connected such that the node that joined midway through can
    /// have their slots considered connected.
    /// agave: set_and_chain_connected_on_root_and_next_slots
    pub fn setAndChainConnectedOnRootAndNextSlots(self: *Self, root: Slot) !void {
        var root_slot_meta: SlotMeta = try self.db.get(self.allocator, schema.slot_meta, root) orelse
            SlotMeta.init(self.allocator, root, null);
        defer root_slot_meta.deinit();

        // If the slot was already connected, there is nothing to do as this slot's
        // children are also assumed to be appropriately connected
        if (root_slot_meta.isConnected()) {
            return;
        }
        self.logger.info().logf("Marking slot {} and any full children slots as connected", .{root});
        var write_batch = try self.db.initWriteBatch();
        defer write_batch.deinit();

        // Mark both connected bits on the root slot so that the flags for this
        // slot match the flags of slots that become connected the typical way.
        _ = root_slot_meta.setParentConnected();
        root_slot_meta.setConnected();
        try write_batch.put(schema.slot_meta, root_slot_meta.slot, root_slot_meta);

        var child_slots = try ArrayList(Slot)
            .initCapacity(self.allocator, root_slot_meta.child_slots.items.len);
        defer child_slots.deinit();

        child_slots.appendSliceAssumeCapacity(root_slot_meta.child_slots.items);
        var i: usize = 0;
        while (i < child_slots.items.len) : (i += 1) {
            const slot = child_slots.items[i];
            var slot_meta: SlotMeta = try self.db.get(self.allocator, schema.slot_meta, slot) orelse {
                self.logger.err().logf("Slot {} is a child but has no SlotMeta in blockstore", .{slot});
                return error.CorruptedBlockstore;
            };
            defer slot_meta.deinit();

            if (slot_meta.setParentConnected()) {
                try child_slots.appendSlice(slot_meta.child_slots.items);
            }
            try write_batch.put(schema.slot_meta, slot_meta.slot, slot_meta);
        }

        try self.db.commit(&write_batch);
    }

    fn isRoot(self: *Self, slot: Slot) !bool {
        return try self.db.get(self.allocator, schema.rooted_slots, slot) orelse false;
    }
};

pub const ScanAndFixRootsMetrics = struct {
    find_missing_roots_us: *Histogram,
    num_roots_to_fix: *Histogram,
    fix_roots_us: *Histogram,

    pub const prefix = "scan_and_fix_roots";
    pub const histogram_buckets = sig.prometheus.histogram.exponentialBuckets(5, -1, 10);
};

const TestDB = sig.ledger.tests.TestDB;

test "setRoots" {
    const allocator = std.testing.allocator;
    const logger = .noop;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var db = try TestDB.init(@src());
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var writer = LedgerResultWriter{
        .allocator = allocator,
        .db = db,
        .logger = logger,
        .lowest_cleanup_slot = &lowest_cleanup_slot,
        .max_root = &max_root,
        .scan_and_fix_roots_metrics = try registry.initStruct(ScanAndFixRootsMetrics),
    };

    const roots: [5]Slot = .{ 1, 2, 3, 4, 5 };
    try writer.setRoots(&roots);

    for (roots) |slot| {
        const is_root = try writer.isRoot(slot);
        try std.testing.expect(is_root);
    }
}

test "scanAndFixRoots" {
    const allocator = std.testing.allocator;
    const logger = .noop;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var db = try TestDB.init(@src());
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var writer = LedgerResultWriter{
        .allocator = allocator,
        .db = db,
        .logger = logger,
        .lowest_cleanup_slot = &lowest_cleanup_slot,
        .max_root = &max_root,
        .scan_and_fix_roots_metrics = try registry.initStruct(ScanAndFixRootsMetrics),
    };

    // slot = 2 is not a root, but should be!
    const roots: [2]Slot = .{ 1, 3 };
    try writer.setRoots(&roots);

    const slot_meta_1 = SlotMeta.init(allocator, 1, null);
    const slot_meta_2 = SlotMeta.init(allocator, 2, 1);
    const slot_meta_3 = SlotMeta.init(allocator, 3, 2);

    var write_batch = try db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(schema.slot_meta, slot_meta_1.slot, slot_meta_1);
    try write_batch.put(schema.slot_meta, slot_meta_2.slot, slot_meta_2);
    try write_batch.put(schema.slot_meta, slot_meta_3.slot, slot_meta_3);
    try db.commit(&write_batch);

    const exit = std.atomic.Value(bool).init(false);

    try std.testing.expectEqual(false, try writer.isRoot(2));

    const num_fixed = try writer.scanAndFixRoots(3, 1, exit);
    try std.testing.expectEqual(1, num_fixed);
}

test "setAndChainConnectedOnRootAndNextSlots" {
    const allocator = std.testing.allocator;
    const logger = .noop;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var db = try TestDB.init(@src());
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var writer = LedgerResultWriter{
        .allocator = allocator,
        .db = db,
        .logger = logger,
        .lowest_cleanup_slot = &lowest_cleanup_slot,
        .max_root = &max_root,
        .scan_and_fix_roots_metrics = try registry.initStruct(ScanAndFixRootsMetrics),
    };

    // 1 is a root
    const roots: [1]Slot = .{1};
    try writer.setRoots(&roots);
    const slot_meta_1 = SlotMeta.init(allocator, 1, null);
    var write_batch = try db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(schema.slot_meta, slot_meta_1.slot, slot_meta_1);
    try db.commit(&write_batch);

    try std.testing.expectEqual(false, slot_meta_1.isConnected());

    try writer.setAndChainConnectedOnRootAndNextSlots(1);

    // should be connected
    const db_slot_meta_1 = (try db.get(allocator, schema.slot_meta, 1)) orelse
        return error.MissingSlotMeta;
    try std.testing.expectEqual(true, db_slot_meta_1.isConnected());

    // write some roots past 1
    const other_roots: [3]Slot = .{ 2, 3, 4 };
    var parent_slot: ?Slot = 1;
    var write_batch2 = try db.initWriteBatch();
    defer write_batch2.deinit();
    try writer.setRoots(&other_roots);

    for (other_roots, 0..) |slot, i| {
        var slot_meta = SlotMeta.init(allocator, slot, parent_slot);
        defer slot_meta.deinit();

        // ensure isFull() is true
        slot_meta.last_index = 1;
        slot_meta.consecutive_received_from_0 = slot_meta.last_index.? + 1;
        // update next slots
        if (i + 1 < other_roots.len) {
            try slot_meta.child_slots.append(other_roots[i + 1]);
        }

        try write_batch2.put(schema.slot_meta, slot_meta.slot, slot_meta);
        // connect the chain
        parent_slot = slot;
    }
    try db.commit(&write_batch2);

    try writer.setAndChainConnectedOnRootAndNextSlots(other_roots[0]);

    for (other_roots) |slot| {
        var db_slot_meta = (try db.get(allocator, schema.slot_meta, slot)) orelse
            return error.MissingSlotMeta;
        defer db_slot_meta.deinit();
        try std.testing.expectEqual(true, db_slot_meta.isConnected());
    }
}

test "setAndChainConnectedOnRootAndNextSlots: disconnected" {
    const allocator = std.testing.allocator;
    const logger = .noop;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var db = try TestDB.init(@src());
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var writer = LedgerResultWriter{
        .allocator = allocator,
        .db = db,
        .logger = logger,
        .lowest_cleanup_slot = &lowest_cleanup_slot,
        .max_root = &max_root,
        .scan_and_fix_roots_metrics = try registry.initStruct(ScanAndFixRootsMetrics),
    };

    // 1 is a root and full
    var write_batch = try db.initWriteBatch();
    defer write_batch.deinit();
    const roots: [3]Slot = .{ 1, 2, 3 };
    try writer.setRoots(&roots);

    var slot_meta_1 = SlotMeta.init(allocator, 1, null);
    defer slot_meta_1.deinit();
    slot_meta_1.last_index = 1;
    slot_meta_1.consecutive_received_from_0 = 1 + 1;
    try slot_meta_1.child_slots.append(2);
    try write_batch.put(schema.slot_meta, slot_meta_1.slot, slot_meta_1);

    // 2 is not full
    var slot_meta_2 = SlotMeta.init(allocator, 2, 1);
    defer slot_meta_2.deinit();
    slot_meta_2.last_index = 1;
    slot_meta_2.consecutive_received_from_0 = 0; // ! NOT FULL
    try slot_meta_2.child_slots.append(3);
    try write_batch.put(schema.slot_meta, slot_meta_2.slot, slot_meta_2);

    // 3 is full
    var slot_meta_3 = SlotMeta.init(allocator, 3, 2);
    defer slot_meta_3.deinit();
    slot_meta_3.last_index = 1;
    slot_meta_3.consecutive_received_from_0 = 1 + 1;
    try write_batch.put(schema.slot_meta, slot_meta_3.slot, slot_meta_3);

    try db.commit(&write_batch);

    try writer.setAndChainConnectedOnRootAndNextSlots(1);

    // should be connected
    var db_slot_meta_1 = (try db.get(allocator, schema.slot_meta, 1)) orelse
        return error.MissingSlotMeta;
    defer db_slot_meta_1.deinit();
    try std.testing.expectEqual(true, db_slot_meta_1.isConnected());

    var db_slot_meta_2: SlotMeta = (try db.get(allocator, schema.slot_meta, 2)) orelse
        return error.MissingSlotMeta;
    defer db_slot_meta_2.deinit();
    try std.testing.expectEqual(true, db_slot_meta_2.isParentConnected());
    try std.testing.expectEqual(false, db_slot_meta_2.isConnected());

    var db_slot_meta_3: SlotMeta = (try db.get(allocator, schema.slot_meta, 3)) orelse
        return error.MissingSlotMeta;
    defer db_slot_meta_3.deinit();
    try std.testing.expectEqual(false, db_slot_meta_3.isParentConnected());
    try std.testing.expectEqual(false, db_slot_meta_3.isConnected());
}
