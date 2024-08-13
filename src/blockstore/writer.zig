pub const std = @import("std");
pub const sig = @import("../lib.zig");
pub const blockstore = @import("lib.zig");

// std
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const AutoHashMap = std.AutoHashMap;

// sig common
const GetMetricError = sig.prometheus.GetMetricError;
const Hash = sig.core.Hash;
const Histogram = sig.prometheus.Histogram;
const Logger = sig.trace.Logger;
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.RwMux;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const Registry = sig.prometheus.Registry;
const Timer = sig.time.Timer;

// blockstore
const AddressSignatureMeta = blockstore.meta.AddressSignatureMeta;
const AncestorIterator = blockstore.reader.AncestorIterator;
const BlockstoreDB = blockstore.blockstore.BlockstoreDB;
const BlockstoreReader = blockstore.reader.BlockstoreReader;
const FrozenHashVersioned = blockstore.meta.FrozenHashVersioned;
const FrozenHashStatus = blockstore.meta.FrozenHashStatus;
const SlotMeta = blockstore.meta.SlotMeta;
const TransactionStatusMeta = blockstore.transaction_status.TransactionStatusMeta;

const schema = blockstore.schema.schema;

pub const BlockstoreWriter = struct {
    allocator: Allocator,
    logger: Logger,
    db: BlockstoreDB,
    // reader: BlockstoreReader,
    lowest_cleanup_slot: RwMux(Slot), // TODO shared
    max_root: std.atomic.Value(Slot), // TODO shared
    scan_and_fix_roots_metrics: ScanAndFixRootsMetrics,

    const Self = @This();

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
        if (try self.db.get(schema.bank_hash, slot)) |prev_value| {
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
        var write_batch = try self.db.writeBatch();
        for (duplicate_confirmed_slot_hashes) |slot_hash| {
            const slot, const frozen_hash = slot_hash;
            const data = FrozenHashVersioned{ .current = FrozenHashStatus{
                .frozen_hash = frozen_hash,
                .is_duplicate_confirmed = true,
            } };
            try write_batch.put(schema.bank_hash, slot, data);
        }
        try self.db.commit(write_batch);
    }

    /// agave: set_roots
    pub fn setRoots(self: *Self, rooted_slots: []const Slot) !void {
        var write_batch = try self.db.initWriteBatch();
        var max_new_rooted_slot: Slot = 0;
        for (rooted_slots) |slot| {
            max_new_rooted_slot = @max(max_new_rooted_slot, slot);
            try write_batch.put(schema.roots, slot, true);
        }

        try self.db.commit(write_batch);
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
        // NOTE: this travels backwards from the start_root to the end_slot
        var ancestor_iterator = try AncestorIterator.initExclusive(&self.db, start_root);

        var find_missing_roots_timer = try Timer.start();
        var roots_to_fix = ArrayList(Slot).init(self.allocator);
        defer roots_to_fix.deinit();

        while (try ancestor_iterator.next()) |slot| {
            if (slot < end_slot) break;
            const is_rooted = try self.isRoot(slot);
            if (!is_rooted) {
                try roots_to_fix.append(slot);
            }
            if (exit.load(.monotonic)) {
                return 0;
            }
        }
        const find_missing_roots_us = find_missing_roots_timer.read().asMicros();
        var fix_roots_timer = try Timer.start();
        if (roots_to_fix.items.len != 0) {
            self.logger.infof("{} slots to be rooted", .{roots_to_fix.items.len});
            const chunk_size = 100;
            const num_chunks = (roots_to_fix.items.len - 1) / chunk_size + 1;
            for (0..num_chunks) |chunk_index| {
                if (exit.load(.monotonic)) {
                    return chunk_index * chunk_size;
                }
                const start_index = chunk_index * chunk_size;
                const end_index = @min(roots_to_fix.items.len, (chunk_index + 1) * chunk_size);
                const chunk = roots_to_fix.items[start_index..end_index];
                // self.logger.tracef("{any}", .{chunk});
                try self.setRoots(chunk);
            }
        } else {
            self.logger.debugf("No missing roots found in range {} to {}", .{ start_root, end_slot });
        }
        const fix_roots_us = fix_roots_timer.read().asMicros();
        const num_roots_fixed = roots_to_fix.items.len;

        self.scan_and_fix_roots_metrics.fix_roots_us.observe(@floatFromInt(fix_roots_us));
        self.scan_and_fix_roots_metrics.find_missing_roots_us.observe(@floatFromInt(find_missing_roots_us));
        self.scan_and_fix_roots_metrics.num_roots_to_fix.observe(@floatFromInt(roots_to_fix.items.len));

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
        var root_meta: SlotMeta = try self.db.get(schema.slot_meta, root) orelse
            SlotMeta.init(self.allocator, root, null);
        // If the slot was already connected, there is nothing to do as this slot's
        // children are also assumed to be appropriately connected
        if (root_meta.isConnected()) {
            return;
        }
        self.logger.infof("Marking slot {} and any full children slots as connected", .{root});
        var write_batch = try self.db.writeBatch();

        // Mark both connected bits on the root slot so that the flags for this
        // slot match the flags of slots that become connected the typical way.
        _ = root_meta.setParentConnected();
        root_meta.setConnected();
        try write_batch.put(schema.slot_meta, root_meta.slot, root_meta);

        // var next_slots = VecDeque::from(root_meta.next_slots);
        var next_slots = try ArrayList(Slot)
            .initCapacity(self.allocator, root_meta.next_slots.items.len);
        next_slots.appendSliceAssumeCapacity(root_meta.next_slots.items);
        var i: usize = 0;
        while (i < next_slots.items.len) : (i += 1) {
            const slot = next_slots.items[i];
            var meta: SlotMeta = try self.db.get(schema.slot_meta, slot) orelse {
                self.logger.errf("Slot {} is a child but has no SlotMeta in blockstore", .{slot});
                return error.CorruptedBlockstore;
            };
            if (meta.setParentConnected()) {
                try next_slots.appendSlice(meta.next_slots.items);
            }
            try write_batch.put(schema.slot_meta, meta.slot, meta);
        }

        try self.db.commit(write_batch);
    }

    fn isRoot(self: *Self, slot: Slot) !bool {
        return try self.db.get(schema.roots, slot) orelse false;
    }
};

const ScanAndFixRootsMetrics = struct {
    find_missing_roots_us: *Histogram,
    num_roots_to_fix: *Histogram,
    fix_roots_us: *Histogram,

    pub fn init(registry: *Registry(.{})) GetMetricError!ScanAndFixRootsMetrics {
        var self: ScanAndFixRootsMetrics = undefined;
        inline for (@typeInfo(ScanAndFixRootsMetrics).Struct.fields) |field| {
            const name = "scan_and_fix_roots_" ++ field.name;
            @field(self, field.name) = try registry.getOrCreateHistogram(name, &buckets);
        }
        return self;
    }

    const buckets: [11]f64 = blk: {
        var bs: [11]f64 = undefined;
        for (0..11) |i| {
            bs[i] = std.math.pow(f64, 5.0, @as(f64, @floatFromInt(i)) - 1.0);
        }
        break :blk bs;
    };
};

const openTestDb = sig.blockstore.insert_shred.openTestDb;

test "setRoots" {
    const allocator = std.testing.allocator;
    const logger = .noop;
    const registry = sig.prometheus.globalRegistry();

    var state = try openTestDb("setRoots");
    defer state.deinit();
    const db = state.db;

    var writer = BlockstoreWriter{
        .allocator = allocator,
        .db = db,
        .logger = logger,
        .lowest_cleanup_slot = RwMux(Slot).init(0),
        .max_root = std.atomic.Value(Slot).init(0),
        .scan_and_fix_roots_metrics = try ScanAndFixRootsMetrics.init(registry),
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
    const registry = sig.prometheus.globalRegistry();

    var state = try openTestDb("scanAndFixRoots");
    defer state.deinit();
    var db = state.db;

    var writer = BlockstoreWriter{
        .allocator = allocator,
        .db = db,
        .logger = logger,
        .lowest_cleanup_slot = RwMux(Slot).init(0),
        .max_root = std.atomic.Value(Slot).init(0),
        .scan_and_fix_roots_metrics = try ScanAndFixRootsMetrics.init(registry),
    };

    // slot = 2 is not a root, but should be!
    const roots: [2]Slot = .{ 1, 3 };
    try writer.setRoots(&roots);

    const slot_meta_1 = SlotMeta.init(allocator, 1, null);
    const slot_meta_2 = SlotMeta.init(allocator, 2, 1);
    const slot_meta_3 = SlotMeta.init(allocator, 3, 2);

    var write_batch = try db.initWriteBatch();
    try write_batch.put(schema.slot_meta, slot_meta_1.slot, slot_meta_1);
    try write_batch.put(schema.slot_meta, slot_meta_2.slot, slot_meta_2);
    try write_batch.put(schema.slot_meta, slot_meta_3.slot, slot_meta_3);
    try db.commit(write_batch);

    const exit = std.atomic.Value(bool).init(false);

    try std.testing.expectEqual(false, try writer.isRoot(2));

    const num_fixed = try writer.scanAndFixRoots(3, 1, exit);
    try std.testing.expectEqual(1, num_fixed);
}
