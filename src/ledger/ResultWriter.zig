//! Persist the results of executing a transaction, executing a block,
//! or reaching consensus on a block.

pub const std = @import("std");
pub const sig = @import("../sig.zig");
pub const ledger_mod = @import("lib.zig");

// std
const Allocator = std.mem.Allocator;
const ArrayList = std.array_list.Managed;

// sig common
const Hash = sig.core.Hash;
const Histogram = sig.prometheus.Histogram;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const Timer = sig.time.Timer;

// ledger
const AncestorIterator = ledger_mod.Reader.AncestorIterator;
const LedgerDB = ledger_mod.db.LedgerDB;
const FrozenHashVersioned = ledger_mod.meta.FrozenHashVersioned;
const FrozenHashStatus = ledger_mod.meta.FrozenHashStatus;
const SlotMeta = ledger_mod.meta.SlotMeta;
const TransactionStatusMeta = ledger_mod.transaction_status.TransactionStatusMeta;

const schema = ledger_mod.schema.schema;

ledger: *ledger_mod.Ledger,
logger: sig.trace.Logger("result_writer"),
metrics: ?ScanAndFixRootsMetrics,

const ResultWriter = @This();

pub fn writeTransactionStatus(
    self: *const ResultWriter,
    slot: Slot,
    signature: Signature,
    writeable_keys: ArrayList(Pubkey),
    readonly_keys: ArrayList(Pubkey),
    status: TransactionStatusMeta,
    transaction_index: usize,
) !void {
    try self.ledger.db.put(schema.transaction_status, .{ signature, slot }, status);
    inline for (.{ writeable_keys, readonly_keys }, .{ true, false }) |keys, writeable| {
        for (keys.items) |address| {
            try self.ledger.db.put(
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
    self: *const ResultWriter,
    slot: Slot,
    frozen_hash: Hash,
    is_duplicate_confirmed: bool,
) !void {
    const allocator = sig.utils.allocators.failing.allocator(.{}); // no allocations needed for hash
    if (try self.ledger.db.get(allocator, schema.bank_hash, slot)) |prev_value| {
        if (frozen_hash.eql(prev_value.frozenHash()) and prev_value.isDuplicateConfirmed()) {
            // Don't overwrite is_duplicate_confirmed == true with is_duplicate_confirmed == false,
            // which may happen on startup when procesing from ledger processor because the
            // blocks may not reflect earlier observed gossip votes from before the restart.
            return;
        }
    }
    const data = FrozenHashVersioned{ .current = FrozenHashStatus{
        .frozen_hash = frozen_hash,
        .is_duplicate_confirmed = is_duplicate_confirmed,
    } };
    try self.ledger.db.put(schema.bank_hash, slot, data);
}

/// Analogous to [set_dead_slot](https://github.com/anza-xyz/agave/blob/2a2f6b976d4a7f5cb2b2552564a603e03eba8bae/ledger/src/blockstore.rs#L4028)
pub fn setDeadSlot(
    self: *const ResultWriter,
    slot: Slot,
) !void {
    try self.ledger.db.put(schema.dead_slots, slot, true);
}

/// Store a duplicate slot proof for the given slot.
///
/// Analogous to [store_duplicate_slot](https://github.com/anza-xyz/agave/blob/60ba168d54d7ac6683f8f2e41a0e325f29d9ab2b/ledger/src/blockstore.rs#L4005)
pub fn storeDuplicateSlot(
    self: *const ResultWriter,
    slot: Slot,
    shred1: []const u8,
    shred2: []const u8,
) !void {
    try self.ledger.db.put(schema.duplicate_slots, slot, .{
        .shred1 = shred1,
        .shred2 = shred2,
    });
}

/// agave: set_duplicate_confirmed_slots_and_hashes
pub fn setDuplicateConfirmedSlotsAndHashes(
    self: *const ResultWriter,
    duplicate_confirmed_slot_hashes: []const struct { Slot, Hash },
) !void {
    var setter = try setDuplicateConfirmedSlotsAndHashesIncremental(self);
    defer setter.deinit();
    errdefer setter.cancel();

    for (duplicate_confirmed_slot_hashes) |slot_hash| {
        const slot, const hash = slot_hash;
        try setter.addSlotAndHash(slot, hash);
    }

    try setter.commit();
}

/// Returns a struct which can be used to enact the same operation as `setDuplicateConfirmedSlotsAndHashes`, incrementally.
pub fn setDuplicateConfirmedSlotsAndHashesIncremental(
    self: *const ResultWriter,
) !SetDuplicateConfirmedSlotsAndHashesIncremental {
    return .{
        .result_writer = self,
        .write_batch = try self.ledger.db.initWriteBatch(),
        .is_committed_or_cancelled = false,
    };
}

pub const SetDuplicateConfirmedSlotsAndHashesIncremental = struct {
    result_writer: *const ResultWriter,
    write_batch: LedgerDB.WriteBatch,
    is_committed_or_cancelled: bool,

    /// Asserts that either `self.cancel()` or `self.commit()` has been called.
    pub fn deinit(self: *SetDuplicateConfirmedSlotsAndHashesIncremental) void {
        std.debug.assert(self.is_committed_or_cancelled);
        self.write_batch.deinit();
    }

    /// Should be called if `self` cannot be completed, e.g. in the error path:
    /// ```zig
    /// var setter = try ledger.setDuplicateConfirmedSlotsAndHashesIncremental();
    /// defer setter.deinit();
    /// errdefer setter.cancel();
    /// ```
    ///
    /// Asserts `self.commit()` was not called before this.
    pub fn cancel(self: *SetDuplicateConfirmedSlotsAndHashesIncremental) void {
        std.debug.assert(!self.is_committed_or_cancelled);
        self.is_committed_or_cancelled = true;
    }

    /// Asserts `self.cancel()` was not called before this.
    pub fn commit(self: *SetDuplicateConfirmedSlotsAndHashesIncremental) !void {
        std.debug.assert(!self.is_committed_or_cancelled);
        try self.result_writer.ledger.db.commit(&self.write_batch);
        self.is_committed_or_cancelled = true;
    }

    /// Asserts that neither of `self.cancel()` and `self.commit()` was called before this.
    pub fn addSlotAndHash(
        self: *SetDuplicateConfirmedSlotsAndHashesIncremental,
        slot: Slot,
        frozen_hash: Hash,
    ) !void {
        std.debug.assert(!self.is_committed_or_cancelled);
        const data: FrozenHashVersioned = .{ .current = .{
            .frozen_hash = frozen_hash,
            .is_duplicate_confirmed = true,
        } };
        try self.write_batch.put(schema.bank_hash, slot, data);
    }
};

/// agave: set_roots
pub fn setRoots(self: *const ResultWriter, rooted_slots: []const Slot) !void {
    var setter = try setRootsIncremental(self);
    defer setter.deinit();
    errdefer setter.cancel();
    for (rooted_slots) |rooted_slot| try setter.addRoot(rooted_slot);
    try setter.commit();
}

/// Returns a struct which can be used to enact the same operation as `setRoots`, incrementally.
pub fn setRootsIncremental(self: *const ResultWriter) !SetRootsIncremental {
    return .{
        .result_writer = self,
        .write_batch = try self.ledger.db.initWriteBatch(),
        .max_new_rooted_slot = 0,
        .is_committed_or_cancelled = false,
    };
}

pub const SetRootsIncremental = struct {
    result_writer: *const ResultWriter,
    write_batch: LedgerDB.WriteBatch,
    max_new_rooted_slot: Slot,
    is_committed_or_cancelled: bool,

    /// Asserts that either `self.cancel()` or `self.commit()` has been called.
    pub fn deinit(self: *SetRootsIncremental) void {
        std.debug.assert(self.is_committed_or_cancelled);
        self.write_batch.deinit();
    }

    /// Should be called if `self` cannot be completed, e.g. in the error path:
    /// ```zig
    /// var setter = try ledger.setRootsIncremental();
    /// defer setter.deinit();
    /// errdefer setter.cancel();
    /// ```
    ///
    /// Asserts `self.commit()` was not called before this.
    pub fn cancel(self: *SetRootsIncremental) void {
        std.debug.assert(!self.is_committed_or_cancelled);
        self.is_committed_or_cancelled = true;
    }

    /// Asserts `self.cancel()` was not called before this.
    pub fn commit(self: *SetRootsIncremental) !void {
        std.debug.assert(!self.is_committed_or_cancelled);
        try self.result_writer.ledger.db.commit(&self.write_batch);
        _ = self.result_writer.ledger.max_root.fetchMax(self.max_new_rooted_slot, .monotonic);
        self.is_committed_or_cancelled = true;
    }

    /// Asserts that neither of `self.cancel()` and `self.commit()` was called before this.
    pub fn addRoot(self: *SetRootsIncremental, rooted_slot: Slot) !void {
        std.debug.assert(!self.is_committed_or_cancelled);
        self.max_new_rooted_slot = @max(self.max_new_rooted_slot, rooted_slot);
        try self.write_batch.put(schema.rooted_slots, rooted_slot, true);
    }
};

/// agave: mark_slots_as_if_rooted_normally_at_startup
pub fn markSlotsAsIfRootedNormallyAtStartup(
    self: *const ResultWriter,
    slot_maybe_hashes: []const struct { Slot, ?Hash },
    with_hash: bool,
) !void {
    {
        var root_setter = try setRootsIncremental(self);
        defer root_setter.deinit();
        errdefer root_setter.cancel();
        for (slot_maybe_hashes) |slot_maybe_hash| {
            const slot, _ = slot_maybe_hash;
            try root_setter.addRoot(slot);
        }
        try root_setter.commit();
    }

    if (with_hash) {
        var slot_hash_setter = try setDuplicateConfirmedSlotsAndHashesIncremental(self);
        defer slot_hash_setter.deinit();
        errdefer slot_hash_setter.cancel();
        for (slot_maybe_hashes) |slot_hash| {
            const slot, const maybe_hash = slot_hash;
            try slot_hash_setter.addSlotAndHash(
                slot,
                maybe_hash orelse return error.MissingHash,
            );
        }
        try slot_hash_setter.commit();
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
///    the ledger if this value is `None`. This slot must be a root.
///  - `end_slot``: The slot to stop the scan at; the scan will continue to
///    the earliest slot in the Ledger if this value is `None`.
///  - `exit`: Exit early if this flag is set to `true`.
/// agave: scan_and_fix_roots
pub fn scanAndFixRoots(
    self: *const ResultWriter,
    allocator: Allocator,
    maybe_start_root: ?Slot,
    maybe_end_slot: ?Slot,
    exit: std.atomic.Value(bool),
) !usize {
    // Hold the lowest_cleanup_slot read lock to prevent any cleaning of
    // the ledger from another thread. Doing so will prevent a
    // possible inconsistency across column families where a slot is:
    //  - Identified as needing root repair by this thread
    //  - Cleaned from the ledger by another thread (LedgerCleanupSerivce)
    //  - Marked as root via Self::set_root() by this this thread
    var lowest_cleanup_slot = self.ledger.highest_slot_cleaned.read();
    defer lowest_cleanup_slot.unlock();

    const start_root = if (maybe_start_root) |slot| blk: {
        if (!try isRoot(self, allocator, slot)) {
            return error.SlotNotRooted;
        }
        break :blk slot;
    } else self.ledger.max_root.load(.monotonic);
    const end_slot = maybe_end_slot orelse lowest_cleanup_slot.get().*;

    var ancestor_iterator = try AncestorIterator
        .initExclusive(allocator, &self.ledger.db, start_root);

    var find_missing_roots_timer = Timer.start();
    var roots_to_fix = ArrayList(Slot).init(allocator);
    defer roots_to_fix.deinit();

    while (try ancestor_iterator.next()) |slot| {
        if (slot < end_slot) break;
        if (!try isRoot(self, allocator, slot)) {
            try roots_to_fix.append(slot);
        }
        if (exit.load(.acquire)) {
            return 0;
        }
    }
    const find_missing_roots_us = find_missing_roots_timer.read().asMicros();
    var fix_roots_timer = Timer.start();
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
            try setRoots(self, chunk);
        }
    } else {
        self.logger.debug().logf(
            "No missing roots found in range {} to {}",
            .{ start_root, end_slot },
        );
    }
    const fix_roots_us = fix_roots_timer.read().asMicros();
    const num_roots_fixed = roots_to_fix.items.len;

    if (self.metrics) |metrics| {
        metrics.fix_roots_us.observe(fix_roots_us);
        metrics.find_missing_roots_us.observe(find_missing_roots_us);
        metrics.num_roots_to_fix.observe(roots_to_fix.items.len);
    }

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
pub fn setAndChainConnectedOnRootAndNextSlots(
    self: *const ResultWriter,
    allocator: Allocator,
    root: Slot,
) !void {
    var root_slot_meta: SlotMeta = try self.ledger.db.get(allocator, schema.slot_meta, root) orelse
        SlotMeta.init(allocator, root, null);
    defer root_slot_meta.deinit();

    // If the slot was already connected, there is nothing to do as this slot's
    // children are also assumed to be appropriately connected
    if (root_slot_meta.isConnected()) {
        return;
    }
    self.logger.info().logf("Marking slot {} and any full children slots as connected", .{root});
    var write_batch = try self.ledger.db.initWriteBatch();
    defer write_batch.deinit();

    // Mark both connected bits on the root slot so that the flags for this
    // slot match the flags of slots that become connected the typical way.
    _ = root_slot_meta.setParentConnected();
    root_slot_meta.setConnected();
    try write_batch.put(schema.slot_meta, root_slot_meta.slot, root_slot_meta);

    var child_slots = try ArrayList(Slot)
        .initCapacity(allocator, root_slot_meta.child_slots.items.len);
    defer child_slots.deinit();

    child_slots.appendSliceAssumeCapacity(root_slot_meta.child_slots.items);
    var i: usize = 0;
    while (i < child_slots.items.len) : (i += 1) {
        const slot = child_slots.items[i];
        var slot_meta: SlotMeta = try self.ledger.db.get(allocator, schema.slot_meta, slot) orelse {
            self.logger.err().logf("Slot {} is a child but has no SlotMeta in ledger", .{slot});
            return error.CorruptedLedger;
        };
        defer slot_meta.deinit();

        if (slot_meta.setParentConnected()) {
            try child_slots.appendSlice(slot_meta.child_slots.items);
        }
        try write_batch.put(schema.slot_meta, slot_meta.slot, slot_meta);
    }

    try self.ledger.db.commit(&write_batch);
}

/// Analogous to [insert_optimistic_slot](https://github.com/anza-xyz/agave/blob/f149dec1d2c98c74305c6d34b494379994731377/ledger/src/blockstore.rs#L3937)
pub fn insertOptimisticSlot(
    self: *const ResultWriter,
    slot: Slot,
    hash: Hash,
    timestamp_ms: sig.core.UnixTimestamp,
) !void {
    try self.ledger.db.put(schema.optimistic_slots, slot, .{ .V0 = .{
        .hash = hash,
        .timestamp = timestamp_ms,
    } });
}

fn isRoot(self: *const ResultWriter, allocator: Allocator, slot: Slot) !bool {
    return try self.ledger.db.get(allocator, schema.rooted_slots, slot) orelse false;
}

pub const ScanAndFixRootsMetrics = struct {
    find_missing_roots_us: *Histogram,
    num_roots_to_fix: *Histogram,
    fix_roots_us: *Histogram,

    pub const prefix = "scan_and_fix_roots";
    pub const histogram_buckets = sig.prometheus.histogram.exponentialBuckets(5, -1, 10);
};

test "setRoots" {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer state.deinit();

    const roots: [5]Slot = .{ 1, 2, 3, 4, 5 };
    var result_writer = state.resultWriter();
    try setRoots(&result_writer, &roots);

    for (roots) |slot| {
        const is_root = try isRoot(&result_writer, allocator, slot);
        try std.testing.expect(is_root);
    }
}

test "setDeadSlot" {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer state.deinit();

    const dead_slots: [4]Slot = .{ 10, 25, 42, 100 };
    const non_existent_slot: Slot = 999; // Slot that doesn't exist in ledger
    const existing_non_dead_slot: Slot = 50; // Slot that exists but is not dead

    var result_writer = state.resultWriter();
    // Add an existing slot to the database (but don't mark it as dead)
    try setRoots(&result_writer, &.{existing_non_dead_slot});

    // Mark slots as dead
    for (dead_slots) |slot| {
        try setDeadSlot(&result_writer, slot);
    }

    // Verify that the slots are marked as dead in the database
    for (dead_slots) |slot| {
        const is_dead = try state.db.get(allocator, schema.dead_slots, slot);
        try std.testing.expectEqual(true, is_dead);
    }

    // Verify that a slot that doesn't exist returns null
    {
        const is_dead = try state.db.get(allocator, schema.dead_slots, non_existent_slot);
        try std.testing.expectEqual(null, is_dead);
    }

    // Verify that an existing slot not marked as dead returns null
    {
        const is_dead = try state.db.get(allocator, schema.dead_slots, existing_non_dead_slot);
        try std.testing.expectEqual(null, is_dead);
        // Verify the slot actually exists in the ledger as a root
        const is_root = try isRoot(&result_writer, allocator, existing_non_dead_slot);
        try std.testing.expectEqual(true, is_root);
    }
}

test "markSlotsAsIfRootedNormallyAtStartup with hash" {
    const allocator = std.testing.allocator;
    var prng_state: std.Random.DefaultPrng = .init(31431);
    const prng = prng_state.random();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer state.deinit();

    const slot_maybe_hashes = [_]struct { Slot, ?Hash }{
        .{ prng.intRangeAtMost(Slot, 100, 200), .initRandom(prng) },
        .{ prng.intRangeAtMost(Slot, 300, 400), .initRandom(prng) },
        .{ prng.intRangeAtMost(Slot, 500, 600), .initRandom(prng) },
        .{ prng.intRangeAtMost(Slot, 700, 800), .initRandom(prng) },
    };
    var result_writer = state.resultWriter();
    try markSlotsAsIfRootedNormallyAtStartup(&result_writer, &slot_maybe_hashes, true);

    for (slot_maybe_hashes) |slot_maybe_hash| {
        const slot, const maybe_hash = slot_maybe_hash;
        try std.testing.expectEqual(true, try isRoot(&result_writer, allocator, slot));
        const expected_value: ledger_mod.meta.FrozenHashVersioned = .{ .current = .{
            .frozen_hash = maybe_hash.?,
            .is_duplicate_confirmed = true,
        } };
        try std.testing.expectEqual(
            expected_value,
            try state.db.get(allocator, schema.bank_hash, slot),
        );
    }

    try std.testing.expectError(
        error.MissingHash,
        markSlotsAsIfRootedNormallyAtStartup(
            &result_writer,
            &.{.{ prng.uintAtMost(Slot, 1000), null }},
            true,
        ),
    );
}

test "markSlotsAsIfRootedNormallyAtStartup without hash" {
    const allocator = std.testing.allocator;
    var prng_state: std.Random.DefaultPrng = .init(6416);
    const prng = prng_state.random();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer state.deinit();

    const slot_maybe_hashes = [_]struct { Slot, ?Hash }{
        .{ prng.intRangeAtMost(Slot, 100, 200), null },
        .{ prng.intRangeAtMost(Slot, 300, 400), null },
        .{ prng.intRangeAtMost(Slot, 500, 600), null },
        .{ prng.intRangeAtMost(Slot, 700, 800), null },
    };
    var result_writer = state.resultWriter();
    try markSlotsAsIfRootedNormallyAtStartup(&result_writer, &slot_maybe_hashes, false);

    for (slot_maybe_hashes) |slot_maybe_hash| {
        const slot, const maybe_hash = slot_maybe_hash;
        std.debug.assert(maybe_hash == null);

        try std.testing.expectEqual(true, try isRoot(&result_writer, allocator, slot));
        try std.testing.expectEqual(null, try state.db.get(allocator, schema.bank_hash, slot));
    }

    try std.testing.expectEqual(
        {},
        markSlotsAsIfRootedNormallyAtStartup(
            &result_writer,
            &.{.{ prng.uintAtMost(Slot, 1000), null }},
            false,
        ),
    );
}

test "setDuplicateConfirmedSlotsAndHashes" {
    const allocator = std.testing.allocator;
    var prng_state: std.Random.DefaultPrng = .init(27911);
    const prng = prng_state.random();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer state.deinit();

    const duplicate_confirmed_slot_hashes = [_]struct { Slot, Hash }{
        .{ prng.intRangeAtMost(Slot, 100, 200), .initRandom(prng) },
        .{ prng.intRangeAtMost(Slot, 300, 400), .initRandom(prng) },
        .{ prng.intRangeAtMost(Slot, 500, 600), .initRandom(prng) },
        .{ prng.intRangeAtMost(Slot, 700, 800), .initRandom(prng) },
    };
    var result_writer = state.resultWriter();
    try setDuplicateConfirmedSlotsAndHashes(&result_writer, &duplicate_confirmed_slot_hashes);

    for (duplicate_confirmed_slot_hashes) |pair| {
        const slot, const expected_hash = pair;
        errdefer std.log.err("error occured for {}:{}", .{ slot, expected_hash });

        const actual_fhv_opt: ?ledger_mod.meta.FrozenHashVersioned =
            try state.db.get(allocator, ledger_mod.schema.schema.bank_hash, slot);
        const expected_fhv: ledger_mod.meta.FrozenHashVersioned = .{ .current = .{
            .frozen_hash = expected_hash,
            .is_duplicate_confirmed = true,
        } };
        try std.testing.expectEqual(expected_fhv, actual_fhv_opt);
    }
}

test "scanAndFixRoots" {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer state.deinit();

    var result_writer = state.resultWriter();
    // slot = 2 is not a root, but should be!
    const roots: [2]Slot = .{ 1, 3 };
    try setRoots(&result_writer, &roots);

    const slot_meta_1 = SlotMeta.init(allocator, 1, null);
    const slot_meta_2 = SlotMeta.init(allocator, 2, 1);
    const slot_meta_3 = SlotMeta.init(allocator, 3, 2);

    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(schema.slot_meta, slot_meta_1.slot, slot_meta_1);
    try write_batch.put(schema.slot_meta, slot_meta_2.slot, slot_meta_2);
    try write_batch.put(schema.slot_meta, slot_meta_3.slot, slot_meta_3);
    try state.db.commit(&write_batch);

    const exit = std.atomic.Value(bool).init(false);

    try std.testing.expectEqual(false, try isRoot(&result_writer, allocator, 2));

    const num_fixed = try scanAndFixRoots(&result_writer, allocator, 3, 1, exit);
    try std.testing.expectEqual(1, num_fixed);
}

test "setAndChainConnectedOnRootAndNextSlots" {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer state.deinit();

    var result_writer = state.resultWriter();
    // 1 is a root
    const roots: [1]Slot = .{1};
    try setRoots(&result_writer, &roots);
    const slot_meta_1 = SlotMeta.init(allocator, 1, null);
    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(schema.slot_meta, slot_meta_1.slot, slot_meta_1);
    try state.db.commit(&write_batch);

    try std.testing.expectEqual(false, slot_meta_1.isConnected());

    try setAndChainConnectedOnRootAndNextSlots(&result_writer, allocator, 1);

    // should be connected
    const db_slot_meta_1 = (try state.db.get(allocator, schema.slot_meta, 1)) orelse
        return error.MissingSlotMeta;
    try std.testing.expectEqual(true, db_slot_meta_1.isConnected());

    // write some roots past 1
    const other_roots: [3]Slot = .{ 2, 3, 4 };
    var parent_slot: ?Slot = 1;
    var write_batch2 = try state.db.initWriteBatch();
    defer write_batch2.deinit();
    try setRoots(&result_writer, &other_roots);

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
    try state.db.commit(&write_batch2);

    try setAndChainConnectedOnRootAndNextSlots(&result_writer, allocator, other_roots[0]);

    for (other_roots) |slot| {
        var db_slot_meta = (try state.db.get(allocator, schema.slot_meta, slot)) orelse
            return error.MissingSlotMeta;
        defer db_slot_meta.deinit();
        try std.testing.expectEqual(true, db_slot_meta.isConnected());
    }
}

test "setAndChainConnectedOnRootAndNextSlots: disconnected" {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer state.deinit();

    var result_writer = state.resultWriter();
    // 1 is a root and full
    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    const roots: [3]Slot = .{ 1, 2, 3 };
    try setRoots(&result_writer, &roots);

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

    try state.db.commit(&write_batch);

    try setAndChainConnectedOnRootAndNextSlots(&result_writer, allocator, 1);

    // should be connected
    var db_slot_meta_1 = (try state.db.get(allocator, schema.slot_meta, 1)) orelse
        return error.MissingSlotMeta;
    defer db_slot_meta_1.deinit();
    try std.testing.expectEqual(true, db_slot_meta_1.isConnected());

    var db_slot_meta_2: SlotMeta = (try state.db.get(allocator, schema.slot_meta, 2)) orelse
        return error.MissingSlotMeta;
    defer db_slot_meta_2.deinit();
    try std.testing.expectEqual(true, db_slot_meta_2.isParentConnected());
    try std.testing.expectEqual(false, db_slot_meta_2.isConnected());

    var db_slot_meta_3: SlotMeta = (try state.db.get(allocator, schema.slot_meta, 3)) orelse
        return error.MissingSlotMeta;
    defer db_slot_meta_3.deinit();
    try std.testing.expectEqual(false, db_slot_meta_3.isParentConnected());
    try std.testing.expectEqual(false, db_slot_meta_3.isConnected());
}

test storeDuplicateSlot {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer state.deinit();

    const slot: Slot = 42;
    const shred1_data = "test_shred_1_payload_data";
    const shred2_data = "test_shred_2_payload_data";

    // Test case: Store a duplicate slot proof
    {
        var result_writer = state.resultWriter();
        try result_writer.storeDuplicateSlot(slot, shred1_data, shred2_data);

        const reader = state.reader();
        const stored_proof = try reader.getDuplicateSlot(allocator, slot);
        try std.testing.expect(stored_proof != null);

        const proof = stored_proof.?;
        defer sig.bincode.free(allocator, proof);

        try std.testing.expectEqualSlices(u8, shred1_data, proof.shred1);
        try std.testing.expectEqualSlices(u8, shred2_data, proof.shred2);
    }

    // Test case: Overwrite an existing duplicate slot proof
    {
        const new_shred1 = "new_test_shred_1_data";
        const new_shred2 = "new_test_shred_2_data";

        var result_writer = state.resultWriter();
        try result_writer.storeDuplicateSlot(slot, new_shred1, new_shred2);

        const reader = state.reader();
        const stored_proof = try reader.getDuplicateSlot(allocator, slot);
        try std.testing.expect(stored_proof != null);

        const proof = stored_proof.?;
        defer sig.bincode.free(allocator, proof);

        try std.testing.expectEqualSlices(u8, new_shred1, proof.shred1);
        try std.testing.expectEqualSlices(u8, new_shred2, proof.shred2);
    }

    // Test case: Store duplicate slot proofs for multiple slots
    {
        const slot2: Slot = 100;
        const slot3: Slot = 200;
        const shred_a = "shred_a_data";
        const shred_b = "shred_b_data";

        var result_writer = state.resultWriter();
        try result_writer.storeDuplicateSlot(slot2, shred_a, shred_b);
        try result_writer.storeDuplicateSlot(slot3, shred_b, shred_a);

        const reader = state.reader();

        const proof2 = (try reader.getDuplicateSlot(allocator, slot2)).?;
        defer sig.bincode.free(allocator, proof2);
        try std.testing.expectEqualSlices(u8, shred_a, proof2.shred1);
        try std.testing.expectEqualSlices(u8, shred_b, proof2.shred2);

        const proof3 = (try reader.getDuplicateSlot(allocator, slot3)).?;
        defer sig.bincode.free(allocator, proof3);
        try std.testing.expectEqualSlices(u8, shred_b, proof3.shred1);
        try std.testing.expectEqualSlices(u8, shred_a, proof3.shred2);
    }
}
