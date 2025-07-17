const std = @import("std");
const sig = @import("../sig.zig");
const ledger = @import("lib.zig");

const AtomicBool = std.atomic.Value(bool);

const Duration = sig.time.Duration;
const Pubkey = sig.core.Pubkey;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;

const BlockstoreDB = ledger.BlockstoreDB;
const BlockstoreReader = ledger.reader.BlockstoreReader;
const LedgerResultWriter = ledger.result_writer.LedgerResultWriter;

const schema = ledger.schema.schema;

// The default time to sleep between checks for new roots
const DEFAULT_MS_PER_SLOT: u64 = 400;

// Perform blockstore cleanup at this interval to limit the overhead of cleanup
// Cleanup will be considered after the latest root has advanced by this value
const DEFAULT_CLEANUP_SLOT_INTERVAL: u64 = 512;

// The above slot interval can be roughly equated to a time interval. So, scale
// how often we check for cleanup with the interval. Doing so will avoid wasted
// checks when we know that the latest root could not have advanced far enough
//
// Given that the timing of new slots/roots is not exact, divide by 10 to avoid
// a long wait incase a check occurs just before the interval has elapsed
const LOOP_LIMITER = Duration.fromMillis(DEFAULT_CLEANUP_SLOT_INTERVAL * DEFAULT_MS_PER_SLOT / 10);

// The identifier for the scoped logger used in this file.
const LOG_SCOPE: []const u8 = "ledger.cleanup_service";

pub fn run(
    logger_: sig.trace.Logger,
    blockstore_reader: *BlockstoreReader,
    db: *BlockstoreDB,
    lowest_cleanup_slot: *sig.sync.RwMux(Slot),
    max_ledger_shreds: u64,
    exit: *AtomicBool,
) !void {
    const logger = logger_.withScope(LOG_SCOPE);
    var last_purge_slot: Slot = 0;

    logger.info().log("Starting blockstore cleanup service");
    while (!exit.load(.acquire)) {
        last_purge_slot = try cleanBlockstore(
            logger.unscoped(),
            blockstore_reader,
            db,
            lowest_cleanup_slot,
            max_ledger_shreds,
            last_purge_slot,
            DEFAULT_CLEANUP_SLOT_INTERVAL,
        );
        std.Thread.sleep(LOOP_LIMITER.asNanos());
    }
}

/// Checks for new roots and initiates a cleanup if the last cleanup was at
/// least `purge_interval` slots ago. A cleanup will no-op if the ledger
/// already has fewer than `max_ledger_shreds`; otherwise, the cleanup will
/// purge enough slots to get the ledger size below `max_ledger_shreds`.
///
/// # Arguments
///
/// - `max_ledger_shreds`: the number of shreds to keep since the new root.
/// - `last_purge_slot`: an both an input and output parameter indicating
///   the id of the last purged slot.  As an input parameter, it works
///   together with `purge_interval` on whether it is too early to perform
///   ledger cleanup.  As an output parameter, it will be updated if this
///   function actually performs the ledger cleanup.
/// - `purge_interval`: the minimum slot interval between two ledger
///   cleanup.  When the max root fetched from the Blockstore minus
///   `last_purge_slot` is fewer than `purge_interval`, the function will
///   simply return `Ok` without actually running the ledger cleanup.
///   In this case, `purge_interval` will remain unchanged.
///
/// Analogous to the [`cleanup_ledger`](https://github.com/anza-xyz/agave/blob/6476d5fac0c30d1f49d13eae118b89be78fb15d2/ledger/src/blockstore_cleanup_service.rs#L198) in agave:
pub fn cleanBlockstore(
    logger_: sig.trace.Logger,
    blockstore_reader: *BlockstoreReader,
    db: *BlockstoreDB,
    lowest_cleanup_slot: *sig.sync.RwMux(Slot),
    max_ledger_shreds: u64,
    last_purge_slot: u64,
    purge_interval: u64,
) !Slot {
    const logger = logger_.withScope(LOG_SCOPE);

    // // TODO: add back when max_root is implemented with consensus
    // const root = blockstore_reader.max_root.load(.acquire);

    // hack to get a conservative estimate of a recent slot that is almost definitely rooted
    const root = if (try blockstore_reader.highestSlot()) |highest|
        highest -| 100
    else
        try blockstore_reader.lowestSlot();

    if (root - last_purge_slot <= purge_interval) return last_purge_slot;

    const result = try findSlotsToClean(blockstore_reader, root, max_ledger_shreds);
    logger.info().logf("findSlotsToClean result: {any}", .{result});

    if (result.should_clean) {
        const slot, var lock = lowest_cleanup_slot.writeWithLock();
        defer lock.unlock();
        slot.* = result.highest_slot_to_purge;
        const did_purge = try purgeSlots(db, 0, result.highest_slot_to_purge);
        if (did_purge) {
            logger.info().log("Purged slots...");
        } else {
            logger.info().log("No slots purged");
        }
        // // TODO: Is this needed, it updates the OldestSlot data structure in
        // // agave which is owned and used by the blockstore database backend.
        // // We do not have an analogous data structure in the blockstore database
        // blockstore_reader.setMaxExpiredSlot(...);
    }

    return root;
}

const SlotsToCleanResult = struct {
    should_clean: bool,
    highest_slot_to_purge: Slot,
    total_shreds: u64,

    pub fn format(
        result: SlotsToCleanResult,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("should_clean: {} ", .{result.should_clean});
        try writer.print("highest_slot_to_purge: {d} ", .{result.highest_slot_to_purge});
        try writer.print("total_shreds: {}", .{result.total_shreds});
    }
};

/// A helper function to `cleanup_ledger` which returns a tuple of the
/// following three elements suggesting whether to clean up the ledger:
///
/// Return value (bool, Slot, u64):
/// - `slots_to_clean` (bool): a boolean value indicating whether there
///   are any slots to clean.  If true, then `cleanup_ledger` function
///   will then proceed with the ledger cleanup.
/// - `highest_slot_to_purge` (Slot): the highest slot to purge.  Any
///   slot which is smaller or equal to `highest_slot_to_purge` will be
///   cleaned up.
/// - `total_shreds` (u64): the total estimated number of shreds before the
///   `root`.
///
/// Analogous to the [`find_slots_to_clean`](https://github.com/anza-xyz/agave/blob/6476d5fac0c30d1f49d13eae118b89be78fb15d2/ledger/src/blockstore_cleanup_service.rs#L103)
fn findSlotsToClean(
    blockstore_reader: *BlockstoreReader,
    max_root: Slot,
    max_ledger_shreds: u64,
) !SlotsToCleanResult {
    const num_shreds = try blockstore_reader.db.count(schema.data_shred);

    // Using the difference between the lowest and highest slot seen will
    // result in overestimating the number of slots in the blockstore since
    // there are likely to be some missing slots, such as when a leader is
    // delinquent for their leader slots.
    //
    // With the below calculations, we will then end up underestimating the
    // mean number of shreds per slot present in the blockstore which will
    // result in cleaning more slots than necessary to get us
    // below max_ledger_shreds.
    //
    // Given that the service runs on an interval, this is good because it
    // means that we are building some headroom so the peak number of alive
    // shreds doesn't get too large before the service's next run.
    //
    // Finally, we have a check to make sure that we don't purge any slots
    // newer than the passed in root. This check is practically only
    // relevant when a cluster has extended periods of not rooting slots.
    // With healthy cluster operation, the minimum ledger size ensures
    // that purged slots will be quite old in relation to the newest root.
    const lowest_slot = try blockstore_reader.lowestSlot();
    const highest_slot = try blockstore_reader.highestSlot() orelse lowest_slot;

    if (highest_slot < lowest_slot) {
        return .{ .should_clean = false, .highest_slot_to_purge = 0, .total_shreds = num_shreds };
    }

    // The + 1 ensures we count the correct number of slots. Additionally,
    // it guarantees num_slots >= 1 for the subsequent division.
    const num_slots = highest_slot - lowest_slot + 1;
    const mean_shreds_per_slot = num_shreds / num_slots;

    if (num_shreds <= max_ledger_shreds) {
        return .{ .should_clean = false, .highest_slot_to_purge = 0, .total_shreds = num_shreds };
    }

    if (mean_shreds_per_slot > 0) {
        // Add an extra (mean_shreds_per_slot - 1) in the numerator
        // so that our integer division rounds up
        const num_slots_to_clean = (num_shreds - max_ledger_shreds + (mean_shreds_per_slot - 1)) / mean_shreds_per_slot;
        const highest_slot_to_purge = @min(lowest_slot + num_slots_to_clean - 1, max_root);
        return .{ .should_clean = true, .highest_slot_to_purge = highest_slot_to_purge, .total_shreds = num_shreds };
    } else {
        return .{ .should_clean = false, .highest_slot_to_purge = 0, .total_shreds = num_shreds };
    }
}

/// NOTE: this purges the range within [from_slot, to_slot] inclusive
///
/// analog to [`run_purge_with_stats`](https://github.com/anza-xyz/agave/blob/26692e666454d340a6691e2483194934e6a8ddfc/ledger/src/blockstore/blockstore_purge.rs#L202)
pub fn purgeSlots(db: *BlockstoreDB, from_slot: Slot, to_slot: Slot) !bool {
    var write_batch = try db.initWriteBatch();
    defer write_batch.deinit();

    // the methods used below are exclusive [from_slot, to_slot), so we add 1 to purge inclusive
    const purge_to_slot = to_slot + 1;

    var did_purge = true;
    writePurgeRange(&write_batch, from_slot, purge_to_slot) catch {
        did_purge = false;
    };
    try db.commit(&write_batch);

    if (did_purge and from_slot == 0) {
        try purgeFilesInRange(db, from_slot, purge_to_slot);
    }

    return did_purge;
}

/// NOTE: this purges the range within [from_slot, to_slot) exclusive
/// is the pseudocode equivalent of the following:
/// inline for (COLUMN_FAMILIES) |cf| {
///     try write_batch.deleteRange(cf, from_slot, to_slot);
/// }
fn writePurgeRange(write_batch: *BlockstoreDB.WriteBatch, from_slot: Slot, to_slot: Slot) !void {
    var delete_count: u32 = 0; // sanity check

    // NOTE: we need to conver the slot into keys for the column families
    // this is only used in this and one other function and should not change, so its ok to hard code it
    try purgeRangeWithCount(write_batch, schema.slot_meta, from_slot, to_slot, &delete_count);
    try purgeRangeWithCount(write_batch, schema.dead_slots, from_slot, to_slot, &delete_count);
    try purgeRangeWithCount(write_batch, schema.duplicate_slots, from_slot, to_slot, &delete_count);
    try purgeRangeWithCount(write_batch, schema.rooted_slots, from_slot, to_slot, &delete_count);
    try purgeRangeWithCount(
        write_batch,
        schema.erasure_meta,
        .{ .slot = from_slot, .erasure_set_index = 0 },
        .{ .slot = to_slot, .erasure_set_index = 0 },
        &delete_count,
    );
    try purgeRangeWithCount(write_batch, schema.orphan_slots, from_slot, to_slot, &delete_count);
    try purgeRangeWithCount(write_batch, schema.index, from_slot, to_slot, &delete_count);
    try purgeRangeWithCount(write_batch, schema.data_shred, .{ from_slot, 0 }, .{ to_slot, 0 }, &delete_count);
    try purgeRangeWithCount(write_batch, schema.code_shred, .{ from_slot, 0 }, .{ to_slot, 0 }, &delete_count);
    try purgeRangeWithCount(
        write_batch,
        schema.transaction_status,
        .{ Signature.ZEROES, from_slot },
        .{ Signature.ZEROES, to_slot },
        &delete_count,
    );
    // NOTE: for `address_signatures`, agave doesnt key based on slot for some reason
    // (permalink comment seems incorrect)
    // https://github.com/anza-xyz/agave/blob/da029625d180dd1d396d26b74a5c281b7786e8c9/ledger/src/blockstore_db.rs#L962
    try purgeRangeWithCount(
        write_batch,
        schema.address_signatures,
        .{ .slot = from_slot, .address = Pubkey.ZEROES, .transaction_index = 0, .signature = Signature.ZEROES },
        .{ .slot = to_slot, .address = Pubkey.ZEROES, .transaction_index = 0, .signature = Signature.ZEROES },
        &delete_count,
    );
    try purgeRangeWithCount(
        write_batch,
        schema.transaction_memos,
        .{ Signature.ZEROES, from_slot },
        .{ Signature.ZEROES, to_slot },
        &delete_count,
    );
    try purgeRangeWithCount(write_batch, schema.transaction_status_index, from_slot, to_slot, &delete_count);
    try purgeRangeWithCount(write_batch, schema.rewards, from_slot, to_slot, &delete_count);
    try purgeRangeWithCount(write_batch, schema.blocktime, from_slot, to_slot, &delete_count);
    try purgeRangeWithCount(write_batch, schema.perf_samples, from_slot, to_slot, &delete_count);
    try purgeRangeWithCount(write_batch, schema.block_height, from_slot, to_slot, &delete_count);
    try purgeRangeWithCount(write_batch, schema.bank_hash, from_slot, to_slot, &delete_count);
    try purgeRangeWithCount(write_batch, schema.optimistic_slots, from_slot, to_slot, &delete_count);
    try purgeRangeWithCount(
        write_batch,
        schema.merkle_root_meta,
        .{ .slot = from_slot, .erasure_set_index = 0 },
        .{ .slot = to_slot, .erasure_set_index = 0 },
        &delete_count,
    );
    // slot is not indexed in this method, so this is a full purge
    // NOTE: do we want to do this? why not just keep the data, since it will be updated/put-back eventually
    try purgeRangeWithCount(write_batch, schema.program_costs, Pubkey.ZEROES, Pubkey.ZEROES, &delete_count);

    // make sure we covered all the column families
    std.debug.assert(delete_count == ledger.schema.list.len);
}

fn purgeRangeWithCount(
    write_batch: *BlockstoreDB.WriteBatch,
    comptime cf: sig.ledger.database.ColumnFamily,
    from_key: cf.Key,
    to_key: cf.Key,
    count: *u32,
) !void {
    try write_batch.deleteRange(cf, from_key, to_key);
    count.* += 1;
}

/// NOTE: this purges the range within [from_slot, to_slot) exclusive
/// is the pseudocode equivalent of the following:
/// inline for (COLUMN_FAMILIES) |cf| {
///     try db.deleteFileRange(cf, from_slot, to_slot);
/// }
fn purgeFilesInRange(db: *BlockstoreDB, from_slot: Slot, to_slot: Slot) !void {
    var delete_count: u32 = 0; // sanity check

    // NOTE: we need to conver the slot into keys for the column families
    // this is only used in this and one other function and should not change, so its ok to hard code it
    try purgeFileRangeWithCount(db, schema.slot_meta, from_slot, to_slot, &delete_count);
    try purgeFileRangeWithCount(db, schema.dead_slots, from_slot, to_slot, &delete_count);
    try purgeFileRangeWithCount(db, schema.duplicate_slots, from_slot, to_slot, &delete_count);
    try purgeFileRangeWithCount(db, schema.rooted_slots, from_slot, to_slot, &delete_count);
    try purgeFileRangeWithCount(
        db,
        schema.erasure_meta,
        .{ .slot = from_slot, .erasure_set_index = 0 },
        .{ .slot = to_slot, .erasure_set_index = 0 },
        &delete_count,
    );
    try purgeFileRangeWithCount(db, schema.orphan_slots, from_slot, to_slot, &delete_count);
    try purgeFileRangeWithCount(db, schema.index, from_slot, to_slot, &delete_count);
    try purgeFileRangeWithCount(db, schema.data_shred, .{ from_slot, 0 }, .{ to_slot, 0 }, &delete_count);
    try purgeFileRangeWithCount(db, schema.code_shred, .{ from_slot, 0 }, .{ to_slot, 0 }, &delete_count);
    try purgeFileRangeWithCount(
        db,
        schema.transaction_status,
        .{ Signature.ZEROES, from_slot },
        .{ Signature.ZEROES, to_slot },
        &delete_count,
    );
    // NOTE: for `address_signatures`, agave doesnt key based on slot for some reason
    // (permalink comment seems incorrect?)
    // https://github.com/anza-xyz/agave/blob/da029625d180dd1d396d26b74a5c281b7786e8c9/ledger/src/blockstore_db.rs#L962
    try purgeFileRangeWithCount(
        db,
        schema.address_signatures,
        .{ .slot = from_slot, .address = Pubkey.ZEROES, .transaction_index = 0, .signature = Signature.ZEROES },
        .{ .slot = to_slot, .address = Pubkey.ZEROES, .transaction_index = 0, .signature = Signature.ZEROES },
        &delete_count,
    );
    try purgeFileRangeWithCount(
        db,
        schema.transaction_memos,
        .{ Signature.ZEROES, from_slot },
        .{ Signature.ZEROES, to_slot },
        &delete_count,
    );
    try purgeFileRangeWithCount(db, schema.transaction_status_index, from_slot, to_slot, &delete_count);
    try purgeFileRangeWithCount(db, schema.rewards, from_slot, to_slot, &delete_count);
    try purgeFileRangeWithCount(db, schema.blocktime, from_slot, to_slot, &delete_count);
    try purgeFileRangeWithCount(db, schema.perf_samples, from_slot, to_slot, &delete_count);
    try purgeFileRangeWithCount(db, schema.block_height, from_slot, to_slot, &delete_count);
    try purgeFileRangeWithCount(db, schema.bank_hash, from_slot, to_slot, &delete_count);
    try purgeFileRangeWithCount(db, schema.optimistic_slots, from_slot, to_slot, &delete_count);
    try purgeFileRangeWithCount(
        db,
        schema.merkle_root_meta,
        .{ .slot = from_slot, .erasure_set_index = 0 },
        .{ .slot = to_slot, .erasure_set_index = 0 },
        &delete_count,
    );
    // slot is not indexed in this method, so this is a full purge
    // NOTE: do we want to do this? why not just keep the data, since it will be updated/put-back eventually
    try purgeFileRangeWithCount(
        db,
        schema.program_costs,
        Pubkey.ZEROES,
        Pubkey.ZEROES,
        &delete_count,
    );

    // make sure we covered all the column families
    std.debug.assert(delete_count == ledger.schema.list.len);
}

fn purgeFileRangeWithCount(
    db: *BlockstoreDB,
    comptime cf: sig.ledger.database.ColumnFamily,
    from_key: cf.Key,
    to_key: cf.Key,
    count: *u32,
) !void {
    try db.deleteFilesInRange(cf, from_key, to_key);
    count.* += 1;
}

const Blockstore = ledger.BlockstoreDB;
const TestDB = ledger.tests.TestDB;

test cleanBlockstore {
    // test setup
    const allocator = std.testing.allocator;
    const logger = sig.trace.DirectPrintLogger.init(allocator, .warn).logger();
    const registry = sig.prometheus.globalRegistry();
    var db = try TestDB.init(@src());
    defer db.deinit();
    var lowest_cleanup_slot = sig.sync.RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader
        .init(allocator, logger, db, registry, &lowest_cleanup_slot, &max_root);

    // insert data
    var batch = try db.initWriteBatch();
    defer batch.deinit();
    for (0..1_000) |i| {
        for (0..10) |j| try batch.put(ledger.schema.schema.data_shred, .{ i, j }, &.{});
        try batch.put(ledger.schema.schema.slot_meta, i, undefined);
    }
    try db.commit(&batch);
    try db.flush(ledger.schema.schema.data_shred);

    // run test subject
    const slot = try cleanBlockstore(logger, &reader, &db, &lowest_cleanup_slot, 100, 0, 0);
    try std.testing.expectEqual(899, slot);

    // verify correct data was purged
    var shred_iter = try db.iterator(ledger.schema.schema.data_shred, .forward, .{ 0, 0 });
    defer shred_iter.deinit();
    var meta_iter = try db.iterator(ledger.schema.schema.slot_meta, .forward, 0);
    defer meta_iter.deinit();
    for (900..1_000) |i| {
        for (0..10) |j| try std.testing.expectEqual(.{ i, j }, (try shred_iter.nextKey()).?);
        try std.testing.expectEqual(i, (try meta_iter.nextKey()).?);
    }
    try std.testing.expectEqual(null, shred_iter.nextKey());
    try std.testing.expectEqual(null, meta_iter.nextKey());
}

test "findSlotsToClean" {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();
    const logger = .noop;

    var db = try TestDB.init(@src());
    defer db.deinit();

    var lowest_cleanup_slot = sig.sync.RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);

    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        &registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    // set highest and lowest slot by inserting slot_meta
    var lowest_slot_meta = ledger.meta.SlotMeta.init(allocator, 10, null);
    defer lowest_slot_meta.deinit();
    lowest_slot_meta.received = 10;

    var highest_slot_meta = ledger.meta.SlotMeta.init(allocator, 20, null);
    defer highest_slot_meta.deinit();
    highest_slot_meta.received = 20;

    {
        var write_batch = try db.initWriteBatch();
        defer write_batch.deinit();
        try write_batch.put(
            ledger.schema.schema.slot_meta,
            lowest_slot_meta.slot,
            lowest_slot_meta,
        );
        try write_batch.put(
            ledger.schema.schema.slot_meta,
            highest_slot_meta.slot,
            highest_slot_meta,
        );
        try db.commit(&write_batch);
    }

    const r = try findSlotsToClean(&reader, 0, 100);
    try std.testing.expectEqual(false, r.should_clean);
    try std.testing.expectEqual(0, r.total_shreds);
    try std.testing.expectEqual(0, r.highest_slot_to_purge);
    var data_shred = try ledger.shred.DataShred.zeroedForTest(allocator);
    defer data_shred.deinit();
    {
        var write_batch = try db.initWriteBatch();
        defer write_batch.deinit();
        for (0..1000) |i| {
            try write_batch.put(ledger.schema.schema.data_shred, .{ 19, i }, data_shred.payload);
        }
        try db.commit(&write_batch);
    }
    // When implementation is rocksdb, we need to flush memtable to disk to be able to assert.
    // We do that by deiniting the current db, which triggers the flushing.
    if (sig.build_options.blockstore_db == .rocksdb) {
        db.deinit();
        db = try TestDB.reuseBlockstore(@src());
        reader.db = db;
    }
    const r2 = try findSlotsToClean(&reader, 0, 100);
    try std.testing.expectEqual(true, r2.should_clean);
    try std.testing.expectEqual(1000, r2.total_shreds);
    try std.testing.expectEqual(0, r2.highest_slot_to_purge);
}

test "purgeSlots" {
    const allocator = std.testing.allocator;
    const logger = .noop;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var db = try TestDB.init(@src());
    defer db.deinit();

    var lowest_cleanup_slot = sig.sync.RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var writer = LedgerResultWriter{
        .allocator = allocator,
        .db = db,
        .logger = logger,
        .lowest_cleanup_slot = &lowest_cleanup_slot,
        .max_root = &max_root,
        .scan_and_fix_roots_metrics = try registry
            .initStruct(ledger.result_writer.ScanAndFixRootsMetrics),
    };

    // write some roots
    const roots: [10]Slot = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
    try writer.setRoots(&roots);

    // purge the range [0, 5]
    const did_purge = try purgeSlots(&db, 0, 5);
    try std.testing.expectEqual(true, did_purge);

    for (0..5 + 1) |slot| {
        const is_root = try db.get(allocator, schema.rooted_slots, slot) orelse false;
        try std.testing.expectEqual(false, is_root);
    }

    for (6..10 + 1) |slot| {
        const is_root = try db.get(allocator, schema.rooted_slots, slot) orelse false;
        try std.testing.expectEqual(true, is_root);
    }

    // write another type
    var write_batch = try db.initWriteBatch();
    defer write_batch.deinit();
    for (0..roots.len + 1) |i| {
        const merkle_root_meta = sig.ledger.shred.ErasureSetId{
            .erasure_set_index = i,
            .slot = i,
        };
        const merkle_meta = sig.ledger.meta.MerkleRootMeta{
            .merkle_root = null,
            .first_received_shred_index = 0,
            .first_received_shred_type = .data,
        };

        try write_batch.put(schema.merkle_root_meta, merkle_root_meta, merkle_meta);
    }
    try db.commit(&write_batch);

    // purge the range [0, 5]
    const did_purge2 = try purgeSlots(&db, 0, 5);
    try std.testing.expectEqual(true, did_purge2);

    for (0..5 + 1) |i| {
        const r = try db.get(allocator, schema.merkle_root_meta, .{ .slot = i, .erasure_set_index = i });
        try std.testing.expectEqual(null, r);
    }

    for (6..10 + 1) |i| {
        const r = try db.get(allocator, schema.merkle_root_meta, .{ .slot = i, .erasure_set_index = i });
        try std.testing.expect(r != null);
    }
}
