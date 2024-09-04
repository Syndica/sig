const std = @import("std");
const sig = @import("../sig.zig");
const ledger = @import("lib.zig");

const AtomicBool = std.atomic.Value(bool);

const BlockstoreReader = ledger.reader.BlockstoreReader;
const BlockstoreWriter = ledger.writer.BlockstoreWriter;
const Slot = sig.core.Slot;
const Duration = sig.time.Duration;
const Schema = ledger.schema.schema;

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

pub fn run(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    blockstore_reader: *BlockstoreReader,
    blockstore_writer: *BlockstoreWriter,
    max_ledger_shreds: u64,
    exit: *AtomicBool,
) !void {
    var last_purge_slot: Slot = 0;

    logger.info("Starting blockstore cleanup service");
    while (!exit.load(.unordered)) {
        last_purge_slot = try cleanBlockstore(
            allocator,
            logger,
            blockstore_reader,
            blockstore_writer,
            max_ledger_shreds,
            last_purge_slot,
            DEFAULT_CLEANUP_SLOT_INTERVAL,
        );
        std.time.sleep(LOOP_LIMITER.asNanos());
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
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger,
    blockstore_reader: *BlockstoreReader,
    blockstore_writer: *BlockstoreWriter,
    max_ledger_shreds: u64,
    last_purge_slot: u64,
    purge_interval: u64,
) !Slot {
    // // TODO: add back when max_root is implemented with consensus
    // const root = blockstore_reader.max_root.load(.unordered);
    // if (root - last_purge_slot <= purge_interval) return last_purge_slot;
    _ = last_purge_slot;
    _ = purge_interval;

    // NOTE: this will clean everything past the lowest slot in the blockstore
    const root: Slot = try blockstore_reader.lowestSlot();
    const result = try findSlotsToClean(
        allocator,
        blockstore_reader,
        root,
        max_ledger_shreds,
    );
    logger.infof("findSlotsToClean result: {any}", .{result});

    if (result.should_clean) {
        blockstore_writer.setLowestCleanupSlot(result.highest_slot_to_purge);
        const did_purge = try blockstore_writer.purgeSlots(0, result.highest_slot_to_purge);
        if (did_purge) {
            logger.info("Purged slots...");
        } else {
            logger.info("No slots purged");
        }
        // // TODO: Is this needed, it updates the OldestSlot data structure in
        // // agave which is owned and used by the blockstore database backend.
        // // We do not have an analogous data structure in the blockstore database
        // blockstore_reader.setMaxExpiredSlot(...);
    }

    return root;
}

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
    allocator: std.mem.Allocator,
    blockstore_reader: *BlockstoreReader,
    max_root: Slot,
    max_ledger_shreds: u64,
) !struct {
    should_clean: bool,
    highest_slot_to_purge: Slot,
    total_shreds: u64,
} {
    const data_shred_cf_name = Schema.data_shred.name;

    const live_files = try blockstore_reader.db.db.liveFiles(allocator);
    defer live_files.deinit();

    var num_shreds: u64 = 0;
    for (live_files.items) |live_file| {
        if (std.mem.eql(u8, live_file.column_family_name, data_shred_cf_name)) {
            num_shreds += live_file.num_entries;
        }
    }

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
    // std.debug.print("num_shreds: {d}, num_slots: {d}, mean_shreds_per_slot: {d}\n", .{num_shreds, num_slots, mean_shreds_per_slot});

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

const Blockstore = ledger.BlockstoreDB;
const TestDB = ledger.tests.TestDB("cleanup_service");

test "findSlotsToClean" {
    const allocator = std.testing.allocator;
    const logger = .noop;
    const registry = sig.prometheus.globalRegistry();

    var db = try TestDB.init("findSlotsToClean");
    defer db.deinit();

    var lowest_cleanup_slot = sig.sync.RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);

    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
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
        try write_batch.put(ledger.schema.schema.slot_meta, lowest_slot_meta.slot, lowest_slot_meta);
        try write_batch.put(ledger.schema.schema.slot_meta, highest_slot_meta.slot, highest_slot_meta);
        try db.commit(write_batch);
    }

    const r = try findSlotsToClean(allocator, &reader, 0, 100);
    try std.testing.expectEqual(false, r.should_clean);
    try std.testing.expectEqual(0, r.total_shreds);
    try std.testing.expectEqual(0, r.highest_slot_to_purge);

    // // TODO: understand how live files are created
    // // add data shreds
    // var data_shred = try ledger.shred.DataShred.default(allocator);
    // defer data_shred.fields.deinit();
    // {
    //     var write_batch = try db.initWriteBatch();
    //     for (0..1000) |i| {
    //         try write_batch.put(ledger.schema.schema.data_shred, .{ 19, i }, data_shred.fields.payload);
    //     }
    //     try db.commit(write_batch);
    // }
    // const r2 = try findSlotsToClean(allocator, &reader, 0, 1);
    // std.debug.print("r2: {any}\n", .{r2});
}
