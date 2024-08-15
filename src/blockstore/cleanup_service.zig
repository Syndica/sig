const std = @import("std");
const sig = @import("../lib.zig");

const AtomicBool = std.atomic.Value(bool);
const Instant = std.time.Instant;

const BlockstoreReader = sig.blockstore.reader.BlockstoreReader;
const BlockstoreWriter = sig.blockstore.writer.BlockstoreWriter;
const Slot = sig.core.Slot;
const Duration = sig.time.Duration;
const Schema = sig.blockstore.schema.schema;

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
    blockstore_reader: *BlockstoreReader,
    blockstore_writer: *BlockstoreWriter,
    max_ledger_shreds: u64,
    exit: *AtomicBool,
) !void {
    var last_purge_slot: Slot = 0;
    var last_check_time = try Instant.now();

    while (!exit.load(.unordered)) {
        const last_check_time_elapsed_nanos = (try Instant.now()).since(last_check_time);
        if (last_check_time_elapsed_nanos > LOOP_LIMITER.asNanos()) {
            last_purge_slot = try cleanBlockstore(
                allocator,
                &blockstore_reader,
                &blockstore_writer,
                max_ledger_shreds,
                last_purge_slot,
                DEFAULT_CLEANUP_SLOT_INTERVAL,
            );
            last_check_time = try Instant.now();
        }
        std.time.sleep(Duration.fromSecs(1).asNanos());
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
    blockstore_reader: *BlockstoreReader,
    blockstore_writer: *BlockstoreWriter,
    max_ledger_shreds: u64,
    last_purge_slot: u64,
    purge_interval: u64,
) !Slot {
    const root = blockstore_reader.max_root.load(.unordered);
    if (root - last_purge_slot <= purge_interval) return last_purge_slot;

    const slots_to_clean, const lowest_cleanup_slot, _ = findSlotsToClean(
        allocator,
        blockstore_reader,
        root,
        max_ledger_shreds,
    );

    if (slots_to_clean) {
        blockstore_writer.setLowestCleanupSlot(lowest_cleanup_slot);
        blockstore_writer.purgeSlots(0, lowest_cleanup_slot);
        // blockstore_reader.setMaxExpiredSlot(lowest_cleanup_slot);
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
/// - `lowest_slot_to_purge` (Slot): the lowest slot to purge.  Any
///   slot which is older or equal to `lowest_slot_to_purge` will be
///   cleaned up.
/// - `total_shreds` (u64): the total estimated number of shreds before the
///   `root`.
///
/// Analogous to the [`find_slots_to_clean`](https://github.com/anza-xyz/agave/blob/6476d5fac0c30d1f49d13eae118b89be78fb15d2/ledger/src/blockstore_cleanup_service.rs#L103)
fn findSlotsToClean(
    allocator: std.mem.Allocator,
    blockstore_reader: *BlockstoreReader,
    root: Slot,
    max_ledger_shreds: u64,
) !struct { bool, Slot, u64 } {
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

    if (highest_slot < lowest_slot) return .{ false, 0, num_shreds };

    // The + 1 ensures we count the correct number of slots. Additionally,
    // it guarantees num_slots >= 1 for the subsequent division.
    const num_slots = highest_slot - lowest_slot + 1;
    const mean_shreds_per_slot = num_shreds / num_slots;

    if (num_shreds <= max_ledger_shreds) return .{ false, 0, num_shreds };

    if (mean_shreds_per_slot > 0) {
        // Add an extra (mean_shreds_per_slot - 1) in the numerator
        // so that our integer division rounds up
        const num_slots_to_clean = (num_shreds - max_ledger_shreds + (mean_shreds_per_slot - 1)) / mean_shreds_per_slot;
        const lowest_cleanup_slot = @min(lowest_slot + num_slots_to_clean - 1, root);
        return .{ true, lowest_cleanup_slot, num_shreds };
    } else {
        return .{ false, 0, num_shreds };
    }
}

const bincode = sig.bincode;
const Blockstore = sig.blockstore.BlockstoreDB;
const ShredInserter = sig.blockstore.ShredInserter;
const CodingShred = sig.shred_collector.shred.CodingShred;
const TestState = sig.blockstore.insert_shred.TestState;

test "findSlotsToClean" {
    const allocator = std.testing.allocator;
    const logger = .noop;
    const registry = sig.prometheus.globalRegistry();

    var state = try TestState.init("findSlotsToClean");
    defer state.deinit();
    const db = state.db;

    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
    );

    _ = try findSlotsToClean(allocator, &reader, 0, 100);
}
