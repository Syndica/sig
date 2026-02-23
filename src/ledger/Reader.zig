pub const std = @import("std");
pub const sig = @import("../sig.zig");
pub const ledger_mod = @import("lib.zig");
const tracy = @import("tracy");

// std
const Allocator = std.mem.Allocator;
const ArrayList = std.array_list.Managed;
const AutoHashMap = std.AutoHashMap;

// sig common
const Counter = sig.prometheus.Counter;
const Entry = sig.core.Entry;
const Hash = sig.core.Hash;
const Histogram = sig.prometheus.Histogram;
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.RwMux;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const SortedSet = sig.utils.collections.SortedSet;
const Timer = sig.time.Timer;
const Transaction = sig.core.Transaction;
const UnixTimestamp = sig.core.UnixTimestamp;

// shred
const Shred = sig.ledger.shred.Shred;
const DataShred = sig.ledger.shred.DataShred;

const shred_layout = sig.ledger.shred.layout;

// ledger
const BytesRef = ledger_mod.database.BytesRef;
const LedgerDB = ledger_mod.db.LedgerDB;
const ColumnFamily = ledger_mod.database.ColumnFamily;
const DuplicateSlotProof = ledger_mod.meta.DuplicateSlotProof;
const PerfSample = ledger_mod.meta.PerfSample;
const SlotMeta = ledger_mod.meta.SlotMeta;
const TransactionStatusMeta = ledger_mod.meta.TransactionStatusMeta;
const TransactionError = ledger_mod.transaction_status.TransactionError;

const schema = ledger_mod.schema.schema;
const key_serializer = ledger_mod.database.key_serializer;
const shredder = ledger_mod.shredder;

const DEFAULT_TICKS_PER_SECOND = sig.core.time.DEFAULT_TICKS_PER_SECOND;

const Logger = sig.trace.Logger("reader");

ledger: *ledger_mod.Ledger,
logger: Logger,
metrics: ?Metrics,
rpc_metrics: ?LedgerRpcApiMetrics,

const Reader = @This();

pub fn isFull(self: *const Reader, allocator: Allocator, slot: Slot) !bool {
    return if (try self.ledger.db.get(allocator, schema.slot_meta, slot)) |meta|
        meta.isFull()
    else
        false;
}

/// Analogous to [slot_meta_iterator](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L604)
pub fn slotMetaIterator(
    self: *const Reader,
    slot: Slot,
) !LedgerDB.Iterator(schema.slot_meta, .forward) {
    return try self.ledger.db.iterator(schema.slot_meta, .forward, slot);
}

/// Analogous to [rooted_slot_iterator](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L667)
pub fn rootedSlotIterator(
    self: *const Reader,
    slot: Slot,
) !LedgerDB.Iterator(schema.rooted_slots, .forward) {
    return self.ledger.db.iterator(schema.rooted_slots, .forward, slot);
}

/// Determines if we can iterate from `starting_slot` to >= `ending_slot` by full slots
/// `starting_slot` is excluded from the `isFull()` check --> TODO: figure out why
///
/// Analogous to [slot_range_connected](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L690)
pub fn slotRangeConnected(
    self: *const Reader,
    allocator: Allocator,
    starting_slot: Slot,
    ending_slot: Slot,
) !bool {
    if (starting_slot == ending_slot) {
        return true;
    }

    var start_slot_meta = try self.ledger.db.get(
        allocator,
        schema.slot_meta,
        starting_slot,
    ) orelse return false;
    defer start_slot_meta.deinit();
    // need a reference so the start_slot_meta.deinit works correctly
    var child_slots: *ArrayList(Slot) = &start_slot_meta.child_slots;

    // TODO: revisit this with more extensive testing. how does agave work fine with
    //       supposed bugs? it may be worth opening a PR in agave with the presumed fix

    // This logic is a little different than agave because agave seems to have several bugs.
    var i: usize = 0;
    var last_slot = starting_slot;
    while (i < child_slots.items.len) : (i += 1) {
        const slot = child_slots.items[i];
        if (try self.ledger.db.get(allocator, schema.slot_meta, slot)) |_slot_meta| {
            var slot_meta = _slot_meta;
            defer slot_meta.deinit();

            if (slot_meta.isFull()) {
                std.debug.assert(last_slot == slot - 1);
                // this append is the same as agave, but is it redundant?
                // does the list already have these slots?
                try child_slots.appendSlice(slot_meta.child_slots.items);
            } else {
                return false; // this is missing from agave, which seems like a bug
            }
        } else {
            return false; // this is missing from agave, which seems like a bug
        }
        if (slot == ending_slot) {
            // in agave this check occurs within the isFull branch, which seems like a bug
            return true;
        }
        last_slot = slot;
    }

    return false;
}

/// Analogous to [get_data_shred](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2220)
pub fn getDataShred(self: *const Reader, slot: Slot, index: u64) !?BytesRef {
    const shred = try self.ledger.db.getBytes(schema.data_shred, .{ slot, index }) orelse
        return null;
    if (shred.data.len != DataShred.constants.payload_size) {
        return error.InvalidDataShred;
    }
    return shred;
}

/// Analogous to [get_coding_shred](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2256)
pub fn getCodeShred(self: *const Reader, slot: Slot, index: u64) !?BytesRef {
    return try self.ledger.db.getBytes(schema.code_shred, .{ slot, index }) orelse return null;
}

/// Analogous to [get_data_shreds_for_slot](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2230)
pub fn getDataShredsForSlot(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
    start_index: u64,
) !ArrayList(Shred) {
    return self.getShredsForSlot(allocator, schema.data_shred, slot, start_index);
}

/// Analogous to [get_coding_shreds_for_slot](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2287-L2288)
pub fn getCodeShredsForSlot(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
    start_index: u64,
) !ArrayList(Shred) {
    return self.getShredsForSlot(allocator, schema.code_shred, slot, start_index);
}

fn getShredsForSlot(
    self: *const Reader,
    allocator: Allocator,
    cf: ColumnFamily,
    slot: Slot,
    start_index: u64,
) !ArrayList(Shred) {
    var iterator = try self.ledger.db.iterator(cf, .forward, .{ slot, start_index });
    defer iterator.deinit();
    var shreds = std.array_list.Managed(Shred).init(allocator);
    while (try iterator.nextBytes()) |shred_entry| {
        const key, const payload = shred_entry;
        defer key.deinit();
        defer payload.deinit();
        const found_slot, _ = try key_serializer.deserialize(
            cf.Key,
            allocator,
            key.data,
        );
        if (found_slot != slot) {
            break;
        }
        try shreds.append(try Shred.fromPayload(allocator, payload.data));
    }
    return shreds;
}

/// Find missing shred indices for a given `slot` within the range
/// [`start_index`, `end_index`]. Missing shreds will only be reported as
/// missing if they should be present by the time this function is called,
/// as controlled by`first_timestamp` and `defer_threshold_ticks`.
///
/// Arguments:
///  - `db_iterator`: Iterator to run search over.
///  - `slot`: The slot to search for missing shreds for.
///  - 'first_timestamp`: Timestamp (ms) for slot's first shred insertion.
///  - `defer_threshold_ticks`: A grace period to allow shreds that are
///    missing to be excluded from the reported missing list. This allows
///    tuning on how aggressively missing shreds should be reported and
///    acted upon.
///  - `start_index`: Begin search (inclusively) at this shred index.
///  - `end_index`: Finish search (exclusively) at this shred index.
///  - `max_missing`: Limit result to this many indices.
///
/// Analogous to [find_missing_data_indexes](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2491)
///
/// agave handles DB errors with placeholder values, which seems like a mistake.
/// this implementation instead returns errors.
pub fn findMissingDataIndexes(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
    first_timestamp: u64,
    defer_threshold_ticks: u64,
    start_index: u64,
    end_index: u64,
    max_missing: usize,
) !ArrayList(u64) {
    if (start_index >= end_index or max_missing == 0) {
        return ArrayList(u64).init(allocator);
    }

    var iter = try self.ledger.db.iterator(schema.data_shred, .forward, .{ slot, start_index });
    defer iter.deinit();

    var missing_indexes = ArrayList(u64).init(allocator);
    const now = @as(u64, @intCast(std.time.milliTimestamp()));
    const ticks_since_first_insert = DEFAULT_TICKS_PER_SECOND * (now -| first_timestamp) / 1000;

    // The index of the first missing shred in the slot
    var prev_index = start_index;
    while (try iter.nextBytes()) |kv_pair| {
        const key, const payload = kv_pair;
        defer key.deinit();
        defer payload.deinit();
        const current_slot, const index = try key_serializer.deserialize(
            schema.data_shred.Key,
            allocator,
            key.data,
        );

        const current_index = if (current_slot > slot) end_index else index;

        const upper_index = @min(current_index, end_index);
        // the tick that will be used to figure out the timeout for this hole
        const reference_tick: u64 = @intCast(try shred_layout.getReferenceTick(payload.data));
        if (ticks_since_first_insert < reference_tick + defer_threshold_ticks) {
            // The higher index holes have not timed out yet
            break;
        }

        const num_to_take = max_missing - missing_indexes.items.len;
        try appendIntegers(&missing_indexes, prev_index, upper_index, num_to_take);

        if (missing_indexes.items.len == max_missing or
            current_slot > slot or
            current_index >= end_index)
        {
            break;
        }

        prev_index = current_index + 1;
    } else {
        const num_to_take = max_missing - missing_indexes.items.len;
        try appendIntegers(&missing_indexes, prev_index, end_index, num_to_take);
    }

    return missing_indexes;
}

fn appendIntegers(
    indexes: *ArrayList(u64),
    prev_index: u64,
    end_index: u64,
    num_to_take: u64,
) !void {
    try indexes.ensureUnusedCapacity(@min(num_to_take, end_index - prev_index));
    var taken: usize = 0;
    for (prev_index..end_index) |index| {
        if (taken >= num_to_take) break;
        indexes.appendAssumeCapacity(index);
        taken += 1;
    }
}

/// Analogous to [get_rooted_block_time](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2523)
pub fn getRootedBlockTime(self: *const Reader, allocator: Allocator, slot: Slot) !UnixTimestamp {
    if (self.rpc_metrics) |m| m.num_get_rooted_block_time.inc();
    var lock = try self.checkLowestCleanupSlot(slot);
    defer lock.unlock();

    if (try self.isRoot(allocator, slot)) {
        return try self.ledger.db.get(allocator, schema.blocktime, slot) orelse
            error.SlotUnavailable;
    }
    return error.SlotNotRooted;
}

/// Analogous to [get_block_height](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2542)
pub fn getBlockHeight(self: *const Reader, allocator: Allocator, slot: Slot) !?u64 {
    if (self.rpc_metrics) |m| m.num_get_block_height.inc();
    var lock = try self.checkLowestCleanupSlot(slot);
    defer lock.unlock();
    return try self.ledger.db.get(allocator, schema.block_height, slot);
}

/// Acquires the `lowest_cleanup_slot` lock and returns a tuple of the held lock
/// and lowest available slot.
///
/// The function will return error.SlotCleanedUp if the input
/// `slot` has already been cleaned-up.
///
/// agave: check_lowest_cleanup_slot
fn checkLowestCleanupSlot(
    self: *const Reader,
    slot: Slot,
) error{SlotCleanedUp}!RwMux(Slot).RLockGuard {
    // lowest_cleanup_slot is the last slot that was not cleaned up by LedgerCleanupService
    const guard = self.ledger.highest_slot_cleaned.read();
    const lowest_cleanup_slot = guard.get().*;
    if (lowest_cleanup_slot > 0 and lowest_cleanup_slot >= slot) {
        return error.SlotCleanedUp;
    }
    // Make caller hold this lock properly; otherwise LedgerCleanupService can purge/compact
    // needed slots here at any given moment
    return guard;
}

/// Acquires the lock of `lowest_cleanup_slot` and returns the tuple of
/// the held lock and the lowest available slot.
///
/// This function ensures a consistent result by using lowest_cleanup_slot
/// as the lower bound for reading columns that do not employ strong read
/// consistency with slot-based delete_range.
///
/// agave: ensure_lowest_cleanup_slot
fn ensureLowestCleanupSlot(
    self: *const Reader,
) error{SlotCleanedUp}!struct { RwMux(Slot).RLockGuard, Slot } {
    const guard = self.ledger.highest_slot_cleaned.read();
    // Make caller hold this lock properly; otherwise LedgerCleanupService can purge/compact
    // needed slots here at any given moment.
    // Ledger callers, like rpc, can process concurrent read queries
    return .{ guard, guard.get().* +| 1 };
}

/// The first complete block that is available in the Ledger ledger
///
/// Analogous to [get_first_available_block](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2556)
pub fn getFirstAvailableBlock(self: *const Reader) !Slot {
    var root_iterator = try self.ledger.db
        .iterator(schema.rooted_slots, .forward, try lowestSlotWithGenesis(self));
    defer root_iterator.deinit();
    const first_root = try root_iterator.nextKey() orelse return 0;
    // If the first root is slot 0, it is genesis. Genesis is always complete, so it is correct
    // to return it as first-available.
    if (first_root == 0) {
        return 0;
    }
    // Otherwise, the block at root-index 0 cannot ever be complete, because it is missing its
    // parent blockhash. A parent blockhash must be calculated from the entries of the previous
    // block. Therefore, the first available complete block is that at root-index 1.
    return try root_iterator.nextKey() orelse 0;
}

fn lowestSlotWithGenesis(
    self: *const Reader,
) !Slot {
    var meta_iter = try self.ledger.db.iterator(schema.slot_meta, .forward, 0);
    defer meta_iter.deinit();
    while (try meta_iter.nextValue()) |slot_meta| {
        if (slot_meta.received > 0) {
            return slot_meta.slot;
        }
    }
    return self.ledger.max_root.load(.monotonic);
}

/// Analogous to [get_rooted_block](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2570)
pub fn getRootedBlock(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
    require_previous_blockhash: bool,
) !VersionedConfirmedBlock {
    if (self.rpc_metrics) |m| m.num_get_rooted_block.inc();
    var lock = try self.checkLowestCleanupSlot(slot);
    defer lock.unlock();

    if (try self.isRoot(allocator, slot)) {
        return self.getCompleteBlock(allocator, slot, require_previous_blockhash);
    }
    return error.SlotNotRooted;
}

/// Analogous to [get_complete_block](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2586)
pub fn getCompleteBlock(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
    require_previous_blockhash: bool,
) !VersionedConfirmedBlock {
    const block_with_entries = try getCompleteBlockWithEntries(
        self,
        allocator,
        slot,
        require_previous_blockhash,
        false,
        false,
    );
    block_with_entries.entries.deinit(); // TODO perf: creating this is a waste
    return block_with_entries.block;
}

/// Analogous to [get_rooted_block_with_entries](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2600)
pub fn getRootedBlockWithEntries(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
    require_previous_blockhash: bool,
) !VersionedConfirmedBlockWithEntries {
    if (self.rpc_metrics) |m| m.num_get_rooted_block_with_entries.inc();
    var lock = try self.checkLowestCleanupSlot(slot);
    defer lock.unlock();

    if (try self.isRoot(allocator, slot)) {
        return self.getCompleteBlockWithEntries(
            allocator,
            slot,
            require_previous_blockhash,
            true,
            false,
        );
    }
    return error.SlotNotRooted;
}

/// Analogous to [get_complete_block_with_entries](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2622)
pub fn getCompleteBlockWithEntries(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
    require_previous_blockhash: bool,
    populate_entries: bool,
    allow_dead_slots: bool,
) !VersionedConfirmedBlockWithEntries {
    const zone = tracy.Zone.init(@src(), .{ .name = "getCompleteBlockWithEntries" });
    defer zone.deinit();

    var slot_meta: SlotMeta = try self.ledger.db.get(allocator, schema.slot_meta, slot) orelse {
        self.logger.debug()
            .logf("getCompleteBlockWithEntries failed for slot {} (missing SlotMeta)", .{slot});
        return error.SlotUnavailable;
    };
    defer slot_meta.deinit();
    if (!slot_meta.isFull()) {
        self.logger.debug()
            .logf("getCompleteBlockWithEntries failed for slot {} (slot not full)", .{slot});
        return error.SlotUnavailable;
    }

    const slot_entries, _, _ =
        try self.getSlotEntriesWithShredInfo(allocator, slot, 0, allow_dead_slots);
    defer {
        for (slot_entries) |se| se.deinit(allocator);
        allocator.free(slot_entries);
    }
    if (slot_entries.len == 0) {
        self.logger.debug()
            .logf("getCompleteBlockWithEntries failed for slot {} (missing slot entries)", .{slot});
        return error.SlotUnavailable;
    }

    const blockhash: Hash = slot_entries[slot_entries.len - 1].hash;
    var starting_transaction_index: usize = 0;

    var entries = if (populate_entries)
        try ArrayList(EntrySummary).initCapacity(allocator, slot_entries.len)
    else
        ArrayList(EntrySummary).init(allocator);
    errdefer entries.deinit();

    var slot_transactions = ArrayList(Transaction).init(allocator);
    var num_moved_slot_transactions: usize = 0;
    defer {
        for (slot_transactions.items[num_moved_slot_transactions..]) |tx| {
            tx.deinit(allocator);
        }
        slot_transactions.deinit();
    }
    for (slot_entries) |*entry| {
        if (populate_entries) {
            try entries.append(.{
                .num_hashes = entry.num_hashes,
                .hash = entry.hash,
                .num_transactions = entry.transactions.len,
                .starting_transaction_index = starting_transaction_index,
            });
            starting_transaction_index += entry.transactions.len;
        }
        try slot_transactions.appendSlice(entry.transactions);
        allocator.free(entry.transactions);
        entry.transactions = &.{};
    }

    var txns_with_statuses = try ArrayList(VersionedTransactionWithStatusMeta)
        .initCapacity(allocator, slot_transactions.items.len);
    errdefer {
        for (txns_with_statuses.items) |item| {
            item.deinit(allocator);
        }
        txns_with_statuses.deinit();
    }
    for (slot_transactions.items) |transaction| {
        transaction.validate() catch |err| {
            self.logger.warn().logf(
                "getCompleteeBlockWithEntries validate failed: {any}, slot: {any}, {any}",
                .{ err, slot, transaction },
            );
        };
        const signature = transaction.signatures[0];
        txns_with_statuses.appendAssumeCapacity(.{
            .transaction = transaction,
            .meta = try self.ledger.db.get(
                allocator,
                schema.transaction_status,
                .{ signature, slot },
            ) orelse
                return error.MissingTransactionMetadata,
        });
        num_moved_slot_transactions += 1;
    }

    // TODO perf: seems wasteful to get all of this, only to read the blockhash
    const parent_slot_entries = if (slot_meta.parent_slot) |parent_slot| blk: {
        const parent_entries_zone = tracy.Zone.init(
            @src(),
            .{ .name = "getCompleteBlockWithEntries: parent slot entries" },
        );
        defer parent_entries_zone.deinit();

        const parent_entries, _, _ = try self.getSlotEntriesWithShredInfo(
            allocator,
            parent_slot,
            0,
            allow_dead_slots,
        );
        break :blk parent_entries;
    } else &.{};
    defer {
        for (parent_slot_entries) |entry| {
            entry.deinit(allocator);
        }
        allocator.free(parent_slot_entries);
    }
    if (parent_slot_entries.len == 0 and require_previous_blockhash) {
        return error.ParentEntriesUnavailable;
    }
    const previous_blockhash = if (parent_slot_entries.len != 0)
        parent_slot_entries[parent_slot_entries.len - 1].hash
    else
        Hash.ZEROES;

    const rewards = try self.ledger.db.get(allocator, schema.rewards, slot) orelse
        schema.rewards.Value{ .rewards = &.{}, .num_partitions = null };

    // The Blocktime and BlockHeight column families are updated asynchronously; they
    // may not be written by the time the complete slot entries are available. In this
    // case, these fields will be null.
    const block_time = try self.ledger.db.get(allocator, schema.blocktime, slot);
    const block_height = try self.ledger.db.get(allocator, schema.block_height, slot);

    const transactions = try txns_with_statuses.toOwnedSlice();
    errdefer allocator.free(transactions);

    return .{
        .block = .{
            .allocator = allocator,
            .previous_blockhash = previous_blockhash,
            .blockhash = blockhash,
            // If the slot is full it should have parent_slot populated from shreds received.
            .parent_slot = slot_meta.parent_slot orelse return error.MissingParentSlot,
            .transactions = transactions,
            .rewards = rewards.rewards,
            .num_partitions = rewards.num_partitions,
            .block_time = block_time,
            .block_height = block_height,
        },
        .entries = entries,
    };
}

/// Returns a transaction status
///
/// Analogous to [get_rooted_transaction_status](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3035)
pub fn getRootedTransactionStatus(
    self: *const Reader,
    allocator: Allocator,
    signature: Signature,
) !?struct { Slot, TransactionStatusMeta } {
    if (self.rpc_metrics) |m| m.num_get_rooted_transaction_status.inc();

    const map = AutoHashMap(Slot, void).init(allocator);
    return self.getTransactionStatus(allocator, signature, &map);
}

/// Returns a transaction status
///
/// Analogous to [get_transaction_status](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3047)
pub fn getTransactionStatus(
    self: *const Reader,
    allocator: Allocator,
    signature: Signature,
    confirmed_unrooted_slots: *const AutoHashMap(Slot, void),
) !?struct { Slot, TransactionStatusMeta } {
    if (self.rpc_metrics) |m| m.num_get_transaction_status.inc();

    const status = try getTransactionStatusWithCounter(
        self,
        allocator,
        signature,
        confirmed_unrooted_slots,
    );
    return status[0];
}

/// Returns a transaction status, as well as a loop counter for unit testing
/// agave: get_transaction_status_with_counter
/// NOTE perf: linear search every time this is run
fn getTransactionStatusWithCounter(
    self: *const Reader,
    allocator: Allocator,
    signature: Signature,
    confirmed_unrooted_slots: *const AutoHashMap(Slot, void),
) !struct { ?struct { Slot, TransactionStatusMeta }, u64 } {
    var counter: u64 = 0;
    var lock, _ = try ensureLowestCleanupSlot(self);
    defer lock.unlock();
    const first_available_block = try getFirstAvailableBlock(self);

    var iterator = try self.ledger.db.iterator(
        schema.transaction_status,
        .forward,
        .{ signature, first_available_block },
    );
    defer iterator.deinit();
    while (try iterator.nextKey()) |key| {
        const found_signature, const slot = key;
        counter += 1;
        if (!signature.eql(&found_signature)) {
            break;
        }
        if (!try self.isRoot(allocator, slot) and !confirmed_unrooted_slots.contains(slot)) {
            continue;
        }
        // TODO get from iterator
        const status = try self.ledger.db.get(allocator, schema.transaction_status, key) orelse
            return error.Unwrap;
        return .{ .{ slot, status }, counter };
    }

    // skipping check for deprecated index: don't need compatibility with agave ledgers

    return .{ null, counter };
}

/// Returns a complete transaction if it was processed in a root
///
/// Analogous to [get_rooted_transaction](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3061)
pub fn getRootedTransaction(
    self: *const Reader,
    allocator: Allocator,
    signature: Signature,
) !?ConfirmedTransactionWithStatusMeta {
    if (self.rpc_metrics) |m| m.num_get_rooted_transaction.inc();
    const map = AutoHashMap(Slot, void).init(allocator);
    return self.getTransactionWithStatus(allocator, signature, &map);
}

/// Returns a complete transaction
///
/// Analogous to [get_complete_transaction](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3073)
pub fn getCompleteTransaction(
    self: *const Reader,
    allocator: Allocator,
    signature: Signature,
    highest_confirmed_slot: Slot,
) !?ConfirmedTransactionWithStatusMeta {
    if (self.rpc_metrics) |m| m.num_get_complete_transaction.inc();

    const max_root = self.ledger.max_root.load(.monotonic);
    var confirmed_unrooted_slots = AutoHashMap(Slot, void).init(allocator);
    var iterator = AncestorIterator{
        .allocator = allocator,
        .db = &self.ledger.db,
        .next_slot = highest_confirmed_slot,
    };
    while (try iterator.next()) |slot| {
        if (slot <= max_root) break;
        try confirmed_unrooted_slots.put(slot, {});
    }

    return self.getTransactionWithStatus(allocator, signature, &confirmed_unrooted_slots);
}

/// Analogous to [get_transaction_with_status](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3090)
fn getTransactionWithStatus(
    self: *const Reader,
    allocator: Allocator,
    signature: Signature,
    confirmed_unrooted_slots: *const AutoHashMap(Slot, void),
) !?ConfirmedTransactionWithStatusMeta {
    const status = try self.getTransactionStatus(allocator, signature, confirmed_unrooted_slots);
    const slot, const meta = status orelse return null;
    const transaction = if (try self.findTransactionInSlot(allocator, slot, signature)) |t|
        t
    else
        return error.TransactionStatusSlotMismatch; // Should not happen

    const block_time = try self.getBlockTime(allocator, slot);

    return .{
        .slot = slot,
        .tx_with_meta = .{ .complete = .{ .transaction = transaction, .meta = meta } },
        .block_time = block_time,
    };
}

fn getBlockTime(self: *const Reader, allocator: Allocator, slot: Slot) !?UnixTimestamp {
    var lock = try self.checkLowestCleanupSlot(slot);
    defer lock.unlock();
    return self.ledger.db.get(allocator, schema.blocktime, slot);
}

/// Analogous to [find_transaction_in_slot](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3115)
///
/// TODO: optimize the performance of this function. this is a critical function for the very
/// slow getTransaction RPC method and it appears to have significant room for improvement.
fn findTransactionInSlot(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
    signature: Signature,
) !?Transaction {
    const slot_entries = try self.getSlotEntries(allocator, slot, 0);
    defer {
        for (slot_entries) |entry| entry.deinit(allocator);
        allocator.free(slot_entries);
    }
    // NOTE perf: linear search runs from scratch every time this is called
    for (slot_entries) |entry| {
        for (entry.transactions) |transaction| {
            // NOTE perf: redundant calls to validate every time this is called
            if (transaction.validate()) |_| {} else |err| {
                self.logger.warn().logf(
                    "LedgerReader.findTransactionInSlot validate failed: {any}, slot: {}, {any}",
                    .{ err, slot, transaction },
                );
            }
            if (signature.eql(&transaction.signatures[0])) {
                return try transaction.clone(allocator);
            }
        }
    }
    return null;
}

/// Analogous to [get_confirmed_signatures_for_address2](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3220)
pub fn getConfirmedSignaturesForAddress(
    self: *const Reader,
    allocator: Allocator,
    address: Pubkey,
    highest_slot: Slot, // highest_super_majority_root or highest_confirmed_slot
    before: ?Signature,
    until: ?Signature,
    limit: usize,
) !SignatureInfosForAddress {
    if (self.rpc_metrics) |m| m.num_get_confirmed_signatures_for_address2.inc();

    var confirmed_unrooted_slots = AutoHashMap(Slot, void).init(allocator);
    defer confirmed_unrooted_slots.deinit();
    const max_root = self.ledger.max_root.load(.monotonic);
    var ancestor_iterator = AncestorIterator{
        .allocator = allocator,
        .db = &self.ledger.db,
        .next_slot = highest_slot,
    };
    while (try ancestor_iterator.next()) |slot| {
        if (slot <= max_root) break;
        try confirmed_unrooted_slots.put(slot, {});
    }

    // Figure the `slot` to start listing signatures at, based on the ledger location of the
    // `before` signature if present.  Also generate a HashSet of signatures that should
    // be excluded from the results.
    var get_before_slot_timer = Timer.start();
    const slot: Slot, //
    var before_excluded_signatures: AutoHashMap(Signature, void) //
    = if (before) |before_signature| blk: {
        if (try self.getTransactionStatus(
            allocator,
            before_signature,
            &confirmed_unrooted_slots,
        )) |status| {
            const slot, _ = status;
            const slot_signatures = try self.getBlockSignaturesReversed(allocator, slot);
            defer slot_signatures.deinit();
            var excluded = AutoHashMap(Signature, void).init(allocator);
            for (slot_signatures.items) |signature| {
                try excluded.put(signature, {});
                if (signature.eql(&before_signature)) break;
            }
            break :blk .{ slot, excluded };
        } else return SignatureInfosForAddress.default(allocator);
    } else .{ highest_slot, AutoHashMap(Signature, void).init(allocator) };
    defer before_excluded_signatures.deinit();
    if (self.metrics) |m| {
        m.get_before_slot_us.observe(get_before_slot_timer.read().asMicros());
    }

    // Generate a HashSet of signatures that should be excluded from the results based on
    // `until` signature
    const first_available_block = try getFirstAvailableBlock(self);
    var get_until_slot_timer = Timer.start();
    const lowest_slot, var until_excluded_signatures = if (until) |until_signature| blk: {
        if (try self.getTransactionStatus(
            allocator,
            until_signature,
            &confirmed_unrooted_slots,
        )) |status| {
            const lowest_slot, _ = status;
            const slot_signatures = try self.getBlockSignatures(allocator, lowest_slot);
            defer slot_signatures.deinit();
            var excluded = AutoHashMap(Signature, void).init(allocator);
            for (slot_signatures.items) |signature| {
                try excluded.put(signature, {});
                if (signature.eql(&until_signature)) break;
            }
            break :blk .{ lowest_slot, excluded };
        } else break :blk .{
            first_available_block,
            AutoHashMap(Signature, void).init(allocator),
        };
    } else .{
        first_available_block,
        AutoHashMap(Signature, void).init(allocator),
    };
    defer until_excluded_signatures.deinit();
    if (self.metrics) |m| {
        m.get_until_slot_us.observe(get_until_slot_timer.read().asMicros());
    }

    // Fetch the list of signatures that affect the given address
    var address_signatures = ArrayList(struct { Slot, Signature }).init(allocator);
    defer address_signatures.deinit();

    // Get signatures in `slot`
    var get_initial_slot_timer = Timer.start();
    const signatures = try self.findAddressSignaturesForSlot(allocator, address, slot);
    for (1..signatures.items.len + 1) |i| {
        const this_slot, const signature = signatures.items[signatures.items.len - i];
        std.debug.assert(slot == this_slot);
        if (!before_excluded_signatures.contains(signature) and
            !until_excluded_signatures.contains(signature))
        {
            try address_signatures.append(.{ this_slot, signature });
        }
    }
    if (self.metrics) |m| {
        m.get_initial_slot_us.observe(get_initial_slot_timer.read().asMicros());
    }

    var address_signatures_iter_timer = Timer.start();
    // Regardless of whether a `before` signature is provided, the latest relevant
    // `slot` is queried directly with the `find_address_signatures_for_slot()`
    // call above. Thus, this iterator starts at the lowest entry of `address,
    // slot` and iterates backwards to continue reporting the next earliest
    // signatures.
    var iterator = try self.ledger.db.iterator(schema.address_signatures, .reverse, .{
        .address = address,
        .slot = slot,
        .transaction_index = 0,
        .signature = Signature.ZEROES,
    });
    defer iterator.deinit();

    // Iterate until limit is reached
    while (try iterator.nextKey()) |key| {
        if (address_signatures.items.len >= limit) break;
        if (key.slot < lowest_slot) {
            break;
        }
        if (address.equals(&key.address) and
            (try self.isRoot(allocator, key.slot) or
                confirmed_unrooted_slots.contains(key.slot)) and
            !until_excluded_signatures.contains(key.signature))
        {
            try address_signatures.append(.{ key.slot, key.signature });
        }
    }
    if (self.metrics) |m| {
        m.address_signatures_iter_us.observe(address_signatures_iter_timer.read().asMicros());
    }

    address_signatures.items.len = @min(address_signatures.items.len, limit);

    // Fill in the status information for each found transaction
    var get_status_info_timer = Timer.start();
    var infos = ArrayList(ConfirmedTransactionStatusWithSignature).init(allocator);
    for (address_signatures.items) |asig| {
        const the_slot, const signature = asig;
        const maybe_status = try self.getTransactionStatus(
            allocator,
            signature,
            &confirmed_unrooted_slots,
        );
        const err = if (maybe_status) |status| status[1].status else null;
        const memo = if (try self.ledger.db.getBytes(
            schema.transaction_memos,
            .{ signature, the_slot },
        )) |memo_ref| blk: {
            var memo = ArrayList(u8).init(allocator);
            try memo.appendSlice(memo_ref.data);
            break :blk memo;
        } else null;
        const block_time = try self.getBlockTime(allocator, the_slot);
        try infos.append(.{
            .signature = signature,
            .slot = the_slot,
            .err = err,
            .memo = memo,
            .block_time = block_time,
        });
    }
    if (self.metrics) |m| {
        m.get_status_info_us.observe(get_status_info_timer.read().asMicros());
    }

    return .{
        .infos = infos,
        .found_before = true, // if `before` signature was not found, this method returned early
    };
}

/// agave: get_block_signatures_rev
/// TODO replace usage with getBlockSignatures
fn getBlockSignaturesReversed(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
) !ArrayList(Signature) {
    const block = try self.getCompleteBlock(allocator, slot, false);
    defer block.deinit(allocator);

    var signatures = try ArrayList(Signature)
        .initCapacity(allocator, block.transactions.len);
    for (1..block.transactions.len + 1) |i| {
        const transaction_with_meta = block.transactions[block.transactions.len - i];
        if (transaction_with_meta.transaction.signatures.len > 0) {
            signatures.appendAssumeCapacity(
                transaction_with_meta.transaction.signatures[0],
            );
        }
    }

    return signatures;
}

fn getBlockSignatures(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
) !ArrayList(Signature) {
    const block = try self.getCompleteBlock(allocator, slot, false);
    defer block.deinit(allocator);

    var signatures = try ArrayList(Signature)
        .initCapacity(allocator, block.transactions.len);
    for (block.transactions) |transaction_with_meta| {
        if (transaction_with_meta.transaction.signatures.len > 0) {
            signatures.appendAssumeCapacity(
                transaction_with_meta.transaction.signatures[0],
            );
        }
    }

    return signatures;
}

const SlotSignature = struct { Slot, Signature };

/// Returns all signatures for an address in a particular slot, regardless of whether that slot
/// has been rooted. The transactions will be ordered by their occurrence in the block
///
/// agave: find_address_signatures_for_slot
fn findAddressSignaturesForSlot(
    self: *const Reader,
    allocator: Allocator,
    pubkey: Pubkey,
    slot: Slot,
) !ArrayList(SlotSignature) {
    var lock, const lowest_available_slot = try ensureLowestCleanupSlot(self);
    defer lock.unlock();
    var signatures = ArrayList(SlotSignature).init(allocator);
    if (slot < lowest_available_slot) {
        return signatures;
    }
    var index_iterator = try self.ledger.db.iterator(schema.address_signatures, .forward, .{
        .address = pubkey,
        .slot = @max(slot, lowest_available_slot),
        .transaction_index = 0,
        .signature = Signature.ZEROES,
    });
    defer index_iterator.deinit();
    while (try index_iterator.nextKey()) |key| {
        if (key.slot > slot or !key.address.equals(&pubkey)) {
            break;
        }
        try signatures.append(.{ slot, key.signature });
    }
    return signatures;
}

const SlotPerfSample = struct { Slot, PerfSample };

/// Analogous to [get_recent_perf_samples](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3408)
pub fn getRecentPerfSamples(
    self: *const Reader,
    allocator: Allocator,
    num: usize,
) !ArrayList(SlotPerfSample) {
    var samples = ArrayList(SlotPerfSample).init(allocator);
    var iterator = try self.ledger.db.iterator(schema.perf_samples, .reverse, null);
    defer iterator.deinit();
    while (try iterator.next()) |perf_sample| {
        if (samples.items.len == num) {
            break;
        }
        try samples.append(perf_sample);
    }
    return samples;
}

const ProgramCost = struct { Pubkey, u64 };

/// Analogous to [read_program_costs](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3445)
pub fn readProgramCosts(
    self: *const Reader,
    allocator: Allocator,
) !ArrayList(ProgramCost) {
    var costs = ArrayList(ProgramCost).init(allocator);
    var iterator = try self.ledger.db.iterator(schema.program_costs, .reverse, null);
    defer iterator.deinit();
    while (try iterator.next()) |next| {
        try costs.append(.{ next[0], next[1].cost });
    }
    return costs;
}

/// Returns the entry vector for the slot starting with `shred_start_index`
///
/// Analogous to [get_slot_entries](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3466)
pub fn getSlotEntries(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
    shred_start_index: u64,
) ![]const Entry {
    const zone = tracy.Zone.init(@src(), .{ .name = "getSlotEntries" });
    defer zone.deinit();

    const entries, _, _ =
        try self.getSlotEntriesWithShredInfo(allocator, slot, shred_start_index, false);
    return entries;
}

/// Returns the entry vector for the slot starting with `shred_start_index`, the number of
/// shreds that comprise the entry vector, and whether the slot is full (consumed all shreds).
///
/// Analogous to [get_slot_entries_with_shred_info](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3473)
pub fn getSlotEntriesWithShredInfo(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
    start_index: u64,
    allow_dead_slots: bool,
) !struct { []Entry, u64, bool } {
    const zone = tracy.Zone.init(@src(), .{ .name = "getSlotEntriesWithShredInfo" });
    defer zone.deinit();

    const completed_ranges, const maybe_slot_meta =
        try self.getCompletedRanges(allocator, slot, start_index);
    defer completed_ranges.deinit();

    // Check if the slot is dead *after* fetching completed ranges to avoid a race
    // where a slot is marked dead by another thread before the completed range query finishes.
    // This should be sufficient because full slots will never be marked dead from another thread,
    // this can only happen during entry processing during replay stage.
    if (try self.isDead(allocator, slot) and !allow_dead_slots) {
        return error.DeadSlot;
    }
    if (completed_ranges.items.len == 0) {
        return .{ &.{}, 0, false };
    }

    const slot_meta = maybe_slot_meta.?;
    _, const end_index = completed_ranges.items[completed_ranges.items.len - 1];
    const num_shreds = end_index - start_index;

    const entries = try getSlotEntriesInBlock(
        self,
        allocator,
        slot,
        completed_ranges,
        &slot_meta,
    );
    return .{ entries, num_shreds, slot_meta.isFull() };
}

/// agave: get_completed_ranges
fn getCompletedRanges(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
    start_index: u64,
) !struct { CompletedRanges, ?SlotMeta } {
    const maybe_slot_meta = try self.ledger.db.get(allocator, schema.slot_meta, slot);
    if (maybe_slot_meta == null) {
        return .{ CompletedRanges.init(allocator), null };
    }
    var slot_meta: SlotMeta = maybe_slot_meta.?;
    defer slot_meta.deinit();

    // Find all the ranges for the completed data blocks
    const completed_ranges = try getCompletedDataRanges(
        allocator,
        @intCast(start_index),
        &slot_meta.completed_data_indexes,
        @intCast(slot_meta.consecutive_received_from_0),
    );

    return .{ completed_ranges, slot_meta };
}

/// Get the range of indexes [start_index, end_index] of every completed data block
/// agave: get_completed_data_ranges
fn getCompletedDataRanges(
    allocator: Allocator,
    start_index: u32,
    completed_data_indexes: *SortedSet(u32),
    consumed: u32,
) Allocator.Error!CompletedRanges {
    // `consumed` is the next missing shred index, but shred `i` existing in
    // completed_data_end_indexes implies it's not missing
    std.debug.assert(!completed_data_indexes.contains(consumed));
    var ranges = CompletedRanges.init(allocator);
    var begin: u32 = start_index;
    for (completed_data_indexes.range(start_index, consumed)) |index| {
        try ranges.append(.{ begin, index + 1 });
        begin = index + 1;
    }
    return ranges;
}

/// Analogous to [get_entries_in_data_block](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3700)
pub fn getEntriesInDataBlock(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
    start_index: u32,
    end_index: u32,
    slot_meta: ?*const SlotMeta,
) ![]const Entry {
    var fba_slice: [@sizeOf(struct { u32, u32 })]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_slice);
    var completed_ranges = CompletedRanges.initCapacity(fba.allocator(), 1) catch unreachable;
    completed_ranges.appendAssumeCapacity(.{ start_index, end_index });
    return self.getSlotEntriesInBlock(allocator, slot, completed_ranges, slot_meta);
}

/// Fetch the entries corresponding to all of the shred indices in `completed_ranges`
/// This function takes advantage of the fact that `completed_ranges` are both
/// contiguous and in sorted order. To clarify, suppose completed_ranges is as follows:
///   completed_ranges = [..., (s_i, e_i), (s_i+1, e_i+1), ...]
/// Then, the following statements are true:
///   s_i < e_i < s_i+1 < e_i+1
///   e_i == s_i+1 + 1
///
/// Analogous to [get_slot_entries_in_block](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3614)
fn getSlotEntriesInBlock(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
    completed_ranges: CompletedRanges,
    maybe_slot_meta: ?*const SlotMeta,
) ![]Entry {
    const zone = tracy.Zone.init(@src(), .{ .name = "getSlotEntriesInBlock" });
    defer zone.deinit();

    if (completed_ranges.items.len == 0) {
        return &.{};
    }
    const all_ranges_start_index = completed_ranges.items[0][0];
    const all_ranges_end_index = completed_ranges.items[completed_ranges.items.len - 1][1];

    var data_shreds = try ArrayList(DataShred).initCapacity(
        allocator,
        all_ranges_end_index - all_ranges_start_index + 1,
    );
    defer {
        for (data_shreds.items) |ds| ds.deinit();
        data_shreds.deinit();
    }
    for (all_ranges_start_index..all_ranges_end_index) |index| {
        // TODO perf: multi_get_bytes
        if (try self.ledger.db.getBytes(
            schema.data_shred,
            .{ slot, @intCast(index) },
        )) |shred_bytes| {
            defer shred_bytes.deinit();
            const shred = try Shred.fromPayload(allocator, shred_bytes.data);
            data_shreds.appendAssumeCapacity(shred.data);
        } else {
            if (maybe_slot_meta) |slot_meta| {
                const lcs_value, var lcs = self.ledger.highest_slot_cleaned.readWithLock();
                defer lcs.unlock();
                if (slot > lcs_value.*) {
                    self.logger.err().logf(
                        // TODO write a function to clean up newlines for cases like this
                        \\Shred with slot: {}, index: {}, consumed: {}, completed_indexes: {any}
                        \\must exist if shred index was included in a range: {} {}
                    ,
                        .{
                            slot,
                            index,
                            slot_meta.consecutive_received_from_0,
                            slot_meta.completed_data_indexes,
                            all_ranges_start_index,
                            all_ranges_end_index,
                        },
                    );
                    return error.CorruptedLedger;
                }
            }
            self.logger.err().logf("Missing shred for slot {}, index {}", .{ slot, index });
            return error.InvalidShredData;
        }
    }

    var entries = std.ArrayListUnmanaged(Entry).empty;
    errdefer {
        for (entries.items) |entry| entry.deinit(allocator);
        entries.deinit(allocator);
    }
    {
        const deserializing_zone = tracy.Zone.init(
            @src(),
            .{ .name = "getSlotEntriesInBlock: deserializing" },
        );
        defer deserializing_zone.deinit();

        for (completed_ranges.items) |range| {
            const start_index, const end_index = range;

            // The indices from completed_ranges refer to shred indices in the
            // entire block; map those indices to indices within data_shreds
            const range_start_index: usize = @intCast(start_index - all_ranges_start_index);
            const range_end_index: usize = @intCast(end_index - all_ranges_start_index);
            const range_shreds: []DataShred =
                data_shreds.items[range_start_index..range_end_index];

            const last_shred = range_shreds[range_shreds.len - 1];
            std.debug.assert(last_shred.dataComplete() or last_shred.isLastInSlot());
            // self.logger.tracef("{any} data shreds in last FEC set", data_shreds.items.len);

            const bytes = shredder.deshred(allocator, range_shreds) catch |e| {
                self.logger.err().logf("failed to deshred entries buffer from shreds: {}", .{e});
                return e;
            };
            defer bytes.deinit();
            const these_entries = bincode.readFromSlice(
                allocator,
                []Entry,
                bytes.items,
                .{},
            ) catch |e| {
                self.logger.err().logf("failed to deserialize entries from shreds: {}", .{e});
                return e;
            };
            defer allocator.free(these_entries);
            errdefer for (these_entries) |e| e.deinit(allocator);
            try entries.appendSlice(allocator, these_entries);
        }
    }
    return entries.toOwnedSlice(allocator);
}

/// Returns a mapping from each elements of `slots` to a list of the
/// element's children slots.
///
/// Analogous to [get_slots_since](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3821)
pub fn getSlotsSince(
    self: *const Reader,
    allocator: Allocator,
    slots: []const Slot,
) !std.AutoArrayHashMapUnmanaged(Slot, std.ArrayListUnmanaged(Slot)) {
    const zone = tracy.Zone.init(@src(), .{ .name = "getSlotsSince" });
    defer zone.deinit();

    // TODO perf: support multi_get in db
    var map = std.AutoArrayHashMapUnmanaged(Slot, std.ArrayListUnmanaged(Slot)).empty;
    errdefer {
        for (map.values()) |*list| list.deinit(allocator);
        map.deinit(allocator);
    }
    for (slots) |slot| {
        if (try self.ledger.db.get(allocator, schema.slot_meta, slot)) |meta| {
            var child_slots = meta.child_slots;
            errdefer child_slots.deinit();
            var cdi = meta.completed_data_indexes;
            cdi.deinit();
            try map.put(allocator, slot, child_slots.moveToUnmanaged());
        }
    }
    return map;
}

/// Analogous to [is_root](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3838)
///
/// agave handles DB errors with placeholder values, which seems like a mistake.
/// this implementation instead returns errors.
pub fn isRoot(self: *const Reader, allocator: Allocator, slot: Slot) !bool {
    return try self.ledger.db.get(allocator, schema.rooted_slots, slot) orelse false;
}

/// Returns true if a slot is between the rooted slot bounds of the ledger, but has not itself
/// been rooted. This is either because the slot was skipped, or due to a gap in ledger data,
/// as when booting from a newer snapshot.
///
/// Analogous to [is_skipped](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3845)
///
/// agave handles DB errors with placeholder values, which seems like a mistake.
/// this implementation instead returns errors.
pub fn isSkipped(self: *const Reader, allocator: Allocator, slot: Slot) !bool {
    var iterator = try self.ledger.db.iterator(schema.rooted_slots, .forward, 0);
    defer iterator.deinit();
    const lowest_root = try iterator.nextKey() orelse 0;
    return if (try self.ledger.db.get(allocator, schema.rooted_slots, slot)) |_|
        false
    else
        slot < self.ledger.max_root.load(.monotonic) and slot > lowest_root;
}

/// Analogous to [get_bank_hash](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3873)
pub fn getBankHash(self: *const Reader, allocator: Allocator, slot: Slot) !?Hash {
    return if (try self.ledger.db.get(allocator, schema.bank_hash, slot)) |versioned|
        versioned.frozenHash()
    else
        null;
}

/// Analogous to [is_duplicate_confirmed](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3880)
pub fn isDuplicateConfirmed(self: *const Reader, allocator: Allocator, slot: Slot) !bool {
    return if (try self.ledger.db.get(allocator, schema.bank_hash, slot)) |versioned|
        versioned.isDuplicateConfirmed()
    else
        false;
}

/// Returns information about a single optimistically confirmed slot
///
/// Analogous to [get_optimistic_slot](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3899)
pub fn getOptimisticSlot(
    self: *const Reader,
    allocator: Allocator,
    slot: Slot,
) !?struct { Hash, UnixTimestamp } {
    const meta = try self.ledger.db.get(allocator, schema.optimistic_slots, slot) orelse
        return null;
    return .{ meta.V0.hash, meta.V0.timestamp };
}

const OptimisticSlot = struct { Slot, Hash, UnixTimestamp };
/// Returns information about the `num` latest optimistically confirmed slot
///
/// The returned slots are sorted in increasing order of slot number.
///
/// Analogous to [get_latest_optimistic_slots](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3907)
pub fn getLatestOptimisticSlots(
    self: *const Reader,
    allocator: Allocator,
    num: usize,
) !ArrayList(OptimisticSlot) {
    var optimistic_slots = std.array_list.Managed(OptimisticSlot).init(allocator);
    errdefer optimistic_slots.deinit();

    var iter = try self.ledger.db.iterator(schema.optimistic_slots, .reverse, null);
    defer iter.deinit();

    var count: usize = 0;
    while (try iter.next()) |entry| : (count += 1) {
        if (count >= num) break;
        const slot, const meta = entry;
        try optimistic_slots.append(.{ slot, meta.V0.hash, meta.V0.timestamp });
    }
    return optimistic_slots;
}

/// Analogous to [is_dead](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3962)
pub fn isDead(self: *const Reader, allocator: Allocator, slot: Slot) !bool {
    return try self.ledger.db.get(allocator, schema.dead_slots, slot) orelse false;
}

/// Analogous to [has_duplicate_shreds_in_slot](https://github.com/anza-xyz/agave/blob/60ba168d54d7ac6683f8f2e41a0e325f29d9ab2b/ledger/src/blockstore.rs#L4040)
pub fn isDuplicateSlot(self: *const Reader, slot: Slot) !bool {
    return try self.ledger.db.contains(schema.duplicate_slots, slot);
}

/// Analogous to [get_first_duplicate_proof](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3983)
pub fn getFirstDuplicateProof(self: *const Reader) !?struct { Slot, DuplicateSlotProof } {
    var iterator = try self.ledger.db.iterator(schema.duplicate_slots, .forward, 0);
    defer iterator.deinit();
    return try iterator.next();
}

/// Analogous to [get_duplicate_slot](https://github.com/anza-xyz/agave/blob/6e84f7eab872cc553995e7d35ff1f2ec0dd37751/ledger/src/blockstore.rs#L4057)
pub fn getDuplicateSlot(self: *const Reader, allocator: Allocator, slot: u64) !?DuplicateSlotProof {
    return try self.ledger.db.get(allocator, schema.duplicate_slots, slot);
}

/// Returns the shred already stored in ledger if it has a different
/// payload than the given `shred` but the same (slot, index, shred-type).
/// This implies the leader generated two different shreds with the same
/// slot, index and shred-type.
/// The payload is modified so that it has the same retransmitter's
/// signature as the `shred` argument.
///
/// Analogous to [is_shred_duplicate](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L4009)
pub fn isShredDuplicate(self: *const Reader, allocator: Allocator, shred: Shred) !?ArrayList(u8) {
    const id = shred.id();
    const other_ref = try switch (shred) {
        .data => self.getDataShred(id.slot, @intCast(id.index)),
        .code => self.getCodeShred(id.slot, @intCast(id.index)),
    } orelse return null;
    defer other_ref.deinit();

    // TODO find another approach that doesn't copy unless it's actually returned
    var other = ArrayList(u8).init(allocator);
    errdefer other.deinit();
    try other.appendSlice(other_ref.data);

    if (shred.retransmitterSignature()) |signature| {
        shred_layout.setRetransmitterSignature(other.items, signature) catch |err| {
            self.logger.err().logf("set retransmitter signature failed: {any}", .{err});
        };
    } else |_| {
        // TODO: agave does nothing here. is that correct?
    }
    if (std.mem.eql(u8, other.items, shred.payload())) {
        other.deinit();
        return null;
    } else {
        return other;
    }
}

/// find the first available slot in ledger that has some data in it
/// Analogous to [lowest_slot](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L4073)
pub fn lowestSlot(self: *const Reader) !Slot {
    var iterator = try self.ledger.db.iterator(schema.slot_meta, .forward, null);
    defer iterator.deinit();
    while (try iterator.next()) |entry| {
        const slot, const meta = entry;
        if (slot > 0 and meta.received > 0) {
            return slot;
        }
    }
    // This means ledger is empty, should never get here aside from right at boot.
    return self.ledger.max_root.load(.monotonic);
}

/// Returns the highest rooted slot known to the ledger
pub fn maxRoot(self: *const Reader) Slot {
    return self.ledger.max_root.load(.monotonic);
}

/// Returns the highest available slot in the ledger
///
/// Analogous to [highest_slot](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L4100)
pub fn highestSlot(self: *const Reader) !?Slot {
    var iterator = try self.ledger.db.iterator(schema.slot_meta, .reverse, null);
    defer iterator.deinit();
    return try iterator.nextKey();
}

const CompletedRanges = ArrayList(struct { u32, u32 });

/// Confirmed block with type guarantees that transaction metadata
/// is always present. Used for uploading to BigTable.
pub const VersionedConfirmedBlock = struct {
    allocator: Allocator,
    previous_blockhash: Hash,
    blockhash: Hash,
    parent_slot: Slot,
    transactions: []const VersionedTransactionWithStatusMeta,
    rewards: []const ledger_mod.meta.Reward,
    num_partitions: ?u64,
    block_time: ?UnixTimestamp,
    block_height: ?u64,

    pub fn deinit(self: @This(), allocator: Allocator) void {
        for (self.transactions) |it| it.deinit(allocator);
        allocator.free(self.transactions);
        allocator.free(self.rewards);
    }
};

/// Confirmed block with type guarantees that transaction metadata is always
/// present, as well as a list of the entry data needed to cryptographically
/// verify the block. Used for uploading to BigTable.
const VersionedConfirmedBlockWithEntries = struct {
    block: VersionedConfirmedBlock,
    entries: ArrayList(EntrySummary),
};

// Data needed to reconstruct an Entry, given an ordered list of transactions in
// a block. Used for uploading to BigTable.
const EntrySummary = struct {
    num_hashes: u64,
    hash: Hash,
    num_transactions: u64,
    starting_transaction_index: usize,
};

const ConfirmedTransactionWithStatusMeta = struct {
    slot: Slot,
    tx_with_meta: TransactionWithStatusMeta,
    block_time: ?UnixTimestamp,
};

pub const TransactionWithStatusMeta = union(enum) {
    // Very old transactions may be missing metadata
    missing_metadata: Transaction,
    // Versioned stored transaction always have metadata
    complete: VersionedTransactionWithStatusMeta,
};

pub const VersionedTransactionWithStatusMeta = struct {
    transaction: Transaction,
    meta: TransactionStatusMeta,

    pub fn deinit(self: @This(), allocator: Allocator) void {
        self.transaction.deinit(allocator);
        self.meta.deinit(allocator);
    }
};

const SignatureInfosForAddress = struct {
    infos: ArrayList(ConfirmedTransactionStatusWithSignature),
    found_before: bool,

    pub fn default(allocator: Allocator) SignatureInfosForAddress {
        return .{
            .infos = ArrayList(ConfirmedTransactionStatusWithSignature).init(allocator),
            .found_before = false,
        };
    }
};

const ConfirmedTransactionStatusWithSignature = struct {
    signature: Signature,
    slot: Slot,
    err: ?TransactionError,
    memo: ?ArrayList(u8),
    block_time: ?UnixTimestamp,
};

pub const Metrics = struct {
    get_before_slot_us: *Histogram,
    get_initial_slot_us: *Histogram,
    address_signatures_iter_us: *Histogram,
    get_status_info_us: *Histogram,
    get_until_slot_us: *Histogram,

    pub const prefix = "ledger_reader";
    pub const histogram_buckets = sig.prometheus.histogram.exponentialBuckets(5, -1, 10);
};

pub const LedgerRpcApiMetrics = struct {
    num_get_block_height: *Counter,
    num_get_complete_transaction: *Counter,
    num_get_confirmed_signatures_for_address: *Counter,
    num_get_confirmed_signatures_for_address2: *Counter,
    num_get_rooted_block: *Counter,
    num_get_rooted_block_time: *Counter,
    num_get_rooted_transaction: *Counter,
    num_get_rooted_transaction_status: *Counter,
    num_get_rooted_block_with_entries: *Counter,
    num_get_transaction_status: *Counter,

    pub const prefix = "ledger_rpc_api";
};

pub const AncestorIterator = struct {
    allocator: Allocator,
    db: *LedgerDB,
    next_slot: ?Slot,

    pub fn initExclusive(
        allocator: Allocator,
        db: *LedgerDB,
        start_slot: Slot,
    ) !AncestorIterator {
        var self = AncestorIterator.initInclusive(allocator, db, start_slot);
        _ = try self.next();
        return self;
    }

    pub fn initInclusive(
        allocator: Allocator,
        db: *LedgerDB,
        start_slot: Slot,
    ) AncestorIterator {
        return .{
            .allocator = allocator,
            .db = db,
            .next_slot = start_slot,
        };
    }

    pub fn next(self: *AncestorIterator) !?Slot {
        if (self.next_slot) |slot| {
            if (slot == 0) {
                self.next_slot = null;
            } else if (try self.db.get(self.allocator, schema.slot_meta, slot)) |slot_meta| {
                defer slot_meta.deinit();
                self.next_slot = slot_meta.parent_slot;
            } else {
                self.next_slot = null;
            }

            return slot;
        }
        return null;
    }
};

const bincode = sig.bincode;
const CodeShred = ledger_mod.shred.CodeShred;

const test_shreds = @import("test_shreds.zig");

// // TODO: -- would likely make most sense to test these with insert_shreds
// getCompletedRanges
// getSlotEntriesInBlock
// getCompleteBlockWithEntries

test getLatestOptimisticSlots {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    {
        var write_batch = try state.db.initWriteBatch();
        defer write_batch.deinit();
        const hash = Hash{ .data = .{1} ** 32 };
        try write_batch.put(schema.optimistic_slots, 1, .{
            .V0 = .{
                .hash = hash,
                .timestamp = 10,
            },
        });
        try state.db.commit(&write_batch);

        const reader = state.reader();
        const get_hash, const ts = (try reader.getOptimisticSlot(allocator, 1)).?;
        try std.testing.expectEqual(hash, get_hash);
        try std.testing.expectEqual(10, ts);

        var opt_slots = try reader.getLatestOptimisticSlots(allocator, 1);
        defer opt_slots.deinit();

        try std.testing.expectEqual(1, opt_slots.items.len);
        try std.testing.expectEqual(1, opt_slots.items[0][0]); // slot match
        try std.testing.expectEqual(hash, opt_slots.items[0][1]); // hash match
        try std.testing.expectEqual(ts, opt_slots.items[0][2]); // ts match
    }

    {
        var write_batch = try state.db.initWriteBatch();
        defer write_batch.deinit();
        const hash = Hash{ .data = .{10} ** 32 };
        try write_batch.put(schema.optimistic_slots, 10, .{
            .V0 = .{
                .hash = hash,
                .timestamp = 100,
            },
        });
        try state.db.commit(&write_batch);

        const reader = state.reader();
        const get_hash, const ts = (try reader.getOptimisticSlot(allocator, 10)).?;
        try std.testing.expectEqual(hash, get_hash);
        try std.testing.expectEqual(100, ts);

        var opt_slots = try reader.getLatestOptimisticSlots(allocator, 2);
        defer opt_slots.deinit();

        try std.testing.expectEqual(2, opt_slots.items.len);
        try std.testing.expectEqual(10, opt_slots.items[0][0]); // slot match
        try std.testing.expectEqual(hash, opt_slots.items[0][1]); // hash match
        try std.testing.expectEqual(ts, opt_slots.items[0][2]); // ts match
    }
}

test getFirstDuplicateProof {
    const allocator = std.testing.allocator;

    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    const path = std.fmt.comptimePrint(
        "{s}/{s}",
        .{ sig.TEST_STATE_DIR ++ "blockstore/insert_shred", "getFirstDuplicateProof" },
    );
    try sig.ledger.tests.freshDir(path);
    var db = try LedgerDB.open(allocator, .FOR_TESTS, path, false);
    defer db.deinit();

    var self = ledger_mod.Ledger{
        .db = db,
        .highest_slot_cleaned = RwMux(Slot).init(0),
        .max_root = std.atomic.Value(Slot).init(0),
        .logger = .FOR_TESTS,
        .metrics = null,
    };

    {
        const proof = DuplicateSlotProof{
            .shred1 = test_shreds.mainnet_shreds[0],
            .shred2 = test_shreds.mainnet_shreds[1],
        };
        var write_batch = try self.db.initWriteBatch();
        defer write_batch.deinit();
        try write_batch.put(schema.duplicate_slots, 19, proof);
        try self.db.commit(&write_batch);

        const reader = self.reader();
        const slot, const proof2 = (try reader.getFirstDuplicateProof()).?;
        defer bincode.free(allocator, proof2);

        try std.testing.expectEqual(19, slot);
        try std.testing.expectEqualSlices(u8, proof.shred1, proof2.shred1);
        try std.testing.expectEqualSlices(u8, proof.shred2, proof2.shred2);
    }
}

test getDuplicateSlot {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    const slot: u64 = 42;

    // Test case 1: No duplicate slot proof exists
    const reader = state.reader();
    const result_none = try reader.getDuplicateSlot(allocator, slot);
    try std.testing.expectEqual(null, result_none);

    // Test case 2: Insert a duplicate slot proof and retrieve it
    {
        const test_shred1 = "test_shred_1_data";
        const test_shred2 = "test_shred_2_data";
        const duplicate_proof = DuplicateSlotProof{
            .shred1 = test_shred1,
            .shred2 = test_shred2,
        };

        var write_batch = try state.db.initWriteBatch();
        defer write_batch.deinit();
        try write_batch.put(schema.duplicate_slots, slot, duplicate_proof);
        try state.db.commit(&write_batch);

        // Retrieve and verify the duplicate slot proof
        const reader2 = state.reader();
        const result_some = try reader2.getDuplicateSlot(allocator, slot);
        try std.testing.expect(result_some != null);

        const retrieved_proof = result_some.?;
        defer bincode.free(allocator, retrieved_proof);

        try std.testing.expectEqualSlices(u8, test_shred1, retrieved_proof.shred1);
        try std.testing.expectEqualSlices(u8, test_shred2, retrieved_proof.shred2);
    }

    // Test case 3: Different slot returns null
    const different_slot: u64 = 123;
    const result_different = try reader.getDuplicateSlot(allocator, different_slot);
    try std.testing.expectEqual(null, result_different);
}

test isDead {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    {
        var write_batch = try state.db.initWriteBatch();
        defer write_batch.deinit();
        try write_batch.put(schema.dead_slots, 19, true);
        try state.db.commit(&write_batch);
    }
    const reader = state.reader();
    try std.testing.expectEqual(try reader.isDead(allocator, 19), true);

    {
        var write_batch = try state.db.initWriteBatch();
        defer write_batch.deinit();
        try write_batch.put(schema.dead_slots, 19, false);
        try state.db.commit(&write_batch);
    }
    try std.testing.expectEqual(try reader.isDead(allocator, 19), false);
}

test getBlockHeight {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(schema.block_height, 19, 19);
    try state.db.commit(&write_batch);

    // should succeeed
    const reader = state.reader();
    const height = try reader.getBlockHeight(allocator, 19);
    try std.testing.expectEqual(19, height);
}

test getRootedBlockTime {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(schema.blocktime, 19, 19);
    try state.db.commit(&write_batch);

    // not rooted
    const reader = state.reader();
    const r = reader.getRootedBlockTime(allocator, 19);
    try std.testing.expectError(error.SlotNotRooted, r);

    // root it
    var write_batch2 = try state.db.initWriteBatch();
    defer write_batch2.deinit();
    try write_batch2.put(schema.rooted_slots, 19, true);
    try state.db.commit(&write_batch2);

    // should succeeed
    const time = try reader.getRootedBlockTime(allocator, 19);
    try std.testing.expectEqual(19, time);
}

test slotMetaIterator {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    var slot_metas = ArrayList(SlotMeta).init(allocator);
    defer {
        for (slot_metas.items) |*slot_meta| {
            slot_meta.deinit();
        }
        slot_metas.deinit();
    }

    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    // 1 -> 2 -> 3
    const roots: [3]Slot = .{ 1, 2, 3 };
    var parent_slot: ?Slot = null;
    for (roots, 0..) |slot, i| {
        var slot_meta = SlotMeta.init(allocator, slot, parent_slot);
        // ensure isFull() is true
        slot_meta.last_index = 1;
        slot_meta.consecutive_received_from_0 = slot_meta.last_index.? + 1;
        // update next slots
        if (i + 1 < roots.len) {
            try slot_meta.child_slots.append(roots[i + 1]);
        }
        try write_batch.put(schema.slot_meta, slot_meta.slot, slot_meta);
        // connect the chain
        parent_slot = slot;

        try slot_metas.append(slot_meta);
    }
    try state.db.commit(&write_batch);

    const reader = state.reader();
    var iter = try reader.slotMetaIterator(0);
    defer iter.deinit();
    var index: u64 = 0;
    while (try iter.next()) |entry| {
        var slot_meta = entry[1];
        defer slot_meta.deinit();

        try std.testing.expectEqual(slot_metas.items[index].slot, slot_meta.slot);
        try std.testing.expectEqual(slot_metas.items[index].last_index, slot_meta.last_index);
        index += 1;
    }
}

test rootedSlotIterator {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    const roots: [3]Slot = .{ 2, 3, 4 };
    for (roots) |slot| {
        try write_batch.put(schema.rooted_slots, slot, true);
    }
    try state.db.commit(&write_batch);

    const reader = state.reader();
    var iter = try reader.rootedSlotIterator(0);
    defer iter.deinit();
    var i: u64 = 0;
    while (try iter.next()) |entry| {
        try std.testing.expectEqual(roots[i], entry[0]);
        i += 1;
    }
}

test slotRangeConnected {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    const roots: [3]Slot = .{ 1, 2, 3 };

    // 1 -> 2 -> 3
    var parent_slot: ?Slot = null;
    for (roots, 0..) |slot, i| {
        var slot_meta = SlotMeta.init(allocator, slot, parent_slot);
        defer slot_meta.deinit();
        // ensure isFull() is true
        slot_meta.last_index = 1;
        slot_meta.consecutive_received_from_0 = slot_meta.last_index.? + 1;
        // update next slots
        if (i + 1 < roots.len) {
            try slot_meta.child_slots.append(roots[i + 1]);
        }
        try write_batch.put(schema.slot_meta, slot_meta.slot, slot_meta);
        // connect the chain
        parent_slot = slot;
    }
    try state.db.commit(&write_batch);

    var write_batch2 = try state.db.initWriteBatch();
    defer write_batch2.deinit();

    const reader = state.reader();
    const is_connected = try reader.slotRangeConnected(allocator, 1, 3);
    try std.testing.expectEqual(true, is_connected);

    // insert a non-full last_slot
    var slot_meta = SlotMeta.init(allocator, 4, parent_slot);
    defer slot_meta.deinit();
    // ensure isFull() is FALSE
    slot_meta.last_index = 1;
    try write_batch2.put(schema.slot_meta, slot_meta.slot, slot_meta);

    // this should still pass
    try std.testing.expectEqual(true, try reader.slotRangeConnected(allocator, 1, 3));
    // this should not pass
    try std.testing.expectEqual(false, try reader.slotRangeConnected(allocator, 1, 4));
    try std.testing.expectEqual(false, try reader.slotRangeConnected(allocator, 1, 5));
}

test highestSlot {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    {
        // insert a shred
        const shred_slot = 10;
        var slot_meta = SlotMeta.init(allocator, shred_slot, null);
        slot_meta.last_index = 21;
        slot_meta.received = 1;

        var write_batch = try state.db.initWriteBatch();
        defer write_batch.deinit();
        try write_batch.put(
            schema.slot_meta,
            shred_slot,
            slot_meta,
        );
        try state.db.commit(&write_batch);

        const reader = state.reader();
        const highest_slot = (try reader.highestSlot()).?;
        try std.testing.expectEqual(slot_meta.slot, highest_slot);
    }

    {
        // insert another shred at a higher slot
        var slot_meta2 = SlotMeta.init(allocator, 100, null);
        slot_meta2.last_index = 21;
        slot_meta2.received = 1;

        var write_batch = try state.db.initWriteBatch();
        defer write_batch.deinit();
        try write_batch.put(
            schema.slot_meta,
            slot_meta2.slot,
            slot_meta2,
        );
        try state.db.commit(&write_batch);

        const reader = state.reader();
        const highest_slot = (try reader.highestSlot()).?;
        try std.testing.expectEqual(slot_meta2.slot, highest_slot);
    }
}

test lowestSlot {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    const shred_slot = 10;
    const shred_index = 10;

    var shred = Shred{ .data = try DataShred.zeroedForTest(allocator) };
    defer shred.deinit();

    shred.data.common.slot = shred_slot;
    shred.data.common.index = shred_index;

    // insert a shred
    var slot_meta = SlotMeta.init(allocator, shred_slot, null);
    slot_meta.last_index = 21;
    slot_meta.received = 1;

    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(
        schema.slot_meta,
        shred_slot,
        slot_meta,
    );
    try state.db.commit(&write_batch);

    const reader = state.reader();
    const lowest_slot = try reader.lowestSlot();
    try std.testing.expectEqual(slot_meta.slot, lowest_slot);
}

test isShredDuplicate {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    const shred_slot = 10;
    const shred_index = 10;

    const size = sig.ledger.shred.DataShred.constants.payload_size;
    const shred_payload = try allocator.alloc(u8, size);
    defer allocator.free(shred_payload);

    var shred: Shred = .{ .data = try DataShred.zeroedForTest(allocator) };
    defer shred.deinit();
    shred.data.common.slot = shred_slot;
    shred.data.common.index = shred_index;
    @memset(shred.data.payload, 0);

    // no duplicate
    const reader = state.reader();
    try std.testing.expectEqual(null, try reader.isShredDuplicate(allocator, shred));

    // insert a shred
    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(
        schema.data_shred,
        .{ shred_slot, shred_index },
        shred_payload,
    );
    try state.db.commit(&write_batch);

    // should now be a duplicate
    const other_payload = (try reader.isShredDuplicate(allocator, shred)).?;
    defer other_payload.deinit();

    try std.testing.expectEqualSlices(u8, shred_payload, other_payload.items);
}

test findMissingDataIndexes {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    const shred_slot = 10;
    const shred_index = 2;

    var shred = Shred{ .data = try DataShred.zeroedForTest(allocator) };
    defer shred.deinit();
    shred.data.common.slot = shred_slot;
    shred.data.common.index = shred_index;

    // set the variant
    const variant = sig.ledger.shred.ShredVariant{
        .shred_type = .data,
        .proof_size = 100 & 0x0F,
        .chained = false,
        .resigned = false,
    };
    shred.data.common.variant = variant;
    try ledger_mod.shred.overwriteShredForTest(allocator, &shred, &(.{2} ** 100));

    var slot_meta = SlotMeta.init(allocator, shred_slot, null);
    slot_meta.last_index = 4;

    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(
        schema.data_shred,
        .{ shred_slot, shred_index },
        shred.payload(),
    );
    try write_batch.put(
        schema.slot_meta,
        shred_slot,
        slot_meta,
    );
    try state.db.commit(&write_batch);

    const reader = state.reader();
    var indexes = try findMissingDataIndexes(
        &reader,
        allocator,
        slot_meta.slot,
        0,
        10,
        0,
        slot_meta.last_index.?,
        100,
    );
    defer indexes.deinit();

    try std.testing.expectEqual(slot_meta.last_index.? - 1, indexes.items.len);
    try std.testing.expectEqualSlices(u64, &.{ 0, 1, 3 }, indexes.items);
}

test getCodeShred {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    var shred = Shred{ .code = try CodeShred.zeroedForTest(allocator) };
    defer shred.deinit();
    shred.code.common.slot = 10;
    shred.code.common.index = 10;

    try std.testing.expect(shred == .code);

    // set the variant
    const variant = sig.ledger.shred.ShredVariant{
        .shred_type = .code,
        .proof_size = 100 & 0x0F,
        .chained = false,
        .resigned = false,
    };
    shred.code.common.variant = variant;
    shred.code.custom.num_data_shreds = 1;
    shred.code.custom.num_code_shreds = 1;
    try ledger_mod.shred.overwriteShredForTest(allocator, &shred, &(.{2} ** 100));

    const shred_slot = shred.commonHeader().slot;
    const shred_index = shred.commonHeader().index;

    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(
        schema.code_shred,
        .{ shred_slot, shred_index },
        shred.payload(),
    );
    try state.db.commit(&write_batch);

    // correct data read
    const reader = state.reader();
    const code_shred = try reader.getCodeShred(shred_slot, shred_index) orelse {
        return error.NullDataShred;
    };
    defer code_shred.deinit();
    try std.testing.expectEqualSlices(u8, shred.payload(), code_shred.data);

    // incorrect slot
    if (try reader.getCodeShred(shred_slot + 10, shred_index) != null) {
        return error.ShouldNotFindDataShred;
    }

    // incorrect index
    if (try reader.getCodeShred(shred_slot, shred_index + 10) != null) {
        return error.ShouldNotFindDataShred;
    }

    // shred is not full
    const is_full = try reader.isFull(allocator, shred_slot);
    try std.testing.expectEqual(false, is_full);

    var shreds = try reader.getCodeShredsForSlot(allocator, shred_slot, shred_index);
    defer {
        for (shreds.items) |*s| s.deinit();
        shreds.deinit();
    }

    try std.testing.expectEqual(1, shreds.items.len);

    const shred_payload_2 = shreds.items[0].payload();
    try std.testing.expectEqualSlices(u8, shred.payload(), shred_payload_2);
}

test getDataShred {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    var shred_vec = sig.ledger.shred.test_data_shred; // local copy
    const shred_payload = shred_vec[0..sig.ledger.shred.DataShred.constants.payload_size];
    const shred_slot = shred_layout.getSlot(shred_payload) orelse return error.InvalidShredData;
    // shred_payload[73] = 0; // zeroth shred index
    const shred_index = shred_layout.getIndex(shred_payload) orelse return error.InvalidShredData;

    var shred = try sig.ledger.shred.Shred.fromPayload(allocator, shred_payload);
    defer shred.deinit();

    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(
        schema.data_shred,
        .{ shred_slot, shred_index },
        shred_payload,
    );
    try state.db.commit(&write_batch);

    // correct data read
    const reader = state.reader();
    const data_shred = try reader.getDataShred(
        shred_slot,
        shred_index,
    ) orelse {
        return error.NullDataShred;
    };
    defer data_shred.deinit();
    try std.testing.expectEqualSlices(u8, shred_payload, data_shred.data);

    // incorrect slot
    if (try reader.getDataShred(shred_slot + 10, shred_index) != null) {
        return error.ShouldNotFindDataShred;
    }

    // incorrect index
    if (try reader.getDataShred(shred_slot, shred_index + 10) != null) {
        return error.ShouldNotFindDataShred;
    }

    // shred is not full
    const is_full = try reader.isFull(allocator, shred_slot);
    try std.testing.expectEqual(false, is_full);

    var iter = try state.db.iterator(schema.data_shred, .forward, null);
    defer iter.deinit();

    var shreds = try reader.getDataShredsForSlot(allocator, shred_slot, shred_index);
    defer {
        for (shreds.items) |*s| {
            s.deinit();
        }
        shreds.deinit();
    }
    try std.testing.expectEqual(1, shreds.items.len);

    const shred_payload_2 = shreds.items[0].payload();
    try std.testing.expectEqualSlices(u8, shred_payload, shred_payload_2);
}

test ensureLowestCleanupSlot {
    const allocator = std.testing.allocator;

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    state.highest_slot_cleaned = RwMux(Slot).init(5);
    const reader = state.reader();

    var lock, const slot = try reader.ensureLowestCleanupSlot();
    defer lock.unlock();
    try std.testing.expectEqual(6, slot);
}

test getBlockTime {
    const allocator = std.testing.allocator;

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    const slot: Slot = 42;
    const timestamp: UnixTimestamp = 1_234_567_890;

    try state.db.put(schema.blocktime, slot, timestamp);

    const reader = state.reader();
    const result = try reader.getBlockTime(allocator, slot);
    try std.testing.expectEqual(timestamp, result.?);

    const no_result = try reader.getBlockTime(allocator, 999);
    try std.testing.expectEqual(null, no_result);
}

test getRecentPerfSamples {
    const allocator = std.testing.allocator;

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();

    // add some perf samples
    for (1..6) |i| {
        const slot: Slot = @intCast(i * 10);
        const sample = PerfSample{
            .num_transactions = @intCast(i * 100),
            .num_slots = 1,
            .sample_period_secs = 60,
            .num_non_vote_transactions = @intCast(i * 90),
        };
        try write_batch.put(schema.perf_samples, slot, sample);
    }
    try state.db.commit(&write_batch);

    const reader = state.reader();
    // get 3 most recent samples
    var samples = try reader.getRecentPerfSamples(allocator, 3);
    defer samples.deinit();

    try std.testing.expectEqual(3, samples.items.len);
    // should be in reverse order (most recent first)
    try std.testing.expectEqual(50, samples.items[0][0]);
    try std.testing.expectEqual(40, samples.items[1][0]);
    try std.testing.expectEqual(30, samples.items[2][0]);
}

test readProgramCosts {
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = rng.random();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();

    // add some program costs
    var pubkey1_data: [32]u8 = undefined;
    random.bytes(&pubkey1_data);
    const pubkey1 = Pubkey{ .data = pubkey1_data };

    var pubkey2_data: [32]u8 = undefined;
    random.bytes(&pubkey2_data);
    const pubkey2 = Pubkey{ .data = pubkey2_data };

    try write_batch.put(schema.program_costs, pubkey1, .{ .cost = 1000 });
    try write_batch.put(schema.program_costs, pubkey2, .{ .cost = 2000 });
    try state.db.commit(&write_batch);

    const reader = state.reader();
    var costs = try reader.readProgramCosts(allocator);
    defer costs.deinit();

    try std.testing.expectEqual(2, costs.items.len);
}

test getRootedBlockWithEntries {
    const allocator = std.testing.allocator;

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    const result = try sig.ledger.tests.insertDataForBlockTest(&state, allocator);
    defer result.deinit();

    const reader = state.reader();
    const slot = result.slot;

    // test with require_previous_blockhash = false
    const block_with_entries = try reader.getRootedBlockWithEntries(allocator, slot + 1, false);
    defer {
        block_with_entries.entries.deinit();
        block_with_entries.block.deinit(allocator);
    }

    try std.testing.expect(block_with_entries.entries.items.len > 0);
    try std.testing.expectEqual(100, block_with_entries.block.transactions.len);

    // test error case: not rooted
    const not_rooted = reader.getRootedBlockWithEntries(allocator, slot + 2, false);
    try std.testing.expectError(error.SlotNotRooted, not_rooted);
}

test getTransactionStatus {
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = rng.random();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    // create a signature and transaction status
    var sig_data: [64]u8 = undefined;
    random.bytes(&sig_data);
    const signature = Signature{ .r = sig_data[0..32].*, .s = sig_data[32..64].* };

    const slot: Slot = 50;
    const status_meta = TransactionStatusMeta{
        .status = null,
        .fee = 100,
        .pre_balances = &.{},
        .post_balances = &.{},
        .inner_instructions = &.{},
        .log_messages = &.{},
        .pre_token_balances = &.{},
        .post_token_balances = &.{},
        .rewards = &.{},
        .loaded_addresses = .{},
        .return_data = .{},
        .compute_units_consumed = 1000,
        .cost_units = null,
    };

    // insert transaction status and root it
    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(schema.transaction_status, .{ signature, slot }, status_meta);
    try write_batch.put(schema.rooted_slots, slot, true);
    try state.db.commit(&write_batch);

    const reader = state.reader();
    const rooted_status = try reader.getRootedTransactionStatus(allocator, signature);
    try std.testing.expect(rooted_status != null);
    const status_slot, const status = rooted_status.?;
    defer status.deinit(allocator);
    try std.testing.expectEqual(slot, status_slot);
    try std.testing.expectEqual(100, status.fee);

    // test with non-existent signature returns null
    var fake_sig_data: [64]u8 = undefined;
    random.bytes(&fake_sig_data);
    const fake_sig = Signature{ .r = fake_sig_data[0..32].*, .s = fake_sig_data[32..64].* };
    const no_status = try reader.getRootedTransactionStatus(allocator, fake_sig);
    try std.testing.expectEqual(null, no_status);
}

test findTransactionInSlot {
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = rng.random();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    const result = try sig.ledger.tests.insertDataForBlockTest(&state, allocator);
    defer result.deinit();

    const reader = state.reader();
    const slot = result.slot;

    const signature = result.entries[0].transactions[0].signatures[0];

    // test finding transaction in slot
    const tx = try reader.findTransactionInSlot(allocator, slot, signature);
    try std.testing.expect(tx != null);
    const found_tx = tx.?;
    defer found_tx.deinit(allocator);
    try std.testing.expect(found_tx.signatures[0].eql(&signature));

    // test with wrong slot
    const no_tx = try reader.findTransactionInSlot(allocator, slot + 100, signature);
    try std.testing.expectEqual(null, no_tx);

    // test with non-existent signature
    var fake_sig_data: [64]u8 = undefined;
    random.bytes(&fake_sig_data);
    const fake_sig = Signature{ .r = fake_sig_data[0..32].*, .s = fake_sig_data[32..64].* };
    const no_tx2 = try reader.findTransactionInSlot(allocator, slot, fake_sig);
    try std.testing.expectEqual(null, no_tx2);
}

test getBlockSignatures {
    const allocator = std.testing.allocator;

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    const result = try sig.ledger.tests.insertDataForBlockTest(&state, allocator);
    defer result.deinit();

    const reader = state.reader();
    const slot = result.slot;

    // test getBlockSignatures
    var signatures = try reader.getBlockSignatures(allocator, slot);
    defer signatures.deinit();
    try std.testing.expect(signatures.items.len > 0);
    try std.testing.expectEqual(100, signatures.items.len);

    // test getBlockSignaturesReversed
    var reversed_sigs = try reader.getBlockSignaturesReversed(allocator, slot);
    defer reversed_sigs.deinit();
    try std.testing.expect(reversed_sigs.items.len > 0);
    try std.testing.expectEqual(signatures.items.len, reversed_sigs.items.len);

    // check that reversed is actually reversed
    for (signatures.items, 0..) |signature, i| {
        const rev_idx = reversed_sigs.items.len - 1 - i;
        try std.testing.expect(signature.eql(&reversed_sigs.items[rev_idx]));
    }
}

test findAddressSignaturesForSlot {
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = rng.random();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    const slot: Slot = 100;
    var address_data: [32]u8 = undefined;
    random.bytes(&address_data);
    const address = Pubkey{ .data = address_data };

    var sig1_data: [64]u8 = undefined;
    random.bytes(&sig1_data);
    const sig1 = Signature{ .r = sig1_data[0..32].*, .s = sig1_data[32..64].* };

    var sig2_data: [64]u8 = undefined;
    random.bytes(&sig2_data);
    const sig2 = Signature{ .r = sig2_data[0..32].*, .s = sig2_data[32..64].* };

    // insert address signatures
    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(schema.address_signatures, .{
        .address = address,
        .slot = slot,
        .transaction_index = 0,
        .signature = sig1,
    }, .{ .writeable = false });
    try write_batch.put(schema.address_signatures, .{
        .address = address,
        .slot = slot,
        .transaction_index = 1,
        .signature = sig2,
    }, .{ .writeable = false });
    try state.db.commit(&write_batch);

    const reader = state.reader();
    var sigs = try reader.findAddressSignaturesForSlot(allocator, address, slot);
    defer sigs.deinit();

    try std.testing.expectEqual(2, sigs.items.len);
    try std.testing.expect(sigs.items[0][1].eql(&sig1));
    try std.testing.expect(sigs.items[1][1].eql(&sig2));

    // test with different address
    var other_address_data: [32]u8 = undefined;
    random.bytes(&other_address_data);
    const other_address = Pubkey{ .data = other_address_data };
    var no_sigs = try reader.findAddressSignaturesForSlot(allocator, other_address, slot);
    defer no_sigs.deinit();
    try std.testing.expectEqual(0, no_sigs.items.len);
}

test getConfirmedSignaturesForAddress {
    const allocator = std.testing.allocator;
    var rng = std.Random.DefaultPrng.init(std.testing.random_seed);
    const random = rng.random();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    state.max_root.store(50, .monotonic);

    const slot: Slot = 10;
    var address_data: [32]u8 = undefined;
    random.bytes(&address_data);
    const address = Pubkey{ .data = address_data };

    var sig_data: [64]u8 = undefined;
    random.bytes(&sig_data);
    const sig1 = Signature{ .r = sig_data[0..32].*, .s = sig_data[32..64].* };

    // set up the database with required data
    var write_batch = try state.db.initWriteBatch();
    defer write_batch.deinit();

    // root the slot
    try write_batch.put(schema.rooted_slots, slot, true);

    // add a slot meta for genesis check
    var slot_meta = SlotMeta.init(allocator, 0, null);
    slot_meta.received = 1;
    try write_batch.put(schema.slot_meta, 0, slot_meta);

    // add transaction status
    const status_meta = TransactionStatusMeta{
        .status = null,
        .fee = 42,
        .pre_balances = &.{},
        .post_balances = &.{},
        .inner_instructions = &.{},
        .log_messages = &.{},
        .pre_token_balances = &.{},
        .post_token_balances = &.{},
        .rewards = &.{},
        .loaded_addresses = .{},
        .return_data = .{},
        .compute_units_consumed = 1000,
        .cost_units = null,
    };
    try write_batch.put(schema.transaction_status, .{ sig1, slot }, status_meta);

    // add address signature mapping
    try write_batch.put(schema.address_signatures, .{
        .address = address,
        .slot = slot,
        .transaction_index = 0,
        .signature = sig1,
    }, .{ .writeable = false });

    try state.db.commit(&write_batch);

    const reader = state.reader();
    var sig_infos = try reader.getConfirmedSignaturesForAddress(
        allocator,
        address,
        slot + 1,
        null,
        null,
        10,
    );
    defer {
        for (sig_infos.infos.items) |*info| {
            if (info.memo) |*m| m.deinit();
        }
        sig_infos.infos.deinit();
    }

    try std.testing.expect(sig_infos.infos.items.len > 0);
    try std.testing.expect(sig_infos.found_before);
}

test isDuplicateSlot {
    const allocator = std.testing.allocator;
    var registry = sig.prometheus.Registry(.{}).init(allocator);
    defer registry.deinit();

    var state = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer state.deinit();

    const reader = state.reader();
    const result_writer = state.resultWriter();

    // Test case: Slot with no duplicate proof returns false
    try std.testing.expectEqual(false, reader.isDuplicateSlot(42));

    // Test case: Slot with duplicate proof returns true
    const slot: Slot = 100;
    try result_writer.storeDuplicateSlot(
        slot,
        "duplicate_shred_1_data",
        "duplicate_shred_2_data",
    );
    try std.testing.expectEqual(true, try reader.isDuplicateSlot(slot));
}
