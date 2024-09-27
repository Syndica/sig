pub const std = @import("std");
pub const sig = @import("../sig.zig");
pub const ledger = @import("lib.zig");

// std
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const AutoHashMap = std.AutoHashMap;

// sig common
const Counter = sig.prometheus.Counter;
const Entry = sig.core.Entry;
const GetMetricError = sig.prometheus.GetMetricError;
const Hash = sig.core.Hash;
const Histogram = sig.prometheus.Histogram;
const Logger = sig.trace.Logger;
const Pubkey = sig.core.Pubkey;
const Registry = sig.prometheus.Registry;
const RwMux = sig.sync.RwMux;
const Signature = sig.core.Signature;
const Slot = sig.core.Slot;
const SortedSet = sig.utils.collections.SortedSet;
const Timer = sig.time.Timer;
const Transaction = sig.core.Transaction;
const VersionedTransaction = sig.core.VersionedTransaction;

// shred
const Shred = sig.ledger.shred.Shred;
const DataShred = sig.ledger.shred.DataShred;

const shred_layout = sig.ledger.shred.layout;

// ledger
const BytesRef = ledger.database.BytesRef;
const BlockstoreDB = ledger.blockstore.BlockstoreDB;
const ColumnFamily = ledger.database.ColumnFamily;
const DuplicateSlotProof = ledger.meta.DuplicateSlotProof;
const PerfSample = ledger.meta.PerfSample;
const SlotMeta = ledger.meta.SlotMeta;
const TransactionStatusMeta = ledger.meta.TransactionStatusMeta;
const TransactionError = ledger.transaction_status.TransactionError;
const UnixTimestamp = ledger.meta.UnixTimestamp;

const schema = ledger.schema.schema;
const key_serializer = ledger.database.key_serializer;
const shredder = ledger.shredder;

const DEFAULT_TICKS_PER_SECOND = sig.core.time.DEFAULT_TICKS_PER_SECOND;

pub const BlockstoreReader = struct {
    allocator: Allocator,
    logger: Logger,
    db: BlockstoreDB,
    // TODO: change naming to 'highest_slot_cleaned'
    lowest_cleanup_slot: *RwMux(Slot),
    max_root: *std.atomic.Value(u64),
    // highest_primary_index_slot: RwMux(?Slot), // TODO shared
    rpc_api_metrics: BlockstoreRpcApiMetrics,
    metrics: BlockstoreReaderMetrics,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        logger: Logger,
        db: BlockstoreDB,
        registry: *Registry(.{}),
        lowest_cleanup_slot: *RwMux(Slot),
        max_root: *std.atomic.Value(u64),
    ) !Self {
        return .{
            .allocator = allocator,
            .logger = logger,
            .db = db,
            .rpc_api_metrics = try BlockstoreRpcApiMetrics.init(registry),
            .metrics = try BlockstoreReaderMetrics.init(registry),
            .lowest_cleanup_slot = lowest_cleanup_slot,
            .max_root = max_root,
        };
    }

    /// Returns true if the specified slot is full.
    ///
    /// Analogous to [is_full](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L500)
    pub fn isFull(self: *Self, slot: Slot) !bool {
        return if (try self.db.get(schema.slot_meta, slot)) |meta|
            meta.isFull()
        else
            false;
    }

    /// Analogous to [slot_meta_iterator](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L604)
    pub fn slotMetaIterator(
        self: *Self,
        slot: Slot,
    ) !BlockstoreDB.Iterator(schema.slot_meta, .forward) {
        return try self.db.iterator(schema.slot_meta, .forward, slot);
    }

    /// Analogous to [rooted_slot_iterator](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L667)
    pub fn rootedSlotIterator(
        self: *Self,
        slot: Slot,
    ) !BlockstoreDB.Iterator(schema.roots, .forward) {
        return self.db.iterator(schema.roots, .forward, slot);
    }

    /// Determines if we can iterate from `starting_slot` to >= `ending_slot` by full slots
    /// `starting_slot` is excluded from the `isFull()` check --> TODO: figure out why
    ///
    /// Analogous to [slot_range_connected](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L690)
    pub fn slotRangeConnected(self: *Self, starting_slot: Slot, ending_slot: Slot) !bool {
        if (starting_slot == ending_slot) {
            return true;
        }

        var start_slot_meta = try self.db.get(schema.slot_meta, starting_slot) orelse return false;
        defer start_slot_meta.deinit();
        // need a reference so the start_slot_meta.deinit works correctly
        var next_slots: *ArrayList(Slot) = &start_slot_meta.next_slots;

        // TODO: revisit this with more extensive testing. how does agave work fine with
        //       supposed bugs? it may be worth opening a PR in agave with the presumed fix

        // This logic is a little different than agave because agave seems to have several bugs.
        var i: usize = 0;
        var last_slot = starting_slot;
        while (i < next_slots.items.len) : (i += 1) {
            const slot = next_slots.items[i];
            if (try self.db.get(schema.slot_meta, slot)) |_slot_meta| {
                var slot_meta = _slot_meta;
                defer slot_meta.deinit();

                if (slot_meta.isFull()) {
                    std.debug.assert(last_slot == slot - 1);
                    // this append is the same as agave, but is it redundant?
                    // does the list already have these slots?
                    try next_slots.appendSlice(slot_meta.next_slots.items);
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
    pub fn getDataShred(self: *Self, slot: Slot, index: u64) !?BytesRef {
        const shred = try self.db.getBytes(schema.data_shred, .{ slot, index }) orelse return null;
        if (shred.data.len != DataShred.constants.payload_size) {
            return error.InvalidDataShred;
        }
        return shred;
    }

    /// Analogous to [get_coding_shred](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2256)
    pub fn getCodeShred(self: *Self, slot: Slot, index: u64) !?BytesRef {
        return try self.db.getBytes(schema.code_shred, .{ slot, index }) orelse return null;
    }

    /// Analogous to [get_data_shreds_for_slot](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2230)
    pub fn getDataShredsForSlot(self: *Self, slot: Slot, start_index: u64) !ArrayList(Shred) {
        return self.getShredsForSlot(schema.data_shred, slot, start_index);
    }

    /// Analogous to [get_coding_shreds_for_slot](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2287-L2288)
    pub fn getCodeShredsForSlot(
        self: *Self,
        slot: Slot,
        start_index: u64,
    ) !ArrayList(Shred) {
        return self.getShredsForSlot(schema.code_shred, slot, start_index);
    }

    fn getShredsForSlot(
        self: *Self,
        cf: ColumnFamily,
        slot: Slot,
        start_index: u64,
    ) !ArrayList(Shred) {
        var iterator = try self.db.iterator(cf, .forward, .{ slot, start_index });
        defer iterator.deinit();
        var shreds = std.ArrayList(Shred).init(self.allocator);
        while (try iterator.nextBytes()) |shred_entry| {
            const key, const payload = shred_entry;
            defer key.deinit();
            defer payload.deinit();
            const found_slot, _ = try key_serializer.deserialize(
                cf.Key,
                self.allocator,
                key.data,
            );
            if (found_slot != slot) {
                break;
            }
            try shreds.append(try Shred.fromPayload(self.allocator, payload.data));
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
        self: *Self,
        slot: Slot,
        first_timestamp: u64,
        defer_threshold_ticks: u64,
        start_index: u64,
        end_index: u64,
        max_missing: usize,
    ) !ArrayList(u64) {
        if (start_index >= end_index or max_missing == 0) {
            return ArrayList(u64).init(self.allocator);
        }

        var iter = try self.db.iterator(schema.data_shred, .forward, .{ slot, start_index });
        defer iter.deinit();

        var missing_indexes = ArrayList(u64).init(self.allocator);
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
                self.allocator,
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
    pub fn getRootedBlockTime(self: *Self, slot: Slot) !UnixTimestamp {
        self.rpc_api_metrics.num_get_rooted_block_time.inc();
        var lock = try self.checkLowestCleanupSlot(slot);
        defer lock.unlock();

        if (try self.isRoot(slot)) {
            return try self.db.get(schema.blocktime, slot) orelse error.SlotUnavailable;
        }
        return error.SlotNotRooted;
    }

    /// Analogous to [get_block_height](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2542)
    pub fn getBlockHeight(self: *Self, slot: Slot) !?u64 {
        self.rpc_api_metrics.num_get_block_height.inc();
        var lock = try self.checkLowestCleanupSlot(slot);
        defer lock.unlock();
        return try self.db.get(schema.block_height, slot);
    }

    /// Acquires the `lowest_cleanup_slot` lock and returns a tuple of the held lock
    /// and lowest available slot.
    ///
    /// The function will return error.SlotCleanedUp if the input
    /// `slot` has already been cleaned-up.
    ///
    /// agave: check_lowest_cleanup_slot
    fn checkLowestCleanupSlot(self: *Self, slot: Slot) error{SlotCleanedUp}!RwMux(Slot).RLockGuard {
        // lowest_cleanup_slot is the last slot that was not cleaned up by LedgerCleanupService
        var guard = self.lowest_cleanup_slot.read();
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
        self: *Self,
    ) error{SlotCleanedUp}!struct { RwMux(Slot).RLockGuard, Slot } {
        var guard = self.lowest_cleanup_slot.read();
        // Make caller hold this lock properly; otherwise LedgerCleanupService can purge/compact
        // needed slots here at any given moment.
        // Blockstore callers, like rpc, can process concurrent read queries
        return .{ guard, guard.get().* +| 1 };
    }

    /// The first complete block that is available in the Blockstore ledger
    ///
    /// Analogous to [get_first_available_block](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2556)
    pub fn getFirstAvailableBlock(self: *Self) !Slot {
        var root_iterator = try self.db.iterator(schema.roots, .forward, try self.lowestSlotWithGenesis());
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

    fn lowestSlotWithGenesis(self: *Self) !Slot {
        var meta_iter = try self.db.iterator(schema.slot_meta, .forward, 0);
        defer meta_iter.deinit();
        while (try meta_iter.nextValue()) |slot_meta| {
            if (slot_meta.received > 0) {
                return slot_meta.slot;
            }
        }
        return self.max_root.load(.monotonic);
    }

    /// Analogous to [get_rooted_block](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2570)
    pub fn getRootedBlock(
        self: *Self,
        slot: Slot,
        require_previous_blockhash: bool,
    ) !VersionedConfirmedBlock {
        self.rpc_api_metrics.num_get_rooted_block.inc();
        var lock = try self.checkLowestCleanupSlot(slot);
        defer lock.unlock();

        if (try self.isRoot(slot)) {
            return self.getCompleteBlock(slot, require_previous_blockhash);
        }
        return error.SlotNotRooted;
    }

    /// Analogous to [get_complete_block](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2586)
    pub fn getCompleteBlock(
        self: *Self,
        slot: Slot,
        require_previous_blockhash: bool,
    ) !VersionedConfirmedBlock {
        const block_with_entries = try self.getCompleteBlockWithEntries(
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
        self: *Self,
        slot: Slot,
        require_previous_blockhash: bool,
    ) !VersionedConfirmedBlockWithEntries {
        self.rpc_api_metrics.num_get_rooted_block_with_entries.inc();
        var lock = try self.checkLowestCleanupSlot(slot);
        defer lock.unlock();

        if (try self.isRoot(slot)) {
            return self.getCompleteBlockWithEntries(slot, require_previous_blockhash, true, false);
        }
        return error.SlotNotRooted;
    }

    /// Analogous to [get_complete_block_with_entries](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L2622)
    pub fn getCompleteBlockWithEntries(
        self: *Self,
        slot: Slot,
        require_previous_blockhash: bool,
        populate_entries: bool,
        allow_dead_slots: bool,
    ) !VersionedConfirmedBlockWithEntries {
        var slot_meta: SlotMeta = try self.db.get(schema.slot_meta, slot) orelse {
            self.logger.debugf("getCompleteBlockWithEntries failed for slot {} (missing SlotMeta)", .{slot});
            return error.SlotUnavailable;
        };
        defer slot_meta.deinit();
        if (!slot_meta.isFull()) {
            self.logger.debugf("getCompleteBlockWithEntries failed for slot {} (slot not full)", .{slot});
            return error.SlotUnavailable;
        }

        const slot_entries, _, _ = try self.getSlotEntriesWithShredInfo(slot, 0, allow_dead_slots);
        defer {
            for (slot_entries.items) |se| se.deinit(self.allocator);
            slot_entries.deinit();
        }
        if (slot_entries.items.len == 0) {
            self.logger.debugf("getCompleteBlockWithEntries failed for slot {} (missing slot entries)", .{slot});
            return error.SlotUnavailable;
        }

        const blockhash: Hash = slot_entries.items[slot_entries.items.len - 1].hash;
        var starting_transaction_index: usize = 0;

        var entries = if (populate_entries)
            try ArrayList(EntrySummary).initCapacity(self.allocator, slot_entries.items.len)
        else
            ArrayList(EntrySummary).init(self.allocator);
        errdefer entries.deinit();

        var slot_transactions = ArrayList(VersionedTransaction).init(self.allocator);
        var num_moved_slot_transactions: usize = 0;
        defer {
            for (slot_transactions.items[num_moved_slot_transactions..]) |tx| {
                tx.deinit(self.allocator);
            }
            slot_transactions.deinit();
        }
        for (slot_entries.items) |*entry| {
            if (populate_entries) {
                try entries.append(.{
                    .num_hashes = entry.num_hashes,
                    .hash = entry.hash,
                    .num_transactions = entry.transactions.items.len,
                    .starting_transaction_index = starting_transaction_index,
                });
                starting_transaction_index += entry.transactions.items.len;
            }
            try slot_transactions.appendSlice(entry.transactions.items);
            entry.transactions.deinit(self.allocator);
            entry.transactions = .{};
        }

        var txns_with_statuses = try ArrayList(VersionedTransactionWithStatusMeta)
            .initCapacity(self.allocator, slot_transactions.items.len);
        errdefer {
            for (txns_with_statuses.items) |item| {
                item.deinit(self.db.allocator);
            }
            txns_with_statuses.deinit();
        }
        for (slot_transactions.items) |transaction| {
            transaction.sanitize() catch |err| {
                self.logger.warnf(
                    "getCompleteeBlockWithEntries sanitize failed: {any}, slot: {any}, {any}",
                    .{ err, slot, transaction },
                );
            };
            const signature = transaction.signatures[0];
            txns_with_statuses.appendAssumeCapacity(.{
                .transaction = transaction,
                .meta = try self.db.get(schema.transaction_status, .{ signature, slot }) orelse
                    return error.MissingTransactionMetadata,
            });
            num_moved_slot_transactions += 1;
        }

        // TODO perf: seems wasteful to get all of this, only to read the blockhash
        const parent_slot_entries = if (slot_meta.parent_slot) |parent_slot| blk: {
            const parent_entries, _, _ = try self
                .getSlotEntriesWithShredInfo(parent_slot, 0, allow_dead_slots);
            break :blk parent_entries;
        } else ArrayList(Entry).init(self.allocator);
        defer {
            for (parent_slot_entries.items) |entry| {
                entry.deinit(self.allocator);
            }
            parent_slot_entries.deinit();
        }
        if (parent_slot_entries.items.len == 0 and require_previous_blockhash) {
            return error.ParentEntriesUnavailable;
        }
        const previous_blockhash = if (parent_slot_entries.items.len != 0)
            parent_slot_entries.items[parent_slot_entries.items.len - 1].hash
        else
            Hash.default();

        const rewards = try self.db.get(schema.rewards, slot) orelse schema.rewards.Value{
            .rewards = &.{},
            .num_partitions = null,
        };

        // The Blocktime and BlockHeight column families are updated asynchronously; they
        // may not be written by the time the complete slot entries are available. In this
        // case, these fields will be null.
        const block_time = try self.db.get(schema.blocktime, slot);
        const block_height = try self.db.get(schema.block_height, slot);

        return VersionedConfirmedBlockWithEntries{
            .block = VersionedConfirmedBlock{
                .allocator = self.allocator,
                .previous_blockhash = try previous_blockhash.base58EncodeAlloc(self.allocator),
                .blockhash = try blockhash.base58EncodeAlloc(self.allocator),
                // If the slot is full it should have parent_slot populated from shreds received.
                .parent_slot = slot_meta.parent_slot orelse return error.MissingParentSlot,
                .transactions = try txns_with_statuses.toOwnedSlice(),
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
        self: *Self,
        signature: Signature,
    ) !?struct { Slot, TransactionStatusMeta } {
        self.rpc_api_metrics.num_get_rooted_transaction_status.inc();

        const map = AutoHashMap(Slot, void).init(self.allocator);
        return self.getTransactionStatus(signature, &map);
    }

    /// Returns a transaction status
    ///
    /// Analogous to [get_transaction_status](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3047)
    pub fn getTransactionStatus(
        self: *Self,
        signature: Signature,
        confirmed_unrooted_slots: *const AutoHashMap(Slot, void),
    ) !?struct { Slot, TransactionStatusMeta } {
        self.rpc_api_metrics.num_get_transaction_status.inc();

        const status = try self.getTransactionStatusWithCounter(signature, confirmed_unrooted_slots);
        return status[0];
    }

    /// Returns a transaction status, as well as a loop counter for unit testing
    /// agave: get_transaction_status_with_counter
    /// NOTE perf: linear search every time this is run
    fn getTransactionStatusWithCounter(
        self: *Self,
        signature: Signature,
        confirmed_unrooted_slots: *const AutoHashMap(Slot, void),
    ) !struct { ?struct { Slot, TransactionStatusMeta }, u64 } {
        var counter: u64 = 0;
        var lock, _ = try self.ensureLowestCleanupSlot();
        defer lock.unlock();
        const first_available_block = try self.getFirstAvailableBlock();

        var iterator = try self.db.iterator(
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
            if (!try self.isRoot(slot) and !confirmed_unrooted_slots.contains(slot)) {
                continue;
            }
            // TODO get from iterator
            const status = try self.db.get(schema.transaction_status, key) orelse return error.Unwrap;
            return .{ .{ slot, status }, counter };
        }

        // skipping check for deprecated index: don't need compatibility with agave ledgers

        return .{ null, counter };
    }

    /// Returns a complete transaction if it was processed in a root
    ///
    /// Analogous to [get_rooted_transaction](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3061)
    pub fn getRootedTransaction(
        self: *Self,
        signature: Signature,
    ) !?ConfirmedTransactionWithStatusMeta {
        self.rpc_api_metrics.num_get_rooted_transaction.inc();
        const map = AutoHashMap(Slot, void).init(self.allocator);
        return self.getTransactionWithStatus(signature, &map);
    }

    /// Returns a complete transaction
    ///
    /// Analogous to [get_complete_transaction](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3073)
    pub fn getCompleteTransaction(
        self: *Self,
        signature: Signature,
        highest_confirmed_slot: Slot,
    ) !?ConfirmedTransactionWithStatusMeta {
        self.rpc_api_metrics.num_get_complete_transaction.inc();

        const max_root = self.max_root.load(.monotonic);
        var confirmed_unrooted_slots = AutoHashMap(Slot, void).init(self.allocator);
        var iterator = AncestorIterator{ .db = &self.db, .next_slot = highest_confirmed_slot };
        while (try iterator.next()) |slot| {
            if (slot <= max_root) break;
            try confirmed_unrooted_slots.put(slot, {});
        }

        return self.getTransactionWithStatus(signature, &confirmed_unrooted_slots);
    }

    /// Analogous to [get_transaction_with_status](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3090)
    fn getTransactionWithStatus(
        self: *Self,
        signature: Signature,
        confirmed_unrooted_slots: *const AutoHashMap(Slot, void),
    ) !?ConfirmedTransactionWithStatusMeta {
        const status = try self.getTransactionStatus(signature, confirmed_unrooted_slots);
        const slot, const meta = status orelse return null;
        const transaction = if (try self.findTransactionInSlot(slot, signature)) |t| t else {
            return error.TransactionStatusSlotMismatch; // Should not happen
        };

        const block_time = try self.getBlockTime(slot);

        return .{
            .slot = slot,
            .tx_with_meta = .{ .complete = .{ .transaction = transaction, .meta = meta } },
            .block_time = block_time,
        };
    }

    fn getBlockTime(self: *Self, slot: Slot) !?UnixTimestamp {
        var lock = try self.checkLowestCleanupSlot(slot);
        defer lock.unlock();
        return self.db.get(schema.blocktime, slot);
    }

    /// Analogous to [find_transaction_in_slot](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3115)
    ///
    /// TODO: optimize the performance of this function. this is a critical function for the very
    /// slow getTransaction RPC method and it appears to have significant room for improvement.
    fn findTransactionInSlot(
        self: *Self,
        slot: Slot,
        signature: Signature,
    ) !?VersionedTransaction {
        const slot_entries = try self.getSlotEntries(slot, 0);
        // NOTE perf: linear search runs from scratch every time this is called
        for (slot_entries.items) |entry| {
            for (entry.transactions.items) |transaction| {
                // NOTE perf: redundant calls to sanitize every time this is called
                if (transaction.sanitize()) |_| {} else |err| {
                    self.logger.warnf(
                        "BlockstoreReader.findTransactionInSlot sanitize failed: {any}, slot: {}, {any}",
                        .{ err, slot, transaction },
                    );
                }
                if (signature.eql(&transaction.signatures[0])) {
                    return transaction;
                }
            }
        }
        return null;
    }

    /// Analogous to [get_confirmed_signatures_for_address2](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3220)
    pub fn getConfirmedSignaturesForAddress(
        self: *Self,
        address: Pubkey,
        highest_slot: Slot, // highest_super_majority_root or highest_confirmed_slot
        before: ?Signature,
        until: ?Signature,
        limit: usize,
    ) !SignatureInfosForAddress {
        self.rpc_api_metrics.num_get_confirmed_signatures_for_address2.inc();

        var confirmed_unrooted_slots = AutoHashMap(Slot, void).init(self.allocator);
        defer confirmed_unrooted_slots.deinit();
        const max_root = self.max_root.load(.monotonic);
        var ancestor_iterator = AncestorIterator{ .db = &self.db, .next_slot = highest_slot };
        while (try ancestor_iterator.next()) |slot| {
            if (slot <= max_root) break;
            try confirmed_unrooted_slots.put(slot, {});
        }

        // Figure the `slot` to start listing signatures at, based on the ledger location of the
        // `before` signature if present.  Also generate a HashSet of signatures that should
        // be excluded from the results.
        var get_before_slot_timer = try Timer.start();
        const slot: Slot, //
        var before_excluded_signatures: AutoHashMap(Signature, void) //
        = if (before) |before_signature| blk: {
            if (try self.getTransactionStatus(
                before_signature,
                &confirmed_unrooted_slots,
            )) |status| {
                const slot, _ = status;
                const slot_signatures = try self.getBlockSignaturesReversed(slot);
                defer slot_signatures.deinit();
                var excluded = AutoHashMap(Signature, void).init(self.allocator);
                for (slot_signatures.items) |signature| {
                    try excluded.put(signature, {});
                    if (signature.eql(&before_signature)) break;
                }
                break :blk .{ slot, excluded };
            } else return SignatureInfosForAddress.default(self.allocator);
        } else .{ highest_slot, AutoHashMap(Signature, void).init(self.allocator) };
        defer before_excluded_signatures.deinit();
        self.metrics.get_before_slot_us
            .observe(@floatFromInt(get_before_slot_timer.read().asMicros()));

        // Generate a HashSet of signatures that should be excluded from the results based on
        // `until` signature
        const first_available_block = try self.getFirstAvailableBlock();
        var get_until_slot_timer = try Timer.start();
        const lowest_slot, var until_excluded_signatures = if (until) |until_signature| blk: {
            if (try self.getTransactionStatus(
                until_signature,
                &confirmed_unrooted_slots,
            )) |status| {
                const slot_, _ = status;
                const slot_signatures = try self.getBlockSignatures(slot_);
                defer slot_signatures.deinit();
                var excluded = AutoHashMap(Signature, void).init(self.allocator);
                for (slot_signatures.items) |signature| {
                    try excluded.put(signature, {});
                    if (signature.eql(&until_signature)) break;
                }
                break :blk .{ slot_, excluded };
            }
        } else .{
            first_available_block,
            AutoHashMap(Signature, void).init(self.allocator),
        };
        defer until_excluded_signatures.deinit();
        self.metrics.get_until_slot_us
            .observe(@floatFromInt(get_until_slot_timer.read().asMicros()));

        // Fetch the list of signatures that affect the given address
        var address_signatures = ArrayList(struct { Slot, Signature }).init(self.allocator);

        // Get signatures in `slot`
        var get_initial_slot_timer = try Timer.start();
        const signatures = try self.findAddressSignaturesForSlot(address, slot);
        for (1..signatures.items.len + 1) |i| {
            const this_slot, const signature = signatures.items[signatures.items.len - i];
            std.debug.assert(slot == this_slot);
            if (!before_excluded_signatures.contains(signature) and
                !until_excluded_signatures.contains(signature))
            {
                try address_signatures.append(.{ this_slot, signature });
            }
        }
        self.metrics.get_initial_slot_us
            .observe(@floatFromInt(get_initial_slot_timer.read().asMicros()));

        var address_signatures_iter_timer = try Timer.start();
        // Regardless of whether a `before` signature is provided, the latest relevant
        // `slot` is queried directly with the `find_address_signatures_for_slot()`
        // call above. Thus, this iterator starts at the lowest entry of `address,
        // slot` and iterates backwards to continue reporting the next earliest
        // signatures.
        var iterator = try self.db.iterator(schema.address_signatures, .reverse, .{
            .address = address,
            .slot = slot,
            .transaction_index = 0,
            .signature = Signature.init(.{0} ** 64),
        });

        // Iterate until limit is reached
        while (try iterator.nextKey()) |key| {
            if (address_signatures.items.len >= limit) break;
            if (key.slot < lowest_slot) {
                break;
            }
            if (address.equals(&key.address) and
                (try self.isRoot(slot) or confirmed_unrooted_slots.contains(slot)) and
                !until_excluded_signatures.contains(key.signature))
            {
                try address_signatures.append(.{ key.slot, key.signature });
            }
        }
        self.metrics.address_signatures_iter_us
            .observe(@floatFromInt(address_signatures_iter_timer.read().asMicros()));

        address_signatures.items.len = @min(address_signatures.items.len, limit);

        // Fill in the status information for each found transaction
        var get_status_info_timer = try Timer.start();
        var infos = ArrayList(ConfirmedTransactionStatusWithSignature).init(self.allocator);
        for (address_signatures.items) |asig| {
            const the_slot, const signature = asig;
            const maybe_status = try self.getTransactionStatus(signature, &confirmed_unrooted_slots);
            const err = if (maybe_status) |status| status[1].status else null;
            const memo = if (try self.db.getBytes(
                schema.transaction_memos,
                .{ signature, the_slot },
            )) |memo_ref| blk: {
                var memo = ArrayList(u8).init(self.allocator);
                try memo.appendSlice(memo_ref.data);
                break :blk memo;
            } else null;
            const block_time = try self.getBlockTime(the_slot);
            try infos.append(.{
                .signature = signature,
                .slot = the_slot,
                .err = err,
                .memo = memo,
                .block_time = block_time,
            });
        }
        self.metrics.get_status_info_us
            .observe(@floatFromInt(get_status_info_timer.read().asMicros()));

        return .{
            .infos = infos,
            .found_before = true, // if `before` signature was not found, this method returned early
        };
    }

    /// agave: get_block_signatures_rev
    /// TODO replace usage with getBlockSignatures
    fn getBlockSignaturesReversed(self: *Self, slot: Slot) !ArrayList(Signature) {
        const block = try self.getCompleteBlock(slot, false);

        var signatures = try ArrayList(Signature)
            .initCapacity(self.allocator, block.transactions.len);
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

    fn getBlockSignatures(self: *Self, slot: Slot) !ArrayList(Signature) {
        const block = try self.getCompleteBlock(slot, false);

        var signatures = try ArrayList(Signature)
            .initCapacity(self.allocator, block.transactions.len);
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
        self: *Self,
        pubkey: Pubkey,
        slot: Slot,
    ) !ArrayList(SlotSignature) {
        var lock, const lowest_available_slot = try self.ensureLowestCleanupSlot();
        defer lock.unlock();
        var signatures = ArrayList(SlotSignature).init(self.allocator);
        if (slot < lowest_available_slot) {
            return signatures;
        }
        var index_iterator = try self.db.iterator(schema.address_signatures, .forward, .{
            .address = pubkey,
            .slot = @max(slot, lowest_available_slot),
            .transaction_index = 0,
            .signature = Signature.init(.{0} ** 64),
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
    pub fn getRecentPerfSamples(self: *Self, num: usize) !ArrayList(SlotPerfSample) {
        var samples = ArrayList(SlotPerfSample).init(self.allocator);
        var iterator = try self.db.iterator(schema.perf_samples, .reverse, null);
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
    pub fn readProgramCosts(self: *Self) !ArrayList(ProgramCost) {
        var costs = ArrayList(ProgramCost).init(self.allocator);
        var iterator = try self.db.iterator(schema.program_costs, .reverse, null);
        defer iterator.deinit();
        while (try iterator.next()) |next| {
            try costs.append(.{ next[0], next[1].cost });
        }
        return costs;
    }

    /// Returns the entry vector for the slot starting with `shred_start_index`
    ///
    /// Analogous to [get_slot_entries](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3466)
    pub fn getSlotEntries(self: *Self, slot: Slot, shred_start_index: u64) !ArrayList(Entry) {
        const entries, _, _ = try self.getSlotEntriesWithShredInfo(slot, shred_start_index, false);
        return entries;
    }

    /// Returns the entry vector for the slot starting with `shred_start_index`, the number of
    /// shreds that comprise the entry vector, and whether the slot is full (consumed all shreds).
    ///
    /// Analogous to [get_slot_entries_with_shred_info](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3473)
    pub fn getSlotEntriesWithShredInfo(
        self: *Self,
        slot: Slot,
        start_index: u64,
        allow_dead_slots: bool,
    ) !struct { ArrayList(Entry), u64, bool } {
        const completed_ranges, const maybe_slot_meta =
            try self.getCompletedRanges(slot, start_index);
        defer completed_ranges.deinit();

        // Check if the slot is dead *after* fetching completed ranges to avoid a race
        // where a slot is marked dead by another thread before the completed range query finishes.
        // This should be sufficient because full slots will never be marked dead from another thread,
        // this can only happen during entry processing during replay stage.
        if (try self.isDead(slot) and !allow_dead_slots) {
            return error.DeadSlot;
        }
        if (completed_ranges.items.len == 0) {
            return .{ ArrayList(Entry).init(self.allocator), 0, false };
        }

        const slot_meta = maybe_slot_meta.?;
        _, const end_index = completed_ranges.items[completed_ranges.items.len - 1];
        const num_shreds = @as(u64, @intCast(end_index)) - start_index + 1;

        const entries = try self.getSlotEntriesInBlock(
            self.allocator,
            slot,
            completed_ranges,
            &slot_meta,
        );
        return .{ entries, num_shreds, slot_meta.isFull() };
    }

    /// agave: get_completed_ranges
    fn getCompletedRanges(
        self: *Self,
        slot: Slot,
        start_index: u64,
    ) !struct { CompletedRanges, ?SlotMeta } {
        const maybe_slot_meta = try self.db.get(schema.slot_meta, slot);
        if (maybe_slot_meta == null) {
            return .{ CompletedRanges.init(self.allocator), null };
        }
        var slot_meta: SlotMeta = maybe_slot_meta.?;
        defer slot_meta.deinit();

        // Find all the ranges for the completed data blocks
        const completed_ranges = try getCompletedDataRanges(
            self.allocator,
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
            try ranges.append(.{ begin, index });
            begin = index + 1;
        }
        return ranges;
    }

    /// Analogous to [get_entries_in_data_block](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3700)
    pub fn getEntriesInDataBlock(
        self: *Self,
        slot: Slot,
        start_index: u32,
        end_index: u32,
        slot_meta: ?*const SlotMeta,
    ) !ArrayList(Entry) {
        var fba_slice: [@sizeOf(struct { u32, u32 })]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&fba_slice);
        var completed_ranges = CompletedRanges.initCapacity(fba.allocator(), 1) catch unreachable;
        completed_ranges.appendAssumeCapacity(.{ start_index, end_index });
        return self.getSlotEntriesInBlock(self.allocator, slot, completed_ranges, slot_meta);
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
        self: *Self,
        allocator: Allocator,
        slot: Slot,
        completed_ranges: CompletedRanges,
        maybe_slot_meta: ?*const SlotMeta,
    ) !ArrayList(Entry) {
        if (completed_ranges.items.len == 0) {
            return ArrayList(Entry).init(allocator);
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
        for (all_ranges_start_index..all_ranges_end_index + 1) |index| {
            // TODO perf: multi_get_bytes
            if (try self.db.getBytes(schema.data_shred, .{ slot, @intCast(index) })) |shred_bytes| {
                defer shred_bytes.deinit();
                const shred = try Shred.fromPayload(allocator, shred_bytes.data);
                data_shreds.appendAssumeCapacity(shred.data);
            } else {
                if (maybe_slot_meta) |slot_meta| {
                    var lcs = self.lowest_cleanup_slot.read();
                    defer lcs.unlock();
                    if (slot > lcs.get().*) {
                        self.logger.errf(
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
                        return error.CorruptedBlockstore;
                    }
                }
                self.logger.errf("Missing shred for slot {}, index {}", .{ slot, index });
                return error.InvalidShredData;
            }
        }

        var entries = ArrayList(Entry).init(allocator);
        errdefer {
            for (entries.items) |entry| entry.deinit(allocator);
            entries.deinit();
        }
        for (completed_ranges.items) |range| {
            const start_index, const end_index = range;

            // The indices from completed_ranges refer to shred indices in the
            // entire block; map those indices to indices within data_shreds
            const range_start_index: usize = @intCast(start_index - all_ranges_start_index);
            const range_end_index: usize = @intCast(end_index - all_ranges_start_index);
            const range_shreds: []DataShred =
                data_shreds.items[range_start_index .. range_end_index + 1];

            const last_shred = range_shreds[range_shreds.len - 1];
            std.debug.assert(last_shred.dataComplete() or last_shred.isLastInSlot());
            // self.logger.tracef("{any} data shreds in last FEC set", data_shreds.items.len);

            const bytes = shredder.deshred(allocator, range_shreds) catch |e| {
                self.logger.errf("failed to deshred entries buffer from shreds: {}", .{e});
                return e;
            };
            defer bytes.deinit();
            const these_entries = sig.bincode
                .readFromSlice(allocator, []Entry, bytes.items, .{}) catch |e| {
                self.logger.errf("failed to deserialize entries from shreds: {}", .{e});
                return e;
            };
            defer allocator.free(these_entries);
            errdefer for (these_entries) |e| e.deinit(allocator);
            try entries.appendSlice(these_entries);
        }
        return entries;
    }

    // pub fn is_last_fec_set_full missing ???

    /// Returns a mapping from each elements of `slots` to a list of the
    /// element's children slots.
    ///
    /// Analogous to [get_slots_since](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3821)
    pub fn getSlotsSince(self: *Self, slots: []const Slot) !AutoHashMap(Slot, ArrayList(Slot)) {
        // TODO perf: support multi_get in db
        var map = AutoHashMap(Slot, ArrayList(Slot)).init(self.allocator);
        errdefer {
            var iter = map.iterator();
            while (iter.next()) |entry| {
                entry.value_ptr.deinit();
            }
            map.deinit();
        }
        for (slots) |slot| {
            if (try self.db.get(schema.slot_meta, slot)) |meta| {
                errdefer meta.next_slots.deinit();
                var cdi = meta.completed_data_indexes;
                cdi.deinit();
                try map.put(slot, meta.next_slots);
            }
        }
        return map;
    }

    /// Analogous to [is_root](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3838)
    ///
    /// agave handles DB errors with placeholder values, which seems like a mistake.
    /// this implementation instead returns errors.
    pub fn isRoot(self: *Self, slot: Slot) !bool {
        return try self.db.get(schema.roots, slot) orelse false;
    }

    /// Returns true if a slot is between the rooted slot bounds of the ledger, but has not itself
    /// been rooted. This is either because the slot was skipped, or due to a gap in ledger data,
    /// as when booting from a newer snapshot.
    ///
    /// Analogous to [is_skipped](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3845)
    ///
    /// agave handles DB errors with placeholder values, which seems like a mistake.
    /// this implementation instead returns errors.
    pub fn isSkipped(self: *Self, slot: Slot) !bool {
        var iterator = try self.db.iterator(schema.roots, .forward, 0);
        defer iterator.deinit();
        const lowest_root = try iterator.nextKey() orelse 0;
        return if (try self.db.get(schema.roots, slot)) |_|
            false
        else
            slot < self.max_root.load(.monotonic) and slot > lowest_root;
    }

    /// Analogous to [get_bank_hash](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3873)
    pub fn getBankHash(self: *Self, slot: Slot) !?Hash {
        return if (try self.db.get(schema.bank_hash, slot)) |versioned|
            versioned.frozenHash()
        else
            null;
    }

    /// Analogous to [is_duplicate_confirmed](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3880)
    pub fn isDuplicateConfirmed(self: *Self, slot: Slot) !bool {
        return if (try self.db.get(schema.bank_hash, slot)) |versioned|
            versioned.isDuplicateConfirmed()
        else
            false;
    }

    /// Returns information about a single optimistically confirmed slot
    ///
    /// Analogous to [get_optimistic_slot](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3899)
    pub fn getOptimisticSlot(self: *Self, slot: Slot) !?struct { Hash, UnixTimestamp } {
        const meta = try self.db.get(schema.optimistic_slots, slot) orelse return null;
        return .{ meta.V0.hash, meta.V0.timestamp };
    }

    const OptimisticSlot = struct { Slot, Hash, UnixTimestamp };
    /// Returns information about the `num` latest optimistically confirmed slot
    ///
    /// The returned slots are sorted in increasing order of slot number.
    ///
    /// Analogous to [get_latest_optimistic_slots](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3907)
    pub fn getLatestOptimisticSlots(
        self: *Self,
        num: usize,
    ) !ArrayList(OptimisticSlot) {
        var optimistic_slots = std.ArrayList(OptimisticSlot).init(self.allocator);
        errdefer optimistic_slots.deinit();

        var iter = try self.db.iterator(schema.optimistic_slots, .reverse, null);
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
    pub fn isDead(self: *Self, slot: Slot) !bool {
        return try self.db.get(schema.dead_slots, slot) orelse false;
    }

    /// Analogous to [get_first_duplicate_proof](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L3983)
    pub fn getFirstDuplicateProof(self: *Self) !?struct { Slot, DuplicateSlotProof } {
        var iterator = try self.db.iterator(schema.duplicate_slots, .forward, 0);
        defer iterator.deinit();
        return try iterator.next();
    }

    /// Returns the shred already stored in blockstore if it has a different
    /// payload than the given `shred` but the same (slot, index, shred-type).
    /// This implies the leader generated two different shreds with the same
    /// slot, index and shred-type.
    /// The payload is modified so that it has the same retransmitter's
    /// signature as the `shred` argument.
    ///
    /// Analogous to [is_shred_duplicate](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L4009)
    pub fn isShredDuplicate(self: *Self, shred: Shred) !?ArrayList(u8) {
        const id = shred.id();
        const other_ref = try switch (shred) {
            .data => self.getDataShred(id.slot, @intCast(id.index)),
            .code => self.getCodeShred(id.slot, @intCast(id.index)),
        } orelse return null;
        defer other_ref.deinit();

        // TODO find another approach that doesn't copy unless it's actually returned
        var other = ArrayList(u8).init(self.allocator);
        errdefer other.deinit();
        try other.appendSlice(other_ref.data);

        if (shred.retransmitterSignature()) |signature| {
            shred_layout.setRetransmitterSignature(other.items, signature) catch |err| {
                self.logger.errf("set retransmitter signature failed: {any}", .{err});
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

    /// find the first available slot in blockstore that has some data in it
    /// Analogous to [lowest_slot](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L4073)
    pub fn lowestSlot(self: *Self) !Slot {
        var iterator = try self.db.iterator(schema.slot_meta, .forward, null);
        defer iterator.deinit();
        while (try iterator.next()) |entry| {
            const slot, const meta = entry;
            if (slot > 0 and meta.received > 0) {
                return slot;
            }
        }
        // This means blockstore is empty, should never get here aside from right at boot.
        return self.max_root.load(.monotonic);
    }

    /// Returns the highest available slot in the blockstore
    ///
    /// Analogous to [highest_slot](https://github.com/anza-xyz/agave/blob/15dbe7fb0fc07e11aaad89de1576016412c7eb9e/ledger/src/blockstore.rs#L4100)
    pub fn highestSlot(self: *Self) !?Slot {
        var iterator = try self.db.iterator(schema.slot_meta, .reverse, null);
        defer iterator.deinit();
        return try iterator.nextKey();
    }
};

const CompletedRanges = ArrayList(struct { u32, u32 });

/// Confirmed block with type guarantees that transaction metadata
/// is always present. Used for uploading to BigTable.
pub const VersionedConfirmedBlock = struct {
    allocator: Allocator,
    previous_blockhash: []const u8,
    blockhash: []const u8,
    parent_slot: Slot,
    transactions: []const VersionedTransactionWithStatusMeta,
    rewards: []const ledger.meta.Reward,
    num_partitions: ?u64,
    block_time: ?UnixTimestamp,
    block_height: ?u64,

    pub fn deinit(self: @This(), allocator: Allocator) void {
        for (self.transactions) |it| it.deinit(allocator);
        for (self.rewards) |it| it.deinit(allocator);
        allocator.free(self.transactions);
        allocator.free(self.rewards);
        allocator.free(self.previous_blockhash);
        allocator.free(self.blockhash);
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

const TransactionWithStatusMeta = union(enum) {
    // Very old transactions may be missing metadata
    missing_metadata: Transaction,
    // Versioned stored transaction always have metadata
    complete: VersionedTransactionWithStatusMeta,
};

pub const VersionedTransactionWithStatusMeta = struct {
    transaction: VersionedTransaction,
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

const BlockstoreReaderMetrics = struct {
    get_before_slot_us: *Histogram,
    get_initial_slot_us: *Histogram,
    address_signatures_iter_us: *Histogram,
    get_status_info_us: *Histogram,
    get_until_slot_us: *Histogram,

    pub fn init(registry: *Registry(.{})) GetMetricError!BlockstoreReaderMetrics {
        var self: BlockstoreReaderMetrics = undefined;
        inline for (@typeInfo(BlockstoreReaderMetrics).Struct.fields) |field| {
            const name = "blockstore_reader_" ++ field.name;
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

const BlockstoreRpcApiMetrics = struct {
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

    pub fn init(registry: *Registry(.{})) GetMetricError!BlockstoreRpcApiMetrics {
        var self: BlockstoreRpcApiMetrics = undefined;
        inline for (@typeInfo(BlockstoreRpcApiMetrics).Struct.fields) |field| {
            const name = "blockstore_rpc_api_" ++ field.name;
            @field(self, field.name) = try registry.getOrCreateCounter(name);
        }
        return self;
    }
};

pub const AncestorIterator = struct {
    db: *BlockstoreDB,
    next_slot: ?Slot,

    pub fn initExclusive(db: *BlockstoreDB, start_slot: Slot) !AncestorIterator {
        var self = AncestorIterator.initInclusive(db, start_slot);
        _ = try self.next();
        return self;
    }

    pub fn initInclusive(db: *BlockstoreDB, start_slot: Slot) AncestorIterator {
        return .{
            .db = db,
            .next_slot = start_slot,
        };
    }

    pub fn next(self: *AncestorIterator) !?Slot {
        if (self.next_slot) |slot| {
            if (slot == 0) {
                self.next_slot = null;
            } else if (try self.db.get(schema.slot_meta, slot)) |slot_meta| {
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
const Blockstore = ledger.BlockstoreDB;
const CodeShred = ledger.shred.CodeShred;
const TestDB = ledger.tests.TestDB("BlockstoreReader");

const test_shreds = @import("test_shreds.zig");

// // TODO: -- would likely make most sense to test these with insert_shreds
// getCompletedRanges
// getSlotEntriesInBlock
// getCompleteBlockWithEntries

test "getLatestOptimisticSlots" {
    const allocator = std.testing.allocator;
    const logger = sig.trace.Logger{ .noop = {} };
    const registry = sig.prometheus.globalRegistry();

    var db = try TestDB.init("getLatestOptimisticSlots");
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    {
        var write_batch = try db.initWriteBatch();
        const hash = Hash{ .data = .{1} ** 32 };
        try write_batch.put(schema.optimistic_slots, 1, .{
            .V0 = .{
                .hash = hash,
                .timestamp = 10,
            },
        });
        try db.commit(write_batch);

        const get_hash, const ts = (try reader.getOptimisticSlot(1)).?;
        try std.testing.expectEqual(hash, get_hash);
        try std.testing.expectEqual(10, ts);

        var opt_slots = try reader.getLatestOptimisticSlots(1);
        defer opt_slots.deinit();

        try std.testing.expectEqual(1, opt_slots.items.len);
        try std.testing.expectEqual(1, opt_slots.items[0][0]); // slot match
        try std.testing.expectEqual(hash, opt_slots.items[0][1]); // hash match
        try std.testing.expectEqual(ts, opt_slots.items[0][2]); // ts match
    }

    {
        var write_batch = try db.initWriteBatch();
        const hash = Hash{ .data = .{10} ** 32 };
        try write_batch.put(schema.optimistic_slots, 10, .{
            .V0 = .{
                .hash = hash,
                .timestamp = 100,
            },
        });
        try db.commit(write_batch);

        const get_hash, const ts = (try reader.getOptimisticSlot(10)).?;
        try std.testing.expectEqual(hash, get_hash);
        try std.testing.expectEqual(100, ts);

        var opt_slots = try reader.getLatestOptimisticSlots(2);
        defer opt_slots.deinit();

        try std.testing.expectEqual(2, opt_slots.items.len);
        try std.testing.expectEqual(10, opt_slots.items[0][0]); // slot match
        try std.testing.expectEqual(hash, opt_slots.items[0][1]); // hash match
        try std.testing.expectEqual(ts, opt_slots.items[0][2]); // ts match
    }
}

test "getFirstDuplicateProof" {
    const allocator = std.testing.allocator;

    const logger = sig.trace.Logger{ .noop = {} };
    const registry = sig.prometheus.globalRegistry();

    const path = std.fmt.comptimePrint("{s}/{s}", .{ sig.TEST_DATA_DIR ++ "blockstore/insert_shred", "getFirstDuplicateProof" });
    try sig.ledger.tests.freshDir(path);
    var db = try BlockstoreDB.open(allocator, logger, path);
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    {
        const proof = DuplicateSlotProof{
            .shred1 = test_shreds.mainnet_shreds[0],
            .shred2 = test_shreds.mainnet_shreds[1],
        };
        var write_batch = try db.initWriteBatch();
        try write_batch.put(schema.duplicate_slots, 19, proof);
        try db.commit(write_batch);

        const slot, const proof2 = (try reader.getFirstDuplicateProof()).?;
        defer bincode.free(allocator, proof2);

        try std.testing.expectEqual(19, slot);
        try std.testing.expectEqualSlices(u8, proof.shred1, proof2.shred1);
        try std.testing.expectEqualSlices(u8, proof.shred2, proof2.shred2);
    }
}

test "isDead" {
    const allocator = std.testing.allocator;
    const logger = sig.trace.Logger{ .noop = {} };
    const registry = sig.prometheus.globalRegistry();

    var db = try TestDB.init("isDead");
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    {
        var write_batch = try db.initWriteBatch();
        try write_batch.put(schema.dead_slots, 19, true);
        try db.commit(write_batch);
    }
    try std.testing.expectEqual(try reader.isDead(19), true);

    {
        var write_batch = try db.initWriteBatch();
        try write_batch.put(schema.dead_slots, 19, false);
        try db.commit(write_batch);
    }
    try std.testing.expectEqual(try reader.isDead(19), false);
}

test "getBlockHeight" {
    const allocator = std.testing.allocator;
    const logger = sig.trace.Logger{ .noop = {} };
    const registry = sig.prometheus.globalRegistry();

    var db = try TestDB.init("getBlockHeight");
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    var write_batch = try db.initWriteBatch();
    try write_batch.put(schema.block_height, 19, 19);
    try db.commit(write_batch);

    // should succeeed
    const height = try reader.getBlockHeight(19);
    try std.testing.expectEqual(19, height);
}

test "getRootedBlockTime" {
    const allocator = std.testing.allocator;
    const logger = sig.trace.Logger{ .noop = {} };
    const registry = sig.prometheus.globalRegistry();

    var db = try TestDB.init("getRootedBlockTime");
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    var write_batch = try db.initWriteBatch();
    try write_batch.put(schema.blocktime, 19, 19);
    try db.commit(write_batch);

    // not rooted
    const r = reader.getRootedBlockTime(19);
    try std.testing.expectError(error.SlotNotRooted, r);

    // root it
    var write_batch2 = try db.initWriteBatch();
    try write_batch2.put(schema.roots, 19, true);
    try db.commit(write_batch2);

    // should succeeed
    const time = try reader.getRootedBlockTime(19);
    try std.testing.expectEqual(19, time);
}

test "slotMetaIterator" {
    const allocator = std.testing.allocator;
    const logger = sig.trace.Logger{ .noop = {} };
    const registry = sig.prometheus.globalRegistry();

    var db = try TestDB.init("slotMetaIterator");
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    var slot_metas = ArrayList(SlotMeta).init(allocator);
    defer {
        for (slot_metas.items) |*slot_meta| {
            slot_meta.deinit();
        }
        slot_metas.deinit();
    }

    var write_batch = try db.initWriteBatch();
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
            try slot_meta.next_slots.append(roots[i + 1]);
        }
        try write_batch.put(schema.slot_meta, slot_meta.slot, slot_meta);
        // connect the chain
        parent_slot = slot;

        try slot_metas.append(slot_meta);
    }
    try db.commit(write_batch);

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

test "rootedSlotIterator" {
    const allocator = std.testing.allocator;
    const logger = sig.trace.Logger{ .noop = {} };
    const registry = sig.prometheus.globalRegistry();

    var db = try TestDB.init("rootedSlotIterator");
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    var write_batch = try db.initWriteBatch();
    const roots: [3]Slot = .{ 2, 3, 4 };
    for (roots) |slot| {
        try write_batch.put(schema.roots, slot, true);
    }
    try db.commit(write_batch);

    var iter = try reader.rootedSlotIterator(0);
    defer iter.deinit();
    var i: u64 = 0;
    while (try iter.next()) |entry| {
        try std.testing.expectEqual(roots[i], entry[0]);
        i += 1;
    }
}

test "slotRangeConnected" {
    const allocator = std.testing.allocator;
    const logger = sig.trace.Logger{ .noop = {} };
    const registry = sig.prometheus.globalRegistry();

    var db = try TestDB.init("slotRangeConnected");
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    var write_batch = try db.initWriteBatch();
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
            try slot_meta.next_slots.append(roots[i + 1]);
        }
        try write_batch.put(schema.slot_meta, slot_meta.slot, slot_meta);
        // connect the chain
        parent_slot = slot;
    }
    try db.commit(write_batch);

    const is_connected = try reader.slotRangeConnected(1, 3);
    try std.testing.expectEqual(true, is_connected);

    // insert a non-full last_slot
    var slot_meta = SlotMeta.init(allocator, 4, parent_slot);
    defer slot_meta.deinit();
    // ensure isFull() is FALSE
    slot_meta.last_index = 1;
    try write_batch.put(schema.slot_meta, slot_meta.slot, slot_meta);

    // this should still pass
    try std.testing.expectEqual(true, try reader.slotRangeConnected(1, 3));
    // this should not pass
    try std.testing.expectEqual(false, try reader.slotRangeConnected(1, 4));
    try std.testing.expectEqual(false, try reader.slotRangeConnected(1, 5));
}

test "highestSlot" {
    const allocator = std.testing.allocator;
    const logger = sig.trace.Logger{ .noop = {} };
    const registry = sig.prometheus.globalRegistry();

    var db = try TestDB.init("highestSlot");
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    {
        // insert a shred
        const shred_slot = 10;
        var slot_meta = SlotMeta.init(allocator, shred_slot, null);
        slot_meta.last_index = 21;
        slot_meta.received = 1;

        var write_batch = try db.initWriteBatch();
        try write_batch.put(
            schema.slot_meta,
            shred_slot,
            slot_meta,
        );
        try db.commit(write_batch);

        const highest_slot = (try reader.highestSlot()).?;
        try std.testing.expectEqual(slot_meta.slot, highest_slot);
    }

    {
        // insert another shred at a higher slot
        var slot_meta2 = SlotMeta.init(allocator, 100, null);
        slot_meta2.last_index = 21;
        slot_meta2.received = 1;

        var write_batch = try db.initWriteBatch();
        try write_batch.put(
            schema.slot_meta,
            slot_meta2.slot,
            slot_meta2,
        );
        try db.commit(write_batch);

        const highest_slot = (try reader.highestSlot()).?;
        try std.testing.expectEqual(slot_meta2.slot, highest_slot);
    }
}

test "lowestSlot" {
    const allocator = std.testing.allocator;
    const logger = sig.trace.Logger{ .noop = {} };
    const registry = sig.prometheus.globalRegistry();

    var db = try TestDB.init("lowestSlot");
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    const shred_slot = 10;
    const shred_index = 10;

    var shred = Shred{ .data = try DataShred.default(allocator) };
    defer shred.deinit();

    shred.data.fields.common.slot = shred_slot;
    shred.data.fields.common.index = shred_index;

    // insert a shred
    var slot_meta = SlotMeta.init(allocator, shred_slot, null);
    slot_meta.last_index = 21;
    slot_meta.received = 1;

    var write_batch = try db.initWriteBatch();
    try write_batch.put(
        schema.slot_meta,
        shred_slot,
        slot_meta,
    );
    try db.commit(write_batch);

    const lowest_slot = try reader.lowestSlot();
    try std.testing.expectEqual(slot_meta.slot, lowest_slot);
}

test "isShredDuplicate" {
    const allocator = std.testing.allocator;
    const logger = sig.trace.Logger{ .noop = {} };
    const registry = sig.prometheus.globalRegistry();

    var db = try TestDB.init("isShredDuplicate");
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    const shred_slot = 10;
    const shred_index = 10;

    const size = sig.ledger.shred.DataShred.constants.payload_size;
    const shred_payload = try allocator.alloc(u8, size);
    defer allocator.free(shred_payload);

    var shred = Shred{ .data = try DataShred.default(allocator) };
    defer shred.deinit();
    shred.data.fields.common.slot = shred_slot;
    shred.data.fields.common.index = shred_index;
    @memset(shred.data.fields.payload, 0);

    // no duplicate
    try std.testing.expectEqual(null, try reader.isShredDuplicate(shred));

    // insert a shred
    var write_batch = try db.initWriteBatch();
    try write_batch.put(
        schema.data_shred,
        .{ shred_slot, shred_index },
        shred_payload,
    );
    try db.commit(write_batch);

    // should now be a duplicate
    const other_payload = (try reader.isShredDuplicate(shred)).?;
    defer other_payload.deinit();

    try std.testing.expectEqualSlices(u8, shred_payload, other_payload.items);
}

test "findMissingDataIndexes" {
    const allocator = std.testing.allocator;
    const logger = sig.trace.Logger{ .noop = {} };
    const registry = sig.prometheus.globalRegistry();

    var db = try TestDB.init("findMissingDataIndexes");
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    const shred_slot = 10;
    const shred_index = 2;

    var shred = Shred{ .data = try DataShred.default(allocator) };
    defer shred.deinit();
    shred.data.fields.common.slot = shred_slot;
    shred.data.fields.common.index = shred_index;

    // set the variant
    const variant = sig.ledger.shred.ShredVariant{
        .shred_type = .data,
        .proof_size = 100 & 0x0F,
        .chained = false,
        .resigned = false,
    };
    shred.data.fields.common.variant = variant;
    try shred.data.fields.writePayload(&(.{2} ** 100));

    var slot_meta = SlotMeta.init(allocator, shred_slot, null);
    slot_meta.last_index = 4;

    var write_batch = try db.initWriteBatch();
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
    try db.commit(write_batch);

    var indexes = try reader.findMissingDataIndexes(
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

test "getCodeShred" {
    const allocator = std.testing.allocator;
    const logger = sig.trace.Logger{ .noop = {} };
    const registry = sig.prometheus.globalRegistry();

    var db = try TestDB.init("getCodeShred");
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    var shred = Shred{ .code = try CodeShred.default(allocator) };
    defer shred.deinit();
    shred.code.fields.common.slot = 10;
    shred.code.fields.common.index = 10;

    try std.testing.expect(shred == .code);

    // set the variant
    const variant = sig.ledger.shred.ShredVariant{
        .shred_type = .code,
        .proof_size = 100 & 0x0F,
        .chained = false,
        .resigned = false,
    };
    shred.code.fields.common.variant = variant;
    try shred.code.fields.writePayload(&(.{2} ** 100));

    const shred_slot = shred.commonHeader().slot;
    const shred_index = shred.commonHeader().index;

    var write_batch = try db.initWriteBatch();
    try write_batch.put(
        schema.code_shred,
        .{ shred_slot, shred_index },
        shred.payload(),
    );
    try db.commit(write_batch);

    // correct data read
    const read_bytes_ref = try reader.getCodeShred(shred_slot, shred_index) orelse {
        return error.NullDataShred;
    };
    try std.testing.expectEqualSlices(u8, shred.payload(), read_bytes_ref.data);

    // incorrect slot
    if (try reader.getCodeShred(shred_slot + 10, shred_index) != null) {
        return error.ShouldNotFindDataShred;
    }

    // incorrect index
    if (try reader.getCodeShred(shred_slot, shred_index + 10) != null) {
        return error.ShouldNotFindDataShred;
    }

    // shred is not full
    const is_full = try reader.isFull(shred_slot);
    try std.testing.expectEqual(false, is_full);

    var shreds = try reader.getCodeShredsForSlot(shred_slot, shred_index);
    defer {
        for (shreds.items) |*s| s.deinit();
        shreds.deinit();
    }

    try std.testing.expectEqual(1, shreds.items.len);

    const shred_payload_2 = shreds.items[0].payload();
    try std.testing.expectEqualSlices(u8, shred.payload(), shred_payload_2);
}

test "getDataShred" {
    const allocator = std.testing.allocator;
    const logger = sig.trace.Logger{ .noop = {} };
    const registry = sig.prometheus.globalRegistry();

    var db = try TestDB.init("getDataShred");
    defer db.deinit();

    var lowest_cleanup_slot = RwMux(Slot).init(0);
    var max_root = std.atomic.Value(Slot).init(0);
    var reader = try BlockstoreReader.init(
        allocator,
        logger,
        db,
        registry,
        &lowest_cleanup_slot,
        &max_root,
    );

    var shred_vec = sig.ledger.shred.test_data_shred; // local copy
    const shred_payload = shred_vec[0..sig.ledger.shred.DataShred.constants.payload_size];
    const shred_slot = shred_layout.getSlot(shred_payload) orelse return error.InvalidShredData;
    // shred_payload[73] = 0; // zero-th shred index
    const shred_index = shred_layout.getIndex(shred_payload) orelse return error.InvalidShredData;

    var shred = try sig.ledger.shred.Shred.fromPayload(allocator, shred_payload);
    defer shred.deinit();

    var write_batch = try db.initWriteBatch();
    try write_batch.put(
        schema.data_shred,
        .{ shred_slot, shred_index },
        shred_payload,
    );
    try db.commit(write_batch);

    // correct data read
    const read_bytes_ref = try reader.getDataShred(
        shred_slot,
        shred_index,
    ) orelse {
        return error.NullDataShred;
    };
    try std.testing.expectEqualSlices(u8, shred_payload, read_bytes_ref.data);

    // incorrect slot
    if (try reader.getDataShred(shred_slot + 10, shred_index) != null) {
        return error.ShouldNotFindDataShred;
    }

    // incorrect index
    if (try reader.getDataShred(shred_slot, shred_index + 10) != null) {
        return error.ShouldNotFindDataShred;
    }

    // shred is not full
    const is_full = try reader.isFull(shred_slot);
    try std.testing.expectEqual(false, is_full);

    var iter = try db.iterator(schema.data_shred, .forward, null);
    defer iter.deinit();

    var shreds = try reader.getDataShredsForSlot(shred_slot, shred_index);
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
