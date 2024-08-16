const std = @import("std");
const sig = @import("../sig.zig");

const bs = sig.ledger;
const meta = bs.meta;
const schema = bs.schema.schema;
const shred_mod = sig.ledger.shred;
const shredder = sig.ledger.shredder;

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const AutoHashMap = std.AutoHashMap;
const Atomic = std.atomic.Value;
const GetMetricError = sig.prometheus.registry.GetMetricError;
const Mutex = std.Thread.Mutex;
const PointerClosure = sig.utils.closure.PointerClosure;

const Counter = sig.prometheus.Counter;
const ErasureSetId = sig.ledger.shred.ErasureSetId;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const Shred = sig.ledger.shred.Shred;
const CodingShred = sig.ledger.shred.CodingShred;
const DataShred = sig.ledger.shred.DataShred;
const ReedSolomonCache = bs.shredder.ReedSolomonCache;
const ShredId = sig.ledger.shred.ShredId;
const SlotLeaderProvider = sig.core.leader_schedule.SlotLeaderProvider;
const SortedSet = sig.utils.collections.SortedSet;
const SortedMap = sig.utils.collections.SortedMap;
const Timer = sig.time.Timer;

const BlockstoreDB = bs.blockstore.BlockstoreDB;
const WriteBatch = BlockstoreDB.WriteBatch;

const ErasureMeta = meta.ErasureMeta;
const Index = meta.Index;
const MerkleRootMeta = meta.MerkleRootMeta;
const ShredIndex = meta.ShredIndex;
const SlotMeta = meta.SlotMeta;

const key_serializer = sig.ledger.database.key_serializer;
const value_serializer = sig.ledger.database.value_serializer;

const DEFAULT_TICKS_PER_SECOND = sig.core.time.DEFAULT_TICKS_PER_SECOND;

pub const ShredInserter = struct {
    allocator: Allocator,
    logger: sig.trace.Logger,
    db: BlockstoreDB,
    lock: Mutex,
    max_root: Atomic(u64), // TODO shared
    metrics: BlockstoreInsertionMetrics,

    const Self = @This();

    pub fn init(
        allocator: Allocator,
        logger: sig.trace.Logger,
        registry: *sig.prometheus.Registry(.{}),
        db: BlockstoreDB,
    ) GetMetricError!Self {
        return .{
            .allocator = allocator,
            .logger = logger,
            .db = db,
            .lock = .{},
            .max_root = Atomic(u64).init(0), // TODO read this from the database
            .metrics = try BlockstoreInsertionMetrics.init(registry),
        };
    }

    pub const InsertShredsResult = struct {
        completed_data_set_infos: ArrayList(CompletedDataSetInfo),
        duplicate_shreds: ArrayList(PossibleDuplicateShred),
    };

    /// The main function that performs the shred insertion logic
    /// and updates corresponding metadata.
    ///
    /// This function updates the following column families:
    ///   - [`schema.dead_slots`]: mark a shred as "dead" if its meta-data indicates
    ///     there is no need to replay this shred.  Specifically when both the
    ///     following conditions satisfy,
    ///     - We get a new shred N marked as the last shred in the slot S,
    ///       but N.index() is less than the current slot_meta.received
    ///       for slot S.
    ///     - The slot is not currently full
    ///     It means there's an alternate version of this slot. See
    ///     `check_insert_data_shred` for more details.
    ///   - [`schema.shred_data`]: stores data shreds (in check_insert_data_shreds).
    ///   - [`schema.shred_code`]: stores coding shreds (in check_insert_coding_shreds).
    ///   - [`schema.slot_meta`]: the SlotMeta of the input `shreds` and their related
    ///     shreds are updated.  Specifically:
    ///     - `handle_chaining()` updates `schema.slot_meta` in two ways.  First, it
    ///       updates the in-memory slot_meta_working_set, which will later be
    ///       persisted in commit_slot_meta_working_set().  Second, for the newly
    ///       chained slots (updated inside handle_chaining_for_slot()), it will
    ///       directly persist their slot-meta into `schema.slot_meta`.
    ///     - In `commit_slot_meta_working_set()`, persists everything stored
    ///       in the in-memory structure slot_meta_working_set, which is updated
    ///       by both `check_insert_data_shred()` and `handle_chaining()`.
    ///   - [`schema.orphans`]: add or remove the ID of a slot to `schema.orphans`
    ///     if it becomes / is no longer an orphan slot in `handle_chaining()`.
    ///   - [`schema.erasure_meta`]: the associated ErasureMeta of the coding and data
    ///     shreds inside `shreds` will be updated and committed to
    ///     `schema.erasure_meta`.
    ///   - [`schema.merkle_root_meta`]: the associated MerkleRootMeta of the coding and data
    ///     shreds inside `shreds` will be updated and committed to
    ///     `schema.merkle_root_meta`.
    ///   - [`schema.index`]: stores (slot id, index to the index_working_set_entry)
    ///     pair to the `schema.index` column family for each index_working_set_entry
    ///     which insert did occur in this function call.
    ///
    /// Arguments:
    ///  - `shreds`: the shreds to be inserted.
    ///  - `is_repaired`: a boolean vector aligned with `shreds` where each
    ///    boolean indicates whether the corresponding shred is repaired or not.
    ///  - `leader_schedule`: the leader schedule
    ///  - `is_trusted`: whether the shreds come from a trusted source. If this
    ///    is set to true, then the function will skip the shred duplication and
    ///    integrity checks.
    ///  - `retransmit_sender`: the sender for transmitting any recovered
    ///    data shreds.
    ///  - `handle_duplicate`: a function for handling shreds that have the same slot
    ///    and index.
    ///  - `self.metrics`: the metric for reporting detailed stats
    ///
    /// On success, the function returns an Ok result with a vector of
    /// `CompletedDataSetInfo` and a vector of its corresponding index in the
    /// input `shreds` vector.
    ///
    /// agave: do_insert_shreds
    pub fn insertShreds(
        self: *Self,
        shreds: []const Shred,
        is_repaired: []const bool,
        leader_schedule: ?SlotLeaderProvider,
        is_trusted: bool,
        retransmit_sender: ?PointerClosure([]const []const u8, void),
    ) !InsertShredsResult {
        self.metrics.num_shreds.add(shreds.len);
        const allocator = self.allocator;
        var reed_solomon_cache = try ReedSolomonCache.init(allocator);
        defer reed_solomon_cache.deinit();
        std.debug.assert(shreds.len == is_repaired.len);
        var total_timer = try Timer.start();
        var write_batch = try self.db.initWriteBatch();

        var just_inserted_shreds = AutoHashMap(ShredId, Shred).init(allocator); // TODO capacity = shreds.len
        var erasure_metas = SortedMap(ErasureSetId, WorkingEntry(ErasureMeta)).init(allocator);
        var merkle_root_metas = AutoHashMap(ErasureSetId, WorkingEntry(MerkleRootMeta)).init(allocator);
        var slot_meta_working_set = AutoHashMap(u64, SlotMetaWorkingSetEntry).init(allocator);
        var index_working_set = AutoHashMap(u64, IndexMetaWorkingSetEntry).init(allocator);
        var duplicate_shreds = ArrayList(PossibleDuplicateShred).init(allocator);
        defer just_inserted_shreds.deinit();
        defer erasure_metas.deinit();
        defer merkle_root_metas.deinit();
        defer deinitMapRecursive(&slot_meta_working_set);
        defer deinitMapRecursive(&index_working_set);
        defer duplicate_shreds.deinit();

        var get_lock_timer = try Timer.start();
        self.lock.lock();
        defer self.lock.unlock();
        self.metrics.insert_lock_elapsed_us.add(get_lock_timer.read().asMicros());

        var shred_insertion_timer = try Timer.start();
        var index_meta_time_us: u64 = 0;
        var newly_completed_data_sets = ArrayList(CompletedDataSetInfo).init(allocator);
        defer newly_completed_data_sets.deinit();
        for (shreds, is_repaired) |shred, is_repair| {
            const shred_source: ShredSource = if (is_repair) .repaired else .turbine;
            switch (shred) {
                .data => |data_shred| {
                    if (self.checkInsertDataShred(
                        data_shred,
                        &erasure_metas,
                        &merkle_root_metas,
                        &index_working_set,
                        &slot_meta_working_set,
                        &write_batch,
                        &just_inserted_shreds,
                        &index_meta_time_us,
                        is_trusted,
                        &duplicate_shreds,
                        leader_schedule,
                        shred_source,
                    )) |completed_data_sets| {
                        if (is_repair) {
                            self.metrics.num_repair.inc();
                        }
                        defer completed_data_sets.deinit();
                        try newly_completed_data_sets.appendSlice(completed_data_sets.items);
                        self.metrics.num_inserted.inc();
                    } else |e| switch (e) {
                        error.Exists => if (is_repair) {
                            self.metrics.num_repaired_data_shreds_exists.inc();
                        } else {
                            self.metrics.num_turbine_data_shreds_exists.inc();
                        },
                        error.InvalidShred => self.metrics.num_data_shreds_invalid.inc(),
                        // error.BlockstoreError => {
                        //     self.metrics.num_data_shreds_blockstore_error.inc();
                        //     // TODO improve this (maybe should be an error set)
                        // },
                        else => return e, // TODO explicit
                    }
                },
                .code => |coding_shred| {
                    // TODO error handling?
                    _ = try self.checkInsertCodingShred(
                        coding_shred,
                        &erasure_metas,
                        &merkle_root_metas,
                        &index_working_set,
                        &write_batch,
                        &just_inserted_shreds,
                        &index_meta_time_us,
                        &duplicate_shreds,
                        is_trusted,
                        shred_source,
                    );
                },
            }
        }
        self.metrics.insert_shreds_elapsed_us.add(shred_insertion_timer.read().asMicros());

        var shred_recovery_timer = try Timer.start();
        var valid_recovered_shreds = ArrayList([]const u8).init(allocator);
        defer valid_recovered_shreds.deinit();
        if (leader_schedule) |slot_leader_provider| {
            const recovered_shreds = try self.tryShredRecovery(
                &erasure_metas,
                &index_working_set,
                &just_inserted_shreds,
                &reed_solomon_cache,
            );
            defer {
                for (recovered_shreds.items) |shred| {
                    shred.deinit();
                }
                recovered_shreds.deinit();
            }

            for (recovered_shreds.items) |shred| {
                if (shred == .data) {
                    self.metrics.num_recovered.inc();
                }
                const leader = slot_leader_provider.call(shred.commonHeader().slot);
                if (leader == null) {
                    continue;
                }
                if (!shred.verify(leader.?)) {
                    self.metrics.num_recovered_failed_sig.inc();
                    continue;
                }
                // Since the data shreds are fully recovered from the
                // erasure batch, no need to store coding shreds in
                // blockstore.
                if (shred == .code) {
                    try valid_recovered_shreds.append(shred.payload()); // TODO lifetime
                    continue;
                }
                if (self.checkInsertDataShred(
                    shred.data,
                    &erasure_metas,
                    &merkle_root_metas,
                    &index_working_set,
                    &slot_meta_working_set,
                    &write_batch,
                    &just_inserted_shreds,
                    &index_meta_time_us,
                    is_trusted,
                    &duplicate_shreds,
                    leader_schedule,
                    .recovered,
                )) |completed_data_sets| {
                    defer completed_data_sets.deinit();
                    try newly_completed_data_sets.appendSlice(completed_data_sets.items);
                    self.metrics.num_inserted.inc();
                    try valid_recovered_shreds.append(shred.payload()); // TODO lifetime
                } else |e| switch (e) {
                    error.Exists => self.metrics.num_recovered_exists.inc(),
                    error.InvalidShred => self.metrics.num_recovered_failed_invalid.inc(),
                    // error.BlockstoreError => {
                    //     self.metrics.num_recovered_blockstore_error.inc();
                    //     // TODO improve this (maybe should be an error set)
                    // },
                    else => return e, // TODO explicit
                }
            }
            if (valid_recovered_shreds.items.len > 0) if (retransmit_sender) |sender| {
                sender.call(valid_recovered_shreds.items); // TODO lifetime
            };
        }
        self.metrics.shred_recovery_elapsed_us.add(shred_recovery_timer.read().asMicros());

        var chaining_timer = try Timer.start();
        // Handle chaining for the members of the slot_meta_working_set that were inserted into,
        // drop the others
        try self.handleChaining(&write_batch, &slot_meta_working_set);
        self.metrics.chaining_elapsed_us.add(chaining_timer.read().asMicros());

        var commit_timer = try Timer.start();
        _ = try commitSlotMetaWorkingSet(
            self.allocator,
            &slot_meta_working_set,
            &.{}, // TODO senders
            &write_batch,
        );
        // TODO return value

        const em0_keys, const em0_values = erasure_metas.items();
        for (em0_keys, em0_values) |erasure_set, working_em| if (working_em == .dirty) {
            const slot = erasure_set.slot;
            const erasure_meta: ErasureMeta = working_em.dirty;
            if (try self.hasDuplicateShredsInSlot(slot)) {
                continue;
            }
            // First coding shred from this erasure batch, check the forward merkle root chaining
            const shred_id = ShredId{
                .slot = slot,
                .index = @intCast(erasure_meta.first_received_coding_index),
                .shred_type = .code,
            };
            // unreachable: Erasure meta was just created, initial shred must exist
            const shred = just_inserted_shreds.get(shred_id) orelse unreachable;
            // TODO: agave discards the result here. should we also?
            _ = try self.checkForwardChainedMerkleRootConsistency(
                shred.code,
                erasure_meta,
                &just_inserted_shreds,
                &merkle_root_metas,
                &duplicate_shreds,
            );
        };

        var merkle_root_metas_iter = merkle_root_metas.iterator();
        while (merkle_root_metas_iter.next()) |mrm_entry| {
            const erasure_set_id = mrm_entry.key_ptr.*;
            const working_merkle_root_meta = mrm_entry.value_ptr;
            if (working_merkle_root_meta.* == .clean or
                try self.hasDuplicateShredsInSlot(erasure_set_id.slot))
            {
                continue;
            }
            // First shred from this erasure batch, check the backwards merkle root chaining
            const merkle_root_meta = working_merkle_root_meta.asRef();
            const shred_id = ShredId{
                .slot = erasure_set_id.slot,
                .index = merkle_root_meta.first_received_shred_index,
                .shred_type = merkle_root_meta.first_received_shred_type,
            };
            // unreachable: Merkle root meta was just created, initial shred must exist
            const shred = just_inserted_shreds.get(shred_id) orelse unreachable;
            // TODO: agave discards the result here. should we also?
            _ = try self.checkBackwardsChainedMerkleRootConsistency(
                shred,
                &just_inserted_shreds,
                &erasure_metas,
                &duplicate_shreds,
            );
        }

        // TODO: this feels redundant: logic of next loop applied to the data of 2 loops ago
        const em1_keys, const em1_values = erasure_metas.items();
        for (em1_keys, em1_values) |erasure_set, *working_erasure_meta| {
            if (working_erasure_meta.* == .clean) {
                continue;
            }
            try write_batch.put(
                schema.erasure_meta,
                erasure_set,
                working_erasure_meta.asRef().*,
            );
        }

        // TODO: this feels redundant: logic of prior loop applied to the data of loop before that
        var merkle_iter = merkle_root_metas.iterator();
        while (merkle_iter.next()) |merkle_entry| {
            const erasure_set_id = merkle_entry.key_ptr.*;
            const working_merkle_meta = merkle_entry.value_ptr;
            if (working_merkle_meta.* == .clean) {
                continue;
            }
            try write_batch.put(
                schema.merkle_root_meta,
                erasure_set_id,
                working_merkle_meta.asRef().*,
            );
        }

        var index_working_set_iterator = index_working_set.iterator();
        while (index_working_set_iterator.next()) |entry| {
            const working_entry = entry.value_ptr;
            if (working_entry.did_insert_occur) {
                try write_batch.put(schema.index, entry.key_ptr.*, working_entry.index);
            }
        }

        self.metrics.commit_working_sets_elapsed_us.add(commit_timer.read().asMicros());

        var write_timer = try Timer.start();
        try self.db.commit(write_batch);
        self.metrics.write_batch_elapsed_us.add(write_timer.read().asMicros());

        // TODO send signals

        self.metrics.total_elapsed_us.add(total_timer.read().asMicros());
        self.metrics.index_meta_time_us.add(index_meta_time_us);

        return .{
            .completed_data_set_infos = newly_completed_data_sets,
            .duplicate_shreds = duplicate_shreds,
        };
    }

    /// agave: check_insert_coding_shred
    /// TODO: break this up
    fn checkInsertCodingShred(
        self: *Self,
        shred: CodingShred,
        erasure_metas: *SortedMap(ErasureSetId, WorkingEntry(ErasureMeta)), // BTreeMap in rust
        merkle_root_metas: *AutoHashMap(ErasureSetId, WorkingEntry(MerkleRootMeta)),
        index_working_set: *AutoHashMap(u64, IndexMetaWorkingSetEntry),
        write_batch: *WriteBatch,
        just_received_shreds: *AutoHashMap(ShredId, Shred),
        index_meta_time_us: *u64,
        duplicate_shreds: *ArrayList(PossibleDuplicateShred),
        is_trusted: bool,
        shred_source: ShredSource,
    ) !bool {
        const slot = shred.fields.common.slot;
        const shred_index: u64 = @intCast(shred.fields.common.index);

        const index_meta_working_set_entry =
            try self.getIndexMetaEntry(self.allocator, slot, index_working_set, index_meta_time_us);
        const index_meta = &index_meta_working_set_entry.index;

        const erasure_set_id = shred.fields.common.erasureSetId();
        // TODO: redundant get or put pattern
        if (!merkle_root_metas.contains(erasure_set_id)) {
            if (try self.db.get(schema.merkle_root_meta, erasure_set_id)) |meta_| {
                try merkle_root_metas.put(erasure_set_id, .{ .clean = meta_ });
            }
        }

        // This gives the index of first coding shred in this FEC block
        // So, all coding shreds in a given FEC block will have the same set index
        if (!is_trusted) {
            if (index_meta.code.contains(shred_index)) {
                self.metrics.num_coding_shreds_exists.inc();
                try duplicate_shreds.append(.{ .Exists = .{ .code = shred } });
                return false;
            }

            if (!shouldInsertCodingShred(&shred, self.max_root.load(.unordered))) {
                self.metrics.num_coding_shreds_invalid.inc();
                return false;
            }

            if (merkle_root_metas.get(erasure_set_id)) |merkle_root_meta| {
                // A previous shred has been inserted in this batch or in blockstore
                // Compare our current shred against the previous shred for potential
                // conflicts
                if (!try self.checkMerkleRootConsistency(
                    just_received_shreds,
                    slot,
                    merkle_root_meta.asRef(),
                    &.{ .code = shred },
                    duplicate_shreds,
                )) {
                    return false;
                }
            }
        }

        // TODO: redundant get or put pattern
        const erasure_meta_entry = try erasure_metas.getOrPut(erasure_set_id);
        if (!erasure_meta_entry.found_existing) {
            if (try self.db.get(schema.erasure_meta, erasure_set_id)) |meta_| {
                erasure_meta_entry.value_ptr.* = .{ .clean = meta_ };
            } else {
                erasure_meta_entry.value_ptr.* = .{
                    .dirty = ErasureMeta.fromCodingShred(shred) orelse return error.Unwrap,
                };
            }
        }
        const erasure_meta = erasure_meta_entry.value_ptr.asRef();

        // NOTE perf: maybe this can be skipped for trusted shreds.
        // agave runs this regardless of trust, but we can check if it has
        // a meaningful performance impact to skip this for trusted shreds.
        if (!erasure_meta.checkCodingShred(shred)) {
            self.metrics.num_coding_shreds_invalid_erasure_config.inc();
            if (!try self.hasDuplicateShredsInSlot(slot)) {
                if (try self.findConflictingCodingShred(
                    shred,
                    slot,
                    erasure_meta,
                    just_received_shreds,
                )) |conflicting_shred| {
                    // TODO: reduce nesting
                    self.db.put(schema.duplicate_slots, slot, .{
                        .shred1 = conflicting_shred,
                        .shred2 = shred.fields.payload,
                    }) catch |e| {
                        // TODO: only log a database error?
                        self.logger.errf(
                            "Unable to store conflicting erasure meta duplicate proof for: {} {any} {}",
                            .{ slot, erasure_set_id, e },
                        );
                    };
                    try duplicate_shreds.append(.{
                        .ErasureConflict = .{
                            // TODO lifetimes
                            .original = .{ .code = shred },
                            .conflict = conflicting_shred,
                        },
                    });
                } else {
                    self.logger.errf(
                    // TODO: clean up newlines from all logs in this file
                        \\Unable to find the conflicting coding shred that set {any}.
                        \\This should only happen in extreme cases where blockstore cleanup has
                        \\caught up to the root. Skipping the erasure meta duplicate shred check
                    , .{erasure_meta});
                }
            }
            // TODO (agave): This is a potential slashing condition
            self.logger.warn("Received multiple erasure configs for the same erasure set!!!");
            self.logger.warnf("Slot: {}, shred index: {}, erasure_set: {any}, is_duplicate: {}, stored config: {any}, new shred: {any}", .{
                slot,
                shred.fields.common.index,
                erasure_set_id,
                try self.hasDuplicateShredsInSlot(slot), // TODO perf redundant
                erasure_meta.config,
                shred,
            });
            return false;
        }
        // TODO self.metrics
        // self.slots_stats
        //     .record_shred(shred.slot(), shred.fec_set_index(), shred_source, None);
        _ = shred_source;

        const result = if (insertCodingShred(index_meta, shred, write_batch)) |_| blk: {
            index_meta_working_set_entry.did_insert_occur = true;
            self.metrics.num_inserted.inc();
            const entry = try merkle_root_metas.getOrPut(erasure_set_id);
            if (!entry.found_existing) {
                entry.value_ptr.* = .{ .dirty = MerkleRootMeta.fromShred(shred) };
            }
            break :blk true;
        } else |_| false;

        const shred_entry = try just_received_shreds.getOrPut(shred.fields.id());
        if (!shred_entry.found_existing) {
            self.metrics.num_coding_shreds_inserted.inc();
            shred_entry.value_ptr.* = .{ .code = shred }; // TODO lifetime
        }

        return result;
    }

    /// agave: should_insert_coding_shred
    fn shouldInsertCodingShred(shred: *const CodingShred, max_root: Slot) bool {
        assertOk(shred.sanitize());
        return shred.fields.common.slot > max_root;
    }

    /// agave: find_conflicting_coding_shred
    fn findConflictingCodingShred(
        self: *Self,
        _: CodingShred,
        slot: Slot,
        erasure_meta: *const ErasureMeta,
        just_received_shreds: *const AutoHashMap(ShredId, Shred),
    ) !?[]const u8 { // TODO consider lifetime
        // Search for the shred which set the initial erasure config, either inserted,
        // or in the current batch in just_received_shreds.
        const index: u32 = @intCast(erasure_meta.first_received_coding_index);
        const shred_id = ShredId{ .slot = slot, .index = index, .shred_type = .code };
        const maybe_shred = try self.getShredFromJustInsertedOrDb(just_received_shreds, shred_id);

        if (index != 0 or maybe_shred != null) {
            return maybe_shred;
        }

        return null;
    }

    // FIXME: the return may be owned by either the hashmap or the database
    /// Finds the corresponding shred at `shred_id` in the just inserted
    /// shreds or the backing store. Returns None if there is no shred.
    /// agave: get_shred_from_just_inserted_or_db
    fn getShredFromJustInsertedOrDb(
        self: *Self,
        just_inserted_shreds: *const AutoHashMap(ShredId, Shred),
        id: ShredId,
    ) !?[]const u8 { // TODO consider lifetime -> return must inform a conditional deinit
        if (just_inserted_shreds.get(id)) |shred| {
            return shred.payload(); // owned by map
        }
        return switch (id.shred_type) {
            // owned by database
            .data => if (try self.db.getBytes(schema.data_shred, .{ id.slot, @intCast(id.index) })) |s| s.data else null,
            .code => if (try self.db.getBytes(schema.code_shred, .{ id.slot, @intCast(id.index) })) |s| s.data else null,
        };
    }

    /// agave: check_insert_data_shred
    fn checkInsertDataShred(
        self: *Self,
        shred: DataShred,
        erasure_metas: *SortedMap(ErasureSetId, WorkingEntry(ErasureMeta)), // BTreeMap in rust
        merkle_root_metas: *AutoHashMap(ErasureSetId, WorkingEntry(MerkleRootMeta)),
        index_working_set: *AutoHashMap(u64, IndexMetaWorkingSetEntry),
        slot_meta_working_set: *AutoHashMap(u64, SlotMetaWorkingSetEntry),
        write_batch: *WriteBatch,
        just_inserted_shreds: *AutoHashMap(ShredId, Shred),
        index_meta_time_us: *u64,
        is_trusted: bool,
        duplicate_shreds: *ArrayList(PossibleDuplicateShred),
        leader_schedule: ?SlotLeaderProvider,
        shred_source: ShredSource,
    ) !ArrayList(CompletedDataSetInfo) {
        const slot = shred.fields.common.slot;
        const shred_index: u64 = @intCast(shred.fields.common.index);
        const shred_union = Shred{ .data = shred };

        const index_meta_working_set_entry =
            try self.getIndexMetaEntry(self.allocator, slot, index_working_set, index_meta_time_us);
        const index_meta = &index_meta_working_set_entry.index;
        const slot_meta_entry = try self.getSlotMetaEntry(
            slot_meta_working_set,
            slot,
            try shred.parent(),
        );
        const slot_meta = &slot_meta_entry.new_slot_meta;

        const erasure_set_id = shred.fields.common.erasureSetId();
        // TODO: redundant get or put pattern
        if (!merkle_root_metas.contains(erasure_set_id)) {
            if (try self.db.get(schema.merkle_root_meta, erasure_set_id)) |meta_| {
                try merkle_root_metas.put(erasure_set_id, .{ .clean = meta_ });
            }
        }

        if (!is_trusted) {
            if (isDataShredPresent(shred, slot_meta, &index_meta.data)) {
                try duplicate_shreds.append(.{ .Exists = shred_union });
                return error.Exists;
            }
            if (shred.isLastInSlot() and
                shred_index < slot_meta.received and
                !slot_meta.isFull())
            {
                // We got a last shred < slot_meta.received, which signals there's an alternative,
                // shorter version of the slot. Because also `!slot_meta.is_full()`, then this
                // means, for the current version of the slot, we might never get all the
                // shreds < the current last index, never replay this slot, and make no
                // progress (for instance if a leader sends an additional detached "last index"
                // shred with a very high index, but none of the intermediate shreds). Ideally, we would
                // just purge all shreds > the new last index slot, but because replay may have already
                // replayed entries past the newly detected "last" shred, then mark the slot as dead
                // and wait for replay to dump and repair the correct version.
                self.logger.warnf(
                    "Received *last* shred index {} less than previous shred index {}, and slot {} is not full, marking slot dead",
                    .{ shred_index, slot_meta.received, slot },
                );
                try write_batch.put(schema.dead_slots, slot, true);
            }

            if (!try self.shouldInsertDataShred(
                shred,
                slot_meta,
                just_inserted_shreds,
                self.max_root.load(.unordered),
                leader_schedule,
                shred_source,
                duplicate_shreds,
            )) {
                return error.InvalidShred;
            }

            if (merkle_root_metas.get(erasure_set_id)) |merkle_root_meta| {
                // A previous shred has been inserted in this batch or in blockstore
                // Compare our current shred against the previous shred for potential
                // conflicts
                if (!try self.checkMerkleRootConsistency(
                    just_inserted_shreds,
                    slot,
                    merkle_root_meta.asRef(),
                    &shred_union,
                    duplicate_shreds,
                )) {
                    return error.InvalidShred;
                }
            }
        }

        const newly_completed_data_sets = try self.insertDataShred(
            slot_meta,
            &index_meta.data,
            &shred,
            write_batch,
            shred_source,
        );
        const entry = try merkle_root_metas.getOrPut(erasure_set_id);
        if (!entry.found_existing) {
            entry.value_ptr.* = .{ .dirty = MerkleRootMeta.fromShred(shred) };
        }
        try just_inserted_shreds.put(shred.fields.id(), shred_union); // TODO check first?
        index_meta_working_set_entry.did_insert_occur = true;
        slot_meta_entry.did_insert_occur = true;

        // TODO: redundant get or put pattern
        const erasure_meta_entry = try erasure_metas.getOrPut(erasure_set_id);
        if (!erasure_meta_entry.found_existing) {
            if (try self.db.get(schema.erasure_meta, erasure_set_id)) |meta_| {
                erasure_meta_entry.value_ptr.* = .{ .clean = meta_ };
            } else {
                std.debug.assert(erasure_metas.remove(erasure_set_id));
            }
        }

        return newly_completed_data_sets;
    }

    /// agave: get_index_meta_entry
    fn getIndexMetaEntry(
        self: *Self,
        allocator: std.mem.Allocator,
        slot: Slot,
        working_set: *AutoHashMap(Slot, IndexMetaWorkingSetEntry),
        index_meta_time_us: *u64,
    ) !*IndexMetaWorkingSetEntry {
        // TODO: redundant get or put pattern
        var timer = try Timer.start();
        const entry = try working_set.getOrPut(slot);
        if (!entry.found_existing) {
            if (try self.db.get(schema.index, slot)) |item| {
                entry.value_ptr.* = .{ .index = item };
            } else {
                entry.value_ptr.* = IndexMetaWorkingSetEntry.init(allocator, slot);
            }
        }
        index_meta_time_us.* += timer.read().asMicros();
        return entry.value_ptr;
    }

    /// agave: get_slot_meta_entry
    fn getSlotMetaEntry(
        self: *Self,
        working_set: *AutoHashMap(u64, SlotMetaWorkingSetEntry),
        slot: Slot,
        parent_slot: Slot,
    ) !*SlotMetaWorkingSetEntry {
        // TODO: redundant get or put pattern
        const entry = try working_set.getOrPut(slot);
        if (!entry.found_existing) {
            if (try self.db.get(schema.slot_meta, slot)) |backup| {
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

    /// agave: insert_coding_shred
    fn insertCodingShred(
        index_meta: *meta.Index,
        shred: CodingShred,
        write_batch: *WriteBatch,
    ) !void {
        const slot = shred.fields.common.slot;
        const shred_index: u64 = @intCast(shred.fields.common.index);

        assertOk(shred.sanitize());

        try write_batch.put(schema.code_shred, .{ slot, shred_index }, shred.fields.payload);
        try index_meta.code.put(shred_index);
    }

    /// Check if the shred already exists in blockstore
    /// agave: is_data_shred_present
    fn isDataShredPresent(
        shred: DataShred,
        slot_meta: *const SlotMeta,
        data_index: *meta.ShredIndex,
    ) bool {
        const shred_index: u64 = @intCast(shred.fields.common.index);
        return shred_index < slot_meta.consecutive_received_from_0 or
            data_index.contains(shred_index);
    }

    /// agave: should_insert_data_shred
    fn shouldInsertDataShred(
        self: *Self,
        shred: DataShred,
        slot_meta: *const SlotMeta,
        just_inserted_shreds: *AutoHashMap(ShredId, Shred),
        max_root: Slot,
        leader_schedule: ?SlotLeaderProvider,
        shred_source: ShredSource,
        duplicate_shreds: *ArrayList(PossibleDuplicateShred),
    ) !bool {
        const slot = shred.fields.common.slot;
        const shred_index_u32 = shred.fields.common.index;
        const shred_index_u64: u64 = @intCast(shred_index_u32);
        const is_last_in_slot = shred.isLastInSlot();
        assertOk(shred.sanitize());

        // Check that we do not receive a shred with either:
        // - shred_index >= than the last_index for the slot
        // - "last_index" true, but shred_index less than our current received
        if (slot_meta.last_index != null and shred_index_u64 > slot_meta.last_index.? or
            is_last_in_slot and shred_index_u64 < slot_meta.received)
        {
            if (!try self.hasDuplicateShredsInSlot(slot)) {
                const shred_id = ShredId{
                    .slot = slot,
                    .index = shred_index_u32,
                    .shred_type = .data,
                };
                // FIXME: leak - decide how to free shred
                const maybe_shred = try self.getShredFromJustInsertedOrDb(just_inserted_shreds, shred_id);
                const ending_shred = if (maybe_shred) |s| s else {
                    self.logger.errf(&newlinesToSpaces(
                        \\Last received data shred {any} indicated by slot meta \
                        \\{any} is missing from blockstore. This should only happen in \
                        \\extreme cases where blockstore cleanup has caught up to the root. \
                        \\Skipping data shred insertion
                    ), .{ shred_id, slot_meta });
                    return false; // TODO: this is redundant
                };
                const dupe = meta.DuplicateSlotProof{
                    .shred1 = ending_shred,
                    .shred2 = shred.fields.payload,
                };
                self.db.put(schema.duplicate_slots, slot, dupe) catch |e| {
                    // TODO: only log a database error?
                    self.logger.errf("failed to store duplicate slot: {}", .{e});
                };
                // FIXME data ownership
                try duplicate_shreds.append(.{ .LastIndexConflict = .{
                    .original = .{ .data = shred },
                    .conflict = ending_shred,
                } });
            }

            const leader_pubkey = slotLeader(leader_schedule, slot);
            self.logger.errf(
                "Leader {any}, slot {}: received shred_index {} < slot.received {}, shred_source: {any}",
                .{ leader_pubkey, slot, shred_index_u32, slot_meta.received, shred_source },
            );
            return false;
        }

        // TODO (from agave) Shouldn't this use shred.parent() instead and update
        // slot_meta.parent_slot accordingly?
        return if (slot_meta.parent_slot) |parent_slot|
            verifyShredSlots(slot, parent_slot, max_root)
        else
            false;
    }

    /// agave: get_data_shred
    fn getDataShred(self: *Self, slot: Slot, index: u64) !?[]const u8 {
        if (try self.db.getBytes(schema.data_shred, .{ slot, index })) |shred| {
            const payload = shred.payload();
            std.debug.assert(payload.len == shred_mod.data_shred.payload_size);
            return payload;
        }
    }

    /// agave: has_duplicate_shreds_in_slot
    fn hasDuplicateShredsInSlot(self: *Self, slot: Slot) !bool {
        // TODO PERF: just need to check for existence, don't need the value
        return try self.db.getBytes(schema.duplicate_slots, slot) != null;
    }

    /// agave: check_merkle_root_consistency
    fn checkMerkleRootConsistency(
        self: *Self,
        just_inserted_shreds: *const AutoHashMap(ShredId, Shred),
        slot: Slot,
        merkle_root_meta: *const meta.MerkleRootMeta,
        shred: *const Shred,
        duplicate_shreds: *ArrayList(PossibleDuplicateShred),
    ) !bool {
        const new_merkle_root = shred.merkleRoot() catch null;
        if (new_merkle_root == null and merkle_root_meta.merkle_root == null or
            new_merkle_root != null and merkle_root_meta.merkle_root != null and
            std.mem.eql(u8, &merkle_root_meta.merkle_root.?.data, &new_merkle_root.?.data))
        {
            // No conflict, either both merkle shreds with same merkle root
            // or both legacy shreds with merkle_root `None`
            return true;
        }

        self.logger.warnf(&newlinesToSpaces(
            \\Received conflicting merkle roots for slot: {}, erasure_set: {any} original merkle
            \\root meta {any} vs conflicting merkle root {any} shred index {} type {any}. Reporting
            \\as duplicate
        ), .{
            slot,
            shred.commonHeader().erasureSetId(),
            merkle_root_meta,
            new_merkle_root,
            shred.commonHeader().index,
            shred,
        });

        if (!try self.hasDuplicateShredsInSlot(slot)) {
            const shred_id = ShredId{
                .slot = slot,
                .index = merkle_root_meta.first_received_shred_index,
                .shred_type = merkle_root_meta.first_received_shred_type,
            };
            if (try self.getShredFromJustInsertedOrDb(just_inserted_shreds, shred_id)) |conflicting_shred| {
                try duplicate_shreds.append(.{
                    .MerkleRootConflict = .{
                        .original = shred.*, // TODO lifetimes (cloned in rust)
                        .conflict = conflicting_shred,
                    },
                });
            } else {
                self.logger.errf(&newlinesToSpaces(
                    \\Shred {any} indiciated by merkle root meta {any} is 
                    \\missing from blockstore. This should only happen in extreme cases where 
                    \\blockstore cleanup has caught up to the root. Skipping the merkle root 
                    \\consistency check
                ), .{ shred_id, merkle_root_meta });
                return true;
            }
        }
        return false;
    }

    /// agave: insert_data_shred
    pub fn insertDataShred(
        self: *const Self,
        slot_meta: *SlotMeta,
        data_index: *meta.ShredIndex,
        shred: *const DataShred,
        write_batch: *WriteBatch,
        _: ShredSource,
    ) !ArrayList(CompletedDataSetInfo) {
        const slot = shred.fields.common.slot;
        const index_u32 = shred.fields.common.index;
        const index: u64 = @intCast(index_u32);

        const new_consecutive = if (slot_meta.consecutive_received_from_0 == index) blk: {
            var current_index = index + 1;
            while (data_index.contains(current_index)) {
                current_index += 1;
            }
            break :blk current_index;
        } else slot_meta.consecutive_received_from_0;

        try write_batch.put(schema.data_shred, .{ slot, index }, shred.fields.payload);
        try data_index.put(index);

        var newly_completed_data_sets = ArrayList(CompletedDataSetInfo).init(self.allocator);
        const shred_indices = try updateSlotMeta(
            self.allocator,
            shred.isLastInSlot(),
            shred.dataComplete(),
            slot_meta,
            index_u32,
            new_consecutive,
            shred.referenceTick(),
            data_index,
        );
        defer shred_indices.deinit();
        for (shred_indices.items) |indices| {
            const start, const end = indices;
            try newly_completed_data_sets.append(.{
                .slot = slot,
                .start_index = start,
                .end_index = end,
            });
        }

        // TODO self.metrics: record_shred
        if (slot_meta.isFull()) {
            self.sendSlotFullTiming(slot);
        }

        return newly_completed_data_sets;
    }

    /// send slot full timing point to poh_timing_report service
    /// agave: send_slot_full_timing
    fn sendSlotFullTiming(self: *const Self, slot: Slot) void {
        _ = self;
        _ = slot;
        // TODO
    }

    // agave: try_shred_recovery
    fn tryShredRecovery(
        self: *Self,
        erasure_metas: *SortedMap(ErasureSetId, WorkingEntry(ErasureMeta)),
        index_working_set: *AutoHashMap(u64, IndexMetaWorkingSetEntry),
        prev_inserted_shreds: *const AutoHashMap(ShredId, Shred),
        reed_solomon_cache: *ReedSolomonCache,
    ) !ArrayList(Shred) {
        // Recovery rules:
        // 1. Only try recovery around indexes for which new data or coding shreds are received
        // 2. For new data shreds, check if an erasure set exists. If not, don't try recovery
        // 3. Before trying recovery, check if enough number of shreds have been received
        // 3a. Enough number of shreds = (#data + #coding shreds) > erasure.num_data
        const keys, const values = erasure_metas.items();
        // let index = &mut index_meta_entry.index;
        for (keys, values) |erasure_set, *working_erasure_meta| {
            const erasure_meta = working_erasure_meta.asRef();
            var index_meta_entry = index_working_set.get(erasure_set.slot) orelse {
                return error.Unwrap; // TODO: consider all the unwraps
            };
            switch (erasure_meta.status(&index_meta_entry.index)) {
                .can_recover => return try self.recoverShreds(
                    &index_meta_entry.index,
                    erasure_meta,
                    prev_inserted_shreds,
                    reed_solomon_cache,
                ),
                .data_full => {
                    // TODO: submit self.metrics
                },
                .still_need => {
                    // TODO: submit self.metrics
                },
            }
        }
        return std.ArrayList(Shred).init(self.allocator);
    }

    /// agave: recover_shreds
    fn recoverShreds(
        self: *Self,
        index: *const Index,
        erasure_meta: *const ErasureMeta,
        prev_inserted_shreds: *const AutoHashMap(ShredId, Shred),
        reed_solomon_cache: *ReedSolomonCache,
    ) !std.ArrayList(Shred) {
        var available_shreds = ArrayList(Shred).init(self.allocator);
        defer available_shreds.deinit();

        try getRecoveryShreds(
            self,
            .data,
            &index.data,
            index.slot,
            erasure_meta.dataShredsIndices(),
            prev_inserted_shreds,
            &available_shreds,
        );
        try getRecoveryShreds(
            self,
            .code,
            &index.code,
            index.slot,
            erasure_meta.codingShredsIndices(),
            prev_inserted_shreds,
            &available_shreds,
        );

        if (shredder.recover(
            self.allocator,
            available_shreds.items,
            reed_solomon_cache,
        )) |shreds| {
            return shreds;
        } else |e| {
            // TODO: submit_self.metrics
            // TODO: consider returning error (agave does not return an error or log)
            self.logger.errf("shred recovery error: {}", .{e});
            return std.ArrayList(Shred).init(self.allocator);
        }
    }

    // agave: get_recovery_data_shreds and get_recovery_coding_shreds
    fn getRecoveryShreds(
        self: *Self,
        comptime shred_type: sig.ledger.shred.ShredType,
        index: *const ShredIndex,
        slot: Slot,
        shred_indices: [2]u64,
        prev_inserted_shreds: *const AutoHashMap(ShredId, Shred),
        available_shreds: *ArrayList(Shred),
    ) !void {
        const column_family = switch (shred_type) {
            .data => schema.data_shred,
            .code => schema.code_shred,
        };
        for (shred_indices[0]..shred_indices[1]) |i| {
            const key = ShredId{ .slot = slot, .index = @intCast(i), .shred_type = shred_type };
            if (prev_inserted_shreds.get(key)) |shred| {
                try available_shreds.append(shred);
            } else if (index.contains(i)) {
                const shred = try self.db.getBytes(column_family, .{ slot, i }) orelse {
                    self.logger.errf(
                        \\Unable to read the {s} with slot {}, index {} for shred
                        \\recovery. The shred is marked present in the slot's {s} index,
                        \\but the shred could not be found in the {s} column.
                    , .{ column_family.name, slot, i, column_family.name, column_family.name });
                    continue;
                };
                defer shred.deinit();
                try available_shreds.append(try Shred.fromPayload(self.allocator, shred.data));
            }
        }
    }

    /// agave: handle_chaining
    fn handleChaining(
        self: *Self,
        write_batch: *WriteBatch,
        working_set: *AutoHashMap(u64, SlotMetaWorkingSetEntry),
    ) !void {
        const count = working_set.count();
        if (count == 0) return; // TODO is this correct?

        // filter out slots that were not inserted
        var keys = try self.allocator.alloc(u64, count);
        defer self.allocator.free(keys);
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
        var new_chained_slots = AutoHashMap(u64, SlotMeta).init(self.allocator);
        defer deinitMapRecursive(&new_chained_slots);
        for (keys[0..keep_i]) |slot| {
            try self.handleChainingForSlot(write_batch, working_set, &new_chained_slots, slot);
        }

        // Write all the newly changed slots in new_chained_slots to the write_batch
        var new_iter = new_chained_slots.iterator();
        while (new_iter.next()) |entry| {
            try write_batch.put(schema.slot_meta, entry.key_ptr.*, entry.value_ptr.*);
        }
    }

    /// agave: handle_chaining_for_slot
    fn handleChainingForSlot(
        self: *Self,
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
                const prev_slot_meta = try self
                    .findSlotMetaElseCreate(working_set, new_chained_slots, prev_slot);

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
            try self.traverseChildrenMut(
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
        self: *Self,
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
        entry.value_ptr.* = if (try self.db.get(schema.slot_meta, slot)) |m|
            m
        else
            SlotMeta.init(self.allocator, slot, null);
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
        self: *Self,
        slots: []const u64,
        working_set: *AutoHashMap(u64, SlotMetaWorkingSetEntry),
        passed_visited_slots: *AutoHashMap(u64, SlotMeta),
    ) !void {
        var slot_lists = std.ArrayList([]const u64).init(self.allocator);
        defer slot_lists.deinit();
        try slot_lists.append(slots);
        var i: usize = 0;
        while (i < slot_lists.items.len) {
            const slot_list = slot_lists.items[i];
            for (slot_list) |slot| {
                const slot_meta = try self.findSlotMetaElseCreate(
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

    /// Returns true if there is no chaining conflict between
    /// the `shred` and `merkle_root_meta` of the next FEC set,
    /// or if shreds from the next set are yet to be received.
    ///
    /// Otherwise return false and add duplicate proof to
    /// `duplicate_shreds`.
    ///
    /// This is intended to be used right after `shred`'s `erasure_meta`
    /// has been created for the first time.
    ///
    /// agave: check_forward_chained_merkle_root_consistency
    fn checkForwardChainedMerkleRootConsistency(
        self: *Self,
        shred: CodingShred,
        erasure_meta: ErasureMeta,
        just_inserted_shreds: *const AutoHashMap(ShredId, Shred),
        merkle_root_metas: *AutoHashMap(ErasureSetId, WorkingEntry(MerkleRootMeta)),
        duplicate_shreds: *std.ArrayList(PossibleDuplicateShred),
    ) !bool {
        std.debug.assert(erasure_meta.checkCodingShred(shred));
        const slot = shred.fields.common.slot;
        const erasure_set_id = shred.fields.common.erasureSetId();

        // If a shred from the next fec set has already been inserted, check the chaining
        const next_fec_set_index = if (erasure_meta.nextFecSetIndex()) |n| n else {
            self.logger.errf(
                "Invalid erasure meta, unable to compute next fec set index {any}",
                .{erasure_meta},
            );
            return false;
        };
        const next_erasure_set = ErasureSetId{ .slot = slot, .fec_set_index = next_fec_set_index };
        const next_merkle_root_meta = if (merkle_root_metas.get(next_erasure_set)) |nes|
            nes.asRef().*
        else if (try self.db.get(schema.merkle_root_meta, next_erasure_set)) |nes|
            nes
        else
            // No shred from the next fec set has been received
            return true;

        const next_shred_id = ShredId{
            .slot = slot,
            .index = next_merkle_root_meta.first_received_shred_index,
            .shred_type = next_merkle_root_meta.first_received_shred_type,
        };
        const next_shred = if (try self.getShredFromJustInsertedOrDb(just_inserted_shreds, next_shred_id)) |ns|
            ns
        else {
            self.logger.errf(
                \\Shred {any} indicated by merkle root meta {any} \
                \\is missing from blockstore. This should only happen in extreme cases where \
                \\blockstore cleanup has caught up to the root. Skipping the forward chained \
                \\merkle root consistency check
            , .{ next_shred_id, next_merkle_root_meta });
            return true;
        };
        const merkle_root = shred.fields.merkleRoot() catch null;
        const chained_merkle_root = shred_mod.layout.getChainedMerkleRoot(next_shred);

        if (!checkChaining(merkle_root, chained_merkle_root)) {
            self.logger.warnf(
                \\Received conflicting chained merkle roots for slot: {}, shred \
                \\{any} type {any} has merkle root {any}, however next fec set \
                \\shred {any} type {any} chains to merkle root \
                \\{any}. Reporting as duplicate
            , .{
                slot,
                erasure_set_id,
                shred.fields.common.shred_variant.shred_type,
                merkle_root,
                next_erasure_set,
                next_merkle_root_meta.first_received_shred_type,
                chained_merkle_root,
            });
            if (!try self.hasDuplicateShredsInSlot(slot)) {
                // TODO lifetime
                try duplicate_shreds.append(.{ .ChainedMerkleRootConflict = .{
                    .original = .{ .code = shred },
                    .conflict = next_shred,
                } });
            }
            return false;
        }

        return true;
    }

    /// Returns true if there is no chaining conflict between
    /// the `shred` and `merkle_root_meta` of the previous FEC set,
    /// or if shreds from the previous set are yet to be received.
    ///
    /// Otherwise return false and add duplicate proof to
    /// `duplicate_shreds`.
    ///
    /// This is intended to be used right after `shred`'s `merkle_root_meta`
    /// has been created for the first time.
    ///
    /// agave: check_backwards_chained_merkle_root_consistency
    fn checkBackwardsChainedMerkleRootConsistency(
        self: *Self,
        shred: Shred,
        just_inserted_shreds: *const AutoHashMap(ShredId, Shred),
        erasure_metas: *SortedMap(ErasureSetId, WorkingEntry(ErasureMeta)), // BTreeMap in agave
        duplicate_shreds: *std.ArrayList(PossibleDuplicateShred),
    ) !bool {
        const slot = shred.commonHeader().slot;
        const erasure_set_id = shred.commonHeader().erasureSetId();
        const fec_set_index = shred.commonHeader().fec_set_index;

        if (fec_set_index == 0) {
            // Although the first fec set chains to the last fec set of the parent block,
            // if this chain is incorrect we do not know which block is the duplicate until votes
            // are received. We instead delay this check until the block reaches duplicate
            // confirmation.
            return true;
        }

        // If a shred from the previous fec set has already been inserted, check the chaining.
        // Since we cannot compute the previous fec set index, we check the in memory map, otherwise
        // check the previous key from blockstore to see if it is consecutive with our current set.
        const prev_erasure_set, const prev_erasure_meta =
            if (try self.previousErasureSet(erasure_set_id, erasure_metas)) |pes|
            pes
        else
            // No shreds from the previous erasure batch have been received,
            // so nothing to check. Once the previous erasure batch is received,
            // we will verify this chain through the forward check above.
            return true;

        const prev_shred_id = ShredId{
            .slot = slot,
            .index = @intCast(prev_erasure_meta.first_received_coding_index),
            .shred_type = .code,
        };
        const prev_shred =
            if (try self.getShredFromJustInsertedOrDb(just_inserted_shreds, prev_shred_id)) |ps| ps else {
            self.logger.warnf(
                \\Shred {any} indicated by the erasure meta {any} \
                \\is missing from blockstore. This can happen if you have recently upgraded \
                \\from a version < v1.18.13, or if blockstore cleanup has caught up to the root. \
                \\Skipping the backwards chained merkle root consistency check
            , .{ prev_shred_id, prev_erasure_meta });
            return true;
        };
        const merkle_root = shred_mod.layout.getChainedMerkleRoot(prev_shred);
        const chained_merkle_root = shred.chainedMerkleRoot() catch null;

        if (!checkChaining(merkle_root, chained_merkle_root)) {
            self.logger.warnf(
                \\Received conflicting chained merkle roots for slot: {}, shred {any} type {any} \
                \\chains to merkle root {any}, however previous fec set coding \
                \\shred {any} has merkle root {any}. Reporting as duplicate
            , .{
                slot,
                shred.commonHeader().erasureSetId(),
                shred.commonHeader().shred_variant.shred_type,
                chained_merkle_root,
                prev_erasure_set,
                merkle_root,
            });
        }

        if (!try self.hasDuplicateShredsInSlot(slot)) {
            // TODO lifetime
            try duplicate_shreds.append(.{ .ChainedMerkleRootConflict = .{
                .original = shred,
                .conflict = prev_shred,
            } });
        }

        return true;
    }

    /// agave: previous_erasure_set
    fn previousErasureSet(
        self: *Self,
        erasure_set: ErasureSetId,
        erasure_metas: *SortedMap(ErasureSetId, WorkingEntry(ErasureMeta)),
    ) !?struct { ErasureSetId, ErasureMeta } { // TODO: agave uses CoW here
        const slot = erasure_set.slot;
        const fec_set_index = erasure_set.fec_set_index;

        // Check the previous entry from the in memory map to see if it is the consecutive
        // set to `erasure set`
        const id_range, const meta_range = erasure_metas.range(
            .{ .slot = slot, .fec_set_index = 0 },
            erasure_set,
        );
        if (id_range.len != 0) {
            const i = id_range.len - 1;
            const last_meta = meta_range[i].asRef();
            if (@as(u32, @intCast(fec_set_index)) == last_meta.nextFecSetIndex()) {
                return .{ id_range[i], last_meta.* };
            }
        }

        // Consecutive set was not found in memory, scan blockstore for a potential candidate
        var iter = try self.db.iterator(schema.erasure_meta, .reverse, erasure_set);
        defer iter.deinit();
        const candidate_set: ErasureSetId, //
        const candidate: ErasureMeta //
        = while (try iter.nextBytes()) |entry| {
            defer for (entry) |e| e.deinit();
            const key = try key_serializer.deserialize(ErasureSetId, self.allocator, entry[0].data);
            if (key.slot != slot) return null;
            if (key.fec_set_index != fec_set_index) break .{
                key,
                try value_serializer.deserialize(ErasureMeta, self.allocator, entry[1].data),
            };
        } else return null;

        // Check if this is actually the consecutive erasure set
        const next = if (candidate.nextFecSetIndex()) |n| n else return error.InvalidErasureConfig;
        return if (next == fec_set_index)
            .{ candidate_set, candidate }
        else
            return null;
    }

    /// agave: check_chaining
    fn checkChaining(
        merkle_root: ?Hash,
        chained_merkle_root: ?Hash,
    ) bool {
        return chained_merkle_root == null or // Chained merkle roots have not been enabled yet
            sig.utils.types.eql(chained_merkle_root, merkle_root);
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
        allocator: Allocator,
        slot_meta_working_set: *const AutoHashMap(u64, SlotMetaWorkingSetEntry),
        completed_slots_senders: []const void, // TODO
        write_batch: *WriteBatch,
    ) !struct { bool, ArrayList(u64) } {
        var should_signal = false;
        var newly_completed_slots = ArrayList(u64).init(allocator);

        // Check if any metadata was changed, if so, insert the new version of the
        // metadata into the write batch
        var iter = slot_meta_working_set.iterator();
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
                try write_batch.put(schema.slot_meta, entry.key_ptr.*, slot_meta.*);
            }
        }

        return .{ should_signal, newly_completed_slots };
    }
};

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

/// agave: is_newly_completed_slot
fn isNewlyCompletedSlot(slot_meta: *const SlotMeta, backup_slot_meta: *const ?SlotMeta) bool {
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

fn verifyShredSlots(slot: Slot, parent: Slot, root: Slot) bool {
    if (slot == 0 and parent == 0 and root == 0) {
        return true; // valid write to slot zero.
    }
    // Ignore shreds that chain to slots before the root,
    // or have invalid parent >= slot.
    return root <= parent and parent < slot;
}

fn slotLeader(provider: ?SlotLeaderProvider, slot: Slot) ?Pubkey {
    return if (provider) |p| if (p.call(slot)) |l| l else null else null;
}

/// update_slot_meta
fn updateSlotMeta(
    allocator: Allocator,
    is_last_in_slot: bool,
    is_last_in_data: bool,
    slot_meta: *SlotMeta,
    index: u32,
    new_consecutive_received_from_0: u64,
    reference_tick: u8,
    received_data_shreds: *meta.ShredIndex,
) Allocator.Error!ArrayList([2]u32) {
    const first_insert = slot_meta.received == 0;
    // Index is zero-indexed, while the "received" height starts from 1,
    // so received = index + 1 for the same shred.
    slot_meta.received = @max(@as(u64, @intCast(index)) + 1, slot_meta.received);
    if (first_insert) {
        // predict the timestamp of what would have been the first shred in this slot
        const slot_time_elapsed = @as(u64, @intCast(reference_tick)) * 1000 / DEFAULT_TICKS_PER_SECOND;
        slot_meta.first_shred_timestamp_milli = @as(u64, @intCast(std.time.milliTimestamp())) -| slot_time_elapsed;
    }
    slot_meta.consecutive_received_from_0 = new_consecutive_received_from_0;
    // If the last index in the slot hasn't been set before, then
    // set it to this shred index
    if (is_last_in_slot and slot_meta.last_index == null) {
        slot_meta.last_index = @intCast(index);
    }
    return try updateCompletedDataIndexes(
        allocator,
        is_last_in_slot or is_last_in_data,
        index,
        received_data_shreds,
        &slot_meta.completed_data_indexes,
    );
}

/// Update the `completed_data_indexes` with a new shred `new_shred_index`. If a
/// data set is complete, return the range of shred indexes [start_index, end_index]
/// for that completed data set.
/// update_completed_data_indexes
fn updateCompletedDataIndexes(
    allocator: Allocator,
    is_last_in_data: bool,
    new_shred_index: u32,
    received_data_shreds: *meta.ShredIndex,
    /// Shreds indices which are marked data complete.
    completed_data_indexes: *SortedSet(u32),
) Allocator.Error!ArrayList([2]u32) {
    var shred_indices = ArrayList(u32).init(allocator);
    defer shred_indices.deinit();
    const subslice = completed_data_indexes.range(null, new_shred_index);
    const start_shred_index = if (subslice.len == 0) 0 else subslice[subslice.len - 1];
    // Consecutive entries i, k, j in this vector represent potential ranges [i, k),
    // [k, j) that could be completed data ranges
    try shred_indices.append(start_shred_index);
    // `new_shred_index` is data complete, so need to insert here into the
    // `completed_data_indexes`
    if (is_last_in_data) {
        try completed_data_indexes.put(new_shred_index);
        try shred_indices.append(new_shred_index + 1);
    }
    const new_subslice = completed_data_indexes.range(new_shred_index + 1, null);
    if (new_subslice.len != 0) {
        try shred_indices.append(new_subslice[0]);
    }

    var ret = ArrayList([2]u32).init(allocator);
    var i: usize = 0;
    while (i + 1 < shred_indices.items.len) {
        const begin = shred_indices.items[i];
        const end = shred_indices.items[i + 1];
        const num_shreds: usize = @intCast(end - begin);
        if (received_data_shreds.range(begin, end).len == num_shreds) {
            try ret.append(.{ begin, end - 1 });
        }
        i += 1;
    }
    return ret;
}

fn WorkingEntry(comptime T: type) type {
    return union(enum) {
        // Value has been modified with respect to the blockstore column
        dirty: T,
        // Value matches what is currently in the blockstore column
        clean: T,

        fn asRef(self: *const @This()) *const T {
            return switch (self.*) {
                .dirty => &self.dirty,
                .clean => &self.clean,
            };
        }
    };
}

const ShredSource = enum {
    turbine,
    repaired,
    recovered,
};

pub const CompletedDataSetInfo = struct {
    /// [`Slot`] to which the [`Shred`]s in this set belong.
    slot: Slot,

    /// Index of the first [`Shred`] in the range of shreds that belong to this set.
    /// Range is inclusive, `start_index..=end_index`.
    start_index: u32,

    /// Index of the last [`Shred`] in the range of shreds that belong to this set.
    /// Range is inclusive, `start_index..=end_index`.
    end_index: u32,
};

const PossibleDuplicateShred = union(enum) {
    Exists: Shred, // Blockstore has another shred in its spot
    LastIndexConflict: ShredConflict, // The index of this shred conflicts with `slot_meta.last_index`
    ErasureConflict: ShredConflict, // The coding shred has a conflict in the erasure_meta
    MerkleRootConflict: ShredConflict, // Merkle root conflict in the same fec set
    ChainedMerkleRootConflict: ShredConflict, // Merkle root chaining conflict with previous fec set
};

const ShredConflict = struct {
    original: Shred,
    conflict: []const u8,
};

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

pub const BlockstoreInsertionMetrics = struct {
    insert_lock_elapsed_us: *Counter, // u64
    insert_shreds_elapsed_us: *Counter, // u64
    shred_recovery_elapsed_us: *Counter, // u64
    chaining_elapsed_us: *Counter, // u64
    commit_working_sets_elapsed_us: *Counter, // u64
    write_batch_elapsed_us: *Counter, // u64
    total_elapsed_us: *Counter, // u64
    index_meta_time_us: *Counter, // u64
    num_shreds: *Counter, // usize
    num_inserted: *Counter, // u64
    num_repair: *Counter, // u64
    num_recovered: *Counter, // usize
    num_recovered_blockstore_error: *Counter, // usize
    num_recovered_inserted: *Counter, // usize
    num_recovered_failed_sig: *Counter, // usize
    num_recovered_failed_invalid: *Counter, // usize
    num_recovered_exists: *Counter, // usize
    num_repaired_data_shreds_exists: *Counter, // usize
    num_turbine_data_shreds_exists: *Counter, // usize
    num_data_shreds_invalid: *Counter, // usize
    num_data_shreds_blockstore_error: *Counter, // usize
    num_coding_shreds_exists: *Counter, // usize
    num_coding_shreds_invalid: *Counter, // usize
    num_coding_shreds_invalid_erasure_config: *Counter, // usize
    num_coding_shreds_inserted: *Counter, // usize

    pub fn init(registry: *sig.prometheus.Registry(.{})) !BlockstoreInsertionMetrics {
        var self: BlockstoreInsertionMetrics = undefined;
        inline for (@typeInfo(BlockstoreInsertionMetrics).Struct.fields) |field| {
            const name = "shred_inserter_" ++ field.name;
            @field(self, field.name) = try registry.getOrCreateCounter(name);
        }
        return self;
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

fn deinitMapRecursive(map: anytype) void {
    var iter = map.iterator();
    while (iter.next()) |entry| {
        entry.value_ptr.deinit();
    }
    map.deinit();
}

fn newlinesToSpaces(comptime fmt: []const u8) [fmt.len]u8 {
    var ret: [fmt.len]u8 = .{' '} ** fmt.len;
    for (fmt, 0..) |char, i| if (char != '\n') {
        ret[i] = char;
    };
    return ret;
}

//////////
// Tests

const test_shreds = @import("test_shreds.zig");
const comptimePrint = std.fmt.comptimePrint;

fn assertOk(result: anytype) void {
    std.debug.assert(if (result) |_| true else |_| false);
}

const test_dir = comptimePrint("test_data/blockstore/insert_shred", .{});

pub const TestState = struct {
    db: BlockstoreDB,
    inserter: ShredInserter,
    registry: sig.prometheus.Registry(.{}),

    // if this leaks, you forgot to call `TestState.deinit`
    _leak_check: []const u8,

    // var gpa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 100 }){};
    // pub const allocator = gpa.allocator();

    pub const allocator = std.testing.allocator;

    pub fn init(comptime test_name: []const u8) !TestState {
        return initWithLogger(test_name, (sig.trace.TestLogger{}).logger());
    }

    fn initWithLogger(comptime test_name: []const u8, logger: sig.trace.Logger) !TestState {
        const path = comptimePrint("{s}/{s}", .{ test_dir, test_name });
        try sig.ledger.tests.freshDir(path);
        const db = try BlockstoreDB.open(allocator, logger, path);
        var registry = sig.prometheus.Registry(.{}).init(allocator);
        const inserter = try ShredInserter.init(allocator, logger, &registry, db);
        return .{
            .db = db,
            .inserter = inserter,
            .registry = registry,
            ._leak_check = try std.testing.allocator.alloc(u8, 1),
        };
    }

    /// Test helper to convert raw bytes into shreds and pass them to insertShreds
    fn insertShredBytes(
        self: *TestState,
        shred_payloads: []const []const u8,
    ) !ShredInserter.InsertShredsResult {
        const shreds = try allocator.alloc(Shred, shred_payloads.len);
        defer {
            for (shreds) |shred| shred.deinit();
            allocator.free(shreds);
        }
        for (shred_payloads, 0..) |payload, i| {
            shreds[i] = try Shred.fromPayload(allocator, payload);
        }
        const is_repairs = try allocator.alloc(bool, shreds.len);
        defer allocator.free(is_repairs);
        for (0..shreds.len) |i| {
            is_repairs[i] = false;
        }
        return self.inserter.insertShreds(shreds, is_repairs, null, false, null);
    }

    fn checkInsertCodingShred(
        self: *TestState,
        shred: Shred,
        write_batch: *WriteBatch,
        merkle_root_metas: *AutoHashMap(ErasureSetId, WorkingEntry(MerkleRootMeta)),
    ) !struct { bool, ArrayList(PossibleDuplicateShred) } {
        var just_inserted_shreds = AutoHashMap(ShredId, Shred).init(allocator);
        var erasure_metas = SortedMap(ErasureSetId, WorkingEntry(ErasureMeta)).init(allocator);

        var slot_meta_working_set = AutoHashMap(u64, SlotMetaWorkingSetEntry).init(allocator);
        var index_working_set = AutoHashMap(u64, IndexMetaWorkingSetEntry).init(allocator);
        var duplicate_shreds = ArrayList(PossibleDuplicateShred).init(allocator);
        defer just_inserted_shreds.deinit();
        defer erasure_metas.deinit();
        defer deinitMapRecursive(&slot_meta_working_set);
        defer deinitMapRecursive(&index_working_set);

        var i: usize = 0;

        return .{
            try self.inserter.checkInsertCodingShred(
                shred.code,
                &erasure_metas,
                merkle_root_metas,
                &index_working_set,
                write_batch,
                &just_inserted_shreds,
                &i,
                &duplicate_shreds,
                false,
                .turbine,
            ),
            duplicate_shreds,
        };
    }

    pub fn deinit(self: *@This()) void {
        self.db.deinit(true);
        self.registry.deinit();
        std.testing.allocator.free(self._leak_check);
        // _ = gpa.detectLeaks();
    }
};

test "insertShreds single shred" {
    var state = try TestState.init("insertShreds single shred");
    defer state.deinit();
    const allocator = std.testing.allocator;
    const shred = try Shred.fromPayload(allocator, &sig.ledger.shred.test_data_shred);
    defer shred.deinit();
    _ = try state.inserter.insertShreds(&.{shred}, &.{false}, null, false, null);
    const stored_shred = try state.db.getBytes(
        schema.data_shred,
        .{ shred.commonHeader().slot, shred.commonHeader().index },
    );
    defer stored_shred.?.deinit();
    try std.testing.expectEqualSlices(u8, shred.payload(), stored_shred.?.data);
}

test "insertShreds 100 shreds from mainnet" {
    var state = try TestState.init("insertShreds 32 shreds");
    defer state.deinit();

    const shred_bytes = test_shreds.mainnet_shreds;
    var shreds = std.ArrayList(Shred).init(std.testing.allocator);
    defer shreds.deinit();
    defer for (shreds.items) |s| s.deinit();

    for (shred_bytes) |payload| {
        const shred = try Shred.fromPayload(std.testing.allocator, payload);
        try shreds.append(shred);
    }
    _ = try state.inserter
        .insertShreds(shreds.items, &(.{false} ** shred_bytes.len), null, false, null);
    for (shreds.items) |shred| {
        const bytes = try state.db.getBytes(
            schema.data_shred,
            .{ shred.commonHeader().slot, shred.commonHeader().index },
        );
        try std.testing.expectEqualSlices(u8, shred.payload(), bytes.?.data);
    }
}

// agave: test_handle_chaining_basic
test "chaining basic" {
    var state = try TestState.init("handle chaining basic");
    defer state.deinit();

    const shreds = test_shreds.handle_chaining_basic_shreds;
    const shreds_per_slot = shreds.len / 3;

    // segregate shreds by slot
    const slots = .{
        shreds[0..shreds_per_slot],
        shreds[shreds_per_slot .. 2 * shreds_per_slot],
        shreds[2 * shreds_per_slot .. 3 * shreds_per_slot],
    };

    // insert slot 1
    _ = try state.insertShredBytes(slots[1]);
    {
        var slot_meta: SlotMeta = (try state.db.get(schema.slot_meta, 1)).?;
        defer slot_meta.deinit();
        try std.testing.expectEqualSlices(u64, &.{}, slot_meta.next_slots.items);
        try std.testing.expect(!slot_meta.isConnected());
        try std.testing.expectEqual(0, slot_meta.parent_slot);
        try std.testing.expectEqual(shreds_per_slot - 1, slot_meta.last_index);
    }

    // insert slot 2
    _ = try state.insertShredBytes(slots[2]);
    {
        var slot_meta: SlotMeta = (try state.db.get(schema.slot_meta, 1)).?;
        defer slot_meta.deinit();
        try std.testing.expectEqualSlices(u64, &.{2}, slot_meta.next_slots.items);
        try std.testing.expect(!slot_meta.isConnected()); // since 0 is not yet inserted
        try std.testing.expectEqual(0, slot_meta.parent_slot);
        try std.testing.expectEqual(shreds_per_slot - 1, slot_meta.last_index);
    }
    {
        var slot_meta: SlotMeta = (try state.db.get(schema.slot_meta, 2)).?;
        defer slot_meta.deinit();
        try std.testing.expectEqualSlices(u64, &.{}, slot_meta.next_slots.items);
        try std.testing.expect(!slot_meta.isConnected()); // since 0 is not yet inserted
        try std.testing.expectEqual(1, slot_meta.parent_slot);
        try std.testing.expectEqual(shreds_per_slot - 1, slot_meta.last_index);
    }

    // insert slot 0
    _ = try state.insertShredBytes(slots[0]);
    {
        var slot_meta: SlotMeta = (try state.db.get(schema.slot_meta, 0)).?;
        defer slot_meta.deinit();
        try std.testing.expectEqualSlices(u64, &.{1}, slot_meta.next_slots.items);
        try std.testing.expect(slot_meta.isConnected());
        try std.testing.expectEqual(0, slot_meta.parent_slot);
        try std.testing.expectEqual(shreds_per_slot - 1, slot_meta.last_index);
    }
    {
        var slot_meta: SlotMeta = (try state.db.get(schema.slot_meta, 1)).?;
        defer slot_meta.deinit();
        try std.testing.expectEqualSlices(u64, &.{2}, slot_meta.next_slots.items);
        try std.testing.expect(slot_meta.isConnected());
        try std.testing.expectEqual(0, slot_meta.parent_slot);
        try std.testing.expectEqual(shreds_per_slot - 1, slot_meta.last_index);
    }
    {
        var slot_meta: SlotMeta = (try state.db.get(schema.slot_meta, 2)).?;
        defer slot_meta.deinit();
        try std.testing.expectEqualSlices(u64, &.{}, slot_meta.next_slots.items);
        try std.testing.expect(slot_meta.isConnected());
        try std.testing.expectEqual(1, slot_meta.parent_slot);
        try std.testing.expectEqual(shreds_per_slot - 1, slot_meta.last_index);
    }
}

// agave: test_merkle_root_metas_coding
test "merkle root metas coding" {
    var state = try TestState.initWithLogger("handle chaining basic", .noop);
    defer state.deinit();
    const allocator = TestState.allocator;

    const slot = 1;
    const start_index = 0;

    const shreds = try loadShredsFromFile(
        allocator,
        &[1]usize{1228} ** 3,
        "test_data/shreds/merkle_root_metas_coding_test_shreds_3_1228.bin",
    );
    defer for (shreds) |shred| shred.deinit();

    { // first shred (should succeed)
        var write_batch = try state.db.initWriteBatch();
        const this_shred = shreds[0];
        var merkle_root_metas =
            AutoHashMap(ErasureSetId, WorkingEntry(MerkleRootMeta)).init(allocator);
        defer merkle_root_metas.deinit();

        const succeeded, //
        const duplicate_shreds = try state
            .checkInsertCodingShred(this_shred, &write_batch, &merkle_root_metas);
        defer duplicate_shreds.deinit();
        try std.testing.expect(succeeded);

        const erasure_set_id = this_shred.commonHeader().erasureSetId();
        const merkle_root_meta = merkle_root_metas.get(erasure_set_id).?.asRef();
        try std.testing.expectEqual(merkle_root_metas.count(), 1);
        try std.testing.expectEqual(
            merkle_root_meta.merkle_root.?,
            try this_shred.merkleRoot(),
        );
        try std.testing.expectEqual(merkle_root_meta.first_received_shred_index, start_index);
        try std.testing.expectEqual(merkle_root_meta.first_received_shred_type, .code);

        var mrm_iter = merkle_root_metas.iterator();
        while (mrm_iter.next()) |entry| {
            const erasure_set = entry.key_ptr;
            const working_merkle_root_meta = entry.value_ptr;
            try write_batch.put(
                schema.merkle_root_meta,
                erasure_set.*,
                working_merkle_root_meta.asRef().*,
            );
        }
        try state.db.commit(write_batch);
    }

    var merkle_root_metas = AutoHashMap(ErasureSetId, WorkingEntry(MerkleRootMeta)).init(allocator);
    defer merkle_root_metas.deinit();

    { // second shred (same index as first, should conflict with merkle root)
        var write_batch = try state.db.initWriteBatch();
        const this_shred = shreds[1];

        const succeeded, //
        const duplicate_shreds = try state
            .checkInsertCodingShred(this_shred, &write_batch, &merkle_root_metas);
        defer duplicate_shreds.deinit();
        try std.testing.expect(!succeeded);

        try std.testing.expectEqual(1, duplicate_shreds.items.len);
        try std.testing.expectEqual(
            slot,
            duplicate_shreds.items[0].MerkleRootConflict.original.commonHeader().slot,
        );

        // Verify that we still have the merkle root meta from the original shred
        try std.testing.expectEqual(merkle_root_metas.count(), 1);
        const original_erasure_set_id = shreds[0].commonHeader().erasureSetId();
        const original_meta_from_map = merkle_root_metas.get(original_erasure_set_id).?.asRef();
        const original_meta_from_db = (try state.db.get(
            schema.merkle_root_meta,
            original_erasure_set_id,
        )).?;
        inline for (.{ original_meta_from_map, original_meta_from_db }) |original_meta| {
            try std.testing.expectEqual(
                original_meta.merkle_root.?,
                try shreds[0].merkleRoot(),
            );
            try std.testing.expectEqual(original_meta.first_received_shred_index, start_index);
            try std.testing.expectEqual(original_meta.first_received_shred_type, .code);
        }

        try state.db.commit(write_batch);
    }

    { // third shred (different index, should succeed)
        var write_batch = try state.db.initWriteBatch();
        const this_shred = shreds[2];
        const this_index = start_index + 31;

        const succeeded, //
        const duplicate_shreds = try state
            .checkInsertCodingShred(this_shred, &write_batch, &merkle_root_metas);
        defer duplicate_shreds.deinit();
        try std.testing.expect(succeeded);

        try std.testing.expectEqual(0, duplicate_shreds.items.len);

        // Verify that we still have the merkle root meta from the original shred
        try std.testing.expectEqual(merkle_root_metas.count(), 2);
        const original_erasure_set_id = shreds[0].commonHeader().erasureSetId();
        const original_meta_from_map = merkle_root_metas.get(original_erasure_set_id).?.asRef();
        const original_meta_from_db = (try state.db.get(
            schema.merkle_root_meta,
            original_erasure_set_id,
        )).?;
        inline for (.{ original_meta_from_map, original_meta_from_db }) |original_meta| {
            try std.testing.expectEqual(
                original_meta.merkle_root.?,
                try shreds[0].merkleRoot(),
            );
            try std.testing.expectEqual(original_meta.first_received_shred_index, start_index);
            try std.testing.expectEqual(original_meta.first_received_shred_type, .code);
        }

        const erasure_set_id = this_shred.commonHeader().erasureSetId();
        const merkle_root_meta = merkle_root_metas.get(erasure_set_id).?.asRef();
        try std.testing.expectEqual(merkle_root_meta.merkle_root.?, try this_shred.merkleRoot());
        try std.testing.expectEqual(merkle_root_meta.first_received_shred_index, this_index);
        try std.testing.expectEqual(merkle_root_meta.first_received_shred_type, .code);

        try state.db.commit(write_batch);
    }
}

// agave: test_recovery
test "recovery" {
    var state = try TestState.init("handle chaining basic");
    defer state.deinit();
    const allocator = TestState.allocator;

    const shreds = try loadShredsFromFile(
        allocator,
        &[1]usize{1203} ** 34 ++ &[1]usize{1228} ** 34,
        "test_data/shreds/recovery_test_shreds_34_data_34_coding.bin",
    );
    defer for (shreds) |s| s.deinit();
    const data_shreds = shreds[0..34];
    const code_shreds = shreds[34..68];

    var leader_schedule = OneSlotLeaderProvider{
        .leader = try Pubkey.fromString("2iWGQbhdWWAA15KTBJuqvAxCdKmEvY26BoFRBU4419Sn"),
    };

    const is_repairs = try allocator.alloc(bool, code_shreds.len);
    defer allocator.free(is_repairs);
    for (0..code_shreds.len) |i| is_repairs[i] = false;

    _ = try state.inserter.insertShreds(
        code_shreds,
        is_repairs,
        leader_schedule.provider(),
        false,
        null,
    );

    for (data_shreds) |data_shred| {
        const key = .{ data_shred.data.fields.common.slot, data_shred.data.fields.common.index };
        const actual_shred = try state.db.getBytes(schema.data_shred, key);
        defer actual_shred.?.deinit();
        try std.testing.expectEqualSlices(u8, data_shred.payload(), actual_shred.?.data);
    }

    // TODO: verify index integrity
}

const OneSlotLeaderProvider = struct {
    leader: Pubkey,

    fn getLeader(self: *OneSlotLeaderProvider, _: Slot) ?Pubkey {
        return self.leader;
    }

    fn provider(self: *OneSlotLeaderProvider) SlotLeaderProvider {
        return SlotLeaderProvider.init(self, OneSlotLeaderProvider.getLeader);
    }
};

const loadShredsFromFile = sig.ledger.shred.loadShredsFromFile;
