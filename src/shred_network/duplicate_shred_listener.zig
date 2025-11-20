const std = @import("std");
const sig = @import("../sig.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const Channel = sig.sync.Channel;
const GossipTable = sig.gossip.GossipTable;
const Logger = sig.trace.Logger("duplicate_shred_listener");
const Pubkey = sig.core.Pubkey;
const RwMux = sig.sync.RwMux;
const Slot = sig.core.Slot;

const GossipVersionedData = sig.gossip.data.GossipVersionedData;
const DuplicateShred = sig.gossip.data.DuplicateShred;

const ResultWriter = sig.ledger.ResultWriter;
const LedgerReader = sig.ledger.Reader;
const DuplicateSlotProof = sig.ledger.meta.DuplicateSlotProof;

const GOSSIP_SLEEP_MILLIS: u64 = 100;
const MAX_NUM_CHUNKS: usize = 3;
const MAX_NUM_ENTRIES_PER_PUBKEY: usize = 128;
const BUFFER_CAPACITY: usize = 512 * MAX_NUM_ENTRIES_PER_PUBKEY;

pub const HandlerParams = struct {
    result_writer: ResultWriter,
    ledger_reader: LedgerReader,
    duplicate_slots_sender: *Channel(Slot),
    leader_schedule: sig.core.leader_schedule.SlotLeaders,
    shred_version: *const std.atomic.Value(u16),
    epoch_schedule: sig.core.EpochSchedule,
    epoch_ctx_mgr: *sig.adapter.EpochContextManager,
};

pub const RecvLoopParams = struct {
    exit: *Atomic(bool),
    gossip_table_rw: *RwMux(GossipTable),
    handler: HandlerParams,
};

const Key = struct { slot: Slot, from: Pubkey };

const BufferEntry = struct {
    chunks: [MAX_NUM_CHUNKS]?[]u8,
};

pub fn recvLoop(
    allocator: Allocator,
    logger: Logger,
    params: RecvLoopParams,
) !void {
    var handler = DuplicateShredHandler.init(allocator, logger, params.handler);
    defer handler.deinit();

    var cursor: usize = 0;
    var buf: [512]GossipVersionedData = undefined;

    while (!params.exit.load(.monotonic)) {
        const gossip_data: []GossipVersionedData = blk: {
            const gossip_table, var lock = params.gossip_table_rw.readWithLock();
            defer lock.unlock();
            break :blk gossip_table.getClonedEntriesWithCursor(
                allocator,
                &buf,
                &cursor,
            ) catch |e| {
                logger.err().logf("duplicate_shred_listener: get entries failed: {}", .{e});
                break :blk &.{};
            };
        };

        if (gossip_data.len == 0) {
            std.time.sleep(GOSSIP_SLEEP_MILLIS * std.time.ns_per_ms);
            continue;
        }

        for (gossip_data) |*versioned| {
            defer versioned.deinit(allocator);
            switch (versioned.data) {
                .DuplicateShred => |data| {
                    _, const duplicate_shred = data;
                    handler.handle(duplicate_shred) catch |e| handler.logger.err().logf(
                        "duplicate_shred_listener: handle chunk failed for slot {}: {}",
                        .{ duplicate_shred.slot, e },
                    );
                },
                else => {},
            }
        }
    }
}

const DuplicateShredHandler = struct {
    allocator: Allocator,
    logger: Logger,
    params: HandlerParams,
    // Because we use UDP for packet transfer, we can normally only send ~1500 bytes
    // in each packet. We send both shreds and meta data in duplicate shred proof, and
    // each shred is normally 1 packet(1500 bytes), so the whole proof is larger than
    // 1 packet and it needs to be cut down as chunks for transfer. So we need to piece
    // together the chunks into the original proof before anything useful is done.
    dup_buffer: std.AutoArrayHashMapUnmanaged(Key, BufferEntry),
    // Cached state: slots for which a duplicate proof is already ingested.
    // This is synchronized with the blockstore during pruning to avoid redundant duplicate slot checks.
    consumed: std.AutoHashMapUnmanaged(Slot, bool),
    // Cached state: last root slot from blockstore to reduce read overhead.
    // Updated at the beginning of each handle() call.
    last_root: Slot,
    // Cached state: the epoch for which cached_staked_nodes is valid.
    // Used to determine when to refresh cached stake information.
    cached_on_epoch: sig.core.Epoch,
    // Cached state: stake information for the current epoch.
    // Refreshed when the epoch changes to avoid repeated lookups during pruning.
    cached_staked_nodes: std.AutoHashMapUnmanaged(Pubkey, u64),
    cached_slots_in_epoch: u64,

    pub fn init(allocator: Allocator, logger: Logger, params: HandlerParams) DuplicateShredHandler {
        return .{
            .allocator = allocator,
            .logger = logger,
            .params = params,
            .dup_buffer = .empty,
            .consumed = .empty,
            .last_root = 0,
            .cached_on_epoch = 0,
            .cached_staked_nodes = .empty,
            .cached_slots_in_epoch = params.epoch_schedule.slots_per_epoch,
        };
    }

    pub fn deinit(self: *DuplicateShredHandler) void {
        for (self.dup_buffer.values()) |entry| {
            for (entry.chunks) |maybe_chunk| if (maybe_chunk) |chunk| self.allocator.free(chunk);
        }
        self.dup_buffer.deinit(self.allocator);
        self.consumed.deinit(self.allocator);
        self.cached_staked_nodes.deinit(self.allocator);
    }

    pub fn handle(self: *DuplicateShredHandler, dup_shred_data: DuplicateShred) !void {
        self.cacheRootInfo();
        try self.maybePruneBuffer();
        try self.handleShredData(dup_shred_data);
    }

    fn cacheRootInfo(self: *DuplicateShredHandler) void {
        const last_root = self.params.ledger_reader.maxRoot();
        // Early return if last_root unchanged and we have cached staked nodes
        if (last_root == self.last_root and self.cached_staked_nodes.count() > 0) return;
        self.last_root = last_root;

        const epoch = self.params.epoch_schedule.getEpoch(self.last_root);
        // Only update cached staked nodes if we don't have any cached or the epoch has changed
        if (self.cached_staked_nodes.count() == 0 or self.cached_on_epoch < epoch) {
            self.cached_on_epoch = epoch;

            // Refresh cached staked nodes from epoch context
            if (self.params.epoch_ctx_mgr.get(epoch)) |ctx| {
                defer self.params.epoch_ctx_mgr.release(ctx);

                // Clear and repopulate cached staked nodes
                self.cached_staked_nodes.clearRetainingCapacity();
                for (ctx.staked_nodes.keys(), ctx.staked_nodes.values()) |pubkey, stake| {
                    self.cached_staked_nodes.put(self.allocator, pubkey, stake) catch {
                        break;
                    };
                }
            }

            self.cached_slots_in_epoch = self.params.epoch_schedule.getSlotsInEpoch(epoch);
        }
    }

    fn shouldConsumeSlot(self: *DuplicateShredHandler, slot: Slot) !bool {
        const max_slot = self.last_root +| self.cached_slots_in_epoch;
        const slot_in_range = slot > self.last_root and slot < max_slot;
        if (!slot_in_range) return false;
        // Returns false if a duplicate proof is already ingested for the slot,
        // and updates local `consumed` cache with blockstore.
        const gop = try self.consumed.getOrPut(self.allocator, slot);
        if (!gop.found_existing) {
            gop.value_ptr.* = try self.params.ledger_reader.isDuplicateSlot(slot);
        }
        return !gop.value_ptr.*;
    }

    fn maybePruneBuffer(self: *DuplicateShredHandler) !void {
        if (self.dup_buffer.count() < BUFFER_CAPACITY *| 2) return;

        // Prune consumed cache to only keep slots greater than last_root
        var consumed_iter = self.consumed.iterator();
        var slots_to_remove: std.ArrayListUnmanaged(Slot) = .empty;
        defer slots_to_remove.deinit(self.allocator);
        while (consumed_iter.next()) |entry| {
            if (entry.key_ptr.* <= self.last_root) {
                try slots_to_remove.append(self.allocator, entry.key_ptr.*);
            }
        }
        for (slots_to_remove.items) |slot| {
            _ = self.consumed.remove(slot);
        }

        // Filter out obsolete slots and limit number of entries per pubkey.
        var counts: std.AutoHashMapUnmanaged(Pubkey, usize) = .empty;
        defer counts.deinit(self.allocator);

        var keys_to_remove: std.ArrayListUnmanaged(Key) = .empty;
        defer keys_to_remove.deinit(self.allocator);

        for (self.dup_buffer.keys()) |key| {
            // Slot must be in valid range
            var keep = key.slot > self.last_root and
                key.slot < self.last_root +| self.cached_slots_in_epoch;
            if (keep) {
                // Not already consumed
                const gop = self.consumed.getOrPut(self.allocator, key.slot) catch {
                    keep = false;
                    continue;
                };
                if (!gop.found_existing) {
                    gop.value_ptr.* = self.params.ledger_reader.isDuplicateSlot(key.slot) catch true;
                }
                keep = !gop.value_ptr.*;
            }
            if (keep) {
                const g = counts.getOrPut(self.allocator, key.from) catch {
                    keys_to_remove.append(self.allocator, key) catch {};
                    continue;
                };
                if (!g.found_existing) g.value_ptr.* = 0;
                g.value_ptr.* +%= 1;
                if (g.value_ptr.* > MAX_NUM_ENTRIES_PER_PUBKEY) {
                    keys_to_remove.append(self.allocator, key) catch {};
                }
            } else {
                keys_to_remove.append(self.allocator, key) catch {};
            }
        }
        for (keys_to_remove.items) |k| {
            _ = self.dup_buffer.swapRemove(k);
        }

        if (self.dup_buffer.count() < BUFFER_CAPACITY) return;

        var tmp: std.ArrayListUnmanaged(struct { u64, Key }) = .empty;
        defer tmp.deinit(self.allocator);
        for (self.dup_buffer.keys()) |key| {
            const stake = self.cached_staked_nodes.get(key.from) orelse 0;
            try tmp.append(self.allocator, .{ stake, key });
        }
        std.sort.pdq(struct { u64, Key }, tmp.items, {}, struct {
            pub fn lessThan(_: void, a: struct { u64, Key }, b: struct { u64, Key }) bool {
                return a[0] < b[0];
            }
        }.lessThan);

        if (tmp.items.len > BUFFER_CAPACITY) {
            const to_remove_count = tmp.items.len - BUFFER_CAPACITY;
            var i: usize = 0;
            while (i < to_remove_count) : (i += 1) {
                _ = self.dup_buffer.swapRemove(tmp.items[i][1]);
            }
        }
    }

    fn handleShredData(self: *DuplicateShredHandler, dup_shred_data: DuplicateShred) !void {
        if (!try self.shouldConsumeSlot(dup_shred_data.slot)) {
            return;
        }

        if (dup_shred_data.chunk_index >= dup_shred_data.num_chunks or
            dup_shred_data.num_chunks > MAX_NUM_CHUNKS) return error.InvalidChunkIndex;

        const key = Key{ .slot = dup_shred_data.slot, .from = dup_shred_data.from };

        if (try self.params.ledger_reader.isDuplicateSlot(key.slot)) {
            self.cleanupEntry(key);
            return;
        }

        const gop = try self.dup_buffer.getOrPut(self.allocator, key);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .chunks = @splat(null) };
        }
        const entry = gop.value_ptr;

        if (entry.chunks[dup_shred_data.chunk_index]) |existing| {
            self.allocator.free(existing);
        }
        entry.chunks[dup_shred_data.chunk_index] = try self.allocator.dupe(u8, dup_shred_data.chunk);

        // If all chunks are already received, reconstruct and store
        // the duplicate slot proof in blockstore
        var filled: usize = 0;
        var total_len: usize = 0;
        for (0..dup_shred_data.num_chunks) |i| {
            if (entry.chunks[i]) |chunk| {
                filled += 1;
                total_len += chunk.len;
            }
        }
        if (filled != dup_shred_data.num_chunks) return;

        const data = try self.allocator.alloc(u8, total_len);
        defer self.allocator.free(data);

        var offset: usize = 0;
        for (0..dup_shred_data.num_chunks) |k| {
            const maybe_chunk = entry.chunks[k];
            if (maybe_chunk) |chunk| {
                @memcpy(data[offset .. offset + chunk.len], chunk);
                offset += chunk.len;
            } else {
                return error.InvalidDuplicateShreds;
            }
        }

        const shred1, const shred2 =
            self.reconstructShredsFromData(key, data) catch {
                self.cleanupEntry(key);
                return;
            };

        defer shred1.deinit();
        defer shred2.deinit();

        self.params.result_writer
            .storeDuplicateSlot(key.slot, shred1.payload(), shred2.payload()) catch |e|
            {
                self.logger.err().logf(
                    "duplicate_shred_listener: storeDuplicateSlot failed for slot {}: {}",
                    .{ key.slot, e },
                );
            };
        // Notify duplicate consensus state machine
        self.params.duplicate_slots_sender.send(key.slot) catch |e| {
            self.logger.err().logf(
                "duplicate_shred_listener: send duplicate slot {} failed: {}",
                .{ key.slot, e },
            );
        };

        self.cleanupEntry(key);
    }

    fn cleanupEntry(self: *DuplicateShredHandler, key: Key) void {
        if (self.dup_buffer.fetchSwapRemove(key)) |kv| {
            const entry = kv.value;
            for (entry.chunks) |maybe_chunk| if (maybe_chunk) |chunk| self.allocator.free(chunk);
        }
    }

    fn reconstructShredsFromData(
        self: *DuplicateShredHandler,
        key: Key,
        data: []const u8,
    ) !struct { sig.ledger.shred.Shred, sig.ledger.shred.Shred } {
        const proof = sig.bincode.readFromSlice(
            self.allocator,
            DuplicateSlotProof,
            data,
            .{},
        ) catch |e| {
            self.logger.err().logf(
                "duplicate_shred_listener: failed to deserialize proof for slot {}: {}",
                .{ key.slot, e },
            );
            return error.InvalidDuplicateShreds;
        };
        defer sig.bincode.free(self.allocator, proof);

        var shred1 = sig.ledger.shred.Shred.fromPayload(self.allocator, proof.shred1) catch {
            return error.InvalidDuplicateShreds;
        };
        errdefer shred1.deinit();
        var shred2 = sig.ledger.shred.Shred.fromPayload(self.allocator, proof.shred2) catch {
            return error.InvalidDuplicateShreds;
        };
        errdefer shred2.deinit();

        if (shred1.commonHeader().slot != key.slot or shred2.commonHeader().slot != key.slot) {
            return error.SlotMismatch;
        }

        const sv: u16 = self.params.shred_version.load(.monotonic);
        if (shred1.commonHeader().version != sv or shred2.commonHeader().version != sv) {
            return error.InvalidShredVersion;
        }

        const leader = self.params.leader_schedule.get(key.slot) orelse {
            return error.UnknownLeader;
        };
        shred1.verify(leader) catch {
            return error.InvalidSignature;
        };
        shred2.verify(leader) catch {
            return error.InvalidSignature;
        };

        const same_fec =
            shred1.commonHeader().erasure_set_index == shred2.commonHeader().erasure_set_index;
        const mr1 = shred1.merkleRoot() catch null;
        const mr2 = shred2.merkleRoot() catch null;
        var conflict_ok = false;
        if (same_fec) {
            if ((mr1 == null) != (mr2 == null)) {
                conflict_ok = true;
            } else if (mr1) |h1| {
                const h2 = mr2.?;
                if (!std.mem.eql(u8, &h1.data, &h2.data)) {
                    conflict_ok = true;
                }
            }
        } else {
            if (std.meta.activeTag(shred1) != std.meta.activeTag(shred2)) {
                return error.ShredTypeMismatch;
            }
            if (shred1.commonHeader().index == shred2.commonHeader().index) {
                if (std.mem.eql(u8, shred1.payload(), shred2.payload())) {
                    return error.InvalidDuplicateShreds;
                }
                conflict_ok = true;
            } else {
                const is_data = switch (shred1) {
                    .data => true,
                    .code => false,
                };
                if (is_data) {
                    const last1 = shred1.isLastInSlot();
                    const last2 = shred2.isLastInSlot();
                    const idx1 = shred1.commonHeader().index;
                    const idx2 = shred2.commonHeader().index;
                    if ((last1 and idx2 > idx1) or (last2 and idx1 > idx2)) {
                        conflict_ok = true;
                    }
                }
            }
        }
        if (!conflict_ok) {
            return error.InvalidDuplicateShreds;
        }

        return .{ shred1, shred2 };
    }
};

test "DuplicateShredHandler: invalid chunk index rejected" {
    const allocator = std.testing.allocator;
    var rng: std.Random.DefaultPrng = .init(std.testing.random_seed);

    var epoch_ctx = try sig.adapter.EpochContextManager.init(allocator, .INIT);
    defer epoch_ctx.deinit();

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var dup_slots_channel = try Channel(Slot).init(allocator);
    defer dup_slots_channel.deinit();

    var shred_version = std.atomic.Value(u16).init(0);

    var handler = DuplicateShredHandler.init(allocator, .noop, .{
        .result_writer = ledger.resultWriter(),
        .ledger_reader = ledger.reader(),
        .duplicate_slots_sender = &dup_slots_channel,
        .leader_schedule = epoch_ctx.slotLeaders(),
        .shred_version = &shred_version,
        .epoch_schedule = epoch_ctx.schedule,
        .epoch_ctx_mgr = &epoch_ctx,
    });
    defer handler.deinit();

    const slot: Slot = 10;
    var chunk_bytes = [_]u8{ 1, 2, 3 };
    const dup: DuplicateShred = .{
        .from = Pubkey.initRandom(rng.random()),
        .wallclock = sig.time.getWallclockMs(),
        .slot = slot,
        .shred_index = 0,
        .shred_type = .Data,
        .num_chunks = 2,
        .chunk_index = 2, // invalid (>= num_chunks)
        .chunk = &chunk_bytes,
    };
    try std.testing.expectError(error.InvalidChunkIndex, handler.handleShredData(dup));
}

test "DuplicateShredHandler: overwrite existing chunk at same index" {
    const allocator = std.testing.allocator;
    var rng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    var epoch_ctx = try sig.adapter.EpochContextManager.init(allocator, .INIT);
    defer epoch_ctx.deinit();

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var dup_slots_channel = try Channel(Slot).init(allocator);
    defer dup_slots_channel.deinit();

    var shred_version = std.atomic.Value(u16).init(0);

    var handler = DuplicateShredHandler.init(allocator, .noop, .{
        .result_writer = ledger.resultWriter(),
        .ledger_reader = ledger.reader(),
        .duplicate_slots_sender = &dup_slots_channel,
        .leader_schedule = epoch_ctx.slotLeaders(),
        .shred_version = &shred_version,
        .epoch_schedule = epoch_ctx.schedule,
        .epoch_ctx_mgr = &epoch_ctx,
    });
    defer handler.deinit();

    const slot: Slot = 11;
    const from = Pubkey.initRandom(rng.random());

    var dup: DuplicateShred = .{
        .from = from,
        .wallclock = sig.time.getWallclockMs(),
        .slot = slot,
        .shred_index = 0,
        .shred_type = .Data,
        .num_chunks = 2,
        .chunk_index = 0,
        .chunk = &.{ 9, 9 },
    };
    try handler.handleShredData(dup);

    var chunk2 = [_]u8{ 7, 7, 7 };
    dup.chunk = &chunk2;
    try handler.handleShredData(dup);

    const key = Key{ .slot = slot, .from = from };
    const entry_ptr = handler.dup_buffer.getPtr(key).?;
    try std.testing.expectEqual(chunk2.len, entry_ptr.chunks[0].?.len);
    try std.testing.expectEqualSlices(u8, entry_ptr.chunks[0].?, &chunk2);
}

test "DuplicateShredHandler: complete invalid proof cleans up entry" {
    const allocator = std.testing.allocator;
    var rng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    var epoch_ctx = try sig.adapter.EpochContextManager.init(allocator, .INIT);
    defer epoch_ctx.deinit();

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var dup_slots_channel = try Channel(Slot).init(allocator);
    defer dup_slots_channel.deinit();

    var shred_version = std.atomic.Value(u16).init(0);

    var handler = DuplicateShredHandler.init(allocator, .noop, .{
        .result_writer = ledger.resultWriter(),
        .ledger_reader = ledger.reader(),
        .duplicate_slots_sender = &dup_slots_channel,
        .leader_schedule = epoch_ctx.slotLeaders(),
        .shred_version = &shred_version,
        .epoch_schedule = epoch_ctx.schedule,
        .epoch_ctx_mgr = &epoch_ctx,
    });
    defer handler.deinit();

    const slot: Slot = 12;
    const from = Pubkey.initRandom(rng.random());
    const key = Key{ .slot = slot, .from = from };

    const dup: DuplicateShred = .{
        .from = from,
        .wallclock = sig.time.getWallclockMs(),
        .slot = slot,
        .shred_index = 0,
        .shred_type = .Data,
        .num_chunks = 1,
        .chunk_index = 0,
        .chunk = &.{ 0xAA, 0xBB, 0xCC }, // bogus
    };
    // Should attempt reconstruction, fail, and cleanup the entry
    try handler.handleShredData(dup);
    try std.testing.expectEqual(null, handler.dup_buffer.get(key));
}

test "DuplicateShredHandler: early duplicate slot skips buffering" {
    const allocator = std.testing.allocator;
    var rng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    var epoch_ctx = try sig.adapter.EpochContextManager.init(allocator, .INIT);
    defer epoch_ctx.deinit();

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var dup_slots_channel = try Channel(Slot).init(allocator);
    defer dup_slots_channel.deinit();

    var shred_version = std.atomic.Value(u16).init(0);

    var handler = DuplicateShredHandler.init(allocator, .noop, .{
        .result_writer = ledger.resultWriter(),
        .ledger_reader = ledger.reader(),
        .duplicate_slots_sender = &dup_slots_channel,
        .leader_schedule = epoch_ctx.slotLeaders(),
        .shred_version = &shred_version,
        .epoch_schedule = epoch_ctx.schedule,
        .epoch_ctx_mgr = &epoch_ctx,
    });
    defer handler.deinit();

    // Mark slot as duplicate in ledger
    const shred: sig.ledger.shred.Shred =
        try .fromPayload(allocator, &sig.ledger.shred.test_data_shred);
    defer shred.deinit();
    const slot: Slot = shred.commonHeader().slot;
    try ledger.resultWriter().storeDuplicateSlot(slot, shred.payload(), shred.payload());

    const from = Pubkey.initRandom(rng.random());
    const key = Key{ .slot = slot, .from = from };

    const dup: DuplicateShred = .{
        .from = from,
        .wallclock = sig.time.getWallclockMs(),
        .slot = slot,
        .shred_index = 0,
        .shred_type = .Data,
        .num_chunks = 2,
        .chunk_index = 0,
        .chunk = &.{ 1, 2, 3 },
    };
    try handler.handleShredData(dup);
    // Should not have buffered anything for this key
    try std.testing.expectEqual(null, handler.dup_buffer.get(key));
}

test "DuplicateShredHandler: cacheRootInfo updates cached slots in epoch" {
    const allocator = std.testing.allocator;
    var epoch_ctx = try sig.adapter.EpochContextManager.init(allocator, .INIT);
    defer epoch_ctx.deinit();

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer ledger.deinit();

    var dup_slots_channel = try Channel(Slot).init(allocator);
    defer dup_slots_channel.deinit();

    var shred_version = std.atomic.Value(u16).init(0);

    var handler = DuplicateShredHandler.init(allocator, .noop, .{
        .result_writer = ledger.resultWriter(),
        .ledger_reader = ledger.reader(),
        .duplicate_slots_sender = &dup_slots_channel,
        .leader_schedule = epoch_ctx.slotLeaders(),
        .shred_version = &shred_version,
        .epoch_schedule = epoch_ctx.schedule,
        .epoch_ctx_mgr = &epoch_ctx,
    });
    defer handler.deinit();

    {
        var setter = try handler.params.result_writer.setRootsIncremental();
        defer setter.deinit();
        try setter.addRoot(1);
        try setter.commit();

        handler.cacheRootInfo();
        const expected_epoch = handler.params.epoch_schedule.getEpoch(1);
        const expected_slots_in_epoch =
            handler.params.epoch_schedule.getSlotsInEpoch(expected_epoch);
        try std.testing.expectEqual(1, handler.last_root);
        try std.testing.expectEqual(expected_slots_in_epoch, handler.cached_slots_in_epoch);
    }

    {
        const update_epoch: sig.core.Epoch = 2;
        const update_slot = handler.params.epoch_schedule.getFirstSlotInEpoch(update_epoch);
        var setter2 = try handler.params.result_writer.setRootsIncremental();
        defer setter2.deinit();
        try setter2.addRoot(update_slot);
        try setter2.commit();

        handler.cacheRootInfo();
        try std.testing.expectEqual(update_slot, handler.last_root);
        const expected_slots_in_epoch2 = handler.params.epoch_schedule.getSlotsInEpoch(update_epoch);
        try std.testing.expectEqual(expected_slots_in_epoch2, handler.cached_slots_in_epoch);
    }
}

test "DuplicateShredHandler: cacheRootInfo populates and uses cached staked nodes" {
    const allocator = std.testing.allocator;
    var epoch_ctx_mgr = try sig.adapter.EpochContextManager.init(allocator, .INIT);
    defer epoch_ctx_mgr.deinit();

    // Set up an epoch context with staked nodes
    var staked_nodes: std.AutoArrayHashMapUnmanaged(Pubkey, u64) = .empty;

    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const node1 = Pubkey.initRandom(prng.random());
    const node2 = Pubkey.initRandom(prng.random());
    const node3 = Pubkey.initRandom(prng.random());

    try staked_nodes.put(allocator, node1, 1_000_000);
    try staked_nodes.put(allocator, node2, 500_000);
    try staked_nodes.put(allocator, node3, 100_000);

    const leader_schedule = try allocator.alloc(Pubkey, 1);
    leader_schedule[0] = node1;

    const epoch_context = sig.core.EpochContext{
        .staked_nodes = staked_nodes,
        .leader_schedule = leader_schedule,
    };
    // Transfer ownership - epoch_ctx_mgr will handle cleanup
    try epoch_ctx_mgr.put(0, epoch_context);

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer ledger.deinit();

    var dup_slots_channel = try Channel(Slot).init(allocator);
    defer dup_slots_channel.deinit();

    var shred_version = std.atomic.Value(u16).init(0);

    var handler = DuplicateShredHandler.init(allocator, .noop, .{
        .result_writer = ledger.resultWriter(),
        .ledger_reader = ledger.reader(),
        .duplicate_slots_sender = &dup_slots_channel,
        .leader_schedule = epoch_ctx_mgr.slotLeaders(),
        .shred_version = &shred_version,
        .epoch_schedule = epoch_ctx_mgr.schedule,
        .epoch_ctx_mgr = &epoch_ctx_mgr,
    });
    defer handler.deinit();

    // Initially cached_staked_nodes should be empty
    try std.testing.expectEqual(0, handler.cached_staked_nodes.count());
    try std.testing.expectEqual(0, handler.cached_on_epoch);

    // Set a root in epoch 0
    {
        var setter = try handler.params.result_writer.setRootsIncremental();
        defer setter.deinit();
        try setter.addRoot(10);
        try setter.commit();
    }

    // Call cacheRootInfo - should populate cached_staked_nodes
    handler.cacheRootInfo();

    try std.testing.expectEqual(10, handler.last_root);
    try std.testing.expectEqual(0, handler.cached_on_epoch);
    try std.testing.expectEqual(3, handler.cached_staked_nodes.count());
    try std.testing.expectEqual(1_000_000, handler.cached_staked_nodes.get(node1).?);
    try std.testing.expectEqual(500_000, handler.cached_staked_nodes.get(node2).?);
    try std.testing.expectEqual(100_000, handler.cached_staked_nodes.get(node3).?);

    // Call cacheRootInfo again with same root - should return early without refetching
    const initial_count = handler.cached_staked_nodes.count();
    handler.cacheRootInfo();
    try std.testing.expectEqual(initial_count, handler.cached_staked_nodes.count());

    // Now test that pruning uses the cached stakes
    handler.last_root = 100;
    handler.cached_slots_in_epoch = 200_000;

    const capacity = BUFFER_CAPACITY;
    const total_entries: usize = capacity * 2;
    const entries_per_node = MAX_NUM_ENTRIES_PER_PUBKEY;
    const num_nodes = total_entries / entries_per_node;

    // Create many nodes - half with high stake (node1), half with low stake (node3)
    var high_stake_nodes = std.ArrayList(Pubkey).init(allocator);
    defer high_stake_nodes.deinit();
    var low_stake_nodes = std.ArrayList(Pubkey).init(allocator);
    defer low_stake_nodes.deinit();

    // Generate nodes and add them to cached_staked_nodes
    for (0..num_nodes / 2) |_| {
        const node = Pubkey.initRandom(prng.random());
        try high_stake_nodes.append(node);
        try handler.cached_staked_nodes.put(allocator, node, 1_000_000);
    }
    for (0..num_nodes / 2) |_| {
        const node = Pubkey.initRandom(prng.random());
        try low_stake_nodes.append(node);
        try handler.cached_staked_nodes.put(allocator, node, 100_000);
    }

    // Create entries - each node gets MAX_NUM_ENTRIES_PER_PUBKEY entries
    var slot: Slot = 150;
    for (high_stake_nodes.items) |node| {
        for (0..entries_per_node) |_| {
            const key = Key{ .slot = slot, .from = node };
            const gop = try handler.dup_buffer.getOrPut(allocator, key);
            if (!gop.found_existing) gop.value_ptr.* = .{ .chunks = @splat(null) };
            slot += 1;
        }
    }
    for (low_stake_nodes.items) |node| {
        for (0..entries_per_node) |_| {
            const key = Key{ .slot = slot, .from = node };
            const gop = try handler.dup_buffer.getOrPut(allocator, key);
            if (!gop.found_existing) gop.value_ptr.* = .{ .chunks = @splat(null) };
            slot += 1;
        }
    }

    try std.testing.expect(handler.dup_buffer.count() >= capacity * 2);
    try handler.maybePruneBuffer();

    // After pruning, buffer should be at capacity
    try std.testing.expectEqual(capacity, handler.dup_buffer.count());

    // Count entries from high-stake vs low-stake nodes
    var high_stake_count: usize = 0;
    var low_stake_count: usize = 0;
    for (handler.dup_buffer.keys()) |key| {
        for (high_stake_nodes.items) |node| {
            if (key.from.equals(&node)) {
                high_stake_count += 1;
                break;
            }
        }
        for (low_stake_nodes.items) |node| {
            if (key.from.equals(&node)) {
                low_stake_count += 1;
                break;
            }
        }
    }

    // High-stake nodes should have more entries retained than low-stake nodes
    try std.testing.expect(high_stake_count > low_stake_count);
}

test "DuplicateShredHandler: maybePruneBuffer prunes when over capacity" {
    const allocator = std.testing.allocator;
    var epoch_ctx = try sig.adapter.EpochContextManager.init(allocator, .INIT);
    defer epoch_ctx.deinit();

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .noop);
    defer ledger.deinit();

    var dup_slots_channel = try Channel(Slot).init(allocator);
    defer dup_slots_channel.deinit();

    var shred_version = std.atomic.Value(u16).init(0);

    var handler = DuplicateShredHandler.init(allocator, .noop, .{
        .result_writer = ledger.resultWriter(),
        .ledger_reader = ledger.reader(),
        .duplicate_slots_sender = &dup_slots_channel,
        .leader_schedule = epoch_ctx.slotLeaders(),
        .shred_version = &shred_version,
        .epoch_schedule = epoch_ctx.schedule,
        .epoch_ctx_mgr = &epoch_ctx,
    });
    defer handler.deinit();

    handler.last_root = 1_000;
    handler.cached_slots_in_epoch = 10;

    const capacity = BUFFER_CAPACITY;
    const total_entries: usize = capacity * 2;

    const from = Pubkey.ZEROES;
    for (0..total_entries) |i| {
        const key = Key{
            .slot = handler.last_root + handler.cached_slots_in_epoch + 100 + i,
            .from = from,
        };
        const gop = try handler.dup_buffer.getOrPut(allocator, key);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .chunks = @splat(null) };
        }
    }

    try std.testing.expect(handler.dup_buffer.count() >= capacity * 2);
    try handler.maybePruneBuffer();
    try std.testing.expectEqual(0, handler.dup_buffer.count());
}

test "DuplicateShredHandler: reconstructShredsFromData returns shreds on valid proof" {
    const allocator = std.testing.allocator;
    var epoch_ctx = try sig.adapter.EpochContextManager.init(allocator, .INIT);
    defer epoch_ctx.deinit();

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var dup_slots_channel = try Channel(Slot).init(allocator);
    defer dup_slots_channel.deinit();

    var base = try sig.ledger.shred.Shred.fromPayload(allocator, &sig.ledger.shred.test_data_shred);
    defer base.deinit();

    const slot: Slot = base.commonHeader().slot;
    const version: u16 = base.commonHeader().version;

    const KeyPair = std.crypto.sign.Ed25519.KeyPair;
    const keypair = try KeyPair.generateDeterministic(@splat(1));
    const leader = Pubkey.fromPublicKey(&keypair.public_key);

    const one_slot_leader_buf = try allocator.alloc(Pubkey, 1);
    defer allocator.free(one_slot_leader_buf);
    one_slot_leader_buf[0] = leader;
    var single = sig.core.leader_schedule.SingleEpochSlotLeaders{
        .start_slot = slot,
        .slot_leaders = one_slot_leader_buf,
    };

    var shred_version = std.atomic.Value(u16).init(version);
    var handler = DuplicateShredHandler.init(allocator, .noop, .{
        .result_writer = ledger.resultWriter(),
        .ledger_reader = ledger.reader(),
        .duplicate_slots_sender = &dup_slots_channel,
        .leader_schedule = single.slotLeaders(),
        .shred_version = &shred_version,
        .epoch_schedule = epoch_ctx.schedule,
        .epoch_ctx_mgr = &epoch_ctx,
    });
    defer handler.deinit();

    var shred1 = try base.clone();
    defer shred1.deinit();
    var shred2 = try base.clone();
    defer shred2.deinit();

    const mr1 = try shred1.merkleRoot();
    const sig1_std = try keypair.sign(&mr1.data, null);
    const sig1 = sig.core.Signature.fromSignature(sig1_std);
    var payload1 = shred1.mutablePayload();
    @memcpy(payload1[0..sig.core.Signature.SIZE], &sig1.toBytes());

    const headers_size = sig.ledger.shred.DataShred.constants.headers_size;
    var payload2 = shred2.mutablePayload();
    payload2[headers_size] = payload2[headers_size] ^ 0x01;
    const mr2 = try shred2.merkleRoot();
    const sig2_std = try keypair.sign(&mr2.data, null);
    const sig2 = sig.core.Signature.fromSignature(sig2_std);
    @memcpy(payload2[0..sig.core.Signature.SIZE], &sig2.toBytes());

    const proof = DuplicateSlotProof{ .shred1 = shred1.payload(), .shred2 = shred2.payload() };
    var proof_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer proof_buf.deinit(allocator);
    try sig.bincode.write(proof_buf.writer(allocator), proof, .{});
    const proof_bytes = try proof_buf.toOwnedSlice(allocator);
    defer allocator.free(proof_bytes);

    const out1, const out2 = try handler.reconstructShredsFromData(
        .{ .slot = slot, .from = leader },
        proof_bytes,
    );
    defer out1.deinit();
    defer out2.deinit();

    try std.testing.expectEqual(slot, out1.commonHeader().slot);
    try std.testing.expectEqual(slot, out2.commonHeader().slot);
}
