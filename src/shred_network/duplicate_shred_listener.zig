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
const DuplicateShredData = sig.gossip.data.DuplicateShred;

const ResultWriter = sig.ledger.ResultWriter;
const LedgerReader = sig.ledger.Reader;
const DuplicateSlotProof = sig.ledger.meta.DuplicateSlotProof;

pub const GOSSIP_SLEEP_MILLIS: u64 = 100;
pub const MAX_NUM_CHUNKS: usize = 3;
pub const MAX_NUM_ENTRIES_PER_PUBKEY: usize = 128;
pub const BUFFER_CAPACITY: usize = 512 * MAX_NUM_ENTRIES_PER_PUBKEY;

pub const Params = struct {
    exit: *Atomic(bool),
    gossip_table_rw: *RwMux(GossipTable),
    result_writer: ResultWriter,
    ledger_reader: LedgerReader,
    duplicate_slots_sender: *Channel(Slot),
    leader_schedule: sig.core.leader_schedule.SlotLeaders,
    shred_version: *const std.atomic.Value(u16),
    epoch_schedule: sig.core.EpochSchedule,
    epoch_ctx_mgr: *sig.adapter.EpochContextManager,
};

pub const DuplicateShredListener = struct {
    thread: std.Thread,

    pub fn start(
        allocator: Allocator,
        logger: Logger,
        params: Params,
    ) !DuplicateShredListener {
        const thread = try std.Thread.spawn(
            .{},
            recvLoop,
            .{ allocator, logger, params },
        );
        errdefer thread.join();

        thread.setName("solCiEntryLstnr") catch {};
        return .{ .thread = thread };
    }

    pub fn join(self: DuplicateShredListener) void {
        self.thread.join();
    }
};

const Key = struct { slot: Slot, from: Pubkey };

const BufferEntry = struct {
    chunks: [MAX_NUM_CHUNKS]?[]u8,
};

pub fn recvLoop(
    allocator: Allocator,
    logger: Logger,
    params: Params,
) !void {
    var handler = DuplicateShredHandler.init(allocator, logger, params);
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
                    _, const dup = data;
                    handler.handle(dup) catch |e| handler.logger.err().logf(
                        "duplicate_shred_listener: handle chunk failed for slot {}: {}",
                        .{ dup.slot, e },
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
    params: Params,
    // Because we use UDP for packet transfer, we can normally only send ~1500 bytes
    // in each packet. We send both shreds and meta data in duplicate shred proof, and
    // each shred is normally 1 packet(1500 bytes), so the whole proof is larger than
    // 1 packet and it needs to be cut down as chunks for transfer. So we need to piece
    // together the chunks into the original proof before anything useful is done.
    dup_buffer: std.AutoHashMapUnmanaged(Key, BufferEntry),
    consumed: std.AutoHashMapUnmanaged(Slot, bool),
    last_root: Slot,
    cached_slots_in_epoch: u64,

    pub fn init(allocator: Allocator, logger: Logger, params: Params) DuplicateShredHandler {
        return .{
            .allocator = allocator,
            .logger = logger,
            .params = params,
            .dup_buffer = .empty,
            .consumed = .empty,
            .last_root = 0,
            .cached_slots_in_epoch = params.epoch_schedule.slots_per_epoch,
        };
    }

    pub fn deinit(self: *DuplicateShredHandler) void {
        var it = self.dup_buffer.valueIterator();
        while (it.next()) |entry| {
            for (entry.chunks) |maybe_chunk| if (maybe_chunk) |chunk| self.allocator.free(chunk);
        }
        self.dup_buffer.deinit(self.allocator);
        self.consumed.deinit(self.allocator);
    }

    pub fn handle(self: *DuplicateShredHandler, dup_shred_data: DuplicateShredData) !void {
        self.cacheRootInfo();
        self.maybePruneBuffer();
        try self.handleShredData(dup_shred_data);
    }

    fn cacheRootInfo(self: *DuplicateShredHandler) void {
        const new_root = self.params.ledger_reader.maxRoot();
        if (new_root == self.last_root) return;
        self.last_root = new_root;
        const epoch = self.params.epoch_schedule.getEpoch(self.last_root);
        self.cached_slots_in_epoch = self.params.epoch_schedule.getSlotsInEpoch(epoch);
    }

    fn shouldConsumeSlot(self: *DuplicateShredHandler, slot: Slot) !bool {
        const max_slot = self.last_root +| self.cached_slots_in_epoch;
        if (!(slot > self.last_root and slot < max_slot)) return false;
        // Returns false if a duplicate proof is already ingested for the slot,
        // and updates local `consumed` cache with blockstore.
        const gop = try self.consumed.getOrPut(self.allocator, slot);
        if (!gop.found_existing) {
            gop.value_ptr.* = try self.params.ledger_reader.isDuplicateSlot(slot);
        }
        return !gop.value_ptr.*;
    }

    fn maybePruneBuffer(self: *DuplicateShredHandler) void {
        if (self.dup_buffer.count() < BUFFER_CAPACITY * 2) return;

        var counts: std.AutoHashMapUnmanaged(Pubkey, usize) = .empty;
        defer counts.deinit(self.allocator);
        var keys_to_remove = std.ArrayListUnmanaged(Key){};
        defer keys_to_remove.deinit(self.allocator);

        var it = self.dup_buffer.keyIterator();
        while (it.next()) |key_ptr| {
            const key = key_ptr.*;
            var keep =
                key.slot > self.last_root and key.slot < self.last_root + self.cached_slots_in_epoch;
            if (keep) {
                keep = (self.shouldConsumeSlot(key.slot) catch false);
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
            _ = self.dup_buffer.remove(k);
        }

        if (self.dup_buffer.count() < BUFFER_CAPACITY) return;

        var tmp = std.ArrayListUnmanaged(struct { u64, Key }){};
        defer tmp.deinit(self.allocator);
        var it2 = self.dup_buffer.keyIterator();
        while (it2.next()) |key_ptr| {
            const key = key_ptr.*;
            const epoch = self.params.epoch_schedule.getEpoch(key.slot);
            const ctx = self.params.epoch_ctx_mgr.get(epoch);
            var stake: u64 = 0;
            if (ctx) |c| {
                if (c.staked_nodes.get(key.from)) |s| stake = s;
                self.params.epoch_ctx_mgr.release(c);
            }
            tmp.append(self.allocator, .{ stake, key }) catch {};
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
                _ = self.dup_buffer.remove(tmp.items[i][1]);
            }
        }
    }

    fn handleShredData(self: *DuplicateShredHandler, dup_shred_data: DuplicateShredData) !void {
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
            gop.value_ptr.* = .{ .chunks = [_]?[]u8{null} ** MAX_NUM_CHUNKS };
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

        var data = try self.allocator.alloc(u8, total_len);
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
        if (self.dup_buffer.fetchRemove(key)) |kv| {
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
            if ((mr1 == null and mr2 != null) or (mr1 != null and mr2 == null)) {
                conflict_ok = true;
            } else if (mr1) |h1| {
                if (mr2) |h2| {
                    if (!std.mem.eql(u8, &h1.data, &h2.data)) {
                        conflict_ok = true;
                    }
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
                    else => false,
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
    var epoch_ctx = try sig.adapter.EpochContextManager.init(allocator, .DEFAULT);
    defer epoch_ctx.deinit();

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var dup_slots_channel = try Channel(Slot).init(allocator);
    defer dup_slots_channel.deinit();

    var shred_version = std.atomic.Value(u16).init(0);

    var handler = DuplicateShredHandler.init(allocator, .noop, .{
        .exit = undefined, // not used in handler
        .gossip_table_rw = undefined,
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
    const dup: DuplicateShredData = .{
        .from = Pubkey.initRandom(std.crypto.random),
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
    var epoch_ctx = try sig.adapter.EpochContextManager.init(allocator, .DEFAULT);
    defer epoch_ctx.deinit();

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var dup_slots_channel = try Channel(Slot).init(allocator);
    defer dup_slots_channel.deinit();

    var shred_version = std.atomic.Value(u16).init(0);

    var handler = DuplicateShredHandler.init(allocator, .noop, .{
        .exit = undefined,
        .gossip_table_rw = undefined,
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
    const from = Pubkey.initRandom(std.crypto.random);

    var chunk1 = [_]u8{ 9, 9 };
    var dup: DuplicateShredData = .{
        .from = from,
        .wallclock = sig.time.getWallclockMs(),
        .slot = slot,
        .shred_index = 0,
        .shred_type = .Data,
        .num_chunks = 2,
        .chunk_index = 0,
        .chunk = &chunk1,
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
    var epoch_ctx = try sig.adapter.EpochContextManager.init(allocator, .DEFAULT);
    defer epoch_ctx.deinit();

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var dup_slots_channel = try Channel(Slot).init(allocator);
    defer dup_slots_channel.deinit();

    var shred_version = std.atomic.Value(u16).init(0);

    var handler = DuplicateShredHandler.init(allocator, .noop, .{
        .exit = undefined,
        .gossip_table_rw = undefined,
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
    const from = Pubkey.initRandom(std.crypto.random);
    const key = Key{ .slot = slot, .from = from };

    var bogus = [_]u8{ 0xAA, 0xBB, 0xCC };
    const dup: DuplicateShredData = .{
        .from = from,
        .wallclock = sig.time.getWallclockMs(),
        .slot = slot,
        .shred_index = 0,
        .shred_type = .Data,
        .num_chunks = 1,
        .chunk_index = 0,
        .chunk = &bogus,
    };
    // Should attempt reconstruction, fail, and cleanup the entry
    try handler.handleShredData(dup);
    try std.testing.expectEqual(null, handler.dup_buffer.get(key));
}

test "DuplicateShredHandler: early duplicate slot skips buffering" {
    const allocator = std.testing.allocator;
    var epoch_ctx = try sig.adapter.EpochContextManager.init(allocator, .DEFAULT);
    defer epoch_ctx.deinit();

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var dup_slots_channel = try Channel(Slot).init(allocator);
    defer dup_slots_channel.deinit();

    var shred_version = std.atomic.Value(u16).init(0);

    var handler = DuplicateShredHandler.init(allocator, .noop, .{
        .exit = undefined,
        .gossip_table_rw = undefined,
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

    const from = Pubkey.initRandom(std.crypto.random);
    const key = Key{ .slot = slot, .from = from };

    var some = [_]u8{ 1, 2, 3 };
    const dup: DuplicateShredData = .{
        .from = from,
        .wallclock = sig.time.getWallclockMs(),
        .slot = slot,
        .shred_index = 0,
        .shred_type = .Data,
        .num_chunks = 2,
        .chunk_index = 0,
        .chunk = &some,
    };
    try handler.handleShredData(dup);
    // Should not have buffered anything for this key
    try std.testing.expectEqual(null, handler.dup_buffer.get(key));
}
