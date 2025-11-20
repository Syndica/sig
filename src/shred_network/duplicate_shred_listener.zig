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
    shred_version: *const std.atomic.Value(u16),
    epoch_tracker: *sig.core.EpochTracker,
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
            .cached_slots_in_epoch = params.epoch_tracker.epoch_schedule.slots_per_epoch,
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

        const epoch = self.params.epoch_tracker.epoch_schedule.getEpoch(self.last_root);
        // Only update cached staked nodes if we don't have any cached or the epoch has changed
        if (self.cached_staked_nodes.count() == 0 or self.cached_on_epoch < epoch) {
            self.cached_on_epoch = epoch;

            // Refresh cached staked nodes from epoch context
            if (self.params.epoch_tracker.getEpochInfo(self.last_root)) |epoch_info| {
                // Clear and repopulate cached staked nodes
                self.cached_staked_nodes.clearRetainingCapacity();
                for (
                    epoch_info.stakes.stakes.vote_accounts.staked_nodes.keys(),
                    epoch_info.stakes.stakes.vote_accounts.staked_nodes.values(),
                ) |pubkey, stake| {
                    self.cached_staked_nodes.put(self.allocator, pubkey, stake) catch {
                        break;
                    };
                }
            } else |_| {}

            self.cached_slots_in_epoch =
                self.params.epoch_tracker.epoch_schedule.getSlotsInEpoch(epoch);
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

        const leader = leader: {
            const info =
                self.params.epoch_tracker.getEpochInfo(key.slot) catch return error.UnknownLeader;
            break :leader info.leaders.getLeaderOrNull(key.slot) orelse return error.UnknownLeader;
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
