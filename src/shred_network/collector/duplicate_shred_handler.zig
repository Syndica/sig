const std = @import("std");
const sig = @import("../../sig.zig");

const bincode = sig.bincode;
const layout = sig.ledger.shred.layout;

const Allocator = std.mem.Allocator;
const KeyPair = sig.identity.KeyPair;

const Channel = sig.sync.Channel;
const ShredInserter = sig.ledger.ShredInserter;
const Slot = sig.core.Slot;

const Logger = sig.trace.Logger("duplicate_shred_handler");

pub const DUPLICATE_SHRED_HEADER_SIZE: u64 = 63;
pub const DUPLICATE_SHRED_MAX_PAYLOAD_SIZE: u16 = 512;

pub const DuplicateShredHandler = struct {
    ledger_reader: sig.ledger.Reader,
    result_writer: sig.ledger.ResultWriter,
    duplicate_slots_sender: ?*Channel(Slot),
    gossip_service: ?*sig.gossip.GossipService,
    keypair: *const KeyPair,
    logger: Logger,

    /// Handles detected duplicate slots by:
    /// - Send duplicate slot notifications to be handled in consensus part of replay
    /// - Store the duplicate proof in the ledger
    /// - Broadcast the duplicate proof via gossip
    /// Analogous to [check_duplicate](https://github.com/anza-xyz/agave/blob/aa2f078836434965e1a5a03af7f95c6640fe6e1e/core/src/window_service.rs#L155)
    pub fn handleDuplicateSlots(
        self: *DuplicateShredHandler,
        allocator: Allocator,
        result: *const ShredInserter.Result,
    ) !void {
        if (result.duplicate_shreds.items.len == 0) return;

        for (result.duplicate_shreds.items) |duplicate_shred| {
            switch (duplicate_shred) {
                .Exists => |shred| {
                    const shred_slot = shred.commonHeader().slot;
                    // Unlike the other cases we have to wait until here to decide to handle the duplicate and store
                    // in ledger. This is because the duplicate could have been part of the same insert batch,
                    // so we wait until the batch has been written.
                    if (try self.ledger_reader.isDuplicateSlot(shred_slot)) {
                        continue; // A duplicate is already recorded, skip
                    }

                    const existing_shred_payload =
                        try self.ledger_reader.isShredDuplicate(allocator, shred) orelse
                        continue; // Not a duplicate, skip this one
                    defer existing_shred_payload.deinit();

                    try self.handleDuplicateSlot(
                        self.duplicate_slots_sender,
                        shred_slot,
                        shred.payload(),
                        existing_shred_payload.items,
                    );
                },
                .LastIndexConflict,
                .ErasureConflict,
                .MerkleRootConflict,
                => |conflict| {
                    const shred_slot = conflict.original.commonHeader().slot;
                    try self.handleDuplicateSlot(
                        self.duplicate_slots_sender,
                        shred_slot,
                        conflict.original.payload(),
                        conflict.conflict.data,
                    );
                },
                .ChainedMerkleRootConflict => |conflict| {
                    const shred_slot = conflict.original.commonHeader().slot;

                    // TODO: Check feature flag for chained_merkle_conflict_duplicate_proofs
                    // For now, we'll store it unconditionally. When feature checking is implemented,
                    // this should check: if (!chained_merkle_conflict_duplicate_proofs) continue;

                    // Although this proof can be immediately stored on detection, we wait until
                    // here in order to check the feature flag, as storage in ledger can
                    // preclude the detection of other duplicate proofs in this slot
                    if (try self.ledger_reader.isDuplicateSlot(shred_slot)) {
                        continue;
                    }

                    try self.handleDuplicateSlot(
                        self.duplicate_slots_sender,
                        shred_slot,
                        conflict.original.payload(),
                        conflict.conflict.data,
                    );
                },
            }
        }
    }

    pub fn handleDuplicateSlot(
        self: *DuplicateShredHandler,
        maybe_sender: ?*Channel(Slot),
        slot: Slot,
        shred_payload: []const u8,
        duplicate_payload: []const u8,
    ) !void {
        // NOTE: All operations in this function (ledger storage, gossip broadcast,
        // consensus notification) are best effort.
        // We catch and log their errors rather than propagating them because:
        // 1. One failure shouldn't prevent the other operations from attempting
        // 2. Duplicate slot detection is auxiliary to the main shred processing pipeline

        // Store in ledger
        self.result_writer.storeDuplicateSlot(
            slot,
            shred_payload,
            duplicate_payload,
        ) catch |err| {
            self.logger.err().logf(
                "failed to store duplicate slot {}: {}",
                .{ slot, err },
            );
        };

        // Broadcast duplicate shred proof via gossip
        if (self.gossip_service) |gossip| {
            self.pushDuplicateShredToGossip(
                gossip,
                slot,
                shred_payload,
                duplicate_payload,
            ) catch |err| {
                self.logger.err().logf(
                    "failed to push duplicate shred to gossip for slot {}: {}",
                    .{ slot, err },
                );
            };
        }

        // Send to consensus (only if consensus is enabled)
        if (maybe_sender) |sender| {
            sender.send(slot) catch |err| {
                self.logger.err().logf(
                    "failed to send duplicate slot {} to consensus: {}",
                    .{ slot, err },
                );
            };
        }
    }

    pub fn pushDuplicateShredToGossip(
        self: *DuplicateShredHandler,
        gossip: *sig.gossip.GossipService,
        slot: Slot,
        shred_payload: []const u8,
        other_payload: []const u8,
    ) !void {
        const my_pubkey = sig.core.Pubkey.fromPublicKey(&self.keypair.public_key);

        // Early return if we already have a duplicate for this slot.
        if (hasDuplicateForSlot(&gossip.gossip_table_rw, my_pubkey, slot)) {
            return;
        }

        // Compute ring offset where new entries should be placed/overwritten.
        const ring_offset = computeRingOffset(&gossip.gossip_table_rw, my_pubkey);

        // Serialize duplicate slot proof.
        const allocator = gossip.allocator;
        const proof_bytes = try serializeDuplicateProof(allocator, shred_payload, other_payload);
        defer allocator.free(proof_bytes);

        // Build chunks that will be converted to CRDS.
        const chunks = try self.buildDuplicateShredChunks(
            gossip.allocator,
            slot,
            shred_payload,
            proof_bytes,
            DUPLICATE_SHRED_MAX_PAYLOAD_SIZE,
        );
        defer {
            for (chunks) |dup| gossip.allocator.free(dup.chunk);
            gossip.allocator.free(chunks);
        }

        try enqueueDuplicateShredCrdsValues(
            gossip,
            ring_offset,
            chunks,
        );
    }

    fn buildDuplicateShredChunks(
        self: *DuplicateShredHandler,
        allocator: std.mem.Allocator,
        slot: Slot,
        shred_payload: []const u8,
        proof_bytes: []const u8,
        max_size: usize,
    ) ![]const sig.gossip.data.DuplicateShred {
        const chunk_size = if (DUPLICATE_SHRED_HEADER_SIZE < max_size)
            max_size - DUPLICATE_SHRED_HEADER_SIZE
        else
            return error.InvalidSizeLimit;

        const num_chunks_usize = (proof_bytes.len + chunk_size - 1) / chunk_size;
        if (num_chunks_usize > std.math.maxInt(u8)) return error.TooManyChunks;
        const num_chunks: u8 = @intCast(num_chunks_usize);

        const wallclock = sig.time.getWallclockMs();

        const shred_index = layout.getIndex(shred_payload) orelse return error.InvalidShred;

        const shred_type: sig.gossip.data.ShredType = .Code;

        var chunks: std.ArrayListUnmanaged(sig.gossip.data.DuplicateShred) = .empty;
        errdefer {
            for (chunks.items) |dup| allocator.free(dup.chunk);
            chunks.deinit(allocator);
        }
        try chunks.ensureTotalCapacity(allocator, num_chunks_usize);

        var chunk_index: u8 = 0;
        var offset: usize = 0;
        while (offset < proof_bytes.len) : ({
            chunk_index += 1;
            offset += chunk_size;
        }) {
            const chunk_end = @min(offset + chunk_size, proof_bytes.len);
            const chunk_data = proof_bytes[offset..chunk_end];
            chunks.appendAssumeCapacity(.{
                .from = sig.core.Pubkey.fromPublicKey(&self.keypair.public_key),
                .wallclock = wallclock,
                .slot = slot,
                .shred_index = shred_index,
                .shred_type = shred_type,
                .num_chunks = num_chunks,
                .chunk_index = chunk_index,
                .chunk = try allocator.dupe(u8, chunk_data),
            });
        }

        return try chunks.toOwnedSlice(allocator);
    }
};

fn hasDuplicateForSlot(
    gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
    my_pubkey: sig.core.Pubkey,
    slot: Slot,
) bool {
    var gossip_table, var lock = gossip_table_rw.readWithLock();
    defer lock.unlock();

    if (gossip_table.pubkey_to_values.get(my_pubkey)) |records| {
        for (records.keys()) |record_ix| {
            const versioned_data = gossip_table.store.getByIndex(record_ix);
            switch (versioned_data.data) {
                .DuplicateShred => |dup| {
                    _, const dup_shred = dup;
                    if (dup_shred.slot == slot) return true;
                },
                else => {},
            }
        }
    }
    return false;
}

pub fn computeRingOffset(
    gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
    my_pubkey: sig.core.Pubkey,
) u16 {
    const MAX_DUPLICATE_SHREDS = sig.gossip.data.MAX_DUPLICATE_SHREDS;
    var num_dup_shreds: u16 = 0;
    var oldest_index: u16 = 0;
    var maybe_oldest_wallclock: ?u64 = null;

    var gossip_table, var lock = gossip_table_rw.readWithLock();
    defer lock.unlock();

    if (gossip_table.pubkey_to_values.get(my_pubkey)) |records| {
        for (records.keys()) |record_ix| {
            const versioned_data = gossip_table.store.getByIndex(record_ix);
            switch (versioned_data.data) {
                .DuplicateShred => |dup| {
                    const index, const dup_shred = dup;
                    num_dup_shreds +%= 1;
                    const wc = dup_shred.wallclock;
                    if (maybe_oldest_wallclock) |old_wc| {
                        if (wc < old_wc or (wc == old_wc and index < oldest_index)) {
                            maybe_oldest_wallclock = wc;
                            oldest_index = index;
                        }
                    } else {
                        maybe_oldest_wallclock = wc;
                        oldest_index = index;
                    }
                },
                else => {},
            }
        }
    }

    return if (num_dup_shreds < MAX_DUPLICATE_SHREDS) num_dup_shreds else oldest_index;
}

pub fn serializeDuplicateProof(
    allocator: std.mem.Allocator,
    shred_payload: []const u8,
    other_payload: []const u8,
) ![]const u8 {
    // TODO validate the shreds. Implement check_shreds in Agave
    const proof = sig.ledger.meta.DuplicateSlotProof{
        .shred1 = shred_payload,
        .shred2 = other_payload,
    };
    var proof_data: std.ArrayListUnmanaged(u8) = .empty;
    errdefer proof_data.deinit(allocator);
    try bincode.write(proof_data.writer(allocator), proof, bincode.Params.standard);
    const bytes = try proof_data.toOwnedSlice(allocator);
    return bytes;
}

fn enqueueDuplicateShredCrdsValues(
    gossip: *sig.gossip.GossipService,
    ring_offset: u16,
    chunks: []const sig.gossip.data.DuplicateShred,
) !void {
    const MAX_DUPLICATE_SHREDS = sig.gossip.data.MAX_DUPLICATE_SHREDS;

    var push_queue, var lock = gossip.push_msg_queue_mux.writeWithLock();
    defer lock.unlock();

    for (chunks, 0..) |duplicate_shred, i| {
        const ring_index: u16 = (ring_offset + @as(u16, @intCast(i))) % MAX_DUPLICATE_SHREDS;
        const chunk_copy = try push_queue.data_allocator.dupe(u8, duplicate_shred.chunk);
        errdefer push_queue.data_allocator.free(chunk_copy);

        const dup_owned = sig.gossip.data.DuplicateShred{
            .from = duplicate_shred.from,
            .wallclock = duplicate_shred.wallclock,
            .slot = duplicate_shred.slot,
            .shred_index = duplicate_shred.shred_index,
            .shred_type = duplicate_shred.shred_type,
            .num_chunks = duplicate_shred.num_chunks,
            .chunk_index = duplicate_shred.chunk_index,
            .chunk = chunk_copy,
        };

        try push_queue.queue.append(.{
            .DuplicateShred = .{ ring_index, dup_owned },
        });
    }
}
