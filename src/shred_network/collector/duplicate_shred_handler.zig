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

pub const GossipContext = struct {
    allocator: Allocator,
    gossip_table_rw: *sig.sync.RwMux(sig.gossip.GossipTable),
    push_msg_queue_mux: *sig.gossip.GossipService.PushMessageQueue,
};

pub const DuplicateShredHandler = struct {
    ledger_reader: sig.ledger.Reader,
    result_writer: sig.ledger.ResultWriter,
    duplicate_slots_sender: ?*Channel(Slot),
    gossip_context: ?*const GossipContext,
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
        if (self.gossip_context) |gossip_ctx| {
            self.pushDuplicateShredToGossip(
                gossip_ctx,
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
        gossip_ctx: *const GossipContext,
        slot: Slot,
        shred_payload: []const u8,
        other_payload: []const u8,
    ) !void {
        const my_pubkey = sig.core.Pubkey.fromPublicKey(&self.keypair.public_key);

        // Early return if we already have a duplicate for this slot.
        if (hasDuplicateForSlot(gossip_ctx.gossip_table_rw, my_pubkey, slot)) {
            return;
        }

        // Compute ring offset where new entries should be placed/overwritten.
        const ring_offset = computeRingOffset(gossip_ctx.gossip_table_rw, my_pubkey);

        // Serialize duplicate slot proof.
        const allocator = gossip_ctx.allocator;
        const proof_bytes = try serializeDuplicateProof(allocator, shred_payload, other_payload);
        defer allocator.free(proof_bytes);

        // Build chunks that will be converted to CRDS.
        const chunks = try self.buildDuplicateShredChunks(
            gossip_ctx.allocator,
            slot,
            shred_payload,
            proof_bytes,
            DUPLICATE_SHRED_MAX_PAYLOAD_SIZE,
        );
        defer {
            for (chunks) |dup| gossip_ctx.allocator.free(dup.chunk);
            gossip_ctx.allocator.free(chunks);
        }

        try enqueueDuplicateShredCrdsValues(
            gossip_ctx,
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
    gossip_ctx: *const GossipContext,
    ring_offset: u16,
    chunks: []const sig.gossip.data.DuplicateShred,
) !void {
    const MAX_DUPLICATE_SHREDS = sig.gossip.data.MAX_DUPLICATE_SHREDS;

    var push_queue, var lock = gossip_ctx.push_msg_queue_mux.writeWithLock();
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

const PossibleDuplicateShred = sig.ledger.shred_inserter.working_state.PossibleDuplicateShred;
const Shred = sig.ledger.shred.Shred;
const schema = sig.ledger.schema.schema;

const TestGossipState = struct {
    gossip_table_rw: sig.sync.RwMux(sig.gossip.GossipTable),
    push_msg_queue: sig.gossip.GossipService.PushMessageQueue,
    allocator: Allocator,

    pub fn init(allocator: Allocator) !TestGossipState {
        const builtin = @import("builtin");
        if (!builtin.is_test) @compileError("TestGossipState is only for testing");

        const gossip_table = try sig.gossip.GossipTable.init(allocator, allocator);
        const gossip_table_rw = sig.sync.RwMux(sig.gossip.GossipTable).init(gossip_table);
        const push_msg_queue = sig.gossip.GossipService.PushMessageQueue.init(.{
            .queue = std.ArrayList(sig.gossip.data.GossipData).init(allocator),
            .data_allocator = allocator,
        });

        return .{
            .gossip_table_rw = gossip_table_rw,
            .push_msg_queue = push_msg_queue,
            .allocator = allocator,
        };
    }

    pub fn context(self: *TestGossipState) GossipContext {
        return .{
            .allocator = self.allocator,
            .gossip_table_rw = &self.gossip_table_rw,
            .push_msg_queue_mux = &self.push_msg_queue,
        };
    }

    pub fn deinit(self: *TestGossipState) void {
        var gossip_table, var lock = self.gossip_table_rw.writeWithLock();
        defer lock.unlock();
        gossip_table.deinit();

        var push_queue, var pq_lock = self.push_msg_queue.writeWithLock();
        defer pq_lock.unlock();
        for (push_queue.queue.items) |*item| item.deinit(push_queue.data_allocator);
        push_queue.queue.deinit();
    }
};
test "handleDuplicateSlots: no sender configured" {
    const allocator = std.testing.allocator;

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const keypair: KeyPair = try .generateDeterministic(@splat(1));

    var handler: DuplicateShredHandler = .{
        .ledger_reader = ledger.reader(),
        .result_writer = ledger.resultWriter(),
        .duplicate_slots_sender = null, // No sender configured
        .gossip_context = null,
        .keypair = &keypair,
        .logger = .noop,
    };

    // Create a result with a duplicate shred
    const shred: Shred = try .fromPayload(allocator, &sig.ledger.shred.test_data_shred);

    var duplicate_shreds: std.ArrayList(PossibleDuplicateShred) = .init(allocator);
    try duplicate_shreds.append(.{ .Exists = shred });

    const result: ShredInserter.Result = .{
        .completed_data_set_infos = .init(allocator),
        .duplicate_shreds = duplicate_shreds,
    };
    defer result.deinit();

    // Should not crash. Will attempt ledger storage and gossip broadcast, but not send to consensus.
    try handler.handleDuplicateSlots(allocator, &result);
}

test "handleDuplicateSlots: no duplicate shreds" {
    const allocator = std.testing.allocator;

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const keypair: KeyPair = try .generateDeterministic(@splat(1));
    var duplicate_slots_channel: Channel(Slot) = try .init(allocator);
    defer duplicate_slots_channel.deinit();

    var handler: DuplicateShredHandler = .{
        .ledger_reader = ledger.reader(),
        .result_writer = ledger.resultWriter(),
        .duplicate_slots_sender = &duplicate_slots_channel,
        .gossip_context = null,
        .keypair = &keypair,
        .logger = .noop,
    };

    // Create a result with no duplicate shreds
    const result: ShredInserter.Result = .{
        .completed_data_set_infos = .init(allocator),
        .duplicate_shreds = .init(allocator),
    };
    defer result.deinit();

    try handler.handleDuplicateSlots(allocator, &result);

    // Verify no slot was sent
    try std.testing.expectEqual(0, duplicate_slots_channel.len());
}

test "handleDuplicateSlots: single duplicate shred" {
    const allocator = std.testing.allocator;

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const keypair: KeyPair = try .generateDeterministic(@splat(1));
    var duplicate_slots_channel: Channel(Slot) = try .init(allocator);
    defer duplicate_slots_channel.deinit();

    var handler: DuplicateShredHandler = .{
        .ledger_reader = ledger.reader(),
        .result_writer = ledger.resultWriter(),
        .duplicate_slots_sender = &duplicate_slots_channel,
        .gossip_context = null,
        .keypair = &keypair,
        .logger = .noop,
    };

    // Create a result with a single duplicate shred
    const shred: Shred = try .fromPayload(allocator, &sig.ledger.shred.test_data_shred);
    defer shred.deinit();
    const expected_slot = shred.commonHeader().slot;
    const shred_id = shred.id();

    // Create a modified payload for the second shred (different data, same slot/index)
    const modified_payload = try allocator.dupe(u8, shred.payload());
    defer allocator.free(modified_payload);
    if (modified_payload.len > 0) {
        modified_payload[modified_payload.len - 1] = modified_payload[modified_payload.len - 1] +% 1;
    }

    // Insert the ORIGINAL shred into the ledger
    var write_batch = try ledger.db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(
        schema.data_shred,
        .{ shred_id.slot, shred_id.index },
        shred.payload(),
    );
    try ledger.db.commit(&write_batch);

    // Now create the duplicate shred with the modified payload
    const duplicate_shred: Shred = try .fromPayload(allocator, modified_payload);

    var duplicate_shreds: std.ArrayList(PossibleDuplicateShred) = .init(allocator);
    try duplicate_shreds.append(.{ .Exists = duplicate_shred });

    const result: ShredInserter.Result = .{
        .completed_data_set_infos = .init(allocator),
        .duplicate_shreds = duplicate_shreds,
    };
    defer result.deinit();

    try handler.handleDuplicateSlots(allocator, &result);

    // Verify exactly one slot was sent
    try std.testing.expectEqual(1, duplicate_slots_channel.len());
    const received_slot = duplicate_slots_channel.tryReceive() orelse return error.TestFailed;
    try std.testing.expectEqual(expected_slot, received_slot);
}

test "handleDuplicateSlots: multiple duplicates same slot" {
    const allocator = std.testing.allocator;

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const keypair: KeyPair = try .generateDeterministic(@splat(1));
    var duplicate_slots_channel: Channel(Slot) = try .init(allocator);
    defer duplicate_slots_channel.deinit();

    var handler: DuplicateShredHandler = .{
        .ledger_reader = ledger.reader(),
        .result_writer = ledger.resultWriter(),
        .duplicate_slots_sender = &duplicate_slots_channel,
        .gossip_context = null,
        .keypair = &keypair,
        .logger = .noop,
    };

    // Create multiple duplicate shreds from the same slot
    const shred1: Shred = try .fromPayload(allocator, &sig.ledger.shred.test_data_shred);
    defer shred1.deinit();
    const expected_slot = shred1.commonHeader().slot;
    const shred_id = shred1.id();

    // Create modified payloads for the duplicate shreds (different data, same slot/index)
    const modified_payload1 = try allocator.dupe(u8, shred1.payload());
    defer allocator.free(modified_payload1);
    const modified_payload2 = try allocator.dupe(u8, shred1.payload());
    defer allocator.free(modified_payload2);
    if (modified_payload1.len > 0) {
        modified_payload1[modified_payload1.len - 1] =
            modified_payload1[modified_payload1.len - 1] +% 1;
        modified_payload2[modified_payload2.len - 1] =
            modified_payload2[modified_payload2.len - 1] +% 2;
    }

    // Insert the ORIGINAL shred into the ledger
    var write_batch = try ledger.db.initWriteBatch();
    defer write_batch.deinit();
    try write_batch.put(
        schema.data_shred,
        .{ shred_id.slot, shred_id.index },
        shred1.payload(),
    );
    try ledger.db.commit(&write_batch);

    const result: ShredInserter.Result = result: {
        // Now create the duplicate shreds with the modified payloads
        const duplicate_shred1: Shred = try .fromPayload(allocator, modified_payload1);
        errdefer duplicate_shred1.deinit();
        const duplicate_shred2: Shred = try .fromPayload(allocator, modified_payload2);
        errdefer duplicate_shred1.deinit();

        var duplicate_shreds = std.ArrayList(PossibleDuplicateShred).init(allocator);
        try duplicate_shreds.appendSlice(&.{
            .{ .Exists = duplicate_shred1 },
            .{ .Exists = duplicate_shred2 },
        });
        break :result .{
            .completed_data_set_infos = .init(allocator),
            .duplicate_shreds = duplicate_shreds,
        };
    };
    defer result.deinit();

    try handler.handleDuplicateSlots(allocator, &result);

    // Verify exactly one slot was sent (first duplicate is processed, subsequent ones are skipped)
    try std.testing.expectEqual(1, duplicate_slots_channel.len());
    const received_slot = duplicate_slots_channel.tryReceive() orelse return error.TestFailed;
    try std.testing.expectEqual(expected_slot, received_slot);
}

test "handleDuplicateSlots: Exists but slot already duplicate" {
    const allocator = std.testing.allocator;

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const keypair: KeyPair = try .generateDeterministic(@splat(1));
    var duplicate_slots_channel: Channel(Slot) = try .init(allocator);
    defer duplicate_slots_channel.deinit();

    var handler: DuplicateShredHandler = .{
        .ledger_reader = ledger.reader(),
        .result_writer = ledger.resultWriter(),
        .duplicate_slots_sender = &duplicate_slots_channel,
        .gossip_context = null,
        .keypair = &keypair,
        .logger = .noop,
    };

    const shred: Shred = try .fromPayload(allocator, &sig.ledger.shred.test_data_shred);
    defer shred.deinit();
    const slot = shred.commonHeader().slot;

    try ledger.resultWriter().storeDuplicateSlot(slot, shred.payload(), shred.payload());

    var duplicate_shreds: std.ArrayList(PossibleDuplicateShred) = .init(allocator);
    try duplicate_shreds.append(.{ .Exists = try shred.clone() });

    const result: ShredInserter.Result = .{
        .completed_data_set_infos = .init(allocator),
        .duplicate_shreds = duplicate_shreds,
    };
    defer result.deinit();

    try handler.handleDuplicateSlots(allocator, &result);

    // Should skip sending since slot is already duplicate
    try std.testing.expectEqual(0, duplicate_slots_channel.len());
}

test "handleDuplicateSlots: emits and stores via handleDuplicateSlot" {
    const allocator = std.testing.allocator;

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const keypair: KeyPair = try .generateDeterministic(@splat(1));
    var duplicate_slots_channel: Channel(Slot) = try .init(allocator);
    defer duplicate_slots_channel.deinit();

    const original: Shred = try .fromPayload(allocator, &sig.ledger.shred.test_data_shred);
    defer original.deinit();
    const expected_slot = original.commonHeader().slot;

    const conflict_payload = try allocator.dupe(u8, original.payload());
    defer allocator.free(conflict_payload);
    if (conflict_payload.len > 0) conflict_payload[conflict_payload.len - 1] +%= 1;

    var handler: DuplicateShredHandler = .{
        .ledger_reader = ledger.reader(),
        .result_writer = ledger.resultWriter(),
        .duplicate_slots_sender = &duplicate_slots_channel,
        .gossip_context = null,
        .keypair = &keypair,
        .logger = .noop,
    };
    try handler.handleDuplicateSlot(
        &duplicate_slots_channel,
        expected_slot,
        original.payload(),
        conflict_payload,
    );

    try std.testing.expectEqual(1, duplicate_slots_channel.len());
    const received_slot = duplicate_slots_channel.tryReceive() orelse return error.TestFailed;
    try std.testing.expectEqual(expected_slot, received_slot);

    // And the ledger should now contain the duplicate slot
    try std.testing.expectEqual(true, ledger.db.contains(schema.duplicate_slots, expected_slot));
}

test "pushDuplicateShredToGossip: enqueues chunks and ring indices" {
    const allocator = std.testing.allocator;

    const keypair: KeyPair = try .generateDeterministic(@splat(1));

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    var gossip_state = try TestGossipState.init(allocator);
    defer gossip_state.deinit();

    const original_shred: Shred = try .fromPayload(allocator, &sig.ledger.shred.test_data_shred);
    defer original_shred.deinit();
    const slot = original_shred.commonHeader().slot;
    const shred_payload = original_shred.payload();

    const other_payload = try allocator.dupe(u8, shred_payload);
    defer allocator.free(other_payload);
    if (other_payload.len > 0) other_payload[other_payload.len - 1] +%= 1;

    var before_len: usize = 0;
    {
        var pqlg = gossip_state.push_msg_queue.lock();
        before_len = pqlg.get().queue.items.len;
        pqlg.unlock();
    }

    const gossip_ctx = gossip_state.context();

    var handler: DuplicateShredHandler = .{
        .ledger_reader = ledger.reader(),
        .result_writer = ledger.resultWriter(),
        .duplicate_slots_sender = null,
        .gossip_context = &gossip_ctx,
        .keypair = &keypair,
        .logger = .noop,
    };
    try handler.pushDuplicateShredToGossip(
        &gossip_ctx,
        slot,
        shred_payload,
        other_payload,
    );

    const proof_bytes = try serializeDuplicateProof(
        allocator,
        shred_payload,
        other_payload,
    );
    defer allocator.free(proof_bytes);
    const chunk_size: usize = DUPLICATE_SHRED_MAX_PAYLOAD_SIZE - DUPLICATE_SHRED_HEADER_SIZE;
    const expected_chunks: usize = (proof_bytes.len + chunk_size - 1) / chunk_size;

    var after_items_len: usize = 0;
    var ring_ok = true;
    var have_dup_entries: usize = 0;
    {
        var pqlg = gossip_state.push_msg_queue.lock();
        defer pqlg.unlock();
        after_items_len = pqlg.get().queue.items.len;

        const start_index = after_items_len - expected_chunks;
        var expect_ring: u16 = 0; // ring_offset should be 0 for empty table
        var i: usize = 0;
        while (i < expected_chunks) : (i += 1) {
            const gd = pqlg.get().queue.items[start_index + i];
            switch (gd) {
                .DuplicateShred => |v| {
                    const ring_index = v[0];
                    const d = v[1];
                    if (ring_index != expect_ring) ring_ok = false;
                    // Basic field checks
                    try std.testing.expectEqual(slot, d.slot);
                    try std.testing.expect(d.chunk_index < d.num_chunks);
                    have_dup_entries += 1;
                    expect_ring +%= 1;
                },
                else => return error.TestFailed,
            }
        }
    }

    try std.testing.expectEqual(expected_chunks, have_dup_entries);
    try std.testing.expect(ring_ok);
    try std.testing.expectEqual(before_len + expected_chunks, after_items_len);
}

test "pushDuplicateShredToGossip: no-op when duplicate for slot exists" {
    const allocator = std.testing.allocator;

    const keypair: KeyPair = try .generateDeterministic(@splat(2));
    const my_pubkey: sig.core.Pubkey = .fromPublicKey(&keypair.public_key);

    var gossip_state = try TestGossipState.init(allocator);
    defer gossip_state.deinit();

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const shred: Shred = try .fromPayload(allocator, &sig.ledger.shred.test_data_shred);
    defer shred.deinit();
    const slot = shred.commonHeader().slot;
    const shred_index = layout.getIndex(&sig.ledger.shred.test_data_shred).?;

    {
        const dup: sig.gossip.data.DuplicateShred = .{
            .from = my_pubkey,
            .wallclock = 1,
            .slot = slot,
            .shred_index = shred_index,
            .shred_type = .Code,
            .num_chunks = 1,
            .chunk_index = 0,
            .chunk = try allocator.dupe(u8, &.{0}),
        };
        errdefer dup.deinit(allocator);
        var lg = gossip_state.gossip_table_rw.write();
        defer lg.unlock();
        _ = try lg.mut().insert(
            .initSigned(&keypair, .{ .DuplicateShred = .{ 0, dup } }),
            0,
        );
    }

    var before_len: usize = 0;
    {
        var pqlg = gossip_state.push_msg_queue.lock();
        before_len = pqlg.get().queue.items.len;
        pqlg.unlock();
    }

    var other = try allocator.dupe(u8, shred.payload());
    defer allocator.free(other);
    if (other.len > 0) other[other.len - 1] +%= 1;

    const gossip_ctx = gossip_state.context();

    var handler: DuplicateShredHandler = .{
        .ledger_reader = ledger.reader(),
        .result_writer = ledger.resultWriter(),
        .duplicate_slots_sender = null,
        .gossip_context = &gossip_ctx,
        .keypair = &keypair,
        .logger = .noop,
    };
    try handler.pushDuplicateShredToGossip(
        &gossip_ctx,
        slot,
        shred.payload(),
        other,
    );

    var after_len: usize = 0;
    {
        var pqlg = gossip_state.push_msg_queue.lock();
        after_len = pqlg.get().queue.items.len;
        pqlg.unlock();
    }
    try std.testing.expectEqual(before_len, after_len);
}

test "computeRingOffset: under capacity and at capacity oldest index" {
    const allocator = std.testing.allocator;

    const keypair: KeyPair = try .generateDeterministic(@splat(3));
    const my_pubkey: sig.core.Pubkey = .fromPublicKey(&keypair.public_key);

    var contact_info =
        try sig.gossip.data.LegacyContactInfo.default(my_pubkey).toContactInfo(allocator);
    try contact_info.setSocket(.gossip, .initIpv4(.{ 127, 0, 0, 1 }, 0));

    const gossip_service = try sig.gossip.GossipService.create(
        allocator,
        allocator,
        contact_info,
        keypair,
        null,
        .noop,
        .{},
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    const insert_dup = struct {
        fn run(
            g: *sig.gossip.GossipService,
            kp: *const KeyPair,
            ring_index: u16,
            wallclock: u64,
            slotarg: Slot,
        ) !void {
            const buf = try g.gossip_data_allocator.dupe(u8, &.{0});
            const signed: sig.gossip.data.SignedGossipData = .initSigned(kp, .{
                .DuplicateShred = .{
                    ring_index, .{
                        .from = .fromPublicKey(&kp.public_key),
                        .wallclock = wallclock,
                        .slot = slotarg,
                        .shred_index = 0,
                        .shred_type = .Code,
                        .num_chunks = 1,
                        .chunk_index = 0,
                        .chunk = buf,
                    },
                },
            });
            errdefer signed.deinit(allocator);
            var lg = g.gossip_table_rw.write();
            defer lg.unlock();
            _ = try lg.mut().insert(signed, wallclock);
        }
    };

    try insert_dup.run(gossip_service, &keypair, 0, 10, 1);
    try insert_dup.run(gossip_service, &keypair, 1, 11, 2);
    try insert_dup.run(gossip_service, &keypair, 2, 12, 3);
    const offset_under = computeRingOffset(&gossip_service.gossip_table_rw, my_pubkey);
    try std.testing.expectEqual(3, offset_under);

    const MAX = sig.gossip.data.MAX_DUPLICATE_SHREDS;
    var i: u16 = 3;
    while (i < MAX) : (i += 1) {
        const wc: u64 = if (i == 5) 1 else 1000 + i;
        try insert_dup.run(gossip_service, &keypair, i, wc, 100 + i);
    }
    const offset_full = computeRingOffset(&gossip_service.gossip_table_rw, my_pubkey);
    try std.testing.expectEqual(5, offset_full);
}
