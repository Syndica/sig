const std = @import("std");
const std14 = @import("std14");
const sig = @import("../../sig.zig");

const bincode = sig.bincode;
const layout = sig.ledger.shred.layout;

const Allocator = std.mem.Allocator;
const KeyPair = sig.identity.KeyPair;

const Channel = sig.sync.Channel;
const ShredInserter = sig.ledger.ShredInserter;
const Slot = sig.core.Slot;

const Logger = sig.trace.Logger("duplicate_shred_handler");

pub const DUPLICATE_SHRED_HEADER_SIZE: usize = 63;
pub const DUPLICATE_SHRED_MAX_PAYLOAD_SIZE: u16 = 512;

const GossipData = sig.gossip.data.GossipData;

const MAX_DUPLICATE_SHREDS: usize = sig.gossip.data.MAX_DUPLICATE_SHREDS;

pub const DuplicateShredHandler = struct {
    ledger_reader: sig.ledger.Reader,
    result_writer: sig.ledger.ResultWriter,
    epoch_tracker: ?*const sig.core.EpochTracker,
    duplicate_slots_sender: ?*Channel(Slot),
    push_msg_queue_mux: ?*sig.gossip.GossipService.PushMessageQueue,
    keypair: *const KeyPair,
    logger: Logger,

    /// Tracks slots for which this handler has already pushed a duplicate proof to gossip.
    slots_pushed_to_gossip: std14.BoundedArray(Slot, MAX_DUPLICATE_SHREDS) = .{},

    /// Ring index used as part of the gossip table label for duplicate shred entries.
    ring_index: u16 = 0,

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

                    const chained_merkle_conflict_duplicate_proofs: bool = feature: {
                        const epoch_tracker = self.epoch_tracker orelse break :feature false;
                        const root_slot = epoch_tracker.root_slot.load(.monotonic);
                        const root_epoch = epoch_tracker.epoch_schedule.getEpoch(root_slot);
                        const epoch_info = epoch_tracker.rooted_epochs.get(root_epoch) catch
                            break :feature false;
                        const feature_slot = epoch_info.feature_set.get(
                            .chained_merkle_conflict_duplicate_proofs,
                        ) orelse break :feature false;
                        const feat_epoch = epoch_tracker.epoch_schedule.getEpoch(feature_slot);
                        const shred_epoch = epoch_tracker.epoch_schedule.getEpoch(shred_slot);
                        break :feature feat_epoch < shred_epoch;
                    };
                    if (!chained_merkle_conflict_duplicate_proofs) continue;

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
        if (self.push_msg_queue_mux) |push_msg_queue_mux| {
            var push_queue, var lock = push_msg_queue_mux.writeWithLock();
            defer lock.unlock();

            self.pushDuplicateShredToGossip(
                push_queue.data_allocator,
                &push_queue.queue,
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
        allocator: std.mem.Allocator,
        push_msg_queue: *std.ArrayList(GossipData),
        slot: Slot,
        shred_payload: []const u8,
        other_payload: []const u8,
    ) !void {
        // Early return if we already pushed a duplicate for this slot to gossip.
        if (self.isSlotPushedToGossip(slot)) {
            return;
        }

        // Serialize duplicate slot proof.
        const proof_bytes = try serializeDuplicateProof(allocator, shred_payload, other_payload);
        defer allocator.free(proof_bytes);

        // Build chunks that will be converted to CRDS.
        const chunks = try self.buildDuplicateShredChunks(
            allocator,
            slot,
            shred_payload,
            proof_bytes,
            DUPLICATE_SHRED_MAX_PAYLOAD_SIZE,
        );
        defer {
            for (chunks) |dup| allocator.free(dup.chunk);
            allocator.free(chunks);
        }

        try enqueueDuplicateShredCrdsValues(
            allocator,
            push_msg_queue,
            self.ring_index,
            chunks,
        );

        // Update ring index for next push to gossip
        self.ring_index =
            (self.ring_index + @as(u16, @intCast(chunks.len))) % @as(
                u16,
                @intCast(MAX_DUPLICATE_SHREDS),
            );

        try self.recordSlotPushedToGossip(slot);
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

        const shred_variant = layout.getShredVariant(shred_payload) orelse return error.InvalidShred;
        const shred_type = shred_variant.shred_type;

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

    fn isSlotPushedToGossip(self: *DuplicateShredHandler, slot: Slot) bool {
        for (self.slots_pushed_to_gossip.constSlice()) |pushed_slot| {
            if (pushed_slot == slot) return true;
        }
        return false;
    }

    fn recordSlotPushedToGossip(self: *DuplicateShredHandler, slot: Slot) !void {
        // If at capacity, remove the oldest entry
        if (self.slots_pushed_to_gossip.len == MAX_DUPLICATE_SHREDS) {
            _ = self.slots_pushed_to_gossip.orderedRemove(0);
        }
        try self.slots_pushed_to_gossip.append(slot);
    }
};

pub fn serializeDuplicateProof(
    allocator: std.mem.Allocator,
    shred_payload: []const u8,
    other_payload: []const u8,
) ![]const u8 {
    // TODO validate the shreds. Implement check_shreds in Agave
    // https://github.com/Syndica/sig/issues/1225
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
    allocator: Allocator,
    push_queue: *std.ArrayList(GossipData),
    ring_offset: u16,
    chunks: []const sig.gossip.data.DuplicateShred,
) !void {
    for (chunks, 0..) |duplicate_shred, i| {
        const ring_index: u16 =
            (ring_offset + @as(u16, @intCast(i))) % @as(u16, @intCast(MAX_DUPLICATE_SHREDS));
        const chunk_copy = try allocator.dupe(u8, duplicate_shred.chunk);
        errdefer allocator.free(chunk_copy);

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

        try push_queue.append(.{
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
        .epoch_tracker = null,
        .duplicate_slots_sender = null, // No sender configured
        .push_msg_queue_mux = null,
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
        .epoch_tracker = null,
        .duplicate_slots_sender = &duplicate_slots_channel,
        .push_msg_queue_mux = null,
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
        .epoch_tracker = null,
        .duplicate_slots_sender = &duplicate_slots_channel,
        .push_msg_queue_mux = null,
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
        .epoch_tracker = null,
        .duplicate_slots_sender = &duplicate_slots_channel,
        .push_msg_queue_mux = null,
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
        errdefer duplicate_shred2.deinit();

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
        .epoch_tracker = null,
        .duplicate_slots_sender = &duplicate_slots_channel,
        .push_msg_queue_mux = null,
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
        .epoch_tracker = null,
        .duplicate_slots_sender = &duplicate_slots_channel,
        .push_msg_queue_mux = null,
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

    var handler: DuplicateShredHandler = .{
        .ledger_reader = ledger.reader(),
        .result_writer = ledger.resultWriter(),
        .epoch_tracker = null,
        .duplicate_slots_sender = null,
        .push_msg_queue_mux = &gossip_state.push_msg_queue,
        .keypair = &keypair,
        .logger = .noop,
    };
    {
        var push_queue, var lock = gossip_state.push_msg_queue.writeWithLock();
        defer lock.unlock();
        try handler.pushDuplicateShredToGossip(
            push_queue.data_allocator,
            &push_queue.queue,
            slot,
            shred_payload,
            other_payload,
        );
    }

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

    var gossip_state = try TestGossipState.init(allocator);
    defer gossip_state.deinit();

    var ledger = try sig.ledger.tests.initTestLedger(allocator, @src(), .FOR_TESTS);
    defer ledger.deinit();

    const shred: Shred = try .fromPayload(allocator, &sig.ledger.shred.test_data_shred);
    defer shred.deinit();
    const slot = shred.commonHeader().slot;

    var before_len: usize = 0;
    {
        var pqlg = gossip_state.push_msg_queue.lock();
        before_len = pqlg.get().queue.items.len;
        pqlg.unlock();
    }

    var other = try allocator.dupe(u8, shred.payload());
    defer allocator.free(other);
    if (other.len > 0) other[other.len - 1] +%= 1;

    var handler: DuplicateShredHandler = .{
        .ledger_reader = ledger.reader(),
        .result_writer = ledger.resultWriter(),
        .epoch_tracker = null,
        .duplicate_slots_sender = null,
        .push_msg_queue_mux = &gossip_state.push_msg_queue,
        .keypair = &keypair,
        .logger = .noop,
    };
    {
        var push_queue, var lock = gossip_state.push_msg_queue.writeWithLock();
        defer lock.unlock();
        try handler.pushDuplicateShredToGossip(
            push_queue.data_allocator,
            &push_queue.queue,
            slot,
            shred.payload(),
            other,
        );
    }

    var after_first_len: usize = 0;
    {
        var pqlg = gossip_state.push_msg_queue.lock();
        after_first_len = pqlg.get().queue.items.len;
        pqlg.unlock();
    }

    {
        var push_queue, var lock = gossip_state.push_msg_queue.writeWithLock();
        defer lock.unlock();
        try handler.pushDuplicateShredToGossip(
            push_queue.data_allocator,
            &push_queue.queue,
            slot,
            shred.payload(),
            other,
        );
    }

    var after_second_len: usize = 0;
    {
        var pqlg = gossip_state.push_msg_queue.lock();
        after_second_len = pqlg.get().queue.items.len;
        pqlg.unlock();
    }

    try std.testing.expectEqual(before_len + (after_first_len - before_len), after_first_len);
    try std.testing.expectEqual(after_first_len, after_second_len);
}
