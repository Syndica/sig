//! Generic producer functions for streaming shreds from an Agave blockstore.
//!
//! These functions are generic over the output ring element type so the same
//! code drives both the IPC service (net.Packet ring) and the standalone CLI
//! tool (StreamPacket ring via UDP).

const std = @import("std");
const lib = @import("lib");
const rocks = @import("rocksdb");
const config = @import("config.zig");
const blockstore_mod = @import("agave_blockstore.zig");
const plan_mod = @import("plan.zig");

const Allocator = std.mem.Allocator;
const Slot = config.Slot;
const Config = config.Config;
const ShredKind = config.ShredKind;
const ShredRef = config.ShredRef;
const RefSchedule = config.RefSchedule;
const SelectedShredPlan = config.SelectedShredPlan;
const SelectedShredAction = config.SelectedShredAction;
const ProducerStats = config.ProducerStats;
const Connection = lib.runner.Connection;

const AgaveBlockstore = blockstore_mod.AgaveBlockstore;

const agave_cf_meta = config.agave_cf_meta;
const parseSlotKey = config.parseSlotKey;
const writeSlotKey = config.writeSlotKey;
const parseShredKey = config.parseShredKey;
const writeShredKey = config.writeShredKey;
const consumeSelectedRefIndex = config.consumeSelectedRefIndex;
const corruptPacketBytes = config.corruptPacketBytes;
const max_shred_packet_bytes = config.max_shred_packet_bytes;
const producer_publish_packets = config.producer_publish_packets;

// Re-exports from plan module
pub const buildSelectedShredPlan = plan_mod.buildSelectedShredPlan;
pub const buildOrderedRefSchedule = plan_mod.buildOrderedRefSchedule;
pub const collectSlotShredRefs = plan_mod.collectSlotShredRefs;

/// Non-throwing cancellation check used in loop conditions and post-loop
/// flush guards. Returns true if the runner has signalled cancellation.
inline fn isCanceled(connection: Connection) bool {
    connection.activity.checkCanceled() catch return true;
    return false;
}

pub fn produceLedgerPackets(
    allocator: Allocator,
    blockstore: *const AgaveBlockstore,
    cfg: Config,
    selected_shreds: ?*const SelectedShredPlan,
    writer: anytype,
    packet_ctx: anytype,
    connection: Connection,
) !ProducerStats {
    return switch (cfg.test_mode) {
        .linear => produceOrderedLedgerPackets(
            blockstore,
            cfg,
            .forward,
            writer,
            packet_ctx,
            connection,
        ),
        .reverse => produceOrderedLedgerPackets(
            blockstore,
            cfg,
            .reverse,
            writer,
            packet_ctx,
            connection,
        ),
        .shuffle_global => produceGlobalShuffledRefSchedule(
            allocator,
            blockstore,
            cfg,
            writer,
            packet_ctx,
            connection,
        ),
        .shuffle_slot => produceSlotShuffledPackets(
            allocator,
            blockstore,
            cfg,
            writer,
            packet_ctx,
            connection,
        ),
        .drop, .late, .duplicate, .corrupt => produceSelectedShredSchedule(
            blockstore,
            selected_shreds.?,
            cfg,
            writer,
            packet_ctx,
            connection,
        ),
    };
}

pub fn produceOrderedLedgerPackets(
    blockstore: *const AgaveBlockstore,
    cfg: Config,
    comptime direction: config.Direction,
    writer: anytype,
    packet_ctx: anytype,
    connection: Connection,
) !ProducerStats {
    var stats: ProducerStats = .{};
    var unpublished_packets: usize = 0;

    var start_key_buf: [8]u8 = undefined;
    const start_key_slot: ?Slot = switch (direction) {
        .forward => cfg.start_slot,
        .reverse => cfg.end_slot,
    };
    const start_key: ?[]const u8 = if (start_key_slot) |slot| start_key: {
        writeSlotKey(&start_key_buf, slot);
        break :start_key start_key_buf[0..];
    } else null;

    const rocks_direction: rocks.IteratorDirection = switch (direction) {
        .forward => .forward,
        .reverse => .reverse,
    };

    var slot_iter = blockstore.db.iterator(
        try blockstore.columnFamily(agave_cf_meta),
        rocks_direction,
        start_key,
    );
    defer slot_iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    while (try slot_iter.next(&err_data)) |entry| {
        if (isCanceled(connection)) break;

        const slot = parseSlotKey(entry[0].data) catch |err| {
            std.log.err("invalid {s} key length: {d}", .{ agave_cf_meta, entry[0].data.len });
            return err;
        };
        if (cfg.pastSlotRange(slot, direction)) break;
        if (!cfg.slotSelected(slot)) continue;

        stats.recordSlot();
        if (direction == .reverse and blockstore.has_code_shred) {
            try produceSlotShreds(
                blockstore,
                slot,
                .code,
                rocks_direction,
                writer,
                packet_ctx,
                connection,
                &unpublished_packets,
                &stats,
            );
        }
        try produceSlotShreds(
            blockstore,
            slot,
            .data,
            rocks_direction,
            writer,
            packet_ctx,
            connection,
            &unpublished_packets,
            &stats,
        );
        if (direction == .forward and blockstore.has_code_shred) {
            try produceSlotShreds(
                blockstore,
                slot,
                .code,
                rocks_direction,
                writer,
                packet_ctx,
                connection,
                &unpublished_packets,
                &stats,
            );
        }
    }

    if (unpublished_packets != 0 and !isCanceled(connection)) {
        writer.markUsed();
    }

    return stats;
}

pub fn produceGlobalShuffledRefSchedule(
    allocator: Allocator,
    blockstore: *const AgaveBlockstore,
    cfg: Config,
    writer: anytype,
    packet_ctx: anytype,
    connection: Connection,
) !ProducerStats {
    var schedule = try buildOrderedRefSchedule(allocator, blockstore, cfg, connection);
    defer schedule.deinit(allocator);

    var prng = std.Random.DefaultPrng.init(cfg.seed.?);
    prng.random().shuffleWithIndex(ShredRef, schedule.refs.items, u64);

    return produceRefSchedule(blockstore, &schedule, &.{}, writer, packet_ctx, connection);
}

pub fn produceSlotShuffledPackets(
    allocator: Allocator,
    blockstore: *const AgaveBlockstore,
    cfg: Config,
    writer: anytype,
    packet_ctx: anytype,
    connection: Connection,
) !ProducerStats {
    var stats: ProducerStats = .{};
    var unpublished_packets: usize = 0;
    var prng = std.Random.DefaultPrng.init(cfg.seed.?);

    var start_key_buf: [8]u8 = undefined;
    const start_key: ?[]const u8 = if (cfg.start_slot) |slot| start_key: {
        writeSlotKey(&start_key_buf, slot);
        break :start_key start_key_buf[0..];
    } else null;

    var slot_iter = blockstore.db.iterator(
        try blockstore.columnFamily(agave_cf_meta),
        .forward,
        start_key,
    );
    defer slot_iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    var refs: std.ArrayList(ShredRef) = .empty;
    defer refs.deinit(allocator);

    while (try slot_iter.next(&err_data)) |entry| {
        if (isCanceled(connection)) break;

        const slot = parseSlotKey(entry[0].data) catch |err| {
            std.log.err("invalid {s} key length: {d}", .{ agave_cf_meta, entry[0].data.len });
            return err;
        };
        if (cfg.pastEndSlot(slot)) break;
        if (!cfg.slotSelected(slot)) continue;

        refs.clearRetainingCapacity();
        try collectSlotShredRefs(allocator, blockstore, slot, .data, &refs, connection);
        if (blockstore.has_code_shred) {
            try collectSlotShredRefs(allocator, blockstore, slot, .code, &refs, connection);
        }

        prng.random().shuffleWithIndex(ShredRef, refs.items, u64);

        stats.recordSlot();

        for (refs.items) |shred_ref| {
            if (isCanceled(connection)) break;
            try produceShredByRef(
                blockstore,
                shred_ref,
                writer,
                packet_ctx,
                connection,
                &unpublished_packets,
                &stats,
            );
        }
    }

    if (unpublished_packets != 0 and !isCanceled(connection)) {
        writer.markUsed();
    }

    return stats;
}

pub fn produceSelectedShredSchedule(
    blockstore: *const AgaveBlockstore,
    selected_shreds: *const SelectedShredPlan,
    cfg: Config,
    writer: anytype,
    packet_ctx: anytype,
    connection: Connection,
) !ProducerStats {
    const refs = selected_shreds.schedule.refs.items;
    const selected_ref_indices = selected_shreds.selected_ref_indices.items;
    const selected_action = SelectedShredAction.fromTestMode(cfg.test_mode);
    var prng = std.Random.DefaultPrng.init(cfg.seed.?);

    var stats: ProducerStats = .{ .slots = selected_shreds.schedule.selected_slots };
    var unpublished_packets: usize = 0;
    var selected_cursor: usize = 0;

    for (refs, 0..) |shred_ref, ref_index| {
        if (isCanceled(connection)) break;

        const is_selected = consumeSelectedRefIndex(
            selected_ref_indices,
            &selected_cursor,
            ref_index,
        );
        if (is_selected and selected_action == .skip) continue;

        if (!is_selected) {
            try produceShredByRef(
                blockstore,
                shred_ref,
                writer,
                packet_ctx,
                connection,
                &unpublished_packets,
                &stats,
            );
            continue;
        }

        switch (selected_action) {
            .skip => unreachable,
            .send_twice => {
                try produceShredByRef(
                    blockstore,
                    shred_ref,
                    writer,
                    packet_ctx,
                    connection,
                    &unpublished_packets,
                    &stats,
                );
                try produceShredByRef(
                    blockstore,
                    shred_ref,
                    writer,
                    packet_ctx,
                    connection,
                    &unpublished_packets,
                    &stats,
                );
            },
            .send_corrupt => try produceCorruptShredByRef(
                blockstore,
                shred_ref,
                cfg.corrupt_bytes,
                prng.random(),
                writer,
                packet_ctx,
                connection,
                &unpublished_packets,
                &stats,
            ),
        }
    }

    if (unpublished_packets != 0 and !isCanceled(connection)) {
        writer.markUsed();
        unpublished_packets = 0;
    }

    if (cfg.test_mode == .late) {
        for (selected_ref_indices) |index| {
            if (isCanceled(connection)) break;
            const shred_ref = refs[index];
            try produceShredByRef(
                blockstore,
                shred_ref,
                writer,
                packet_ctx,
                connection,
                &unpublished_packets,
                &stats,
            );
        }

        if (unpublished_packets != 0 and !isCanceled(connection)) {
            writer.markUsed();
        }
    }

    return stats;
}

pub fn produceRefSchedule(
    blockstore: *const AgaveBlockstore,
    schedule: *const RefSchedule,
    skip_indices: []const usize,
    writer: anytype,
    packet_ctx: anytype,
    connection: Connection,
) !ProducerStats {
    var stats: ProducerStats = .{ .slots = schedule.selected_slots };
    var unpublished_packets: usize = 0;
    var skip_cursor: usize = 0;

    for (schedule.refs.items, 0..) |shred_ref, index| {
        if (isCanceled(connection)) break;
        if (skip_cursor < skip_indices.len and skip_indices[skip_cursor] == index) {
            skip_cursor += 1;
            continue;
        }

        try produceShredByRef(
            blockstore,
            shred_ref,
            writer,
            packet_ctx,
            connection,
            &unpublished_packets,
            &stats,
        );
    }

    if (unpublished_packets != 0 and !isCanceled(connection)) {
        writer.markUsed();
    }

    return stats;
}

pub fn produceSlotShreds(
    blockstore: *const AgaveBlockstore,
    slot: Slot,
    kind: ShredKind,
    comptime direction: rocks.IteratorDirection,
    writer: anytype,
    packet_ctx: anytype,
    connection: Connection,
    unpublished_packets: *usize,
    stats: *ProducerStats,
) !void {
    var start_key_buf: [16]u8 = undefined;
    writeShredKey(&start_key_buf, .{
        .slot = slot,
        .index = switch (direction) {
            .forward => 0,
            .reverse => std.math.maxInt(u64),
        },
    });

    var shred_iter = blockstore.db.iterator(
        try blockstore.columnFamily(kind.columnFamilyName()),
        direction,
        start_key_buf[0..],
    );
    defer shred_iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    while (try shred_iter.next(&err_data)) |entry| {
        if (isCanceled(connection)) break;

        const key = parseShredKey(entry[0].data) catch |err| {
            std.log.err(
                "invalid {s} key length: {d}",
                .{ kind.columnFamilyName(), entry[0].data.len },
            );
            return err;
        };
        if (key.slot != slot) break;
        try publishPacket(
            entry[1].data,
            kind,
            writer,
            packet_ctx,
            connection,
            unpublished_packets,
            stats,
        );
    }
}

pub fn produceShredByRef(
    blockstore: *const AgaveBlockstore,
    shred_ref: ShredRef,
    writer: anytype,
    packet_ctx: anytype,
    connection: Connection,
    unpublished_packets: *usize,
    stats: *ProducerStats,
) !void {
    var key_buf: [16]u8 = undefined;
    writeShredKey(&key_buf, shred_ref.key());

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    const cf = try blockstore.columnFamily(shred_ref.kind.columnFamilyName());
    const packet = try blockstore.db.get(
        cf,
        key_buf[0..],
        &err_data,
    ) orelse return error.MissingShred;
    defer packet.deinit();

    try publishPacket(
        packet.data,
        shred_ref.kind,
        writer,
        packet_ctx,
        connection,
        unpublished_packets,
        stats,
    );
}

pub fn produceCorruptShredByRef(
    blockstore: *const AgaveBlockstore,
    shred_ref: ShredRef,
    corrupt_bytes: usize,
    random: std.Random,
    writer: anytype,
    packet_ctx: anytype,
    connection: Connection,
    unpublished_packets: *usize,
    stats: *ProducerStats,
) !void {
    var key_buf: [16]u8 = undefined;
    writeShredKey(&key_buf, shred_ref.key());

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    const cf = try blockstore.columnFamily(shred_ref.kind.columnFamilyName());
    const packet = try blockstore.db.get(
        cf,
        key_buf[0..],
        &err_data,
    ) orelse return error.MissingShred;
    defer packet.deinit();

    if (packet.data.len > max_shred_packet_bytes) return error.ShredPacketTooLarge;

    var corrupt_packet: [max_shred_packet_bytes]u8 = undefined;
    const corrupt_data = corrupt_packet[0..packet.data.len];
    @memcpy(corrupt_data, packet.data);
    try corruptPacketBytes(corrupt_data, corrupt_bytes, random);

    try publishPacket(
        corrupt_data,
        shred_ref.kind,
        writer,
        packet_ctx,
        connection,
        unpublished_packets,
        stats,
    );
}

/// Core packet publishing function — generic over the ring writer type.
///
/// `writer` must support `.peek()`, `.next()`, `.markUsed()`.
/// `packet_ctx` must support `.acquirePacketSlot(writer, unpublished_packets)`
/// which returns a pointer to the ring element, and `.fillPacket(element, data)`.
/// The `connection` parameter is accepted for signature symmetry but is not
/// used here — `acquirePacketSlot` is responsible for cooperative cancellation.
pub fn publishPacket(
    packet_data: []const u8,
    kind: ShredKind,
    writer: anytype,
    packet_ctx: anytype,
    _: Connection,
    unpublished_packets: *usize,
    stats: *ProducerStats,
) !void {
    if (packet_data.len > max_shred_packet_bytes) return error.ShredPacketTooLarge;

    const Ctx = @TypeOf(packet_ctx.*);
    const out = try Ctx.acquirePacketSlot(
        packet_ctx,
        writer,
        unpublished_packets,
    );

    Ctx.fillPacket(out, packet_data);

    _ = writer.next();
    stats.recordPacket(kind, packet_data.len);
    unpublished_packets.* += 1;

    if (unpublished_packets.* == producer_publish_packets) {
        writer.markUsed();
        unpublished_packets.* = 0;
    }
}
