//! Streams raw shreds from an Agave ledger (RocksDB) directly into shared
//! memory, bypassing the network. This replaces the `net` service in offline
//! test topologies, feeding shred packets to `shred_receiver` via the same
//! `net.Pair.recv` ring buffer that the net service would normally write to.

const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tracy = @import("tracy");
const services = @import("services");
const rocks = @import("rocksdb");
const rocks_c = @import("rocksdb-c");

comptime {
    _ = start;
}

pub const name = .shred_streamer;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadWrite = services.shred_streamer.ReadWrite;
pub const ReadOnly = services.shred_streamer.ReadOnly;

const Packet = lib.net.Packet;
const StreamerConfig = lib.shred.StreamerConfig;
const TestMode = StreamerConfig.TestMode;
const ShredKindFilter = StreamerConfig.ShredKindFilter;
const Slot = u64;

const agave_cf_default = "default";
const agave_cf_meta = "meta";
const agave_cf_data_shred = "data_shred";
const agave_cf_code_shred = "code_shred";
const publish_batch_size: usize = 32;

var scratch_memory: [1024 * 1024 * 1024]u8 = undefined;

pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
    const zone = tracy.Zone.init(@src(), .{ .name = @tagName(name) });
    defer zone.deinit();

    var fba: std.heap.FixedBufferAllocator = .init(&scratch_memory);
    const allocator = fba.allocator();

    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    const config = ro.config;
    logger.info().logf("Opening ledger at: {s}", .{config.ledgerPath()});

    var blockstore = AgaveBlockstore.open(allocator, config.ledgerPath()) catch |err| {
        logger.err().logf("Failed to open blockstore: {}", .{err});
        return err;
    };
    defer blockstore.deinit(allocator);

    logger.info().logf("Blockstore opened, has_code_shred={}", .{blockstore.has_code_shred});

    var packet_writer = rw.tvu_socket.recv.get(.writer);

    switch (config.test_mode) {
        .linear => try streamOrdered(
            &blockstore,
            config,
            .forward,
            &packet_writer,
            runner,
            logger,
        ),
        .reverse => try streamOrdered(
            &blockstore,
            config,
            .reverse,
            &packet_writer,
            runner,
            logger,
        ),
        .shuffle_global => try streamShuffledGlobal(
            allocator,
            &blockstore,
            config,
            &packet_writer,
            runner,
            logger,
        ),
        .shuffle_slot => try streamShuffledSlot(
            allocator,
            &blockstore,
            config,
            &packet_writer,
            runner,
            logger,
        ),
        .drop, .late, .duplicate, .corrupt => try streamWithSelectedShreds(
            allocator,
            &blockstore,
            config,
            &packet_writer,
            runner,
            logger,
        ),
    }

    logger.info().logf("Ledger streaming complete, idling", .{});

    // Service must be !noreturn — idle until topology shuts down.
    while (true) {
        try runner.activity.signalIdleSpinning();
    }
}

// -- Streaming modes --------------------------------------------------------

fn streamOrdered(
    blockstore: *const AgaveBlockstore,
    config: *const StreamerConfig,
    comptime direction: rocks.IteratorDirection,
    writer: *lib.net.Pair.PacketRing.Iterator(.writer),
    runner: lib.runner.Connection,
    logger: anytype,
) !void {
    var start_key_buf: [8]u8 = undefined;
    const start_key_slot = switch (direction) {
        .forward => config.startSlot(),
        .reverse => config.endSlot(),
    };
    const start_key: ?[]const u8 = if (start_key_slot) |slot| blk: {
        writeSlotKey(&start_key_buf, slot);
        break :blk start_key_buf[0..];
    } else null;

    var slot_iter = blockstore.db.iterator(
        try blockstore.columnFamily(agave_cf_meta),
        direction,
        start_key,
    );
    defer slot_iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    var slots_streamed: u64 = 0;
    var packets_streamed: u64 = 0;

    while (try slot_iter.next(&err_data)) |entry| {
        try runner.activity.checkCanceled();

        const slot = parseSlotKey(entry[0].data) catch continue;
        if (pastSlotRange(config, slot, direction)) break;
        if (!slotSelected(config, slot)) continue;

        slots_streamed += 1;
        if (direction == .reverse and blockstore.has_code_shred) {
            packets_streamed += try streamSlotShreds(
                blockstore, slot, .code, direction, writer, runner, config,
            );
        }
        packets_streamed += try streamSlotShreds(
            blockstore, slot, .data, direction, writer, runner, config,
        );
        if (direction == .forward and blockstore.has_code_shred) {
            packets_streamed += try streamSlotShreds(
                blockstore, slot, .code, direction, writer, runner, config,
            );
        }

        if (slots_streamed % 100 == 0) {
            logger.info().logf("Streamed {d} slots, {d} packets (current slot: {d})", .{
                slots_streamed, packets_streamed, slot,
            });
        }
    }

    logger.info().logf("Finished: {d} slots, {d} packets", .{ slots_streamed, packets_streamed });
}

fn streamShuffledGlobal(
    allocator: std.mem.Allocator,
    blockstore: *const AgaveBlockstore,
    config: *const StreamerConfig,
    writer: *lib.net.Pair.PacketRing.Iterator(.writer),
    runner: lib.runner.Connection,
    logger: anytype,
) !void {
    var refs = try collectAllRefs(allocator, blockstore, config, runner);
    defer refs.deinit(allocator);

    var prng = std.Random.DefaultPrng.init(config.getSeed().?);
    prng.random().shuffleWithIndex(ShredRef, refs.items, u64);

    try streamRefs(blockstore, refs.items, writer, runner, config, logger);
}

fn streamShuffledSlot(
    allocator: std.mem.Allocator,
    blockstore: *const AgaveBlockstore,
    config: *const StreamerConfig,
    writer: *lib.net.Pair.PacketRing.Iterator(.writer),
    runner: lib.runner.Connection,
    logger: anytype,
) !void {
    var prng = std.Random.DefaultPrng.init(config.getSeed().?);

    var start_key_buf: [8]u8 = undefined;
    const start_key: ?[]const u8 = if (config.startSlot()) |slot| blk: {
        writeSlotKey(&start_key_buf, slot);
        break :blk start_key_buf[0..];
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

    var slots_streamed: u64 = 0;
    var packets_streamed: u64 = 0;

    while (try slot_iter.next(&err_data)) |entry| {
        try runner.activity.checkCanceled();

        const slot = parseSlotKey(entry[0].data) catch continue;
        if (pastEndSlot(config, slot)) break;
        if (!slotSelected(config, slot)) continue;

        refs.clearRetainingCapacity();
        try collectSlotShredRefs(allocator, blockstore, slot, .data, &refs, runner);
        if (blockstore.has_code_shred) {
            try collectSlotShredRefs(allocator, blockstore, slot, .code, &refs, runner);
        }

        prng.random().shuffleWithIndex(ShredRef, refs.items, u64);

        for (refs.items) |ref| {
            try publishShredByRef(blockstore, ref, writer, runner, config);
            packets_streamed += 1;
        }

        slots_streamed += 1;
        if (slots_streamed % 100 == 0) {
            logger.info().logf("Streamed {d} slots, {d} packets (current slot: {d})", .{
                slots_streamed, packets_streamed, slot,
            });
        }
    }

    logger.info().logf("Finished: {d} slots, {d} packets", .{ slots_streamed, packets_streamed });
}

fn streamWithSelectedShreds(
    allocator: std.mem.Allocator,
    blockstore: *const AgaveBlockstore,
    config: *const StreamerConfig,
    writer: *lib.net.Pair.PacketRing.Iterator(.writer),
    runner: lib.runner.Connection,
    logger: anytype,
) !void {
    var refs = try collectAllRefs(allocator, blockstore, config, runner);
    defer refs.deinit(allocator);

    var selected_indices = try chooseSelectedIndices(
        allocator,
        refs.items,
        config.shred_kind,
        config.selected_count,
        config.getSeed().?,
    );
    defer selected_indices.deinit(allocator);

    var prng = std.Random.DefaultPrng.init(config.getSeed().?);
    var selected_cursor: usize = 0;
    var packets_streamed: u64 = 0;

    for (refs.items, 0..) |ref, ref_index| {
        try runner.activity.checkCanceled();

        const is_selected = isSelectedIndex(selected_indices.items, &selected_cursor, ref_index);

        switch (config.test_mode) {
            .drop => {
                if (is_selected) continue;
                try publishShredByRef(blockstore, ref, writer, runner, config);
                packets_streamed += 1;
            },
            .late => {
                if (is_selected) continue;
                try publishShredByRef(blockstore, ref, writer, runner, config);
                packets_streamed += 1;
            },
            .duplicate => {
                try publishShredByRef(blockstore, ref, writer, runner, config);
                packets_streamed += 1;
                if (is_selected) {
                    try publishShredByRef(blockstore, ref, writer, runner, config);
                    packets_streamed += 1;
                }
            },
            .corrupt => {
                if (is_selected) {
                    try publishCorruptShredByRef(
                        blockstore, ref, config.corrupt_bytes, prng.random(),
                        writer, runner, config,
                    );
                } else {
                    try publishShredByRef(blockstore, ref, writer, runner, config);
                }
                packets_streamed += 1;
            },
            else => unreachable,
        }
    }

    // For .late mode, send the skipped shreds at the end
    if (config.test_mode == .late) {
        selected_cursor = 0;
        for (selected_indices.items) |index| {
            try runner.activity.checkCanceled();
            try publishShredByRef(blockstore, refs.items[index], writer, runner, config);
            packets_streamed += 1;
        }
    }

    logger.info().logf("Finished with test_mode, {d} packets", .{packets_streamed});
}

fn streamRefs(
    blockstore: *const AgaveBlockstore,
    refs: []const ShredRef,
    writer: *lib.net.Pair.PacketRing.Iterator(.writer),
    runner: lib.runner.Connection,
    config: *const StreamerConfig,
    logger: anytype,
) !void {
    var packets_streamed: u64 = 0;
    for (refs) |ref| {
        try runner.activity.checkCanceled();
        try publishShredByRef(blockstore, ref, writer, runner, config);
        packets_streamed += 1;
    }
    logger.info().logf("Finished: {d} packets", .{packets_streamed});
}

// -- Packet publishing ------------------------------------------------------

fn publishShredByRef(
    blockstore: *const AgaveBlockstore,
    ref: ShredRef,
    writer: *lib.net.Pair.PacketRing.Iterator(.writer),
    runner: lib.runner.Connection,
    config: *const StreamerConfig,
) !void {
    var key_buf: [16]u8 = undefined;
    writeShredKey(&key_buf, ref.key());

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    const cf = try blockstore.columnFamily(ref.kind.columnFamilyName());
    const value = try blockstore.db.get(cf, key_buf[0..], &err_data) orelse return;
    defer value.deinit();

    if (value.data.len > Packet.capacity) return;

    try writePacket(writer, value.data, runner, config);
}

fn publishCorruptShredByRef(
    blockstore: *const AgaveBlockstore,
    ref: ShredRef,
    corrupt_bytes: u32,
    random: std.Random,
    writer: *lib.net.Pair.PacketRing.Iterator(.writer),
    runner: lib.runner.Connection,
    config: *const StreamerConfig,
) !void {
    var key_buf: [16]u8 = undefined;
    writeShredKey(&key_buf, ref.key());

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    const cf = try blockstore.columnFamily(ref.kind.columnFamilyName());
    const value = try blockstore.db.get(cf, key_buf[0..], &err_data) orelse return;
    defer value.deinit();

    if (value.data.len > Packet.capacity) return;

    var corrupt_data: [Packet.capacity]u8 = undefined;
    const data = corrupt_data[0..value.data.len];
    @memcpy(data, value.data);

    const byte_count = @min(corrupt_bytes, @as(u32, @intCast(data.len)));
    for (0..byte_count) |_| {
        const idx = random.uintLessThan(usize, data.len);
        const bit: u3 = @intCast(random.uintLessThan(u8, 8));
        data[idx] ^= @as(u8, 1) << bit;
    }

    try writePacket(writer, data, runner, config);
}

fn writePacket(
    writer: *lib.net.Pair.PacketRing.Iterator(.writer),
    payload: []const u8,
    runner: lib.runner.Connection,
    config: *const StreamerConfig,
) !void {
    // Rate limiting
    if (config.rateHz()) |rate| {
        const interval_ns: u64 = @max(1, @as(u64, @intFromFloat(
            @ceil(@as(f64, @floatFromInt(std.time.ns_per_s)) / rate),
        )));
        std.Thread.sleep(interval_ns);
    }

    // Wait for ring slot to be available
    while (writer.peek() == null) {
        try runner.activity.signalIdleSpinning();
    }

    const slot = writer.next().?;
    @memcpy(slot.data[0..payload.len], payload);
    slot.len = @intCast(payload.len);
    slot.addr = std.mem.zeroes(std.net.Address);
    writer.markUsed();
}

// -- Slot/shred iteration ---------------------------------------------------

fn streamSlotShreds(
    blockstore: *const AgaveBlockstore,
    slot: Slot,
    kind: ShredKind,
    comptime direction: rocks.IteratorDirection,
    writer: *lib.net.Pair.PacketRing.Iterator(.writer),
    runner: lib.runner.Connection,
    config: *const StreamerConfig,
) !u64 {
    var start_key_buf: [16]u8 = undefined;
    const start_index: u64 = switch (direction) {
        .forward => 0,
        .reverse => std.math.maxInt(u64),
    };
    writeShredKey(&start_key_buf, .{ .slot = slot, .index = start_index });

    var iter = blockstore.db.iterator(
        try blockstore.columnFamily(kind.columnFamilyName()),
        direction,
        start_key_buf[0..],
    );
    defer iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    var count: u64 = 0;
    while (try iter.next(&err_data)) |entry| {
        try runner.activity.checkCanceled();

        const key = parseShredKey(entry[0].data) catch continue;
        if (key.slot != slot) break;

        const payload = entry[1].data;
        if (payload.len > Packet.capacity) continue;

        try writePacket(writer, payload, runner, config);
        count += 1;
    }
    return count;
}

fn collectAllRefs(
    allocator: std.mem.Allocator,
    blockstore: *const AgaveBlockstore,
    config: *const StreamerConfig,
    runner: lib.runner.Connection,
) !std.ArrayList(ShredRef) {
    var refs: std.ArrayList(ShredRef) = .empty;
    errdefer refs.deinit(allocator);

    var start_key_buf: [8]u8 = undefined;
    const start_key: ?[]const u8 = if (config.startSlot()) |slot| blk: {
        writeSlotKey(&start_key_buf, slot);
        break :blk start_key_buf[0..];
    } else null;

    var slot_iter = blockstore.db.iterator(
        try blockstore.columnFamily(agave_cf_meta),
        .forward,
        start_key,
    );
    defer slot_iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    while (try slot_iter.next(&err_data)) |entry| {
        try runner.activity.checkCanceled();

        const slot = parseSlotKey(entry[0].data) catch continue;
        if (pastEndSlot(config, slot)) break;
        if (!slotSelected(config, slot)) continue;

        try collectSlotShredRefs(allocator, blockstore, slot, .data, &refs, runner);
        if (blockstore.has_code_shred) {
            try collectSlotShredRefs(allocator, blockstore, slot, .code, &refs, runner);
        }
    }

    return refs;
}

fn collectSlotShredRefs(
    allocator: std.mem.Allocator,
    blockstore: *const AgaveBlockstore,
    slot: Slot,
    kind: ShredKind,
    refs: *std.ArrayList(ShredRef),
    runner: lib.runner.Connection,
) !void {
    var start_key_buf: [16]u8 = undefined;
    writeShredKey(&start_key_buf, .{ .slot = slot, .index = 0 });

    var iter = blockstore.db.iterator(
        try blockstore.columnFamily(kind.columnFamilyName()),
        .forward,
        start_key_buf[0..],
    );
    defer iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    while (try iter.next(&err_data)) |entry| {
        try runner.activity.checkCanceled();

        const key = parseShredKey(entry[0].data) catch continue;
        if (key.slot != slot) break;
        try refs.append(allocator, .{ .slot = key.slot, .index = key.index, .kind = kind });
    }
}

fn chooseSelectedIndices(
    allocator: std.mem.Allocator,
    refs: []const ShredRef,
    shred_kind: ShredKindFilter,
    count: u32,
    seed: u64,
) !std.ArrayList(usize) {
    var candidates: std.ArrayList(usize) = .empty;
    errdefer candidates.deinit(allocator);

    for (refs, 0..) |ref, i| {
        const matches = switch (shred_kind) {
            .any => true,
            .data => ref.kind == .data,
            .code => ref.kind == .code,
        };
        if (matches) try candidates.append(allocator, i);
    }

    const actual_count = @min(count, @as(u32, @intCast(candidates.items.len)));
    var prng = std.Random.DefaultPrng.init(seed);
    prng.random().shuffleWithIndex(usize, candidates.items, u64);
    candidates.shrinkRetainingCapacity(actual_count);
    std.mem.sortUnstable(usize, candidates.items, {}, std.sort.asc(usize));
    return candidates;
}

fn isSelectedIndex(indices: []const usize, cursor: *usize, ref_index: usize) bool {
    if (cursor.* >= indices.len) return false;
    if (indices[cursor.*] != ref_index) return false;
    cursor.* += 1;
    return true;
}

// -- Slot/shred key helpers -------------------------------------------------

const ShredKey = struct {
    slot: Slot,
    index: u64,
};

const ShredKind = enum(u8) {
    data,
    code,

    fn columnFamilyName(kind: ShredKind) []const u8 {
        return switch (kind) {
            .data => agave_cf_data_shred,
            .code => agave_cf_code_shred,
        };
    }
};

const ShredRef = struct {
    slot: Slot,
    index: u64,
    kind: ShredKind,

    fn key(self: ShredRef) ShredKey {
        return .{ .slot = self.slot, .index = self.index };
    }
};

fn slotSelected(config: *const StreamerConfig, slot: Slot) bool {
    if (config.startSlot()) |s| {
        if (slot < s) return false;
    }
    return !pastEndSlot(config, slot);
}

fn pastEndSlot(config: *const StreamerConfig, slot: Slot) bool {
    return if (config.endSlot()) |end| slot > end else false;
}

fn pastSlotRange(
    config: *const StreamerConfig,
    slot: Slot,
    comptime direction: rocks.IteratorDirection,
) bool {
    return switch (direction) {
        .forward => pastEndSlot(config, slot),
        .reverse => if (config.startSlot()) |s| slot < s else false,
    };
}

fn writeSlotKey(buf: *[8]u8, slot: Slot) void {
    std.mem.writeInt(u64, buf, slot, .big);
}

fn parseSlotKey(data: []const u8) !Slot {
    if (data.len != 8) return error.InvalidKeyLength;
    return std.mem.readInt(u64, data[0..8], .big);
}

fn writeShredKey(buf: *[16]u8, key: ShredKey) void {
    std.mem.writeInt(u64, buf[0..8], key.slot, .big);
    std.mem.writeInt(u64, buf[8..16], key.index, .big);
}

fn parseShredKey(data: []const u8) !ShredKey {
    if (data.len != 16) return error.InvalidKeyLength;
    return .{
        .slot = std.mem.readInt(u64, data[0..8], .big),
        .index = std.mem.readInt(u64, data[8..16], .big),
    };
}

// -- Agave blockstore (RocksDB) wrapper -------------------------------------

const AgaveBlockstore = struct {
    rocksdb_path: []const u8,
    db: rocks.DB,
    column_families: []const rocks.ColumnFamily,
    has_code_shred: bool,

    fn open(allocator: std.mem.Allocator, ledger_path: []const u8) !AgaveBlockstore {
        const rocksdb_path = try std.fmt.allocPrint(allocator, "{s}/rocksdb", .{ledger_path});
        errdefer allocator.free(rocksdb_path);

        // List column families using the raw C API
        const rocksdb_path_z = try allocator.dupeZ(u8, rocksdb_path);
        defer allocator.free(rocksdb_path_z);

        const options = rocks_c.rocksdb_options_create() orelse return error.RocksDBOptionsCreate;
        defer rocks_c.rocksdb_options_destroy(options);

        var err_ptr: ?[*:0]u8 = null;
        var cf_count: usize = 0;
        const raw_cf_names = rocks_c.rocksdb_list_column_families(
            options,
            rocksdb_path_z.ptr,
            &cf_count,
            @ptrCast(&err_ptr),
        );
        if (err_ptr) |err_z| {
            defer rocks_c.rocksdb_free(err_z);
            std.log.err("failed to list column families: {s}", .{std.mem.span(err_z)});
            return error.RocksDBListColumnFamilies;
        }
        if (raw_cf_names == null) return error.RocksDBListColumnFamilies;
        defer rocks_c.rocksdb_list_column_families_destroy(raw_cf_names, cf_count);

        // Check for required/optional column families
        var has_code_shred = false;
        var has_default = false;
        var has_meta = false;
        var has_data_shred = false;
        for (raw_cf_names[0..cf_count]) |raw_name| {
            const cf_name = std.mem.span(raw_name);
            if (std.mem.eql(u8, cf_name, agave_cf_default)) has_default = true;
            if (std.mem.eql(u8, cf_name, agave_cf_meta)) has_meta = true;
            if (std.mem.eql(u8, cf_name, agave_cf_data_shred)) has_data_shred = true;
            if (std.mem.eql(u8, cf_name, agave_cf_code_shred)) has_code_shred = true;
        }
        if (!has_default or !has_meta or !has_data_shred) return error.MissingColumnFamily;

        // Build column family descriptions for opening
        const cf_desc_count: usize = if (has_code_shred) 4 else 3;
        const cfs = try allocator.alloc(rocks.ColumnFamilyDescription, cf_desc_count);
        defer allocator.free(cfs);
        cfs[0] = .{ .name = agave_cf_default };
        cfs[1] = .{ .name = agave_cf_meta };
        cfs[2] = .{ .name = agave_cf_data_shred };
        if (has_code_shred) cfs[3] = .{ .name = agave_cf_code_shred };

        var open_err: ?rocks.Data = null;
        defer if (open_err) |err| err.deinit();

        var db, const opened_cfs = rocks.DB.open(
            allocator,
            rocksdb_path_z,
            .{},
            cfs,
            true,
            &open_err,
        ) catch |err| {
            if (open_err) |rocks_err| {
                std.log.err("failed to open RocksDB at {s}: {s}", .{ rocksdb_path, rocks_err.data });
            }
            return err;
        };
        errdefer db.deinit();
        errdefer allocator.free(opened_cfs);

        return .{
            .rocksdb_path = rocksdb_path,
            .db = db,
            .column_families = opened_cfs,
            .has_code_shred = has_code_shred,
        };
    }

    fn deinit(self: *AgaveBlockstore, allocator: std.mem.Allocator) void {
        allocator.free(self.column_families);
        self.db.deinit();
        allocator.free(self.rocksdb_path);
    }

    fn columnFamily(self: *const AgaveBlockstore, cf_name: []const u8) !rocks.ColumnFamilyHandle {
        for (self.column_families) |cf| {
            if (std.mem.eql(u8, cf.name, cf_name)) return cf.handle;
        }
        return error.MissingColumnFamily;
    }
};
