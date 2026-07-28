//! Streams raw shreds from an Agave ledger to a UDP target.
//!
//! Producer and plan-building logic lives in the shared `shred_stream` lib
//! module, which is also used by the in-topology `shred_streamer` service.
//! The CLI supplies its own transport (StreamPacket → UDP) via a small
//! `CliPacketContext` and a stack-allocated `lib.runner.Activity` for
//! cancellation.

const std = @import("std");
const lib = @import("lib");
const Ring = lib.ipc.Ring;
const shred_stream = @import("shred_stream");

const Allocator = std.mem.Allocator;

// --- Type aliases from the shred_stream lib module ---
const Slot = shred_stream.config.Slot;
const TestMode = shred_stream.config.TestMode;
const ShredKind = shred_stream.config.ShredKind;
const Config = shred_stream.Config;
const ShredKey = shred_stream.config.ShredKey;
const SelectedShredPlan = shred_stream.config.SelectedShredPlan;
const ProducerStats = shred_stream.config.ProducerStats;
const ProducerProgress = shred_stream.config.ProducerProgress;
const SlotStats = shred_stream.config.SlotStats;
const ShredStats = shred_stream.config.ShredStats;
const LedgerStats = shred_stream.config.LedgerStats;
const AgaveBlockstore = shred_stream.AgaveBlockstore;

const parseSlotKey = shred_stream.config.parseSlotKey;
const writeSlotKey = shred_stream.config.writeSlotKey;
const parseShredKey = shred_stream.config.parseShredKey;
const writeShredKey = shred_stream.config.writeShredKey;
const parseArgs = shred_stream.parseArgs;
const printHelp = shred_stream.printHelp;
const resolveRocksDbPath = shred_stream.resolveRocksDbPath;

const agave_cf_meta = shred_stream.config.agave_cf_meta;
const agave_cf_data_shred = shred_stream.config.agave_cf_data_shred;
const agave_cf_code_shred = shred_stream.config.agave_cf_code_shred;
const max_shred_packet_bytes = shred_stream.config.max_shred_packet_bytes;
const producer_publish_packets = shred_stream.config.producer_publish_packets;
const stream_queue_packets = shred_stream.config.stream_queue_packets;
const no_current_slot = shred_stream.config.no_current_slot;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);

    var stdout_buf: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
    const stdout = &stdout_writer.interface;

    const parse_result = parseArgs(stdout, argv[1..]) catch |err| switch (err) {
        error.InvalidArguments => {
            try printHelp(stdout);
            try stdout.flush();
            return err;
        },
        error.WriteFailed => return err,
    };

    switch (parse_result) {
        .help => try printHelp(stdout),
        .config => |config| {
            // The lib's finalize() makes --target optional (the in-topology
            // service doesn't need it). The CLI still requires it because
            // packets go out over UDP.
            if (config.target == null) {
                try stdout.print("missing required argument: --target <ip:port>\n", .{});
                try printHelp(stdout);
                try stdout.flush();
                return error.InvalidArguments;
            }
            try run(gpa, stdout, config);
        },
    }
    try stdout.flush();
}

fn run(allocator: Allocator, stdout: *std.Io.Writer, config: Config) !void {
    const target = try std.net.Address.parseIpAndPort(config.target.?);

    // The lib's AgaveBlockstore.open expects an already-resolved rocksdb
    // directory path; resolve it here in the CLI.
    const rocksdb_path = try resolveRocksDbPath(allocator, config.ledger);
    defer allocator.free(rocksdb_path);

    var blockstore = try AgaveBlockstore.open(allocator, rocksdb_path);
    defer blockstore.deinit(allocator);

    try stdout.print("shred-stream config:\n", .{});
    try stdout.print("  ledger: {s}\n", .{config.ledger});
    try stdout.print("  rocksdb: {s}\n", .{blockstore.rocksdb_path});
    try stdout.print("  target: {s}\n", .{config.target.?});
    try stdout.print("  start_slot: {?d}\n", .{config.start_slot});
    try stdout.print("  end_slot: {?d}\n", .{config.end_slot});
    try stdout.print("  rate_hz: {?}\n", .{config.rate_hz});
    try stdout.print("  test_mode: {s}\n", .{config.test_mode.modeName()});
    try stdout.print("  seed: {?}\n", .{config.seed});
    if (config.test_mode.usesSelectedShreds()) {
        try stdout.print("  selected_count: {d}\n", .{config.selected_count});
        try stdout.print("  shred_kind: {s}\n", .{config.shred_kind.kindName()});
        try stdout.print("  plan_limit: {d}\n", .{config.plan_limit});
        if (config.test_mode == .corrupt) {
            try stdout.print("  corrupt_bytes: {d}\n", .{config.corrupt_bytes});
        }
    }
    try stdout.print("  dry_run: {}\n", .{config.dry_run});
    try stdout.print("  column_families:\n", .{});
    try stdout.print("    {s}: present\n", .{agave_cf_meta});
    try stdout.print("    {s}: present\n", .{agave_cf_data_shred});
    try stdout.print("    {s}: {s}\n", .{
        agave_cf_code_shred,
        if (blockstore.has_code_shred) "present" else "missing",
    });

    if (!blockstore.has_code_shred) {
        try stdout.print(
            "warning: missing optional {s} column family; streaming data shreds only\n",
            .{agave_cf_code_shred},
        );
    }

    // Build a selected-shred plan for modes that need one. The CLI shares
    // an Activity across preflight (plan building) and streaming for a
    // single, unified cancellation signal.
    var activity: lib.runner.Activity = .{};
    var service_view = activity.serviceView();
    const connection: lib.runner.Connection = .{ .activity = &service_view };

    var selected_shreds: ?SelectedShredPlan = null;
    defer if (selected_shreds) |*plan| plan.deinit(allocator);
    if (config.test_mode.usesSelectedShreds()) {
        selected_shreds = try shred_stream.buildSelectedShredPlan(
            allocator,
            stdout,
            &blockstore,
            config,
            connection,
        );
        try printSelectedShredPlan(stdout, &selected_shreds.?, config.test_mode, config.plan_limit);
    }

    if (config.dry_run) {
        const stats = try scanLedger(&blockstore, config);
        try printLedgerStats(stdout, stats);
    } else {
        const sockfd = try std.posix.socket(
            target.any.family,
            std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC,
            std.posix.IPPROTO.UDP,
        );
        // The net thread borrows this fd. Keep ownership here so every path joins
        // the net thread before closing the fd exactly once.
        defer std.posix.close(sockfd);

        var ring: StreamPacketRing = undefined;
        ring.init();

        var producer_done: std.atomic.Value(bool) = .init(false);
        var net_thread_failed: std.atomic.Value(bool) = .init(false);
        var net_thread_stats: NetThreadStats = .{};
        var net_progress: NetThreadProgress = .{};
        var producer_failed: std.atomic.Value(bool) = .init(false);
        var producer_progress: ProducerProgress = .{};
        var producer_result: ProducerThreadResult = .{};

        var maybe_net_thread: ?std.Thread = null;
        var maybe_producer_thread: ?std.Thread = null;
        errdefer {
            activity.state.store(.canceled, .release);
            producer_done.store(true, .release);
            if (maybe_producer_thread) |thread| thread.join();
            if (maybe_net_thread) |thread| thread.join();
        }

        maybe_net_thread = try std.Thread.spawn(
            .{},
            netThreadMain,
            .{
                &ring,
                &producer_done,
                &activity,
                &net_thread_stats,
                &net_progress,
                &net_thread_failed,
                sockfd,
                target,
                config.rate_hz,
            },
        );

        maybe_producer_thread = try std.Thread.spawn(
            .{},
            producerThreadMain,
            .{
                &blockstore,
                allocator,
                config,
                if (selected_shreds) |*plan| plan else null,
                &ring,
                &producer_done,
                &activity,
                &producer_progress,
                &producer_failed,
                &producer_result,
            },
        );

        try monitorProgress(
            stdout,
            &ring,
            &producer_done,
            &activity,
            &producer_progress,
            &net_progress,
            config.rate_hz,
        );

        maybe_producer_thread.?.join();
        maybe_producer_thread = null;
        maybe_net_thread.?.join();
        maybe_net_thread = null;

        try printProducerStats(stdout, producer_result.stats);
        try printNetThreadStats(stdout, net_thread_stats);

        if (producer_failed.load(.monotonic)) return error.ProducerThreadFailed;
        if (net_thread_failed.load(.monotonic)) return error.NetThreadFailed;
    }
}

// ---------------------------------------------------------------------------
// CLI-specific transport types
//
// StreamPacket + StreamPacketRing carry per-shred metadata across the
// producer/net-thread boundary so the net thread can report per-kind
// statistics for the user. The in-topology service uses net.Packet instead
// (raw bytes only), so these types stay local to the CLI.
// ---------------------------------------------------------------------------

const StreamPacket = extern struct {
    data: [max_shred_packet_bytes]u8,
    slot: Slot,
    shred_index: u64,
    len: u16,
    kind: ShredKind,
};

const StreamPacketRing = Ring(stream_queue_packets, StreamPacket);

const NetThreadStats = struct {
    data_packets: u64 = 0,
    code_packets: u64 = 0,
    payload_bytes: u64 = 0,
    empty_polls: u64 = 0,
    send_errors: u64 = 0,

    fn recordPacket(self: *NetThreadStats, packet: *const StreamPacket) void {
        switch (packet.kind) {
            .data => self.data_packets += 1,
            .code => self.code_packets += 1,
        }
        self.payload_bytes += packet.len;
    }
};

const NetThreadProgress = struct {
    data_packets: std.atomic.Value(u64) = .init(0),
    code_packets: std.atomic.Value(u64) = .init(0),
    payload_bytes: std.atomic.Value(u64) = .init(0),
    empty_polls: std.atomic.Value(u64) = .init(0),
    send_errors: std.atomic.Value(u64) = .init(0),

    fn store(self: *NetThreadProgress, stats: NetThreadStats) void {
        self.data_packets.store(stats.data_packets, .release);
        self.code_packets.store(stats.code_packets, .release);
        self.payload_bytes.store(stats.payload_bytes, .release);
        self.empty_polls.store(stats.empty_polls, .release);
        self.send_errors.store(stats.send_errors, .release);
    }
};

const ProducerThreadResult = struct {
    stats: ProducerStats = .{},
};

const ProgressSnapshot = struct {
    produced_packets: u64,
    sent_packets: u64,
    producer_full_polls: u64,
    sender_empty_polls: u64,

    fn init(
        producer_progress: *ProducerProgress,
        net_progress: *NetThreadProgress,
    ) ProgressSnapshot {
        const produced_packets = producer_progress.data_packets.load(.acquire) +
            producer_progress.code_packets.load(.acquire);
        const sent_packets = net_progress.data_packets.load(.acquire) +
            net_progress.code_packets.load(.acquire);

        return .{
            .produced_packets = produced_packets,
            .sent_packets = sent_packets,
            .producer_full_polls = producer_progress.full_polls.load(.acquire),
            .sender_empty_polls = net_progress.empty_polls.load(.acquire),
        };
    }
};

// ---------------------------------------------------------------------------
// CliPacketContext — implements the lib's PacketContext interface for the
// CLI. Fills StreamPacket metadata (slot/index/kind) and updates
// ProducerProgress atomics so the monitor thread can print live stats.
// ---------------------------------------------------------------------------

const CliPacketContext = struct {
    progress: *ProducerProgress,
    activity: *lib.runner.Activity,
    last_slot: Slot = no_current_slot,

    /// Acquire the next writable ring slot. Spins on backpressure and
    /// returns `error.Canceled` if the shared Activity has been canceled.
    pub fn acquirePacketSlot(
        self: *CliPacketContext,
        writer: *StreamPacketRing.Iterator(.writer),
        unpublished_packets: *usize,
    ) !*StreamPacket {
        while (true) {
            if (writer.peek()) |slot_ptr| return slot_ptr;
            if (unpublished_packets.* != 0) {
                writer.markUsed();
                unpublished_packets.* = 0;
                continue;
            }
            _ = self.progress.full_polls.fetchAdd(1, .monotonic);
            if (self.activity.state.load(.acquire) == .canceled) return error.Canceled;
            std.atomic.spinLoopHint();
        }
    }

    /// Copy the shred payload + metadata into the ring slot, and update
    /// ProducerProgress atomics so the monitor thread sees per-second
    /// throughput / current slot / per-kind counts.
    pub fn fillPacket(
        self: *CliPacketContext,
        out: *StreamPacket,
        packet_data: []const u8,
        kind: ShredKind,
        key: ShredKey,
    ) void {
        out.slot = key.slot;
        out.shred_index = key.index;
        out.kind = kind;
        out.len = @intCast(packet_data.len);
        @memcpy(out.data[0..packet_data.len], packet_data);

        if (key.slot != self.last_slot) {
            self.last_slot = key.slot;
            _ = self.progress.slots.fetchAdd(1, .monotonic);
            self.progress.current_slot.store(key.slot, .release);
        }
        switch (kind) {
            .data => _ = self.progress.data_packets.fetchAdd(1, .monotonic),
            .code => _ = self.progress.code_packets.fetchAdd(1, .monotonic),
        }
        _ = self.progress.payload_bytes.fetchAdd(@intCast(packet_data.len), .monotonic);
    }
};

// Adapts the fallible net thread loop to std.Thread.spawn's void entry point.
fn netThreadMain(
    ring: *StreamPacketRing,
    done: *std.atomic.Value(bool),
    activity: *lib.runner.Activity,
    stats: *NetThreadStats,
    progress: *NetThreadProgress,
    failed: *std.atomic.Value(bool),
    sockfd: std.posix.fd_t,
    target: std.net.Address,
    rate_hz: ?f64,
) !void {
    var reader = ring.get(.reader);
    netThreadMainInner(
        &reader,
        done,
        activity,
        stats,
        progress,
        sockfd,
        target,
        rate_hz,
    ) catch |err| {
        failed.store(true, .release);
        stats.send_errors += 1;
        progress.store(stats.*);
        activity.state.store(.canceled, .release);
        return err;
    };
}

fn netThreadMainInner(
    reader: *StreamPacketRing.Iterator(.reader),
    done: *std.atomic.Value(bool),
    activity: *lib.runner.Activity,
    stats: *NetThreadStats,
    progress: *NetThreadProgress,
    sockfd: std.posix.fd_t,
    target: std.net.Address,
    rate_hz: ?f64,
) !void {
    defer reader.markUsed();

    const packet_interval_ns: ?u64 = if (rate_hz) |rate|
        @max(1, @as(u64, @intFromFloat(@ceil(@as(f64, @floatFromInt(std.time.ns_per_s)) / rate))))
    else
        null;
    var base_instant: ?std.time.Instant = null;
    var next_send_offset_ns: u64 = 0;

    while (activity.state.load(.acquire) != .canceled and
        (!done.load(.acquire) or reader.peek() != null))
    {
        var consumed: usize = 0;
        while (consumed < producer_publish_packets) {
            const packet = reader.next() orelse break;

            if (packet_interval_ns) |interval_ns| {
                const now = try std.time.Instant.now();
                const now_offset_ns = if (base_instant) |base|
                    now.since(base)
                else blk: {
                    base_instant = now;
                    break :blk 0;
                };

                if (now_offset_ns < next_send_offset_ns) {
                    std.Thread.sleep(next_send_offset_ns - now_offset_ns);
                }

                const sent = try std.posix.sendto(
                    sockfd,
                    packet.data[0..packet.len],
                    std.posix.MSG.NOSIGNAL,
                    &target.any,
                    target.getOsSockLen(),
                );
                std.debug.assert(sent == packet.len);

                const after = try std.time.Instant.now();
                const after_offset_ns = after.since(base_instant.?);
                next_send_offset_ns = @max(next_send_offset_ns, after_offset_ns) + interval_ns;
            } else {
                const sent = try std.posix.sendto(
                    sockfd,
                    packet.data[0..packet.len],
                    std.posix.MSG.NOSIGNAL,
                    &target.any,
                    target.getOsSockLen(),
                );
                std.debug.assert(sent == packet.len);
            }

            stats.recordPacket(packet);
            consumed += 1;
        }

        if (consumed != 0) {
            progress.store(stats.*);
            reader.markUsed();
            continue;
        }

        stats.empty_polls += 1;
        if (stats.empty_polls % 1024 == 0) {
            progress.empty_polls.store(stats.empty_polls, .release);
        }
        std.atomic.spinLoopHint();
    }
}

/// Producer thread — delegates all shred production to the shared lib.
/// The lib returns ProducerStats on success and propagates errors on
/// cancellation or RocksDB failure. `error.Canceled` is treated as a
/// graceful stop (partial stats via progress atomics), not a failure.
fn producerThreadMain(
    blockstore: *const AgaveBlockstore,
    allocator: Allocator,
    config: Config,
    selected_shreds: ?*const SelectedShredPlan,
    ring: *StreamPacketRing,
    done: *std.atomic.Value(bool),
    activity: *lib.runner.Activity,
    progress: *ProducerProgress,
    failed: *std.atomic.Value(bool),
    result: *ProducerThreadResult,
) !void {
    var writer = ring.get(.writer);
    var service_view = activity.serviceView();
    const connection: lib.runner.Connection = .{ .activity = &service_view };

    var ctx: CliPacketContext = .{ .progress = progress, .activity = activity };

    result.stats = shred_stream.produceLedgerPackets(
        allocator,
        blockstore,
        config,
        selected_shreds,
        &writer,
        &ctx,
        connection,
    ) catch |err| switch (err) {
        // Graceful cancellation — partial progress is already in atomics.
        error.Canceled => blk: {
            done.store(true, .release);
            break :blk .{};
        },
        else => {
            failed.store(true, .release);
            activity.state.store(.canceled, .release);
            done.store(true, .release);
            return err;
        },
    };
    done.store(true, .release);
}

fn monitorProgress(
    stdout: *std.Io.Writer,
    ring: *StreamPacketRing,
    producer_done: *std.atomic.Value(bool),
    activity: *lib.runner.Activity,
    producer_progress: *ProducerProgress,
    net_progress: *NetThreadProgress,
    rate_hz: ?f64,
) !void {
    var last_snapshot = ProgressSnapshot.init(producer_progress, net_progress);
    while (activity.state.load(.acquire) != .canceled and !producer_done.load(.acquire)) {
        std.Thread.sleep(std.time.ns_per_s);
        try printProgress(stdout, ring, producer_progress, net_progress, last_snapshot, rate_hz);
        last_snapshot = ProgressSnapshot.init(producer_progress, net_progress);
    }

    while (activity.state.load(.acquire) != .canceled) {
        const queue_packets = ring.tail.value.load(.acquire) -% ring.head.value.load(.acquire);
        if (queue_packets == 0) break;
        std.Thread.sleep(std.time.ns_per_s);
        try printProgress(stdout, ring, producer_progress, net_progress, last_snapshot, rate_hz);
        last_snapshot = ProgressSnapshot.init(producer_progress, net_progress);
    }
}

fn printProgress(
    stdout: *std.Io.Writer,
    ring: *StreamPacketRing,
    producer_progress: *ProducerProgress,
    net_progress: *NetThreadProgress,
    last_snapshot: ProgressSnapshot,
    rate_hz: ?f64,
) !void {
    const current_slot = producer_progress.current_slot.load(.acquire);
    const slots = producer_progress.slots.load(.acquire);
    const produced_data = producer_progress.data_packets.load(.acquire);
    const produced_code = producer_progress.code_packets.load(.acquire);
    const produced_packets = produced_data + produced_code;
    const sent_data = net_progress.data_packets.load(.acquire);
    const sent_code = net_progress.code_packets.load(.acquire);
    const sent_packets = sent_data + sent_code;
    const send_pps = sent_packets -| last_snapshot.sent_packets;
    const produced_pps = produced_packets -| last_snapshot.produced_packets;
    const queue_packets = ring.tail.value.load(.acquire) -% ring.head.value.load(.acquire);
    const producer_full_polls = producer_progress.full_polls.load(.acquire);
    const sender_empty_polls = net_progress.empty_polls.load(.acquire);
    const producer_blocked = queue_packets == stream_queue_packets or
        producer_full_polls != last_snapshot.producer_full_polls;
    const net_idle = sender_empty_polls != last_snapshot.sender_empty_polls;

    if (current_slot == no_current_slot) {
        try stdout.print("slot=-", .{});
    } else {
        try stdout.print("slot={d}", .{current_slot});
    }
    try stdout.print(
        " slots={d} produced={d} sent={d} produce_pps={d} send_pps={d}" ++
            " queue={d}/{d} producer_backpressured={} net_idle={}",
        .{
            slots,
            produced_packets,
            sent_packets,
            produced_pps,
            send_pps,
            queue_packets,
            stream_queue_packets,
            producer_blocked,
            net_idle,
        },
    );
    if (rate_hz) |rate| {
        try stdout.print(" rate_hz={d:.0}", .{rate});
    }
    try stdout.print("\n", .{});
    try stdout.flush();
}

// ---------------------------------------------------------------------------
// Dry-run scanning (CLI-only; no lib equivalent).
// ---------------------------------------------------------------------------

fn scanLedger(blockstore: *const AgaveBlockstore, config: Config) !LedgerStats {
    return .{
        .slots = try scanSlots(blockstore, config),
        .data_shreds = try scanShreds(blockstore, config, agave_cf_data_shred),
        .code_shreds = if (blockstore.has_code_shred)
            try scanShreds(blockstore, config, agave_cf_code_shred)
        else
            null,
    };
}

fn scanSlots(blockstore: *const AgaveBlockstore, config: Config) !SlotStats {
    const rocks = @import("rocksdb");
    var stats: SlotStats = .{};

    var start_key_buf: [8]u8 = undefined;
    const start_key: ?[]const u8 = if (config.start_slot) |slot| start_key: {
        writeSlotKey(&start_key_buf, slot);
        break :start_key start_key_buf[0..];
    } else null;

    var iter = blockstore.db.iterator(
        try blockstore.columnFamily(agave_cf_meta),
        .forward,
        start_key,
    );
    defer iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    while (try iter.next(&err_data)) |entry| {
        const slot = parseSlotKey(entry[0].data) catch |err| {
            std.debug.print("invalid {s} key length: {d}\n", .{ agave_cf_meta, entry[0].data.len });
            return err;
        };
        if (config.pastEndSlot(slot)) break;
        stats.record(slot, config.slotSelected(slot));
    }

    return stats;
}

fn scanShreds(
    blockstore: *const AgaveBlockstore,
    config: Config,
    column_family_name: []const u8,
) !ShredStats {
    const rocks = @import("rocksdb");
    var stats: ShredStats = .{};

    var start_key_buf: [16]u8 = undefined;
    const start_key: ?[]const u8 = if (config.start_slot) |slot| start_key: {
        writeShredKey(&start_key_buf, .{ .slot = slot, .index = 0 });
        break :start_key start_key_buf[0..];
    } else null;

    var iter = blockstore.db.iterator(
        try blockstore.columnFamily(column_family_name),
        .forward,
        start_key,
    );
    defer iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    while (try iter.next(&err_data)) |entry| {
        const key = parseShredKey(entry[0].data) catch |err| {
            std.debug.print(
                "invalid {s} key length: {d}\n",
                .{ column_family_name, entry[0].data.len },
            );
            return err;
        };
        if (config.pastEndSlot(key.slot)) break;
        stats.record(key, entry[1].data.len, config.slotSelected(key.slot));
    }

    return stats;
}

// ---------------------------------------------------------------------------
// Print helpers.
// ---------------------------------------------------------------------------

fn printLedgerStats(stdout: *std.Io.Writer, stats: LedgerStats) !void {
    try stdout.print("ledger_stats:\n", .{});
    try stdout.print("  max_packet_bytes: {d}\n", .{max_shred_packet_bytes});

    try stdout.print("  slots:\n", .{});
    try stdout.print("    total: {d}\n", .{stats.slots.total});
    try stdout.print("    first: {?d}\n", .{stats.slots.first});
    try stdout.print("    last: {?d}\n", .{stats.slots.last});
    try stdout.print("    selected: {d}\n", .{stats.slots.selected});
    try stdout.print("    selected_first: {?d}\n", .{stats.slots.selected_first});
    try stdout.print("    selected_last: {?d}\n", .{stats.slots.selected_last});

    try printShredStats(stdout, agave_cf_data_shred, stats.data_shreds);
    if (stats.code_shreds) |code_shreds| {
        try printShredStats(stdout, agave_cf_code_shred, code_shreds);
    } else {
        try stdout.print("  {s}: missing\n", .{agave_cf_code_shred});
    }
}

fn printSelectedShredPlan(
    stdout: *std.Io.Writer,
    selected_shreds: *const SelectedShredPlan,
    test_mode: TestMode,
    preview_limit: usize,
) !void {
    const refs = selected_shreds.schedule.refs.items;
    const selected_ref_indices = selected_shreds.selected_ref_indices.items;
    const affected_slots = countSelectedShredSlots(selected_shreds);
    const action = switch (test_mode) {
        .drop => "dropped",
        .late => "delayed",
        .duplicate => "duplicated",
        .corrupt => "corrupted",
        .linear, .reverse, .shuffle_global, .shuffle_slot => unreachable,
    };

    try stdout.print("{s}_plan:\n", .{test_mode.modeName()});
    try stdout.print("  eligible_shreds: {d}\n", .{selected_shreds.eligible_shreds});
    try stdout.print(
        "  {s}_shreds: {d}\n",
        .{ action, selected_ref_indices.len },
    );
    try stdout.print("  affected_slots: {d}\n", .{affected_slots});
    try stdout.print("  preview_slots: {d}\n", .{@min(preview_limit, affected_slots)});

    if (preview_limit == 0 or affected_slots == 0) return;

    try stdout.print("  {s}_shreds_preview:\n", .{action});

    var skip_index: usize = 0;
    var printed_slots: usize = 0;
    while (skip_index < selected_ref_indices.len) {
        const slot = refs[selected_ref_indices[skip_index]].slot;
        const slot_start = skip_index;
        while (skip_index < selected_ref_indices.len and
            refs[selected_ref_indices[skip_index]].slot == slot)
        {
            skip_index += 1;
        }
        const slot_selected_ref_indices = selected_ref_indices[slot_start..skip_index];

        if (printed_slots == preview_limit) break;
        try stdout.print("    {d}: data=[", .{slot});
        try printSelectedShredIndexList(stdout, selected_shreds, slot_selected_ref_indices, .data);
        try stdout.print("] code=[", .{});
        try printSelectedShredIndexList(stdout, selected_shreds, slot_selected_ref_indices, .code);
        try stdout.print("]\n", .{});
        printed_slots += 1;
    }

    if (affected_slots > printed_slots) {
        try stdout.print("  omitted_slots: {d}\n", .{affected_slots - printed_slots});
    }
}

fn countSelectedShredSlots(selected_shreds: *const SelectedShredPlan) usize {
    const refs = selected_shreds.schedule.refs.items;
    const selected_ref_indices = selected_shreds.selected_ref_indices.items;

    var count: usize = 0;
    var previous_slot: ?Slot = null;
    for (selected_ref_indices) |selected_ref_index| {
        const slot = refs[selected_ref_index].slot;
        if (previous_slot == null or previous_slot.? != slot) {
            count += 1;
            previous_slot = slot;
        }
    }
    return count;
}

fn printSelectedShredIndexList(
    stdout: *std.Io.Writer,
    selected_shreds: *const SelectedShredPlan,
    selected_ref_indices: []const usize,
    kind: ShredKind,
) !void {
    const refs = selected_shreds.schedule.refs.items;

    var first = true;
    for (selected_ref_indices) |selected_ref_index| {
        const shred_ref = refs[selected_ref_index];
        if (shred_ref.kind != kind) continue;
        if (!first) try stdout.print(", ", .{});
        try stdout.print("{d}", .{shred_ref.index});
        first = false;
    }
}

fn printProducerStats(stdout: *std.Io.Writer, stats: ProducerStats) !void {
    try stdout.print("producer_walk:\n", .{});
    try stdout.print("  slots: {d}\n", .{stats.slots});
    try stdout.print("  data_packets: {d}\n", .{stats.data_packets});
    try stdout.print("  code_packets: {d}\n", .{stats.code_packets});
    try stdout.print("  total_packets: {d}\n", .{stats.data_packets + stats.code_packets});
    try stdout.print("  payload_bytes: {d}\n", .{stats.payload_bytes});
}

fn printNetThreadStats(stdout: *std.Io.Writer, stats: NetThreadStats) !void {
    try stdout.print("net_thread:\n", .{});
    try stdout.print("  data_packets: {d}\n", .{stats.data_packets});
    try stdout.print("  code_packets: {d}\n", .{stats.code_packets});
    try stdout.print("  total_packets: {d}\n", .{stats.data_packets + stats.code_packets});
    try stdout.print("  payload_bytes: {d}\n", .{stats.payload_bytes});
    try stdout.print("  empty_polls: {d}\n", .{stats.empty_polls});
    try stdout.print("  send_errors: {d}\n", .{stats.send_errors});
}

fn printShredStats(stdout: *std.Io.Writer, name: []const u8, stats: ShredStats) !void {
    try stdout.print("  {s}:\n", .{name});
    try stdout.print("    total_packets: {d}\n", .{stats.total_packets});
    try stdout.print("    total_payload_bytes: {d}\n", .{stats.total_payload_bytes});
    try stdout.print("    first_slot: {?d}\n", .{stats.first_slot});
    try stdout.print("    last_slot: {?d}\n", .{stats.last_slot});
    try stdout.print("    max_packet_bytes: {d}\n", .{stats.max_packet_bytes});
    try stdout.print("    oversized_packets: {d}\n", .{stats.oversized_packets});
    try stdout.print("    selected_packets: {d}\n", .{stats.selected_packets});
    try stdout.print("    selected_payload_bytes: {d}\n", .{stats.selected_payload_bytes});
    try stdout.print("    selected_first_slot: {?d}\n", .{stats.selected_first_slot});
    try stdout.print("    selected_last_slot: {?d}\n", .{stats.selected_last_slot});
    try stdout.print("    selected_max_packet_bytes: {d}\n", .{stats.selected_max_packet_bytes});
    try stdout.print("    selected_oversized_packets: {d}\n", .{stats.selected_oversized_packets});
}
