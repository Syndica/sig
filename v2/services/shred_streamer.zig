//! Streams raw shreds from an Agave ledger into the shred_receiver via IPC ring.
//!
//! This service reads shreds from a RocksDB-backed Agave ledger and writes them
//! as net.Packet structs into the net.Pair.recv ring — the same interface that
//! the net service uses. The shred_receiver reads from this ring unchanged.
//!
//! Configuration is passed via shared memory as a CLI args string (see
//! lib.shred_streamer.Config). The service parses the args on startup.

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

pub const ReadOnly = services.shred_streamer.ReadOnly;
pub const ReadWrite = services.shred_streamer.ReadWrite;

const Allocator = std.mem.Allocator;
const Slot = u64;
const Ring = lib.ipc.Ring;

const agave_cf_default = "default";
const agave_cf_meta = "meta";
const agave_cf_data_shred = "data_shred";
const agave_cf_code_shred = "code_shred";
const max_shred_packet_bytes: usize = 1232;
const producer_publish_packets: usize = 32;
const stream_queue_packets = 8192;
const no_current_slot = std.math.maxInt(Slot);

const TestMode = enum {
    linear,
    reverse,
    shuffle_global,
    shuffle_slot,
    drop,
    late,
    duplicate,
    corrupt,

    fn parse(raw: []const u8) ?TestMode {
        if (std.mem.eql(u8, raw, "linear")) return .linear;
        if (std.mem.eql(u8, raw, "reverse")) return .reverse;
        if (std.mem.eql(u8, raw, "shuffle-global")) return .shuffle_global;
        if (std.mem.eql(u8, raw, "shuffle-slot")) return .shuffle_slot;
        if (std.mem.eql(u8, raw, "drop")) return .drop;
        if (std.mem.eql(u8, raw, "late")) return .late;
        if (std.mem.eql(u8, raw, "duplicate")) return .duplicate;
        if (std.mem.eql(u8, raw, "corrupt")) return .corrupt;
        return null;
    }

    fn modeName(self: TestMode) []const u8 {
        return switch (self) {
            .linear => "linear",
            .reverse => "reverse",
            .shuffle_global => "shuffle-global",
            .shuffle_slot => "shuffle-slot",
            .drop => "drop",
            .late => "late",
            .duplicate => "duplicate",
            .corrupt => "corrupt",
        };
    }

    fn usesSelectedShreds(self: TestMode) bool {
        return switch (self) {
            .drop, .late, .duplicate, .corrupt => true,
            .linear, .reverse, .shuffle_global, .shuffle_slot => false,
        };
    }
};

const ShredKindFilter = enum {
    any,
    data,
    code,

    fn parse(raw: []const u8) ?ShredKindFilter {
        if (std.mem.eql(u8, raw, "any")) return .any;
        if (std.mem.eql(u8, raw, "data")) return .data;
        if (std.mem.eql(u8, raw, "code")) return .code;
        return null;
    }

    fn kindName(self: ShredKindFilter) []const u8 {
        return switch (self) {
            .any => "any",
            .data => "data",
            .code => "code",
        };
    }

    fn matches(self: ShredKindFilter, kind: ShredKind) bool {
        return switch (self) {
            .any => true,
            .data => kind == .data,
            .code => kind == .code,
        };
    }
};

const Config = struct {
    ledger: []const u8,
    target: []const u8 = "",
    start_slot: ?Slot = null,
    end_slot: ?Slot = null,
    rate_hz: ?f64 = null,
    test_mode: TestMode = .linear,
    seed: ?u64 = null,
    selected_count: usize = 1,
    shred_kind: ShredKindFilter = .any,
    plan_limit: usize = 20,
    corrupt_bytes: usize = 1,
    dry_run: bool = false,

    fn slotSelected(self: Config, slot: Slot) bool {
        if (self.start_slot) |start_slot| {
            if (slot < start_slot) return false;
        }
        return !self.pastEndSlot(slot);
    }

    fn pastEndSlot(self: Config, slot: Slot) bool {
        return if (self.end_slot) |end_slot| slot > end_slot else false;
    }

    fn pastSlotRange(
        self: Config,
        slot: Slot,
        comptime direction: rocks.IteratorDirection,
    ) bool {
        return switch (direction) {
            .forward => self.pastEndSlot(slot),
            .reverse => if (self.start_slot) |start_slot| slot < start_slot else false,
        };
    }
};

const PartialConfig = struct {
    ledger: ?[]const u8 = null,
    target: ?[]const u8 = null,
    start_slot: ?Slot = null,
    end_slot: ?Slot = null,
    rate_hz: ?f64 = null,
    test_mode: TestMode = .linear,
    seed: ?u64 = null,
    selected_count: ?usize = null,
    shred_kind: ?ShredKindFilter = null,
    plan_limit: ?usize = null,
    corrupt_bytes: ?usize = null,
    dry_run: bool = false,

    fn finalize(self: PartialConfig, stdout: *std.Io.Writer) ParseArgsError!Config {
        const ledger = self.ledger orelse {
            try stdout.print("missing required argument: --ledger <path>\n", .{});
            return error.InvalidArguments;
        };
        // --target is optional: only needed by the legacy UDP path (legacyMain),
        // not by the v2 service which writes directly to the IPC ring.
        const target = self.target orelse "";

        if (self.start_slot != null and
            self.end_slot != null and
            self.end_slot.? < self.start_slot.?)
        {
            try stdout.print("--end-slot must be greater than or equal to --start-slot\n", .{});
            return error.InvalidArguments;
        }

        switch (self.test_mode) {
            .linear, .reverse => {
                if (self.seed != null) {
                    try stdout.print(
                        "--seed is only valid with --test-mode shuffle-global, " ++
                            "shuffle-slot, drop, late, duplicate, or corrupt\n",
                        .{},
                    );
                    return error.InvalidArguments;
                }
            },
            .shuffle_global, .shuffle_slot, .drop, .late, .duplicate, .corrupt => {
                if (self.seed == null) {
                    try stdout.print(
                        "--test-mode {s} requires --seed\n",
                        .{self.test_mode.modeName()},
                    );
                    return error.InvalidArguments;
                }
                if (self.start_slot == null or self.end_slot == null) {
                    try stdout.print(
                        "--test-mode {s} requires both --start-slot and --end-slot\n",
                        .{self.test_mode.modeName()},
                    );
                    return error.InvalidArguments;
                }
            },
        }

        if (!self.test_mode.usesSelectedShreds()) {
            if (self.selected_count != null) {
                try stdout.print(
                    "--count is only valid with --test-mode drop, late, duplicate, or corrupt\n",
                    .{},
                );
                return error.InvalidArguments;
            }
            if (self.shred_kind != null) {
                try stdout.print(
                    "--shred-kind is only valid with --test-mode drop, late, " ++
                        "duplicate, or corrupt\n",
                    .{},
                );
                return error.InvalidArguments;
            }
            if (self.plan_limit != null) {
                try stdout.print(
                    "--plan-limit is only valid with --test-mode drop, late, " ++
                        "duplicate, or corrupt\n",
                    .{},
                );
                return error.InvalidArguments;
            }
            if (self.corrupt_bytes != null) {
                try stdout.print("--corrupt-bytes is only valid with --test-mode corrupt\n", .{});
                return error.InvalidArguments;
            }
        } else if (self.test_mode != .corrupt and self.corrupt_bytes != null) {
            try stdout.print("--corrupt-bytes is only valid with --test-mode corrupt\n", .{});
            return error.InvalidArguments;
        }

        return .{
            .ledger = ledger,
            .target = target,
            .start_slot = self.start_slot,
            .end_slot = self.end_slot,
            .rate_hz = self.rate_hz,
            .test_mode = self.test_mode,
            .seed = self.seed,
            .selected_count = self.selected_count orelse 1,
            .shred_kind = self.shred_kind orelse .any,
            .plan_limit = self.plan_limit orelse 20,
            .corrupt_bytes = self.corrupt_bytes orelse 1,
            .dry_run = self.dry_run,
        };
    }
};

const ParseResult = union(enum) {
    config: Config,
    help,
};

const ParseArgsError = error{
    InvalidArguments,
    WriteFailed,
};

const Arg = enum {
    help,
    ledger,
    target,
    start_slot,
    end_slot,
    rate_hz,
    test_mode,
    seed,
    count,
    shred_kind,
    plan_limit,
    corrupt_bytes,
    dry_run,

    fn parse(raw: []const u8) ?Arg {
        if (std.mem.eql(u8, raw, "--help") or std.mem.eql(u8, raw, "-h")) return .help;
        if (std.mem.eql(u8, raw, "--ledger")) return .ledger;
        if (std.mem.eql(u8, raw, "--target")) return .target;
        if (std.mem.eql(u8, raw, "--start-slot")) return .start_slot;
        if (std.mem.eql(u8, raw, "--end-slot")) return .end_slot;
        if (std.mem.eql(u8, raw, "--rate-hz")) return .rate_hz;
        if (std.mem.eql(u8, raw, "--test-mode")) return .test_mode;
        if (std.mem.eql(u8, raw, "--seed")) return .seed;
        if (std.mem.eql(u8, raw, "--count")) return .count;
        if (std.mem.eql(u8, raw, "--shred-kind")) return .shred_kind;
        if (std.mem.eql(u8, raw, "--plan-limit")) return .plan_limit;
        if (std.mem.eql(u8, raw, "--corrupt-bytes")) return .corrupt_bytes;
        if (std.mem.eql(u8, raw, "--dry-run")) return .dry_run;
        return null;
    }

    fn flagName(arg: Arg) []const u8 {
        return switch (arg) {
            .help => "--help",
            .ledger => "--ledger",
            .target => "--target",
            .start_slot => "--start-slot",
            .end_slot => "--end-slot",
            .rate_hz => "--rate-hz",
            .test_mode => "--test-mode",
            .seed => "--seed",
            .count => "--count",
            .shred_kind => "--shred-kind",
            .plan_limit => "--plan-limit",
            .corrupt_bytes => "--corrupt-bytes",
            .dry_run => "--dry-run",
        };
    }
};

/// Service entry point — adapted from the old standalone `main()` + `run()` flow.
///
/// Changes from the original script:
/// - Reads CLI args from shared memory (ro.config) instead of std.process.argsAlloc
/// - Writes net.Packet to the IPC ring (rw.shred_pair.recv) instead of UDP sendto
/// - Single-threaded: no net thread or monitor thread (rate limiting is inline)
/// - Uses cooperative scheduling (signalIdleSpinning) for back-pressure and shutdown
/// - Currently only implements linear mode; other test modes remain in legacyMain
pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
    const zone = tracy.Zone.init(@src(), .{ .name = @tagName(name) });
    defer zone.deinit();

    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    // Parse config from shared memory args
    const args_str = ro.config.getArgs();
    var arg_ptrs: [64][]const u8 = undefined;
    var arg_count: usize = 0;
    var iter = std.mem.splitScalar(u8, args_str, ' ');
    while (iter.next()) |arg| {
        if (arg.len == 0) continue;
        if (arg_count >= arg_ptrs.len) break;
        arg_ptrs[arg_count] = arg;
        arg_count += 1;
    }

    var discard_writer: std.Io.Writer.Discarding = .init(&.{});
    const parse_result = parseArgs(&discard_writer.writer, arg_ptrs[0..arg_count]) catch |err| {
        logger.err().logf("failed to parse args: {}", .{err});
        return err;
    };

    const config: Config = switch (parse_result) {
        .help => {
            logger.info().logf("help requested, going idle", .{});
            while (true) try runner.activity.signalIdleSpinning();
        },
        .config => |c| c,
    };

    logger.info().logf("streaming from ledger: {s}", .{config.ledger});

    // Open blockstore
    var blockstore = AgaveBlockstore.open(gpa, config.ledger) catch |err| {
        logger.err().logf("failed to open blockstore: {}", .{err});
        return err;
    };
    defer blockstore.deinit(gpa);

    // Stream shreds to ring
    var writer = rw.shred_pair.recv.get(.writer);
    var unpublished_packets: usize = 0;
    var stats: ProducerStats = .{};

    if (!config.dry_run) {
        // Linear mode: iterate slots and write shreds to ring
        var start_key_buf: [8]u8 = undefined;
        const start_key: ?[]const u8 = if (config.start_slot) |slot| start_key: {
            writeSlotKey(&start_key_buf, slot);
            break :start_key start_key_buf[0..];
        } else null;

        logger.info().logf(
            "starting iteration: start_slot={?d} end_slot={?d}",
            .{ config.start_slot, config.end_slot },
        );

        var slot_iter = blockstore.db.iterator(
            try blockstore.columnFamily(agave_cf_meta),
            .forward,
            start_key,
        );
        defer slot_iter.deinit();

        var err_data: ?rocks.Data = null;
        defer if (err_data) |err| err.deinit();

        // Log the first entry to check if iterator produces anything
        var iter_entries: u64 = 0;

        while (try slot_iter.next(&err_data)) |entry| {
            try runner.activity.checkCanceled();
            iter_entries += 1;

            const slot = parseSlotKey(entry[0].data) catch |err| {
                logger.err().logf(
                    "invalid meta key length: {d} (entry #{d})",
                    .{ entry[0].data.len, iter_entries },
                );
                return err;
            };

            // Log first few entries regardless of selection to debug range issues
            if (iter_entries <= 5) {
                logger.info().logf(
                    "iter entry #{d}: slot={d} selected={}",
                    .{ iter_entries, slot, config.slotSelected(slot) },
                );
            }

            if (config.pastEndSlot(slot)) {
                logger.info().logf("past end slot at {d}, stopping", .{slot});
                break;
            }
            if (!config.slotSelected(slot)) continue;

            stats.recordSlot();
            logger.info().logf("streaming slot {d} (#{d})", .{ slot, stats.slots });

            // Stream data shreds for this slot
            try streamSlotShreds(
                &blockstore,
                slot,
                .data,
                &writer,
                &unpublished_packets,
                &stats,
                runner,
                config.rate_hz,
            );

            // Stream code shreds if available
            if (blockstore.has_code_shred) {
                try streamSlotShreds(
                    &blockstore,
                    slot,
                    .code,
                    &writer,
                    &unpublished_packets,
                    &stats,
                    runner,
                    config.rate_hz,
                );
            }
        }

        logger.info().logf(
            "iteration done: raw_entries={d} selected_slots={d}",
            .{ iter_entries, stats.slots },
        );
    }

    // Final flush + close
    if (unpublished_packets > 0) {
        writer.markUsed();
    }
    writer.view.close();

    logger.info().logf(
        "streaming complete: slots={d} data={d} code={d} bytes={d}",
        .{ stats.slots, stats.data_packets, stats.code_packets, stats.payload_bytes },
    );

    // Idle until canceled
    while (true) try runner.activity.signalIdleSpinning();
}

/// Streams all shreds of a given kind for a single slot into the net.Pair ring.
///
/// Adapted from `produceSlotShreds` (the legacy version below) which writes to the
/// internal StreamPacketRing. Key differences:
/// - Output target is net.Pair.PacketRing (shared IPC ring to shred_receiver)
/// - Rate limiting is inline (from netThreadMainInner) instead of in a separate thread
/// - Back-pressure uses signalIdleSpinning for cooperative scheduling + cancel checks
/// - Uses net.Packet layout (data + len + addr) instead of StreamPacket
fn streamSlotShreds(
    blockstore: *const AgaveBlockstore,
    slot: Slot,
    kind: ShredKind,
    writer: *lib.net.Pair.PacketRing.Iterator(.writer),
    unpublished_packets: *usize,
    stats: *ProducerStats,
    runner: lib.runner.Connection,
    rate_hz: ?f64,
) !void {
    var start_key_buf: [16]u8 = undefined;
    writeShredKey(&start_key_buf, .{ .slot = slot, .index = 0 });

    var shred_iter = blockstore.db.iterator(
        try blockstore.columnFamily(kind.columnFamilyName()),
        .forward,
        start_key_buf[0..],
    );
    defer shred_iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    // Rate limiting state
    const packet_interval_ns: ?u64 = if (rate_hz) |rate|
        @max(1, @as(u64, @intFromFloat(@ceil(@as(f64, @floatFromInt(std.time.ns_per_s)) / rate))))
    else
        null;
    var base_instant: ?std.time.Instant = null;
    var next_send_offset_ns: u64 = 0;

    while (try shred_iter.next(&err_data)) |entry| {
        try runner.activity.checkCanceled();

        const key = parseShredKey(entry[0].data) catch return;
        if (key.slot != slot) break;

        const packet_data = entry[1].data;
        if (packet_data.len > max_shred_packet_bytes) continue; // skip oversized

        // Rate limiting
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
            next_send_offset_ns = @max(next_send_offset_ns, now_offset_ns) + interval_ns;
        }

        // Wait for a writable slot in the ring
        const out: *lib.net.Packet = while (true) {
            if (writer.peek()) |p| break p;
            // Ring full — flush pending writes so reader can drain
            if (unpublished_packets.* != 0) {
                writer.markUsed();
                unpublished_packets.* = 0;
                continue;
            }
            try runner.activity.signalIdleSpinning();
        };

        // Fill the packet
        out.len = @intCast(packet_data.len);
        @memcpy(out.data[0..packet_data.len], packet_data);
        out.addr = std.mem.zeroes(std.net.Address);
        _ = writer.next();

        stats.recordPacket(kind, packet_data.len);
        unpublished_packets.* += 1;

        // Batch commit
        if (unpublished_packets.* >= producer_publish_packets) {
            writer.markUsed();
            unpublished_packets.* = 0;
        }
    }
}

// Legacy main() — kept for reference until all test modes are ported to serviceMain.
// lint: allow_unused
fn legacyMain() !void {
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
        .config => |config| try run(gpa, stdout, config),
    }
    try stdout.flush();
}

fn run(allocator: Allocator, stdout: *std.Io.Writer, config: Config) !void {
    const target = try std.net.Address.parseIpAndPort(config.target);

    var blockstore = try AgaveBlockstore.open(allocator, config.ledger);
    defer blockstore.deinit(allocator);

    try stdout.print("shred-stream config:\n", .{});
    try stdout.print("  ledger: {s}\n", .{config.ledger});
    try stdout.print("  rocksdb: {s}\n", .{blockstore.rocksdb_path});
    try stdout.print("  target: {s}\n", .{config.target});
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

    var selected_shreds: ?SelectedShredPlan = null;
    defer if (selected_shreds) |*plan| plan.deinit(allocator);
    if (config.test_mode.usesSelectedShreds()) {
        var preflight_stop: std.atomic.Value(bool) = .init(false);
        selected_shreds = try buildSelectedShredPlan(
            allocator,
            stdout,
            &blockstore,
            config,
            &preflight_stop,
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
        var stop: std.atomic.Value(bool) = .init(false);
        var net_thread_failed: std.atomic.Value(bool) = .init(false);
        var net_thread_stats: NetThreadStats = .{};
        var net_progress: NetThreadProgress = .{};
        var producer_failed: std.atomic.Value(bool) = .init(false);
        var producer_progress: ProducerProgress = .{};
        var producer_result: ProducerThreadResult = .{};

        var maybe_net_thread: ?std.Thread = null;
        var maybe_producer_thread: ?std.Thread = null;
        errdefer {
            stop.store(true, .release);
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
                &stop,
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
                &stop,
                &producer_progress,
                &producer_failed,
                &producer_result,
            },
        );

        try monitorProgress(
            stdout,
            &ring,
            &producer_done,
            &stop,
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

const AgaveBlockstore = struct {
    rocksdb_path: []const u8,
    db: rocks.DB,
    column_families: []const rocks.ColumnFamily,
    has_code_shred: bool,

    fn open(allocator: Allocator, ledger_path: []const u8) !AgaveBlockstore {
        const rocksdb_path = try resolveRocksDbPath(allocator, ledger_path);
        errdefer allocator.free(rocksdb_path);

        var available_cfs = try listColumnFamilies(allocator, rocksdb_path);
        defer available_cfs.deinit(allocator);

        try requireColumnFamily(&available_cfs, agave_cf_default);
        try requireColumnFamily(&available_cfs, agave_cf_meta);
        try requireColumnFamily(&available_cfs, agave_cf_data_shred);

        const has_code_shred = available_cfs.contains(agave_cf_code_shred);
        const cfs = try columnFamilyDescriptions(allocator, has_code_shred);
        defer allocator.free(cfs);

        const rocksdb_path_z = try allocator.dupeZ(u8, rocksdb_path);
        defer allocator.free(rocksdb_path_z);

        var err_data: ?rocks.Data = null;
        defer if (err_data) |err| err.deinit();

        var db, const opened_cfs = rocks.DB.open(
            allocator,
            rocksdb_path_z,
            .{},
            cfs,
            true,
            &err_data,
        ) catch |err| {
            if (err_data) |rocks_err| {
                std.debug.print(
                    "failed to open RocksDB at {s}: {s}\n",
                    .{ rocksdb_path, rocks_err.data },
                );
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

    fn deinit(self: *AgaveBlockstore, allocator: Allocator) void {
        allocator.free(self.column_families);
        self.db.deinit();
        allocator.free(self.rocksdb_path);
    }

    fn columnFamily(self: *const AgaveBlockstore, cf_name: []const u8) !rocks.ColumnFamilyHandle {
        for (self.column_families) |column_family| {
            if (std.mem.eql(u8, column_family.name, cf_name)) return column_family.handle;
        }
        return error.MissingColumnFamily;
    }
};

const LedgerStats = struct {
    slots: SlotStats,
    data_shreds: ShredStats,
    code_shreds: ?ShredStats,
};

const SlotStats = struct {
    total: u64 = 0,
    selected: u64 = 0,
    first: ?Slot = null,
    last: ?Slot = null,
    selected_first: ?Slot = null,
    selected_last: ?Slot = null,

    fn record(self: *SlotStats, slot: Slot, selected: bool) void {
        self.total += 1;
        self.first = if (self.first) |first| @min(first, slot) else slot;
        self.last = if (self.last) |last| @max(last, slot) else slot;

        if (!selected) return;
        self.selected += 1;
        self.selected_first = if (self.selected_first) |first| @min(first, slot) else slot;
        self.selected_last = if (self.selected_last) |last| @max(last, slot) else slot;
    }
};

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

const RefSchedule = struct {
    refs: std.ArrayList(ShredRef) = .empty,
    selected_slots: u64 = 0,

    fn deinit(self: *RefSchedule, allocator: Allocator) void {
        self.refs.deinit(allocator);
    }
};

const SelectedShredPlan = struct {
    schedule: RefSchedule = .{},
    selected_ref_indices: std.ArrayList(usize) = .empty,
    eligible_shreds: usize = 0,

    fn deinit(self: *SelectedShredPlan, allocator: Allocator) void {
        self.selected_ref_indices.deinit(allocator);
        self.schedule.deinit(allocator);
    }
};

const SelectedShredAction = enum {
    skip,
    send_twice,
    send_corrupt,

    fn fromTestMode(test_mode: TestMode) SelectedShredAction {
        return switch (test_mode) {
            .drop, .late => .skip,
            .duplicate => .send_twice,
            .corrupt => .send_corrupt,
            .linear, .reverse, .shuffle_global, .shuffle_slot => unreachable,
        };
    }
};

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

const ProducerStats = struct {
    slots: u64 = 0,
    data_packets: u64 = 0,
    code_packets: u64 = 0,
    payload_bytes: u64 = 0,

    fn recordSlot(self: *ProducerStats) void {
        self.slots += 1;
    }

    fn recordPacket(self: *ProducerStats, kind: ShredKind, payload_len: usize) void {
        switch (kind) {
            .data => self.data_packets += 1,
            .code => self.code_packets += 1,
        }
        self.payload_bytes += @intCast(payload_len);
    }
};

const ProducerProgress = struct {
    current_slot: std.atomic.Value(Slot) = .init(no_current_slot),
    slots: std.atomic.Value(u64) = .init(0),
    data_packets: std.atomic.Value(u64) = .init(0),
    code_packets: std.atomic.Value(u64) = .init(0),
    payload_bytes: std.atomic.Value(u64) = .init(0),
    full_polls: std.atomic.Value(u64) = .init(0),

    fn store(self: *ProducerProgress, stats: ProducerStats) void {
        self.slots.store(stats.slots, .release);
        self.data_packets.store(stats.data_packets, .release);
        self.code_packets.store(stats.code_packets, .release);
        self.payload_bytes.store(stats.payload_bytes, .release);
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

// Adapts the fallible net thread loop to std.Thread.spawn's void entry point.
fn netThreadMain(
    ring: *StreamPacketRing,
    done: *std.atomic.Value(bool),
    stop: *std.atomic.Value(bool),
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
        stop,
        stats,
        progress,
        sockfd,
        target,
        rate_hz,
    ) catch |err| {
        failed.store(true, .release);
        stats.send_errors += 1;
        progress.store(stats.*);
        stop.store(true, .release);
        return err;
    };
}

fn netThreadMainInner(
    reader: *StreamPacketRing.Iterator(.reader),
    done: *std.atomic.Value(bool),
    stop: *std.atomic.Value(bool),
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

    while (!stop.load(.acquire) and (!done.load(.acquire) or reader.peek() != null)) {
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

fn producerThreadMain(
    blockstore: *const AgaveBlockstore,
    allocator: Allocator,
    config: Config,
    selected_shreds: ?*const SelectedShredPlan,
    ring: *StreamPacketRing,
    done: *std.atomic.Value(bool),
    stop: *std.atomic.Value(bool),
    progress: *ProducerProgress,
    failed: *std.atomic.Value(bool),
    result: *ProducerThreadResult,
) !void {
    var writer = ring.get(.writer);
    result.stats = produceLedgerPackets(
        allocator,
        blockstore,
        config,
        selected_shreds,
        &writer,
        stop,
        progress,
    ) catch |err| {
        failed.store(true, .release);
        stop.store(true, .release);
        done.store(true, .release);
        return err;
    };
    progress.store(result.stats);
    done.store(true, .release);
}

fn monitorProgress(
    stdout: *std.Io.Writer,
    ring: *StreamPacketRing,
    producer_done: *std.atomic.Value(bool),
    stop: *std.atomic.Value(bool),
    producer_progress: *ProducerProgress,
    net_progress: *NetThreadProgress,
    rate_hz: ?f64,
) !void {
    var last_snapshot = ProgressSnapshot.init(producer_progress, net_progress);
    while (!stop.load(.acquire) and !producer_done.load(.acquire)) {
        std.Thread.sleep(std.time.ns_per_s);
        try printProgress(stdout, ring, producer_progress, net_progress, last_snapshot, rate_hz);
        last_snapshot = ProgressSnapshot.init(producer_progress, net_progress);
    }

    while (!stop.load(.acquire)) {
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

const ShredStats = struct {
    total_packets: u64 = 0,
    selected_packets: u64 = 0,
    total_payload_bytes: u64 = 0,
    selected_payload_bytes: u64 = 0,
    max_packet_bytes: usize = 0,
    selected_max_packet_bytes: usize = 0,
    oversized_packets: u64 = 0,
    selected_oversized_packets: u64 = 0,
    first_slot: ?Slot = null,
    last_slot: ?Slot = null,
    selected_first_slot: ?Slot = null,
    selected_last_slot: ?Slot = null,

    fn record(self: *ShredStats, key: ShredKey, packet_len: usize, selected: bool) void {
        self.total_packets += 1;
        self.total_payload_bytes += @intCast(packet_len);
        self.max_packet_bytes = @max(self.max_packet_bytes, packet_len);
        if (packet_len > max_shred_packet_bytes) self.oversized_packets += 1;
        self.first_slot = if (self.first_slot) |first| @min(first, key.slot) else key.slot;
        self.last_slot = if (self.last_slot) |last| @max(last, key.slot) else key.slot;

        if (!selected) return;
        self.selected_packets += 1;
        self.selected_payload_bytes += @intCast(packet_len);
        self.selected_max_packet_bytes = @max(self.selected_max_packet_bytes, packet_len);
        if (packet_len > max_shred_packet_bytes) self.selected_oversized_packets += 1;

        self.selected_first_slot = if (self.selected_first_slot) |first|
            @min(first, key.slot)
        else
            key.slot;

        self.selected_last_slot = if (self.selected_last_slot) |last|
            @max(last, key.slot)
        else
            key.slot;
    }
};

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

fn produceLedgerPackets(
    allocator: Allocator,
    blockstore: *const AgaveBlockstore,
    config: Config,
    selected_shreds: ?*const SelectedShredPlan,
    writer: *StreamPacketRing.Iterator(.writer),
    stop: *std.atomic.Value(bool),
    progress: *ProducerProgress,
) !ProducerStats {
    return switch (config.test_mode) {
        .linear => produceOrderedLedgerPackets(
            blockstore,
            config,
            .forward,
            writer,
            stop,
            progress,
        ),
        .reverse => produceOrderedLedgerPackets(
            blockstore,
            config,
            .reverse,
            writer,
            stop,
            progress,
        ),
        .shuffle_global => produceGlobalShuffledRefSchedule(
            allocator,
            blockstore,
            config,
            writer,
            stop,
            progress,
        ),
        .shuffle_slot => produceSlotShuffledPackets(
            allocator,
            blockstore,
            config,
            writer,
            stop,
            progress,
        ),
        .drop, .late, .duplicate, .corrupt => produceSelectedShredSchedule(
            blockstore,
            selected_shreds.?,
            config,
            writer,
            stop,
            progress,
        ),
    };
}

fn produceOrderedLedgerPackets(
    blockstore: *const AgaveBlockstore,
    config: Config,
    comptime direction: rocks.IteratorDirection,
    writer: *StreamPacketRing.Iterator(.writer),
    stop: *std.atomic.Value(bool),
    progress: *ProducerProgress,
) !ProducerStats {
    var stats: ProducerStats = .{};
    var unpublished_packets: usize = 0;

    var start_key_buf: [8]u8 = undefined;
    const start_key_slot = switch (direction) {
        .forward => config.start_slot,
        .reverse => config.end_slot,
    };
    const start_key: ?[]const u8 = if (start_key_slot) |slot| start_key: {
        writeSlotKey(&start_key_buf, slot);
        break :start_key start_key_buf[0..];
    } else null;

    var slot_iter = blockstore.db.iterator(
        try blockstore.columnFamily(agave_cf_meta),
        direction,
        start_key,
    );
    defer slot_iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    while (try slot_iter.next(&err_data)) |entry| {
        if (stop.load(.acquire)) break;

        const slot = parseSlotKey(entry[0].data) catch |err| {
            std.debug.print("invalid {s} key length: {d}\n", .{ agave_cf_meta, entry[0].data.len });
            return err;
        };
        if (config.pastSlotRange(slot, direction)) break;
        if (!config.slotSelected(slot)) continue;

        progress.current_slot.store(slot, .release);
        stats.recordSlot();
        progress.store(stats);
        if (direction == .reverse and blockstore.has_code_shred) {
            try produceSlotShreds(
                blockstore,
                slot,
                .code,
                direction,
                writer,
                stop,
                progress,
                &unpublished_packets,
                &stats,
            );
        }
        try produceSlotShreds(
            blockstore,
            slot,
            .data,
            direction,
            writer,
            stop,
            progress,
            &unpublished_packets,
            &stats,
        );
        if (direction == .forward and blockstore.has_code_shred) {
            try produceSlotShreds(
                blockstore,
                slot,
                .code,
                direction,
                writer,
                stop,
                progress,
                &unpublished_packets,
                &stats,
            );
        }
    }

    if (unpublished_packets != 0 and !stop.load(.acquire)) {
        progress.store(stats);
        writer.markUsed();
    }

    progress.store(stats);
    return stats;
}

fn produceGlobalShuffledRefSchedule(
    allocator: Allocator,
    blockstore: *const AgaveBlockstore,
    config: Config,
    writer: *StreamPacketRing.Iterator(.writer),
    stop: *std.atomic.Value(bool),
    progress: *ProducerProgress,
) !ProducerStats {
    var schedule = try buildOrderedRefSchedule(allocator, blockstore, config, stop);
    defer schedule.deinit(allocator);

    var prng = std.Random.DefaultPrng.init(config.seed.?);
    prng.random().shuffleWithIndex(ShredRef, schedule.refs.items, u64);

    return produceRefSchedule(blockstore, &schedule, &.{}, writer, stop, progress);
}

fn produceSlotShuffledPackets(
    allocator: Allocator,
    blockstore: *const AgaveBlockstore,
    config: Config,
    writer: *StreamPacketRing.Iterator(.writer),
    stop: *std.atomic.Value(bool),
    progress: *ProducerProgress,
) !ProducerStats {
    var stats: ProducerStats = .{};
    var unpublished_packets: usize = 0;
    var prng = std.Random.DefaultPrng.init(config.seed.?);

    var start_key_buf: [8]u8 = undefined;
    const start_key: ?[]const u8 = if (config.start_slot) |slot| start_key: {
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
        if (stop.load(.acquire)) break;

        const slot = parseSlotKey(entry[0].data) catch |err| {
            std.debug.print("invalid {s} key length: {d}\n", .{ agave_cf_meta, entry[0].data.len });
            return err;
        };
        if (config.pastEndSlot(slot)) break;
        if (!config.slotSelected(slot)) continue;

        refs.clearRetainingCapacity();
        try collectSlotShredRefs(allocator, blockstore, slot, .data, &refs, stop);
        if (blockstore.has_code_shred) {
            try collectSlotShredRefs(allocator, blockstore, slot, .code, &refs, stop);
        }

        prng.random().shuffleWithIndex(ShredRef, refs.items, u64);

        progress.current_slot.store(slot, .release);
        stats.recordSlot();
        progress.store(stats);

        for (refs.items) |shred_ref| {
            if (stop.load(.acquire)) break;
            try produceShredByRef(
                blockstore,
                shred_ref,
                writer,
                stop,
                progress,
                &unpublished_packets,
                &stats,
            );
        }
    }

    if (unpublished_packets != 0 and !stop.load(.acquire)) {
        progress.store(stats);
        writer.markUsed();
    }

    progress.store(stats);
    return stats;
}

fn buildOrderedRefSchedule(
    allocator: Allocator,
    blockstore: *const AgaveBlockstore,
    config: Config,
    stop: *std.atomic.Value(bool),
) !RefSchedule {
    var schedule: RefSchedule = .{};
    errdefer schedule.deinit(allocator);

    var start_key_buf: [8]u8 = undefined;
    const start_key: ?[]const u8 = if (config.start_slot) |slot| start_key: {
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

    while (try slot_iter.next(&err_data)) |entry| {
        if (stop.load(.acquire)) break;

        const slot = parseSlotKey(entry[0].data) catch |err| {
            std.debug.print("invalid {s} key length: {d}\n", .{ agave_cf_meta, entry[0].data.len });
            return err;
        };
        if (config.pastEndSlot(slot)) break;
        if (!config.slotSelected(slot)) continue;

        schedule.selected_slots += 1;
        try collectSlotShredRefs(allocator, blockstore, slot, .data, &schedule.refs, stop);
        if (blockstore.has_code_shred) {
            try collectSlotShredRefs(allocator, blockstore, slot, .code, &schedule.refs, stop);
        }
    }

    return schedule;
}

fn collectSlotShredRefs(
    allocator: Allocator,
    blockstore: *const AgaveBlockstore,
    slot: Slot,
    kind: ShredKind,
    refs: *std.ArrayList(ShredRef),
    stop: *std.atomic.Value(bool),
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
        if (stop.load(.acquire)) break;

        const key = parseShredKey(entry[0].data) catch |err| {
            std.debug.print(
                "invalid {s} key length: {d}\n",
                .{ kind.columnFamilyName(), entry[0].data.len },
            );
            return err;
        };
        if (key.slot != slot) break;
        try refs.append(
            allocator,
            .{ .slot = key.slot, .index = key.index, .kind = kind },
        );
    }
}

fn buildSelectedShredPlan(
    allocator: Allocator,
    stdout: *std.Io.Writer,
    blockstore: *const AgaveBlockstore,
    config: Config,
    stop: *std.atomic.Value(bool),
) !SelectedShredPlan {
    var plan: SelectedShredPlan = .{
        .schedule = try buildOrderedRefSchedule(allocator, blockstore, config, stop),
    };
    errdefer plan.deinit(allocator);

    plan.eligible_shreds = countEligibleShreds(plan.schedule.refs.items, config.shred_kind);
    plan.selected_ref_indices = try chooseSelectedRefIndices(
        allocator,
        stdout,
        plan.schedule.refs.items,
        config.shred_kind,
        config.selected_count,
        config.seed.?,
    );
    return plan;
}

fn produceSelectedShredSchedule(
    blockstore: *const AgaveBlockstore,
    selected_shreds: *const SelectedShredPlan,
    config: Config,
    writer: *StreamPacketRing.Iterator(.writer),
    stop: *std.atomic.Value(bool),
    progress: *ProducerProgress,
) !ProducerStats {
    const refs = selected_shreds.schedule.refs.items;
    const selected_ref_indices = selected_shreds.selected_ref_indices.items;
    const selected_action = SelectedShredAction.fromTestMode(config.test_mode);
    var prng = std.Random.DefaultPrng.init(config.seed.?);

    var stats: ProducerStats = .{ .slots = selected_shreds.schedule.selected_slots };
    var unpublished_packets: usize = 0;
    var selected_cursor: usize = 0;

    for (refs, 0..) |shred_ref, ref_index| {
        if (stop.load(.acquire)) break;

        const is_selected = consumeSelectedRefIndex(
            selected_ref_indices,
            &selected_cursor,
            ref_index,
        );
        if (is_selected and selected_action == .skip) continue;

        progress.current_slot.store(shred_ref.slot, .release);
        progress.store(stats);

        if (!is_selected) {
            // No special action for this shred, just send it.
            try produceShredByRef(
                blockstore,
                shred_ref,
                writer,
                stop,
                progress,
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
                    stop,
                    progress,
                    &unpublished_packets,
                    &stats,
                );
                try produceShredByRef(
                    blockstore,
                    shred_ref,
                    writer,
                    stop,
                    progress,
                    &unpublished_packets,
                    &stats,
                );
            },
            .send_corrupt => try produceCorruptShredByRef(
                blockstore,
                shred_ref,
                config.corrupt_bytes,
                prng.random(),
                writer,
                stop,
                progress,
                &unpublished_packets,
                &stats,
            ),
        }
    }

    if (unpublished_packets != 0 and !stop.load(.acquire)) {
        progress.store(stats);
        writer.markUsed();
        unpublished_packets = 0;
    }

    if (config.test_mode == .late) {
        for (selected_ref_indices) |index| {
            if (stop.load(.acquire)) break;
            const shred_ref = refs[index];
            progress.current_slot.store(shred_ref.slot, .release);
            progress.store(stats);
            try produceShredByRef(
                blockstore,
                shred_ref,
                writer,
                stop,
                progress,
                &unpublished_packets,
                &stats,
            );
        }

        if (unpublished_packets != 0 and !stop.load(.acquire)) {
            progress.store(stats);
            writer.markUsed();
        }
    }

    progress.store(stats);
    return stats;
}

fn consumeSelectedRefIndex(
    selected_ref_indices: []const usize,
    selected_cursor: *usize,
    ref_index: usize,
) bool {
    if (selected_cursor.* >= selected_ref_indices.len) return false;
    if (selected_ref_indices[selected_cursor.*] != ref_index) return false;
    selected_cursor.* += 1;
    return true;
}

fn countEligibleShreds(refs: []const ShredRef, shred_kind: ShredKindFilter) usize {
    var count: usize = 0;
    for (refs) |shred_ref| {
        if (shred_kind.matches(shred_ref.kind)) count += 1;
    }
    return count;
}

fn chooseSelectedRefIndices(
    allocator: Allocator,
    stdout: *std.Io.Writer,
    refs: []const ShredRef,
    shred_kind: ShredKindFilter,
    count: usize,
    seed: u64,
) !std.ArrayList(usize) {
    var candidates: std.ArrayList(usize) = .empty;
    errdefer candidates.deinit(allocator);

    for (refs, 0..) |shred_ref, ref_index| {
        if (shred_kind.matches(shred_ref.kind)) {
            try candidates.append(allocator, ref_index);
        }
    }

    if (count > candidates.items.len) {
        try stdout.print(
            "--count {d} exceeds {d} eligible {s} shreds\n",
            .{ count, candidates.items.len, shred_kind.kindName() },
        );
        return error.InvalidSelectedShredCount;
    }

    var prng = std.Random.DefaultPrng.init(seed);
    prng.random().shuffleWithIndex(usize, candidates.items, u64);
    candidates.shrinkRetainingCapacity(count);
    std.mem.sortUnstable(usize, candidates.items, {}, std.sort.asc(usize));
    return candidates;
}

fn produceRefSchedule(
    blockstore: *const AgaveBlockstore,
    schedule: *const RefSchedule,
    skip_indices: []const usize,
    writer: *StreamPacketRing.Iterator(.writer),
    stop: *std.atomic.Value(bool),
    progress: *ProducerProgress,
) !ProducerStats {
    var stats: ProducerStats = .{ .slots = schedule.selected_slots };
    var unpublished_packets: usize = 0;
    var skip_cursor: usize = 0;

    for (schedule.refs.items, 0..) |shred_ref, index| {
        if (stop.load(.acquire)) break;
        if (skip_cursor < skip_indices.len and skip_indices[skip_cursor] == index) {
            skip_cursor += 1;
            continue;
        }

        progress.current_slot.store(shred_ref.slot, .release);
        progress.store(stats);
        try produceShredByRef(
            blockstore,
            shred_ref,
            writer,
            stop,
            progress,
            &unpublished_packets,
            &stats,
        );
    }

    if (unpublished_packets != 0 and !stop.load(.acquire)) {
        progress.store(stats);
        writer.markUsed();
    }

    progress.store(stats);
    return stats;
}

fn produceCorruptShredByRef(
    blockstore: *const AgaveBlockstore,
    shred_ref: ShredRef,
    corrupt_bytes: usize,
    random: std.Random,
    writer: *StreamPacketRing.Iterator(.writer),
    stop: *std.atomic.Value(bool),
    progress: *ProducerProgress,
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
        shred_ref.key(),
        shred_ref.kind,
        corrupt_data,
        writer,
        stop,
        progress,
        unpublished_packets,
        stats,
    );
}

fn corruptPacketBytes(packet_data: []u8, corrupt_bytes: usize, random: std.Random) !void {
    if (corrupt_bytes > packet_data.len) return error.CorruptBytesExceedPacket;

    var indices: [max_shred_packet_bytes]usize = undefined;
    for (indices[0..packet_data.len], 0..) |*index, value| {
        index.* = value;
    }
    random.shuffleWithIndex(usize, indices[0..packet_data.len], u64);

    for (indices[0..corrupt_bytes]) |index| {
        const bit_index: u3 = @intCast(random.uintLessThan(u8, 8));
        packet_data[index] ^= @as(u8, 1) << bit_index;
    }
}

fn produceShredByRef(
    blockstore: *const AgaveBlockstore,
    shred_ref: ShredRef,
    writer: *StreamPacketRing.Iterator(.writer),
    stop: *std.atomic.Value(bool),
    progress: *ProducerProgress,
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
        shred_ref.key(),
        shred_ref.kind,
        packet.data,
        writer,
        stop,
        progress,
        unpublished_packets,
        stats,
    );
}

fn publishPacket(
    key: ShredKey,
    kind: ShredKind,
    packet_data: []const u8,
    writer: *StreamPacketRing.Iterator(.writer),
    stop: *std.atomic.Value(bool),
    progress: *ProducerProgress,
    unpublished_packets: *usize,
    stats: *ProducerStats,
) !void {
    if (packet_data.len > max_shred_packet_bytes) return error.ShredPacketTooLarge;

    const out = while (true) {
        if (stop.load(.acquire)) return;
        if (writer.next()) |out| break out;
        if (unpublished_packets.* != 0) {
            writer.markUsed();
            unpublished_packets.* = 0;
            continue;
        }
        _ = progress.full_polls.fetchAdd(1, .monotonic);
        std.atomic.spinLoopHint();
    };

    out.slot = key.slot;
    out.shred_index = key.index;
    out.kind = kind;
    out.len = @intCast(packet_data.len);
    @memcpy(out.data[0..packet_data.len], packet_data);

    stats.recordPacket(kind, packet_data.len);
    unpublished_packets.* += 1;

    if (unpublished_packets.* == producer_publish_packets) {
        progress.store(stats.*);
        writer.markUsed();
        unpublished_packets.* = 0;
    }
}

fn produceSlotShreds(
    blockstore: *const AgaveBlockstore,
    slot: Slot,
    kind: ShredKind,
    comptime direction: rocks.IteratorDirection,
    writer: *StreamPacketRing.Iterator(.writer),
    stop: *std.atomic.Value(bool),
    progress: *ProducerProgress,
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

    var iter = blockstore.db.iterator(
        try blockstore.columnFamily(kind.columnFamilyName()),
        direction,
        start_key_buf[0..],
    );
    defer iter.deinit();

    var err_data: ?rocks.Data = null;
    defer if (err_data) |err| err.deinit();

    // TODO(perf): Use the ipc-ring as backing stable memory for RocksDB shred storage and
    // remove the memcpys here.
    while (try iter.next(&err_data)) |entry| {
        if (stop.load(.acquire)) break;

        const key = parseShredKey(entry[0].data) catch |err| {
            std.debug.print(
                "invalid {s} key length: {d}\n",
                .{ kind.columnFamilyName(), entry[0].data.len },
            );
            return err;
        };
        if (key.slot != slot) break;
        try publishPacket(
            key,
            kind,
            entry[1].data,
            writer,
            stop,
            progress,
            unpublished_packets,
            stats,
        );
    }
    progress.store(stats.*);
}

fn scanSlots(blockstore: *const AgaveBlockstore, config: Config) !SlotStats {
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

fn printShredStats(stdout: *std.Io.Writer, cf_name: []const u8, stats: ShredStats) !void {
    try stdout.print("  {s}:\n", .{cf_name});
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

fn parseSlotKey(key: []const u8) !Slot {
    if (key.len != 8) return error.InvalidSlotKey;
    return std.mem.readInt(u64, key[0..8], .big);
}

fn writeSlotKey(key: *[8]u8, slot: Slot) void {
    std.mem.writeInt(u64, key, slot, .big);
}

fn parseShredKey(key: []const u8) !ShredKey {
    if (key.len != 16) return error.InvalidShredKey;
    return .{
        .slot = std.mem.readInt(u64, key[0..8], .big),
        .index = std.mem.readInt(u64, key[8..16], .big),
    };
}

fn writeShredKey(key: *[16]u8, shred_key: ShredKey) void {
    std.mem.writeInt(u64, key[0..8], shred_key.slot, .big);
    std.mem.writeInt(u64, key[8..16], shred_key.index, .big);
}

fn resolveRocksDbPath(allocator: Allocator, ledger_path: []const u8) ![]const u8 {
    const nested_rocksdb_path = try std.fs.path.join(allocator, &.{ ledger_path, "rocksdb" });

    if (std.fs.cwd().statFile(nested_rocksdb_path)) |stat| {
        if (stat.kind == .directory) return nested_rocksdb_path;
    } else |_| {}
    allocator.free(nested_rocksdb_path);

    if (std.fs.cwd().statFile(ledger_path)) |stat| {
        if (stat.kind == .directory) return try allocator.dupe(u8, ledger_path);
    } else |_| {}

    std.debug.print("ledger path does not exist or is not a directory: {s}\n", .{ledger_path});
    return error.InvalidLedgerPath;
}

const ColumnFamilyNames = struct {
    names: []const []const u8,

    fn deinit(self: *ColumnFamilyNames, allocator: Allocator) void {
        for (self.names) |cf_name| allocator.free(cf_name);
        allocator.free(self.names);
    }

    fn contains(self: *const ColumnFamilyNames, cf_name: []const u8) bool {
        for (self.names) |candidate| {
            if (std.mem.eql(u8, candidate, cf_name)) return true;
        }
        return false;
    }
};

fn listColumnFamilies(allocator: Allocator, rocksdb_path: []const u8) !ColumnFamilyNames {
    const options = rocks_c.rocksdb_options_create() orelse return error.RocksDBOptionsCreate;
    defer rocks_c.rocksdb_options_destroy(options);

    const rocksdb_path_z = try allocator.dupeZ(u8, rocksdb_path);
    defer allocator.free(rocksdb_path_z);

    var err_ptr: ?[*:0]u8 = null;
    var count: usize = 0;
    const raw_names = rocks_c.rocksdb_list_column_families(
        options,
        rocksdb_path_z.ptr,
        &count,
        @ptrCast(&err_ptr),
    );
    if (err_ptr) |err_z| {
        defer rocks_c.rocksdb_free(err_z);
        std.debug.print(
            "failed to list RocksDB column families at {s}: {s}\n",
            .{ rocksdb_path, std.mem.span(err_z) },
        );
        return error.RocksDBListColumnFamilies;
    }
    if (raw_names == null) return error.RocksDBListColumnFamilies;
    defer rocks_c.rocksdb_list_column_families_destroy(raw_names, count);

    const names = try allocator.alloc([]const u8, count);
    var names_len: usize = 0;
    errdefer {
        for (names[0..names_len]) |n| allocator.free(n);
        allocator.free(names);
    }

    for (names, raw_names[0..count]) |*n, raw_name| {
        n.* = try allocator.dupe(u8, std.mem.span(raw_name));
        names_len += 1;
    }

    return .{ .names = names };
}

fn requireColumnFamily(available_cfs: *const ColumnFamilyNames, cf_name: []const u8) !void {
    if (available_cfs.contains(cf_name)) return;
    std.debug.print("missing required column family: {s}\n", .{cf_name});
    return error.MissingRequiredColumnFamily;
}

fn columnFamilyDescriptions(
    allocator: Allocator,
    has_code_shred: bool,
) Allocator.Error![]const rocks.ColumnFamilyDescription {
    const count: usize = if (has_code_shred) 4 else 3;
    const cfs = try allocator.alloc(rocks.ColumnFamilyDescription, count);
    cfs[0] = .{ .name = agave_cf_default };
    cfs[1] = .{ .name = agave_cf_meta };
    cfs[2] = .{ .name = agave_cf_data_shred };
    if (has_code_shred) cfs[3] = .{ .name = agave_cf_code_shred };
    return cfs;
}

fn parseArgs(stdout: *std.Io.Writer, args: []const []const u8) ParseArgsError!ParseResult {
    var config: PartialConfig = .{};
    var seen: std.EnumSet(Arg) = .initEmpty();

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        const parsed_arg = Arg.parse(arg) orelse {
            if (std.mem.startsWith(u8, arg, "-")) {
                try stdout.print("unknown flag: {s}\n", .{arg});
            } else {
                try stdout.print("unexpected argument: {s}\n", .{arg});
            }
            return error.InvalidArguments;
        };

        if (parsed_arg == .help) return .help;

        if (seen.contains(parsed_arg)) {
            try stdout.print("duplicate argument: {s}\n", .{parsed_arg.flagName()});
            return error.InvalidArguments;
        }
        seen.insert(parsed_arg);

        switch (parsed_arg) {
            .help => unreachable,
            .ledger => config.ledger = try nextValue(stdout, args, &i, parsed_arg.flagName()),
            .target => config.target = try nextValue(stdout, args, &i, parsed_arg.flagName()),
            .start_slot => config.start_slot = try parseSlot(
                stdout,
                try nextValue(stdout, args, &i, parsed_arg.flagName()),
                parsed_arg.flagName(),
            ),
            .end_slot => config.end_slot = try parseSlot(
                stdout,
                try nextValue(stdout, args, &i, parsed_arg.flagName()),
                parsed_arg.flagName(),
            ),
            .rate_hz => config.rate_hz = try parseRateHz(
                stdout,
                try nextValue(stdout, args, &i, parsed_arg.flagName()),
            ),
            .test_mode => config.test_mode = try parseTestMode(
                stdout,
                try nextValue(stdout, args, &i, parsed_arg.flagName()),
            ),
            .seed => config.seed = try parseSeed(
                stdout,
                try nextValue(stdout, args, &i, parsed_arg.flagName()),
            ),
            .count => config.selected_count = try parseSelectedCount(
                stdout,
                try nextValue(stdout, args, &i, parsed_arg.flagName()),
            ),
            .shred_kind => config.shred_kind = try parseShredKind(
                stdout,
                try nextValue(stdout, args, &i, parsed_arg.flagName()),
            ),
            .plan_limit => config.plan_limit = try parsePlanLimit(
                stdout,
                try nextValue(stdout, args, &i, parsed_arg.flagName()),
            ),
            .corrupt_bytes => config.corrupt_bytes = try parseCorruptBytes(
                stdout,
                try nextValue(stdout, args, &i, parsed_arg.flagName()),
            ),
            .dry_run => config.dry_run = true,
        }
    }

    return .{ .config = try config.finalize(stdout) };
}

fn nextValue(
    stdout: *std.Io.Writer,
    args: []const []const u8,
    index: *usize,
    flag: []const u8,
) ParseArgsError![]const u8 {
    if (index.* + 1 >= args.len) {
        try stdout.print("missing value for {s}\n", .{flag});
        return error.InvalidArguments;
    }

    index.* += 1;
    return args[index.*];
}

fn parseSlot(stdout: *std.Io.Writer, value: []const u8, flag: []const u8) ParseArgsError!Slot {
    return std.fmt.parseUnsigned(Slot, value, 10) catch {
        try stdout.print("invalid slot for {s}: {s}\n", .{ flag, value });
        return error.InvalidArguments;
    };
}

fn parseRateHz(stdout: *std.Io.Writer, value: []const u8) ParseArgsError!f64 {
    const rate_hz = std.fmt.parseFloat(f64, value) catch {
        try stdout.print("invalid rate for --rate-hz: {s}\n", .{value});
        return error.InvalidArguments;
    };

    if (!(rate_hz > 0) or !std.math.isFinite(rate_hz)) {
        try stdout.print("--rate-hz must be a finite positive value\n", .{});
        return error.InvalidArguments;
    }

    return rate_hz;
}

fn parseTestMode(stdout: *std.Io.Writer, value: []const u8) ParseArgsError!TestMode {
    return TestMode.parse(value) orelse {
        try stdout.print("invalid test mode for --test-mode: {s}\n", .{value});
        try stdout.print(
            "valid test modes: linear, reverse, shuffle-global, shuffle-slot, drop, late, " ++
                "duplicate, corrupt\n",
            .{},
        );
        return error.InvalidArguments;
    };
}

fn parseSeed(stdout: *std.Io.Writer, value: []const u8) ParseArgsError!u64 {
    if (std.mem.startsWith(u8, value, "0x") or std.mem.startsWith(u8, value, "0X")) {
        return std.fmt.parseUnsigned(u64, value[2..], 16) catch {
            try stdout.print("invalid seed for --seed: {s}\n", .{value});
            return error.InvalidArguments;
        };
    }

    return std.fmt.parseUnsigned(u64, value, 10) catch {
        try stdout.print("invalid seed for --seed: {s}\n", .{value});
        return error.InvalidArguments;
    };
}

fn parseSelectedCount(stdout: *std.Io.Writer, value: []const u8) ParseArgsError!usize {
    const selected_count = std.fmt.parseUnsigned(usize, value, 10) catch {
        try stdout.print("invalid count for --count: {s}\n", .{value});
        return error.InvalidArguments;
    };
    if (selected_count == 0) {
        try stdout.print("--count must be greater than zero\n", .{});
        return error.InvalidArguments;
    }
    return selected_count;
}

fn parseShredKind(stdout: *std.Io.Writer, value: []const u8) ParseArgsError!ShredKindFilter {
    return ShredKindFilter.parse(value) orelse {
        try stdout.print("invalid shred kind for --shred-kind: {s}\n", .{value});
        try stdout.print("valid shred kinds: any, data, code\n", .{});
        return error.InvalidArguments;
    };
}

fn parsePlanLimit(stdout: *std.Io.Writer, value: []const u8) ParseArgsError!usize {
    return std.fmt.parseUnsigned(usize, value, 10) catch {
        try stdout.print("invalid limit for --plan-limit: {s}\n", .{value});
        return error.InvalidArguments;
    };
}

fn parseCorruptBytes(stdout: *std.Io.Writer, value: []const u8) ParseArgsError!usize {
    const corrupt_bytes = std.fmt.parseUnsigned(usize, value, 10) catch {
        try stdout.print("invalid byte count for --corrupt-bytes: {s}\n", .{value});
        return error.InvalidArguments;
    };
    if (corrupt_bytes == 0) {
        try stdout.print("--corrupt-bytes must be greater than zero\n", .{});
        return error.InvalidArguments;
    }
    return corrupt_bytes;
}

fn printHelp(stdout: *std.Io.Writer) !void {
    try stdout.print(
        \\usage: shred-stream --ledger <path> --target <ip:port> [options]
        \\
        \\required:
        \\  --ledger <path>       Agave ledger directory or rocksdb directory
        \\  --target <ip:port>    UDP target, usually 127.0.0.1:8002
        \\
        \\options:
        \\  --start-slot <slot>   First slot to stream
        \\  --end-slot <slot>     Inclusive last slot to stream
        \\  --rate-hz <float>     Maximum packets per second
        \\  --test-mode <mode>    linear, reverse, shuffle-global, shuffle-slot, drop, late, duplicate, or corrupt
        \\  --seed <seed>         Decimal or 0x-prefixed seed for randomized test modes
        \\  --count <n>           Number of selected shreds for selected-shred modes (default: 1)
        \\  --shred-kind <kind>   any, data, or code shreds for selected-shred modes (default: any)
        \\  --plan-limit <n>      Maximum affected slots to preview for selected-shred modes (default: 20)
        \\  --corrupt-bytes <n>   Packet bytes to flip per selected shred in corrupt mode (default: 1)
        \\  --dry-run             Read and print stats without sending UDP
        \\  -h, --help            Print this help
        \\
    , .{});
}

var discarding: std.Io.Writer.Discarding = .init(&.{});

test "parse arguments" {
    {
        const result = try parseArgs(
            &discarding.writer,
            &.{ "--ledger", "ledger", "--target", "127.0.0.1:8002" },
        );
        const config = result.config;
        try std.testing.expectEqualStrings("ledger", config.ledger);
        try std.testing.expectEqualStrings("127.0.0.1:8002", config.target);
        try std.testing.expectEqual(@as(?Slot, null), config.start_slot);
        try std.testing.expectEqual(@as(?Slot, null), config.end_slot);
        try std.testing.expectEqual(@as(?f64, null), config.rate_hz);
        try std.testing.expectEqual(.linear, config.test_mode);
        try std.testing.expectEqual(@as(?u64, null), config.seed);
        try std.testing.expectEqual(@as(usize, 1), config.selected_count);
        try std.testing.expectEqual(.any, config.shred_kind);
        try std.testing.expectEqual(@as(usize, 20), config.plan_limit);
        try std.testing.expect(!config.dry_run);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--rate-hz",    "100.5",
            "--test-mode",  "reverse",
            "--dry-run",
        });
        const config = result.config;
        try std.testing.expectEqual(@as(?Slot, 10), config.start_slot);
        try std.testing.expectEqual(@as(?Slot, 20), config.end_slot);
        try std.testing.expectEqual(@as(?f64, 100.5), config.rate_hz);
        try std.testing.expectEqual(.reverse, config.test_mode);
        try std.testing.expectEqual(@as(?u64, null), config.seed);
        try std.testing.expect(config.dry_run);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",    "ledger",
            "--target",    "127.0.0.1:8002",
            "--test-mode", "linear",
        });
        try std.testing.expectEqual(.linear, result.config.test_mode);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--test-mode",  "shuffle-global",
            "--seed",       "0xdeadbeef",
        });
        try std.testing.expectEqual(.shuffle_global, result.config.test_mode);
        try std.testing.expectEqual(@as(?u64, 0xdeadbeef), result.config.seed);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--test-mode",  "shuffle-global",
            "--seed",       "12345",
        });
        try std.testing.expectEqual(@as(?u64, 12345), result.config.seed);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--test-mode",  "shuffle-slot",
            "--seed",       "12345",
        });
        try std.testing.expectEqual(.shuffle_slot, result.config.test_mode);
        try std.testing.expectEqual(@as(?u64, 12345), result.config.seed);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--test-mode",  "drop",
            "--seed",       "12345",
        });
        try std.testing.expectEqual(.drop, result.config.test_mode);
        try std.testing.expectEqual(@as(?u64, 12345), result.config.seed);
        try std.testing.expectEqual(@as(usize, 1), result.config.selected_count);
        try std.testing.expectEqual(.any, result.config.shred_kind);
        try std.testing.expectEqual(@as(usize, 20), result.config.plan_limit);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--test-mode",  "drop",
            "--seed",       "12345",
            "--count",      "2",
            "--shred-kind", "code",
            "--plan-limit", "5",
        });
        try std.testing.expectEqual(.drop, result.config.test_mode);
        try std.testing.expectEqual(@as(usize, 2), result.config.selected_count);
        try std.testing.expectEqual(.code, result.config.shred_kind);
        try std.testing.expectEqual(@as(usize, 5), result.config.plan_limit);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--test-mode",  "late",
            "--seed",       "12345",
            "--count",      "3",
            "--shred-kind", "data",
            "--plan-limit", "0",
        });
        try std.testing.expectEqual(.late, result.config.test_mode);
        try std.testing.expectEqual(@as(?u64, 12345), result.config.seed);
        try std.testing.expectEqual(@as(usize, 3), result.config.selected_count);
        try std.testing.expectEqual(.data, result.config.shred_kind);
        try std.testing.expectEqual(@as(usize, 0), result.config.plan_limit);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",     "ledger",
            "--target",     "127.0.0.1:8002",
            "--start-slot", "10",
            "--end-slot",   "20",
            "--test-mode",  "duplicate",
            "--seed",       "12345",
            "--count",      "4",
            "--shred-kind", "any",
            "--plan-limit", "7",
        });
        try std.testing.expectEqual(.duplicate, result.config.test_mode);
        try std.testing.expectEqual(@as(?u64, 12345), result.config.seed);
        try std.testing.expectEqual(@as(usize, 4), result.config.selected_count);
        try std.testing.expectEqual(.any, result.config.shred_kind);
        try std.testing.expectEqual(@as(usize, 7), result.config.plan_limit);
    }

    {
        const result = try parseArgs(&discarding.writer, &.{
            "--ledger",        "ledger",
            "--target",        "127.0.0.1:8002",
            "--start-slot",    "10",
            "--end-slot",      "20",
            "--test-mode",     "corrupt",
            "--seed",          "12345",
            "--count",         "4",
            "--shred-kind",    "data",
            "--plan-limit",    "7",
            "--corrupt-bytes", "3",
        });
        try std.testing.expectEqual(.corrupt, result.config.test_mode);
        try std.testing.expectEqual(@as(?u64, 12345), result.config.seed);
        try std.testing.expectEqual(@as(usize, 4), result.config.selected_count);
        try std.testing.expectEqual(.data, result.config.shred_kind);
        try std.testing.expectEqual(@as(usize, 7), result.config.plan_limit);
        try std.testing.expectEqual(@as(usize, 3), result.config.corrupt_bytes);
    }

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "shuffle-global",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "shuffle-global",
        "--seed",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "shuffle-slot",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "shuffle-slot",
        "--seed",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "drop",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "late",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "duplicate",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "corrupt",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "drop",
        "--seed",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "late",
        "--seed",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "duplicate",
        "--seed",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "corrupt",
        "--seed",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--seed",       "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--count",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--shred-kind", "data",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--plan-limit", "5",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",        "ledger",
        "--target",        "127.0.0.1:8002",
        "--start-slot",    "10",
        "--end-slot",      "20",
        "--corrupt-bytes", "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",    "ledger",
        "--target",    "127.0.0.1:8002",
        "--test-mode", "reverse",
        "--seed",      "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--test-mode",  "drop",
        "--seed",       "1",
        "--count",      "0",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--test-mode",  "drop",
        "--seed",       "1",
        "--shred-kind", "bad-kind",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--test-mode",  "drop",
        "--seed",       "1",
        "--plan-limit", "not-a-limit",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",        "ledger",
        "--target",        "127.0.0.1:8002",
        "--start-slot",    "10",
        "--end-slot",      "20",
        "--test-mode",     "drop",
        "--seed",          "1",
        "--corrupt-bytes", "1",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",        "ledger",
        "--target",        "127.0.0.1:8002",
        "--start-slot",    "10",
        "--end-slot",      "20",
        "--test-mode",     "corrupt",
        "--seed",          "1",
        "--corrupt-bytes", "0",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",        "ledger",
        "--target",        "127.0.0.1:8002",
        "--start-slot",    "10",
        "--end-slot",      "20",
        "--test-mode",     "corrupt",
        "--seed",          "1",
        "--corrupt-bytes", "not-a-count",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "10",
        "--end-slot",   "20",
        "--test-mode",  "shuffle-global",
        "--seed",       "not-a-seed",
    }));

    try std.testing.expectError(error.InvalidArguments, parseArgs(&discarding.writer, &.{
        "--ledger",     "ledger",
        "--target",     "127.0.0.1:8002",
        "--start-slot", "20",
        "--end-slot",   "10",
    }));
}

test "choose shred target indices" {
    const allocator = std.testing.allocator;
    const refs = [_]ShredRef{
        .{ .slot = 1, .index = 0, .kind = .data },
        .{ .slot = 1, .index = 1, .kind = .code },
        .{ .slot = 1, .index = 2, .kind = .data },
        .{ .slot = 1, .index = 3, .kind = .code },
        .{ .slot = 1, .index = 4, .kind = .data },
    };

    var first = try chooseSelectedRefIndices(allocator, &discarding.writer, &refs, .data, 2, 12345);
    defer first.deinit(allocator);
    var second = try chooseSelectedRefIndices(
        allocator,
        &discarding.writer,
        &refs,
        .data,
        2,
        12345,
    );
    defer second.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 2), first.items.len);
    try std.testing.expectEqualSlices(usize, first.items, second.items);
    for (first.items) |index| {
        try std.testing.expect(refs[index].kind == .data);
    }

    var code = try chooseSelectedRefIndices(allocator, &discarding.writer, &refs, .code, 2, 12345);
    defer code.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), code.items.len);
    for (code.items) |index| {
        try std.testing.expect(refs[index].kind == .code);
    }

    try std.testing.expectError(
        error.InvalidSelectedShredCount,
        chooseSelectedRefIndices(allocator, &discarding.writer, &refs, .code, 3, 12345),
    );
}

test "parse and write slot keys" {
    const key = [_]u8{ 0, 0, 0, 0, 0, 0, 0x04, 0xd2 };
    try std.testing.expectEqual(@as(Slot, 1234), try parseSlotKey(&key));

    var written_key: [8]u8 = undefined;
    writeSlotKey(&written_key, 1234);
    try std.testing.expectEqualSlices(u8, &key, &written_key);

    try std.testing.expectError(error.InvalidSlotKey, parseSlotKey(&.{ 1, 2, 3 }));
}

test "parse and write shred keys" {
    const key = [_]u8{
        0, 0, 0, 0, 0, 0, 0x04, 0xd2,
        0, 0, 0, 0, 0, 0, 0x16, 0x2e,
    };

    const shred_key = try parseShredKey(&key);
    try std.testing.expectEqual(@as(Slot, 1234), shred_key.slot);
    try std.testing.expectEqual(@as(u64, 5678), shred_key.index);

    var written_key: [16]u8 = undefined;
    writeShredKey(&written_key, .{ .slot = 1234, .index = 5678 });
    try std.testing.expectEqualSlices(u8, &key, &written_key);

    try std.testing.expectError(error.InvalidShredKey, parseShredKey(&.{ 1, 2, 3 }));
}

test "slot bounds helpers respect optional bounds" {
    const base: Config = .{ .ledger = "ledger" };
    try std.testing.expect(base.slotSelected(10));
    try std.testing.expect(!base.pastEndSlot(100));

    var bounded = base;
    bounded.start_slot = 10;
    bounded.end_slot = 20;
    try std.testing.expect(!bounded.slotSelected(9));
    try std.testing.expect(bounded.slotSelected(10));
    try std.testing.expect(bounded.slotSelected(20));
    try std.testing.expect(!bounded.slotSelected(21));
    try std.testing.expect(!bounded.pastEndSlot(20));
    try std.testing.expect(bounded.pastEndSlot(21));
}

test "resolve rocksdb path" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("ledger/rocksdb");

    const ledger_path = try tmp.dir.realpathAlloc(std.testing.allocator, "ledger");
    defer std.testing.allocator.free(ledger_path);

    const rocksdb_path = try resolveRocksDbPath(std.testing.allocator, ledger_path);
    defer std.testing.allocator.free(rocksdb_path);

    const expected = try tmp.dir.realpathAlloc(std.testing.allocator, "ledger/rocksdb");
    defer std.testing.allocator.free(expected);

    try std.testing.expectEqualStrings(expected, rocksdb_path);

    const direct_path = try tmp.dir.realpathAlloc(std.testing.allocator, "ledger/rocksdb");
    defer std.testing.allocator.free(direct_path);

    const direct_rocksdb_path = try resolveRocksDbPath(std.testing.allocator, direct_path);
    defer std.testing.allocator.free(direct_rocksdb_path);

    try std.testing.expectEqualStrings(direct_path, direct_rocksdb_path);
}
