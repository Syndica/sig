//! Streams raw shreds from an Agave ledger into the shred_receiver via IPC ring.
//!
//! This service reads shreds from a RocksDB-backed Agave ledger and writes them
//! as net.Packet structs into the net.Pair.recv ring — the same interface that
//! the net service uses. The shred_receiver reads from this ring unchanged.
//!
//! All 8 test modes are supported: linear, reverse, shuffle-global, shuffle-slot,
//! drop, late, duplicate, and corrupt.
//!
//! Configuration is passed via shared memory as a CLI args string (see
//! lib.shred_streamer.Config). The service parses the args on startup.

const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tracy = @import("tracy");
const services = @import("services");
const shred_stream = @import("shred_stream");

comptime {
    _ = start;
}

pub const name = .shred_streamer;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = services.shred_streamer.ReadOnly;
pub const ReadWrite = services.shred_streamer.ReadWrite;

const Config = shred_stream.Config;

// ---------------------------------------------------------------------------
// Service entry point
// ---------------------------------------------------------------------------

/// Service entry point — supports all 8 test modes.
///
/// Changes from the standalone CLI tool:
/// - Reads CLI args from shared memory (ro.config) instead of std.process.argsAlloc
/// - Writes net.Packet to the IPC ring (rw.shred_pair.recv) instead of UDP sendto
/// - Single-threaded: no net thread or monitor thread (rate limiting is inline)
/// - Uses cooperative scheduling (signalIdleSpinning) for back-pressure and shutdown
/// - --dry-run is rejected (not meaningful for in-topology streaming)
pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
    const zone = tracy.Zone.init(@src(), .{ .name = @tagName(name) });
    defer zone.deinit();

    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    var discard_writer: std.Io.Writer.Discarding = .init(&.{});

    const config: Config = cfg: {
        if (ro.config.getRawArgs()) |args_str| {
            // Fallback: raw CLI args string — parse them.
            var arg_ptrs: [64][]const u8 = undefined;
            var arg_count: usize = 0;
            var iter = std.mem.splitScalar(u8, args_str, ' ');
            while (iter.next()) |arg| {
                if (arg.len == 0) continue;
                if (arg_count >= arg_ptrs.len) {
                    logger.err().logf("too many CLI args (max {d})", .{arg_ptrs.len});
                    return error.InvalidArguments;
                }
                arg_ptrs[arg_count] = arg;
                arg_count += 1;
            }

            const parse_result = shred_stream.parseArgs(&discard_writer.writer, arg_ptrs[0..arg_count]) catch |err| {
                logger.err().logf("failed to parse args: {}", .{err});
                return err;
            };

            break :cfg switch (parse_result) {
                .help => {
                    logger.info().logf("help requested, going idle", .{});
                    while (true) try runner.activity.signalIdleSpinning();
                },
                .config => |c| c,
            };
        } else {
            const ipc = ro.config;
            break :cfg .{
                .ledger = ipc.getLedger(),
                .start_slot = if (ipc.has_start_slot) ipc.start_slot else null,
                .end_slot = if (ipc.has_end_slot) ipc.end_slot else null,
                .rate_hz = if (ipc.has_rate_hz) ipc.rate_hz else null,
                .test_mode = @enumFromInt(@intFromEnum(ipc.test_mode)),
                .seed = if (ipc.has_seed) ipc.seed else null,
                .selected_count = ipc.selected_count,
                .shred_kind = @enumFromInt(@intFromEnum(ipc.shred_kind)),
                .plan_limit = ipc.plan_limit,
                .corrupt_bytes = ipc.corrupt_bytes,
                .dry_run = ipc.dry_run,
            };
        }
    };

    // Reject --dry-run: doesn't make sense for in-topology streaming.
    if (config.dry_run) {
        logger.err().logf("--dry-run is not supported in the in-topology service", .{});
        return error.InvalidArguments;
    }

    logger.info().logf("streaming from ledger: {s}", .{config.ledger});
    logger.info().logf("test mode: {s}", .{config.test_mode.modeName()});

    // Open blockstore
    var blockstore = shred_stream.AgaveBlockstore.open(gpa, config.ledger) catch |err| {
        logger.err().logf("failed to open blockstore: {}", .{err});
        return err;
    };
    defer blockstore.deinit(gpa);

    // Build selected-shred plan if needed (drop/late/duplicate/corrupt modes).
    var selected_shreds: ?shred_stream.SelectedShredPlan = null;
    defer if (selected_shreds) |*plan| plan.deinit(gpa);
    if (config.test_mode.usesSelectedShreds()) {
        selected_shreds = shred_stream.buildSelectedShredPlan(
            gpa,
            &discard_writer.writer,
            &blockstore,
            config,
            &ServiceCancelAdapter{ .runner = runner },
        ) catch |err| {
            logger.err().logf("failed to build selected shred plan: {}", .{err});
            return err;
        };
    }

    // Stream shreds to ring using generic producers.
    var writer = rw.shred_pair.recv.get(.writer);
    var ctx = ServicePacketContext{
        .runner = runner,
        .rate_hz = config.rate_hz,
    };

    logger.info().logf(
        "starting iteration: start_slot={?d} end_slot={?d}",
        .{ config.start_slot, config.end_slot },
    );

    const stats = shred_stream.produceLedgerPackets(
        gpa,
        &blockstore,
        config,
        if (selected_shreds) |*plan| plan else null,
        &writer,
        &ctx,
        &ServiceCancelAdapter{ .runner = runner },
    ) catch |err| {
        logger.err().logf("producer error: {}", .{err});
        return err;
    };

    // Final flush + close
    writer.markUsed();
    writer.view.close();

    logger.info().logf(
        "streaming complete: slots={d} data={d} code={d} bytes={d}",
        .{ stats.slots, stats.data_packets, stats.code_packets, stats.payload_bytes },
    );

    // Idle until canceled
    while (true) try runner.activity.signalIdleSpinning();
}

// ---------------------------------------------------------------------------
// Packet context — abstracts how packets are written to the IPC ring
// ---------------------------------------------------------------------------

/// Context for writing net.Packet to the IPC ring (service mode).
/// Handles back-pressure via cooperative scheduling and inline rate limiting.
const ServicePacketContext = struct {
    runner: lib.runner.Connection,
    rate_hz: ?f64,

    // Rate limiting state
    base_instant: ?std.time.Instant = null,
    next_send_offset_ns: u64 = 0,

    pub fn fillPacket(out: *lib.net.Packet, packet_data: []const u8) void {
        out.len = @intCast(packet_data.len);
        @memcpy(out.data[0..packet_data.len], packet_data);
        out.addr = std.mem.zeroes(std.net.Address);
    }

    pub fn waitForSlot(
        self: *ServicePacketContext,
        writer: *lib.net.Pair.PacketRing.Iterator(.writer),
        unpublished_packets: *usize,
    ) !*lib.net.Packet {
        // Rate limiting
        if (self.rate_hz) |rate| {
            const interval_ns: u64 = @max(1, @as(u64, @intFromFloat(
                @ceil(@as(f64, @floatFromInt(std.time.ns_per_s)) / rate),
            )));
            const now = try std.time.Instant.now();
            const now_offset_ns = if (self.base_instant) |base|
                now.since(base)
            else blk: {
                self.base_instant = now;
                break :blk 0;
            };
            if (now_offset_ns < self.next_send_offset_ns) {
                std.Thread.sleep(self.next_send_offset_ns - now_offset_ns);
            }
            self.next_send_offset_ns = @max(self.next_send_offset_ns, now_offset_ns) + interval_ns;
        }

        // Wait for a writable slot in the ring
        var was_idle = false;
        const result = while (true) {
            if (writer.peek()) |p| break p;
            // Ring full — flush pending writes so reader can drain
            if (unpublished_packets.* != 0) {
                writer.markUsed();
                unpublished_packets.* = 0;
                continue;
            }
            was_idle = true;
            try self.runner.activity.signalIdleSpinning();
        };
        // Re-signal active after recovering from back-pressure idle.
        if (was_idle) try self.runner.activity.signalActive();
        return result;
    }
};

/// Adapter for cancellation checks — used by producers and plan builders.
const ServiceCancelAdapter = struct {
    runner: lib.runner.Connection,

    pub fn isCanceled(self: *const ServiceCancelAdapter) bool {
        self.runner.activity.checkCanceled() catch return true;
        return false;
    }
};
