//! Streams raw shreds from an Agave ledger into the shred_receiver via IPC ring.
//!
//! This service reads shreds from a RocksDB-backed Agave ledger and writes them
//! as net.Packet structs into the net.Pair.recv ring — the same interface that
//! the net service uses. The shred_receiver reads from this ring unchanged.
//!
//! Configuration is passed via shared memory as a strongly-typed struct
//! (see lib.shred_streamer.Config). The topology launcher parses CLI args
//! and populates the IPC config; the service just reads typed fields.

const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tracy = @import("tracy");
const services = @import("services");
const shred_stream = @import("shred_stream");

comptime {
    _ = start;
    // Ensure IPC config enum ordinals match the shred_stream module's enum
    // ordinals. Both are ordered: linear, reverse, shuffle_global,
    // shuffle_slot, drop, late, duplicate, corrupt.
    const IpcMode = lib.shred_streamer.Config.TestMode;
    const StreamMode = shred_stream.config.TestMode;
    for (@typeInfo(IpcMode).@"enum".fields) |f| {
        std.debug.assert(@intFromEnum(@field(StreamMode, f.name)) == f.value);
    }
    const IpcKind = lib.shred_streamer.Config.ShredKindFilter;
    const StreamKind = shred_stream.config.ShredKindFilter;
    for (@typeInfo(IpcKind).@"enum".fields) |f| {
        std.debug.assert(@intFromEnum(@field(StreamKind, f.name)) == f.value);
    }
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

/// Service entry point — reads typed config from IPC and streams shreds to the
/// IPC ring consumed by shred_receiver.
///
/// Only the `.linear` test mode is supported in the in-topology setup at this
/// time. Other modes (drop/late/duplicate/corrupt/shuffle/reverse) are useful
/// for the standalone CLI tool but not for offline replay; they are rejected
/// with a clear error.
pub fn serviceMain(runner: lib.runner.Connection, ro: ReadOnly, rw: ReadWrite) !noreturn {
    const zone = tracy.Zone.init(@src(), .{ .name = @tagName(name) });
    defer zone.deinit();

    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const logger = rw.tel.acquireLogger(@tagName(name), "main");
    rw.tel.signalReady();

    const ipc = ro.config;
    const config: Config = .{
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

    // --dry-run is meaningful for the standalone CLI (which prints stats to
    // stdout); it has no analogue in the in-topology service.
    if (config.dry_run) {
        logger.err().logf("--dry-run is not supported in the in-topology service", .{});
        return error.InvalidArguments;
    }

    logger.info().logf("streaming from ledger: {s}", .{config.ledger});
    logger.info().logf("test mode: {s}", .{config.test_mode.modeName()});

    // Open blockstore. The launcher is responsible for resolving `config.ledger`
    // to the actual rocksdb directory before writing it into the IPC config.
    var blockstore = shred_stream.AgaveBlockstore.open(gpa, config.ledger) catch |err| {
        logger.err().logf("failed to open blockstore at {s}: {}", .{ config.ledger, err });
        return err;
    };
    defer blockstore.deinit(gpa);

    // Build a selected-shred plan for modes that need one (drop/late/duplicate/corrupt).
    // Linear/reverse/shuffle-* don't touch this plan and receive null.
    var selected_shreds: ?shred_stream.config.SelectedShredPlan = null;
    defer if (selected_shreds) |*plan| plan.deinit(gpa);
    if (config.test_mode.usesSelectedShreds()) {
        var discard: std.Io.Writer.Discarding = .init(&.{});
        selected_shreds = shred_stream.buildSelectedShredPlan(
            gpa,
            &discard.writer,
            &blockstore,
            config,
            runner,
        ) catch |err| {
            logger.err().logf("failed to build selected-shred plan: {}", .{err});
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
        runner,
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
///
/// Rate limiting is applied per-packet in `acquirePacketSlot`, mirroring the
/// original standalone script's per-packet rate limiting from its net thread.
const ServicePacketContext = struct {
    runner: lib.runner.Connection,
    rate_hz: ?f64,

    // Rate limiting state
    base_instant: ?std.time.Instant = null,
    next_send_offset_ns: u64 = 0,

    pub fn fillPacket(
        _: *ServicePacketContext,
        out: *lib.net.Packet,
        packet_data: []const u8,
        _: shred_stream.config.ShredKind,
        _: shred_stream.config.ShredKey,
    ) void {
        out.len = @intCast(packet_data.len);
        @memcpy(out.data[0..packet_data.len], packet_data);
        out.addr = .initIp4(.{ 0, 0, 0, 0 }, 0);
    }

    /// Acquires the next writable slot in the IPC ring, with optional rate
    /// limiting. Called once per packet (not per Solana slot). The "slot"
    /// refers to a ring buffer position.
    ///
    /// This mirrors the original script's per-packet rate limiting that ran
    /// on the net thread's send loop.
    pub fn acquirePacketSlot(
        self: *ServicePacketContext,
        writer: *lib.net.Pair.PacketRing.Iterator(.writer),
        unpublished_packets: *usize,
    ) !*lib.net.Packet {
        // Rate limiting (per-packet)
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
        const result = while (true) {
            if (writer.peek()) |p| break p;
            // Ring full — flush pending writes so reader can drain
            if (unpublished_packets.* != 0) {
                writer.markUsed();
                unpublished_packets.* = 0;
                continue;
            }
            try self.runner.activity.signalIdleSpinning();
        };
        try self.runner.activity.signalActive();
        return result;
    }
};
