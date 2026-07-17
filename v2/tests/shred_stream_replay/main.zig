//! Topology launcher for offline shred stream replay.
//!
//! Streams raw shreds from an Agave ledger through the shred_receiver service
//! without requiring the net or gossip services.
//!
//! Usage:
//!   bbt-shred-stream-replay --ledger <path> [--start-slot N] [--end-slot N] [--rate-hz F] ...
//!
//! All CLI arguments are passed through to the shred_streamer service via shared memory.
//! Build with -Ddebug-skip-shred-sig-verify -Ddebug-skip-shred-version-check for testing
//! without a leader schedule.

const std = @import("std");
const lib = @import("lib");
const services = @import("services");
const tel = lib.telemetry;
const topology = lib.topology;

const Region = topology.Region;

const Topology = struct {
    shred_streamer: topology.ServiceRegions(.from(services.shred_streamer)),
    shred_receiver: topology.ServiceRegions(.from(services.shred_receiver)),
    telemetry: topology.ServiceRegions(.from(services.telemetry)),
};

pub fn main() !void {
    var dba_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dba_state.deinit();
    const gpa = dba_state.allocator();

    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);

    // -- Populate shred_streamer config from CLI args -- //

    var streamer_config: Region(lib.shred_streamer.Config) = try .simple();
    const config_ptr = streamer_config.ptr();
    config_ptr.populate(argv[1..]) catch {
        std.debug.print("error: CLI args too long (max {d} bytes)\n", .{lib.shred_streamer.Config.max_args_len});
        return error.ArgsTooLong;
    };

    // Parse --start-slot from args for RuntimeMetadata pre-population
    const start_slot = parseStartSlot(argv[1..]);

    // -- Create shared memory regions -- //

    // net.Pair: connects shred_streamer (writer) → shred_receiver (reader)
    const net_pair_params: lib.net.Pair.InitParams = .{ .port = 0 };
    var net_to_shred: Region(lib.net.Pair) = try .sized(net_pair_params.size());
    net_pair_params.init(net_to_shred.ptr());

    // shred.RecvConfig: relies on -Ddebug-skip-shred-sig-verify for now
    var shred_recv_config: Region(lib.shred.RecvConfig) = try .simple();
    shred_recv_config.ptr().shred_version = 0;
    // leader_schedule is zeroed — works with debug build flags

    // DeshredRing: output of shred_receiver — must be drained by this launcher
    var deshred_ring: Region(lib.shred.DeshredRing) = try .simple();
    deshred_ring.ptr().init();

    // Get local mapping BEFORE finish() so we can drain it in the wait loop.
    // Without draining, shred_receiver panics when the ring fills up.
    const deshred_ptr = try deshred_ring.memfd.mmapStaticSize(.rw, lib.shred.DeshredRing, .{});
    defer std.posix.munmap(@ptrCast(deshred_ptr));

    // RuntimeMetadata: pre-populate slot so shred_receiver doesn't block
    var snapshot_metadata: Region(lib.accounts_db.RuntimeMetadata) = try .simple();
    snapshot_metadata.ptr().init();
    snapshot_metadata.ptr().populateSlot(start_slot);

    // Telemetry: service_count = 2 (shred_streamer + shred_receiver call signalReady)
    const telemetry_params: tel.Region.InitParams = .{
        .port = 0,
        .log_filters_encoded = tel.log.Filter.parseListStrLitIntoBinary(.info, "").?,
        .service_count = 2,
        .id_mem_len = 4096 * 16,
        .gauges_len = 4096 * 2,
        .histogram_data_len = 4096 * 3,
    };
    var telemetry_region: Region(tel.Region) = try .sized(telemetry_params.info().regionSize());
    telemetry_region.ptr().init(telemetry_params);

    // -- Spawn services -- //

    var children: topology.Children(Topology) = undefined;
    try children.spawn(.threaded, .{
        .shred_streamer = .{
            .ro = .{ .config = streamer_config.finish() },
            .rw = .{
                .shred_pair = net_to_shred.finish(),
                .tel = telemetry_region.finish(),
            },
        },
        .shred_receiver = .{
            .ro = .{ .config = shred_recv_config.finish() },
            .rw = .{
                .snapshot_metadata = snapshot_metadata.finish(),
                .tvu_socket = net_to_shred.finish(),
                .deshredded_out = deshred_ring.finish(),
                .tel = telemetry_region.finish(),
            },
        },
        .telemetry = .{
            .ro = .{},
            .rw = .{ .region = telemetry_region.finish() },
        },
    });

    // -- Wait loop: drain DeshredRing to prevent shred_receiver panic -- //

    var deshred_reader = deshred_ptr.get(.reader);
    while (children.isActive()) {
        while (deshred_reader.next()) |_| {}
        deshred_reader.markUsed();
        std.atomic.spinLoopHint();
    }

    children.cancel();
    try children.wait(5 * std.time.ns_per_s);
}

/// Quick scan of args for --start-slot value (for pre-populating RuntimeMetadata).
fn parseStartSlot(args: []const []const u8) u64 {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--start-slot")) {
            if (i + 1 < args.len) {
                return std.fmt.parseUnsigned(u64, args[i + 1], 10) catch 0;
            }
        }
    }
    return 0;
}
