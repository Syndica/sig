//! This is the root process, in charge of initialising and spawning all services.
//!
//! Responsibilities:
//!  - Parsing config
//!  - Creation of shared memory regions
//!  - Initialising shared data structures / passing through config
//!  - Creating sandboxed processes (unsandboxed single-process also supported for e.g. profiling)
//!  - Waiting for first service failure, and shutdown
//!
//! See `services` for how this works.
//!

const std = @import("std");

comptime {
    _ = std.testing.refAllDecls(@This());
}

const services = @import("services.zig");
const lib = @import("lib");
const tel = lib.telemetry;

const Config = struct {
    sandboxing_mode: SandboxingMode,

    cluster: lib.solana.Cluster,

    /// path to a file containing the output of `solana leader-schedule`
    leader_schedule_file: []const u8,

    gossip: Gossip,
    shred_network: ShredNetwork,

    snapshot: Snapshot,
    telemetry: Telemetry,

    const SandboxingMode = enum { sandboxed, threaded };

    const Gossip = struct {
        port: u16,
    };

    const ShredNetwork = struct {
        recv_port: u16,
    };

    const Telemetry = struct {
        port: u16,
        log_level: tel.log.Level,
    };

    const Snapshot = struct {
        folder: []const u8,
        known_validators: []const []const u8,
    };

    pub fn format(self: Config, writer: *std.Io.Writer) !void {
        try std.zon.stringify.serialize(self, .{ .whitespace = true }, writer);
    }
};

pub fn main() !void {
    var dba_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dba_state.deinit();
    const allocator = dba_state.allocator();

    var log_filters: std.Io.Writer.Allocating = .init(allocator);
    defer log_filters.deinit();

    const config: Config = cfg: {
        var args = std.process.args();
        _ = args.next();
        const cfg_path = args.next() orelse return error.ConfigPathMissing;
        const log_filters_str_opt = args.next();

        const cfg_file = try std.fs.cwd().openFile(cfg_path, .{});
        defer cfg_file.close();

        const cfg_str = try cfg_file.readToEndAllocOptions(allocator, 1024 * 1024, null, .@"1", 0);
        defer allocator.free(cfg_str);

        var diag: std.zon.parse.Diagnostics = .{};
        defer diag.deinit(allocator);

        const config = std.zon.parse.fromSlice(Config, allocator, cfg_str, &diag, .{}) catch |err| {
            std.log.err("{f}", .{diag});
            return err;
        };

        try tel.log.Filter.parseListAndWriteBinary(
            &log_filters.writer,
            config.telemetry.log_level,
            log_filters_str_opt orelse "",
        );

        break :cfg config;
    };
    defer std.zon.parse.free(allocator, config);

    std.log.info("config: {f}", .{config});

    const gossip_cluster_info: lib.gossip.ClusterInfo =
        try .getFromEcho(config.gossip.port, config.cluster);

    const schedule_file = try std.fs.cwd().openFile(config.leader_schedule_file, .{});
    defer schedule_file.close();
    var reader_buf: [4096]u8 = undefined;
    var reader = schedule_file.reader(&reader_buf);

    const service_instances: []const services.ServiceInstance = &.{
        .{ .service = .shred_receiver },
        .{ .service = .net },
        .{ .service = .gossip },
        .{ .service = .replay },
        .{ .service = .snapshot },
        .{ .service = .telemetry },
    };

    const shared_regions = services.toSharedRegions(.{
        // net -> shred
        .net_to_shred = .{ .port = config.shred_network.recv_port },
        // shred constants
        .shred_recv_config = .{
            .schedule_string = &reader.interface,
            .shred_version = gossip_cluster_info.shred_version,
        },

        // net -> gossip
        .net_to_gossip = .{ .port = config.gossip.port },
        // gossip constants
        .gossip_config = .{
            .cluster_info = gossip_cluster_info,
            // TODO: read this from identity file in signer service
            .keypair = .fromKeyPair(.generate()),
            .turbine_recv_port = config.shred_network.recv_port,
        },

        .snapshot_config = .{
            .folder_path = config.snapshot.folder,
            .cluster = config.cluster,
            .known_validators = config.snapshot.known_validators,
        },

        .gossip_to_snapshot = {},

        // shred receiver -> replay
        .deshredded_out = {},

        .telemetry = .{
            .port = config.telemetry.port,
            .log_filters_encoded = log_filters.written(),
            .service_count = services.telemetryServiceCount(service_instances),

            .id_mem_len = 4096 * 16,
            .gauges_len = 4096 * 2,

            .histogram_data_len = 4096 * 3,
        },
    });

    switch (config.sandboxing_mode) {
        .sandboxed => try services.spawnAndWait(
            allocator,
            service_instances,
            &shared_regions,
        ),
        .threaded => try services.spawnAndWaitNoSandbox(
            allocator,
            service_instances,
            &shared_regions,
        ),
    }
}
