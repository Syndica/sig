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

    const service_map = try topology.serviceMap(.{
        // gossip constants
        .gossip_config = .{
            .cluster_info = gossip_cluster_info,
            // TODO: read this from identity file in signer service
            .keypair = .fromKeyPair(.generate()),
            .turbine_recv_port = config.shred_network.recv_port,
        },
        // shred constants
        .shred_recv_config = .{
            .schedule_string = &reader.interface,
            .shred_version = gossip_cluster_info.shred_version,
        },
        .snapshot_config = .{
            .folder_path = config.snapshot.folder,
            .cluster = config.cluster,
            .known_validators = config.snapshot.known_validators,
        },

        // shred receiver -> replay
        .shreds_to_replay = {},
        // gossip -(source)-> snapshot
        .gossip_source_to_snapshot = {},

        // net -> gossip
        .net_to_gossip = .{ .port = config.gossip.port },
        // net -> shred
        .net_to_shred = .{ .port = config.shred_network.recv_port },

        .telemetry = .{
            .port = config.telemetry.port,
            .log_filters_encoded = log_filters.written(),
            .service_count = @intCast(
                topology.countTotalBindingShares(.telemetry) - 1,
            ),

            .id_mem_len = 4096 * 16,
            .gauges_len = 4096 * 2,

            .histogram_data_len = 4096 * 3,
        },
    });

    switch (config.sandboxing_mode) {
        .sandboxed => try topology.spawnAndWait(&service_map),
        .threaded => try topology.spawnAndWaitNoSandbox(&service_map),
    }
}

const topology_schema: lib.topology.Schema = .{
    .services = @import("./services.zon"),
};

pub const topology = lib.topology.Bind(topology_schema, Region, .init(.{
    .gossip_config = .initOne(.@"gossip:config"),
    .shred_recv_config = .initOne(.@"shred_receiver:config"),
    .snapshot_config = .initOne(.@"snapshot:config"),

    .gossip_source_to_snapshot = .initMany(&.{
        .@"gossip:source_to_snapshot",
        .@"snapshot:source_from_gossip",
    }),
    .shreds_to_replay = .initMany(&.{
        .@"shred_receiver:deshredded_out",
        .@"replay:deshredded_in",
    }),
    .net_to_gossip = .initMany(&.{
        .@"net:to_gossip",
        .@"gossip:from_net",
    }),
    .net_to_shred = .initMany(&.{
        .@"net:to_shred",
        .@"shred_receiver:from_net",
    }),

    .telemetry = .initMany(&.{
        .@"telemetry:main",
        .@"net:telemetry",
        .@"gossip:telemetry",
        .@"shred_receiver:telemetry",
        .@"snapshot:telemetry",
    }),
}));

pub const Region = union(enum) {
    gossip_config: lib.gossip.Config.InitParams,
    shred_recv_config: struct {
        // TODO: this should not exist - remove once we can open snapshots again
        schedule_string: *std.Io.Reader,
        shred_version: u16,
    },
    snapshot_config: struct {
        folder_path: []const u8,
        cluster: lib.solana.Cluster,
        known_validators: []const []const u8,
    },

    shreds_to_replay,
    gossip_source_to_snapshot,

    net_to_gossip: lib.net.Pair.InitParams,
    net_to_shred: lib.net.Pair.InitParams,

    telemetry: tel.Region.InitParams,

    pub const Tag = @typeInfo(Region).@"union".tag_type.?;

    pub fn size(self: Region) usize {
        return switch (self) {
            .gossip_config => |cfg| cfg.size(),
            .shred_recv_config => @sizeOf(lib.shred.RecvConfig),
            .snapshot_config => @sizeOf(lib.snapshot.SnapshotConfig),

            .shreds_to_replay => @sizeOf(lib.shred.DeshredRing),
            .gossip_source_to_snapshot => @sizeOf(lib.snapshot.SnapshotSourceRing),

            .net_to_gossip,
            .net_to_shred,
            => |cfg| cfg.size(),

            .telemetry => |params| params.info().regionSize(),
        };
    }

    pub fn init(self: Region, buf: []align(std.heap.page_size_min) u8) !void {
        std.log.info("Initialising: {}", .{std.meta.activeTag(self)});

        return switch (self) {
            .gossip_config => |cfg| cfg.init(buf),
            .shred_recv_config => |cfg| {
                std.debug.assert(buf.len == @sizeOf(lib.shred.RecvConfig));
                const data: *lib.shred.RecvConfig = @ptrCast(buf);

                try lib.solana.LeaderSchedule.fromCommand(
                    &data.leader_schedule,
                    cfg.schedule_string,
                );
                data.shred_version = cfg.shred_version;
            },
            .snapshot_config => |cfg| {
                std.debug.assert(buf.len == @sizeOf(lib.snapshot.SnapshotConfig));
                const data: *lib.snapshot.SnapshotConfig = @ptrCast(buf);

                if (cfg.known_validators.len == 0) {
                    std.log.err(
                        "known_validators must not be empty. Specify validator " ++
                            "pubkeys, or \"*\" to opt in to untrusted snapshot sources.",
                        .{},
                    );
                    return error.NoKnownValidators;
                }
                if (cfg.known_validators.len > lib.snapshot.SnapshotConfig.MAX_KNOWN_VALIDATORS) {
                    return error.TooManyKnownValidators;
                }

                @memcpy(data.folder_buffer[0..cfg.folder_path.len], cfg.folder_path);
                data.folder_len = @intCast(cfg.folder_path.len);
                data.cluster = cfg.cluster;

                const has_wildcard = for (cfg.known_validators) |entry| {
                    if (std.mem.eql(u8, entry, "*")) break true;
                } else false;

                if (has_wildcard) {
                    if (cfg.known_validators.len > 1) {
                        std.log.warn(
                            "known_validators contains \"*\" alongside other entries; " ++
                                "\"*\" takes precedence, ignoring the rest.",
                            .{},
                        );
                    }
                    data.known_validators_allow_all = true;
                    // NOTE: we zero out known_validators_len to make it clear that no validator pubkeys were provided.
                    data.known_validators_len = 0;
                } else {
                    data.known_validators_allow_all = false;
                    data.known_validators_len = @intCast(cfg.known_validators.len);
                    for (
                        cfg.known_validators,
                        data.known_validators_buffer[0..cfg.known_validators.len],
                    ) |pkstr, *pkptr| {
                        pkptr.* = lib.solana.Pubkey.parseRuntime(pkstr) catch |err| {
                            std.log.err(
                                "invalid known_validator entry '{s}': {s}",
                                .{ pkstr, @errorName(err) },
                            );
                            return err;
                        };
                    }
                }
            },

            .shreds_to_replay => {
                std.debug.assert(buf.len == @sizeOf(lib.shred.DeshredRing));
                const data: *lib.shred.DeshredRing = @ptrCast(buf);
                data.init();
            },
            .gossip_source_to_snapshot => {
                std.debug.assert(buf.len == @sizeOf(lib.snapshot.SnapshotSourceRing));
                const data: *lib.snapshot.SnapshotSourceRing = @ptrCast(buf);
                data.init();
            },

            .net_to_gossip,
            .net_to_shred,
            => |cfg| cfg.init(buf),

            .telemetry => |params| {
                std.debug.assert(buf.len == params.info().regionSize());
                const data: *tel.Region = @ptrCast(buf);

                data.init(params);
            },
        };
    }
};
