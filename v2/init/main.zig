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

const std = @import("std");

comptime {
    _ = std.testing.refAllDecls(@This());
}

const lib = @import("lib");
const tracy = @import("tracy");
const services = @import("services");
const tel = lib.telemetry;
const topology = lib.topology;

const Region = topology.Region;
const ServiceRegions = topology.ServiceRegions;

/// Config for Sig, including service-specific configured values.
const Config = struct {
    sandboxing_mode: SandboxingMode,

    cluster: lib.solana.Cluster,

    /// path to a file containing the output of `solana leader-schedule`
    leader_schedule_file: []const u8,

    gossip: Gossip,
    shred_network: ShredNetwork,

    telemetry: Telemetry,

    snapshot: Snapshot,
    accounts_db: AccountsDb,

    const SandboxingMode = enum { sandboxed, threaded };

    const Gossip = struct {
        port: u16,
        advertise_tvu_port: bool,
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

    const AccountsDb = struct {
        file: []const u8,
        rooted: MemorySize,
        unrooted: MemorySize,

        // For nicer initialization of constants (instead of x * 1024 * 1024 * 1024)
        const MemorySize = union(enum) {
            bytes: usize,
            kb: usize,
            mb: usize,
            gb: usize,

            fn toBytes(self: MemorySize) usize {
                return switch (self) {
                    .bytes => |b| b,
                    .kb => |b| b * 1024,
                    .mb => |b| b * 1024 * 1024,
                    .gb => |b| b * 1024 * 1024 * 1024,
                };
            }
        };
    };

    pub fn format(self: Config, writer: *std.Io.Writer) !void {
        try std.zon.stringify.serialize(self, .{ .whitespace = true }, writer);
    }

    fn zonFmt(self: Config, params: ZonFmt.Params) ZonFmt {
        return .{
            .value = self,
            .params = params,
        };
    }

    const ZonFmt = struct {
        value: Config,
        params: Params,

        pub const Params = struct {
            indent_level: u8 = 0,
        };

        pub fn format(self: ZonFmt, w: *std.Io.Writer) std.Io.Writer.Error!void {
            var sz: std.zon.Serializer = .{
                .writer = w,
                .indent_level = self.params.indent_level,
                .options = .{ .whitespace = true },
            };
            var struct_sz = try sz.beginStruct(.{
                .whitespace_style = .{ .wrap = true },
            });

            const FieldEnum = std.meta.FieldEnum(Config);
            inline for (@typeInfo(Config).@"struct".fields) |s_field| {
                try struct_sz.fieldPrefix(s_field.name);
                const field_ptr = &@field(self.value, s_field.name);
                switch (@field(FieldEnum, s_field.name)) {
                    .sandboxing_mode,
                    .cluster,
                    .leader_schedule_file,
                    => try sz.value(field_ptr.*, .{}),
                    // print all structs as mult-line
                    .gossip,
                    .shred_network,
                    .snapshot,
                    .accounts_db,
                    .telemetry,
                    => {
                        var field_struct_sz = try sz.beginStruct(.{
                            .whitespace_style = .{ .wrap = true },
                        });
                        inline for (@typeInfo(s_field.type).@"struct".fields) |s_field_field| {
                            try field_struct_sz.fieldPrefix(s_field_field.name);
                            try sz.value(@field(field_ptr, s_field_field.name), .{});
                        }
                        try field_struct_sz.end();
                    },
                }
            }

            try struct_sz.end();
        }
    };
};

/// Names + region wiring for every service in the runner. One field per service:
/// the field name selects the service to spawn (`svc_main_<name>`); the value is
/// a `ServiceLayout` whose `.ro`/`.rw` fields hold the typed regions matching the
/// service's `ReadOnly`/`ReadWrite` schema in `init/services.zig`.
const Topology = struct {
    net: ServiceRegions(.from(services.net)),
    gossip: ServiceRegions(.from(services.gossip)),
    shred_receiver: ServiceRegions(.from(services.shred_receiver)),
    replay: ServiceRegions(.from(services.replay)),
    snapshot: ServiceRegions(.from(services.snapshot)),
    accounts_db: ServiceRegions(.from(services.accounts_db)),
    telemetry: ServiceRegions(.from(services.telemetry)),
    exec: ServiceRegions(.from(services.exec)),
};

pub fn main() !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "main" });
    defer zone.deinit();

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

    std.log.info("config: {f}", .{config.zonFmt(.{})});

    const gossip_cluster_info: lib.gossip.ClusterInfo =
        try .getFromEcho(config.gossip.port, config.cluster);

    const schedule_file = try std.fs.cwd().openFile(config.leader_schedule_file, .{});
    defer schedule_file.close();
    var reader_buf: [4096]u8 = undefined;
    var reader = schedule_file.reader(&reader_buf);

    // -- Create + initialise shared memory regions -- //

    const gossip_params: lib.gossip.Config.InitParams = .{
        .cluster_info = gossip_cluster_info,
        // TODO: read this from identity file in signer service
        .keypair = .fromKeyPair(.generate()),
        .turbine_recv_port = config.shred_network.recv_port,
        .advertise_tvu_port = config.gossip.advertise_tvu_port,
    };
    var gossip_config: Region(lib.gossip.Config) = try .sized(gossip_params.size());
    gossip_params.init(gossip_config.ptr());

    var shred_recv_config: Region(lib.shred.RecvConfig) = try .simple();
    const shred_recv_data = shred_recv_config.ptr();
    try lib.solana.LeaderSchedule.fromCommand(&shred_recv_data.leader_schedule, &reader.interface);
    shred_recv_data.shred_version = gossip_cluster_info.shred_version;

    var snapshot_config: Region(lib.snapshot.SnapshotConfig) = try .simple();
    try populateSnapshotConfig(snapshot_config.ptr(), config.snapshot, config.cluster);

    var accounts_db_config: Region(lib.accounts_db.RootedConfig) = try .sized(
        @sizeOf(lib.accounts_db.RootedConfig) + config.accounts_db.rooted.toBytes(),
    );
    accounts_db_config.ptr().file_len = @intCast(config.accounts_db.file.len);
    @memcpy(
        accounts_db_config.ptr().file_path[0..accounts_db_config.ptr().file_len],
        config.accounts_db.file,
    );
    accounts_db_config.ptr().memory_len = config.accounts_db.rooted.toBytes();

    const net_to_shred_params: lib.net.Pair.InitParams =
        .{ .port = config.shred_network.recv_port };
    var net_to_shred: Region(lib.net.Pair) = try .sized(net_to_shred_params.size());
    net_to_shred_params.init(net_to_shred.ptr());

    const net_to_gossip_params: lib.net.Pair.InitParams = .{ .port = config.gossip.port };
    var net_to_gossip: Region(lib.net.Pair) = try .sized(net_to_gossip_params.size());
    net_to_gossip_params.init(net_to_gossip.ptr());

    var gossip_source_to_snapshot: Region(lib.snapshot.SnapshotSourceRing) = try .simple();
    gossip_source_to_snapshot.ptr().init();

    var snapshot_ready_to_accounts_db: Region(lib.snapshot.SnapshotData) = try .simple();
    snapshot_ready_to_accounts_db.ptr().init();

    var snapshot_metadata: Region(lib.accounts_db.RuntimeMetadata) = try .simple();
    snapshot_metadata.ptr().init();

    const unrooted_memory = config.accounts_db.unrooted.toBytes();
    var account_pool: Region(lib.accounts_db.AccountPool) =
        try .sized(@sizeOf(lib.accounts_db.AccountPool) + unrooted_memory);
    account_pool.ptr().init(unrooted_memory);

    var replay_scratch: Region([lib.replay.scratch_buffer_size]u8) = try .simple();

    var shreds_to_replay: Region(lib.shred.DeshredRing) = try .simple();
    shreds_to_replay.ptr().init();

    var replay_account_lookups: Region(lib.accounts_db.AccountLookups) = try .simple();
    replay_account_lookups.ptr().init();

    var transaction_pool: Region(lib.replay.TransactionPool) =
        try .sized(lib.replay.TransactionPool.size());
    transaction_pool.ptr().init();

    var block_pool: Region(lib.replay.BlockPool) = try .sized(lib.replay.BlockPool.size());
    block_pool.ptr().init();

    var exec_req_response: Region(lib.replay.ExecReqResponse) = try .simple();
    exec_req_response.ptr().init();

    // The telemetry service owns one share; every other telemetry share belongs to a service
    // that will call signalReady once it has registered its metrics/log stream.
    const telemetry_params: tel.Region.InitParams = .{
        .port = config.telemetry.port,
        .log_filters_encoded = log_filters.written(),
        .service_count = topology.countRegionShares(Topology, tel.Region) - 1,
        .id_mem_len = 4096 * 16,
        .gauges_len = 4096 * 2,
        .histogram_data_len = 4096 * 3,
    };
    var telemetry_region: Region(tel.Region) = try .sized(telemetry_params.info().regionSize());
    telemetry_region.ptr().init(telemetry_params);

    // -- Build the topology and spawn -- //

    const mode: topology.Mode = switch (config.sandboxing_mode) {
        .sandboxed => .sandboxed,
        .threaded => .threaded,
    };

    var children: topology.Children(Topology) = undefined;
    try children.spawn(mode, .{
        .net = .{
            .ro = .{},
            .rw = .{
                .gossip_pair = net_to_gossip.finish(),
                .shred_pair = net_to_shred.finish(),
                .tel = telemetry_region.finish(),
            },
        },
        .gossip = .{
            .ro = .{ .config = gossip_config.finish() },
            .rw = .{
                .net_pair = net_to_gossip.finish(),
                .gossip_to_snapshot = gossip_source_to_snapshot.finish(),
                .tel = telemetry_region.finish(),
            },
        },
        .shred_receiver = .{
            .ro = .{ .config = shred_recv_config.finish() },
            .rw = .{
                .snapshot_metadata = snapshot_metadata.finish(),
                .tvu_socket = net_to_shred.finish(),
                .deshredded_out = shreds_to_replay.finish(),
                .tel = telemetry_region.finish(),
            },
        },
        .replay = .{
            .ro = .{},
            .rw = .{
                .scratch_memory = replay_scratch.finish(),
                .snapshot_metadata_in = snapshot_metadata.finish(),
                .deshredded_in = shreds_to_replay.finish(),
                .replay_transaction_pool = transaction_pool.finish(),
                .block_pool = block_pool.finish(),
                .exec_req_response = exec_req_response.finish(),
                .account_pool = account_pool.finish(),
                .account_lookups = replay_account_lookups.finish(),
                .tel = telemetry_region.finish(),
            },
        },
        .snapshot = .{
            .ro = .{ .config = snapshot_config.finish() },
            .rw = .{
                .source_from_gossip = gossip_source_to_snapshot.finish(),
                .ready_snapshot_out = snapshot_ready_to_accounts_db.finish(),
                .tel = telemetry_region.finish(),
            },
        },
        .accounts_db = .{
            .ro = .{},
            .rw = .{
                .config = accounts_db_config.finish(),
                .ready_snapshot_in = snapshot_ready_to_accounts_db.finish(),
                .snapshot_metadata_out = snapshot_metadata.finish(),
                .account_pool = account_pool.finish(),
                .replay_lookups = replay_account_lookups.finish(),
                .tel = telemetry_region.finish(),
            },
        },
        .telemetry = .{
            .ro = .{},
            .rw = .{ .region = telemetry_region.finish() },
        },
        .exec = .{
            .ro = .{
                .replay_transaction_pool = transaction_pool.finish(),
                .block_pool = block_pool.finish(),
            },
            .rw = .{ .exec_req_response = exec_req_response.finish() },
        },
    });
    try children.wait(null);

    tracy.message("exiting");
}

fn populateSnapshotConfig(
    data: *lib.snapshot.SnapshotConfig,
    cfg: Config.Snapshot,
    cluster: lib.solana.Cluster,
) !void {
    if (cfg.known_validators.len == 0) {
        std.log.err(
            "known_validators must not be empty. Specify validator pubkeys, " ++
                "or \"*\" to opt in to untrusted snapshot sources.",
            .{},
        );
        return error.NoKnownValidators;
    }
    if (cfg.known_validators.len > lib.snapshot.SnapshotConfig.MAX_KNOWN_VALIDATORS) {
        return error.TooManyKnownValidators;
    }

    @memcpy(data.folder_buffer[0..cfg.folder.len], cfg.folder);
    data.folder_len = @intCast(cfg.folder.len);
    data.cluster = cluster;

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
}
