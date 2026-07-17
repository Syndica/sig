//! Test topology for shred streaming from a local Agave ledger.
//!
//! This replaces the `net` and `gossip` services with a `shred_streamer`
//! service that reads shreds from a RocksDB-backed Agave ledger and writes
//! them directly into shared memory, feeding the same `shred_receiver` →
//! `replay` pipeline used in the full topology.

const std = @import("std");
const lib = @import("lib");
const services = @import("services");
const tel = lib.telemetry;
const topology = lib.topology;

const Region = topology.Region;
const ServiceRegions = topology.ServiceRegions;

const Topology = struct {
    shred_streamer: ServiceRegions(.from(services.shred_streamer)),
    shred_receiver: ServiceRegions(.from(services.shred_receiver)),
    replay: ServiceRegions(.from(services.replay)),
    snapshot: ServiceRegions(.from(services.snapshot)),
    accounts_db: ServiceRegions(.from(services.accounts_db)),
    exec: ServiceRegions(.from(services.exec)),
    telemetry: ServiceRegions(.from(services.telemetry)),
};

const Config = struct {
    cluster: lib.solana.Cluster,
    leader_schedule_file: []const u8,
    shred_version: u16,

    shred_streamer: ShredStreamer,
    telemetry: Telemetry,
    snapshot: Snapshot,
    accounts_db: AccountsDb,

    const ShredStreamer = struct {
        ledger: []const u8,
        start_slot: ?u64 = null,
        end_slot: ?u64 = null,
        rate_hz: ?f64 = null,
        test_mode: lib.shred.StreamerConfig.TestMode = .linear,
        seed: ?u64 = null,
        selected_count: u32 = 1,
        shred_kind: lib.shred.StreamerConfig.ShredKindFilter = .any,
        plan_limit: u32 = 20,
        corrupt_bytes: u32 = 1,
        dry_run: bool = false,
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

        const parsed = std.zon.parse.fromSlice(Config, allocator, cfg_str, &diag, .{}) catch |err| {
            std.log.err("{f}", .{diag});
            return err;
        };

        try tel.log.Filter.parseListAndWriteBinary(
            &log_filters.writer,
            parsed.telemetry.log_level,
            log_filters_str_opt orelse "",
        );

        break :cfg parsed;
    };
    defer std.zon.parse.free(allocator, config);

    // -- Create + initialise shared memory regions -- //

    // Shred streamer config
    var streamer_config: Region(lib.shred.StreamerConfig) = try .simple();
    const sc = streamer_config.ptr();
    const ledger = config.shred_streamer.ledger;
    @memcpy(sc.ledger_path[0..ledger.len], ledger);
    sc.ledger_path_len = @intCast(ledger.len);
    sc.has_start_slot = config.shred_streamer.start_slot != null;
    sc.start_slot = config.shred_streamer.start_slot orelse 0;
    sc.has_end_slot = config.shred_streamer.end_slot != null;
    sc.end_slot = config.shred_streamer.end_slot orelse 0;
    sc.has_rate_hz = config.shred_streamer.rate_hz != null;
    sc.rate_hz = config.shred_streamer.rate_hz orelse 0;
    sc.test_mode = config.shred_streamer.test_mode;
    sc.has_seed = config.shred_streamer.seed != null;
    sc.seed = config.shred_streamer.seed orelse 0;
    sc.selected_count = config.shred_streamer.selected_count;
    sc.shred_kind = config.shred_streamer.shred_kind;
    sc.plan_limit = config.shred_streamer.plan_limit;
    sc.corrupt_bytes = config.shred_streamer.corrupt_bytes;
    sc.dry_run = config.shred_streamer.dry_run;

    // Shred receiver config (leader schedule + shred version)
    const schedule_file = try std.fs.cwd().openFile(config.leader_schedule_file, .{});
    defer schedule_file.close();
    var reader_buf: [4096]u8 = undefined;
    var reader = schedule_file.reader(&reader_buf);

    var shred_recv_config: Region(lib.shred.RecvConfig) = try .simple();
    const recv_data = shred_recv_config.ptr();
    try lib.solana.LeaderSchedule.fromCommand(&recv_data.leader_schedule, &reader.interface);
    recv_data.shred_version = config.shred_version;

    // Snapshot config
    var snapshot_config: Region(lib.snapshot.SnapshotConfig) = try .simple();
    try populateSnapshotConfig(snapshot_config.ptr(), config.snapshot, config.cluster);

    // Accounts DB config
    var accounts_db_config: Region(lib.accounts_db.RootedConfig) = try .sized(
        @sizeOf(lib.accounts_db.RootedConfig) + config.accounts_db.rooted.toBytes(),
    );
    accounts_db_config.ptr().file_len = @intCast(config.accounts_db.file.len);
    @memcpy(
        accounts_db_config.ptr().file_path[0..accounts_db_config.ptr().file_len],
        config.accounts_db.file,
    );
    accounts_db_config.ptr().memory_len = config.accounts_db.rooted.toBytes();

    // net.Pair for shred_streamer → shred_receiver (no real UDP port)
    const net_to_shred_params: lib.net.Pair.InitParams = .{ .port = 0 };
    var net_to_shred: Region(lib.net.Pair) = try .sized(net_to_shred_params.size());
    net_to_shred_params.init(net_to_shred.ptr());

    // Snapshot source ring (normally from gossip, but we still need it for snapshot service)
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

    // Telemetry: count all non-telemetry services that share the telemetry region
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

    // -- Spawn topology -- //

    var children: topology.Children(Topology) = undefined;
    try children.spawn(.threaded, .{
        .shred_streamer = .{
            .ro = .{ .config = streamer_config.finish() },
            .rw = .{
                .tvu_socket = net_to_shred.finish(),
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
        .exec = .{
            .ro = .{
                .replay_transaction_pool = transaction_pool.finish(),
                .block_pool = block_pool.finish(),
            },
            .rw = .{ .exec_req_response = exec_req_response.finish() },
        },
        .telemetry = .{
            .ro = .{},
            .rw = .{ .region = telemetry_region.finish() },
        },
    });
    try children.wait(null);
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
        data.known_validators_allow_all = true;
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
