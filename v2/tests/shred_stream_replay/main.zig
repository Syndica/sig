//! Topology launcher for offline replay.
//!
//! Streams raw shreds from an Agave ledger through the full validator pipeline
//! (shred_receiver → replay → exec) with accounts_db and snapshot services,
//! but without networking (net, gossip).
//!
//! This is essentially a full validator minus networking, with shred_streamer
//! replacing the net service as the shred source.
//!
//! Prerequisites:
//!   - A testnet snapshot must already exist on disk in the configured snapshot
//!     folder (e.g., `./validator/snapshot-*.tar.zst`). Without gossip, the
//!     snapshot service cannot discover sources — it will block indefinitely
//!     if no snapshot file is found.
//!   - An Agave ledger (RocksDB) to stream shreds from.
//!
//! Usage:
//!   replay-offline <config.zon> --ledger <path> [--start-slot N] [--end-slot N] ...
//!
//! The first argument is a .zon config file (same format as the main validator,
//! network fields like gossip/shred_network are ignored if present).
//! Remaining arguments are passed through to the shred_streamer service via
//! shared memory. Build with -Ddebug-skip-shred-sig-verify
//! -Ddebug-skip-shred-version-check for testing without a leader schedule.

const std = @import("std");
const lib = @import("lib");
const services = @import("services");
const tel = lib.telemetry;
const topology = lib.topology;

const Region = topology.Region;

/// Config for the offline replay topology. Only declares fields relevant to
/// shred-stream-replay. Unknown fields (e.g., gossip, shred_network) are
/// silently ignored so that the main validator .zon config can be reused.
const Config = struct {
    sandboxing_mode: SandboxingMode = .threaded,

    cluster: lib.solana.Cluster,

    /// Not used in offline mode (leader schedule is skipped with debug flags).
    leader_schedule_file: []const u8 = "",

    telemetry: Telemetry,

    snapshot: Snapshot,
    accounts_db: AccountsDb,

    const SandboxingMode = enum { sandboxed, threaded };

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

/// Full validator topology minus networking. Replaces the net service with
/// shred_streamer, which reads shreds from an Agave ledger on disk.
const Topology = struct {
    shred_streamer: topology.ServiceRegions(.from(services.shred_streamer)),
    shred_receiver: topology.ServiceRegions(.from(services.shred_receiver)),
    replay: topology.ServiceRegions(.from(services.replay)),
    snapshot: topology.ServiceRegions(.from(services.snapshot)),
    accounts_db: topology.ServiceRegions(.from(services.accounts_db)),
    telemetry: topology.ServiceRegions(.from(services.telemetry)),
    exec: topology.ServiceRegions(.from(services.exec)),
};

pub fn main() !void {
    var dba_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dba_state.deinit();
    const allocator = dba_state.allocator();

    // -- Parse arguments -- //

    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    if (argv.len < 2) {
        std.debug.print(
            "usage: replay-offline <config.zon>" ++
                " [shred-streamer-args...]\n\n" ++
                "  <config.zon>  Path to validator config file" ++
                " (same format as main validator).\n" ++
                "                A snapshot must already exist" ++
                " in the configured snapshot folder.\n\n" ++
                "  Remaining arguments are passed to the" ++
                " shred_streamer service:\n" ++
                "    --ledger <path>  Path to Agave ledger\n" ++
                "    --start-slot <N> First slot to stream\n" ++
                "    --end-slot <N>   Last slot to stream\n" ++
                "    --rate-hz <F>    Rate limit in Hz\n",
            .{},
        );
        return error.ConfigPathMissing;
    }

    // -- Parse .zon config -- //

    var log_filters: std.Io.Writer.Allocating = .init(allocator);
    defer log_filters.deinit();

    const config: Config = cfg: {
        const cfg_path = argv[1];
        const cfg_file = std.fs.cwd().openFile(cfg_path, .{}) catch |err| {
            std.debug.print(
                "error: cannot open config file '{s}': {s}\n",
                .{ cfg_path, @errorName(err) },
            );
            return err;
        };
        defer cfg_file.close();

        const cfg_str = try cfg_file.readToEndAllocOptions(allocator, 1024 * 1024, null, .@"1", 0);
        defer allocator.free(cfg_str);

        var diag: std.zon.parse.Diagnostics = .{};
        defer diag.deinit(allocator);

        const c = std.zon.parse.fromSlice(Config, allocator, cfg_str, &diag, .{
            .ignore_unknown_fields = true,
        }) catch |err| {
            std.log.err("{f}", .{diag});
            return err;
        };

        try tel.log.Filter.parseListAndWriteBinary(
            &log_filters.writer,
            c.telemetry.log_level,
            "",
        );

        break :cfg c;
    };
    defer std.zon.parse.free(allocator, config);

    // -- Populate shred_streamer config from remaining CLI args -- //

    var streamer_config: Region(lib.shred_streamer.Config) = try .simple();
    streamer_config.ptr().populate(argv[2..]) catch {
        std.debug.print(
            "error: shred_streamer CLI args too long (max {d} bytes)\n",
            .{lib.shred_streamer.Config.max_args_len},
        );
        return error.ArgsTooLong;
    };

    // -- Create shared memory regions -- //
    // Mirrors v2/init/main.zig, minus gossip/net regions.

    // net.Pair: connects shred_streamer (writer) → shred_receiver (reader).
    // Port 0 because there is no real network socket.
    const net_pair_params: lib.net.Pair.InitParams = .{ .port = 0 };
    var net_to_shred: Region(lib.net.Pair) = try .sized(net_pair_params.size());
    net_pair_params.init(net_to_shred.ptr());

    // shred.RecvConfig: leader_schedule is zeroed — relies on
    // -Ddebug-skip-shred-sig-verify build flag for offline use.
    var shred_recv_config: Region(lib.shred.RecvConfig) = try .simple();
    shred_recv_config.ptr().shred_version = 0;

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

    // gossip_source_to_snapshot: snapshot service expects this in ReadWrite.
    // In offline mode no gossip writes to it — the snapshot service will find
    // an existing snapshot on disk via findExistingSnapshot() instead.
    var gossip_source_to_snapshot: Region(lib.snapshot.SnapshotSourceRing) = try .simple();
    gossip_source_to_snapshot.ptr().init();

    var snapshot_ready_to_accounts_db: Region(lib.snapshot.SnapshotData) = try .simple();
    snapshot_ready_to_accounts_db.ptr().init();

    // RuntimeMetadata: accounts_db will populate slot + blockhash_queue after
    // loading the snapshot. Replay and shred_receiver block on getSlotBlocking()
    // until that happens.
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

    // The telemetry service owns one share; every other telemetry share belongs
    // to a service that will call signalReady once it has registered its
    // metrics/log stream.
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
    // Always threaded: shred_streamer uses RocksDB which cannot be sandboxed.

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

    // Wait for all services to finish their work and go idle.
    // In offline replay the pipeline drains naturally:
    //   shred_streamer → shred_receiver → replay → exec
    // Once every service reports idle, cancel and clean up.
    while (children.isActive()) {
        std.atomic.spinLoopHint();
    }

    children.cancel();
    try children.wait(5 * std.time.ns_per_s);
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
