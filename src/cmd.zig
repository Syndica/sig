const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build-options");
const cli = @import("cli");
const sig = @import("sig.zig");
const config = @import("config.zig");
const tracy = @import("tracy");

const replay = sig.replay;

const ChannelPrintLogger = sig.trace.ChannelPrintLogger;
const ClusterType = sig.core.ClusterType;
const ContactInfo = sig.gossip.ContactInfo;
const FullAndIncrementalManifest = sig.accounts_db.snapshot.FullAndIncrementalManifest;
const GenesisConfig = sig.core.GenesisConfig;
const GeyserWriter = sig.geyser.GeyserWriter;
const GossipService = sig.gossip.GossipService;
const IpAddr = sig.net.IpAddr;
const LeaderSchedule = sig.core.leader_schedule.LeaderSchedule;
const LeaderScheduleCache = sig.core.leader_schedule.LeaderScheduleCache;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SnapshotFiles = sig.accounts_db.snapshot.SnapshotFiles;
const SocketAddr = sig.net.SocketAddr;
const SocketTag = sig.gossip.SocketTag;
const Ledger = sig.ledger.Ledger;

const createGeyserWriter = sig.geyser.core.createGeyserWriter;
const downloadSnapshotsFromGossip = sig.accounts_db.snapshot.downloadSnapshotsFromGossip;
const getShredAndIPFromEchoServer = sig.net.echo.getShredAndIPFromEchoServer;
const getWallclockMs = sig.time.getWallclockMs;
const globalRegistry = sig.prometheus.globalRegistry;
const loadSnapshot = sig.accounts_db.snapshot.load.loadSnapshot;
const servePrometheus = sig.prometheus.servePrometheus;

const Logger = sig.trace.Logger("cmd");

// We set this so that std.log knows not to log .debug level messages
// which libraries we import will use
pub const std_options: std.Options = .{
    // Set the log level to info
    .log_level = .info,
};

fn GpaOrCAllocator(comptime gpa_config: std.heap.DebugAllocatorConfig) type {
    if (builtin.mode == .Debug) {
        return std.heap.DebugAllocator(gpa_config);
    }

    return struct {
        fn deinit(_: @This()) void {}
        inline fn allocator(_: @This()) std.mem.Allocator {
            return std.heap.c_allocator;
        }
    };
}

pub fn main() !void {
    tracy.setThreadName("Main");
    tracy.startupProfiler();
    defer tracy.shutdownProfiler();

    const zone = tracy.Zone.init(@src(), .{ .name = "main" });
    defer zone.deinit();

    var gpa_state: GpaOrCAllocator(.{}) = .{};
    // defer _ = gpa_state.deinit();

    var tracing_gpa = tracy.TracingAllocator{
        .name = "gpa",
        .parent = gpa_state.allocator(),
    };
    const gpa = tracing_gpa.allocator();

    var gossip_gpa_state: GpaOrCAllocator(.{ .stack_trace_frames = 100 }) = .{};
    var tracing_gossip_gpa = tracy.TracingAllocator{
        .name = "gossip gpa",
        .parent = gossip_gpa_state.allocator(),
    };
    // defer _ = gossip_gpa_state.deinit();
    const gossip_gpa = tracing_gossip_gpa.allocator();

    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);

    const parser = cli.Parser(Cmd, Cmd.cmd_info);
    const tty_config = std.io.tty.detectConfig(std.io.getStdOut());
    const stdout = std.io.getStdOut().writer();
    const cmd = try parser.parse(
        gpa,
        "sig",
        tty_config,
        stdout,
        argv[1..],
    ) orelse return;
    defer parser.free(gpa, cmd);

    var current_config: config.Cmd = .{};

    current_config.log_filters = try .parse(gpa, cmd.log_filters);
    defer current_config.log_filters.deinit(gpa);

    current_config.metrics_port = cmd.metrics_port;
    current_config.log_file = cmd.log_file;
    current_config.tee_logs = cmd.tee_logs;

    // If no subcommand was provided, print a friendly header and help information.
    const subcmd = cmd.subcmd orelse {
        // Render the top-level help.
        _ = try parser.parse(gpa, "sig", tty_config, stdout, &.{"--help"});
        return;
    };

    switch (subcmd) {
        .identity => try identity(gpa, current_config),
        .gossip => |params| {
            current_config.shred_version = params.shred_version;
            params.gossip_base.apply(&current_config);
            params.gossip_node.apply(&current_config);
            try gossip(gpa, gossip_gpa, current_config);
        },
        .validator => |params| {
            current_config.shred_version = params.shred_version;
            current_config.leader_schedule_path = params.leader_schedule;
            current_config.vote_account = params.vote_account;
            params.gossip_base.apply(&current_config);
            params.gossip_node.apply(&current_config);
            params.repair.apply(&current_config);
            current_config.shred_network.dump_shred_tracker = params.repair.dump_shred_tracker;
            current_config.accounts_db.snapshot_dir = params.snapshot_dir;
            current_config.genesis_file_path = params.genesis_file_path;
            params.accountsdb_base.apply(&current_config);
            params.accountsdb_download.apply(&current_config);
            params.geyser.apply(&current_config);
            current_config.replay_threads = params.replay_threads;
            current_config.disable_consensus = params.disable_consensus;
            current_config.stop_at_slot = params.stop_at_slot;
            current_config.voting_enabled = params.voting_enabled or params.vote_account != null;
            current_config.rpc_port = params.rpc_port;
            try validator(gpa, gossip_gpa, current_config);
        },
        .replay_offline => |params| {
            current_config.shred_version = params.shred_version;
            current_config.leader_schedule_path = params.leader_schedule;
            params.gossip_base.apply(&current_config);
            params.gossip_node.apply(&current_config);
            params.repair.apply(&current_config);
            current_config.accounts_db.snapshot_dir = params.snapshot_dir;
            current_config.genesis_file_path = params.genesis_file_path;
            params.accountsdb_base.apply(&current_config);
            params.accountsdb_download.apply(&current_config);
            params.geyser.apply(&current_config);
            current_config.replay_threads = params.replay_threads;
            current_config.disable_consensus = params.disable_consensus;
            current_config.stop_at_slot = params.stop_at_slot;
            try replayOffline(gpa, current_config);
        },
        .shred_network => |params| {
            current_config.shred_version = params.shred_version;
            current_config.leader_schedule_path = params.leader_schedule;
            params.gossip_base.apply(&current_config);
            params.gossip_node.apply(&current_config);
            params.repair.apply(&current_config);
            current_config.shred_network.dump_shred_tracker = params.repair.dump_shred_tracker;
            current_config.turbine.overwrite_stake_for_testing =
                params.overwrite_stake_for_testing;
            current_config.shred_network.no_retransmit = params.no_retransmit;
            current_config.accounts_db.snapshot_metadata_only = params.snapshot_metadata_only;
            try shredNetwork(gpa, gossip_gpa, current_config);
        },
        .snapshot_download => |params| {
            current_config.shred_version = params.shred_version;
            current_config.accounts_db.snapshot_dir = params.snapshot_dir;
            params.accountsdb_download.apply(&current_config);
            params.gossip_base.apply(&current_config);
            try downloadSnapshot(gpa, gossip_gpa, current_config);
        },
        .snapshot_validate => |params| {
            current_config.accounts_db.snapshot_dir = params.snapshot_dir;
            current_config.genesis_file_path = params.genesis_file_path;
            params.accountsdb_base.apply(&current_config);
            current_config.gossip.cluster = params.gossip_cluster;
            params.geyser.apply(&current_config);
            try validateSnapshot(gpa, current_config);
        },
        .snapshot_create => |params| {
            // current_config.accounts_db.snapshot_dir = params.snapshot_dir;
            // current_config.genesis_file_path = params.genesis_file_path;
            // try createSnapshot(gpa, current_config);
            _ = params;
            @panic("TODO: support snapshot creation");
        },
        .print_manifest => |params| {
            current_config.accounts_db.snapshot_dir = params.snapshot_dir;
            try printManifest(gpa, current_config);
        },
        .leader_schedule => |params| {
            current_config.shred_version = params.shred_version;
            current_config.leader_schedule_path = params.leader_schedule;
            params.gossip_base.apply(&current_config);
            params.gossip_node.apply(&current_config);
            current_config.accounts_db.snapshot_dir = params.snapshot_dir;
            current_config.genesis_file_path = params.genesis_file_path;
            params.accountsdb_base.apply(&current_config);
            params.accountsdb_download.apply(&current_config);
            try printLeaderSchedule(gpa, current_config);
        },
        .test_transaction_sender => |params| {
            current_config.shred_version = params.shred_version;
            current_config.genesis_file_path = params.genesis_file_path;
            current_config.test_transaction_sender.n_transactions = params.n_transactions;
            current_config.test_transaction_sender.n_lamports_per_transaction =
                params.n_lamports_per_tx;
            params.gossip_base.apply(&current_config);
            params.gossip_node.apply(&current_config);
            try testTransactionSenderService(gpa, gossip_gpa, current_config);
        },
        .mock_rpc_server => |params| {
            params.gossip_base.apply(&current_config);
            params.gossip_node.apply(&current_config);
            current_config.accounts_db.snapshot_dir = params.snapshot_dir;
            current_config.genesis_file_path = params.genesis_file_path;
            params.accountsdb_base.apply(&current_config);
            params.accountsdb_download.apply(&current_config);
            try mockRpcServer(gpa, current_config);
        },
    }
}

const Cmd = struct {
    log_filters: []const u8,
    metrics_port: u16,
    log_file: ?[]const u8,
    tee_logs: bool,
    subcmd: ?union(enum) {
        identity,
        gossip: Gossip,
        validator: Validator,
        replay_offline: Validator,
        shred_network: ShredNetwork,
        snapshot_download: SnapshotDownload,
        snapshot_validate: SnapshotValidate,
        snapshot_create: SnapshotCreate,
        print_manifest: PrintManifest,
        leader_schedule: LeaderScheduleSubCmd,
        test_transaction_sender: TestTransactionSender,
        mock_rpc_server: MockRpcServer,
    },

    const cmd_info: cli.CommandInfo(@This()) = .{
        .help = .{
            .short = std.fmt.comptimePrint(
                \\Version: {}
                \\
                \\Sig is a Solana validator client written in Zig. The project is still a
                \\work in progress so contributions are welcome.
            , .{build_options.version}),
            .long = null,
        },
        .sub = .{
            .subcmd = .{
                .identity = identity_cmd_info,
                .gossip = Gossip.cmd_info,
                .validator = Validator.cmd_info,
                .replay_offline = Validator.cmd_info,
                .shred_network = ShredNetwork.cmd_info,
                .snapshot_download = SnapshotDownload.cmd_info,
                .snapshot_validate = SnapshotValidate.cmd_info,
                .snapshot_create = SnapshotCreate.cmd_info,
                .print_manifest = PrintManifest.cmd_info,
                .leader_schedule = LeaderScheduleSubCmd.cmd_info,
                .test_transaction_sender = TestTransactionSender.cmd_info,
                .mock_rpc_server = MockRpcServer.cmd_info,
            },
            .log_filters = .{
                .kind = .named,
                .name_override = null,
                .alias = .l,
                .default_value = if (builtin.mode == .Debug) "debug" else "info",
                .config = .string,
                .help = "The amount of detail to log.",
            },
            .metrics_port = .{
                .kind = .named,
                .name_override = null,
                .alias = .m,
                .default_value = 12345,
                .config = {},
                .help = "Port to expose prometheus metrics via http",
            },
            .log_file = .{
                .kind = .named,
                .name_override = null,
                .alias = .none,
                .default_value = null,
                .config = .string,
                .help = "Write logs to this file instead of stderr",
            },
            .tee_logs = .{
                .kind = .named,
                .name_override = null,
                .alias = .none,
                .default_value = false,
                .config = {},
                .help =
                \\If --log-file is set, it disables logging to stderr.
                \\Enable this flag to reactivate stderr logging when using --log-file.
                ,
            },
        },
    };

    const shred_version_arg: cli.ArgumentInfo(?u16) = .{
        .kind = .named,
        .name_override = "shred-version",
        .alias = .none,
        .default_value = null,
        .config = {},
        .help = "The shred version for the network",
    };

    const leader_schedule_arg: cli.ArgumentInfo(?[]const u8) = .{
        .kind = .named,
        .name_override = "leader-schedule",
        .alias = .none,
        .default_value = null,
        .config = .string,
        .help = "Set a file path to load the leader schedule. Use '--' to load from stdin",
    };

    const gossip_cluster_arg: cli.ArgumentInfo(?[]const u8) = .{
        .kind = .named,
        .name_override = "cluster",
        .alias = .c,
        .default_value = null,
        .config = .string,
        .help = "cluster to connect to - adds gossip entrypoints, sets default genesis file path",
    };

    const snapshot_dir_arg: cli.ArgumentInfo([]const u8) = .{
        .kind = .named,
        .name_override = "snapshot-dir",
        .alias = .s,
        .default_value = sig.VALIDATOR_DIR ++ "accounts_db",
        .config = .string,
        .help = "path to snapshot directory" ++
            " (where snapshots are downloaded and/or unpacked to/from)" ++
            " - default: {VALIDATOR_DIR}/accounts_db",
    };

    const genesis_file_path_arg: cli.ArgumentInfo(?[]const u8) = .{
        .kind = .named,
        .name_override = "genesis-file-path",
        .alias = .g,
        .default_value = null,
        .config = .string,
        .help = "path to the genesis file." ++
            " defaults to 'data/genesis-files/<network>_genesis.bin' if --network option is set",
    };

    const force_new_snapshot_download_arg: cli.ArgumentInfo(bool) = .{
        .kind = .named,
        .name_override = "force-new-snapshot-download",
        .alias = .none,
        .default_value = false,
        .config = {},
        .help = "force download of new snapshot (usually to get a more up-to-date snapshot)",
    };

    const replay_threads_arg: cli.ArgumentInfo(u16) = .{
        .kind = .named,
        .name_override = "replay-threads",
        .alias = .none,
        .default_value = 4,
        .config = {},
        .help = "Number of threads to use in the replay thread pool. " ++
            "Set to 1 for fully synchronous execution of replay.",
    };

    const disable_consensus_arg: cli.ArgumentInfo(bool) = .{
        .kind = .named,
        .name_override = "disable-consensus",
        .alias = .none,
        .default_value = false,
        .config = {},
        .help = "Disable running consensus in replay.",
    };

    const stop_at_slot_arg: cli.ArgumentInfo(?Slot) = .{
        .kind = .named,
        .name_override = "stop-at-slot",
        .alias = .none,
        .default_value = null,
        .config = {},
        .help = "Stop processing at this slot.",
    };

    const voting_enabled_arg: cli.ArgumentInfo(bool) = .{
        .kind = .named,
        .name_override = "voting-enabled",
        .alias = .none,
        .default_value = false,
        .config = {},
        .help = "Enable validator voting. When false, operate as non-voting.",
    };

    const rpc_port_arg: cli.ArgumentInfo(?u16) = .{
        .kind = .named,
        .name_override = "rpc-port",
        .alias = .none,
        .default_value = null,
        .config = {},
        .help = "Enable the HTTP RPC server on the given TCP port",
    };

    const vote_account_arg: cli.ArgumentInfo(?[]const u8) = .{
        .kind = .named,
        .name_override = "vote-account",
        .alias = .none,
        .default_value = null,
        .config = .string,
        .help = "Base58 string of the vote account's address, or a path to vote account json" ++
            " keypair file. Defaults to sig/vote-account.json in your system's app config folder",
    };

    const GossipArgumentsCommon = struct {
        host: ?[]const u8,
        port: u16,
        entrypoints: []const []const u8,
        network: ?[]const u8,

        const cmd_info: cli.ArgumentInfoGroup(@This()) = .{
            .host = .{
                .kind = .named,
                .name_override = "gossip-host",
                .alias = .none,
                .default_value = null,
                .config = .string,
                .help = "IPv4 address for the validator to advertise in gossip" ++
                    " - default: get from --entrypoint, fallback to 127.0.0.1",
            },
            .port = .{
                .kind = .named,
                .name_override = "gossip-port",
                .alias = .p,
                .default_value = 8001,
                .config = {},
                .help = "The port to run gossip listener",
            },
            .entrypoints = .{
                .kind = .named,
                .name_override = "entrypoint",
                .alias = .e,
                .default_value = &.{},
                .config = .string,
                .help = "gossip address of the entrypoint validators",
            },
            .network = gossip_cluster_arg,
        };

        fn apply(args: @This(), cfg: *config.Cmd) void {
            cfg.gossip.host = args.host;
            cfg.gossip.port = args.port;
            cfg.gossip.entrypoints = args.entrypoints;
            cfg.gossip.cluster = args.network;
        }
    };
    const GossipArgumentsNode = struct {
        spy_node: bool,
        dump: bool,

        const cmd_info: cli.ArgumentInfoGroup(@This()) = .{
            .spy_node = .{
                .kind = .named,
                .name_override = "spy-node",
                .alias = .none,
                .default_value = false,
                .config = {},
                .help = "run as a gossip spy node (minimize outgoing packets)",
            },
            .dump = .{
                .kind = .named,
                .name_override = "dump-gossip",
                .alias = .none,
                .default_value = false,
                .config = {},
                .help = "periodically dump gossip table to csv files and logs",
            },
        };

        fn apply(args: @This(), cfg: *config.Cmd) void {
            cfg.gossip.spy_node = args.spy_node;
            cfg.gossip.dump = args.dump;
        }
    };

    const AccountsDbArgumentsBase = struct {
        use_disk_index: bool,
        n_threads_snapshot_load: u32,
        n_threads_snapshot_unpack: u16,
        force_unpack_snapshot: bool,
        number_of_index_shards: u64,
        accounts_per_file_estimate: u64,
        skip_snapshot_validation: bool,

        const cmd_info: cli.ArgumentInfoGroup(@This()) = .{
            .use_disk_index = .{
                .kind = .named,
                .name_override = null,
                .alias = .none,
                .default_value = false,
                .config = {},
                .help = "use disk-memory for the account index",
            },
            .n_threads_snapshot_load = .{
                .kind = .named,
                .name_override = null,
                .alias = .t,
                .default_value = 0,
                .config = {},
                .help = "number of threads used to initialize the account index - default: ncpus",
            },
            .n_threads_snapshot_unpack = .{
                .kind = .named,
                .name_override = null,
                .alias = .u,
                .default_value = 0,
                .config = {},
                .help = "number of threads to unpack snapshots - default: ncpus * 2",
            },
            .force_unpack_snapshot = .{
                .kind = .named,
                .name_override = null,
                .alias = .f,
                .default_value = false,
                .config = {},
                .help = "unpacks a snapshot (even if it exists)",
            },
            .number_of_index_shards = .{
                .kind = .named,
                .name_override = null,
                .alias = .none,
                .default_value = sig.accounts_db.db.ACCOUNT_INDEX_SHARDS,
                .config = {},
                .help = "number of shards for the account index's pubkey_ref_map",
            },
            .accounts_per_file_estimate = .{
                .kind = .named,
                .name_override = null,
                .alias = .a,
                .default_value = sig.accounts_db.db
                    .getAccountPerFileEstimateFromCluster(.testnet) catch
                    @compileError("account_per_file_estimate missing for default cluster"),
                .config = {},
                .help = "number of accounts to estimate inside of account files" ++
                    " (used for pre-allocation)",
            },
            .skip_snapshot_validation = .{
                .kind = .named,
                .name_override = null,
                .alias = .none,
                .default_value = false,
                .config = {},
                .help = "skip the validation of the snapshot",
            },
        };

        fn apply(args: @This(), cfg: *config.Cmd) void {
            cfg.accounts_db.use_disk_index = args.use_disk_index;
            cfg.accounts_db.num_threads_snapshot_load = args.n_threads_snapshot_load;
            cfg.accounts_db.num_threads_snapshot_unpack = args.n_threads_snapshot_unpack;
            cfg.accounts_db.force_unpack_snapshot = args.force_unpack_snapshot;
            cfg.accounts_db.number_of_index_shards = args.number_of_index_shards;
            cfg.accounts_db.accounts_per_file_estimate = args.accounts_per_file_estimate;
            cfg.accounts_db.skip_snapshot_validation = args.skip_snapshot_validation;
        }
    };
    const AccountsDbArgumentsDownload = struct {
        min_snapshot_download_speed_mb: u64,
        trusted_validators: []const []const u8,

        const cmd_info: cli.ArgumentInfoGroup(@This()) = .{
            .min_snapshot_download_speed_mb = .{
                .kind = .named,
                .name_override = "min-snapshot-download-speed",
                .alias = .none,
                .default_value = 20,
                .config = {},
                .help = "minimum download speed of full snapshots in megabytes per second" ++
                    " - default: 20MB/s",
            },
            .trusted_validators = .{
                .kind = .named,
                .name_override = "trusted-validator",
                .alias = .t,
                .default_value = &.{},
                .config = .string,
                .help = "public key of a validator whose snapshot hash is trusted to be downloaded",
            },
        };

        fn apply(args: @This(), cfg: *config.Cmd) void {
            cfg.accounts_db.min_snapshot_download_speed_mbs = args.min_snapshot_download_speed_mb;
            cfg.gossip.trusted_validators = args.trusted_validators;
        }
    };
    const RepairArgumentsBase = struct {
        turbine_port: u16,
        repair_port: u16,
        test_repair_for_slot: ?Slot,
        max_shreds: u64,
        num_retransmit_threads: ?usize,
        dump_shred_tracker: bool,

        const cmd_info: cli.ArgumentInfoGroup(@This()) = .{
            .turbine_port = .{
                .kind = .named,
                .name_override = null,
                .alias = .none,
                .default_value = 8002,
                .config = {},
                .help = "The port to run turbine shred listener (aka TVU port)",
            },
            .repair_port = .{
                .kind = .named,
                .name_override = null,
                .alias = .none,
                .default_value = 8003,
                .config = {},
                .help = "The port to run shred repair listener",
            },
            .test_repair_for_slot = .{
                .kind = .named,
                .name_override = null,
                .alias = .none,
                .default_value = null,
                .config = {},
                .help =
                \\Set a slot here to repeatedly send repair requests for shreds from this slot
                \\This is only intended for use during short-lived tests of the repair service
                \\Do not set this during normal usage.
                ,
            },
            .num_retransmit_threads = .{
                .kind = .named,
                .name_override = "num-retransmit-threads",
                .alias = .none,
                .default_value = null,
                .config = {},
                .help = "The number of retransmit threads to use for the turbine service" ++
                    " - default: cpu count",
            },
            .max_shreds = .{
                .kind = .named,
                .name_override = "max-shreds",
                .alias = .none,
                .default_value = 5_000_000,
                .config = {},
                .help = "Max number of shreds to store in the ledger",
            },
            .dump_shred_tracker = .{
                .kind = .named,
                .name_override = "dump-shred-tracker",
                .alias = .none,
                .default_value = false,
                .config = {},
                .help = "Create shred-tracker.txt" ++
                    " to visually represent the currently tracked slots.",
            },
        };

        fn apply(args: @This(), cfg: *config.Cmd) void {
            cfg.shred_network.turbine_recv_port = args.turbine_port;
            cfg.shred_network.repair_port = args.repair_port;
            cfg.shred_network.root_slot = args.test_repair_for_slot;
            cfg.turbine.num_retransmit_threads = args.num_retransmit_threads;
            cfg.max_shreds = args.max_shreds;
        }
    };
    const GeyserArgumentsBase = struct {
        enable: bool,
        pipe_path: []const u8,
        writer_fba_bytes: usize,

        const cmd_info: cli.ArgumentInfoGroup(@This()) = .{
            .enable = .{
                .kind = .named,
                .name_override = "enable-geyser",
                .alias = .none,
                .default_value = false,
                .config = {},
                .help = "enable geyser",
            },
            .pipe_path = .{
                .kind = .named,
                .name_override = "geyser-pipe-path",
                .alias = .none,
                .default_value = sig.VALIDATOR_DIR ++ "geyser.pipe",
                .config = .string,
                .help = "path to the geyser pipe",
            },
            .writer_fba_bytes = .{
                .kind = .named,
                .name_override = "geyser-writer-fba-bytes",
                .alias = .none,
                .default_value = 1 << 32, // 4gb
                .config = {},
                .help = "number of bytes to allocate for the geyser writer",
            },
        };

        fn apply(args: @This(), cfg: *config.Cmd) void {
            cfg.geyser.enable = args.enable;
            cfg.geyser.pipe_path = args.pipe_path;
            cfg.geyser.writer_fba_bytes = args.writer_fba_bytes;
        }
    };

    const identity_cmd_info: cli.CommandInfo(void) = .{
        .help = .{
            .short = "Get own identity.",
            .long =
            \\Gets own identity (Pubkey) or creates one if doesn't exist.
            \\
            \\NOTE: Keypair is saved in sig/identity.json in your system's app config folder.
            ,
        },
        .sub = .{},
    };

    const Gossip = struct {
        shred_version: ?u16,
        gossip_base: GossipArgumentsCommon,
        gossip_node: GossipArgumentsNode,

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "Run gossip client.",
                .long = "Start Solana gossip client on specified port.",
            },
            .sub = .{
                .shred_version = shred_version_arg,
                .gossip_base = GossipArgumentsCommon.cmd_info,
                .gossip_node = GossipArgumentsNode.cmd_info,
            },
        };
    };

    const Validator = struct {
        shred_version: ?u16,
        leader_schedule: ?[]const u8,
        vote_account: ?[]const u8,
        gossip_base: GossipArgumentsCommon,
        gossip_node: GossipArgumentsNode,
        repair: RepairArgumentsBase,
        snapshot_dir: []const u8,
        genesis_file_path: ?[]const u8,
        accountsdb_base: AccountsDbArgumentsBase,
        accountsdb_download: AccountsDbArgumentsDownload,
        force_new_snapshot_download: bool,
        geyser: GeyserArgumentsBase,
        replay_threads: u16,
        disable_consensus: bool,
        stop_at_slot: ?sig.core.Slot,
        voting_enabled: bool,
        rpc_port: ?u16,

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "Run Solana validator.",
                .long = "Start a full Solana validator client.",
            },
            .sub = .{
                .shred_version = shred_version_arg,
                .leader_schedule = leader_schedule_arg,
                .vote_account = vote_account_arg,
                .gossip_base = GossipArgumentsCommon.cmd_info,
                .gossip_node = GossipArgumentsNode.cmd_info,
                .repair = RepairArgumentsBase.cmd_info,
                .snapshot_dir = snapshot_dir_arg,
                .genesis_file_path = genesis_file_path_arg,
                .accountsdb_base = AccountsDbArgumentsBase.cmd_info,
                .accountsdb_download = AccountsDbArgumentsDownload.cmd_info,
                .force_new_snapshot_download = force_new_snapshot_download_arg,
                .geyser = GeyserArgumentsBase.cmd_info,
                .replay_threads = replay_threads_arg,
                .disable_consensus = disable_consensus_arg,
                .voting_enabled = voting_enabled_arg,
                .rpc_port = rpc_port_arg,
                .stop_at_slot = stop_at_slot_arg,
            },
        };
    };

    const ShredNetwork = struct {
        shred_version: ?u16,
        leader_schedule: ?[]const u8,
        gossip_base: GossipArgumentsCommon,
        gossip_node: GossipArgumentsNode,
        repair: RepairArgumentsBase,
        /// TODO: Remove when no longer needed
        overwrite_stake_for_testing: bool,
        no_retransmit: bool,
        snapshot_metadata_only: bool,

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "Run the shred network to collect and store shreds.",
                .long =
                \\ This command runs the shred network without running the full validator
                \\ (mainly excluding the accounts-db setup).
                \\
                \\ NOTE: this means that this command *requires* a leader schedule to be provided
                \\ (which would usually be derived from the accountsdb snapshot).
                \\
                \\ NOTE: this command also requires `root_slot` (`--test-repair-for-slot`) to be
                \\ given as well (which is usually derived from the accountsdb snapshot).
                \\ This can be done with `--test-repair-for-slot $(solana slot -u testnet)`
                \\ for testnet or another `-u` for mainnet/devnet.
                ,
            },
            .sub = .{
                .shred_version = shred_version_arg,
                .leader_schedule = leader_schedule_arg,
                .gossip_base = GossipArgumentsCommon.cmd_info,
                .gossip_node = GossipArgumentsNode.cmd_info,
                .repair = RepairArgumentsBase.cmd_info,
                .overwrite_stake_for_testing = .{
                    .kind = .named,
                    .name_override = null,
                    .alias = .none,
                    .default_value = false,
                    .config = {},
                    .help = "Overwrite the stake for testing purposes",
                },
                .no_retransmit = .{
                    .kind = .named,
                    .name_override = null,
                    .alias = .none,
                    .default_value = true,
                    .config = {},
                    .help = "Shreds will be received and stored but not retransmitted",
                },
                .snapshot_metadata_only = .{
                    .kind = .named,
                    .name_override = null,
                    .alias = .none,
                    .default_value = false,
                    .config = {},
                    .help = "load only the snapshot metadata",
                },
            },
        };
    };

    const SnapshotDownload = struct {
        shred_version: ?u16,
        snapshot_dir: []const u8,
        accountsdb_download: AccountsDbArgumentsDownload,
        gossip_base: GossipArgumentsCommon,

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "Downloads a snapshot.",
                .long = "Starts a gossip client and downloads a snapshot from peers.",
            },
            .sub = .{
                .shred_version = shred_version_arg,
                .snapshot_dir = snapshot_dir_arg,
                .accountsdb_download = AccountsDbArgumentsDownload.cmd_info,
                .gossip_base = GossipArgumentsCommon.cmd_info,
            },
        };
    };

    const SnapshotValidate = struct {
        snapshot_dir: []const u8,
        genesis_file_path: ?[]const u8,
        accountsdb_base: AccountsDbArgumentsBase,
        gossip_cluster: ?[]const u8,
        geyser: GeyserArgumentsBase,

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "Validates a snapshot.",
                .long = "Loads and validates a snapshot (doesnt download a snapshot).",
            },
            .sub = .{
                .snapshot_dir = snapshot_dir_arg,
                .genesis_file_path = genesis_file_path_arg,
                .accountsdb_base = AccountsDbArgumentsBase.cmd_info,
                .gossip_cluster = gossip_cluster_arg,
                .geyser = GeyserArgumentsBase.cmd_info,
            },
        };
    };

    const SnapshotCreate = struct {
        snapshot_dir: []const u8,
        genesis_file_path: ?[]const u8,

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "Loads from a snapshot" ++
                    " and outputs to new snapshot 'alt_{VALIDATOR_DIR}/'.",
                .long = null,
            },
            .sub = .{
                .snapshot_dir = snapshot_dir_arg,
                .genesis_file_path = genesis_file_path_arg,
            },
        };
    };

    const PrintManifest = struct {
        snapshot_dir: []const u8,

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "Prints a manifest file.",
                .long = "Loads and prints a manifest file.",
            },
            .sub = .{
                .snapshot_dir = snapshot_dir_arg,
            },
        };
    };

    const LeaderScheduleSubCmd = struct {
        shred_version: ?u16,
        leader_schedule: ?[]const u8,
        gossip_base: GossipArgumentsCommon,
        gossip_node: GossipArgumentsNode,
        snapshot_dir: []const u8,
        genesis_file_path: ?[]const u8,
        accountsdb_base: AccountsDbArgumentsBase,
        accountsdb_download: AccountsDbArgumentsDownload,
        force_new_snapshot_download: bool,

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "Prints the leader schedule from the snapshot.",
                .long =
                \\- Starts gossip
                \\- acquires a snapshot if necessary
                \\- loads accounts db from the snapshot
                \\- calculates the leader schedule from the snaphot
                \\- prints the leader schedule in the same format as `solana leader-schedule`
                \\- exits
                ,
            },
            .sub = .{
                .shred_version = shred_version_arg,
                .leader_schedule = leader_schedule_arg,
                .gossip_base = GossipArgumentsCommon.cmd_info,
                .gossip_node = GossipArgumentsNode.cmd_info,
                .snapshot_dir = snapshot_dir_arg,
                .genesis_file_path = genesis_file_path_arg,
                .accountsdb_base = AccountsDbArgumentsBase.cmd_info,
                .accountsdb_download = AccountsDbArgumentsDownload.cmd_info,
                .force_new_snapshot_download = force_new_snapshot_download_arg,
            },
        };
    };

    const TestTransactionSender = struct {
        shred_version: ?u16,
        genesis_file_path: ?[]const u8,
        n_transactions: u64,
        n_lamports_per_tx: u64,
        gossip_base: GossipArgumentsCommon,
        gossip_node: GossipArgumentsNode,

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "Test transaction sender service.",
                .long =
                \\Simulates a stream of transaction being sent to the transaction sender by
                \\running a mock transaction generator thread. For the moment this just sends
                \\transfer transactions between to hard coded testnet accounts.
                ,
            },
            .sub = .{
                .shred_version = shred_version_arg,
                .genesis_file_path = genesis_file_path_arg,
                .n_transactions = .{
                    .kind = .named,
                    .name_override = "n-transactions",
                    .alias = .t,
                    .default_value = 3,
                    .config = {},
                    .help = "number of transactions to send",
                },
                .n_lamports_per_tx = .{
                    .kind = .named,
                    .name_override = "n-lamports-per-tx",
                    .alias = .l,
                    .default_value = 1e7,
                    .config = {},
                    .help = "number of lamports to send per transaction",
                },
                .gossip_base = GossipArgumentsCommon.cmd_info,
                .gossip_node = GossipArgumentsNode.cmd_info,
            },
        };
    };

    const MockRpcServer = struct {
        gossip_base: GossipArgumentsCommon,
        gossip_node: GossipArgumentsNode,
        snapshot_dir: []const u8,
        genesis_file_path: ?[]const u8,
        accountsdb_base: AccountsDbArgumentsBase,
        accountsdb_download: AccountsDbArgumentsDownload,
        force_new_snapshot_download: bool,

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "Run a mock RPC server.",
                .long = null,
            },
            .sub = .{
                .gossip_base = GossipArgumentsCommon.cmd_info,
                .gossip_node = GossipArgumentsNode.cmd_info,
                .snapshot_dir = snapshot_dir_arg,
                .genesis_file_path = genesis_file_path_arg,
                .accountsdb_base = AccountsDbArgumentsBase.cmd_info,
                .accountsdb_download = AccountsDbArgumentsDownload.cmd_info,
                .force_new_snapshot_download = force_new_snapshot_download_arg,
            },
        };
    };
};

/// entrypoint to print (and create if NONE) pubkey in ~/.sig/identity.key
fn identity(allocator: std.mem.Allocator, cfg: config.Cmd) !void {
    const maybe_file, const logger = try spawnLogger(allocator, cfg);
    defer if (maybe_file) |file| file.close();
    defer logger.deinit();

    const keypair = try sig.identity.getOrInit(allocator, .from(logger));
    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);

    logger.info().logf("Identity: {s}", .{pubkey});
}

/// entrypoint to run only gossip
fn gossip(
    allocator: std.mem.Allocator,
    gossip_value_allocator: std.mem.Allocator,
    cfg: config.Cmd,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "gossip" });
    defer zone.deinit();

    var app_base = try AppBase.init(allocator, cfg);
    errdefer {
        app_base.shutdown();
        app_base.deinit();
    }

    const gossip_service = try startGossip(
        allocator,
        gossip_value_allocator,
        cfg,
        &app_base,
        &.{},
        .{},
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    // block forever
    gossip_service.service_manager.join();
}

/// entrypoint to run a full solana validator
fn validator(
    allocator: std.mem.Allocator,
    gossip_value_allocator: std.mem.Allocator,
    cfg: config.Cmd,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "validator" });
    defer zone.deinit();

    var app_base = try AppBase.init(allocator, cfg);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    app_base.logger.info().logf("starting validator with cfg: {}", .{cfg});

    const repair_port: u16 = cfg.shred_network.repair_port;
    const turbine_recv_port: u16 = cfg.shred_network.turbine_recv_port;
    const snapshot_dir_str = cfg.accounts_db.snapshot_dir;

    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{
        .iterate = true,
    });
    defer snapshot_dir.close();

    var gossip_votes = try sig.sync.Channel(sig.gossip.data.Vote).init(allocator);
    defer gossip_votes.deinit();

    var gossip_service = try startGossip(
        allocator,
        gossip_value_allocator,
        cfg,
        &app_base,
        &.{
            .{ .tag = .repair, .port = repair_port },
            .{ .tag = .turbine_recv, .port = turbine_recv_port },
        },
        .{ .vote_collector = &gossip_votes },
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    const geyser_writer: ?*GeyserWriter = if (!cfg.geyser.enable)
        null
    else
        try createGeyserWriter(
            allocator,
            cfg.geyser.pipe_path,
            cfg.geyser.writer_fba_bytes,
        );
    defer if (geyser_writer) |geyser| {
        geyser.deinit();
        allocator.destroy(geyser.exit);
        allocator.destroy(geyser);
    };

    const snapshot_files = try sig.accounts_db.snapshot.download.getOrDownloadSnapshotFiles(
        allocator,
        .from(app_base.logger),
        snapshot_dir,
        .{
            .gossip_service = gossip_service,
            .force_new_snapshot_download = cfg.accounts_db.force_new_snapshot_download,
            .min_snapshot_download_speed_mbs = cfg.accounts_db.min_snapshot_download_speed_mbs,
            .max_number_of_download_attempts = //
            cfg.accounts_db.max_number_of_snapshot_download_attempts,
        },
    );

    const rooted_file = try std.fs.path.joinZ(allocator, &.{ snapshot_dir_str, "accounts.db" });
    defer allocator.free(rooted_file);

    var rooted_db: sig.accounts_db.Two.Rooted = try .init(rooted_file);
    defer rooted_db.deinit();

    // snapshot
    var loaded_snapshot = try loadSnapshot(
        allocator,
        .from(app_base.logger),
        snapshot_dir,
        snapshot_files,
        .{
            .genesis_file_path = try cfg.genesisFilePath() orelse {
                return error.GenesisPathNotProvided;
            },
            .extract = if (cfg.accounts_db.skip_snapshot_validation)
                .{ .entire_snapshot = &rooted_db }
            else
                .{ .entire_snapshot_and_validate = &rooted_db },
        },
    );
    defer loaded_snapshot.deinit();

    var new_db: sig.accounts_db.Two = try .init(allocator, rooted_db);
    defer new_db.deinit();

    const collapsed_manifest = &loaded_snapshot.collapsed_manifest;
    const bank_fields = &collapsed_manifest.bank_fields;

    // ledger
    var ledger = try Ledger.init(
        allocator,
        .from(app_base.logger),
        sig.VALIDATOR_DIR ++ "ledger",
        app_base.metrics_registry,
    );
    defer ledger.deinit();
    const ledger_cleanup_service = try std.Thread.spawn(.{}, sig.ledger.cleanup_service.run, .{
        sig.ledger.cleanup_service.Logger.from(app_base.logger),
        &ledger,
        cfg.max_shreds,
        app_base.exit,
    });

    // Random number generator
    var prng = std.Random.DefaultPrng.init(@bitCast(std.time.timestamp()));

    // shred networking
    const my_contact_info =
        sig.gossip.data.ThreadSafeContactInfo.fromContactInfo(gossip_service.my_contact_info);

    const epoch_schedule = bank_fields.epoch_schedule;
    const epoch = bank_fields.epoch;

    const staked_nodes = try collapsed_manifest.epochStakes(epoch);
    var epoch_context_manager = try sig.adapter.EpochContextManager.init(allocator, epoch_schedule);
    defer epoch_context_manager.deinit();
    try epoch_context_manager.contexts.realign(epoch);
    {
        var staked_nodes_cloned = try staked_nodes.clone(allocator);
        errdefer staked_nodes_cloned.deinit(allocator);

        const leader_schedule = if (try getLeaderScheduleFromCli(allocator, cfg)) |leader_schedule|
            leader_schedule[1].slot_leaders
        else ls: {
            // TODO: Implement feature gating for vote keyed leader schedule.
            // [agave] https://github.com/anza-xyz/agave/blob/e468acf4da519171510f2ec982f70a0fd9eb2c8b/ledger/src/leader_schedule_utils.rs#L12
            // [agave] https://github.com/anza-xyz/agave/blob/e468acf4da519171510f2ec982f70a0fd9eb2c8b/runtime/src/bank.rs#L4833
            break :ls if (true)
                try LeaderSchedule.fromVoteAccounts(
                    allocator,
                    epoch,
                    epoch_schedule.slots_per_epoch,
                    try collapsed_manifest.epochVoteAccounts(epoch),
                )
            else
                try LeaderSchedule.fromStakedNodes(
                    allocator,
                    epoch,
                    epoch_schedule.slots_per_epoch,
                    staked_nodes,
                );
        };
        errdefer allocator.free(leader_schedule);

        try epoch_context_manager.put(epoch, .{
            .staked_nodes = staked_nodes_cloned,
            .leader_schedule = leader_schedule,
        });
    }

    const rpc_cluster_type = loaded_snapshot.genesis_config.cluster_type;
    var rpc_client = try sig.rpc.Client.init(allocator, rpc_cluster_type, .{});
    defer rpc_client.deinit();

    var rpc_epoch_ctx_service = sig.adapter.RpcEpochContextService.init(
        allocator,
        .from(app_base.logger),
        &epoch_context_manager,
        rpc_client,
    );

    const rpc_epoch_ctx_service_thread = try std.Thread.spawn(
        .{},
        sig.adapter.RpcEpochContextService.run,
        .{ &rpc_epoch_ctx_service, app_base.exit },
    );

    const turbine_config = cfg.turbine;

    // shred network
    var shred_network_manager = try sig.shred_network.start(
        cfg.shred_network.toConfig(loaded_snapshot.collapsed_manifest.bank_fields.slot),
        .{
            .allocator = allocator,
            .logger = .from(app_base.logger),
            .registry = app_base.metrics_registry,
            .random = prng.random(),
            .ledger = &ledger,
            .my_keypair = &app_base.my_keypair,
            .exit = app_base.exit,
            .gossip_table_rw = &gossip_service.gossip_table_rw,
            .my_shred_version = &gossip_service.my_shred_version,
            .epoch_context_mgr = &epoch_context_manager,
            .my_contact_info = my_contact_info,
            .n_retransmit_threads = turbine_config.num_retransmit_threads,
            .overwrite_turbine_stake_for_testing = turbine_config.overwrite_stake_for_testing,
        },
    );
    defer shred_network_manager.deinit();

    // Vote account. if not provided, disable voting
    const maybe_vote_pubkey: ?Pubkey = if (cfg.voting_enabled) blk: {
        const vote_keypair_path = cfg.vote_account orelse default_path: {
            const app_data_dir_path = try std.fs.getAppDataDir(allocator, "sig");
            defer allocator.free(app_data_dir_path);
            break :default_path try std.fs.path.join(
                allocator,
                &.{ app_data_dir_path, "vote-account.json" },
            );
        };
        defer if (cfg.vote_account == null) allocator.free(vote_keypair_path);

        break :blk sig.identity.readPubkey(
            .from(app_base.logger),
            vote_keypair_path,
        ) catch |err| {
            app_base.logger.err().logf(
                "vote-account: failed to read {s}: {}; voting will be disabled",
                .{ vote_keypair_path, err },
            );
            break :blk null;
        };
    } else null;

    // If voting was enabled but no vote account is available, disable voting.
    const voting_enabled = cfg.voting_enabled and maybe_vote_pubkey != null;

    const maybe_vote_sockets: ?replay.consensus.core.VoteSockets = if (voting_enabled)
        try replay.consensus.core.VoteSockets.init()
    else
        null;

    var replay_service_state: ReplayAndConsensusServiceState = try .init(allocator, .{
        .app_base = &app_base,
        .account_store = .{ .accounts_db_two = &new_db },
        .loaded_snapshot = &loaded_snapshot,
        .ledger = &ledger,
        .epoch_context_manager = &epoch_context_manager,
        .replay_threads = cfg.replay_threads,
        .disable_consensus = cfg.disable_consensus,
        .voting_enabled = voting_enabled,
        .vote_account_address = maybe_vote_pubkey,
        .stop_at_slot = cfg.stop_at_slot,
    });
    defer replay_service_state.deinit(allocator);

    const replay_thread = try replay_service_state.spawnService(
        &app_base,
        if (maybe_vote_sockets) |*vs| vs else null,
        &gossip_votes,
    );

    const rpc_server_thread = if (cfg.rpc_port) |rpc_port|
        try std.Thread.spawn(.{}, runRPCServer, .{
            allocator,
            app_base.logger,
            app_base.exit,
            std.net.Address.initIp4(.{ 0, 0, 0, 0 }, rpc_port),
            &app_base.rpc_hooks,
        })
    else
        null;

    if (rpc_server_thread) |thread| thread.join();
    replay_thread.join();
    rpc_epoch_ctx_service_thread.join();
    gossip_service.service_manager.join();
    shred_network_manager.join();
    ledger_cleanup_service.join();
}

fn runRPCServer(
    allocator: std.mem.Allocator,
    logger: Logger,
    exit: *std.atomic.Value(bool),
    server_addr: std.net.Address,
    rpc_hooks: *sig.rpc.Hooks,
) !void {
    var server_ctx = try sig.rpc.server.Context.init(.{
        .allocator = allocator,
        .logger = .from(logger),
        .rpc_hooks = rpc_hooks,
        .read_buffer_size = sig.rpc.server.MIN_READ_BUFFER_SIZE,
        .socket_addr = server_addr,
        .reuse_address = true,
    });
    defer server_ctx.joinDeinit();

    // var maybe_liou = try sig.rpc.server.LinuxIoUring.init(&server_ctx);
    // defer if (maybe_liou) |*liou| liou.deinit();

    try sig.rpc.server.serve(
        exit,
        &server_ctx,
        .basic, // if (maybe_liou != null) .{ .linux_io_uring = &maybe_liou.? } else .basic,
    );
}

/// entrypoint to run a minimal replay node
fn replayOffline(
    allocator: std.mem.Allocator,
    cfg: config.Cmd,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "cmd.replay" });
    defer zone.deinit();

    var app_base = try AppBase.init(allocator, cfg);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    app_base.logger.info().logf("starting replay-offline with cfg: {}", .{cfg});

    const snapshot_dir_str = cfg.accounts_db.snapshot_dir;

    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{
        .iterate = true,
    });
    defer snapshot_dir.close();

    const snapshot_files = try SnapshotFiles.find(allocator, snapshot_dir);

    const rooted_file = try std.fs.path.joinZ(allocator, &.{ snapshot_dir_str, "accounts.db" });
    defer allocator.free(rooted_file);

    var rooted_db: sig.accounts_db.Two.Rooted = try .init(rooted_file);
    defer rooted_db.deinit();

    // snapshot
    var loaded_snapshot = try loadSnapshot(
        allocator,
        .from(app_base.logger),
        snapshot_dir,
        snapshot_files,
        .{
            .genesis_file_path = try cfg.genesisFilePath() orelse {
                return error.GenesisPathNotProvided;
            },
            .extract = if (cfg.accounts_db.skip_snapshot_validation)
                .{ .entire_snapshot = &rooted_db }
            else
                .{ .entire_snapshot_and_validate = &rooted_db },
        },
    );
    defer loaded_snapshot.deinit();

    var new_db: sig.accounts_db.Two = try .init(allocator, rooted_db);
    defer new_db.deinit();

    const collapsed_manifest = &loaded_snapshot.collapsed_manifest;
    const bank_fields = &collapsed_manifest.bank_fields;

    // leader schedule
    var leader_schedule_cache = LeaderScheduleCache.init(allocator, bank_fields.epoch_schedule);
    if (try getLeaderScheduleFromCli(allocator, cfg)) |leader_schedule| {
        try leader_schedule_cache.put(bank_fields.epoch, leader_schedule[1]);
    } else {
        const schedule = try collapsed_manifest.leaderSchedule(allocator, null);
        errdefer schedule.deinit();
        try leader_schedule_cache.put(bank_fields.epoch, schedule);
    }

    // ledger
    var ledger = try Ledger.init(
        allocator,
        .from(app_base.logger),
        sig.VALIDATOR_DIR ++ "ledger",
        app_base.metrics_registry,
    );
    defer ledger.deinit();
    const ledger_cleanup_service = try std.Thread.spawn(.{}, sig.ledger.cleanup_service.run, .{
        sig.ledger.cleanup_service.Logger.from(app_base.logger),
        &ledger,
        cfg.max_shreds,
        app_base.exit,
    });

    const epoch_schedule = bank_fields.epoch_schedule;
    const epoch = bank_fields.epoch;

    const staked_nodes = try collapsed_manifest.epochStakes(epoch);
    var epoch_context_manager = try sig.adapter.EpochContextManager.init(allocator, epoch_schedule);
    defer epoch_context_manager.deinit();
    try epoch_context_manager.contexts.realign(epoch);
    {
        var staked_nodes_cloned = try staked_nodes.clone(allocator);
        errdefer staked_nodes_cloned.deinit(allocator);

        // TODO: Implement feature gating for vote keyed leader schedule.
        // [agave] https://github.com/anza-xyz/agave/blob/e468acf4da519171510f2ec982f70a0fd9eb2c8b/ledger/src/leader_schedule_utils.rs#L12
        // [agave] https://github.com/anza-xyz/agave/blob/e468acf4da519171510f2ec982f70a0fd9eb2c8b/runtime/src/bank.rs#L4833
        const leader_schedule = if (true)
            try LeaderSchedule.fromVoteAccounts(
                allocator,
                epoch,
                epoch_schedule.slots_per_epoch,
                try collapsed_manifest.epochVoteAccounts(epoch),
            )
        else
            try LeaderSchedule.fromStakedNodes(
                allocator,
                epoch,
                epoch_schedule.slots_per_epoch,
                staked_nodes,
            );
        errdefer allocator.free(leader_schedule);

        try epoch_context_manager.put(epoch, .{
            .staked_nodes = staked_nodes_cloned,
            .leader_schedule = leader_schedule,
        });
    }

    var replay_service_state: ReplayAndConsensusServiceState = try .init(allocator, .{
        .app_base = &app_base,
        .account_store = .{ .accounts_db_two = &new_db },
        .loaded_snapshot = &loaded_snapshot,
        .ledger = &ledger,
        .epoch_context_manager = &epoch_context_manager,
        .replay_threads = cfg.replay_threads,
        .disable_consensus = cfg.disable_consensus,
        .voting_enabled = false,
        .vote_account_address = null,
        .stop_at_slot = cfg.stop_at_slot,
    });
    defer replay_service_state.deinit(allocator);

    const replay_thread = try replay_service_state.spawnService(
        &app_base,
        null,
        null,
    );

    replay_thread.join();
    ledger_cleanup_service.join();
}

fn shredNetwork(
    allocator: std.mem.Allocator,
    gossip_value_allocator: std.mem.Allocator,
    cfg: config.Cmd,
) !void {
    var app_base = try AppBase.init(allocator, cfg);
    defer {
        if (!app_base.closed) app_base.shutdown();
        app_base.deinit();
    }

    const genesis_path = try cfg.genesisFilePath() orelse
        return error.GenesisPathNotProvided;
    const genesis_config = try GenesisConfig.init(allocator, genesis_path);

    var rpc_client = try sig.rpc.Client.init(allocator, genesis_config.cluster_type, .{});
    defer rpc_client.deinit();

    const shred_network_conf = cfg.shred_network.toConfig(
        cfg.shred_network.root_slot orelse blk: {
            const response = try rpc_client.getSlot(.{});
            break :blk try response.result();
        },
    );
    app_base.logger.info().logf(
        "Starting after assumed root slot: {?}",
        .{shred_network_conf.root_slot},
    );

    const repair_port: u16 = shred_network_conf.repair_port;
    const turbine_recv_port: u16 = shred_network_conf.turbine_recv_port;

    var gossip_service = try startGossip(allocator, gossip_value_allocator, cfg, &app_base, &.{
        .{ .tag = .repair, .port = repair_port },
        .{ .tag = .turbine_recv, .port = turbine_recv_port },
    }, .{});
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    var epoch_context_manager = try sig.adapter.EpochContextManager
        .init(allocator, genesis_config.epoch_schedule);
    var rpc_epoch_ctx_service = sig.adapter.RpcEpochContextService
        .init(allocator, .from(app_base.logger), &epoch_context_manager, rpc_client);
    const rpc_epoch_ctx_service_thread = try std.Thread.spawn(
        .{},
        sig.adapter.RpcEpochContextService.run,
        .{ &rpc_epoch_ctx_service, app_base.exit },
    );

    var ledger = try Ledger.init(
        allocator,
        .from(app_base.logger),
        sig.VALIDATOR_DIR ++ "ledger",
        app_base.metrics_registry,
    );
    defer ledger.deinit();
    const ledger_cleanup_service = try std.Thread.spawn(.{}, sig.ledger.cleanup_service.run, .{
        sig.ledger.cleanup_service.Logger.from(app_base.logger),
        &ledger,
        cfg.max_shreds,
        app_base.exit,
    });

    var prng = std.Random.DefaultPrng.init(@bitCast(std.time.timestamp()));

    const my_contact_info =
        sig.gossip.data.ThreadSafeContactInfo.fromContactInfo(gossip_service.my_contact_info);

    // shred networking
    var shred_network_manager = try sig.shred_network.start(shred_network_conf, .{
        .allocator = allocator,
        .logger = .from(app_base.logger),
        .registry = app_base.metrics_registry,
        .random = prng.random(),
        .ledger = &ledger,
        .my_keypair = &app_base.my_keypair,
        .exit = app_base.exit,
        .gossip_table_rw = &gossip_service.gossip_table_rw,
        .my_shred_version = &gossip_service.my_shred_version,
        .epoch_context_mgr = &epoch_context_manager,
        .my_contact_info = my_contact_info,
        .n_retransmit_threads = cfg.turbine.num_retransmit_threads,
        .overwrite_turbine_stake_for_testing = cfg.turbine.overwrite_stake_for_testing,
    });
    defer shred_network_manager.deinit();

    rpc_epoch_ctx_service_thread.join();
    gossip_service.service_manager.join();
    shred_network_manager.join();
    ledger_cleanup_service.join();
}

fn printManifest(allocator: std.mem.Allocator, cfg: config.Cmd) !void {
    var app_base = try AppBase.init(allocator, cfg);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    const snapshot_dir_str = cfg.accounts_db.snapshot_dir;
    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{
        .iterate = true,
    });
    defer snapshot_dir.close();

    const snapshot_file_info = try SnapshotFiles.find(allocator, snapshot_dir);

    var snapshots = try FullAndIncrementalManifest.fromFiles(
        allocator,
        .from(app_base.logger),
        snapshot_dir,
        snapshot_file_info,
    );
    defer snapshots.deinit(allocator);

    _ = try snapshots.collapse(allocator);

    // TODO: support better inspection of snapshots (maybe dump to a file as json?)
    std.debug.print("full snapshots: {any}\n", .{snapshots.full.bank_fields});
}

// fn createSnapshot(allocator: std.mem.Allocator, cfg: config.Cmd) !void {
//     var app_base = try AppBase.init(allocator, cfg);
//     defer {
//         app_base.shutdown();
//         app_base.deinit();
//     }

//     const snapshot_dir_str = cfg.accounts_db.snapshot_dir;
//     var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{});
//     defer snapshot_dir.close();

//     var loaded_snapshot = try loadSnapshot(
//         allocator,
//         cfg.accounts_db,
//         try cfg.genesisFilePath() orelse return error.GenesisPathNotProvided,
//         .from(app_base.logger),
//         .{
//             .gossip_service = null,
//             .geyser_writer = null,
//             .validate_snapshot = false,
//             .metadata_only = false,
//         },
//     );
//     defer loaded_snapshot.deinit();

//     var accounts_db = loaded_snapshot.accounts_db;
//     const slot = loaded_snapshot.combined_manifest.full.bank_fields.slot;

//     var n_accounts_indexed: u64 = 0;
//     for (accounts_db.account_index.pubkey_ref_map.shards) |*shard_rw| {
//         const shard, var lock = shard_rw.readWithLock();
//         defer lock.unlock();
//         n_accounts_indexed += shard.count();
//     }
//     app_base.logger.info().logf("accountsdb: indexed {d} accounts", .{n_accounts_indexed});

//     const output_dir_name = "alt_" ++ sig.VALIDATOR_DIR; // TODO: pull out to cli arg
//     var output_dir = try std.fs.cwd().makeOpenPath(output_dir_name, .{});
//     defer output_dir.close();

//     app_base.logger.info().logf(
//         "accountsdb[manager]: generating full snapshot for slot {d}",
//         .{slot},
//     );
//     _ = try accounts_db.generateFullSnapshot(.{
//         .target_slot = slot,
//         .bank_fields = &loaded_snapshot.combined_manifest.full.bank_fields,
//         .lamports_per_signature = lps: {
//             var prng = std.Random.DefaultPrng.init(1234);
//             break :lps prng.random().int(u64);
//         },
//         .old_snapshot_action = .delete_old,
//     });
// }

fn validateSnapshot(allocator: std.mem.Allocator, cfg: config.Cmd) !void {
    var app_base = try AppBase.init(allocator, cfg);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    const snapshot_dir_str = cfg.accounts_db.snapshot_dir;
    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{ .iterate = true });
    defer snapshot_dir.close();

    const geyser_writer: ?*GeyserWriter = if (!cfg.geyser.enable)
        null
    else
        try createGeyserWriter(
            allocator,
            cfg.geyser.pipe_path,
            cfg.geyser.writer_fba_bytes,
        );
    defer if (geyser_writer) |geyser| {
        geyser.deinit();
        allocator.destroy(geyser.exit);
        allocator.destroy(geyser);
    };

    const snapshot_files = try SnapshotFiles.find(allocator, snapshot_dir);

    const rooted_file = try std.fs.path.joinZ(allocator, &.{ snapshot_dir_str, "accounts.db" });
    defer allocator.free(rooted_file);

    var rooted_db: sig.accounts_db.Two.Rooted = try .init(rooted_file);
    defer rooted_db.deinit();

    var loaded_snapshot = try loadSnapshot(
        allocator,
        .from(app_base.logger),
        snapshot_dir,
        snapshot_files,
        .{
            .genesis_file_path = try cfg.genesisFilePath() orelse {
                return error.GenesisPathNotProvided;
            },
            .extract = .{ .entire_snapshot_and_validate = &rooted_db },
        },
    );
    defer loaded_snapshot.deinit();
}

/// entrypoint to print the leader schedule and then exit
fn printLeaderSchedule(allocator: std.mem.Allocator, cfg: config.Cmd) !void {
    var app_base = try AppBase.init(allocator, cfg);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    const root_slot, //
    const leader_schedule //
    = try getLeaderScheduleFromCli(allocator, cfg) orelse b: {
        app_base.logger.info().log("Downloading a snapshot to calculate the leader schedule.");

        const snapshot_dir_str = cfg.accounts_db.snapshot_dir;
        var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{ .iterate = true });
        defer snapshot_dir.close();

        const snapshot_files =
            SnapshotFiles.find(allocator, snapshot_dir) catch |err| switch (err) {
                error.NoFullSnapshotFileInfoFound => {
                    app_base.logger.err().log(
                        \\\ No snapshot found and no gossip service to download a snapshot from.
                        \\\ Download using the `snapshot-download` command.
                    );
                    return err;
                },
                else => return err,
            };

        var loaded_snapshot = try loadSnapshot(
            allocator,
            .from(app_base.logger),
            snapshot_dir,
            snapshot_files,
            .{
                .genesis_file_path = try cfg.genesisFilePath() orelse {
                    return error.GenesisPathNotProvided;
                },
                .extract = .metadata_only,
            },
        );
        defer loaded_snapshot.deinit();

        const bank_fields = &loaded_snapshot.collapsed_manifest.bank_fields;
        _, const slot_index = bank_fields.epoch_schedule.getEpochAndSlotIndex(bank_fields.slot);
        break :b .{
            bank_fields.slot - slot_index,
            try loaded_snapshot.collapsed_manifest.leaderSchedule(allocator, null),
        };
    };

    var stdout = std.io.bufferedWriter(std.io.getStdOut().writer());
    try leader_schedule.write(stdout.writer(), root_slot);
    try stdout.flush();
}

fn getLeaderScheduleFromCli(
    allocator: std.mem.Allocator,
    cfg: config.Cmd,
) !?struct { Slot, LeaderSchedule } {
    return if (cfg.leader_schedule_path) |path|
        if (std.mem.eql(u8, "--", path))
            try LeaderSchedule.read(allocator, std.io.getStdIn().reader())
        else
            try LeaderSchedule.read(allocator, (try std.fs.cwd().openFile(path, .{})).reader())
    else
        null;
}

fn testTransactionSenderService(
    allocator: std.mem.Allocator,
    gossip_value_allocator: std.mem.Allocator,
    cfg: config.Cmd,
) !void {
    var app_base = try AppBase.init(allocator, cfg);
    defer {
        if (!app_base.closed) app_base.shutdown(); // we have this incase an error occurs
        app_base.deinit();
    }

    // read genesis (used for leader schedule)
    const genesis_file_path = try cfg.genesisFilePath() orelse
        @panic("No genesis file path found: use -g or -n");
    const genesis_config = try GenesisConfig.init(allocator, genesis_file_path);

    // start gossip (used to get TPU ports of leaders)
    const gossip_service = try startGossip(
        allocator,
        gossip_value_allocator,
        cfg,
        &app_base,
        &.{},
        .{},
    );
    defer {
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    // define cluster of where to land transactions
    const rpc_cluster: ClusterType = if (try cfg.gossip.getCluster()) |n| switch (n) {
        .mainnet => .MainnetBeta,
        .devnet => .Devnet,
        .testnet => .Testnet,
        .localnet => .LocalHost,
    } else {
        @panic("cluster option (-c) not provided");
    };
    app_base.logger.warn().logf(
        "Starting transaction sender service on {s}...",
        .{@tagName(rpc_cluster)},
    );

    // setup channel for communication to the tx-sender service
    const transaction_channel =
        try sig.sync.Channel(sig.transaction_sender.TransactionInfo).create(allocator);
    defer transaction_channel.destroy();

    // this handles transactions and forwards them to leaders TPU ports
    var transaction_sender_service = try sig.transaction_sender.Service.init(
        allocator,
        .from(app_base.logger),
        .{ .cluster = rpc_cluster, .socket = SocketAddr.init(app_base.my_ip, 0) },
        transaction_channel,
        &gossip_service.gossip_table_rw,
        genesis_config.epoch_schedule,
        app_base.exit,
    );
    const transaction_sender_handle = try std.Thread.spawn(
        .{},
        sig.transaction_sender.Service.run,
        .{&transaction_sender_service},
    );

    // rpc is used to get blockhashes and other balance information
    var rpc_client = try sig.rpc.Client.init(allocator, rpc_cluster, .{
        .logger = .from(app_base.logger),
    });
    defer rpc_client.deinit();

    // this sends mock txs to the transaction sender
    var mock_transfer_service = try sig.transaction_sender.MockTransferService.init(
        allocator,
        transaction_channel,
        rpc_client,
        app_base.exit,
        .from(app_base.logger),
    );
    // send and confirm mock transactions
    try mock_transfer_service.run(
        cfg.test_transaction_sender.n_transactions,
        cfg.test_transaction_sender.n_lamports_per_transaction,
    );

    gossip_service.shutdown();
    app_base.shutdown();
    transaction_sender_handle.join();
}

fn mockRpcServer(allocator: std.mem.Allocator, cfg: config.Cmd) !void {
    const logger: sig.trace.Logger("mock rpc") = .{
        .impl = .direct_print,
        .max_level = .trace,
        .filters = .trace,
    };

    var snapshot_dir = try std.fs.cwd().makeOpenPath(cfg.accounts_db.snapshot_dir, .{
        .iterate = true,
    });
    defer snapshot_dir.close();

    const snap_files = try sig.accounts_db.db.findAndUnpackSnapshotFilePair(
        allocator,
        std.Thread.getCpuCount() catch 1,
        snapshot_dir,
        snapshot_dir,
    );

    var accountsdb = try sig.accounts_db.AccountsDB.init(.{
        .allocator = allocator,
        .logger = .noop,
        .snapshot_dir = snapshot_dir,
        .geyser_writer = null,
        .gossip_view = null,
        .index_allocation = .ram,
        .number_of_index_shards = 1,
    });
    defer accountsdb.deinit();

    {
        const all_snap_fields = try FullAndIncrementalManifest.fromFiles(
            allocator,
            .from(logger),
            snapshot_dir,
            snap_files,
        );
        defer all_snap_fields.deinit(allocator);

        const manifest =
            try accountsdb.loadWithDefaults(allocator, all_snap_fields, 1, true, 1500);
        defer manifest.deinit(allocator);
    }

    var rpc_hooks = sig.rpc.Hooks{};
    defer rpc_hooks.deinit(allocator);
    try accountsdb.registerRPCHooks(&rpc_hooks);

    var server_ctx = try sig.rpc.server.Context.init(.{
        .allocator = allocator,
        .logger = .from(logger),
        .rpc_hooks = &rpc_hooks,

        .read_buffer_size = sig.rpc.server.MIN_READ_BUFFER_SIZE,
        .socket_addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 8899),
        .reuse_address = true,
    });
    defer server_ctx.joinDeinit();

    // var maybe_liou = try sig.rpc.server.LinuxIoUring.init(&server_ctx);
    // defer if (maybe_liou) |*liou| liou.deinit();

    var exit = std.atomic.Value(bool).init(false);
    try sig.rpc.server.serve(
        &exit,
        &server_ctx,
        .basic, // if (maybe_liou != null) .{ .linux_io_uring = &maybe_liou.? } else .basic,
    );
}

/// State that typically needs to be initialized at the start of the app,
/// and deinitialized only when the app exits.
const AppBase = struct {
    allocator: std.mem.Allocator,
    logger: Logger,
    log_file: ?std.fs.File,
    metrics_registry: *sig.prometheus.Registry(.{}),
    metrics_thread: std.Thread,

    rpc_hooks: sig.rpc.Hooks,

    my_keypair: sig.identity.KeyPair,
    entrypoints: []SocketAddr,
    shred_version: u16,
    my_ip: IpAddr,
    my_port: u16,

    exit: *std.atomic.Value(bool),
    closed: bool,

    fn init(allocator: std.mem.Allocator, cfg: config.Cmd) !AppBase {
        const maybe_file, const logger = try spawnLogger(allocator, cfg);
        errdefer if (maybe_file) |file| file.close();
        errdefer logger.deinit();

        const exit = try allocator.create(std.atomic.Value(bool));
        errdefer allocator.destroy(exit);
        exit.* = std.atomic.Value(bool).init(false);

        const metrics_registry = globalRegistry();
        const metrics_thread = try sig.utils.service_manager.spawnService( //
            .from(logger), exit, "metrics endpoint", .{}, //
            servePrometheus, .{ allocator, metrics_registry, cfg.metrics_port });
        errdefer metrics_thread.detach();

        const my_keypair = try sig.identity.getOrInit(allocator, .from(logger));
        const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);

        const entrypoints = try cfg.gossip.getEntrypointAddrs(allocator);

        const echo_data = try getShredAndIPFromEchoServer(.from(logger), entrypoints);

        const my_shred_version =
            cfg.shred_version orelse
            echo_data.shred_version orelse
            0;

        const config_host = cfg.gossip.getHost() catch null;
        const my_ip: IpAddr = config_host orelse echo_data.ip orelse .initIpv4(.{ 127, 0, 0, 1 });

        const my_port = cfg.gossip.port;

        logger.info()
            .field("metrics_port", cfg.metrics_port)
            .field("identity", my_pubkey)
            .field("entrypoints", entrypoints)
            .field("shred_version", my_shred_version)
            .log("app setup");

        return .{
            .allocator = allocator,
            .logger = logger,
            .log_file = maybe_file,
            .metrics_registry = metrics_registry,
            .metrics_thread = metrics_thread,
            .rpc_hooks = .{},
            .my_keypair = my_keypair,
            .entrypoints = entrypoints,
            .shred_version = my_shred_version,
            .my_ip = my_ip,
            .my_port = my_port,
            .exit = exit,
            .closed = false,
        };
    }

    pub fn spawnService(
        self: *const AppBase,
        name: []const u8,
        run_config: sig.utils.service_manager.RunConfig,
        function: anytype,
        args: anytype,
    ) std.Thread.SpawnError!std.Thread {
        return try sig.utils.service_manager.spawnService(
            .from(self.logger),
            self.exit,
            name,
            run_config,
            function,
            args,
        );
    }

    /// Signals the shutdown, however it does not block.
    pub fn shutdown(self: *AppBase) void {
        std.debug.assert(!self.closed);
        defer self.closed = true;
        self.exit.store(true, .release);
    }

    pub fn deinit(self: *AppBase) void {
        std.debug.assert(self.closed); // call `self.shutdown()` first
        self.allocator.free(self.entrypoints);
        self.rpc_hooks.deinit(self.allocator);
        self.metrics_thread.detach();
        self.logger.deinit();
        if (self.log_file) |file| file.close();
        self.allocator.destroy(self.exit);
    }
};

fn startGossip(
    allocator: std.mem.Allocator,
    gossip_value_allocator: std.mem.Allocator,
    cfg: config.Cmd,
    app_base: *AppBase,
    /// Extra sockets to publish in gossip, other than the gossip socket
    extra_sockets: []const struct { tag: SocketTag, port: u16 },
    broker: sig.gossip.service.LocalMessageBroker,
) !*GossipService {
    const zone = tracy.Zone.init(@src(), .{ .name = "cmd startGossip" });
    defer zone.deinit();

    app_base.logger.info()
        .field("host", app_base.my_ip)
        .field("port", app_base.my_port)
        .log("gossip setup");

    // setup contact info
    const my_pubkey = Pubkey.fromPublicKey(&app_base.my_keypair.public_key);

    var contact_info = ContactInfo.init(allocator, my_pubkey, getWallclockMs(), 0);
    errdefer contact_info.deinit();

    try contact_info.setSocket(.gossip, SocketAddr.init(app_base.my_ip, app_base.my_port));
    for (extra_sockets) |s| {
        try contact_info.setSocket(s.tag, SocketAddr.init(app_base.my_ip, s.port));
    }
    contact_info.shred_version = app_base.shred_version;

    const service = try GossipService.create(
        allocator,
        gossip_value_allocator,
        contact_info,
        app_base.my_keypair, // TODO: consider security implication of passing keypair by value
        app_base.entrypoints,
        .from(app_base.logger),
        broker,
    );

    try service.start(.{
        .spy_node = cfg.gossip.spy_node,
        .dump = cfg.gossip.dump,
    });

    try app_base.rpc_hooks.set(allocator, struct {
        info: ContactInfo,

        pub fn getHealth(
            _: @This(),
            _: std.mem.Allocator,
            _: anytype,
        ) !sig.rpc.methods.GetHealth.Response {
            // TODO: more intricate
            return .ok;
        }

        pub fn getIdentity(
            self: @This(),
            _: std.mem.Allocator,
            _: anytype,
        ) !sig.rpc.methods.GetIdentity.Response {
            return .{ .identity = self.info.pubkey };
        }

        pub fn getVersion(
            self: @This(),
            allocator_: std.mem.Allocator,
            _: anytype,
        ) !sig.rpc.methods.GetVersion.Response {
            const client_version = self.info.version;
            const solana_version = try std.fmt.allocPrint(allocator_, "{}.{}.{}", .{
                client_version.major,
                client_version.minor,
                client_version.patch,
            });

            return .{
                .solana_core = solana_version,
                .feature_set = client_version.feature_set,
            };
        }
    }{ .info = contact_info });

    return service;
}

const ReplayAndConsensusServiceState = struct {
    replay_state: replay.service.ReplayState,
    consensus: ?Consensus,
    metrics: replay.service.Metrics,

    const Consensus = struct {
        tower: replay.TowerConsensus,
        senders: replay.TowerConsensus.Senders,
        receivers: replay.TowerConsensus.Receivers,
    };

    fn deinit(self: *ReplayAndConsensusServiceState, allocator: std.mem.Allocator) void {
        self.replay_state.deinit();
        if (self.consensus) |*c| {
            c.tower.deinit(allocator);
            c.senders.destroy();
            c.receivers.destroy();
        }
    }

    /// Helper for initializing replay state from relevant data.
    fn init(
        allocator: std.mem.Allocator,
        params: struct {
            app_base: *const AppBase,
            account_store: sig.accounts_db.AccountStore,
            loaded_snapshot: *sig.accounts_db.snapshot.LoadedSnapshot,
            ledger: *Ledger,
            epoch_context_manager: *sig.adapter.EpochContextManager,
            replay_threads: u32,
            disable_consensus: bool,
            voting_enabled: bool,
            vote_account_address: ?Pubkey,
            stop_at_slot: ?Slot,
        },
    ) !ReplayAndConsensusServiceState {
        var replay_state: replay.service.ReplayState = replay_state: {
            const account_store = params.account_store;
            const manifest = &params.loaded_snapshot.collapsed_manifest;
            const bank_fields = &manifest.bank_fields;
            const epoch = bank_fields.epoch;

            const epoch_stakes_map = &manifest.bank_extra.versioned_epoch_stakes;
            const epoch_stakes = epoch_stakes_map.get(epoch) orelse
                return error.EpochStakesMissingFromSnapshot;

            const feature_set = try sig.replay.service.getActiveFeatures(
                allocator,
                account_store.reader().forSlot(&bank_fields.ancestors),
                bank_fields.slot,
            );

            const root_slot_constants: sig.core.SlotConstants =
                try .fromBankFields(allocator, bank_fields, feature_set);
            errdefer root_slot_constants.deinit(allocator);

            const lt_hash = manifest.bank_extra.accounts_lt_hash;

            var root_slot_state: sig.core.SlotState =
                try .fromBankFields(allocator, bank_fields, lt_hash);
            errdefer root_slot_state.deinit(allocator);

            const hard_forks = try bank_fields.hard_forks.clone(allocator);
            errdefer hard_forks.deinit(allocator);

            const current_epoch_constants: sig.core.EpochConstants = try .fromBankFields(
                bank_fields,
                try epoch_stakes.current.convert(allocator, .delegation),
            );
            errdefer current_epoch_constants.deinit(allocator);

            break :replay_state try .init(.{
                .allocator = allocator,
                .logger = .from(params.app_base.logger),
                .identity = .{
                    .validator = .fromPublicKey(&params.app_base.my_keypair.public_key),
                    .vote_account = params.vote_account_address,
                },
                .signing = .{
                    .node = params.app_base.my_keypair,
                    .authorized_voters = if (params.voting_enabled)
                        // TODO: Parse authorized voter keypairs from CLI args (--authorized-voter)
                        // For now, default to using the node keypair as the authorized voter
                        // (same as Agave's default behavior when no --authorized-voter is specified)
                        // ref https://github.com/anza-xyz/agave/blob/67a1cc9ef4222187820818d95325a0c8e700312f/validator/src/commands/run/execute.rs#L136-L138
                        &.{params.app_base.my_keypair}
                    else
                        &.{},
                },
                .account_store = account_store,
                .ledger = params.ledger,
                .epoch_schedule = bank_fields.epoch_schedule,
                .slot_leaders = params.epoch_context_manager.slotLeaders(),
                .root = .{
                    .slot = bank_fields.slot,
                    .constants = root_slot_constants,
                    .state = root_slot_state,
                },
                .current_epoch = epoch,
                .current_epoch_constants = current_epoch_constants,
                .hard_forks = hard_forks,
                .replay_threads = params.replay_threads,
                .stop_at_slot = params.stop_at_slot,
            }, if (params.disable_consensus) .disabled else .enabled);
        };
        errdefer replay_state.deinit();

        const consensus: ?Consensus = if (params.disable_consensus) null else c: {
            var tower_consensus: replay.TowerConsensus = try .init(allocator, .{
                .logger = .from(replay_state.logger),
                .identity = replay_state.identity,
                .signing = replay_state.signing,
                .account_reader = replay_state.account_store.reader(),
                .ledger = replay_state.ledger,
                .slot_tracker = &replay_state.slot_tracker,
                .now = .now(),
                .registry = params.app_base.metrics_registry,
            });
            errdefer tower_consensus.deinit(allocator);

            const senders: replay.TowerConsensus.Senders = try .create(allocator);
            errdefer senders.destroy();

            // Create receivers, passing the replay_votes channel owned by ReplayState
            const receivers: replay.TowerConsensus.Receivers = try .create(
                allocator,
                replay_state.replay_votes_channel,
            );
            errdefer receivers.destroy();

            break :c .{
                .tower = tower_consensus,
                .senders = senders,
                .receivers = receivers,
            };
        };

        const metrics = try params.app_base.metrics_registry.initStruct(replay.service.Metrics);

        return .{
            .replay_state = replay_state,
            .consensus = consensus,
            .metrics = metrics,
        };
    }

    /// Run `replay.service.advanceReplay` in a loop as a service.
    fn spawnService(
        self: *ReplayAndConsensusServiceState,
        app_base: *const AppBase,
        vote_sockets: ?*const replay.consensus.core.VoteSockets,
        gossip_votes: ?*sig.sync.Channel(sig.gossip.data.Vote),
    ) !std.Thread {
        return try app_base.spawnService(
            "replay",
            .{
                .return_handler = .{ .log_return = false },
                .error_handler = .{
                    .max_iterations = 0,
                    .set_exit_on_completion = true,
                },
            },
            replay.service.advanceReplay,
            .{
                &self.replay_state,
                self.metrics,
                if (self.consensus) |*c| replay.service.AvanceReplayConsensusParams{
                    .tower = &c.tower,
                    .gossip_votes = gossip_votes,
                    .senders = c.senders,
                    .receivers = c.receivers,
                    .vote_sockets = vote_sockets,
                } else null,
            },
        );
    }
};

fn spawnLogger(
    allocator: std.mem.Allocator,
    cfg: config.Cmd,
) !struct { ?std.fs.File, Logger } {
    const file, const writer = if (cfg.log_file) |path| blk: {
        const file = std.fs.cwd().openFile(path, .{ .mode = .write_only }) catch |e| switch (e) {
            error.FileNotFound => try std.fs.cwd().createFile(path, .{}),
            else => return e,
        };
        try file.seekFromEnd(0);
        break :blk .{ file, file.writer() };
    } else .{ null, null };

    var std_logger = try ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_buffer = 1 << 20,
        .write_stderr = cfg.tee_logs or cfg.log_file == null,
    }, writer);

    return .{ file, .from(std_logger.logger("spawnLogger", cfg.log_filters)) };
}

/// entrypoint to download snapshot
fn downloadSnapshot(
    allocator: std.mem.Allocator,
    gossip_value_allocator: std.mem.Allocator,
    cfg: config.Cmd,
) !void {
    var app_base = try AppBase.init(allocator, cfg);
    errdefer {
        app_base.shutdown();
        app_base.deinit();
    }

    if (app_base.entrypoints.len == 0) {
        @panic("cannot download a snapshot with no entrypoints");
    }
    const gossip_service = try startGossip(
        allocator,
        gossip_value_allocator,
        cfg,
        &app_base,
        &.{},
        .{},
    );
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    const trusted_validators = try getTrustedValidators(allocator, cfg);
    defer if (trusted_validators) |*tvs| tvs.deinit();

    const snapshot_dir_str = cfg.accounts_db.snapshot_dir;
    const min_mb_per_sec = cfg.accounts_db.min_snapshot_download_speed_mbs;

    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{});
    defer snapshot_dir.close();

    const full_file, const maybe_inc_file = try downloadSnapshotsFromGossip(
        allocator,
        .from(app_base.logger),
        if (trusted_validators) |trusted| trusted.items else null,
        gossip_service,
        snapshot_dir,
        @intCast(min_mb_per_sec),
        cfg.accounts_db.max_number_of_snapshot_download_attempts,
        null,
    );
    defer full_file.close();
    defer if (maybe_inc_file) |inc_file| inc_file.close();
}

fn getTrustedValidators(allocator: std.mem.Allocator, cfg: config.Cmd) !?std.ArrayList(Pubkey) {
    var trusted_validators: ?std.ArrayList(Pubkey) = null;
    if (cfg.gossip.trusted_validators.len > 0) {
        trusted_validators = try std.ArrayList(Pubkey).initCapacity(
            allocator,
            cfg.gossip.trusted_validators.len,
        );
        for (cfg.gossip.trusted_validators) |trusted_validator| {
            trusted_validators.?.appendAssumeCapacity(try Pubkey.parseRuntime(trusted_validator));
        }
    }
    return trusted_validators;
}

pub const panic = std.debug.FullPanic(loggingPanic);

fn loggingPanic(message: []const u8, first_trace_addr: ?usize) noreturn {
    std.debug.lockStdErr();
    defer std.debug.unlockStdErr();
    const writer = std.io.getStdErr().writer();
    sig.trace.logfmt.writeLog(writer, "panic", .@"error", .{}, "{s}", .{message}) catch {};
    std.debug.defaultPanic(message, first_trace_addr);
}
