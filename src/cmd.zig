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
const Gauge = sig.prometheus.gauge.Gauge;
const FullAndIncrementalManifest = sig.accounts_db.snapshot.FullAndIncrementalManifest;
const GenesisConfig = sig.core.GenesisConfig;
const GeyserWriter = sig.geyser.GeyserWriter;
const GossipService = sig.gossip.GossipService;
const IpAddr = sig.net.IpAddr;
const LeaderSchedule = sig.core.leader_schedule.LeaderSchedule;
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
const downloadAndExtractGenesis = sig.core.genesis_download.downloadAndExtractGenesis;

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

    var tracing_gpa: tracy.TracingAllocator = .{
        .name = "gpa",
        .parent = gpa_state.allocator(),
    };
    const gpa = tracing_gpa.allocator();

    var tracing_gossip_gpa: tracy.TracingAllocator = .{
        .name = "gossip gpa",
        .parent = tracing_gpa.allocator(),
    };
    const gossip_gpa = tracing_gossip_gpa.allocator();

    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);

    const parser = cli.Parser(Cmd, Cmd.cmd_info);
    const tty_config = std.io.tty.detectConfig(.stdout());
    const stdout = std.fs.File.stdout().deprecatedWriter();
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
    current_config.validator_dir = try ensureValidatorDir(gpa, cmd.validator_dir);

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
            current_config.shred_network.log_finished_slots = params.repair.log_finished_slots;
            current_config.accounts_db.snapshot_dir = try current_config.derivePathFromValidatorDir(
                gpa,
                params.snapshot_dir,
                "accounts_db",
            );
            current_config.cli_provided_genesis_file_path = params.genesis_file_path;
            params.accountsdb_base.apply(&current_config);
            params.accountsdb_download.apply(&current_config);
            params.geyser.apply(&current_config);
            current_config.geyser.pipe_path = try current_config.derivePathFromValidatorDir(
                gpa,
                current_config.geyser.pipe_path,
                "geyser.pipe",
            );
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
            current_config.accounts_db.snapshot_dir = try current_config.derivePathFromValidatorDir(
                gpa,
                params.snapshot_dir,
                "accounts_db",
            );
            current_config.cli_provided_genesis_file_path = params.genesis_file_path;
            params.accountsdb_base.apply(&current_config);
            params.accountsdb_download.apply(&current_config);
            params.geyser.apply(&current_config);
            current_config.geyser.pipe_path = try current_config.derivePathFromValidatorDir(
                gpa,
                current_config.geyser.pipe_path,
                "geyser.pipe",
            );
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
            current_config.cli_provided_genesis_file_path = params.genesis_file_path;
            current_config.shred_network.dump_shred_tracker = params.repair.dump_shred_tracker;
            current_config.shred_network.log_finished_slots = params.repair.log_finished_slots;
            current_config.turbine.overwrite_stake_for_testing =
                params.overwrite_stake_for_testing;
            current_config.shred_network.no_retransmit = params.no_retransmit;
            current_config.accounts_db.snapshot_metadata_only = params.snapshot_metadata_only;
            try shredNetwork(gpa, gossip_gpa, current_config);
        },
        .snapshot_download => |params| {
            current_config.shred_version = params.shred_version;
            current_config.accounts_db.snapshot_dir = try current_config.derivePathFromValidatorDir(
                gpa,
                params.snapshot_dir,
                "accounts_db",
            );
            params.accountsdb_download.apply(&current_config);
            params.gossip_base.apply(&current_config);
            try downloadSnapshot(gpa, gossip_gpa, current_config);
        },
        .snapshot_validate => |params| {
            current_config.accounts_db.snapshot_dir = try current_config.derivePathFromValidatorDir(
                gpa,
                params.snapshot_dir,
                "accounts_db",
            );
            current_config.cli_provided_genesis_file_path = params.genesis_file_path;
            params.accountsdb_base.apply(&current_config);
            current_config.cluster = params.gossip_cluster;
            params.geyser.apply(&current_config);
            current_config.geyser.pipe_path = try current_config.derivePathFromValidatorDir(
                gpa,
                current_config.geyser.pipe_path,
                "geyser.pipe",
            );
            try validateSnapshot(gpa, current_config);
        },
        .snapshot_create => |params| {
            // current_config.accounts_db.snapshot_dir = params.snapshot_dir;
            // current_config.cli_provided_genesis_file_path = params.genesis_file_path;
            // try createSnapshot(gpa, current_config);
            _ = params;
            @panic("TODO: support snapshot creation");
        },
        .print_manifest => |params| {
            current_config.accounts_db.snapshot_dir = try current_config.derivePathFromValidatorDir(
                gpa,
                params.snapshot_dir,
                "accounts_db",
            );
            try printManifest(gpa, current_config);
        },
        .leader_schedule => |params| {
            current_config.shred_version = params.shred_version;
            current_config.leader_schedule_path = params.leader_schedule;
            params.gossip_base.apply(&current_config);
            params.gossip_node.apply(&current_config);
            current_config.accounts_db.snapshot_dir = try current_config.derivePathFromValidatorDir(
                gpa,
                params.snapshot_dir,
                "accounts_db",
            );
            current_config.cli_provided_genesis_file_path = params.genesis_file_path;
            params.accountsdb_base.apply(&current_config);
            params.accountsdb_download.apply(&current_config);
            try printLeaderSchedule(gpa, current_config);
        },
        .test_transaction_sender => |params| {
            current_config.shred_version = params.shred_version;
            current_config.cli_provided_genesis_file_path = params.genesis_file_path;
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

            current_config.accounts_db.snapshot_dir = try current_config.derivePathFromValidatorDir(
                gpa,
                params.snapshot_dir,
                "accounts_db",
            );
            current_config.cli_provided_genesis_file_path = params.genesis_file_path;
            params.accountsdb_base.apply(&current_config);
            params.accountsdb_download.apply(&current_config);
            try mockRpcServer(gpa, current_config);
        },
        .agave_migration_tool => |params| {
            var app_base = try AppBase.init(gpa, current_config);
            defer {
                app_base.shutdown();
                app_base.deinit();
            }

            const out_dir = params.out_dir orelse return error.NoOutDirSpecified;

            switch (params.direction) {
                .sig_to_agave => try sig.ledger.database.agave_migration.migrateLedgerToAgave(
                    gpa,
                    .from(app_base.logger),
                    params.in_dir,
                    out_dir,
                ),
                .agave_to_sig => try sig.ledger.database.agave_migration.migrateLedgerFromAgave(
                    gpa,
                    .from(app_base.logger),
                    params.in_dir,
                    out_dir,
                ),
            }
        },
        .ledger => |params| {
            const action = params.action orelse {
                _ = try parser.parse(gpa, "sig", tty_config, stdout, &.{ "ledger", "--help" });
                return;
            };
            try ledgerTool(gpa, current_config, action);
        },
    }
}

const Cmd = struct {
    log_filters: []const u8,
    metrics_port: u16,
    log_file: ?[]const u8,
    tee_logs: bool,
    validator_dir: []const u8,
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
        agave_migration_tool: AgaveMigrationTool,
        ledger: LedgerSubCmd,
    },

    const cmd_info: cli.CommandInfo(@This()) = .{
        .help = .{
            .short = std.fmt.comptimePrint(
                \\Version: {f}
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
                .agave_migration_tool = AgaveMigrationTool.cmd_info,
                .ledger = LedgerSubCmd.cmd_info,
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
            .validator_dir = .{
                .kind = .named,
                .name_override = "validator-dir",
                .alias = .d,
                .default_value = sig.VALIDATOR_DIR,
                .config = .string,
                .help =
                \\base directory for all validator data (ledger, accounts_db, geyser pipe).
                \\Subdirectory paths are derived from this base unless explicitly overridden.
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
        .help = "path to snapshot directory (where snapshots are downloaded and/or unpacked). " ++
            "Defaults to <validator-dir>/accounts_db. Overrides --validator-dir for this path.",
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
            cfg.cluster = args.network;
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
        dbg_db_init: bool,

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
            .dbg_db_init = .{
                .kind = .named,
                .name_override = "dbg-db-init",
                .alias = .none,
                .default_value = false,
                .config = {},
                .help =
                \\save/restore the initial accounts.db to/from accounts.db.init for fast debug cycles.
                \\first run: loads snapshot normally, then copies accounts.db -> accounts.db.init.
                \\subsequent runs: copies accounts.db.init -> accounts.db, skipping db population.
                ,
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
            cfg.accounts_db.dbg_db_init = args.dbg_db_init;
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
        log_finished_slots: bool,

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
            .log_finished_slots = .{
                .kind = .named,
                .name_override = "log-finished-slots",
                .alias = .none,
                .default_value = false,
                .config = {},
                .help = "Log the highest finished slot when it updates.",
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
                .help =
                \\path to the geyser pipe.
                \\Defaults to <validator-dir>/geyser.pipe. Overrides --validator-dir for this path.
                ,
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

    const in_dir_arg: cli.ArgumentInfo([]const u8) = .{
        .kind = .named,
        .name_override = "in-dir",
        .alias = .i,
        .default_value = sig.VALIDATOR_DIR ++ "ledger",
        .config = .string,
        .help = "path to Sig ledger directory",
    };

    const out_dir_arg: cli.ArgumentInfo(?[]const u8) = .{
        .kind = .named,
        .name_override = "out-dir",
        .alias = .o,
        .default_value = null,
        .config = .string,
        .help = "path to Agave ledger directory",
    };

    const MigrationDirection = enum { agave_to_sig, sig_to_agave };

    const direction_arg: cli.ArgumentInfo(MigrationDirection) = .{
        .kind = .named,
        .name_override = "direction",
        .alias = .d,
        .config = {},
        .default_value = .agave_to_sig,
        .help = "format migration direction",
    };

    const AgaveMigrationTool = struct {
        in_dir: []const u8,
        out_dir: ?[]const u8,
        direction: MigrationDirection,

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "Convert between Sig and Agave ledger formats",
                .long =
                \\Migrates to and from Sig's and Agave's RocksDb ledger formats.
                \\
                \\This tool is to be used when you have a ledger made by Agave which you want to run
                \\with Sig, or vice versa.
                \\
                \\Usage:
                \\1. Make a new directory to output the newly formatted ledger.
                \\2. Build Sig (release build recommended).
                \\3. Run
                \\   a) sig agave-migration-tool -i sig-ledger-dir -o agave-ledger-dir
                \\   b) sig agave-migration-tool -i agave-ledger-dir -o sig-ledger-dir
                \\4. Copy over the snapshot files as needed for the outputted ledger directory.
                \\5. If converting a Sig ledger to Agave, run agave with e.g.
                \\
                \\   $bin/agave-validator
                \\      --identity $identity
                \\      --ledger $ledger
                \\      --entrypoint entrypoint.testnet.solana.com:8001
                \\      --rpc-port 8899
                \\      --no-voting
                \\      --no-snapshots
                \\      --no-snapshot-fetch
                \\      --use-snapshot-archives-at-startup always
                \\      --limit-ledger-size 50000000000000 
                \\
                \\   After this has processed the ledger, it will be usable from other agave tools.
                ,
            },
            .sub = .{
                .in_dir = in_dir_arg,
                .out_dir = out_dir_arg,
                .direction = direction_arg,
            },
        };
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
        genesis_file_path: ?[]const u8,
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
                .genesis_file_path = genesis_file_path_arg,
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

    const LedgerSubCmd = struct {
        action: ?union(enum) {
            bounds,
            retain: Retain,
        },

        const Retain = struct {
            start_slot: ?Slot,
            end_slot: ?Slot,
        };

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "Ledger utilities for inspecting and modifying the ledger database.",
                .long =
                \\Provides utilities for working with the ledger database:
                \\
                \\  bounds  - Print the min and max slot in the ledger
                \\  retain  - Remove all slots from the ledger outside the specified range
                \\
                \\Use --validator-dir to specify the validator directory containing the ledger.
                ,
            },
            .sub = .{
                .action = .{
                    .bounds = .{
                        .help = .{
                            .short = "Print the min and max slot in the ledger.",
                            .long = null,
                        },
                        .sub = .{},
                    },
                    .retain = .{
                        .help = .{
                            .short = "Remove all slots from the ledger outside the specified range.",
                            .long =
                            \\Removes all slots from the ledger that are outside the range
                            \\[start-slot, end-slot]. If start-slot is not specified, it defaults
                            \\to the minimum slot in the ledger. If end-slot is not specified,
                            \\it defaults to the maximum slot in the ledger.
                            ,
                        },
                        .sub = .{
                            .start_slot = .{
                                .kind = .named,
                                .name_override = "start-slot",
                                .alias = .none,
                                .default_value = null,
                                .config = {},
                                .help =
                                \\The first slot to retain (inclusive). 
                                \\Defaults to min slot in ledger.
                                ,
                            },
                            .end_slot = .{
                                .kind = .named,
                                .name_override = "end-slot",
                                .alias = .none,
                                .default_value = null,
                                .config = {},
                                .help =
                                \\The last slot to retain (inclusive). 
                                \\Defaults to max slot in ledger.
                                ,
                            },
                        },
                    },
                },
            },
        };
    };
};

const AllocationMetrics = struct {
    allocated_bytes_gpa: *Gauge(u64),
    allocated_bytes_load_snapshot: *Gauge(u64),
    allocated_bytes_accountsdb_unrooted: *Gauge(u64),
    allocated_bytes_ledger: *Gauge(u64),
    allocated_bytes_sqlite: *Gauge(u64),
};

/// Checks for an `accounts.db.init` snapshot in `snapshot_dir` to speed up debug cycles.
///
/// - If `accounts.db.init` exists: copies it over `accounts.db` and returns `true`.
///   The caller should then load the snapshot with `.metadata_only` to skip repopulating the DB.
/// - If `accounts.db.init` does not exist: returns `false`.
///   The caller should load the snapshot normally, then call `saveDbInit` afterwards.
fn restoreDbInitIfExists(snapshot_dir: std.fs.Dir, logger: Logger) !bool {
    if (snapshot_dir.access("accounts.db.init", .{})) {
        logger.info().log("--dbg-db-init: accounts.db.init found, restoring to accounts.db");
        try std.fs.Dir.copyFile(snapshot_dir, "accounts.db.init", snapshot_dir, "accounts.db", .{});
        return true;
    } else |_| {
        logger.info().log(
            "--dbg-db-init: accounts.db.init not found, will save after snapshot load",
        );
        return false;
    }
}

/// Copies `accounts.db` to `accounts.db.init` after a successful snapshot load.
/// Called on the first run with `--dbg-db-init` when no `.init` file exists yet.
fn saveDbInit(snapshot_dir: std.fs.Dir, logger: Logger) !void {
    logger.info().log("--dbg-db-init: saving accounts.db to accounts.db.init");
    try std.fs.Dir.copyFile(snapshot_dir, "accounts.db", snapshot_dir, "accounts.db.init", .{});
}

/// Ensures the validator directory exists. Create it if it does not.
fn ensureValidatorDir(allocator: std.mem.Allocator, validator_dir: []const u8) ![]const u8 {
    std.fs.cwd().access(validator_dir, .{}) catch |access_err| {
        switch (access_err) {
            error.FileNotFound => {
                std.fs.cwd().makePath(validator_dir) catch |create_err| {
                    std.debug.print(
                        "Cannot create validator directory '{s}': {}",
                        .{ validator_dir, create_err },
                    );
                    return create_err;
                };
            },
            else => {
                std.debug.print(
                    "Cannot access validator directory '{s}': {}",
                    .{ validator_dir, access_err },
                );
                return access_err;
            },
        }
    };
    return std.fs.realpathAlloc(allocator, validator_dir);
}

/// Ensures a genesis file is available by either using the provided path
/// or downloading it from the network for the specified cluster.
///
/// Returns the path to the genesis file. If downloaded, the file is stored
/// in `<validator_dir>/genesis.bin`.
///
/// TODO: The hash is NOT verified against the cluster's expected genesis hash.
fn ensureGenesis(
    allocator: std.mem.Allocator,
    cfg: config.Cmd,
    logger: Logger,
) ![]const u8 {
    // If explicit path provided, use it directly
    if (try cfg.genesisFilePath()) |provided_path| {
        logger.info().logf("Using provided genesis file: {s}", .{provided_path});
        return try allocator.dupe(u8, provided_path);
    }

    // If genesis already exists in validator dir, use it
    const existing_path = try std.fs.path.join(
        allocator,
        &.{ cfg.validator_dir, "genesis.bin" },
    );
    errdefer allocator.free(existing_path);
    const maybe_genesis_file: ?std.fs.File = std.fs.cwd().openFile(
        existing_path,
        .{},
    ) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (maybe_genesis_file != null) {
        logger.info().logf("Using existing genesis file: {s}", .{existing_path});
        maybe_genesis_file.?.close();
        return existing_path;
    }
    allocator.free(existing_path);

    // Determine cluster for genesis
    const cluster = try cfg.getCluster() orelse {
        logger.err().log(
            \\No genesis file path provided and no cluster specified. 
            \\Use --genesis-file-path or --cluster"
        );
        return error.GenesisPathNotProvided;
    };

    // Otherwise, download genesis from network
    logger.info().logf("Downloading genesis from {s} cluster...", .{@tagName(cluster)});
    const cluster_url = cluster.getRpcUrl() orelse @panic("No RPC Url!");
    const genesis_path = downloadAndExtractGenesis(
        allocator,
        cluster_url,
        cfg.validator_dir,
        .from(logger),
    ) catch |err| {
        logger.err().logf("Failed to download genesis: {}", .{err});
        return error.GenesisDownloadFailed;
    };

    logger.info().logf("Genesis downloaded to: {s}", .{genesis_path});
    return genesis_path;
}

/// entrypoint to print (and create if NONE) pubkey in ~/.sig/identity.key
fn identity(allocator: std.mem.Allocator, cfg: config.Cmd) !void {
    const maybe_file, const logger = try spawnLogger(allocator, cfg);
    defer if (maybe_file) |file| file.close();
    defer logger.deinit();

    const keypair = try sig.identity.getOrInit(allocator, .from(logger));
    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);

    logger.info().logf("Identity: {f}", .{pubkey});
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
    gpa: std.mem.Allocator,
    gossip_value_allocator: std.mem.Allocator,
    cfg: config.Cmd,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "validator" });
    defer zone.deinit();

    var app_base = try AppBase.init(gpa, cfg);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    app_base.logger.info().logf("starting validator with cfg: {}", .{cfg});

    const allocation_metrics = try app_base.metrics_registry.initStruct(AllocationMetrics);

    var gpa_metrics: sig.trace.GaugeAllocator = .{
        .counter = allocation_metrics.allocated_bytes_gpa,
        .parent = gpa,
    };

    const allocator = gpa_metrics.allocator();

    const genesis_file_path = try ensureGenesis(allocator, cfg, app_base.logger);
    defer allocator.free(genesis_file_path);

    const repair_port: u16 = cfg.shred_network.repair_port;
    const turbine_recv_port: u16 = cfg.shred_network.turbine_recv_port;
    const snapshot_dir_str = cfg.accounts_db.snapshot_dir;

    const ledger_dir = try std.fs.path.join(allocator, &.{ cfg.validator_dir, "ledger" });
    defer allocator.free(ledger_dir);

    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{
        .iterate = true,
    });
    defer snapshot_dir.close();

    var gossip_votes: sig.sync.Channel(sig.gossip.data.Vote) = try .init(allocator);
    defer gossip_votes.deinit();

    var duplicate_shreds: sig.sync.Channel(sig.gossip.data.DuplicateShred) = try .init(allocator);
    defer duplicate_shreds.deinit();

    var gossip_service = try startGossip(
        allocator,
        gossip_value_allocator,
        cfg,
        &app_base,
        &.{
            .{ .tag = .repair, .port = repair_port },
            .{ .tag = .turbine_recv, .port = turbine_recv_port },
        },
        .{
            .vote_collector = &gossip_votes,
            .duplicate_shred_listener = &duplicate_shreds,
        },
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

    var snapshot_tracy: tracy.TracingAllocator = .{
        .name = "loadSnapshot",
        .parent = allocator,
    };
    var snapshot_tracy_metrics: sig.trace.GaugeAllocator = .{
        .counter = allocation_metrics.allocated_bytes_load_snapshot,
        .parent = snapshot_tracy.allocator(),
    };

    const snapshot_files = try sig.accounts_db.snapshot.download.getOrDownloadSnapshotFiles(
        snapshot_tracy_metrics.allocator(),
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

    const init_db_exists: bool = if (cfg.accounts_db.dbg_db_init)
        try restoreDbInitIfExists(snapshot_dir, .from(app_base.logger))
    else
        false;

    var rooted_db: sig.accounts_db.Two.Rooted = try .init(rooted_file);
    defer rooted_db.deinit();
    rooted_db.sqlite_mem_used = allocation_metrics.allocated_bytes_sqlite;

    // snapshot
    var loaded_snapshot = try loadSnapshot(
        allocator,
        .from(app_base.logger),
        snapshot_dir,
        snapshot_files,
        .{
            .genesis_file_path = genesis_file_path,
            .extract = if (init_db_exists)
                .metadata_only
            else if (cfg.accounts_db.skip_snapshot_validation)
                .{ .entire_snapshot = &rooted_db }
            else
                .{ .entire_snapshot_and_validate = &rooted_db },
        },
    );
    defer loaded_snapshot.deinit();

    if (cfg.accounts_db.dbg_db_init and !init_db_exists)
        try saveDbInit(snapshot_dir, .from(app_base.logger));

    const static_rpc_ctx: sig.rpc.methods.StaticHookContext = .{
        .genesis_hash = loaded_snapshot.genesis_config.hash,
    };

    try app_base.rpc_hooks.set(allocator, &static_rpc_ctx);

    var unrooted_tracy: tracy.TracingAllocator = .{
        .name = "AccountsDB Unrooted",
        .parent = allocator,
    };
    var unrooted_tracy_metrics: sig.trace.GaugeAllocator = .{
        .counter = allocation_metrics.allocated_bytes_accountsdb_unrooted,
        .parent = unrooted_tracy.allocator(),
    };

    var new_db: sig.accounts_db.Two = try .init(unrooted_tracy_metrics.allocator(), rooted_db);
    defer new_db.deinit();

    const collapsed_manifest = &loaded_snapshot.collapsed_manifest;

    var ledger_tracy: tracy.TracingAllocator = .{
        .name = "Ledger",
        .parent = allocator,
    };
    var ledger_tracy_metrics: sig.trace.GaugeAllocator = .{
        .counter = allocation_metrics.allocated_bytes_ledger,
        .parent = ledger_tracy.allocator(),
    };

    // ledger
    var ledger = try Ledger.init(
        ledger_tracy_metrics.allocator(),
        .from(app_base.logger),
        ledger_dir,
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

    const feature_set = try loaded_snapshot.featureSet(allocator, &new_db);
    var epoch_tracker = try sig.core.EpochTracker.initFromManifest(
        allocator,
        collapsed_manifest,
        &feature_set,
    );
    defer epoch_tracker.deinit(allocator);

    const rpc_cluster_type = loaded_snapshot.genesis_config.cluster_type;
    const rpc_url = rpc_cluster_type.getRpcUrl() orelse @panic("No RPC Url for cluster type!");
    var rpc_client = try sig.rpc.Client.init(allocator, rpc_url, .{});
    defer rpc_client.deinit();

    const turbine_config = cfg.turbine;

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
        .epoch_tracker = &epoch_tracker,
        .replay_threads = cfg.replay_threads,
        .disable_consensus = cfg.disable_consensus,
        .voting_enabled = voting_enabled,
        .vote_account_address = maybe_vote_pubkey,
        .stop_at_slot = cfg.stop_at_slot,
    });
    defer replay_service_state.deinit(allocator);

    const account_store = sig.accounts_db.AccountStore{
        .accounts_db_two = &new_db,
    };

    // Health check override for RPC (can be set to true to force healthy status)
    var override_health_check: std.atomic.Value(bool) = .init(false);

    try app_base.rpc_hooks.set(allocator, sig.rpc.methods.RpcHookContext{
        .slot_tracker = &replay_service_state.replay_state.slot_tracker,
        .epoch_tracker = &epoch_tracker,
        .account_reader = account_store.reader(),
        .ledger = &ledger,
        .override_health_check = &override_health_check,
    });

    const replay_thread = try replay_service_state.spawnService(
        &app_base,
        if (maybe_vote_sockets) |*vs| vs else null,
        &gossip_votes,
        &gossip_service.gossip_table_rw,
    );

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
            .epoch_tracker = &epoch_tracker,
            .my_contact_info = my_contact_info,
            .n_retransmit_threads = turbine_config.num_retransmit_threads,
            .overwrite_turbine_stake_for_testing = turbine_config.overwrite_stake_for_testing,
            .rpc_hooks = null,
            .duplicate = if (replay_service_state.consensus) |consensus| .{
                .shred_receiver = &duplicate_shreds,
                .slots_sender = consensus.receivers.duplicate_slots,
            } else null,
            .push_msg_queue_mux = &gossip_service.push_msg_queue_mux,
        },
    );
    defer shred_network_manager.deinit();

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
    gpa: std.mem.Allocator,
    cfg: config.Cmd,
) !void {
    const zone = tracy.Zone.init(@src(), .{ .name = "cmd.replay" });
    defer zone.deinit();

    var app_base = try AppBase.init(gpa, cfg);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    app_base.logger.info().logf("starting replay-offline with cfg: {}", .{cfg});

    const allocation_metrics = try app_base.metrics_registry.initStruct(AllocationMetrics);

    var gpa_metrics: sig.trace.GaugeAllocator = .{
        .counter = allocation_metrics.allocated_bytes_gpa,
        .parent = gpa,
    };

    const allocator = gpa_metrics.allocator();

    const genesis_file_path = try ensureGenesis(allocator, cfg, app_base.logger);
    defer allocator.free(genesis_file_path);

    var snapshot_dir = try std.fs.cwd().makeOpenPath(
        cfg.accounts_db.snapshot_dir,
        .{ .iterate = true },
    );
    defer snapshot_dir.close();

    const ledger_dir = try std.fs.path.join(allocator, &.{ cfg.validator_dir, "ledger" });
    defer allocator.free(ledger_dir);

    const snapshot_files = try SnapshotFiles.find(allocator, snapshot_dir);

    const rooted_file = try std.fs.path.joinZ(
        allocator,
        &.{ cfg.accounts_db.snapshot_dir, "accounts.db" },
    );
    defer allocator.free(rooted_file);

    const init_db_exists: bool = if (cfg.accounts_db.dbg_db_init)
        try restoreDbInitIfExists(snapshot_dir, .from(app_base.logger))
    else
        false;

    var rooted_db: sig.accounts_db.Two.Rooted = try .init(rooted_file);
    defer rooted_db.deinit();
    rooted_db.sqlite_mem_used = allocation_metrics.allocated_bytes_sqlite;

    var snapshot_tracy: tracy.TracingAllocator = .{
        .name = "loadSnapshot",
        .parent = allocator,
    };
    var snapshot_tracy_metrics: sig.trace.GaugeAllocator = .{
        .counter = allocation_metrics.allocated_bytes_load_snapshot,
        .parent = snapshot_tracy.allocator(),
    };

    // snapshot
    var loaded_snapshot = try loadSnapshot(
        snapshot_tracy_metrics.allocator(),
        .from(app_base.logger),
        snapshot_dir,
        snapshot_files,
        .{
            .genesis_file_path = genesis_file_path,
            .extract = if (init_db_exists)
                .metadata_only
            else if (cfg.accounts_db.skip_snapshot_validation)
                .{ .entire_snapshot = &rooted_db }
            else
                .{ .entire_snapshot_and_validate = &rooted_db },
        },
    );
    defer loaded_snapshot.deinit();

    if (cfg.accounts_db.dbg_db_init and !init_db_exists)
        try saveDbInit(snapshot_dir, .from(app_base.logger));

    var unrooted_tracy: tracy.TracingAllocator = .{
        .name = "AccountsDB Unrooted",
        .parent = allocator,
    };
    var unrooted_tracy_metrics: sig.trace.GaugeAllocator = .{
        .counter = allocation_metrics.allocated_bytes_accountsdb_unrooted,
        .parent = unrooted_tracy.allocator(),
    };

    var new_db: sig.accounts_db.Two = try .init(unrooted_tracy_metrics.allocator(), rooted_db);
    defer new_db.deinit();

    const collapsed_manifest = &loaded_snapshot.collapsed_manifest;

    var ledger_tracy: tracy.TracingAllocator = .{
        .name = "Ledger",
        .parent = allocator,
    };
    var ledger_tracy_metrics: sig.trace.GaugeAllocator = .{
        .counter = allocation_metrics.allocated_bytes_ledger,
        .parent = ledger_tracy.allocator(),
    };

    // ledger
    var ledger = try Ledger.init(
        ledger_tracy_metrics.allocator(),
        .from(app_base.logger),
        ledger_dir,
        app_base.metrics_registry,
    );
    defer ledger.deinit();
    const ledger_cleanup_service = try std.Thread.spawn(.{}, sig.ledger.cleanup_service.run, .{
        sig.ledger.cleanup_service.Logger.from(app_base.logger),
        &ledger,
        cfg.max_shreds,
        app_base.exit,
    });

    const feature_set = try loaded_snapshot.featureSet(allocator, &new_db);
    var epoch_tracker = try sig.core.EpochTracker.initFromManifest(
        allocator,
        collapsed_manifest,
        &feature_set,
    );
    defer epoch_tracker.deinit(allocator);

    var replay_service_state: ReplayAndConsensusServiceState = try .init(allocator, .{
        .app_base = &app_base,
        .account_store = .{ .accounts_db_two = &new_db },
        .loaded_snapshot = &loaded_snapshot,
        .ledger = &ledger,
        .epoch_tracker = &epoch_tracker,
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

    const genesis_file_path = try ensureGenesis(allocator, cfg, app_base.logger);
    defer allocator.free(genesis_file_path);
    const genesis_config = try GenesisConfig.init(allocator, genesis_file_path);

    const ledger_dir = try std.fs.path.join(allocator, &.{ cfg.validator_dir, "ledger" });
    defer allocator.free(ledger_dir);

    const rpc_url = genesis_config.cluster_type.getRpcUrl() orelse
        @panic("No RPC Url for cluster type!");
    var rpc_client = try sig.rpc.Client.init(allocator, rpc_url, .{});
    defer rpc_client.deinit();

    const shred_network_conf = cfg.shred_network.toConfig(
        cfg.shred_network.root_slot orelse blk: {
            const response = try rpc_client.getSlot(.{});
            break :blk try response.result();
        },
    );
    app_base.logger.info().logf(
        "Starting after assumed root slot: {any}",
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

    var epoch_tracker = sig.core.EpochTracker.init(
        .initFromGenesisConfig(&genesis_config),
        shred_network_conf.root_slot,
        genesis_config.epoch_schedule,
    );
    defer epoch_tracker.deinit(allocator);

    var rpc_epoch_ctx_service = RpcLeaderScheduleService
        .init(allocator, .from(app_base.logger), &epoch_tracker, rpc_client);
    const rpc_epoch_ctx_service_thread = try std.Thread.spawn(
        .{},
        RpcLeaderScheduleService.run,
        .{ &rpc_epoch_ctx_service, app_base.exit },
    );

    var start = sig.time.Timer.start();
    while (start.read().asSecs() < 30) {
        const leader_schedules = epoch_tracker.getLeaderSchedules() catch {
            std.Thread.sleep(1_000_000_000);
            continue;
        };
        if (leader_schedules.next != null) break;
    }

    var ledger = try Ledger.init(
        allocator,
        .from(app_base.logger),
        ledger_dir,
        app_base.metrics_registry,
    );
    defer ledger.deinit();
    const ledger_cleanup_service = try std.Thread.spawn(.{}, sig.ledger.cleanup_service.run, .{
        sig.ledger.cleanup_service.Logger.from(app_base.logger),
        &ledger,
        cfg.max_shreds,
        app_base.exit,
    });

    var prng: std.Random.DefaultPrng = .init(@bitCast(std.time.timestamp()));

    const my_contact_info: sig.gossip.data.ThreadSafeContactInfo =
        .fromContactInfo(gossip_service.my_contact_info);

    // shred networking
    var shred_network_manager = try sig.shred_network.start(shred_network_conf, .{
        .allocator = allocator,
        .logger = .from(app_base.logger),
        .registry = app_base.metrics_registry,
        .random = prng.random(),
        .ledger = &ledger,
        .exit = app_base.exit,
        .my_keypair = &app_base.my_keypair,
        .gossip_table_rw = &gossip_service.gossip_table_rw,
        .my_shred_version = &gossip_service.my_shred_version,
        .epoch_tracker = &epoch_tracker,
        .my_contact_info = my_contact_info,
        .n_retransmit_threads = cfg.turbine.num_retransmit_threads,
        .overwrite_turbine_stake_for_testing = cfg.turbine.overwrite_stake_for_testing,
        .rpc_hooks = null,
        // No consensus in the standalone mode, so duplicate slots are not reported.
        .duplicate = null,
        .push_msg_queue_mux = &gossip_service.push_msg_queue_mux,
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

    const genesis_file_path = try ensureGenesis(allocator, cfg, .from(app_base.logger));
    defer allocator.free(genesis_file_path);

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
            .genesis_file_path = genesis_file_path,
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

    const leader_schedule //
    = try getLeaderScheduleFromCli(allocator, cfg) orelse b: {
        const cluster_type = try cfg.getCluster() orelse
            return error.ClusterNotProvided;

        const rpc_url = cluster_type.getRpcUrl() orelse @panic("No RPC Url for cluster type!");
        var rpc_client = try sig.rpc.Client.init(allocator, rpc_url, .{});
        defer rpc_client.deinit();

        const slot = blk: {
            const response = try rpc_client.getSlot(.{});
            defer response.deinit();
            break :blk try response.result();
        };

        const leader_schedule = blk: {
            const response = try rpc_client.getLeaderSchedule(.{ .slot = slot });
            defer response.deinit();

            const rpc_schedule = (try response.result()).value;
            break :blk try sig.core.leader_schedule.computeFromMap(
                allocator,
                &rpc_schedule,
            );
        };
        break :b leader_schedule;
    };
    defer leader_schedule.deinit(allocator);

    var buffer: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&buffer);
    try leader_schedule.write(&stdout.interface);
    try stdout.interface.flush();
}

fn getLeaderScheduleFromCli(
    allocator: std.mem.Allocator,
    cfg: config.Cmd,
) !?LeaderSchedule {
    return if (cfg.leader_schedule_path) |path|
        if (std.mem.eql(u8, "--", path))
            try LeaderSchedule.read(allocator, std.fs.File.stdin().deprecatedReader())
        else
            try LeaderSchedule.read(
                allocator,
                (try std.fs.cwd().openFile(path, .{})).deprecatedReader(),
            )
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
    const genesis_file_path = try ensureGenesis(allocator, cfg, .from(app_base.logger));
    defer allocator.free(genesis_file_path);

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
    const rpc_cluster: ClusterType = try cfg.getCluster() orelse {
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
    const rpc_url = rpc_cluster.getRpcUrl() orelse @panic("No RPC Url for cluster type!");
    var rpc_client = try sig.rpc.Client.init(allocator, rpc_url, .{
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

/// Entrypoint for ledger utilities
fn ledgerTool(
    allocator: std.mem.Allocator,
    cfg: config.Cmd,
    action: std.meta.Child(@TypeOf(@as(Cmd.LedgerSubCmd, undefined).action)),
) !void {
    const maybe_file, const logger = try spawnLogger(allocator, cfg);
    defer if (maybe_file) |file| file.close();
    defer logger.deinit();

    var stdout_file_writer = std.fs.File.stdout().writer(&.{});
    const stdout = &stdout_file_writer.interface;

    const ledger_dir = try std.fs.path.join(allocator, &.{ cfg.validator_dir, "ledger" });
    defer allocator.free(ledger_dir);

    var ledger_state = Ledger.init(allocator, .from(logger), ledger_dir, null) catch |err| {
        logger.err().logf("Failed to open ledger at '{s}': {}", .{ ledger_dir, err });
        return err;
    };
    defer ledger_state.deinit();

    const reader = ledger_state.reader();

    switch (action) {
        .bounds => {
            const lowest_slot = try reader.lowestSlot();
            const highest_slot = try reader.highestSlot() orelse lowest_slot;
            try stdout.print("Ledger bounds: {d} to {d}\n", .{ lowest_slot, highest_slot });
        },
        .retain => |retain_params| {
            const lowest_slot = try reader.lowestSlot();
            const highest_slot = try reader.highestSlot() orelse lowest_slot;

            const start_slot = retain_params.start_slot orelse lowest_slot;
            const end_slot = retain_params.end_slot orelse highest_slot;

            if (start_slot > end_slot) {
                logger.err().logf("Invalid range: start-slot ({d}) > end-slot ({d})", .{
                    start_slot,
                    end_slot,
                });
                return error.InvalidSlotRange;
            }

            try stdout.print("Current ledger bounds: [{d}, {d}]\n", .{
                lowest_slot,
                highest_slot,
            });
            try stdout.print("Retaining slots in range: [{d}, {d}]\n", .{
                start_slot,
                end_slot,
            });

            // Purge slots before start_slot
            if (start_slot > lowest_slot) {
                try stdout.print("Purging slots [{d}, {d})...\n", .{ lowest_slot, start_slot });
                const did_purge = try sig.ledger.cleanup_service.purgeSlots(
                    &ledger_state.db,
                    lowest_slot,
                    start_slot - 1,
                );
                if (did_purge) {
                    try stdout.print("  Purged slots before {d}\n", .{start_slot});
                }
            }

            // Purge slots after end_slot
            if (end_slot < highest_slot) {
                try stdout.print("Purging slots ({d}, {d}]...\n", .{ end_slot, highest_slot });
                const did_purge = try sig.ledger.cleanup_service.purgeSlots(
                    &ledger_state.db,
                    end_slot + 1,
                    highest_slot,
                );
                if (did_purge) {
                    try stdout.print("  Purged slots after {d}\n", .{end_slot});
                }
            }

            try stdout.print("Done. Retained slots in range [{d}, {d}]\n", .{
                start_slot,
                end_slot,
            });
        },
    }
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

        const entrypoints = try cfg.gossip.getEntrypointAddrs(try cfg.getCluster(), allocator);
        if (entrypoints.len == 0) logger.warn().log("no gossip entrypoints provided");

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
            epoch_tracker: *sig.core.EpochTracker,
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

            const feature_set = try sig.replay.service.getActiveFeatures(
                allocator,
                account_store.reader().forSlot(&bank_fields.ancestors),
                bank_fields.slot,
            );

            const root_slot_constants: sig.core.SlotConstants =
                try .fromBankFields(allocator, bank_fields, feature_set);
            errdefer root_slot_constants.deinit(allocator);

            const lt_hash = manifest.bank_extra.accounts_lt_hash;

            const account_reader = account_store.reader().forSlot(&bank_fields.ancestors);
            var root_slot_state: sig.core.SlotState =
                try .fromBankFields(allocator, bank_fields, lt_hash, account_reader);
            errdefer root_slot_state.deinit(allocator);

            const hard_forks = try bank_fields.hard_forks.clone(allocator);
            errdefer hard_forks.deinit(allocator);

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
                        (&params.app_base.my_keypair)[0..1]
                    else
                        &.{},
                },
                .account_store = account_store,
                .ledger = params.ledger,
                .epoch_tracker = params.epoch_tracker,
                .root = .{
                    .slot = bank_fields.slot,
                    .constants = root_slot_constants,
                    .state = root_slot_state,
                },
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
        gossip_table: ?*sig.sync.RwMux(sig.gossip.GossipTable),
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
                    .gossip_table = gossip_table,
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
        break :blk .{ file, file.deprecatedWriter() };
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

fn getTrustedValidators(
    allocator: std.mem.Allocator,
    cfg: config.Cmd,
) !?std.array_list.Managed(Pubkey) {
    var trusted_validators: ?std.array_list.Managed(Pubkey) = null;
    if (cfg.gossip.trusted_validators.len > 0) {
        trusted_validators = try std.array_list.Managed(Pubkey).initCapacity(
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
    const writer = std.fs.File.stderr().deprecatedWriter();
    sig.trace.logfmt.writeLog(writer, "panic", .@"error", .{}, "{s}", .{message}) catch {};
    std.debug.defaultPanic(message, first_trace_addr);
}

/// NOTE: This only populates the leader schedule, and leaves the epoch stake & features empty (ie ALL_DISABLED).
const RpcLeaderScheduleService = struct {
    allocator: std.mem.Allocator,
    logger: RpcLeaderScheduleServiceLogger,
    rpc_client: sig.rpc.Client,
    epoch_tracker: *sig.core.EpochTracker,

    const RpcLeaderScheduleServiceLogger = sig.trace.Logger(@typeName(RpcLeaderScheduleService));

    fn init(
        allocator: std.mem.Allocator,
        logger: RpcLeaderScheduleServiceLogger,
        epoch_tracker: *sig.core.EpochTracker,
        rpc_client: sig.rpc.Client,
    ) RpcLeaderScheduleService {
        return .{
            .allocator = allocator,
            .logger = logger.withScope(@typeName(RpcLeaderScheduleService)),
            .rpc_client = rpc_client,
            .epoch_tracker = epoch_tracker,
        };
    }

    fn run(self: *RpcLeaderScheduleService, exit: *std.atomic.Value(bool)) void {
        var i: usize = 0;
        while (!exit.load(.monotonic)) {
            if (i % 1000 == 0) {
                var result: anyerror!void = undefined;
                for (0..3) |_| {
                    result = self.refresh();
                    if (result != error.EndOfStream) break;
                }
                result catch |e|
                    self.logger.err().logf("failed to refresh epoch context via rpc: {}", .{e});
            }
            std.Thread.sleep(std.time.ns_per_s);
            i += 1;
        }
    }

    fn refresh(self: *RpcLeaderScheduleService) !void {
        const response = try self.rpc_client.getSlot(.{});
        defer response.deinit();
        const slot = try response.result();

        // Get the current epoch, and the epoch whose stakes were used to compute the leader schedule
        // for the current epoch.
        const epoch = self.epoch_tracker.epoch_schedule.getEpoch(slot);
        const leader_schedule_epoch = self.epoch_tracker.epoch_schedule.getEpoch(
            slot -| self.epoch_tracker.epoch_schedule.leader_schedule_slot_offset,
        );

        // Iterate from the leader schedule epoch to the current epoch, and populate any missing epochs in the epoch tracker.
        for (leader_schedule_epoch..epoch + 1) |e| {
            if (self.epoch_tracker.rooted_epochs.isNext(e)) {
                const first_slot_in_epoch = self.epoch_tracker.epoch_schedule.getFirstSlotInEpoch(e);

                // The leaders saved in epoch E, are the leaders which will be active in epoch E + 1.
                // Therefore, we need to fetch the leader schedule for epoch E + 1.
                // We store the leaders for epoch E + 1 in the epoch info for epoch E since they are
                // computed using the stakes from epoch E.
                const leaders = try self.getLeaderSchedule(
                    first_slot_in_epoch +|
                        self.epoch_tracker.epoch_schedule.leader_schedule_slot_offset,
                    &self.epoch_tracker.epoch_schedule,
                );

                const entry = try self.allocator.create(sig.core.EpochInfo);
                entry.* = .{
                    .leaders = leaders,
                    .stakes = .EMPTY,
                    // TODO: if you need features here for whatever reason, you'll have to implement
                    // some way to forward them from replay, or source them by some other means.
                    .feature_set = .ALL_DISABLED,
                };
                entry.stakes.stakes.epoch = e;
                errdefer {
                    entry.deinit(self.allocator);
                    self.allocator.destroy(entry);
                }

                try self.epoch_tracker.rooted_epochs.insert(self.allocator, e, entry);
            }
        }
    }

    fn getLeaderSchedule(
        self: *RpcLeaderScheduleService,
        slot: sig.core.Slot,
        epoch_schedule: *const sig.core.EpochSchedule,
    ) !LeaderSchedule {
        const response = try self.rpc_client.getLeaderSchedule(.{ .slot = slot });
        defer response.deinit();
        const rpc_schedule = (try response.result()).value;
        var leaders = try sig.core.leader_schedule.computeFromMap(
            self.allocator,
            &rpc_schedule,
        );
        const epoch = epoch_schedule.getEpoch(slot);
        leaders.start = epoch_schedule.getFirstSlotInEpoch(epoch);
        leaders.end = epoch_schedule.getLastSlotInEpoch(epoch);
        return leaders;
    }
};
