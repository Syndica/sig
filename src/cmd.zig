const std = @import("std");
const builtin = @import("builtin");
const cli = @import("cli");
const sig = @import("sig.zig");
const config = @import("config.zig");
const tracy = @import("tracy");

const AccountsDB = sig.accounts_db.AccountsDB;
const BlockstoreReader = sig.ledger.BlockstoreReader;
const ChannelPrintLogger = sig.trace.ChannelPrintLogger;
const ClusterType = sig.core.ClusterType;
const ContactInfo = sig.gossip.ContactInfo;
const FullAndIncrementalManifest = sig.accounts_db.FullAndIncrementalManifest;
const GenesisConfig = sig.core.GenesisConfig;
const GeyserWriter = sig.geyser.GeyserWriter;
const GossipService = sig.gossip.GossipService;
const IpAddr = sig.net.IpAddr;
const LeaderSchedule = sig.core.leader_schedule.LeaderSchedule;
const LeaderScheduleCache = sig.core.leader_schedule.LeaderScheduleCache;
const Logger = sig.trace.Logger;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;
const SnapshotFiles = sig.accounts_db.SnapshotFiles;
const SocketAddr = sig.net.SocketAddr;
const SocketTag = sig.gossip.SocketTag;
const StatusCache = sig.accounts_db.StatusCache;

const createGeyserWriter = sig.geyser.core.createGeyserWriter;
const downloadSnapshotsFromGossip = sig.accounts_db.downloadSnapshotsFromGossip;
const getShredAndIPFromEchoServer = sig.net.echo.getShredAndIPFromEchoServer;
const globalRegistry = sig.prometheus.globalRegistry;
const servePrometheus = sig.prometheus.servePrometheus;

/// The identifier for the scoped logger used in this file.
const LOG_SCOPE = "cmd";
const ScopedLogger = sig.trace.ScopedLogger(LOG_SCOPE);

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

    const zone = tracy.initZone(@src(), .{ .name = "main" });
    defer zone.deinit();

    var gpa_state: GpaOrCAllocator(.{}) = .{};
    // defer _ = gpa_state.deinit();

    var tracing_allocator = tracy.TracingAllocator.initNamed("gpa", gpa_state.allocator());
    const gpa = tracing_allocator.allocator();

    var gossip_gpa_state: GpaOrCAllocator(.{ .stack_trace_frames = 100 }) = .{};
    // defer _ = gossip_gpa_state.deinit();
    const gossip_gpa = gossip_gpa_state.allocator();

    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);

    const parser = cli.Parser(Cmd, Cmd.cmd_info);
    const cmd = try parser.parse(
        gpa,
        "sig",
        std.io.tty.detectConfig(std.io.getStdOut()),
        std.io.getStdOut().writer(),
        argv[1..],
    ) orelse return;
    defer parser.free(gpa, cmd);

    var current_config: config.Cmd = .{};
    current_config.log_level = cmd.log_level;
    current_config.metrics_port = cmd.metrics_port;
    current_config.log_file = cmd.log_file;
    current_config.tee_logs = cmd.tee_logs;

    switch (cmd.subcmd orelse return error.MissingSubcommand) {
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
            params.gossip_base.apply(&current_config);
            params.gossip_node.apply(&current_config);
            params.repair.apply(&current_config);
            current_config.accounts_db.snapshot_dir = params.snapshot_dir;
            current_config.genesis_file_path = params.genesis_file_path;
            params.accountsdb_base.apply(&current_config);
            params.accountsdb_download.apply(&current_config);
            params.accountsdb_index.apply(&current_config);
            params.geyser.apply(&current_config);
            try validator(gpa, gossip_gpa, current_config);
        },
        .shred_network => |params| {
            current_config.shred_version = params.shred_version;
            current_config.leader_schedule_path = params.leader_schedule;
            params.gossip_base.apply(&current_config);
            params.gossip_node.apply(&current_config);
            params.repair.apply(&current_config);
            current_config.shred_network.dump_shred_tracker = params.dump_shred_tracker;
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
            params.accountsdb_index.apply(&current_config);
            current_config.gossip.cluster = params.gossip_cluster;
            params.geyser.apply(&current_config);
            try validateSnapshot(gpa, current_config);
        },
        .snapshot_create => |params| {
            current_config.accounts_db.snapshot_dir = params.snapshot_dir;
            current_config.genesis_file_path = params.genesis_file_path;
            try createSnapshot(gpa, current_config);
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
            params.accountsdb_index.apply(&current_config);
            try mockRpcServer(gpa, current_config);
        },
    }
}

const Cmd = struct {
    log_level: sig.trace.Level,
    metrics_port: u16,
    log_file: ?[]const u8,
    tee_logs: bool,
    subcmd: ?union(enum) {
        identity,
        gossip: Gossip,
        validator: Validator,
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
            .short =
            \\Sig is a Solana client implementation written in Zig.
            \\This is still a WIP, PRs welcome.
            ,
            .long = null,
        },
        .sub = .{
            .subcmd = .{
                .identity = identity_cmd_info,
                .gossip = Gossip.cmd_info,
                .validator = Validator.cmd_info,
                .shred_network = ShredNetwork.cmd_info,
                .snapshot_download = SnapshotDownload.cmd_info,
                .snapshot_validate = SnapshotValidate.cmd_info,
                .snapshot_create = SnapshotCreate.cmd_info,
                .print_manifest = PrintManifest.cmd_info,
                .leader_schedule = LeaderScheduleSubCmd.cmd_info,
                .test_transaction_sender = TestTransactionSender.cmd_info,
                .mock_rpc_server = MockRpcServer.cmd_info,
            },
            .log_level = .{
                .kind = .named,
                .name_override = null,
                .alias = .l,
                .default_value = .debug,
                .config = {},
                .help = "The amount of detail to log",
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
        };

        fn apply(args: @This(), cfg: *config.Cmd) void {
            cfg.accounts_db.use_disk_index = args.use_disk_index;
            cfg.accounts_db.num_threads_snapshot_load = args.n_threads_snapshot_load;
            cfg.accounts_db.num_threads_snapshot_unpack = args.n_threads_snapshot_unpack;
            cfg.accounts_db.force_unpack_snapshot = args.force_unpack_snapshot;
            cfg.accounts_db.number_of_index_shards = args.number_of_index_shards;
            cfg.accounts_db.accounts_per_file_estimate = args.accounts_per_file_estimate;
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
    const AccountsDbArgumentsIndex = struct {
        fastload: bool,
        save_index: bool,

        const cmd_info: cli.ArgumentInfoGroup(@This()) = .{
            .fastload = .{
                .kind = .named,
                .name_override = null,
                .alias = .none,
                .default_value = false,
                .config = {},
                .help = "fastload the accounts db",
            },
            .save_index = .{
                .kind = .named,
                .name_override = null,
                .alias = .none,
                .default_value = false,
                .config = {},
                .help = "save the account index to disk",
            },
        };

        fn apply(args: @This(), cfg: *config.Cmd) void {
            cfg.accounts_db.fastload = args.fastload;
            cfg.accounts_db.save_index = args.save_index;
        }
    };
    const RepairArgumentsBase = struct {
        turbine_port: u16,
        repair_port: u16,
        test_repair_for_slot: ?Slot,
        max_shreds: u64,
        num_retransmit_threads: ?usize,

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
                .help = "Max number of shreds to store in the blockstore",
            },
        };

        fn apply(args: @This(), cfg: *config.Cmd) void {
            cfg.shred_network.turbine_recv_port = args.turbine_port;
            cfg.shred_network.repair_port = args.repair_port;
            cfg.shred_network.start_slot = args.test_repair_for_slot;
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
            \\NOTE: Keypair is saved in $HOME/.sig/identity.key.
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
        gossip_base: GossipArgumentsCommon,
        gossip_node: GossipArgumentsNode,
        repair: RepairArgumentsBase,
        snapshot_dir: []const u8,
        genesis_file_path: ?[]const u8,
        accountsdb_base: AccountsDbArgumentsBase,
        accountsdb_download: AccountsDbArgumentsDownload,
        force_new_snapshot_download: bool,
        accountsdb_index: AccountsDbArgumentsIndex,
        geyser: GeyserArgumentsBase,

        const cmd_info: cli.CommandInfo(@This()) = .{
            .help = .{
                .short = "Run Solana validator.",
                .long = "Start a full Solana validator client.",
            },
            .sub = .{
                .shred_version = shred_version_arg,
                .leader_schedule = leader_schedule_arg,
                .gossip_base = GossipArgumentsCommon.cmd_info,
                .gossip_node = GossipArgumentsNode.cmd_info,
                .repair = RepairArgumentsBase.cmd_info,
                .snapshot_dir = snapshot_dir_arg,
                .genesis_file_path = genesis_file_path_arg,
                .accountsdb_base = AccountsDbArgumentsBase.cmd_info,
                .accountsdb_download = AccountsDbArgumentsDownload.cmd_info,
                .force_new_snapshot_download = force_new_snapshot_download_arg,
                .accountsdb_index = AccountsDbArgumentsIndex.cmd_info,
                .geyser = GeyserArgumentsBase.cmd_info,
            },
        };
    };

    const ShredNetwork = struct {
        shred_version: ?u16,
        leader_schedule: ?[]const u8,
        gossip_base: GossipArgumentsCommon,
        gossip_node: GossipArgumentsNode,
        repair: RepairArgumentsBase,
        dump_shred_tracker: bool,
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
                \\ NOTE: this command also requires `start_slot` (`--test-repair-for-slot`) to be
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
                .dump_shred_tracker = .{
                    .kind = .named,
                    .name_override = "dump-shred-tracker",
                    .alias = .none,
                    .default_value = false,
                    .config = {},
                    .help = "Create shred-tracker.txt" ++
                        " to visually represent the currently tracked slots.",
                },
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
        accountsdb_index: AccountsDbArgumentsIndex,
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
                .accountsdb_index = AccountsDbArgumentsIndex.cmd_info,
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
        accountsdb_index: AccountsDbArgumentsIndex,

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
                .accountsdb_index = AccountsDbArgumentsIndex.cmd_info,
            },
        };
    };
};

/// entrypoint to print (and create if NONE) pubkey in ~/.sig/identity.key
fn identity(allocator: std.mem.Allocator, cfg: config.Cmd) !void {
    const maybe_file, const logger = try spawnLogger(allocator, cfg);
    defer if (maybe_file) |file| file.close();
    defer logger.deinit();

    const keypair = try sig.identity.getOrInit(allocator, logger);
    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);

    logger.info().logf("Identity: {s}\n", .{pubkey});
}

/// entrypoint to run only gossip
fn gossip(
    allocator: std.mem.Allocator,
    gossip_value_allocator: std.mem.Allocator,
    cfg: config.Cmd,
) !void {
    const zone = tracy.initZone(@src(), .{ .name = "gossip" });
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
    const zone = tracy.initZone(@src(), .{ .name = "validator" });
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

    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{});
    defer snapshot_dir.close();

    var gossip_service = try startGossip(allocator, gossip_value_allocator, cfg, &app_base, &.{
        .{ .tag = .repair, .port = repair_port },
        .{ .tag = .turbine_recv, .port = turbine_recv_port },
    });
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

    // snapshot
    var loaded_snapshot = try loadSnapshot(allocator, cfg, app_base.logger.unscoped(), .{
        .gossip_service = gossip_service,
        .geyser_writer = geyser_writer,
        .validate_snapshot = true,
    });
    defer loaded_snapshot.deinit();

    const collapsed_manifest = &loaded_snapshot.collapsed_manifest;
    const bank_fields = &collapsed_manifest.bank_fields;

    // leader schedule
    var leader_schedule_cache = LeaderScheduleCache.init(allocator, bank_fields.epoch_schedule);
    if (try getLeaderScheduleFromCli(allocator, cfg)) |leader_schedule| {
        try leader_schedule_cache.put(bank_fields.epoch, leader_schedule[1]);
    } else {
        const schedule = try bank_fields.leaderSchedule(allocator);
        errdefer schedule.deinit();
        try leader_schedule_cache.put(bank_fields.epoch, schedule);
    }

    // blockstore
    var blockstore_db = try sig.ledger.BlockstoreDB.open(
        allocator,
        app_base.logger.unscoped(),
        sig.VALIDATOR_DIR ++ "blockstore",
    );
    const shred_inserter = try sig.ledger.ShredInserter.init(
        allocator,
        app_base.logger.unscoped(),
        app_base.metrics_registry,
        blockstore_db,
    );

    // cleanup service
    const lowest_cleanup_slot = try allocator.create(sig.sync.RwMux(sig.core.Slot));
    lowest_cleanup_slot.* = sig.sync.RwMux(sig.core.Slot).init(0);
    defer allocator.destroy(lowest_cleanup_slot);

    const max_root = try allocator.create(std.atomic.Value(sig.core.Slot));
    max_root.* = std.atomic.Value(sig.core.Slot).init(0);
    defer allocator.destroy(max_root);

    const blockstore_reader = try allocator.create(BlockstoreReader);
    defer allocator.destroy(blockstore_reader);
    blockstore_reader.* = try BlockstoreReader.init(
        allocator,
        app_base.logger.unscoped(),
        blockstore_db,
        app_base.metrics_registry,
        lowest_cleanup_slot,
        max_root,
    );

    var cleanup_service_handle = try std.Thread.spawn(.{}, sig.ledger.cleanup_service.run, .{
        app_base.logger.unscoped(),
        blockstore_reader,
        &blockstore_db,
        lowest_cleanup_slot,
        cfg.max_shreds,
        app_base.exit,
    });
    defer cleanup_service_handle.join();

    // Random number generator
    var prng = std.Random.DefaultPrng.init(@bitCast(std.time.timestamp()));

    // shred networking
    const my_contact_info =
        sig.gossip.data.ThreadSafeContactInfo.fromContactInfo(gossip_service.my_contact_info);

    const epoch_schedule = bank_fields.epoch_schedule;
    const epoch = bank_fields.epoch;
    const staked_nodes =
        try bank_fields.getStakedNodes(allocator, epoch);

    var epoch_context_manager = try sig.adapter.EpochContextManager.init(
        allocator,
        epoch_schedule,
    );
    try epoch_context_manager.put(epoch, .{
        .staked_nodes = try staked_nodes.clone(allocator),
        .leader_schedule = try LeaderSchedule.fromStakedNodes(
            allocator,
            epoch,
            epoch_schedule.slots_per_epoch,
            staked_nodes,
        ),
    });

    const rpc_cluster_type = loaded_snapshot.genesis_config.cluster_type;
    var rpc_client = try sig.rpc.Client.init(allocator, rpc_cluster_type, .{});
    defer rpc_client.deinit();

    var rpc_epoch_ctx_service = sig.adapter.RpcEpochContextService.init(
        allocator,
        app_base.logger.unscoped(),
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
            .logger = app_base.logger.unscoped(),
            .registry = app_base.metrics_registry,
            .random = prng.random(),
            .my_keypair = &app_base.my_keypair,
            .exit = app_base.exit,
            .gossip_table_rw = &gossip_service.gossip_table_rw,
            .my_shred_version = &gossip_service.my_shred_version,
            .epoch_context_mgr = &epoch_context_manager,
            .shred_inserter = shred_inserter,
            .my_contact_info = my_contact_info,
            .n_retransmit_threads = turbine_config.num_retransmit_threads,
            .overwrite_turbine_stake_for_testing = turbine_config.overwrite_stake_for_testing,
        },
    );
    defer shred_network_manager.deinit();

    const replay_thread = try app_base.spawnService(
        "replay",
        sig.replay.service.run,
        .{sig.replay.service.ReplayDependencies{
            .allocator = allocator,
            .logger = app_base.logger.unscoped(),
            .exit = app_base.exit,
            .blockstore_reader = blockstore_reader,
            .accounts_db = &loaded_snapshot.accounts_db,
            .epoch_schedule = bank_fields.epoch_schedule,
        }},
    );

    replay_thread.join();
    rpc_epoch_ctx_service_thread.join();
    gossip_service.service_manager.join();
    shred_network_manager.join();
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
        cfg.shred_network.start_slot orelse blk: {
            const response = try rpc_client.getSlot(.{});
            break :blk try response.result();
        },
    );
    app_base.logger.info().logf("Starting from slot: {?}", .{shred_network_conf.start_slot});

    const repair_port: u16 = shred_network_conf.repair_port;
    const turbine_recv_port: u16 = shred_network_conf.turbine_recv_port;

    var gossip_service = try startGossip(allocator, gossip_value_allocator, cfg, &app_base, &.{
        .{ .tag = .repair, .port = repair_port },
        .{ .tag = .turbine_recv, .port = turbine_recv_port },
    });
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    var epoch_context_manager = try sig.adapter.EpochContextManager
        .init(allocator, genesis_config.epoch_schedule);
    var rpc_epoch_ctx_service = sig.adapter.RpcEpochContextService
        .init(allocator, app_base.logger.unscoped(), &epoch_context_manager, rpc_client);
    const rpc_epoch_ctx_service_thread = try std.Thread.spawn(
        .{},
        sig.adapter.RpcEpochContextService.run,
        .{ &rpc_epoch_ctx_service, app_base.exit },
    );

    // blockstore
    var blockstore_db = try sig.ledger.BlockstoreDB.open(
        allocator,
        app_base.logger.unscoped(),
        sig.VALIDATOR_DIR ++ "blockstore",
    );
    const shred_inserter = try sig.ledger.ShredInserter.init(
        allocator,
        app_base.logger.unscoped(),
        app_base.metrics_registry,
        blockstore_db,
    );

    // cleanup service
    const lowest_cleanup_slot = try allocator.create(sig.sync.RwMux(sig.core.Slot));
    lowest_cleanup_slot.* = sig.sync.RwMux(sig.core.Slot).init(0);
    defer allocator.destroy(lowest_cleanup_slot);

    const max_root = try allocator.create(std.atomic.Value(sig.core.Slot));
    max_root.* = std.atomic.Value(sig.core.Slot).init(0);
    defer allocator.destroy(max_root);

    const blockstore_reader = try allocator.create(BlockstoreReader);
    defer allocator.destroy(blockstore_reader);
    blockstore_reader.* = try BlockstoreReader.init(
        allocator,
        app_base.logger.unscoped(),
        blockstore_db,
        app_base.metrics_registry,
        lowest_cleanup_slot,
        max_root,
    );

    var cleanup_service_handle = try std.Thread.spawn(.{}, sig.ledger.cleanup_service.run, .{
        app_base.logger.unscoped(),
        blockstore_reader,
        &blockstore_db,
        lowest_cleanup_slot,
        cfg.max_shreds,
        app_base.exit,
    });
    defer cleanup_service_handle.join();

    var prng = std.Random.DefaultPrng.init(@bitCast(std.time.timestamp()));

    const my_contact_info =
        sig.gossip.data.ThreadSafeContactInfo.fromContactInfo(gossip_service.my_contact_info);

    // shred networking
    var shred_network_manager = try sig.shred_network.start(shred_network_conf, .{
        .allocator = allocator,
        .logger = app_base.logger.unscoped(),
        .registry = app_base.metrics_registry,
        .random = prng.random(),
        .my_keypair = &app_base.my_keypair,
        .exit = app_base.exit,
        .gossip_table_rw = &gossip_service.gossip_table_rw,
        .my_shred_version = &gossip_service.my_shred_version,
        .epoch_context_mgr = &epoch_context_manager,
        .shred_inserter = shred_inserter,
        .my_contact_info = my_contact_info,
        .n_retransmit_threads = cfg.turbine.num_retransmit_threads,
        .overwrite_turbine_stake_for_testing = cfg.turbine.overwrite_stake_for_testing,
    });
    defer shred_network_manager.deinit();

    rpc_epoch_ctx_service_thread.join();
    gossip_service.service_manager.join();
    shred_network_manager.join();
}

fn printManifest(allocator: std.mem.Allocator, cfg: config.Cmd) !void {
    var app_base = try AppBase.init(allocator, cfg);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    const snapshot_dir_str = cfg.accounts_db.snapshot_dir;
    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{});
    defer snapshot_dir.close();

    const snapshot_file_info = try SnapshotFiles.find(allocator, snapshot_dir);

    var snapshots = try FullAndIncrementalManifest.fromFiles(
        allocator,
        app_base.logger.unscoped(),
        snapshot_dir,
        snapshot_file_info,
    );
    defer snapshots.deinit(allocator);

    _ = try snapshots.collapse(allocator);

    // TODO: support better inspection of snapshots (maybe dump to a file as json?)
    std.debug.print("full snapshots: {any}\n", .{snapshots.full.bank_fields});
}

fn createSnapshot(allocator: std.mem.Allocator, cfg: config.Cmd) !void {
    var app_base = try AppBase.init(allocator, cfg);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    const snapshot_dir_str = cfg.accounts_db.snapshot_dir;
    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{});
    defer snapshot_dir.close();

    var loaded_snapshot = try loadSnapshot(allocator, cfg, app_base.logger.unscoped(), .{
        .gossip_service = null,
        .geyser_writer = null,
        .validate_snapshot = false,
        .metadata_only = false,
    });
    defer loaded_snapshot.deinit();

    var accounts_db = loaded_snapshot.accounts_db;
    const slot = loaded_snapshot.combined_manifest.full.bank_fields.slot;

    var n_accounts_indexed: u64 = 0;
    for (accounts_db.account_index.pubkey_ref_map.shards) |*shard_rw| {
        const shard, var lock = shard_rw.readWithLock();
        defer lock.unlock();
        n_accounts_indexed += shard.count();
    }
    app_base.logger.info().logf("accountsdb: indexed {d} accounts", .{n_accounts_indexed});

    const output_dir_name = "alt_" ++ sig.VALIDATOR_DIR; // TODO: pull out to cli arg
    var output_dir = try std.fs.cwd().makeOpenPath(output_dir_name, .{});
    defer output_dir.close();

    app_base.logger.info().logf(
        "accountsdb[manager]: generating full snapshot for slot {d}",
        .{slot},
    );
    _ = try accounts_db.generateFullSnapshot(.{
        .target_slot = slot,
        .bank_fields = &loaded_snapshot.combined_manifest.full.bank_fields,
        .lamports_per_signature = lps: {
            var prng = std.Random.DefaultPrng.init(1234);
            break :lps prng.random().int(u64);
        },
        .old_snapshot_action = .delete_old,
    });
}

fn validateSnapshot(allocator: std.mem.Allocator, cfg: config.Cmd) !void {
    var app_base = try AppBase.init(allocator, cfg);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    const snapshot_dir_str = cfg.accounts_db.snapshot_dir;
    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{});
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

    var loaded_snapshot = try loadSnapshot(allocator, cfg, app_base.logger.unscoped(), .{
        .gossip_service = null,
        .geyser_writer = geyser_writer,
        .validate_snapshot = true,
        .metadata_only = false,
    });
    defer loaded_snapshot.deinit();
}

/// entrypoint to print the leader schedule and then exit
fn printLeaderSchedule(allocator: std.mem.Allocator, cfg: config.Cmd) !void {
    var app_base = try AppBase.init(allocator, cfg);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    const start_slot, //
    const leader_schedule //
    = try getLeaderScheduleFromCli(allocator, cfg) orelse b: {
        app_base.logger.info().log("Downloading a snapshot to calculate the leader schedule.");

        var loaded_snapshot = loadSnapshot(allocator, cfg, app_base.logger.unscoped(), .{
            .gossip_service = null,
            .geyser_writer = null,
            .validate_snapshot = true,
            .metadata_only = false,
        }) catch |err| {
            if (err == error.SnapshotsNotFoundAndNoGossipService) {
                app_base.logger.err().log(
                    \\\ No snapshot found and no gossip service to download a snapshot from.
                    \\\ Download using the `snapshot-download` command.
                );
            }
            return err;
        };
        defer loaded_snapshot.deinit();

        const bank_fields = &loaded_snapshot.collapsed_manifest.bank_fields;
        _, const slot_index = bank_fields.epoch_schedule.getEpochAndSlotIndex(bank_fields.slot);
        break :b .{
            bank_fields.slot - slot_index,
            try bank_fields.leaderSchedule(allocator),
        };
    };

    var stdout = std.io.bufferedWriter(std.io.getStdOut().writer());
    try leader_schedule.write(stdout.writer(), start_slot);
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
    const gossip_service = try startGossip(allocator, gossip_value_allocator, cfg, &app_base, &.{});
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
        app_base.logger.unscoped(),
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
        .logger = app_base.logger.unscoped(),
    });
    defer rpc_client.deinit();

    // this sends mock txs to the transaction sender
    var mock_transfer_service = try sig.transaction_sender.MockTransferService.init(
        allocator,
        transaction_channel,
        rpc_client,
        app_base.exit,
        app_base.logger.unscoped(),
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
    const logger: sig.trace.Logger = .{ .direct_print = .{ .max_level = .trace } };

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
            logger.unscoped(),
            snapshot_dir,
            snap_files,
        );
        defer all_snap_fields.deinit(allocator);

        const manifest = try accountsdb.loadWithDefaults(
            allocator,
            all_snap_fields,
            1,
            true,
            1500,
            false,
            false,
        );
        defer manifest.deinit(allocator);
    }

    var server_ctx = try sig.rpc.server.Context.init(.{
        .allocator = allocator,
        .logger = logger,
        .accountsdb = &accountsdb,

        .read_buffer_size = sig.rpc.server.MIN_READ_BUFFER_SIZE,
        .socket_addr = std.net.Address.initIp4(.{ 0, 0, 0, 0 }, 8899),
        .reuse_address = true,
    });
    defer server_ctx.joinDeinit();

    var maybe_liou = try sig.rpc.server.LinuxIoUring.init(&server_ctx);
    defer if (maybe_liou) |*liou| liou.deinit();

    var exit = std.atomic.Value(bool).init(false);
    try sig.rpc.server.serve(
        &exit,
        &server_ctx,
        if (maybe_liou != null) .{ .linux_io_uring = &maybe_liou.? } else .basic,
    );
}

/// State that typically needs to be initialized at the start of the app,
/// and deinitialized only when the app exits.
const AppBase = struct {
    allocator: std.mem.Allocator,
    logger: ScopedLogger,
    log_file: ?std.fs.File,
    metrics_registry: *sig.prometheus.Registry(.{}),
    metrics_thread: std.Thread,

    my_keypair: sig.identity.KeyPair,
    entrypoints: []SocketAddr,
    shred_version: u16,
    my_ip: IpAddr,
    my_port: u16,

    exit: *std.atomic.Value(bool),
    closed: bool,

    fn init(allocator: std.mem.Allocator, cfg: config.Cmd) !AppBase {
        const maybe_file, const plain_logger = try spawnLogger(allocator, cfg);
        errdefer if (maybe_file) |file| file.close();
        const logger = plain_logger.withScope(LOG_SCOPE);
        errdefer logger.deinit();

        const exit = try allocator.create(std.atomic.Value(bool));
        errdefer allocator.destroy(exit);
        exit.* = std.atomic.Value(bool).init(false);

        const metrics_registry = globalRegistry();
        const metrics_thread = try sig.utils.service_manager.spawnService( //
            plain_logger, exit, "metrics endpoint", .{}, //
            servePrometheus, .{ allocator, metrics_registry, cfg.metrics_port });
        errdefer metrics_thread.detach();

        const my_keypair = try sig.identity.getOrInit(allocator, logger.unscoped());
        const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);

        const entrypoints = try cfg.gossip.getEntrypointAddrs(allocator);

        const echo_data = try getShredAndIPFromEchoServer(logger.unscoped(), entrypoints);

        const my_shred_version =
            cfg.shred_version orelse
            echo_data.shred_version orelse
            0;

        const config_host = cfg.gossip.getHost() catch null;
        const my_ip = config_host orelse echo_data.ip orelse IpAddr.newIpv4(127, 0, 0, 1);

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
        function: anytype,
        args: anytype,
    ) std.Thread.SpawnError!std.Thread {
        return try sig.utils.service_manager.spawnService(
            self.logger,
            self.exit,
            name,
            .{},
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
) !*GossipService {
    const zone = tracy.initZone(@src(), .{ .name = "cmd startGossip" });
    defer zone.deinit();

    app_base.logger.info()
        .field("host", app_base.my_ip)
        .field("port", app_base.my_port)
        .log("gossip setup");

    // setup contact info
    const my_pubkey = Pubkey.fromPublicKey(&app_base.my_keypair.public_key);

    var contact_info = ContactInfo.init(allocator, my_pubkey, sig.time.clock.now(), 0);
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
        app_base.logger.unscoped(),
    );

    try service.start(.{
        .spy_node = cfg.gossip.spy_node,
        .dump = cfg.gossip.dump,
    });

    return service;
}

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
        .max_level = cfg.log_level,
        .max_buffer = 1 << 20,
        .write_stderr = cfg.tee_logs or cfg.log_file == null,
    }, writer);

    return .{ file, std_logger.logger() };
}

const LoadedSnapshot = struct {
    allocator: std.mem.Allocator,
    accounts_db: AccountsDB,
    combined_manifest: sig.accounts_db.snapshots.FullAndIncrementalManifest,
    collapsed_manifest: sig.accounts_db.snapshots.Manifest,
    genesis_config: GenesisConfig,
    status_cache: ?sig.accounts_db.snapshots.StatusCache,

    pub fn deinit(self: *@This()) void {
        self.accounts_db.deinit();
        self.combined_manifest.deinit(self.allocator);
        self.collapsed_manifest.deinit(self.allocator);
        self.genesis_config.deinit(self.allocator);
        if (self.status_cache) |status_cache| {
            status_cache.deinit(self.allocator);
        }
    }
};

const LoadSnapshotOptions = struct {
    /// optional service to download a fresh snapshot from gossip. if null, will read from the snapshot_dir
    gossip_service: ?*GossipService,
    /// optional geyser to write snapshot data to
    geyser_writer: ?*GeyserWriter,
    /// whether to validate the snapshot account data against the metadata
    validate_snapshot: bool,
    /// whether to load only the metadata of the snapshot
    metadata_only: bool = false,
};

fn loadSnapshot(
    allocator: std.mem.Allocator,
    cfg: config.Cmd,
    unscoped_logger: Logger,
    options: LoadSnapshotOptions,
) !LoadedSnapshot {
    const zone = tracy.initZone(@src(), .{ .name = "cmd loadSnapshot" });
    defer zone.deinit();

    const logger = unscoped_logger.withScope(@typeName(@This()) ++ "." ++ @src().fn_name);

    var validator_dir = try std.fs.cwd().makeOpenPath(sig.VALIDATOR_DIR, .{});
    defer validator_dir.close();

    const genesis_file_path = try cfg.genesisFilePath() orelse
        return error.GenesisPathNotProvided;

    const adb_config = cfg.accounts_db;
    const snapshot_dir_str = adb_config.snapshot_dir;

    const combined_manifest, //
    const snapshot_files //
    = try sig.accounts_db.download.getOrDownloadAndUnpackSnapshot(
        allocator,
        logger.unscoped(),
        snapshot_dir_str,
        .{
            .gossip_service = options.gossip_service,
            .force_unpack_snapshot = adb_config.force_unpack_snapshot,
            .force_new_snapshot_download = adb_config.force_new_snapshot_download,
            .num_threads_snapshot_unpack = adb_config.num_threads_snapshot_unpack,
            .max_number_of_download_attempts = adb_config.max_number_of_snapshot_download_attempts,
            .min_snapshot_download_speed_mbs = adb_config.min_snapshot_download_speed_mbs,
        },
    );

    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{ .iterate = true });
    defer snapshot_dir.close();

    logger.info().logf("full snapshot: {s}", .{sig.utils.fmt.tryRealPath(
        snapshot_dir,
        snapshot_files.full.snapshotArchiveName().constSlice(),
    )});
    if (snapshot_files.incremental()) |inc_snap| {
        logger.info().logf("incremental snapshot: {s}", .{
            sig.utils.fmt.tryRealPath(snapshot_dir, inc_snap.snapshotArchiveName().constSlice()),
        });
    }

    // cli parsing
    const n_threads_snapshot_load: u32 = blk: {
        const cli_n_threads_snapshot_load: u32 =
            cfg.accounts_db.num_threads_snapshot_load;
        if (cli_n_threads_snapshot_load == 0) {
            // default value
            break :blk std.math.lossyCast(u32, try std.Thread.getCpuCount());
        } else {
            break :blk cli_n_threads_snapshot_load;
        }
    };

    var accounts_db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = logger.unscoped(),
        // where we read the snapshot from
        .snapshot_dir = snapshot_dir,
        .geyser_writer = options.geyser_writer,
        // gossip information for propogating snapshot info
        .gossip_view = if (options.gossip_service) |service|
            try AccountsDB.GossipView.fromService(service)
        else
            null,
        // to use disk or ram for the index
        .index_allocation = if (cfg.accounts_db.use_disk_index) .disk else .ram,
        // number of shards for the index
        .number_of_index_shards = cfg.accounts_db.number_of_index_shards,
    });
    errdefer accounts_db.deinit();

    const collapsed_manifest = if (options.metadata_only)
        try combined_manifest.collapse(allocator)
    else
        try accounts_db.loadWithDefaults(
            allocator,
            combined_manifest,
            n_threads_snapshot_load,
            options.validate_snapshot,
            cfg.accounts_db.accounts_per_file_estimate,
            cfg.accounts_db.fastload,
            cfg.accounts_db.save_index,
        );
    errdefer collapsed_manifest.deinit(allocator);

    // this should exist before we start to unpack
    logger.info().log("reading genesis...");

    const genesis_config = GenesisConfig.init(allocator, genesis_file_path) catch |err| {
        if (err == error.FileNotFound) {
            logger.err().logf(
                "genesis config not found - expecting {s} to exist",
                .{genesis_file_path},
            );
        }
        return err;
    };
    errdefer genesis_config.deinit(allocator);

    logger.info().log("validating bank...");

    try collapsed_manifest.bank_fields.validate(&genesis_config);

    if (options.metadata_only) {
        logger.info().log("accounts-db setup done...");
        return .{
            .allocator = allocator,
            .accounts_db = accounts_db,
            .combined_manifest = combined_manifest,
            .collapsed_manifest = collapsed_manifest,
            .genesis_config = genesis_config,
            .status_cache = null,
        };
    }

    // validate the status cache
    const status_cache = StatusCache.initFromDir(allocator, snapshot_dir) catch |err| {
        if (err == error.FileNotFound) {
            logger.err().logf(
                "status_cache not found - expecting {s}/snapshots/status_cache to exist",
                .{snapshot_dir_str},
            );
        }
        return err;
    };
    errdefer status_cache.deinit(allocator);

    const slot_history = try accounts_db.getSlotHistory(allocator);
    defer slot_history.deinit(allocator);

    try status_cache.validate(allocator, collapsed_manifest.bank_fields.slot, &slot_history);

    logger.info().log("accounts-db setup done...");

    return .{
        .allocator = allocator,
        .accounts_db = accounts_db,
        .combined_manifest = combined_manifest,
        .collapsed_manifest = collapsed_manifest,
        .genesis_config = genesis_config,
        .status_cache = status_cache,
    };
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
        app_base.logger.unscoped(),
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
        for (cfg.gossip.trusted_validators) |trusted_validator_str| {
            trusted_validators.?.appendAssumeCapacity(
                try Pubkey.parseBase58String(trusted_validator_str),
            );
        }
    }
    return trusted_validators;
}
