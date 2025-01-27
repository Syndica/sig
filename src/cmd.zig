const builtin = @import("builtin");
const cli = @import("zig-cli");
const sig = @import("sig.zig");
const std = @import("std");
const config = @import("cmd/config.zig");

const AccountsDB = sig.accounts_db.AccountsDB;
const FullAndIncrementalManifest = sig.accounts_db.FullAndIncrementalManifest;
const Bank = sig.accounts_db.Bank;
const Slot = sig.core.Slot;
const ContactInfo = sig.gossip.ContactInfo;
const GenesisConfig = sig.accounts_db.GenesisConfig;
const GossipService = sig.gossip.GossipService;
const IpAddr = sig.net.IpAddr;
const Logger = sig.trace.Logger;
const ChannelPrintLogger = sig.trace.ChannelPrintLogger;
const Pubkey = sig.core.Pubkey;
const LeaderSchedule = sig.core.leader_schedule.LeaderSchedule;
const SnapshotFiles = sig.accounts_db.SnapshotFiles;
const SocketAddr = sig.net.SocketAddr;
const StatusCache = sig.accounts_db.StatusCache;
const LeaderScheduleCache = sig.core.leader_schedule.LeaderScheduleCache;
const ClusterType = sig.accounts_db.genesis_config.ClusterType;
const BlockstoreReader = sig.ledger.BlockstoreReader;
const SocketTag = sig.gossip.SocketTag;
const GeyserWriter = sig.geyser.GeyserWriter;

const downloadSnapshotsFromGossip = sig.accounts_db.downloadSnapshotsFromGossip;
const globalRegistry = sig.prometheus.globalRegistry;
const getWallclockMs = sig.time.getWallclockMs;
const spawnMetrics = sig.prometheus.spawnMetrics;
const getShredAndIPFromEchoServer = sig.net.echo.getShredAndIPFromEchoServer;
const createGeyserWriterFromConfig = sig.geyser.core.createGeyserWriterFromConfig;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const gpa_allocator = if (builtin.mode == .Debug)
    gpa.allocator()
else
    std.heap.c_allocator;

var gossip_value_gpa: std.heap.GeneralPurposeAllocator(.{
    .stack_trace_frames = 100,
}) = .{};
const gossip_value_gpa_allocator = if (builtin.mode == .Debug)
    gossip_value_gpa.allocator()
else
    std.heap.c_allocator;

/// The identifier for the scoped logger used in this file.
const LOG_SCOPE = "cmd";
const ScopedLogger = sig.trace.ScopedLogger(LOG_SCOPE);

var current_config: config.Cmd = .{};

// We set this so that std.log knows not to log .debug level messages
// which libraries we import will use
pub const std_options: std.Options = .{
    // Set the log level to info
    .log_level = .info,
};

pub fn main() !void {
    defer {
        // _ = gpa.deinit(); TODO: this causes literally thousands of leaks
        // _ = gossip_value_gpa.deinit(); // Commented out for no leeks
    }

    var shred_version_option = cli.Option{
        .long_name = "shred-version",
        .help = "The shred version for the network",
        .value_ref = cli.mkRef(&current_config.shred_version),
        .required = false,
        .value_name = "Shred Version",
    };

    var gossip_host_option = cli.Option{
        .long_name = "gossip-host",
        .help =
        \\IPv4 address for the validator to advertise in gossip
        \\ - default: get from --entrypoint, fallback to 127.0.0.1"
        ,
        .value_ref = cli.mkRef(&current_config.gossip.host),
        .required = false,
        .value_name = "Gossip Host",
    };

    var gossip_port_option = cli.Option{
        .long_name = "gossip-port",
        .help = "The port to run gossip listener - default: 8001",
        .short_alias = 'p',
        .value_ref = cli.mkRef(&current_config.gossip.port),
        .required = false,
        .value_name = "Gossip Port",
    };

    var repair_port_option = cli.Option{
        .long_name = "repair-port",
        .help = "The port to run shred repair listener - default: 8002",
        .value_ref = cli.mkRef(&current_config.shred_network.repair_port),
        .required = false,
        .value_name = "Repair Port",
    };

    var turbine_recv_port_option = cli.Option{
        .long_name = "turbine-port",
        .help = "The port to run turbine shred listener (aka TVU port) - default: 8003",
        .value_ref = cli.mkRef(&current_config.shred_network.turbine_recv_port),
        .required = false,
        .value_name = "Turbine Port",
    };

    var turbine_num_retransmit_threads = cli.Option{
        .long_name = "num-retransmit-threads",
        .help = "The number of retransmit threads to use for the turbine service" ++
            " - default: cpu count",
        .value_ref = cli.mkRef(&current_config.turbine.num_retransmit_threads),
        .required = false,
        .value_name = "Number of turbine retransmit threads",
    };

    // TODO: Remove when no longer needed
    var turbine_overwrite_stake_for_testing = cli.Option{
        .long_name = "overwrite-stake-for-testing",
        .help = "Overwrite the stake for testing purposes",
        .value_ref = cli.mkRef(&current_config.turbine.overwrite_stake_for_testing),
        .required = false,
        .value_name = "Overwrite stake for testing",
    };

    var leader_schedule_option = cli.Option{
        .long_name = "leader-schedule",
        .help = "Set a file path to load the leader schedule. Use '--' to load from stdin",
        .value_ref = cli.mkRef(&current_config.leader_schedule_path),
        .required = false,
        .value_name = "Leader schedule source",
    };

    var max_shreds_option = cli.Option{
        .long_name = "max-shreds",
        .help = "Max number of shreds to store in the blockstore",
        .value_ref = cli.mkRef(&current_config.leader_schedule_path),
        .required = false,
        .value_name = "max shreds",
    };

    var test_repair_option = cli.Option{
        .long_name = "test-repair-for-slot",
        .help = "Set a slot here to repeatedly send repair requests for shreds from this slot." ++
            " This is only intended for use during short-lived tests of the repair service." ++
            " Do not set this during normal usage.",
        .value_ref = cli.mkRef(&current_config.shred_network.start_slot),
        .required = false,
        .value_name = "slot number",
    };

    var retransmit_option = cli.Option{
        .long_name = "no-retransmit",
        .help = "Shreds will be received and stored but not retransmitted",
        .value_ref = cli.mkRef(&current_config.shred_network.no_retransmit),
        .required = false,
        .value_name = "Disable Shred Retransmission",
    };

    var dump_shred_tracker = cli.Option{
        .long_name = "dump-shred-tracker",
        .help = "Create shred-tracker.txt to visually represent the currently tracked slots.",
        .value_ref = cli.mkRef(&current_config.shred_network.dump_shred_tracker),
        .required = false,
        .value_name = "Dump Shred Tracker",
    };

    var gossip_entrypoints_option = cli.Option{
        .long_name = "entrypoint",
        .help = "gossip address of the entrypoint validators",
        .short_alias = 'e',
        .value_ref = cli.mkRef(&current_config.gossip.entrypoints),
        .required = false,
        .value_name = "Entrypoints",
    };

    var network_option = cli.Option{
        .long_name = "network",
        .help = "cluster to connect to - adds gossip entrypoints, sets default genesis file path",
        .short_alias = 'n',
        .value_ref = cli.mkRef(&current_config.gossip.network),
        .required = false,
        .value_name = "Network for Entrypoints",
    };

    var trusted_validators_option = cli.Option{
        .long_name = "trusted_validator",
        .help = "public key of a validator whose snapshot hash is trusted to be downloaded",
        .short_alias = 't',
        .value_ref = cli.mkRef(&current_config.gossip.trusted_validators),
        .required = false,
        .value_name = "Trusted Validator",
    };

    var gossip_spy_node_option = cli.Option{
        .long_name = "spy-node",
        .help = "run as a gossip spy node (minimize outgoing packets)",
        .value_ref = cli.mkRef(&current_config.gossip.spy_node),
        .required = false,
        .value_name = "Spy Node",
    };

    var gossip_dump_option = cli.Option{
        .long_name = "dump-gossip",
        .help = "periodically dump gossip table to csv files and logs",
        .value_ref = cli.mkRef(&current_config.gossip.dump),
        .required = false,
        .value_name = "Gossip Table Dump",
    };

    var log_level_option = cli.Option{
        .long_name = "log-level",
        .help = "The amount of detail to log (default = debug)",
        .short_alias = 'l',
        .value_ref = cli.mkRef(&current_config.log_level),
        .required = false,
        .value_name = "err|warn|info|debug",
    };

    var metrics_port_option = cli.Option{
        .long_name = "metrics-port",
        .help = "port to expose prometheus metrics via http - default: 12345",
        .short_alias = 'm',
        .value_ref = cli.mkRef(&current_config.metrics_port),
        .required = false,
        .value_name = "port_number",
    };

    // accounts-db options
    var n_threads_snapshot_load_option = cli.Option{
        .long_name = "n-threads-snapshot-load",
        .help = "number of threads used to initialize the account index: - default: ncpus",
        .short_alias = 't',
        .value_ref = cli.mkRef(&current_config.accounts_db.num_threads_snapshot_load),
        .required = false,
        .value_name = "n_threads_snapshot_load",
    };

    var n_threads_snapshot_unpack_option = cli.Option{
        .long_name = "n-threads-snapshot-unpack",
        .help = "number of threads to unpack snapshots (from .tar.zst) - default: ncpus * 2",
        .short_alias = 'u',
        .value_ref = cli.mkRef(&current_config.accounts_db.num_threads_snapshot_unpack),
        .required = false,
        .value_name = "n_threads_snapshot_unpack",
    };

    var force_unpack_snapshot_option = cli.Option{
        .long_name = "force-unpack-snapshot",
        .help = "unpacks a snapshot (even if it exists)",
        .short_alias = 'f',
        .value_ref = cli.mkRef(&current_config.accounts_db.force_unpack_snapshot),
        .required = false,
        .value_name = "force_unpack_snapshot",
    };

    var use_disk_index_option = cli.Option{
        .long_name = "use-disk-index",
        .help = "use disk-memory for the account index",
        .value_ref = cli.mkRef(&current_config.accounts_db.use_disk_index),
        .required = false,
        .value_name = "use_disk_index",
    };

    var force_new_snapshot_download_option = cli.Option{
        .long_name = "force-new-snapshot-download",
        .help = "force download of new snapshot (usually to get a more up-to-date snapshot)",
        .value_ref = cli.mkRef(&current_config.accounts_db.force_new_snapshot_download),
        .required = false,
        .value_name = "force_new_snapshot_download",
    };

    var snapshot_dir_option = cli.Option{
        .long_name = "snapshot-dir",
        .help = "path to snapshot directory" ++
            " (where snapshots are downloaded and/or unpacked to/from)" ++
            " - default: {VALIDATOR_DIR}/accounts_db",
        .short_alias = 's',
        .value_ref = cli.mkRef(&current_config.accounts_db.snapshot_dir),
        .required = false,
        .value_name = "snapshot_dir",
    };

    var snapshot_metadata_only = cli.Option{
        .long_name = "snapshot-metadata-only",
        .help = "load only the snapshot metadata",
        .value_ref = cli.mkRef(&current_config.accounts_db.snapshot_metadata_only),
        .required = false,
        .value_name = "snapshot_metadata_only",
    };

    var genesis_file_path = cli.Option{
        .long_name = "genesis-file-path",
        .help = "path to the genesis file." ++
            " defaults to 'data/genesis-files/<network>_genesis.bin' if --network option is set",
        .short_alias = 'g',
        .value_ref = cli.mkRef(&current_config.genesis_file_path),
        .required = false,
        .value_name = "genesis_file_path",
    };

    var min_snapshot_download_speed_mb_option = cli.Option{
        .long_name = "min-snapshot-download-speed",
        .help = "minimum download speed of full snapshots in megabytes per second" ++
            " - default: 20MB/s",
        .value_ref = cli.mkRef(&current_config.accounts_db.min_snapshot_download_speed_mbs),
        .required = false,
        .value_name = "min_snapshot_download_speed_mb",
    };

    var number_of_index_shards_option = cli.Option{
        .long_name = "number-of-index-bins",
        .help = "number of shards for the account index's pubkey_ref_map",
        .value_ref = cli.mkRef(&current_config.accounts_db.number_of_index_shards),
        .required = false,
        .value_name = "number_of_index_shards",
    };

    var accounts_per_file_estimate = cli.Option{
        .long_name = "accounts-per-file-estimate",
        .short_alias = 'a',
        .help = "number of accounts to estimate inside of account files (used for pre-allocation)",
        .value_ref = cli.mkRef(&current_config.accounts_db.accounts_per_file_estimate),
        .required = false,
        .value_name = "accounts_per_file_estimate",
    };

    var fastload_option = cli.Option{
        .long_name = "fastload",
        .help = "fastload the accounts db",
        .value_ref = cli.mkRef(&current_config.accounts_db.fastload),
        .required = false,
        .value_name = "fastload",
    };

    var save_index_option = cli.Option{
        .long_name = "save-index",
        .help = "save the account index to disk",
        .value_ref = cli.mkRef(&current_config.accounts_db.save_index),
        .required = false,
        .value_name = "save_index",
    };

    // geyser options
    var enable_geyser_option = cli.Option{
        .long_name = "enable-geyser",
        .help = "enable geyser",
        .value_ref = cli.mkRef(&current_config.geyser.enable),
        .required = false,
        .value_name = "enable_geyser",
    };

    var geyser_pipe_path_option = cli.Option{
        .long_name = "geyser-pipe-path",
        .help = "path to the geyser pipe",
        .value_ref = cli.mkRef(&current_config.geyser.pipe_path),
        .required = false,
        .value_name = "geyser_pipe_path",
    };

    var geyser_writer_fba_bytes_option = cli.Option{
        .long_name = "geyser-writer-fba-bytes",
        .help = "number of bytes to allocate for the geyser writer",
        .value_ref = cli.mkRef(&current_config.geyser.writer_fba_bytes),
        .required = false,
        .value_name = "geyser_writer_fba_bytes",
    };

    // test-transaction sender options
    var n_transactions_option = cli.Option{
        .long_name = "n-transactions",
        .short_alias = 't',
        .help = "number of transactions to send",
        .value_ref = cli.mkRef(&current_config.test_transaction_sender.n_transactions),
        .required = false,
        .value_name = "n_transactions",
    };

    var n_lamports_per_tx_option = cli.Option{
        .long_name = "n-lamports-per-tx",
        .short_alias = 'l',
        .help = "number of lamports to send per transaction",
        .value_ref = cli.mkRef(&current_config.test_transaction_sender.n_lamports_per_transaction),
        .required = false,
        .value_name = "n_lamports_per_tx",
    };

    const app = cli.App{
        .version = "0.2.0",
        .author = "Syndica & Contributors",
        .command = .{
            .name = "sig",
            .description = .{
                .one_line =
                \\Sig is a Solana client implementation written in Zig.
                \\This is still a WIP, PRs welcome.
                // .detailed = "",
            },
            .options = &.{ &log_level_option, &metrics_port_option },
            .target = .{
                .subcommands = &.{
                    &cli.Command{
                        .name = "identity",
                        .description = .{
                            .one_line = "Get own identity",
                            .detailed =
                            \\Gets own identity (Pubkey) or creates one if doesn't exist.
                            \\
                            \\NOTE: Keypair is saved in $HOME/.sig/identity.key.
                            ,
                        },
                        .target = .{
                            .action = .{
                                .exec = identity,
                            },
                        },
                    },

                    &cli.Command{
                        .name = "gossip",
                        .description = .{
                            .one_line = "Run gossip client",
                            .detailed =
                            \\Start Solana gossip client on specified port.
                            ,
                        },
                        .options = &.{
                            &gossip_host_option,
                            &gossip_port_option,
                            &gossip_entrypoints_option,
                            &gossip_spy_node_option,
                            &gossip_dump_option,
                            &network_option,
                            &shred_version_option,
                        },
                        .target = .{
                            .action = .{
                                .exec = gossip,
                            },
                        },
                    },

                    &cli.Command{
                        .name = "validator",
                        .description = .{
                            .one_line = "Run Solana validator",
                            .detailed =
                            \\Start a full Solana validator client.
                            ,
                        },
                        .options = &.{
                            &shred_version_option,
                            // gossip
                            &gossip_host_option,
                            &gossip_port_option,
                            &gossip_entrypoints_option,
                            &gossip_spy_node_option,
                            &gossip_dump_option,
                            // repair
                            &turbine_recv_port_option,
                            &repair_port_option,
                            &test_repair_option,
                            // blockstore cleanup service
                            &max_shreds_option,
                            // turbine
                            &turbine_num_retransmit_threads,
                            // accounts-db
                            &snapshot_dir_option,
                            &use_disk_index_option,
                            &n_threads_snapshot_load_option,
                            &n_threads_snapshot_unpack_option,
                            &force_unpack_snapshot_option,
                            &min_snapshot_download_speed_mb_option,
                            &force_new_snapshot_download_option,
                            &trusted_validators_option,
                            &number_of_index_shards_option,
                            &genesis_file_path,
                            &accounts_per_file_estimate,
                            &fastload_option,
                            &save_index_option,
                            // geyser
                            &enable_geyser_option,
                            &geyser_pipe_path_option,
                            &geyser_writer_fba_bytes_option,
                            // general
                            &leader_schedule_option,
                            &network_option,
                        },
                        .target = .{
                            .action = .{
                                .exec = validator,
                            },
                        },
                    },

                    &cli.Command{
                        .name = "shred-network",
                        .description = .{
                            .one_line = "Run the shred network to collect and store shreds",
                            .detailed =
                            \\ This command runs the shred network without running the full validator
                            \\ (mainly excluding the accounts-db setup).
                            \\
                            \\ NOTE: this means that this command *requires* a leader schedule to be provided
                            \\ (which would usually be derived from the accountsdb snapshot).
                            \\
                            \\ NOTE: this command also requires `start_slot` (`--test-repair-for-slot`) to be given as well
                            \\ (which is usually derived from the accountsdb snapshot).
                            \\ This can be done with `--test-repair-for-slot $(solana slot -u testnet)`
                            \\ for testnet or another `-u` for mainnet/devnet.
                            ,
                        },
                        .options = &.{
                            &shred_version_option,
                            // gossip
                            &gossip_host_option,
                            &gossip_port_option,
                            &gossip_entrypoints_option,
                            &gossip_spy_node_option,
                            &gossip_dump_option,
                            // shred_network
                            &turbine_recv_port_option,
                            &repair_port_option,
                            &test_repair_option,
                            &dump_shred_tracker,
                            &turbine_num_retransmit_threads,
                            &turbine_overwrite_stake_for_testing,
                            &retransmit_option,
                            // blockstore cleanup service
                            &max_shreds_option,
                            // general
                            &leader_schedule_option,
                            &network_option,
                            &snapshot_metadata_only,
                        },
                        .target = .{
                            .action = .{
                                .exec = shredNetwork,
                            },
                        },
                    },

                    &cli.Command{
                        .name = "snapshot-download",
                        .description = .{
                            .one_line = "Downloads a snapshot",
                            .detailed =
                            \\starts a gossip client and downloads a snapshot from peers
                            ,
                        },
                        .options = &.{
                            &shred_version_option,
                            // where to download the snapshot
                            &snapshot_dir_option,
                            // download options
                            &trusted_validators_option,
                            &min_snapshot_download_speed_mb_option,
                            // gossip options
                            &gossip_host_option,
                            &gossip_port_option,
                            &gossip_entrypoints_option,
                            &network_option,
                        },
                        .target = .{
                            .action = .{
                                .exec = downloadSnapshot,
                            },
                        },
                    },
                    &cli.Command{
                        .name = "snapshot-validate",
                        .description = .{
                            .one_line = "Validates a snapshot",
                            .detailed =
                            \\Loads and validates a snapshot (doesnt download a snapshot).
                            ,
                        },
                        .options = &.{
                            &snapshot_dir_option,
                            &use_disk_index_option,
                            &n_threads_snapshot_load_option,
                            &n_threads_snapshot_unpack_option,
                            &force_unpack_snapshot_option,
                            &number_of_index_shards_option,
                            &genesis_file_path,
                            &accounts_per_file_estimate,
                            &fastload_option,
                            &save_index_option,
                            &network_option,
                            // geyser
                            &enable_geyser_option,
                            &geyser_pipe_path_option,
                            &geyser_writer_fba_bytes_option,
                        },
                        .target = .{
                            .action = .{
                                .exec = validateSnapshot,
                            },
                        },
                    },

                    &cli.Command{
                        .name = "snapshot-create",
                        .description = .{
                            .one_line =
                            \\Loads from a snapshot and outputs to new snapshot alt_{VALIDATOR_DIR}/
                            ,
                        },
                        .options = &.{
                            &snapshot_dir_option,
                            &genesis_file_path,
                        },
                        .target = .{
                            .action = .{
                                .exec = createSnapshot,
                            },
                        },
                    },

                    &cli.Command{
                        .name = "print-manifest",
                        .description = .{
                            .one_line = "Prints a manifest file",
                            .detailed =
                            \\ Loads and prints a manifest file
                            ,
                        },
                        .options = &.{
                            &snapshot_dir_option,
                        },
                        .target = .{
                            .action = .{
                                .exec = printManifest,
                            },
                        },
                    },

                    &cli.Command{
                        .name = "leader-schedule",
                        .description = .{
                            .one_line = "Prints the leader schedule from the snapshot",
                            .detailed =
                            \\- Starts gossip
                            \\- acquires a snapshot if necessary
                            \\- loads accounts db from the snapshot
                            \\- calculates the leader schedule from the snaphot
                            \\- prints the leader schedule in the same format as `solana leader-schedule`
                            \\- exits
                            ,
                        },
                        .options = &.{
                            &shred_version_option,
                            // gossip
                            &gossip_host_option,
                            &gossip_port_option,
                            &gossip_entrypoints_option,
                            &gossip_spy_node_option,
                            &gossip_dump_option,
                            // accounts-db
                            &snapshot_dir_option,
                            &use_disk_index_option,
                            &n_threads_snapshot_load_option,
                            &n_threads_snapshot_unpack_option,
                            &force_unpack_snapshot_option,
                            &min_snapshot_download_speed_mb_option,
                            &force_new_snapshot_download_option,
                            &trusted_validators_option,
                            &number_of_index_shards_option,
                            &genesis_file_path,
                            &accounts_per_file_estimate,
                            // general
                            &leader_schedule_option,
                            &network_option,
                        },
                        .target = .{
                            .action = .{
                                .exec = printLeaderSchedule,
                            },
                        },
                    },
                    &cli.Command{
                        .name = "test-transaction-sender",
                        .description = .{
                            .one_line = "Test transaction sender service",
                            .detailed =
                            \\Simulates a stream of transaction being sent to the transaction sender by
                            \\running a mock transaction generator thread. For the moment this just sends
                            \\transfer transactions between to hard coded testnet accounts.
                            ,
                        },
                        .options = &.{
                            &shred_version_option,
                            // gossip
                            &network_option,
                            &gossip_host_option,
                            &gossip_port_option,
                            &gossip_entrypoints_option,
                            &gossip_spy_node_option,
                            &gossip_dump_option,
                            &network_option,
                            &genesis_file_path,
                            // command specific
                            &n_transactions_option,
                            &n_lamports_per_tx_option,
                        },
                        .target = .{
                            .action = .{
                                .exec = testTransactionSenderService,
                            },
                        },
                    },
                },
            },
        },
    };
    return cli.run(&app, gpa_allocator);
}

/// entrypoint to print (and create if NONE) pubkey in ~/.sig/identity.key
fn identity() !void {
    const logger = try spawnLogger(gpa_allocator);
    defer logger.deinit();

    const keypair = try sig.identity.getOrInit(gpa_allocator, logger);
    const pubkey = Pubkey.fromPublicKey(&keypair.public_key);

    logger.info().logf("Identity: {s}\n", .{pubkey});
}

/// entrypoint to run only gossip
fn gossip() !void {
    var app_base = try AppBase.init(gpa_allocator);
    errdefer {
        app_base.shutdown();
        app_base.deinit();
    }

    const gossip_service = try startGossip(gpa_allocator, &app_base, &.{});
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        gpa_allocator.destroy(gossip_service);
    }

    // block forever
    gossip_service.service_manager.join();
}

/// entrypoint to run a full solana validator
fn validator() !void {
    const allocator = gpa_allocator;
    var app_base = try AppBase.init(allocator);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    const repair_port: u16 = current_config.shred_network.repair_port;
    const turbine_recv_port: u16 = current_config.shred_network.turbine_recv_port;
    const snapshot_dir_str = current_config.accounts_db.snapshot_dir;

    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{});
    defer snapshot_dir.close();

    var gossip_service = try startGossip(allocator, &app_base, &.{
        .{ .tag = .repair, .port = repair_port },
        .{ .tag = .turbine_recv, .port = turbine_recv_port },
    });
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    const geyser_writer: ?*GeyserWriter = createGeyserWriterFromConfig(
        allocator,
        current_config.geyser,
    ) catch |err| switch (err) {
        error.GeyserWriterIsDisabled => null,
        else => return err,
    };
    defer {
        if (geyser_writer) |geyser| {
            geyser.deinit();
            allocator.destroy(geyser.exit);
        }
    }

    // snapshot
    var loaded_snapshot = try loadSnapshot(allocator, app_base.logger.unscoped(), .{
        .gossip_service = gossip_service,
        .geyser_writer = geyser_writer,
        .validate_snapshot = true,
    });
    defer loaded_snapshot.deinit();

    const collapsed_manifest = &loaded_snapshot.collapsed_manifest;
    const bank_fields = &collapsed_manifest.bank_fields;

    // leader schedule
    var leader_schedule_cache = LeaderScheduleCache.init(allocator, bank_fields.epoch_schedule);
    if (try getLeaderScheduleFromCli(allocator)) |leader_schedule| {
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
        current_config.max_shreds,
        &app_base.exit,
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
    var rpc_client = sig.rpc.Client.init(allocator, rpc_cluster_type, .{});
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
        .{ &rpc_epoch_ctx_service, &app_base.exit },
    );

    const turbine_config = current_config.turbine;

    // shred network
    var shred_network_manager = try sig.shred_network.start(
        current_config.shred_network.toConfig(loaded_snapshot.collapsed_manifest.bank_fields.slot),
        .{
            .allocator = allocator,
            .logger = app_base.logger.unscoped(),
            .registry = app_base.metrics_registry,
            .random = prng.random(),
            .my_keypair = &app_base.my_keypair,
            .exit = &app_base.exit,
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

    rpc_epoch_ctx_service_thread.join();
    gossip_service.service_manager.join();
    shred_network_manager.join();
}

fn shredNetwork() !void {
    const allocator = gpa_allocator;
    var app_base = try AppBase.init(allocator);
    defer {
        if (!app_base.closed) app_base.shutdown();
        app_base.deinit();
    }

    const genesis_path = try current_config.genesisFilePath() orelse
        return error.GenesisPathNotProvided;
    const genesis_config = try GenesisConfig.init(allocator, genesis_path);

    var rpc_client = sig.rpc.Client.init(allocator, genesis_config.cluster_type, .{});
    defer rpc_client.deinit();

    const shred_network_conf = current_config.shred_network.toConfig(
        current_config.shred_network.start_slot orelse blk: {
            const response = try rpc_client.getSlot(allocator, .{});
            break :blk try response.result();
        },
    );
    app_base.logger.info().logf("Starting from slot: {?}", .{shred_network_conf.start_slot});

    const repair_port: u16 = shred_network_conf.repair_port;
    const turbine_recv_port: u16 = shred_network_conf.turbine_recv_port;

    var gossip_service = try startGossip(allocator, &app_base, &.{
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
        .{ &rpc_epoch_ctx_service, &app_base.exit },
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
        current_config.max_shreds,
        &app_base.exit,
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
        .exit = &app_base.exit,
        .gossip_table_rw = &gossip_service.gossip_table_rw,
        .my_shred_version = &gossip_service.my_shred_version,
        .epoch_context_mgr = &epoch_context_manager,
        .shred_inserter = shred_inserter,
        .my_contact_info = my_contact_info,
        .n_retransmit_threads = current_config.turbine.num_retransmit_threads,
        .overwrite_turbine_stake_for_testing = current_config.turbine.overwrite_stake_for_testing,
    });
    defer shred_network_manager.deinit();

    rpc_epoch_ctx_service_thread.join();
    gossip_service.service_manager.join();
    shred_network_manager.join();
}

fn printManifest() !void {
    const allocator = gpa_allocator;
    var app_base = try AppBase.init(allocator);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    const snapshot_dir_str = current_config.accounts_db.snapshot_dir;
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

fn createSnapshot() !void {
    const allocator = gpa_allocator;
    var app_base = try AppBase.init(allocator);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    const snapshot_dir_str = current_config.accounts_db.snapshot_dir;
    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{});
    defer snapshot_dir.close();

    var loaded_snapshot = try loadSnapshot(allocator, app_base.logger.unscoped(), .{
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

fn validateSnapshot() !void {
    const allocator = gpa_allocator;
    var app_base = try AppBase.init(allocator);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    const snapshot_dir_str = current_config.accounts_db.snapshot_dir;
    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{});
    defer snapshot_dir.close();

    const geyser_writer: ?*GeyserWriter = createGeyserWriterFromConfig(
        allocator,
        current_config.geyser,
    ) catch |err| switch (err) {
        error.GeyserWriterIsDisabled => null,
        else => return err,
    };
    defer {
        if (geyser_writer) |geyser| {
            geyser.deinit();
            allocator.destroy(geyser.exit);
        }
    }

    var loaded_snapshot = try loadSnapshot(allocator, app_base.logger.unscoped(), .{
        .gossip_service = null,
        .geyser_writer = geyser_writer,
        .validate_snapshot = true,
        .metadata_only = false,
    });
    defer loaded_snapshot.deinit();
}

/// entrypoint to print the leader schedule and then exit
fn printLeaderSchedule() !void {
    const allocator = gpa_allocator;
    var app_base = try AppBase.init(allocator);
    defer {
        app_base.shutdown();
        app_base.deinit();
    }

    const start_slot, const leader_schedule = try getLeaderScheduleFromCli(allocator) orelse b: {
        app_base.logger.info().log("Downloading a snapshot to calculate the leader schedule.");

        var loaded_snapshot = loadSnapshot(allocator, app_base.logger.unscoped(), .{
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

fn getLeaderScheduleFromCli(allocator: std.mem.Allocator) !?struct { Slot, LeaderSchedule } {
    return if (current_config.leader_schedule_path) |path|
        if (std.mem.eql(u8, "--", path))
            try LeaderSchedule.read(allocator, std.io.getStdIn().reader())
        else
            try LeaderSchedule.read(allocator, (try std.fs.cwd().openFile(path, .{})).reader())
    else
        null;
}

pub fn testTransactionSenderService() !void {
    const allocator = gpa_allocator;

    var app_base = try AppBase.init(allocator);
    defer {
        if (!app_base.closed) app_base.shutdown(); // we have this incase an error occurs
        app_base.deinit();
    }

    // read genesis (used for leader schedule)
    const genesis_file_path = try current_config.genesisFilePath() orelse
        @panic("No genesis file path found: use -g or -n");
    const genesis_config = try GenesisConfig.init(allocator, genesis_file_path);

    // start gossip (used to get TPU ports of leaders)
    const gossip_service = try startGossip(allocator, &app_base, &.{});
    defer {
        gossip_service.deinit();
        allocator.destroy(gossip_service);
    }

    // define cluster of where to land transactions
    const rpc_cluster: ClusterType = if (try current_config.gossip.getCluster()) |n| switch (n) {
        .mainnet => .MainnetBeta,
        .devnet => .Devnet,
        .testnet => .Testnet,
        .localnet => .LocalHost,
    } else {
        @panic("network option (-n) not provided");
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
        &app_base.exit,
    );
    const transaction_sender_handle = try std.Thread.spawn(
        .{},
        sig.transaction_sender.Service.run,
        .{&transaction_sender_service},
    );

    // rpc is used to get blockhashes and other balance information
    var rpc_client = sig.rpc.Client.init(allocator, rpc_cluster, .{
        .logger = app_base.logger.unscoped(),
    });
    defer rpc_client.deinit();

    // this sends mock txs to the transaction sender
    var mock_transfer_service = try sig.transaction_sender.MockTransferService.init(
        allocator,
        transaction_channel,
        rpc_client,
        &app_base.exit,
        app_base.logger.unscoped(),
    );
    // send and confirm mock transactions
    try mock_transfer_service.run(
        current_config.test_transaction_sender.n_transactions,
        current_config.test_transaction_sender.n_lamports_per_transaction,
    );

    gossip_service.shutdown();
    app_base.shutdown();
    transaction_sender_handle.join();
}

/// State that typically needs to be initialized at the start of the app,
/// and deinitialized only when the app exits.
const AppBase = struct {
    allocator: std.mem.Allocator,
    logger: ScopedLogger,
    metrics_registry: *sig.prometheus.Registry(.{}),
    metrics_thread: std.Thread,

    my_keypair: sig.identity.KeyPair,
    entrypoints: []SocketAddr,
    shred_version: u16,
    my_ip: IpAddr,
    my_port: u16,

    exit: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    closed: bool,

    const Self = @This();

    fn init(allocator: std.mem.Allocator) !AppBase {
        const logger = (try spawnLogger(allocator)).withScope(LOG_SCOPE);
        errdefer logger.deinit();

        const metrics_registry = globalRegistry();
        const metrics_thread = try spawnMetrics(allocator, current_config.metrics_port);
        errdefer metrics_thread.detach();

        const my_keypair = try sig.identity.getOrInit(allocator, logger.unscoped());
        const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);

        const entrypoints = try current_config.gossip.getEntrypointAddrs(allocator);

        const echo_data = try getShredAndIPFromEchoServer(
            logger.unscoped(),
            allocator,
            entrypoints,
        );

        // zig fmt: off
        const my_shred_version = current_config.shred_version
            orelse echo_data.shred_version
            orelse 0;
        // zig fmt: on

        const config_host = current_config.gossip.getHost() catch null;
        const my_ip = config_host orelse echo_data.ip orelse IpAddr.newIpv4(127, 0, 0, 1);

        const my_port = current_config.gossip.port;

        logger.info()
            .field("metrics_port", current_config.metrics_port)
            .field("identity", my_pubkey)
            .field("entrypoints", entrypoints)
            .field("shred_version", my_shred_version)
            .log("app setup");

        return .{
            .allocator = allocator,
            .logger = logger,
            .metrics_registry = metrics_registry,
            .metrics_thread = metrics_thread,
            .my_keypair = my_keypair,
            .entrypoints = entrypoints,
            .shred_version = my_shred_version,
            .my_ip = my_ip,
            .my_port = my_port,
            .closed = false,
        };
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
    }
};

fn startGossip(
    allocator: std.mem.Allocator,
    app_base: *AppBase,
    /// Extra sockets to publish in gossip, other than the gossip socket
    extra_sockets: []const struct { tag: SocketTag, port: u16 },
) !*GossipService {
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
        gpa_allocator,
        gossip_value_gpa_allocator,
        contact_info,
        app_base.my_keypair, // TODO: consider security implication of passing keypair by value
        app_base.entrypoints,
        app_base.logger.unscoped(),
    );

    try service.start(.{
        .spy_node = current_config.gossip.spy_node,
        .dump = current_config.gossip.dump,
    });

    return service;
}

fn spawnLogger(allocator: std.mem.Allocator) !Logger {
    var std_logger = try ChannelPrintLogger.init(.{
        .allocator = allocator,
        .max_level = current_config.log_level,
        .max_buffer = 1 << 20,
    });
    return std_logger.logger();
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
    unscoped_logger: Logger,
    options: LoadSnapshotOptions,
) !LoadedSnapshot {
    const logger = unscoped_logger.withScope(@typeName(@This()) ++ "." ++ @src().fn_name);

    var validator_dir = try std.fs.cwd().makeOpenPath(sig.VALIDATOR_DIR, .{});
    defer validator_dir.close();

    const genesis_file_path = try current_config.genesisFilePath() orelse
        return error.GenesisPathNotProvided;

    const adb_config = current_config.accounts_db;
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
            current_config.accounts_db.num_threads_snapshot_load;
        if (cli_n_threads_snapshot_load == 0) {
            // default value
            break :blk std.math.lossyCast(u32, try std.Thread.getCpuCount());
        } else {
            break :blk cli_n_threads_snapshot_load;
        }
    };
    logger.info().logf("n_threads_snapshot_load: {d}", .{n_threads_snapshot_load});

    var accounts_db = try AccountsDB.init(.{
        .allocator = allocator,
        .logger = logger.unscoped(),
        .snapshot_dir = snapshot_dir,
        .geyser_writer = options.geyser_writer,
        .gossip_view = if (options.gossip_service) |service|
            try AccountsDB.GossipView.fromService(service)
        else
            null,
        .index_allocation = if (current_config.accounts_db.use_disk_index) .disk else .ram,
        .number_of_index_shards = current_config.accounts_db.number_of_index_shards,
        .lru_size = 10_000,
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
            current_config.accounts_db.accounts_per_file_estimate,
            current_config.accounts_db.fastload,
            current_config.accounts_db.save_index,
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

    try Bank.validateBankFields(&collapsed_manifest.bank_fields, &genesis_config);

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
fn downloadSnapshot() !void {
    var app_base = try AppBase.init(gpa_allocator);
    errdefer {
        app_base.shutdown();
        app_base.deinit();
    }

    if (app_base.entrypoints.len == 0) {
        @panic("cannot download a snapshot with no entrypoints");
    }
    const gossip_service = try startGossip(gpa_allocator, &app_base, &.{});
    defer {
        gossip_service.shutdown();
        gossip_service.deinit();
        gpa_allocator.destroy(gossip_service);
    }

    const trusted_validators = try getTrustedValidators(gpa_allocator);
    defer if (trusted_validators) |*tvs| tvs.deinit();

    const snapshot_dir_str = current_config.accounts_db.snapshot_dir;
    const min_mb_per_sec = current_config.accounts_db.min_snapshot_download_speed_mbs;

    var snapshot_dir = try std.fs.cwd().makeOpenPath(snapshot_dir_str, .{});
    defer snapshot_dir.close();

    const full_file, const maybe_inc_file = try downloadSnapshotsFromGossip(
        gpa_allocator,
        app_base.logger.unscoped(),
        if (trusted_validators) |trusted| trusted.items else null,
        gossip_service,
        snapshot_dir,
        @intCast(min_mb_per_sec),
        current_config.accounts_db.max_number_of_snapshot_download_attempts,
        null,
    );
    defer full_file.close();
    defer if (maybe_inc_file) |inc_file| inc_file.close();
}

fn getTrustedValidators(allocator: std.mem.Allocator) !?std.ArrayList(Pubkey) {
    var trusted_validators: ?std.ArrayList(Pubkey) = null;
    if (current_config.gossip.trusted_validators.len > 0) {
        trusted_validators = try std.ArrayList(Pubkey).initCapacity(
            allocator,
            current_config.gossip.trusted_validators.len,
        );
        for (current_config.gossip.trusted_validators) |trusted_validator_str| {
            trusted_validators.?.appendAssumeCapacity(
                try Pubkey.fromString(trusted_validator_str),
            );
        }
    }
    return trusted_validators;
}
