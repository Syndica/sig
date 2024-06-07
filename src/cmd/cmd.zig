const std = @import("std");
const base58 = @import("base58-zig");
const cli = @import("zig-cli");
const network = @import("zig-network");
const helpers = @import("helpers.zig");
const sig = @import("../lib.zig");
const config = @import("config.zig");

const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Random = std.rand.Random;
const Socket = network.Socket;

const AccountsDB = sig.accounts_db.AccountsDB;
const AccountsDBConfig = sig.accounts_db.AccountsDBConfig;
const AllSnapshotFields = sig.accounts_db.AllSnapshotFields;
const Bank = sig.accounts_db.Bank;
const ContactInfo = sig.gossip.ContactInfo;
const GenesisConfig = sig.accounts_db.GenesisConfig;
const GossipService = sig.gossip.GossipService;
const IpAddr = sig.net.IpAddr;
const Level = sig.trace.Level;
const Logger = sig.trace.Logger;
const Pubkey = sig.core.Pubkey;
const ShredCollectorDependencies = sig.shred_collector.ShredCollectorDependencies;
const SnapshotFieldsAndPaths = sig.accounts_db.SnapshotFieldsAndPaths;
const SnapshotFiles = sig.accounts_db.SnapshotFiles;
const SocketAddr = sig.net.SocketAddr;
const StatusCache = sig.accounts_db.StatusCache;

const downloadSnapshotsFromGossip = sig.accounts_db.downloadSnapshotsFromGossip;
const enumFromName = sig.utils.types.enumFromName;
const getOrInitIdentity = helpers.getOrInitIdentity;
const globalRegistry = sig.prometheus.globalRegistry;
const getWallclockMs = sig.gossip.getWallclockMs;
const parallelUnpackZstdTarBall = sig.accounts_db.parallelUnpackZstdTarBall;
const requestIpEcho = sig.net.requestIpEcho;
const servePrometheus = sig.prometheus.servePrometheus;

const socket_tag = sig.gossip.socket_tag;
const SOCKET_TIMEOUT_US = sig.net.SOCKET_TIMEOUT_US;
const ACCOUNT_INDEX_BINS = sig.accounts_db.ACCOUNT_INDEX_BINS;

// TODO: use better allocator, unless GPA becomes more performant.

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const gpa_allocator = gpa.allocator();

var gossip_value_gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
const gossip_value_gpa_allocator = gossip_value_gpa.allocator();

const base58Encoder = base58.Encoder.init(.{});

const gossip_host = struct {
    // TODO: support domain names and ipv6 addresses
    var option = cli.Option{
        .long_name = "gossip-host",
        .help = "IPv4 address for the validator to advertise in gossip - default: get from --entrypoint, fallback to 127.0.0.1",
        .value_ref = cli.mkRef(&config.current.gossip.host),
        .required = false,
        .value_name = "Gossip Host",
    };

    fn get() !?IpAddr {
        if (config.current.gossip.host) |str| {
            var buf: [15]u8 = undefined;
            @memcpy(buf[0..str.len], str);
            @memcpy(buf[str.len .. str.len + 2], ":0");
            const sa = try SocketAddr.parseIpv4(buf[0 .. str.len + 2]);
            return .{ .ipv4 = sa.V4.ip };
        }
        return null;
    }
};

var gossip_port_option = cli.Option{
    .long_name = "gossip-port",
    .help = "The port to run gossip listener - default: 8001",
    .short_alias = 'p',
    .value_ref = cli.mkRef(&config.current.gossip.port),
    .required = false,
    .value_name = "Gossip Port",
};

var repair_port_option = cli.Option{
    .long_name = "repair-port",
    .help = "The port to run shred repair listener - default: 8002",
    .value_ref = cli.mkRef(&config.current.shred_collector.repair_port),
    .required = false,
    .value_name = "Repair Port",
};

var turbine_recv_port_option = cli.Option{
    .long_name = "turbine-port",
    .help = "The port to run turbine shred listener (aka TVU port) - default: 8003",
    .value_ref = cli.mkRef(&config.current.shred_collector.turbine_recv_port),
    .required = false,
    .value_name = "Turbine Port",
};

var test_repair_option = cli.Option{
    .long_name = "test-repair-for-slot",
    .help = "Set a slot here to repeatedly send repair requests for shreds from this slot. This is only intended for use during short-lived tests of the repair service. Do not set this during normal usage.",
    .value_ref = cli.mkRef(&config.current.shred_collector.start_slot),
    .required = false,
    .value_name = "slot number",
};

var gossip_entrypoints_option = cli.Option{
    .long_name = "entrypoint",
    .help = "gossip address of the entrypoint validators",
    .short_alias = 'e',
    .value_ref = cli.mkRef(&config.current.gossip.entrypoints),
    .required = false,
    .value_name = "Entrypoints",
};

var trusted_validators_option = cli.Option{
    .long_name = "trusted_validator",
    .help = "public key of a validator whose snapshot hash is trusted to be downloaded",
    .short_alias = 't',
    .value_ref = cli.mkRef(&config.current.gossip.trusted_validators),
    .required = false,
    .value_name = "Trusted Validator",
};

var gossip_spy_node_option = cli.Option{
    .long_name = "spy-node",
    .help = "run as a gossip spy node (minimize outgoing packets)",
    .value_ref = cli.mkRef(&config.current.gossip.spy_node),
    .required = false,
    .value_name = "Spy Node",
};

var gossip_dump_option = cli.Option{
    .long_name = "dump-gossip",
    .help = "periodically dump gossip table to csv files and logs",
    .value_ref = cli.mkRef(&config.current.gossip.dump),
    .required = false,
    .value_name = "Gossip Table Dump",
};

var log_level_option = cli.Option{
    .long_name = "log-level",
    .help = "The amount of detail to log (default = debug)",
    .short_alias = 'l',
    .value_ref = cli.mkRef(&config.current.log_level),
    .required = false,
    .value_name = "err|warn|info|debug",
};

var metrics_port_option = cli.Option{
    .long_name = "metrics-port",
    .help = "port to expose prometheus metrics via http - default: 12345",
    .short_alias = 'm',
    .value_ref = cli.mkRef(&config.current.metrics_port),
    .required = false,
    .value_name = "port_number",
};

// accounts-db options
var n_threads_snapshot_load_option = cli.Option{
    .long_name = "n-threads-snapshot-load",
    .help = "number of threads to load snapshots: - default: ncpus",
    .short_alias = 't',
    .value_ref = cli.mkRef(&config.current.accounts_db.num_threads_snapshot_load),
    .required = false,
    .value_name = "n_threads_snapshot_load",
};

var n_threads_snapshot_unpack_option = cli.Option{
    .long_name = "n-threads-snapshot-unpack",
    .help = "number of threads to unpack snapshots - default: ncpus * 2",
    .short_alias = 'u',
    .value_ref = cli.mkRef(&config.current.accounts_db.num_threads_snapshot_unpack),
    .required = false,
    .value_name = "n_threads_snapshot_unpack",
};

var disk_index_path_option = cli.Option{
    .long_name = "disk-index-path",
    .help = "path to disk index - default: no disk index, index will use ram",
    .short_alias = 'd',
    .value_ref = cli.mkRef(&config.current.accounts_db.disk_index_path),
    .required = false,
    .value_name = "disk_index_path",
};

var force_unpack_snapshot_option = cli.Option{
    .long_name = "force-unpack-snapshot",
    .help = "force unpack snapshot even if it exists",
    .short_alias = 'f',
    .value_ref = cli.mkRef(&config.current.accounts_db.force_unpack_snapshot),
    .required = false,
    .value_name = "force_unpack_snapshot",
};

var force_new_snapshot_download_option = cli.Option{
    .long_name = "force-new-snapshot-download",
    .help = "force download of new snapshot (usually to get a more up-to-date snapshot)",
    .value_ref = cli.mkRef(&config.current.accounts_db.force_new_snapshot_download),
    .required = false,
    .value_name = "force_new_snapshot_download",
};

var snapshot_dir_option = cli.Option{
    .long_name = "snapshot-dir",
    .help = "path to snapshot directory (where snapshots are downloaded and/or unpacked to/from) - default: test_data/",
    .short_alias = 's',
    .value_ref = cli.mkRef(&config.current.accounts_db.snapshot_dir),
    .required = false,
    .value_name = "snapshot_dir",
};

var min_snapshot_download_speed_mb_option = cli.Option{
    .long_name = "min-snapshot-download-speed",
    .help = "minimum download speed of full snapshots in megabytes per second - default: 20MB/s",
    .value_ref = cli.mkRef(&config.current.accounts_db.min_snapshot_download_speed_mbs),
    .required = false,
    .value_name = "min_snapshot_download_speed_mb",
};

var storage_cache_size_option = cli.Option{
    .long_name = "storage-cache-size",
    .help = "number of accounts preallocate for the storage cache for accounts-db (used when writing accounts whose slot has not been rooted) - default: 10k",
    .value_ref = cli.mkRef(&config.current.accounts_db.storage_cache_size),
    .required = false,
    .value_name = "storage_cache_size",
};

var number_of_index_bins_option = cli.Option{
    .long_name = "number-of-index-bins",
    .help = "number of bins to shard the index pubkeys across",
    .value_ref = cli.mkRef(&config.current.accounts_db.num_account_index_bins),
    .required = false,
    .value_name = "number_of_index_bins",
};

var app = &cli.App{
    .version = "0.2.0",
    .author = "Syndica & Contributors",
    .command = .{
        .name = "sig",
        .description = .{
            .one_line = "Sig is a Solana client implementation written in Zig.\nThis is still a WIP, PRs welcome.",
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
                        &gossip_host.option,
                        &gossip_port_option,
                        &gossip_entrypoints_option,
                        &gossip_spy_node_option,
                        &gossip_dump_option,
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
                        // gossip
                        &gossip_host.option,
                        &gossip_port_option,
                        &gossip_entrypoints_option,
                        &gossip_spy_node_option,
                        &gossip_dump_option,
                        // repair
                        &turbine_recv_port_option,
                        &repair_port_option,
                        &test_repair_option,
                        // accounts-db
                        &snapshot_dir_option,
                        &n_threads_snapshot_load_option,
                        &n_threads_snapshot_unpack_option,
                        &disk_index_path_option,
                        &force_unpack_snapshot_option,
                        &min_snapshot_download_speed_mb_option,
                        &force_new_snapshot_download_option,
                        &trusted_validators_option,
                    },
                    .target = .{
                        .action = .{
                            .exec = validator,
                        },
                    },
                },
                &cli.Command{
                    .name = "download-snapshot",
                    .description = .{
                        .one_line = "Downloads a snapshot",
                        .detailed =
                        \\starts a gossip client and downloads a snapshot from peers
                        ,
                    },
                    .options = &.{
                        // where to download the snapshot
                        &snapshot_dir_option,
                        // download options
                        &trusted_validators_option,
                        &min_snapshot_download_speed_mb_option,
                        // gossip options
                        &gossip_host.option,
                        &gossip_port_option,
                        &gossip_entrypoints_option,
                    },
                    .target = .{
                        .action = .{
                            .exec = downloadSnapshot,
                        },
                    },
                },
            },
        },
    },
};

/// entrypoint to print (and create if NONE) pubkey in ~/.sig/identity.key
fn identity() !void {
    var logger = Logger.init(gpa_allocator, try enumFromName(Level, config.current.log_level));
    defer logger.deinit();
    logger.spawn();

    const keypair = try getOrInitIdentity(gpa_allocator, logger);
    var pubkey: [50]u8 = undefined;
    const size = try base58Encoder.encode(&keypair.public_key.toBytes(), &pubkey);
    try std.io.getStdErr().writer().print("Identity: {s}\n", .{pubkey[0..size]});
}

/// entrypoint to run only gossip
fn gossip() !void {
    var logger = try spawnLogger();
    defer logger.deinit();
    const metrics_thread = try spawnMetrics(logger);
    defer metrics_thread.detach();

    var exit = std.atomic.Value(bool).init(false);
    const my_keypair = try getOrInitIdentity(gpa_allocator, logger);
    const entrypoints = try getEntrypoints(logger);
    defer entrypoints.deinit();
    const my_data = try getMyDataFromIpEcho(logger, entrypoints.items);

    var gossip_service = try initGossip(
        logger,
        my_keypair,
        &exit,
        entrypoints.items,
        my_data.shred_version,
        my_data.ip,
        &.{},
    );
    defer gossip_service.deinit();

    try runGossipWithConfigValues(&gossip_service);
}

/// entrypoint to run a full solana validator
fn validator() !void {
    var logger = try spawnLogger();
    defer logger.deinit();
    const metrics_thread = try spawnMetrics(logger);
    defer metrics_thread.detach();

    var rand = std.rand.DefaultPrng.init(@bitCast(std.time.timestamp()));
    var exit = std.atomic.Value(bool).init(false);
    const my_keypair = try getOrInitIdentity(gpa_allocator, logger);
    const entrypoints = try getEntrypoints(logger);
    defer entrypoints.deinit();
    const ip_echo_data = try getMyDataFromIpEcho(logger, entrypoints.items);

    const repair_port: u16 = config.current.shred_collector.repair_port;
    const turbine_recv_port: u16 = config.current.shred_collector.repair_port;

    // gossip
    var gossip_service = try initGossip(
        logger,
        my_keypair,
        &exit,
        entrypoints.items,
        ip_echo_data.shred_version, // TODO atomic owned at top level? or owned by gossip is good?
        ip_echo_data.ip,
        &.{
            .{ .tag = socket_tag.REPAIR, .port = repair_port },
            .{ .tag = socket_tag.TURBINE_RECV, .port = turbine_recv_port },
        },
    );
    defer gossip_service.deinit();
    const gossip_handle = try std.Thread.spawn(.{}, runGossipWithConfigValues, .{&gossip_service});

    // shred collector
    var shred_collector = try sig.shred_collector.start(
        config.current.shred_collector,
        ShredCollectorDependencies{
            .allocator = gpa_allocator,
            .logger = logger,
            .random = rand.random(),
            .my_keypair = &my_keypair,
            .exit = &exit,
            .gossip_table_rw = &gossip_service.gossip_table_rw,
            .my_shred_version = &gossip_service.my_shred_version,
        },
    );
    defer shred_collector.deinit();

    // accounts db
    var snapshots = try getOrDownloadSnapshots(
        gpa_allocator,
        logger,
        &gossip_service,
    );
    defer snapshots.deinit(gpa_allocator);

    logger.infof("full snapshot: {s}", .{snapshots.full_path});
    if (snapshots.incremental_path) |inc_path| {
        logger.infof("incremental snapshot: {s}", .{inc_path});
    }

    // cli parsing
    const snapshot_dir_str = config.current.accounts_db.snapshot_dir;
    const n_cpus = @as(u32, @truncate(try std.Thread.getCpuCount()));
    var n_threads_snapshot_load: u32 = @intCast(config.current.accounts_db.num_threads_snapshot_load);
    if (n_threads_snapshot_load == 0) {
        n_threads_snapshot_load = n_cpus;
    }

    var accounts_db = try AccountsDB.init(
        gpa_allocator,
        logger,
        AccountsDBConfig{
            .disk_index_path = config.current.accounts_db.disk_index_path,
            .storage_cache_size = @intCast(config.current.accounts_db.storage_cache_size),
            .number_of_index_bins = @intCast(config.current.accounts_db.num_account_index_bins),
        },
    );
    defer accounts_db.deinit();

    const snapshot_fields = try accounts_db.loadWithDefaults(
        &snapshots,
        snapshot_dir_str,
        n_threads_snapshot_load,
        true, // validate too
    );
    const bank_fields = snapshot_fields.bank_fields;

    // this should exist before we start to unpack
    logger.infof("reading genesis...", .{});
    const genesis_config = readGenesisConfig(gpa_allocator, snapshot_dir_str) catch |err| {
        if (err == error.GenesisNotFound) {
            logger.errf("genesis.bin not found - expecting {s}/genesis.bin to exist", .{snapshot_dir_str});
        }
        return err;
    };
    defer genesis_config.deinit(gpa_allocator);

    logger.infof("validating bank...", .{});
    const bank = Bank.init(&accounts_db, &bank_fields);
    try Bank.validateBankFields(bank.bank_fields, &genesis_config);

    // validate the status cache
    logger.infof("validating status cache...", .{});
    var status_cache = readStatusCache(gpa_allocator, snapshot_dir_str) catch |err| {
        if (err == error.StatusCacheNotFound) {
            logger.errf("status-cache.bin not found - expecting {s}/snapshots/status-cache to exist", .{snapshot_dir_str});
        }
        return err;
    };
    defer status_cache.deinit();

    var slot_history = try accounts_db.getSlotHistory();
    defer slot_history.deinit(accounts_db.allocator);
    try status_cache.validate(gpa_allocator, bank_fields.slot, &slot_history);

    logger.infof("accounts-db setup done...", .{});

    gossip_handle.join();
    shred_collector.join();
}

/// Initialize an instance of GossipService and configure with CLI arguments
fn initGossip(
    logger: Logger,
    my_keypair: KeyPair,
    exit: *Atomic(bool),
    entrypoints: []const SocketAddr,
    shred_version: u16,
    gossip_host_ip: IpAddr,
    sockets: []const struct { tag: u8, port: u16 },
) !GossipService {
    const gossip_port: u16 = config.current.gossip.port;
    logger.infof("gossip host: {any}", .{gossip_host_ip});
    logger.infof("gossip port: {d}", .{gossip_port});

    // setup contact info
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    var contact_info = ContactInfo.init(gpa_allocator, my_pubkey, getWallclockMs(), 0);
    try contact_info.setSocket(socket_tag.GOSSIP, SocketAddr.init(gossip_host_ip, gossip_port));
    for (sockets) |s| try contact_info.setSocket(s.tag, SocketAddr.init(gossip_host_ip, s.port));
    contact_info.shred_version = shred_version;

    return try GossipService.init(
        gpa_allocator,
        gossip_value_gpa_allocator,
        contact_info,
        my_keypair,
        entrypoints,
        exit,
        logger,
    );
}

fn runGossipWithConfigValues(gossip_service: *GossipService) !void {
    const gossip_config = config.current.gossip;
    return gossip_service.run(.{
        .spy_node = gossip_config.spy_node,
        .dump = gossip_config.dump,
    });
}

/// determine our shred version and ip. in the solana-labs client, the shred version
/// comes from the snapshot, and ip echo is only used to validate it.
fn getMyDataFromIpEcho(
    logger: Logger,
    entrypoints: []SocketAddr,
) !struct { shred_version: u16, ip: IpAddr } {
    var my_ip_from_entrypoint: ?IpAddr = null;
    const my_shred_version = loop: for (entrypoints) |entrypoint| {
        if (requestIpEcho(gpa_allocator, entrypoint.toAddress(), .{})) |response| {
            if (my_ip_from_entrypoint == null) my_ip_from_entrypoint = response.address;
            if (response.shred_version) |shred_version| {
                var addr_str = entrypoint.toString();
                logger.infof(
                    "shred version: {} - from entrypoint ip echo: {s}",
                    .{ shred_version.value, addr_str[0][0..addr_str[1]] },
                );
                break shred_version.value;
            }
        } else |_| {}
    } else {
        logger.warn("could not get a shred version from an entrypoint");
        break :loop 0;
    };
    const my_ip = try gossip_host.get() orelse my_ip_from_entrypoint orelse IpAddr.newIpv4(127, 0, 0, 1);
    logger.infof("my ip: {}", .{my_ip});
    return .{
        .shred_version = my_shred_version,
        .ip = my_ip,
    };
}

fn getEntrypoints(logger: Logger) !std.ArrayList(SocketAddr) {
    const EntrypointSet = std.ArrayHashMap(void, void, struct {
        // zig fmt: off
        pub fn hash(_: @This(), _: void) u32 { unreachable; }
        pub fn eql(_: @This(), _: void, _: void, _: usize) bool { unreachable; }
        // zig fmt: on
    }, true);
    const EntrypointCtx = struct {
        entrypoints: []const SocketAddr,
        pub fn hash(_: @This(), entrypoint: SocketAddr) u32 {
            const array, const len = entrypoint.toString();
            return std.array_hash_map.hashString(array[0..len]);
        }
        pub fn eql(ctx: @This(), a: SocketAddr, _: void, b_index: usize) bool {
            return a.eql(&ctx.entrypoints[b_index]);
        }
    };

    var entrypoints = std.ArrayList(SocketAddr).init(gpa_allocator);
    errdefer entrypoints.deinit();

    var entrypoint_set = EntrypointSet.init(gpa_allocator);
    defer entrypoint_set.deinit();

    try entrypoint_set.ensureTotalCapacity(config.current.gossip.entrypoints.len);
    try entrypoints.ensureTotalCapacityPrecise(config.current.gossip.entrypoints.len);

    for (config.current.gossip.entrypoints) |entrypoint| {
        const socket_addr = SocketAddr.parse(entrypoint) catch brk: {
            const domain_port_sep = std.mem.indexOfScalar(u8, entrypoint, ':') orelse {
                logger.field("entrypoint", entrypoint).err("entrypoint port missing");
                return error.EntrypointPortMissing;
            };
            const domain_str = entrypoint[0..domain_port_sep];
            if (domain_str.len == 0) {
                logger.errf("'{s}': entrypoint domain not valid", .{entrypoint});
                return error.EntrypointDomainNotValid;
            }
            // parse port from string
            const port = std.fmt.parseInt(u16, entrypoint[domain_port_sep + 1 ..], 10) catch {
                logger.errf("'{s}': entrypoint port not valid", .{entrypoint});
                return error.EntrypointPortNotValid;
            };

            // get dns address lists
            const addr_list = try std.net.getAddressList(gpa_allocator, domain_str, port);
            defer addr_list.deinit();

            if (addr_list.addrs.len == 0) {
                logger.errf("'{s}': entrypoint resolve dns failed (no records found)", .{entrypoint});
                return error.EntrypointDnsResolutionFailure;
            }

            // use first A record address
            const ipv4_addr = addr_list.addrs[0];

            const socket_addr = SocketAddr.fromIpV4Address(ipv4_addr);
            std.debug.assert(socket_addr.port() == port);
            break :brk socket_addr;
        };

        const gop = entrypoint_set.getOrPutAssumeCapacityAdapted(socket_addr, EntrypointCtx{ .entrypoints = entrypoints.items });
        if (!gop.found_existing) {
            entrypoints.appendAssumeCapacity(socket_addr);
        }
    }

    // log entrypoints
    const EntrypointsFmt = struct {
        entrypoints: []const SocketAddr,

        pub fn format(
            entrypoints_fmt: @This(),
            comptime fmt_str: []const u8,
            fmt_options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            for (0.., entrypoints_fmt.entrypoints) |i, entrypoint| {
                if (i != 0) try writer.writeAll(", ");
                try entrypoint.toAddress().format(fmt_str, fmt_options, writer);
            }
        }
    };
    logger.infof("entrypoints: {}", .{EntrypointsFmt{ .entrypoints = entrypoints.items }});

    return entrypoints;
}

/// Initializes the global registry. Returns error if registry was already initialized.
/// Spawns a thread to serve the metrics over http on the CLI configured port.
fn spawnMetrics(logger: Logger) !std.Thread {
    const metrics_port: u16 = config.current.metrics_port;
    logger.infof("metrics port: {d}", .{metrics_port});
    const registry = globalRegistry();
    return try std.Thread.spawn(.{}, servePrometheus, .{ gpa_allocator, registry, metrics_port });
}

fn spawnLogger() !Logger {
    var logger = Logger.init(gpa_allocator, try enumFromName(Level, config.current.log_level));
    logger.spawn();
    return logger;
}

/// load genesis config with default filenames
fn readGenesisConfig(
    allocator: std.mem.Allocator,
    snapshot_dir: []const u8,
) !GenesisConfig {
    const genesis_path = try std.fmt.allocPrint(
        allocator,
        "{s}/genesis.bin",
        .{snapshot_dir},
    );
    defer allocator.free(genesis_path);

    std.fs.cwd().access(genesis_path, .{}) catch {
        return error.GenesisNotFound;
    };

    const genesis_config = try GenesisConfig.init(allocator, genesis_path);
    return genesis_config;
}

fn readStatusCache(
    allocator: std.mem.Allocator,
    snapshot_dir: []const u8,
) !StatusCache {
    const status_cache_path = try std.fmt.allocPrint(
        gpa_allocator,
        "{s}/{s}",
        .{ snapshot_dir, "snapshots/status_cache" },
    );
    defer allocator.free(status_cache_path);

    std.fs.cwd().access(status_cache_path, .{}) catch {
        return error.StatusCacheNotFound;
    };

    const status_cache = try StatusCache.init(allocator, status_cache_path);
    return status_cache;
}

/// entrypoint to download snapshot
fn downloadSnapshot() !void {
    var logger = try spawnLogger();
    defer logger.deinit();

    var exit = std.atomic.Value(bool).init(false);
    const my_keypair = try getOrInitIdentity(gpa_allocator, logger);
    const entrypoints = try getEntrypoints(logger);
    defer entrypoints.deinit();

    const my_data = try getMyDataFromIpEcho(logger, entrypoints.items);

    var gossip_service = try initGossip(
        .noop,
        my_keypair,
        &exit,
        entrypoints.items,
        my_data.shred_version,
        my_data.ip,
        &.{},
    );
    defer gossip_service.deinit();
    const handle = try std.Thread.spawn(.{}, runGossipWithConfigValues, .{&gossip_service});
    handle.detach();

    const trusted_validators = try getTrustedValidators(gpa_allocator);
    defer if (trusted_validators) |*tvs| tvs.deinit();

    const snapshot_dir_str = config.current.accounts_db.snapshot_dir;
    const min_mb_per_sec = config.current.accounts_db.min_snapshot_download_speed_mbs;
    try downloadSnapshotsFromGossip(
        gpa_allocator,
        logger,
        trusted_validators,
        &gossip_service,
        snapshot_dir_str,
        @intCast(min_mb_per_sec),
    );
}

fn getTrustedValidators(
    allocator: std.mem.Allocator,
) !?std.ArrayList(Pubkey) {
    var trusted_validators: ?std.ArrayList(Pubkey) = null;
    if (config.current.gossip.trusted_validators.len > 0) {
        trusted_validators = try std.ArrayList(Pubkey).initCapacity(
            allocator,
            config.current.gossip.trusted_validators.len,
        );
        for (config.current.gossip.trusted_validators) |trusted_validator_str| {
            trusted_validators.?.appendAssumeCapacity(
                try Pubkey.fromString(trusted_validator_str),
            );
        }
    }

    return trusted_validators;
}

fn getOrDownloadSnapshots(
    allocator: std.mem.Allocator,
    logger: Logger,
    gossip_service: ?*GossipService,
) !SnapshotFieldsAndPaths {
    // arg parsing
    const snapshot_dir_str = config.current.accounts_db.snapshot_dir;
    const force_unpack_snapshot = config.current.accounts_db.force_unpack_snapshot;
    const force_new_snapshot_download = config.current.accounts_db.force_new_snapshot_download;

    const n_cpus = @as(u32, @truncate(try std.Thread.getCpuCount()));
    var n_threads_snapshot_unpack: u32 = @intCast(config.current.accounts_db.num_threads_snapshot_unpack);
    if (n_threads_snapshot_unpack == 0) {
        n_threads_snapshot_unpack = n_cpus * 2;
    }

    // if this exists, we wont look for a .tar.zstd
    const accounts_path = try std.fmt.allocPrint(
        allocator,
        "{s}/accounts/",
        .{snapshot_dir_str},
    );
    defer allocator.free(accounts_path);

    const maybe_snapshot_files: ?SnapshotFiles = blk: {
        if (force_new_snapshot_download) {
            break :blk null;
        }

        break :blk SnapshotFiles.find(allocator, snapshot_dir_str) catch |err| {
            // if we cant find the full snapshot, we try to download it
            if (err == error.NoFullSnapshotFileInfoFound) {
                break :blk null;
            } else {
                return err;
            }
        };
    };

    var snapshot_files = maybe_snapshot_files orelse blk: {
        const trusted_validators = try getTrustedValidators(gpa_allocator);
        defer if (trusted_validators) |*tvs| tvs.deinit();

        const min_mb_per_sec = config.current.accounts_db.min_snapshot_download_speed_mbs;
        try downloadSnapshotsFromGossip(
            allocator,
            logger,
            trusted_validators,
            gossip_service orelse return error.SnapshotsNotFoundAndNoGossipService,
            snapshot_dir_str,
            @intCast(min_mb_per_sec),
        );
        break :blk try SnapshotFiles.find(allocator, snapshot_dir_str);
    };
    defer snapshot_files.deinit(allocator);

    if (snapshot_files.incremental_snapshot == null) {
        logger.infof("no incremental snapshot found", .{});
    }

    var accounts_path_exists = true;
    std.fs.cwd().access(accounts_path, .{}) catch {
        accounts_path_exists = false;
    };
    const should_unpack_snapshot = !accounts_path_exists or force_unpack_snapshot;

    var timer = try std.time.Timer.start();
    if (should_unpack_snapshot) {
        logger.infof("unpacking snapshots...", .{});
        // if accounts/ doesnt exist then we unpack the found snapshots
        var snapshot_dir = try std.fs.cwd().openDir(snapshot_dir_str, .{ .iterate = true });
        defer snapshot_dir.close();

        // TODO: delete old accounts/ dir if it exists
        timer.reset();
        logger.infof("unpacking {s}...", .{snapshot_files.full_snapshot.filename});
        try parallelUnpackZstdTarBall(
            allocator,
            logger,
            snapshot_files.full_snapshot.filename,
            snapshot_dir,
            n_threads_snapshot_unpack,
            true,
        );
        logger.infof("unpacked snapshot in {s}", .{std.fmt.fmtDuration(timer.read())});

        // TODO: can probs do this in parallel with full snapshot
        if (snapshot_files.incremental_snapshot) |incremental_snapshot| {
            timer.reset();
            logger.infof("unpacking {s}...", .{incremental_snapshot.filename});
            try parallelUnpackZstdTarBall(
                allocator,
                logger,
                incremental_snapshot.filename,
                snapshot_dir,
                n_threads_snapshot_unpack,
                false,
            );
            logger.infof("unpacked snapshot in {s}", .{std.fmt.fmtDuration(timer.read())});
        }
    } else {
        logger.infof("not unpacking snapshot...", .{});
    }

    timer.reset();
    logger.infof("reading snapshot metadata...", .{});
    const snapshots = try AllSnapshotFields.fromFiles(allocator, snapshot_dir_str, snapshot_files);
    logger.infof("read snapshot metdata in {s}", .{std.fmt.fmtDuration(timer.read())});

    return snapshots;
}

pub fn run() !void {
    return cli.run(app, gpa_allocator);
}
