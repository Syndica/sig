const std = @import("std");
const base58 = @import("base58-zig");
const cli = @import("zig-cli");
const network = @import("zig-network");
const helpers = @import("helpers.zig");
const sig = @import("../lib.zig");
const config = @import("config.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const AccountsDB = sig.accounts_db.AccountsDB;
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
const SingleEpochLeaderSchedule = sig.core.leader_schedule.SingleEpochLeaderSchedule;
const SnapshotFieldsAndPaths = sig.accounts_db.SnapshotFieldsAndPaths;
const SnapshotFiles = sig.accounts_db.SnapshotFiles;
const SocketAddr = sig.net.SocketAddr;
const StatusCache = sig.accounts_db.StatusCache;

const downloadSnapshotsFromGossip = sig.accounts_db.downloadSnapshotsFromGossip;
const enumFromName = sig.utils.types.enumFromName;
const getOrInitIdentity = helpers.getOrInitIdentity;
const globalRegistry = sig.prometheus.globalRegistry;
const getWallclockMs = sig.gossip.getWallclockMs;
const leaderScheduleFromBank = sig.core.leader_schedule.leaderScheduleFromBank;
const parallelUnpackZstdTarBall = sig.accounts_db.parallelUnpackZstdTarBall;
const parseLeaderSchedule = sig.core.leader_schedule.parseLeaderSchedule;
const requestIpEcho = sig.net.requestIpEcho;
const servePrometheus = sig.prometheus.servePrometheus;
const writeLeaderSchedule = sig.core.leader_schedule.writeLeaderSchedule;

const SocketTag = sig.gossip.SocketTag;

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

var leader_schedule_option = cli.Option{
    .long_name = "leader-schedule",
    .help = "Set a file path to load the leader schedule. Use '--' to load from stdin",
    .value_ref = cli.mkRef(&config.current.leader_schedule_path),
    .required = false,
    .value_name = "Leader schedule source",
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

var force_unpack_snapshot_option = cli.Option{
    .long_name = "force-unpack-snapshot",
    .help = "force unpack snapshot even if it exists",
    .short_alias = 'f',
    .value_ref = cli.mkRef(&config.current.accounts_db.force_unpack_snapshot),
    .required = false,
    .value_name = "force_unpack_snapshot",
};

var use_disk_index_option = cli.Option{
    .long_name = "use-disk-index",
    .help = "use disk based index for accounts index",
    .value_ref = cli.mkRef(&config.current.accounts_db.use_disk_index),
    .required = false,
    .value_name = "use_disk_index",
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

var number_of_index_bins_option = cli.Option{
    .long_name = "number-of-index-bins",
    .help = "number of bins to shard the index pubkeys across",
    .value_ref = cli.mkRef(&config.current.accounts_db.number_of_index_bins),
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
                        &use_disk_index_option,
                        &n_threads_snapshot_load_option,
                        &n_threads_snapshot_unpack_option,
                        &force_unpack_snapshot_option,
                        &min_snapshot_download_speed_mb_option,
                        &force_new_snapshot_download_option,
                        &trusted_validators_option,
                        // general
                        &leader_schedule_option,
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
                        // gossip
                        &gossip_host.option,
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
                        // general
                        &leader_schedule_option,
                    },
                    .target = .{
                        .action = .{
                            .exec = printLeaderSchedule,
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
    var app_base = try AppBase.init(gpa_allocator);

    var gossip_service, var gossip_manager = try startGossip(gpa_allocator, &app_base, &.{});
    defer gossip_service.deinit();
    defer gossip_manager.deinit();

    gossip_manager.join();
}

/// entrypoint to run a full solana validator
fn validator() !void {
    const allocator = gpa_allocator;
    var app_base = try AppBase.init(allocator);

    const repair_port: u16 = config.current.shred_collector.repair_port;
    const turbine_recv_port: u16 = config.current.shred_collector.repair_port;

    var gossip_service, var gossip_manager = try startGossip(allocator, &app_base, &.{
        .{ .tag = .repair, .port = repair_port },
        .{ .tag = .turbine_recv, .port = turbine_recv_port },
    });
    defer gossip_service.deinit();
    defer gossip_manager.deinit();

    const snapshot = try loadSnapshot(allocator, app_base.logger, gossip_service, false);

    // leader schedule
    var leader_schedule = try getLeaderScheduleFromCli(allocator) orelse
        try leaderScheduleFromBank(allocator, &snapshot.bank);
    const leader_provider = leader_schedule.provider();

    // shred collector
    var shred_col_conf = config.current.shred_collector;
    shred_col_conf.start_slot = shred_col_conf.start_slot orelse snapshot.bank.bank_fields.slot;
    var rng = std.rand.DefaultPrng.init(@bitCast(std.time.timestamp()));
    var shred_collector_manager = try sig.shred_collector.start(
        shred_col_conf,
        ShredCollectorDependencies{
            .allocator = allocator,
            .logger = app_base.logger,
            .random = rng.random(),
            .my_keypair = &app_base.my_keypair,
            .exit = &app_base.exit,
            .gossip_table_rw = &gossip_service.gossip_table_rw,
            .my_shred_version = &gossip_service.my_shred_version,
            .leader_schedule = leader_provider,
        },
    );
    defer shred_collector_manager.deinit();

    gossip_manager.join();
    shred_collector_manager.join();
}

/// entrypoint to print the leader schedule and then exit
fn printLeaderSchedule() !void {
    const allocator = gpa_allocator;
    var app_base = try AppBase.init(allocator);

    const leader_schedule = try getLeaderScheduleFromCli(allocator) orelse b: {
        var gossip_service, var gossip_manager = try startGossip(allocator, &app_base, &.{});
        defer gossip_service.deinit();
        defer gossip_manager.deinit();
        const snapshot = try loadSnapshot(allocator, app_base.logger, gossip_service, false);
        break :b try leaderScheduleFromBank(allocator, &snapshot.bank);
    };

    var stdout = std.io.bufferedWriter(std.io.getStdOut().writer());
    try writeLeaderSchedule(leader_schedule, stdout.writer());
    try stdout.flush();
}

fn getLeaderScheduleFromCli(allocator: Allocator) !?SingleEpochLeaderSchedule {
    return if (config.current.leader_schedule_path) |path|
        if (std.mem.eql(u8, "--", path))
            try parseLeaderSchedule(allocator, std.io.getStdIn().reader())
        else
            try parseLeaderSchedule(allocator, (try std.fs.cwd().openFile(path, .{})).reader())
    else
        null;
}

/// State that typically needs to be initialized at the start of the app,
/// and deinitialized only when the app exits.
const AppBase = struct {
    exit: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    logger: Logger,
    metrics_thread: std.Thread,
    my_keypair: KeyPair,
    entrypoints: std.ArrayList(SocketAddr),
    shred_version: u16,
    my_ip: IpAddr,

    fn init(allocator: Allocator) !AppBase {
        var logger = try spawnLogger();
        errdefer logger.deinit();
        const metrics_thread = try spawnMetrics(logger);
        errdefer metrics_thread.detach();
        const my_keypair = try getOrInitIdentity(allocator, logger);
        const entrypoints = try getEntrypoints(logger);
        errdefer entrypoints.deinit();
        const ip_echo_data = try getMyDataFromIpEcho(logger, entrypoints.items);

        return .{
            .logger = logger,
            .metrics_thread = metrics_thread,
            .my_keypair = my_keypair,
            .entrypoints = entrypoints,
            .shred_version = ip_echo_data.shred_version,
            .my_ip = ip_echo_data.ip,
        };
    }

    pub fn deinit(self: @This()) void {
        self.exit.store(true, .unordered);
        self.entrypoints.deinit();
        self.metrics_thread.detach();
        self.logger.deinit();
    }
};

/// Initialize an instance of GossipService and configure with CLI arguments
fn initGossip(
    logger: Logger,
    my_keypair: KeyPair,
    exit: *Atomic(bool),
    entrypoints: []const SocketAddr,
    shred_version: u16,
    gossip_host_ip: IpAddr,
    sockets: []const struct { tag: SocketTag, port: u16 },
) !GossipService {
    const gossip_port: u16 = config.current.gossip.port;
    logger.infof("gossip host: {any}", .{gossip_host_ip});
    logger.infof("gossip port: {d}", .{gossip_port});

    // setup contact info
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    var contact_info = ContactInfo.init(gpa_allocator, my_pubkey, getWallclockMs(), 0);
    try contact_info.setSocket(.gossip, SocketAddr.init(gossip_host_ip, gossip_port));
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

fn startGossip(
    allocator: Allocator,
    app_base: *AppBase,
    /// Extra sockets to publish in gossip, other than the gossip socket
    extra_sockets: []const struct { tag: SocketTag, port: u16 },
) !struct { *GossipService, sig.utils.service_manager.ServiceManager } {
    const gossip_port = config.current.gossip.port;
    app_base.logger.infof("gossip host: {any}", .{app_base.my_ip});
    app_base.logger.infof("gossip port: {d}", .{gossip_port});

    // setup contact info
    const my_pubkey = Pubkey.fromPublicKey(&app_base.my_keypair.public_key);
    var contact_info = ContactInfo.init(allocator, my_pubkey, getWallclockMs(), 0);
    try contact_info.setSocket(.gossip, SocketAddr.init(app_base.my_ip, gossip_port));
    for (extra_sockets) |s| try contact_info.setSocket(s.tag, SocketAddr.init(app_base.my_ip, s.port));
    contact_info.shred_version = app_base.shred_version;

    var manager = sig.utils.service_manager.ServiceManager.init(
        allocator,
        app_base.logger,
        &app_base.exit,
        "gossip",
        .{},
        .{},
    );
    const service = try manager.arena().create(GossipService);
    service.* = try GossipService.init(
        gpa_allocator,
        gossip_value_gpa_allocator,
        contact_info,
        app_base.my_keypair, // TODO: consider security implication of passing keypair by value
        app_base.entrypoints.items,
        &app_base.exit,
        app_base.logger,
    );
    try manager.defers.deferCall(GossipService.deinit, .{service});

    try service.start(.{
        .spy_node = config.current.gossip.spy_node,
        .dump = config.current.gossip.dump,
    }, &manager);

    return .{ service, manager };
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
    var entrypoints = std.ArrayList(SocketAddr).init(gpa_allocator);
    errdefer entrypoints.deinit();

    const EntrypointSet = std.AutoArrayHashMap(SocketAddr, void);
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

        const gop = entrypoint_set.getOrPutAssumeCapacity(socket_addr);
        if (!gop.found_existing) {
            entrypoints.appendAssumeCapacity(socket_addr);
        }
    }

    // log entrypoints
    logger.infof("entrypoints: {any}", .{entrypoints.items});

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

const LoadedSnapshot = struct {
    allocator: Allocator,
    accounts_db: AccountsDB,
    snapshots: SnapshotFieldsAndPaths,
    snapshot_fields: sig.accounts_db.SnapshotFields,
    /// contains pointers to `accounts_db` and `snapshot_fields`
    bank: Bank,
    genesis_config: GenesisConfig,

    pub fn deinit(self: *@This()) void {
        self.genesis_config.deinit(self.allocator);
        self.snapshot_fields.deinit(self.allocator);
        self.accounts_db.deinit();
        self.snapshots.deinit(self.allocator);
        self.accounts_db.deinit(false); // keep index files on disk
        self.allocator.destroy(self);
    }
};

fn loadSnapshot(
    allocator: Allocator,
    logger: Logger,
    gossip_service: *GossipService,
    validate_genesis: bool,
) !*LoadedSnapshot {
    const output = try allocator.create(LoadedSnapshot);
    var snapshots = try getOrDownloadSnapshots(
        allocator,
        logger,
        gossip_service,
    );

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

    output.accounts_db = try AccountsDB.init(
        allocator,
        logger,
        config.current.accounts_db,
    );

    output.snapshot_fields = try output.accounts_db.loadWithDefaults(
        &snapshots,
        snapshot_dir_str,
        n_threads_snapshot_load,
        true, // validate too
    );

    const bank_fields = &output.snapshot_fields.bank_fields;

    // this should exist before we start to unpack
    logger.infof("reading genesis...", .{});
    output.genesis_config = readGenesisConfig(allocator, snapshot_dir_str) catch |err| {
        if (err == error.GenesisNotFound) {
            logger.errf("genesis.bin not found - expecting {s}/genesis.bin to exist", .{snapshot_dir_str});
        }
        return err;
    };

    logger.infof("validating bank...", .{});
    output.bank = Bank.init(&output.accounts_db, bank_fields);
    Bank.validateBankFields(output.bank.bank_fields, &output.genesis_config) catch |e| switch (e) {
        // TODO: remove when genesis validation works on all clusters
        error.BankAndGenesisMismatch => if (validate_genesis) {
            return e;
        } else {
            logger.err("Bank failed genesis validation.");
        },
        else => return e,
    };

    // validate the status cache
    logger.infof("validating status cache...", .{});
    var status_cache = readStatusCache(allocator, snapshot_dir_str) catch |err| {
        if (err == error.StatusCacheNotFound) {
            logger.errf("status-cache.bin not found - expecting {s}/snapshots/status-cache to exist", .{snapshot_dir_str});
        }
        return err;
    };
    defer status_cache.deinit();

    var slot_history = try output.accounts_db.getSlotHistory();
    defer slot_history.deinit(output.accounts_db.allocator);
    try status_cache.validate(allocator, bank_fields.slot, &slot_history);

    logger.infof("accounts-db setup done...", .{});

    return output;
}

/// load genesis config with default filenames
fn readGenesisConfig(allocator: Allocator, snapshot_dir: []const u8) !GenesisConfig {
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

fn readStatusCache(allocator: Allocator, snapshot_dir: []const u8) !StatusCache {
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
        if (trusted_validators) |trusted| trusted.items else null,
        &gossip_service,
        snapshot_dir_str,
        @intCast(min_mb_per_sec),
    );
}

fn getTrustedValidators(allocator: Allocator) !?std.ArrayList(Pubkey) {
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
    allocator: Allocator,
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
            if (trusted_validators) |trusted| trusted.items else null,
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
