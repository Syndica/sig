const std = @import("std");
const base58 = @import("base58-zig");
const cli = @import("zig-cli");
const dns = @import("zigdig");
const network = @import("zig-network");
const sig = @import("../lib.zig");
const helpers = @import("helpers.zig");

const Atomic = std.atomic.Atomic;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const Random = std.rand.Random;
const Socket = network.Socket;

const ContactInfo = sig.gossip.ContactInfo;
const GossipService = sig.gossip.GossipService;
const IpAddr = sig.net.IpAddr;
const Level = sig.trace.Level;
const Logger = sig.trace.Logger;
const Pubkey = sig.core.Pubkey;
const Registry = sig.prometheus.Registry;
const RepairService = sig.tvu.RepairService;
const RepairPeerProvider = sig.tvu.RepairPeerProvider;
const RepairRequester = sig.tvu.RepairRequester;
const ShredReceiver = sig.tvu.ShredReceiver;
const SocketAddr = sig.net.SocketAddr;

const enumFromName = sig.utils.enumFromName;
const getOrInitIdentity = helpers.getOrInitIdentity;
const globalRegistry = sig.prometheus.globalRegistry;
const getWallclockMs = sig.gossip.getWallclockMs;
const requestIpEcho = sig.net.requestIpEcho;
const servePrometheus = sig.prometheus.servePrometheus;

const socket_tag = sig.gossip.socket_tag;

// TODO fix
const SnapshotFiles = @import("../accountsdb/snapshots.zig").SnapshotFiles;
const parallelUnpackZstdTarBall = @import("../accountsdb/snapshots.zig").parallelUnpackZstdTarBall;
const SnapshotFieldsAndPaths = @import("../accountsdb/snapshots.zig").SnapshotFieldsAndPaths;
const AllSnapshotFields = @import("../accountsdb/snapshots.zig").AllSnapshotFields;
const AccountsDB = @import("../accountsdb/db.zig").AccountsDB;
const ACCOUNT_INDEX_BINS = @import("../accountsdb/db.zig").ACCOUNT_INDEX_BINS;
const AccountsDBConfig = @import("../accountsdb/db.zig").AccountsDBConfig;
const GenesisConfig = @import("../accountsdb/genesis_config.zig").GenesisConfig;
const StatusCache = @import("../accountsdb/snapshots.zig").StatusCache;
const SnapshotFields = @import("../accountsdb/snapshots.zig").SnapshotFields;
const Bank = @import("../accountsdb/bank.zig").Bank;
const downloadSnapshotsFromGossip = @import("../accountsdb/download.zig").downloadSnapshotsFromGossip;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const gpa_allocator = gpa.allocator();
const base58Encoder = base58.Encoder.init(.{});

const gossip_host = struct {
    // TODO: support domain names and ipv6 addresses
    var option = cli.Option{
        .long_name = "gossip-host",
        .help = "IPv4 address for the validator to advertise in gossip - default: get from --entrypoint, fallback to 127.0.0.1",
        .value = cli.OptionValue{ .string = null },
        .required = false,
        .value_name = "Gossip Host",
    };

    fn get() !?IpAddr {
        if (option.value.string) |str| {
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
    .value = cli.OptionValue{ .int = 8001 },
    .required = false,
    .value_name = "Gossip Port",
};

var repair_port_option = cli.Option{
    .long_name = "repair-port",
    .help = "The port to run tvu repair listener - default: 8002",
    .value = cli.OptionValue{ .int = 8002 },
    .required = false,
    .value_name = "Repair Port",
};

var test_repair_option = cli.Option{
    .long_name = "test-repair-for-slot",
    .help = "Set a slot here to repeatedly send repair requests for shreds from this slot. This is only intended for use during short-lived tests of the repair service. Do not set this during normal usage.",
    .value = cli.OptionValue{ .int = null },
    .required = false,
    .value_name = "slot number",
};

var gossip_entrypoints_option = cli.Option{
    .long_name = "entrypoint",
    .help = "gossip address of the entrypoint validators",
    .short_alias = 'e',
    .value = cli.OptionValue{ .string_list = null },
    .required = false,
    .value_name = "Entrypoints",
};

var trusted_validators_option = cli.Option{
    .long_name = "trusted_validator",
    .help = "public key of a validator whose snapshot hash is trusted to be downloaded",
    .short_alias = 't',
    .value = cli.OptionValue{ .string_list = null },
    .required = false,
    .value_name = "Trusted Validator",
};

var gossip_spy_node_option = cli.Option{
    .long_name = "spy-node",
    .help = "run as a gossip spy node (minimize outgoing packets)",
    .value = cli.OptionValue{ .bool = false },
    .required = false,
    .value_name = "Spy Node",
};

var gossip_dump_option = cli.Option{
    .long_name = "dump-gossip",
    .help = "periodically dump gossip table to csv files and logs",
    .value = cli.OptionValue{ .bool = false },
    .required = false,
    .value_name = "Gossip Table Dump",
};

var log_level_option = cli.Option{
    .long_name = "log-level",
    .help = "The amount of detail to log (default = debug)",
    .short_alias = 'l',
    .value = cli.OptionValue{ .string = "debug" },
    .required = false,
    .value_name = "err|warn|info|debug",
};

var metrics_port_option = cli.Option{
    .long_name = "metrics-port",
    .help = "port to expose prometheus metrics via http - default: 12345",
    .short_alias = 'm',
    .value = cli.OptionValue{ .int = 12345 },
    .required = false,
    .value_name = "port_number",
};

// accounts-db options
var n_threads_snapshot_load_option = cli.Option{
    .long_name = "n-threads-snapshot-load",
    .help = "number of threads to load incremental snapshots: - default: ncpus",
    .short_alias = 't',
    .value = cli.OptionValue{ .int = 0 },
    .required = false,
    .value_name = "n_threads_snapshot_load",
};

var n_threads_snapshot_unpack_option = cli.Option{
    .long_name = "n-threads-snapshot-unpack",
    .help = "number of threads to unpack incremental snapshots - default: ncpus * 2",
    .short_alias = 'u',
    .value = cli.OptionValue{ .int = 0 },
    .required = false,
    .value_name = "n_threads_snapshot_unpack",
};

var disk_index_path_option = cli.Option{
    .long_name = "disk-index-path",
    .help = "path to disk index - default: no disk index, index will use ram",
    .short_alias = 'd',
    .value = cli.OptionValue{ .string = null },
    .required = false,
    .value_name = "disk_index_path",
};

var force_unpack_snapshot_option = cli.Option{
    .long_name = "force-unpack-snapshot",
    .help = "force unpack snapshot even if it exists",
    .short_alias = 'f',
    .value = cli.OptionValue{ .bool = false },
    .required = false,
    .value_name = "force_unpack_snapshot",
};

var force_new_snapshot_download_option = cli.Option{
    .long_name = "force-new-snapshot-download",
    .help = "force download of new snapshot (usually to get a more up-to-date snapshot)",
    .value = cli.OptionValue{ .bool = false },
    .required = false,
    .value_name = "force_new_snapshot_download",
};

var snapshot_dir_option = cli.Option{
    .long_name = "snapshot-dir",
    .help = "path to snapshot directory (where snapshots are downloaded and/or unpacked to/from) - default: test_data/",
    .short_alias = 's',
    .value = cli.OptionValue{ .string = "test_data/" },
    .required = false,
    .value_name = "snapshot_dir",
};

var min_snapshot_download_speed_mb_option = cli.Option{
    .long_name = "min-snapshot-download-speed",
    .help = "minimum download speed of full snapshots in megabytes per second - default: 20MB/s",
    .value = cli.OptionValue{ .int = 20 },
    .required = false,
    .value_name = "min_snapshot_download_speed_mb",
};

var storage_cache_size_option = cli.Option{
    .long_name = "storage-cache-size",
    .help = "number of accounts preallocate for the storage cache for accounts-db (used when writing accounts whose slot has not been rooted) - default: 10k",
    .value = cli.OptionValue{ .int = 10_000 },
    .required = false,
    .value_name = "storage_cache_size",
};

var number_of_index_bins_option = cli.Option{
    .long_name = "number-of-index-bins",
    .help = "number of bins to shard the index pubkeys across",
    .value = cli.OptionValue{ .int = ACCOUNT_INDEX_BINS },
    .required = false,
    .value_name = "number_of_index_bins",
};

var app = &cli.App{
    .name = "sig",
    .description = "Sig is a Solana client implementation written in Zig.\nThis is still a WIP, PRs welcome.",
    .version = "0.1.1",
    .author = "Syndica & Contributors",
    .options = &.{ &log_level_option, &metrics_port_option },
    .subcommands = &.{
        &cli.Command{
            .name = "identity",
            .help = "Get own identity",
            .description =
            \\Gets own identity (Pubkey) or creates one if doesn't exist.
            \\
            \\NOTE: Keypair is saved in $HOME/.sig/identity.key.
            ,
            .action = identity,
        },
        &cli.Command{
            .name = "gossip",
            .help = "Run gossip client",
            .description =
            \\Start Solana gossip client on specified port.
            ,
            .action = gossip,
            .options = &.{
                &gossip_host.option,
                &gossip_port_option,
                &gossip_entrypoints_option,
                &gossip_spy_node_option,
                &gossip_dump_option,
            },
        },
        &cli.Command{
            .name = "validator",
            .help = "Run validator",
            .description =
            \\Start a full Solana validator client.
            ,
            .action = validator,
            .options = &.{
                // gossip
                &gossip_host.option,
                &gossip_port_option,
                &gossip_entrypoints_option,
                &gossip_spy_node_option,
                &gossip_dump_option,
                // repair
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
            },
        },
        &cli.Command{
            .name = "download_snapshot",
            .help = "downloads a snapshot",
            .description =
            \\starts a gossip client and downloads a snapshot from peers
            ,
            .action = downloadSnapshot,
            .options = &.{
                // where to download the snapshot
                &snapshot_dir_option,
                // gossip options
                &gossip_host.option,
                &gossip_port_option,
                &gossip_entrypoints_option,
                &trusted_validators_option,
                &min_snapshot_download_speed_mb_option,
            },
        },
    },
};

/// entrypoint to print (and create if DNE) pubkey in ~/.sig/identity.key
fn identity(_: []const []const u8) !void {
    var logger = Logger.init(gpa_allocator, try enumFromName(Level, log_level_option.value.string.?));
    defer logger.deinit();
    logger.spawn();

    const keypair = try getOrInitIdentity(gpa_allocator, logger);
    var pubkey: [50]u8 = undefined;
    var size = try base58Encoder.encode(&keypair.public_key.toBytes(), &pubkey);
    try std.io.getStdErr().writer().print("Identity: {s}\n", .{pubkey[0..size]});
}

/// entrypoint to run only gossip
fn gossip(_: []const []const u8) !void {
    var logger = try spawnLogger();
    defer logger.deinit();
    const metrics_thread = try spawnMetrics(logger);
    defer metrics_thread.detach();

    var exit = std.atomic.Atomic(bool).init(false);
    const my_keypair = try getOrInitIdentity(gpa_allocator, logger);
    const entrypoints = try getEntrypoints(logger);
    defer entrypoints.deinit();
    const my_data = try getMyDataFromIpEcho(logger, entrypoints.items);

    var gossip_service = try initGossip(
        logger,
        my_keypair,
        &exit,
        entrypoints,
        my_data.shred_version,
        my_data.ip,
        &.{},
    );
    defer gossip_service.deinit();

    var handle = try spawnGossip(&gossip_service);
    handle.join();
}

/// entrypoint to run a full solana validator
fn validator(_: []const []const u8) !void {
    var logger = try spawnLogger();
    defer logger.deinit();
    const metrics_thread = try spawnMetrics(logger);
    defer metrics_thread.detach();

    var rand = std.rand.DefaultPrng.init(@bitCast(std.time.timestamp()));
    var exit = std.atomic.Atomic(bool).init(false);
    const my_keypair = try getOrInitIdentity(gpa_allocator, logger);
    const entrypoints = try getEntrypoints(logger);
    defer entrypoints.deinit();
    const ip_echo_data = try getMyDataFromIpEcho(logger, entrypoints.items);

    const repair_port: u16 = @intCast(repair_port_option.value.int.?);

    // gossip
    var gossip_service = try initGossip(
        logger,
        my_keypair,
        &exit,
        entrypoints,
        ip_echo_data.shred_version, // TODO atomic owned at top level? or owned by gossip is good?
        ip_echo_data.ip,
        &.{.{ .tag = socket_tag.REPAIR, .port = repair_port }},
    );
    defer gossip_service.deinit();
    var gossip_handle = try spawnGossip(&gossip_service);

    // repair
    var repair_socket = try Socket.create(network.AddressFamily.ipv4, network.Protocol.udp);
    try repair_socket.bindToPort(repair_port);
    try repair_socket.setReadTimeout(sig.net.SOCKET_TIMEOUT);

    var repair_svc = try initRepair(
        logger,
        &my_keypair,
        &exit,
        rand.random(),
        &gossip_service,
        &repair_socket,
    );
    defer repair_svc.deinit();
    var repair_handle = try std.Thread.spawn(.{}, RepairService.run, .{&repair_svc});

    var shred_receiver = ShredReceiver{
        .allocator = gpa_allocator,
        .keypair = &my_keypair,
        .exit = &exit,
        .logger = logger,
        .socket = &repair_socket,
    };
    var shred_receive_handle = try std.Thread.spawn(.{}, ShredReceiver.run, .{&shred_receiver});

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

    var accounts_db = try AccountsDB.init(
        gpa_allocator,
        logger,
        AccountsDBConfig{
            .disk_index_path = disk_index_path_option.value.string,
            .storage_cache_size = @intCast(storage_cache_size_option.value.int.?),
            .number_of_index_bins = @intCast(number_of_index_bins_option.value.int.?),
        },
    );
    defer accounts_db.deinit();

    const snapshot = try snapshots.all_fields.collapse();

    // cli parsing
    const snapshot_dir_str = snapshot_dir_option.value.string.?;
    const accounts_path = try std.fmt.allocPrint(gpa_allocator, "{s}/accounts/", .{snapshot_dir_str});

    const n_cpus = @as(u32, @truncate(try std.Thread.getCpuCount()));
    var n_threads_snapshot_load: u32 = @intCast(n_threads_snapshot_load_option.value.int.?);
    if (n_threads_snapshot_load == 0) {
        n_threads_snapshot_load = n_cpus;
    }

    var timer = try std.time.Timer.start();
    logger.infof("loading from snapshot...", .{});
    try accounts_db.loadFromSnapshot(
        snapshot.accounts_db_fields,
        accounts_path,
        n_threads_snapshot_load,
        std.heap.page_allocator,
    );
    logger.infof("loaded from snapshot in {s}", .{std.fmt.fmtDuration(timer.read())});

    const full_snapshot = snapshots.all_fields.full;
    try accounts_db.validateLoadFromSnapshot(
        snapshot.bank_fields.incremental_snapshot_persistence,
        full_snapshot.bank_fields.slot,
        full_snapshot.bank_fields.capitalization,
    );
    logger.infof("validated from snapshot in {s}", .{std.fmt.fmtDuration(timer.read())});

    // this should exist before we start to unpack
    const genesis_path = try std.fmt.allocPrint(
        gpa_allocator,
        "{s}/genesis.bin",
        .{snapshot_dir_str},
    );
    defer gpa_allocator.free(genesis_path);

    std.fs.cwd().access(genesis_path, .{}) catch {
        logger.errf("genesis.bin not found: {s}", .{genesis_path});
        return error.GenesisNotFound;
    };

    // use the genesis to validate the bank
    const genesis_config = try GenesisConfig.init(gpa_allocator, genesis_path);
    defer genesis_config.deinit(gpa_allocator);

    logger.infof("validating bank...", .{});
    const bank = Bank.init(&accounts_db, &snapshot.bank_fields);
    try Bank.validateBankFields(bank.bank_fields, &genesis_config);

    // validate the status cache
    logger.infof("validating status cache...", .{});
    const status_cache_path = try std.fmt.allocPrint(
        gpa_allocator,
        "{s}/{s}",
        .{ snapshot_dir_str, "snapshots/status_cache" },
    );
    defer gpa_allocator.free(status_cache_path);

    var status_cache = try StatusCache.init(gpa_allocator, status_cache_path);
    defer status_cache.deinit();

    var slot_history = try accounts_db.getSlotHistory();
    defer slot_history.deinit(accounts_db.allocator);

    const bank_slot = snapshot.bank_fields.slot;
    try status_cache.validate(gpa_allocator, bank_slot, &slot_history);

    logger.infof("accounts-db setup done...", .{});

    gossip_handle.join();
    repair_handle.join();
    shred_receive_handle.join();
}

/// Initialize an instance of GossipService and configure with CLI arguments
fn initGossip(
    logger: Logger,
    my_keypair: KeyPair,
    exit: *Atomic(bool),
    entrypoints: std.ArrayList(SocketAddr),
    shred_version: u16,
    gossip_host_ip: IpAddr,
    sockets: []const struct { tag: u8, port: u16 },
) !GossipService {
    var gossip_port: u16 = @intCast(gossip_port_option.value.int.?);
    logger.infof("gossip host: {any}", .{gossip_host_ip});
    logger.infof("gossip port: {d}", .{gossip_port});

    // setup contact info
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    var contact_info = ContactInfo.init(gpa_allocator, my_pubkey, getWallclockMs(), 0);
    try contact_info.setSocket(socket_tag.GOSSIP, SocketAddr.init(gossip_host_ip, gossip_port));
    for (sockets) |s| try contact_info.setSocket(s.tag, SocketAddr.init(gossip_host_ip, s.port));
    contact_info.shred_version = shred_version;

    return try GossipService.init(
        gpa_allocator,
        contact_info,
        my_keypair,
        entrypoints,
        exit,
        logger,
    );
}

fn initRepair(
    logger: Logger,
    my_keypair: *const KeyPair,
    exit: *Atomic(bool),
    random: Random,
    gossip_service: *GossipService,
    socket: *Socket,
) !RepairService {
    var peer_provider = try RepairPeerProvider.init(
        gpa_allocator,
        random,
        &gossip_service.gossip_table_rw,
        Pubkey.fromPublicKey(&my_keypair.public_key),
        &gossip_service.my_shred_version,
    );
    return RepairService{
        .allocator = gpa_allocator,
        .requester = RepairRequester{
            .allocator = gpa_allocator,
            .rng = random,
            .udp_send_socket = socket,
            .keypair = my_keypair,
            .logger = logger,
        },
        .peer_provider = peer_provider,
        .logger = logger,
        .exit = exit,
        .slot_to_request = if (test_repair_option.value.int) |n| @intCast(n) else null,
    };
}

/// Spawn a thread to run gossip and configure with CLI arguments
fn spawnGossip(gossip_service: *GossipService) std.Thread.SpawnError!std.Thread {
    const spy_node = gossip_spy_node_option.value.bool;
    return try std.Thread.spawn(
        .{},
        GossipService.run,
        .{ gossip_service, spy_node, gossip_dump_option.value.bool },
    );
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
    if (gossip_entrypoints_option.value.string_list) |entrypoints_strs| {
        for (entrypoints_strs) |entrypoint| {
            var socket_addr = SocketAddr.parse(entrypoint) catch brk: {
                // if we couldn't parse as IpV4, we attempt to resolve DNS and get IP
                var domain_and_port = std.mem.splitScalar(u8, entrypoint, ':');
                const domain_str = domain_and_port.next() orelse {
                    logger.field("entrypoint", entrypoint).err("entrypoint domain missing");
                    return error.EntrypointDomainMissing;
                };
                const port_str = domain_and_port.next() orelse {
                    logger.field("entrypoint", entrypoint).err("entrypoint port missing");
                    return error.EntrypointPortMissing;
                };

                // get dns address lists
                var addr_list = try dns.helpers.getAddressList(domain_str, gpa_allocator);
                defer addr_list.deinit();
                if (addr_list.addrs.len == 0) {
                    logger.field("entrypoint", entrypoint).err("entrypoint resolve dns failed (no records found)");
                    return error.EntrypointDnsResolutionFailure;
                }

                // use first A record address
                var ipv4_addr = addr_list.addrs[0];

                // parse port from string
                var port = std.fmt.parseInt(u16, port_str, 10) catch {
                    logger.field("entrypoint", entrypoint).err("entrypoint port not valid");
                    return error.EntrypointPortNotValid;
                };

                var socket_addr = SocketAddr.fromIpV4Address(ipv4_addr);
                socket_addr.setPort(port);
                break :brk socket_addr;
            };

            try entrypoints.append(socket_addr);
        }
    }

    // log entrypoints
    var entrypoint_string = try gpa_allocator.alloc(u8, 53 * entrypoints.items.len);
    defer gpa_allocator.free(entrypoint_string);
    var stream = std.io.fixedBufferStream(entrypoint_string);
    var writer = stream.writer();
    for (0.., entrypoints.items) |i, entrypoint| {
        try entrypoint.toAddress().format("", .{}, writer);
        if (i != entrypoints.items.len - 1) try writer.writeAll(", ");
    }
    logger.infof("entrypoints: {s}", .{entrypoint_string[0..stream.pos]});

    return entrypoints;
}

/// Initializes the global registry. Returns error if registry was already initialized.
/// Spawns a thread to serve the metrics over http on the CLI configured port.
fn spawnMetrics(logger: Logger) !std.Thread {
    var metrics_port: u16 = @intCast(metrics_port_option.value.int.?);
    logger.infof("metrics port: {d}", .{metrics_port});
    const registry = globalRegistry();
    return try std.Thread.spawn(.{}, servePrometheus, .{ gpa_allocator, registry, metrics_port });
}

fn spawnLogger() !Logger {
    var logger = Logger.init(gpa_allocator, try enumFromName(Level, log_level_option.value.string.?));
    logger.spawn();
    return logger;
}

/// entrypoint to download snapshot
fn downloadSnapshot(_: []const []const u8) !void {
    var logger = try spawnLogger();
    defer logger.deinit();

    var exit = std.atomic.Atomic(bool).init(false);
    const my_keypair = try getOrInitIdentity(gpa_allocator, logger);
    const entrypoints = try getEntrypoints(logger);
    defer entrypoints.deinit();

    const my_data = try getMyDataFromIpEcho(logger, entrypoints.items);

    var gossip_service = try initGossip(
        .noop,
        my_keypair,
        &exit,
        entrypoints,
        my_data.shred_version,
        my_data.ip,
        &.{},
    );
    defer gossip_service.deinit();
    var handle = try spawnGossip(&gossip_service);

    const trusted_validators = try getTrustedValidators(gpa_allocator);
    defer if (trusted_validators) |*tvs| tvs.deinit();

    const snapshot_dir_str = snapshot_dir_option.value.string.?;
    const min_mb_per_sec = min_snapshot_download_speed_mb_option.value.int.?;
    try downloadSnapshotsFromGossip(
        gpa_allocator,
        logger,
        trusted_validators,
        &gossip_service,
        snapshot_dir_str,
        @intCast(min_mb_per_sec),
    );

    handle.join();
}

fn getTrustedValidators(
    allocator: std.mem.Allocator,
) !?std.ArrayList(Pubkey) {
    var trusted_validators: ?std.ArrayList(Pubkey) = null;
    if (trusted_validators_option.value.string_list) |trusted_validator_strs| {
        trusted_validators = try std.ArrayList(Pubkey).initCapacity(
            allocator,
            trusted_validator_strs.len,
        );
        for (trusted_validator_strs) |trusted_validator_str| {
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
    const snapshot_dir_str = snapshot_dir_option.value.string.?;
    const force_unpack_snapshot = force_unpack_snapshot_option.value.bool;
    const force_new_snapshot_download = force_new_snapshot_download_option.value.bool;

    const n_cpus = @as(u32, @truncate(try std.Thread.getCpuCount()));
    var n_threads_snapshot_unpack: u32 = @intCast(n_threads_snapshot_unpack_option.value.int.?);
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

    var maybe_snapshot_files: ?SnapshotFiles = SnapshotFiles.find(allocator, snapshot_dir_str) catch |err| blk: {
        // if we cant find the full snapshot, we try to download it
        if (err == error.NoFullSnapshotFileInfoFound) {
            break :blk null;
        } else {
            return err;
        }
    };

    const should_download_new_snapshot = force_new_snapshot_download or maybe_snapshot_files == null;
    if (should_download_new_snapshot) { 
        const trusted_validators = try getTrustedValidators(gpa_allocator);
        defer if (trusted_validators) |*tvs| tvs.deinit();

        const min_mb_per_sec = min_snapshot_download_speed_mb_option.value.int.?;
        try downloadSnapshotsFromGossip(
            allocator,
            logger,
            trusted_validators,
            gossip_service orelse return error.SnapshotsNotFoundAndNoGossipService,
            snapshot_dir_str,
            @intCast(min_mb_per_sec),
        );
        maybe_snapshot_files = try SnapshotFiles.find(allocator, snapshot_dir_str);
    }

    // SAFE: this unwrap is safe because we either found the snapshot or downloaded it
    var snapshot_files = maybe_snapshot_files.?;
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
        var snapshot_dir = try std.fs.cwd().openDir(snapshot_dir_str, .{});
        defer snapshot_dir.close();

        // TODO: delete old accounts/ dir if it exists
        timer.reset();
        logger.infof("unpacking {s}...", .{snapshot_files.full_snapshot.filename});
        try parallelUnpackZstdTarBall(
            allocator,
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
    var snapshots = try AllSnapshotFields.fromFiles(allocator, snapshot_dir_str, snapshot_files);
    logger.infof("read snapshot metdata in {s}", .{std.fmt.fmtDuration(timer.read())});

    return snapshots;
}

pub fn run() !void {
    return cli.run(app, gpa_allocator);
}
