const std = @import("std");
const base58 = @import("base58-zig");
const cli = @import("zig-cli");
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
const RepairService = sig.tvu.repair.RepairService;
const RepairPeerProvider = sig.tvu.repair.RepairPeerProvider;
const RepairRequester = sig.tvu.repair.RepairRequester;
const ShredReceiver = sig.tvu.ShredReceiver;
const SocketAddr = sig.net.SocketAddr;

const enumFromName = sig.utils.enumFromName;
const getOrInitIdentity = helpers.getOrInitIdentity;
const globalRegistry = sig.prometheus.globalRegistry;
const getWallclockMs = sig.gossip.getWallclockMs;
const requestIpEcho = sig.net.requestIpEcho;
const servePrometheus = sig.prometheus.servePrometheus;

const socket_tag = sig.gossip.socket_tag;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const gpa_allocator = gpa.allocator();
const base58Encoder = base58.Encoder.init(.{});

const gossip_host = struct {
    // TODO: support domain names and ipv6 addresses
    var option = cli.Option{
        .long_name = "gossip-host",
        .help = "IPv4 address for the validator to advertise in gossip - default: 127.0.0.1",
        .value = cli.OptionValue{ .string = "127.0.0.1" },
        .required = false,
        .value_name = "Gossip Host",
    };

    fn get() ![4]u8 {
        const str = option.value.string.?;
        var buf: [15]u8 = undefined;
        @memcpy(buf[0..str.len], str);
        @memcpy(buf[str.len .. str.len + 2], ":0");
        const sa = try SocketAddr.parseIpv4(buf[0 .. str.len + 2]);
        return sa.V4.ip.octets;
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
    .short_alias = 'p',
    .value = cli.OptionValue{ .int = 8002 },
    .required = false,
    .value_name = "Repair Port",
};

var gossip_entrypoints_option = cli.Option{
    .long_name = "entrypoint",
    .help = "gossip address of the entrypoint validators",
    .short_alias = 'e',
    .value = cli.OptionValue{ .string_list = null },
    .required = false,
    .value_name = "Entrypoints",
};

var gossip_spy_node_option = cli.Option{
    .long_name = "spy-node",
    .help = "run as a gossip spy node (minimize outgoing packets)",
    .value = cli.OptionValue{ .bool = false },
    .required = false,
    .value_name = "Spy Node",
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
    .help = "port to expose prometheus metrics via http",
    .short_alias = 'm',
    .value = cli.OptionValue{ .int = 12345 },
    .required = false,
    .value_name = "port_number",
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
        &cli.Command{ .name = "gossip", .help = "Run gossip client", .description = 
        \\Start Solana gossip client on specified port.
        , .action = gossip, .options = &.{
            &gossip_host.option,
            &gossip_port_option,
            &gossip_entrypoints_option,
            &gossip_spy_node_option,
        } },
        &cli.Command{ .name = "validator", .help = "Run validator", .description = 
        \\Start a full Solana validator client.
        , .action = validator, .options = &.{
            &gossip_host.option,
            &gossip_port_option,
            &gossip_entrypoints_option,
            &gossip_spy_node_option,
            &repair_port_option,
        } },
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
    const shred_version = getShredVersionFromIpEcho(logger, entrypoints.items);

    var gossip_service = try initGossip(logger, my_keypair, &exit, entrypoints, shred_version, &.{});
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
    const shred_version = getShredVersionFromIpEcho(logger, entrypoints.items); // TODO atomic owned here? or owned by gossip is good?

    const repair_port: u16 = @intCast(repair_port_option.value.int.?);

    var gossip_service = try initGossip(
        logger,
        my_keypair,
        &exit,
        entrypoints,
        shred_version,
        &.{.{ .tag = socket_tag.REPAIR, .port = repair_port }},
    );
    defer gossip_service.deinit();
    var gossip_handle = try spawnGossip(&gossip_service);

    var repair_socket = try Socket.create(network.AddressFamily.ipv4, network.Protocol.udp);
    try repair_socket.bindToPort(repair_port);
    try repair_socket.setReadTimeout(sig.net.SOCKET_TIMEOUT);

    var repair_svc = try initRepair(logger, &my_keypair, &exit, rand.random(), &gossip_service, &repair_socket);
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
    sockets: []const struct { tag: u8, port: u16 },
) !GossipService {
    const gossip_host_ip = try gossip_host.get();
    var gossip_port: u16 = @intCast(gossip_port_option.value.int.?);
    logger.infof("gossip host: {any}", .{gossip_host_ip});
    logger.infof("gossip port: {d}", .{gossip_port});

    // setup contact info
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, false);
    var contact_info = ContactInfo.init(gpa_allocator, my_pubkey, getWallclockMs(), 0);
    try contact_info.setSocket(socket_tag.GOSSIP, SocketAddr.initIpv4(gossip_host_ip, gossip_port));
    for (sockets) |socket| {
        try contact_info.setSocket(socket.tag, SocketAddr.initIpv4(gossip_host_ip, socket.port));
    }
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
        Pubkey.fromPublicKey(&my_keypair.public_key, true),
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
    };
}

/// Spawn a thread to run gossip and configure with CLI arguments
fn spawnGossip(gossip_service: *GossipService) std.Thread.SpawnError!std.Thread {
    const spy_node = gossip_spy_node_option.value.bool;
    return try std.Thread.spawn(
        .{},
        GossipService.run,
        .{ gossip_service, spy_node },
    );
}

/// determine our shred version. in the solana-labs client, this approach is only
/// used for validation. normally, shred version comes from the snapshot.
fn getShredVersionFromIpEcho(logger: Logger, entrypoints: []SocketAddr) u16 {
    for (entrypoints) |entrypoint| {
        if (requestIpEcho(gpa_allocator, entrypoint.toAddress(), .{})) |response| {
            if (response.shred_version) |shred_version| {
                var addr_str = entrypoint.toString();
                logger.infof(
                    "shred version: {} - from entrypoint ip echo: {s}",
                    .{ shred_version.value, addr_str[0][0..addr_str[1]] },
                );
                return shred_version.value;
            }
        } else |_| {}
    } else {
        logger.warn("could not get a shred version from an entrypoint");
        return 0;
    }
}

fn getEntrypoints(logger: Logger) !std.ArrayList(SocketAddr) {
    var entrypoints = std.ArrayList(SocketAddr).init(gpa_allocator);
    if (gossip_entrypoints_option.value.string_list) |entrypoints_strs| {
        for (entrypoints_strs) |entrypoint| {
            var value = SocketAddr.parse(entrypoint) catch {
                std.debug.print("Invalid entrypoint: {s}\n", .{entrypoint});
                return error.InvalidEntrypoint;
            };
            try entrypoints.append(value);
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

pub fn run() !void {
    return cli.run(app, gpa_allocator);
}
