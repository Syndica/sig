const std = @import("std");
const cli = @import("zig-cli");
const base58 = @import("base58-zig");
const enumFromName = @import("../utils/types.zig").enumFromName;
const getOrInitIdentity = @import("./helpers.zig").getOrInitIdentity;
const LegacyContactInfo = @import("../gossip/crds.zig").LegacyContactInfo;
const Logger = @import("../trace/log.zig").Logger;
const Level = @import("../trace/level.zig").Level;
const io = std.io;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const SocketAddr = @import("../net/net.zig").SocketAddr;
const GossipService = @import("../gossip/gossip_service.zig").GossipService;
const servePrometheus = @import("../prometheus/http.zig").servePrometheus;
const global_registry = @import("../prometheus/registry.zig").global_registry;
const Registry = @import("../prometheus/registry.zig").Registry;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const gpa_allocator = gpa.allocator();
const base58Encoder = base58.Encoder.init(.{});

var gossip_port_option = cli.Option{
    .long_name = "gossip-port",
    .help = "The port to run gossip listener - default: 8001",
    .short_alias = 'p',
    .value = cli.OptionValue{ .int = 8001 },
    .required = false,
    .value_name = "Gossip Port",
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
            &gossip_port_option,
            &gossip_entrypoints_option,
            &gossip_spy_node_option,
        } },
    },
};

// prints (and creates if DNE) pubkey in ~/.sig/identity.key
fn identity(_: []const []const u8) !void {
    var logger = Logger.init(gpa_allocator, try enumFromName(Level, log_level_option.value.string.?));
    defer logger.deinit();
    logger.spawn();

    const keypair = try getOrInitIdentity(gpa_allocator, logger);
    var pubkey: [50]u8 = undefined;
    var size = try base58Encoder.encode(&keypair.public_key.toBytes(), &pubkey);
    try std.io.getStdErr().writer().print("Identity: {s}\n", .{pubkey[0..size]});
}

// gossip entrypoint
fn gossip(_: []const []const u8) !void {
    var logger = Logger.init(gpa_allocator, try enumFromName(Level, log_level_option.value.string.?));
    defer logger.deinit();
    logger.spawn();

    // var logger: Logger = .noop;

    const metrics_thread = try spawnMetrics(gpa_allocator, logger);

    var my_keypair = try getOrInitIdentity(gpa_allocator, logger);

    var gossip_port: u16 = @intCast(gossip_port_option.value.int.?);
    var gossip_address = SocketAddr.initIpv4(.{ 0, 0, 0, 0 }, gossip_port);
    logger.infof("gossip port: {d}\n", .{gossip_port});

    // setup contact info
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, false);
    var contact_info = LegacyContactInfo.default(my_pubkey);
    contact_info.shred_version = 0;
    contact_info.gossip = gossip_address;

    var entrypoints = std.ArrayList(SocketAddr).init(gpa_allocator);
    defer entrypoints.deinit();
    if (gossip_entrypoints_option.value.string_list) |entrypoints_strs| {
        for (entrypoints_strs) |entrypoint| {
            var value = SocketAddr.parse(entrypoint) catch {
                std.debug.print("Invalid entrypoint: {s}\n", .{entrypoint});
                return;
            };
            try entrypoints.append(value);
        }
    }
    std.debug.print("entrypoints: {any}\n", .{entrypoints.items});

    var exit = std.atomic.Atomic(bool).init(false);
    var gossip_service = try GossipService.init(
        gpa_allocator,
        contact_info,
        my_keypair,
        entrypoints,
        &exit,
        logger,
    );
    defer gossip_service.deinit();

    const spy_node = gossip_spy_node_option.value.bool;
    var handle = try std.Thread.spawn(
        .{},
        GossipService.run,
        .{ &gossip_service, spy_node },
    );

    handle.join();
    metrics_thread.detach();
}

/// Initializes the global registry. Returns error if registry was already initialized.
/// Spawns a thread to serve the metrics over http on the CLI configured port.
/// Uses same allocator for both registry and http adapter.
fn spawnMetrics(allocator: std.mem.Allocator, logger: Logger) !std.Thread {
    var metrics_port: u16 = @intCast(metrics_port_option.value.int.?);
    logger.infof("metrics port: {d}\n", .{metrics_port});
    const registry = try global_registry.initialize(Registry(.{}).init, .{allocator});
    return try std.Thread.spawn(.{}, servePrometheus, .{ allocator, registry, metrics_port });
}

pub fn run() !void {
    return cli.run(app, gpa_allocator);
}
