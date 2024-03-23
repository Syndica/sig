const std = @import("std");
const cli = @import("zig-cli");
const base58 = @import("base58-zig");
const dns = @import("zigdig");
const enumFromName = @import("../utils/types.zig").enumFromName;
const getOrInitIdentity = @import("./helpers.zig").getOrInitIdentity;
const ContactInfo = @import("../gossip/data.zig").ContactInfo;
const SOCKET_TAG_GOSSIP = @import("../gossip/data.zig").SOCKET_TAG_GOSSIP;
const Logger = @import("../trace/log.zig").Logger;
const Level = @import("../trace/level.zig").Level;
const io = std.io;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const SocketAddr = @import("../net/net.zig").SocketAddr;
const echo = @import("../net/echo.zig");
const GossipService = @import("../gossip/service.zig").GossipService;
const servePrometheus = @import("../prometheus/http.zig").servePrometheus;
const globalRegistry = @import("../prometheus/registry.zig").globalRegistry;
const Registry = @import("../prometheus/registry.zig").Registry;
const getWallclockMs = @import("../gossip/data.zig").getWallclockMs;
const IpAddr = @import("../lib.zig").net.IpAddr;

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
    logger.infof("gossip port: {d}", .{gossip_port});

    var entrypoints = std.ArrayList(SocketAddr).init(gpa_allocator);
    defer entrypoints.deinit();
    if (gossip_entrypoints_option.value.string_list) |entrypoints_strs| {
        for (entrypoints_strs) |entrypoint| {
            var socket_addr = brk: {
                var value = SocketAddr.parse(entrypoint) catch {
                    // if we couldn't parse as IpV4, we attempt to resolve DNS and get IP
                    var domain_and_port = std.mem.splitScalar(u8, entrypoint, ':');
                    const domain_str = domain_and_port.next() orelse return error.EntrypointDomainMissing;
                    const port_str = domain_and_port.next() orelse return error.EntrypointPortMissing;

                    // get dns address lists
                    var addr_list = try dns.helpers.getAddressList(domain_str, gpa_allocator);
                    defer addr_list.deinit();
                    if (addr_list.addrs.len == 0) {
                        return error.EntrypointDnsResolutionFailure;
                    }

                    // use first A record address
                    var ipv4_addr: u32 = addr_list.addrs[0].in.sa.addr;

                    // parse port from string
                    var port = std.fmt.parseInt(u16, port_str, 10) catch return error.EntrypointPortNotValid;

                    break :brk SocketAddr.initIpv4(.{
                        @as(u8, @intCast(ipv4_addr & 0xFF)),
                        @as(u8, @intCast(ipv4_addr >> 8 & 0xFF)),
                        @as(u8, @intCast(ipv4_addr >> 16 & 0xFF)),
                        @as(u8, @intCast(ipv4_addr >> 24 & 0xFF)),
                    }, port);
                };
                break :brk value;
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

    // determine our shred version and ip. in the solana-labs client, the shred version
    // comes from the snapshot, and ip echo is only used to validate it.
    var my_ip_from_entrypoint: ?IpAddr = null;
    const my_shred_version = loop: for (entrypoints.items) |entrypoint| {
        if (echo.requestIpEcho(gpa_allocator, entrypoint.toAddress(), .{})) |response| {
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

    // setup contact info
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, false);
    var contact_info = ContactInfo.init(gpa_allocator, my_pubkey, getWallclockMs(), 0);
    contact_info.shred_version = my_shred_version;
    var gossip_address = SocketAddr.init(my_ip, gossip_port);
    try contact_info.setSocket(SOCKET_TAG_GOSSIP, gossip_address);

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
    logger.infof("metrics port: {d}", .{metrics_port});
    const registry = globalRegistry();
    return try std.Thread.spawn(.{}, servePrometheus, .{ allocator, registry, metrics_port });
}

pub fn run() !void {
    return cli.run(app, gpa_allocator);
}
