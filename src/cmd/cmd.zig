const std = @import("std");
const cli = @import("zig-cli");
const base58 = @import("base58-zig");
const getOrInitIdentity = @import("./helpers.zig").getOrInitIdentity;
const LegacyContactInfo = @import("../gossip/crds.zig").LegacyContactInfo;
const Logger = @import("../trace/log.zig").Logger;
const io = std.io;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const SocketAddr = @import("../net/net.zig").SocketAddr;
const GossipService = @import("../gossip/gossip_service.zig").GossipService;

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

var app = &cli.App{
    .name = "sig",
    .description = "Sig is a Solana client implementation written in Zig.\nThis is still a WIP, PRs welcome.",
    .version = "0.1.1",
    .author = "Syndica & Contributors",
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
        } },
    },
};

// prints (and creates if DNE) pubkey in ~/.sig/identity.key
fn identity(_: []const []const u8) !void {
    var logger = Logger.init(gpa_allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    const keypair = try getOrInitIdentity(gpa_allocator, logger);
    var pubkey: [50]u8 = undefined;
    var size = try base58Encoder.encode(&keypair.public_key.toBytes(), &pubkey);
    try std.io.getStdErr().writer().print("Identity: {s}\n", .{pubkey[0..size]});
}

// gossip entrypoint
fn gossip(_: []const []const u8) !void {
    var logger = Logger.init(gpa_allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    var my_keypair = try getOrInitIdentity(gpa_allocator, logger);

    var gossip_port: u16 = @intCast(gossip_port_option.value.int.?);
    var gossip_address = SocketAddr.initIpv4(.{ 0, 0, 0, 0 }, gossip_port);
    std.debug.print("gossip port: {d}\n", .{gossip_port});

    // setup contact info
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, false);
    var contact_info = LegacyContactInfo.default(my_pubkey);
    contact_info.shred_version = 0; // TODO: double check
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

    var handle = try std.Thread.spawn(
        .{},
        GossipService.run,
        .{&gossip_service},
    );

    handle.join();
}

pub fn run() !void {
    return cli.run(app, gpa_allocator);
}
