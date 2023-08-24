const std = @import("std");
const cli = @import("zig-cli");
const gossipCmd = @import("../gossip/cmd.zig");
const base58 = @import("base58-zig");
const LegacyContactInfo = @import("../gossip/crds.zig").LegacyContactInfo;
const Logger = @import("../trace/log.zig").Logger;
const io = std.io;

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
var gpa_allocator = gpa.allocator();
const base58Encoder = base58.Encoder.init(.{});

var gossip_port_option = cli.Option{
    .long_name = "gossip-port",
    .help = "The port to run gossip listener - default: 8001",
    .short_alias = 'p',
    .value = cli.OptionValue{ .int = 8001 },
    .required = false,
    .value_name = "Gossip Port",
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
        } },
    },
};

// prints (and creates if DNE) pubkey in ~/.sig/identity.key
fn identity(_: []const []const u8) !void {
    var logger = Logger.init(gpa_allocator, .debug);
    defer logger.deinit();
    logger.spawn();

    const keypair = try gossipCmd.getOrInitIdentity(gpa_allocator, logger);
    var pubkey: [50]u8 = undefined;
    var size = try base58Encoder.encode(&keypair.public_key.toBytes(), &pubkey);
    try std.io.getStdErr().writer().print("Identity: {s}\n", .{pubkey[0..size]});
}

// gossip entrypoint
fn gossip(_: []const []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(gpa_allocator);
    var logger = Logger.init(arena.allocator(), .debug);
    logger.spawn();

    var gossip_port: u16 = @intCast(gossip_port_option.value.int.?);
    var my_keypair = try gossipCmd.getOrInitIdentity(gpa_allocator, logger);

    // TODO
    var entrypoints = std.ArrayList(LegacyContactInfo).init(gpa_allocator);

    gossipCmd.runGossipService(
        gpa_allocator,
        &my_keypair,
        // cli args
        gossip_port,
        entrypoints,
        logger,
    ) catch {};
    logger.deinit();
}

pub fn run() !void {
    return cli.run(app, gpa.allocator());
}
