const std = @import("std");
const cli = @import("zig-cli");
const gossipCmd = @import("../gossip/cmd.zig");
const base58 = @import("base58-zig");
const LegacyContactInfo = @import("../gossip/crds.zig").LegacyContactInfo;
const io = std.io;

var allocator = std.heap.GeneralPurposeAllocator(.{}){};
var gpa = allocator.allocator();
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

fn identity(_: []const []const u8) !void {
    const id = try gossipCmd.getOrInitIdentity(gpa);
    var pk: [50]u8 = undefined;
    var size = try base58Encoder.encode(&id.public_key.toBytes(), &pk);
    try std.io.getStdErr().writer().print("Identity: {s}\n", .{pk[0..size]});
}

fn gossip(_: []const []const u8) !void {
    var gossip_port: u16 = @intCast(gossip_port_option.value.int.?);
    var entrypoints = std.ArrayList(LegacyContactInfo).init(gpa);
    try gossipCmd.runGossipService(gossip_port, entrypoints);
}

pub fn run() !void {
    return cli.run(app, gpa);
}
