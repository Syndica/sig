const std = @import("std");
const GossipService = @import("gossip_service.zig").GossipService;
const Logger = @import("../trace/log.zig").Logger;

const crds = @import("crds.zig");
const LegacyContactInfo = crds.LegacyContactInfo;
const AtomicBool = std.atomic.Atomic(bool);

const SocketAddr = @import("net.zig").SocketAddr;
const UdpSocket = @import("zig-network").Socket;

const Keypair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const get_wallclock = @import("crds.zig").get_wallclock;

pub fn main() !void {
    // var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // var allocator = gpa.allocator();

    // var logger = Logger.init(gpa.allocator(), .debug);
    // defer logger.deinit();
    // logger.spawn();

    // // setup the gossip service
    // var gossip_port: u16 = 9999;
    // var my_keypair = try Keypair.create(null);
    // var exit = AtomicBool.init(false);

    // // start running gossip
    // var handle = try gossipCmd.runGossipService(
    //     allocator,
    //     my_keypair,
    //     gossip_port,
    //     std.ArrayList(LegacyContactInfo).init(allocator),
    //     logger,
    //     &exit,
    // );
    // std.debug.print("gossip service started on port {d}\n", .{gossip_port});

    // // blast it
    // // TODO
    // std.time.sleep(1 * std.time.ns_per_s);

    // // cleanup
    // std.debug.print("gossip service exiting\n", .{});
    // exit.store(true, std.atomic.Ordering.Unordered);
    // handle.join();

    // std.debug.print("fuzzing done\n", .{});
}
