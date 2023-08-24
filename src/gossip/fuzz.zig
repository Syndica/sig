const std = @import("std");
const GossipService = @import("./gossip_service.zig").GossipService;
const Logger = @import("../trace/log.zig").Logger;

const crds = @import("../gossip/crds.zig");
const LegacyContactInfo = crds.LegacyContactInfo;
const AtomicBool = std.atomic.Atomic(bool);

const SocketAddr = @import("net.zig").SocketAddr;
const UdpSocket = @import("zig-network").Socket;

const Keypair = std.crypto.sign.Ed25519.KeyPair;
const Pubkey = @import("../core/pubkey.zig").Pubkey;
const get_wallclock = @import("../gossip/crds.zig").get_wallclock;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    var allocator = gpa.allocator();

    var logger = Logger.init(gpa.allocator(), .debug);
    defer logger.deinit();
    logger.spawn();

    // setup the gossip service
    var gossip_port: u16 = 9999;

    // bind the gossip socket
    var gossip_socket_addr = SocketAddr.init_ipv4(.{ 127, 0, 0, 1 }, gossip_port);
    var gossip_socket = try UdpSocket.create(.ipv4, .udp);
    try gossip_socket.bind(gossip_socket_addr.toEndpoint());

    // create cluster info
    var my_keypair = try Keypair.create(null);
    var my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key, false);
    var legacy_contact_info = LegacyContactInfo.default(my_pubkey);
    legacy_contact_info.gossip = gossip_socket_addr;

    var exit = AtomicBool.init(false);

    var gossip_service = try GossipService.init(
        allocator,
        legacy_contact_info,
        my_keypair,
        gossip_socket,
        exit,
    );

    // start running gossip
    try gossip_service.run(logger);

    // blast it
    // TODO
    std.time.sleep(1 * std.time.ns_per_s);

    // cleanup
    gossip_service.deinit();
}
