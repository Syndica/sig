const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const ContactInfo = sig.gossip.ContactInfo;
const Logger = sig.trace.Logger;
const Network = sig.cmd.config.Network;
const GossipService = sig.gossip.GossipService;
const SocketAddr = sig.net.SocketAddr;

const resolveSocketAddr = sig.net.net.resolveSocketAddr;
const getMyDataFromIpEcho = sig.cmd.cmd.getMyDataFromIpEcho;
const getOrInitIdentity = sig.cmd.helpers.getOrInitIdentity;
const getWallclockMs = sig.time.getWallclockMs;

/// inits a gossip client with the minimum required configuration
/// relying on the network to provide the entrypoints
pub fn initGossipFromNetwork(
    allocator: std.mem.Allocator,
    logger: Logger,
    gossip_network: Network,
) !*GossipService {
    var entrypoints = std.ArrayList(SocketAddr).init(allocator);
    defer entrypoints.deinit();
    for (gossip_network.entrypoints()) |entrypoint| {
        logger.info().logf("adding predefined entrypoint: {s}", .{entrypoint});
        const socket_addr = try resolveSocketAddr(allocator, entrypoint);
        try entrypoints.append(socket_addr);
    }

    const ip_echo_data = try getMyDataFromIpEcho(logger, entrypoints.items);
    const my_shred_version = ip_echo_data.shred_version;
    const my_ip = ip_echo_data.ip;

    const default_config = sig.cmd.config.GossipConfig{};
    const my_port = default_config.port; // default port
    const my_keypair = try getOrInitIdentity(allocator, logger);

    // setup contact info
    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    var contact_info = ContactInfo.init(allocator, my_pubkey, getWallclockMs(), 0);
    try contact_info.setSocket(.gossip, SocketAddr.init(my_ip, my_port));
    contact_info.shred_version = my_shred_version;

    return try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        entrypoints.items,
        logger,
    );
}
