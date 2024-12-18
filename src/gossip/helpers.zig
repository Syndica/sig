const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const ContactInfo = sig.gossip.ContactInfo;
const Logger = sig.trace.Logger;
const Cluster = sig.core.Cluster;
const GossipService = sig.gossip.GossipService;
const SocketAddr = sig.net.SocketAddr;
const IpAddr = sig.net.IpAddr;

const resolveSocketAddr = sig.net.net.resolveSocketAddr;
const getShredAndIPFromEchoServer = sig.net.echo.getShredAndIPFromEchoServer;
const getOrInitIdentity = sig.cmd.helpers.getOrInitIdentity;
const getWallclockMs = sig.time.getWallclockMs;
const getClusterEntrypoints = sig.gossip.service.getClusterEntrypoints;

/// inits a gossip client with the minimum required configuration
/// relying on the cluster to provide the entrypoints
pub fn initGossipFromCluster(
    allocator: std.mem.Allocator,
    logger: Logger,
    cluster: Cluster,
) !*GossipService {
    // gather entrypoints
    var entrypoints = std.ArrayList(SocketAddr).init(allocator);
    defer entrypoints.deinit();

    const entrypoints_strs = getClusterEntrypoints(cluster);
    for (entrypoints_strs) |entrypoint_str| {
        const socket_addr = try resolveSocketAddr(allocator, entrypoint_str);
        try entrypoints.append(socket_addr);
    }
    logger.info().logf("using predefined entrypoints: {any}", .{entrypoints});

    // create contact info
    const echo_data = try getShredAndIPFromEchoServer(
        logger.unscoped(),
        allocator,
        entrypoints.items,
    );
    const my_shred_version = echo_data.shred_version orelse 0;
    logger.info().logf("my shred version: {d}", .{my_shred_version});
    const my_ip = echo_data.ip orelse IpAddr.newIpv4(127, 0, 0, 1);
    logger.info().logf("my ip: {any}", .{my_ip});

    const default_config = sig.cmd.config.GossipConfig{};
    const my_port = default_config.port; // default port
    const my_keypair = try getOrInitIdentity(allocator, logger);
    logger.info().logf("gossip_port: {d}", .{my_port});

    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    var contact_info = ContactInfo.init(allocator, my_pubkey, getWallclockMs(), 0);
    try contact_info.setSocket(.gossip, SocketAddr.init(my_ip, my_port));
    contact_info.shred_version = my_shred_version;

    // create gossip
    return try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        entrypoints.items,
        logger,
    );
}
