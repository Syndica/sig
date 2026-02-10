const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const ContactInfo = sig.gossip.ContactInfo;
const Cluster = sig.core.Cluster;
const GossipService = sig.gossip.GossipService;
const SocketAddr = sig.net.SocketAddr;
const IpAddr = sig.net.IpAddr;

const resolveSocketAddr = sig.net.net.resolveSocketAddr;
const getShredAndIPFromEchoServer = sig.net.echo.getShredAndIPFromEchoServer;
const getWallclockMs = sig.time.getWallclockMs;
const getClusterEntrypoints = sig.gossip.service.getClusterEntrypoints;

/// inits a gossip client with the minimum required configuration
/// relying on the cluster to provide the entrypoints
pub fn initGossipFromCluster(
    allocator: std.mem.Allocator,
    logger: sig.trace.Logger("gossip"),
    cluster: Cluster,
    my_port: u16,
) !*GossipService {
    // gather entrypoints
    var entrypoints = std.array_list.Managed(SocketAddr).init(allocator);
    defer entrypoints.deinit();

    const entrypoints_strs = getClusterEntrypoints(cluster);
    for (entrypoints_strs) |entrypoint_str| {
        const socket_addr = try resolveSocketAddr(allocator, entrypoint_str);
        try entrypoints.append(socket_addr);
    }

    // create contact info
    const echo_data = try getShredAndIPFromEchoServer(.from(logger), entrypoints.items);
    const my_shred_version = echo_data.shred_version orelse 0;
    const my_ip: IpAddr = echo_data.ip orelse .initIpv4(.{ 127, 0, 0, 1 });

    const my_keypair = try sig.identity.getOrInit(allocator, .from(logger));

    const my_pubkey = Pubkey.fromPublicKey(&my_keypair.public_key);
    var contact_info = ContactInfo.init(allocator, my_pubkey, getWallclockMs(), 0);
    try contact_info.setSocket(.gossip, SocketAddr.init(my_ip, my_port));
    contact_info.shred_version = my_shred_version;

    logger.info()
        .field("my_pubkey", my_pubkey)
        .field("my_ip", my_ip)
        .field("my_shred_version", my_shred_version)
        .field("gossip_port", my_port)
        .field("entrypoints", entrypoints.items)
        .log("setting up gossip");

    // create gossip
    return try GossipService.create(
        allocator,
        allocator,
        contact_info,
        my_keypair,
        entrypoints.items,
        .from(logger),
        .{},
    );
}
