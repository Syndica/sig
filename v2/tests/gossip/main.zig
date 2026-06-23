const std = @import("std");
const lib = @import("lib");
const services = @import("services");
const tel = lib.telemetry;
const topology = lib.topology;

const Region = topology.Region;

const Topology = struct {
    gossip: topology.ServiceRegions(services.gossip),
    telemetry: topology.ServiceRegions(services.telemetry),
};

pub fn main() !void {
    var dba_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dba_state.deinit();
    const gpa = dba_state.allocator();

    const gossip_port = 8001;
    const self_kp: lib.gossip.KeyPair = .fromKeyPair(try .generateDeterministic(@splat(1)));
    const ext_kp: lib.gossip.KeyPair = .fromKeyPair(try .generateDeterministic(@splat(2)));

    const gossip_cluster_info: lib.gossip.ClusterInfo = .{
        .public_ip = .fromNetAddress(.initIp4(.{ 123, 45, 67, 89 }, gossip_port)),
        .shred_version = 42,

        .entry_addrs_len = 0,
        .entry_addrs = @splat(undefined),
    };

    // -- Create regions -- //

    const gossip_params: lib.gossip.Config.InitParams = .{
        .cluster_info = gossip_cluster_info,
        // TODO: read this from identity file in signer service
        .keypair = self_kp,
        .turbine_recv_port = 8002,
        .advertise_tvu_port = false,
    };
    var gossip_config: Region(lib.gossip.Config) = try .sized(gossip_params.size());
    gossip_params.init(gossip_config.ptr());

    var gossip_source_to_snapshot: Region(lib.snapshot.SnapshotSourceRing) = try .simple();
    gossip_source_to_snapshot.ptr().init();

    const net_to_gossip_params: lib.net.Pair.InitParams = .{ .port = gossip_port };
    var net_to_gossip: Region(lib.net.Pair) = try .sized(net_to_gossip_params.size());
    net_to_gossip_params.init(net_to_gossip.ptr());

    // We're spawning gossip + telemetry, so 1 service shares the telemetry region (gossip).
    const telemetry_params: tel.Region.InitParams = .{
        .port = 12345,
        .log_filters_encoded = lib.telemetry.log.Filter.parseListStrLitIntoBinary(.fatal, "").?,
        .service_count = 1,
        .id_mem_len = 4096 * 16,
        .gauges_len = 4096 * 2,
        .histogram_data_len = 4096 * 3,
    };
    var telemetry_region: Region(tel.Region) = try .sized(telemetry_params.info().regionSize());
    telemetry_region.ptr().init(telemetry_params);

    // -- Inject test packet -- //

    const net_pair = try net_to_gossip.memfd.mmapStaticSize(.rw, lib.net.Pair, .{});
    defer std.posix.munmap(@ptrCast(net_pair));

    const ping_token: [32]u8 = @splat(12);
    const ping_token_hash: lib.solana.Hash = .initMany(&.{ "SOLANA_PING_PONG", &ping_token });
    {
        var iter = net_pair.recv.get(.writer);
        defer iter.markUsed();

        const gm: lib.gossip.GossipMessage = .{
            .ping_message = .{
                .from = ext_kp.pubkey,
                .token = ping_token,
                .signature = try ext_kp.sign(&ping_token),
            },
        };
        const packet = iter.next().?;
        var fbw: std.Io.Writer = .fixed(&packet.data);
        try lib.gossip.bincode.write(&fbw, gm);
        packet.len = @intCast(fbw.end);
    }

    // -- Spawn services -- //

    var children: topology.Children(Topology) = undefined;
    try children.spawn(.sandboxed, .{
        .gossip = .{
            .ro = .{ .config = gossip_config.finish() },
            .rw = .{
                .net_pair = net_to_gossip.finish(),
                .gossip_to_snapshot = gossip_source_to_snapshot.finish(),
                .tel = telemetry_region.finish(),
            },
        },
        .telemetry = .{
            .ro = .{},
            .rw = .{ .region = telemetry_region.finish() },
        },
    });

    // wait for gossip and telemetry to go idle
    while (children.isActive()) : (std.atomic.spinLoopHint()) {}

    // go and ask all the services to cancel
    children.cancel();

    // and then actually wait for the services to exit
    try children.wait(2 * std.time.ns_per_s);

    // -- Verify outgoing messages -- //

    var msgs: std.ArrayList(lib.gossip.GossipMessage) = .empty;
    defer msgs.deinit(gpa);

    var msg_buf: [16 * 1024]u8 align(16) = undefined;
    var msg_fba: std.heap.FixedBufferAllocator = .init(&msg_buf);

    var iter = net_pair.send.get(.reader);
    defer iter.markUsed();
    while (iter.next()) |packet| {
        var fbr: std.Io.Reader = .fixed(packet.data[0..packet.len]);
        const gm = try lib.gossip.bincode.read(&msg_fba, &fbr, lib.gossip.GossipMessage);
        try msgs.append(gpa, gm);
    }

    try std.testing.expectEqual(2, msgs.items.len);
    const ping_message_gm, const pong_message_gm = switch (msgs.items[0]) {
        .ping_message => .{ msgs.items[0], msgs.items[1] },
        else => .{ msgs.items[1], msgs.items[0] },
    };
    try std.testing.expectEqual(.ping_message, std.meta.activeTag(ping_message_gm));
    try std.testing.expectEqual(.pong_message, std.meta.activeTag(pong_message_gm));

    const ping_message = ping_message_gm.ping_message;
    const pong_message = pong_message_gm.pong_message;

    try std.testing.expectEqual(self_kp.pubkey, ping_message.from);
    try std.testing.expectEqual(self_kp.pubkey, pong_message.from);

    try std.testing.expectEqual(ping_token_hash, pong_message.hash);
}
