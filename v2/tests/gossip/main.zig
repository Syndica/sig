const std = @import("std");
const lib = @import("lib");
const services = @import("services");
const tel = lib.telemetry;
const testing = lib.gossip.testing;
const topology = lib.topology;

const Region = topology.Region;

const Topology = struct {
    gossip: topology.ServiceRegions(.from(services.gossip)),
    telemetry: topology.ServiceRegions(.from(services.telemetry)),
};

/// Verifies gossip ping/pong behavior through sandboxed services and shared-memory rings.
pub fn main() !void {
    const gossip_port = 8001;
    const self_kp = try testing.deterministicKeyPair(1);
    const ext_kp = try testing.deterministicKeyPair(2);

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

        iter.next().?.* = try testing.packetFromMessage(
            .initIp4(.{ 127, 0, 0, 1 }, 9001),
            try testing.pingMessage(&ext_kp, ping_token),
        );
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

    var messages_len: usize = 0;
    var found_ping = false;
    var found_pong = false;
    var iter = net_pair.send.get(.reader);
    defer iter.markUsed();
    while (iter.next()) |packet| {
        messages_len += 1;
        var message_memory: [16 * 1024]u8 = undefined;
        const message = try testing.readMessage(&message_memory, packet);
        switch (message) {
            .ping_message => |ping| {
                if (!ping.from.equals(&self_kp.pubkey)) continue;
                try ping.signature.verify(&ping.from, &ping.token);
                found_ping = true;
            },
            .pong_message => |pong| {
                if (!pong.from.equals(&self_kp.pubkey)) continue;
                try std.testing.expect(pong.hash.eql(&ping_token_hash));
                try pong.signature.verify(&pong.from, &pong.hash.data);
                found_pong = true;
            },
            else => {},
        }
    }
    try std.testing.expectEqual(2, messages_len);
    try std.testing.expect(found_ping);
    try std.testing.expect(found_pong);
}
