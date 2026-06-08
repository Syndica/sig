const std = @import("std");
const lib = @import("lib");
const tel = lib.telemetry;

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

    const service_map = try topology.serviceMap(.{
        // gossip constants
        .gossip_config = .{
            .cluster_info = gossip_cluster_info,
            // TODO: read this from identity file in signer service
            .keypair = self_kp,
            .turbine_recv_port = 8002,
            .advertise_tvu_port = false,
        },
        // gossip -(source)-> snapshot
        .gossip_source_to_snapshot = {},
        // net -> gossip
        .net_to_gossip = .{ .port = gossip_port },
        .telemetry = .{
            .port = 12345,
            .log_filters_encoded = lib.telemetry.log.Filter.parseListStrLitIntoBinary(.fatal, "").?,
            .service_count = @intCast(
                topology.countTotalBindingShares(.telemetry) - 1,
            ),

            .id_mem_len = 4096 * 16,
            .gauges_len = 4096 * 2,

            .histogram_data_len = 4096 * 3,
        },
    });

    const net_to_gossip_memfd = service_map.entries.get(.gossip).?.bindings.get(.net_to_gossip).?;
    const net_pair = try net_to_gossip_memfd.memfd.mmapStaticSize(lib.net.Pair, .{});
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

    var spawned: topology.Children = undefined;
    try spawned.spawn(.sandboxed, &service_map);

    const activities = spawned.activityViews();

    // wait for gossip and telemetry to go idle
    blk: while (true) {
        for (activities) |*view| {
            if (view.isActive()) continue :blk;
        }
        break :blk;
    }

    // go and ask all the services to cancel
    for (activities) |*view| view.cancel();

    // and then actually wait for the services to exit
    try spawned.wait(10 * std.time.ns_per_ms);

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

const topology_schema: lib.topology.Schema = .{
    .services = @import("schema"),
};

pub const topology = lib.topology.Bind(topology_schema, Region, .init(.{
    .gossip_config = .initOne(.@"gossip:config"),
    .gossip_source_to_snapshot = .initOne(.@"gossip:source_to_snapshot"),
    .net_to_gossip = .initOne(.@"gossip:from_net"),
    .telemetry = .initMany(&.{ .@"telemetry:main", .@"gossip:telemetry" }),
}));

pub const Region = union(enum) {
    gossip_config: lib.gossip.Config.InitParams,
    gossip_source_to_snapshot,
    net_to_gossip: lib.net.Pair.InitParams,
    telemetry: tel.Region.InitParams,

    pub const Tag = @typeInfo(Region).@"union".tag_type.?;

    pub fn size(self: Region) usize {
        return switch (self) {
            .gossip_config => |cfg| cfg.size(),
            .gossip_source_to_snapshot => @sizeOf(lib.snapshot.SnapshotSourceRing),
            .net_to_gossip => |cfg| cfg.size(),
            .telemetry => |params| params.info().regionSize(),
        };
    }

    pub fn init(self: Region, buf: []align(std.heap.page_size_min) u8) !void {
        std.log.info("Initialising: {}", .{std.meta.activeTag(self)});

        return switch (self) {
            .gossip_config => |cfg| cfg.init(buf),
            .gossip_source_to_snapshot => {
                std.debug.assert(buf.len == @sizeOf(lib.snapshot.SnapshotSourceRing));
                const data: *lib.snapshot.SnapshotSourceRing = @ptrCast(buf);
                data.init();
            },
            .net_to_gossip => |cfg| cfg.init(buf),

            .telemetry => |params| {
                std.debug.assert(buf.len == params.info().regionSize());
                const data: *tel.Region = @ptrCast(buf);

                data.init(params);
            },
        };
    }
};
