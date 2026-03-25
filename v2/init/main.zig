const std = @import("std");

comptime {
    _ = std.testing.refAllDecls(@This());
}

const services_zon = @import("services.zon");
const services = @import("services.zig");
const lib = @import("lib");

const Config = struct {
    sandboxing_mode: SandboxingMode,

    cluster: lib.solana.Cluster,

    /// path to a file containing the output of `solana leader-schedule`
    leader_schedule_file: []const u8,

    gossip: Gossip,
    shred_network: ShredNetwork,

    const SandboxingMode = enum { sandboxed, threaded };

    const Gossip = struct {
        port: u16,
    };

    const ShredNetwork = struct {
        recv_port: u16,
    };
};

pub fn main() !void {
    var dba_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dba_state.deinit();
    const allocator = dba_state.allocator();

    const config: Config = cfg: {
        var args = std.process.args();
        _ = args.next();
        const cfg_path = args.next() orelse return error.ConfigPathMissing;

        const cfg_file = try std.fs.cwd().openFile(cfg_path, .{});
        defer cfg_file.close();

        const cfg_str = try cfg_file.readToEndAllocOptions(allocator, 1024 * 1024, null, .@"1", 0);
        defer allocator.free(cfg_str);

        var diag: std.zon.parse.Diagnostics = .{};
        defer diag.deinit(allocator);

        break :cfg std.zon.parse.fromSlice(Config, allocator, cfg_str, &diag, .{}) catch |err| {
            std.log.err("{f}", .{diag});
            return err;
        };
    };
    defer std.zon.parse.free(allocator, config);

    std.log.info("config: {}", .{config});

    const gossip_cluster_info: lib.gossip.ClusterInfo =
        try .getFromEcho(config.gossip.port, config.cluster);

    const schedule_file = try std.fs.cwd().openFile(config.leader_schedule_file, .{});
    defer schedule_file.close();
    var reader_buf: [4096]u8 = undefined;
    var reader = schedule_file.reader(&reader_buf);

    const service_instances: []const services.ServiceInstance = &.{
        .{ .service = .shred_receiver },
        .{ .service = .net },
        .{ .service = .gossip },
    };

    const shared_regions = services.toSharedRegions(.{
        // net -> shred
        .net_to_shred = .{ .port = config.shred_network.recv_port },
        // shred constants
        .shred_recv_config = .{
            .schedule_string = &reader.interface,
            .shred_version = gossip_cluster_info.shred_version,
        },

        // net -> gossip
        .net_to_gossip = .{ .port = config.gossip.port },
        // gossip constants
        .gossip_config = .{
            .cluster_info = gossip_cluster_info,
            // TODO: read this from identity file in signer service
            .keypair = .fromKeyPair(.generate()),
            .turbine_recv_port = config.shred_network.recv_port,
        },
    });

    switch (config.sandboxing_mode) {
        .sandboxed => try services.spawnAndWait(
            allocator,
            service_instances,
            &shared_regions,
        ),
        .threaded => try services.spawnAndWaitNoSandbox(
            allocator,
            service_instances,
            &shared_regions,
        ),
    }
}
