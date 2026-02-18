const std = @import("std");
const tracy = @import("tracy");

test {
    _ = std.testing.refAllDecls(@This());
}

const services = @import("services.zig");

const Config = struct {
    sandboxing_mode: SandboxingMode,

    cluster: Cluster,

    /// path to a file containing the output of `solana leader-schedule`
    leader_schedule_file: []const u8,

    gossip: Gossip,
    shred_network: ShredNetwork,

    const SandboxingMode = enum { sandboxed, threaded };

    const Cluster = enum { testnet, devnet, mainnet };

    const Gossip = struct {
        port: u16,
    };

    const ShredNetwork = struct {
        recv_port: u16,
    };
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

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
            std.debug.print("{f}\n", .{diag});
            return err;
        };
    };
    defer std.zon.parse.free(allocator, config);

    std.debug.print("config: {}\n", .{config});

    if (config.sandboxing_mode == .threaded) tracy.startupProfiler();
    defer if (config.sandboxing_mode == .threaded) tracy.shutdownProfiler();

    const schedule_file = try std.fs.cwd().openFile(config.leader_schedule_file, .{});
    defer schedule_file.close();
    var reader_buf: [4096]u8 = undefined;
    var reader = schedule_file.reader(&reader_buf);

    const service_instances: []const services.ServiceInstance = &.{
        .{ .service = .shred_receiver },
        .{ .service = .net },
    };

    const shared_regions: []const services.SharedRegion = &.{
        .{
            .region = .{ .net_pair = .{ .port = config.shred_network.recv_port } },
            .shares = &.{
                .{ .instance = .{ .service = .shred_receiver }, .rw = true },
                .{ .instance = .{ .service = .net }, .rw = true },
            },
        },
        .{
            .region = .{ .leader_schedule = .{ .schedule_string = &reader.interface } },
            .shares = &.{
                .{ .instance = .{ .service = .shred_receiver } },
            },
        },
    };

    switch (config.sandboxing_mode) {
        .sandboxed => try services.spawnAndWait(allocator, service_instances, shared_regions),
        .threaded => try services.spawnAndWaitNoSandbox(allocator, service_instances, shared_regions),
    }
}
