const std = @import("std");

comptime {
    _ = std.testing.refAllDecls(@This());
}

const services = @import("services.zig");
const common = @import("common");
const obs = common.observability;

const Config = struct {
    sandboxing_mode: SandboxingMode,

    cluster: Cluster,

    /// path to a file containing the output of `solana leader-schedule`
    leader_schedule_file: []const u8,

    gossip: Gossip,
    shred_network: ShredNetwork,

    observability: Observability,

    const SandboxingMode = enum { sandboxed, threaded };

    const Cluster = enum { testnet, devnet, mainnet };

    const Gossip = struct {
        port: u16,
    };

    const ShredNetwork = struct {
        recv_port: u16,
    };

    const Observability = struct {
        port: u16,
    };
};

pub fn main() !void {
    var dba_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = dba_state.deinit();
    const allocator = dba_state.allocator();

    const config: Config, //
    const log_level: obs.log.Level //
    = cfg: {
        var args = std.process.args();
        _ = args.next();
        const cfg_path = args.next() orelse return error.ConfigPathMissing;
        const log_level = level: {
            const str = args.next() orelse "info";
            break :level std.meta.stringToEnum(obs.log.Level, str) orelse {
                std.log.err("Invalid log level '{s}'", .{str});
                return error.InvalidLogLevel;
            };
        };

        const cfg_file = try std.fs.cwd().openFile(cfg_path, .{});
        defer cfg_file.close();

        const cfg_str = try cfg_file.readToEndAllocOptions(allocator, 1024 * 1024, null, .@"1", 0);
        defer allocator.free(cfg_str);

        var diag: std.zon.parse.Diagnostics = .{};
        defer diag.deinit(allocator);

        const config = std.zon.parse.fromSlice(Config, allocator, cfg_str, &diag, .{}) catch |err| {
            std.log.err("{f}", .{diag});
            return err;
        };
        break :cfg .{ config, log_level };
    };
    defer std.zon.parse.free(allocator, config);

    std.log.info("config: {}", .{config});

    const schedule_file = try std.fs.cwd().openFile(config.leader_schedule_file, .{});
    defer schedule_file.close();
    var reader_buf: [4096]u8 = undefined;
    var reader = schedule_file.reader(&reader_buf);

    const service_instances: []const services.ServiceInstance = &.{
        .{ .service = .shred_receiver },
        .{ .service = .net },
        .{ .service = .observability },
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
        .{
            .region = .{
                .obs_init = .{
                    .port = config.observability.port,
                    .max_log_level = log_level,
                    .service_count = service_instances.len - 1,
                },
            },
            .shares = &.{
                .{ .instance = .{ .service = .observability } },
                .{ .instance = .{ .service = .net }, .rw = true },
                .{ .instance = .{ .service = .shred_receiver }, .rw = true },
            },
        },
        .{
            .region = .{
                .obs_log_streams = .{
                    .max_log_streams = service_instances.len - 1,
                },
            },
            .shares = &.{
                .{ .instance = .{ .service = .observability }, .rw = true },
                .{ .instance = .{ .service = .net }, .rw = true },
                .{ .instance = .{ .service = .shred_receiver }, .rw = true },
            },
        },
        .{
            .region = .{ .obs_id_mem = .{} },
            .shares = &.{
                .{ .instance = .{ .service = .observability } },
                .{ .instance = .{ .service = .net }, .rw = true },
                .{ .instance = .{ .service = .shred_receiver }, .rw = true },
            },
        },
        .{
            .region = .{ .obs_gauges = .{} },
            .shares = &.{
                .{ .instance = .{ .service = .observability } },
                .{ .instance = .{ .service = .net }, .rw = true },
                .{ .instance = .{ .service = .shred_receiver }, .rw = true },
            },
        },
        .{
            .region = .{ .obs_histogram_data = .{} },
            .shares = &.{
                .{ .instance = .{ .service = .observability }, .rw = true },
                .{ .instance = .{ .service = .net }, .rw = true },
                .{ .instance = .{ .service = .shred_receiver }, .rw = true },
            },
        },
    };

    switch (config.sandboxing_mode) {
        .sandboxed => try services.spawnAndWait(
            allocator,
            service_instances,
            shared_regions,
        ),
        .threaded => try services.spawnAndWaitNoSandbox(
            allocator,
            service_instances,
            shared_regions,
        ),
    }
}
