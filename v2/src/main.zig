const std = @import("std");
const services = @import("services.zig");

const Config = struct {
    cluster: Cluster,
    gossip: Gossip,
    shred_network: ShredNetwork,

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

    std.debug.print("config: {}\n", .{config});

    try services.spawnAndWait(
        allocator,
        &.{
            .{ .service = .shred_receiver },
            .{ .service = .net },
        },
        &.{
            .{
                .region = .{ .net_pair = .{ .port = config.shred_network.recv_port } },
                .shares = &.{
                    .{ .instance = .{ .service = .shred_receiver }, .rw = true },
                    .{ .instance = .{ .service = .net }, .rw = true },
                },
            },
        },
    );
}
