const std = @import("std");
const services = @import("services.zig");

const Config = struct {
    gossip: Gossip,

    const Gossip = struct {
        cluster: Cluster,
        port: u16,
        const Cluster = enum { testnet, devnet, mainnet };
    };
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const config = cfg: {
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
            .{ .service = .prng },
            .{ .service = .logger },
            .{ .service = .net },
            .{ .service = .ping },
        },
        &.{
            .{
                .region = .prng_state,
                .shares = &.{
                    .{ .instance = .{ .service = .prng }, .rw = true },
                    .{ .instance = .{ .service = .logger } },
                },
            },
            .{
                .region = .{ .net_pair = .{ .port = 123 } },
                .shares = &.{
                    .{ .instance = .{ .service = .net }, .rw = true },
                    .{ .instance = .{ .service = .ping }, .rw = true },
                },
            },
        },
    );
}
