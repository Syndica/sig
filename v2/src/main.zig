const std = @import("std");
const services = @import("services.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

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
                .region = .net_pair,
                .shares = &.{
                    .{ .instance = .{ .service = .net }, .rw = true },
                    .{ .instance = .{ .service = .ping }, .rw = true },
                },
            },
        },
    );
}
