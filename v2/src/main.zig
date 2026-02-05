const std = @import("std");
const common = @import("common");
const services = @import("services.zig");

pub fn main() !void {
    try services.spawnAndWait(
        std.heap.page_allocator,
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
