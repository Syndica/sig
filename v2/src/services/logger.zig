const std = @import("std");
const start = @import("start");

comptime {
    _ = start;
}

pub const name: []const u8 = "logger";
pub const _start = {};
pub const panic = start.panic;

pub const ReadOnly = struct {
    prng_state: []const u8 = &.{},
};

pub fn main(writer: *std.io.Writer, ro: ReadOnly) !noreturn {
    var i: u32 = 0;
    while (i < 10) : (i += 1) {
        defer writer.flush() catch {};

        try writer.print("logger: {x}\n", .{ro.prng_state});
        std.Thread.sleep(std.time.ns_per_ms * 500);
    }

    try writer.print("logger: finished, time to exit\n", .{});

    return error.TimeToExit;
}

test main {
    var buf: [100]u8 = undefined;
    var discarding = std.io.Writer.Discarding.init(&buf);
    const writer = &discarding.writer;

    var prng_state: std.Random.Xoroshiro128 = .init(5083);

    try std.testing.expectError(
        error.TimeToExit,
        main(writer, .{ .prng_state = @ptrCast(&prng_state.s) }),
    );
}
