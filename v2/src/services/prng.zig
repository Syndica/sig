const std = @import("std");
const start = @import("start");

comptime {
    _ = start;
}

pub const name: []const u8 = "prng";
pub const _start = {};
pub const panic = start.panic;

pub const ReadWrite = struct {
    prng_state: *std.Random.Xoroshiro128,
};

pub fn main(writer: *std.io.Writer, rw: ReadWrite) !noreturn {
    _ = writer;

    rw.prng_state.seed(123);
    while (true) rw.prng_state.seed(rw.prng_state.next());
}
