/// This service consumes information from other services,
/// and sends them to an aggregator (prometheus).
const obs = @This();

const std = @import("std");
const start = @import("start");
const lib = @import("lib");
const api = lib.observability;

comptime {
    _ = start;
}

pub const name = .observability;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {};

pub const ReadWrite = struct {};

pub fn serviceMain(ro: ReadOnly, rw: ReadWrite) !noreturn {
    _ = ro;
    _ = rw;
    while (true) {}
}
