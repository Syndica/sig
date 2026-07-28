const std = @import("std");
const start = @import("start_service");
const lib = @import("lib");
const tracy = @import("tracy");

comptime {
    _ = start;
}

pub const name = .healthy;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {};
pub const ReadWrite = struct {};

pub fn serviceMain(runner: lib.runner.Connection, _: ReadOnly, _: ReadWrite) !noreturn {
    while (true) {
        const zone = tracy.Zone.init(@src(), .{});
        defer zone.deinit();

        try runner.activity.checkCanceled();
        std.atomic.spinLoopHint();
    }
}
