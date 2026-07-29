const start = @import("start_service");
const lib = @import("lib");

comptime {
    _ = start;
}

pub const name = .failing;
pub const panic = start.panic;
pub const std_options = start.options;

pub const ReadOnly = struct {};
pub const ReadWrite = struct {};

pub fn serviceMain(_: lib.runner.Connection, _: ReadOnly, _: ReadWrite) !noreturn {
    return error.IntentionalFailure;
}
