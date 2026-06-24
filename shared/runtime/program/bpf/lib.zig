comptime {
    if (@import("builtin").is_test) {
        _ = @import("serialize.zig");
        _ = @import("tests.zig");
    }
}

pub const tests = @import("tests.zig");
pub const serialize = @import("serialize.zig");
