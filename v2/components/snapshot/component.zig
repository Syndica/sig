comptime {
    if (@import("builtin").is_test) {
        _ = @import("download.zig");
    }
}

pub const api = @import("api");

pub const download = @import("download.zig");
