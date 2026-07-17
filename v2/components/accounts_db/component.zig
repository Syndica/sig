comptime {
    if (@import("builtin").is_test) {
        _ = @import("rooted.zig");
        _ = @import("table.zig");
    }
}

pub const api = @import("api");

pub const AccountPool = api.AccountPool;
pub const Rooted = @import("rooted.zig").Rooted;
pub const Table = @import("table.zig").Table;
