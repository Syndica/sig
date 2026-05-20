comptime {
    if (@import("builtin").is_test) {
        _ = @import("collections/pool.zig");
    }
}

pub const Pool = @import("collections/pool.zig").Pool;
pub const SharedPool = @import("collections/pool.zig").SharedPool;
