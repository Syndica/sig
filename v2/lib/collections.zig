comptime {
    if (@import("builtin").is_test) {
        _ = @import("collections/lcrs_tree.zig");
        _ = @import("collections/pool.zig");
    }
}

pub const Pool = @import("collections/pool.zig").Pool;
pub const LCRSTree = @import("collections/lcrs_tree.zig").LCRSTree;
