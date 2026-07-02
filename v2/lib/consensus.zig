pub const leaf = @import("consensus/leaf.zig");
pub const loop_tree = @import("consensus/loop-tree.zig");
pub const recurse_tree = @import("consensus/recurse-tree.zig");

comptime {
    if (@import("builtin").is_test) {
        _ = @import("consensus/leaf.zig");
        _ = @import("consensus/loop-tree.zig");
        _ = @import("consensus/recurse-tree.zig");
    }
}
