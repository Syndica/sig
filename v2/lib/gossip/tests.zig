comptime {
    if (@import("builtin").is_test) {
        _ = @import("tests/TestNode.zig");
        _ = @import("tests/component.zig");
        _ = @import("tests/fuzz.zig");
        _ = @import("tests/testing.zig");
    }
}
