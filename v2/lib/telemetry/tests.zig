comptime {
    if (@import("builtin").is_test) {
        _ = @import("tests/TestMetricStore.zig");
    }
}
