const std = @import("std");

test {
    // Uncomment to see logs during tests
    // std.testing.log_level = .debug;
}

comptime {
    _ = @import("server/tests.zig");
    _ = @import("client/tests.zig");
}
