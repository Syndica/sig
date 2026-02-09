comptime {
    _ = @import("connection_tests.zig");
    _ = @import("close_tests.zig");
    _ = @import("ping_pong_tests.zig");
    _ = @import("max_message_tests.zig");
    _ = @import("timeout_tests.zig");
}
