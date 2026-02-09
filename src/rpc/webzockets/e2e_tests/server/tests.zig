comptime {
    // Handshake & connection setup
    _ = @import("handshake_tests.zig");
    _ = @import("rejection_tests.zig");

    // Protocol compliance
    _ = @import("close_tests.zig");
    _ = @import("protocol_error_tests.zig");
    _ = @import("fragmentation_tests.zig");

    // Messaging
    _ = @import("echo_tests.zig");
    _ = @import("buffer_tier_tests.zig");

    // Resources
    _ = @import("pool_tests.zig");

    // Stress/load
    _ = @import("stress_tests.zig");

    // Timeouts
    _ = @import("timeout_tests.zig");
}
