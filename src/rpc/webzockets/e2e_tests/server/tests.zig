comptime {
    _ = @import("handshake_tests.zig");
    _ = @import("rejection_tests.zig");
    _ = @import("close_tests.zig");
    _ = @import("protocol_error_tests.zig");
    _ = @import("fragmentation_tests.zig");
    _ = @import("echo_tests.zig");
    _ = @import("pause_resume_tests.zig");
    _ = @import("buffer_tier_tests.zig");
    _ = @import("pool_tests.zig");
    _ = @import("raw_send_tests.zig");
    _ = @import("stress_tests.zig");
    _ = @import("timeout_tests.zig");
}
