comptime {
    _ = @import("subscription_tests.zig");
    _ = @import("account_subscription_tests.zig");
    _ = @import("program_subscription_tests.zig");
    _ = @import("logs_subscription_tests.zig");
    _ = @import("block_subscription_tests.zig");
    _ = @import("slots_updates_subscription_tests.zig");
    _ = @import("error_tests.zig");
    _ = @import("multi_client_tests.zig");
    _ = @import("http_integration_tests.zig");
}
