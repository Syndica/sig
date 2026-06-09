comptime {
    if (@import("builtin").is_test) {
        _ = @import("time.zig");
    }
}

pub const time = @import("time.zig");

pub const Instant = time.Instant;
pub const Timer = time.Timer;
pub const Duration = time.Duration;
