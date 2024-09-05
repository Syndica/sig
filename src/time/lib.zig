const std = @import("std");
pub const estimate = @import("estimate.zig");
pub const time = @import("time.zig");

pub const Instant = time.Instant;
pub const Timer = time.Timer;
pub const Duration = time.Duration;

/// returns current timestamp in milliseconds
pub fn getWallclockMs() u64 {
    return @intCast(std.time.milliTimestamp());
}
