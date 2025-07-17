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

pub const stake_weighted_timestamp = @import("stake_weighted_timestamp.zig");
pub const MaxAllowableDrift = stake_weighted_timestamp.MaxAllowableDrift;
pub const EpochStartTimestamp = stake_weighted_timestamp.EpochStartTimestamp;
pub const calculateStakeWeightedTimestamp =
    stake_weighted_timestamp.calculateStakeWeightedTimestamp;
