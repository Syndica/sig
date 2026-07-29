const std = @import("std");
const shared = @import("shared");

pub const estimate = @import("estimate.zig");
pub const stake_weighted_timestamp = @import("stake_weighted_timestamp.zig");
pub const time = shared.time.time;

pub const Instant = shared.time.Instant;
pub const Timer = shared.time.Timer;
pub const Duration = shared.time.Duration;

/// returns current timestamp in milliseconds
pub fn getWallclockMs() u64 {
    return @intCast(std.time.milliTimestamp());
}

pub const MaxAllowableDrift = stake_weighted_timestamp.MaxAllowableDrift;
pub const EpochStartTimestamp = stake_weighted_timestamp.EpochStartTimestamp;
pub const calculateStakeWeightedTimestamp =
    stake_weighted_timestamp.calculateStakeWeightedTimestamp;
