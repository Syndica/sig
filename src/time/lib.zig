pub const estimate = @import("estimate.zig");
pub const stake_weighted_timestamp = @import("stake_weighted_timestamp.zig");
pub const time = @import("time.zig");

pub const Instant = time.Instant;
pub const Timer = time.Timer;
pub const Duration = time.Duration;

/// returns current timestamp in milliseconds
pub fn getWallclockMs() u64 {
    return @intCast(time.milliTimestamp());
}

pub const MaxAllowableDrift = stake_weighted_timestamp.MaxAllowableDrift;
pub const EpochStartTimestamp = stake_weighted_timestamp.EpochStartTimestamp;
pub const calculateStakeWeightedTimestamp =
    stake_weighted_timestamp.calculateStakeWeightedTimestamp;

pub const timestamp = time.timestamp;
pub const milliTimestamp = time.milliTimestamp;
pub const microTimestamp = time.microTimestamp;
