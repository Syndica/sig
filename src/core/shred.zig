const std = @import("std");

/// ***ShredVersion***
/// Currently it's being manually set.
///
/// TODO: use bankforks to calculate shred version
/// ```
pub const ShredVersion = struct {
    value: u16,

    const Self = @This();

    pub fn init_manually_set(version: u16) Self {
        return Self{ .value = version };
    }
};
