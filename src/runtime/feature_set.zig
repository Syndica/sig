const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

pub const LIFT_CPI_CALLER_RESTRICTION =
    Pubkey.parseBase58String("HcW8ZjBezYYgvcbxNJwqv1t484Y2556qJsfNDWvJGZRH") catch unreachable;

pub const REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS =
    Pubkey.parseBase58String("FfgtauHUWKeXTzjXkua9Px4tNGBFHKZ9WaigM5VbbzFx") catch unreachable;

/// `FeatureSet` holds the set of currently active and inactive features
///
/// TODO: add features
///
/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/feature-set/src/lib.rs#L1188
pub const FeatureSet = struct {
    active: std.AutoArrayHashMapUnmanaged(Pubkey, Slot),

    pub const EMPTY = FeatureSet{
        .active = .{},
    };

    pub fn deinit(self: *FeatureSet, allocator: std.mem.Allocator) void {
        self.active.deinit(allocator);
    }
};
