const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;

/// `FeatureSet` holds the set of currently active and inactive features
///
/// TODO: add features
///
/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/feature-set/src/lib.rs#L1188
pub const FeatureSet = struct {
    active: std.AutoArrayHashMapUnmanaged(Pubkey, u64),
    inactive: std.AutoArrayHashMapUnmanaged(Pubkey, void),

    pub const EMPTY = FeatureSet{
        .active = .{},
        .inactive = .{},
    };
};
