// https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/feature-set/src/lib.rs

const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const Features = struct {
    active: std.AutoArrayHashMap(Pubkey, u64),
    inactive: std.AutoArrayHashMapUnmanaged(Pubkey, void),
};
