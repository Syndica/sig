const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

pub const LIFT_CPI_CALLER_RESTRICTION =
    Pubkey.parseBase58String("HcW8ZjBezYYgvcbxNJwqv1t484Y2556qJsfNDWvJGZRH") catch unreachable;

pub const REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS =
    Pubkey.parseBase58String("FfgtauHUWKeXTzjXkua9Px4tNGBFHKZ9WaigM5VbbzFx") catch unreachable;

pub const RELAX_AUTHORITY_SIGNER_CHECK_FOR_LOOKUP_TABLE_CREATION =
    Pubkey.parseBase58String("FKAcEvNgSY79RpqsPNUV5gDyumopH4cEHqUxyfm8b8Ap") catch unreachable;

/// `FeatureSet` holds the set of currently active and inactive features
///
/// TODO: add features
///
/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/feature-set/src/lib.rs#L1188
pub const FeatureSet = struct {
    active: std.AutoArrayHashMapUnmanaged(Pubkey, Slot),
    inactive: std.AutoArrayHashMapUnmanaged(Pubkey, Slot),

    pub const EMPTY = FeatureSet{
        .active = .{},
        .inactive = .{},
    };

    pub fn deinit(self: *FeatureSet, allocator: std.mem.Allocator) void {
        self.active.deinit(allocator);
        self.inactive.deinit(allocator);
    }

    pub fn isActive(self: *const FeatureSet, feature: Pubkey) bool {
        return self.active.contains(feature);
    }

    pub const allow_commission_decrease_at_any_time =
        Pubkey.parseBase58String("5x3825XS7M2A3Ekbn5VGGkvFoAg5qrRWkTrY4bARP1GL") catch unreachable;

    pub const commission_updates_only_allowed_in_first_half_of_epoch =
        Pubkey.parseBase58String("noRuG2kzACwgaY7TVmLRnUNPLKNVQE1fb7X55YWBehp") catch unreachable;
};
