const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

pub const LIFT_CPI_CALLER_RESTRICTION =
    Pubkey.parseBase58String("HcW8ZjBezYYgvcbxNJwqv1t484Y2556qJsfNDWvJGZRH") catch unreachable;

// [agave] github.com/anza-xyz/agave/issues/5464
// the key of this was changed in march 2025... what?
pub const REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS =
    Pubkey.parseBase58String("FXs1zh47QbNnhXcnB6YiAQoJ4sGB91tKF3UFHLcKT7PM") catch unreachable;

pub const ENABLE_BPF_LOADER_SET_AUTHORITY_CHECKED_IDX =
    Pubkey.parseBase58String("HcW8ZjBezYYgvcbxNJwqv1t484Y2556qJsfNDWvJGZRH") catch unreachable;

pub const ENABLE_LOADER_V4 =
    Pubkey.parseBase58String("8Cb77yHjPWe9wuWUfXeh6iszFGCDGNCoFk3tprViYHNm") catch unreachable;

pub const RELAX_AUTHORITY_SIGNER_CHECK_FOR_LOOKUP_TABLE_CREATION =
    Pubkey.parseBase58String("FKAcEvNgSY79RpqsPNUV5gDyumopH4cEHqUxyfm8b8Ap") catch unreachable;

pub const DISABLE_ACCOUNT_LOADER_SPECIAL_CASE =
    Pubkey.parseBase58String("EQUMpNFr7Nacb1sva56xn1aLfBxppEoSBH8RRVdkcD1x") catch unreachable;

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
