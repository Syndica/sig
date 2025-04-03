const std = @import("std");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

pub const LIFT_CPI_CALLER_RESTRICTION =
    Pubkey.parseBase58String("HcW8ZjBezYYgvcbxNJwqv1t484Y2556qJsfNDWvJGZRH") catch unreachable;

pub const REMOVE_ACCOUNTS_EXECUTABLE_FLAG_CHECKS =
    Pubkey.parseBase58String("FfgtauHUWKeXTzjXkua9Px4tNGBFHKZ9WaigM5VbbzFx") catch unreachable;

pub const ENABLE_BPF_LOADER_SET_AUTHORITY_CHECKED_IDX =
    Pubkey.parseBase58String("HcW8ZjBezYYgvcbxNJwqv1t484Y2556qJsfNDWvJGZRH") catch unreachable;

pub const ENABLE_LOADER_V4 =
    Pubkey.parseBase58String("8Cb77yHjPWe9wuWUfXeh6iszFGCDGNCoFk3tprViYHNm") catch unreachable;

pub const RELAX_AUTHORITY_SIGNER_CHECK_FOR_LOOKUP_TABLE_CREATION =
    Pubkey.parseBase58String("FKAcEvNgSY79RpqsPNUV5gDyumopH4cEHqUxyfm8b8Ap") catch unreachable;

pub const ALLOW_COMMISSION_DECREASE_AT_ANY_TIME =
    Pubkey.parseBase58String("5x3825XS7M2A3Ekbn5VGGkvFoAg5qrRWkTrY4bARP1GL") catch unreachable;

pub const COMMISSION_UPDATES_ONLY_ALLOWED_IN_FIRST_HALF_OF_EPOCH =
    Pubkey.parseBase58String("noRuG2kzACwgaY7TVmLRnUNPLKNVQE1fb7X55YWBehp") catch unreachable;

pub const DEPRECATE_LEGACY_VOTE_IXS =
    Pubkey.parseBase58String("depVvnQ2UysGrhwdiwU42tCadZL8GcBb1i2GYhMopQv") catch unreachable;

pub const ENABLE_TOWER_SYNC_IX =
    Pubkey.parseBase58String("tSynMCspg4xFiCj1v3TDb4c7crMR5tSBhLz4sF7rrNA") catch unreachable;

pub const BPF_ACCOUNT_DATA_DIRECT_MAPPING =
    Pubkey.parseBase58String("AjX3A4Nv2rzUuATEUWLP4rrBaBropyUnHxEvFDj1dKbx") catch unreachable;

pub const ENABLE_POSEIDON_SYSCALL =
    Pubkey.parseBase58String("FL9RsQA6TVUoh5xJQ9d936RHSebA1NLQqe3Zv9sXZRpr") catch unreachable;

pub const DISABLE_DEPLOY_OF_ALLOC_FREE_SYSCALL =
    Pubkey.parseBase58String("79HWsX9rpnnJBPcdNURVqygpMAfxdrAirzAGAVmf92im") catch unreachable;

/// `FeatureSet` holds the set of currently active and inactive features
///
/// TODO: add features
///
/// [agave] https://github.com/anza-xyz/agave/blob/8db563d3bba4d03edf0eb2737fba87f394c32b64/sdk/feature-set/src/lib.rs#L1188
pub const FeatureSet = struct {
    active: std.AutoArrayHashMapUnmanaged(Pubkey, Slot),

    pub const EMPTY: FeatureSet = .{ .active = .{} };

    pub fn deinit(self: FeatureSet, allocator: std.mem.Allocator) void {
        var active_ = self.active;
        active_.deinit(allocator);
    }
};
