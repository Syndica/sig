//! [agave] https://github.com/anza-xyz/agave/blob/v4.1.0-beta.3/builtins-default-costs/src/lib.rs

const std = @import("std");
const sig = @import("../../lib.zig");

const programs = sig.runtime.program;

const Feature = sig.core.features.Feature;

pub const TOTAL_COUNT_BUILTINS: usize = 9;
pub const BUILTIN_COSTS: std.StaticStringMap(BuiltinCost) = costs: {
    @setEvalBranchQuota(10_000);
    const entries = MIGRATING_BUILTIN_COSTS ++ NON_MIGRATING_BUILTIN_COSTS;
    break :costs .initComptime(&entries);
};
pub const MAYBE_BUILTIN_KEY = key: {
    var table = [_]bool{false} ** 256;
    for (BUILTIN_COSTS.keys()) |key| table[key[0]] = true;
    break :key table;
};

pub fn getMigrationFeatureId(index: usize) Feature {
    return MIGRATING_BUILTIN_COSTS[index][1].coreBpfMigrationFeature().?;
}

/// [SIMD-0387] The Vote program is NOT migrating to on-chain BPF, but the
/// proposal removes it from builtin program cost modeling once
/// `bls_pubkey_management_in_vote_account` activates. Re-using the
/// migration mechanism is how agave evicts vote from the builtin cost
/// table; see
/// [agave]
/// https://github.com/anza-xyz/agave/blob/v4.1.0-beta.3/builtins-default-costs/src/lib.rs#L94-L106
pub const MIGRATING_BUILTIN_COSTS = [_]struct { []const u8, BuiltinCost }{
    .{
        &programs.vote.ID.data,
        .{
            .migrating = .{
                .native_cost = programs.vote.COMPUTE_UNITS,
                .core_bf_migration_feature = .bls_pubkey_management_in_vote_account,
                .position = 0,
            },
        },
    },
};

pub const NON_MIGRATING_BUILTIN_COSTS = [_]struct { []const u8, BuiltinCost }{
    .{
        &programs.system.ID.data,
        .{ .not_migrating = programs.system.COMPUTE_UNITS },
    },
    .{
        &programs.compute_budget.ID.data,
        .{ .not_migrating = programs.compute_budget.COMPUTE_UNITS },
    },
    .{
        &programs.bpf_loader.v1.ID.data,
        .{ .not_migrating = programs.bpf_loader.v1.COMPUTE_UNITS },
    },
    .{
        &programs.bpf_loader.v2.ID.data,
        .{ .not_migrating = programs.bpf_loader.v2.COMPUTE_UNITS },
    },
    .{
        &programs.bpf_loader.v3.ID.data,
        .{ .not_migrating = programs.bpf_loader.v3.COMPUTE_UNITS },
    },
    .{
        &programs.bpf_loader.v4.ID.data,
        .{ .not_migrating = programs.bpf_loader.v4.COMPUTE_UNITS },
    },
    .{
        &programs.precompiles.secp256k1.ID.data,
        .{ .not_migrating = 0 },
    },
    .{
        &programs.precompiles.ed25519.ID.data,
        .{ .not_migrating = 0 },
    },
};

const BuiltinCost = union(enum(u8)) {
    migrating: struct {
        native_cost: u64,
        core_bf_migration_feature: Feature,
        position: usize,
    },
    not_migrating: u64,

    pub fn nativeCost(self: BuiltinCost) u64 {
        return switch (self) {
            .migrating => |m| m.native_cost,
            .not_migrating => |n| n,
        };
    }

    pub fn coreBpfMigrationFeature(self: BuiltinCost) ?Feature {
        return switch (self) {
            .migrating => |m| m.core_bf_migration_feature,
            .not_migrating => null,
        };
    }

    pub fn position(self: BuiltinCost) ?usize {
        return switch (self) {
            .migrating => |m| m.position,
            .not_migrating => null,
        };
    }
};
