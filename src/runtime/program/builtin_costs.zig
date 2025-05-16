//! [agave] https://github.com/firedancer-io/agave/blob/403d23b809fc513e2c4b433125c127cf172281a2/builtins-default-costs/src/lib.rs

const std = @import("std");
const sig = @import("../../sig.zig");

const features = sig.runtime.features;
const programs = sig.runtime.program;

const Pubkey = sig.core.Pubkey;
const FeatureSet = sig.runtime.FeatureSet;

pub const TOTAL_COUNT_BUILTINS: usize = 12;
pub const BUILTIN_COSTS = initBuiltinCosts();
pub const MAYBE_BUILTIN_KEY = initMaybeBuiltinKey();

pub fn getMigrationFeatureId(index: usize) Pubkey {
    return MIGRATING_BUILTIN_COSTS[index][1].coreBpfMigrationFeature() orelse
        @panic("not a migrating builtin");
}

fn initBuiltinCosts() std.StaticStringMap(BuiltinCost) {
    @setEvalBranchQuota(10_000);
    const entries = MIGRATING_BUILTIN_COSTS ++ NON_MIGRATING_BUILTIN_COSTS;
    return std.StaticStringMap(BuiltinCost).initComptime(&entries);
}

fn initMaybeBuiltinKey() [256]bool {
    var table = [_]bool{false} ** 256;
    for (BUILTIN_COSTS.keys()) |key| table[key[0]] = true;
    return table;
}

pub const MIGRATING_BUILTIN_COSTS = [_]struct { []const u8, BuiltinCost }{
    .{
        &programs.stake.ID.data,
        .{
            .migrating = .{
                .native_cost = programs.stake.COMPUTE_UNITS,
                .core_bf_migration_feature = features.MIGRATE_STAKE_PROGRAM_TO_CORE_BPF,
                .position = 0,
            },
        },
    },
    .{
        &programs.config.ID.data,
        .{
            .migrating = .{
                .native_cost = programs.config.COMPUTE_UNITS,
                .core_bf_migration_feature = features.MIGRATE_CONFIG_PROGRAM_TO_CORE_BPF,
                .position = 1,
            },
        },
    },
    .{
        &programs.address_lookup_table.ID.data,
        .{
            .migrating = .{
                .native_cost = programs.address_lookup_table.COMPUTE_UNITS,
                .core_bf_migration_feature = features
                    .MIGRATE_ADDRESS_LOOKUP_TABLE_PROGRAM_TO_CORE_BPF,
                .position = 2,
            },
        },
    },
};

pub const NON_MIGRATING_BUILTIN_COSTS = [_]struct { []const u8, BuiltinCost }{
    .{
        &programs.vote.ID.data,
        .{ .not_migrating = programs.vote.COMPUTE_UNITS },
    },
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
        core_bf_migration_feature: Pubkey,
        position: usize,
    },
    not_migrating: u64,

    pub fn nativeCost(self: BuiltinCost) u64 {
        return switch (self) {
            .migrating => |m| m.native_cost,
            .not_migrating => |n| n,
        };
    }

    pub fn coreBpfMigrationFeature(self: BuiltinCost) ?Pubkey {
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

    pub fn hasMigrated(self: BuiltinCost, feature_set: *const FeatureSet) bool {
        return switch (self) {
            .migrating => |m| feature_set.active.contains(m.core_bf_migration_feature),
            .not_migrating => false,
        };
    }
};
