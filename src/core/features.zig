const std = @import("std");
const sig = @import("../sig.zig");
const shared = @import("shared");

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

pub const FEATURE_SET_ID = shared.core.features.FEATURE_SET_ID;
pub const ZonInfo = shared.core.features.ZonInfo;
pub const all_features = shared.core.features.all_features;
pub const features = shared.core.features.features;
pub const Feature = shared.core.features.Feature;
pub const pubkey_map = shared.core.features.pubkey_map;
pub const isKnownFeatureId = shared.core.features.isKnownFeatureId;
pub const Set = shared.core.features.Set;

const FeatureActivationState = union(enum) {
    pending,
    activated: u64,
    invalid,
};

/// Returns the activation slot from a feature account.
/// - Returns `.pending` if the feature is pending activation (valid 9-byte account with null slot)
/// - Returns `.{ .activated = slot }` if already activated
/// - Returns `.invalid` if the account is not a valid feature account
pub fn activationStateFromAccount(account: sig.core.Account) !FeatureActivationState {
    if (account.data.len() < 9 or
        !account.owner.equals(&sig.runtime.ids.FEATURE_PROGRAM_ID)) return .invalid;

    var feature_bytes = [_]u8{0} ** 9;
    account.data.readAll(&feature_bytes);
    const maybe_slot = sig.bincode.readFromSlice(
        failing_allocator,
        ?u64,
        &feature_bytes,
        .{},
    ) catch @panic("failed to deserialize feature account data");

    return if (maybe_slot) |slot| .{ .activated = slot } else .pending;
}

test "full inflation enabled" {
    var feature_set: Set = .ALL_DISABLED;
    var new_feature_set: Set = .ALL_DISABLED;

    try std.testing.expect(!feature_set.fullInflationFeaturesEnabled(0, &new_feature_set));
    feature_set.setSlot(.full_inflation_mainnet_vote, 0);
    try std.testing.expect(!feature_set.fullInflationFeaturesEnabled(0, &new_feature_set));
    feature_set.setSlot(.full_inflation_mainnet_enable, 0);
    try std.testing.expect(!feature_set.fullInflationFeaturesEnabled(0, &new_feature_set));
    new_feature_set.setSlot(.full_inflation_mainnet_enable, 0);
    try std.testing.expect(feature_set.fullInflationFeaturesEnabled(0, &new_feature_set));

    feature_set = .ALL_DISABLED;
    new_feature_set = .ALL_DISABLED;
    try std.testing.expect(!feature_set.fullInflationFeaturesEnabled(0, &new_feature_set));
    feature_set.setSlot(.full_inflation_devnet_and_testnet, 0);
    try std.testing.expect(!feature_set.fullInflationFeaturesEnabled(0, &new_feature_set));
    new_feature_set.setSlot(.full_inflation_devnet_and_testnet, 0);
    try std.testing.expect(feature_set.fullInflationFeaturesEnabled(0, &new_feature_set));
}

test "runtime feature map excludes reverted entries" {
    const runtime_feature_name = "deprecate_rewards_sysvar";

    var found_runtime_in_all = false;
    var expected_runtime_count: usize = 0;
    var excluded_names: [all_features.len][]const u8 = undefined;
    var excluded_count: usize = 0;

    for (all_features) |feature| {
        if (std.mem.eql(u8, std.mem.sliceTo(feature.name, 0), runtime_feature_name)) {
            found_runtime_in_all = true;
            try std.testing.expect(feature.status != .reverted);
        }
        if (feature.status != .reverted) {
            expected_runtime_count += 1;
        } else {
            excluded_names[excluded_count] = std.mem.sliceTo(feature.name, 0);
            excluded_count += 1;
        }
    }

    try std.testing.expect(found_runtime_in_all);
    try std.testing.expectEqual(expected_runtime_count, features.len);

    inline for (@typeInfo(Feature).@"enum".fields) |field| {
        for (excluded_names[0..excluded_count]) |excluded_name| {
            try std.testing.expect(!std.mem.eql(u8, field.name, excluded_name));
        }
    }
}
