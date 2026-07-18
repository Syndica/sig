const shared = @import("shared");
const sig = @import("../sig.zig");

const Pubkey = sig.core.Pubkey;

// Re-export the shared features namespace so `sig.core.features.*` in v1
// resolves through this file. Anything already exposed by
// `shared.v2.features` stays reachable via these aliases.
pub const FEATURE_SET_ID = shared.v2.features.FEATURE_SET_ID;
pub const ZonInfo = shared.v2.features.ZonInfo;
pub const Status = shared.v2.features.Status;
pub const all_features = shared.v2.features.all_features;
pub const features = shared.v2.features.features;
pub const Feature = shared.v2.features.Feature;
pub const pubkey_map = shared.v2.features.pubkey_map;
pub const status_map = shared.v2.features.status_map;
pub const isKnownFeatureId = shared.v2.features.isKnownFeatureId;
pub const Set = shared.v2.features.Set;

const failing_allocator = shared.utils.allocators.failing.allocator(.{});

/// Returns the activation slot from a feature account.
/// - Returns `.pending` if the feature is pending activation (valid 9-byte account with null slot)
/// - Returns `.{ .activated = slot }` if already activated
/// - Returns `.invalid` if the account is not a valid feature account
pub const FeatureActivationState = union(enum) {
    pending,
    activated: u64,
    invalid,
};

/// Feature accounts must have at least 9 bytes of data (bincode-serialized ?u64)
/// An empty account (0 bytes) is not a valid pending feature
/// [solana-sdk] https://github.com/anza-xyz/solana-sdk/blob/54449336c03ae8a99bc37745ac97ab90a77eb24b/feature-gate-interface/src/state.rs#L37
pub fn activationStateFromAccount(owner: Pubkey, data: []const u8) !FeatureActivationState {
    if (data.len < 9 or
        !owner.equals(&sig.runtime.ids.FEATURE_PROGRAM_ID)) return .invalid;

    const maybe_slot = shared.bincode.readFromSlice(
        failing_allocator,
        ?u64,
        data[0..9],
        .{},
    ) catch @panic("failed to deserialize feature account data");

    return if (maybe_slot) |slot| .{ .activated = slot } else .pending;
}
