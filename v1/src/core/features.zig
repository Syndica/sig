//! v1-only additions on top of the shared `features` namespace.
//!
//! `activationStateFromAccount` (with its helper `FeatureActivationState`)
//! is only consumed by v1 (from `replay/epoch_transitions.zig`); nothing
//! in the runtime tree references it, so it lives here rather than in
//! the shared runtime module.

const shared = @import("shared");
const sig = @import("../sig.zig");

const Pubkey = shared.core.Pubkey;

// Re-export the shared features namespace so `sig.core.features.*` in v1
// resolves through this file. Anything already exposed by
// `shared.core.features` stays reachable via these aliases.
pub const FEATURE_SET_ID = shared.core.features.FEATURE_SET_ID;
pub const ZonInfo = shared.core.features.ZonInfo;
pub const Status = shared.core.features.Status;
pub const all_features = shared.core.features.all_features;
pub const features = shared.core.features.features;
pub const Feature = shared.core.features.Feature;
pub const pubkey_map = shared.core.features.pubkey_map;
pub const status_map = shared.core.features.status_map;
pub const isKnownFeatureId = shared.core.features.isKnownFeatureId;
pub const Set = shared.core.features.Set;

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
