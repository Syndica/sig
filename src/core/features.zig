const sig = @import("../sig.zig");
const shared_features = @import("shared").core.features;

pub const NUM_FEATURES = shared_features.NUM_FEATURES;
pub const FEATURE_SET_ID = shared_features.FEATURE_SET_ID;
pub const Feature = shared_features.Feature;
pub const map = shared_features.map;
pub const Set = shared_features.Set;
pub const FeatureActivationState = shared_features.FeatureActivationState;

const failing_allocator = sig.utils.allocators.failing.allocator(.{});

/// Feature accounts must have at least 9 bytes of data (bincode-serialized ?u64)
/// An empty account (0 bytes) is not a valid pending feature
/// [solana-sdk] https://github.com/anza-xyz/solana-sdk/blob/54449336c03ae8a99bc37745ac97ab90a77eb24b/feature-gate-interface/src/state.rs#L37
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
