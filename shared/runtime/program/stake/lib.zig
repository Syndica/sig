const sig = @import("../../../lib.zig");

comptime {
    if (@import("builtin").is_test) {
        _ = @import("instruction.zig");
        _ = @import("state.zig");
    }
}

pub const state = @import("state.zig");
const instruction = @import("instruction.zig");

const Slot = sig.core.Slot;
const FeatureSet = sig.core.FeatureSet;
const Pubkey = sig.core.Pubkey;

pub const Instruction = instruction.Instruction;
pub const LockupArgs = instruction.LockupArgs;

pub const StakeStateV2 = state.StakeStateV2;

pub const ID: Pubkey = .parse("Stake11111111111111111111111111111111111111");

/// [agave] https://github.com/solana-program/stake/blob/a1c20c8033f29f6015a691325df433dcfeaf5cea/interface/src/error.rs#L14
pub const StakeError = enum(u32) {
    /// Not enough credits to redeem.
    no_credits_to_redeem,
    /// Lockup has not yet expired.
    lockup_in_force,
    /// Stake already deactivated.
    already_deactivated,
    /// One re-delegation permitted per epoch.
    too_soon_to_redelegate,
    /// Split amount is more than is staked.
    insufficient_stake,
    /// Stake account with transient stake cannot be merged.
    merge_transient_stake,
    /// Stake account merge failed due to different authority, lockups or state.
    merge_mismatch,
    /// Custodian address not present.
    custodian_missing,
    /// Custodian signature not present.
    custodian_signature_missing,
    /// Insufficient voting activity in the reference vote account.
    insufficient_reference_votes,
    /// Stake account is not delegated to the provided vote account.
    vote_address_mismatch,
    /// Stake account has not been delinquent for the minimum epochs required
    /// for deactivation.
    minimum_delinquent_epochs_for_deactivation_not_met,
    /// Delegation amount is less than the minimum.
    insufficient_delegation,
    /// Stake account with transient or inactive stake cannot be redelegated.
    redelegate_transient_or_inactive_stake,
    /// Stake redelegation to the same vote account is not permitted.
    redelegate_to_same_vote_account,
    /// Redelegated stake must be fully activated before deactivation.
    redelegated_stake_must_fully_activate_before_deactivation_is_permitted,
    /// Stake action is not permitted while the epoch rewards period is active.
    epoch_rewards_active,
};

pub fn getMinimumDelegation(slot: Slot, feature_set: *const FeatureSet) u64 {
    const LAMPORTS_PER_SOL: u64 = 1_000_000_000;
    return if (feature_set.active(.upgrade_bpf_stake_program_to_v5, slot))
        1 * LAMPORTS_PER_SOL
    else
        1;
}
