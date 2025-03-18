const sig = @import("../../../sig.zig");

/// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/error.rs#L11
///
/// Reasons the vote might have had an error
pub const VoteError = enum(u8) {
    vote_too_old,
    slots_mismatch,
    slot_hash_mismatch,
    empty_slots,
    timestamp_too_old,
    too_soon_to_reauthorize,
    lockout_conflict,
    new_vote_state_lockout_mismatch,
    slots_not_ordered,
    confirmations_not_ordered,
    zero_confirmations,
    confirmation_too_large,
    root_roll_back,
    confirmation_roll_back,
    slot_smaller_than_root,
    too_many_votes,
    votes_too_old_all_filtered,
    root_on_different_fork,
    active_vote_account_close,
    commission_update_too_late,
    assertion_failed,
};
