const sig = @import("../../../sig.zig");
const InstructionError = sig.core.instruction.InstructionError;

/// Builtin return values occupy the upper 32 bits
const BUILTIN_BIT_SHIFT: usize = 32;

// TODO this should be an error set and not an enum.
pub const VoteError = enum {
    vote_too_old,
    slots_mismatch,
    slot_hash_mismatch,
    empty_slots,
    timestamp_too_old,
    too_soon_to_reauthorize,
    // TODO: figure out how to migrate these new errors
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

    pub fn toInstructionError(self: *const VoteError) InstructionError!void {
        const error_value = @intFromEnum(self.*);
        if (@as(usize, error_value) >> BUILTIN_BIT_SHIFT == 0) {
            // TODO Agave custom error takes an arguments.
            return InstructionError.Custom;
        } else {
            return InstructionError.InvalidError;
        }
    }
};
