const sig = @import("../../../sig.zig");

/// Agave https://github.com/anza-xyz/solana-sdk/blob/4e30766b8d327f0191df6490e48d9ef521956495/vote-interface/src/error.rs#L11
///
/// Reasons the vote might have had an error
pub const VoteError = error{
    VoteTooOld,
    SlotsMismatch,
    SlotHashMismatch,
    EmptySlots,
    TimestampTooOld,
    TooSoonToReauthorize,
    LockoutConflict,
    NewVoteStateLockoutMismatch,
    SlotsNotOrdered,
    ConfirmationsNotOrdered,
    ZeroConfirmations,
    ConfirmationTooLarge,
    RootRollBack,
    ConfirmationRollBack,
    SlotSmallerThanRoot,
    TooManyVotes,
    VotesTooOldAllFiltered,
    RootOnDifferentFork,
    ActiveVoteAccountClose,
    CommissionUpdateTooLate,
    AssertionFailed,
};
