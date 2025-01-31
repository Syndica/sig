const std = @import("std");
const sig = @import("../../sig.zig");

const Epoch = sig.core.Epoch;
const Hash = sig.core.Hash;
const Pubkey = sig.core.Pubkey;
const Slot = sig.core.Slot;

pub fn id() Pubkey {
    return sig.runtime.ids.VOTE_PROGRAM_ID;
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/instruction.rs#L24
pub const VoteProgramInstruction = union(enum) {
    /// Initialize a vote account
    ///
    /// # Account references
    ///   0. `[WRITE]` Uninitialized vote account
    ///   1. `[]` Rent sysvar
    ///   2. `[]` Clock sysvar
    ///   3. `[SIGNER]` New validator identity (node_pubkey)
    initialize_account: VoteInit,

    /// Authorize a key to send votes or issue a withdrawal
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the Pubkey for authorization
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Vote or withdraw authority
    authorize: struct { Pubkey, VoteAuthorize },

    /// A Vote instruction with recent votes
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to vote with
    ///   1. `[]` Slot hashes sysvar
    ///   2. `[]` Clock sysvar
    ///   3. `[SIGNER]` Vote authority
    vote: Vote,

    /// Withdraw some amount of funds
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to withdraw from
    ///   1. `[WRITE]` Recipient account
    ///   2. `[SIGNER]` Withdraw authority
    withdraw: u64,

    /// Update the vote account's validator identity (node_pubkey)
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the given authority public key
    ///   1. `[SIGNER]` New validator identity (node_pubkey)
    ///   2. `[SIGNER]` Withdraw authority
    update_validator_identity,

    /// Update the commission for the vote account
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated
    ///   1. `[SIGNER]` Withdraw authority
    update_commission: u8,

    /// A Vote instruction with recent votes
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to vote with
    ///   1. `[]` Slot hashes sysvar
    ///   2. `[]` Clock sysvar
    ///   3. `[SIGNER]` Vote authority
    vote_switch: struct { Vote, Hash },

    /// Authorize a key to send votes or issue a withdrawal
    ///
    /// This instruction behaves like `Authorize` with the additional requirement that the new vote
    /// or withdraw authority must also be a signer.
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the Pubkey for authorization
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Vote or withdraw authority
    ///   3. `[SIGNER]` New vote or withdraw authority
    authorize_checked: struct { VoteAuthorize },

    /// Update the onchain vote state for the signer.
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to vote with
    ///   1. `[SIGNER]` Vote authority
    update_vote_state: VoteStateUpdate,

    /// Update the onchain vote state for the signer along with a switching proof.
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to vote with
    ///   1. `[SIGNER]` Vote authority
    update_vote_state_switch: struct { VoteStateUpdate, Hash },

    /// Given that the current Voter or Withdrawer authority is a derived key,
    /// this instruction allows someone who can sign for that derived key's
    /// base key to authorize a new Voter or Withdrawer for a vote account.
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to be updated
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Base key of current Voter or Withdrawer authority's derived key
    authorize_with_seed: VoteAuthorizeWithSeedArgs,

    /// Given that the current Voter or Withdrawer authority is a derived key,
    /// this instruction allows someone who can sign for that derived key's
    /// base key to authorize a new Voter or Withdrawer for a vote account.
    ///
    /// This instruction behaves like `AuthorizeWithSeed` with the additional requirement
    /// that the new vote or withdraw authority must also be a signer.
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to be updated
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Base key of current Voter or Withdrawer authority's derived key
    ///   3. `[SIGNER]` New vote or withdraw authority
    authorize_checked_with_seed: VoteAuthorizeCheckedWithSeedArgs,

    /// Update the onchain vote state for the signer.
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to vote with
    ///   1. `[SIGNER]` Vote authority
    /// TODO: Check serde in agave
    /// #[serde(with = "serde_compact_vote_state_update")]
    compact_update_vote_state: VoteStateUpdate,

    /// Update the onchain vote state for the signer along with a switching proof.
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to vote with
    ///   1. `[SIGNER]` Vote authority
    compact_update_vote_state_switch: struct {
        // TODO: Check serde in agave
        // #[serde(with = "serde_compact_vote_state_update")]
        VoteStateUpdate,
        Hash,
    },

    /// Sync the onchain vote state with local tower
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to vote with
    ///   1. `[SIGNER]` Vote authority
    /// TODO: Check serde in agave
    /// #[serde(with = "serde_tower_sync")]
    tower_sync: TowerSync,

    /// Sync the onchain vote state with local tower along with a switching proof
    ///
    /// # Account references
    ///   0. `[Write]` Vote account to vote with
    ///   1. `[SIGNER]` Vote authority
    tower_sync_switch: struct {
        // TODO: Check serde in agave
        // #[serde(with = "serde_tower_sync")]
        TowerSync,
        Hash,
    },

    pub fn program_id(_: VoteProgramInstruction) Pubkey {
        return id();
    }
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/error.rs#L11
pub const VoteProgramError = error{
    /// vote already recorded or not in slot hashes history
    VoteTooOld,
    /// vote slots do not match bank history
    SlotsMismatch,
    /// vote hash does not match bank hash
    SlotHashMismatch,
    /// vote has no slots, invalid
    EmptySlots,
    /// vote timestamp not recent
    TimestampTooOld,
    /// authorized voter has already been changed this epoch
    TooSoonToReauthorize,
    // TODO: figure out how to migrate these new errors
    /// Old state had vote which should not have been popped off by vote in new state
    LockoutConflict,
    /// Proposed state had earlier slot which should have been popped off by later vote
    NewVoteStateLockoutMismatch,
    /// Vote slots are not ordered
    SlotsNotOrdered,
    /// Confirmations are not ordered
    ConfirmationsNotOrdered,
    /// Zero confirmations
    ZeroConfirmations,
    /// Confirmation exceeds limit
    ConfirmationTooLarge,
    /// Root rolled back
    RootRollBack,
    /// Confirmations for same vote were smaller in new proposed state
    ConfirmationRollBack,
    /// New state contained a vote slot smaller than the root
    SlotSmallerThanRoot,
    /// New state contained too many votes
    TooManyVotes,
    /// every slot in the vote was older than the SlotHashes history
    VotesTooOldAllFiltered,
    /// Proposed root is not in slot hashes
    RootOnDifferentFork,
    /// Cannot close vote account unless it stopped voting at least one full epoch ago
    ActiveVoteAccountClose,
    /// Cannot update commission at this point in the epoch
    CommissionUpdateTooLate,
    /// Assertion failed
    AssertionFailed,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/state/mod.rs#L59
pub const Vote = struct {
    /// A stack of votes starting with the oldest vote
    slots: []Slot,
    /// signature of the bank's state at the last slot
    hash: Hash,
    /// processing timestamp of last slot
    timestamp: ?i64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/state/mod.rs#L59
pub const Lockout = struct {
    slot: Slot,
    confirmation_count: u32,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/state/mod.rs#L142
pub const LandedVote = struct {
    // Latency is the difference in slot number between the slot that was voted on (lockout.slot) and the slot in
    // which the vote that added this Lockout landed.  For votes which were cast before versions of the validator
    // software which recorded vote latencies, latency is recorded as 0.
    latency: u8,
    lockout: Lockout,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/state/mod.rs#L173
pub const VoteStateUpdate = struct {
    /// The proposed tower
    lockouts: []Lockout, // VecDeque<Lockout>,
    /// The proposed root
    root: ?Slot,
    /// signature of the bank's state at the last slot
    hash: Hash,
    /// processing timestamp of last slot
    timestamp: ?i64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/state/mod.rs#L226
pub const TowerSync = struct {
    /// The proposed tower
    lockouts: []Lockout, // VecDeque<Lockout>,
    /// The proposed root
    root: ?Slot,
    /// signature of the bank's state at the last slot
    hash: Hash,
    /// processing timestamp of last slot
    timestamp: ?i64,
    /// the unique identifier for the chain up to and
    /// including this block. Does not require replaying
    /// in order to compute.
    block_id: Hash,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/state/mod.rs#L285
pub const VoteInit = struct {
    node_pubkey: Pubkey,
    authorized_voter: Pubkey,
    authorized_withdrawer: Pubkey,
    commission: u8,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/state/mod.rs#L293
pub const VoteAuthorize = enum {
    voter,
    withdrawer,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/state/mod.rs#L299
pub const VoteAuthorizeWithSeedArgs = struct {
    authorization_type: VoteAuthorize,
    current_authority_derived_key_owner: Pubkey,
    current_authority_derived_key_seed: []const u8,
    new_authority: Pubkey,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/state/mod.rs#L307
pub const VoteAuthorizeCheckedWithSeedArgs = struct {
    authorization_type: VoteAuthorize,
    current_authority_derived_key_owner: Pubkey,
    current_authority_derived_key_seed: []const u8,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/state/mod.rs#L316
pub const BlockTimestamp = struct {
    slot: Slot,
    timestamp: i64,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/state/mod.rs#L322
const MAX_ITEMS: usize = 32;

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/state/mod.rs#L326
pub fn CircBuf(comptime T: type) type {
    return struct {
        buf: [MAX_ITEMS]T,
        idx: usize,
        is_empty: bool,
    };
}

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/state/mod.rs#L395
pub const VoteState = struct {
    /// the node that votes in this account
    node_pubkey: Pubkey,

    /// the signer for withdrawals
    authorized_withdrawer: Pubkey,
    /// percentage (0-100) that represents what part of a rewards
    ///  payout should be given to this VoteAccount
    commission: u8,

    votes: []LandedVote, // VecDeque<LandedVote>,

    // This usually the last Lockout which was popped from self.votes.
    // However, it can be arbitrary slot, when being used inside Tower
    root_slot: ?Slot,

    /// the signer for vote transactions
    authorized_voters: AuthorizedVoters,

    /// history of prior authorized voters and the epochs for which
    /// they were set, the bottom end of the range is inclusive,
    /// the top of the range is exclusive
    prior_voters: CircBuf(struct { Pubkey, Epoch, Epoch }),

    /// history of how many credits earned by the end of each epoch
    ///  each tuple is (Epoch, credits, prev_credits)
    epoch_credits: []struct { Epoch, u64, u64 },

    /// most recent timestamp submitted with a vote
    last_timestamp: BlockTimestamp,
};

/// [agave] https://github.com/anza-xyz/agave/blob/faea52f338df8521864ab7ce97b120b2abb5ce13/sdk/program/src/vote/authorized_voters.rs#L12-L14
pub const AuthorizedVoters = struct {
    authorized_voters: std.AutoArrayHashMap(Epoch, Pubkey), // BTreeMap<Epoch, Pubkey>,
};
