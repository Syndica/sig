const std = @import("std");
const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;
const VoteAuthorize = sig.runtime.program.vote_program.VoteAuthorize;
const VoteAuthorizeWithSeedArgs = sig.runtime.program.vote_program.VoteAuthorizeWithSeedArgs;
const VoteAuthorizeCheckedWithSeedArgs = sig.runtime.program.vote_program.VoteAuthorizeCheckedWithSeedArgs;

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/3426febe49bd701f54ea15ce11d539e277e2810e/vote-interface/src/instruction.rs#L26
pub const Instruction = union(enum) {
    /// Indexes into the `accounts` array
    /// for the `initialize_account` instruction.
    pub const InitializeAccountIndex = enum(u8) {
        Account = 0,
        RentSysvar = 1,
        ClockSysvar = 2,
        Signer = 3,

        pub fn index(self: InitializeAccountIndex) u8 {
            return @intFromEnum(self);
        }
    };
    /// Initialize a vote account
    ///
    /// # Account references
    ///   0. `[WRITE]` Uninitialized vote account
    ///   1. `[]` Rent sysvar
    ///   2. `[]` Clock sysvar
    ///   3. `[SIGNER]` New validator identity (node_pubkey)
    initialize_account: struct {
        node_pubkey: Pubkey,
        /// The vote authority keypair signs vote transactions. Can be the same as the identity account.
        authorized_voter: Pubkey,
        /// The authorized withdrawer keypair is used to withdraw funds from a vote account,
        /// including validator rewards. Only this keypair can access the funds.
        authorized_withdrawer: Pubkey,
        /// Commission is the percentage of network rewards kept by the validator.
        /// The rest is distributed to delegators based on their stake weight.
        commission: u8,
    },

    /// Authorize a key to send votes or issue a withdrawal
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the Pubkey for authorization
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Vote or withdraw authority
    authorize: struct {
        new_authorized_pubkey: Pubkey,
        vote_authorize: VoteAuthorize,
    },

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
    authorize_checked: VoteAuthorize,
};
