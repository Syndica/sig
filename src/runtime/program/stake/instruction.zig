const sig = @import("../../../sig.zig");
const state = @import("state.zig");

const bincode = sig.bincode;
const Pubkey = sig.core.Pubkey;
const Epoch = sig.core.Epoch;

const Authorized = state.StakeStateV2.Authorized;
const Lockup = state.StakeStateV2.Lockup;
const StakeAuthorize = state.StakeStateV2.StakeAuthorize;

/// [agave] https://github.com/solana-program/stake/blob/bb6932ed816eb39205102eee2e0cbc0cd511dcaa/interface/src/instruction.rs#L37
pub const Instruction = union(enum) {
    /// Initialize a stake with lockup and authorization information
    ///
    /// # Account references
    ///   0. `[WRITE]` Uninitialized stake account
    ///   1. `[]` Rent sysvar
    ///
    /// [`Authorized`] carries pubkeys that must sign staker transactions
    /// and withdrawer transactions; [`Lockup`] carries information about
    /// withdrawal restrictions.
    initialize: struct { Authorized, Lockup },

    /// Authorize a key to manage stake or withdrawal
    ///
    /// # Account references
    ///   0. `[WRITE]` Stake account to be updated
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` The stake or withdraw authority
    ///   3. Optional: `[SIGNER]` Lockup authority, if updating StakeAuthorize::Withdrawer before
    ///      lockup expiration
    authorize: struct { Pubkey, StakeAuthorize },

    /// Delegate a stake to a particular vote account
    ///
    /// # Account references
    ///   0. `[WRITE]` Initialized stake account to be delegated
    ///   1. `[]` Vote account to which this stake will be delegated
    ///   2. `[]` Clock sysvar
    ///   3. `[]` Stake history sysvar that carries stake warmup/cooldown history
    ///   4. `[]` Unused account, formerly the stake config
    ///   5. `[SIGNER]` Stake authority
    ///
    /// The entire balance of the staking account is staked. `DelegateStake`
    /// can be called multiple times, but re-delegation is delayed by one epoch.
    delegate_stake,

    /// Split `u64` tokens and stake off a stake account into another stake account.
    ///
    /// # Account references
    ///   0. `[WRITE]` Stake account to be split; must be in the Initialized or Stake state
    ///   1. `[WRITE]` Uninitialized stake account that will take the split-off amount
    ///   2. `[SIGNER]` Stake authority
    split: u64,

    /// Withdraw unstaked lamports from the stake account
    ///
    /// # Account references
    ///   0. `[WRITE]` Stake account from which to withdraw
    ///   1. `[WRITE]` Recipient account
    ///   2. `[]` Clock sysvar
    ///   3. `[]` Stake history sysvar that carries stake warmup/cooldown history
    ///   4. `[SIGNER]` Withdraw authority
    ///   5. Optional: `[SIGNER]` Lockup authority, if before lockup expiration
    ///
    /// The `u64` is the portion of the stake account balance to be withdrawn,
    /// must be `<= StakeAccount.lamports - staked_lamports`.
    withdraw: u64,

    /// Deactivates the stake in the account
    ///
    /// # Account references
    ///   0. `[WRITE]` Delegated stake account
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Stake authority
    deactivate,

    /// Set stake lockup
    ///
    /// If a lockup is not active, the withdraw authority may set a new lockup
    /// If a lockup is active, the lockup custodian may update the lockup parameters
    ///
    /// # Account references
    ///   0. `[WRITE]` Initialized stake account
    ///   1. `[SIGNER]` Lockup authority or withdraw authority
    set_lockup: LockupArgs,

    /// Merge two stake accounts.
    ///
    /// Both accounts must have identical lockup and authority keys. A merge
    /// is possible between two stakes in the following states with no additional
    /// conditions:
    ///
    /// * two deactivated stakes
    /// * an inactive stake into an activating stake during its activation epoch
    ///
    /// For the following cases, the voter pubkey and vote credits observed must match:
    ///
    /// * two activated stakes
    /// * two activating accounts that share an activation epoch, during the activation epoch
    ///
    /// All other combinations of stake states will fail to merge, including all
    /// "transient" states, where a stake is activating or deactivating with a
    /// non-zero effective stake.
    ///
    /// # Account references
    ///   0. `[WRITE]` Destination stake account for the merge
    ///   1. `[WRITE]` Source stake account for to merge.  This account will be drained
    ///   2. `[]` Clock sysvar
    ///   3. `[]` Stake history sysvar that carries stake warmup/cooldown history
    ///   4. `[SIGNER]` Stake authority
    merge,

    /// Authorize a key to manage stake or withdrawal with a derived key
    ///
    /// # Account references
    ///   0. `[WRITE]` Stake account to be updated
    ///   1. `[SIGNER]` Base key of stake or withdraw authority
    ///   2. `[]` Clock sysvar
    ///   3. Optional: `[SIGNER]` Lockup authority, if updating [`StakeAuthorize::Withdrawer`]
    ///      before lockup expiration
    authorize_with_seed: AuthorizeWithSeedArgs,

    /// Initialize a stake with authorization information
    ///
    /// This instruction is similar to `Initialize` except that the withdraw authority
    /// must be a signer, and no lockup is applied to the account.
    ///
    /// # Account references
    ///   0. `[WRITE]` Uninitialized stake account
    ///   1. `[]` Rent sysvar
    ///   2. `[]` The stake authority
    ///   3. `[SIGNER]` The withdraw authority
    initialize_checked,

    /// Authorize a key to manage stake or withdrawal
    ///
    /// This instruction behaves like `Authorize` with the additional requirement that the new
    /// stake or withdraw authority must also be a signer.
    ///
    /// # Account references
    ///   0. `[WRITE]` Stake account to be updated
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` The stake or withdraw authority
    ///   3. `[SIGNER]` The new stake or withdraw authority
    ///   4. Optional: `[SIGNER]` Lockup authority, if updating [`StakeAuthorize::Withdrawer`]
    ///      before lockup expiration
    authorize_checked: StakeAuthorize,

    /// Authorize a key to manage stake or withdrawal with a derived key
    ///
    /// This instruction behaves like `AuthorizeWithSeed` with the additional requirement that
    /// the new stake or withdraw authority must also be a signer.
    ///
    /// # Account references
    ///   0. `[WRITE]` Stake account to be updated
    ///   1. `[SIGNER]` Base key of stake or withdraw authority
    ///   2. `[]` Clock sysvar
    ///   3. `[SIGNER]` The new stake or withdraw authority
    ///   4. Optional: `[SIGNER]` Lockup authority, if updating [`StakeAuthorize::Withdrawer`]
    ///      before lockup expiration
    authorize_checked_with_seed: AuthorizeCheckedWithSeedArgs,

    /// Set stake lockup
    ///
    /// This instruction behaves like `SetLockup` with the additional requirement that
    /// the new lockup authority also be a signer.
    ///
    /// If a lockup is not active, the withdraw authority may set a new lockup
    /// If a lockup is active, the lockup custodian may update the lockup parameters
    ///
    /// # Account references
    ///   0. `[WRITE]` Initialized stake account
    ///   1. `[SIGNER]` Lockup authority or withdraw authority
    ///   2. Optional: `[SIGNER]` New lockup authority
    set_lockup_checked: LockupCheckedArgs,

    /// Get the minimum stake delegation, in lamports
    ///
    /// # Account references
    ///   None
    ///
    /// Returns the minimum delegation as a little-endian encoded u64 value.
    /// Programs can use the [`get_minimum_delegation()`] helper function to invoke and
    /// retrieve the return value for this instruction.
    ///
    /// [`get_minimum_delegation()`]: crate::tools::get_minimum_delegation
    get_minimum_delegation,

    /// Deactivate stake delegated to a vote account that has been delinquent for at least
    /// [`crate::MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION`] epochs.
    ///
    /// No signer is required for this instruction as it is a common good to deactivate abandoned
    /// stake.
    ///
    /// # Account references
    ///   0. `[WRITE]` Delegated stake account
    ///   1. `[]` Delinquent vote account for the delegated stake account
    ///   2. `[]` Reference vote account that has voted at least once in the last
    ///      [`crate::MINIMUM_DELINQUENT_EPOCHS_FOR_DEACTIVATION`] epochs
    deactivate_delinquent,

    /// Redelegate activated stake to another vote account.
    ///
    /// Upon success:
    ///   * the balance of the delegated stake account will be reduced to the undelegated amount in
    ///     the account (rent exempt minimum and any additional lamports not part of the delegation),
    ///     and scheduled for deactivation.
    ///   * the provided uninitialized stake account will receive the original balance of the
    ///     delegated stake account, minus the rent exempt minimum, and scheduled for activation to
    ///     the provided vote account. Any existing lamports in the uninitialized stake account
    ///     will also be included in the re-delegation.
    ///
    /// # Account references
    ///   0. `[WRITE]` Delegated stake account to be redelegated. The account must be fully
    ///      activated and carry a balance greater than or equal to the minimum delegation amount
    ///      plus rent exempt minimum
    ///   1. `[WRITE]` Uninitialized stake account that will hold the redelegated stake
    ///   2. `[]` Vote account to which this stake will be re-delegated
    ///   3. `[]` Unused account, formerly the stake config
    ///   4. `[SIGNER]` Stake authority
    ///
    /// deprecated since 2.1.0
    _redelegate,

    /// Move stake between accounts with the same authorities and lockups, using Staker authority.
    ///
    /// The source account must be fully active. If its entire delegation is moved, it immediately
    /// becomes inactive. Otherwise, at least the minimum delegation of active stake must remain.
    ///
    /// The destination account must be fully active or fully inactive. If it is active, it must
    /// be delegated to the same vote account as the source. If it is inactive, it
    /// immediately becomes active, and must contain at least the minimum delegation. The
    /// destination must be pre-funded with the rent-exempt reserve.
    ///
    /// This instruction only affects or moves active stake. Additional unstaked lamports are never
    /// moved, activated, or deactivated, and accounts are never deallocated.
    ///
    /// # Account references
    ///   0. `[WRITE]` Active source stake account
    ///   1. `[WRITE]` Active or inactive destination stake account
    ///   2. `[SIGNER]` Stake authority
    ///
    /// The `u64` is the portion of the stake to move, which may be the entire delegation
    move_stake: u64,

    /// Move unstaked lamports between accounts with the same authorities and lockups, using Staker
    /// authority.
    ///
    /// The source account must be fully active or fully inactive. The destination may be in any
    /// mergeable state (active, inactive, or activating, but not in warmup cooldown). Only lamports that
    /// are neither backing a delegation nor required for rent-exemption may be moved.
    ///
    /// # Account references
    ///   0. `[WRITE]` Active or inactive source stake account
    ///   1. `[WRITE]` Mergeable destination stake account
    ///   2. `[SIGNER]` Stake authority
    ///
    /// The `u64` is the portion of available lamports to move
    move_lamports: u64,
};

pub const LockupArgs = struct {
    unix_timestamp: ?i64 = null,
    epoch: ?Epoch = null,
    custodian: ?Pubkey = null,
};

pub const AuthorizeCheckedWithSeedArgs = struct {
    stake_authorize: StakeAuthorize,
    authority_seed: []const u8, // is there a fixed upper bound here?
    authority_owner: Pubkey,

    pub const @"!bincode-config:authority_seed" = bincode.utf8StringCodec([]const u8);
};

pub const AuthorizeWithSeedArgs = struct {
    new_authorized_pubkey: Pubkey,
    stake_authorize: StakeAuthorize,
    authority_seed: []const u8, // is there a fixed upper bound here?
    authority_owner: Pubkey,

    pub const @"!bincode-config:authority_seed" = bincode.utf8StringCodec([]const u8);
};

pub const LockupCheckedArgs = struct {
    unix_timestamp: ?i64 = null,
    epoch: ?Epoch = null,
};
