const std = @import("std");
const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/3426febe49bd701f54ea15ce11d539e277e2810e/vote-interface/src/instruction.rs#L26
pub const Instruction = union(enum) {
    /// Indexes into the `accounts` array
    /// for the `initialize_account` instruction.
    pub const InitializeAccountIndex = enum(u8) {
        Account = 0,
        RentSysvar = 1,
        ClockSysvar = 2,
        Signer = 3,
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
};
