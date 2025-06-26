const sig = @import("../../../sig.zig");

const Pubkey = sig.core.Pubkey;

pub const Status = enum(u64) {
    /// Program is in maintenance
    retracted,
    /// Program is ready to be executed
    deployed,
    /// Same as `Deployed`, but can not be retracted anymore
    finalized,
};

/// [agave] https://github.com/anza-xyz/solana-sdk/blob/c7c8c604991bf5d1e4441f32659546c84a17d92c/loader-v4-interface/src/state.rs#L19
pub const State = extern struct {
    /// Slot in which the program was last deployed, retracted or initialized.
    slot: u64,
    /// Address of signer which can send program management instructions when the status is not finalized.
    /// Otherwise a forwarding to the next version of the finalized program.
    authority_address_or_next_version: Pubkey,
    /// Deployment status.
    status: Status,
    // The raw program data follows this serialized structure in the
    // account's data.

    pub const PROGRAM_DATA_METADATA_SIZE = @sizeOf(State);
};