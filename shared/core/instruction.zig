const Pubkey = @import("pubkey.zig").Pubkey;

pub const InstructionAccount = struct {
    /// An account's public key
    pubkey: Pubkey,
    /// True if account must sign the transaction
    is_signer: bool,
    /// True if the account is mutable
    is_writable: bool,
};
