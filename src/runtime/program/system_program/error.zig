/// [agave] https://github.com/solana-program/system/blob/6185b40460c3e7bf8badf46626c60f4e246eb422/interface/src/error.rs#L12
pub const Error = error{
    /// An account with the same address already exists.
    AccountAlreadyInUse,
    /// Account does not have enough SOL to perform the operation.
    ResultWithNegativeLamports,
    /// Cannot assign account to this program id.
    InvalidProgramId,
    /// Cannot allocate account data of this length.
    InvalidAccountDataLength,
    /// Length of requested seed is too long.
    MaxSeedLengthExceeded,
    /// Provided address does not match addressed derived from seed.
    AddressWithSeedMismatch,
    /// Advancing stored nonce requires a populated RecentBlockhashes sysvar.
    NonceNoRecentBlockhashes,
    /// Stored nonce is still in recent_blockhashes.
    NonceBlockhashNotExpired,
    /// Specified nonce does not match stored nonce.
    NonceUnexpectedBlockhashValue,
};
