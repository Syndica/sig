//! Re-export the crypto public API from the sig-crypto library.
//! The canonical implementation lives in crypto/api.zig.

const crypto = @import("crypto");

pub const ed25519 = crypto.ed25519;
pub const Hash = crypto.Hash;
pub const Pubkey = crypto.Pubkey;
pub const Signature = crypto.Signature;
