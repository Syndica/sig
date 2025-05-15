pub const el_gamal = @import("el_gamal.zig");
pub const merlin = @import("merlin.zig");
pub const pedersen = el_gamal.pedersen;

const sigma_proofs = @import("sigma_proofs/lib.zig");
pub const ZeroCiphertextProof = sigma_proofs.ZeroCiphertextProof;
pub const CiphertextCiphertextEqualityProof = sigma_proofs.CiphertextCiphertextEqualityProof;

pub const ElGamalKeypair = el_gamal.Keypair;
pub const ElGamalPubkey = el_gamal.Pubkey;
pub const ElGamalCiphertext = el_gamal.Ciphertext;
pub const Strobe128 = merlin.Strobe128;
pub const Transcript = merlin.Transcript;
