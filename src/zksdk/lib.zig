pub const el_gamal = @import("el_gamal.zig");
pub const merlin = @import("merlin.zig");

pub const ElGamalCiphertext = el_gamal.Ciphertext;
pub const ElGamalKeypair = el_gamal.Keypair;
pub const ElGamalPubkey = el_gamal.Pubkey;
pub const pedersen = el_gamal.pedersen;
pub const Strobe128 = merlin.Strobe128;
pub const Transcript = merlin.Transcript;

const zero_ciphertext = @import("sigma_proofs/zero_ciphertext.zig");
const ciphertext = @import("sigma_proofs/ciphertext_ciphertext.zig");
const percentage = @import("sigma_proofs/percentage_with_cap.zig");

pub const ZeroCiphertextProof = zero_ciphertext.ZeroCiphertextProof;
pub const CiphertextCiphertextEqualityProof = ciphertext.CiphertextCiphertextEqualityProof;
pub const PercentageWithCapProof = percentage.PercentageWithCapProof;
