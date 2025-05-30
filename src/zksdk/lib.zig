pub const el_gamal = @import("el_gamal.zig");
pub const merlin = @import("merlin.zig");

pub const ElGamalCiphertext = el_gamal.Ciphertext;
pub const ElGamalKeypair = el_gamal.Keypair;
pub const ElGamalPubkey = el_gamal.Pubkey;
pub const pedersen = el_gamal.pedersen;
pub const Strobe128 = merlin.Strobe128;
pub const Transcript = merlin.Transcript;

// sigma proofs
const ciphertext_ciphertext = @import("sigma_proofs/ciphertext_ciphertext.zig");
const ciphertext_commitment = @import("sigma_proofs/ciphertext_commitment.zig");
const percentage = @import("sigma_proofs/percentage_with_cap.zig");
const pubkey_validity = @import("sigma_proofs/pubkey_validity.zig");
const zero_ciphertext = @import("sigma_proofs/zero_ciphertext.zig");

pub const CiphertextCiphertextEqualityData = ciphertext_ciphertext.Data;
pub const CiphertextCommitmentEqualityData = ciphertext_commitment.Data;
pub const PercentageWithCapProof = percentage.Proof;
pub const PubkeyValidityProofData = pubkey_validity.Data;
pub const ZeroCiphertextProofData = zero_ciphertext.Data;

// grouped ciphertext validity
const grouped_cipher_handles_2 = @import("sigma_proofs/grouped_ciphertext/handles_2.zig");
const grouped_cipher_handles_3 = @import("sigma_proofs/grouped_ciphertext/handles_3.zig");

pub const GroupedCiphertext2HandlesValidityProof = grouped_cipher_handles_2.Proof;
pub const GroupedCiphertext3HandlesValidityProof = grouped_cipher_handles_3.Proof;

// range proof
pub const bulletproofs = @import("range_proof/bulletproofs.zig");

pub const RangeProofU64Data = bulletproofs.Data(64);
pub const RangeProofU128Data = bulletproofs.Data(128);
pub const RangeProofU256Data = bulletproofs.Data(256);
