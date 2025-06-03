pub const el_gamal = @import("el_gamal.zig");
pub const pedersen = @import("pedersen.zig");
pub const merlin = @import("merlin.zig");

pub const ElGamalCiphertext = el_gamal.Ciphertext;
pub const ElGamalKeypair = el_gamal.Keypair;
pub const ElGamalPubkey = el_gamal.Pubkey;
pub const GroupedElGamalCiphertext = el_gamal.GroupedElGamalCiphertext;
pub const Strobe128 = merlin.Strobe128;
pub const Transcript = merlin.Transcript;

// sigma proofs
const ciphertext_ciphertext = @import("sigma_proofs/ciphertext_ciphertext.zig");
const ciphertext_commitment = @import("sigma_proofs/ciphertext_commitment.zig");
const percentage = @import("sigma_proofs/percentage_with_cap.zig");
const pubkey_validity = @import("sigma_proofs/pubkey_validity.zig");
const zero_ciphertext = @import("sigma_proofs/zero_ciphertext.zig");

pub const CiphertextCiphertextData = ciphertext_ciphertext.Data;
pub const CiphertextCommitmentData = ciphertext_commitment.Data;
pub const PercentageWithCapData = percentage.Data;
pub const PubkeyProofData = pubkey_validity.Data;
pub const ZeroCiphertextData = zero_ciphertext.Data;

// grouped ciphertext validity
const grouped_cipher_handles_2 = @import("sigma_proofs/grouped_ciphertext/handles_2.zig");
const grouped_cipher_handles_3 = @import("sigma_proofs/grouped_ciphertext/handles_3.zig");

pub const GroupedCiphertext2HandlesData = grouped_cipher_handles_2.Data;
pub const BatchedGroupedCiphertext2HandlesData = grouped_cipher_handles_2.BatchedData;
pub const GroupedCiphertext3HandlesData = grouped_cipher_handles_3.Data;
pub const BatchedGroupedCiphertext3HandlesData = grouped_cipher_handles_3.BatchedData;

// range proof
pub const bulletproofs = @import("range_proof/bulletproofs.zig");

pub const RangeProofU64Data = bulletproofs.Data(64);
pub const RangeProofU128Data = bulletproofs.Data(128);
pub const RangeProofU256Data = bulletproofs.Data(256);
