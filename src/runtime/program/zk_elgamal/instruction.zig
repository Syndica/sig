const sig = @import("../../../sig.zig");
const Pubkey = sig.core.Pubkey;

pub const ProofInstruction = enum(u8) {
    /// Close a zero-knowledge proof context state.
    ///
    /// Accounts expected by this instruction:
    ///   0. `[writable]` The proof context account to close
    ///   1. `[writable]` The destination account for lamports
    ///   2. `[signer]` The context account's owner
    ///
    /// Data expected by this instruction:
    ///   None
    ///
    close_context_state,

    /// Verify a zero-ciphertext proof.
    ///
    /// A zero-ciphertext proof certifies that an ElGamal ciphertext encrypts the value zero.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[]` (Optional) Account to read the proof from
    ///   1. `[writable]` (Optional) The proof context account
    ///   2. `[]` (Optional) The proof context account owner
    ///
    /// The instruction expects either:
    ///   i. `ZeroCiphertextProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    verify_zero_ciphertext,

    /// Verify a ciphertext-ciphertext equality proof.
    ///
    /// A ciphertext-ciphertext equality proof certifies that two ElGamal ciphertexts encrypt the
    /// same message.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[]` (Optional) Account to read the proof from
    ///   1. `[writable]` (Optional) The proof context account
    ///   2. `[]` (Optional) The proof context account owner
    ///
    /// The instruction expects either:
    ///   i. `CiphertextCiphertextEqualityProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    verify_ciphertext_ciphertext_equality,

    /// Verify a ciphertext-commitment equality proof.
    ///
    /// A ciphertext-commitment equality proof certifies that an ElGamal ciphertext and a Pedersen
    /// commitment encrypt/encode the same message.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[]` (Optional) Account to read the proof from
    ///   1. `[writable]` (Optional) The proof context account
    ///   2. `[]` (Optional) The proof context account owner
    ///
    /// The instruction expects either:
    ///   i. `CiphertextCommitmentEqualityProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    verify_ciphertext_commitment_equality,

    /// Verify a public key validity zero-knowledge proof.
    ///
    /// A public key validity proof certifies that an ElGamal public key is well-formed and the
    /// prover knows the corresponding secret key.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[]` (Optional) Account to read the proof from
    ///   1. `[writable]` (Optional) The proof context account
    ///   2. `[]` (Optional) The proof context account owner
    ///
    /// The instruction expects either:
    ///   i. `PubkeyValidityData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    verify_pubkey_validity,

    /// Verify a percentage-with-cap proof.
    ///
    /// A percentage-with-cap proof certifies that a tuple of Pedersen commitments satisfy a
    /// percentage relation.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[]` (Optional) Account to read the proof from
    ///   1. `[writable]` (Optional) The proof context account
    ///   2. `[]` (Optional) The proof context account owner
    ///
    /// The instruction expects either:
    ///   i. `PercentageWithCapProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    verify_percentage_with_cap,

    /// Verify a 64-bit batched range proof.
    ///
    /// A batched range proof is defined with respect to a sequence of Pedersen commitments `[c_1,
    /// ..., C_N]` and bit-lengths `[n_1, ..., n_N]`. It certifies that each commitment `C_i` is a
    /// commitment to a positive number of bit-length `n_i`. Batch verifying range proofs is more
    /// efficient than verifying independent range proofs on commitments `C_1, ..., C_N`
    /// separately.
    ///
    /// The bit-length of a batched range proof specifies the sum of the individual bit-lengths
    /// `n_1, ..., n_N`. For example, this instruction can be used to certify that two commitments
    /// `C_1` and `C_2` each hold positive 32-bit numbers.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[]` (Optional) Account to read the proof from
    ///   1. `[writable]` (Optional) The proof context account
    ///   2. `[]` (Optional) The proof context account owner
    ///
    /// The instruction expects either:
    ///   i. `BatchedRangeProofU64Data` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    verify_batched_range_proof_u64,

    /// Verify 128-bit batched range proof.
    ///
    /// The bit-length of a batched range proof specifies the sum of the individual bit-lengths
    /// `n_1, ..., n_N`. For example, this instruction can be used to certify that two commitments
    /// `C_1` and `C_2` each hold positive 64-bit numbers.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[]` (Optional) Account to read the proof from
    ///   1. `[writable]` (Optional) The proof context account
    ///   2. `[]` (Optional) The proof context account owner
    ///
    /// The instruction expects either:
    ///   i. `BatchedRangeProofU128Data` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    verify_batched_range_proof_u128,

    /// Verify 256-bit batched range proof.
    ///
    /// The bit-length of a batched range proof specifies the sum of the individual bit-lengths
    /// `n_1, ..., n_N`. For example, this instruction can be used to certify that four commitments
    /// `[C_1, C_2, C_3, C_4]` each hold positive 64-bit numbers.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[]` (Optional) Account to read the proof from
    ///   1. `[writable]` (Optional) The proof context account
    ///   2. `[]` (Optional) The proof context account owner
    ///
    /// The instruction expects either:
    ///   i. `BatchedRangeProofU256Data` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    verify_batched_range_proof_u256,

    /// Verify a grouped-ciphertext with 2 handles validity proof.
    ///
    /// A grouped-ciphertext validity proof certifies that a grouped ElGamal ciphertext is
    /// well-defined, i.e. the ciphertext can be decrypted by private keys associated with its
    /// decryption handles.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[]` (Optional) Account to read the proof from
    ///   1. `[writable]` (Optional) The proof context account
    ///   2. `[]` (Optional) The proof context account owner
    ///
    /// The instruction expects either:
    ///   i. `GroupedCiphertext2HandlesValidityProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    verify_grouped_ciphertext2_handles_validity,

    /// Verify a batched grouped-ciphertext with 2 handles validity proof.
    ///
    /// A batched grouped-ciphertext validity proof certifies the validity of two grouped ElGamal
    /// ciphertext that are encrypted using the same set of ElGamal public keys. A batched
    /// grouped-ciphertext validity proof is shorter and more efficient than two individual
    /// grouped-ciphertext validity proofs.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   0. `[]` (Optional) Account to read the proof from
    ///   1. `[writable]` (Optional) The proof context account
    ///   2. `[]` (Optional) The proof context account owner
    ///
    /// The instruction expects either:
    ///   i. `BatchedGroupedCiphertext2HandlesValidityProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    verify_batched_grouped_ciphertext2_handles_validity,

    /// Verify a grouped-ciphertext with 3 handles validity proof.
    ///
    /// A grouped-ciphertext validity proof certifies that a grouped ElGamal ciphertext is
    /// well-defined, i.e. the ciphertext can be decrypted by private keys associated with its
    /// decryption handles.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Creating a proof context account
    ///   0. `[]` (Optional) Account to read the proof from
    ///   1. `[writable]` The proof context account
    ///   2. `[]` The proof context account owner
    ///
    ///   * Otherwise
    ///     None
    ///
    /// The instruction expects either:
    ///   i. `GroupedCiphertext3HandlesValidityProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    verify_grouped_ciphertext3_handles_validity,

    /// Verify a batched grouped-ciphertext with 3 handles validity proof.
    ///
    /// A batched grouped-ciphertext validity proof certifies the validity of two grouped ElGamal
    /// ciphertext that are encrypted using the same set of ElGamal public keys. A batched
    /// grouped-ciphertext validity proof is shorter and more efficient than two individual
    /// grouped-ciphertext validity proofs.
    ///
    /// Accounts expected by this instruction:
    ///
    ///   * Creating a proof context account
    ///   0. `[]` (Optional) Account to read the proof from
    ///   1. `[writable]` The proof context account
    ///   2. `[]` The proof context account owner
    ///
    ///   * Otherwise
    ///     None
    ///
    /// The instruction expects either:
    ///   i. `BatchedGroupedCiphertext3HandlesValidityProofData` if proof is provided as instruction data
    ///   ii. `u32` byte offset if proof is provided as an account
    ///
    verify_batched_grouped_ciphertext3_handles_validity,
};

pub const ContextStateInfo = struct {
    state_account: Pubkey,
    state_authority: Pubkey,
};
