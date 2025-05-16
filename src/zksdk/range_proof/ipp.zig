const std = @import("std");

const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;

/// Inner-Product (Sub)Proof
///
/// This proof allows the prover to convince the verifier that the inner
/// product of two secret vectors `a` and `b` equals a known scalar
/// `c = <a, b>`, without revealing the vectors themselves.
///
/// In the context of the Bulletproofs range proofs, the vectors `a` and `b`
/// are part of a larger commitment to a vector of bit values (used to
/// prove a value lies within a range), and the inner product argument is used
/// to reduce the size of the overall proof from linear to logarithmic in the
/// size of the range.
///
/// The protocol works by recursively folding the vectors `a` and `b` into
/// smaller vectors, committing to linear combinations at each step. This folding
/// is done in logarthmic rounds, and in each round the prover sends two group
/// elements (`Lᵢ` and `Rᵢ`) that allow the verifier to reconstruct the
/// final scalar product from the compressed vectors.
///
/// The security of the proof relies on the discrete logarithm harness assumption,
/// and the commitment sceheme used (Pedersen commitment) ensures that the
/// vectors remain hidden while the correctness of the inner product is verifiable.
///
/// - Bulletproofs paper (Bünz et al., 2018): https://eprint.iacr.org/2017/1066
/// - Dalek Bulletproofs implementation and docs: https://doc.dalek.rs/bulletproofs/
/// - Agave IPP implementation: https://github.com/anza-xyz/agave/blob/93699947720534741b2b4d9b6e1696d81e386dcc/zk-sdk/src/range_proof/inner_product.rs
pub const Proof = struct {
    L_vec: []const Ristretto255,
    R_vec: []const Ristretto255,
    a: Scalar,
    b: Scalar,
};
