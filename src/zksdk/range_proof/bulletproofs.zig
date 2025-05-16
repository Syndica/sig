//! Bulletproofs range-proof implementation over Curve25519 Ristretto points.
//!
//! Specifically implements non-interactive range proof aggregation
//! that is described in the original Bulletproofs
//! [paper](https://eprint.iacr.org/2017/1066) (Section 4.3).

const std = @import("std");
const sig = @import("../../sig.zig");
const InnerProductProof = @import("ipp.zig").Proof;

const el_gamal = sig.zksdk.el_gamal;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const Transcript = sig.zksdk.Transcript;

pub const Proof = struct {
    A: Ristretto255,
    S: Ristretto255,
    T_1: Ristretto255,
    T_2: Ristretto255,
    t_x: Scalar,
    t_x_blinding: Scalar,
    e_blinding: Scalar,
    ipp: InnerProductProof,
};

test "single rangeproof" {
    const commitment, const opening = el_gamal.pedersen.init(u64, 55);
    _ = commitment;
    _ = opening;

    var creation_transcript = Transcript.init("test");
    var verification_transcript = Transcript.init("test");

    _ = &creation_transcript;
    _ = &verification_transcript;
}
