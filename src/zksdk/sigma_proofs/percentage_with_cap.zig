const std = @import("std");
const sig = @import("../../sig.zig");

const Edwards25519 = std.crypto.ecc.Edwards25519;
const el_gamal = sig.zksdk.el_gamal;
const pedersen = el_gamal.pedersen;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const Transcript = sig.zksdk.Transcript;
const weak_mul = sig.vm.syscalls.ecc.weak_mul;

pub const PercentageWithCapProof = struct {
    max_proof: MaxProof,
    equality_proof: EqualityProof,

    /// TODO: simplify params to take in ciphertexts instead of commitment/opening pair
    pub fn init(
        percentage_commitment: *const pedersen.Commitment,
        percentage_opening: *const pedersen.Opening,
        percentage_amount: u64,
        delta_commitment: *const pedersen.Commitment,
        delta_opening: *const pedersen.Opening,
        delta_amount: u64,
        claimed_commitment: *const pedersen.Commitment,
        claimed_opening: *const pedersen.Opening,
        max_value: u64,
        transcript: *Transcript,
    ) PercentageWithCapProof {
        transcript.appendDomSep("percentage-with-cap-proof");

        var transcript_percentage_above_max = transcript.*;
        var transcript_percentage_below_max = transcript.*;

        const proof_above_max = createProofAboveMax(
            percentage_opening,
            delta_commitment,
            claimed_commitment,
            &transcript_percentage_above_max,
        );

        const proof_below_max = createProofBelowMax(
            percentage_commitment,
            delta_opening,
            delta_amount,
            claimed_opening,
            max_value,
            &transcript_percentage_below_max,
        );

        // TODO: do these really need to be made constant time? check agave impl.
        // not sure if these init functions are actually exposed to SVM.

        // Chooses between `proof_below_max` and `proof_above_max` depending
        // on whether the percentage amount is above the max amount.
        const below_max = percentage_amount <= max_value;

        const max_proof: MaxProof = if (below_max)
            proof_below_max.max_proof
        else
            proof_above_max.max_proof;

        const equality_proof: EqualityProof = if (below_max)
            proof_below_max.equality_proof
        else
            proof_above_max.equality_proof;

        transcript.appendPoint("Y_max_proof", max_proof.Y_max_proof);
        transcript.appendPoint("Y_delta", equality_proof.Y_delta);
        transcript.appendPoint("Y_claimed", equality_proof.Y_claimed);

        _ = transcript.challengeScalar("c");
        _ = transcript.challengeScalar("w");

        return .{
            .max_proof = max_proof,
            .equality_proof = equality_proof,
        };
    }

    fn createProofAboveMax(
        percentage_opening: *const pedersen.Opening,
        delta_commitment: *const pedersen.Commitment,
        claimed_commitment: *const pedersen.Commitment,
        transcript: *Transcript,
    ) PercentageWithCapProof {
        const C_delta = delta_commitment.point;
        const C_claimed = claimed_commitment.point;

        const z_x = Scalar.random();
        const z_delta = Scalar.random();
        const z_claimed = Scalar.random();
        const c_equality = Scalar.random();

        const Y_delta = weak_mul.mulMulti(3, .{
            el_gamal.G.p,
            el_gamal.H.p,
            C_delta.p,
        }, .{
            z_x.toBytes(),
            z_delta.toBytes(),
            Edwards25519.scalar.neg(c_equality.toBytes()),
        });

        const Y_claimed = weak_mul.mulMulti(3, .{
            el_gamal.G.p,
            el_gamal.H.p,
            C_claimed.p,
        }, .{
            z_x.toBytes(),
            z_claimed.toBytes(),
            Edwards25519.scalar.neg(c_equality.toBytes()),
        });

        const equality_proof: EqualityProof = .{
            .Y_delta = .{ .p = Y_delta },
            .Y_claimed = .{ .p = Y_claimed },
            .z_x = z_x,
            .z_delta = z_delta,
            .z_claimed = z_claimed,
        };

        const r_percentage = percentage_opening.scalar;

        const y_max_proof = Scalar.random();
        // Scalar.random() cannot return zero, and H isn't an identity.
        const Y_max_proof = el_gamal.H.mul(y_max_proof.toBytes()) catch unreachable;

        transcript.appendPoint("Y_max_proof", Y_max_proof);
        transcript.appendPoint("Y_delta", .{ .p = Y_delta });
        transcript.appendPoint("Y_claimed", .{ .p = Y_claimed });

        const c = transcript.challengeScalar("c");
        const c_max_proof = Edwards25519.scalar.sub(c, c_equality.toBytes());

        _ = transcript.challengeScalar("w");

        const z_max_proof = Scalar.fromBytes(c_max_proof).mul(r_percentage).add(y_max_proof);

        const max_proof: MaxProof = .{
            .Y_max_proof = Y_max_proof,
            .z_max_proof = z_max_proof,
            .c_max_proof = Scalar.fromBytes(c_max_proof),
        };

        return .{
            .max_proof = max_proof,
            .equality_proof = equality_proof,
        };
    }

    fn createProofBelowMax(
        percentage_commitment: *const pedersen.Commitment,
        delta_opening: *const pedersen.Opening,
        delta_amount: u64,
        claimed_opening: *const pedersen.Opening,
        max_value: u64,
        transcript: *Transcript,
    ) PercentageWithCapProof {
        const m = el_gamal.scalarFromInt(u64, max_value);
        const C_percentage = percentage_commitment.point;

        const z_max_proof = Scalar.random();
        const c_max_proof = Scalar.random();

        const Y_max_proof = weak_mul.mulMulti(3, .{
            el_gamal.H.p,
            C_percentage.p,
            el_gamal.G.p,
        }, .{
            z_max_proof.toBytes(),
            Edwards25519.scalar.neg(c_max_proof.toBytes()),
            c_max_proof.mul(m).toBytes(),
        });

        const max_proof: MaxProof = .{
            .Y_max_proof = .{ .p = Y_max_proof },
            .z_max_proof = z_max_proof,
            .c_max_proof = c_max_proof,
        };

        const x = el_gamal.scalarFromInt(u64, delta_amount);

        const r_delta = delta_opening.scalar;
        const r_claimed = claimed_opening.scalar;

        const y_x = Scalar.random();
        const y_delta = Scalar.random();
        const y_claimed = Scalar.random();

        const Y_delta = weak_mul.mulMulti(2, .{
            el_gamal.G.p,
            el_gamal.H.p,
        }, .{
            y_x.toBytes(),
            y_delta.toBytes(),
        });

        const Y_claimed = weak_mul.mulMulti(2, .{
            el_gamal.G.p,
            el_gamal.H.p,
        }, .{
            y_x.toBytes(),
            y_claimed.toBytes(),
        });

        transcript.appendPoint("Y_max_proof", .{ .p = Y_max_proof });
        transcript.appendPoint("Y_delta", .{ .p = Y_delta });
        transcript.appendPoint("Y_claimed", .{ .p = Y_claimed });

        const c = transcript.challengeScalar("c");
        const c_equality = Scalar.fromBytes(Edwards25519.scalar.sub(c, c_max_proof.toBytes()));

        _ = transcript.challengeScalar("w");

        const z_x = c_equality.mul(x).add(y_x);
        const z_delta = c_equality.mul(r_delta).add(y_delta);
        const z_claimed = c_equality.mul(r_claimed).add(y_claimed);

        const equality_proof: EqualityProof = .{
            .Y_delta = .{ .p = Y_delta },
            .Y_claimed = .{ .p = Y_claimed },
            .z_x = z_x,
            .z_delta = z_delta,
            .z_claimed = z_claimed,
        };

        return .{
            .max_proof = max_proof,
            .equality_proof = equality_proof,
        };
    }

    pub fn verify(
        self: PercentageWithCapProof,
        percentage_commitment: *const pedersen.Commitment,
        delta_commitment: *const pedersen.Commitment,
        claimed_commitment: *const pedersen.Commitment,
        max_value: u64,
        transcript: *Transcript,
    ) !void {
        transcript.appendDomSep("percentage-with-cap-proof");

        const m = el_gamal.scalarFromInt(u64, max_value);

        const C_max = percentage_commitment.point;
        const C_delta = delta_commitment.point;
        const C_claimed = claimed_commitment.point;

        try transcript.validateAndAppendPoint("Y_max_proof", self.max_proof.Y_max_proof);
        try transcript.validateAndAppendPoint("Y_delta", self.equality_proof.Y_delta);
        try transcript.validateAndAppendPoint("Y_claimed", self.equality_proof.Y_claimed);

        const Y_max = self.max_proof.Y_max_proof;
        const z_max = self.max_proof.z_max_proof;

        const Y_delta_real = self.equality_proof.Y_delta;
        const Y_claimed = self.equality_proof.Y_claimed;

        const z_x = self.equality_proof.z_x;
        const z_delta_real = self.equality_proof.z_delta;
        const z_claimed = self.equality_proof.z_claimed;

        const c = transcript.challengeScalar("c");
        const c_max_proof = self.max_proof.c_max_proof;
        const c_equality = Edwards25519.scalar.sub(c, c_max_proof.toBytes());

        transcript.appendScalar("z_max", z_max);
        transcript.appendScalar("z_x", z_x);
        transcript.appendScalar("z_delta_real", z_delta_real);
        transcript.appendScalar("z_claimed", z_claimed);

        const w = Scalar.fromBytes(transcript.challengeScalar("w"));
        const ww = w.mul(w);

        //     We store points and scalars in the following arrays:

        //         points  scalars
        //     0   G        c_max * m - (w + ww) z_x
        //     1   H        z_max - (w z_delta + ww z_claimed)
        //     2   C_max   -c_max
        //     3   Y_delta  w
        //     4   C_delta  w c_eq
        //     5   Y_claim  ww
        //     6   C_claim  ww c_eq
        //    ------------------------ MSM
        //         Y_max

        // c_max * m - (w + ww) * z_x
        const g = g: {
            const a = ww.add(w);
            const b = a.mul(z_x).toBytes();
            break :g Edwards25519.scalar.sub(m.mul(c_max_proof).toBytes(), b);
        };

        // z_max - (w * z_delta + ww * z_claimed)
        const h = h: {
            const a = w.mul(z_delta_real);
            const b = ww.mul(z_claimed).add(a);
            break :h Edwards25519.scalar.sub(z_max.toBytes(), b.toBytes());
        };

        const check = weak_mul.mulMulti(7, .{
            el_gamal.G.p,
            el_gamal.H.p,
            C_max.p,
            Y_delta_real.p,
            C_delta.p,
            Y_claimed.p,
            C_claimed.p,
        }, .{
            g, // c_max * m - (w + ww) z_x
            h, // z_max - (w z_delta + ww z_claimed)
            Edwards25519.scalar.neg(c_max_proof.toBytes()), // -c_max
            w.toBytes(), // w
            w.mul(Scalar.fromBytes(c_equality)).toBytes(), // w * c_eq
            ww.toBytes(), // ww
            ww.mul(Scalar.fromBytes(c_equality)).toBytes(), // ww * c_eq
        });

        if (!Y_max.equivalent(.{ .p = check })) {
            return error.AlgebraicRelation;
        }
    }

    pub fn fromBytes(bytes: [256]u8) !PercentageWithCapProof {
        const Y_max_proof = try Ristretto255.fromBytes(bytes[0..32].*);
        const z_max_proof = Scalar.fromBytes(bytes[32..64].*);
        const c_max_proof = Scalar.fromBytes(bytes[64..96].*);
        try Edwards25519.scalar.rejectNonCanonical(z_max_proof.toBytes());
        try Edwards25519.scalar.rejectNonCanonical(c_max_proof.toBytes());

        const Y_delta = try Ristretto255.fromBytes(bytes[96..128].*);
        const Y_claimed = try Ristretto255.fromBytes(bytes[128..160].*);

        const z_x = Scalar.fromBytes(bytes[160..192].*);
        const z_delta = Scalar.fromBytes(bytes[192..224].*);
        const z_claimed = Scalar.fromBytes(bytes[224..256].*);
        try Edwards25519.scalar.rejectNonCanonical(z_x.toBytes());
        try Edwards25519.scalar.rejectNonCanonical(z_delta.toBytes());
        try Edwards25519.scalar.rejectNonCanonical(z_claimed.toBytes());

        return .{
            .max_proof = .{
                .Y_max_proof = Y_max_proof,
                .z_max_proof = z_max_proof,
                .c_max_proof = c_max_proof,
            },
            .equality_proof = .{
                .Y_delta = Y_delta,
                .Y_claimed = Y_claimed,
                .z_x = z_x,
                .z_delta = z_delta,
                .z_claimed = z_claimed,
            },
        };
    }

    pub fn fromBase64(string: []const u8) !PercentageWithCapProof {
        const base64 = std.base64.standard;
        var buffer: [256]u8 = .{0} ** 256;
        const decoded_length = try base64.Decoder.calcSizeForSlice(string);
        try std.base64.standard.Decoder.decode(
            buffer[0..decoded_length],
            string,
        );
        return fromBytes(buffer);
    }
};

/// The proof certifies that a Pedersen commitment encodes the maximum cap bound.
const MaxProof = struct {
    Y_max_proof: Ristretto255,
    z_max_proof: Scalar,
    c_max_proof: Scalar,
};

/// The proof certifies that the "real" delta value commitment and the "claimed" delta value
/// commitment encode the same message.
const EqualityProof = struct {
    Y_delta: Ristretto255,
    Y_claimed: Ristretto255,
    z_x: Scalar,
    z_delta: Scalar,
    z_claimed: Scalar,
};

test "above max proof" {
    const transfer_amount: u64 = 55;
    const max_value: u64 = 3;

    const percentage_rate: u64 = 555; // 5.55%
    const percentage_amount: u64 = 4;
    const delta: u64 = 9475; // (4 * 1000) - (55 * 555)

    const transfer_commitment, const transfer_opening = pedersen.init(u64, transfer_amount);
    const percentage_commitment, const percentage_opening = pedersen.init(u64, max_value);

    const scalar_rate = el_gamal.scalarFromInt(u64, percentage_rate);
    const constant_scalar = el_gamal.scalarFromInt(u64, 10_000);

    const delta_commitment: pedersen.Commitment = d: {
        const a = try percentage_commitment.point.mul(constant_scalar.toBytes());
        const b = a.p.sub(transfer_commitment.point.p);
        break :d .{ .point = .{ .p = try b.mul(scalar_rate.toBytes()) } };
    };
    const delta_opening: pedersen.Opening = d: {
        const a = percentage_opening.scalar.mul(constant_scalar);
        const b = Edwards25519.scalar.sub(a.toBytes(), transfer_opening.scalar.toBytes());
        break :d .{ .scalar = Scalar.fromBytes(b).mul(scalar_rate) };
    };

    const claimed_commitment, const claimed_opening = pedersen.init(u64, 0);

    var prover_transcript = Transcript.init("test");
    var verifier_transcript = Transcript.init("test");

    var proof = PercentageWithCapProof.init(
        &percentage_commitment,
        &percentage_opening,
        percentage_amount,
        &delta_commitment,
        &delta_opening,
        delta,
        &claimed_commitment,
        &claimed_opening,
        max_value,
        &prover_transcript,
    );

    try proof.verify(
        &percentage_commitment,
        &delta_commitment,
        &claimed_commitment,
        max_value,
        &verifier_transcript,
    );
}

test "below max proof" {
    const transfer_amount: u64 = 1;
    const max_value: u64 = 3;

    const percentage_rate: u64 = 400;
    const percentage_amount: u64 = 1;
    const delta: u64 = 9600;

    const transfer_commitment, const transfer_opening = pedersen.init(u64, transfer_amount);
    const percentage_commitment, const percentage_opening = pedersen.init(u64, percentage_amount);

    const scalar_rate = el_gamal.scalarFromInt(u64, percentage_rate);
    const constant_scalar = el_gamal.scalarFromInt(u64, 10_000);

    const delta_commitment: pedersen.Commitment = d: {
        const a = try percentage_commitment.point.mul(constant_scalar.toBytes());
        const b = try transfer_commitment.point.mul(scalar_rate.toBytes());
        break :d .{ .point = .{ .p = a.p.sub(b.p) } };
    };

    const delta_opening: pedersen.Opening = d: {
        const a = percentage_opening.scalar.mul(constant_scalar);
        const b = transfer_opening.scalar.mul(scalar_rate);
        break :d .{ .scalar = Scalar.fromBytes(Edwards25519.scalar.sub(a.toBytes(), b.toBytes())) };
    };

    const claimed_commitment, const claimed_opening = pedersen.init(u64, delta);

    {
        const a = try el_gamal.H.mul(delta_opening.scalar.toBytes());
        const b: Ristretto255 = .{ .p = delta_commitment.point.p.sub(a.p) };

        const c = try el_gamal.H.mul(claimed_opening.scalar.toBytes());
        const d: Ristretto255 = .{ .p = claimed_commitment.point.p.sub(c.p) };

        try std.testing.expect(b.equivalent(d));
    }

    var prover_transcript = Transcript.init("test");
    var verifier_transcript = Transcript.init("test");

    var proof = PercentageWithCapProof.init(
        &percentage_commitment,
        &percentage_opening,
        percentage_amount,
        &delta_commitment,
        &delta_opening,
        delta,
        &claimed_commitment,
        &claimed_opening,
        max_value,
        &prover_transcript,
    );

    try proof.verify(
        &percentage_commitment,
        &delta_commitment,
        &claimed_commitment,
        max_value,
        &verifier_transcript,
    );
}

test "is zero" {
    const transfer_amount: u64 = 100;
    const max_value: u64 = 3;

    const percentage_rate: u64 = 100; // 1.00%
    const percentage_amount: u64 = 1;
    const delta: u64 = 0; // (1 * 10_000) - (100 * 100)

    const transfer_commitment, const transfer_opening = pedersen.init(u64, transfer_amount);
    const percentage_commitment, const percentage_opening = pedersen.init(u64, percentage_amount);

    const scalar_rate = el_gamal.scalarFromInt(u64, percentage_rate);
    const constant_scalar = el_gamal.scalarFromInt(u64, 10_000);

    const delta_commitment: pedersen.Commitment = d: {
        const a = try percentage_commitment.point.mul(constant_scalar.toBytes());
        const b = try transfer_commitment.point.mul(scalar_rate.toBytes());
        break :d .{ .point = .{ .p = a.p.sub(b.p) } };
    };

    const delta_opening: pedersen.Opening = d: {
        const a = percentage_opening.scalar.mul(constant_scalar);
        const b = transfer_opening.scalar.mul(scalar_rate);
        break :d .{ .scalar = Scalar.fromBytes(Edwards25519.scalar.sub(a.toBytes(), b.toBytes())) };
    };
    const claimed_commitment, const claimed_opening = pedersen.init(u64, delta);

    var prover_transcript = Transcript.init("test");
    var verifier_transcript = Transcript.init("test");

    var proof = PercentageWithCapProof.init(
        &percentage_commitment,
        &percentage_opening,
        percentage_amount,
        &delta_commitment,
        &delta_opening,
        delta,
        &claimed_commitment,
        &claimed_opening,
        max_value,
        &prover_transcript,
    );

    try proof.verify(
        &percentage_commitment,
        &delta_commitment,
        &claimed_commitment,
        max_value,
        &verifier_transcript,
    );
}

test "proof string" {
    const max_value: u64 = 3;

    const percentage_commitment_string = "JGuzRjhmp3d8PWshbrN3Q7kg027OdPn7IU26ISTiz3c=";
    const percentage_commitment = try pedersen.Commitment.fromBase64(percentage_commitment_string);

    const delta_commitment_string = "3mwfK4u0J0UqCVznbxyCjlGEgMrI+XHdW7g00YVjSVA=";
    const delta_commitment = try pedersen.Commitment.fromBase64(delta_commitment_string);

    const claimed_commitment_string = "/t9n3yJa7p9wJV5P2cclnUiirKU5oNUv/gQMe27WMT4=";
    const claimed_commitment = try pedersen.Commitment.fromBase64(claimed_commitment_string);

    // zig fmt: off
    const proof_string = "SpmzL7hrLLp7P/Cz+2kBh22QKq3mWb0v28Er6lO9aRfBer77VY03i9VSEd4uHYMXdaf/MBPUsDVjUxNjoauwBmw6OrAcq6tq9o1Z+NS8lkukVh6sqSrSh9dy9ipq6JcIePAVmGwDNk07ACgPE/ynrenwSPJ7ZHDGZszGkw95h25gTKPyoaMbvZoXGLtkuHmvXJ7KBBJmK2eTzELb6UF2HOUg9cGFgomL8Xa3l14LBDMwLAokJK4n2d6eTkk1O0ECddmTDwoG6lmt0fHXYm37Z+k4yrQkhUgKwph2nLWG3Q7zvRM2qVFxFUGfLWJq5Sm7l7segOm+hQpRaH+q7OHNBg==";
    const proof = try PercentageWithCapProof.fromBase64(proof_string);
    // zig fmt: on

    var verifier_transcript = Transcript.init("test");

    try proof.verify(
        &percentage_commitment,
        &delta_commitment,
        &claimed_commitment,
        max_value,
        &verifier_transcript,
    );
}
