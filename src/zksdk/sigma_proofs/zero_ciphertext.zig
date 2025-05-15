const std = @import("std");
const sig = @import("../../sig.zig");

const Edwards25519 = std.crypto.ecc.Edwards25519;
const el_gamal = sig.zksdk.el_gamal;
const ElGamalCiphertext = sig.zksdk.ElGamalCiphertext;
const ElGamalKeypair = sig.zksdk.ElGamalKeypair;
const ElGamalPubkey = sig.zksdk.ElGamalPubkey;
const pedersen = el_gamal.pedersen;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const Transcript = sig.zksdk.Transcript;
const weak_mul = sig.vm.syscalls.ecc.weak_mul;

pub const ZeroCiphertextProof = struct {
    P: Ristretto255,
    D: Ristretto255,
    z: Scalar,

    pub fn init(
        kp: *const ElGamalKeypair,
        ciphertext: *const ElGamalCiphertext,
        transcript: *Transcript,
    ) ZeroCiphertextProof {
        transcript.appendMessage("dom-sep", "zero-ciphertext-proof");

        const P = kp.public.p;
        const s = kp.secret.scalar;
        const D = ciphertext.handle.point;

        // masking factor
        var y = Scalar.random();
        defer std.crypto.utils.secureZero(u64, &y.limbs);

        // random() guarantees that y isn't zero and P must not be zero.
        const Y_P = P.mul(y.toBytes()) catch unreachable;
        const Y_D: Ristretto255 = .{ .p = weak_mul.mul(D.p, y.toBytes()) };

        transcript.appendMessage("Y_P", &Y_P.toBytes());
        transcript.appendMessage("Y_D", &Y_D.toBytes());

        const c = transcript.challengeScalar("c");
        _ = transcript.challengeScalar("w");

        // compute the masked secret key
        const z = s.mul(Scalar.fromBytes(c)).add(y);

        return .{
            .P = Y_P,
            .D = Y_D,
            .z = z,
        };
    }

    pub fn verify(
        self: ZeroCiphertextProof,
        pubkey: *const ElGamalPubkey,
        ciphertext: *const ElGamalCiphertext,
        transcript: *Transcript,
    ) !void {
        transcript.appendMessage("dom-sep", "zero-ciphertext-proof");

        const P = pubkey.p;
        const C = ciphertext.commitment.point;
        const D = ciphertext.handle.point;
        const Y_P = self.P;

        // record Y in transcript and receieve challenge scalars
        try transcript.validateAndAppendPoint("Y_P", self.P);
        transcript.appendPoint("Y_D", self.D);

        const c = transcript.challengeScalar("c");

        transcript.appendMessage("z", &self.z.toBytes());
        const w = transcript.challengeScalar("w"); // w used for batch verification

        const w_negated = Edwards25519.scalar.neg(w);
        const Y_D = self.D;

        //     points  scalars
        // 0   H       -c
        // 1   P        z
        // 2   C       -wc
        // 3   D        wz
        // 4   Y_D     -w
        // ----------------------- MSM
        //     Y_P

        // we need to use weak_mul since the protocol itself relies
        // on producing identity points in order to indicate that the proof was valid.
        // zig fmt: off
        const check =  weak_mul.mulMulti(5, .{
            el_gamal.H.p,
            P.p,
            C.p,
            D.p,
            Y_D.p,
        }, .{
            Edwards25519.scalar.neg(c),                                     // -c
            self.z.toBytes(),                                               // z
            Scalar.fromBytes(w_negated).mul(Scalar.fromBytes(c)).toBytes(), // -w * c
            Scalar.fromBytes(w).mul(self.z).toBytes(),                      // w * z
            w_negated,                                                      // -w
        });
        // zig fmt: on

        if (!Y_P.equivalent(.{ .p = check })) {
            return error.AlgebraicRelation;
        }
    }

    pub fn fromBytes(bytes: [96]u8) !ZeroCiphertextProof {
        const P = try Ristretto255.fromBytes(bytes[0..32].*);
        const D = try Ristretto255.fromBytes(bytes[32..64].*);
        const z = Scalar.fromBytes(bytes[64..96].*);
        try Edwards25519.scalar.rejectNonCanonical(z.toBytes());
        return .{
            .P = P,
            .D = D,
            .z = z,
        };
    }

    pub fn fromBase64(string: []const u8) !ZeroCiphertextProof {
        const base64 = std.base64.standard;
        var buffer: [96]u8 = .{0} ** 96;
        const decoded_length = try base64.Decoder.calcSizeForSlice(string);
        try std.base64.standard.Decoder.decode(
            buffer[0..decoded_length],
            string,
        );
        return fromBytes(buffer);
    }
};

test "sanity" {
    var kp = ElGamalKeypair.random();

    var prover_transcript = Transcript.init("test");
    var verifier_transcript = Transcript.init("test");

    // general case: encryption of 0
    {
        const elgamal_ciphertext = el_gamal.encrypt(u64, 0, &kp.public);
        const proof = ZeroCiphertextProof.init(&kp, &elgamal_ciphertext, &prover_transcript);
        try proof.verify(&kp.public, &elgamal_ciphertext, &verifier_transcript);
    }

    // general case: encryption of > 0
    {
        const elgamal_ciphertext = el_gamal.encrypt(u64, 1, &kp.public);
        const proof = ZeroCiphertextProof.init(&kp, &elgamal_ciphertext, &prover_transcript);
        try std.testing.expectError(
            error.AlgebraicRelation,
            proof.verify(&kp.public, &elgamal_ciphertext, &verifier_transcript),
        );
    }
}

test "edge case" {
    var kp = ElGamalKeypair.random();

    {
        var prover_transcript = Transcript.init("test");
        var verifier_transcript = Transcript.init("test");

        // All zero ciphertext should be a valid encoding for the scalar "0"
        var ciphertext = try ElGamalCiphertext.fromBytes(.{0} ** 64);
        const proof = ZeroCiphertextProof.init(&kp, &ciphertext, &prover_transcript);
        try proof.verify(&kp.public, &ciphertext, &verifier_transcript);
    }

    // If either the commitment or the handle are zero, the ciphertext is always
    // invalid and proof verification should always reject it.

    {
        // zeroed commitment

        var prover_transcript = Transcript.init("test");
        var verifier_transcript = Transcript.init("test");

        const zeroed_commitment: pedersen.Commitment = .{
            .point = try Ristretto255.fromBytes(.{0} ** 32),
        };
        const opening = pedersen.Opening.random();
        const handle = pedersen.DecryptHandle.init(&kp.public, &opening);

        const ciphertext: ElGamalCiphertext = .{
            .commitment = zeroed_commitment,
            .handle = handle,
        };

        const proof = ZeroCiphertextProof.init(&kp, &ciphertext, &prover_transcript);
        try std.testing.expectError(
            error.AlgebraicRelation,
            proof.verify(&kp.public, &ciphertext, &verifier_transcript),
        );
    }

    {
        // zeroed handle

        var prover_transcript = Transcript.init("test");
        var verifier_transcript = Transcript.init("test");

        const commitment, _ = pedersen.init(u64, 0);
        const ciphertext: ElGamalCiphertext = .{
            .commitment = commitment,
            .handle = .{ .point = try Ristretto255.fromBytes(.{0} ** 32) },
        };

        const proof = ZeroCiphertextProof.init(&kp, &ciphertext, &prover_transcript);
        try std.testing.expectError(
            error.AlgebraicRelation,
            proof.verify(&kp.public, &ciphertext, &verifier_transcript),
        );
    }

    // if the public key is zeroed, then the proof should always reject
    {
        var prover_transcript = Transcript.init("test");
        var verifier_transcript = Transcript.init("test");

        const public: ElGamalPubkey = .{ .p = try Ristretto255.fromBytes(.{0} ** 32) };
        const ciphertext = el_gamal.encrypt(u64, 0, &public);

        const proof = ZeroCiphertextProof.init(&kp, &ciphertext, &prover_transcript);
        try std.testing.expectError(
            error.AlgebraicRelation,
            proof.verify(&kp.public, &ciphertext, &verifier_transcript),
        );
    }
}

test "proof string" {
    const pubkey_string = "Vlx+Fr61KnreO27JDg5MsBN8NgbICGa3fIech8oZ4hQ=";
    const pubkey = try ElGamalPubkey.fromBase64(pubkey_string);

    // zig fmt: off
    const ciphertext_string = "wps5X1mou5PUdPD+llxiJ+aoX4YWrR/S6/U2MUC2LjLS7wDu6S9nOG92VMnlngQaP4irBY0OqlsGdXS4j8DROg==";
    const ciphertext = try ElGamalCiphertext.fromBase64(ciphertext_string);

    const proof_string = "qMDiQ5zPcTYFhchYBZzRS81UGIt2QRNce2/ULEqDBXBQEnGRI0u0G1HzRJfpIbOWCHBwMaNgsT1jTZwTOTWyMBE/2UjHI4x9IFpAM6ccGuexo/HjSECPDgL+85zrfA8L";
    const proof = try ZeroCiphertextProof.fromBase64(proof_string);
        // zig fmt: on

    var verifier_transcript = Transcript.init("test");
    try proof.verify(&pubkey, &ciphertext, &verifier_transcript);
}
