const std = @import("std");
const sig = @import("../../sig.zig");

const Edwards25519 = std.crypto.ecc.Edwards25519;
const el_gamal = sig.zksdk.el_gamal;
const pedersen = sig.zksdk.pedersen;
const ElGamalCiphertext = sig.zksdk.ElGamalCiphertext;
const ElGamalKeypair = sig.zksdk.ElGamalKeypair;
const ElGamalPubkey = sig.zksdk.ElGamalPubkey;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const Transcript = sig.zksdk.Transcript;
const weak_mul = sig.vm.syscalls.ecc.weak_mul;
const ProofType = sig.runtime.program.zk_elgamal.ProofType;

pub const Proof = struct {
    P: Ristretto255,
    D: Ristretto255,
    z: Scalar,

    pub fn init(
        kp: *const ElGamalKeypair,
        ciphertext: *const ElGamalCiphertext,
        transcript: *Transcript,
    ) Proof {
        transcript.appendDomSep("zero-ciphertext-proof");

        const P = kp.public.point;
        const s = kp.secret.scalar;
        const D = ciphertext.handle.point;

        // masking factor
        var y = Scalar.random();
        defer std.crypto.secureZero(u64, &y.limbs);

        // random() guarantees that y isn't zero and P must not be zero.
        const Y_P = P.mul(y.toBytes()) catch unreachable;
        const Y_D: Ristretto255 = .{ .p = weak_mul.mul(D.p, y.toBytes()) };

        transcript.appendPoint("Y_P", Y_P);
        transcript.appendPoint("Y_D", Y_D);

        const c = transcript.challengeScalar("c");
        _ = transcript.challengeScalar("w");

        // compute the masked secret key
        const z = s.mul(c).add(y);

        return .{
            .P = Y_P,
            .D = Y_D,
            .z = z,
        };
    }

    pub fn verify(
        self: Proof,
        pubkey: *const ElGamalPubkey,
        ciphertext: *const ElGamalCiphertext,
        transcript: *Transcript,
    ) !void {
        transcript.appendDomSep("zero-ciphertext-proof");

        const P = pubkey.point;
        const C = ciphertext.commitment.point;
        const D = ciphertext.handle.point;
        const Y_P = self.P;

        // record Y in transcript and receieve challenge scalars
        try transcript.validateAndAppendPoint("Y_P", self.P);
        transcript.appendPoint("Y_D", self.D);

        const c = transcript.challengeScalar("c");

        transcript.appendScalar("z", self.z);
        const w = transcript.challengeScalar("w"); // w used for batch verification

        const w_negated = Edwards25519.scalar.neg(w.toBytes());
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
            pedersen.H.p,
            P.p,
            C.p,
            D.p,
            Y_D.p,
        }, .{
            Edwards25519.scalar.neg(c.toBytes()),                                     // -c
            self.z.toBytes(),                                               // z
            Scalar.fromBytes(w_negated).mul(c).toBytes(), // -w * c
            w.mul(self.z).toBytes(),                      // w * z
            w_negated,                                                      // -w
        });
        // zig fmt: on

        if (!Y_P.equivalent(.{ .p = check })) {
            return error.AlgebraicRelation;
        }
    }

    pub fn fromBytes(bytes: [96]u8) !Proof {
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

    pub fn toBytes(self: Proof) [96]u8 {
        return self.P.toBytes() ++ self.D.toBytes() ++ self.z.toBytes();
    }

    pub fn fromBase64(string: []const u8) !Proof {
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

pub const Data = struct {
    context: Context,
    proof: Proof,

    pub const TYPE: ProofType = .zero_ciphertext;
    pub const BYTE_LEN = 192;

    pub const Context = struct {
        pubkey: ElGamalPubkey,
        ciphertext: ElGamalCiphertext,

        pub const BYTE_LEN = 96;

        pub fn fromBytes(bytes: [96]u8) !Context {
            return .{
                .pubkey = try ElGamalPubkey.fromBytes(bytes[0..32].*),
                .ciphertext = try ElGamalCiphertext.fromBytes(bytes[32..96].*),
            };
        }

        pub fn toBytes(self: Context) [96]u8 {
            return self.pubkey.toBytes() ++ self.ciphertext.toBytes();
        }

        fn newTranscript(self: Context) Transcript {
            var transcript = Transcript.init("zero-ciphertext-instruction");
            transcript.appendPubkey("pubkey", self.pubkey);
            transcript.appendCiphertext("ciphertext", self.ciphertext);
            return transcript;
        }
    };

    pub fn init(
        keypair: *const ElGamalKeypair,
        ciphertext: *const ElGamalCiphertext,
    ) Data {
        const context: Context = .{
            .ciphertext = ciphertext.*,
            .pubkey = keypair.public,
        };
        var transcript = context.newTranscript();
        const proof = Proof.init(keypair, ciphertext, &transcript);
        return .{ .context = context, .proof = proof };
    }

    pub fn fromBytes(data: []const u8) !Data {
        if (data.len != BYTE_LEN) return error.InvalidLength;
        return .{
            .context = try Context.fromBytes(data[0..96].*),
            .proof = try Proof.fromBytes(data[96..192].*),
        };
    }

    pub fn toBytes(self: Data) [BYTE_LEN]u8 {
        return self.context.toBytes() ++ self.proof.toBytes();
    }

    pub fn verify(self: Data) !void {
        var transcript = self.context.newTranscript();
        const pubkey = self.context.pubkey;
        const ciphertext = self.context.ciphertext;
        try self.proof.verify(&pubkey, &ciphertext, &transcript);
    }

    test "correctness" {
        const kp = ElGamalKeypair.random();

        {
            // general case: encryption of 0
            const ciphertext = el_gamal.encrypt(u64, 0, &kp.public);
            const zero_ciphertext_proof_data: Data = .init(&kp, &ciphertext);
            try zero_ciphertext_proof_data.verify();
        }
        {
            // general case: encryption of > 0
            const ciphertext = el_gamal.encrypt(u64, 1, &kp.public);
            const zero_ciphertext_proof_data: Data = .init(&kp, &ciphertext);
            try std.testing.expectError(
                error.AlgebraicRelation,
                zero_ciphertext_proof_data.verify(),
            );
        }
    }
};

test "sanity" {
    var kp = ElGamalKeypair.random();

    var prover_transcript = Transcript.init("test");
    var verifier_transcript = Transcript.init("test");

    // general case: encryption of 0
    {
        const elgamal_ciphertext = el_gamal.encrypt(u64, 0, &kp.public);
        const proof = Proof.init(&kp, &elgamal_ciphertext, &prover_transcript);
        try proof.verify(&kp.public, &elgamal_ciphertext, &verifier_transcript);
    }

    // general case: encryption of > 0
    {
        const elgamal_ciphertext = el_gamal.encrypt(u64, 1, &kp.public);
        const proof = Proof.init(&kp, &elgamal_ciphertext, &prover_transcript);
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
        const proof = Proof.init(&kp, &ciphertext, &prover_transcript);
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

        const proof = Proof.init(&kp, &ciphertext, &prover_transcript);
        try std.testing.expectError(
            error.AlgebraicRelation,
            proof.verify(&kp.public, &ciphertext, &verifier_transcript),
        );
    }

    {
        // zeroed handle

        var prover_transcript = Transcript.init("test");
        var verifier_transcript = Transcript.init("test");

        const commitment, _ = pedersen.initValue(u64, 0);
        const ciphertext: ElGamalCiphertext = .{
            .commitment = commitment,
            .handle = .{ .point = try Ristretto255.fromBytes(.{0} ** 32) },
        };

        const proof = Proof.init(&kp, &ciphertext, &prover_transcript);
        try std.testing.expectError(
            error.AlgebraicRelation,
            proof.verify(&kp.public, &ciphertext, &verifier_transcript),
        );
    }

    // if the public key is zeroed, then the proof should always reject
    {
        var prover_transcript = Transcript.init("test");
        var verifier_transcript = Transcript.init("test");

        const public: ElGamalPubkey = .{ .point = try Ristretto255.fromBytes(.{0} ** 32) };
        const ciphertext = el_gamal.encrypt(u64, 0, &public);

        const proof = Proof.init(&kp, &ciphertext, &prover_transcript);
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
    const proof = try Proof.fromBase64(proof_string);
    // zig fmt: on

    var verifier_transcript = Transcript.init("test");
    try proof.verify(&pubkey, &ciphertext, &verifier_transcript);
}
