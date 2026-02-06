//! [fd](https://github.com/firedancer-io/firedancer/blob/33538d35a623675e66f38f77d7dc86c1ba43c935/src/flamenco/runtime/program/zksdk/instructions/fd_zksdk_zero_ciphertext.c)
//! [agave](https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/zero_ciphertext.rs)

const std = @import("std");
const sig = @import("../../sig.zig");

const ed25519 = sig.crypto.ed25519;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const elgamal = sig.zksdk.elgamal;
const ElGamalCiphertext = sig.zksdk.ElGamalCiphertext;
const ElGamalKeypair = sig.zksdk.ElGamalKeypair;
const ElGamalPubkey = sig.zksdk.ElGamalPubkey;
const pedersen = sig.zksdk.pedersen;
const ProofType = sig.runtime.program.zk_elgamal.ProofType;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const Transcript = sig.zksdk.Transcript;

pub const Proof = struct {
    P: Ristretto255,
    D: Ristretto255,
    z: Scalar,

    const contract: Transcript.Contract = &.{
        .{ .label = "pubkey", .type = .validate_pubkey },
        .{ .label = "ciphertext", .type = .validate_ciphertext },
        .domain(.@"zero-ciphertext-proof"),

        .{ .label = "Y_P", .type = .validate_point },
        .{ .label = "Y_D", .type = .point },
        .{ .label = "c", .type = .challenge },

        .{ .label = "z", .type = .scalar },
        .{ .label = "w", .type = .challenge }, // w used for batch verification
    };

    pub fn init(
        kp: *const ElGamalKeypair,
        ciphertext: *const ElGamalCiphertext,
        transcript: *Transcript,
    ) Proof {
        comptime var session = Transcript.getSession(contract);
        defer session.finish();

        transcript.appendNoValidate(&session, .pubkey, "pubkey", kp.public);
        transcript.appendNoValidate(&session, .ciphertext, "ciphertext", ciphertext.*);
        transcript.appendDomSep(&session, .@"zero-ciphertext-proof");

        const P = kp.public.point;
        const s = kp.secret.scalar;
        const D = ciphertext.handle.point;

        // Generate a random masking factor that also serves as a nonce.
        var y = Scalar.random();
        defer std.crypto.secureZero(u64, &y.limbs);
        const Y_P, const Y_D = ed25519.mulManyWithSameScalar(2, .{ P, D }, y.toBytes());

        // Record Y in the transcript and receive a challenge scalar.
        transcript.appendNoValidate(&session, .point, "Y_P", Y_P);
        transcript.append(&session, .point, "Y_D", Y_D);
        const c = transcript.challengeScalar(&session, "c");

        // Compute the masked secret key.
        const z = s.mul(c).add(y);

        transcript.append(&session, .scalar, "z", z);
        _ = transcript.challengeScalar(&session, "w");

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
        comptime var session = Transcript.getSession(contract);
        defer session.finish();

        // [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/zero_ciphertext.rs#L104
        try transcript.append(&session, .validate_pubkey, "pubkey", pubkey.*);
        // [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/zero_ciphertext.rs#L105
        try transcript.append(&session, .validate_ciphertext, "ciphertext", ciphertext.*);

        transcript.appendDomSep(&session, .@"zero-ciphertext-proof");

        const P = pubkey.point;
        const C = ciphertext.commitment.point;
        const D = ciphertext.handle.point;
        const Y_P = self.P;

        // Record Y in the transcript and receive challenge scalars.
        try transcript.append(&session, .validate_point, "Y_P", self.P);
        transcript.append(&session, .point, "Y_D", self.D);

        const c = transcript.challengeScalar(&session, "c");

        transcript.append(&session, .scalar, "z", self.z);
        const w = transcript.challengeScalar(&session, "w");

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

        // zig fmt: off
        const check =  ed25519.mulMulti(5, .{
            pedersen.H,
            P,
            C,
            D,
            Y_D,
        }, .{
            Edwards25519.scalar.neg(c.toBytes()),         // -c
            self.z.toBytes(),                             //  z
            Scalar.fromBytes(w_negated).mul(c).toBytes(), // -w * c
            w.mul(self.z).toBytes(),                      //  w * z
            w_negated,                                    // -w
        });
        // zig fmt: on

        if (!Y_P.equivalent(check)) {
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
    };

    pub fn init(keypair: *const ElGamalKeypair, ciphertext: *const ElGamalCiphertext) Data {
        const context: Context = .{
            .ciphertext = ciphertext.*,
            .pubkey = keypair.public,
        };

        var transcript = Transcript.init(.@"zero-ciphertext-instruction");
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
        var transcript = Transcript.init(.@"zero-ciphertext-instruction");
        try self.proof.verify(
            &self.context.pubkey,
            &self.context.ciphertext,
            &transcript,
        );
    }

    test "correctness" {
        const kp = ElGamalKeypair.random();

        {
            // general case: encryption of 0
            const ciphertext = elgamal.encrypt(u64, 0, &kp.public);
            const zero_ciphertext_proof_data: Data = .init(&kp, &ciphertext);
            try zero_ciphertext_proof_data.verify();
        }
        {
            // general case: encryption of > 0
            const ciphertext = elgamal.encrypt(u64, 1, &kp.public);
            const zero_ciphertext_proof_data: Data = .init(&kp, &ciphertext);
            try std.testing.expectError(
                error.AlgebraicRelation,
                zero_ciphertext_proof_data.verify(),
            );
        }
    }
};

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/zero_ciphertext.rs#L209
test "sanity" {
    var kp = ElGamalKeypair.random();

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    // general case: encryption of 0
    {
        const elgamal_ciphertext = elgamal.encrypt(u64, 0, &kp.public);
        const proof = Proof.init(&kp, &elgamal_ciphertext, &prover_transcript);
        try proof.verify(&kp.public, &elgamal_ciphertext, &verifier_transcript);
    }

    // general case: encryption of > 0
    {
        const elgamal_ciphertext = elgamal.encrypt(u64, 1, &kp.public);
        const proof = Proof.init(&kp, &elgamal_ciphertext, &prover_transcript);
        try std.testing.expectError(
            error.AlgebraicRelation,
            proof.verify(&kp.public, &elgamal_ciphertext, &verifier_transcript),
        );
    }
}

test "identity cases" {
    var kp = ElGamalKeypair.random();

    // [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/zero_ciphertext.rs#L250-L258
    {
        var prover_transcript = Transcript.initTest("Test");
        var verifier_transcript = Transcript.initTest("Test");

        // All zero ciphertext should be a valid encoding for the scalar "0"
        var ciphertext = try ElGamalCiphertext.fromBytes(.{0} ** 64);
        const proof = Proof.init(&kp, &ciphertext, &prover_transcript);
        try std.testing.expectError(
            error.IdentityElement,
            proof.verify(&kp.public, &ciphertext, &verifier_transcript),
        );
    }

    // invalid and proof verification should always reject it.
    // [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/zero_ciphertext.rs#L260-L278
    {
        var prover_transcript = Transcript.initTest("Test");
        var verifier_transcript = Transcript.initTest("Test");

        const zeroed_commitment: pedersen.Commitment = .{
            .point = try Ristretto255.fromBytes(@splat(0)),
        };
        const opening = pedersen.Opening.random();
        const handle = pedersen.DecryptHandle.init(&kp.public, &opening);

        const ciphertext: ElGamalCiphertext = .{
            .commitment = zeroed_commitment,
            .handle = handle,
        };

        const proof = Proof.init(&kp, &ciphertext, &prover_transcript);
        try std.testing.expectError(
            error.IdentityElement,
            proof.verify(&kp.public, &ciphertext, &verifier_transcript),
        );
    }

    {
        // zeroed handle
        var prover_transcript = Transcript.initTest("Test");
        var verifier_transcript = Transcript.initTest("Test");

        const commitment, _ = pedersen.initValue(u64, 0);
        const ciphertext: ElGamalCiphertext = .{
            .commitment = commitment,
            .handle = .{ .point = try Ristretto255.fromBytes(@splat(0)) },
        };

        const proof = Proof.init(&kp, &ciphertext, &prover_transcript);
        try std.testing.expectError(
            error.IdentityElement,
            proof.verify(&kp.public, &ciphertext, &verifier_transcript),
        );
    }

    // if the public key is zeroed, then the proof should always reject
    // [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/zero_ciphertext.rs#L280-L292
    {
        var prover_transcript = Transcript.initTest("Test");
        var verifier_transcript = Transcript.initTest("Test");

        const public: ElGamalPubkey = .{ .point = try Ristretto255.fromBytes(@splat(0)) };
        const ciphertext = elgamal.encrypt(u64, 0, &public);

        const proof = Proof.init(&kp, &ciphertext, &prover_transcript);
        try std.testing.expectError(
            error.IdentityElement,
            proof.verify(&public, &ciphertext, &verifier_transcript),
        );
    }
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/zero_ciphertext.rs#L296
test "proof string" {
    const pubkey_string = "iKeujRa2kL82Az2fl7MXHYVMc0XJFoGZckD7LvPtSU8=";
    const pubkey = try ElGamalPubkey.fromBase64(pubkey_string);

    // sig fmt: off
    const ciphertext_string = "crvDqbMD4OVe4mkuzqUJrhyblxTAu3vaUqMvfYuAHybADkpXli9m1zXHrvdpO1PfDQ6U/RHxLgr3XUvDg2sLBA==";
    const ciphertext = try ElGamalCiphertext.fromBase64(ciphertext_string);

    const proof_string = "fMibXtwhpBMr5FWg9CrBqlCrLq/cC2RmiwMpToMHxSyCI5AT+Ns4orbzcbqTiOJzF+tCgaJj+XCLXHk/YQLcQ4G+g3bppv3RDOLmGnVuyepMsSCVI4CGykTBqXb+ReQJ";
    const proof = try Proof.fromBase64(proof_string);
    // sig fmt: on

    var verifier_transcript = Transcript.initTest("test");
    try proof.verify(&pubkey, &ciphertext, &verifier_transcript);
}
