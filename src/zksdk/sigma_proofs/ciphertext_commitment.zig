//! [fd](https://github.com/firedancer-io/firedancer/blob/33538d35a623675e66f38f77d7dc86c1ba43c935/src/flamenco/runtime/program/zksdk/instructions/fd_zksdk_ciphertext_commitment_equality.c)
//! [agave](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs)

const std = @import("std");
const builtin = @import("builtin");
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
    Y_0: Ristretto255,
    Y_1: Ristretto255,
    Y_2: Ristretto255,
    z_s: Scalar,
    z_x: Scalar,
    z_r: Scalar,

    const contract: Transcript.Contract = &.{
        .{ .label = "pubkey", .type = .validate_pubkey },
        .{ .label = "ciphertext", .type = .validate_ciphertext },
        .{ .label = "commitment", .type = .validate_commitment },
        .domain(.@"ciphertext-commitment-equality-proof"),

        .{ .label = "Y_0", .type = .validate_point },
        .{ .label = "Y_1", .type = .validate_point },
        .{ .label = "Y_2", .type = .validate_point },
        .{ .label = "c", .type = .challenge },

        .{ .label = "z_s", .type = .scalar },
        .{ .label = "z_x", .type = .scalar },
        .{ .label = "z_r", .type = .scalar },
        .{ .label = "w", .type = .challenge }, // w used for batch verification
    };

    /// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L71
    pub fn init(
        kp: *const ElGamalKeypair,
        ciphertext: *const ElGamalCiphertext,
        commitment: *const pedersen.Commitment,
        opening: *const pedersen.Opening,
        amount: u64,
        transcript: *Transcript,
    ) Proof {
        comptime var session = Transcript.getSession(contract);
        defer session.finish();

        transcript.appendNoValidate(&session, .pubkey, "pubkey", kp.public);
        transcript.appendNoValidate(&session, .ciphertext, "ciphertext", ciphertext.*);
        transcript.appendNoValidate(&session, .commitment, "commitment", commitment.*);
        transcript.appendDomSep(&session, .@"ciphertext-commitment-equality-proof");

        const P = kp.public;
        const D = ciphertext.handle.point;

        const r = opening.scalar;
        const s = kp.secret.scalar;
        var x = pedersen.scalarFromInt(u64, amount);

        var y_s = Scalar.random();
        var y_x = Scalar.random();
        var y_r = Scalar.random();
        defer {
            std.crypto.secureZero(u64, &x.limbs);
            std.crypto.secureZero(u64, &y_s.limbs);
            std.crypto.secureZero(u64, &y_x.limbs);
            std.crypto.secureZero(u64, &y_r.limbs);
        }

        const Y_0 = ed25519.mul(true, P.point, y_s.toBytes());
        const Y_1 = ed25519.mulMulti(
            2,
            .{ pedersen.G, D },
            .{ y_x.toBytes(), y_s.toBytes() },
        );
        const Y_2 = ed25519.mulMulti(
            2,
            .{ pedersen.G, pedersen.H },
            .{ y_x.toBytes(), y_r.toBytes() },
        );

        transcript.appendNoValidate(&session, .point, "Y_0", Y_0);
        transcript.appendNoValidate(&session, .point, "Y_1", Y_1);
        transcript.appendNoValidate(&session, .point, "Y_2", Y_2);

        const c = transcript.challengeScalar(&session, "c");

        const z_s = c.mul(s).add(y_s);
        const z_x = c.mul(x).add(y_x);
        const z_r = c.mul(r).add(y_r);

        if (builtin.mode == .Debug) {
            transcript.append(&session, .scalar, "z_s", z_s);
            transcript.append(&session, .scalar, "z_x", z_x);
            transcript.append(&session, .scalar, "z_r", z_r);
            _ = transcript.challengeScalar(&session, "w");
        }

        return .{
            .Y_0 = Y_0,
            .Y_1 = Y_1,
            .Y_2 = Y_2,
            .z_s = z_s,
            .z_x = z_x,
            .z_r = z_r,
        };
    }

    /// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L139
    pub fn verify(
        self: Proof,
        pubkey: *const ElGamalPubkey,
        ciphertext: *const ElGamalCiphertext,
        commitment: *const pedersen.Commitment,
        transcript: *Transcript,
    ) !void {
        comptime var session = Transcript.getSession(contract);
        defer session.finish();

        try transcript.append(&session, .validate_pubkey, "pubkey", pubkey.*);
        try transcript.append(&session, .validate_ciphertext, "ciphertext", ciphertext.*);
        try transcript.append(&session, .validate_commitment, "commitment", commitment.*);
        transcript.appendDomSep(&session, .@"ciphertext-commitment-equality-proof");

        const P = pubkey.point;
        const C_ciphertext = ciphertext.commitment.point;
        const D = ciphertext.handle.point;
        const C_commitment = commitment.point;

        try transcript.append(&session, .validate_point, "Y_0", self.Y_0);
        try transcript.append(&session, .validate_point, "Y_1", self.Y_1);
        try transcript.append(&session, .validate_point, "Y_2", self.Y_2);

        const c = transcript.challengeScalar(&session, "c").toBytes();

        transcript.append(&session, .scalar, "z_s", self.z_s);
        transcript.append(&session, .scalar, "z_x", self.z_x);
        transcript.append(&session, .scalar, "z_r", self.z_r);
        const w = transcript.challengeScalar(&session, "w");

        const c_negated = Scalar.fromBytes(Edwards25519.scalar.neg(c));
        const z_s_w = self.z_s.mul(w);
        const c_negated_w = c_negated.mul(w);
        const w_negated = Scalar.fromBytes(Edwards25519.scalar.neg(w.toBytes()));

        //     points  scalars
        // 0   G       z_x w + z_x
        // 1   H       z_r - c w^2
        // 2   Y_0     -w^2
        // 3   Y_1     -w
        // 4   P_src   z_s w^2
        // 5   C_src   -c w
        // 6   D_src   z_s w
        // 7   C_dst   -c
        // ----------------------- MSM
        //     Y_2

        const check = ed25519.mulMulti(8, .{
            pedersen.G,
            pedersen.H,
            self.Y_0,
            self.Y_1,
            P,
            C_ciphertext,
            D,
            C_commitment,
        }, .{
            self.z_x.mul(w).add(self.z_x).toBytes(),
            c_negated_w.mul(w).add(self.z_r).toBytes(),
            w_negated.mul(w).toBytes(),
            w_negated.toBytes(),
            z_s_w.mul(w).toBytes(),
            c_negated_w.toBytes(),
            z_s_w.toBytes(),
            c_negated.toBytes(),
        });

        if (!self.Y_2.equivalent(check)) {
            return error.AlgebraicRelation;
        }
    }

    pub fn fromBytes(bytes: [192]u8) !Proof {
        const Y_0 = try Ristretto255.fromBytes(bytes[0..32].*);
        const Y_1 = try Ristretto255.fromBytes(bytes[32..64].*);
        const Y_2 = try Ristretto255.fromBytes(bytes[64..96].*);

        const z_s = Scalar.fromBytes(bytes[96..128].*);
        const z_x = Scalar.fromBytes(bytes[128..160].*);
        const z_r = Scalar.fromBytes(bytes[160..192].*);

        try Edwards25519.scalar.rejectNonCanonical(z_s.toBytes());
        try Edwards25519.scalar.rejectNonCanonical(z_x.toBytes());
        try Edwards25519.scalar.rejectNonCanonical(z_r.toBytes());

        return .{
            .Y_0 = Y_0,
            .Y_1 = Y_1,
            .Y_2 = Y_2,
            .z_s = z_s,
            .z_x = z_x,
            .z_r = z_r,
        };
    }

    fn toBytes(self: Proof) [192]u8 {
        return self.Y_0.toBytes() ++ self.Y_1.toBytes() ++ self.Y_2.toBytes() ++
            self.z_s.toBytes() ++ self.z_x.toBytes() ++ self.z_r.toBytes();
    }

    pub fn fromBase64(string: []const u8) !Proof {
        const base64 = std.base64.standard;
        var buffer: [192]u8 = .{0} ** 192;
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

    pub const TYPE: ProofType = .ciphertext_commitment_equality;
    pub const BYTE_LEN = 320;

    pub const Context = struct {
        pubkey: ElGamalPubkey,
        ciphertext: ElGamalCiphertext,
        commitment: pedersen.Commitment,

        pub const BYTE_LEN = 128;

        fn fromBytes(bytes: [128]u8) !Context {
            return .{
                .pubkey = try ElGamalPubkey.fromBytes(bytes[0..32].*),
                .ciphertext = try ElGamalCiphertext.fromBytes(bytes[32..96].*),
                .commitment = try pedersen.Commitment.fromBytes(bytes[96..128].*),
            };
        }

        pub fn toBytes(self: Context) [128]u8 {
            return self.pubkey.toBytes() ++
                self.ciphertext.toBytes() ++
                self.commitment.point.toBytes();
        }
    };

    pub fn init(
        kp: *const ElGamalKeypair,
        ciphertext: *const ElGamalCiphertext,
        commitment: *const pedersen.Commitment,
        opening: *const pedersen.Opening,
        amount: u64,
    ) Data {
        const context: Context = .{
            .pubkey = kp.public,
            .ciphertext = ciphertext.*,
            .commitment = commitment.*,
        };
        var transcript = Transcript.init(.@"ciphertext-commitment-equality-instruction");
        const proof = Proof.init(
            kp,
            ciphertext,
            commitment,
            opening,
            amount,
            &transcript,
        );
        return .{ .context = context, .proof = proof };
    }

    pub fn fromBytes(data: []const u8) !Data {
        if (data.len != BYTE_LEN) return error.InvalidLength;
        return .{
            .context = try Context.fromBytes(data[0..128].*),
            .proof = try Proof.fromBytes(data[128..][0..192].*),
        };
    }

    pub fn toBytes(self: Data) [BYTE_LEN]u8 {
        return self.context.toBytes() ++ self.proof.toBytes();
    }

    pub fn verify(self: Data) !void {
        var transcript = Transcript.init(.@"ciphertext-commitment-equality-instruction");
        try self.proof.verify(
            &self.context.pubkey,
            &self.context.ciphertext,
            &self.context.commitment,
            &transcript,
        );
    }

    test "correctness" {
        const kp = ElGamalKeypair.random();
        const amount: u64 = 55;
        const ciphertext = elgamal.encrypt(u64, amount, &kp.public);
        const commitment, const opening = pedersen.initValue(u64, amount);

        const proof_data = Data.init(
            &kp,
            &ciphertext,
            &commitment,
            &opening,
            amount,
        );
        try proof_data.verify();
    }
};

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L292-L318
test "success case" {
    const kp = ElGamalKeypair.random();
    const message: u64 = 55;

    const ciphertext = elgamal.encrypt(u64, message, &kp.public);
    const commitment, const opening = pedersen.initValue(u64, message);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &kp,
        &ciphertext,
        &commitment,
        &opening,
        message,
        &prover_transcript,
    );
    try proof.verify(
        &kp.public,
        &ciphertext,
        &commitment,
        &verifier_transcript,
    );
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L320-L352
test "fail case" {
    const kp = ElGamalKeypair.random();
    const encrypted_message: u64 = 55;
    const committed_message: u64 = 77;

    const ciphertext = elgamal.encrypt(u64, encrypted_message, &kp.public);
    const commitment, const opening = pedersen.initValue(u64, committed_message);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &kp,
        &ciphertext,
        &commitment,
        &opening,
        encrypted_message,
        &prover_transcript,
    );

    try std.testing.expectError(
        error.AlgebraicRelation,
        proof.verify(
            &kp.public,
            &ciphertext,
            &commitment,
            &verifier_transcript,
        ),
    );
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L357-L387
test "public key zeroed" {
    // if ElGamal public key is zeroed (invalid), then the proof should always fail to verify.
    const zeroed_public = try ElGamalPubkey.fromBytes(.{0} ** 32);
    const secret = ElGamalKeypair.Secret.random();
    const kp: ElGamalKeypair = .{ .public = zeroed_public, .secret = secret };

    const message: u64 = 55;
    const ciphertext = elgamal.encrypt(u64, message, &kp.public);
    const commitment, const opening = pedersen.initValue(u64, message);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &kp,
        &ciphertext,
        &commitment,
        &opening,
        message,
        &prover_transcript,
    );

    try std.testing.expectError(
        error.IdentityElement, // invalid point
        proof.verify(
            &kp.public,
            &ciphertext,
            &commitment,
            &verifier_transcript,
        ),
    );
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L389-L417
test "all zeroed" {
    const kp = ElGamalKeypair.random();

    const message: u64 = 0;
    const ciphertext = try ElGamalCiphertext.fromBytes(.{0} ** 64);
    const commitment = try pedersen.Commitment.fromBytes(.{0} ** 32);
    const opening = try pedersen.Opening.fromBytes(.{0} ** 32);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &kp,
        &ciphertext,
        &commitment,
        &opening,
        message,
        &prover_transcript,
    );

    try std.testing.expectError(
        error.IdentityElement,
        proof.verify(
            &kp.public,
            &ciphertext,
            &commitment,
            &verifier_transcript,
        ),
    );
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L419-L447
test "commitment zeroed" {
    const kp = ElGamalKeypair.random();

    const message: u64 = 0;
    const ciphertext = elgamal.encrypt(u64, message, &kp.public);
    const commitment = try pedersen.Commitment.fromBytes(.{0} ** 32);
    const opening = try pedersen.Opening.fromBytes(.{0} ** 32);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &kp,
        &ciphertext,
        &commitment,
        &opening,
        message,
        &prover_transcript,
    );

    try std.testing.expectError(
        error.IdentityElement,
        proof.verify(
            &kp.public,
            &ciphertext,
            &commitment,
            &verifier_transcript,
        ),
    );
}

test "ciphertext zeroed" {
    const kp = ElGamalKeypair.random();

    const message: u64 = 0;
    const ciphertext = try ElGamalCiphertext.fromBytes(.{0} ** 64);
    const commitment, const opening = pedersen.initValue(u64, message);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &kp,
        &ciphertext,
        &commitment,
        &opening,
        message,
        &prover_transcript,
    );

    try std.testing.expectError(
        error.IdentityElement,
        proof.verify(
            &kp.public,
            &ciphertext,
            &commitment,
            &verifier_transcript,
        ),
    );
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/ciphertext_commitment_equality.rs#L451
test "proof strings" {
    const pubkey_string = "uO3j5FuK4OGJD8ain+4MXLU84ixomYnBI5s0pQ3X0Cs=";
    const pubkey = try ElGamalPubkey.fromBase64(pubkey_string);

    const commitment_string = "RNst9nTGL7PkluExuhmD1kJNM86ZZH6OE8R4P1pPFHQ=";
    const commitment = try pedersen.Commitment.fromBase64(commitment_string);

    // sig fmt: off
    const ciphertext_string = "PsM4qA4ImFKGui57JZKzIFl1RO30GG+saCMmI9gAAENu82mvud6uhZ6YLJoLcq5hLSLPY48R8p//H24gNjxoBg==";
    const ciphertext = try ElGamalCiphertext.fromBase64(ciphertext_string);

    const proof_string = "ELyazp4KuO/vLn91GiiEBgwYlMvisVisVRf8DWRjE1KoFGV2mxRX370N/roHFXArVXGTzL1e0C8UAPHHVYI5M+rE7mXhpGJ1rpMuGduCavOb7WIvzYE0xO6gQmPMeow08x5O/e4SlyGfA2s1S/Z8J+t9yxqbfqTugn9TNjFBFAcM3WOOFGk0dQdi7V3YGpNQMz3P9oWE7d1SsVohUDYEAvyaqXYWc0+YSJEdC7BaRdTqXp4ft8ybAjNB6SmCeisO";
    const proof = try Proof.fromBase64(proof_string);
    // sig fmt: on

    var verifier_transcript = Transcript.initTest("Test");
    try proof.verify(
        &pubkey,
        &ciphertext,
        &commitment,
        &verifier_transcript,
    );
}
