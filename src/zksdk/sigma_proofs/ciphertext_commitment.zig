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

pub const Proof = struct {
    Y_0: Ristretto255,
    Y_1: Ristretto255,
    Y_2: Ristretto255,
    z_s: Scalar,
    z_x: Scalar,
    z_r: Scalar,

    pub fn init(
        kp: *const ElGamalKeypair,
        ciphertext: *const ElGamalCiphertext,
        opening: *const pedersen.Opening,
        amount: u64,
        transcript: *Transcript,
    ) Proof {
        transcript.appendDomSep("ciphertext-commitment-equality-proof");

        const P = kp.public;
        const D = ciphertext.handle.point;

        const s = kp.secret.scalar;
        const x = el_gamal.scalarFromInt(u64, amount);
        const r = opening.scalar;

        var y_s = Scalar.random();
        var y_x = Scalar.random();
        var y_r = Scalar.random();
        defer {
            std.crypto.utils.secureZero(u64, &y_s.limbs);
            std.crypto.utils.secureZero(u64, &y_x.limbs);
            std.crypto.utils.secureZero(u64, &y_r.limbs);
        }

        const Y_0 = weak_mul.mul(P.p.p, y_s.toBytes());
        const Y_1 = weak_mul.mulMulti(
            2,
            .{ el_gamal.G.p, D.p },
            .{ y_x.toBytes(), y_s.toBytes() },
        );
        const Y_2 = weak_mul.mulMulti(
            2,
            .{ el_gamal.G.p, el_gamal.H.p },
            .{ y_x.toBytes(), y_r.toBytes() },
        );

        transcript.appendPoint("Y_0", .{ .p = Y_0 });
        transcript.appendPoint("Y_1", .{ .p = Y_1 });
        transcript.appendPoint("Y_2", .{ .p = Y_2 });

        const c = transcript.challengeScalar("c");
        _ = transcript.challengeScalar("w");

        const z_s = c.mul(s).add(y_s);
        const z_x = c.mul(x).add(y_x);
        const z_r = c.mul(r).add(y_r);

        return .{
            .Y_0 = .{ .p = Y_0 },
            .Y_1 = .{ .p = Y_1 },
            .Y_2 = .{ .p = Y_2 },
            .z_s = z_s,
            .z_x = z_x,
            .z_r = z_r,
        };
    }

    pub fn verify(
        self: Proof,
        pubkey: *const ElGamalPubkey,
        ciphertext: *const ElGamalCiphertext,
        commitment: *const pedersen.Commitment,
        transcript: *Transcript,
    ) !void {
        transcript.appendDomSep("ciphertext-commitment-equality-proof");

        const P = pubkey.p;
        const C_ciphertext = ciphertext.commitment.point;
        const D = ciphertext.handle.point;
        const C_commitment = commitment.point;

        try transcript.validateAndAppendPoint("Y_0", self.Y_0);
        try transcript.validateAndAppendPoint("Y_1", self.Y_1);
        try transcript.validateAndAppendPoint("Y_2", self.Y_2);

        const c = transcript.challengeScalar("c").toBytes();
        const w = transcript.challengeScalar("w");

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

        // zig fmt: off
        const check = weak_mul.mulMulti(8, .{
            el_gamal.G.p,
            el_gamal.H.p,
            self.Y_0.p,
            self.Y_1.p,
            P.p,
            C_ciphertext.p,
            D.p,
            C_commitment.p,
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
        // zig fmt: on

        if (!self.Y_2.equivalent(.{ .p = check })) {
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

test "success case" {
    const kp = ElGamalKeypair.random();
    const message: u64 = 55;

    const ciphertext = el_gamal.encrypt(u64, message, &kp.public);
    const commitment, const opening = el_gamal.pedersen.initValue(u64, message);

    var prover_transcript = Transcript.init("Test");
    var verifier_transcript = Transcript.init("Test");

    const proof = Proof.init(
        &kp,
        &ciphertext,
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

test "fail case" {
    const kp = ElGamalKeypair.random();
    const encrypted_message: u64 = 55;
    const committed_message: u64 = 77;

    const ciphertext = el_gamal.encrypt(u64, encrypted_message, &kp.public);
    const commitment, const opening = el_gamal.pedersen.initValue(u64, committed_message);

    var prover_transcript = Transcript.init("test");
    var verifier_transcript = Transcript.init("test");

    const proof = Proof.init(
        &kp,
        &ciphertext,
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

test "public key zeroed" {
    // if ElGamal public key is zeroed (invalid), then the proof should always fail to verify.
    const zeroed_public = try ElGamalPubkey.fromBytes(.{0} ** 32);
    const secret = ElGamalKeypair.Secret.random();
    const kp: ElGamalKeypair = .{ .public = zeroed_public, .secret = secret };

    const message: u64 = 55;
    const ciphertext = el_gamal.encrypt(u64, message, &kp.public);
    const commitment, const opening = el_gamal.pedersen.initValue(u64, message);

    var prover_transcript = Transcript.init("test");
    var verifier_transcript = Transcript.init("test");

    const proof = Proof.init(
        &kp,
        &ciphertext,
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

test "all zoered" {
    // if the ciphertext is all-zero (valid commitment of 0)
    // and the commitment is all-zero, then the proof should still succeed.
    const kp = ElGamalKeypair.random();

    const message: u64 = 0;
    const ciphertext = try ElGamalCiphertext.fromBytes(.{0} ** 64);
    const commitment = try pedersen.Commitment.fromBytes(.{0} ** 32);
    const opening = try pedersen.Opening.fromBytes(.{0} ** 32);

    var prover_transcript = Transcript.init("test");
    var verifier_transcript = Transcript.init("test");

    const proof = Proof.init(
        &kp,
        &ciphertext,
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

test "commitment zeroed" {
    // if the commitment is all-zero and the ciphertext is a correct
    // encryption of 0, then the proof should still succeed.
    const kp = ElGamalKeypair.random();

    const message: u64 = 0;
    const ciphertext = el_gamal.encrypt(u64, message, &kp.public);
    const commitment = try pedersen.Commitment.fromBytes(.{0} ** 32);
    const opening = try pedersen.Opening.fromBytes(.{0} ** 32);

    var prover_transcript = Transcript.init("test");
    var verifier_transcript = Transcript.init("test");

    const proof = Proof.init(
        &kp,
        &ciphertext,
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

test "ciphertext zeroed" {
    // if the ciphertext is all-zero and the commitment correctly encodes 0
    // then the proof should still succeed.
    const kp = ElGamalKeypair.random();

    const message: u64 = 0;
    const ciphertext = try ElGamalCiphertext.fromBytes(.{0} ** 64);
    const commitment, const opening = el_gamal.pedersen.initValue(u64, message);

    var prover_transcript = Transcript.init("test");
    var verifier_transcript = Transcript.init("test");

    const proof = Proof.init(
        &kp,
        &ciphertext,
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

test "proof strings" {
    const pubkey_string = "JNa7rRrDm35laU7f8HPds1PmHoZEPSHFK/M+aTtEhAk=";
    const pubkey = try ElGamalPubkey.fromBase64(pubkey_string);

    const commitment_string = "ngPTYvbY9P5l6aOfr7bLQiI+0HZsw8GBgiumdW3tNzw=";
    const commitment = try pedersen.Commitment.fromBase64(commitment_string);

    // zig fmt: off
    const ciphertext_string = "RAXnbQ/DPRlYAWmD+iHRNqMDv7oQcPgQ7OejRzj4bxVy2qOJNziqqDOC7VP3iTW1+z/jckW4smA3EUF7i/r8Rw==";
    const ciphertext = try ElGamalCiphertext.fromBase64(ciphertext_string);

    const proof_string = "cCZySLxB2XJdGyDvckVBm2OWiXqf7Jf54IFoDuLJ4G+ySj+lh5DbaDMHDhuozQC9tDWtk2mFITuaXOc5Zw3nZ2oEvVYpqv5hN+k5dx9k8/nZKabUCkZwx310z7x4fE4Np5SY9PYia1hkrq9AWq0b3v97XvW1+XCSSxuflvBk5wsdaQQ+ZgcmPnKWKjHfRwmU2k5iVgYzs2VmvZa5E3OWBoM/M2yFNvukY+FCC2YMnspO0c4lNBr/vDFQuHdW0OgJ";
    const proof = try Proof.fromBase64(proof_string);
    // zig fmt: on

    var verifier_transcript = Transcript.init("Test");
    try proof.verify(
        &pubkey,
        &ciphertext,
        &commitment,
        &verifier_transcript,
    );
}
