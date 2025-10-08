//! [fd](https://github.com/firedancer-io/firedancer/blob/33538d35a623675e66f38f77d7dc86c1ba43c935/src/flamenco/runtime/program/zksdk/instructions/fd_zksdk_ciphertext_ciphertext_equality.c)
//! [agave](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/zk-sdk/src/sigma_proofs/ciphertext_ciphertext_equality.rs)

const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../sig.zig");

const Edwards25519 = std.crypto.ecc.Edwards25519;
const elgamal = sig.zksdk.elgamal;
const pedersen = sig.zksdk.pedersen;
const ElGamalCiphertext = sig.zksdk.ElGamalCiphertext;
const ElGamalKeypair = sig.zksdk.ElGamalKeypair;
const ElGamalPubkey = sig.zksdk.ElGamalPubkey;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const Transcript = sig.zksdk.Transcript;
const ed25519 = sig.crypto.ed25519;
const ProofType = sig.runtime.program.zk_elgamal.ProofType;

pub const Proof = struct {
    Y_0: Ristretto255,
    Y_1: Ristretto255,
    Y_2: Ristretto255,
    Y_3: Ristretto255,
    z_s: Scalar,
    z_x: Scalar,
    z_r: Scalar,

    const contract: Transcript.Contract = &.{
        .{ .label = "Y_0", .type = .validate_point },
        .{ .label = "Y_1", .type = .validate_point },
        .{ .label = "Y_2", .type = .validate_point },
        .{ .label = "Y_3", .type = .validate_point },
        .{ .label = "c", .type = .challenge },

        .{ .label = "z_s", .type = .scalar },
        .{ .label = "z_x", .type = .scalar },
        .{ .label = "z_r", .type = .scalar },
        .{ .label = "w", .type = .challenge }, // w used for batch verification
    };

    pub fn init(
        first_kp: *const ElGamalKeypair,
        second_pubkey: *const ElGamalPubkey,
        first_ciphertext: *const ElGamalCiphertext,
        second_opening: *const pedersen.Opening,
        amount: u64,
        transcript: *Transcript,
    ) Proof {
        transcript.appendDomSep(.@"ciphertext-ciphertext-equality-proof");

        const P_first = first_kp.public.point;
        const D_first = first_ciphertext.handle.point;
        const P_second = second_pubkey.point;

        const r = second_opening.scalar;
        const s = first_kp.secret.scalar;
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

        const Y_0 = ed25519.mul(true, P_first, y_s.toBytes());
        // TODO: another optimization to explore is pre-computing the `G` and `H` straus lookup
        // tables here, we need some way of checking that they are in-fact the G and H point
        // inside of the `mulMulti`. maybe have a wrapper ristretto struct?
        const Y_1 = ed25519.mulMulti(
            2,
            .{ pedersen.G, D_first },
            .{ y_x.toBytes(), y_s.toBytes() },
        );
        const Y_2 = ed25519.mulMulti(
            2,
            .{ pedersen.G, pedersen.H },
            .{ y_x.toBytes(), y_r.toBytes() },
        );
        const Y_3 = ed25519.mul(true, P_second, y_r.toBytes());

        comptime var session = Transcript.getSession(contract);
        defer session.finish();

        transcript.appendNoValidate(&session, "Y_0", Y_0);
        transcript.appendNoValidate(&session, "Y_1", Y_1);
        transcript.appendNoValidate(&session, "Y_2", Y_2);
        transcript.appendNoValidate(&session, "Y_3", Y_3);

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
            .Y_3 = Y_3,
            .z_s = z_s,
            .z_x = z_x,
            .z_r = z_r,
        };
    }

    pub fn verify(
        self: Proof,
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        first_ciphertext: *const ElGamalCiphertext,
        second_ciphertext: *const ElGamalCiphertext,
        transcript: *Transcript,
    ) !void {
        transcript.appendDomSep(.@"ciphertext-ciphertext-equality-proof");

        const P_first = first_pubkey.point;
        const C_first = first_ciphertext.commitment.point;
        const D_first = first_ciphertext.handle.point;

        const P_second = second_pubkey.point;
        const C_second = second_ciphertext.commitment.point;
        const D_second = second_ciphertext.handle.point;

        comptime var session = Transcript.getSession(contract);
        defer session.finish();

        try transcript.append(&session, .validate_point, "Y_0", self.Y_0);
        try transcript.append(&session, .validate_point, "Y_1", self.Y_1);
        try transcript.append(&session, .validate_point, "Y_2", self.Y_2);
        try transcript.append(&session, .validate_point, "Y_3", self.Y_3);

        const c = transcript.challengeScalar(&session, "c").toBytes();

        transcript.append(&session, .scalar, "z_s", self.z_s);
        transcript.append(&session, .scalar, "z_x", self.z_x);
        transcript.append(&session, .scalar, "z_r", self.z_r);

        const w = transcript.challengeScalar(&session, "w");

        const ww = w.mul(w);
        const www = ww.mul(w);

        const w_negated = Edwards25519.scalar.neg(w.toBytes());
        const ww_negated = Edwards25519.scalar.neg(ww.toBytes());
        const www_negated = Edwards25519.scalar.neg(www.toBytes());

        const Y_0 = self.Y_0;
        const Y_1 = self.Y_1;
        const Y_2 = self.Y_2;
        const Y_3 = self.Y_3;

        const z_s = self.z_s.toBytes();
        const z_r = self.z_r.toBytes();

        //         points  scalars
        //     0   G        z_x (w + ww)
        //     1   H       -c + z_r ww
        //     2   P1       z_s
        //     3   D1       z_s w
        //     4   Y_1     -w
        //     5   C1      -w c
        //     6   Y_2     -ww
        //     7   C2      -ww c
        //     8   Y_3     -www
        //     9   D2      -www c
        //    10   P2       www z_r
        //   ------------------------ MSM
        //         Y_0

        // zig fmt: off
        const check = ed25519.mulMulti(11, .{
            pedersen.G,
            pedersen.H,
            P_first,
            D_first,
            Y_1,
            C_first,
            Y_2,
            C_second,
            Y_3,
            D_second,
            P_second,
        }, .{
            w.add(ww).mul(self.z_x).toBytes(),                      // z_x * (w + ww)
            Edwards25519.scalar.sub(self.z_r.mul(ww).toBytes(), c), // -c + (z_r * ww)
            z_s,                                                    // z_s
            self.z_s.mul(w).toBytes(),                              // z_s * w
            w_negated,                                              // -w
            Edwards25519.scalar.mul(w_negated, c),                  // -w * c
            ww_negated,                                             // -ww
            Edwards25519.scalar.mul(ww_negated, c),                 // -ww * c
            www_negated,                                            // -www
            Edwards25519.scalar.mul(www_negated, c),                // -www * c
            Edwards25519.scalar.mul(www.toBytes(), z_r),            //  www * z_r
        });
        // zig fmt: on

        if (!Y_0.equivalent(check)) {
            return error.AlgebraicRelation;
        }
    }

    pub fn fromBytes(bytes: [224]u8) !Proof {
        const Y_0 = try Ristretto255.fromBytes(bytes[0..32].*);
        const Y_1 = try Ristretto255.fromBytes(bytes[32..64].*);
        const Y_2 = try Ristretto255.fromBytes(bytes[64..96].*);
        const Y_3 = try Ristretto255.fromBytes(bytes[96..128].*);

        const z_s = Scalar.fromBytes(bytes[128..160].*);
        const z_x = Scalar.fromBytes(bytes[160..192].*);
        const z_r = Scalar.fromBytes(bytes[192..224].*);

        try Edwards25519.scalar.rejectNonCanonical(z_s.toBytes());
        try Edwards25519.scalar.rejectNonCanonical(z_x.toBytes());
        try Edwards25519.scalar.rejectNonCanonical(z_r.toBytes());

        return .{
            .Y_0 = Y_0,
            .Y_1 = Y_1,
            .Y_2 = Y_2,
            .Y_3 = Y_3,
            .z_s = z_s,
            .z_x = z_x,
            .z_r = z_r,
        };
    }

    pub fn fromBase64(string: []const u8) !Proof {
        const base64 = std.base64.standard;
        var buffer: [224]u8 = .{0} ** 224;
        const decoded_length = try base64.Decoder.calcSizeForSlice(string);
        try std.base64.standard.Decoder.decode(
            buffer[0..decoded_length],
            string,
        );
        return fromBytes(buffer);
    }

    pub fn toBytes(self: Proof) [224]u8 {
        return self.Y_0.toBytes() ++
            self.Y_1.toBytes() ++ self.Y_2.toBytes() ++ self.Y_3.toBytes() ++
            self.z_s.toBytes() ++ self.z_x.toBytes() ++ self.z_r.toBytes();
    }
};

pub const Data = struct {
    context: Context,
    proof: Proof,

    pub const TYPE: ProofType = .ciphertext_ciphertext_equality;
    pub const BYTE_LEN = 416;

    pub const Context = struct {
        first_pubkey: ElGamalPubkey,
        second_pubkey: ElGamalPubkey,
        first_ciphertext: ElGamalCiphertext,
        second_ciphertext: ElGamalCiphertext,

        pub const BYTE_LEN = (2 * 32) + (2 * 64);

        // TODO: is it a problem that we error on invalid point here?
        pub fn fromBytes(bytes: [192]u8) !Context {
            return .{
                .first_pubkey = try ElGamalPubkey.fromBytes(bytes[0..32].*),
                .second_pubkey = try ElGamalPubkey.fromBytes(bytes[32..64].*),
                .first_ciphertext = try ElGamalCiphertext.fromBytes(bytes[64..128].*),
                .second_ciphertext = try ElGamalCiphertext.fromBytes(bytes[128..192].*),
            };
        }

        pub fn toBytes(self: Context) [192]u8 {
            return self.first_pubkey.toBytes() ++ self.second_pubkey.toBytes() ++
                self.first_ciphertext.toBytes() ++ self.second_ciphertext.toBytes();
        }

        // zig fmt: off
        fn newTranscript(self: Context) Transcript {
            return .init(.@"ciphertext-ciphertext-equality-instruction", &.{
                .{ .label = "first-pubkey",      .message = .{ .pubkey = self.first_pubkey } },
                .{ .label = "second-pubkey",     .message = .{ .pubkey = self.second_pubkey } },

                .{ .label = "first-ciphertext",  .message = .{ .ciphertext = self.first_ciphertext } },
                .{ .label = "second-ciphertext", .message = .{ .ciphertext = self.second_ciphertext } },
            });
        }
        // zig fmt: on
    };

    pub fn init(
        first_keypair: *const ElGamalKeypair,
        second_pubkey: *const ElGamalPubkey,
        first_ciphertext: *const ElGamalCiphertext,
        second_ciphertext: *const ElGamalCiphertext,
        second_opening: *const pedersen.Opening,
        amount: u64,
    ) Data {
        const context: Context = .{
            .first_pubkey = first_keypair.public,
            .second_pubkey = second_pubkey.*,
            .first_ciphertext = first_ciphertext.*,
            .second_ciphertext = second_ciphertext.*,
        };
        var transcript = context.newTranscript();
        const proof = Proof.init(
            first_keypair,
            second_pubkey,
            first_ciphertext,
            second_opening,
            amount,
            &transcript,
        );
        return .{ .context = context, .proof = proof };
    }

    pub fn fromBytes(data: []const u8) !Data {
        if (data.len != BYTE_LEN) return error.InvalidLength;
        return .{
            .context = try Context.fromBytes(data[0..192].*),
            .proof = try Proof.fromBytes(data[192..][0..224].*),
        };
    }

    pub fn toBytes(self: Data) [BYTE_LEN]u8 {
        return self.context.toBytes() ++ self.proof.toBytes();
    }

    pub fn verify(self: Data) !void {
        var transcript = self.context.newTranscript();
        try self.proof.verify(
            &self.context.first_pubkey,
            &self.context.second_pubkey,
            &self.context.first_ciphertext,
            &self.context.second_ciphertext,
            &transcript,
        );
    }

    test "correctness" {
        const first_kp = ElGamalKeypair.random();
        const second_kp = ElGamalKeypair.random();

        {
            const amount: u64 = 0;
            const first_ciphertext = elgamal.encrypt(u64, amount, &first_kp.public);

            const second_opening = pedersen.Opening.random();
            const second_ciphertext = elgamal.encryptWithOpening(
                u64,
                amount,
                &second_kp.public,
                &second_opening,
            );

            const proof_data: Data = .init(
                &first_kp,
                &second_kp.public,
                &first_ciphertext,
                &second_ciphertext,
                &second_opening,
                amount,
            );
            try proof_data.verify();
        }

        {
            const amount: u64 = 55;
            const first_ciphertext = elgamal.encrypt(u64, amount, &first_kp.public);

            const second_opening = pedersen.Opening.random();
            const second_ciphertext = elgamal.encryptWithOpening(
                u64,
                amount,
                &second_kp.public,
                &second_opening,
            );

            const proof_data: Data = .init(
                &first_kp,
                &second_kp.public,
                &first_ciphertext,
                &second_ciphertext,
                &second_opening,
                amount,
            );
            try proof_data.verify();
        }

        {
            const amount: u64 = std.math.maxInt(u64);
            const first_ciphertext = elgamal.encrypt(u64, amount, &first_kp.public);

            const second_opening = pedersen.Opening.random();
            const second_ciphertext = elgamal.encryptWithOpening(
                u64,
                amount,
                &second_kp.public,
                &second_opening,
            );

            const proof_data: Data = .init(
                &first_kp,
                &second_kp.public,
                &first_ciphertext,
                &second_ciphertext,
                &second_opening,
                amount,
            );
            try proof_data.verify();
        }
    }
};

test "correctness" {
    const first_kp = ElGamalKeypair.random();
    const second_kp = ElGamalKeypair.random();
    const message: u64 = 55;

    const first_ciphertext = elgamal.encrypt(u64, message, &first_kp.public);
    const second_opening = pedersen.Opening.random();
    const second_ciphertext = elgamal.encryptWithOpening(
        u64,
        message,
        &second_kp.public,
        &second_opening,
    );

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_kp,
        &second_kp.public,
        &first_ciphertext,
        &second_opening,
        message,
        &prover_transcript,
    );
    try proof.verify(
        &first_kp.public,
        &second_kp.public,
        &first_ciphertext,
        &second_ciphertext,
        &verifier_transcript,
    );
}

test "different messages" {
    const first_kp = ElGamalKeypair.random();
    const second_kp = ElGamalKeypair.random();

    const first_message: u64 = 55;
    const second_message: u64 = 77;

    const first_ciphertext = elgamal.encrypt(u64, first_message, &first_kp.public);
    const second_opening = pedersen.Opening.random();
    const second_ciphertext = elgamal.encryptWithOpening(
        u64,
        second_message,
        &second_kp.public,
        &second_opening,
    );

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_kp,
        &second_kp.public,
        &first_ciphertext,
        &second_opening,
        first_message,
        &prover_transcript,
    );
    try std.testing.expectError(
        error.AlgebraicRelation,
        proof.verify(
            &first_kp.public,
            &second_kp.public,
            &first_ciphertext,
            &second_ciphertext,
            &verifier_transcript,
        ),
    );
}

test "proof string" {
    const first_pubkey_string = "VOPKaqo4nsX4XnbgGjCKHkLkR6JG1jX9D5G/e0EuYmM=";
    const first_pubkey = try ElGamalPubkey.fromBase64(first_pubkey_string);

    const second_pubkey_string = "JnVhtKo9B7g9c8Obo/5/EqvA59i3TvtuOcQWf17T7SU=";
    const second_pubkey = try ElGamalPubkey.fromBase64(second_pubkey_string);

    // zig fmt: off
    const first_ciphertext_string = "oKv6zxN051MXdk2cISD+CUsH2+FINoH1iB4WZyuy6nNkE7Q+eLiY9JB8itJhgKHJEA/1sAzDvpnRlLL06OXvIg==";
    const first_ciphertext = try ElGamalCiphertext.fromBase64(first_ciphertext_string);

    const second_ciphertext_string = "ooSA2cQDqutgyCBoMiQktM1Cu4NDNEbphF010gjG4iF0iMK1N+u/Qxqk0wwO/+w+5S6RiicwPs4mEKRJpFiHEw==";
    const second_ciphertext = try ElGamalCiphertext.fromBase64(second_ciphertext_string);

    const proof_string = "MlfRDO4sBPbpciEXci3QfVSLVABAJ0s8wMZ/Uz3AyETmGJ1BUE961fHIiNQXPD0j1uu1Josj//E8loPD1w+4E3bfDBJ3Mp2YqeOv41Bdec02YXlAotTGjq/UfncGdUhyampkuXUmSvnmkf5BIp4nr3X18cR9KHTAzBrKv6erjAxIckyRnACaZGEx+ZboEb3FBEXqTklytT1nrebbwkjvDUWbcpZrE+xxBWYek3qeq1x1debzxVhtS2yx44cvR5UIGLzGYa2ec/xh7wvyNEbnX80rZju2dztr4bN5f2vrTgk=";
    const proof = try Proof.fromBase64(proof_string);
    // zig fmt: on

    var verifier_transcript = Transcript.initTest("Test");

    try proof.verify(
        &first_pubkey,
        &second_pubkey,
        &first_ciphertext,
        &second_ciphertext,
        &verifier_transcript,
    );
}
