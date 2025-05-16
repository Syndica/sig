const std = @import("std");
const sig = @import("../../../sig.zig");

const Edwards25519 = std.crypto.ecc.Edwards25519;
const el_gamal = sig.zksdk.el_gamal;
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
    z_r: Scalar,
    z_x: Scalar,

    pub fn init(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        amount: u64,
        opening: *const pedersen.Opening,
        transcript: *Transcript,
    ) Proof {
        transcript.appendDomSep("validity-proof");
        transcript.appendU64("handles", 2);

        const P_first = first_pubkey.p;
        const P_second = second_pubkey.p;

        const x = el_gamal.scalarFromInt(u64, amount);
        const r = opening.scalar;

        var y_r = Scalar.random();
        var y_x = Scalar.random();
        defer {
            std.crypto.utils.secureZero(u64, &y_r.limbs);
            std.crypto.utils.secureZero(u64, &y_x.limbs);
        }

        const Y_0: Ristretto255 = .{ .p = weak_mul.mulMulti(
            2,
            .{ el_gamal.H.p, el_gamal.G.p },
            .{ y_r.toBytes(), y_x.toBytes() },
        ) };
        const Y_1: Ristretto255 = .{ .p = weak_mul.mul(P_first.p, y_r.toBytes()) };
        const Y_2: Ristretto255 = .{ .p = weak_mul.mul(P_second.p, y_r.toBytes()) };

        transcript.appendPoint("Y_0", Y_0);
        transcript.appendPoint("Y_1", Y_1);
        transcript.appendPoint("Y_2", Y_2);

        const c = transcript.challengeScalar("c");
        _ = transcript.challengeScalar("w");

        // masked message and opening
        const z_r = Scalar.fromBytes(c).mul(r).add(y_r);
        const z_x = Scalar.fromBytes(c).mul(x).add(y_x);

        return .{
            .Y_0 = Y_0,
            .Y_1 = Y_1,
            .Y_2 = Y_2,
            .z_r = z_r,
            .z_x = z_x,
        };
    }

    pub fn verify(
        self: Proof,
        commitment: *const pedersen.Commitment,
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        first_handle: *const pedersen.DecryptHandle,
        second_handle: *const pedersen.DecryptHandle,
        transcript: *Transcript,
    ) !void {
        transcript.appendDomSep("validity-proof");
        transcript.appendU64("handles", 2);

        try transcript.validateAndAppendPoint("Y_0", self.Y_0);
        try transcript.validateAndAppendPoint("Y_1", self.Y_1);
        // Y_2 can be all zero point if the second public key is all zero
        transcript.appendPoint("Y_2", self.Y_2);

        const c = transcript.challengeScalar("c");

        transcript.appendScalar("z_r", self.z_r);
        transcript.appendScalar("z_x", self.z_x);
        const w = Scalar.fromBytes(transcript.challengeScalar("w"));

        const c_negated = Scalar.fromBytes(Edwards25519.scalar.neg(c));
        const w_negated = Scalar.fromBytes(Edwards25519.scalar.neg(w.toBytes()));

        //      points   scalars
        //  0   G        z_x
        //  1   H        z_r
        //  2   Y_1     -w
        //  3   Y_2     -w^2
        //  4   pub1     z_r w
        //  5   C       -c
        //  6   h1      -c w
        //  7   C_hi    -c t       (if batched)
        //  8   h1_hi   -c w t     (if batched)
        //  9   pub2     z_r w^2   (if second_pubkey_not_zero)
        // 10   h2      -c w^2     (if second_pubkey_not_zero)
        // 11   h2_hi   -c w^2 t   (if batched && second_pubkey_not_zero)
        // ----------------------- MSM
        //      Y_0

        var second_pubkey_not_zero: bool = true;
        // TODO: optimize to affine x coord check
        if (std.mem.allEqual(u8, &second_pubkey.toBytes(), 0)) {
            second_pubkey_not_zero = false;
            // TODO
            // if second_pubkey is zero, second_handle, second_handle_hi (if exists),
            // and self.Y_2 must all be zero as well.
        }

        var points: std.BoundedArray(Edwards25519, 12) = .{};
        var scalars: std.BoundedArray([32]u8, 12) = .{};

        try points.appendSlice(&.{
            el_gamal.G.p,
            el_gamal.H.p,
            self.Y_1.p,
            self.Y_2.p,
            first_pubkey.p.p,
            commitment.point.p,
            first_handle.point.p,
        });

        const c_negated_w = c_negated.mul(w);
        const z_r_w = self.z_r.mul(w);

        try scalars.appendSlice(&.{
            self.z_x.toBytes(),
            self.z_r.toBytes(),
            w_negated.toBytes(),
            w_negated.mul(w).toBytes(),
            z_r_w.toBytes(),
            c_negated.toBytes(),
            c_negated_w.toBytes(),
        });

        if (second_pubkey_not_zero) {
            try points.appendSlice(&.{
                second_pubkey.p.p,
                second_handle.point.p,
            });
            try scalars.appendSlice(&.{
                z_r_w.mul(w).toBytes(),
                c_negated_w.mul(w).toBytes(),
            });
        }

        const check = switch (points.len) {
            inline
            // batched is false + pubkey2_not_zero is false
            7,
            // batched is true  + pubkey2_not_zero is false
            // batched is false + pubkey2_not_zero is true
            9,
            // batched is true  + pubkey2_not_zero is true
            12,
            => |N| weak_mul.mulMulti(
                N,
                points.constSlice()[0..N].*,
                scalars.constSlice()[0..N].*,
            ),
            else => unreachable,
        };

        if (!self.Y_0.equivalent(.{ .p = check })) {
            return error.AlgebraicRelation;
        }
    }

    pub fn fromBytes(bytes: [160]u8) !Proof {
        const Y_0 = try Ristretto255.fromBytes(bytes[0..32].*);
        const Y_1 = try Ristretto255.fromBytes(bytes[32..64].*);
        const Y_2 = try Ristretto255.fromBytes(bytes[64..96].*);
        const z_r = Scalar.fromBytes(bytes[96..128].*);
        const z_x = Scalar.fromBytes(bytes[128..160].*);

        try Edwards25519.scalar.rejectNonCanonical(z_r.toBytes());
        try Edwards25519.scalar.rejectNonCanonical(z_x.toBytes());

        return .{
            .Y_0 = Y_0,
            .Y_1 = Y_1,
            .Y_2 = Y_2,
            .z_r = z_r,
            .z_x = z_x,
        };
    }

    pub fn fromBase64(string: []const u8) !Proof {
        const base64 = std.base64.standard;
        var buffer: [160]u8 = .{0} ** 160;
        const decoded_length = try base64.Decoder.calcSizeForSlice(string);
        try std.base64.standard.Decoder.decode(
            buffer[0..decoded_length],
            string,
        );
        return fromBytes(buffer);
    }
};

test "correctness" {
    const first_kp = ElGamalKeypair.random();
    const first_pubkey = first_kp.public;

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const amount: u64 = 55;
    const commitment, const opening = pedersen.init(u64, amount);

    const first_handle = pedersen.DecryptHandle.init(&first_pubkey, &opening);
    const second_handle = pedersen.DecryptHandle.init(&second_pubkey, &opening);

    var prover_transcript = Transcript.init("test");
    var verifier_transcript = Transcript.init("test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        amount,
        &opening,
        &prover_transcript,
    );

    try proof.verify(
        &commitment,
        &first_pubkey,
        &second_pubkey,
        &first_handle,
        &second_handle,
        &verifier_transcript,
    );
}

test "first pubkey zeroed" {
    // if the first pubkey is zeroed, then the proof should always fail to verify.
    const first_pubkey = try ElGamalPubkey.fromBytes(.{0} ** 32);

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const amount: u64 = 55;
    const commitment, const opening = pedersen.init(u64, amount);

    const first_handle = pedersen.DecryptHandle.init(&first_pubkey, &opening);
    const second_handle = pedersen.DecryptHandle.init(&second_pubkey, &opening);

    var prover_transcript = Transcript.init("test");
    var verifier_transcript = Transcript.init("test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        amount,
        &opening,
        &prover_transcript,
    );

    try std.testing.expectError(
        error.IdentityElement,
        proof.verify(
            &commitment,
            &first_pubkey,
            &second_pubkey,
            &first_handle,
            &second_handle,
            &verifier_transcript,
        ),
    );
}

test "zeroed ciphertext" {
    // all-zeroed ciphertext should still be valid.
    const first_kp = ElGamalKeypair.random();
    const first_pubkey = first_kp.public;

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const amount: u64 = 0;
    const commitment = try pedersen.Commitment.fromBytes(.{0} ** 32);
    const opening = try pedersen.Opening.fromBytes(.{0} ** 32);

    const first_handle = pedersen.DecryptHandle.init(&first_pubkey, &opening);
    const second_handle = pedersen.DecryptHandle.init(&second_pubkey, &opening);

    var prover_transcript = Transcript.init("test");
    var verifier_transcript = Transcript.init("test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        amount,
        &opening,
        &prover_transcript,
    );

    try proof.verify(
        &commitment,
        &first_pubkey,
        &second_pubkey,
        &first_handle,
        &second_handle,
        &verifier_transcript,
    );
}

test "proof string" {
    const commitment_string = "VjdpJcofkU/Lhd6RRvwsCoqaZ8XSbhiizI7jsxZNKSU=";
    const commitment = try pedersen.Commitment.fromBase64(commitment_string);

    const first_pubkey_string = "YllcTvlVBp9nv+bi8d0Z9UOujPfMsgH3ZcCqQSwXfic=";
    const first_pubkey = try ElGamalPubkey.fromBase64(first_pubkey_string);

    const second_pubkey_string = "CCq+4oKGWlh3pkSbZpEsj6vfimhC/c3TxTVAghXq5Xo=";
    const second_pubkey = try ElGamalPubkey.fromBase64(second_pubkey_string);

    const first_handle_string = "EE1qdL/QLMGXvsWIjw2c07Vg/DgUsaexxQECKtjEwWE=";
    const first_handle = try pedersen.DecryptHandle.fromBase64(first_handle_string);

    const second_handle_string = "2Jn0+IVwpI5O/5pBU/nizS759k6dNn6UyUzxc1bt3RM=";
    const second_handle = try pedersen.DecryptHandle.fromBase64(second_handle_string);

    // zig fmt: off
    const proof_string = "/GITIw3LjQSphEG1GWYpKGjKUrYnC1n4yGFDvBwcE2V6XdSM8FKgc3AjQYJWGVkUMsciv/vMRv3lyDuW4VJJclQk9STY7Pd2F4r6Lz1P3fBmODbDp++k3Ni759FrV141Oy4puCzHV8+LHg6ePh3WlZ8yL+Ri6VDTyLc+3pblSQ0VIno0QoxyavznU6faQhuCXuy3bD+E87ZlRNtk9jPKDg==";
    const proof = try Proof.fromBase64(proof_string);
    // zig fmt: on

    var verifier_transcript = Transcript.init("Test");
    try proof.verify(
        &commitment,
        &first_pubkey,
        &second_pubkey,
        &first_handle,
        &second_handle,
        &verifier_transcript,
    );
}
