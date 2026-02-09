//! [fd](https://github.com/firedancer-io/firedancer/blob/33538d35a623675e66f38f77d7dc86c1ba43c935/src/flamenco/runtime/program/zksdk/instructions/fd_zksdk_grouped_ciphertext_2_handles_validity.c)
//! [agave](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_2.rs)

const std = @import("std");
const builtin = @import("builtin");
const std14 = @import("std14");
const sig = @import("../../../sig.zig");

const Edwards25519 = std.crypto.ecc.Edwards25519;
const elgamal = sig.zksdk.elgamal;
const pedersen = sig.zksdk.pedersen;
const ElGamalKeypair = sig.zksdk.ElGamalKeypair;
const ElGamalPubkey = sig.zksdk.ElGamalPubkey;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const Transcript = sig.zksdk.Transcript;
const ed25519 = sig.crypto.ed25519;
const GroupedElGamalCiphertext = elgamal.GroupedElGamalCiphertext;
const ProofType = sig.runtime.program.zk_elgamal.ProofType;

pub const Proof = struct {
    Y_0: Ristretto255,
    Y_1: Ristretto255,
    Y_2: Ristretto255,
    z_r: Scalar,
    z_x: Scalar,

    // the extra contract on top of the base `contract` used in `init`.
    const batched_contract: Transcript.Contract = &.{
        .{ .label = "t", .type = .challenge },
    };

    const contract: Transcript.Contract = &.{
        .{ .label = "Y_0", .type = .validate_point },
        .{ .label = "Y_1", .type = .validate_point },
        .{ .label = "Y_2", .type = .point },
        .{ .label = "c", .type = .challenge },

        .{ .label = "z_r", .type = .scalar },
        .{ .label = "z_x", .type = .scalar },
        .{ .label = "w", .type = .challenge },
    };

    pub fn initBatched(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        amount_lo: u64,
        amount_hi: u64,
        opening_lo: *const pedersen.Opening,
        opening_hi: *const pedersen.Opening,
        transcript: *Transcript,
    ) Proof {
        transcript.appendHandleDomSep(.batched, .two);

        comptime var session = Transcript.getSession(batched_contract);
        defer session.finish();
        const t = transcript.challengeScalar(&session, "t");

        const scalar_lo = pedersen.scalarFromInt(u64, amount_lo);
        const scalar_hi = pedersen.scalarFromInt(u64, amount_hi);

        const batched_message = scalar_hi.mul(t).add(scalar_lo);
        const batched_opening: pedersen.Opening = .{
            .scalar = opening_hi.scalar.mul(t).add(opening_lo.scalar),
        };

        return init(
            first_pubkey,
            second_pubkey,
            batched_message,
            &batched_opening,
            transcript,
        );
    }

    pub fn init(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        amount: anytype,
        opening: *const pedersen.Opening,
        transcript: *Transcript,
    ) Proof {
        transcript.appendHandleDomSep(.unbatched, .two);

        const P_first = first_pubkey.point;
        const P_second = second_pubkey.point;

        var x: Scalar = switch (@TypeOf(amount)) {
            Scalar => amount,
            u64 => pedersen.scalarFromInt(u64, amount),
            else => unreachable,
        };
        const r = opening.scalar;

        var y_r = Scalar.random();
        var y_x = Scalar.random();
        defer {
            std.crypto.secureZero(u64, &x.limbs);
            std.crypto.secureZero(u64, &y_r.limbs);
            std.crypto.secureZero(u64, &y_x.limbs);
        }

        const Y_0 = ed25519.mulMulti(
            2,
            .{ pedersen.H, pedersen.G },
            .{ y_r.toBytes(), y_x.toBytes() },
        );
        const Y_1: Ristretto255 = ed25519.mul(true, P_first, y_r.toBytes());
        const Y_2: Ristretto255 = ed25519.mul(true, P_second, y_r.toBytes());

        comptime var session = Transcript.getSession(contract);
        defer session.finish();

        transcript.appendNoValidate(&session, "Y_0", Y_0);
        transcript.appendNoValidate(&session, "Y_1", Y_1);
        transcript.append(&session, .point, "Y_2", Y_2);
        const c = transcript.challengeScalar(&session, "c");

        // masked message and opening
        const z_r = c.mul(r).add(y_r);
        const z_x = c.mul(x).add(y_x);

        if (builtin.mode == .Debug) {
            transcript.append(&session, .scalar, "z_r", z_r);
            transcript.append(&session, .scalar, "z_x", z_x);
            _ = transcript.challengeScalar(&session, "w");
        }

        return .{
            .Y_0 = Y_0,
            .Y_1 = Y_1,
            .Y_2 = Y_2,
            .z_r = z_r,
            .z_x = z_x,
        };
    }

    fn Params(batched: bool) type {
        return if (batched) struct {
            first_pubkey: *const ElGamalPubkey,
            second_pubkey: *const ElGamalPubkey,
            commitment: *const pedersen.Commitment,
            commitment_hi: *const pedersen.Commitment,
            first_handle: *const pedersen.DecryptHandle,
            first_handle_hi: *const pedersen.DecryptHandle,
            second_handle: *const pedersen.DecryptHandle,
            second_handle_hi: *const pedersen.DecryptHandle,
        } else struct {
            first_pubkey: *const ElGamalPubkey,
            second_pubkey: *const ElGamalPubkey,
            commitment: *const pedersen.Commitment,
            first_handle: *const pedersen.DecryptHandle,
            second_handle: *const pedersen.DecryptHandle,
        };
    }

    pub fn verify(
        self: Proof,
        comptime batched: bool,
        params: Params(batched),
        transcript: *Transcript,
    ) !void {
        // for batched we have the batched contract which includes the initial
        // `t` challenge, and then the base one that's shared between batched and non batched.
        comptime var session = Transcript.getSession(if (batched)
            batched_contract ++ contract
        else
            contract);
        defer session.finish();

        const t = if (batched) t: {
            transcript.appendHandleDomSep(.batched, .two);
            break :t transcript.challengeScalar(&session, "t");
        } else void; // shouldn't be referenced

        transcript.appendHandleDomSep(.unbatched, .two);

        try transcript.append(&session, .validate_point, "Y_0", self.Y_0);
        try transcript.append(&session, .validate_point, "Y_1", self.Y_1);
        // Y_2 can be all zero point if the second public key is all zero
        transcript.append(&session, .point, "Y_2", self.Y_2);

        const c = transcript.challengeScalar(&session, "c").toBytes();

        transcript.append(&session, .scalar, "z_r", self.z_r);
        transcript.append(&session, .scalar, "z_x", self.z_x);
        const w = transcript.challengeScalar(&session, "w");

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
        if (params.second_pubkey.point.p.x.isZero()) {
            second_pubkey_not_zero = false;

            // if second_pubkey is zero, then second_handle, second_handle_hi, and Y_2
            // must all be zero as well.
            try params.second_handle.point.rejectIdentity();
            try self.Y_2.rejectIdentity();
            if (batched) try params.second_handle_hi.point.rejectIdentity();
        }

        const c_negated_w = c_negated.mul(w);
        const z_r_w = self.z_r.mul(w);

        var points: std14.BoundedArray(Ristretto255, 12) = .{};
        var scalars: std14.BoundedArray([32]u8, 12) = .{};

        try points.appendSlice(&.{
            pedersen.G,
            pedersen.H,
            self.Y_1,
            self.Y_2,
            params.first_pubkey.point,
            params.commitment.point,
            params.first_handle.point,
        });

        try scalars.appendSlice(&.{
            self.z_x.toBytes(),
            self.z_r.toBytes(),
            w_negated.toBytes(),
            w_negated.mul(w).toBytes(),
            z_r_w.toBytes(),
            c_negated.toBytes(),
            c_negated_w.toBytes(),
        });

        if (batched) {
            try points.appendSlice(&.{
                params.commitment_hi.point,
                params.first_handle_hi.point,
            });
            try scalars.appendSlice(&.{
                c_negated.mul(t).toBytes(),
                c_negated_w.mul(t).toBytes(),
            });
        }

        if (second_pubkey_not_zero) {
            try points.appendSlice(&.{
                params.second_pubkey.point,
                params.second_handle.point,
            });
            try scalars.appendSlice(&.{
                z_r_w.mul(w).toBytes(),
                c_negated_w.mul(w).toBytes(),
            });
        }

        if (batched and second_pubkey_not_zero) {
            try points.append(params.second_handle_hi.point);
            try scalars.append(c_negated_w.mul(w).mul(t).toBytes());
        }

        // assert the only possible lengths to help the optimizer a bit
        switch (points.len) {
            // batched is false + pubkey2_not_zero is false
            7 => {},
            // batched is true  + pubkey2_not_zero is false
            // batched is false + pubkey2_not_zero is true
            9 => {},
            // batched is true  + pubkey2_not_zero is true
            12 => {},
            else => unreachable, // nothing else should be possible!
        }

        const check = ed25519.straus.mulMultiRuntime(
            12,
            false,
            true,
            points.constSlice(),
            scalars.constSlice(),
        );

        if (!self.Y_0.equivalent(check)) {
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

    fn toBytes(self: Proof) [160]u8 {
        return self.Y_0.toBytes() ++ self.Y_1.toBytes() ++
            self.Y_2.toBytes() ++ self.z_r.toBytes() ++ self.z_x.toBytes();
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

pub const Data = struct {
    context: Context,
    proof: Proof,

    pub const TYPE: ProofType = .grouped_ciphertext2_handles_validity;
    pub const BYTE_LEN = 320;

    pub const Context = struct {
        first_pubkey: ElGamalPubkey,
        second_pubkey: ElGamalPubkey,
        grouped_ciphertext: GroupedElGamalCiphertext(2),

        pub const BYTE_LEN = 160;

        pub fn fromBytes(bytes: [160]u8) !Context {
            return .{
                .first_pubkey = try .fromBytes(bytes[0..32].*),
                .second_pubkey = try .fromBytes(bytes[32..64].*),
                .grouped_ciphertext = try .fromBytes(bytes[64..][0..96].*),
            };
        }

        pub fn toBytes(self: Context) [160]u8 {
            return self.first_pubkey.toBytes() ++
                self.second_pubkey.toBytes() ++
                self.grouped_ciphertext.toBytes();
        }

        // zig fmt: off
        fn newTranscript(self: Context) Transcript {
            return .init(.@"grouped-ciphertext-validity-2-handles-instruction", &.{
                .{ .label = "first-pubkey",       .message = .{ .pubkey = self.first_pubkey } },
                .{ .label = "second-pubkey",      .message = .{ .pubkey = self.second_pubkey } },
                .{ .label = "grouped-ciphertext", .message = .{ .grouped_2 = self.grouped_ciphertext } },
            });
        }
        // zig fmt: on
    };

    pub fn init(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        grouped_ciphertext: *const GroupedElGamalCiphertext(2),
        amount: u64,
        opening: *const pedersen.Opening,
    ) Data {
        const context: Context = .{
            .first_pubkey = first_pubkey.*,
            .second_pubkey = second_pubkey.*,
            .grouped_ciphertext = grouped_ciphertext.*,
        };
        var transcript = context.newTranscript();
        const proof = Proof.init(
            first_pubkey,
            second_pubkey,
            amount,
            opening,
            &transcript,
        );
        return .{ .context = context, .proof = proof };
    }

    pub fn fromBytes(data: []const u8) !Data {
        if (data.len != BYTE_LEN) return error.InvalidLength;
        return .{
            .context = try Context.fromBytes(data[0..160].*),
            .proof = try Proof.fromBytes(data[160..][0..160].*),
        };
    }

    pub fn toBytes(self: Data) [BYTE_LEN]u8 {
        return self.context.toBytes() ++ self.proof.toBytes();
    }

    pub fn verify(self: Data) !void {
        var transcript = self.context.newTranscript();

        const grouped_ciphertext = self.context.grouped_ciphertext;
        const first_handle = grouped_ciphertext.handles[0];
        const second_handle = grouped_ciphertext.handles[1];

        try self.proof.verify(
            false,
            .{
                .commitment = &grouped_ciphertext.commitment,
                .first_pubkey = &self.context.first_pubkey,
                .second_pubkey = &self.context.second_pubkey,
                .first_handle = &first_handle,
                .second_handle = &second_handle,
            },
            &transcript,
        );
    }

    test "correctness" {
        const first_kp = ElGamalKeypair.random();
        const first_pubkey = first_kp.public;

        const second_kp = ElGamalKeypair.random();
        const second_pubkey = second_kp.public;

        const amount: u64 = 55;
        const opening = pedersen.Opening.random();
        const grouped_ciphertext = elgamal.GroupedElGamalCiphertext(2).encryptWithOpening(
            .{ first_pubkey, second_pubkey },
            amount,
            &opening,
        );

        const proof = Data.init(
            &first_pubkey,
            &second_pubkey,
            &grouped_ciphertext,
            amount,
            &opening,
        );

        try proof.verify();
    }
};

pub const BatchedData = struct {
    context: Context,
    proof: Proof,

    pub const TYPE: ProofType = .batched_grouped_ciphertext2_handles_validity;
    pub const BYTE_LEN = 416;

    pub const Context = struct {
        first_pubkey: ElGamalPubkey,
        second_pubkey: ElGamalPubkey,
        grouped_ciphertext_lo: GroupedElGamalCiphertext(2),
        grouped_ciphertext_hi: GroupedElGamalCiphertext(2),

        pub const BYTE_LEN = 256;

        pub fn fromBytes(bytes: [256]u8) !Context {
            return .{
                .first_pubkey = try .fromBytes(bytes[0..32].*),
                .second_pubkey = try .fromBytes(bytes[32..64].*),
                .grouped_ciphertext_lo = try .fromBytes(bytes[64..][0..96].*),
                .grouped_ciphertext_hi = try .fromBytes(bytes[160..][0..96].*),
            };
        }

        pub fn toBytes(self: Context) [256]u8 {
            return self.first_pubkey.toBytes() ++
                self.second_pubkey.toBytes() ++
                self.grouped_ciphertext_lo.toBytes() ++
                self.grouped_ciphertext_hi.toBytes();
        }

        // zig fmt: off
        fn newTranscript(self: Context) Transcript {
            return .init(.@"batched-grouped-ciphertext-validity-2-handles-instruction", &.{
                .{ .label = "first-pubkey",          .message = .{ .pubkey = self.first_pubkey } },
                .{ .label = "second-pubkey",         .message = .{ .pubkey = self.second_pubkey } },
                .{ .label = "grouped-ciphertext-lo", .message = .{ .grouped_2 = self.grouped_ciphertext_lo } },
                .{ .label = "grouped-ciphertext-hi", .message = .{ .grouped_2 = self.grouped_ciphertext_hi } },
            });
        }
        // zig fmt: on
    };

    pub fn init(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        grouped_ciphertext_lo: *const GroupedElGamalCiphertext(2),
        grouped_ciphertext_hi: *const GroupedElGamalCiphertext(2),
        amount_lo: u64,
        amount_hi: u64,
        opening_lo: *const pedersen.Opening,
        opening_hi: *const pedersen.Opening,
    ) BatchedData {
        const context: Context = .{
            .first_pubkey = first_pubkey.*,
            .second_pubkey = second_pubkey.*,
            .grouped_ciphertext_lo = grouped_ciphertext_lo.*,
            .grouped_ciphertext_hi = grouped_ciphertext_hi.*,
        };
        var transcript = context.newTranscript();
        const proof = Proof.initBatched(
            first_pubkey,
            second_pubkey,
            amount_lo,
            amount_hi,
            opening_lo,
            opening_hi,
            &transcript,
        );
        return .{ .context = context, .proof = proof };
    }

    pub fn fromBytes(data: []const u8) !BatchedData {
        if (data.len != BYTE_LEN) return error.InvalidLength;
        return .{
            .context = try Context.fromBytes(data[0..256].*),
            .proof = try Proof.fromBytes(data[256..][0..160].*),
        };
    }

    pub fn toBytes(self: BatchedData) [BYTE_LEN]u8 {
        return self.context.toBytes() ++ self.proof.toBytes();
    }

    pub fn verify(self: BatchedData) !void {
        var transcript = self.context.newTranscript();

        const grouped_ciphertext_lo = self.context.grouped_ciphertext_lo;
        const grouped_ciphertext_hi = self.context.grouped_ciphertext_hi;

        const first_handle_lo = grouped_ciphertext_lo.handles[0];
        const second_handle_lo = grouped_ciphertext_lo.handles[1];
        const first_handle_hi = grouped_ciphertext_hi.handles[0];
        const second_handle_hi = grouped_ciphertext_hi.handles[1];

        try self.proof.verify(
            true,
            .{
                .first_pubkey = &self.context.first_pubkey,
                .second_pubkey = &self.context.second_pubkey,
                .commitment = &grouped_ciphertext_lo.commitment,
                .commitment_hi = &grouped_ciphertext_hi.commitment,
                .first_handle = &first_handle_lo,
                .second_handle = &second_handle_lo,
                .first_handle_hi = &first_handle_hi,
                .second_handle_hi = &second_handle_hi,
            },
            &transcript,
        );
    }

    test "correctness" {
        const first_kp = ElGamalKeypair.random();
        const first_pubkey = first_kp.public;

        const second_kp = ElGamalKeypair.random();
        const second_pubkey = second_kp.public;

        const amount_lo: u64 = 11;
        const amount_hi: u64 = 22;

        const opening_lo = pedersen.Opening.random();
        const opening_hi = pedersen.Opening.random();

        const grouped_ciphertext_lo = elgamal.GroupedElGamalCiphertext(2).encryptWithOpening(
            .{ first_pubkey, second_pubkey },
            amount_lo,
            &opening_lo,
        );
        const grouped_ciphertext_hi = elgamal.GroupedElGamalCiphertext(2).encryptWithOpening(
            .{ first_pubkey, second_pubkey },
            amount_hi,
            &opening_hi,
        );

        const proof = BatchedData.init(
            &first_pubkey,
            &second_pubkey,
            &grouped_ciphertext_lo,
            &grouped_ciphertext_hi,
            amount_lo,
            amount_hi,
            &opening_lo,
            &opening_hi,
        );

        try proof.verify();
    }
};

test "correctness" {
    const first_kp = ElGamalKeypair.random();
    const first_pubkey = first_kp.public;

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const amount: u64 = 55;
    const commitment, const opening = pedersen.initValue(u64, amount);

    const first_handle = pedersen.DecryptHandle.init(&first_pubkey, &opening);
    const second_handle = pedersen.DecryptHandle.init(&second_pubkey, &opening);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        amount,
        &opening,
        &prover_transcript,
    );

    try proof.verify(
        false,
        .{
            .first_pubkey = &first_pubkey,
            .second_pubkey = &second_pubkey,
            .commitment = &commitment,
            .first_handle = &first_handle,
            .second_handle = &second_handle,
        },
        &verifier_transcript,
    );
}

test "first pubkey zeroed" {
    // if the first pubkey is zeroed, then the proof should always fail to verify.
    const first_pubkey = try ElGamalPubkey.fromBytes(.{0} ** 32);

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const amount: u64 = 55;
    const commitment, const opening = pedersen.initValue(u64, amount);

    const first_handle = pedersen.DecryptHandle.init(&first_pubkey, &opening);
    const second_handle = pedersen.DecryptHandle.init(&second_pubkey, &opening);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

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
            false,
            .{
                .first_pubkey = &first_pubkey,
                .second_pubkey = &second_pubkey,
                .commitment = &commitment,
                .first_handle = &first_handle,
                .second_handle = &second_handle,
            },
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

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        amount,
        &opening,
        &prover_transcript,
    );

    try proof.verify(
        false,
        .{
            .first_pubkey = &first_pubkey,
            .second_pubkey = &second_pubkey,
            .commitment = &commitment,
            .first_handle = &first_handle,
            .second_handle = &second_handle,
        },
        &verifier_transcript,
    );
}

test "zeroed decryption handle" {
    // decryption handle can be zero as long as the Pedersen commitment is valid
    const first_kp = ElGamalKeypair.random();
    const first_pubkey = first_kp.public;

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const amount: u64 = 55;
    const zeroed_opening = try pedersen.Opening.fromBytes(.{0} ** 32);
    const commitment = pedersen.initOpening(u64, amount, &zeroed_opening);

    const first_handle = pedersen.DecryptHandle.init(&first_pubkey, &zeroed_opening);
    const second_handle = pedersen.DecryptHandle.init(&second_pubkey, &zeroed_opening);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        amount,
        &zeroed_opening,
        &prover_transcript,
    );

    try proof.verify(
        false,
        .{
            .first_pubkey = &first_pubkey,
            .second_pubkey = &second_pubkey,
            .commitment = &commitment,
            .first_handle = &first_handle,
            .second_handle = &second_handle,
        },
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

    var verifier_transcript = Transcript.initTest("Test");
    try proof.verify(
        false,
        .{
            .first_pubkey = &first_pubkey,
            .second_pubkey = &second_pubkey,
            .commitment = &commitment,
            .first_handle = &first_handle,
            .second_handle = &second_handle,
        },
        &verifier_transcript,
    );
}

test "batched sanity" {
    const first_kp = ElGamalKeypair.random();
    const first_pubkey = first_kp.public;

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const amount_lo: u64 = 55;
    const amount_hi: u64 = 77;

    const commitment_lo, const opening_lo = pedersen.initValue(u64, amount_lo);
    const commitment_hi, const opening_hi = pedersen.initValue(u64, amount_hi);

    const first_handle_lo = pedersen.DecryptHandle.init(&first_pubkey, &opening_lo);
    const first_handle_hi = pedersen.DecryptHandle.init(&first_pubkey, &opening_hi);

    const second_handle_lo = pedersen.DecryptHandle.init(&second_pubkey, &opening_lo);
    const second_handle_hi = pedersen.DecryptHandle.init(&second_pubkey, &opening_hi);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.initBatched(
        &first_pubkey,
        &second_pubkey,
        amount_lo,
        amount_hi,
        &opening_lo,
        &opening_hi,
        &prover_transcript,
    );

    try proof.verify(
        true,
        .{
            .first_pubkey = &first_pubkey,
            .second_pubkey = &second_pubkey,
            .commitment = &commitment_lo,
            .commitment_hi = &commitment_hi,
            .first_handle = &first_handle_lo,
            .first_handle_hi = &first_handle_hi,
            .second_handle = &second_handle_lo,
            .second_handle_hi = &second_handle_hi,
        },
        &verifier_transcript,
    );
}

test "batched proof string" {
    const first_pubkey_string = "3FQGicS6AgVkRnX5Sau8ybxJDvlehmbdvBUdo+o+oE4=";
    const first_pubkey = try ElGamalPubkey.fromBase64(first_pubkey_string);

    const second_pubkey_string = "IieU/fJCRksbDNvIJZvg/N/safpnIWAGT/xpUAG7YUg=";
    const second_pubkey = try ElGamalPubkey.fromBase64(second_pubkey_string);

    const commitment_lo_string = "Lq0z7bx3ccyxIB0rRHoWzcba8W1azvAhMfnJogxcz2I=";
    const commitment_lo = try pedersen.Commitment.fromBase64(commitment_lo_string);

    const commitment_hi_string = "dLPLdQrcl5ZWb0EaJcmebAlJA6RrzKpMSYPDVMJdOm0=";
    const commitment_hi = try pedersen.Commitment.fromBase64(commitment_hi_string);

    const first_handle_lo_string = "GizvHRUmu6CMjhH7qWg5Rqu43V69Nyjq4QsN/yXBHT8=";
    const first_handle_lo = try pedersen.DecryptHandle.fromBase64(first_handle_lo_string);

    const first_handle_hi_string = "qMuR929bbkKiVJfRvYxnb90rbh2btjNDjaXpeLCvQWk=";
    const first_handle_hi = try pedersen.DecryptHandle.fromBase64(first_handle_hi_string);

    const second_handle_lo_string = "MmDbMo2l/jAcXUIm09AQZsBXa93lI2BapAiGZ6f9zRs=";
    const second_handle_lo = try pedersen.DecryptHandle.fromBase64(second_handle_lo_string);

    const second_handle_hi_string = "gKhb0o3d22XcUcQl5hENF4l1SJwg1vpgiw2RDYqXOxY=";
    const second_handle_hi = try pedersen.DecryptHandle.fromBase64(second_handle_hi_string);

    // zig fmt: off
    const proof_string = "2n2mADpkNrop+eHJj1sAryXWcTtC/7QKcxMp7FdHeh8wjGKLAa9kC89QLGrphv7pZdb2J25kKXqhWUzRBsJWU0izi5vxau9XX6cyd72F3Q9hMXBfjk3htOHI0VnGAalZ/3dZ6C7erjGQDoeTVGOd1vewQ+NObAbfZwcry3+VhQNpkhL17E1dUgZZ+mb5K0tXAjWCmVh1OfN9h3sGltTUCg==";
    const proof = try Proof.fromBase64(proof_string);
    // zig fmt: on

    var verifier_transcript = Transcript.initTest("Test");

    try proof.verify(
        true,
        .{
            .first_pubkey = &first_pubkey,
            .second_pubkey = &second_pubkey,
            .commitment = &commitment_lo,
            .commitment_hi = &commitment_hi,
            .first_handle = &first_handle_lo,
            .first_handle_hi = &first_handle_hi,
            .second_handle = &second_handle_lo,
            .second_handle_hi = &second_handle_hi,
        },
        &verifier_transcript,
    );
}
