//! [fd](https://github.com/firedancer-io/firedancer/blob/33538d35a623675e66f38f77d7dc86c1ba43c935/src/flamenco/runtime/program/zksdk/instructions/fd_zksdk_grouped_ciphertext_3_handles_validity.c)
//! [agave](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs)

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
const GroupedElGamalCiphertext = sig.zksdk.GroupedElGamalCiphertext;
const ProofType = sig.runtime.program.zk_elgamal.ProofType;

pub const Proof = struct {
    Y_0: Ristretto255,
    Y_1: Ristretto255,
    Y_2: Ristretto255,
    Y_3: Ristretto255,
    z_r: Scalar,
    z_x: Scalar,

    // the extra contract on top of the base `contract` used in `init`.
    const batched_contract: Transcript.Contract = &.{
        .{ .label = "t", .type = .challenge },
    };

    const contract: Transcript.Contract = &.{
        .{ .label = "Y_0", .type = .validate_point },
        .{ .label = "Y_1", .type = .validate_point },
        .{ .label = "Y_2", .type = .validate_point },
        .{ .label = "Y_3", .type = .point },
        .{ .label = "c", .type = .challenge },

        .{ .label = "z_r", .type = .scalar },
        .{ .label = "z_x", .type = .scalar },
        .{ .label = "w", .type = .challenge },
    };

    pub fn initBatched(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        third_pubkey: *const ElGamalPubkey,
        amount_lo: u64,
        amount_hi: u64,
        opening_lo: *const pedersen.Opening,
        opening_hi: *const pedersen.Opening,
        transcript: *Transcript,
    ) Proof {
        transcript.appendHandleDomSep(.batched, .three);

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
            third_pubkey,
            batched_message,
            &batched_opening,
            transcript,
        );
    }

    pub fn init(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        third_pubkey: *const ElGamalPubkey,
        amount: anytype,
        opening: *const pedersen.Opening,
        transcript: *Transcript,
    ) Proof {
        transcript.appendHandleDomSep(.unbatched, .three);

        comptime var session = Transcript.getSession(contract);
        defer session.finish();

        const P_first = first_pubkey.point;
        const P_second = second_pubkey.point;
        const P_third = third_pubkey.point;

        var x: Scalar = switch (@TypeOf(amount)) {
            u64 => pedersen.scalarFromInt(u64, amount),
            Scalar => amount,
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
        const Y_3: Ristretto255 = ed25519.mul(true, P_third, y_r.toBytes());

        transcript.appendNoValidate(&session, "Y_0", Y_0);
        transcript.appendNoValidate(&session, "Y_1", Y_1);
        transcript.appendNoValidate(&session, "Y_2", Y_2);
        transcript.append(&session, .point, "Y_3", Y_3);

        const c = transcript.challengeScalar(&session, "c");

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
            .Y_3 = Y_3,
            .z_r = z_r,
            .z_x = z_x,
        };
    }

    fn Params(batched: bool) type {
        return if (batched)
            struct {
                first_pubkey: *const ElGamalPubkey,
                second_pubkey: *const ElGamalPubkey,
                third_pubkey: *const ElGamalPubkey,
                commitment: *const pedersen.Commitment,
                commitment_hi: *const pedersen.Commitment,
                first_handle: *const pedersen.DecryptHandle,
                first_handle_hi: *const pedersen.DecryptHandle,
                second_handle: *const pedersen.DecryptHandle,
                second_handle_hi: *const pedersen.DecryptHandle,
                third_handle: *const pedersen.DecryptHandle,
                third_handle_hi: *const pedersen.DecryptHandle,
            }
        else
            struct {
                commitment: *const pedersen.Commitment,
                first_pubkey: *const ElGamalPubkey,
                second_pubkey: *const ElGamalPubkey,
                third_pubkey: *const ElGamalPubkey,
                first_handle: *const pedersen.DecryptHandle,
                second_handle: *const pedersen.DecryptHandle,
                third_handle: *const pedersen.DecryptHandle,
            };
    }

    pub fn verify(
        self: Proof,
        comptime batched: bool,
        params: Params(batched),
        transcript: *Transcript,
    ) !void {
        comptime var session = Transcript.getSession(if (batched)
            batched_contract ++ contract
        else
            contract);
        defer session.finish();

        const t = if (batched) t: {
            transcript.appendHandleDomSep(.batched, .three);
            break :t transcript.challengeScalar(&session, "t");
        } else void; // shouldn't be referenced

        transcript.appendHandleDomSep(.unbatched, .three);

        try transcript.append(&session, .validate_point, "Y_0", self.Y_0);
        try transcript.append(&session, .validate_point, "Y_1", self.Y_1);
        try transcript.append(&session, .validate_point, "Y_2", self.Y_2);
        transcript.append(&session, .point, "Y_3", self.Y_3);

        const c = transcript.challengeScalar(&session, "c");
        const c_negated = Scalar.fromBytes(Edwards25519.scalar.neg(c.toBytes()));

        transcript.append(&session, .scalar, "z_r", self.z_r);
        transcript.append(&session, .scalar, "z_x", self.z_x);
        const w = transcript.challengeScalar(&session, "w");
        const ww = w.mul(w);
        const www = ww.mul(w);

        const w_negated = Scalar.fromBytes(Edwards25519.scalar.neg(w.toBytes()));
        const ww_negated = w_negated.mul(w);
        const www_negated = ww_negated.mul(w);

        //      points  scalars
        //  0   G        z_x
        //  1   H        z_r
        //  2   C       -c
        //  3   pub1     w z_r
        //  4   Y_1     -w
        //  5   h1      -w c
        //  6   pub2     ww z_r
        //  7   Y_2     -ww
        //  8   h2      -ww c
        //  9   pub3     www z_r
        // 10   Y_3     -www
        // 11   h3      -www c
        // 12   C_hi    -c t      (if batched)
        // 13   h1_hi   -c w t    (if batched)
        // 14   h2_hi   -c ww t   (if batched)
        // 15   h3_hi   -c www t  (if batched)
        // ----------------------- MSM
        //      Y_0

        var points: std14.BoundedArray(Ristretto255, 16) = .{};
        var scalars: std14.BoundedArray([32]u8, 16) = .{};

        try points.appendSlice(&.{
            pedersen.G,
            pedersen.H,
            params.commitment.point,
            params.first_pubkey.point,
            self.Y_1,
            params.first_handle.point,
            params.second_pubkey.point,
            self.Y_2,
            params.second_handle.point,
            params.third_pubkey.point,
            self.Y_3,
            params.third_handle.point,
        });
        // zig fmt: off
        try scalars.appendSlice(&.{
            self.z_x.toBytes(),           //  z_x
            self.z_r.toBytes(),           //  z_r
            c_negated.toBytes(),          // -c
            w.mul(self.z_r).toBytes(),    //  w * z_r
            w_negated.toBytes(),          // -w
            w_negated.mul(c).toBytes(),   // -w * c
            ww.mul(self.z_r).toBytes(),   //  ww * z_r
            ww_negated.toBytes(),         // -ww,
            ww_negated.mul(c).toBytes(),  // -ww * c
            www.mul(self.z_r).toBytes(),  //  www * z_r
            www_negated.toBytes(),        // -www
            www_negated.mul(c).toBytes(), // -www * c
        });
        // zig fmt: on

        if (batched) {
            try points.appendSlice(&.{
                params.commitment_hi.point,
                params.first_handle_hi.point,
                params.second_handle_hi.point,
                params.third_handle_hi.point,
            });
            try scalars.appendSlice(&.{
                c_negated.mul(t).toBytes(), // -c * t
                c_negated.mul(w).mul(t).toBytes(), // -c * w * t
                c_negated.mul(ww).mul(t).toBytes(), // -c * ww * t
                c_negated.mul(www).mul(t).toBytes(), // -c * www * t
            });
        }

        // give the optimizer a little hint on the two possible lengths
        switch (points.len) {
            12, 16 => {},
            else => unreachable,
        }

        const check = ed25519.straus.mulMultiRuntime(
            16,
            false,
            true,
            points.constSlice(),
            scalars.constSlice(),
        );

        if (!self.Y_0.equivalent(check)) {
            return error.AlgebraicRelation;
        }
    }

    pub fn fromBytes(bytes: [192]u8) !Proof {
        const Y_0 = try Ristretto255.fromBytes(bytes[0..32].*);
        const Y_1 = try Ristretto255.fromBytes(bytes[32..64].*);
        const Y_2 = try Ristretto255.fromBytes(bytes[64..96].*);
        const Y_3 = try Ristretto255.fromBytes(bytes[96..128].*);
        const z_r = Scalar.fromBytes(bytes[128..160].*);
        const z_x = Scalar.fromBytes(bytes[160..192].*);

        try Edwards25519.scalar.rejectNonCanonical(z_r.toBytes());
        try Edwards25519.scalar.rejectNonCanonical(z_x.toBytes());

        return .{
            .Y_0 = Y_0,
            .Y_1 = Y_1,
            .Y_2 = Y_2,
            .Y_3 = Y_3,
            .z_r = z_r,
            .z_x = z_x,
        };
    }

    fn toBytes(self: Proof) [192]u8 {
        return self.Y_0.toBytes() ++ self.Y_1.toBytes() ++ self.Y_2.toBytes() ++
            self.Y_3.toBytes() ++ self.z_r.toBytes() ++ self.z_x.toBytes();
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

    pub const TYPE: ProofType = .grouped_ciphertext3_handles_validity;
    pub const BYTE_LEN = 416;

    pub const Context = struct {
        first_pubkey: ElGamalPubkey,
        second_pubkey: ElGamalPubkey,
        third_pubkey: ElGamalPubkey,
        grouped_ciphertext: GroupedElGamalCiphertext(3),

        pub const BYTE_LEN = 224;

        pub fn fromBytes(bytes: [224]u8) !Context {
            return .{
                .first_pubkey = try .fromBytes(bytes[0..32].*),
                .second_pubkey = try .fromBytes(bytes[32..64].*),
                .third_pubkey = try .fromBytes(bytes[64..96].*),
                .grouped_ciphertext = try .fromBytes(bytes[96..][0..128].*),
            };
        }

        pub fn toBytes(self: Context) [224]u8 {
            return self.first_pubkey.toBytes() ++
                self.second_pubkey.toBytes() ++
                self.third_pubkey.toBytes() ++
                self.grouped_ciphertext.toBytes();
        }

        // zig fmt: off
        fn newTranscript(self: Context) Transcript {
            return .init(.@"grouped-ciphertext-validity-3-handles-instruction", &.{
                .{ .label = "first-pubkey",       .message = .{ .pubkey = self.first_pubkey } },
                .{ .label = "second-pubkey",      .message = .{ .pubkey = self.second_pubkey } },
                .{ .label = "third-pubkey",       .message = .{ .pubkey = self.third_pubkey } },
                .{ .label = "grouped-ciphertext", .message = .{ .grouped_3 = self.grouped_ciphertext } },
            });
        }
        // zig fmt: on
    };

    pub fn init(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        third_pubkey: *const ElGamalPubkey,
        grouped_ciphertext: *const GroupedElGamalCiphertext(3),
        amount: u64,
        opening: *const pedersen.Opening,
    ) Data {
        const context: Context = .{
            .first_pubkey = first_pubkey.*,
            .second_pubkey = second_pubkey.*,
            .third_pubkey = third_pubkey.*,
            .grouped_ciphertext = grouped_ciphertext.*,
        };
        var transcript = context.newTranscript();
        const proof = Proof.init(
            first_pubkey,
            second_pubkey,
            third_pubkey,
            amount,
            opening,
            &transcript,
        );
        return .{ .context = context, .proof = proof };
    }

    pub fn fromBytes(data: []const u8) !Data {
        if (data.len != BYTE_LEN) return error.InvalidLength;
        return .{
            .context = try Context.fromBytes(data[0..224].*),
            .proof = try Proof.fromBytes(data[224..][0..192].*),
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
        const third_handle = grouped_ciphertext.handles[2];

        try self.proof.verify(
            false,
            .{
                .commitment = &grouped_ciphertext.commitment,
                .first_pubkey = &self.context.first_pubkey,
                .second_pubkey = &self.context.second_pubkey,
                .third_pubkey = &self.context.third_pubkey,
                .first_handle = &first_handle,
                .second_handle = &second_handle,
                .third_handle = &third_handle,
            },
            &transcript,
        );
    }

    test "correctness" {
        const first_kp = ElGamalKeypair.random();
        const first_pubkey = first_kp.public;

        const second_kp = ElGamalKeypair.random();
        const second_pubkey = second_kp.public;

        const third_kp = ElGamalKeypair.random();
        const third_pubkey = third_kp.public;

        const amount: u64 = 55;
        const opening = pedersen.Opening.random();
        const grouped_ciphertext = elgamal.GroupedElGamalCiphertext(3).encryptWithOpening(
            .{ first_pubkey, second_pubkey, third_pubkey },
            amount,
            &opening,
        );

        const proof = Data.init(
            &first_pubkey,
            &second_pubkey,
            &third_pubkey,
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

    pub const TYPE: ProofType = .batched_grouped_ciphertext3_handles_validity;
    pub const BYTE_LEN = 544;

    pub const Context = struct {
        first_pubkey: ElGamalPubkey,
        second_pubkey: ElGamalPubkey,
        third_pubkey: ElGamalPubkey,
        grouped_ciphertext_lo: GroupedElGamalCiphertext(3),
        grouped_ciphertext_hi: GroupedElGamalCiphertext(3),

        pub const BYTE_LEN = 352;

        pub fn fromBytes(bytes: [352]u8) !Context {
            return .{
                .first_pubkey = try .fromBytes(bytes[0..32].*),
                .second_pubkey = try .fromBytes(bytes[32..64].*),
                .third_pubkey = try .fromBytes(bytes[64..96].*),
                .grouped_ciphertext_lo = try .fromBytes(bytes[96..][0..128].*),
                .grouped_ciphertext_hi = try .fromBytes(bytes[224..][0..128].*),
            };
        }

        pub fn toBytes(self: Context) [352]u8 {
            return self.first_pubkey.toBytes() ++
                self.second_pubkey.toBytes() ++
                self.third_pubkey.toBytes() ++
                self.grouped_ciphertext_lo.toBytes() ++
                self.grouped_ciphertext_hi.toBytes();
        }

        // zig fmt: off
        fn newTranscript(self: Context) Transcript {
            return .init(.@"batched-grouped-ciphertext-validity-3-handles-instruction", &.{
                .{ .label = "first-pubkey",          .message = .{ .pubkey = self.first_pubkey } },
                .{ .label = "second-pubkey",         .message = .{ .pubkey = self.second_pubkey } },
                .{ .label = "third-pubkey",          .message = .{ .pubkey = self.third_pubkey } },
                .{ .label = "grouped-ciphertext-lo", .message = .{ .grouped_3 = self.grouped_ciphertext_lo } },
                .{ .label = "grouped-ciphertext-hi", .message = .{ .grouped_3 = self.grouped_ciphertext_hi } },
            });
        }
        // zig fmt: on
    };

    pub fn init(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        third_pubkey: *const ElGamalPubkey,
        grouped_ciphertext_lo: *const GroupedElGamalCiphertext(3),
        grouped_ciphertext_hi: *const GroupedElGamalCiphertext(3),
        amount_lo: u64,
        amount_hi: u64,
        opening_lo: *const pedersen.Opening,
        opening_hi: *const pedersen.Opening,
    ) BatchedData {
        const context: Context = .{
            .first_pubkey = first_pubkey.*,
            .second_pubkey = second_pubkey.*,
            .third_pubkey = third_pubkey.*,
            .grouped_ciphertext_lo = grouped_ciphertext_lo.*,
            .grouped_ciphertext_hi = grouped_ciphertext_hi.*,
        };
        var transcript = context.newTranscript();
        const proof = Proof.initBatched(
            first_pubkey,
            second_pubkey,
            third_pubkey,
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
            .context = try Context.fromBytes(data[0..352].*),
            .proof = try Proof.fromBytes(data[352..][0..192].*),
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
        const third_handle_lo = grouped_ciphertext_lo.handles[2];

        const first_handle_hi = grouped_ciphertext_hi.handles[0];
        const second_handle_hi = grouped_ciphertext_hi.handles[1];
        const third_handle_hi = grouped_ciphertext_hi.handles[2];

        try self.proof.verify(
            true,
            .{
                .commitment = &grouped_ciphertext_lo.commitment,
                .commitment_hi = &grouped_ciphertext_hi.commitment,
                .first_pubkey = &self.context.first_pubkey,
                .second_pubkey = &self.context.second_pubkey,
                .third_pubkey = &self.context.third_pubkey,
                .first_handle = &first_handle_lo,
                .second_handle = &second_handle_lo,
                .third_handle = &third_handle_lo,
                .first_handle_hi = &first_handle_hi,
                .second_handle_hi = &second_handle_hi,
                .third_handle_hi = &third_handle_hi,
            },
            &transcript,
        );
    }

    test "correctness" {
        const first_kp = ElGamalKeypair.random();
        const first_pubkey = first_kp.public;

        const second_kp = ElGamalKeypair.random();
        const second_pubkey = second_kp.public;

        const third_kp = ElGamalKeypair.random();
        const third_pubkey = third_kp.public;

        const amount_lo: u64 = 11;
        const amount_hi: u64 = 22;

        const opening_lo = pedersen.Opening.random();
        const opening_hi = pedersen.Opening.random();

        const grouped_ciphertext_lo = elgamal.GroupedElGamalCiphertext(3).encryptWithOpening(
            .{ first_pubkey, second_pubkey, third_pubkey },
            amount_lo,
            &opening_lo,
        );
        const grouped_ciphertext_hi = elgamal.GroupedElGamalCiphertext(3).encryptWithOpening(
            .{ first_pubkey, second_pubkey, third_pubkey },
            amount_hi,
            &opening_hi,
        );

        const proof = BatchedData.init(
            &first_pubkey,
            &second_pubkey,
            &third_pubkey,
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

    const third_kp = ElGamalKeypair.random();
    const third_pubkey = third_kp.public;

    const amount: u64 = 55;
    const commitment, const opening = pedersen.initValue(u64, amount);

    const first_handle = pedersen.DecryptHandle.init(&first_pubkey, &opening);
    const second_handle = pedersen.DecryptHandle.init(&second_pubkey, &opening);
    const third_handle = pedersen.DecryptHandle.init(&third_pubkey, &opening);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        &third_pubkey,
        amount,
        &opening,
        &prover_transcript,
    );

    try proof.verify(
        false,
        .{
            .commitment = &commitment,
            .first_pubkey = &first_pubkey,
            .second_pubkey = &second_pubkey,
            .third_pubkey = &third_pubkey,
            .first_handle = &first_handle,
            .second_handle = &second_handle,
            .third_handle = &third_handle,
        },
        &verifier_transcript,
    );
}

test "first/second pubkey zeroed" {
    // if first or second public key zeroed, then the proof should always fail

    const first_pubkey = try ElGamalPubkey.fromBytes(.{0} ** 32);
    const second_pubkey = try ElGamalPubkey.fromBytes(.{0} ** 32);

    const third_kp = ElGamalKeypair.random();
    const third_pubkey = third_kp.public;

    const amount: u64 = 55;
    const commitment, const opening = pedersen.initValue(u64, amount);

    const first_handle = pedersen.DecryptHandle.init(&first_pubkey, &opening);
    const second_handle = pedersen.DecryptHandle.init(&second_pubkey, &opening);
    const third_handle = pedersen.DecryptHandle.init(&third_pubkey, &opening);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        &third_pubkey,
        amount,
        &opening,
        &prover_transcript,
    );

    try std.testing.expectError(
        error.IdentityElement,
        proof.verify(
            false,
            .{
                .commitment = &commitment,
                .first_pubkey = &first_pubkey,
                .second_pubkey = &second_pubkey,
                .third_pubkey = &third_pubkey,
                .first_handle = &first_handle,
                .second_handle = &second_handle,
                .third_handle = &third_handle,
            },
            &verifier_transcript,
        ),
    );
}

test "zeroed ciphertext" {
    // zeroed ciphertext should still be successfully verify
    const first_kp = ElGamalKeypair.random();
    const first_pubkey = first_kp.public;

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const third_kp = ElGamalKeypair.random();
    const third_pubkey = third_kp.public;

    const amount: u64 = 0;
    const commitment = try pedersen.Commitment.fromBytes(.{0} ** 32);
    const opening = try pedersen.Opening.fromBytes(.{0} ** 32);

    const first_handle = pedersen.DecryptHandle.init(&first_pubkey, &opening);
    const second_handle = pedersen.DecryptHandle.init(&second_pubkey, &opening);
    const third_handle = pedersen.DecryptHandle.init(&third_pubkey, &opening);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        &third_pubkey,
        amount,
        &opening,
        &prover_transcript,
    );

    try proof.verify(
        false,
        .{
            .commitment = &commitment,
            .first_pubkey = &first_pubkey,
            .second_pubkey = &second_pubkey,
            .third_pubkey = &third_pubkey,
            .first_handle = &first_handle,
            .second_handle = &second_handle,
            .third_handle = &third_handle,
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

    const third_kp = ElGamalKeypair.random();
    const third_pubkey = third_kp.public;

    const amount: u64 = 55;
    const zeroed_opening = try pedersen.Opening.fromBytes(.{0} ** 32);
    const commitment = pedersen.initOpening(u64, amount, &zeroed_opening);

    const first_handle = pedersen.DecryptHandle.init(&first_pubkey, &zeroed_opening);
    const second_handle = pedersen.DecryptHandle.init(&second_pubkey, &zeroed_opening);
    const third_handle = pedersen.DecryptHandle.init(&third_pubkey, &zeroed_opening);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        &third_pubkey,
        amount,
        &zeroed_opening,
        &prover_transcript,
    );

    try proof.verify(
        false,
        .{
            .commitment = &commitment,
            .first_pubkey = &first_pubkey,
            .second_pubkey = &second_pubkey,
            .third_pubkey = &third_pubkey,
            .first_handle = &first_handle,
            .second_handle = &second_handle,
            .third_handle = &third_handle,
        },
        &verifier_transcript,
    );
}

test "proof string" {
    const commitment_string = "DDSCVZLH+eqC9gX+ZeP3HQQxigojAOgda3YwVChR5W4=";
    const commitment = try pedersen.Commitment.fromBase64(commitment_string);

    const first_pubkey_string = "yGGJnLUs8B744So/Ua3n2wNm+8u9ey/6KrDdHx4ySwk=";
    const first_pubkey = try ElGamalPubkey.fromBase64(first_pubkey_string);

    const second_pubkey_string = "ZFETe85sZdWpxLAo177kwiOxZCpsXGeyZEnzern7tAk=";
    const second_pubkey = try ElGamalPubkey.fromBase64(second_pubkey_string);

    const third_pubkey_string = "duUYiBx0l0jRRPsTLCoCD8PIKFczPdrxl+2f4eCflhQ=";
    const third_pubkey = try ElGamalPubkey.fromBase64(third_pubkey_string);

    const first_handle_string = "Asor2klomf847EmJZmXn3qoi0SGE3cBXCkKttbJa+lE=";
    const first_handle = try pedersen.DecryptHandle.fromBase64(first_handle_string);

    const second_handle_string = "kJ0GYHDVeB1Kgvqp+MY/my3BYZvqsC5Mv0gQLJHnNBQ=";
    const second_handle = try pedersen.DecryptHandle.fromBase64(second_handle_string);

    const third_handle_string = "Jnd5jZLNDOMMt+kbgQWCQqTytbwHx3Bz5vwtfDLhRn0=";
    const third_handle = try pedersen.DecryptHandle.fromBase64(third_handle_string);

    // zig fmt: off
    const proof_string = "8NoqOM40+fvPY2aHzO0SdWZM6lvSoaqI7KpaFuE4wQUaqewILtQV8IMHeHmpevxt/GTErJsdcV8kY3HDZ1GHbMoDujYpstUhyubX1voJh/DstYAL1SQqlRpNLG+kWEUZYvCudTur7i5R+zqZQY3sRMEAxW458V+1GmyCWbWP3FZEz5gX/Pa28/ZNLBvmSPpJBZapXRI5Ra0dKPskFmQ0CH0gBWo6pxj/PH9sgNEkLrbVZB7jpVtdmNzivwgFeb4M";
    const proof = try Proof.fromBase64(proof_string);
    // zig fmt: on

    var verifier_transcript = Transcript.initTest("Test");

    try proof.verify(
        false,
        .{
            .commitment = &commitment,
            .first_pubkey = &first_pubkey,
            .second_pubkey = &second_pubkey,
            .third_pubkey = &third_pubkey,
            .first_handle = &first_handle,
            .second_handle = &second_handle,
            .third_handle = &third_handle,
        },
        &verifier_transcript,
    );
}

test "batched correctness" {
    const first_kp = ElGamalKeypair.random();
    const first_pubkey = first_kp.public;

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const third_kp = ElGamalKeypair.random();
    const third_pubkey = third_kp.public;

    const amount_lo: u64 = 55;
    const amount_hi: u64 = 77;

    const commitment_lo, const opening_lo = pedersen.initValue(u64, amount_lo);
    const commitment_hi, const opening_hi = pedersen.initValue(u64, amount_hi);

    const first_handle_lo = pedersen.DecryptHandle.init(&first_pubkey, &opening_lo);
    const first_handle_hi = pedersen.DecryptHandle.init(&first_pubkey, &opening_hi);

    const second_handle_lo = pedersen.DecryptHandle.init(&second_pubkey, &opening_lo);
    const second_handle_hi = pedersen.DecryptHandle.init(&second_pubkey, &opening_hi);

    const third_handle_lo = pedersen.DecryptHandle.init(&third_pubkey, &opening_lo);
    const third_handle_hi = pedersen.DecryptHandle.init(&third_pubkey, &opening_hi);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.initBatched(
        &first_pubkey,
        &second_pubkey,
        &third_pubkey,
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
            .third_pubkey = &third_pubkey,
            .commitment = &commitment_lo,
            .commitment_hi = &commitment_hi,
            .first_handle = &first_handle_lo,
            .first_handle_hi = &first_handle_hi,
            .second_handle = &second_handle_lo,
            .second_handle_hi = &second_handle_hi,
            .third_handle = &third_handle_lo,
            .third_handle_hi = &third_handle_hi,
        },
        &verifier_transcript,
    );
}

test "batched proof string" {
    const first_pubkey_string = "PFQ4AD4W/Y4BEg3nI/qckFLhnjMQ12xPHyaMg9Bkg3w=";
    const first_pubkey = try ElGamalPubkey.fromBase64(first_pubkey_string);

    const second_pubkey_string = "2CZ4h5oK7zh4/3P6s/kCQoNlpUPk1IrsrAtTWjCtfFo=";
    const second_pubkey = try ElGamalPubkey.fromBase64(second_pubkey_string);

    const third_pubkey_string = "yonKhqkoXNvMbN/tU6fjHFhfZuNPpvMj8L55aP2bBG4=";
    const third_pubkey = try ElGamalPubkey.fromBase64(third_pubkey_string);

    const commitment_lo_string = "atIteiveexponnuF2Z1nbovZYYtcGWjglpEA3caMShM=";
    const commitment_lo = try pedersen.Commitment.fromBase64(commitment_lo_string);

    const commitment_hi_string = "IoZlSj7spae2ogiAUiEuuwAjYA5khgBH8FhaHzkh+lc=";
    const commitment_hi = try pedersen.Commitment.fromBase64(commitment_hi_string);

    const first_handle_lo_string = "6PlKiitdapVZnh7VccQNbskXop9nmITGppLsV42UMkU=";
    const first_handle_lo = try pedersen.DecryptHandle.fromBase64(first_handle_lo_string);

    const first_handle_hi_string = "vF+oZ3WWnrJyJ95Wl8EW+aVJiFmruiuRw6+TT3QVMBI=";
    const first_handle_hi = try pedersen.DecryptHandle.fromBase64(first_handle_hi_string);

    const second_handle_lo_string = "rvxzo5ZyrD6YTm7X3GjplgOGJjx6PtoZ+DKbL4LsQWA=";
    const second_handle_lo = try pedersen.DecryptHandle.fromBase64(second_handle_lo_string);

    const second_handle_hi_string = "0mdZSGiWQhOjqsExqFMD8hfgUlRRRrF/G3CJ7d0LEEk=";
    const second_handle_hi = try pedersen.DecryptHandle.fromBase64(second_handle_hi_string);

    const third_handle_lo_string = "bpT2LuFektFhI/sacjSsqNtCsO8ac5qn0jWeMeQq4WM=";
    const third_handle_lo = try pedersen.DecryptHandle.fromBase64(third_handle_lo_string);

    const third_handle_hi_string = "OE8z7Bbv2AHnjxebK6ASJfkJbOlYQdnN6ZPkG2u4SnA=";
    const third_handle_hi = try pedersen.DecryptHandle.fromBase64(third_handle_hi_string);

    // zig fmt: off
    const proof_string = "GkjZ7QKcJq5X/OU8wb26wZ7p2D9thVK+Cb11CzRjWUoihYvGfuCbVG1vr4qtnfx65SS4jVK1H0q/948A9wy8ZPTrOZJA122G4+cpt5mKnSrKq/vbv4ZRha0oR9RGJFZ2SPT3gx2jysKDKRAQgBLOzSGfQg9Hsbz57i55SQfliUF5mByZKuzGKHSIHi81BDqbrFAj6x5bOeMAaLqsCboCA5XGDUZ2HMPUGuAd9F+OaVH+eJZnuoDjwwcBQ2eANgMB";
    const proof = try Proof.fromBase64(proof_string);
    // zig fmt: on

    var verifier_transcript = Transcript.initTest("Test");

    try proof.verify(
        true,
        .{
            .first_pubkey = &first_pubkey,
            .second_pubkey = &second_pubkey,
            .third_pubkey = &third_pubkey,
            .commitment = &commitment_lo,
            .commitment_hi = &commitment_hi,
            .first_handle = &first_handle_lo,
            .first_handle_hi = &first_handle_hi,
            .second_handle = &second_handle_lo,
            .second_handle_hi = &second_handle_hi,
            .third_handle = &third_handle_lo,
            .third_handle_hi = &third_handle_hi,
        },
        &verifier_transcript,
    );
}
