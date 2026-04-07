//! [fd](https://github.com/firedancer-io/firedancer/blob/33538d35a623675e66f38f77d7dc86c1ba43c935/src/flamenco/runtime/program/zksdk/instructions/fd_zksdk_percentage_with_cap.c)
//! [agave](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/zk-sdk/src/sigma_proofs/percentage_with_cap.rs)

const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../sig.zig");

const ed25519 = sig.crypto.ed25519;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const pedersen = sig.zksdk.pedersen;
const ProofType = sig.runtime.program.zk_elgamal.ProofType;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const Transcript = sig.zksdk.Transcript;
const DomainSeperator = Transcript.DomainSeperator;

pub const Proof = struct {
    max_proof: MaxProof,
    equality_proof: EqualityProof,

    /// The percentage-with-cap sigma proof is a bit different in that it creates
    /// two possible proofs and then selects which one to use. This requires us
    /// to perform the same transcript contract twice. The best way to represent
    /// that in a safe manner is to simply have an "init" contract, which will be
    /// run a single time at the start, and the state of that transcript is cloned
    /// and copied into each of the potential proofs which then run the "proof" contract.
    const init_contract: Transcript.Contract = &.{
        .{ .label = "percentage-commitment", .type = .validate_commitment },
        .{ .label = "delta-commitment", .type = .validate_commitment },
        .{ .label = "claimed-commitment", .type = .validate_commitment },
        .{ .label = "max-value", .type = .u64 },
        .domain(.@"percentage-with-cap-proof"),
    };
    const proof_contract: Transcript.Contract = &.{
        .{ .label = "Y_max_proof", .type = .validate_point },
        .{ .label = "Y_delta", .type = .validate_point },
        .{ .label = "Y_claimed", .type = .validate_point },
        .{ .label = "c", .type = .challenge },

        .{ .label = "z_max", .type = .scalar },
        .{ .label = "c_max_proof", .type = .scalar },
        .{ .label = "z_x", .type = .scalar },
        .{ .label = "z_delta_real", .type = .scalar },
        .{ .label = "z_claimed", .type = .scalar },
        .{ .label = "w", .type = .challenge },
    };

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
    ) Proof {
        {
            comptime var session = Transcript.getInitSession(init_contract);
            defer session.finish();

            // sig fmt: off
            transcript.appendNoValidate(&session, .commitment, "percentage-commitment", percentage_commitment.*);
            transcript.appendNoValidate(&session, .commitment, "delta-commitment", delta_commitment.*);
            transcript.appendNoValidate(&session, .commitment, "claimed-commitment", claimed_commitment.*);
            transcript.append(&session, .u64, "max-value", max_value);
            transcript.appendDomSep(&session, .@"percentage-with-cap-proof");
            // sig fmt: on
        }

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

        // Chooses between `proof_below_max` and `proof_above_max` depending
        // on whether the percentage amount is above the max amount.
        const below_max = percentage_amount <= max_value;
        const active = if (below_max) proof_below_max else proof_above_max;

        return .{
            .max_proof = active.max_proof,
            .equality_proof = active.equality_proof,
        };
    }

    fn createProofAboveMax(
        percentage_opening: *const pedersen.Opening,
        delta_commitment: *const pedersen.Commitment,
        claimed_commitment: *const pedersen.Commitment,
        transcript: *Transcript,
    ) Proof {
        const C_delta = delta_commitment.point;
        const C_claimed = claimed_commitment.point;

        const z_x = Scalar.random();
        const z_delta = Scalar.random();
        const z_claimed = Scalar.random();
        var c_equality = Scalar.random();
        defer std.crypto.secureZero(u64, &c_equality.limbs);

        const Y_delta = ed25519.mulMulti(3, .{
            pedersen.G,
            pedersen.H,
            C_delta,
        }, .{
            z_x.toBytes(),
            z_delta.toBytes(),
            Edwards25519.scalar.neg(c_equality.toBytes()),
        });

        const Y_claimed = ed25519.mulMulti(3, .{
            pedersen.G,
            pedersen.H,
            C_claimed,
        }, .{
            z_x.toBytes(),
            z_claimed.toBytes(),
            Edwards25519.scalar.neg(c_equality.toBytes()),
        });

        const equality_proof: EqualityProof = .{
            .Y_delta = Y_delta,
            .Y_claimed = Y_claimed,
            .z_x = z_x,
            .z_delta = z_delta,
            .z_claimed = z_claimed,
        };

        const r_percentage = percentage_opening.scalar;

        var y_max_proof = Scalar.random();
        const Y_max_proof = ed25519.straus.mulByKnown(pedersen.H, y_max_proof.toBytes());
        defer std.crypto.secureZero(u64, &y_max_proof.limbs);

        comptime var session = Transcript.getSession(proof_contract);
        defer session.finish();

        transcript.appendNoValidate(&session, .point, "Y_max_proof", Y_max_proof);
        transcript.appendNoValidate(&session, .point, "Y_delta", Y_delta);
        transcript.appendNoValidate(&session, .point, "Y_claimed", Y_claimed);

        const c = transcript.challengeScalar(&session, "c").toBytes();
        const c_max_proof = Edwards25519.scalar.sub(c, c_equality.toBytes());

        const z_max_proof = Scalar.fromBytes(c_max_proof).mul(r_percentage).add(y_max_proof);

        const max_proof: MaxProof = .{
            .Y_max_proof = Y_max_proof,
            .z_max_proof = z_max_proof,
            .c_max_proof = Scalar.fromBytes(c_max_proof),
        };

        if (builtin.mode == .Debug) {
            transcript.append(&session, .scalar, "z_max", z_max_proof);
            transcript.append(&session, .scalar, "c_max_proof", Scalar.fromBytes(c_max_proof));
            transcript.append(&session, .scalar, "z_x", z_x);
            transcript.append(&session, .scalar, "z_delta_real", z_delta);
            transcript.append(&session, .scalar, "z_claimed", z_claimed);
            _ = transcript.challengeScalar(&session, "w");
        }

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
    ) Proof {
        const m = pedersen.scalarFromInt(u64, max_value);
        const C_percentage = percentage_commitment.point;

        const z_max_proof = Scalar.random();
        const c_max_proof = Scalar.random();

        const Y_max_proof = ed25519.mulMulti(3, .{
            pedersen.H,
            C_percentage,
            pedersen.G,
        }, .{
            z_max_proof.toBytes(),
            Edwards25519.scalar.neg(c_max_proof.toBytes()),
            c_max_proof.mul(m).toBytes(),
        });

        const max_proof: MaxProof = .{
            .Y_max_proof = Y_max_proof,
            .z_max_proof = z_max_proof,
            .c_max_proof = c_max_proof,
        };

        var x = pedersen.scalarFromInt(u64, delta_amount);
        defer std.crypto.secureZero(u64, &x.limbs);

        const r_delta = delta_opening.scalar;
        const r_claimed = claimed_opening.scalar;

        var y_x = Scalar.random();
        var y_delta = Scalar.random();
        var y_claimed = Scalar.random();
        defer {
            std.crypto.secureZero(u64, &y_x.limbs);
            std.crypto.secureZero(u64, &y_delta.limbs);
            std.crypto.secureZero(u64, &y_claimed.limbs);
        }

        const Y_delta = ed25519.mulMulti(2, .{
            pedersen.G,
            pedersen.H,
        }, .{
            y_x.toBytes(),
            y_delta.toBytes(),
        });

        const Y_claimed = ed25519.mulMulti(2, .{
            pedersen.G,
            pedersen.H,
        }, .{
            y_x.toBytes(),
            y_claimed.toBytes(),
        });

        comptime var session = Transcript.getSession(proof_contract);
        defer session.finish();

        transcript.appendNoValidate(&session, .point, "Y_max_proof", Y_max_proof);
        transcript.appendNoValidate(&session, .point, "Y_delta", Y_delta);
        transcript.appendNoValidate(&session, .point, "Y_claimed", Y_claimed);

        const c = transcript.challengeScalar(&session, "c").toBytes();
        var c_equality = Scalar.fromBytes(Edwards25519.scalar.sub(c, c_max_proof.toBytes()));
        defer std.crypto.secureZero(u64, &c_equality.limbs);

        const z_x = c_equality.mul(x).add(y_x);
        const z_delta = c_equality.mul(r_delta).add(y_delta);
        const z_claimed = c_equality.mul(r_claimed).add(y_claimed);

        const equality_proof: EqualityProof = .{
            .Y_delta = Y_delta,
            .Y_claimed = Y_claimed,
            .z_x = z_x,
            .z_delta = z_delta,
            .z_claimed = z_claimed,
        };

        if (builtin.mode == .Debug) {
            transcript.append(&session, .scalar, "z_max", z_max_proof);
            transcript.append(&session, .scalar, "c_max_proof", c_max_proof);
            transcript.append(&session, .scalar, "z_x", z_x);
            transcript.append(&session, .scalar, "z_delta_real", z_delta);
            transcript.append(&session, .scalar, "z_claimed", z_claimed);
            _ = transcript.challengeScalar(&session, "w");
        }

        return .{
            .max_proof = max_proof,
            .equality_proof = equality_proof,
        };
    }

    pub fn verify(
        self: Proof,
        percentage_commitment: *const pedersen.Commitment,
        delta_commitment: *const pedersen.Commitment,
        claimed_commitment: *const pedersen.Commitment,
        max_value: u64,
        transcript: *Transcript,
    ) !void {
        {
            comptime var session = Transcript.getInitSession(init_contract);
            defer session.finish();

            // sig fmt: off
            try transcript.append(&session, .validate_commitment, "percentage-commitment", percentage_commitment.*);
            try transcript.append(&session, .validate_commitment, "delta-commitment", delta_commitment.*);
            try transcript.append(&session, .validate_commitment, "claimed-commitment", claimed_commitment.*);
            transcript.append(&session, .u64, "max-value", max_value);
            transcript.appendDomSep(&session, .@"percentage-with-cap-proof");
            // sig fmt: on
        }

        const m = pedersen.scalarFromInt(u64, max_value);

        const C_max = percentage_commitment.point;
        const C_delta = delta_commitment.point;
        const C_claimed = claimed_commitment.point;

        comptime var session = Transcript.getSession(proof_contract);
        defer session.finish();

        const Y_max = self.max_proof.Y_max_proof;
        const z_max = self.max_proof.z_max_proof;

        const Y_delta_real = self.equality_proof.Y_delta;
        const Y_claimed = self.equality_proof.Y_claimed;

        const z_x = self.equality_proof.z_x;
        const z_delta_real = self.equality_proof.z_delta;
        const z_claimed = self.equality_proof.z_claimed;

        try transcript.append(&session, .validate_point, "Y_max_proof", Y_max);
        try transcript.append(&session, .validate_point, "Y_delta", Y_delta_real);
        try transcript.append(&session, .validate_point, "Y_claimed", Y_claimed);

        const c = transcript.challengeScalar(&session, "c").toBytes();
        const c_max_proof = self.max_proof.c_max_proof;
        const c_equality = Edwards25519.scalar.sub(c, c_max_proof.toBytes());

        transcript.append(&session, .scalar, "z_max", z_max);
        transcript.append(&session, .scalar, "c_max_proof", c_max_proof);
        transcript.append(&session, .scalar, "z_x", z_x);
        transcript.append(&session, .scalar, "z_delta_real", z_delta_real);
        transcript.append(&session, .scalar, "z_claimed", z_claimed);

        const w = transcript.challengeScalar(&session, "w");
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

        const check = ed25519.mulMulti(7, .{
            pedersen.G,
            pedersen.H,
            C_max,
            Y_delta_real,
            C_delta,
            Y_claimed,
            C_claimed,
        }, .{
            g, // c_max * m - (w + ww) z_x
            h, // z_max - (w z_delta + ww z_claimed)
            Edwards25519.scalar.neg(c_max_proof.toBytes()), // -c_max
            w.toBytes(), // w
            w.mul(Scalar.fromBytes(c_equality)).toBytes(), // w * c_eq
            ww.toBytes(), // ww
            ww.mul(Scalar.fromBytes(c_equality)).toBytes(), // ww * c_eq
        });

        if (!Y_max.equivalent(check)) {
            return error.AlgebraicRelation;
        }
    }

    pub fn fromBytes(bytes: [256]u8) !Proof {
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

    fn toBytes(self: Proof) [256]u8 {
        const max_proof = self.max_proof;
        const equality_proof = self.equality_proof;
        return max_proof.Y_max_proof.toBytes() ++ max_proof.z_max_proof.toBytes() ++
            max_proof.c_max_proof.toBytes() ++ equality_proof.Y_delta.toBytes() ++
            equality_proof.Y_claimed.toBytes() ++ equality_proof.z_x.toBytes() ++
            equality_proof.z_delta.toBytes() ++ equality_proof.z_claimed.toBytes();
    }

    pub fn fromBase64(string: []const u8) !Proof {
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

pub const Data = struct {
    context: Context,
    proof: Proof,

    pub const TYPE: ProofType = .percentage_with_cap;
    pub const BYTE_LEN = 360;
    const DOMAIN: DomainSeperator = .@"percentage-with-cap-instruction";

    pub const Context = struct {
        percentage_commitment: pedersen.Commitment,
        delta_commitment: pedersen.Commitment,
        claimed_commitment: pedersen.Commitment,
        max_value: u64,

        pub const BYTE_LEN = 104;

        pub fn fromBytes(bytes: [104]u8) !Context {
            return .{
                .percentage_commitment = try pedersen.Commitment.fromBytes(bytes[0..32].*),
                .delta_commitment = try pedersen.Commitment.fromBytes(bytes[32..64].*),
                .claimed_commitment = try pedersen.Commitment.fromBytes(bytes[64..96].*),
                .max_value = @bitCast(bytes[96..][0..8].*),
            };
        }

        pub fn toBytes(self: Context) [104]u8 {
            return self.percentage_commitment.toBytes() ++ self.delta_commitment.toBytes() ++
                self.claimed_commitment.toBytes() ++ @as([8]u8, @bitCast(self.max_value));
        }
    };

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
    ) Data {
        const context: Context = .{
            .percentage_commitment = percentage_commitment.*,
            .delta_commitment = delta_commitment.*,
            .claimed_commitment = claimed_commitment.*,
            .max_value = max_value,
        };
        var transcript = Transcript.init(DOMAIN);
        const proof = Proof.init(
            percentage_commitment,
            percentage_opening,
            percentage_amount,
            delta_commitment,
            delta_opening,
            delta_amount,
            claimed_commitment,
            claimed_opening,
            max_value,
            &transcript,
        );
        return .{ .context = context, .proof = proof };
    }

    pub fn fromBytes(data: []const u8) !Data {
        if (data.len != BYTE_LEN) return error.InvalidLength;
        return .{
            .context = try Context.fromBytes(data[0..104].*),
            .proof = try Proof.fromBytes(data[104..][0..256].*),
        };
    }

    pub fn toBytes(self: Data) [BYTE_LEN]u8 {
        return self.context.toBytes() ++ self.proof.toBytes();
    }

    pub fn verify(self: Data) !void {
        var transcript = Transcript.init(DOMAIN);
        try self.proof.verify(
            &self.context.percentage_commitment,
            &self.context.delta_commitment,
            &self.context.claimed_commitment,
            self.context.max_value,
            &transcript,
        );
    }

    test "below max value" {
        const base_amount: u64 = 1;
        const max_value: u64 = 3;

        const percentage_rate: u16 = 400;
        const percentage_amount: u64 = 1;
        const delta_amount: u64 = 9_600;

        const base_commitment, const base_opening = pedersen.initValue(u64, base_amount);
        const percentage_commitment, //
        const percentage_opening = pedersen.initValue(u64, percentage_amount);

        const scalar_rate = pedersen.scalarFromInt(u64, percentage_rate);
        const ten_thousand = pedersen.scalarFromInt(u64, 10_000);

        const delta_commitment: pedersen.Commitment = d: {
            const a = try percentage_commitment.point.mul(ten_thousand.toBytes());
            const b = try base_commitment.point.mul(scalar_rate.toBytes());
            break :d .{ .point = .{ .p = a.p.sub(b.p) } };
        };
        const delta_opening: pedersen.Opening = d: {
            const a = percentage_opening.scalar.mul(ten_thousand);
            const b = base_opening.scalar.mul(scalar_rate);
            const c = Edwards25519.scalar.sub(a.toBytes(), b.toBytes());
            break :d .{ .scalar = Scalar.fromBytes(c) };
        };

        const claimed_commitment, const claimed_opening = pedersen.initValue(u64, delta_amount);

        const proof_data = Data.init(
            &percentage_commitment,
            &percentage_opening,
            percentage_amount,
            &delta_commitment,
            &delta_opening,
            delta_amount,
            &claimed_commitment,
            &claimed_opening,
            max_value,
        );

        try proof_data.verify();
    }

    test "equal to max value" {
        const base_amount: u64 = 55;
        const max_value: u64 = 3;

        const percentage_rate: u16 = 555;
        const percentage_amount: u64 = 4;
        const delta_amount: u64 = 9600;

        const transfer_commitment, const transfer_opening = pedersen.initValue(u64, base_amount);
        const percentage_commitment, const percentage_opening = pedersen.initValue(u64, max_value);

        const scalar_rate = pedersen.scalarFromInt(u64, percentage_rate);
        const ten_thousand = pedersen.scalarFromInt(u64, 10_000);

        const delta_commitment: pedersen.Commitment = d: {
            const a = try percentage_commitment.point.mul(ten_thousand.toBytes());
            const b = try transfer_commitment.point.mul(scalar_rate.toBytes());
            break :d .{ .point = .{ .p = a.p.sub(b.p) } };
        };
        const delta_opening: pedersen.Opening = d: {
            const a = percentage_opening.scalar.mul(ten_thousand);
            const b = transfer_opening.scalar.mul(scalar_rate);
            const c = Edwards25519.scalar.sub(a.toBytes(), b.toBytes());
            break :d .{ .scalar = Scalar.fromBytes(c) };
        };

        const claimed_commitment, const claimed_opening = pedersen.initValue(u64, 0);

        const proof_data = Data.init(
            &percentage_commitment,
            &percentage_opening,
            percentage_amount,
            &delta_commitment,
            &delta_opening,
            delta_amount,
            &claimed_commitment,
            &claimed_opening,
            max_value,
        );

        try proof_data.verify();
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

    const transfer_commitment, const transfer_opening = pedersen.initValue(u64, transfer_amount);
    const percentage_commitment, const percentage_opening = pedersen.initValue(u64, max_value);

    const scalar_rate = pedersen.scalarFromInt(u64, percentage_rate);
    const ten_thousand = pedersen.scalarFromInt(u64, 10_000);

    const delta_commitment: pedersen.Commitment = d: {
        const a = try percentage_commitment.point.mul(ten_thousand.toBytes());
        const b = try transfer_commitment.point.mul(scalar_rate.toBytes());
        break :d .{ .point = .{ .p = a.p.sub(b.p) } };
    };
    const delta_opening: pedersen.Opening = d: {
        const a = percentage_opening.scalar.mul(ten_thousand);
        const b = transfer_opening.scalar.mul(scalar_rate);
        break :d .{ .scalar = Scalar.fromBytes(Edwards25519.scalar.sub(a.toBytes(), b.toBytes())) };
    };

    const claimed_commitment, const claimed_opening = pedersen.initValue(u64, 0);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    var proof = Proof.init(
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

    const transfer_commitment, const transfer_opening =
        pedersen.initValue(u64, transfer_amount);
    const percentage_commitment, const percentage_opening =
        pedersen.initValue(u64, percentage_amount);

    const scalar_rate = pedersen.scalarFromInt(u64, percentage_rate);
    const ten_thousand = pedersen.scalarFromInt(u64, 10_000);

    const delta_commitment: pedersen.Commitment = d: {
        const a = try percentage_commitment.point.mul(ten_thousand.toBytes());
        const b = try transfer_commitment.point.mul(scalar_rate.toBytes());
        break :d .{ .point = .{ .p = a.p.sub(b.p) } };
    };
    const delta_opening: pedersen.Opening = d: {
        const a = percentage_opening.scalar.mul(ten_thousand);
        const b = transfer_opening.scalar.mul(scalar_rate);
        break :d .{ .scalar = Scalar.fromBytes(Edwards25519.scalar.sub(a.toBytes(), b.toBytes())) };
    };

    const claimed_commitment, const claimed_opening = pedersen.initValue(u64, delta);

    {
        const a = try pedersen.H.mul(delta_opening.scalar.toBytes());
        const b: Ristretto255 = .{ .p = delta_commitment.point.p.sub(a.p) };

        const c = try pedersen.H.mul(claimed_opening.scalar.toBytes());
        const d: Ristretto255 = .{ .p = claimed_commitment.point.p.sub(c.p) };

        try std.testing.expect(b.equivalent(d));
    }

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    var proof = Proof.init(
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

    const transfer_commitment, const transfer_opening =
        pedersen.initValue(u64, transfer_amount);
    const percentage_commitment, const percentage_opening =
        pedersen.initValue(u64, percentage_amount);

    const scalar_rate = pedersen.scalarFromInt(u64, percentage_rate);
    const ten_thousand = pedersen.scalarFromInt(u64, 10_000);

    const delta_commitment: pedersen.Commitment = d: {
        const a = try percentage_commitment.point.mul(ten_thousand.toBytes());
        const b = try transfer_commitment.point.mul(scalar_rate.toBytes());
        break :d .{ .point = .{ .p = a.p.sub(b.p) } };
    };

    const delta_opening: pedersen.Opening = d: {
        const a = percentage_opening.scalar.mul(ten_thousand);
        const b = transfer_opening.scalar.mul(scalar_rate);
        break :d .{ .scalar = Scalar.fromBytes(Edwards25519.scalar.sub(a.toBytes(), b.toBytes())) };
    };
    const claimed_commitment, const claimed_opening = pedersen.initValue(u64, delta);

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    var proof = Proof.init(
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

    const percentage_commitment_string = "OBDhFPvEfM1g2lR5dF0eH2pFGJC+MSW+B71WrUz8bkk=";
    const percentage_commitment = try pedersen.Commitment.fromBase64(percentage_commitment_string);

    const delta_commitment_string = "DGcxgwh381H/WiDlptyk3o2Q+eyDIEmIVY6JsdUI3GA=";
    const delta_commitment = try pedersen.Commitment.fromBase64(delta_commitment_string);

    const claimed_commitment_string = "PCUoVQfHE0ZV/ZrV5ECyqTzcZpSa3Hs9rkgoCTPsoxI=";
    const claimed_commitment = try pedersen.Commitment.fromBase64(claimed_commitment_string);

    // zig fmt: off
    const proof_string ="NPcjkaOzpPNz7uNZXMry5MsiVyqbSnThXioe+Ulw606XDZl2dpKcQ+wYhQqC+XH4aXCgbNB2mClYNZcR0pt7CFh64cJdNGkNuzVAjQBfeq0G+UM7ciF31UcT+1gvjcsIXA2RX9dpiXZWNqCBYbV4nwAV94RFi+ro4HNDBLnmQ3+C2xtal1Qob2tqurvUTYnUdaQDEpDdVhGhvOh8Y/jvTr4h2aQeDSBCi03qN9L4y8jAUXR4UcqwPWBJo7hp2gsF+qmg3iawG/d9taaOssRny6OVWwhuBU1P7pMKZeh1xAo/HCbAYY+CEz9SyMnUPPuZq+38npHiy6icqQoItwfRDg==";
    const proof = try Proof.fromBase64(proof_string);
    // zig fmt: on

    var verifier_transcript = Transcript.initTest("test");
    try proof.verify(
        &percentage_commitment,
        &delta_commitment,
        &claimed_commitment,
        max_value,
        &verifier_transcript,
    );
}
