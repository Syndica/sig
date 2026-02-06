//! [fd](https://github.com/firedancer-io/firedancer/blob/33538d35a623675e66f38f77d7dc86c1ba43c935/src/flamenco/runtime/program/zksdk/instructions/fd_zksdk_grouped_ciphertext_2_handles_validity.c)
//! [agave](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_2.rs)

const std = @import("std");
const builtin = @import("builtin");
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
const GroupedElGamalCiphertext = elgamal.GroupedElGamalCiphertext(2);
const ProofType = sig.runtime.program.zk_elgamal.ProofType;

pub const Proof = struct {
    Y_0: Ristretto255,
    Y_1: Ristretto255,
    Y_2: Ristretto255,
    z_r: Scalar,
    z_x: Scalar,

    // The contract that batched proofs perform before the base contract.
    const batched_contract: Transcript.Contract = &.{
        .{ .label = "first-pubkey", .type = .validate_pubkey },
        .{ .label = "second-pubkey", .type = .pubkey },
        .{ .label = "grouped-ciphertext-lo", .type = .validate_grouped_2 },
        .{ .label = "grouped-ciphertext-hi", .type = .validate_grouped_2 },
        .domain(.@"batched-validity-proof"),
        .{ .label = "handles", .type = .u64 },
        .{ .label = "t", .type = .challenge },
    };

    /// This is the contract that un-batched proofs perform at the start.
    /// It's seperate as it differs from the one that batched does.
    const init_contract: Transcript.Contract = &.{
        .{ .label = "first-pubkey", .type = .validate_pubkey },
        .{ .label = "second-pubkey", .type = .pubkey },
        .{ .label = "grouped-ciphertext", .type = .validate_grouped_2 },
    };

    /// This is the contract both batched and unbatched proofs need to execute.
    /// It's always performed after either the `init_contract` or `batched_contract`.
    const base_contract: Transcript.Contract = &.{
        .domain(.@"validity-proof"),
        .{ .label = "handles", .type = .u64 },

        .{ .label = "Y_0", .type = .validate_point },
        .{ .label = "Y_1", .type = .validate_point },
        .{ .label = "Y_2", .type = .point },
        .{ .label = "c", .type = .challenge },

        .{ .label = "z_r", .type = .scalar },
        .{ .label = "z_x", .type = .scalar },
        .{ .label = "w", .type = .challenge },
    };

    /// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/batched_grouped_ciphertext_validity/handles_2.rs#L63
    pub fn initBatched(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        grouped_ciphertext_lo: *const GroupedElGamalCiphertext,
        grouped_ciphertext_hi: *const GroupedElGamalCiphertext,
        amount_lo: u64,
        amount_hi: u64,
        opening_lo: *const pedersen.Opening,
        opening_hi: *const pedersen.Opening,
        transcript: *Transcript,
    ) Proof {
        comptime var session = Transcript.getSession(batched_contract);
        defer session.finish();

        transcript.appendNoValidate(&session, .pubkey, "first-pubkey", first_pubkey.*);
        transcript.append(&session, .pubkey, "second-pubkey", second_pubkey.*);
        transcript.appendNoValidate(&session, .grouped_2, "grouped-ciphertext-lo", grouped_ciphertext_lo.*);
        transcript.appendNoValidate(&session, .grouped_2, "grouped-ciphertext-hi", grouped_ciphertext_hi.*);

        transcript.appendDomSep(&session, .@"batched-validity-proof");
        transcript.append(&session, .u64, "handles", 2);

        const t = transcript.challengeScalar(&session, "t");

        const scalar_lo = pedersen.scalarFromInt(u64, amount_lo);
        const scalar_hi = pedersen.scalarFromInt(u64, amount_hi);

        const batched_message = scalar_hi.mul(t).add(scalar_lo);
        const batched_opening: pedersen.Opening = .{
            .scalar = opening_hi.scalar.mul(t).add(opening_lo.scalar),
        };

        return initDirect(first_pubkey, second_pubkey, batched_message, &batched_opening, transcript);
    }

    /// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_2.rs#L68
    pub fn init(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        grouped_ciphertext: *const GroupedElGamalCiphertext,
        amount: anytype,
        opening: *const pedersen.Opening,
        transcript: *Transcript,
    ) Proof {
        comptime var session = Transcript.getInitSession(init_contract);
        defer session.finish();

        transcript.appendNoValidate(&session, .pubkey, "first-pubkey", first_pubkey.*);
        transcript.append(&session, .pubkey, "second-pubkey", second_pubkey.*);
        transcript.appendNoValidate(&session, .grouped_2, "grouped-ciphertext", grouped_ciphertext.*);

        return initDirect(first_pubkey, second_pubkey, amount, opening, transcript);
    }

    /// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_2.rs#L85
    pub fn initDirect(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        amount: anytype,
        opening: *const pedersen.Opening,
        transcript: *Transcript,
    ) Proof {
        comptime var session = Transcript.getSession(base_contract);
        defer session.finish();

        transcript.appendDomSep(&session, .@"validity-proof");
        transcript.append(&session, .u64, "handles", 2);

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

        transcript.appendNoValidate(&session, .point, "Y_0", Y_0);
        transcript.appendNoValidate(&session, .point, "Y_1", Y_1);
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

    /// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_2.rs#L145
    pub fn verify(
        self: Proof,
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        grouped_ciphertext: *const GroupedElGamalCiphertext,
        transcript: *Transcript,
    ) !void {
        comptime var session = Transcript.getInitSession(init_contract);
        defer session.finish();

        try transcript.append(&session, .validate_pubkey, "first-pubkey", first_pubkey.*);
        transcript.append(&session, .pubkey, "second-pubkey", second_pubkey.*);
        try transcript.append(&session, .validate_grouped_2, "grouped-ciphertext", grouped_ciphertext.*);

        try self.verifyDirect(false, .{
            .first_pubkey = first_pubkey,
            .second_pubkey = second_pubkey,
            .commitment = &grouped_ciphertext.commitment,
            .first_handle = &grouped_ciphertext.handles[0],
            .second_handle = &grouped_ciphertext.handles[1],
        }, {}, transcript);
    }

    /// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/batched_grouped_ciphertext_validity/handles_2.rs#L106
    pub fn verifyBatched(
        self: Proof,
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        grouped_ciphertext_lo: *const GroupedElGamalCiphertext,
        grouped_ciphertext_hi: *const GroupedElGamalCiphertext,
        transcript: *Transcript,
    ) !void {
        comptime var session = Transcript.getInitSession(batched_contract);
        defer session.finish();

        try transcript.append(&session, .validate_pubkey, "first-pubkey", first_pubkey.*);
        transcript.append(&session, .pubkey, "second-pubkey", second_pubkey.*);
        try transcript.append(&session, .validate_grouped_2, "grouped-ciphertext-lo", grouped_ciphertext_lo.*);
        try transcript.append(&session, .validate_grouped_2, "grouped-ciphertext-hi", grouped_ciphertext_hi.*);

        transcript.appendDomSep(&session, .@"batched-validity-proof");
        transcript.append(&session, .u64, "handles", 2);
        const t = transcript.challengeScalar(&session, "t");

        try self.verifyDirect(true, .{
            .first_pubkey = first_pubkey,
            .second_pubkey = second_pubkey,
            .commitment = &grouped_ciphertext_lo.commitment,
            .first_handle = &grouped_ciphertext_lo.handles[0],
            .second_handle = &grouped_ciphertext_lo.handles[1],
            .commitment_hi = &grouped_ciphertext_hi.commitment,
            .first_handle_hi = &grouped_ciphertext_hi.handles[0],
            .second_handle_hi = &grouped_ciphertext_hi.handles[1],
        }, t, transcript);
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

    /// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_2.rs#L170
    pub fn verifyDirect(
        self: Proof,
        comptime batched: bool,
        params: Params(batched),
        t: if (batched) Scalar else void,
        transcript: *Transcript,
    ) !void {
        comptime var session = Transcript.getSession(base_contract);
        defer session.finish();

        transcript.appendDomSep(&session, .@"validity-proof");
        transcript.append(&session, .u64, "handles", 2);

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

            // if second_pubkey is zero, then second_handle, second_handle_hi, and Y_2 must all be zero as well.
            try params.second_handle.point.rejectIdentity();
            try self.Y_2.rejectIdentity();
            if (batched) try params.second_handle_hi.point.rejectIdentity();
        }

        const c_negated_w = c_negated.mul(w);
        const z_r_w = self.z_r.mul(w);

        var points: std.BoundedArray(Ristretto255, 12) = .{};
        var scalars: std.BoundedArray([32]u8, 12) = .{};

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
            else => unreachable, // nothing is possible!
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
        grouped_ciphertext: GroupedElGamalCiphertext,

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
    };

    pub fn init(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        grouped_ciphertext: *const GroupedElGamalCiphertext,
        amount: u64,
        opening: *const pedersen.Opening,
    ) Data {
        const context: Context = .{
            .first_pubkey = first_pubkey.*,
            .second_pubkey = second_pubkey.*,
            .grouped_ciphertext = grouped_ciphertext.*,
        };
        var transcript = Transcript.init(.@"grouped-ciphertext-validity-2-handles-instruction");
        const proof = Proof.init(
            first_pubkey,
            second_pubkey,
            grouped_ciphertext,
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
        var transcript = Transcript.init(.@"grouped-ciphertext-validity-2-handles-instruction");
        try self.proof.verify(
            &self.context.first_pubkey,
            &self.context.second_pubkey,
            &self.context.grouped_ciphertext,
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
        grouped_ciphertext_lo: GroupedElGamalCiphertext,
        grouped_ciphertext_hi: GroupedElGamalCiphertext,

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
    };

    pub fn init(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        grouped_ciphertext_lo: *const GroupedElGamalCiphertext,
        grouped_ciphertext_hi: *const GroupedElGamalCiphertext,
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
        var transcript = Transcript.init(.@"batched-grouped-ciphertext-validity-2-handles-instruction");
        const proof = Proof.initBatched(
            first_pubkey,
            second_pubkey,
            grouped_ciphertext_lo,
            grouped_ciphertext_hi,
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
        var transcript = Transcript.init(.@"batched-grouped-ciphertext-validity-2-handles-instruction");
        try self.proof.verifyBatched(
            &self.context.first_pubkey,
            &self.context.second_pubkey,
            &self.context.grouped_ciphertext_lo,
            &self.context.grouped_ciphertext_hi,
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

        const grouped_ciphertext_lo = GroupedElGamalCiphertext.encryptWithOpening(
            .{ first_pubkey, second_pubkey },
            amount_lo,
            &opening_lo,
        );
        const grouped_ciphertext_hi = GroupedElGamalCiphertext.encryptWithOpening(
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

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_2.rs#L311
test "correctness" {
    const first_kp = ElGamalKeypair.random();
    const first_pubkey = first_kp.public;

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const amount: u64 = 55;
    const opening = pedersen.Opening.random();
    const grouped_ciphertext = GroupedElGamalCiphertext.encryptWithOpening(
        .{ first_pubkey, second_pubkey },
        amount,
        &opening,
    );

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        &grouped_ciphertext,
        amount,
        &opening,
        &prover_transcript,
    );
    try proof.verify(
        &first_pubkey,
        &second_pubkey,
        &grouped_ciphertext,
        &verifier_transcript,
    );
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_2.rs#L353-L389
test "first pubkey zeroed" {
    const first_pubkey = try ElGamalPubkey.fromBytes(.{0} ** 32);

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const amount: u64 = 55;
    const opening = pedersen.Opening.random();
    const grouped_ciphertext = GroupedElGamalCiphertext.encryptWithOpening(
        .{ first_pubkey, second_pubkey },
        amount,
        &opening,
    );

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        &grouped_ciphertext,
        amount,
        &opening,
        &prover_transcript,
    );

    try std.testing.expectError(
        error.IdentityElement,
        proof.verify(
            &first_pubkey,
            &second_pubkey,
            &grouped_ciphertext,
            &verifier_transcript,
        ),
    );
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_2.rs#L391-L429
test "zeroed ciphertext" {
    const first_kp = ElGamalKeypair.random();
    const first_pubkey = first_kp.public;

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const amount: u64 = 0;
    const opening = try pedersen.Opening.fromBytes(.{0} ** 32);
    const grouped_ciphertext = GroupedElGamalCiphertext.encryptWithOpening(
        .{ first_pubkey, second_pubkey },
        amount,
        &opening,
    );

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        &grouped_ciphertext,
        amount,
        &opening,
        &prover_transcript,
    );

    try std.testing.expectError(
        error.IdentityElement,
        proof.verify(
            &first_pubkey,
            &second_pubkey,
            &grouped_ciphertext,
            &verifier_transcript,
        ),
    );
}

test "proof string" {
    const first_pubkey_string = "gtNxEo4FPZgflFBNJP5bH5j8lNIKy2tSdMc2NgH9/GE=";
    const first_pubkey = try ElGamalPubkey.fromBase64(first_pubkey_string);

    const second_pubkey_string = "2n1QN21P9Sct2VLIPZPnMrKaaOk32HgJswBSrnS//2c=";
    const second_pubkey = try ElGamalPubkey.fromBase64(second_pubkey_string);

    const grouped_ciphertext_string = "ZBw1CGUSTw+HUMOz5kZfudrvpA06RRXZ3r1Fbbl9W2NgowjM+0pXGDX3o+15YjMOdYLMpATyRVOAn/tvViyndEZy4BYO6P9gK3snCDVBqVLWe3NhpYqZODiy0KycRLo1";
    const grouped_ciphertext = try GroupedElGamalCiphertext.fromBase64(grouped_ciphertext_string);

    // sig fmt: off
    const proof_string = "0KudqgloR0IekkFmhDTz63kwtqecTVEMZtmb1qruARuqqki5AjgZoyHy6qJG3AugO4Ur8AP6/4RbH+EJExAzNKJincDYZUxe1VFZRgmD4pRnfYz2NEqZ3YizYC3NQ051ii91O1FxQzYfXOjsnQl4qvtkZqM6c6gZMxWtVmlMJAuu3buONyUOsyDHEx0gXBWTN5hv/CvSZij7owfPnZ36CA==";
    const proof = try Proof.fromBase64(proof_string);
    // sig fmt: on

    var verifier_transcript = Transcript.initTest("Test");
    try proof.verify(
        &first_pubkey,
        &second_pubkey,
        &grouped_ciphertext,
        &verifier_transcript,
    );
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/batched_grouped_ciphertext_validity/handles_2.rs#L203
test "batched sanity" {
    const first_kp = ElGamalKeypair.random();
    const first_pubkey = first_kp.public;

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const amount_lo: u64 = 55;
    const amount_hi: u64 = 77;

    const opening_lo = pedersen.Opening.random();
    const opening_hi = pedersen.Opening.random();
    const grouped_ciphertext_lo = GroupedElGamalCiphertext.encryptWithOpening(
        .{ first_pubkey, second_pubkey },
        amount_lo,
        &opening_lo,
    );
    const grouped_ciphertext_hi = GroupedElGamalCiphertext.encryptWithOpening(
        .{ first_pubkey, second_pubkey },
        amount_hi,
        &opening_hi,
    );

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.initBatched(
        &first_pubkey,
        &second_pubkey,
        &grouped_ciphertext_lo,
        &grouped_ciphertext_hi,
        amount_lo,
        amount_hi,
        &opening_lo,
        &opening_hi,
        &prover_transcript,
    );

    try proof.verifyBatched(
        &first_pubkey,
        &second_pubkey,
        &grouped_ciphertext_lo,
        &grouped_ciphertext_hi,
        &verifier_transcript,
    );
}

test "batched proof string" {
    const first_pubkey_string = "cvkvHnlr6h8V9V1Q2mGj5+XH6SBvJRR3dMdDYtgnpwk=";
    const first_pubkey = try ElGamalPubkey.fromBase64(first_pubkey_string);

    const second_pubkey_string = "evcjLw8+v2mcWRisCCKXbjWVNRsC0JufOoSV5cR9ixg=";
    const second_pubkey = try ElGamalPubkey.fromBase64(second_pubkey_string);

    // sig fmt: off
    const grouped_ciphertext_lo_string = "MsnlU3s9YjWFaC3IjIKS52yl41X1xH+mre0BbAwE2j3E28wjWQPZn4B4nM+eV0zgihHq7uUSY57a4l42HJRULIBlCR/8G2Wfuq63WVbBroxmRbbJzZFGgdpGVLoFA8Aw";
    const grouped_ciphertext_lo = try GroupedElGamalCiphertext.fromBase64(grouped_ciphertext_lo_string);

    const grouped_ciphertext_hi_string = "2kpzTKaOoiNM/zZimt9g5uX60GFCes355lM4S2QvWx46YMpuGWoU5gG5G9hoCuY5T9PwGTiIQashf6mUFuulPWr0EYKatR7Q8dfyeFpJl2pdZ2Imwmf5LDqDUXSt9Zg3";
    const grouped_ciphertext_hi = try GroupedElGamalCiphertext.fromBase64(grouped_ciphertext_hi_string);

    const proof_string = "GqVxS3sISd9hw3r0jDx3qwNFArLpiXMcySvtQqu5PSGoZDTtRgXMDiSEPSRoTER7/pjI/z2G8yNWYBMS6E28U8rnVCAS6k1K8anbrTF4n7TRmAac4CdpKCh8AZPzvi40kpWskl20Fogq8WPVf1r2i6nesQGTrMsKXH5j7ShC8QZbPtTn878eTdB7K9DNWFxGshxL8KzMh0dLMlj7IAJnAg==";
    const proof = try Proof.fromBase64(proof_string);
    // sig fmt: on

    var verifier_transcript = Transcript.initTest("Test");

    try proof.verifyBatched(
        &first_pubkey,
        &second_pubkey,
        &grouped_ciphertext_lo,
        &grouped_ciphertext_hi,
        &verifier_transcript,
    );
}
