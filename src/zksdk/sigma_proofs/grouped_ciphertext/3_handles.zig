//! [fd](https://github.com/firedancer-io/firedancer/blob/33538d35a623675e66f38f77d7dc86c1ba43c935/src/flamenco/runtime/program/zksdk/instructions/fd_zksdk_grouped_ciphertext_3_handles_validity.c)
//! [agave](https://github.com/anza-xyz/agave/blob/5a9906ebf4f24cd2a2b15aca638d609ceed87797/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs)

const std = @import("std");
const builtin = @import("builtin");
const sig = @import("../../../sig.zig");

const ed25519 = sig.crypto.ed25519;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const elgamal = sig.zksdk.elgamal;
const ElGamalKeypair = sig.zksdk.ElGamalKeypair;
const ElGamalPubkey = sig.zksdk.ElGamalPubkey;
const GroupedElGamalCiphertext = sig.zksdk.GroupedElGamalCiphertext(3);
const pedersen = sig.zksdk.pedersen;
const ProofType = sig.runtime.program.zk_elgamal.ProofType;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const Transcript = sig.zksdk.Transcript;

pub const Proof = struct {
    Y_0: Ristretto255,
    Y_1: Ristretto255,
    Y_2: Ristretto255,
    Y_3: Ristretto255,
    z_r: Scalar,
    z_x: Scalar,

    // The contract that batched proofs perform before the base contract.
    const batched_contract: Transcript.Contract = &.{
        .{ .label = "first-pubkey", .type = .validate_pubkey },
        .{ .label = "second-pubkey", .type = .validate_pubkey },
        .{ .label = "third-pubkey", .type = .pubkey },
        .{ .label = "grouped-ciphertext-lo", .type = .validate_grouped_3 },
        .{ .label = "grouped-ciphertext-hi", .type = .validate_grouped_3 },
        .domain(.@"batched-validity-proof"),
        .{ .label = "handles", .type = .u64 },
        .{ .label = "t", .type = .challenge },
    };

    /// This is the contract that un-batched proofs perform at the start.
    /// It's seperate as it differs from the one that batched does.
    const init_contract: Transcript.Contract = &.{
        .{ .label = "first-pubkey", .type = .validate_pubkey },
        .{ .label = "second-pubkey", .type = .validate_pubkey },
        .{ .label = "third-pubkey", .type = .pubkey },
        .{ .label = "grouped-ciphertext", .type = .validate_grouped_3 },
    };

    /// This is the contract both batched and unbatched proofs need to execute.
    /// It's always performed after either the `init_contract` or `batched_contract`.
    const base_contract: Transcript.Contract = &.{
        .domain(.@"validity-proof"),
        .{ .label = "handles", .type = .u64 },

        .{ .label = "Y_0", .type = .validate_point },
        .{ .label = "Y_1", .type = .validate_point },
        .{ .label = "Y_2", .type = .validate_point },
        .{ .label = "Y_3", .type = .point },
        .{ .label = "c", .type = .challenge },

        .{ .label = "z_r", .type = .scalar },
        .{ .label = "z_x", .type = .scalar },
        .{ .label = "w", .type = .challenge },
    };

    pub fn init(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        third_pubkey: *const ElGamalPubkey,
        grouped_ciphertext: *const GroupedElGamalCiphertext,
        amount: anytype,
        opening: *const pedersen.Opening,
        transcript: *Transcript,
    ) Proof {
        comptime var session = Transcript.getInitSession(init_contract);
        defer session.finish();

        transcript.appendNoValidate(&session, .pubkey, "first-pubkey", first_pubkey.*);
        transcript.appendNoValidate(&session, .pubkey, "second-pubkey", second_pubkey.*);
        transcript.append(&session, .pubkey, "third-pubkey", third_pubkey.*);
        transcript.appendNoValidate(&session, .grouped_3, "grouped-ciphertext", grouped_ciphertext.*);

        return initDirect(first_pubkey, second_pubkey, third_pubkey, amount, opening, transcript);
    }

    pub fn initBatched(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        third_pubkey: *const ElGamalPubkey,
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
        transcript.appendNoValidate(&session, .pubkey, "second-pubkey", second_pubkey.*);
        transcript.append(&session, .pubkey, "third-pubkey", third_pubkey.*);
        transcript.appendNoValidate(&session, .grouped_3, "grouped-ciphertext-lo", grouped_ciphertext_lo.*);
        transcript.appendNoValidate(&session, .grouped_3, "grouped-ciphertext-hi", grouped_ciphertext_hi.*);

        transcript.appendDomSep(&session, .@"batched-validity-proof");
        transcript.append(&session, .u64, "handles", 3);

        const t = transcript.challengeScalar(&session, "t");

        const scalar_lo = pedersen.scalarFromInt(u64, amount_lo);
        const scalar_hi = pedersen.scalarFromInt(u64, amount_hi);

        const batched_message = scalar_hi.mul(t).add(scalar_lo);
        const batched_opening: pedersen.Opening = .{
            .scalar = opening_hi.scalar.mul(t).add(opening_lo.scalar),
        };

        return initDirect(
            first_pubkey,
            second_pubkey,
            third_pubkey,
            batched_message,
            &batched_opening,
            transcript,
        );
    }

    pub fn initDirect(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        third_pubkey: *const ElGamalPubkey,
        amount: anytype,
        opening: *const pedersen.Opening,
        transcript: *Transcript,
    ) Proof {
        comptime var session = Transcript.getSession(base_contract);
        defer session.finish();

        transcript.appendDomSep(&session, .@"validity-proof");
        transcript.append(&session, .u64, "handles", 3);

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

        transcript.appendNoValidate(&session, .point, "Y_0", Y_0);
        transcript.appendNoValidate(&session, .point, "Y_1", Y_1);
        transcript.appendNoValidate(&session, .point, "Y_2", Y_2);
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

    /// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L163
    pub fn verify(
        self: Proof,
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        third_pubkey: *const ElGamalPubkey,
        grouped_ciphertext: *const GroupedElGamalCiphertext,
        transcript: *Transcript,
    ) !void {
        comptime var session = Transcript.getInitSession(init_contract);
        defer session.finish();

        try transcript.append(&session, .validate_pubkey, "first-pubkey", first_pubkey.*);
        try transcript.append(&session, .validate_pubkey, "second-pubkey", second_pubkey.*);
        transcript.append(&session, .pubkey, "third-pubkey", third_pubkey.*);
        try transcript.append(&session, .validate_grouped_3, "grouped-ciphertext", grouped_ciphertext.*);

        try self.verifyDirect(false, .{
            .first_pubkey = first_pubkey,
            .second_pubkey = second_pubkey,
            .third_pubkey = third_pubkey,
            .commitment = &grouped_ciphertext.commitment,
            .first_handle = &grouped_ciphertext.handles[0],
            .second_handle = &grouped_ciphertext.handles[1],
            .third_handle = &grouped_ciphertext.handles[2],
        }, {}, transcript);
    }

    /// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/batched_grouped_ciphertext_validity/handles_3.rs#L111
    pub fn verifyBatched(
        self: Proof,
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        third_pubkey: *const ElGamalPubkey,
        grouped_ciphertext_lo: *const GroupedElGamalCiphertext,
        grouped_ciphertext_hi: *const GroupedElGamalCiphertext,
        transcript: *Transcript,
    ) !void {
        comptime var session = Transcript.getInitSession(batched_contract);
        defer session.finish();

        try transcript.append(&session, .validate_pubkey, "first-pubkey", first_pubkey.*);
        try transcript.append(&session, .validate_pubkey, "second-pubkey", second_pubkey.*);
        transcript.append(&session, .pubkey, "third-pubkey", third_pubkey.*);
        try transcript.append(&session, .validate_grouped_3, "grouped-ciphertext-lo", grouped_ciphertext_lo.*);
        try transcript.append(&session, .validate_grouped_3, "grouped-ciphertext-hi", grouped_ciphertext_hi.*);

        transcript.appendDomSep(&session, .@"batched-validity-proof");
        transcript.append(&session, .u64, "handles", 3);
        const t = transcript.challengeScalar(&session, "t");

        try self.verifyDirect(true, .{
            .first_pubkey = first_pubkey,
            .second_pubkey = second_pubkey,
            .third_pubkey = third_pubkey,
            .commitment = &grouped_ciphertext_lo.commitment,
            .first_handle = &grouped_ciphertext_lo.handles[0],
            .second_handle = &grouped_ciphertext_lo.handles[1],
            .third_handle = &grouped_ciphertext_lo.handles[2],
            .commitment_hi = &grouped_ciphertext_hi.commitment,
            .first_handle_hi = &grouped_ciphertext_hi.handles[0],
            .second_handle_hi = &grouped_ciphertext_hi.handles[1],
            .third_handle_hi = &grouped_ciphertext_hi.handles[2],
        }, t, transcript);
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

    /// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L198
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
        transcript.append(&session, .u64, "handles", 3);

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

        var points: std.BoundedArray(Ristretto255, 16) = .{};
        var scalars: std.BoundedArray([32]u8, 16) = .{};

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

        // Give the optimizer a little hint on the two possible lengths
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
        grouped_ciphertext: GroupedElGamalCiphertext,

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
    };

    pub fn init(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        third_pubkey: *const ElGamalPubkey,
        grouped_ciphertext: *const GroupedElGamalCiphertext,
        amount: u64,
        opening: *const pedersen.Opening,
    ) Data {
        const context: Context = .{
            .first_pubkey = first_pubkey.*,
            .second_pubkey = second_pubkey.*,
            .third_pubkey = third_pubkey.*,
            .grouped_ciphertext = grouped_ciphertext.*,
        };
        var transcript = Transcript.init(.@"batched-grouped-ciphertext-validity-3-handles-instruction");
        const proof = Proof.init(
            first_pubkey,
            second_pubkey,
            third_pubkey,
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
            .context = try Context.fromBytes(data[0..224].*),
            .proof = try Proof.fromBytes(data[224..][0..192].*),
        };
    }

    pub fn toBytes(self: Data) [BYTE_LEN]u8 {
        return self.context.toBytes() ++ self.proof.toBytes();
    }

    pub fn verify(self: Data) !void {
        var transcript = Transcript.init(.@"batched-grouped-ciphertext-validity-3-handles-instruction");
        try self.proof.verify(
            &self.context.first_pubkey,
            &self.context.second_pubkey,
            &self.context.third_pubkey,
            &self.context.grouped_ciphertext,
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
        grouped_ciphertext_lo: GroupedElGamalCiphertext,
        grouped_ciphertext_hi: GroupedElGamalCiphertext,

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
    };

    pub fn init(
        first_pubkey: *const ElGamalPubkey,
        second_pubkey: *const ElGamalPubkey,
        third_pubkey: *const ElGamalPubkey,
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
            .third_pubkey = third_pubkey.*,
            .grouped_ciphertext_lo = grouped_ciphertext_lo.*,
            .grouped_ciphertext_hi = grouped_ciphertext_hi.*,
        };
        var transcript = Transcript.init(.@"batched-grouped-ciphertext-validity-2-handles-instruction");
        const proof = Proof.initBatched(
            first_pubkey,
            second_pubkey,
            third_pubkey,
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
            .context = try Context.fromBytes(data[0..352].*),
            .proof = try Proof.fromBytes(data[352..][0..192].*),
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
            &self.context.third_pubkey,
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

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L362
test "correctness" {
    const first_kp = ElGamalKeypair.random();
    const first_pubkey = first_kp.public;

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const third_kp = ElGamalKeypair.random();
    const third_pubkey = third_kp.public;

    const amount: u64 = 55;
    const opening = pedersen.Opening.random();
    const grouped_ciphertext = GroupedElGamalCiphertext.encryptWithOpening(
        .{ first_pubkey, second_pubkey, third_pubkey },
        amount,
        &opening,
    );

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        &third_pubkey,
        &grouped_ciphertext,
        amount,
        &opening,
        &prover_transcript,
    );
    try proof.verify(
        &first_pubkey,
        &second_pubkey,
        &third_pubkey,
        &grouped_ciphertext,
        &verifier_transcript,
    );
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L410-L451
test "first/second pubkey zeroed" {
    const first_pubkey = try ElGamalPubkey.fromBytes(@splat(0));
    const second_pubkey = try ElGamalPubkey.fromBytes(@splat(0));

    const third_kp = ElGamalKeypair.random();
    const third_pubkey = third_kp.public;

    const amount: u64 = 55;
    const opening = pedersen.Opening.random();
    const grouped_ciphertext = GroupedElGamalCiphertext.encryptWithOpening(
        .{ first_pubkey, second_pubkey, third_pubkey },
        amount,
        &opening,
    );

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        &third_pubkey,
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
            &third_pubkey,
            &grouped_ciphertext,
            &verifier_transcript,
        ),
    );
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L453-L497
test "zeroed ciphertext" {
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

    const grouped_ciphertext: GroupedElGamalCiphertext = .{
        .commitment = commitment,
        .handles = .{ first_handle, second_handle, third_handle },
    };

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.init(
        &first_pubkey,
        &second_pubkey,
        &third_pubkey,
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
            &third_pubkey,
            &grouped_ciphertext,
            &verifier_transcript,
        ),
    );
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/grouped_ciphertext_validity/handles_3.rs#L501
test "proof string" {
    const first_pubkey_string = "EAbHeljb89aEvbxaq2i3T8e7kEh1iZa55G67S4aPN2U=";
    const first_pubkey = try ElGamalPubkey.fromBase64(first_pubkey_string);

    const second_pubkey_string = "lH291F1FwDQEFq3kyCEQ7ANACAoS+tthsCLBRMMKvCo=";
    const second_pubkey = try ElGamalPubkey.fromBase64(second_pubkey_string);

    const third_pubkey_string = "EuaVaP3a6YvTokc8dq6kKTnn9cz8A92nMISmDzWElGo=";
    const third_pubkey = try ElGamalPubkey.fromBase64(third_pubkey_string);

    // sig fmt: off
    const grouped_ciphertext_string = "BpvM2hRQg9xKqEC68Zjc7jtVKyfZ5hiF+BgF0+Pnz1CI+/lX8i7xgBejr9O+hrrKWAomNC6Zv5M8B+MUokxAClLrs+zhcm5TdpLbvtUsM/PTKVNKh30PRGSKr12e65EJ5EgyNO2FjjLL4o2jSJepbrOohkUVWojqTGQ4nZAhtVI=";
    const grouped_ciphertext = try GroupedElGamalCiphertext.fromBase64(grouped_ciphertext_string);

    const proof_string = "yAJhtqJPhXdUN24lYeD7J+n7/6F+aV+H0rBSseHvD1dEr2FWy9bl20Qf5E3CHA8IlvOzQQpMJiZ8B9sxhqGdDgwVNbhPhMaKksRqMyKrHq2Vpi3Uz8LB6/uCQNcYyLBMlCjgVpscvudqpLuIpk3PRVhC5igNBV9GSL6iXKAuhkWc2ubCdlZKXJM1xFAnTbn5RSoRmSonESBr4NBwjHyaCHMwX7W8+jjxBc3hDSJOqKNkZgym0gmWv64cc32wKVEA";
    const proof = try Proof.fromBase64(proof_string);
    // sig fmt: on

    var verifier_transcript = Transcript.initTest("Test");
    try proof.verify(
        &first_pubkey,
        &second_pubkey,
        &third_pubkey,
        &grouped_ciphertext,
        &verifier_transcript,
    );
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/batched_grouped_ciphertext_validity/handles_3.rs#L222
test "batched correctness" {
    const first_kp = ElGamalKeypair.random();
    const first_pubkey = first_kp.public;

    const second_kp = ElGamalKeypair.random();
    const second_pubkey = second_kp.public;

    const third_kp = ElGamalKeypair.random();
    const third_pubkey = third_kp.public;

    const amount_lo: u64 = 55;
    const amount_hi: u64 = 77;
    const opening_lo = pedersen.Opening.random();
    const opening_hi = pedersen.Opening.random();
    const grouped_ciphertext_lo = GroupedElGamalCiphertext.encryptWithOpening(
        .{ first_pubkey, second_pubkey, third_pubkey },
        amount_lo,
        &opening_lo,
    );
    const grouped_ciphertext_hi = GroupedElGamalCiphertext.encryptWithOpening(
        .{ first_pubkey, second_pubkey, third_pubkey },
        amount_hi,
        &opening_hi,
    );

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof.initBatched(
        &first_pubkey,
        &second_pubkey,
        &third_pubkey,
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
        &third_pubkey,
        &grouped_ciphertext_lo,
        &grouped_ciphertext_hi,
        &verifier_transcript,
    );
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.0/zk-sdk/src/sigma_proofs/batched_grouped_ciphertext_validity/handles_3.rs#L290
test "batched proof string" {
    const first_pubkey_string = "mv/4oSby3PfTEG9gG4SDDlkN3b0YTpuyjdX9+40FKQY=";
    const first_pubkey = try ElGamalPubkey.fromBase64(first_pubkey_string);

    const second_pubkey_string = "hPehNW3wI5YdK5b4yeIM+t9zS5oBtGILLiltFUui1UA=";
    const second_pubkey = try ElGamalPubkey.fromBase64(second_pubkey_string);

    const third_pubkey_string = "hlACCsmVJVIZxa25qpKbjBO11wg/Tdtcz954OtHOWVw=";
    const third_pubkey = try ElGamalPubkey.fromBase64(third_pubkey_string);

    // sig fmt: off
    const grouped_ciphertext_lo_string = "ksKg6KXMBA9iFSh/PMqV9k03AGz5eigsm2+TT6RZplg2HCExsRJJQCpHbCu+ab7aj5hMEWhNLokKB2S2uEsnEF7w6HriN99/+vKbkGg7613d2+TzX8gxjeC6boZWtGFCqH00JXSvbZIjbvOPffhGy/Y7u/zh1r+aeDmuQRd7vmM=";
    const grouped_ciphertext_lo = try GroupedElGamalCiphertext.fromBase64(grouped_ciphertext_lo_string);

    const grouped_ciphertext_hi_string = "DMNBOrDAamfntobNpK1EXJ/dSA44Qmhc5EeVcZTz/gQOnxO4GYRSpeiu7IwujAPPalnuaWkQYlzfS8b79OfNJRganJZYVQg4aU2Ul+OjKrETKdhCo7K3qFhMoJiZGJFKnHLFCGyDsCPyvc2FQopxjbaDjrVsmDTMEJPStpZZAH8=";
    const grouped_ciphertext_hi = try GroupedElGamalCiphertext.fromBase64(grouped_ciphertext_hi_string);

    const proof_string = "tA4eOWOFFKF50h5vEGUdh7znZDV2KY/PJN8aFsqtyVuOvHoJQTyxMA8f1PTYa39rTkiVEYz3r2eV4Es8gvDMXCZdQoSc/mHE5QsPLT02ArpTSsFoZ1z4E9DZOxIuoqQ5EBc4Zy/brk2NWbpJua4FtPQB7fLHWIS/YgK7v6/cKlKhz64iyKeZxmNFKi12awd5s9vRGDGZvv0inoF+QoqgBB5PRTCR933/r4+Alkx340oFTQnZG7HABG4ora3i0KwK";
    const proof = try Proof.fromBase64(proof_string);
    // sig fmt: on

    var verifier_transcript = Transcript.initTest("Test");
    try proof.verifyBatched(
        &first_pubkey,
        &second_pubkey,
        &third_pubkey,
        &grouped_ciphertext_lo,
        &grouped_ciphertext_hi,
        &verifier_transcript,
    );
}
