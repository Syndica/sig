//! Bulletproofs range-proof implementation over Curve25519 Ristretto points.
//!
//! Specifically implements non-interactive range proof aggregation
//! that is described in the original Bulletproofs
//! [paper](https://eprint.iacr.org/2017/1066) (Section 4.3).

const std = @import("std");
const builtin = @import("builtin");
const std14 = @import("std14");
const sig = @import("../../sig.zig");
const table = @import("table");
pub const InnerProductProof = @import("ipp.zig").Proof; // pub so tests can run

const pedersen = sig.zksdk.pedersen;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const ed25519 = sig.crypto.ed25519;
const Transcript = sig.zksdk.Transcript;
const ProofType = sig.runtime.program.zk_elgamal.ProofType;

pub const ZERO = Scalar.fromBytes(Edwards25519.scalar.zero);
pub const ONE = Scalar.fromBytes(.{1} ++ .{0} ** 31);
pub const TWO = Scalar.fromBytes(.{2} ++ .{0} ** 31);
const MAX_COMMITMENTS = 8;

pub fn Proof(bit_size: comptime_int) type {
    std.debug.assert(std.math.isPowerOfTwo(bit_size));
    std.debug.assert(bit_size <= 256);
    const logn: u64 = std.math.log2_int(u64, bit_size);
    const max = (2 * bit_size) + (2 * logn) + 5 + 8;

    const contract: Transcript.Contract = &[_]Transcript.Input{
        .{ .label = "A", .type = .validate_point },
        .{ .label = "S", .type = .validate_point },
        .{ .label = "y", .type = .challenge },
        .{ .label = "z", .type = .challenge },

        .{ .label = "T_1", .type = .validate_point },
        .{ .label = "T_2", .type = .validate_point },
        .{ .label = "x", .type = .challenge },

        .{ .label = "t_x", .type = .scalar },
        .{ .label = "t_x_blinding", .type = .scalar },
        .{ .label = "e_blinding", .type = .scalar },
        .{ .label = "w", .type = .challenge },

        .{ .label = "c", .type = .challenge },

        //  InnerProductProof(bit_size).contract runs here

        .{ .label = "ipp_a", .type = .scalar },
        .{ .label = "ipp_b", .type = .scalar },
        .{ .label = "d", .type = .challenge },
    };

    return struct {
        A: Ristretto255,
        S: Ristretto255,
        T_1: Ristretto255,
        T_2: Ristretto255,
        t_x: Scalar,
        t_x_blinding: Scalar,
        e_blinding: Scalar,
        ipp: InnerProductProof(bit_size),

        const Self = @This();

        // number of bytes this proof takes up in the compressed form
        pub const BYTE_LEN = (4 * 32) + // the four ristretto points
            (3 * 32) + // the three scalars
            2 * (logn * 32) + // the L_vec and R_vec in the ipp
            2 * 32; // the `a` and `b` scalars in the ipp

        /// degree-1 vector polynomial
        const VecPoly1 = struct {
            a: [bit_size]Scalar,
            b: [bit_size]Scalar,

            const zero: VecPoly1 = .{
                .a = @splat(ZERO),
                .b = @splat(ZERO),
            };

            fn ip(l: VecPoly1, r: VecPoly1) Poly2 {
                const t0 = innerProduct(&l.a, &r.a);
                const t2 = innerProduct(&l.b, &r.b);

                const la_plus_lb = addVec(&l.a, &l.b);
                const ra_plus_rb = addVec(&r.a, &r.b);

                // p - t0 - t2
                const p = innerProduct(&la_plus_lb, &ra_plus_rb);
                const t1 = Edwards25519.scalar.sub(p.toBytes(), t0.toBytes());

                return .{
                    .a = t0,
                    .b = .fromBytes(Edwards25519.scalar.sub(t1, t2.toBytes())),
                    .c = t2,
                };
            }

            fn eval(l: VecPoly1, x: Scalar) [bit_size]Scalar {
                var out: [bit_size]Scalar = undefined;
                for (&out, l.a, l.b) |*o, a, b| {
                    o.* = b.mul(x).add(a);
                }
                return out;
            }

            fn addVec(a: *const [bit_size]Scalar, b: *const [bit_size]Scalar) [bit_size]Scalar {
                var out: [bit_size]Scalar = undefined;
                for (&out, a, b) |*o, j, k| {
                    o.* = j.add(k);
                }
                return out;
            }
        };

        /// degree-2 scalar vector polynomial
        const Poly2 = struct {
            a: Scalar,
            b: Scalar,
            c: Scalar,

            fn evaluate(self: Poly2, x: Scalar) Scalar {
                const t0 = x.mul(self.c);
                const t1 = self.b.add(t0);
                const t2 = x.mul(t1);
                return t2.add(self.a);
            }
        };

        pub fn init(
            amounts: []const u64,
            bit_lengths: []const u64,
            openings: []const pedersen.Opening,
            transcript: *Transcript,
        ) !Self {
            // amounts, bit_lengths, and opening must all be the same length
            std.debug.assert(amounts.len == bit_lengths.len and openings.len == amounts.len);

            // should be checked before
            var nm: u64 = 0;
            for (bit_lengths) |len| {
                std.debug.assert(len != 0 and len <= bit_size);
                nm += len;
            }
            std.debug.assert(nm == bit_size);

            transcript.appendRangeProof(.range, bit_size);

            // bit-decompose values and generate their Pedersen vector commitment
            const a_blinding: Scalar = .random();
            var A = pedersen.H.mul(a_blinding.toBytes()) catch unreachable;

            var bit: u64 = 0;
            for (amounts, bit_lengths) |amount, n| {
                for (0..n) |j| {
                    // init functions aren't exposed, so doesn't need to be constant time.
                    const v = (amount >> @intCast(j)) & 0b1 != 0;
                    const point: Ristretto255 = if (v)
                        table.G[bit]
                    else
                        // TODO: use ristretto neg() alias when added to stdlib
                        .{ .p = table.H[bit].p.neg() };
                    A = A.add(point);
                    bit += 1;
                }
            }

            var s_L: [bit_size][32]u8 = undefined;
            var s_R: [bit_size][32]u8 = undefined;
            for (&s_L, &s_R) |*l, *r| {
                l.* = Scalar.random().toBytes();
                r.* = Scalar.random().toBytes();
            }
            const s_blinding = Scalar.random();

            const S = sig.crypto.ed25519.mulMulti(
                1 + bit_size * 2,
                .{pedersen.H} ++ table.G[0..bit_size].* ++ table.H[0..bit_size].*,
                .{s_blinding.toBytes()} ++ s_L ++ s_R,
            );

            comptime var session = Transcript.getSession(contract);
            defer session.finish();

            transcript.appendNoValidate(&session, "A", A);
            transcript.appendNoValidate(&session, "S", S);

            // y and z are used to merge multiple inner product relations into one inner product
            const y = transcript.challengeScalar(&session, "y");
            const z = transcript.challengeScalar(&session, "z");

            var l_poly: VecPoly1 = .zero;
            var r_poly: VecPoly1 = .zero;

            var i: usize = 0;
            var exp_z = z.mul(z);
            var exp_y = ONE;

            for (amounts, bit_lengths) |amount, n| {
                var exp_2 = ONE;

                for (0..n) |j| {
                    const predicate: u8 = @intCast(amount >> @intCast(j) & 0b1);
                    const a_L: [32]u8 = .{predicate} ++ .{0} ** 31;
                    const a_R = Edwards25519.scalar.sub(a_L, ONE.toBytes());

                    l_poly.a[i] = .fromBytes(Edwards25519.scalar.sub(a_L, z.toBytes()));
                    l_poly.b[i] = .fromBytes(s_L[i]);
                    // exp_y * (a_R + z) + exp_z * exp_2
                    r_poly.a[i] = exp_y.mul(Scalar.fromBytes(a_R).add(z)).add(exp_z.mul(exp_2));
                    r_poly.b[i] = exp_y.mul(Scalar.fromBytes(s_R[i]));

                    exp_y = exp_y.mul(y);
                    exp_2 = exp_2.add(exp_2);

                    i += 1;
                }
                exp_z = exp_z.mul(z);
            }

            const t_poly = l_poly.ip(r_poly);

            const T_1, const t_1_blinding = pedersen.initScalar(t_poly.b);
            const T_2, const t_2_blinding = pedersen.initScalar(t_poly.c);

            transcript.appendNoValidate(&session, "T_1", T_1.point);
            transcript.appendNoValidate(&session, "T_2", T_2.point);

            // evaluate t(x) on challenge x and homomorphically compute the openings for
            // z^2 * V_1 + z^3 * V_2 + ... + z^{m+1} * V_m + delta(y, z)*G + x*T_1 + x^2*T_2
            const x = transcript.challengeScalar(&session, "x");

            var agg_opening = ZERO;
            var agg_scalar = z;
            for (openings) |opening| {
                agg_scalar = agg_scalar.mul(z);
                agg_opening = agg_opening.add(agg_scalar.mul(opening.scalar));
            }

            const t_binding_poly: Poly2 = .{
                .a = agg_opening,
                .b = t_1_blinding.scalar,
                .c = t_2_blinding.scalar,
            };

            const t_x = t_poly.evaluate(x);
            const t_x_blinding = t_binding_poly.evaluate(x);

            transcript.append(&session, .scalar, "t_x", t_x);
            transcript.append(&session, .scalar, "t_x_blinding", t_x_blinding);

            // homomorphically compuate the openings for A + x*S
            const e_blinding = s_blinding.mul(x).add(a_blinding);
            transcript.append(&session, .scalar, "e_blinding", e_blinding);

            // compute the inner product argument on the commitment:
            // P = <l(x), G> + <r(x), H'> + <l(x), r(x)>*Q
            const w = transcript.challengeScalar(&session, "w");
            const Q = ed25519.straus.mulByKnown(pedersen.G, w.toBytes());

            const G_factors: [bit_size]Scalar = @splat(ONE);
            const H_factors = genPowers(bit_size, y.invert());

            _ = transcript.challengeScalar(&session, "c");

            var l_vec = l_poly.eval(x);
            var r_vec = r_poly.eval(x);
            const ipp_proof = InnerProductProof(bit_size).init(
                Q,
                &G_factors,
                &H_factors,
                &l_vec,
                &r_vec,
                transcript,
            );

            if (builtin.mode == .Debug) {
                transcript.append(&session, .scalar, "ipp_a", ipp_proof.a);
                transcript.append(&session, .scalar, "ipp_b", ipp_proof.b);
                _ = transcript.challengeScalar(&session, "d");
            }

            return .{
                .A = A,
                .S = S,
                .T_1 = T_1.point,
                .T_2 = T_2.point,
                .t_x = t_x,
                .t_x_blinding = t_x_blinding,
                .e_blinding = e_blinding,
                .ipp = ipp_proof,
            };
        }

        /// Uses the optimized verification described in section 6.2 of
        /// the [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf) paper.
        pub fn verify(
            self: Self,
            commitments: []const pedersen.Commitment,
            bit_lengths: []const u64,
            transcript: *Transcript,
        ) !void {
            std.debug.assert(commitments.len == bit_lengths.len);

            transcript.appendRangeProof(.range, bit_size);

            comptime var session = Transcript.getSession(contract);
            defer session.finish();

            try transcript.append(&session, .validate_point, "A", self.A);
            try transcript.append(&session, .validate_point, "S", self.S);

            const y = transcript.challengeScalar(&session, "y");
            const z = transcript.challengeScalar(&session, "z");

            try transcript.append(&session, .validate_point, "T_1", self.T_1);
            try transcript.append(&session, .validate_point, "T_2", self.T_2);

            const x = transcript.challengeScalar(&session, "x");

            transcript.append(&session, .scalar, "t_x", self.t_x);
            transcript.append(&session, .scalar, "t_x_blinding", self.t_x_blinding);
            transcript.append(&session, .scalar, "e_blinding", self.e_blinding);

            const w = transcript.challengeScalar(&session, "w");
            // only left for legacy reasons, use `d` instead
            _ = transcript.challengeScalar(&session, "c");

            const x_sq, //
            const x_inv_sq, //
            const s //
            = try self.ipp.verificationScalars(transcript);

            const a = self.ipp.a;
            const b = self.ipp.b;

            transcript.append(&session, .scalar, "ipp_a", a);
            transcript.append(&session, .scalar, "ipp_b", b);

            const d = transcript.challengeScalar(&session, "d");

            // (numbers use u128 as the example)
            //        points                scalars
            //   0    H                     -(e_blinding + d * t_x_blinding)
            //   1    S                     x
            //   2    T_1                   d * x
            //   3    T_2                   d * x * x
            //   4    commitments[ 0 ]      c z^2
            //        ...                   ...
            //   9    commitments[ 3 ]      c z^6
            //   8    L_vec[ 0 ]            x_sq[ 0 ]
            //        ...                   ...
            //  14    L_vec[ 6 ]            x_sq[ 6 ]
            //  15    R_vec[ 0 ]            x_sq_inv[ 0 ]
            //        ...                   ...
            //  21    R_vec[ 6 ]            x_sq_inv[ 6 ]
            //  22    generators_H[ 0 ]     TODO
            //        ...                   ...
            // 149    generators_H[ 127 ]   TODO
            // 150    generators_G[ 0 ]     (-a * s_0) + (-z)
            //        ...                   ...
            // 277    generators_G[ 127 ]   (-a * s_127) + (-z)
            // 278    G                     basepoint_scalar
            // ------------------------------------------------------ MSM
            //       -A
            //
            // basepoint_scalar depends on a bunch of values computed beforehand so it's added last

            var points: std14.BoundedArray(Ristretto255, max) = .{};
            var scalars: std14.BoundedArray([32]u8, max) = .{};

            points.appendSliceAssumeCapacity(&.{
                pedersen.H,
                self.S,
                self.T_1,
                self.T_2,
            });

            for (commitments) |commitment| points.appendAssumeCapacity(commitment.point);
            for (self.ipp.L_vec) |l| points.appendAssumeCapacity(l);
            for (self.ipp.R_vec) |r| points.appendAssumeCapacity(r);

            points.appendSliceAssumeCapacity(table.H[0..bit_size]);
            points.appendSliceAssumeCapacity(table.G[0..bit_size]);

            const d_txb = d.mul(self.t_x_blinding);
            const H = Edwards25519.scalar.neg(d_txb.add(self.e_blinding).toBytes());
            const d_x = d.mul(x);

            // G's scalar is inserted last, see below.
            scalars.appendSliceAssumeCapacity(&.{
                H, // H
                x.toBytes(), // S
                d_x.toBytes(), // T_1
                d_x.mul(x).toBytes(), // T_2
            });

            // commitments: c z^2, c z^3 ...
            const zz = z.mul(z);
            scalars.appendAssumeCapacity(zz.mul(d).toBytes());
            for (1..commitments.len) |_| {
                const z_d = Scalar.fromBytes(scalars.constSlice()[scalars.len - 1]);
                scalars.appendAssumeCapacity(z_d.mul(z).toBytes());
            }

            // L_vec: u0^2, u1^2...
            // R_vec: 1/u0^2, 1/u1^2...
            for (x_sq) |sq| scalars.appendAssumeCapacity(sq.toBytes());
            for (x_inv_sq) |inv_sq| scalars.appendAssumeCapacity(inv_sq.toBytes());

            // generators_H: l_j^(-x^2_j) * r_j^(-x^{-2}_j)
            const minus_b = Scalar.fromBytes(Edwards25519.scalar.neg(b.toBytes()));
            var exp_z = zz;
            var z_and_2 = exp_z;
            var exp_y_inv = y;
            var j: u64 = 0;
            var m: u64 = 0;
            const y_inv = y.invert();
            for (0..bit_size) |i| {
                defer j += 1;
                if (j == bit_lengths[m]) {
                    j = 0;
                    m += 1;
                    exp_z = exp_z.mul(z);
                    z_and_2 = exp_z;
                }
                if (j != 0) z_and_2 = z_and_2.add(z_and_2);
                exp_y_inv = exp_y_inv.mul(y_inv);
                const result = s[bit_size - 1 - i].mul(minus_b).add(z_and_2);
                scalars.appendAssumeCapacity(result.mul(exp_y_inv).add(z).toBytes());
            }

            // generators_G: (-a * s_i) + (-z)
            const z_negated = Scalar.fromBytes(Edwards25519.scalar.neg(z.toBytes()));
            const a_negated = Scalar.fromBytes(Edwards25519.scalar.neg(a.toBytes()));
            for (s) |s_i| {
                const result = a_negated.mul(s_i).add(z_negated);
                scalars.appendAssumeCapacity(result.toBytes());
            }

            const delta_tx = Scalar.fromBytes(Edwards25519.scalar.sub(
                delta(bit_lengths, y, z).toBytes(),
                self.t_x.toBytes(),
            )).mul(d);
            const abw_tx = a_negated.mul(b).add(self.t_x).mul(w);
            const basepoint_scalar = delta_tx.add(abw_tx);
            scalars.appendAssumeCapacity(basepoint_scalar.toBytes()); // G
            points.appendAssumeCapacity(pedersen.G);

            const check: Ristretto255 = sig.crypto.ed25519.mulMultiRuntime(
                max,
                false,
                true,
                points.constSlice(),
                scalars.constSlice(),
            );

            if (!check.equivalent(.{ .p = self.A.p.neg() })) {
                return error.AlgebraicRelation;
            }
        }

        /// Compute \delta(y,z) = (z - z^{2}) \langle \mathbf{1}, {\mathbf{y}}^{n \cdot m} \rangle - \sum_{j=0}^{m-1} z^{j+3} \cdot \langle \mathbf{1}, {\mathbf{2}}^{n \cdot m} \rangle
        fn delta(bit_lengths: []const u64, y: Scalar, z: Scalar) Scalar {
            const sum_y = sumOfPowers(bit_size, y);
            const zz = z.mul(z);
            const negative_z = Scalar.fromBytes(Edwards25519.scalar.sub(
                z.toBytes(),
                zz.toBytes(),
            ));
            var agg_delta = negative_z.mul(sum_y);
            var exp_z = zz.mul(z);
            for (bit_lengths) |n_i| {
                const sum_2 = sumOfPowers(n_i, TWO);
                agg_delta = Scalar.fromBytes(Edwards25519.scalar.sub(
                    agg_delta.toBytes(),
                    exp_z.mul(sum_2).toBytes(),
                ));
                exp_z = exp_z.mul(z);
            }
            return agg_delta;
        }

        fn sumOfPowers(n: u64, x: Scalar) Scalar {
            // TODO: use O(2log(n)) algorithm instead when `n` is a power of two
            var acc = ZERO;
            var next_exp = ONE;
            for (0..n) |_| {
                const exp_x = next_exp;
                next_exp = next_exp.mul(x);
                acc = acc.add(exp_x);
            }
            return acc;
        }

        pub fn fromBytes(bytes: [BYTE_LEN]u8) !Self {
            const A = try Ristretto255.fromBytes(bytes[0..32].*);
            const S = try Ristretto255.fromBytes(bytes[32..64].*);
            const T_1 = try Ristretto255.fromBytes(bytes[64..96].*);
            const T_2 = try Ristretto255.fromBytes(bytes[96..128].*);

            const t_x = Scalar.fromBytes(bytes[128..160].*);
            const t_x_blinding = Scalar.fromBytes(bytes[160..192].*);
            const e_blinding = Scalar.fromBytes(bytes[192..224].*);

            try Edwards25519.scalar.rejectNonCanonical(t_x.toBytes());
            try Edwards25519.scalar.rejectNonCanonical(t_x_blinding.toBytes());
            try Edwards25519.scalar.rejectNonCanonical(e_blinding.toBytes());

            const ipp = try InnerProductProof(bit_size).fromBytes(bytes[224..].*);

            return .{
                .A = A,
                .S = S,
                .T_1 = T_1,
                .T_2 = T_2,
                .t_x = t_x,
                .t_x_blinding = t_x_blinding,
                .e_blinding = e_blinding,
                .ipp = ipp,
            };
        }

        pub fn toBytes(self: Self) [BYTE_LEN]u8 {
            const outer = self.A.toBytes() ++
                self.S.toBytes() ++ self.T_1.toBytes() ++ self.T_2.toBytes() ++
                self.t_x.toBytes() ++ self.t_x_blinding.toBytes() ++ self.e_blinding.toBytes();

            const IPP = InnerProductProof(bit_size);
            var inner: [IPP.BYTE_LEN]u8 = undefined;
            for (self.ipp.L_vec, self.ipp.R_vec, 0..) |l, r, i| {
                const position = 2 * i * 32;
                @memcpy(inner[position..][0..32], &l.toBytes());
                @memcpy(inner[position + 32 ..][0..32], &r.toBytes());
            }
            const final = 2 * logn * 32;
            inner[final..][0..32].* = self.ipp.a.toBytes();
            inner[final..][32..][0..32].* = self.ipp.b.toBytes();

            return outer ++ inner;
        }

        pub fn fromBase64(string: []const u8) !Self {
            const base64 = std.base64.standard;
            var buffer: [BYTE_LEN]u8 = .{0} ** BYTE_LEN;
            const decoded_length = try base64.Decoder.calcSizeForSlice(string);
            try std.base64.standard.Decoder.decode(
                buffer[0..decoded_length],
                string,
            );
            return fromBytes(buffer);
        }
    };
}

pub fn Data(bit_size: comptime_int) type {
    return struct {
        context: Context,
        proof: P,

        const Self = @This();
        const P = Proof(bit_size);

        pub const TYPE: ProofType = switch (bit_size) {
            64 => .batched_range_proof_u64,
            128 => .batched_range_proof_u128,
            256 => .batched_range_proof_u256,
            else => unreachable,
        };
        pub const BYTE_LEN = P.BYTE_LEN + @sizeOf(Context);

        pub fn init(
            commitments: []const pedersen.Commitment,
            amounts: []const u64,
            bit_lengths: []const u64,
            openings: []const pedersen.Opening,
        ) !Self {
            var batched_bit_length: u64 = 0;
            for (bit_lengths) |length| {
                batched_bit_length = try std.math.add(
                    u64,
                    batched_bit_length,
                    length,
                );
            }
            if (batched_bit_length != bit_size) return error.IllegalAmountBitLength;

            const context = try Context.init(
                commitments,
                amounts,
                bit_lengths,
                openings,
            );

            var transcript = context.newTranscript();
            const proof = try P.init(
                amounts,
                bit_lengths,
                openings,
                &transcript,
            );

            return .{
                .context = context,
                .proof = proof,
            };
        }

        pub fn fromBytes(data: []const u8) !Self {
            if (data.len != BYTE_LEN) return error.InvalidLength;
            return .{
                .context = @bitCast(data[0..Context.BYTE_LEN].*),
                .proof = try P.fromBytes(data[Context.BYTE_LEN..][0..P.BYTE_LEN].*),
            };
        }

        pub fn toBytes(self: Self) [BYTE_LEN]u8 {
            return self.context.toBytes() ++ self.proof.toBytes();
        }

        pub fn verify(self: Self) !void {
            const context = self.context;
            var commitments: std14.BoundedArray(pedersen.Commitment, 8) = .{};
            var bit_lengths: std14.BoundedArray(u64, 8) = .{};

            for (context.commitments, context.bit_lengths) |commitment, length| {
                if (std.mem.allEqual(u8, &commitment, 0)) break; // we've hit the terminator
                commitments.appendAssumeCapacity(.{
                    .point = try Ristretto255.fromBytes(commitment),
                });
                bit_lengths.appendAssumeCapacity(length);
            }

            var transcript = context.newTranscript();
            try self.proof.verify(
                commitments.constSlice(),
                bit_lengths.constSlice(),
                &transcript,
            );
        }

        pub const Context = extern struct {
            // commitments and bit_lengths are stored as "null terminated", where
            // the next-after-last element is an identity point. 0 is allowed
            // in the bit lengths, so the length there is derived from the
            // number of commitments parsed out.
            // important to have for constant size serialization in `toBytes()`.
            commitments: [MAX_COMMITMENTS][32]u8,
            bit_lengths: [MAX_COMMITMENTS]u8,

            pub const BYTE_LEN = (MAX_COMMITMENTS * 32) + MAX_COMMITMENTS;

            fn init(
                commitments: []const pedersen.Commitment,
                amounts: []const u64,
                bit_lengths: []const u64,
                openings: []const pedersen.Opening,
            ) !Context {
                const num_commitments = commitments.len;
                if (num_commitments > MAX_COMMITMENTS or
                    num_commitments != amounts.len or
                    num_commitments != bit_lengths.len or
                    num_commitments != openings.len)
                {
                    return error.IllegalCommitmentLength;
                }

                var compressed_commitments: [MAX_COMMITMENTS][32]u8 = @splat(@splat(0));
                for (
                    compressed_commitments[0..num_commitments],
                    commitments,
                ) |*compressed, commitment| {
                    try commitment.point.rejectIdentity();
                    compressed.* = commitment.point.toBytes();
                }

                var compressed_bit_lengths: [MAX_COMMITMENTS]u8 = @splat(0);
                for (
                    compressed_bit_lengths[0..num_commitments],
                    bit_lengths,
                ) |*compressed, length| {
                    compressed.* = std.math.cast(u8, length) orelse
                        return error.IllegalAmountBitLength;
                }

                return .{
                    .commitments = compressed_commitments,
                    .bit_lengths = compressed_bit_lengths,
                };
            }

            pub fn toBytes(self: Context) [Context.BYTE_LEN]u8 {
                return @bitCast(self);
            }

            // sig fmt: off
            fn newTranscript(self: Context) Transcript {
                return .init(.@"batched-range-proof-instruction", &.{
                    .{ .label = "commitments", .message = .{ .bytes = std.mem.sliceAsBytes(&self.commitments) } },
                    .{ .label = "bit-lengths", .message = .{ .bytes = std.mem.sliceAsBytes(&self.bit_lengths) } },
                });
            }
            // sig fmt: on
        };
    };
}

/// Computes the inner product between two vectors.
///
/// Asserts the length is the same.
pub fn innerProduct(a: []const Scalar, b: []const Scalar) Scalar {
    std.debug.assert(a.len == b.len);
    var out = Scalar.fromBytes(Edwards25519.scalar.zero);
    for (a, b) |c, d| out = out.add(c.mul(d));
    return out;
}

/// Generates a list of the powers of `x`.
pub fn genPowers(comptime n: usize, x: Scalar) [n]Scalar {
    var next_exp = ONE;
    var out: [n]Scalar = undefined;
    for (&out) |*o| {
        const exp_x = next_exp;
        next_exp = next_exp.mul(x);
        o.* = exp_x;
    }
    return out;
}

test "single rangeproof" {
    const commitment, const opening = pedersen.initValue(u64, 55);

    var creation_transcript = Transcript.initTest("Test");
    var verification_transcript = Transcript.initTest("Test");

    const proof = try Proof(32).init(
        &.{55},
        &.{32},
        &.{opening},
        &creation_transcript,
    );

    try proof.verify(
        &.{commitment},
        &.{32},
        &verification_transcript,
    );
}

test "aggregated rangeproof" {
    const comm1, const opening1 = pedersen.initValue(u64, 55);
    const comm2, const opening2 = pedersen.initValue(u64, 77);
    const comm3, const opening3 = pedersen.initValue(u64, 99);

    var creation_transcript = Transcript.initTest("Test");
    var verification_transcript = Transcript.initTest("Test");

    const proof = try Proof(128).init(
        &.{ 55, 77, 99 },
        &.{ 64, 32, 32 },
        &.{ opening1, opening2, opening3 },
        &creation_transcript,
    );

    try proof.verify(
        &.{ comm1, comm2, comm3 },
        &.{ 64, 32, 32 },
        &verification_transcript,
    );
}

test "proof string" {
    const commitment_1_string = "dDaa/MTEDlyI0Nxx+iu1tOteZsTWmPXAfn9QI0W9mSc=";
    const commitment_1 = try pedersen.Commitment.fromBase64(commitment_1_string);

    const commitment_2_string = "tnRILjKpogi2sXxLgZzMqlqPMLnCJmrSjZ5SPQYhtgg=";
    const commitment_2 = try pedersen.Commitment.fromBase64(commitment_2_string);

    const commitment_3_string = "ZAC5ZLXotsMOVExtrr56D/EZNeyo9iWepNbeH22EuRo=";
    const commitment_3 = try pedersen.Commitment.fromBase64(commitment_3_string);

    // zig fmt: off
    const proof_string = "AvvBQL63pXMXsmuvuNbs/CqXdzeyrMpEIO2O/cI6/SyqU4N+7HUU3LmXai9st+DxqTnuKsm0SgnADfpLpQCEbDDupMb09NY8oHT8Bx8WQhv9eyoBlrPRd7DVhOUsio02gBshe3p2Wj7+yDCpFaZ7/PMypFBX6+E+EqCiPI6yUk4ztslWY0Ksac41eJgcPzXyIx2kvmSTsVBKLb7U01PWBC+AUyUmK3/IdvmJ4DnlS3xFrdg/mxSsYJFd3OZA3cwDb0jePQf/P43/2VVqPRixMVO7+VGoMKPoRTEEVbClsAlW6stGTFPcrimu3c+geASgvwElkIKNGtYcjoj3SS+/VeqIG9Ei1j+TJtPhOE9SG4KNw9xBGwecpliDbQhKjO950EVcnOts+a525/frZV1jHJmOOrZtKRV4pvk37dtQkx4sv+pxRmfVrjwOcKQeg+BzcuF0vaQbqa4SUbzbO9z3RwIMlYIBaz0bqZgJmtPOFuFmNyCJaeB29vlcEAfYbn5gdlgtWP50tKmhoskndulziKZjz4qHSA9rbG2ZtoMHoCsAobHKu2H9OxcaK4Scj1QGwst+zXBEY8uePNbxvU5DMJLVFORtLUXkVdPCmCSsm1Bz4TRbnls8LOVW6wqTgShQMhjNM3RtwdHXENPn5uDnhyvfduAcL+DtI8AIJyRneROefk7i7gjal8dLdMM/QnXT7ctpMQU6uNlpsNzq65xlOQKXO71vQ3c2mE/DmxVJi6BTS5WCzavvhiqdhQyRL61ESCALQpaP0/d0DLwLikVH3ypuDLEnVXe9Pmkxdd0xCzO6QcfyK50CPnV/dVgHeLg8EVag2O83+/7Ys5oLxrDad9TJTDcrT2xsRqECFnSA+z9uZtDPujhQL0ogS5RH4agnQN4mVGTwOLV8OKpn+AvWq6+j1/9EXFkLPBTU5wT0FQuT2VZ8xp5GeqdI13Zey1uPrxc6CZZ407y9OINED4IdBQ==";
    const proof = try Proof(128).fromBase64(proof_string);
    // zig fmt: on

    var verification_transcript = Transcript.initTest("Test");
    try proof.verify(
        &.{ commitment_1, commitment_2, commitment_3 },
        &.{ 64, 32, 32 },
        &verification_transcript,
    );
}

test "u64 data" {
    const amount_1: u64 = std.math.maxInt(u8);
    const amount_2: u64 = 77;
    const amount_3: u64 = 99;
    const amount_4: u64 = 99;
    const amount_5: u64 = 11;
    const amount_6: u64 = 33;
    const amount_7: u64 = 99;
    const amount_8: u64 = 99;

    const commitment_1, const opening_1 = pedersen.initValue(u64, amount_1);
    const commitment_2, const opening_2 = pedersen.initValue(u64, amount_2);
    const commitment_3, const opening_3 = pedersen.initValue(u64, amount_3);
    const commitment_4, const opening_4 = pedersen.initValue(u64, amount_4);
    const commitment_5, const opening_5 = pedersen.initValue(u64, amount_5);
    const commitment_6, const opening_6 = pedersen.initValue(u64, amount_6);
    const commitment_7, const opening_7 = pedersen.initValue(u64, amount_7);
    const commitment_8, const opening_8 = pedersen.initValue(u64, amount_8);

    const proof_data = try Data(64).init(&.{
        commitment_1, commitment_2, commitment_3, commitment_4,
        commitment_5, commitment_6, commitment_7, commitment_8,
    }, &.{
        amount_1, amount_2, amount_3, amount_4,
        amount_5, amount_6, amount_7, amount_8,
    }, &.{ 8, 8, 8, 8, 8, 8, 8, 8 }, &.{
        opening_1, opening_2, opening_3, opening_4,
        opening_5, opening_6, opening_7, opening_8,
    });

    try proof_data.verify();
}

test "u64 data too large" {
    const amount_1: u64 = std.math.maxInt(u8) + 1; // not representable as an 8-bit number
    const amount_2: u64 = 77;
    const amount_3: u64 = 99;
    const amount_4: u64 = 99;
    const amount_5: u64 = 11;
    const amount_6: u64 = 33;
    const amount_7: u64 = 99;
    const amount_8: u64 = 99;

    const commitment_1, const opening_1 = pedersen.initValue(u64, amount_1);
    const commitment_2, const opening_2 = pedersen.initValue(u64, amount_2);
    const commitment_3, const opening_3 = pedersen.initValue(u64, amount_3);
    const commitment_4, const opening_4 = pedersen.initValue(u64, amount_4);
    const commitment_5, const opening_5 = pedersen.initValue(u64, amount_5);
    const commitment_6, const opening_6 = pedersen.initValue(u64, amount_6);
    const commitment_7, const opening_7 = pedersen.initValue(u64, amount_7);
    const commitment_8, const opening_8 = pedersen.initValue(u64, amount_8);

    const proof_data = try Data(64).init(&.{
        commitment_1, commitment_2, commitment_3, commitment_4,
        commitment_5, commitment_6, commitment_7, commitment_8,
    }, &.{
        amount_1, amount_2, amount_3, amount_4,
        amount_5, amount_6, amount_7, amount_8,
    }, &.{ 8, 8, 8, 8, 8, 8, 8, 8 }, &.{
        opening_1, opening_2, opening_3, opening_4,
        opening_5, opening_6, opening_7, opening_8,
    });

    try std.testing.expectError(
        error.AlgebraicRelation,
        proof_data.verify(),
    );
}

test "u128 data" {
    const amount_1: u64 = std.math.maxInt(u16);
    const amount_2: u64 = 77;
    const amount_3: u64 = 99;
    const amount_4: u64 = 99;
    const amount_5: u64 = 11;
    const amount_6: u64 = 33;
    const amount_7: u64 = 99;
    const amount_8: u64 = 99;

    const commitment_1, const opening_1 = pedersen.initValue(u64, amount_1);
    const commitment_2, const opening_2 = pedersen.initValue(u64, amount_2);
    const commitment_3, const opening_3 = pedersen.initValue(u64, amount_3);
    const commitment_4, const opening_4 = pedersen.initValue(u64, amount_4);
    const commitment_5, const opening_5 = pedersen.initValue(u64, amount_5);
    const commitment_6, const opening_6 = pedersen.initValue(u64, amount_6);
    const commitment_7, const opening_7 = pedersen.initValue(u64, amount_7);
    const commitment_8, const opening_8 = pedersen.initValue(u64, amount_8);

    const proof_data = try Data(128).init(&.{
        commitment_1, commitment_2, commitment_3, commitment_4,
        commitment_5, commitment_6, commitment_7, commitment_8,
    }, &.{
        amount_1, amount_2, amount_3, amount_4,
        amount_5, amount_6, amount_7, amount_8,
    }, &.{ 16, 16, 16, 16, 16, 16, 16, 16 }, &.{
        opening_1, opening_2, opening_3, opening_4,
        opening_5, opening_6, opening_7, opening_8,
    });

    try proof_data.verify();
}

test "u128 data too large" {
    const amount_1: u64 = std.math.maxInt(u16) + 1; // not representable as a 16-bit number
    const amount_2: u64 = 77;
    const amount_3: u64 = 99;
    const amount_4: u64 = 99;
    const amount_5: u64 = 11;
    const amount_6: u64 = 33;
    const amount_7: u64 = 99;
    const amount_8: u64 = 99;

    const commitment_1, const opening_1 = pedersen.initValue(u64, amount_1);
    const commitment_2, const opening_2 = pedersen.initValue(u64, amount_2);
    const commitment_3, const opening_3 = pedersen.initValue(u64, amount_3);
    const commitment_4, const opening_4 = pedersen.initValue(u64, amount_4);
    const commitment_5, const opening_5 = pedersen.initValue(u64, amount_5);
    const commitment_6, const opening_6 = pedersen.initValue(u64, amount_6);
    const commitment_7, const opening_7 = pedersen.initValue(u64, amount_7);
    const commitment_8, const opening_8 = pedersen.initValue(u64, amount_8);

    const proof_data = try Data(128).init(&.{
        commitment_1, commitment_2, commitment_3, commitment_4,
        commitment_5, commitment_6, commitment_7, commitment_8,
    }, &.{
        amount_1, amount_2, amount_3, amount_4,
        amount_5, amount_6, amount_7, amount_8,
    }, &.{ 16, 16, 16, 16, 16, 16, 16, 16 }, &.{
        opening_1, opening_2, opening_3, opening_4,
        opening_5, opening_6, opening_7, opening_8,
    });

    try std.testing.expectError(
        error.AlgebraicRelation,
        proof_data.verify(),
    );
}

test "u256 data" {
    const amount_1: u64 = std.math.maxInt(u32);
    const amount_2: u64 = 77;
    const amount_3: u64 = 99;
    const amount_4: u64 = 99;
    const amount_5: u64 = 11;
    const amount_6: u64 = 33;
    const amount_7: u64 = 99;
    const amount_8: u64 = 99;

    const commitment_1, const opening_1 = pedersen.initValue(u64, amount_1);
    const commitment_2, const opening_2 = pedersen.initValue(u64, amount_2);
    const commitment_3, const opening_3 = pedersen.initValue(u64, amount_3);
    const commitment_4, const opening_4 = pedersen.initValue(u64, amount_4);
    const commitment_5, const opening_5 = pedersen.initValue(u64, amount_5);
    const commitment_6, const opening_6 = pedersen.initValue(u64, amount_6);
    const commitment_7, const opening_7 = pedersen.initValue(u64, amount_7);
    const commitment_8, const opening_8 = pedersen.initValue(u64, amount_8);

    const proof_data = try Data(256).init(&.{
        commitment_1, commitment_2, commitment_3, commitment_4,
        commitment_5, commitment_6, commitment_7, commitment_8,
    }, &.{
        amount_1, amount_2, amount_3, amount_4,
        amount_5, amount_6, amount_7, amount_8,
    }, &.{ 32, 32, 32, 32, 32, 32, 32, 32 }, &.{
        opening_1, opening_2, opening_3, opening_4,
        opening_5, opening_6, opening_7, opening_8,
    });

    try proof_data.verify();
}

test "u256 data too large" {
    const amount_1: u64 = std.math.maxInt(u32) + 1; // not representable as a 32-bit number
    const amount_2: u64 = 77;
    const amount_3: u64 = 99;
    const amount_4: u64 = 99;
    const amount_5: u64 = 11;
    const amount_6: u64 = 33;
    const amount_7: u64 = 99;
    const amount_8: u64 = 99;

    const commitment_1, const opening_1 = pedersen.initValue(u64, amount_1);
    const commitment_2, const opening_2 = pedersen.initValue(u64, amount_2);
    const commitment_3, const opening_3 = pedersen.initValue(u64, amount_3);
    const commitment_4, const opening_4 = pedersen.initValue(u64, amount_4);
    const commitment_5, const opening_5 = pedersen.initValue(u64, amount_5);
    const commitment_6, const opening_6 = pedersen.initValue(u64, amount_6);
    const commitment_7, const opening_7 = pedersen.initValue(u64, amount_7);
    const commitment_8, const opening_8 = pedersen.initValue(u64, amount_8);

    const proof_data = try Data(256).init(&.{
        commitment_1, commitment_2, commitment_3, commitment_4,
        commitment_5, commitment_6, commitment_7, commitment_8,
    }, &.{
        amount_1, amount_2, amount_3, amount_4,
        amount_5, amount_6, amount_7, amount_8,
    }, &.{ 32, 32, 32, 32, 32, 32, 32, 32 }, &.{
        opening_1, opening_2, opening_3, opening_4,
        opening_5, opening_6, opening_7, opening_8,
    });

    try std.testing.expectError(
        error.AlgebraicRelation,
        proof_data.verify(),
    );
}
