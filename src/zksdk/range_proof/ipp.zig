const std = @import("std");
const sig = @import("../../sig.zig");

const Edwards25519 = std.crypto.ecc.Edwards25519;
const Sha3 = std.crypto.hash.sha3.Sha3_512;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const weak_mul = sig.vm.syscalls.ecc.weak_mul;
const Transcript = sig.zksdk.Transcript;
const bp = sig.zksdk.bulletproofs;

/// Inner-Product (Sub)Proof
///
/// This proof allows the prover to convince the verifier that the inner
/// product of two secret vectors `a` and `b` equals a known scalar
/// `c = <a, b>`, without revealing the vectors themselves.
///
/// In the context of the Bulletproofs range proofs, the vectors `a` and `b`
/// are part of a larger commitment to a vector of bit values (used to
/// prove a value lies within a range), and the inner product argument is used
/// to reduce the size of the overall proof from linear to logarithmic in the
/// size of the range.
///
/// The protocol works by recursively folding the vectors `a` and `b` into
/// smaller vectors, committing to linear combinations at each step. This folding
/// is done in logarthmic rounds, and in each round the prover sends two group
/// elements (`Lᵢ` and `Rᵢ`) that allow the verifier to reconstruct the
/// final scalar product from the compressed vectors.
///
/// The security of the proof relies on the discrete logarithm harness assumption,
/// and the commitment sceheme used (Pedersen commitment) ensures that the
/// vectors remain hidden while the correctness of the inner product is verifiable.
///
/// - Bulletproofs paper (Bünz et al., 2018): https://eprint.iacr.org/2017/1066
/// - Dalek Bulletproofs implementation and docs: https://doc.dalek.rs/bulletproofs/
/// - Agave IPP implementation: https://github.com/anza-xyz/agave/blob/93699947720534741b2b4d9b6e1696d81e386dcc/zk-sdk/src/range_proof/inner_product.rs
pub fn Proof(bit_size: comptime_int) type {
    const logn: u64 = std.math.log2_int(u64, bit_size);
    const max_elements =
        bit_size * 2 + // g_times_a_times_s and h_times_b_div_s
        logn * 2 + // neg_u_sq and neg_u_inv_sq
        1 // a * b
    ;

    return struct {
        L_vec: [logn]Ristretto255,
        R_vec: [logn]Ristretto255,
        a: Scalar,
        b: Scalar,

        const Self = @This();
        pub const BYTE_LEN = (2 * logn * 32) + 64;

        pub fn init(
            Q: Ristretto255,
            G_factors: [bit_size]Scalar,
            H_factors: [bit_size]Scalar,
            G_vec: [bit_size]Edwards25519,
            H_vec: [bit_size]Edwards25519,
            a_vec: [bit_size]Scalar,
            b_vec: [bit_size]Scalar,
            transcript: *Transcript,
        ) Self {
            var G_buffer = G_vec;
            var H_buffer = H_vec;
            var a_buffer = a_vec;
            var b_buffer = b_vec;

            var G: []Edwards25519 = &G_buffer;
            var H: []Edwards25519 = &H_buffer;
            var a: []Scalar = &a_buffer;
            var b: []Scalar = &b_buffer;

            transcript.appendDomSep("inner-product");
            transcript.appendU64("n", bit_size);

            var L_vec: std.BoundedArray(Ristretto255, logn) = .{};
            var R_vec: std.BoundedArray(Ristretto255, logn) = .{};

            // If it's the first iteration, unroll the Hprime = H*y_inv scalar mults
            // into multiscalar muls, for performance.
            var n: u64 = bit_size;
            if (bit_size != 1) {
                n = n / 2;

                const a_L = a[0..n];
                const a_R = a[n..];
                const b_L = b[0..n];
                const b_R = b[n..];
                const G_L = G[0..n];
                const G_R = G[n..];
                const H_L = H[0..n];
                const H_R = H[n..];

                const c_L = bp.innerProduct(a_L, b_R);
                const c_R = bp.innerProduct(a_R, b_L);

                var scalars: std.BoundedArray([32]u8, bit_size + 1) = .{};
                var points: std.BoundedArray(Edwards25519, bit_size + 1) = .{};

                for (a_L, G_factors[n .. n * 2]) |ai, gi| {
                    scalars.appendAssumeCapacity(ai.mul(gi).toBytes());
                }
                for (b_R, H_factors[0..n]) |bi, hi| {
                    scalars.appendAssumeCapacity(bi.mul(hi).toBytes());
                }
                scalars.appendAssumeCapacity(c_L.toBytes());

                for (G_R) |gi| points.appendAssumeCapacity(gi);
                for (H_L) |hi| points.appendAssumeCapacity(hi);
                points.appendAssumeCapacity(Q.p);

                const L: Ristretto255 = .{ .p = weak_mul.mulMulti(
                    bit_size + 1,
                    points.constSlice()[0 .. bit_size + 1].*,
                    scalars.constSlice()[0 .. bit_size + 1].*,
                ) };

                points.len = 0;
                scalars.len = 0;

                for (a_R, G_factors[0..n]) |ai, gi| {
                    scalars.appendAssumeCapacity(ai.mul(gi).toBytes());
                }
                for (b_L, H_factors[n .. n * 2]) |bi, hi| {
                    scalars.appendAssumeCapacity(bi.mul(hi).toBytes());
                }
                scalars.appendAssumeCapacity(c_R.toBytes());

                for (G_L) |gi| points.appendAssumeCapacity(gi);
                for (H_R) |hi| points.appendAssumeCapacity(hi);
                points.appendAssumeCapacity(Q.p);

                const R: Ristretto255 = .{ .p = weak_mul.mulMulti(
                    bit_size + 1,
                    points.constSlice()[0 .. bit_size + 1].*,
                    scalars.constSlice()[0 .. bit_size + 1].*,
                ) };

                L_vec.appendAssumeCapacity(L);
                R_vec.appendAssumeCapacity(R);

                transcript.appendPoint("L", L);
                transcript.appendPoint("R", R);

                const u = transcript.challengeScalar("u");
                const u_inv = u.invert();

                // Reduce round
                for (0..n) |i| {
                    a_L[i] = a_L[i].mul(u).add(u_inv.mul(a_R[i]));
                    b_L[i] = b_L[i].mul(u_inv).add(u.mul(b_R[i]));
                    G_L[i] = weak_mul.mulMulti(
                        2,
                        .{ G_L[i], G_R[i] },
                        .{
                            u_inv.mul(G_factors[i]).toBytes(),
                            u.mul(G_factors[n + i]).toBytes(),
                        },
                    );
                    H_L[i] = weak_mul.mulMulti(
                        2,
                        .{ H_L[i], H_R[i] },
                        .{
                            u.mul(H_factors[i]).toBytes(),
                            u_inv.mul(H_factors[n + i]).toBytes(),
                        },
                    );
                }

                a = a_L;
                b = b_L;
                G = G_L;
                H = H_L;
            }

            while (n != 1) {
                n = n / 2;

                const a_L = a[0..n];
                const a_R = a[n..];
                const b_L = b[0..n];
                const b_R = b[n..];
                const G_L = G[0..n];
                const G_R = G[n..];
                const H_L = H[0..n];
                const H_R = H[n..];

                const c_L = bp.innerProduct(a_L, b_R);
                const c_R = bp.innerProduct(a_R, b_L);

                // TODO: if we're here after the first round, then the size has already been
                // divided by two, meaning we should be able to limit the bounded arrays to
                // bit_size / 2 + 1 instead, will need to do some testing.
                var scalars: std.BoundedArray([32]u8, bit_size + 1) = .{};
                var points: std.BoundedArray(Edwards25519, bit_size + 1) = .{};

                for (a_L) |ai| scalars.appendAssumeCapacity(ai.toBytes());
                for (b_R) |bi| scalars.appendAssumeCapacity(bi.toBytes());
                scalars.appendAssumeCapacity(c_L.toBytes());

                for (G_R) |gi| points.appendAssumeCapacity(gi);
                for (H_L) |hi| points.appendAssumeCapacity(hi);
                points.appendAssumeCapacity(Q.p);

                const L: Ristretto255 = .{
                    .p = switch (points.len) {
                        inline //
                        3, // 1 + 1 + 1
                        5, // 2 + 2 + 1
                        9, // 4 + 4 + 1
                        17, // 8 + 8 + 1
                        33, // 16 + 16 + 1
                        65, // 32 + 32 + 1
                        129, // 64 + 64 + 1
                        => |N| weak_mul.mulMulti(
                            N,
                            points.constSlice()[0..N].*,
                            scalars.constSlice()[0..N].*,
                        ),
                        else => unreachable, // TODO
                    },
                };

                points.len = 0;
                scalars.len = 0;

                for (a_R) |ai| scalars.appendAssumeCapacity(ai.toBytes());
                for (b_L) |bi| scalars.appendAssumeCapacity(bi.toBytes());
                scalars.appendAssumeCapacity(c_R.toBytes());

                for (G_L) |gi| points.appendAssumeCapacity(gi);
                for (H_R) |hi| points.appendAssumeCapacity(hi);
                points.appendAssumeCapacity(Q.p);

                const R: Ristretto255 = .{
                    .p = switch (points.len) {
                        inline //
                        3, // 1 + 1 + 1
                        5, // 2 + 2 + 1
                        9, // 4 + 4 + 1
                        17, // 8 + 8 + 1
                        33, // 16 + 16 + 1
                        65, // 32 + 32 + 1
                        129, // 64 + 64 + 1
                        => |N| weak_mul.mulMulti(
                            N,
                            points.constSlice()[0..N].*,
                            scalars.constSlice()[0..N].*,
                        ),
                        else => unreachable, // TODO
                    },
                };

                L_vec.appendAssumeCapacity(L);
                R_vec.appendAssumeCapacity(R);

                transcript.appendPoint("L", L);
                transcript.appendPoint("R", R);

                const u = transcript.challengeScalar("u");
                const u_inv = u.invert();

                for (0..n) |i| {
                    a_L[i] = a_L[i].mul(u).add(u_inv.mul(a_R[i]));
                    b_L[i] = b_L[i].mul(u_inv).add(u.mul(b_R[i]));
                    G_L[i] = weak_mul.mulMulti(
                        2,
                        .{ G_L[i], G_R[i] },
                        .{ u_inv.toBytes(), u.toBytes() },
                    );
                    H_L[i] = weak_mul.mulMulti(
                        2,
                        .{ H_L[i], H_R[i] },
                        .{ u.toBytes(), u_inv.toBytes() },
                    );
                }

                a = a_L;
                b = b_L;
                G = G_L;
                H = H_L;
            }

            // there should have been log(bit_size) reductions
            std.debug.assert(L_vec.len == logn);
            std.debug.assert(R_vec.len == logn);
            return .{
                .L_vec = L_vec.buffer[0..logn].*,
                .R_vec = R_vec.buffer[0..logn].*,
                .a = a[0],
                .b = b[0],
            };
        }

        pub fn verify(
            self: Self,
            G_factors: *const [bit_size]Scalar,
            H_factors: *const [bit_size]Scalar,
            P: Ristretto255,
            Q: Ristretto255,
            G: *const [bit_size]Edwards25519,
            H: *const [bit_size]Edwards25519,
            transcript: *Transcript,
        ) !void {
            const u_sq, const u_inv_sq, const s = try self.verificationScalars(transcript);

            var scalars: std.BoundedArray([32]u8, max_elements) = .{};
            var points: std.BoundedArray(Edwards25519, max_elements) = .{};

            scalars.appendAssumeCapacity(self.a.mul(self.b).toBytes());
            for (G_factors, s) |gi, si| {
                const mul = self.a.mul(si).mul(gi);
                scalars.appendAssumeCapacity(mul.toBytes());
            }
            // 1/s[i] is s[!i], and !i runs from n-1 to 0 as i runs from 0 to n-1
            for (H_factors, 0..bit_size) |hi, idx| {
                const si_inv = s[bit_size - idx - 1];
                const mul = self.b.mul(si_inv).mul(hi);
                scalars.appendAssumeCapacity(mul.toBytes());
            }
            for (u_sq) |ui| {
                const neg = Edwards25519.scalar.neg(ui.toBytes());
                scalars.appendAssumeCapacity(neg);
            }
            for (u_inv_sq) |ui| {
                const neg = Edwards25519.scalar.neg(ui.toBytes());
                scalars.appendAssumeCapacity(neg);
            }

            points.appendAssumeCapacity(Q.p);
            for (G) |g| points.appendAssumeCapacity(g);
            for (H) |h| points.appendAssumeCapacity(h);
            for (self.L_vec) |l| points.appendAssumeCapacity(l.p);
            for (self.R_vec) |r| points.appendAssumeCapacity(r.p);

            const check = weak_mul.mulMulti(
                max_elements,
                points.constSlice()[0..max_elements].*,
                scalars.constSlice()[0..max_elements].*,
            );

            if (!P.equivalent(.{ .p = check })) {
                return error.AlgebraicRelation;
            }
        }

        pub fn verificationScalars(self: Self, transcript: *Transcript) !struct {
            [logn]Scalar, // u_sq
            [logn]Scalar, // u_inv_sq
            [bit_size]Scalar, // s
        } {
            transcript.appendDomSep("inner-product");
            transcript.appendU64("n", bit_size);

            // 1. Recompute x_k,...,x_1 based on the proof transcript

            var challenges: std.BoundedArray(Scalar, logn) = .{};
            for (self.L_vec, self.R_vec) |L, R| {
                try transcript.validateAndAppendPoint("L", L);
                try transcript.validateAndAppendPoint("R", R);
                challenges.appendAssumeCapacity(transcript.challengeScalar("u"));
            }

            // 2. Compute 1/(u_k...u_1) and 1/u_k, ..., 1/u_1

            // The inverse of the product of all scalars in the challenge.
            var allinv = bp.ONE;
            var challenges_inv = challenges;
            for (challenges_inv.slice()) |*scalar| {
                allinv = allinv.mul(scalar.*);
                scalar.* = scalar.invert();
            }
            allinv = allinv.invert();

            // 3. Compute u_i^2 and (1/u_i)^2

            for (challenges.slice(), challenges_inv.slice()) |*c, *c_inv| {
                c.* = c.mul(c.*);
                c_inv.* = c_inv.mul(c_inv.*);
            }
            const challenges_sq = challenges;
            const challenges_inv_sq = challenges_inv;

            // 4. Compute s values inductively.

            var s: std.BoundedArray(Scalar, bit_size) = .{};
            s.appendAssumeCapacity(allinv);
            for (1..bit_size) |i| {
                const log_i = std.math.log2_int(u64, i);
                const k = @as(u64, 1) << log_i;
                const u_lg_i_sq = challenges_sq.constSlice()[logn - 1 - log_i];
                s.appendAssumeCapacity(s.constSlice()[i - k].mul(u_lg_i_sq));
            }

            std.debug.assert(challenges_sq.len == logn);
            std.debug.assert(challenges_inv_sq.len == logn);
            std.debug.assert(s.len == bit_size);
            return .{
                challenges_sq.buffer,
                challenges_inv_sq.buffer,
                s.buffer,
            };
        }

        pub fn fromBytes(bytes: [BYTE_LEN]u8) !Self {
            var L_vec: [logn]Ristretto255 = undefined;
            var R_vec: [logn]Ristretto255 = undefined;
            for (&L_vec, &R_vec, 0..) |*l, *r, i| {
                const position = 2 * i * 32;
                l.* = try Ristretto255.fromBytes(bytes[position..][0..32].*);
                r.* = try Ristretto255.fromBytes(bytes[position + 32 ..][0..32].*);
            }

            const a = Scalar.fromBytes(bytes[2 * logn * 32 ..][0..32].*);
            const b = Scalar.fromBytes(bytes[2 * logn * 32 ..][32..][0..32].*);

            try Edwards25519.scalar.rejectNonCanonical(a.toBytes());
            try Edwards25519.scalar.rejectNonCanonical(b.toBytes());

            return .{
                .a = a,
                .b = b,
                .L_vec = L_vec,
                .R_vec = R_vec,
            };
        }
    };
}

test "basic correctness" {
    const n: u64 = 32;

    var gc = bp.GeneratorsChain.init("G");
    var hc = bp.GeneratorsChain.init("H");
    var G: [n]Edwards25519 = undefined;
    var H: [n]Edwards25519 = undefined;
    for (&G, &H) |*g, *h| {
        g.* = gc.next().p;
        h.* = hc.next().p;
    }

    const Q = Q: {
        var output: [64]u8 = undefined;
        Sha3.hash("test point", &output, .{});
        break :Q Ristretto255.fromUniform(output);
    };

    var a: [n]Scalar = undefined;
    var b: [n]Scalar = undefined;
    for (&a, &b) |*i, *j| {
        i.* = Scalar.random();
        j.* = Scalar.random();
    }
    const c = bp.innerProduct(&a, &b);

    const G_factors: [n]Scalar = @splat(bp.ONE);
    const y_inv = Scalar.random();
    const H_factors = bp.genPowers(n, y_inv);

    // P would be determined upstream, but we need a correct P to check the proof.
    //
    // To generate P = <a,G> + <b,H'> + <a,b> Q, compute
    //             P = <a,G> + <b',H> + <a,b> Q,
    // where b' = b ∘ y^(-n)
    const P_len = 2 * n + 1;
    var scalars: std.BoundedArray([32]u8, P_len) = .{};
    for (a) |as| try scalars.append(as.toBytes());
    for (b, H_factors) |bi, yi| try scalars.append(bi.mul(yi).toBytes());
    try scalars.append(c.toBytes());

    var points: std.BoundedArray(Edwards25519, P_len) = .{};
    for (G) |g| try points.append(g);
    for (H) |h| try points.append(h);
    try points.append(Q.p);

    const P: Ristretto255 = .{ .p = weak_mul.mulMulti(
        P_len,
        points.buffer,
        scalars.buffer,
    ) };

    var prover_transcript = Transcript.init("innerproducttest");
    var verifier_transcript = Transcript.init("innerproducttest");

    const proof = Proof(32).init(
        Q,
        G_factors,
        H_factors,
        G,
        H,
        a,
        b,
        &prover_transcript,
    );

    try proof.verify(
        &(.{bp.ONE} ** n),
        &H_factors,
        P,
        Q,
        &G,
        &H,
        &verifier_transcript,
    );
}
