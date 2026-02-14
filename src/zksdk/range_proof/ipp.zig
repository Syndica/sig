const std = @import("std");
const table = @import("table");
const sig = @import("../../sig.zig");

const Edwards25519 = std.crypto.ecc.Edwards25519;
const Sha3 = std.crypto.hash.sha3.Sha3_512;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const ed25519 = sig.crypto.ed25519;
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
/// is done in logarithmic rounds, and in each round the prover sends two group
/// elements (`Lᵢ` and `Rᵢ`) that allow the verifier to reconstruct the
/// final scalar product from the compressed vectors.
///
/// The security of the proof relies on the discrete logarithm harness assumption,
/// and the commitment scheme used (Pedersen commitment) ensures that the
/// vectors remain hidden while the correctness of the inner product is verifiable.
///
/// - Bulletproofs paper (Bünz et al., 2018): https://eprint.iacr.org/2017/1066
/// - Dalek Bulletproofs implementation and docs: https://doc.dalek.rs/bulletproofs/
/// - Agave IPP implementation: https://github.com/anza-xyz/agave/blob/93699947720534741b2b4d9b6e1696d81e386dcc/zk-sdk/src/range_proof/inner_product.rs
pub fn Proof(comptime bit_size: u64) type {
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

        const triple: [3]Transcript.Input = .{
            .{ .label = "L", .type = .validate_point },
            .{ .label = "R", .type = .validate_point },
            .{ .label = "u", .type = .challenge },
        };

        // The contract is the domain seperator followed by logn "L, R, u" inputs.
        const contract: Transcript.Contract = &[_]Transcript.Input{
            .domain(.@"inner-product"),
            .{ .label = "n", .type = .u64 },
        } ++ (&triple) ** logn;

        /// Modifies the mutable array pointers in undefined ways, so do not rely on the value of them after `init`.
        pub fn init(
            Q: Ristretto255,
            G_factors: *const [bit_size]Scalar,
            H_factors: *const [bit_size]Scalar,
            a_vec: *[bit_size]Scalar,
            b_vec: *[bit_size]Scalar,
            transcript: *Transcript,
        ) Self {
            var G_buffer = table.G[0..bit_size].*;
            var H_buffer = table.H[0..bit_size].*;
            var G: []Ristretto255 = &G_buffer;
            var H: []Ristretto255 = &H_buffer;
            var a: []Scalar = a_vec;
            var b: []Scalar = b_vec;

            comptime var session = Transcript.getSession(contract);
            defer session.finish();

            transcript.appendRangeProof(&session, .inner, bit_size);

            var L_vec: std.BoundedArray(Ristretto255, logn) = .{};
            var R_vec: std.BoundedArray(Ristretto255, logn) = .{};

            const rounds = @ctz(bit_size);
            inline for (0..rounds) |i| {
                const first_round = (i == 0);
                const n = bit_size >> @intCast(i + 1);

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

                // after the first round, the size has been divded by two, meaning we
                // only need to have bit_size / 2 + 1 elements in the arrays.
                var scalars: std.BoundedArray([32]u8, bit_size + 1) = .{};
                var points: std.BoundedArray(Ristretto255, bit_size + 1) = .{};

                if (first_round) {
                    for (a_L, G_factors[n .. n * 2]) |ai, gi| {
                        scalars.appendAssumeCapacity(ai.mul(gi).toBytes());
                    }
                    for (b_R, H_factors[0..n]) |bi, hi| {
                        scalars.appendAssumeCapacity(bi.mul(hi).toBytes());
                    }
                } else {
                    for (a_L) |ai| scalars.appendAssumeCapacity(ai.toBytes());
                    for (b_R) |bi| scalars.appendAssumeCapacity(bi.toBytes());
                }
                scalars.appendAssumeCapacity(c_L.toBytes());

                for (G_R) |gi| points.appendAssumeCapacity(gi);
                for (H_L) |hi| points.appendAssumeCapacity(hi);
                points.appendAssumeCapacity(Q);

                const L = sig.crypto.ed25519.pippenger.mulMultiRuntime(
                    257, // 128 + 128 + 1
                    false,
                    true,
                    points.constSlice(),
                    scalars.constSlice(),
                );

                // reset the arrays
                points.len = 0;
                scalars.len = 0;

                if (first_round) {
                    for (a_R, G_factors[0..n]) |ai, gi| {
                        scalars.appendAssumeCapacity(ai.mul(gi).toBytes());
                    }
                    for (b_L, H_factors[n .. n * 2]) |bi, hi| {
                        scalars.appendAssumeCapacity(bi.mul(hi).toBytes());
                    }
                } else {
                    for (a_R) |ai| scalars.appendAssumeCapacity(ai.toBytes());
                    for (b_L) |bi| scalars.appendAssumeCapacity(bi.toBytes());
                }
                scalars.appendAssumeCapacity(c_R.toBytes());

                for (G_L) |gi| points.appendAssumeCapacity(gi);
                for (H_R) |hi| points.appendAssumeCapacity(hi);
                points.appendAssumeCapacity(Q);

                const R = sig.crypto.ed25519.pippenger.mulMultiRuntime(
                    257, // 128 + 128 + 1
                    false,
                    true,
                    points.constSlice(),
                    scalars.constSlice(),
                );

                L_vec.appendAssumeCapacity(L);
                R_vec.appendAssumeCapacity(R);

                transcript.appendNoValidate(&session, .point, "L", L);
                transcript.appendNoValidate(&session, .point, "R", R);

                const u = transcript.challengeScalar(&session, "u");
                const u_inv = u.invert();

                for (0..n) |j| {
                    // L_j = L_j * u + u^-1 * R_j
                    a_L[j] = a_L[j].mul(u).add(u_inv.mul(a_R[j]));
                    b_L[j] = b_L[j].mul(u_inv).add(u.mul(b_R[j]));

                    // For the first round, unroll the H' = H * y_inv scalar multiplications
                    // into multiscalar multiplications, for performance.
                    // zig fmt: off
                    const first =  if (first_round) u_inv.mul(G_factors[j])     else u_inv;
                    const second = if (first_round) u.mul(G_factors[n + j])     else u;
                    const third =  if (first_round) u.mul(H_factors[j])         else u;
                    const fourth = if (first_round) u_inv.mul(H_factors[n + j]) else u_inv;
                    // zig fmt: on

                    G_L[j] = ed25519.mulMulti(
                        2,
                        .{ G_L[j], G_R[j] },
                        .{ first.toBytes(), second.toBytes() },
                    );
                    H_L[j] = ed25519.mulMulti(
                        2,
                        .{ H_L[j], H_R[j] },
                        .{ third.toBytes(), fourth.toBytes() },
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

        fn verify(
            self: Self,
            G_factors: *const [bit_size]Scalar,
            H_factors: *const [bit_size]Scalar,
            P: Ristretto255,
            Q: Ristretto255,
            transcript: *Transcript,
        ) !void {
            const u_sq, //
            const u_inv_sq, //
            const s = try self.verificationScalars(transcript);

            var scalars: std.BoundedArray([32]u8, max_elements) = .{};
            var points: std.BoundedArray(Ristretto255, max_elements) = .{};

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

            points.appendAssumeCapacity(Q);
            for (table.G[0..bit_size]) |g| points.appendAssumeCapacity(g);
            for (table.H[0..bit_size]) |h| points.appendAssumeCapacity(h);
            for (self.L_vec) |l| points.appendAssumeCapacity(l);
            for (self.R_vec) |r| points.appendAssumeCapacity(r);

            const check = sig.crypto.ed25519.mulMultiRuntime(
                max_elements,
                false,
                true,
                points.constSlice(),
                scalars.constSlice(),
            );

            if (!P.equivalent(check)) {
                return error.AlgebraicRelation;
            }
        }

        pub fn verificationScalars(self: Self, transcript: *Transcript) !struct {
            [logn]Scalar, // u_sq
            [logn]Scalar, // u_inv_sq
            [bit_size]Scalar, // s
        } {
            comptime var session = Transcript.getSession(contract);
            defer session.finish();

            transcript.appendRangeProof(&session, .inner, bit_size);

            // 1. Recompute x_k,...,x_1 based on the proof transcript
            var challenges: [logn]Scalar = undefined;
            inline for (&challenges, self.L_vec, self.R_vec) |*c, L, R| {
                try transcript.append(&session, .validate_point, "L", L);
                try transcript.append(&session, .validate_point, "R", R);
                c.* = transcript.challengeScalar(&session, "u");
            }

            // 2. Compute 1/(u_k...u_1) and 1/u_k, ..., 1/u_1
            var challenges_inv = challenges;
            const allinv = batchInvert(logn, &challenges_inv);

            // 3. Compute u_i^2 and (1/u_i)^2
            for (&challenges, &challenges_inv) |*c, *c_inv| {
                c.* = c.mul(c.*);
                c_inv.* = c_inv.mul(c_inv.*);
            }

            // 4. Compute s values inductively.
            var s: [bit_size]Scalar = undefined;
            s[0] = allinv;
            for (1..bit_size) |i| {
                const log_i = std.math.log2_int(u64, i);
                const k = @as(u64, 1) << log_i;
                const u_lg_i_sq = challenges[logn - 1 - log_i];
                s[i] = s[i - k].mul(u_lg_i_sq);
            }

            return .{
                challenges,
                challenges_inv,
                s,
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

fn batchInvert(comptime N: u32, scalars: *[N]Scalar) Scalar {
    var acc: Scalar = bp.ONE;
    var scratch: [N]Scalar = @splat(bp.ONE);
    defer std.crypto.secureZero(u8, std.mem.sliceAsBytes(&scratch));

    for (scalars, &scratch) |input, *s| {
        s.* = acc;
        acc = acc.mul(input);
    }
    std.debug.assert(!acc.isZero());

    acc = acc.invert();
    const allinv = acc;

    for (0..N) |fwd| {
        const i = N - 1 - fwd;
        const s = scratch[i];
        const input = &scalars[i];

        const tmp = acc.mul(input.*);
        input.* = acc.mul(s);
        acc = tmp;
    }

    return allinv;
}

// [agave] https://github.com/solana-program/zk-elgamal-proof/blob/d789e2a811c3912a43c1c0a52a2ac1079ce85f6c/zk-sdk/src/range_proof/inner_product.rs#L474
test "basic correctness" {
    const n: u64 = 32;

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

    var points: std.BoundedArray(Ristretto255, P_len) = .{};
    try points.appendSlice(table.G[0..n]);
    try points.appendSlice(table.H[0..n]);
    try points.append(Q);

    const P = ed25519.mulMultiRuntime(
        P_len,
        false,
        true,
        points.constSlice(),
        scalars.constSlice(),
    );

    var prover_transcript = Transcript.initTest("Test");
    var verifier_transcript = Transcript.initTest("Test");

    const proof = Proof(32).init(
        Q,
        &G_factors,
        &H_factors,
        &a,
        &b,
        &prover_transcript,
    );
    try proof.verify(
        &(.{bp.ONE} ** n),
        &H_factors,
        P,
        Q,
        &verifier_transcript,
    );
}
