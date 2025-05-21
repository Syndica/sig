const std = @import("std");
const sig = @import("../../sig.zig");

const Edwards25519 = std.crypto.ecc.Edwards25519;
const Sha3 = std.crypto.hash.sha3.Sha3_512;
const Shake256 = std.crypto.hash.sha3.Shake256;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;
const weak_mul = sig.vm.syscalls.ecc.weak_mul;
const Transcript = sig.zksdk.Transcript;

const ONE = Scalar.fromBytes(.{1} ++ .{0} ** 31);

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
    const log_n = std.math.log2_int(u64, bit_size);
    return struct {
        L_vec: [log_n]Ristretto255,
        R_vec: [log_n]Ristretto255,
        a: Scalar,
        b: Scalar,

        const Self = @This();

        pub fn init(
            arena: *std.heap.ArenaAllocator,
            Q: Ristretto255,
            G_factors: []const Scalar,
            H_factors: []const Scalar,
            G_vec: []const Ristretto255,
            H_vec: []const Ristretto255,
            a_vec: []const Scalar,
            b_vec: []const Scalar,
            transcript: *Transcript,
        ) !Self {
            const allocator = arena.allocator();

            var G = try allocator.dupe(Ristretto255, G_vec);
            var H = try allocator.dupe(Ristretto255, H_vec);
            var a = try allocator.dupe(Scalar, a_vec);
            var b = try allocator.dupe(Scalar, b_vec);

            var n = G.len;

            if (H.len != n or
                a.len != n or
                b.len != n or
                G_factors.len != n or
                H_factors.len != n)
            {
                return error.GeneratorLengthMismatch;
            }

            if (!std.math.isPowerOfTwo(n)) {
                return error.InvalidBitSize;
            }

            transcript.appendDomSep("inner-product");
            transcript.appendU64("n", n);

            var L_vec: std.BoundedArray(Ristretto255, log_n) = .{};
            var R_vec: std.BoundedArray(Ristretto255, log_n) = .{};

            // If it's the first iteration, unroll the Hprime = H*y_inv scalar mults
            // into multiscalar muls, for performance.
            if (n != 1) {
                n = n / 2;

                const a_L = a[0..n];
                const a_R = a[n..];
                const b_L = b[0..n];
                const b_R = b[n..];
                const G_L = G[0..n];
                const G_R = G[n..];
                const H_L = H[0..n];
                const H_R = H[n..];

                const c_L = innerProduct(a_L, b_R);
                const c_R = innerProduct(a_R, b_L);

                var scalars: std.BoundedArray([32]u8, bit_size + 1) = .{};
                var points: std.BoundedArray(Edwards25519, bit_size + 1) = .{};

                for (a_L, G_factors[n .. n * 2]) |ai, gi| {
                    scalars.appendAssumeCapacity(ai.mul(gi).toBytes());
                }
                for (b_R, H_factors[0..n]) |bi, hi| {
                    scalars.appendAssumeCapacity(bi.mul(hi).toBytes());
                }
                scalars.appendAssumeCapacity(c_L.toBytes());

                for (G_R) |gi| points.appendAssumeCapacity(gi.p);
                for (H_L) |hi| points.appendAssumeCapacity(hi.p);
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

                for (G_L) |gi| points.appendAssumeCapacity(gi.p);
                for (H_R) |hi| points.appendAssumeCapacity(hi.p);
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

                const u = Scalar.fromBytes(transcript.challengeScalar("u"));
                const u_inv = u.invert();

                // Reduce round
                for (0..n) |i| {
                    a_L[i] = a_L[i].mul(u).add(u_inv.mul(a_R[i]));
                    b_L[i] = b_L[i].mul(u_inv).add(u.mul(b_R[i]));
                    G_L[i] = .{ .p = weak_mul.mulMulti(2, .{
                        G_L[i].p, G_R[i].p,
                    }, .{
                        u_inv.mul(G_factors[i]).toBytes(),
                        u.mul(G_factors[n + i]).toBytes(),
                    }) };
                    H_L[i] = .{ .p = weak_mul.mulMulti(2, .{
                        H_L[i].p, H_R[i].p,
                    }, .{
                        u.mul(H_factors[i]).toBytes(),
                        u_inv.mul(H_factors[n + i]).toBytes(),
                    }) };
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

                const c_L = innerProduct(a_L, b_R);
                const c_R = innerProduct(a_R, b_L);

                // TODO: if we're here after the first round, then the size has already been
                // divided by two, meaning we should be able to limit the bounded arrays to
                // bit_size / 2 + 1 instead, will need to do some testing.
                var scalars: std.BoundedArray([32]u8, bit_size + 1) = .{};
                var points: std.BoundedArray(Edwards25519, bit_size + 1) = .{};

                for (a_L) |ai| scalars.appendAssumeCapacity(ai.toBytes());
                for (b_R) |bi| scalars.appendAssumeCapacity(bi.toBytes());
                scalars.appendAssumeCapacity(c_L.toBytes());

                for (G_R) |gi| points.appendAssumeCapacity(gi.p);
                for (H_L) |hi| points.appendAssumeCapacity(hi.p);
                points.appendAssumeCapacity(Q.p);

                const L: Ristretto255 = .{
                    .p = switch (points.len) {
                        inline //
                        3, // 1 + 1 + 1
                        5, // 2 + 2 + 1
                        9, // 4 + 4 + 1
                        17, // 8 + 8 + 1
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

                for (G_L) |gi| points.appendAssumeCapacity(gi.p);
                for (H_R) |hi| points.appendAssumeCapacity(hi.p);
                points.appendAssumeCapacity(Q.p);

                const R: Ristretto255 = .{
                    .p = switch (points.len) {
                        inline //
                        3, // 1 + 1 + 1
                        5, // 2 + 2 + 1
                        9, // 4 + 4 + 1
                        17, // 8 + 8 + 1
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

                const u = Scalar.fromBytes(transcript.challengeScalar("u"));
                const u_inv = u.invert();

                for (0..n) |i| {
                    a_L[i] = a_L[i].mul(u).add(u_inv.mul(a_R[i]));
                    b_L[i] = b_L[i].mul(u_inv).add(u.mul(b_R[i]));
                    G_L[i] = .{ .p = weak_mul.mulMulti(
                        2,
                        .{ G_L[i].p, G_R[i].p },
                        .{ u_inv.toBytes(), u.toBytes() },
                    ) };
                    H_L[i] = .{ .p = weak_mul.mulMulti(
                        2,
                        .{ H_L[i].p, H_R[i].p },
                        .{ u.toBytes(), u_inv.toBytes() },
                    ) };
                }

                a = a_L;
                b = b_L;
                G = G_L;
                H = H_L;
            }

            // there should have been log(bit_size) reductions
            std.debug.assert(L_vec.len == log_n);
            std.debug.assert(R_vec.len == log_n);
            return .{
                .L_vec = L_vec.buffer[0..log_n].*,
                .R_vec = R_vec.buffer[0..log_n].*,
                .a = a[0],
                .b = b[0],
            };
        }
    };
}

const GeneratorsChain = struct {
    shake: Shake256,

    fn init(comptime label: []const u8) GeneratorsChain {
        var shake = Shake256.init(.{});
        shake.update("GeneratorsChain");
        shake.update(label);
        return .{ .shake = shake };
    }

    fn next(self: *GeneratorsChain) Ristretto255 {
        var bytes: [64]u8 = undefined;
        self.shake.squeeze(&bytes);
        return Ristretto255.fromUniform(bytes);
    }
};

/// Computes the inner product between two vectors.
///
/// Asserts the length is the same.
fn innerProduct(a: []const Scalar, b: []const Scalar) Scalar {
    std.debug.assert(a.len == b.len);
    var out = Scalar.fromBytes(Edwards25519.scalar.zero);
    for (a, b) |c, d| {
        out = out.add(c.mul(d));
    }
    return out;
}

/// Generates a list of the powers of `x`.
fn genPowers(allocator: std.mem.Allocator, x: Scalar, n: usize) ![]const Scalar {
    var list: std.ArrayListUnmanaged(Scalar) = .{};
    var next_exp = ONE;
    for (0..n) |_| {
        const exp_x = next_exp;
        next_exp = next_exp.mul(x);
        try list.append(allocator, exp_x);
    }
    return list.toOwnedSlice(allocator);
}

test "basic correctness" {
    const allocator = std.testing.allocator;
    const n: u64 = 32;

    var G: std.ArrayListUnmanaged(Ristretto255) = .{};
    defer G.deinit(allocator);
    var H: std.ArrayListUnmanaged(Ristretto255) = .{};
    defer H.deinit(allocator);

    var gc = GeneratorsChain.init("G");
    var hc = GeneratorsChain.init("H");
    for (0..n) |_| {
        try G.append(allocator, gc.next());
        try H.append(allocator, hc.next());
    }

    const Q = Q: {
        var output: [64]u8 = undefined;
        Sha3.hash("test point", &output, .{});
        break :Q Ristretto255.fromUniform(output);
    };

    var a: std.ArrayListUnmanaged(Scalar) = .{};
    defer a.deinit(allocator);
    var b: std.ArrayListUnmanaged(Scalar) = .{};
    defer b.deinit(allocator);

    for (0..n) |_| {
        try a.append(allocator, Scalar.random());
        try b.append(allocator, Scalar.random());
    }
    const c = innerProduct(a.items, b.items);

    const G_factors = try allocator.alloc(Scalar, n);
    defer allocator.free(G_factors);
    @memset(G_factors, ONE);

    const y_inv = Scalar.random();
    const H_factors = try genPowers(allocator, y_inv, n);
    defer allocator.free(H_factors);

    // P would be determined upstream, but we need a correct P to check the proof.
    //
    // To generate P = <a,G> + <b,H'> + <a,b> Q, compute
    //             P = <a,G> + <b',H> + <a,b> Q,
    // where b' = b ∘ y^(-n)
    var scalars: std.ArrayListUnmanaged([32]u8) = .{};
    defer scalars.deinit(allocator);
    for (a.items) |as| try scalars.append(allocator, as.toBytes());
    for (b.items, H_factors) |bi, yi| {
        try scalars.append(allocator, bi.mul(yi).toBytes());
    }
    try scalars.append(allocator, c.toBytes());

    var points: std.ArrayListUnmanaged(Edwards25519) = .{};
    defer points.deinit(allocator);
    for (G.items) |g| try points.append(allocator, g.p);
    for (H.items) |h| try points.append(allocator, h.p);
    try points.append(allocator, Q.p);

    const P = weak_mul.mulMulti(
        n,
        points.items[0..n].*,
        scalars.items[0..n].*,
    );
    _ = P;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var prover_transcript = Transcript.init("innerproducttest");
    const proof = try Proof(32).init(
        &arena,
        Q,
        G_factors,
        H_factors,
        G.items,
        H.items,
        a.items,
        b.items,
        &prover_transcript,
    );
    _ = proof;
}
