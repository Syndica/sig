//! Authored by David Rubin <david@vortan.dev>

const std = @import("std");
const builtin = @import("builtin");

const pshufb_intrinsic: enum { avx512f, avx2, ssse3, fallback } = intrin: {
    if (builtin.cpu.has(.x86, .avx512f)) break :intrin .avx512f;
    if (builtin.cpu.has(.x86, .avx2)) break :intrin .avx2;
    if (builtin.cpu.has(.x86, .ssse3)) break :intrin .ssse3;
    break :intrin .fallback;
};

const L = switch (pshufb_intrinsic) {
    .avx512f => 64,
    .avx2 => 32,
    .ssse3 => 16,
    .fallback => 16,
};

const V = @Vector(L, u8);

const BinOp = fn (V, V) callconv(.c) V;

const pshufb: BinOp = switch (pshufb_intrinsic) {
    .avx512f => @extern(*const BinOp, .{ .name = "llvm.x86.avx512.pshuf.b.512" }).*,
    .avx2 => @extern(*const BinOp, .{ .name = "llvm.x86.avx2.pshuf.b" }).*,
    .ssse3 => @extern(*const BinOp, .{ .name = "llvm.x86.ssse3.pshuf.b.128" }).*,
    .fallback => pshufbFallback,
};

fn pshufbFallback(a_vec: @Vector(16, u8), mask: @Vector(16, u8)) callconv(.c) @Vector(16, u8) {
    const Vec = @Vector(16, u8);
    const a: [16]u8 = a_vec;
    const indices: [16]u8 = mask & @as(Vec, @splat(0x0f));

    var shuffled: [16]u8 = undefined;
    inline for (0..16) |i| shuffled[i] = a[indices[i]];

    const zero: Vec = @splat(0);
    const should_zero = mask & @as(Vec, @splat(0x80)) != zero;

    return @select(u8, should_zero, zero, shuffled);
}

/// The number of points we'll use for the interpolation.
const N = 64;
const Mask = std.meta.Int(.unsigned, N);

/// Recovers erased shreds in a Reed-Solomon coded set.
///
/// This function operates on a fixed-size RS(64, k) coding, where there
/// are `k` data shreds, and `64 - k` parity shreds.
///
/// `shred-sz`, the byte-length of each shred. Must be a mutliple of 32.
///
/// `shreds`, all 64 shred slices in order.  The first `data_shreds` slots
/// are data shreds and the remanining are parity shreds. Erased shreds
/// must still have valid writable memory backing them, as their contents
/// will be overwritten with the recovered data.
///
/// `data_shreds`, the number of data shreds in the encoding. This value
/// does not depend on the number of *erased* shreds, but on the original
/// number that was encoded. For a 32 data-shred 32 parity-shred coding,
/// this value would just be 32.
///
/// `parity_shreds`, the number of parity shreds in the encoding. Same
/// principal as `data_shreds`.
///
/// `mask`. A bitmask describingg which shreds are recovered. Bit `i`
/// is set if `shreds[i]` is erased and needs to be recovered. Bits beyond
/// `data_shreds + parity_shreds` are ignored.
///
/// Will retrun an error if,
///
/// - `Partial` if fewer than `data_shreds` non-erased shreds are available
/// in positions `0..data_shreds+parity_shreds`. Recovery is impossible without
/// enough evaluation points.
///
/// - `Corrupt` if a non-erased shred's contents is inconsistent with others
/// (the input codeword was not a valid RS codeword).
pub fn recover64(
    shred_sz: usize,
    shreds: *const [64][]u8,
    data_shreds: usize,
    parity_shreds: usize,
    mask: Mask,
) !void {
    @setEvalBranchQuota(100_000);
    const shred_cnt = data_shreds + parity_shreds;
    std.debug.assert(shred_cnt >= L);

    const erased: std.bit_set.IntegerBitSet(N) = .{ .mask = mask };
    var interp: [N]bool align(32) = undefined;

    var loaded_cnt: u32 = 0;
    for (0..N) |i| {
        const load_shred = (i < shred_cnt) and (loaded_cnt < data_shreds) and !erased.isSet(i);
        interp[i] = !load_shred;
        loaded_cnt += @intFromBool(load_shred);
    }
    if (loaded_cnt < data_shreds) return error.Partial;

    // Store the difference for each shred that was regenerated.
    // This must be 0, otherwise there's a corrupt shred.
    var diff: V = @splat(0);

    const pi = Pi.generate(interp);

    var position: u64 = 0;
    while (position < shred_sz) {
        // Load in the data, reading from `shreds` if it is not-erased,
        // and zeroing out the register if it is erased.
        var in: [N]V = undefined;
        inline for (0..N) |i| {
            in[i] = if (interp[i]) @splat(0) else shreds[i][position..][0..L].*;
        }

        // Multiply each evaluation point by Pi to get P(x)*Pi(x).
        // This zeroes out the erased points (since Pi(x) is zero there) and
        // scales the known positions so that the combined polynomial has
        // degree < N, making it suitable for IFFT. We technically only need
        // to multiply the non-erased points, but branching would cost more
        // than the multiply.
        inline for (0..N) |i| in[i] = GF.mul(in[i], pi[i]);

        // Convert the N evaluation values of P(x)*Pi(x) into its
        // coefficient representation.
        inline for (Butterfly.ifft) |b| ifft(&in, b.r0, b.r1, b.c);

        // Take the formal derivative in the coefficient basis. Combined
        // with the surrounding FFT/IFFT pair, this computes (P(x)*Pi(x))'
        // at each evaluation point. At erased positions where Pi(x)=0, this
        // equals P(x)*Pi'(x), from which we recover P(x) by dividing by Pi'(x) below.
        Table.formalDerivative(&in);

        // Convert the derivative's coefficients back to the evaluation values.
        inline for (Butterfly.fft_0) |b| fft(&in, b.r0, b.r1, b.c);

        // Divive by Pi to recover P(x) at each position. Remember that for
        // erased positions pi[i] holds 1/Pi'(x), making this a divison.
        inline for (0..N) |i| in[i] = GF.mul(in[i], pi[i]);

        // Write the result back.
        const processed = @min(shred_cnt, N);
        inline for (0..N) |n| {
            if (n >= processed) break;
            const ptr = shreds[n][position..][0..L];
            if (erased.isSet(n)) {
                ptr.* = in[n];
            } else if (interp[n]) {
                diff |= in[n] ^ @as(V, ptr.*);
            } else {
                in[n] = ptr.*;
            }
        }

        if (@reduce(.Or, diff) != 0) return error.Corrupt;
        position += L;
        if (shred_sz - L < position and position < shred_sz) {
            position = shred_sz - L;
        }
    }
}

/// Given a Reed-Solomon codeword of length N over GF(2^8), some positions
/// may be erased or lost. We want to recover the original polynomial P(x)
/// of degree  < k from known positions.
///
/// The Lin et al. approach constructs the erasure locator polynomial:
///     Pi(x) = \prod_{i: erased} (x ⊕ i)
/// where ⊕ is addition in G(2^8). Pi(x) has roots exactly at the erased
/// positions. When we generate this polynomial here, we pass in the
/// array of erased positions to be used.
///
/// Because GF(2^8) has characteristic 2, subtraction and
/// addition are the same, so (x - i) = (x + i) = (x ⊕ i).
///
/// At non-erased positions, we need Pi(x) itself (to divide out from
/// P * Pi to recover P). At erased positions Pi(x) = 0, so instead we
/// need Pi'(x) (the formal derivative) to use the product rule:
///     (P * Pi)'(x) = P'(x) * Pi(x) + P(x) * Pi'(x)
///                  for erased x where Pi(x)=0,
///                  = P(x)*Pi'(x)
///     P(x) = (P*Pi)'(x) / Pi'(x)
/// so generate returns Pi(x) for non-erased x, and Pi'(x) for erased x.
///
/// Taking logarithms (base 2):
///     log(Pi(x)) = \sigma_{i: erased} log(x ⊕ i)
/// which is the same convolution for two functions over {0, ..., N-1}:
///    - f(i) = erased[i]
///    - g(i) = log(i) (the discrete log, i.e. L~ from the paper)
///
///     (f ⊕ g)(x) = \sigma_i f(i) · g(x ⊕ i) = \sigma_{i: erased} log(x ⊕ i) = log(Pi(x))
///
/// The Walsh-Hadamard transform diagonalizes XOR convulation, just like
/// the DFT diagonalizes cyclic convluation:
///     FWHT(f ⊕ g) = FWHT(f) ·FWHT(g)
const Pi = struct {
    /// This table is computed the same way as the one in gf.exp_table,
    /// but is based on a generator of 16 rather than 2, as that is
    /// what `exp` operates on.
    const exp_table = gf.expTable(16);

    const zero: V = @splat(0);
    const max: V = @splat(0xFF);
    const top: V = @splat(0x80);

    const W = @Vector(L, u16);

    const chunks = N / L;

    /// The paper calls this L~, i.e. (0, log(1), log(2), log(3), ..., log(n-1)).
    const twiddle: [chunks]W = t: {
        var arr: [N]u16 = undefined;
        arr[0] = 0;
        for (1..N) |i| arr[i] = gf.log_table[i];

        // FWHT mod 255
        var s: usize = 1;
        while (s < N) : (s *= 2) {
            var i: usize = 0;
            while (i < N) : (i += 2 * s) {
                for (0..s) |j| {
                    const a = arr[i + j];
                    const b = arr[i + j + s];
                    arr[i + j] = (a + b) % 255;
                    arr[i + j + s] = (a + 255 - b) % 255;
                }
            }
        }

        break :t @bitCast(arr);
    };

    /// Compute gf.exp(x) for each byte lane.
    /// Uses a 4-bit base lookup + conditional multiplication for upper bits.
    fn exp16(x: V) V {
        const low = x & @as(V, @splat(0xF));
        var result = pshufb((exp_table[0..16] ** (L / 16)).*, low);
        inline for (0..4) |bit| {
            const mask = x << @splat(3 - bit);
            const acc = GF.mul(result, exp_table[1 << (bit + 4)]);
            result = @select(u8, mask & top != zero, acc, result);
        }
        return result;
    }

    fn addMod255(a: V, b: V) V {
        const sum = a +% b;
        const overflowed: V = @select(u8, sum < a, max, zero);
        return sum -% overflowed;
    }

    fn fwht(data: V) V {
        var result = data;
        comptime var shift = L / 2;
        inline while (shift >= 1) : (shift /= 2) {
            comptime var indices: [L]i32 = undefined;
            inline for (0..L) |i| indices[i] = i ^ shift;

            comptime var blend: [L]bool = undefined;
            inline for (0..L) |i| blend[i] = (i & shift) != 0;

            const shuffled = @shuffle(u8, result, undefined, indices);
            const negated = max -% result;
            const unshifted = @select(u8, blend, negated, result);
            result = addMod255(unshifted, shuffled);
        }
        return result;
    }

    fn fwhtFull(data: [chunks]V) [chunks]V {
        var result = data;

        comptime var k = chunks / 2;
        inline while (k >= 1) : (k /= 2) {
            const tmp = result;
            inline for (0..chunks) |c| {
                result[c] = if (c & k == 0)
                    addMod255(tmp[c], tmp[c ^ k])
                else
                    addMod255(max -% tmp[c], tmp[c ^ k]);
            }
        }

        inline for (0..chunks) |c| result[c] = fwht(result[c]);
        return result;
    }

    fn generate(is_erased: [N]bool) [N]u8 {
        var erased: [chunks]V = undefined;
        inline for (0..chunks) |c| {
            const b: @Vector(L, bool) = is_erased[c * L ..][0..L].*;
            erased[c] = @intFromBool(b);
        }

        const transformed = fwhtFull(erased);

        var short: [chunks]V = undefined;
        inline for (0..chunks) |c| {
            const product = (@as(W, transformed[c]) * twiddle[c]) % @as(W, @splat(255));
            short[c] = @truncate(product);
        }

        const log_pi = fwhtFull(short);

        var out: [N]u8 = undefined;
        inline for (0..chunks) |c| {
            const fixed = @select(u8, erased[c] == zero, log_pi[c], max -% log_pi[c]);
            out[c * L ..][0..L].* = exp16(fixed);
        }
        return out;
    }
};

/// Scalar operations on GF(2^8) reduced by x^8+x^4+x^3+x^2+x+1.
const gf = struct {
    fn mul(x: u8, y: u8) u8 {
        var a: u8 = x;
        var b: u8 = y;
        var p: u8 = 0;
        for (0..8) |_| {
            p ^= (b & 1) *% a;
            a = (a << 1) ^ ((a >> 7) *% 0x1D);
            b >>= 1;
        }
        return p;
    }

    fn pow(base: u8, exp: u8) u8 {
        var result: u8 = 1;
        var b: u8 = base;
        var e: u8 = exp;
        while (e != 0) {
            if ((e & 1) != 0) result = mul(result, b);
            b = mul(b, b);
            e >>= 1;
        }
        return result;
    }

    /// GF(2^8) division, using Fermat's little theorem
    /// a/b = a * b^{-1} = a * b^{254}
    fn div(a: u8, b: u8) u8 {
        return mul(a, pow(b, 254));
    }

    fn expTable(gen: comptime_int) [256]u8 {
        @setEvalBranchQuota(100_000);
        var exp: [256]u8 = undefined;
        exp[0] = 1;
        for (1..255) |i| exp[i] = mul(exp[i - 1], gen);
        exp[255] = exp[0];
        return exp;
    }
    const log_table = l: {
        const exp = expTable(2);
        var log: [256]u8 = undefined;
        log[0] = 0;
        for (0..255) |i| log[exp[i]] = i;
        break :l log;
    };
};

const GF = switch (builtin.cpu.has(.x86, .gfni)) {
    true => struct {
        /// Computes a translation table for emulating a GF multiplication
        /// on the ReedSolomon polynomial with the vgf2p8affineqb instruction.
        ///
        /// The vgf2p8mul does the same thing, but on the "wrong" polynomial,
        /// which means we cannot use it.
        const table = t: {
            @setEvalBranchQuota(100_000);
            var output: [256]@Vector(L / 8, u64) = undefined;
            for (0..256) |i| {
                var t: [8]u8 = undefined;
                for (0..8) |j| t[j] = gf.mul(i, 1 << j);
                var w: u64 = 0;
                for (0..64) |j| {
                    const bit = 1 << 7 - j / 8;
                    if (t[j % 8] & bit != 0) w |= 1 << j;
                }
                output[i] = @splat(w);
            }
            break :t output;
        };
        fn mul(x: V, c: u8) V {
            return asm ("vgf2p8affineqb $0x00, %[c], %[x], %[r]"
                : [r] "=v" (-> V),
                : [c] "rm" (table[c]),
                  [x] "v" (x),
            );
        }
    },
    false => struct {
        const scale: [256]u8 = s: {
            @setEvalBranchQuota(100_000);
            var arr: [256]u8 = undefined;
            for (0..256) |i| arr[i] = gf.mul(i, 16);
            break :s arr;
        };

        const table: [256]V = t: {
            @setEvalBranchQuota(200_000);
            var arr: [256]V = undefined;
            for (0..256) |i| {
                for (0..L) |j| {
                    arr[i][j] = gf.mul(i, j % 16);
                }
            }
            break :t arr;
        };

        fn mul(x: V, c: u8) V {
            const lo = x & @as(V, @splat(0x0F));
            const hi = x >> @splat(4);
            const p0 = pshufb(table[c], lo);
            const p1 = pshufb(table[scale[c]], hi);
            return p0 ^ p1;
        }
    },
};

const Table = struct {
    const lookup = l: {
        @setEvalBranchQuota(100_000);
        var arr: [8][256]u8 = undefined;
        for (0..8) |j| for (0..256) |x| {
            if (j == 0) {
                arr[0][x] = x;
            } else {
                arr[j][x] = gf.mul(arr[j - 1][x], arr[j - 1][x ^ (1 << (j - 1))]);
            }
        };
        break :l arr;
    };

    /// We compute the normalized subspace polynomial table.
    /// s_j(x) = prod_{k=0}^{2^j - 1} (x + k)
    /// S_j(x) = s_j(x) / s_j(2^j)
    ///
    /// s_0(x) = x
    /// s_1(x) = x*(x+1)
    /// s_2(x) = x*(x+1)*(x+2)*(x+3)
    /// ...
    /// S_j(x) normalizes so that S_j(2^j) = 1.
    ///
    /// The recurrence is:
    ///  s_j(x) = s_{j-1}(x) * s_{j-1}(x ^ 2^{j-1})
    ///
    /// This works because the set {0, 1, ..., 2^j - 1} is the union
    /// of {0, 1, ..., 2^{j-1} - 1} and {2^{j-1}, ..., 2^j - 1}, and
    /// x + (k + 2^{j-1}) = (x ^ 2^{j-1}) + k in GF(2^8).
    const bar = b: {
        @setEvalBranchQuota(1_000_000);
        var arr: [8][256]u8 = undefined;
        for (0..8) |j| for (0..256) |x| {
            arr[j][x] = gf.div(lookup[j][x], lookup[j][1 << j]);
        };
        _ = @This().B;
        break :b arr;
    };

    /// The novel polymnomial basis, defined by the normalized subspace polynomails.
    ///
    /// Any polynomial P of degree < N can be uniquely written in a "novel basis".
    ///
    ///     P(x) = \sum_{i=0}^{N-1} c_i * \phi_i(x)
    ///
    /// where the basis polynomial \phi_i(x) is the product of S_l(x) for each
    /// bit l set in i:
    ///
    ///     \phi_i(x) = \prod_{l: bit l set in i} S_l(x)
    ///
    /// Examples:
    ///     \phi_0(x) = 1
    ///     \phi_1(x) = S_0(x) = x
    ///     \phi_3(x) = S_0(x) * S_1(x)
    ///     \phi_5(x) = S_0(x) * S_2(x)
    ///
    /// The coefficients c_i are what `in` holds when passed into `formalDerivative`.
    ///
    /// The property we hold that makes the basis useful is that each S_l(x)
    /// is a linearized polynomial, a polynomial of the form x^(2+l)...,
    /// with all roots forming a linear subspace of GF(2^8). Because every term
    /// has degree that is a power of 2, and GF(2^8) has characteristic 2:
    ///
    ///     S_l'(x) = prime[l]
    ///
    /// prime[l] = S_l'(0) = s_l'(x) / s_l'(2^l)
    ///          = (\prod_{k=1}^{2^l - 1} k) / s_l(2^l)
    const prime = p: {
        @setEvalBranchQuota(1_000_000);
        var arr: [8]u8 = @splat(1);
        for (1..8) |l| {
            const length = 1 << l;
            var x = std.simd.iota(u8, length - 1);
            x += @splat(1);

            var y: u8 = x[0];
            for (1..length - 1) |i| y = gf.mul(y, x[i]);

            arr[l] = gf.div(y, lookup[l][length]);
        }
        break :p arr;
    };

    /// B[i] is the product of prime[l] for each bit l set in i:
    ///
    ///     B[i] = \prod_{l: bit l set in i} prime[l]
    ///
    /// This is the formal derivative1 of \phi_i evaluated at 0:
    ///
    ///     \phi_i'(0) = (\prod_{l: bit l set} S_l(x))' |_{x=0}
    ///
    /// Since S_l(0) = 0 for all l (0 is always the root), every term
    /// in the sum vanishes except when the product \prod_{l'!=l} S_{l'}(0)
    /// contains no S factors, i.e. when i has exactly one bit set. This
    /// means B[i] represents the product of derivative constants for all
    /// bits of i, which is what `formalDerivative` is based on.
    const B = b: {
        @setEvalBranchQuota(1_000_000);
        var arr: [256]u8 = undefined;
        for (0..256) |i| {
            var prod: u8 = 1;
            for (0..8) |j| {
                if (i & (1 << j) != 0) prod = gf.mul(prod, prime[j]);
            }
            arr[i] = prod;
        }
        break :b arr;
    };

    /// Computes the formal derivative of P in the novel polynomial basis.
    ///
    /// Given the coefficient representation c_i of P(x) = \sum_i c_i \phi_i(x),
    /// applying the product rule to each basis polynomial:
    ///
    ///     \phi_i'(x) = \sum_{l: bit l set in i} S_l'(x) \prod_{{l: bit l set in i} \ {l}} S_{l'}(x)
    ///                = \sum_{l: bit l set in i} prime[l] \cdot \phi_{i ⊕ (1 << l)}(x)
    ///
    /// where we used S_l'(x) = prime[l]. Summing over all i:
    ///
    ///     P'(x) = \sum_i c_i \sum{l: bit l set in i} prime[l] \cdot \phi_{i ⊕ (1 << l)}(x)
    ///
    /// Collecting by output index k (where k = i with bit l cleared):
    ///
    ///     d_k = \sum{l: bit l not set in k} c_{k | (1 << l)} \cdot prime[l]
    ///
    /// which is the coefficient of \phi_k in P'(x). The algorithm computes
    /// this efficiently by using the nice multiplicative structure of B:
    ///
    ///     B[k | (1 << l)] = B[k] * prime[l]
    ///
    /// so the sum can be rewritten as:
    ///
    ///     d_k = \frac{1}{B[k]} \sum_{l: bit l not set in k} c_{k | (1 << l)} \cdot B[k | (1 << l)]
    ///
    /// The first loop implements the inner sum via a scatter pass. For each
    /// j, scale c_j by B[j] and scatter to all j ⊕ (1 << l). Since clearing
    /// a set bit only decreases the index, every target j ⊕ (1 << l) < j was
    /// already zeroed when j was processed, so each target nicely accumulates.
    /// The second loop then multiplies each accumulated value by \frac{1}{B[k]}
    /// to recover d_k.
    fn formalDerivative(in: *[N]V) void {
        @setEvalBranchQuota(1_000 * N);
        inline for (0..N) |j| {
            in[j] = GF.mul(in[j], Table.B[j]);
            inline for (0..8) |l| if (j & (1 << l) != 0) {
                in[j ^ (1 << l)] ^= in[j]; // GF(2^8) addition
            };
            in[j] = @splat(0);
        }
        inline for (0..N) |j| {
            in[j] = GF.mul(in[j], gf.div(1, Table.B[j]));
        }
    }
};

const Butterfly = struct {
    r0: comptime_int,
    r1: comptime_int,
    c: comptime_int,

    const fft_0 = genForwards(N, 0, 0, 0);
    const ifft = genBackwards(N, 0, 0, 0);

    /// The IFFT and FFT decompose into log2(N) rounds of butterfly operations.
    /// At round j (stride 2^j), each buttefly pairs elements at positions
    /// (base, base + 2^j) and multiplies by S_j(omega ^ beta).
    ///
    /// ifft (evaluation -> coefficient):
    ///   v[r1] ^= v[r0]
    ///   v[r0] ^= S_j(omega ^ beta) * v[r1]
    ///
    /// fft (coefficient -> evaluation):
    ///   v[r0] ^= S_j(omega ^ beta) * v[r1]
    ///   v[r1] ^= v[r0]
    ///
    /// where omega is the base position within the round (aligned to 2*stride)
    /// and beta is the evaluation shift.
    fn gen(n: u8, beta: u8, i_round: u8, r_offset: u8) []const Butterfly {
        const half_len = n / (1 << (i_round + 1));
        comptime var butterflies: [half_len]Butterfly = undefined;
        for (&butterflies, 0..) |*b, j| {
            const omega = j * (1 << (i_round + 1));
            const c = Table.bar[i_round][omega ^ beta];
            b.* = .{ .r0 = r_offset + omega, .r1 = r_offset + (1 << i_round) + omega, .c = c };
        }
        return &butterflies;
    }

    fn genForwards(n: u8, beta: u8, i_round: u8, r_offset: u8) []const Butterfly {
        if (1 << i_round == n) return &.{};
        const result: []const Butterfly =
            genForwards(n, beta, i_round + 1, r_offset) ++
            genForwards(n, beta, i_round + 1, r_offset + (1 << i_round));
        return result ++ Butterfly.gen(n, beta, i_round, r_offset);
    }
    fn genBackwards(n: u8, beta: u8, i_round: u8, r_offset: u8) []const Butterfly {
        if (1 << i_round == n) return &.{};
        var result: []const Butterfly = Butterfly.gen(n, beta, i_round, r_offset);
        result = result ++ genBackwards(n, beta, i_round + 1, r_offset);
        result = result ++ genBackwards(n, beta, i_round + 1, r_offset + (1 << i_round));
        return result;
    }
};

inline fn ifft(v: *[N]V, a: comptime_int, b: comptime_int, c: comptime_int) void {
    v[b] ^= v[a];
    if (c != 0) v[a] = v[a] ^ GF.mul(v[b], c);
}

inline fn fft(v: *[N]V, a: comptime_int, b: comptime_int, c: comptime_int) void {
    if (c != 0) v[a] = v[a] ^ GF.mul(v[b], c);
    v[b] ^= v[a];
}

test pshufbFallback {
    const a: @Vector(16, u8) = .{ 17, 201, 3, 99, 44, 8, 250, 61, 12, 7, 111, 92, 5, 180, 33, 14 };
    const mask: @Vector(16, u8) = .{
        0x00, 0x03, 0x8f, 0x11, 0x7e, 0x05, 0x80, 0x0a,
        0x02, 0x4c, 0x09, 0x8d, 0x0f, 0x06, 0x1a, 0x0b,
    };
    const expected: @Vector(16, u8) = .{
        17, 99, 0, 201, 33, 8, 0, 111, 3, 5, 7, 0, 14, 250, 111, 92,
    };

    const actual = pshufbFallback(a, mask);
    if (builtin.cpu.has(.x86, .ssse3)) {
        const calculated = @extern(
            *const fn (@Vector(16, u8), @Vector(16, u8)) callconv(.c) @Vector(16, u8),
            .{ .name = "llvm.x86.ssse3.pshuf.b.128" },
        ).*(a, mask);
        try std.testing.expectEqual(calculated, actual);
    }
    try std.testing.expectEqual(expected, actual);
}
