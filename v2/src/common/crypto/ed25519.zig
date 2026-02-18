const std = @import("std");
const builtin = @import("builtin");
const common = @import("../../common.zig");

const Signature = common.solana.Signature;
const Pubkey = common.solana.Pubkey;

pub const pippenger = @import("ed25519/pippenger.zig");
pub const straus = @import("ed25519/straus.zig");

pub const mul = straus.mul;
pub const mulManyWithSameScalar = straus.mulManyWithSameScalar;
pub const mulMulti = straus.mulMulti;

const convention: std.builtin.CallingConvention = switch (builtin.mode) {
    .ReleaseFast => .@"inline",
    else => .auto,
};

const generic = @import("ed25519/generic.zig");
const avx512 = @import("ed25519/avx512.zig");
const has_avx512 = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx512ifma) and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx512vl);
pub const use_avx125 = has_avx512 and builtin.zig_backend == .stage2_llvm;

// avx512 implementation relies on llvm specific tricks
const namespace = if (use_avx125) avx512 else generic;
pub const ExtendedPoint = namespace.ExtendedPoint;
pub const CachedPoint = namespace.CachedPoint;

const Edwards25519 = std.crypto.ecc.Edwards25519;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Sha512 = std.crypto.hash.sha2.Sha512;
const CompressedScalar = [32]u8;

/// Mainly used for transaction signature verification.
///
/// Verifies signatures in a somewhat batched manner in order to retain conformance with Agave's
/// loop of verify_stricts. Due to the unfortunately inconsistent nature of EdDSA, while
/// a batched method would be faster and remain compliant with the RFC, it would fail to
/// catch certain types of invalid signatures, incorrectly allowing them, thus breaking consensus
/// with the rest of the network.
///
/// Perhaps in the future we can move Solana over to using ed25519-zebra or move from a `verify_strict`
/// loop to a `verify` one, allowing batched verification.
pub fn verifyBatchOverSingleMessage(
    max: comptime_int,
    signatures: []const Signature,
    public_keys: []const Pubkey,
    message: []const u8,
) !void {
    std.debug.assert(signatures.len <= max);
    std.debug.assert(public_keys.len <= max);
    std.debug.assert(signatures.len == public_keys.len);

    var s_batch: std.BoundedArray(CompressedScalar, max) = .{};
    var a_batch: std.BoundedArray(Edwards25519, max) = .{};
    var hram_batch: std.BoundedArray(CompressedScalar, max) = .{};
    var expected_r_batch: std.BoundedArray(Edwards25519, max) = .{};

    for (signatures, public_keys) |signature, pubkey| {
        const r = signature.r;
        const s = signature.s;

        try Edwards25519.scalar.rejectNonCanonical(s);

        const a = try Edwards25519.fromBytes(pubkey.data);
        const expected_r = try Edwards25519.fromBytes(r);

        try affineLowOrder(a);
        try affineLowOrder(expected_r);

        var h = Sha512.init(.{});
        h.update(&r);
        h.update(&pubkey.data);
        h.update(message);
        var hram64: [Sha512.digest_length]u8 = undefined;
        h.final(&hram64);

        expected_r_batch.appendAssumeCapacity(expected_r);
        s_batch.appendAssumeCapacity(s);
        a_batch.appendAssumeCapacity(a);
        hram_batch.appendAssumeCapacity(Edwards25519.scalar.reduce64(hram64));
    }

    for (
        a_batch.constSlice(),
        hram_batch.constSlice(),
        s_batch.constSlice(),
        expected_r_batch.constSlice(),
    ) |a, k, s, expected_r| {
        const r = doubleBaseMul(k, a.neg(), s);
        if (!affineEqual(r, expected_r)) return error.InvalidSignature;
    }
}

/// See the doc-comment above `verifyBatchOverSingleMessage` for further detail,
/// but this is that same thing, just for single messages, and with the ability to toggle
/// between `verify` and `verify_strict` semantics (used in ed25519 precompile).
pub fn verifySignature(
    signature: Signature,
    pubkey: Pubkey,
    message: []const u8,
    strict: bool,
) !void {
    const s = signature.s;
    const r = signature.r;
    try Edwards25519.scalar.rejectNonCanonical(s);

    const a = try Edwards25519.fromBytes(pubkey.data);
    const expected_r = try Edwards25519.fromBytes(r);

    if (strict) {
        try affineLowOrder(a);
        try affineLowOrder(expected_r);
    }

    var h = Sha512.init(.{});
    h.update(&r);
    h.update(&pubkey.data);
    h.update(message);
    var hram64: [Sha512.digest_length]u8 = undefined;
    h.final(&hram64);

    const computed = doubleBaseMul(Edwards25519.scalar.reduce64(hram64), a.neg(), s);
    if (!affineEqual(computed, expected_r)) return error.InvalidSignature;
}

/// Equate two ed25519 points with the assumption that b.z is 1.
/// b.z == 1 is common when we have just deserialized a point from the wire
pub fn affineEqual(a: Edwards25519, b: Edwards25519) bool {
    const x1 = b.x.mul(a.z);
    const y1 = b.y.mul(a.z);
    return x1.equivalent(a.x) and y1.equivalent(a.y);
}

/// Determines whether `a` is of small order (in the torision subgroup E[8]), but with the
/// assumption that `a.Z == 1`.
///
/// There are 8 points with an order <= 8:
/// Order | Point                   | Serialize Point
/// 1       (0,         1)            0100000000000000000000000000000000000000000000000000000000000000
/// 2       (0,         2^255 - 20)   ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
/// 4       (-sqrt(-1), 0)            0000000000000000000000000000000000000000000000000000000000000080
/// 4       (sqrt(-1),  0)            0000000000000000000000000000000000000000000000000000000000000000
/// 8       ...                       c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
/// 8       ...                       c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
/// 8       ...                       26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
/// 8       ...                       26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85
///
/// Since in this function we know that Z will be 1, we don't need to perform any
/// normalization to cancel out the projective denominator, instead just directly performing
/// checks on the x,y coordinates. You'll notice that low-order points when negated still
/// retain their low-order nature, so there are 4 "pairs" of low order points. This means
/// just checking a single coordinate of the point is enough to determine if it's in the blacklist,
/// meaning we only need 4 equivalence checks to cover all of the pairs.
///
pub fn affineLowOrder(a: Edwards25519) !void {
    // y coordinate of points 5 and 6
    const y0: Edwards25519.Fe = .{ .limbs = .{
        0x4d3d706a17c7,
        0x1aec1679749fb,
        0x14c80a83d9c40,
        0x3a763661c967d,
        0x7a03ac9277fdc,
    } };
    // y coordinate of points 7 and 8
    const y1: Edwards25519.Fe = .{ .limbs = .{
        0x7b2c28f95e826,
        0x6513e9868b604,
        0x6b37f57c263bf,
        0x4589c99e36982,
        0x5fc536d88023,
    } };

    if (a.x.isZero() // first pair
    or a.y.isZero() // second pair
    or a.y.equivalent(y0) // third pair
    or a.y.equivalent(y1) // fourth pair
    ) return error.WeakPublicKey;
}

pub fn ReturnType(encoded: bool, ristretto: bool) type {
    const Base = if (ristretto) Ristretto255 else Edwards25519;
    return if (encoded) (error{NonCanonical} || std.crypto.errors.EncodingError)!Base else Base;
}

pub fn PointType(encoded: bool, ristretto: bool) type {
    if (encoded) return [32]u8;
    return if (ristretto) Ristretto255 else Edwards25519;
}

/// MSM in variable time with a runtime known (but comptime bounded) number
/// of points. useful for things such as bulletproofs where we are generic over
/// the bitsize and it can change between being more optimal to use straus or pippenger.
///
/// Generally speaking, `mulMulti` will be more useful as in most cases the number of points
/// and scalars is known ahead of time.
pub fn mulMultiRuntime(
    comptime max_elements: comptime_int,
    /// Set to true if the input is in wire-format. This lets us usually save
    /// an extra stack copy and loop when buffering the decoding process,
    /// instead just doing it once here straight into the extended point form.
    ///
    /// Changes the return type of the function to an error union, in case
    /// the encoded points decode into a non-canonical form.
    comptime encoded: bool,
    /// (Option only applies if we're decoding from a wire format).
    ///
    /// Set to true if the wire format we're decoding from is Ristretto instead
    /// of Edwards25519. The actual MSM itself still happens on the underlying
    /// Edwards25519 element, since there's no difference between the operation
    /// on Ristretto and Edwards25519, but the decoding is different.
    comptime ristretto: bool,
    ed_points: []const PointType(encoded, ristretto),
    compressed_scalars: []const CompressedScalar,
) ReturnType(encoded, ristretto) {
    // through impirical benchmarking, we see that pippenger's MSM becomes faster around
    // the 190 element mark.
    // TODO: maybe consider checking the `max_elements < 190` here instead
    // in order to avoid generating both versions? probably would be slower, not sure about the
    // code size impact.

    if (ed_points.len < 190) {
        return straus.mulMultiRuntime(
            max_elements,
            encoded,
            ristretto,
            ed_points,
            compressed_scalars,
        );
    } else {
        return pippenger.mulMultiRuntime(
            max_elements,
            encoded,
            ristretto,
            ed_points,
            compressed_scalars,
        );
    }
}

/// Stores a lookup table of multiplications of a point over radix-16 scalars, which is the most
/// common usecase for straus' method. table contains 1P, 2P, 3P, 4P, 5P, 6P, 7P, 8P, and
/// our window for the scalar indexes into it. Since we want radix-16 (i.e one nibble per byte),
/// we need 16 points, however we can optimize further by centering the radix at 0 (-8..8) and
/// negating the cached point if the radix is below zero. Thus our initialization for the table
/// is twice as keep while retaining the same effect.
pub const LookupTable = struct {
    table: [8]CachedPoint,

    pub fn init(point: Edwards25519) callconv(convention) LookupTable {
        const e: ExtendedPoint = .fromPoint(point);
        var points: [8]CachedPoint = @splat(.fromExtended(e));
        for (0..7) |i| points[i + 1] = .fromExtended(e.addCached(points[i]));
        return .{ .table = points };
    }

    /// NOTE: variable time!
    pub fn select(self: LookupTable, index: i8) callconv(convention) CachedPoint {
        // ensure we're in radix
        std.debug.assert(index >= -8);
        std.debug.assert(index <= 8);

        const abs = @abs(index);

        // t == |x| * P
        var t: CachedPoint = if (abs == 0) .identityElement else self.table[abs - 1];
        // if index was negative, negate the point
        if (index < 0) t = t.neg();

        return t;
    }
};

/// Similar structure to `LookupTable` but it holds odd multiples of the root point:
/// 1A, 3A, 5A, 7A, 9A, 11A, 13A, 15A.
const NafLookupTable5 = struct {
    table: [8]CachedPoint,

    fn init(point: Edwards25519) callconv(convention) NafLookupTable5 {
        const A: ExtendedPoint = .fromPoint(point);
        var Ai: [8]CachedPoint = @splat(.fromExtended(A));
        const A2 = A.dbl();
        for (0..7) |i| Ai[i + 1] = .fromExtended(A2.addCached(Ai[i]));
        return .{ .table = Ai };
    }

    fn select(self: NafLookupTable5, index: u64) CachedPoint {
        std.debug.assert(index & 1 == 1); // make sure the index is odd
        std.debug.assert(index < 16); // fits inside
        return self.table[index / 2];
    }
};

/// Same thing as `NafLookupTable5` but just stores points for radix 2^8 instead of 2^5
const NafLookupTable8 = struct {
    table: [64]CachedPoint,

    fn init(point: Edwards25519) callconv(convention) NafLookupTable8 {
        const A: ExtendedPoint = .fromPoint(point);
        var Ai: [64]CachedPoint = @splat(.fromExtended(A));
        const A2 = A.dbl();
        for (0..63) |i| Ai[i + 1] = .fromExtended(A2.addCached(Ai[i]));
        return .{ .table = Ai };
    }

    fn select(self: NafLookupTable8, index: u64) CachedPoint {
        std.debug.assert(index & 1 == 1); // make sure the index is odd
        std.debug.assert(index < 128);
        return self.table[index / 2];
    }
};

/// Compute `(aA + bB)`, in variable time, where `B` is the Ed25519 basepoint.
pub fn doubleBaseMul(a: CompressedScalar, A: Edwards25519, b: CompressedScalar) Edwards25519 {
    const a_naf = asNaf(a, 5);
    const b_naf = asNaf(b, 8);

    // Search through our NAFs to find the first index that will actually affect the outcome.
    // Otherwise the prepending 0s added by `asNaf` will just keep doubling the identityElement.
    var i: u64 = std.math.maxInt(u8);
    for (0..256) |rev| {
        i = 256 - rev - 1;
        if (a_naf[i] != 0 or b_naf[i] != 0) break;
    }

    const table_A: NafLookupTable5 = .init(A);

    // avx512 backend only needs ~25k quota, but avx2 one needs ~100k
    // TODO: make comptime precompilation stuff use the avx512 one because of this
    @setEvalBranchQuota(100_000);

    // Since we are pre-computing the basePoint lookup table, we might as well pre-compute it
    // for a larger amount of points in order to make it fast.
    const table_B: NafLookupTable8 = comptime .init(.basePoint);

    var Q: ExtendedPoint = .identityElement;
    while (true) {
        Q = Q.dbl();

        switch (std.math.order(a_naf[i], 0)) {
            .gt => Q = Q.addCached(table_A.select(@intCast(a_naf[i]))),
            .lt => Q = Q.subCached(table_A.select(@intCast(-a_naf[i]))),
            .eq => {},
        }

        switch (std.math.order(b_naf[i], 0)) {
            .gt => Q = Q.addCached(table_B.select(@intCast(b_naf[i]))),
            .lt => Q = Q.subCached(table_B.select(@intCast(-b_naf[i]))),
            .eq => {},
        }

        if (i == 0) break;
        i -= 1;
    }

    return Q.toPoint();
}

/// Ported from: https://github.com/dalek-cryptography/curve25519-dalek/blob/c3a82a8a38a58aee500a20bde1664012fcfa83ba/curve25519-dalek/src/scalar.rs#L958
fn asNaf(a: CompressedScalar, w: comptime_int) [256]i8 {
    std.debug.assert(w >= 2);
    std.debug.assert(w <= 8);

    var naf: [256]i8 = @splat(0);

    var x: [5]u64 = @splat(0);
    @memcpy(std.mem.asBytes(x[0..4]), &a);

    const width = 1 << w;
    const window_mask = width - 1;

    var pos: u64 = 0;
    var carry: u64 = 0;
    while (pos < 256) {
        const idx = pos / 64;
        const bit_idx: std.math.Log2Int(u64) = @intCast(pos % 64);

        const bit_buf: u64 = switch (bit_idx) {
            0...63 - w => x[idx] >> bit_idx,
            else => x[idx] >> bit_idx | x[1 + idx] << @intCast(64 - @as(u7, bit_idx)),
        };

        const window = carry + (bit_buf & window_mask);

        if (window & 1 == 0) {
            pos += 1;
            continue;
        }

        if (window < width / 2) {
            carry = 0;
            naf[pos] = @intCast(window);
        } else {
            carry = 1;
            const signed: i64 = @bitCast(window);
            naf[pos] = @as(i8, @truncate(signed)) -% @as(i8, @truncate(width));
        }

        pos += w;
    }

    return naf;
}

test asNaf {
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/c3a82a8a38a58aee500a20bde1664012fcfa83ba/curve25519-dalek/src/scalar.rs#L1495-L1513
    const A_SCALAR: [32]u8 = .{
        0x1a, 0x0e, 0x97, 0x8a, 0x90, 0xf6, 0x62, 0x2d, 0x37, 0x47, 0x02, 0x3f, 0x8a, 0xd8,
        0x26, 0x4d, 0xa7, 0x58, 0xaa, 0x1b, 0x88, 0xe0, 0x40, 0xd1, 0x58, 0x9e, 0x7b, 0x7f,
        0x23, 0x76, 0xef, 0x09,
    };
    const A_NAF: [256]i8 = .{
        0,  13, 0, 0,  0,  0, 0, 0, 0, 7,   0,  0,   0,  0, 0,  0,  -9, 0,  0, 0,  0,  -11,
        0,  0,  0, 0,  3,  0, 0, 0, 0, 1,   0,  0,   0,  0, 9,  0,  0,  0,  0, -5, 0,  0,
        0,  0,  0, 0,  3,  0, 0, 0, 0, 11,  0,  0,   0,  0, 11, 0,  0,  0,  0, 0,  -9, 0,
        0,  0,  0, 0,  -3, 0, 0, 0, 0, 9,   0,  0,   0,  0, 0,  1,  0,  0,  0, 0,  0,  0,
        -1, 0,  0, 0,  0,  0, 9, 0, 0, 0,   0,  -15, 0,  0, 0,  0,  -7, 0,  0, 0,  0,  -9,
        0,  0,  0, 0,  0,  5, 0, 0, 0, 0,   13, 0,   0,  0, 0,  0,  -3, 0,  0, 0,  0,  -11,
        0,  0,  0, 0,  -7, 0, 0, 0, 0, -13, 0,  0,   0,  0, 11, 0,  0,  0,  0, -9, 0,  0,
        0,  0,  0, 1,  0,  0, 0, 0, 0, -15, 0,  0,   0,  0, 1,  0,  0,  0,  0, 7,  0,  0,
        0,  0,  0, 0,  0,  0, 5, 0, 0, 0,   0,  0,   13, 0, 0,  0,  0,  0,  0, 11, 0,  0,
        0,  0,  0, 15, 0,  0, 0, 0, 0, -9,  0,  0,   0,  0, 0,  0,  0,  -1, 0, 0,  0,  0,
        0,  0,  0, 7,  0,  0, 0, 0, 0, -15, 0,  0,   0,  0, 0,  15, 0,  0,  0, 0,  15, 0,
        0,  0,  0, 15, 0,  0, 0, 0, 0, 1,   0,  0,   0,  0,
    };

    const result = asNaf(A_SCALAR, 5);
    try std.testing.expectEqualSlices(i8, &A_NAF, &result);
}

test "wnaf reconstruction" {
    const Scalar = Edwards25519.scalar.Scalar;
    for (0..1000) |_| {
        const scalar: Scalar = .random();
        inline for (.{ 5, 6, 7, 8 }) |w| {
            const naf = asNaf(scalar.toBytes(), w);
            var y: Scalar = .fromBytes(@splat(0));
            for (0..256) |rev| {
                const i = 256 - rev - 1;
                y = y.add(y);

                const n = @abs(naf[i]);
                var limbs: [32]u8 = @splat(0);
                std.mem.writeInt(u64, limbs[0..8], n, .little);

                const digit: Scalar = .fromBytes(if (naf[i] < 0)
                    Edwards25519.scalar.neg(limbs)
                else
                    limbs);

                y = y.add(digit);
            }

            try std.testing.expectEqual(y, scalar);
        }
    }
}

test doubleBaseMul {
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/c3a82a8a38a58aee500a20bde1664012fcfa83ba/curve25519-dalek/src/edwards.rs#L1812-L1835
    const A_TIMES_BASEPOINT: [32]u8 = .{
        0xea, 0x27, 0xe2, 0x60, 0x53, 0xdf, 0x1b, 0x59, 0x56, 0xf1, 0x4d, 0x5d, 0xec, 0x3c, 0x34,
        0xc3, 0x84, 0xa2, 0x69, 0xb7, 0x4c, 0xc3, 0x80, 0x3e, 0xa8, 0xe2, 0xe7, 0xc9, 0x42, 0x5e,
        0x40, 0xa5,
    };
    const A_SCALAR: [32]u8 = .{
        0x1a, 0x0e, 0x97, 0x8a, 0x90, 0xf6, 0x62, 0x2d, 0x37, 0x47, 0x02, 0x3f, 0x8a, 0xd8,
        0x26, 0x4d, 0xa7, 0x58, 0xaa, 0x1b, 0x88, 0xe0, 0x40, 0xd1, 0x58, 0x9e, 0x7b, 0x7f,
        0x23, 0x76, 0xef, 0x09,
    };
    const B_SCALAR: [32]u8 = .{
        0x91, 0x26, 0x7a, 0xcf, 0x25, 0xc2, 0x09, 0x1b, 0xa2, 0x17, 0x74, 0x7b, 0x66, 0xf0,
        0xb3, 0x2e, 0x9d, 0xf2, 0xa5, 0x67, 0x41, 0xcf, 0xda, 0xc4, 0x56, 0xa7, 0xd4, 0xaa,
        0xb8, 0x60, 0x8a, 0x05,
    };
    const DOUBLE_BASE_MUL_RESULT: [32]u8 = .{
        0x7d, 0xfd, 0x6c, 0x45, 0xaf, 0x6d, 0x6e, 0x0e, 0xba, 0x20, 0x37, 0x1a, 0x23, 0x64, 0x59,
        0xc4, 0xc0, 0x46, 0x83, 0x43, 0xde, 0x70, 0x4b, 0x85, 0x09, 0x6f, 0xfe, 0x35, 0x4f, 0x13,
        0x2b, 0x42,
    };

    const A: Edwards25519 = try .fromBytes(A_TIMES_BASEPOINT);
    const result = doubleBaseMul(A_SCALAR, A, B_SCALAR);

    try std.testing.expectEqualSlices(u8, &result.toBytes(), &DOUBLE_BASE_MUL_RESULT);
}

test "eddsa test cases" {
    const Vec = struct {
        msg_hex: []const u8,
        public_key_hex: *const [64:0]u8,
        sig_hex: *const [128:0]u8,
        expected: ?anyerror,
    };

    // Entries based off of ed25519-dalek 2.0 `verify_strict`. Dalek sometimes returns slightly
    // different types of errors, due to differences in the order of input parsing, but the
    // main factor we care about is whether or not it accepts the signature.
    // sig fmt: off
    const entries = [_]Vec{
        Vec{
            .msg_hex = "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
            .public_key_hex = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            .sig_hex = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
            .expected = error.WeakPublicKey, // 0
        },
        Vec{
            .msg_hex = "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
            .public_key_hex = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            .sig_hex = "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
            .expected = error.WeakPublicKey, // 1
        },
        Vec{
            .msg_hex = "48656c6c6f",
            .public_key_hex = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
            .sig_hex = "1c1ad976cbaae3b31dee07971cf92c928ce2091a85f5899f5e11ecec90fc9f8e93df18c5037ec9b29c07195ad284e63d548cd0a6fe358cc775bd6c1608d2c905",
            .expected = null,
        },
        Vec{
            .msg_hex = "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
            .public_key_hex = "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            .sig_hex = "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
            .expected = null, // 3 - mixed orders
        },
        Vec{
            .msg_hex = "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
            .public_key_hex = "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            .sig_hex = "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
            .expected = error.InvalidSignature, // 4 - cofactored verification
        },
        Vec{
            .msg_hex = "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
            .public_key_hex = "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            .sig_hex = "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
            .expected = error.InvalidSignature, // 5 - cofactored verification
        },
        Vec{
            .msg_hex = "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
            .public_key_hex = "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
            .sig_hex = "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
            .expected = error.NonCanonical, // 6 - S > L
        },
        Vec{
            .msg_hex = "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
            .public_key_hex = "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
            .sig_hex = "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
            .expected = error.NonCanonical, // 7 - S >> L
        },
        Vec{
            .msg_hex = "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
            .public_key_hex = "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
            .sig_hex = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
            .expected = error.WeakPublicKey, // 8 - non-canonical R
        },
        Vec{
            .msg_hex = "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
            .public_key_hex = "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
            .sig_hex = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
            .expected = error.WeakPublicKey, // 9 - non-canonical R
        },
        Vec{
            .msg_hex = "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
            .public_key_hex = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            .sig_hex = "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
            .expected = error.WeakPublicKey, // 10 - small-order A
        },
        Vec{
            .msg_hex = "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
            .public_key_hex = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            .sig_hex = "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
            .expected = error.WeakPublicKey, // 11 - small-order A
        },
    };
    // sig fmt: on

    for (entries) |entry| {
        var msg: [64 / 2]u8 = undefined;
        const msg_len = entry.msg_hex.len / 2;
        _ = try std.fmt.hexToBytes(msg[0..msg_len], entry.msg_hex);
        var public_key_bytes: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&public_key_bytes, entry.public_key_hex);
        var sig_bytes: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&sig_bytes, entry.sig_hex);

        const public_key: Pubkey = try .fromBytes(public_key_bytes);
        const signature: Signature = .fromBytes(sig_bytes);

        const result = verifyBatchOverSingleMessage(
            1,
            &.{signature},
            &.{public_key},
            msg[0..msg_len],
        );

        if (entry.expected) |error_type| {
            try std.testing.expectError(error_type, result);
        } else {
            try result;
        }
    }
}

test "batch verification" {
    for (0..100) |_| {
        const key_pair1 = std.crypto.sign.Ed25519.KeyPair.generate();
        const key_pair2 = std.crypto.sign.Ed25519.KeyPair.generate();
        var msg1: [64]u8 = undefined;
        var msg2: [64]u8 = undefined;
        std.crypto.random.bytes(&msg1);
        std.crypto.random.bytes(&msg2);
        const sig1 = try key_pair1.sign(&msg1, null);
        const sig2 = try key_pair2.sign(&msg1, null);

        try verifyBatchOverSingleMessage(2, &.{
            .fromSignature(sig1),
            .fromSignature(sig2),
        }, &.{
            .fromPublicKey(&key_pair1.public_key),
            .fromPublicKey(&key_pair2.public_key),
        }, &msg1);

        try std.testing.expectError(
            error.InvalidSignature,
            verifyBatchOverSingleMessage(2, &.{
                .fromSignature(sig1),
                .fromSignature(sig2),
            }, &.{
                .fromPublicKey(&key_pair1.public_key),
                .fromPublicKey(&key_pair1.public_key),
            }, &msg1),
        );

        try std.testing.expectError(
            error.InvalidSignature,
            verifyBatchOverSingleMessage(2, &.{
                .fromSignature(sig1),
                .fromSignature(sig2),
            }, &.{
                .fromPublicKey(&key_pair1.public_key),
                .fromPublicKey(&key_pair2.public_key),
            }, &msg2),
        );
    }
}

test "wycheproof" {
    const groups = @import("ed25519/wycheproof.zig").groups;
    for (groups) |group| {
        var public_key_buffer: [32]u8 = undefined;
        const public_key = try std.fmt.hexToBytes(&public_key_buffer, group.pubkey);
        if (public_key.len != 32) continue;

        for (group.cases) |case| {
            var msg_buffer: [1024]u8 = undefined;
            const msg_len = case.msg.len / 2;
            const message = try std.fmt.hexToBytes(msg_buffer[0..msg_len], case.msg);

            var sig_buffer: [64]u8 = undefined;
            if (case.sig.len > 64 * 2) continue;
            const signature_bytes = try std.fmt.hexToBytes(&sig_buffer, case.sig);
            if (signature_bytes.len != 64) continue;

            const pubkey = Pubkey.fromBytes(public_key_buffer) catch continue;
            const signature: Signature = .fromBytes(sig_buffer);

            // Single verify
            {
                const result = verifyBatchOverSingleMessage(
                    1,
                    &.{signature},
                    &.{pubkey},
                    message,
                );

                switch (case.expected) {
                    .valid => try result,
                    .invalid => try std.testing.expect(std.meta.isError(result)),
                }
            }

            // Multi verify
            {
                const result = verifyBatchOverSingleMessage(
                    10, // more max than inputs
                    &.{ signature, signature, signature, signature },
                    &.{ pubkey, pubkey, pubkey, pubkey },
                    message,
                );

                switch (case.expected) {
                    .valid => try result,
                    .invalid => try std.testing.expect(std.meta.isError(result)),
                }
            }
        }
    }
}
