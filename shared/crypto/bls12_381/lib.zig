const std = @import("std");
const c = @import("blst").c;
pub const tests = @import("tests.zig");

/// We do not need to provide any more granular errors than a simple pass/fail.
pub const Error = error{Failed};

/// Domain separation tag used by Solana's BLS proof-of-possession scheme.
/// Matches the value used by agave's solana-sdk bls-signatures crate and by
/// firedancer's `fd_bls12_381.c::FD_BLS_SIG_DOMAIN_POP`.
///
/// [firedancer] https://github.com/firedancer-io/firedancer/blob/main/src/ballet/bls/fd_bls12_381.c#L437
pub const PROOF_OF_POSSESSION_DST: []const u8 =
    "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

const Scalar = struct {
    scalar: c.scalar,

    fn fromBytes(bytes: *const [32]u8, endian: std.builtin.Endian) Error!Scalar {
        var scalar: c.scalar = undefined;
        switch (endian) {
            .little => c.scalar_from_lendian(&scalar, bytes),
            .big => c.scalar_from_bendian(&scalar, bytes),
        }
        if (!c.scalar_fr_check(&scalar)) return error.Failed;
        return .{ .scalar = scalar };
    }
};

pub const G1 = Definition(
    c.p1,
    c.p1_affine,
    c.fp,
    96,
    .{
        .uncompress = c.p1_uncompress,
        .deserialize = c.p1_deserialize,
        .serialize = c.p1_serialize,
        .affine_in_group = c.p1_affine_in_g1,
        .affine_serialize = c.p1_affine_serialize,
        .from_affine = c.p1_from_affine,
        .add = c.p1_add_or_double_affine,
        .cneg = c.fp_cneg,
        .mult = c.p1_mult,
        .affine_is_inf = c.p1_affine_is_inf,
    },
);

pub const G2 = Definition(
    c.p2,
    c.p2_affine,
    c.fp2,
    192,
    .{
        .uncompress = c.p2_uncompress,
        .deserialize = c.p2_deserialize,
        .serialize = c.p2_serialize,
        .affine_in_group = c.p2_affine_in_g2,
        .affine_serialize = c.p2_affine_serialize,
        .from_affine = c.p2_from_affine,
        .add = c.p2_add_or_double_affine,
        .cneg = c.fp2_cneg,
        .mult = c.p2_mult,
        .affine_is_inf = c.p2_affine_is_inf,
    },
);

fn Definition(
    Point: type,
    Aff: type,
    Fp: type,
    size: u32,
    comptime api: struct {
        uncompress: fn (*Aff, [*]const u8) callconv(.c) u32,
        deserialize: fn (*Aff, [*]const u8) callconv(.c) u32,
        serialize: fn ([*]u8, *const Point) callconv(.c) void,
        affine_in_group: fn (*const Aff) callconv(.c) bool,
        affine_serialize: fn ([*]u8, *const Aff) callconv(.c) void,
        from_affine: fn (*Point, *const Aff) callconv(.c) void,
        add: fn (*Point, *const Point, *const Aff) callconv(.c) void,
        cneg: fn (*Fp, *const Fp, bool) callconv(.c) void,
        mult: fn (*Point, *const Point, [*]const u8, u64) callconv(.c) void,
        affine_is_inf: fn (*const Aff) callconv(.c) bool,
    },
) type {
    return struct {
        p: Point,

        const Self = @This();

        const Affine = struct {
            p: Aff,

            fn fromBytesUnchecked(bytes: *const [size]u8, endian: std.builtin.Endian) Error!Affine {
                const in = switch (endian) {
                    .little => bswap(bytes),
                    .big => bytes.*,
                };
                var r: Aff = undefined;

                // Reject the point if the compressed or parity flag is set.
                if (in[0] & 0xA0 != 0) return error.Failed;

                if (api.deserialize(&r, &in) != c.SUCCESS) return error.Failed;
                return .{ .p = r };
            }
            fn fromBytes(bytes: *const [size]u8, endian: std.builtin.Endian) Error!Affine {
                const a = try fromBytesUnchecked(bytes, endian);
                if (!api.affine_in_group(&a.p)) return error.Failed;
                return a;
            }

            fn isInf(a: *const Affine) bool {
                return api.affine_is_inf(&a.p);
            }
        };

        pub fn validate(in: *const [size]u8, endian: std.builtin.Endian) Error!void {
            _ = try Affine.fromBytes(in, endian);
        }

        pub fn decompress(
            bytes: *const [size / 2]u8,
            out: *[size]u8,
            endian: std.builtin.Endian,
        ) Error!void {
            const in = switch (endian) {
                .little => bswapElement(bytes),
                .big => bytes.*,
            };

            var r: Aff = undefined;
            // Decompress the element and serialize.
            if (api.uncompress(&r, &in) != c.SUCCESS) return error.Failed;
            if (!api.affine_in_group(&r)) return error.Failed;
            api.affine_serialize(out, &r);

            if (endian == .little) out.* = bswap(out);
        }

        pub fn add(
            out: *[size]u8,
            a: *const [size]u8,
            b: *const [size]u8,
            endian: std.builtin.Endian,
        ) Error!void {
            // As per SIMD-0388, points x and y remain unchecked.
            const x = try Affine.fromBytesUnchecked(a, endian);
            const y = try Affine.fromBytesUnchecked(b, endian);
            const p: Self = .fromAffine(x);

            var r: Self = .{ .p = undefined };
            api.add(&r.p, &p.p, &y.p);
            r.toBytes(out, endian);
        }

        pub fn subtract(
            out: *[size]u8,
            a: *const [size]u8,
            b: *const [size]u8,
            endian: std.builtin.Endian,
        ) Error!void {
            // As per SIMD-0388, points x and y remain unchecked.
            const x = try Affine.fromBytesUnchecked(a, endian);
            var y = try Affine.fromBytesUnchecked(b, endian);
            const p: Self = .fromAffine(x);

            api.cneg(&y.p.y, &y.p.y, true); // Negate y

            var r: Self = .{ .p = undefined };
            api.add(&r.p, &p.p, &y.p);
            r.toBytes(out, endian);
        }

        pub fn multiply(
            out: *[size]u8,
            n: *const [32]u8,
            a: *const [size]u8,
            endian: std.builtin.Endian,
        ) Error!void {
            // Both `x` and `y` are validated per SIMD-0388.
            const x = try Affine.fromBytes(a, endian);
            const y = try Scalar.fromBytes(n, endian);
            const p: Self = .fromAffine(x);

            var r: Self = .{ .p = undefined };
            api.mult(&r.p, &p.p, &y.scalar.b, 255);
            r.toBytes(out, endian);
        }

        fn bswapElement(in: *const [size / 2]u8) [size / 2]u8 {
            const p: std.meta.Int(.unsigned, size * 4) = @bitCast(in.*);
            return @bitCast(@byteSwap(p));
        }

        fn bswap(in: *const [size]u8) [size]u8 {
            const x = bswapElement(in[0 .. size / 2]);
            const y = bswapElement(in[size / 2 .. size]);
            return x ++ y;
        }

        fn fromAffine(a: Affine) Self {
            var r: Point = undefined;
            api.from_affine(&r, &a.p);
            return .{ .p = r };
        }

        fn toBytes(p: *const Self, out: *[size]u8, endian: std.builtin.Endian) void {
            api.serialize(out, &p.p);
            if (endian == .little) out.* = bswap(out);
        }
    };
}

const BATCH_SIZE = 8;

pub fn pairingSyscall(
    out: *[48 * 12]u8,
    a: []const u8,
    b: []const u8,
    n: u64,
    endian: std.builtin.Endian,
) Error!void {
    if (n > BATCH_SIZE) return error.Failed; // hard limit on number of pairings allowed

    var g1: [BATCH_SIZE]c.p1_affine = undefined;
    var g2: [BATCH_SIZE]c.p2_affine = undefined;
    var g1_ptr: [BATCH_SIZE]*const c.p1_affine = undefined;
    var g2_ptr: [BATCH_SIZE]*const c.p2_affine = undefined;

    var j: u32 = 0;
    for (0..n) |i| {
        const w = try G1.Affine.fromBytes(a[96 * i ..][0..96], endian);
        const z = try G2.Affine.fromBytes(b[96 * 2 * i ..][0..192], endian);

        // Skip pairs where either side if the point at infinity. blst's
        // `miller_loop_n` does not handle infinity and silently produces
        // garbage for such pairs, which does not match what blstrs does.
        // Matching blstrs, we define e(0, Q) = e(P, 0) = 1 in GT, and simply
        // omit these pairs from the miller loop.
        if (w.isInf() or z.isInf()) continue;

        g1[j] = w.p;
        g2[j] = z.p;
        g1_ptr[j] = &g1[j];
        g2_ptr[j] = &g2[j];
        j += 1;
    }

    var r: c.fp12 = c.fp12_one().*;
    if (n > 0) {
        @branchHint(.likely);
        c.miller_loop_n(&r, &g2_ptr, &g1_ptr, j);
        c.final_exp(&r, &r);
    }

    for (0..12) |i| {
        const offset = switch (endian) {
            .little => i,
            .big => (12 - 1 - i),
        };
        const func = &switch (endian) {
            .little => c.lendian_from_fp,
            .big => c.bendian_from_fp,
        };
        func(out[48 * offset ..][0..48], &r.fp6[i / 6].fp2[(i / 2) % 3].fp[i % 2]);
    }
}

/// Verifies a BLS proof of possession in the min-pubkey-size scheme used by
/// Solana's vote program (SIMD-0387):
///   - public key in G1 (48-byte compressed)
///   - signature   in G2 (96-byte compressed)
///   - hash-to-curve domain separator: `PROOF_OF_POSSESSION_DST`
///
/// The check performed is `e(pk, H(msg)) == e(g1, sig)`, equivalently
/// `e(pk, H(msg)) * e(-g1, sig) == 1` in GT.
///
/// Mirrors firedancer's `fd_bls12_381_core_verify` /
/// `fd_bls12_381_proof_of_possession_verify`. As in firedancer, we explicitly
/// reject empty messages (msg.len == 0) to match agave's behavior of binding
/// the public key into the message in this scheme; in practice the SIMD-0387
/// PoP message is always 89 bytes so this branch is defensive.
///
/// [firedancer] https://github.com/firedancer-io/firedancer/blob/main/src/ballet/bls/fd_bls12_381.c#L460-L527
pub fn proofOfPossessionVerify(
    msg: []const u8,
    proof_compressed: *const [96]u8,
    pubkey_compressed: *const [48]u8,
) Error!void {
    // Match firedancer's defensive minimum length. The Solana PoP message is
    // always "ALPENGLOW" || vote_pubkey (32) || bls_pubkey (48) = 89 bytes, so
    // any caller-driven shorter message indicates a programming error.
    if (msg.len < 48) return error.Failed;

    // 1. Decompress public key into G1 affine and validate.
    var pk: c.p1_affine = undefined;
    if (c.p1_uncompress(&pk, pubkey_compressed) != c.SUCCESS) return error.Failed;
    if (!c.p1_affine_in_g1(&pk)) return error.Failed;
    // Reject the identity element. Matches solana-sdk bls-signatures.
    // [agave] https://github.com/anza-xyz/solana-sdk/blob/b66abfddd564aef5b4b82cf4e76381e96f2459f0/bls-signatures/src/pubkey/verify.rs#L120
    if (c.p1_affine_is_inf(&pk)) return error.Failed;

    // 2. Hash the message into G2 (validity in G2 is implicit in hash_to_g2).
    var hashed_msg: c.p2 = undefined;
    var hashed_msg_affine: c.p2_affine = undefined;
    c.hash_to_g2(
        &hashed_msg,
        msg.ptr,
        msg.len,
        PROOF_OF_POSSESSION_DST.ptr,
        PROOF_OF_POSSESSION_DST.len,
        null,
        0,
    );
    c.p2_to_affine(&hashed_msg_affine, &hashed_msg);

    // 3. Decompress signature into G2 affine and validate.
    var sig: c.p2_affine = undefined;
    if (c.p2_uncompress(&sig, proof_compressed) != c.SUCCESS) return error.Failed;
    if (!c.p2_affine_in_g2(&sig)) return error.Failed;

    // 4. Compute -g1 in affine form (g1 is the canonical generator of G1).
    var neg_g1_proj: c.p1 = c.p1_generator().*;
    c.p1_cneg(&neg_g1_proj, true);
    var neg_g1: c.p1_affine = undefined;
    c.p1_to_affine(&neg_g1, &neg_g1_proj);

    // 5. Pairing check: miller_loop_n over both pairs, then final_verify
    //    against fp12_one (which performs the final exponentiation).
    const g1_pts = [2]*const c.p1_affine{ &pk, &neg_g1 };
    const g2_pts = [2]*const c.p2_affine{ &hashed_msg_affine, &sig };
    var r: c.fp12 = c.fp12_one().*;
    c.miller_loop_n(&r, &g2_pts, &g1_pts, 2);
    if (!c.fp12_finalverify(&r, c.fp12_one())) return error.Failed;
}

// Test vectors are intentionally minimal; the agave-side conformance harness
// in solfuzz-agave covers exhaustive matrices. These ensure the wire-up is
// correct.
test "proofOfPossessionVerify: rejects too-short message" {
    const proof: [96]u8 = @splat(0);
    const pk: [48]u8 = @splat(0);
    try std.testing.expectError(error.Failed, proofOfPossessionVerify("", &proof, &pk));
    try std.testing.expectError(error.Failed, proofOfPossessionVerify("short", &proof, &pk));
}

test "proofOfPossessionVerify: rejects all-zero pubkey/proof" {
    // All-zero compressed form is invalid (0xA0 / 0xC0 prefix bits required).
    const proof: [96]u8 = @splat(0);
    const pk: [48]u8 = @splat(0);
    var msg: [89]u8 = @splat(0);
    @memcpy(msg[0..9], "ALPENGLOW");
    try std.testing.expectError(error.Failed, proofOfPossessionVerify(&msg, &proof, &pk));
}

// Test vector lifted from firedancer's `test_bls12_381.c` POP success case 1:
// m = "ALPENGLOW" || vote_account_pubkey (32B) || bls_pubkey (48B).
// [firedancer] https://github.com/firedancer-io/firedancer/blob/main/src/ballet/bls/test_bls12_381.c#L1162-L1176
test "proofOfPossessionVerify: firedancer alpenglow vector verifies" {
    var msg: [89]u8 = undefined;
    var proof: [96]u8 = undefined;
    var pk: [48]u8 = undefined;
    _ = try std.fmt.hexToBytes(
        &msg,
        "414c50454e474c4f57" ++
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" ++
            "b8778284f744f6ae2791145183ef8fcb66dcd6602da8ca1add3e6828904db482708fb1d9bd2cbeb72320cdef56d173bc",
    );
    _ = try std.fmt.hexToBytes(
        &proof,
        "b21b2bc4933e1d2cd32e9b976cc89a98d14f45c89356bb67afab0bc48a6ff9c2" ++
            "d3c4d2394d68706077e5dd7596459da70227c70f2f14adbfbcf6b46ae34f970f" ++
            "88b49dd8185f705333f682eb27674e8abbdf21519dd01424f6993713c9e4632d",
    );
    _ = try std.fmt.hexToBytes(
        &pk,
        "b8778284f744f6ae2791145183ef8fcb66dcd6602da8ca1add3e6828904db482708fb1d9bd2cbeb72320cdef56d173bc",
    );
    try proofOfPossessionVerify(&msg, &proof, &pk);

    // Tampering: flip one byte in the message and verification must fail.
    var bad_msg = msg;
    bad_msg[0] ^= 0xFF;
    try std.testing.expectError(
        error.Failed,
        proofOfPossessionVerify(&bad_msg, &proof, &pk),
    );

    // Tampering: flip a byte of the proof.
    var bad_proof = proof;
    bad_proof[0] ^= 0x01;
    try std.testing.expectError(
        error.Failed,
        proofOfPossessionVerify(&msg, &bad_proof, &pk),
    );
}
