const sig = @import("../../sig.zig");
const std = @import("std");
const builtin = @import("builtin");

pub const pippenger = @import("pippenger.zig");
pub const straus = @import("straus.zig");

pub const mul = straus.mul;
pub const mulManyWithSameScalar = straus.mulManyWithSameScalar;
pub const mulMulti = straus.mulMulti;

const generic = @import("generic.zig");
const avx512 = @import("avx512.zig");
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

pub fn verifyBatchOverSingleMessage(
    max: comptime_int,
    signatures: []const sig.core.Signature,
    public_keys: []const sig.core.Pubkey,
    message: []const u8,
) !void {
    std.debug.assert(signatures.len <= max);
    std.debug.assert(public_keys.len <= max);
    std.debug.assert(signatures.len == public_keys.len);

    var r_batch: std.BoundedArray(CompressedScalar, max) = .{};
    var s_batch: std.BoundedArray(CompressedScalar, max) = .{};
    var a_batch: std.BoundedArray(Edwards25519, max) = .{};
    var expected_r_batch: std.BoundedArray(Edwards25519, max) = .{};

    for (signatures, public_keys) |signature, pubkey| {
        const r = signature.r;
        const s = signature.s;
        try Edwards25519.scalar.rejectNonCanonical(s);
        const a = try Edwards25519.fromBytes(pubkey.data);
        try a.rejectIdentity();
        try Edwards25519.rejectNonCanonical(r);
        const expected_r = try Edwards25519.fromBytes(r);
        try expected_r.rejectIdentity();

        expected_r_batch.appendAssumeCapacity(expected_r);
        r_batch.appendAssumeCapacity(r);
        s_batch.appendAssumeCapacity(s);
        a_batch.appendAssumeCapacity(a);
    }

    var hram_batch: std.BoundedArray(CompressedScalar, max) = .{};
    for (public_keys, 0..) |pubkey, i| {
        var h = Sha512.init(.{});
        h.update(&r_batch.constSlice()[i]);
        h.update(&pubkey.data);
        h.update(message);
        var hram64: [Sha512.digest_length]u8 = undefined;
        h.final(&hram64);
        hram_batch.appendAssumeCapacity(Edwards25519.scalar.reduce64(hram64));
    }

    var z_batch: std.BoundedArray(CompressedScalar, max) = .{};
    z_batch.len = signatures.len;
    for (z_batch.slice()) |*z| {
        std.crypto.random.bytes(z[0..16]);
        @memset(z[16..], 0);
    }

    var zs_sum = Edwards25519.scalar.zero;
    for (z_batch.constSlice(), 0..) |z, i| {
        const zs = Edwards25519.scalar.mul(z, s_batch.constSlice()[i]);
        zs_sum = Edwards25519.scalar.add(zs_sum, zs);
    }
    zs_sum = Edwards25519.scalar.mul8(zs_sum);

    var zhs: std.BoundedArray(CompressedScalar, max) = .{};
    for (z_batch.constSlice(), 0..) |z, i| {
        zhs.appendAssumeCapacity(Edwards25519.scalar.mul(z, hram_batch.constSlice()[i]));
    }

    const zr = mulMultiRuntime(
        max,
        false,
        false,
        expected_r_batch.constSlice(),
        z_batch.constSlice(),
    ).clearCofactor();
    const zah = mulMultiRuntime(
        max,
        false,
        false,
        a_batch.constSlice(),
        zhs.constSlice(),
    ).clearCofactor();

    const zsb = try Edwards25519.basePoint.mulPublic(zs_sum);
    if (zr.add(zah).sub(zsb).rejectIdentity()) |_| {
        return error.SignatureVerificationFailed;
    } else |_| {}
}

/// Equate two ed25519 points with the assumption that b.z is 1.
/// b.z == 1 is commong when we have just deserialized a point from the wire
pub fn affineEqual(a: Edwards25519, b: Edwards25519) bool {
    const x1 = b.x.mul(a.z);
    const y1 = b.y.mul(a.z);
    return x1.equivalent(a.x) and y1.equivalent(a.y);
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

test "batch verification" {
    // run for 100 loops to ensure our z scalar randomization works
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
            error.SignatureVerificationFailed,
            verifyBatchOverSingleMessage(2, &.{
                .fromSignature(sig1),
                .fromSignature(sig2),
            }, &.{
                .fromPublicKey(&key_pair1.public_key),
                .fromPublicKey(&key_pair1.public_key),
            }, &msg1),
        );

        try std.testing.expectError(
            error.SignatureVerificationFailed,
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
