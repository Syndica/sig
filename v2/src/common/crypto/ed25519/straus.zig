const std = @import("std");

test {
    _ = std.testing.refAllDecls(@This());
}
const common = @import("common");

const ed25519 = common.crypto.ed25519;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const CompressedScalar = Edwards25519.scalar.CompressedScalar;

const ExtendedPoint = ed25519.ExtendedPoint;
const LookupTable = ed25519.LookupTable;

fn asRadix16(c: CompressedScalar) [64]i8 {
    std.debug.assert(c[31] <= 127);

    var output: [64]i8 = @splat(0);

    // radix 256 -> radix 16
    for (0..32) |i| {
        output[i * 2] = @intCast(c[i] & 0b1111);
        output[i * 2 + 1] = @intCast(c[i] >> 4);
    }

    // recenter
    for (0..63) |i| {
        const carry = (output[i] + 8) >> 4;
        output[i] -= carry << 4;
        output[i + 1] += carry;
    }

    return output;
}

pub fn mulMultiRuntime(
    comptime max: comptime_int,
    comptime encoded: bool,
    comptime ristretto: bool,
    points: []const ed25519.PointType(encoded, ristretto),
    scalars: []const CompressedScalar,
) ed25519.MulMultiReturnType(encoded, ristretto) {
    std.debug.assert(points.len <= max);
    std.debug.assert(scalars.len <= max);
    std.debug.assert(points.len == scalars.len);

    var scalars_in_radix_buf: [max][64]i8 = undefined;
    var scalars_in_radix: std.ArrayListUnmanaged([64]i8) = .initBuffer(&scalars_in_radix_buf);
    for (scalars) |scalar| {
        scalars_in_radix.appendAssumeCapacity(asRadix16(scalar));
    }

    var lookup_tables_buf: [max]LookupTable = undefined;
    var lookup_tables: std.ArrayList(LookupTable) = .initBuffer(&lookup_tables_buf);
    for (points) |point| {
        // Translate from whatever the input format is to a decompressed Ed25519 point.
        const decompressed = switch (encoded) {
            true => switch (ristretto) {
                true => (try Ristretto255.fromBytes(point)).p,
                else => try Edwards25519.fromBytes(point),
            },
            else => switch (ristretto) {
                true => point.p,
                else => point,
            },
        };
        lookup_tables.appendAssumeCapacity(.init(decompressed));
    }

    var q: ExtendedPoint = .identityElement;
    for (0..64) |rev| {
        const i = 64 - rev - 1;
        q = q.mulByPow2(4);
        for (scalars_in_radix.items, lookup_tables.items) |s, lt| {
            q = q.addCached(lt.select(s[i]));
        }
    }

    return switch (ristretto) {
        true => .{ .p = q.toPoint() },
        else => q.toPoint(),
    };
}

/// Same as `mulMulti` except it takes a comptime known amount of points/scalars. Seems
/// to help with inlining part of the precomputation steps to the callsite.
pub fn mulMulti(
    comptime N: comptime_int,
    points: [N]Ristretto255,
    scalars: [N]CompressedScalar,
) Ristretto255 {
    var radix: [N][64]i8 = undefined;
    for (&radix, scalars) |*r, s| {
        r.* = asRadix16(s);
    }

    var lts: [N]LookupTable = undefined;
    for (&lts, points) |*lt, p| {
        lt.* = .init(p.p);
    }

    var q: ExtendedPoint = .identityElement;
    for (0..64) |rev| {
        const i = 64 - rev - 1;
        q = q.mulByPow2(4);
        for (&radix, &lts) |s, lt| {
            q = q.addCached(lt.select(s[i]));
        }
    }

    return .{ .p = q.toPoint() };
}

/// variable time, variable base scalar multiplication
pub fn mul(
    comptime ristretto: bool,
    point: ed25519.PointType(false, ristretto),
    scalar: CompressedScalar,
) ed25519.PointType(false, ristretto) {
    const lookup_table: LookupTable = .init(if (ristretto) point.p else point);
    const radix = asRadix16(scalar);

    const q = step(lookup_table, radix);

    return switch (ristretto) {
        true => .{ .p = q },
        else => q,
    };
}

/// Variable-base multiplication of `scalar` by a comptime known point.
pub fn mulByKnown(comptime point: Ristretto255, scalar: CompressedScalar) Ristretto255 {
    @setEvalBranchQuota(9_000);
    const lookup_table: LookupTable = comptime .init(point.p);
    const radix = asRadix16(scalar);
    return .{ .p = step(lookup_table, radix) };
}

/// Small optimization, sometimes we need to multiply a few points with the same scalar.
/// By batching them into this one function, we can save on converting the scalar into radix-16
/// for each point and instead just reuse the single transformation.
pub fn mulManyWithSameScalar(
    comptime N: comptime_int,
    points: [N]Ristretto255,
    scalar: CompressedScalar,
) [N]Ristretto255 {
    const radix = asRadix16(scalar);
    var output: [N]Ristretto255 = undefined;
    for (points, &output) |point, *out| {
        out.* = .{ .p = step(.init(point.p), radix) };
    }
    return output;
}

inline fn step(
    lookup_table: LookupTable,
    radix: [64]i8,
) Edwards25519 {
    var q: ExtendedPoint = .identityElement;
    for (0..64) |rev| {
        const i = 64 - rev - 1;
        q = q.mulByPow2(4);
        q = q.addCached(lookup_table.select(radix[i]));
    }
    return q.toPoint();
}
