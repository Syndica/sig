const std = @import("std");
const sig = @import("../../sig.zig");
const crypto = std.crypto;
const Ed25519 = crypto.ecc.Edwards25519;
const Ristretto255 = crypto.ecc.Ristretto255;
const CompressedScalar = Ed25519.scalar.CompressedScalar;

const ExtendedPoint = sig.crypto.ed25519.ExtendedPoint;
const CachedPoint = sig.crypto.ed25519.CachedPoint;

const LookupTable = struct {
    table: [8]CachedPoint,

    fn init(point: Ed25519) LookupTable {
        const e: ExtendedPoint = .fromPoint(point);
        var points: [8]CachedPoint = @splat(.fromExtended(e));
        for (0..7) |i| points[i + 1] = .fromExtended(e.addCached(points[i]));
        return .{ .table = points };
    }

    /// NOTE: variable time!
    fn select(self: LookupTable, index: i8) CachedPoint {
        // ensure we're in radix
        std.debug.assert(index >= -8);
        std.debug.assert(index <= 8);

        const abs = @abs(index);

        // set t = 0 * P = identityElement
        var t: CachedPoint = .identityElement;
        for (1..9) |j| if (abs == j) {
            t = self.table[j - 1];
        };
        // now t == |x| * P

        if (abs != index) t = t.neg();
        // not t == x * P

        return t;
    }
};

pub fn mulMulti(
    comptime max: comptime_int,
    points: []const Ed25519,
    scalars: []const CompressedScalar,
) Ed25519 {
    std.debug.assert(points.len <= max);
    std.debug.assert(scalars.len <= max);
    std.debug.assert(points.len == scalars.len);

    var scalars_in_radix: std.BoundedArray([64]i8, max) = .{};
    for (scalars) |scalar| {
        scalars_in_radix.appendAssumeCapacity(sig.crypto.ed25519.asRadix16(scalar));
    }

    var lookup_tables: std.BoundedArray(LookupTable, max) = .{};
    for (points) |point| {
        lookup_tables.appendAssumeCapacity(.init(point));
    }

    var q: ExtendedPoint = .identityElement;
    for (0..64) |rev| {
        const i = 64 - rev - 1;
        q = q.mulByPow2(4);
        for (scalars_in_radix.constSlice(), lookup_tables.constSlice()) |s, lt| {
            q = q.addCached(lt.select(s[i]));
        }
    }

    return q.toPoint();
}
