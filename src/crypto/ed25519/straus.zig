const std = @import("std");
const sig = @import("../../sig.zig");
const ed25519 = sig.crypto.ed25519;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const CompressedScalar = Edwards25519.scalar.CompressedScalar;

const ExtendedPoint = ed25519.ExtendedPoint;
const CachedPoint = ed25519.CachedPoint;

const LookupTable = struct {
    table: [8]CachedPoint,

    fn init(point: Edwards25519) LookupTable {
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

        // t == |x| * P
        var t: CachedPoint = if (abs == 0) .identityElement else self.table[abs - 1];
        // if index was negative, negate the point
        if (abs != index) t = t.neg();

        return t;
    }
};

pub fn mulMulti(
    comptime max: comptime_int,
    comptime encoded: bool,
    comptime ristretto: bool,
    points: []const ed25519.PointType(encoded, ristretto),
    scalars: []const CompressedScalar,
) ed25519.ReturnType(encoded, ristretto) {
    std.debug.assert(points.len <= max);
    std.debug.assert(scalars.len <= max);
    std.debug.assert(points.len == scalars.len);

    var scalars_in_radix: std.BoundedArray([64]i8, max) = .{};
    for (scalars) |scalar| {
        scalars_in_radix.appendAssumeCapacity(sig.crypto.ed25519.asRadix16(scalar));
    }

    var lookup_tables: std.BoundedArray(LookupTable, max) = .{};
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
        for (scalars_in_radix.constSlice(), lookup_tables.constSlice()) |s, lt| {
            q = q.addCached(lt.select(s[i]));
        }
    }

    return switch (ristretto) {
        true => .{ .p = q.toPoint() },
        else => q.toPoint(),
    };
}
